"""DMPNode — orchestrator that wires storage, DNS, HTTP, and cleanup.

Running a DMP node is usually just:

    from dmp.server.node import DMPNode

    node = DMPNode.from_env()
    node.start()
    node.wait()   # blocks until SIGTERM/SIGINT

Or as a module entrypoint:

    python -m dmp.server.node

Environment variables (all optional, sensible defaults for dev):

    DMP_DB_PATH            path to sqlite db                default: /var/lib/dmp/dmp.db
    DMP_DNS_HOST           bind host for the UDP DNS server  default: 0.0.0.0
    DMP_DNS_PORT           UDP port for DNS queries          default: 5353
    DMP_DNS_TTL            TTL seconds advertised in DNS     default: 60
    DMP_DNS_RATE           DNS queries per second per IP     default: 0 (disabled)
    DMP_DNS_BURST          DNS burst budget per IP           default: 0
    DMP_HTTP_HOST          bind host for HTTP API            default: 0.0.0.0
    DMP_HTTP_PORT          TCP port for HTTP API             default: 8053
    DMP_HTTP_TOKEN         bearer token for /v1/*            default: none (open)
    DMP_HTTP_RATE          HTTP requests per second per IP   default: 0 (disabled)
    DMP_HTTP_BURST         HTTP burst budget per IP          default: 0
    DMP_CLEANUP_INTERVAL   seconds between cleanup sweeps    default: 60
    DMP_LOG_LEVEL          python logging level              default: INFO
    DMP_LOG_FORMAT         "text" (default) or "json"        default: text

    DMP_CLUSTER_FILE           on-disk cluster.json (peer list)     default: /var/lib/dmp/cluster.json
    DMP_CLUSTER_MANIFEST_PATH  alias for DMP_CLUSTER_FILE (operator-facing name)
    DMP_NODE_ID                this node's id in the cluster        default: none (skip self-filter)
    DMP_SYNC_PEERS             comma-separated HTTP peer URLs       default: none (falls back to cluster file)
                               e.g. "http://dnsmesh-node-b:8053,http://dnsmesh-node-c:8053".
                               Takes precedence over DMP_CLUSTER_FILE when set.
    DMP_SYNC_PEER_TOKEN        shared token for /v1/sync/*          default: none (endpoints 403)
    DMP_SYNC_INTERVAL          seconds between sync ticks           default: 10
    DMP_SYNC_INTERVAL_SECONDS  alias for DMP_SYNC_INTERVAL (operator-facing name)
    DMP_SYNC_OPERATOR_SPK      hex ed25519 operator pubkey for
                               cluster-record re-verify             default: none
    DMP_CLUSTER_BASE_DOMAIN    cluster_name (e.g. "mesh.example.com")
                               gossiped manifests MUST bind to. When
                               set together with DMP_SYNC_OPERATOR_SPK
                               the anti-entropy worker also gossips the
                               signed manifest across peers (M3.3).
                               If unset, derived from the on-disk
                               cluster manifest.                     default: none
    DMP_SYNC_SELF_ENDPOINT     this node's HTTP URL on the peer
                               network (e.g. "http://dnsmesh-node-a:8053")
                               used to filter self out of a gossiped
                               manifest so a node never syncs with
                               itself.                               default: none

Peer URLs from DMP_SYNC_PEERS point at the OTHER nodes' HTTP base (e.g.
``http://dnsmesh-node-b:8053``). The worker appends ``/v1/sync/digest`` and
``/v1/sync/pull`` itself; callers should not include those suffixes.

Port 53 is privileged on Linux. In a container, publish with
`-p 53:5353/udp` or run with CAP_NET_BIND_SERVICE.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from dmp.server.anti_entropy import (
    AntiEntropyWorker,
    SyncPeer,
    load_peers_from_cluster_json,
)
from dmp.server.cleanup import CleanupWorker
from dmp.server.dns_server import DMPDnsServer
from dmp.server.http_api import (
    DEFAULT_MAX_TTL,
    DEFAULT_MAX_VALUE_BYTES,
    DEFAULT_MAX_VALUES_PER_NAME,
    DMPHttpApi,
)
from dmp.server.logging_config import configure_logging
from dmp.server.metrics import REGISTRY
from dmp.server.rate_limit import RateLimit
from dmp.storage.sqlite_store import SqliteMailboxStore

log = logging.getLogger(__name__)


def _default_token_db_path(record_db_path: str) -> str:
    """Resolve a token-DB path that sits alongside the record DB.

    Matches the default used by ``dnsmesh-node-admin --db ...``. Kept in
    two places rather than imported from admin.py to avoid the server
    main loop depending on an admin module.
    """
    from pathlib import Path as _Path

    p = _Path(record_db_path)
    return str(p.with_name(p.stem + "_tokens" + p.suffix))


def _default_heartbeat_db_path(record_db_path: str) -> str:
    """``dmp.db`` -> ``dmp_heartbeats.db`` alongside the record DB."""
    from pathlib import Path as _Path

    p = _Path(record_db_path)
    return str(p.with_name(p.stem + "_heartbeats" + p.suffix))


@dataclass
class _HeartbeatBundle:
    """Everything DMPNode hands to the HTTP API + worker when the
    heartbeat layer is opt-in-enabled. None when disabled."""

    store: object  # SeenStore; typed loose to avoid the import at
    # module load time for disabled deployments
    worker: object  # HeartbeatWorker
    submit_rate_limit: "RateLimit"
    seen_rate_limit: "RateLimit"
    self_endpoint: str
    self_spk_hex: str


def _load_heartbeat_from_env(record_db_path: str):
    """Return a ``_HeartbeatBundle`` if opt-in-enabled, else None.

    Prerequisites when enabled:
      - ``DMP_HEARTBEAT_ENABLED`` is truthy.
      - ``DMP_HEARTBEAT_SELF_ENDPOINT`` (fully-qualified HTTPS URL
        of this node, matching the hostname that peers reach).
      - ``DMP_HEARTBEAT_OPERATOR_KEY_PATH`` (file containing the
        node operator's Ed25519 private seed, 64-hex-char or
        32-byte binary).

    Misconfigured state (enabled but prerequisites missing) logs an
    ERROR and returns None rather than silently disabling — the
    operator asked for the feature, they should see the reason.
    """
    if os.environ.get("DMP_HEARTBEAT_ENABLED", "").strip() not in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return None

    self_endpoint = os.environ.get("DMP_HEARTBEAT_SELF_ENDPOINT", "").strip()
    key_path = os.environ.get("DMP_HEARTBEAT_OPERATOR_KEY_PATH", "").strip()
    if not self_endpoint:
        log.error(
            "DMP_HEARTBEAT_ENABLED but DMP_HEARTBEAT_SELF_ENDPOINT unset; "
            "heartbeat layer disabled."
        )
        return None
    if not key_path:
        log.error(
            "DMP_HEARTBEAT_ENABLED but DMP_HEARTBEAT_OPERATOR_KEY_PATH unset; "
            "heartbeat layer disabled."
        )
        return None

    # Load the Ed25519 private seed. Accept either hex-encoded text
    # (64 chars) or raw 32-byte binary. Any other shape -> fail.
    try:
        from pathlib import Path as _Path

        raw = _Path(key_path).expanduser().read_bytes().strip()
    except OSError as exc:
        log.error("heartbeat operator key unreadable: %s", exc)
        return None

    seed: Optional[bytes] = None
    if len(raw) == 32:
        seed = raw
    else:
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            text = ""
        if len(text) == 64:
            try:
                seed = bytes.fromhex(text)
            except ValueError:
                seed = None
    if seed is None or len(seed) != 32:
        log.error(
            "heartbeat operator key at %s is neither 32 raw bytes nor 64-hex",
            key_path,
        )
        return None

    # Build an OperatorSigner from the seed. DMPCrypto derives its
    # Ed25519 key from the X25519 private bytes; the heartbeat path
    # wants to use the operator's standalone Ed25519 key (same
    # artifact `generate-cluster-manifest.py` emits), so we use the
    # lightweight wrapper instead.
    from dmp.core.operator_signer import OperatorSigner

    crypto = OperatorSigner(seed)

    # SeenStore alongside the record DB (override via env).
    from dmp.server.heartbeat_store import SeenStore

    seen_db = os.environ.get(
        "DMP_HEARTBEAT_DB_PATH", ""
    ).strip() or _default_heartbeat_db_path(record_db_path)
    retention_hours = int(os.environ.get("DMP_HEARTBEAT_RETENTION_HOURS", "72"))
    max_rows = int(os.environ.get("DMP_HEARTBEAT_SEEN_MAX_ROWS", "10000"))
    store = SeenStore(
        seen_db,
        retention_seconds=retention_hours * 3600,
        max_rows=max_rows,
    )

    # Worker config.
    from dmp.server.heartbeat_worker import (
        HeartbeatWorker,
        HeartbeatWorkerConfig,
    )

    seed_peers_raw = os.environ.get("DMP_HEARTBEAT_SEEDS", "")
    seed_peers = tuple(s.strip() for s in seed_peers_raw.split(",") if s.strip())
    interval = int(os.environ.get("DMP_HEARTBEAT_INTERVAL_SECONDS", "300"))
    ttl = int(os.environ.get("DMP_HEARTBEAT_TTL_SECONDS", "86400"))
    max_peers = int(os.environ.get("DMP_HEARTBEAT_MAX_PEERS", "25"))
    version = os.environ.get("DMP_HEARTBEAT_VERSION", "").strip() or "dev"
    cfg = HeartbeatWorkerConfig(
        self_endpoint=self_endpoint,
        version=version,
        seed_peers=seed_peers,
        interval_seconds=interval,
        ttl_seconds=ttl,
        max_peers=max_peers,
    )
    worker = HeartbeatWorker(cfg, crypto, store)

    # Rate limits on the HTTP endpoints — independent submit / seen
    # buckets per codex phase-3 P2.
    submit_rate = float(os.environ.get("DMP_HEARTBEAT_SUBMIT_RATE_PER_SEC", "1.0"))
    submit_burst = float(os.environ.get("DMP_HEARTBEAT_SUBMIT_BURST", "30"))
    seen_rate = float(os.environ.get("DMP_HEARTBEAT_SEEN_RATE_PER_SEC", "5.0"))
    seen_burst = float(os.environ.get("DMP_HEARTBEAT_SEEN_BURST", "60"))

    return _HeartbeatBundle(
        store=store,
        worker=worker,
        submit_rate_limit=RateLimit(rate_per_second=submit_rate, burst=submit_burst),
        seen_rate_limit=RateLimit(rate_per_second=seen_rate, burst=seen_burst),
        self_endpoint=self_endpoint,
        self_spk_hex=crypto.get_signing_public_key_bytes().hex(),
    )


def _peer_id_from_url(url: str) -> str:
    """Derive a short stable peer id from an HTTP URL.

    Used when DMP_SYNC_PEERS feeds the worker directly — there is no
    ``node_id`` to key on, so we synthesize one. The id shows up in
    logs and as the watermark key, so stability across restarts of
    the same peer matters AND distinctness across peers on the same
    host is mandatory. If two peers collapse onto one watermark,
    anti-entropy advances past records that exist only on the other
    endpoint.

    Key includes host AND port AND path — two nodes on the same host
    at different ports are distinct peers. A short sha256 suffix of
    the full URL keeps the id under the ``MAX_NODE_ID_LEN`` cap in
    ``dmp.core.cluster`` while guaranteeing uniqueness.
    """
    import hashlib
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or url).strip().lower()
        port = parsed.port
        path = parsed.path or ""
    except Exception:
        host = url.strip().lower()
        port = None
        path = ""
    if not host:
        host = "peer"
    # Full-URL digest ensures peers on the same host but different
    # ports/paths never share a watermark key.
    key = f"{host}:{port or ''}{path}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:6]
    # Keep a human-readable host prefix for log legibility; cap the
    # total id at 16 chars (MAX_NODE_ID_LEN).
    prefix_len = max(1, 16 - 1 - len(digest))  # 1 for the '-' separator
    return f"{host[:prefix_len]}-{digest}"


def _peers_from_url_list(
    urls: List[str],
    *,
    self_node_id: Optional[str] = None,
    self_http_endpoint: Optional[str] = None,
) -> List[SyncPeer]:
    """Build a ``SyncPeer`` list from a raw URL list (DMP_SYNC_PEERS).

    Skips empty / duplicate entries so a stray ``"a,,b"`` or ``"a,a"``
    doesn't wedge the round-robin index on a phantom peer. Also drops
    any URL matching ``self_http_endpoint`` (case-insensitive,
    trailing-slash-normalized) or whose synthesized peer id matches
    ``self_node_id``.

    The URL-based check is the one that actually fires for the common
    DMP_SYNC_PEERS configuration: ``_peer_id_from_url`` produces
    synthetic ids like ``host-abc123``, while ``self_node_id`` is the
    operator-defined manifest id (``node-a``). Comparing the two never
    matches, so without the URL check an operator who accidentally
    includes their own URL in DMP_SYNC_PEERS would have the worker
    sync with itself indefinitely.
    """
    self_ep_norm = (
        self_http_endpoint.rstrip("/").lower() if self_http_endpoint else None
    )
    seen_urls: set = set()
    peers: List[SyncPeer] = []
    for raw in urls:
        url = raw.strip().rstrip("/")
        if not url:
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        if self_ep_norm and url.lower() == self_ep_norm:
            continue
        peer_id = _peer_id_from_url(url)
        if self_node_id and peer_id == self_node_id:
            continue
        peers.append(SyncPeer(node_id=peer_id, http_endpoint=url))
    return peers


@dataclass
class DMPNodeConfig:
    db_path: str = "/var/lib/dmp/dmp.db"
    dns_host: str = "0.0.0.0"
    dns_port: int = 5353
    dns_ttl: int = 60
    # Conservative on-by-default DNS rate limit. Operators who need a
    # busier public resolver can raise these via env vars.
    dns_rate: float = 50.0
    dns_burst: float = 200.0
    http_host: str = "0.0.0.0"
    http_port: int = 8053
    # `http_token` is the operator (write-anywhere) token. In M5.5+ it is
    # also aliased as `DMP_OPERATOR_TOKEN` for clarity; `DMP_HTTP_TOKEN`
    # remains supported for backward compatibility.
    http_token: Optional[str] = None
    # Multi-tenant auth (M5.5):
    #   auth_mode = "open"         — no auth, dev only. Chosen when no
    #                                 token is configured.
    #             = "legacy"       — single shared operator token
    #                                 (pre-M5.5 behavior).
    #             = "multi-tenant" — per-user tokens + operator token for
    #                                 operator-reserved namespaces.
    # If DMP_AUTH_MODE is unset, it's derived from whether http_token is
    # set, so existing deploys upgrade without a config change.
    auth_mode: Optional[str] = None
    # Path to the sqlite token store. Defaults to sibling of db_path.
    token_db_path: Optional[str] = None
    # Bursts are sized for legitimate bulk publishes: a fresh
    # `dnsmesh identity refresh-prekeys --count 50` + a manifest and half a
    # dozen chunks lands under the burst, while a sustained flood is
    # still throttled to http_rate per second.
    http_rate: float = 10.0
    http_burst: float = 100.0
    # Resource caps on publish — see http_api.DEFAULT_MAX_*.
    max_ttl: int = DEFAULT_MAX_TTL
    max_value_bytes: int = DEFAULT_MAX_VALUE_BYTES
    max_values_per_name: int = DEFAULT_MAX_VALUES_PER_NAME
    # Per-server concurrency ceilings. Above these caps the server drops
    # new connections/packets rather than spawning unbounded threads.
    http_max_concurrency: int = 64
    dns_max_concurrency: int = 128
    cleanup_interval: float = 60.0
    log_level: str = "INFO"
    log_format: str = "text"  # "text" or "json"

    # M2.4 anti-entropy. See dmp.server.anti_entropy for the full design.
    # Empty cluster_file or a missing file silently disables the worker —
    # a solo node has nothing to sync with.
    cluster_file: str = "/var/lib/dmp/cluster.json"
    node_id: Optional[str] = None
    sync_peer_token: Optional[str] = None
    sync_interval: float = 10.0
    # Hex-encoded Ed25519 operator public key used to re-verify signed
    # cluster-manifest records pulled from peers. Optional — without it
    # cluster records are accepted after a structural parse, which is
    # fine for most operators (the node's own operator deployed the
    # cluster.json anyway).
    sync_cluster_operator_spk_hex: Optional[str] = None
    # M3.3 manifest gossip. When cluster_base_domain is set AND
    # sync_cluster_operator_spk_hex is set, the anti-entropy worker
    # gossips the signed manifest across peers: one tick after the
    # operator rolls a higher-seq manifest onto any one node, the rest
    # install it automatically. Without base_domain the worker cannot
    # bind the incoming manifest to the expected cluster_name, so
    # gossip stays off. Derived from the manifest on disk when unset
    # so existing deployments pick up the feature for free.
    cluster_base_domain: Optional[str] = None
    # Operator-facing URL this node exposes on the peer HTTP network.
    # Used to filter self out of a gossiped manifest's node list — a
    # node that lists itself in the peer set would otherwise create an
    # infinite-tick self-sync loop. Defaults to None (self-exclusion
    # then relies on ``node_id`` alone, which is correct for the
    # compose-sample setup).
    sync_self_endpoint: Optional[str] = None
    # M2.5/M2.6 direct-peer-list env wiring. When non-empty, these URLs
    # become the SyncPeer list directly and cluster_file is ignored. Each
    # entry is an HTTP base URL (no trailing path); the anti-entropy
    # worker appends /v1/sync/* itself. Peer ids default to the URL host
    # so logs stay readable in docker-compose deployments where node
    # names are container DNS names.
    sync_peers: List[str] = field(default_factory=list)

    @classmethod
    def from_env(cls) -> "DMPNodeConfig":
        # M2.5/M2.6: accept operator-facing aliases alongside the older
        # names. Aliases exist so the docker-compose.cluster sample's env
        # files read naturally ("_SECONDS", "_PATH") while keeping the
        # short historical forms working for older deployments. The older
        # name wins when BOTH are set — we log a warning there so the
        # operator can clean up, but we don't fail to start.
        cluster_file_default = os.environ.get("DMP_CLUSTER_FILE")
        cluster_manifest_path = os.environ.get("DMP_CLUSTER_MANIFEST_PATH")
        if cluster_file_default and cluster_manifest_path:
            log.warning(
                "both DMP_CLUSTER_FILE and DMP_CLUSTER_MANIFEST_PATH set; "
                "using DMP_CLUSTER_FILE"
            )
        cluster_file = cluster_file_default or cluster_manifest_path or cls.cluster_file

        sync_interval_default = os.environ.get("DMP_SYNC_INTERVAL")
        sync_interval_seconds = os.environ.get("DMP_SYNC_INTERVAL_SECONDS")
        if sync_interval_default and sync_interval_seconds:
            log.warning(
                "both DMP_SYNC_INTERVAL and DMP_SYNC_INTERVAL_SECONDS set; "
                "using DMP_SYNC_INTERVAL"
            )
        sync_interval_raw = (
            sync_interval_default or sync_interval_seconds or str(cls.sync_interval)
        )

        # DMP_SYNC_PEERS parses as a comma-separated URL list. Empty /
        # unset / whitespace-only values yield an empty list, which is
        # the "no direct peer wiring; fall back to cluster file" path.
        raw_peers = os.environ.get("DMP_SYNC_PEERS") or ""
        sync_peers = [p.strip() for p in raw_peers.split(",") if p.strip()]

        # M3.3 gossip. ``DMP_CLUSTER_BASE_DOMAIN`` pins the cluster_name
        # gossiped manifests must bind to. Without a pinned operator
        # public key on top, gossip stays off regardless — a log warning
        # fires in ``_make_anti_entropy_worker`` so operators catch the
        # misconfig. ``DMP_SYNC_SELF_ENDPOINT`` is the URL this node
        # exposes on the peer HTTP network; used to drop self out of a
        # gossiped manifest's node list.
        # DNS names are case-insensitive; the sqlite store matches
        # owner names byte-for-byte. Normalize (strip trailing dot,
        # lowercase) so Mesh.Example.COM and mesh.example.com resolve
        # to the same cluster.* rrset for both the endpoint and the
        # worker's seq check.
        _raw_base_domain = os.environ.get("DMP_CLUSTER_BASE_DOMAIN") or None
        cluster_base_domain = (
            _raw_base_domain.rstrip(".").lower() if _raw_base_domain else None
        )
        sync_self_endpoint = os.environ.get("DMP_SYNC_SELF_ENDPOINT") or None

        return cls(
            db_path=os.environ.get("DMP_DB_PATH", cls.db_path),
            dns_host=os.environ.get("DMP_DNS_HOST", cls.dns_host),
            dns_port=int(os.environ.get("DMP_DNS_PORT", cls.dns_port)),
            dns_ttl=int(os.environ.get("DMP_DNS_TTL", cls.dns_ttl)),
            dns_rate=float(os.environ.get("DMP_DNS_RATE", cls.dns_rate)),
            dns_burst=float(os.environ.get("DMP_DNS_BURST", cls.dns_burst)),
            http_host=os.environ.get("DMP_HTTP_HOST", cls.http_host),
            http_port=int(os.environ.get("DMP_HTTP_PORT", cls.http_port)),
            # DMP_OPERATOR_TOKEN is the preferred name as of M5.5;
            # fall back to DMP_HTTP_TOKEN for deploys that predate it.
            http_token=(
                os.environ.get("DMP_OPERATOR_TOKEN")
                or os.environ.get("DMP_HTTP_TOKEN")
                or None
            ),
            auth_mode=os.environ.get("DMP_AUTH_MODE") or None,
            token_db_path=os.environ.get("DMP_TOKEN_DB_PATH") or None,
            http_rate=float(os.environ.get("DMP_HTTP_RATE", cls.http_rate)),
            http_burst=float(os.environ.get("DMP_HTTP_BURST", cls.http_burst)),
            max_ttl=int(os.environ.get("DMP_MAX_TTL", cls.max_ttl)),
            max_value_bytes=int(
                os.environ.get("DMP_MAX_VALUE_BYTES", cls.max_value_bytes)
            ),
            max_values_per_name=int(
                os.environ.get("DMP_MAX_VALUES_PER_NAME", cls.max_values_per_name)
            ),
            http_max_concurrency=int(
                os.environ.get("DMP_HTTP_MAX_CONCURRENCY", cls.http_max_concurrency)
            ),
            dns_max_concurrency=int(
                os.environ.get("DMP_DNS_MAX_CONCURRENCY", cls.dns_max_concurrency)
            ),
            cleanup_interval=float(
                os.environ.get("DMP_CLEANUP_INTERVAL", cls.cleanup_interval)
            ),
            log_level=os.environ.get("DMP_LOG_LEVEL", cls.log_level),
            log_format=os.environ.get("DMP_LOG_FORMAT", cls.log_format),
            cluster_file=cluster_file,
            node_id=os.environ.get("DMP_NODE_ID") or None,
            sync_peer_token=os.environ.get("DMP_SYNC_PEER_TOKEN") or None,
            sync_interval=float(sync_interval_raw),
            sync_cluster_operator_spk_hex=(
                os.environ.get("DMP_SYNC_OPERATOR_SPK") or None
            ),
            sync_peers=sync_peers,
            cluster_base_domain=cluster_base_domain,
            sync_self_endpoint=sync_self_endpoint,
        )


class DMPNode:
    """A full DMP node: sqlite store + DNS server + HTTP API + cleanup."""

    def __init__(self, config: Optional[DMPNodeConfig] = None):
        self.config = config or DMPNodeConfig()
        self.store: Optional[SqliteMailboxStore] = None
        self.dns: Optional[DMPDnsServer] = None
        self.http: Optional[DMPHttpApi] = None
        self.cleanup: Optional[CleanupWorker] = None
        self.anti_entropy: Optional[AntiEntropyWorker] = None
        self._stopped = threading.Event()

    @classmethod
    def from_env(cls) -> "DMPNode":
        return cls(DMPNodeConfig.from_env())

    def start(self) -> None:
        configure_logging(self.config.log_level, self.config.log_format)

        self._ensure_db_parent_exists()

        self.store = SqliteMailboxStore(self.config.db_path)

        # Publish the signed cluster manifest into the store on startup
        # if one is mounted. Clients fan out / union-read against the
        # cluster by first resolving `cluster.<base>` TXT — if the node
        # never puts the wire into its own mailbox, there's nothing for
        # DNS-based bootstrap to find. This runs even when DMP_SYNC_PEERS
        # took precedence over the manifest for peer discovery, because
        # the client-facing cluster TXT still needs to exist. Silently
        # no-op if the file is missing / malformed — anti-entropy and
        # the HTTP API are independent subsystems.
        self._publish_cluster_manifest_from_file()

        # Expose record count as a lazy Prometheus gauge.
        REGISTRY.register_lazy_gauge(
            "dmp_records",
            lambda: float(self.store.record_count()) if self.store else 0.0,
            help_text="Live records in the DMP mailbox store",
        )

        self.dns = DMPDnsServer(
            self.store,
            host=self.config.dns_host,
            port=self.config.dns_port,
            ttl=self.config.dns_ttl,
            rate_limit=RateLimit(
                rate_per_second=self.config.dns_rate,
                burst=self.config.dns_burst,
            ),
            max_concurrency=self.config.dns_max_concurrency,
        )
        # Derive the cluster base domain for the gossip endpoint — same
        # derivation path the anti-entropy worker uses. Configured
        # override wins; fall back to the on-disk manifest's signed
        # cluster_name so existing deployments pick the endpoint up
        # without a config change.
        gossip_base = (
            self.config.cluster_base_domain
            or self._derive_cluster_base_domain()
            or self._derive_cluster_base_domain_from_store()
        )
        # Parse operator_spk once so the HTTP endpoint can filter
        # unverified wires from the cluster RRset before picking the
        # highest-seq candidate. Falls back to structural-only selection
        # when not set (back-compat path; gossip is disabled in that
        # mode anyway).
        http_operator_spk: Optional[bytes] = None
        if self.config.sync_cluster_operator_spk_hex:
            try:
                raw = bytes.fromhex(self.config.sync_cluster_operator_spk_hex.strip())
                if len(raw) == 32:
                    http_operator_spk = raw
            except ValueError:
                http_operator_spk = None
        # Multi-tenant auth plumbing (M5.5). The TokenStore is created
        # lazily — only when auth_mode is explicitly "multi-tenant" OR
        # the operator set DMP_TOKEN_DB_PATH — so legacy / open-mode
        # deploys don't grow a spurious sqlite file.
        token_store = None
        if (
            self.config.auth_mode == "multi-tenant"
            or self.config.token_db_path is not None
        ):
            from dmp.server.tokens import TokenStore

            token_db = self.config.token_db_path or _default_token_db_path(
                self.config.db_path
            )
            token_store = TokenStore(token_db)

        # M5.5 phase 3: registration config read from env. Harmless to
        # instantiate in open / legacy modes — DMPHttpApi only wires
        # the plumbing when enabled + multi-tenant + a token_store
        # exists (see DMPHttpApi.start).
        from dmp.server.registration import RegistrationConfig

        registration_config = RegistrationConfig.from_env()

        # M5.8 heartbeat — opt-in discovery directory. Wired only
        # when DMP_HEARTBEAT_ENABLED=1 AND the operator has provided
        # the signing-key material + public hostname. Solo-node
        # deployments and pre-M5.8 configs see no wiring at all.
        heartbeat_bundle = _load_heartbeat_from_env(self.config.db_path)

        self.http = DMPHttpApi(
            self.store,
            host=self.config.http_host,
            port=self.config.http_port,
            bearer_token=self.config.http_token,
            max_ttl=self.config.max_ttl,
            max_value_bytes=self.config.max_value_bytes,
            max_values_per_name=self.config.max_values_per_name,
            max_concurrency=self.config.http_max_concurrency,
            rate_limit=RateLimit(
                rate_per_second=self.config.http_rate,
                burst=self.config.http_burst,
            ),
            sync_peer_token=self.config.sync_peer_token,
            cluster_base_domain=gossip_base,
            sync_cluster_operator_spk=http_operator_spk,
            auth_mode=self.config.auth_mode,
            token_store=token_store,
            registration_config=registration_config,
            heartbeat_store=heartbeat_bundle.store if heartbeat_bundle else None,
            heartbeat_submit_rate_limit=(
                heartbeat_bundle.submit_rate_limit if heartbeat_bundle else None
            ),
            heartbeat_seen_rate_limit=(
                heartbeat_bundle.seen_rate_limit if heartbeat_bundle else None
            ),
            heartbeat_self_endpoint=(
                heartbeat_bundle.self_endpoint if heartbeat_bundle else None
            ),
            heartbeat_self_spk_hex=(
                heartbeat_bundle.self_spk_hex if heartbeat_bundle else None
            ),
        )
        self.heartbeat_worker = heartbeat_bundle.worker if heartbeat_bundle else None
        self.cleanup = CleanupWorker(
            self.store.cleanup_expired,
            interval_seconds=self.config.cleanup_interval,
        )

        # Anti-entropy (M2.4). Only wire if a cluster file is reachable
        # and we have at least one peer after filtering self out. A
        # missing file is the standard "solo node" case and must not
        # prevent startup.
        self.anti_entropy = self._make_anti_entropy_worker()

        self.dns.start()
        self.http.start()
        self.cleanup.start()
        if self.heartbeat_worker is not None:
            self.heartbeat_worker.start()
        if self.anti_entropy is not None:
            self.anti_entropy.start()
        log.info(
            "DMP node up: dns=%s:%d/udp http=%s:%d db=%s peers=%d",
            self.config.dns_host,
            self.dns.port,
            self.config.http_host,
            self.http.port,
            self.config.db_path,
            len(self.anti_entropy.peers) if self.anti_entropy else 0,
        )

    def _publish_cluster_manifest_from_file(self) -> None:
        """If a signed cluster manifest is mounted at ``cluster_file``
        AND it parses as a ClusterManifest wire blob, publish it under
        ``cluster.<cluster_name>`` TXT in the local store so clients
        fanning out / union-reading against this cluster can discover
        the node list by DNS.

        Silently no-ops when:
        - no path is configured,
        - the file doesn't exist,
        - the file contains JSON (peer list) instead of a signed
          manifest wire blob (detected by prefix),
        - parsing / signature verification fails.

        Malformed content must never block startup — the manifest is
        orthogonal to everything else the node does.
        """
        path = self.config.cluster_file
        if not path or not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
        except OSError as e:
            log.warning("cluster manifest: cannot read %s: %s", path, e)
            return
        # The same path can carry either the raw wire string OR the
        # JSON envelope ``{"wire": "..."}`` used by
        # ``load_peers_from_cluster_json``. Extract the wire from both
        # shapes; genuine JSON peer-list files (no "wire" key) are
        # silently ignored here.
        from dmp.core.cluster import RECORD_PREFIX as _CLUSTER_PREFIX
        from dmp.core.cluster import ClusterManifest, cluster_rrset_name

        wire: Optional[str] = None
        if raw.startswith(_CLUSTER_PREFIX):
            wire = raw
        elif raw.startswith("{"):
            try:
                import json as _json

                doc = _json.loads(raw)
            except Exception:
                return
            candidate = doc.get("wire") if isinstance(doc, dict) else None
            if isinstance(candidate, str) and candidate.startswith(_CLUSTER_PREFIX):
                wire = candidate
        if wire is None:
            return
        # If the operator pinned an operator_spk for sync, use it for
        # verification before publishing. Otherwise publish opaquely
        # and rely on the client's own pin to reject if wrong.
        operator_spk: Optional[bytes] = None
        if self.config.sync_cluster_operator_spk_hex:
            try:
                operator_spk = bytes.fromhex(
                    self.config.sync_cluster_operator_spk_hex.strip()
                )
                if len(operator_spk) != 32:
                    operator_spk = None
            except ValueError:
                operator_spk = None
        manifest = None
        if operator_spk is not None:
            manifest = ClusterManifest.parse_and_verify(wire, operator_spk)
            if manifest is None:
                log.warning(
                    "cluster manifest at %s does not verify under the "
                    "configured DMP_SYNC_OPERATOR_SPK; not publishing",
                    path,
                )
                return
        else:
            # Best-effort parse without signature verification just so
            # we can derive the cluster_name for the TXT owner AND the
            # exp for a sensible TTL.
            try:
                import base64
                import struct

                blob = base64.b64decode(wire[len(_CLUSTER_PREFIX) :], validate=True)
                body = blob[:-64]
                # Magic(7) + seq(8) + exp(8) + operator_spk(32) + name_len(1)
                manifest_exp = int.from_bytes(body[15:23], "big")
                name_len = body[55]
                cluster_name = body[56 : 56 + name_len].decode("utf-8").rstrip(".")
            except Exception as e:
                log.warning("cluster manifest at %s malformed: %s", path, e)
                return

            class _Bag:
                pass

            manifest = _Bag()
            manifest.cluster_name = cluster_name
            manifest.exp = manifest_exp

        rrset = cluster_rrset_name(manifest.cluster_name)
        # TTL tracks the manifest's own signed expiry, NOT max_ttl. The
        # generic max_ttl cap exists to bound untrusted publishes via
        # the public HTTP API; the cluster manifest is operator-signed
        # and parse_and_verify already rejects past-exp records, so
        # clamping here just reintroduces early expiry — a manifest
        # valid for multiple days would still vanish from the local
        # store after max_ttl (default 86400s), breaking
        # /v1/sync/cluster-manifest for late-joining peers. Trust the
        # signed exp.
        import time as _time

        now = int(_time.time())
        ttl = max(1, int(manifest.exp) - now)
        assert self.store is not None
        if self.store.publish_txt_record(rrset, wire, ttl=ttl):
            log.info(
                "cluster manifest published: %s -> %s (%d bytes)",
                rrset,
                path,
                len(wire.encode("utf-8")),
            )

    def _make_anti_entropy_worker(self) -> Optional[AntiEntropyWorker]:
        # Two peer-discovery modes, checked in order:
        #
        # 1. ``sync_peers`` (DMP_SYNC_PEERS) — direct URL list. Preferred
        #    for docker-compose deployments where every node already
        #    knows the others by container DNS name. No signed manifest
        #    needed for peer discovery; the operator's env file IS the
        #    source of truth for who is in the cluster.
        # 2. ``cluster_file`` (DMP_CLUSTER_FILE / DMP_CLUSTER_MANIFEST_PATH)
        #    — signed cluster manifest on disk. Used when the operator
        #    already keeps their manifest under config management.
        #
        # If neither produces peers, the worker is skipped (solo node).
        peer_source: str
        if self.config.sync_peers:
            peers = _peers_from_url_list(
                self.config.sync_peers,
                self_node_id=self.config.node_id,
                self_http_endpoint=self.config.sync_self_endpoint,
            )
            peer_source = f"DMP_SYNC_PEERS ({len(self.config.sync_peers)} urls)"
        else:
            path = self.config.cluster_file
            if not path or not os.path.isfile(path):
                return None
            peers = load_peers_from_cluster_json(
                path,
                self_node_id=self.config.node_id,
                self_http_endpoint=self.config.sync_self_endpoint,
            )
            peer_source = path
        if not peers:
            return None
        if not self.config.sync_peer_token:
            # A token is required for the sync endpoints to return
            # anything; without one every outbound sync would bounce 403.
            # Log loudly so the operator notices the misconfig.
            log.warning(
                "anti-entropy: %d peer(s) from %s but no sync_peer_token "
                "configured; worker not started",
                len(peers),
                peer_source,
            )
            return None
        operator_spk = None
        if self.config.sync_cluster_operator_spk_hex:
            try:
                operator_spk = bytes.fromhex(
                    self.config.sync_cluster_operator_spk_hex.strip()
                )
                if len(operator_spk) != 32:
                    raise ValueError("operator_spk must be 32 bytes")
            except ValueError as e:
                log.warning("anti-entropy: invalid operator_spk hex: %s", e)
                operator_spk = None

        # M3.3 gossip anchors. The worker needs both (operator_spk,
        # base_domain) to install a gossiped manifest; without base_domain
        # we can still derive it from the on-disk manifest.
        base_domain = self.config.cluster_base_domain
        if operator_spk is not None and not base_domain:
            # Three-tier derivation: env var → on-disk cluster file →
            # previously-gossiped manifest in the local sqlite store.
            # The last tier is the restart-recovery path for gossip-only
            # nodes (DMP_SYNC_PEERS + DMP_SYNC_OPERATOR_SPK, no file,
            # no env). Without it, a node that learned the cluster via
            # gossip would come back from restart with gossip disabled
            # even though a valid manifest was already persisted.
            base_domain = (
                self._derive_cluster_base_domain()
                or self._derive_cluster_base_domain_from_store()
            )

        # Operator wiring check: if DMP_SYNC_PEERS was used (so there's
        # no signed manifest on disk to derive trust from) AND the
        # operator didn't pin a signing key, manifest gossip is off. Log
        # a warning so the operator notices they're missing the M3.3
        # benefit — anti-entropy data sync still works.
        if self.config.sync_peers and operator_spk is None:
            log.warning(
                "anti-entropy: DMP_SYNC_PEERS set but DMP_SYNC_OPERATOR_SPK "
                "is not; manifest gossip is DISABLED. Operators must "
                "continue to push new cluster manifests to each node "
                "by hand. Pin an operator public key to enable gossip."
            )
        elif operator_spk is not None and not base_domain:
            log.warning(
                "anti-entropy: DMP_SYNC_OPERATOR_SPK set but no cluster "
                "base domain could be determined (set DMP_CLUSTER_BASE_DOMAIN "
                "or mount a cluster manifest file); manifest gossip is "
                "DISABLED."
            )

        return AntiEntropyWorker(
            store=self.store,
            peers=peers,
            sync_token=self.config.sync_peer_token,
            interval_seconds=self.config.sync_interval,
            cluster_operator_spk=operator_spk,
            base_domain=base_domain,
            self_node_id=self.config.node_id,
            self_http_endpoint=self.config.sync_self_endpoint,
        )

    def _derive_cluster_base_domain_from_store(self) -> Optional[str]:
        """Recover ``cluster_base_domain`` from a previously-gossiped
        manifest persisted in the local sqlite store.

        A gossip-only node (bootstrapped via ``DMP_SYNC_PEERS`` +
        ``DMP_SYNC_OPERATOR_SPK``, no cluster_file, no
        ``DMP_CLUSTER_BASE_DOMAIN``) used to come back from a restart
        with manifest gossip DISABLED: neither env nor file provided a
        base_domain, so ``_make_anti_entropy_worker`` couldn't wire the
        gossip path even though a valid manifest was already sitting in
        the local store. This method scans the store for any
        ``cluster.*`` TXT value that verifies under the pinned
        operator_spk and returns the cluster_name from the highest-seq
        match.

        Requires ``DMP_SYNC_OPERATOR_SPK`` to be set — without a trust
        anchor we won't pull a base_domain out of unverified store
        contents.
        """
        if not self.config.sync_cluster_operator_spk_hex:
            return None
        try:
            operator_spk = bytes.fromhex(
                self.config.sync_cluster_operator_spk_hex.strip()
            )
            if len(operator_spk) != 32:
                return None
        except ValueError:
            return None
        if self.store is None or not hasattr(self.store, "list_names"):
            return None
        try:
            names = self.store.list_names()
        except Exception:
            return None
        from dmp.core.cluster import ClusterManifest

        # A valid manifest for cluster X lives at ``cluster.X`` and
        # embeds ``cluster_name=X``. Use that alignment to filter: a
        # manifest whose embedded cluster_name doesn't match the owner
        # it was stored under isn't a candidate (defense against stray
        # publishes). Then if MORE THAN ONE distinct aligned cluster is
        # present and signed by the same key (e.g. operator reuses the
        # key across dev/prod environments), recovery is fundamentally
        # ambiguous — we'd have no principled way to pick one over the
        # other, so refuse and require the operator to disambiguate
        # via DMP_CLUSTER_BASE_DOMAIN.
        aligned_by_cluster: Dict[str, int] = {}  # cluster_name -> highest seq
        for name in names:
            if not name.startswith("cluster."):
                continue
            owner_cluster = name[len("cluster.") :]  # the X in cluster.X
            try:
                values = self.store.query_txt_record(name)
            except Exception:
                continue
            for wire in values or []:
                if not isinstance(wire, str):
                    continue
                m = ClusterManifest.parse_and_verify(
                    wire,
                    operator_spk,
                    expected_cluster_name=owner_cluster,
                )
                if m is None:
                    continue
                prior = aligned_by_cluster.get(m.cluster_name, -1)
                if m.seq > prior:
                    aligned_by_cluster[m.cluster_name] = m.seq
        if len(aligned_by_cluster) == 0:
            return None
        if len(aligned_by_cluster) > 1:
            log.warning(
                "anti-entropy: local store carries verified manifests for "
                "%d distinct clusters (%s); cannot auto-recover "
                "cluster_base_domain. Set DMP_CLUSTER_BASE_DOMAIN "
                "explicitly.",
                len(aligned_by_cluster),
                ", ".join(sorted(aligned_by_cluster.keys())),
            )
            return None
        return next(iter(aligned_by_cluster.keys()))

    def _derive_cluster_base_domain(self) -> Optional[str]:
        """Extract ``cluster_name`` from the on-disk cluster file when
        ``DMP_CLUSTER_BASE_DOMAIN`` is unset.

        Security: when ``DMP_SYNC_OPERATOR_SPK`` is pinned, the file's
        wire must VERIFY under that key before we trust its
        cluster_name. Without this check, a stale or wrong-zone
        cluster_file on disk could set ``expected_cluster_name`` for
        the gossip layer — the node would then accept gossiped
        manifests for the wrong cluster name, even though
        ``_publish_cluster_manifest_from_file`` already refused to
        publish that same file.

        Falls back to structural parse only when no operator_spk is
        configured (gossip is disabled in that mode anyway, so the
        base_domain is informational).

        Returns None on missing file, malformed content, or signature
        rejection — gossip then stays off.
        """
        path = self.config.cluster_file
        if not path or not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw = fh.read().strip()
        except OSError:
            return None
        from dmp.core.cluster import ClusterManifest
        from dmp.core.cluster import RECORD_PREFIX as _CLUSTER_PREFIX

        # cluster_file has two supported shapes:
        #   1) the raw wire string ``v=dmp1;t=cluster;<base64>``
        #   2) a JSON envelope ``{"wire": "v=dmp1;t=cluster;..."}`` —
        #      this is the shape load_peers_from_cluster_json already
        #      accepts for peer discovery. Without this branch, nodes
        #      using the JSON form silently fall through to "no gossip"
        #      because the raw-wire prefix check fails.
        wire: str
        if raw.startswith(_CLUSTER_PREFIX):
            wire = raw
        elif raw.startswith("{"):
            try:
                import json as _json

                doc = _json.loads(raw)
            except Exception:
                return None
            candidate = doc.get("wire") if isinstance(doc, dict) else None
            if not isinstance(candidate, str) or not candidate.startswith(
                _CLUSTER_PREFIX
            ):
                return None
            wire = candidate
        else:
            return None

        # If the operator key is pinned, require the file to verify
        # under it before we trust the embedded cluster_name. This
        # prevents a stale / wrong-zone cluster_file from steering the
        # gossip layer into the wrong cluster.
        if self.config.sync_cluster_operator_spk_hex:
            try:
                operator_spk = bytes.fromhex(
                    self.config.sync_cluster_operator_spk_hex.strip()
                )
            except ValueError:
                return None
            if len(operator_spk) != 32:
                return None
            parsed = ClusterManifest.parse_and_verify(wire, operator_spk)
            if parsed is None:
                log.warning(
                    "anti-entropy: cluster_file %s does not verify under "
                    "DMP_SYNC_OPERATOR_SPK; refusing to derive base_domain "
                    "from it. Set DMP_CLUSTER_BASE_DOMAIN explicitly or "
                    "replace the file.",
                    path,
                )
                return None
            return parsed.cluster_name

        try:
            import base64 as _b64

            blob = _b64.b64decode(wire[len(_CLUSTER_PREFIX) :], validate=True)
        except Exception:
            return None
        if len(blob) < 56 + 64:
            return None
        body = blob[:-64]
        try:
            name_len = body[55]
            return body[56 : 56 + name_len].decode("utf-8").rstrip(".")
        except Exception:
            return None

    def stop(self) -> None:
        log.info("DMP node shutting down")
        # Stop the sync worker before the HTTP server goes: in-flight sync
        # POSTs against a dying peer are harmless (they just fail the tick),
        # but we want clean teardown ordering for tests and logs.
        if self.anti_entropy:
            self.anti_entropy.stop()
        if self.cleanup:
            self.cleanup.stop()
        if self.http:
            self.http.stop()
        if self.dns:
            self.dns.stop()
        if self.store:
            self.store.close()
        self._stopped.set()

    def wait(self) -> None:
        """Block until stop() is called or a signal arrives."""
        self._install_signal_handlers()
        try:
            self._stopped.wait()
        except KeyboardInterrupt:
            self.stop()

    def _ensure_db_parent_exists(self) -> None:
        parent = os.path.dirname(self.config.db_path) or "."
        os.makedirs(parent, exist_ok=True)

    def _install_signal_handlers(self) -> None:
        def _handle(signum, frame):
            log.info("received signal %s", signum)
            self.stop()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handle)
            except ValueError:
                # Not in main thread — skip.
                pass


def main() -> None:
    node = DMPNode.from_env()
    node.start()
    node.wait()


if __name__ == "__main__":
    main()
