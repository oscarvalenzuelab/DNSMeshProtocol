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

    DMP_CLUSTER_FILE       on-disk cluster.json (peer list)  default: /var/lib/dmp/cluster.json
    DMP_NODE_ID            this node's id in the cluster     default: none (skip self-filter)
    DMP_SYNC_PEER_TOKEN    shared token for /v1/sync/*       default: none (endpoints 403)
    DMP_SYNC_INTERVAL      seconds between sync ticks        default: 10
    DMP_SYNC_OPERATOR_SPK  hex ed25519 operator pubkey for
                           cluster-record re-verify         default: none

Port 53 is privileged on Linux. In a container, publish with
`-p 53:5353/udp` or run with CAP_NET_BIND_SERVICE.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
from dataclasses import dataclass
from typing import Optional

from dmp.server.anti_entropy import AntiEntropyWorker, load_peers_from_cluster_json
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
    http_token: Optional[str] = None
    # Bursts are sized for legitimate bulk publishes: a fresh
    # `dmp identity refresh-prekeys --count 50` + a manifest and half a
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

    @classmethod
    def from_env(cls) -> "DMPNodeConfig":
        return cls(
            db_path=os.environ.get("DMP_DB_PATH", cls.db_path),
            dns_host=os.environ.get("DMP_DNS_HOST", cls.dns_host),
            dns_port=int(os.environ.get("DMP_DNS_PORT", cls.dns_port)),
            dns_ttl=int(os.environ.get("DMP_DNS_TTL", cls.dns_ttl)),
            dns_rate=float(os.environ.get("DMP_DNS_RATE", cls.dns_rate)),
            dns_burst=float(os.environ.get("DMP_DNS_BURST", cls.dns_burst)),
            http_host=os.environ.get("DMP_HTTP_HOST", cls.http_host),
            http_port=int(os.environ.get("DMP_HTTP_PORT", cls.http_port)),
            http_token=os.environ.get("DMP_HTTP_TOKEN") or None,
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
            cluster_file=os.environ.get("DMP_CLUSTER_FILE", cls.cluster_file),
            node_id=os.environ.get("DMP_NODE_ID") or None,
            sync_peer_token=os.environ.get("DMP_SYNC_PEER_TOKEN") or None,
            sync_interval=float(
                os.environ.get("DMP_SYNC_INTERVAL", cls.sync_interval)
            ),
            sync_cluster_operator_spk_hex=(
                os.environ.get("DMP_SYNC_OPERATOR_SPK") or None
            ),
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
        )
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

    def _make_anti_entropy_worker(self) -> Optional[AntiEntropyWorker]:
        path = self.config.cluster_file
        if not path or not os.path.isfile(path):
            return None
        peers = load_peers_from_cluster_json(path, self_node_id=self.config.node_id)
        if not peers:
            return None
        if not self.config.sync_peer_token:
            # A token is required for the sync endpoints to return
            # anything; without one every outbound sync would bounce 403.
            # Log loudly so the operator notices the misconfig.
            log.warning(
                "anti-entropy: %d peer(s) in %s but no sync_peer_token "
                "configured — worker not started",
                len(peers),
                path,
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
        return AntiEntropyWorker(
            store=self.store,
            peers=peers,
            sync_token=self.config.sync_peer_token,
            interval_seconds=self.config.sync_interval,
            cluster_operator_spk=operator_spk,
        )

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
