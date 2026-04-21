"""Anti-entropy sync worker for DMP nodes.

Today a cluster is kept consistent purely by client-side fan-out: every
publish goes to every node. If a node was offline when a publish happened
it never learns about the record. M2.4 closes that gap with a pull-based
background sync that each node runs against its peers.

Design (see M2.4 task for the full rationale):

1.  Peer list comes from on-disk ``cluster.json`` — the operator's signed
    manifest, same shape clients pin. We only read the HTTP endpoints.
2.  Each tick picks one peer round-robin, calls ``/v1/sync/digest?since=
    <watermark>`` to fetch ``(name, hash, ts)`` tuples, diffs against the
    local store, and calls ``/v1/sync/pull`` to retrieve the missing
    values.
3.  Every pulled value is **re-validated** before we write it. Peers are
    untrusted; a liar who returns a forged slot manifest must not be
    able to poison the local store.
4.  The watermark is per-peer and lives in memory for the process
    lifetime. A restart of this node re-syncs from ts=0, which is cheap
    (only hashes are exchanged during digest; pull only fetches the
    strictly-missing delta).

The worker is a daemon thread so a dying main process doesn't keep it
alive, and ``stop()`` signals shutdown cleanly through an Event.

Security invariants:

- Returned records MUST match the names the worker requested. A peer
  cannot smuggle extra records into the pull response.
- Signature-bearing record types (manifest, identity) re-verify against
  their embedded signing key before hitting the store. Cluster
  manifests re-verify against the node's configured operator_spk when
  one is set; otherwise they go through a structural parse that rejects
  bad magic / base64 / trailing bytes but cannot catch a
  different-but-still-validly-signed manifest. The operator SHOULD
  configure ``sync_cluster_operator_spk`` if it cares about that axis.
- Prekey and bootstrap records are signed by keys the node generally
  doesn't have pinned, so we accept them after a structural parse; the
  client-side lookup still re-verifies against the identity / bootstrap
  signer key it pins independently.
- Chunk records (``v=dmp1;t=chunk;d=...``) are not signed on their own;
  they are bound by the signed slot manifest that references them.
  Verification there is the client's job; the node just hosts the blob.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union
from urllib import error as urlerror
from urllib import request as urlrequest

from dmp.core.bootstrap import RECORD_PREFIX as _BOOTSTRAP_PREFIX
from dmp.core.cluster import ClusterManifest
from dmp.core.cluster import RECORD_PREFIX as _CLUSTER_PREFIX
from dmp.core.identity import IdentityRecord
from dmp.core.identity import RECORD_PREFIX as _IDENTITY_PREFIX
from dmp.core.manifest import RECORD_PREFIX as _MANIFEST_PREFIX
from dmp.core.manifest import SlotManifest
from dmp.core.prekeys import RECORD_PREFIX as _PREKEY_PREFIX

log = logging.getLogger(__name__)

# Transport limits exposed as module constants so tests can poke them.
DEFAULT_HTTP_TIMEOUT = 5.0
DIGEST_DEFAULT_LIMIT = 1000
DIGEST_MAX_LIMIT = 10_000
PULL_MAX_NAMES = 256

# TTL-refresh diff slop. Two nodes in sync will have `ttl_remaining` that
# differs by at most one RTT + clock skew; use a few seconds of slop so
# every digest tick doesn't flag every row as "TTL drifted". A real
# refresh (caller re-publishes with a fresh TTL) produces deltas >> this.
_TTL_REFRESH_SLOP_SECONDS = 5

# A well-formed chunk record prefix (the only type without a d= suffix and
# not in the signed-type list).
_CHUNK_PREFIX = "v=dmp1;t=chunk;d="

# Watermark type alias. The compound (stored_ts_ms, name, value_hash) form
# replaces the plain int cursor from the original M2.4 code; the value_hash
# tiebreaker was added in followup-2 so > ``pull_batch_limit`` values at the
# same (ts, name) — a multi-value RRset burst — paginate correctly.
Cursor = Tuple[int, str, str]

# Digest-entry validation: peers are untrusted, so we harden every field
# before it's allowed to influence the local watermark. The DNS-label
# regex rejects anything that couldn't plausibly be a record name; the
# 60-second future-skew window absorbs honest clock drift while capping a
# malicious peer's ability to poke the watermark out past our real data.
_VALID_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,253}$")
_VALID_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_TTL = 2**31
_CLOCK_SKEW_MS = 60_000


def _valid_digest_entry(entry: Any) -> bool:
    """True if ``entry`` is a structurally-sound digest record.

    Only entries that pass this check are allowed to advance our
    per-peer watermark. A buggy or malicious peer that stuffs
    ``{"ts": 9999999999999, "name": "bogus", "hash": "not-sha256"}``
    into their digest response cannot poke the local watermark out past
    the real data — if they could, legitimate updates with lower ts
    would be invisible to every subsequent digest call (their stored_ts
    lives below the poisoned cutoff).

    Checks (all required):

    - ``name`` is a string, <= 253 bytes, matches ``_VALID_NAME_RE``.
    - ``hash`` is a 64-char lowercase hex string (sha256 hex digest).
    - ``ts`` is an int in [0, now_ms + 60s]. Future timestamps beyond the
      skew window are treated as forged; absent ts is treated as 0.
    - ``ttl`` is an int in [0, 2**31].
    """
    if not isinstance(entry, dict):
        return False
    name = entry.get("name")
    if not isinstance(name, str):
        return False
    if len(name.encode("utf-8")) > 253:
        return False
    if not _VALID_NAME_RE.match(name):
        return False
    h = entry.get("hash")
    if not isinstance(h, str) or not _VALID_HASH_RE.match(h):
        return False
    ts = entry.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool):
        return False
    now_ms = int(time.time() * 1000)
    if ts < 0 or ts > now_ms + _CLOCK_SKEW_MS:
        return False
    ttl = entry.get("ttl")
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        return False
    if ttl < 0 or ttl > _MAX_TTL:
        return False
    return True


def _parse_next_cursor(raw: Any) -> Optional[Cursor]:
    """Parse a peer-supplied ``next_cursor`` into ``(ts, name, value_hash)``.

    Accepts either the followup-2 ``"<ts>:<name>:<value_hash>"`` wire
    form or the legacy followup-1 ``"<ts>:<name>"`` form (the latter is
    promoted to ``(ts, name, "")``). Returns ``None`` if the peer
    returned something unparseable — we just fall back to advancing the
    watermark from the validated entries.

    We split on the first two ``:``s (``maxsplit=2``) so a malformed
    suffix cannot silently corrupt the ts half; any further ``:`` ends
    up inside the value_hash check, which rejects non-hex content.
    """
    if not isinstance(raw, str):
        return None
    parts = raw.split(":", 2)
    if len(parts) == 2:
        ts_str, name = parts
        value_hash = ""
    elif len(parts) == 3:
        ts_str, name, value_hash = parts
    else:
        return None
    try:
        ts = int(ts_str)
    except (ValueError, TypeError):
        return None
    if ts < 0:
        return None
    now_ms = int(time.time() * 1000)
    if ts > now_ms + _CLOCK_SKEW_MS:
        return None
    if len(name) > 253:
        return None
    # value_hash must be empty or a 64-char lowercase hex digest.
    if value_hash and not _VALID_HASH_RE.match(value_hash):
        return None
    return (ts, name, value_hash)


def _cursor_ge(a: Cursor, b: Cursor) -> bool:
    """True iff cursor ``a`` is >= cursor ``b`` in
    (ts, name, value_hash) order."""
    return tuple(a) >= tuple(b)


def _cursor_gt(a: Cursor, b: Cursor) -> bool:
    """True iff cursor ``a`` is strictly greater than cursor ``b``."""
    return tuple(a) > tuple(b)


@dataclass
class SyncPeer:
    """One peer in the sync loop."""

    node_id: str
    http_endpoint: str  # e.g. "https://node2.example.com:8053"


def load_peers_from_cluster_json(
    path: str,
    *,
    self_node_id: Optional[str] = None,
) -> List[SyncPeer]:
    """Parse an on-disk cluster.json into a SyncPeer list.

    The file is expected to contain the signed wire record as a raw string,
    or a JSON object with ``{"wire": "<record>"}`` / a pre-parsed
    ``{"nodes": [...]}`` shape. We accept all three so operators who keep
    their manifest in different forms aren't forced to convert.

    Returns an empty list (with a warning) if the file is missing or
    malformed — a node without peers is still a valid node; it just has
    nothing to sync with.

    `self_node_id` filters the node's own entry out of the peer set so a
    node doesn't try to sync with itself.
    """
    try:
        with open(path, "r") as f:
            text = f.read()
    except (FileNotFoundError, PermissionError, OSError) as e:
        log.warning("anti-entropy: cluster file %s unreadable: %s", path, e)
        return []

    text = text.strip()
    if not text:
        return []

    # Try wire-record-in-a-string first.
    if text.startswith(_CLUSTER_PREFIX):
        return _peers_from_wire(text, self_node_id)

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        log.warning("anti-entropy: cluster file %s is not JSON: %s", path, e)
        return []

    if isinstance(parsed, dict) and isinstance(parsed.get("wire"), str):
        return _peers_from_wire(parsed["wire"], self_node_id)

    if isinstance(parsed, dict) and isinstance(parsed.get("nodes"), list):
        peers: List[SyncPeer] = []
        for entry in parsed["nodes"]:
            if not isinstance(entry, dict):
                continue
            nid = entry.get("node_id")
            http = entry.get("http_endpoint")
            if not isinstance(nid, str) or not isinstance(http, str):
                continue
            if self_node_id and nid == self_node_id:
                continue
            peers.append(SyncPeer(node_id=nid, http_endpoint=http))
        return peers

    log.warning("anti-entropy: cluster file %s has no recognizable shape", path)
    return []


def _peers_from_wire(wire: str, self_node_id: Optional[str]) -> List[SyncPeer]:
    """Parse a raw wire cluster manifest into peers (no signature check).

    We do NOT verify the cluster signature here — the operator deploying
    this file *is* the trust anchor for peer discovery; they placed the
    file on disk. All we need is the structural parse to pull out
    node_id/http_endpoint. Signature verification happens client-side
    when clients resolve the cluster record via DNS.
    """
    # Lazy: reuse the binary body parser. We just strip the prefix + b64,
    # drop the trailing 64-byte sig, and hand off to from_body_bytes.
    try:
        blob = base64.b64decode(wire[len(_CLUSTER_PREFIX) :], validate=True)
    except Exception as e:
        log.warning("anti-entropy: cluster wire base64 invalid: %s", e)
        return []
    if len(blob) < 64 + 7:
        return []
    body = blob[:-64]
    try:
        manifest = ClusterManifest.from_body_bytes(body)
    except ValueError as e:
        log.warning("anti-entropy: cluster manifest body malformed: %s", e)
        return []
    peers: List[SyncPeer] = []
    for node in manifest.nodes:
        if self_node_id and node.node_id == self_node_id:
            continue
        peers.append(SyncPeer(node_id=node.node_id, http_endpoint=node.http_endpoint))
    return peers


def _classify_record(value: str) -> str:
    """Return a short tag for the record type: manifest/identity/prekey/
    cluster/bootstrap/chunk/unknown. Used only for logging + dispatch."""
    if value.startswith(_MANIFEST_PREFIX):
        return "manifest"
    if value.startswith(_IDENTITY_PREFIX):
        return "identity"
    if value.startswith(_PREKEY_PREFIX):
        return "prekey"
    if value.startswith(_CLUSTER_PREFIX):
        return "cluster"
    if value.startswith(_BOOTSTRAP_PREFIX):
        return "bootstrap"
    if value.startswith(_CHUNK_PREFIX):
        return "chunk"
    return "unknown"


def _structural_parse_signed(value: str, prefix: str) -> bool:
    """Confirm a ``<prefix>;d=<b64>`` or ``<prefix><b64>`` record is at least
    base64-decodable and carries a signature-sized tail.

    For record types where the node has no way to know the correct
    signer key (prekey, bootstrap), we can't do a trust-real verify —
    but we can still reject obvious garbage. The client that reads this
    record later will do its own real verification against the key it
    pins.
    """
    payload = value[len(prefix) :]
    try:
        blob = base64.b64decode(payload, validate=True)
    except Exception:
        return False
    # 64-byte sig + at least 1 byte of body.
    return len(blob) >= 65


def verify_record(
    value: str,
    *,
    cluster_operator_spk: Optional[bytes] = None,
) -> bool:
    """Re-verify a record as if it had been published to us directly.

    Returns True if the record is safe to write to the local store,
    False otherwise. The anti-entropy worker is the only caller; the
    public publish path goes through HTTP and does its own validation.

    Records with self-identifying signers (manifest, identity) undergo
    full signature verification. Cluster manifests verify against
    ``cluster_operator_spk`` if the node has one pinned; otherwise a
    structural parse is used. Prekey / bootstrap records don't expose
    the signer key at this layer; we use a structural parse and the
    *client* reading the record later will re-verify with the real key.
    Chunks and unknown blobs are accepted as opaque (the signed manifest
    that references a chunk is the thing that binds it).
    """
    if not isinstance(value, str) or not value:
        return False
    kind = _classify_record(value)
    if kind == "manifest":
        return SlotManifest.parse_and_verify(value) is not None
    if kind == "identity":
        return IdentityRecord.parse_and_verify(value) is not None
    if kind == "cluster":
        if cluster_operator_spk is not None:
            return (
                ClusterManifest.parse_and_verify(value, cluster_operator_spk)
                is not None
            )
        return _structural_parse_signed(value, _CLUSTER_PREFIX)
    if kind == "prekey":
        return _structural_parse_signed(value, _PREKEY_PREFIX)
    if kind == "bootstrap":
        return _structural_parse_signed(value, _BOOTSTRAP_PREFIX)
    # chunks and unknown — accept. Chunks are bound by their manifest;
    # unknown types are future-proofing.
    return True


# Transport — isolated behind a small callable so tests can inject a fake
# without stubbing the entire urllib module. A real caller hits HTTP.

HttpGet = Callable[[str, Optional[str], float], Tuple[int, bytes]]
HttpPost = Callable[[str, Optional[str], bytes, float], Tuple[int, bytes]]


def _default_http_get(
    url: str, token: Optional[str], timeout: float
) -> Tuple[int, bytes]:
    req = urlrequest.Request(url, method="GET")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return (resp.status, resp.read())
    except urlerror.HTTPError as e:
        # HTTPError IS a response; read the body so tests can inspect error JSON.
        try:
            body = e.read() or b""
        except Exception:
            body = b""
        return (e.code, body)
    except (urlerror.URLError, TimeoutError) as e:
        log.debug("anti-entropy: GET %s failed: %s", url, e)
        return (0, b"")


def _default_http_post(
    url: str, token: Optional[str], body: bytes, timeout: float
) -> Tuple[int, bytes]:
    req = urlrequest.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return (resp.status, resp.read())
    except urlerror.HTTPError as e:
        try:
            err_body = e.read() or b""
        except Exception:
            err_body = b""
        return (e.code, err_body)
    except (urlerror.URLError, TimeoutError) as e:
        log.debug("anti-entropy: POST %s failed: %s", url, e)
        return (0, b"")


@dataclass
class SyncStats:
    ticks: int = 0
    digests_fetched: int = 0
    records_pulled: int = 0
    records_written: int = 0
    records_rejected: int = 0
    errors: int = 0


class AntiEntropyWorker:
    """Background pull-based anti-entropy against a peer set.

    Usage::

        worker = AntiEntropyWorker(
            store=node.store,
            peers=[SyncPeer("n2", "http://host:8053")],
            sync_token="shared-operator-token",
            interval_seconds=5.0,
        )
        worker.start()
        ...
        worker.stop()
    """

    def __init__(
        self,
        *,
        store,
        peers: Iterable[SyncPeer],
        sync_token: Optional[str] = None,
        interval_seconds: float = 10.0,
        digest_batch_limit: int = DIGEST_DEFAULT_LIMIT,
        pull_batch_limit: int = PULL_MAX_NAMES,
        http_timeout: float = DEFAULT_HTTP_TIMEOUT,
        cluster_operator_spk: Optional[bytes] = None,
        base_domain: Optional[str] = None,
        self_node_id: Optional[str] = None,
        self_http_endpoint: Optional[str] = None,
        http_get: Optional[HttpGet] = None,
        http_post: Optional[HttpPost] = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._store = store
        # ``base_domain`` is the cluster_name this node expects gossiped
        # manifests to bind to. When both ``cluster_operator_spk`` and
        # ``base_domain`` are set, each tick also fetches
        # /v1/sync/cluster-manifest from the peer and installs any
        # higher-seq verifying manifest locally. Without both, manifest
        # gossip is disabled — trust-on-first-use for a new operator key
        # would be a tooth in the chain of trust.
        self._base_domain = base_domain
        self._self_node_id = self_node_id
        self._self_http_endpoint = (
            self_http_endpoint.rstrip("/") if self_http_endpoint else None
        )
        self._peers: List[SyncPeer] = self._filter_self(list(peers))
        self._token = sync_token
        self._interval = float(interval_seconds)
        self._digest_limit = max(1, min(int(digest_batch_limit), DIGEST_MAX_LIMIT))
        self._pull_limit = max(1, min(int(pull_batch_limit), PULL_MAX_NAMES))
        self._timeout = float(http_timeout)
        self._cluster_operator_spk = (
            bytes(cluster_operator_spk) if cluster_operator_spk else None
        )
        self._http_get = http_get or _default_http_get
        self._http_post = http_post or _default_http_post

        # Compound (ts_ms, name, value_hash) watermark per peer. The
        # name + value_hash halves break same-millisecond / same-name
        # pagination ties that plain ts would drop (a multi-value RRset
        # at one ts would lose values to the tie-break). Initial value
        # (0, "", "") means "pull from the beginning."
        self._watermarks: Dict[str, Cursor] = {
            p.node_id: (0, "", "") for p in self._peers
        }
        self._rr_index: int = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.stats = SyncStats()
        # Gossip bookkeeping. ``_installed_seq`` tracks the highest seq
        # of any cluster manifest this worker has installed locally so
        # we reject downgrades without re-reading the store on every
        # tick. A fresh worker starts at -1 so seq=0 manifests can be
        # installed on first tick (seq fits in uint64, but -1 is still a
        # safe strict-less sentinel against any real seq).
        self._installed_seq: int = -1

    # ---- self-exclusion ----------------------------------------------------

    def _filter_self(self, peers: List[SyncPeer]) -> List[SyncPeer]:
        """Drop any peer entry that matches this node's identity.

        Matches on ``self_node_id`` OR ``self_http_endpoint`` (normalized
        by stripping trailing slashes), whichever is provided. This is
        the non-negotiable "never sync with yourself" guard: a node
        gossiping with itself is an infinite loop on first tick,
        because /v1/sync/cluster-manifest would return the very
        manifest we just installed, making the worker retry forever.
        """
        out: List[SyncPeer] = []
        for p in peers:
            if self._self_node_id and p.node_id == self._self_node_id:
                continue
            if self._self_http_endpoint:
                if p.http_endpoint.rstrip("/") == self._self_http_endpoint:
                    continue
            out.append(p)
        return out

    # ---- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        if not self._peers:
            log.info("anti-entropy: no peers configured, worker stays idle")
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="dmp-anti-entropy", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=timeout)
        self._thread = None

    # ---- main loop ---------------------------------------------------------

    def _run(self) -> None:
        # First tick after `interval` seconds; this matches CleanupWorker's
        # behavior and keeps startup cheap. An operator wanting an immediate
        # sync should call `tick_once()` before `start()`.
        while not self._stop.wait(self._interval):
            try:
                self.tick_once()
            except Exception:
                log.exception("anti-entropy: tick raised — continuing")
                self.stats.errors += 1

    def tick_once(self) -> None:
        """Run one sync cycle against one peer. Public for tests.

        The tick does two things per peer:

        1. Digest/pull for data records (the existing M2.4 flow).
        2. If manifest gossip is enabled (both ``cluster_operator_spk``
           and ``base_domain`` were supplied), fetch
           ``/v1/sync/cluster-manifest`` from the peer and install any
           higher-seq verifying manifest — swapping the live peer set
           to match.
        """
        with self._lock:
            self.stats.ticks += 1
            if not self._peers:
                return
            peer = self._peers[self._rr_index % len(self._peers)]
            self._rr_index = (self._rr_index + 1) % len(self._peers)
        self._sync_with_peer(peer)
        if self._gossip_enabled():
            try:
                self._try_gossip_manifest_from(peer)
            except Exception:
                # Gossip must never take down the data-sync tick. A
                # gossip failure is a missed rollout, not a security
                # problem: the pinned operator_spk remains unchanged,
                # so a malformed response cannot install anything.
                log.exception(
                    "anti-entropy: gossip from %s raised — continuing", peer.node_id
                )
                self.stats.errors += 1

    # ---- gossip ------------------------------------------------------------

    def _gossip_enabled(self) -> bool:
        """True when both the operator_spk anchor AND a target
        base_domain are configured. Without either, we don't know what
        to verify against or which cluster_name to bind the incoming
        manifest to — gossip stays off rather than falling back to
        trust-on-first-use."""
        return self._cluster_operator_spk is not None and bool(self._base_domain)

    def _try_gossip_manifest_from(self, peer: SyncPeer) -> None:
        """Fetch peer's /v1/sync/cluster-manifest; install if verifying
        AND seq > current. Never downgrades, never installs across a
        different operator key, never installs across a different
        cluster_name.

        Failure modes (all log-and-skip):
        - peer returns non-200 / 204 / unparseable JSON
        - wire missing or not a string
        - ``parse_and_verify`` returns None (bad sig, wrong operator,
          expired, wrong cluster_name)
        - seq <= currently installed (no-op)
        """
        assert self._base_domain is not None  # _gossip_enabled()
        assert self._cluster_operator_spk is not None  # _gossip_enabled()

        url = f"{peer.http_endpoint.rstrip('/')}/v1/sync/cluster-manifest"
        status, body = self._http_get(url, self._token, self._timeout)
        if status == 204:
            # Peer has no manifest to share — normal during early
            # cluster bootstrap.
            return
        if status != 200:
            if status != 0:
                log.debug(
                    "anti-entropy: gossip from %s returned HTTP %d",
                    peer.node_id,
                    status,
                )
            return
        try:
            doc = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            log.warning("anti-entropy: gossip %s returned non-JSON", peer.node_id)
            return
        if not isinstance(doc, dict):
            return
        wire = doc.get("wire")
        if not isinstance(wire, str) or not wire:
            return

        manifest = ClusterManifest.parse_and_verify(
            wire,
            self._cluster_operator_spk,
            expected_cluster_name=self._base_domain,
        )
        if manifest is None:
            # Peer returned something — malformed, wrong key, wrong
            # cluster_name, expired, or signature invalid. The pinned
            # operator_spk is the only trust anchor; any verify miss
            # is silent (no install, no watermark move).
            log.warning(
                "anti-entropy: gossip %s returned non-verifying manifest",
                peer.node_id,
            )
            return

        current = self._current_installed_seq()
        if manifest.seq <= current:
            # No-op: peer has the same or older view. The higher-seq
            # manifest that lives locally was either set up by the
            # operator on disk or installed by a previous gossip tick.
            return

        # Good: higher-seq verifying manifest. Install:
        # 1) republish wire under cluster.<base> TXT (append-semantics
        #    keeps the old wire visible during the TTL window, which
        #    is fine — clients pick highest-seq that verifies).
        # 2) swap the live peer set to the new node list, preserving
        #    watermarks for retained peers.
        self._install_gossiped_manifest(manifest, wire)

    def _current_installed_seq(self) -> int:
        """Return the highest seq currently visible to this worker.

        Returns ``max(in-memory-cached seq, local-store max-verified
        seq)``. Re-reading the store on every call is deliberate: the
        operator rollout path pushes a new manifest to one node via
        ``/v1/records/cluster.<base>`` (NOT through install_gossiped_
        manifest), which means the worker's cache is blind to that
        fresh value. Caching only would let a peer at seq == cache but
        > disk sneak in a downgrade. Ground truth lives in the store.

        The cache IS still useful: it captures in-process installs
        whose wire hasn't been fully flushed / isn't yet visible to
        query_txt_record via expiry semantics. We take the max of
        both sources.
        """
        disk_best = -1
        if self._base_domain and self._cluster_operator_spk is not None:
            from dmp.core.cluster import cluster_rrset_name

            try:
                rrset = cluster_rrset_name(self._base_domain)
            except ValueError:
                rrset = None
            if rrset is not None and hasattr(self._store, "query_txt_record"):
                try:
                    values = self._store.query_txt_record(rrset)
                except Exception:
                    values = None
                for wire in values or []:
                    if not isinstance(wire, str):
                        continue
                    m = ClusterManifest.parse_and_verify(
                        wire,
                        self._cluster_operator_spk,
                        expected_cluster_name=self._base_domain,
                    )
                    if m is not None and m.seq > disk_best:
                        disk_best = m.seq
        return max(self._installed_seq, disk_best)

    def _install_gossiped_manifest(
        self, manifest: "ClusterManifest", wire: str
    ) -> None:
        """Store the wire + swap the peer list. Called only after
        parse_and_verify succeeded and seq is strictly higher than any
        manifest seen before."""
        from dmp.core.cluster import cluster_rrset_name

        try:
            rrset = cluster_rrset_name(manifest.cluster_name)
        except ValueError:
            # Shouldn't happen after parse_and_verify, but guard anyway.
            log.warning("anti-entropy: gossip install: invalid cluster_name")
            return

        # Republish into the local store. publish_txt_record is
        # append-semantics: a duplicate is a no-op TTL refresh, not an
        # overwrite. Old + new co-reside until the old TTL expires,
        # matching the operator-rollout DNS pattern the client's
        # highest-seq-wins fetch already handles.
        try:
            # TTL anchors to the manifest's own ``exp`` timestamp.
            # A fixed 5-min TTL aged out gossiped manifests on nodes
            # that learned the cluster ONLY via gossip — after 300s the
            # record expired, /v1/sync/cluster-manifest returned 204,
            # and downstream peers/clients could no longer discover the
            # current manifest from this node. Tying the TTL to the
            # manifest's expiry guarantees the TXT outlives its own
            # validity window; a fresh install each time the worker
            # learns a higher seq refreshes it.
            import time as _time

            now = int(_time.time())
            # TTL tracks the manifest's own signed expiry — no cap. The
            # manifest's parse_and_verify already rejects past-exp, so
            # letting the TXT live the full validity window keeps the
            # gossip-only node's /v1/sync/cluster-manifest responsive
            # for the entire operator-chosen lifetime. Worst case a
            # multi-day-valid manifest pins a record for several days;
            # operator bumps seq to roll out a replacement.
            exp_remaining = max(1, manifest.exp - now)
            self._store.publish_txt_record(rrset, wire, ttl=exp_remaining)
        except Exception:
            log.exception(
                "anti-entropy: gossip install: store publish for %s failed", rrset
            )
            return

        # Swap peers. Retained peers keep their watermarks; new peers
        # start at the sentinel; dropped peers have their state cleared.
        new_peers: List[SyncPeer] = []
        for node in manifest.nodes:
            new_peers.append(
                SyncPeer(node_id=node.node_id, http_endpoint=node.http_endpoint)
            )
        self.replace_peers(new_peers)

        self._installed_seq = manifest.seq
        log.info(
            "anti-entropy: gossip installed manifest seq=%d from peers (%d nodes)",
            manifest.seq,
            len(manifest.nodes),
        )

    def replace_peers(self, peers: Iterable[SyncPeer]) -> None:
        """Swap the worker's peer list at runtime.

        Called by the gossip path when a higher-seq manifest lands,
        but also safe to call from tests or operator tooling. Preserves
        watermarks for peers retained across the swap. New peers start
        at the ``(0, "", "")`` sentinel. Dropped peers have their
        watermark entry removed.

        Identity for retention is the PAIR (node_id, normalized
        http_endpoint). Same-node_id-different-endpoint counts as
        a genuinely new peer (endpoint rotation → fresh state).
        Same-endpoint-different-node_id ALSO counts as retained:
        this is the DMP_SYNC_PEERS → gossiped-manifest handoff path,
        where peers were initially seeded with URL-derived synthetic
        ids and then reappear under operator-defined ids. Without
        that cross-key match the first gossip install would drop
        every synthetic watermark and force a full rescan of records
        we already validated.

        Self-exclusion is re-applied so callers don't have to
        pre-filter.
        """
        new_list = self._filter_self(list(peers))
        # Deduplicate by node_id, preserving first-seen order.
        seen: Set[str] = set()
        deduped: List[SyncPeer] = []
        for p in new_list:
            if p.node_id in seen:
                continue
            seen.add(p.node_id)
            deduped.append(p)

        def _norm_endpoint(url: str) -> str:
            # Same normalization _peer_id_from_url uses — strip trailing
            # slashes, lowercase. Keeps url-synthetic and operator-pinned
            # peers matchable by stable key.
            return url.strip().rstrip("/").lower()

        # Retention rule (narrow by design):
        #   1. Same (node_id, endpoint) pair → preserve cursor (no change).
        #   2. Endpoint unchanged, old node_id was SYNTHETIC (URL-derived
        #      via _peer_id_from_url) and new id is operator-defined →
        #      preserve cursor: this is the DMP_SYNC_PEERS-to-gossiped-
        #      manifest handoff where the "node" was always the endpoint
        #      and the synthetic id was our internal invention.
        #   3. Any other rotation (endpoint change OR operator-id→
        #      operator-id under same endpoint) → FRESH cursor. Both
        #      indicate a real replacement; resuming mid-stream would
        #      skip history the new peer hasn't replicated.
        #
        # _peer_id_from_url lives in dmp.server.node to avoid a circular
        # import at module load; resolve lazily here.
        def _is_synthetic_id(peer: SyncPeer) -> bool:
            try:
                from dmp.server.node import _peer_id_from_url
            except Exception:
                return False
            return peer.node_id == _peer_id_from_url(peer.http_endpoint)

        with self._lock:
            old_peers_by_ep: Dict[str, SyncPeer] = {}
            for old_peer in self._peers:
                old_peers_by_ep[_norm_endpoint(old_peer.http_endpoint)] = old_peer

            new_watermarks: Dict[str, Cursor] = {}
            for p in deduped:
                key_ep = _norm_endpoint(p.http_endpoint)
                old_peer = old_peers_by_ep.get(key_ep)
                old_cursor = (
                    self._watermarks.get(old_peer.node_id) if old_peer else None
                )
                preserve = False
                if old_peer is not None and old_cursor is not None:
                    if old_peer.node_id == p.node_id:
                        # Case 1: identical (id, endpoint).
                        preserve = True
                    elif _is_synthetic_id(old_peer):
                        # Case 2: synthetic→operator handoff.
                        preserve = True
                    # Else: case 3 — operator-id change on same endpoint
                    # means a real node replacement. Fresh cursor.
                new_watermarks[p.node_id] = old_cursor if preserve else (0, "", "")
            self._watermarks = new_watermarks
            self._peers = deduped
            if self._peers:
                self._rr_index = self._rr_index % len(self._peers)
            else:
                self._rr_index = 0

    # ---- per-peer work -----------------------------------------------------

    def _sync_with_peer(self, peer: SyncPeer) -> None:
        watermark = self._current_watermark(peer.node_id)
        digest = self._fetch_digest(peer, watermark)
        if digest is None:
            return
        entries, has_more, peer_next_cursor = digest
        self.stats.digests_fetched += 1

        if not entries:
            # Empty page — nothing newer than our watermark. We
            # deliberately do NOT trust the peer's next_cursor here: with
            # no validated data to anchor against, a lying peer could
            # push us arbitrarily far forward. Leave the watermark where
            # it is; next tick will re-query from the same cursor and
            # pick up anything that appeared in the interim.
            return

        # Hard security gate: drop structurally-invalid entries BEFORE they
        # can touch either the pull set or the watermark calculation. A
        # peer that returns {"ts": far_future, "name": "bogus"} must not
        # be able to skip the local node past legitimate lower-ts updates.
        valid_entries = [e for e in entries if _valid_digest_entry(e)]
        rejected = len(entries) - len(valid_entries)
        if rejected:
            log.warning(
                "anti-entropy: peer %s returned %d structurally-invalid "
                "digest entries (dropped, watermark unaffected)",
                peer.node_id,
                rejected,
            )
            self.stats.records_rejected += rejected

        if not valid_entries:
            # Everything the peer sent was garbage. Do NOT trust their
            # next_cursor either — they already demonstrated they'll lie.
            return

        # Build local {name -> {hash -> ttl_remaining}} index for just
        # the names the peer lists. We only need to hash the values at
        # those names, not the whole store, so this is cheap even with
        # a big store. The TTL side of the value powers TTL-refresh
        # detection further down: when value hashes match but the peer's
        # TTL is materially higher than ours, the peer has seen a
        # republish we missed.
        peer_names = [e["name"] for e in valid_entries]
        local_by_name: Dict[str, Dict[str, int]] = {}
        local_store_records = self._store.get_records_by_name(peer_names)
        for r in local_store_records:
            local_by_name.setdefault(r.name, {})[r.record_hash] = int(r.ttl_remaining)

        # Diff on (name, hash) PAIRS, not name. A single name with
        # multiple values (e.g. a prekey set: 5 TXT entries under
        # ``prekeys.id-xxx``) surfaces in the digest as 5 entries sharing
        # a name but with distinct hashes. Keying only on ``name`` would
        # mark the first one seen and silently drop the rest — the bug
        # this fix closes.
        to_pull: List[Tuple[str, str]] = []
        seen_pairs: Set[Tuple[str, str]] = set()
        # Also track pairs considered "handled" — those we either pulled
        # successfully OR already had at the same hash with a
        # close-enough TTL. Only handled pairs can advance the watermark.
        handled_pairs: Set[Tuple[str, str]] = set()
        for entry in valid_entries:
            name = entry["name"]
            h = entry["hash"]
            if (name, h) in seen_pairs:
                # Duplicate (name, hash) in the page. Skip; we already
                # processed it above.
                continue
            seen_pairs.add((name, h))
            local_hashes = local_by_name.get(name, {})
            if h in local_hashes:
                # Same value hash — check for a TTL-only refresh. The peer's
                # digest carries ttl as of when it built the response; if
                # the peer says the row has materially more life left than
                # ours does, they've seen a refresh we missed.
                peer_ttl = entry.get("ttl")
                if isinstance(peer_ttl, int) and peer_ttl > 0:
                    local_ttl = local_hashes[h]
                    if peer_ttl <= local_ttl + _TTL_REFRESH_SLOP_SECONDS:
                        # Already in sync (within slop). Handled.
                        handled_pairs.add((name, h))
                        continue
                    # fallthrough — schedule a pull to refresh our expiry
                else:
                    # Legacy peer that didn't emit ttl. Fall back to
                    # hash-only behavior (no refresh detection, but no
                    # false positives either).
                    handled_pairs.add((name, h))
                    continue
            to_pull.append((name, h))

        pulled_pairs: Set[Tuple[str, str]] = set()
        if to_pull:
            pulled_pairs = self._pull_and_write(peer, to_pull)
        handled_pairs |= pulled_pairs

        # Watermark advance.
        #
        # The hard safety property: never advance past a digest entry
        # that wasn't handled this tick (pulled, or already-present with
        # matching hash + compatible TTL). Pairs that went into
        # ``to_pull`` but weren't returned by ``_pull_and_write`` must
        # stay visible to the next digest: that includes entries beyond
        # ``pull_batch_limit`` and those the peer declined or we
        # rejected.
        #
        # The original M2.4 design advanced past peer-rejection failures
        # to avoid getting stuck on a bad row. With the compound (ts,
        # name, value_hash) cursor the validation gate above already
        # filters the common "malicious poke" case, so it's safer to
        # hold the watermark at the last handled entry and let the next
        # tick retry. A truly dead row will eventually expire and fall
        # out of the digest entirely.
        # Walk `valid_entries` IN ORDER and advance only through the
        # contiguous handled prefix from the front. If entry B at index
        # i is unhandled, we stop BEFORE it — even if entry C at index
        # i+1 was handled, we must leave C behind too, because the next
        # tick's `since=<cursor>` query would otherwise skip past B.
        # max-of-handled would lose B forever.
        contiguous_handled: List[Cursor] = []
        for e in valid_entries:
            if (e["name"], e["hash"]) in handled_pairs:
                contiguous_handled.append((int(e["ts"]), e["name"], e["hash"]))
            else:
                break
        if contiguous_handled:
            max_handled = contiguous_handled[-1]
        else:
            max_handled = watermark

        # Watermark is always ``max_handled`` — the deepest point we can
        # justify from records we actually validated and wrote.
        #
        # Peer's next_cursor is NOT trusted for watermark advancement.
        # It can be:
        #   - ahead of max_handled (peer fabricating a forged-future
        #     pointer to skip us past real rows), OR
        #   - behind max_handled (stale/buggy peer, which would drag the
        #     watermark backward from the page tail we just handled and
        #     wedge the loop replaying the same rows), OR
        #   - equal to max_handled (fine but adds nothing).
        # In all cases taking max_handled is safe; no peer lie can
        # advance us past data we validated. The peer's cursor is still
        # used as the _next request cursor_ (see _fetch_digest) so a
        # busy peer's pagination remains cheap, but it never touches
        # the watermark directly.
        new_watermark = max_handled

        if _cursor_gt(new_watermark, watermark):
            self._watermarks[peer.node_id] = new_watermark

    def _fetch_digest(
        self, peer: SyncPeer, watermark: Cursor
    ) -> Optional[Tuple[List[dict], bool, Optional[Cursor]]]:
        # Send the compound cursor as the opaque
        # ``cursor=<ts>:<name>:<value_hash>`` query param. DNS names
        # don't contain colons and value_hash is lowercase hex, so the
        # delimiter is unambiguous. Empty halves (e.g. the ``(0, "", "")``
        # sentinel) still parse cleanly as ``"0::"``.
        cur_ts, cur_name, cur_hash = watermark
        cursor_param = f"{int(cur_ts)}:{cur_name}:{cur_hash}"
        url = (
            f"{peer.http_endpoint.rstrip('/')}/v1/sync/digest"
            f"?cursor={cursor_param}&limit={self._digest_limit}"
        )
        status, body = self._http_get(url, self._token, self._timeout)
        if status != 200:
            if status != 0:
                log.warning(
                    "anti-entropy: digest %s returned HTTP %d", peer.node_id, status
                )
            self.stats.errors += 1
            return None
        try:
            doc = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            log.warning("anti-entropy: digest %s returned non-JSON", peer.node_id)
            self.stats.errors += 1
            return None
        records = doc.get("records")
        has_more = bool(doc.get("has_more"))
        next_cursor = _parse_next_cursor(doc.get("next_cursor"))
        if not isinstance(records, list):
            self.stats.errors += 1
            return None
        return (records, has_more, next_cursor)

    def _pull_and_write(
        self, peer: SyncPeer, pairs: List[Tuple[str, str]]
    ) -> Set[Tuple[str, str]]:
        """Pull up to ``pull_batch_limit`` (name, hash) pairs from
        ``peer``, verify+write each, and return the set of pairs we
        successfully stored.

        The caller uses the returned set to advance the watermark: any
        pair present in the digest but absent from this set (because it
        was deferred past the batch limit, rejected, or failed to write)
        must remain visible to the next digest request.
        """
        # Cap the request to the pull limit; if the peer's digest named
        # more than that, we'll catch the remainder on the next tick
        # (their stored_ts hasn't changed, so they'll still show up in
        # the next digest window — as long as we don't advance the
        # watermark past them, see `_sync_with_peer`).
        requested = pairs[: self._pull_limit]
        # Map name -> set of expected hashes the peer advertised. A peer
        # may legitimately have multiple advertised hashes at one name
        # (multi-value RRset); tracking the set lets a future hash-match
        # verifier know which hash a given pulled value should match.
        expected_hashes_by_name: Dict[str, Set[str]] = {}
        for name, h in requested:
            expected_hashes_by_name.setdefault(name, set()).add(h)
        requested_names = [name for name, _ in requested]
        written: Set[Tuple[str, str]] = set()
        url = f"{peer.http_endpoint.rstrip('/')}/v1/sync/pull"
        # Deduplicate names before the wire — the /pull endpoint does its
        # own dedup but sending two copies of the same name on a
        # multi-value RRset pull is wasted bandwidth.
        payload = json.dumps({"names": list(dict.fromkeys(requested_names))}).encode(
            "utf-8"
        )
        status, body = self._http_post(url, self._token, payload, self._timeout)
        if status != 200:
            if status != 0:
                log.warning(
                    "anti-entropy: pull %s returned HTTP %d", peer.node_id, status
                )
            self.stats.errors += 1
            return written
        try:
            doc = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.stats.errors += 1
            return written
        records = doc.get("records")
        if not isinstance(records, list):
            self.stats.errors += 1
            return written

        for rec in records:
            if not isinstance(rec, dict):
                continue
            name = rec.get("name")
            value = rec.get("value")
            ttl = rec.get("ttl")
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or not isinstance(ttl, int)
                or ttl <= 0
            ):
                self.stats.records_rejected += 1
                continue
            # Defense: peer must only return records for names we asked about.
            expected = expected_hashes_by_name.get(name)
            if expected is None:
                log.warning(
                    "anti-entropy: peer %s returned unsolicited name %s",
                    peer.node_id,
                    name,
                )
                self.stats.records_rejected += 1
                continue
            # Hash-match check: the pulled value's sha256 MUST match one
            # of the hashes the digest advertised for this name. A peer
            # that advertised H1 and returns a value hashing to H2 is
            # lying — accepting would both write the wrong data AND
            # advance the watermark past H1 (the new write's stored_ts
            # would bump forward), so H1 would never be retried. Reject
            # instead; the pair stays unhandled and the next digest
            # tick will re-ask.
            #
            # Order of gates (all must pass):
            #   1. Hash-match vs digest (this check).
            #   2. Structural / signature verify (below).
            #   3. Write to store.
            #   4. Mark (name, hash) handled by adding to `written`.
            actual_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
            if actual_hash not in expected:
                log.warning(
                    "anti-entropy: peer %s returned value for %s whose "
                    "hash %s is not among advertised hashes %s",
                    peer.node_id,
                    name,
                    actual_hash,
                    sorted(expected),
                )
                self.stats.records_rejected += 1
                continue
            self.stats.records_pulled += 1
            # Re-verify signed record types. If verification fails, drop.
            if not verify_record(
                value, cluster_operator_spk=self._cluster_operator_spk
            ):
                log.warning(
                    "anti-entropy: peer %s returned unverifiable record for %s",
                    peer.node_id,
                    name,
                )
                self.stats.records_rejected += 1
                continue
            # Write via publish_txt_record, which is append-semantics: a
            # duplicate is a no-op TTL refresh, not an overwrite.
            try:
                self._store.publish_txt_record(name, value, ttl=int(ttl))
                self.stats.records_written += 1
                written.add((name, actual_hash))
            except Exception:
                log.exception("anti-entropy: local publish failed for %s", name)
                self.stats.errors += 1
        return written

    # ---- testing introspection --------------------------------------------

    def _current_watermark(self, node_id: str) -> Cursor:
        """Return the compound watermark for ``node_id``, migrating any
        legacy shape on first access.

        The integer form lingers on disk nowhere (watermarks are
        in-memory) but tests occasionally seed them via ``set_watermark``
        with the old shape. We coerce:

        - ``int`` → ``(int, "", "")``
        - ``(int, str)`` → ``(int, str, "")``
        - ``(int, str, str)`` → returned as-is

        Anything else is reset to ``(0, "", "")``.
        """
        raw = self._watermarks.get(node_id, (0, "", ""))
        if isinstance(raw, int):
            migrated: Cursor = (raw, "", "")
            self._watermarks[node_id] = migrated
            return migrated
        if isinstance(raw, tuple) and len(raw) == 2:
            migrated2: Cursor = (int(raw[0]), str(raw[1]), "")
            self._watermarks[node_id] = migrated2
            return migrated2
        # Defensive: three-tuple shape check.
        if (
            not isinstance(raw, tuple)
            or len(raw) != 3
            or not isinstance(raw[0], int)
            or not isinstance(raw[1], str)
            or not isinstance(raw[2], str)
        ):
            self._watermarks[node_id] = (0, "", "")
            return (0, "", "")
        return raw

    def watermark(self, node_id: str) -> Cursor:
        """Return the ``(stored_ts_ms, name, value_hash)`` watermark for
        ``node_id``.

        The return shape evolved ``int`` → ``(int, str)`` in M2.4
        follow-up, then ``(int, str)`` → ``(int, str, str)`` in
        follow-up-2. Callers that treat the result as truthy (``if
        worker.watermark(...)``) still work because ``(0, "", "")`` is
        the sole "pull from beginning" sentinel.
        """
        return self._current_watermark(node_id)

    def set_watermark(self, node_id: str, ts: Union[int, Tuple]) -> None:
        """Seed a watermark for tests. Accepts the legacy ``int``, the
        followup-1 ``(int, str)`` shape, or the followup-2
        ``(int, str, str)`` shape. Legacy values are normalized on the
        way in."""
        if isinstance(ts, int):
            self._watermarks[node_id] = (int(ts), "", "")
        elif isinstance(ts, tuple) and len(ts) == 2:
            self._watermarks[node_id] = (int(ts[0]), str(ts[1]), "")
        elif isinstance(ts, tuple) and len(ts) == 3:
            self._watermarks[node_id] = (
                int(ts[0]),
                str(ts[1]),
                str(ts[2]),
            )
        else:
            raise TypeError("watermark must be int, (int, str), or (int, str, str)")

    @property
    def peers(self) -> List[SyncPeer]:
        return list(self._peers)
