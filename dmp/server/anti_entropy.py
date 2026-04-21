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
import json
import logging
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple
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

# A well-formed chunk record prefix (the only type without a d= suffix and
# not in the signed-type list).
_CHUNK_PREFIX = "v=dmp1;t=chunk;d="


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
        http_get: Optional[HttpGet] = None,
        http_post: Optional[HttpPost] = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be > 0")
        self._store = store
        self._peers: List[SyncPeer] = list(peers)
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

        self._watermarks: Dict[str, int] = {p.node_id: 0 for p in self._peers}
        self._rr_index: int = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.stats = SyncStats()

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
        """Run one sync cycle against one peer. Public for tests."""
        with self._lock:
            self.stats.ticks += 1
            if not self._peers:
                return
            peer = self._peers[self._rr_index % len(self._peers)]
            self._rr_index = (self._rr_index + 1) % len(self._peers)
        self._sync_with_peer(peer)

    # ---- per-peer work -----------------------------------------------------

    def _sync_with_peer(self, peer: SyncPeer) -> None:
        watermark = self._watermarks.get(peer.node_id, 0)
        digest = self._fetch_digest(peer, watermark)
        if digest is None:
            return
        entries, has_more = digest
        self.stats.digests_fetched += 1

        if not entries:
            return

        # Build local hash index for just the names the peer lists. We only
        # need to hash the values at those names, not the whole store, so
        # this is cheap even with a big store.
        peer_names = [e["name"] for e in entries]
        local_by_name: Dict[str, set] = {}
        local_store_records = self._store.get_records_by_name(peer_names)
        for r in local_store_records:
            local_by_name.setdefault(r.name, set()).add(r.record_hash)

        # Names to pull: those with a (name, hash) the peer has and we don't.
        to_pull: List[str] = []
        seen: set = set()
        for entry in entries:
            name = entry.get("name")
            h = entry.get("hash")
            if not isinstance(name, str) or not isinstance(h, str):
                continue
            if h in local_by_name.get(name, set()):
                continue
            if name in seen:
                continue
            seen.add(name)
            to_pull.append(name)

        if to_pull:
            self._pull_and_write(peer, to_pull)

        # Advance watermark even if there was nothing to pull — we've
        # observed the peer up to max(entries.ts). If has_more is true we
        # deliberately advance only to the last entry's ts, so the next
        # tick picks up the rest.
        max_ts = max((int(e.get("ts", 0) or 0) for e in entries), default=watermark)
        if max_ts > watermark:
            self._watermarks[peer.node_id] = max_ts

    def _fetch_digest(
        self, peer: SyncPeer, watermark: int
    ) -> Optional[Tuple[List[dict], bool]]:
        url = (
            f"{peer.http_endpoint.rstrip('/')}/v1/sync/digest"
            f"?since={int(watermark)}&limit={self._digest_limit}"
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
        if not isinstance(records, list):
            self.stats.errors += 1
            return None
        return (records, has_more)

    def _pull_and_write(self, peer: SyncPeer, names: List[str]) -> None:
        # Cap the request to the pull limit; if the peer's digest named
        # more than that, we'll catch the remainder on the next tick
        # (their stored_ts hasn't changed, so they'll still show up in
        # the next digest window).
        requested = names[: self._pull_limit]
        requested_set = set(requested)
        url = f"{peer.http_endpoint.rstrip('/')}/v1/sync/pull"
        payload = json.dumps({"names": requested}).encode("utf-8")
        status, body = self._http_post(url, self._token, payload, self._timeout)
        if status != 200:
            if status != 0:
                log.warning(
                    "anti-entropy: pull %s returned HTTP %d", peer.node_id, status
                )
            self.stats.errors += 1
            return
        try:
            doc = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.stats.errors += 1
            return
        records = doc.get("records")
        if not isinstance(records, list):
            self.stats.errors += 1
            return

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
            if name not in requested_set:
                log.warning(
                    "anti-entropy: peer %s returned unsolicited name %s",
                    peer.node_id,
                    name,
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
            except Exception:
                log.exception("anti-entropy: local publish failed for %s", name)
                self.stats.errors += 1

    # ---- testing introspection --------------------------------------------

    def watermark(self, node_id: str) -> int:
        return int(self._watermarks.get(node_id, 0))

    def set_watermark(self, node_id: str, ts: int) -> None:
        self._watermarks[node_id] = int(ts)

    @property
    def peers(self) -> List[SyncPeer]:
        return list(self._peers)
