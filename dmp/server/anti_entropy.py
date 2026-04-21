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
        handled_cursors: List[Cursor] = [
            (int(e["ts"]), e["name"], e["hash"])
            for e in valid_entries
            if (e["name"], e["hash"]) in handled_pairs
        ]
        if handled_cursors:
            max_handled = max(handled_cursors)
        else:
            max_handled = watermark

        # Peer's next_cursor is a pagination hint. We only trust it when:
        #   - every validated (name, hash) pair was handled (so no entry
        #     is being skipped), AND
        #   - it does not point STRICTLY PAST max_handled (so the peer
        #     isn't fabricating a future cursor to poke our watermark
        #     ahead of any real data we've verified).
        # If the peer lied about where pagination ends, we ignore the
        # cursor and advance only to max_handled — the next tick will
        # still re-request from there and see any rows we missed.
        new_watermark = max_handled
        if (
            peer_next_cursor is not None
            and len(handled_pairs) == len(seen_pairs)
            and _cursor_ge(peer_next_cursor, watermark)
            and not _cursor_gt(peer_next_cursor, max_handled)
        ):
            new_watermark = peer_next_cursor

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
