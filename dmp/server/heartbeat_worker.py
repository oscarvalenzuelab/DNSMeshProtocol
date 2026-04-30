"""Heartbeat worker — DNS-native publish/discover (M9.1.2).

Each tick (default every 5 minutes):

1. Build + sign the node's own ``HeartbeatRecord`` using the operator
   Ed25519 key loaded at startup.
2. Publish the wire as a TXT record at ``_dnsmesh-heartbeat.<own-zone>``
   via the local DNSRecordWriter — the same writer the cluster
   manifest publisher uses. After publish the record is queryable
   via the recursive DNS chain by anyone in the world.
3. For each configured seed zone, query
   ``_dnsmesh-heartbeat.<seed-zone>`` via the local DNSRecordReader
   to learn that peer's current state. Each verified wire is fed to
   ``SeenStore.accept`` (which checks signature + freshness + low-
   order pubkey before storing — a hostile peer cannot poison the
   store because every row is a verifiable Ed25519 signature).
4. Optionally also harvest the peer's transitive seen-graph by
   querying ``_dnsmesh-seen.<seed-zone>`` (M9.1.3, multi-record
   TXT). Implemented in this module but feature-flagged on the
   record-writer being present so legacy in-memory tests can
   exercise just step 2 + 3 without the gossip layer.

Failures are logged at INFO and don't stop the worker. A peer zone
that fails to resolve stays in the list but gets a cooldown on the
next tick so a consistently-broken zone doesn't hog budget.

This is a clean break from the M5.8 HTTP-gossip model. The worker
no longer POSTs to peers' ``/v1/heartbeat`` endpoint; that whole HTTP
exchange path is gone in 0.5.0. Anti-entropy between cluster peers
remains HTTP-based (it's an HA implementation detail, not a federation
primitive — see M9 design notes).
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Set
from urllib.parse import urlsplit

from dmp.core.crypto import DMPCrypto
from dmp.core.heartbeat import HeartbeatRecord
from dmp.network.base import DNSRecordReader, DNSRecordWriter
from dmp.server.heartbeat_store import SeenStore

log = logging.getLogger(__name__)


# Defaults — tuneable via env on DMPNode startup.
DEFAULT_INTERVAL_SECONDS = 300  # 5 minutes
DEFAULT_TTL_SECONDS = 86_400  # 24 hours
DEFAULT_MAX_PEERS = 25
# Cooldown applied to a peer that fails a single tick. Next tick we
# skip it. Counter resets on successful contact.
DEFAULT_FAILURE_COOLDOWN_TICKS = 1
# Cap on how many gossip wires the worker will ingest from ONE peer
# per response. A hostile seed can answer with an unbounded `seen`
# RRset; without a cap, the worker burns signature-verify + sqlite
# cycles processing the flood. Same defense the M5.8 HTTP path had.
DEFAULT_MAX_GOSSIP_PER_RESPONSE = 20
# How many recently-seen peer wires this node republishes under
# _dnsmesh-seen.<own-zone>. Bounded so the RRset stays tractable for
# resolvers and doesn't grow unbounded when the directory does.
DEFAULT_MAX_SEEN_PUBLISH = 50

# DNS owner names the worker publishes / queries under.
HEARTBEAT_RRSET_PREFIX = "_dnsmesh-heartbeat"
SEEN_RRSET_PREFIX = "_dnsmesh-seen"


def _zone_from_seed(seed: str) -> str:
    """Normalize a heartbeat seed into a DNS zone label.

    M9 transition: pre-0.5.0 operators populated ``DMP_HEARTBEAT_SEEDS``
    with URLs (``https://dnsmesh.io``). The new format wants bare
    zones (``dnsmesh.io``). To avoid asking every operator to
    rewrite ``node.env`` on the upgrade, accept either. Strip a
    leading ``<scheme>://`` and any trailing ``:port`` / path.
    Empty / unparseable input returns the empty string so the
    caller can drop it.
    """
    if not isinstance(seed, str) or not seed:
        return ""
    s = seed.strip()
    if "://" in s:
        try:
            parts = urlsplit(s)
            host = (parts.hostname or "").strip().lower()
        except ValueError:
            return ""
        return host
    # Already a bare hostname — strip an explicit port if present.
    if ":" in s and not s.startswith("["):
        s = s.split(":", 1)[0]
    return s.lower()


def heartbeat_rrset_name(zone: str) -> str:
    """Owner name a node publishes its heartbeat under."""
    if not isinstance(zone, str) or not zone:
        raise ValueError("zone must be a non-empty string")
    return f"{HEARTBEAT_RRSET_PREFIX}.{zone}"


def seen_rrset_name(zone: str) -> str:
    """Owner name a node publishes its seen-graph under (M9.1.3)."""
    if not isinstance(zone, str) or not zone:
        raise ValueError("zone must be a non-empty string")
    return f"{SEEN_RRSET_PREFIX}.{zone}"


@dataclass(frozen=True)
class HeartbeatWorkerConfig:
    """Plain-data config the worker reads at construction.

    The worker owns no mutable config — a re-config requires a
    restart, matching the pattern the rest of DMPNode uses.

    M9 fields:
      - ``dns_zone`` is the zone the worker publishes its own
        heartbeat under. Required when ``record_writer`` is wired in.
      - ``seed_zones`` are the DNS zones the worker queries for peer
        heartbeats. Replaces the URL-based ``seed_peers`` from M5.8.
        ``DMPNode`` reads ``DMP_HEARTBEAT_SEEDS`` and parses each
        entry through ``_zone_from_seed`` so legacy URL configs keep
        working.
    """

    self_endpoint: str
    version: str
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_peers: int = DEFAULT_MAX_PEERS
    failure_cooldown_ticks: int = DEFAULT_FAILURE_COOLDOWN_TICKS
    max_gossip_per_response: int = DEFAULT_MAX_GOSSIP_PER_RESPONSE
    max_seen_publish: int = DEFAULT_MAX_SEEN_PUBLISH
    capabilities: int = 0
    claim_provider_zone: str = ""
    # M9 — DNS-native publish/discover.
    dns_zone: str = ""
    seed_zones: tuple = ()


class HeartbeatWorker:
    """Background DNS-native heartbeat publisher + seen-graph harvester.

    Not thread-safe from the outside — call start() / stop() from
    the main thread (DMPNode does this). Internally the worker
    runs in its own daemon thread and communicates with the
    SeenStore via its thread-safe API.
    """

    def __init__(
        self,
        config: HeartbeatWorkerConfig,
        operator_crypto: DMPCrypto,
        seen_store: SeenStore,
        *,
        record_writer: Optional[DNSRecordWriter] = None,
        dns_reader: Optional[DNSRecordReader] = None,
        cluster_peers_provider: Optional[Callable[[], Iterable[str]]] = None,
    ) -> None:
        """Construct the worker.

        ``record_writer`` is the local store the node uses to publish
        its own zone records. When None, the worker still ticks but
        publishes nothing — useful for tests that only want to
        exercise the gossip-ingest side.

        ``dns_reader`` is the resolver the worker uses to fetch peer
        heartbeat records. When None, the worker skips the harvest
        step. Tests pass an in-memory store implementing the same
        interface.

        ``cluster_peers_provider`` is an optional zero-arg callable
        that returns cluster peer endpoints (for clustered nodes
        that want to harvest each peer's zone). Each entry is
        normalized via ``_zone_from_seed``. None in solo-node mode.
        """
        self._cfg = config
        self._crypto = operator_crypto
        self._store = seen_store
        self._record_writer = record_writer
        self._dns_reader = dns_reader
        self._cluster_peers_provider = cluster_peers_provider or (lambda: ())

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Cooldown map: peer zone -> ticks-until-retry. A peer that
        # failed on the last tick waits at least one tick before we
        # try again, so a persistent error doesn't monopolize budget.
        self._cooldown: dict = {}
        # Last self-heartbeat wire we published, so the next tick can
        # evict ONLY our own previous wire (not the whole RRset).
        # Codex round-18 P1: a delete-before-publish that wipes the
        # owner-name RRset breaks shared zones — every cluster peer
        # publishing under DMP_CLUSTER_BASE_DOMAIN clobbered the
        # others' wires every tick.
        self._last_self_wire: Optional[str] = None
        # Same per-wire eviction story for the seen-graph. Codex
        # round-19 P1: ``_dnsmesh-seen.<shared-zone>`` is shared with
        # sibling cluster nodes; we only delete the wires we last
        # published, never the whole RRset.
        self._last_seen_wires: Set[str] = set()
        # Codex round-22 P1 — restart leaves orphan self-wires at
        # ``_dnsmesh-heartbeat.<own-zone>``. ``_last_self_wire`` lives
        # in process memory only, so each restart loses the eviction
        # tracking and the next publish appends without cleanup. Over
        # multiple restarts (e.g. an upgrade cycle) the RRset grows
        # unbounded until each wire's ``exp`` fires (24h default),
        # which inflates UDP responses past 512 bytes and makes
        # public recursors return empty for the heartbeat query.
        # First call to ``_publish_own`` does a one-time sweep of
        # any existing self-wires (matched by operator_spk on parse-
        # and-verify) and deletes them before publishing the fresh
        # one. Flips after the first successful sweep.
        self._orphan_sweep_done: bool = False
        # Same orphan-sweep story for ``_dnsmesh-seen.<own-zone>``.
        # ``_last_seen_wires`` is process-memory only, so every
        # restart leaves the prior tick's published wires in place
        # with no eviction tracking. They linger until each wire's
        # ``exp`` fires (24h default), which over a few upgrade
        # cycles inflates the seen RRset past the recursive-resolver
        # UDP buffer (1232 bytes EDNS) — the response then exceeds
        # ``to_wire()``'s size budget, the UDP path raises
        # ``dns.exception.TooBig``, and federation discovery silently
        # breaks. First ``_publish_seen_graph`` does a one-time sweep
        # of any wire at ``_dnsmesh-seen.<own-zone>`` that is either
        # (a) signed by THIS operator (self never belongs in a node's
        # own seen RRset — seen is "OTHER nodes I have heard from")
        # or (b) a stale prior-tick wire for a peer we still see, so
        # cluster siblings' wires under shared zones remain intact.
        self._seen_orphan_sweep_done: bool = False

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="dmp-heartbeat-worker",
            daemon=True,
        )
        self._thread.start()
        log.info(
            "heartbeat worker started: zone=%s interval=%ds seeds=%d",
            self._cfg.dns_zone or "(none)",
            self._cfg.interval_seconds,
            len(self._cfg.seed_zones),
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # ------------------------------------------------------------------
    # tick mechanics
    # ------------------------------------------------------------------

    def _run(self) -> None:
        # First tick runs immediately so a fresh node publishes a
        # heartbeat without waiting `interval_seconds` for the first
        # sweep.
        while not self._stop_event.is_set():
            try:
                self.tick_once()
            except Exception:
                log.exception("heartbeat tick raised; continuing")
            self._stop_event.wait(self._cfg.interval_seconds)

    def tick_once(self, *, now: Optional[int] = None) -> int:
        """Run one tick synchronously. Returns the number of peer zones
        that produced a successfully-verified heartbeat ingest. Exposed
        for tests.
        """
        tick_start = int(now) if now is not None else int(time.time())

        # 1. Publish own heartbeat into our zone (if writer + zone
        #    are both configured). A standalone node with no zone
        #    config still ticks; it just doesn't expose itself in
        #    DNS this round.
        self._publish_own(tick_start)

        # 2. Harvest peer heartbeats by querying each seed zone.
        zones = self._build_seed_zones()
        successes = 0
        for zone in zones:
            cd = self._cooldown.get(zone, 0)
            if cd > 0:
                self._cooldown[zone] = cd - 1
                continue

            per_peer_now = int(now) if now is not None else int(time.time())
            ingested = self._fetch_and_ingest(zone, per_peer_now)
            if ingested:
                successes += 1
                self._cooldown.pop(zone, None)
            else:
                self._cooldown[zone] = self._cfg.failure_cooldown_ticks

        # 3. Republish the recently-verified seen-graph at
        #    _dnsmesh-seen.<own-zone>. Always runs after the harvest
        #    so freshly-ingested peers from this tick can also be
        #    crawled by other nodes through this zone. Multi-record
        #    TXT publish — one TXT value per peer wire.
        self._publish_seen_graph(tick_start)
        return successes

    # ------------------------------------------------------------------
    # publish
    # ------------------------------------------------------------------

    def _publish_own(self, now_i: int) -> bool:
        """Publish this node's signed heartbeat at
        ``_dnsmesh-heartbeat.<dns_zone>``. Returns True on success.

        Replace-OUR-OWN-wire semantic: ``DNSRecordWriter.publish_txt_record``
        is APPEND with content-keyed dedup, so a long-running node
        would otherwise leave every historical heartbeat at the same
        name (each tick bumps ``ts`` so the wire bytes differ).
        Readers like ``cmd_peers`` and ``_seed_provider_via_dns``
        short-circuit on the first verifiable wire and could lock
        onto an arbitrarily old self-record (codex round-5 P1).

        We delete ONLY our own previous wire (tracked across ticks
        in ``self._last_self_wire``) before publishing the fresh
        one — peers' wires at the same RRset name stay intact.
        Codex round-18 P1: the prior whole-RRset delete clobbered
        sibling cluster nodes that share a ``DMP_CLUSTER_BASE_DOMAIN``.
        """
        if self._record_writer is None or not self._cfg.dns_zone:
            return False
        try:
            wire = self._build_own_wire(now_i)
        except ValueError:
            log.exception("heartbeat self-wire build failed; skipping publish")
            return False
        try:
            name = heartbeat_rrset_name(self._cfg.dns_zone)
        except ValueError:
            return False
        # Codex round-22 P1 — first-tick orphan sweep. ``_last_self_wire``
        # only tracks wires this process published; on a restart it's
        # ``None`` and the previous lifetime's wires are orphaned at
        # the RRset until ``exp`` (24h default) lapses. Sweep them
        # explicitly so each restart leaves exactly one self-wire,
        # not N+1.
        if not self._orphan_sweep_done:
            self._sweep_orphan_self_wires(name, current_wire=wire, now=now_i)
            self._orphan_sweep_done = True
        # Evict our previous self-wire if any. ``delete_txt_record(value=…)``
        # only matches that one TXT value; other publishers' wires
        # under the same RRset are unaffected.
        if self._last_self_wire and self._last_self_wire != wire:
            try:
                self._record_writer.delete_txt_record(name, value=self._last_self_wire)
            except Exception:
                log.exception(
                    "heartbeat self-wire eviction raised for %s; continuing",
                    name,
                )
        try:
            ok = bool(
                self._record_writer.publish_txt_record(
                    name, wire, ttl=self._cfg.ttl_seconds
                )
            )
        except Exception:
            log.exception("heartbeat self-publish raised")
            return False
        if ok:
            self._last_self_wire = wire
        else:
            log.info("heartbeat self-publish to %s returned False", name)
        return ok

    def _sweep_orphan_self_wires(
        self, name: str, *, current_wire: str, now: int
    ) -> int:
        """Delete prior-process self-wires at ``name``.

        Called once per worker lifetime, before the first publish.
        Reads the current RRset from the local store, parses each
        TXT value, identifies entries signed by THIS operator's
        signing key, and deletes them. The fresh wire about to be
        published replaces them all with a single entry.

        Other publishers' wires under the same RRset are untouched —
        the match key is the operator's Ed25519 spk, not the owner
        name. Cluster siblings sharing a zone keep their wires.

        ``current_wire`` is excluded from the sweep so we don't
        delete the wire we're about to publish (rare, but possible
        if an earlier process happened to publish the byte-identical
        wire — same ts, same sig — within this second).

        ``now`` is the tick's reference time. We pass it explicitly
        through to ``parse_and_verify`` so a wire whose ``exp`` has
        already lapsed in wall-clock terms but remains "current" in
        the worker's logical time still matches. The test harness
        also relies on this — fixture clocks aren't real time.
        Wide skew (``10**9``) lets us match wires from arbitrarily
        long ago without rejecting them on freshness alone; only
        the signature + spk identity gates whether we delete.

        Returns the number of orphan wires deleted, for tests and
        operator visibility. Zero on first install, on a healthy
        long-running process, or when the writer doesn't expose a
        read API.
        """
        reader = self._record_writer
        if not hasattr(reader, "query_txt_record"):
            return 0
        try:
            existing = reader.query_txt_record(name)
        except Exception:
            log.exception("orphan self-wire sweep: query raised for %s", name)
            return 0
        if not existing:
            return 0

        own_spk = self._crypto.get_signing_public_key_bytes()
        deleted = 0
        for value in existing:
            if value == current_wire:
                continue
            rec = HeartbeatRecord.parse_and_verify(
                value, now=now, ts_skew_seconds=10**9
            )
            if rec is None:
                # Bad sig / shape / expired — safe to ignore. We don't
                # delete other operators' garbage; the DNS server's own
                # ingest path is what cleans those.
                continue
            if bytes(rec.operator_spk) != own_spk:
                continue
            try:
                if self._record_writer.delete_txt_record(name, value=value):
                    deleted += 1
            except Exception:
                log.exception(
                    "orphan self-wire delete raised for %s; continuing",
                    name,
                )
        if deleted:
            log.info(
                "swept %d orphan self-wire(s) at %s on worker startup",
                deleted,
                name,
            )
        return deleted

    def _sweep_orphan_seen_wires(
        self, name: str, *, next_wires: Set[str], now: int
    ) -> int:
        """Delete prior-process orphans at ``_dnsmesh-seen.<own-zone>``.

        Mirror of ``_sweep_orphan_self_wires`` for the seen RRset.
        Two classes of wire are deleted:

        1. Wires signed by THIS operator. Self never belongs in the
           local seen RRset (seen = "OTHER nodes I have heard from").
           Any self-wire there is leakage from a prior bootstrap path
           that later got fixed; we clean it up unconditionally.

        2. Wires for a peer ``(operator_spk, endpoint)`` that appears
           in ``next_wires`` but with a different wire payload — the
           existing one is our prior tick's stale copy of that peer.
           Replacing it with the fresh ``next_wires`` entry collapses
           the per-peer wire history into the latest signed copy.

        Anything else stays. Cluster siblings publishing into a
        shared ``_dnsmesh-seen.<shared-zone>`` keep their wires.
        Wires we can't parse (bad sig, expired beyond skew, malformed)
        are left alone — see ``_sweep_orphan_self_wires`` rationale.

        Returns the number of orphan wires deleted.
        """
        reader = self._record_writer
        if not hasattr(reader, "query_txt_record"):
            return 0
        try:
            existing = reader.query_txt_record(name)
        except Exception:
            log.exception("orphan seen-wire sweep: query raised for %s", name)
            return 0
        if not existing:
            return 0

        own_spk = self._crypto.get_signing_public_key_bytes()
        # Build a (spk_hex, endpoint) -> wire map of what we're about
        # to publish so we can detect prior-tick stale copies of the
        # SAME peer in the live RRset.
        next_keyed: dict = {}
        for w in next_wires:
            rec = HeartbeatRecord.parse_and_verify(w, now=now, ts_skew_seconds=10**9)
            if rec is None:
                continue
            next_keyed[(bytes(rec.operator_spk).hex(), rec.endpoint)] = w

        deleted = 0
        for value in existing:
            if value in next_wires:
                # Already what we want there — leave it.
                continue
            rec = HeartbeatRecord.parse_and_verify(
                value, now=now, ts_skew_seconds=10**9
            )
            if rec is None:
                continue
            spk = bytes(rec.operator_spk)
            should_delete = False
            if spk == own_spk:
                # Class 1: self in our own seen — never belongs.
                should_delete = True
            else:
                # Class 2: prior-tick stale for a peer we still see.
                key = (spk.hex(), rec.endpoint)
                if key in next_keyed and next_keyed[key] != value:
                    should_delete = True
            if not should_delete:
                continue
            try:
                if self._record_writer.delete_txt_record(name, value=value):
                    deleted += 1
            except Exception:
                log.exception(
                    "orphan seen-wire delete raised for %s; continuing",
                    name,
                )
        if deleted:
            log.info(
                "swept %d orphan seen-wire(s) at %s on worker startup",
                deleted,
                name,
            )
        return deleted

    def _publish_seen_graph(self, now_i: int) -> int:
        """Republish recently-seen peer wires under
        ``_dnsmesh-seen.<dns_zone>`` as a multi-value TXT RRset.

        One TXT value per peer wire. The wire is what SeenStore.accept
        already verified, so consumers re-verify each entry on their
        side and never need to trust this node's claim that the wire
        is authentic. Capped at ``max_seen_publish`` so a node with
        thousands of seen peers doesn't try to push them all into
        one RRset (resolvers MUST handle multi-value TXT, but real-
        world authoritative APIs and recursors get unhappy past a
        few KB).

        Returns the number of TXT values published.
        """
        if self._record_writer is None or not self._cfg.dns_zone:
            return 0
        try:
            name = seen_rrset_name(self._cfg.dns_zone)
        except ValueError:
            return 0
        try:
            rows = self._store.list_recent(limit=self._cfg.max_seen_publish, now=now_i)
        except Exception:
            log.exception("SeenStore.list_recent raised; skipping seen-graph publish")
            return 0

        # Replace-OUR-OWN-wires semantic. ``DNSRecordWriter.publish_txt_record``
        # is APPEND, so without explicit eviction the old wires
        # linger until TTL expiry and consumers see stale + fresh
        # peers mixed (M9.1.3 P1 — discovery convergence stalls
        # after a few ticks).
        #
        # Round-19 P1: a whole-RRset delete (``value=None``) wipes
        # sibling cluster nodes that publish into the same shared
        # ``_dnsmesh-seen.<shared-zone>``. We track exactly which
        # wires THIS node published last tick and evict only those —
        # peers' contributions stay intact.
        own_spk_hex = self._crypto.get_signing_public_key_bytes().hex()
        next_wires: Set[str] = set()
        for row in rows:
            wire = getattr(row, "wire", None)
            if not isinstance(wire, str) or not wire:
                continue
            # Self never belongs in our own seen RRset. Seen is
            # "OTHER nodes I have heard from" — listing ourselves
            # there is both semantically wrong (an operator can't
            # vouch for their own liveness via their own gossip
            # claim) and a foot-gun: aggregators that build a
            # discovery graph from seen-edges would draw a self-
            # loop. Defensive filter even though ``_fetch_and_ingest``
            # also drops self at the source — a future bootstrap
            # path that lands self in the store via some other route
            # (manifest re-ingest, admin import, …) shouldn't leak
            # into DNS.
            row_spk_hex = getattr(row, "operator_spk_hex", "") or ""
            if row_spk_hex.lower() == own_spk_hex.lower():
                continue
            next_wires.add(wire)

        # One-shot startup sweep of orphan seen-wires from prior
        # processes — see ``_seen_orphan_sweep_done`` docstring.
        if not self._seen_orphan_sweep_done:
            try:
                self._sweep_orphan_seen_wires(name, next_wires=next_wires, now=now_i)
            except Exception:
                log.exception("orphan seen-wire sweep raised for %s", name)
            # Mark done regardless of success so a persistent error
            # in the sweep path doesn't re-run on every tick.
            self._seen_orphan_sweep_done = True
        # Anything we published last time but won't republish now
        # has dropped out (peer aged out of SeenStore). Evict those
        # specific values from the RRset.
        for stale in self._last_seen_wires - next_wires:
            try:
                self._record_writer.delete_txt_record(name, value=stale)
            except Exception:
                log.exception(
                    "seen-graph stale-wire eviction raised for %s; continuing",
                    name,
                )

        published = 0
        published_now: Set[str] = set()
        for wire in next_wires:
            try:
                ok = bool(
                    self._record_writer.publish_txt_record(
                        name, wire, ttl=self._cfg.ttl_seconds
                    )
                )
            except Exception:
                log.exception("seen-graph publish raised for %s", name)
                continue
            if ok:
                published += 1
                published_now.add(wire)
        # Track only what actually landed — wires we tried to publish
        # but the writer rejected stay out of the eviction set so the
        # next tick won't try to delete something we never wrote.
        self._last_seen_wires = published_now
        return published

    # ------------------------------------------------------------------
    # harvest
    # ------------------------------------------------------------------

    def _fetch_and_ingest(self, zone: str, now_i: int) -> bool:
        """Query ``_dnsmesh-heartbeat.<zone>`` AND ``_dnsmesh-seen.<zone>``,
        ingest verified wires from both into the local SeenStore.

        The two RRsets carry distinct populations:
          - heartbeat: the peer's own signed liveness record.
          - seen: the peer's republished view of OTHER nodes it has
            seen recently (M9.1.3 transitive discovery).

        Without harvesting the seen-graph, ``A`` seeded with ``B``
        never learns about ``C`` even when ``B`` has been talking to
        ``C``. Codex P2 — restores the transitive convergence M9.1.3
        was supposed to deliver.

        Truncates the ingest set at ``max_gossip_per_response`` PER
        RRset so a hostile zone can't force unbounded crypto work by
        returning a giant batch.
        """
        if self._dns_reader is None:
            return False
        names: List[str] = []
        try:
            names.append(heartbeat_rrset_name(zone))
        except ValueError:
            return False
        try:
            names.append(seen_rrset_name(zone))
        except ValueError:
            pass

        # Drop wires the peer is gossiping back to us about ourselves
        # at ingest time. Without this filter, a peer that has us in
        # its own seen-graph (which is the common case once federation
        # converges) seeds our local SeenStore with our own wire under
        # ``(operator_spk_hex, endpoint)`` — and then ``_publish_seen_graph``
        # republishes it under our own ``_dnsmesh-seen.<zone>``. That
        # creates a self-loop in the federation discovery graph and,
        # in fleets where many peers see us, can also push the local
        # seen RRset over the recursive-resolver UDP buffer. Drop at
        # the source so self never lands in the store.
        own_spk = self._crypto.get_signing_public_key_bytes()

        accepted = 0
        for name in names:
            try:
                records = self._dns_reader.query_txt_record(name)
            except Exception:
                log.info("heartbeat DNS query to %s failed", name)
                continue
            if not records:
                continue
            for wire in records[: self._cfg.max_gossip_per_response]:
                if not isinstance(wire, str):
                    continue
                # Cheap pre-check: parse-and-verify is the same call
                # ``SeenStore.accept`` does, but here we use it solely
                # to read ``operator_spk`` so we can short-circuit on
                # self before the store insert. A wire that fails
                # verification here will also fail there; ``accept``
                # returns None and we correctly don't count it.
                rec = HeartbeatRecord.parse_and_verify(wire, now=now_i)
                if rec is not None and bytes(rec.operator_spk) == own_spk:
                    continue
                try:
                    if self._store.accept(wire, remote_addr=zone, now=now_i):
                        accepted += 1
                except Exception:
                    log.exception("SeenStore.accept raised for wire from %s", name)
        return accepted > 0

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _build_own_wire(self, now_i: int) -> str:
        hb = HeartbeatRecord(
            endpoint=self._cfg.self_endpoint,
            operator_spk=self._crypto.get_signing_public_key_bytes(),
            version=self._cfg.version,
            ts=now_i,
            exp=now_i + self._cfg.ttl_seconds,
            capabilities=self._cfg.capabilities,
            claim_provider_zone=self._cfg.claim_provider_zone,
        )
        return hb.sign(self._crypto)

    def _build_seed_zones(self) -> List[str]:
        """Assemble the per-tick zone list to harvest.

        Order = configured seeds first, then cluster peers (already
        trusted via the signed manifest), then gossip-learned peers
        from the seen-store. De-duped preserving order, capped at
        ``max_peers``. The node's own zone is filtered out so we
        never query ourselves.
        """
        self_zone = (self._cfg.dns_zone or "").lower()
        seen: Set[str] = set()
        out: List[str] = []

        def _add(raw: str) -> None:
            zone = _zone_from_seed(raw)
            if not zone or zone == self_zone or zone in seen:
                return
            seen.add(zone)
            out.append(zone)

        for seed in self._cfg.seed_zones:
            _add(seed)
        try:
            for u in self._cluster_peers_provider():
                _add(u)
        except Exception:
            log.exception(
                "cluster_peers_provider raised; continuing with seeds + gossip"
            )
        # Gossip-learned: pull peer zones directly from the wires in
        # the seen-store. ``list_zones_for_harvest`` reads the
        # operator-advertised ``claim_provider_zone`` field
        # (M9.1.1) and only falls back to endpoint-host derivation
        # for legacy peers. This matters when a node's HTTP host
        # sits beneath the served zone (e.g. api.example.com /
        # example.com) — the previous endpoint-host projection
        # produced ``api.example.com`` and the worker queried the
        # wrong RRset, breaking transitive discovery (codex
        # round-3 P2).
        try:
            for zone in self._store.list_zones_for_harvest(
                limit=self._cfg.max_peers * 2, now=None
            ):
                _add(zone)
        except AttributeError:
            # Older SeenStore that doesn't have the new helper —
            # fall back to the URL-host projection.
            try:
                for u in self._store.list_for_ping(
                    limit=self._cfg.max_peers * 2, now=None
                ):
                    _add(u)
            except Exception:
                log.exception("SeenStore.list_for_ping raised; continuing")
        except Exception:
            log.exception("SeenStore.list_zones_for_harvest raised; continuing")

        return out[: self._cfg.max_peers]
