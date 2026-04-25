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
        if not zones:
            return 0

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
        return successes

    # ------------------------------------------------------------------
    # publish
    # ------------------------------------------------------------------

    def _publish_own(self, now_i: int) -> bool:
        """Publish this node's signed heartbeat at
        ``_dnsmesh-heartbeat.<dns_zone>``. Returns True on success.
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
        try:
            ok = bool(
                self._record_writer.publish_txt_record(
                    name, wire, ttl=self._cfg.ttl_seconds
                )
            )
        except Exception:
            log.exception("heartbeat self-publish raised")
            return False
        if not ok:
            log.info("heartbeat self-publish to %s returned False", name)
        return ok

    # ------------------------------------------------------------------
    # harvest
    # ------------------------------------------------------------------

    def _fetch_and_ingest(self, zone: str, now_i: int) -> bool:
        """Query ``_dnsmesh-heartbeat.<zone>`` and ingest verified wires.

        Returns True if at least one wire was accepted. Truncates the
        ingest set at ``max_gossip_per_response`` so a hostile zone
        can't force unbounded crypto work by returning a giant RRset.
        """
        if self._dns_reader is None:
            return False
        try:
            name = heartbeat_rrset_name(zone)
        except ValueError:
            return False
        try:
            records = self._dns_reader.query_txt_record(name)
        except Exception:
            log.info("heartbeat DNS query to %s failed", name)
            return False
        if not records:
            return False
        accepted = 0
        for wire in records[: self._cfg.max_gossip_per_response]:
            if not isinstance(wire, str):
                continue
            try:
                if self._store.accept(wire, remote_addr=zone, now=now_i):
                    accepted += 1
            except Exception:
                log.exception(
                    "SeenStore.accept raised for wire from %s", zone
                )
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
        # Gossip-learned: pull endpoints from seen-store and project
        # to zones. Pull twice the cap so we still have candidates
        # after self + dup elimination.
        try:
            for u in self._store.list_for_ping(
                limit=self._cfg.max_peers * 2, now=None
            ):
                _add(u)
        except Exception:
            log.exception("SeenStore.list_for_ping raised; continuing")

        return out[: self._cfg.max_peers]
