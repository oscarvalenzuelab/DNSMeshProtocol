"""Heartbeat worker — periodically emits this node's heartbeat + gossip.

M5.8 phase 4. Runs as a daemon thread inside the node process when
``DMP_HEARTBEAT_ENABLED=1``. Each tick (default every 5 minutes):

1. Build + sign the node's own ``HeartbeatRecord`` using the operator
   Ed25519 key loaded at startup.
2. Build the outbound ping list: seeds ∪ cluster peers ∪
   ``SeenStore.list_for_ping`` (gossip-learned), de-duplicated and
   capped at ``max_peers``.
3. POST ``{"wire": own_wire}`` to each peer's ``/v1/heartbeat``.
4. On 200, parse the response's ``seen`` array and hand each wire to
   ``SeenStore.accept`` (which verifies + dedupes — a hostile peer
   cannot poison the store because signatures gate every row).

Failures are logged at INFO and don't stop the worker. A peer that
returns 4xx/5xx stays in the list but gets a cooldown on the next
tick so a consistently-broken URL doesn't hog budget.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Set

from dmp.core.crypto import DMPCrypto
from dmp.core.heartbeat import HeartbeatRecord
from dmp.server.heartbeat_store import SeenStore

log = logging.getLogger(__name__)


# Defaults — tuneable via env on DMPNode startup.
DEFAULT_INTERVAL_SECONDS = 300  # 5 minutes
DEFAULT_TTL_SECONDS = 86_400  # 24 hours
DEFAULT_MAX_PEERS = 25
DEFAULT_HTTP_TIMEOUT_SECONDS = 10
# Cooldown applied to a peer that fails a single tick. Next tick we
# skip it. Counter resets on successful contact.
DEFAULT_FAILURE_COOLDOWN_TICKS = 1


@dataclass(frozen=True)
class HeartbeatWorkerConfig:
    """Plain-data config the worker reads at construction.

    The worker owns no mutable config — a re-config requires a
    restart, matching the pattern the rest of DMPNode uses.
    """

    self_endpoint: str
    version: str
    seed_peers: tuple = ()
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_peers: int = DEFAULT_MAX_PEERS
    http_timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS
    failure_cooldown_ticks: int = DEFAULT_FAILURE_COOLDOWN_TICKS


class HeartbeatWorker:
    """Background heartbeat emitter + gossip ingester.

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
        cluster_peers_provider: Optional[Callable[[], Iterable[str]]] = None,
        http_poster: Optional[Callable[[str, dict, float], Optional[dict]]] = None,
    ) -> None:
        """Construct the worker.

        ``cluster_peers_provider`` is an optional zero-arg callable
        that returns the current set of cluster peer endpoints
        (typically reads from the same cluster manifest the
        anti-entropy worker uses). None in solo-node mode.

        ``http_poster`` is the HTTP transport. Default is a thin
        requests wrapper; tests inject a stub.
        """
        self._cfg = config
        self._crypto = operator_crypto
        self._store = seen_store
        self._cluster_peers_provider = cluster_peers_provider or (lambda: ())
        self._http_poster = http_poster or _default_http_poster

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Cooldown map: peer URL -> ticks-until-retry. A peer that
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
            "heartbeat worker started: self=%s interval=%ds max_peers=%d",
            self._cfg.self_endpoint,
            self._cfg.interval_seconds,
            self._cfg.max_peers,
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
            # Sleep respecting the stop event so shutdown is prompt.
            self._stop_event.wait(self._cfg.interval_seconds)

    def tick_once(self, *, now: Optional[int] = None) -> int:
        """Run one tick synchronously. Returns count of successful
        POSTs. Exposed for tests."""
        now_i = int(now) if now is not None else int(time.time())
        # Build + sign own heartbeat. Worker is in-process, so any
        # sign error is a config bug worth surfacing; we log and
        # skip the tick rather than crash the daemon.
        try:
            own_wire = self._build_own_wire(now_i)
        except ValueError:
            log.exception("heartbeat self-wire build failed; skipping tick")
            return 0

        # Assemble the ping list: seeds + gossip-learned + cluster
        # peers. De-dup preserving order; cap at max_peers.
        peers = self._build_peer_list(now_i)
        if not peers:
            # Solo node with no seeds — still valid, just nothing
            # to send yet. A peer pushing to us will populate the
            # store and future ticks will gossip outward.
            return 0

        successes = 0
        for peer in peers:
            # Cooldown.
            cd = self._cooldown.get(peer, 0)
            if cd > 0:
                self._cooldown[peer] = cd - 1
                continue
            response = self._http_poster(
                peer + "/v1/heartbeat",
                {"wire": own_wire},
                self._cfg.http_timeout_seconds,
            )
            if response is None or not isinstance(response, dict):
                self._cooldown[peer] = self._cfg.failure_cooldown_ticks
                log.info("heartbeat post to %s failed", peer)
                continue
            # Success path: ingest any gossip response.
            self._cooldown.pop(peer, None)
            successes += 1
            seen_wires = response.get("seen") or []
            if isinstance(seen_wires, list):
                for w in seen_wires:
                    if isinstance(w, str):
                        self._store.accept(
                            w, remote_addr=peer, now=now_i
                        )
        return successes

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
        )
        return hb.sign(self._crypto)

    def _build_peer_list(self, now_i: int) -> List[str]:
        """Assemble the outbound ping list for this tick.

        Order = seeds first (known-good starting points), then
        cluster peers (already trusted via the signed manifest), then
        gossip-learned from the seen store. De-duped preserving
        order, cap at max_peers. The node's own endpoint is filtered
        out so we never ping ourselves.
        """
        self_ep = self._cfg.self_endpoint.rstrip("/")
        seen: Set[str] = set()
        out: List[str] = []

        def _add(url: str) -> None:
            if not isinstance(url, str):
                return
            norm = url.rstrip("/")
            if not norm or norm == self_ep:
                return
            if norm in seen:
                return
            seen.add(norm)
            out.append(norm)

        for u in self._cfg.seed_peers:
            _add(u)
        try:
            for u in self._cluster_peers_provider():
                _add(u)
        except Exception:
            log.exception(
                "cluster_peers_provider raised; continuing with seeds + gossip"
            )
        # Gossip-learned: pull twice the cap so we still have
        # candidates after self + dup elimination.
        try:
            for u in self._store.list_for_ping(
                limit=self._cfg.max_peers * 2, now=now_i
            ):
                _add(u)
        except Exception:
            log.exception("SeenStore.list_for_ping raised; continuing")

        return out[: self._cfg.max_peers]


# ---------------------------------------------------------------------------


def _default_http_poster(
    url: str, body: dict, timeout: float
) -> Optional[dict]:
    """Default HTTP POST. Returns decoded JSON on 200, None otherwise.

    Deferred requests import so importing this module in a minimal
    test environment doesn't pull the whole requests dependency tree
    just for type-checking.
    """
    import requests

    try:
        r = requests.post(url, json=body, timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        parsed = r.json()
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None
