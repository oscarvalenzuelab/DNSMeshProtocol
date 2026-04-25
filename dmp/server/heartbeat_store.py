"""SeenStore — sqlite table of verified heartbeats this node has received.

M5.8 phase 2. Each row carries the full signed wire string so a
later GET /v1/nodes/seen can hand it back verbatim and the consumer
can re-verify the signature independently. We never store "trust-me"
metadata — only the signed source of truth.

Primary key is ``(operator_spk, endpoint)``: a repeat heartbeat from
the same node simply overwrites the older row, keeping the store
bounded by the number of distinct nodes we've ever heard from, not
by the number of heartbeats received. A retention sweep evicts rows
whose ``exp`` is far enough in the past that the operator has clearly
gone dark.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from dmp.core.heartbeat import HeartbeatRecord


def _zone_from_endpoint_host(endpoint: str) -> str:
    """Best-effort URL-host fallback for peers that don't yet advertise
    ``claim_provider_zone``. Returns lowercase bare hostname or "".
    """
    if not isinstance(endpoint, str) or not endpoint:
        return ""
    try:
        parts = urlsplit(endpoint if "://" in endpoint else "https://" + endpoint)
    except ValueError:
        return ""
    host = (parts.hostname or "").strip().lower()
    if not host:
        return ""
    if host.replace(".", "").isdigit() or ":" in host:
        return ""
    return host

# Default retention — how long past `exp` we keep a row before the
# sweep evicts it. Tuned so a brief operator outage (a few hours)
# doesn't immediately disappear the node from the directory.
DEFAULT_RETENTION_SECONDS = 72 * 3600  # 3 days

# Hard ceiling on the number of live rows. A flood of distinct
# (operator, endpoint) pairs from a malicious crawler can't grow
# the store unboundedly. On insert-past-cap we evict by
# received_at ASC (oldest first).
DEFAULT_MAX_ROWS = 10_000


_SCHEMA = """
CREATE TABLE IF NOT EXISTS heartbeats_seen (
    operator_spk_hex  TEXT NOT NULL,
    endpoint          TEXT NOT NULL,
    wire              TEXT NOT NULL,
    ts                INTEGER NOT NULL,
    exp               INTEGER NOT NULL,
    version           TEXT NOT NULL DEFAULT '',
    received_at       INTEGER NOT NULL,
    remote_addr       TEXT,
    PRIMARY KEY (operator_spk_hex, endpoint)
);

CREATE INDEX IF NOT EXISTS idx_hb_ts          ON heartbeats_seen(ts DESC);
CREATE INDEX IF NOT EXISTS idx_hb_exp         ON heartbeats_seen(exp);
CREATE INDEX IF NOT EXISTS idx_hb_received_at ON heartbeats_seen(received_at);
"""


@dataclass(frozen=True)
class SeenRow:
    operator_spk_hex: str
    endpoint: str
    wire: str
    ts: int
    exp: int
    version: str
    received_at: int
    remote_addr: Optional[str]


class SeenStore:
    """Thread-safe sqlite-backed store of received + verified heartbeats.

    The caller must have ALREADY run HeartbeatRecord.parse_and_verify
    on the wire before calling :meth:`accept` — this layer trusts its
    input. parse_and_verify already enforces freshness, low-order
    block, and signature integrity.
    """

    def __init__(
        self,
        db_path: str,
        *,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
        max_rows: int = DEFAULT_MAX_ROWS,
    ) -> None:
        self._path = db_path
        self._retention = int(retention_seconds)
        self._max_rows = int(max_rows)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # writes
    # ------------------------------------------------------------------

    def accept(
        self,
        wire: str,
        *,
        remote_addr: str = "",
        now: Optional[int] = None,
        ts_skew_seconds: Optional[int] = None,
    ) -> Optional[HeartbeatRecord]:
        """Verify + store a heartbeat wire. Returns the record on success.

        Signature / freshness / low-order-pubkey checks happen
        INSIDE this call via ``HeartbeatRecord.parse_and_verify``.
        A caller cannot accidentally persist an unverified wire —
        the API takes the wire string only, and any verification
        failure short-circuits to ``None`` without touching the DB.

        The wire string is stored verbatim (not re-serialized from
        the parsed record) so a downstream consumer of
        ``GET /v1/nodes/seen`` sees the operator's exact signature
        bytes, not our best-guess reconstruction.

        Returns:
            The parsed ``HeartbeatRecord`` on accept, ``None`` when
            parse_and_verify rejected the wire.
        """
        now_i = int(now) if now is not None else int(time.time())
        kwargs = {"now": now_i}
        if ts_skew_seconds is not None:
            kwargs["ts_skew_seconds"] = int(ts_skew_seconds)
        record = HeartbeatRecord.parse_and_verify(wire, **kwargs)
        if record is None:
            return None

        spk_hex = bytes(record.operator_spk).hex()
        with self._lock:
            # Row-count cap enforcement: before counting, drop stale
            # rows so the cap is over LIVE rows, not "ever-received"
            # rows. Otherwise a pile of unswept expired rows would
            # cause a fresh legitimate accept to evict another live
            # node. Codex phase-2 P2 fix.
            self._conn.execute("DELETE FROM heartbeats_seen WHERE exp <= ?", (now_i,))
            self._conn.execute(
                """INSERT INTO heartbeats_seen
                   (operator_spk_hex, endpoint, wire, ts, exp, version,
                    received_at, remote_addr)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(operator_spk_hex, endpoint) DO UPDATE SET
                     wire = excluded.wire,
                     ts = excluded.ts,
                     exp = excluded.exp,
                     version = excluded.version,
                     received_at = excluded.received_at,
                     remote_addr = excluded.remote_addr
                   WHERE excluded.ts >= heartbeats_seen.ts""",
                (
                    spk_hex,
                    record.endpoint,
                    wire,
                    record.ts,
                    record.exp,
                    record.version,
                    now_i,
                    remote_addr or None,
                ),
            )
            # Now cap is checked over live rows only (stale already
            # pruned above). Oldest-received-first eviction.
            count_row = self._conn.execute(
                "SELECT COUNT(*) FROM heartbeats_seen"
            ).fetchone()
            if count_row and count_row[0] > self._max_rows:
                over = count_row[0] - self._max_rows
                self._conn.execute(
                    """DELETE FROM heartbeats_seen
                       WHERE (operator_spk_hex, endpoint) IN (
                         SELECT operator_spk_hex, endpoint
                         FROM heartbeats_seen
                         ORDER BY received_at ASC
                         LIMIT ?
                       )""",
                    (over,),
                )
            self._conn.commit()
        return record

    def sweep_expired(self, now: Optional[int] = None) -> int:
        """Delete rows whose `exp` is older than `now - retention`.

        Returns the count deleted. Intended to be called periodically
        (the node's cleanup worker) rather than on every insert.
        """
        now_i = int(now) if now is not None else int(time.time())
        cutoff = now_i - self._retention
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM heartbeats_seen WHERE exp < ?", (cutoff,)
            )
            deleted = cur.rowcount
            self._conn.commit()
        return deleted

    def forget(self, operator_spk_hex: str, endpoint: str) -> bool:
        """Drop a specific row. Returns True iff a row was removed.

        Operator-facing escape hatch — e.g. the operator has learned
        a listed node's key was compromised and wants the directory
        to stop re-exporting its (genuinely-signed) heartbeats.
        """
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM heartbeats_seen WHERE operator_spk_hex=? AND endpoint=?",
                (operator_spk_hex, endpoint),
            )
            removed = cur.rowcount > 0
            self._conn.commit()
        return removed

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------

    def list_recent(
        self,
        *,
        limit: int = 500,
        now: Optional[int] = None,
    ) -> List[SeenRow]:
        """Return rows not yet expired (``exp > now``), newest ``ts`` first.

        No mutation — reading this after a stale-but-unswept row is
        still in the DB must NOT return it. `GET /v1/nodes/seen`
        calls this; an aggregator consuming the endpoint must
        re-verify every entry on its side regardless, but filtering
        at source is a courtesy.
        """
        now_i = int(now) if now is not None else int(time.time())
        limit = max(0, int(limit))
        rows = self._conn.execute(
            """SELECT operator_spk_hex, endpoint, wire, ts, exp, version,
                      received_at, remote_addr
               FROM heartbeats_seen
               WHERE exp > ?
               ORDER BY ts DESC
               LIMIT ?""",
            (now_i, limit),
        ).fetchall()
        return [SeenRow(*r) for r in rows]

    def list_for_ping(
        self,
        *,
        limit: int,
        now: Optional[int] = None,
    ) -> List[str]:
        """Return up to `limit` endpoint URLs from recently-seen nodes.

        Used by the heartbeat worker when expanding its ping list
        beyond the seed set. Caller owns de-duplication and capping
        against its own list (which includes seeds + cluster peers).
        """
        now_i = int(now) if now is not None else int(time.time())
        limit = max(0, int(limit))
        rows = self._conn.execute(
            """SELECT endpoint
               FROM heartbeats_seen
               WHERE exp > ?
               ORDER BY ts DESC
               LIMIT ?""",
            (now_i, limit),
        ).fetchall()
        return [r[0] for r in rows]

    def list_zones_for_harvest(
        self,
        *,
        limit: int,
        now: Optional[int] = None,
    ) -> List[str]:
        """Return up to ``limit`` peer DNS zones for transitive
        discovery (M9 codex round-3 P2).

        Reads the operator-advertised ``claim_provider_zone`` field
        directly off each verified wire (M9.1.1). Falls back to the
        endpoint host when the wire field is empty (legacy / opt-out
        peers). Endpoint-host derivation is wrong in general — a node
        publishing under ``example.com`` may serve HTTP at
        ``api.example.com`` — so the wire-zone path is preferred
        when present.
        """
        now_i = int(now) if now is not None else int(time.time())
        limit = max(0, int(limit))
        rows = self._conn.execute(
            """SELECT wire, endpoint
               FROM heartbeats_seen
               WHERE exp > ?
               ORDER BY ts DESC
               LIMIT ?""",
            (now_i, limit),
        ).fetchall()
        out: List[str] = []
        for wire, endpoint in rows:
            zone = ""
            try:
                rec = HeartbeatRecord.parse_and_verify(wire, now=now_i)
                if rec is not None and rec.claim_provider_zone:
                    zone = rec.claim_provider_zone.strip().lower().rstrip(".")
            except Exception:
                zone = ""
            if not zone:
                # Fallback — derive from endpoint host. Same path as
                # the legacy heartbeat-worker behavior; covers older
                # peers that don't advertise the field yet.
                zone = _zone_from_endpoint_host(endpoint)
            if zone:
                out.append(zone)
        return out

    def count(self) -> int:
        with self._lock:
            r = self._conn.execute("SELECT COUNT(*) FROM heartbeats_seen").fetchone()
        return int(r[0]) if r else 0

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SeenStore":  # pragma: no cover
        return self

    def __exit__(self, *_a) -> None:  # pragma: no cover
        self.close()
