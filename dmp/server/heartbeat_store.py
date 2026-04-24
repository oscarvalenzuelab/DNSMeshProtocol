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

from dmp.core.heartbeat import HeartbeatRecord

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
        record: HeartbeatRecord,
        wire: str,
        *,
        remote_addr: str = "",
        now: Optional[int] = None,
    ) -> None:
        """Store a verified heartbeat. Upserts on (operator_spk, endpoint).

        No signature re-check here — the caller is responsible for
        running ``HeartbeatRecord.parse_and_verify`` first. Accepting
        the wire string verbatim (rather than re-serializing from the
        record's fields) is deliberate: it preserves the operator's
        exact signature bytes so a downstream verifier sees what the
        signer emitted. Re-serializing would force every consumer to
        trust our serialization to produce byte-identical output.
        """
        now_i = int(now) if now is not None else int(time.time())
        spk_hex = bytes(record.operator_spk).hex()
        with self._lock:
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
            # Enforce the row-count cap opportunistically on insert.
            # Oldest-received-first eviction. Only evict when we're
            # over cap AND at least one row qualifies.
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
