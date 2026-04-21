"""SqliteMailboxStore — persistent TTL-aware DNSRecordStore.

One row per (name, value) pair with an expires_at cutoff. Reads filter on
expires_at > now, so expired records are invisible even before the cleanup
worker reaps them. The cleanup worker is a separate concern
(`dmp.server.cleanup.CleanupWorker`) that periodically calls
`cleanup_expired()` to bound disk usage.

Thread-safe via a per-store RLock around a single shared connection. Sqlite's
WAL journaling is enabled so readers don't block a long writer.

Each row also carries a `stored_ts` column — the unix-**milliseconds** moment
at which the local node first accepted the write. Distinct from `created_at`
(the same moment in seconds; kept as a separate column so a future schema
change can carry the *authoritative publisher's* timestamp in `created_at`
while `stored_ts` remains the local receiver's view). The anti-entropy sync
worker uses `stored_ts` as the watermark so a peer catching up sees records
ordered by local arrival, not by upstream publish time. Millisecond
resolution keeps pagination correct even when >limit records land in the
same second.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass
from threading import RLock
from typing import Iterable, List, Optional, Tuple

from dmp.network.base import DNSRecordStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    name       TEXT NOT NULL,
    value      TEXT NOT NULL,
    ttl        INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    stored_ts  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (name, value)
);
CREATE INDEX IF NOT EXISTS idx_records_name      ON records(name);
CREATE INDEX IF NOT EXISTS idx_records_expires   ON records(expires_at);
CREATE INDEX IF NOT EXISTS idx_records_stored_ts ON records(stored_ts);
"""


@dataclass(frozen=True)
class StoredRecord:
    """One row from the store plus the data the sync worker needs.

    Kept as a small dataclass so `iter_records_since` callers aren't
    juggling anonymous 4-tuples. `ttl_remaining` is not the on-disk ttl
    column; it is the seconds remaining until expiry at the time of the
    read, which is what a pulling peer should re-publish with.
    """

    name: str
    value: str
    ttl_remaining: int
    stored_ts: int

    @property
    def record_hash(self) -> str:
        """SHA-256 hex digest of the TXT value. Stable across nodes."""
        return hashlib.sha256(self.value.encode("utf-8")).hexdigest()


class SqliteMailboxStore(DNSRecordStore):
    """DNS TXT record store backed by a sqlite database.

    Call sites treat this exactly like InMemoryDNSStore; the contract is
    `DNSRecordStore`. The difference is that records survive process restart
    and expire automatically based on their `ttl`.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = RLock()
        # check_same_thread=False because we serialize through _lock ourselves.
        self._conn = sqlite3.connect(
            db_path, isolation_level=None, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Best-effort schema migrations.

        Two evolutions land here:

        - `stored_ts` was added in M2.4 for the anti-entropy sync
          worker. Older DBs created before M2.4 don't have the column;
          we add it (and its index) so reopening a pre-M2.4 DB doesn't
          crash. Initial rows are backfilled from `created_at`.
        - M2.4-followup: `stored_ts` was upgraded from unix-seconds to
          unix-milliseconds. Rows that were written by the interim
          M2.4-seconds code carry small values (< ~10^12). We detect
          that and multiply in place so same-second pagination stays
          correct going forward. Fresh DBs skip this branch entirely.
        """
        with self._lock:
            cols = {
                row[1]
                for row in self._conn.execute("PRAGMA table_info(records)").fetchall()
            }
            if "stored_ts" not in cols:
                # Pre-M2.4 DB. Add the column and backfill from created_at
                # (seconds), which the next step will upgrade to ms.
                self._conn.execute(
                    "ALTER TABLE records ADD COLUMN stored_ts INTEGER NOT NULL "
                    "DEFAULT 0"
                )
                self._conn.execute(
                    "UPDATE records SET stored_ts = created_at WHERE stored_ts = 0"
                )
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_records_stored_ts "
                    "ON records(stored_ts)"
                )

            # Seconds→ms detection. Any stored_ts below the year-2001-in-ms
            # threshold (10^12) must be a seconds value from the interim
            # M2.4 code, so bump it. Zero values (which _SCHEMA defaults to)
            # are left alone — they mean "never synced" and must stay a
            # valid below-all-watermarks sentinel.
            _MS_THRESHOLD = 1_000_000_000_000  # year 2001 in ms
            self._conn.execute(
                "UPDATE records SET stored_ts = stored_ts * 1000 "
                "WHERE stored_ts > 0 AND stored_ts < ?",
                (_MS_THRESHOLD,),
            )

    # ---- DNSRecordStore contract ------------------------------------------

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        now_s = int(time.time())
        now_ms = int(time.time() * 1000)
        expires = now_s + int(ttl)
        with self._lock:
            # Append semantics. DNS natively supports multiple TXT records at
            # one name (an RRset); the prior "replace all" behavior let an
            # attacker who could reach the publish endpoint wipe other
            # senders' manifests out of a recipient's mailbox slot. With
            # append, an attacker can *add* records but cannot *remove*
            # legitimate ones. The PRIMARY KEY (name, value) means an honest
            # duplicate republish refreshes the TTL without growing the row
            # set. `stored_ts` records the millisecond at which this *node*
            # accepted the write; sync peers use it as their cursor and the
            # ms resolution keeps pagination correct even when many writes
            # land inside the same second.
            self._conn.execute(
                "INSERT OR REPLACE INTO records "
                "(name, value, ttl, created_at, expires_at, stored_ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, value, int(ttl), now_s, expires, now_ms),
            )
        return True

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        with self._lock:
            cur = (
                self._conn.execute(
                    "DELETE FROM records WHERE name = ? AND value = ?",
                    (name, value),
                )
                if value is not None
                else self._conn.execute("DELETE FROM records WHERE name = ?", (name,))
            )
            return cur.rowcount > 0

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        now = int(time.time())
        with self._lock:
            rows = self._conn.execute(
                "SELECT value FROM records WHERE name = ? AND expires_at > ? "
                "ORDER BY created_at",
                (name, now),
            ).fetchall()
        if not rows:
            return None
        return [row[0] for row in rows]

    # ---- admin helpers -----------------------------------------------------

    def cleanup_expired(self, now: Optional[int] = None) -> int:
        """Remove records whose `expires_at` has passed. Returns rows deleted."""
        cutoff = int(time.time()) if now is None else int(now)
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM records WHERE expires_at <= ?", (cutoff,)
            )
            return cur.rowcount

    def record_count(self, include_expired: bool = False) -> int:
        with self._lock:
            if include_expired:
                row = self._conn.execute("SELECT COUNT(*) FROM records").fetchone()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM records WHERE expires_at > ?",
                    (int(time.time()),),
                ).fetchone()
        return int(row[0])

    def list_names(self) -> List[str]:
        now = int(time.time())
        with self._lock:
            rows = self._conn.execute(
                "SELECT DISTINCT name FROM records WHERE expires_at > ? "
                "ORDER BY name",
                (now,),
            ).fetchall()
        return [row[0] for row in rows]

    # ---- anti-entropy support ---------------------------------------------

    def iter_records_since(
        self,
        since_ts: int = 0,
        *,
        limit: Optional[int] = None,
        cursor: Optional[Tuple[int, str]] = None,
    ) -> List[StoredRecord]:
        """Return non-expired records strictly past the given cursor,
        oldest first, ordered by (stored_ts ASC, name ASC, value ASC).

        Used by the anti-entropy digest endpoint. There are two entry
        shapes for historical reasons:

        - ``cursor=(ts, name)`` — the compound cursor added in the M2.4
          follow-up. Returns rows where ``stored_ts > ts`` OR
          (``stored_ts == ts`` AND ``name > name``). This is the only
          pagination shape that remains correct when > ``limit`` rows
          land in the same millisecond: a plain ``stored_ts > cursor_ts``
          either skips the tail (advance past the ms) or replays the
          same page forever (keep the old ms).
        - ``since_ts=<ms>`` — the legacy shape. Degenerates to
          ``cursor=(since_ts, "")``; since every real name is strictly
          greater than the empty string, the name comparison collapses
          and we recover the original ``stored_ts > since_ts`` behavior.

        Passing both raises ``ValueError`` so callers don't accidentally
        double-dip.

        `limit` caps the batch size; None means no cap. The cap is enforced
        at the SQL layer so a peer asking for 10 records on a million-row
        store doesn't read the world into memory.
        """
        if cursor is not None and since_ts:
            raise ValueError("pass cursor OR since_ts, not both")
        if cursor is None:
            cursor = (int(since_ts), "")
        cur_ts, cur_name = int(cursor[0]), str(cursor[1])
        now = int(time.time())
        with self._lock:
            sql = (
                "SELECT name, value, expires_at, stored_ts FROM records "
                "WHERE (stored_ts > ? OR (stored_ts = ? AND name > ?)) "
                "AND expires_at > ? "
                "ORDER BY stored_ts ASC, name ASC, value ASC"
            )
            params: Tuple = (cur_ts, cur_ts, cur_name, now)
            if limit is not None:
                sql += " LIMIT ?"
                params = params + (int(limit),)
            rows = self._conn.execute(sql, params).fetchall()
        out: List[StoredRecord] = []
        for name, value, expires_at, stored_ts in rows:
            ttl_remaining = max(0, int(expires_at) - now)
            out.append(
                StoredRecord(
                    name=name,
                    value=value,
                    ttl_remaining=ttl_remaining,
                    stored_ts=int(stored_ts),
                )
            )
        return out

    def get_records_by_name(self, names: Iterable[str]) -> List[StoredRecord]:
        """Return all non-expired records whose name is in `names`.

        Used by the anti-entropy pull endpoint. Expired records are
        filtered out — a peer that asks for a record that just expired
        simply doesn't get it back (matches query_txt_record semantics).
        Names that don't exist are silently absent from the result; the
        caller distinguishes missing-from-expired-or-unknown by
        requested-minus-returned.
        """
        # Deduplicate and materialize — sqlite parameter lists can't handle
        # an arbitrary iterable and we want a stable order.
        unique = list(dict.fromkeys(names))
        if not unique:
            return []
        now = int(time.time())
        out: List[StoredRecord] = []
        with self._lock:
            # Chunk the IN() to avoid SQLITE_MAX_VARIABLE_NUMBER (default 999)
            # and to keep plan-complexity predictable. 256 is the pull-endpoint
            # cap so one chunk covers the common case.
            for i in range(0, len(unique), 256):
                batch = unique[i : i + 256]
                placeholders = ",".join("?" * len(batch))
                sql = (
                    f"SELECT name, value, expires_at, stored_ts FROM records "
                    f"WHERE name IN ({placeholders}) AND expires_at > ? "
                    f"ORDER BY stored_ts ASC, name ASC, value ASC"
                )
                rows = self._conn.execute(sql, (*batch, now)).fetchall()
                for name, value, expires_at, stored_ts in rows:
                    ttl_remaining = max(0, int(expires_at) - now)
                    out.append(
                        StoredRecord(
                            name=name,
                            value=value,
                            ttl_remaining=ttl_remaining,
                            stored_ts=int(stored_ts),
                        )
                    )
        return out

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SqliteMailboxStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
