"""SqliteMailboxStore — persistent TTL-aware DNSRecordStore.

One row per (name, value) pair with an expires_at cutoff. Reads filter on
expires_at > now, so expired records are invisible even before the cleanup
worker reaps them. The cleanup worker is a separate concern
(`dmp.server.cleanup.CleanupWorker`) that periodically calls
`cleanup_expired()` to bound disk usage.

Thread-safe via a per-store RLock around a single shared connection. Sqlite's
WAL journaling is enabled so readers don't block a long writer.

Each row also carries a `stored_ts` column — the unix-seconds moment at which
the local node first accepted the write. Distinct from `created_at`
(effectively the same value today; kept as a separate column so a future
schema change can carry the *authoritative publisher's* timestamp in
`created_at` while `stored_ts` remains the local receiver's view). The
anti-entropy sync worker uses `stored_ts` as the watermark so a peer catching
up sees records ordered by local arrival, not by upstream publish time.
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

        `stored_ts` was added in M2.4 for the anti-entropy sync worker.
        Older databases created before this release don't have the
        column. We add it here (and its index) so reopening a pre-M2.4
        db doesn't crash. The DEFAULT 0 in _SCHEMA covers fresh rows;
        the ALTER handles the existing ones.
        """
        with self._lock:
            cols = {
                row[1]
                for row in self._conn.execute("PRAGMA table_info(records)").fetchall()
            }
            if "stored_ts" not in cols:
                # Older DB; add the column, backfill from created_at so
                # existing rows have a sane watermark, then index it.
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

    # ---- DNSRecordStore contract ------------------------------------------

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        now = int(time.time())
        expires = now + int(ttl)
        with self._lock:
            # Append semantics. DNS natively supports multiple TXT records at
            # one name (an RRset); the prior "replace all" behavior let an
            # attacker who could reach the publish endpoint wipe other
            # senders' manifests out of a recipient's mailbox slot. With
            # append, an attacker can *add* records but cannot *remove*
            # legitimate ones. The PRIMARY KEY (name, value) means an honest
            # duplicate republish refreshes the TTL without growing the row
            # set. `stored_ts` records the moment this *node* accepted the
            # write; sync peers use it as their cursor.
            self._conn.execute(
                "INSERT OR REPLACE INTO records "
                "(name, value, ttl, created_at, expires_at, stored_ts) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, value, int(ttl), now, expires, now),
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
        self, since_ts: int, *, limit: Optional[int] = None
    ) -> List[StoredRecord]:
        """Return non-expired records whose `stored_ts` is strictly greater than
        `since_ts`, oldest first.

        Used by the anti-entropy digest endpoint. The peer passes the watermark
        it last saw from this node; we return everything newer. Ordering by
        stored_ts ASC lets the peer advance its watermark monotonically even if
        it processes the result incrementally.

        `limit` caps the batch size; None means no cap. The cap is enforced at
        the SQL layer so a peer asking for 10 records on a million-row store
        doesn't read the world into memory.
        """
        now = int(time.time())
        with self._lock:
            sql = (
                "SELECT name, value, expires_at, stored_ts FROM records "
                "WHERE stored_ts > ? AND expires_at > ? "
                "ORDER BY stored_ts ASC, name ASC, value ASC"
            )
            params: Tuple = (int(since_ts), now)
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
