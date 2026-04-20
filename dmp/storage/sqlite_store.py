"""SqliteMailboxStore — persistent TTL-aware DNSRecordStore.

One row per (name, value) pair with an expires_at cutoff. Reads filter on
expires_at > now, so expired records are invisible even before the cleanup
worker reaps them. The cleanup worker is a separate concern
(`dmp.server.cleanup.CleanupWorker`) that periodically calls
`cleanup_expired()` to bound disk usage.

Thread-safe via a per-store RLock around a single shared connection. Sqlite's
WAL journaling is enabled so readers don't block a long writer.
"""

from __future__ import annotations

import os
import sqlite3
import time
from threading import RLock
from typing import List, Optional

from dmp.network.base import DNSRecordStore


_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    name       TEXT NOT NULL,
    value      TEXT NOT NULL,
    ttl        INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (name, value)
);
CREATE INDEX IF NOT EXISTS idx_records_name    ON records(name);
CREATE INDEX IF NOT EXISTS idx_records_expires ON records(expires_at);
"""


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
            # set.
            self._conn.execute(
                "INSERT OR REPLACE INTO records "
                "(name, value, ttl, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (name, value, int(ttl), now, expires),
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
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM records"
                ).fetchone()
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

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SqliteMailboxStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
