"""In-memory DNS store for tests and local development.

Not suitable for anything that leaves a single Python process. It fakes
the authoritative-write / recursive-read split with a single dict, so
writes are instantly visible to reads.
"""

import time
from threading import RLock
from typing import Dict, Iterable, List, Optional, Tuple

from dmp.network.base import DNSRecordStore
from dmp.storage.sqlite_store import StoredRecord


class InMemoryDNSStore(DNSRecordStore):
    """Dict-backed DNS store. Thread-safe for single-process tests."""

    def __init__(self) -> None:
        self._lock = RLock()
        # name -> list[(value, expires_at, stored_ts)]. We carry the same
        # metadata SqliteMailboxStore does so the anti-entropy sync worker
        # can run in unit tests against this store.
        self._records: Dict[str, List[Tuple[str, int, int]]] = {}

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Append to the RRset at `name`. Duplicates are collapsed.

        DNS allows multiple TXT records at one name (an RRset). A publish at
        an already-occupied name ADDS to the set rather than replacing it,
        so an attacker who reaches the publish endpoint can add records but
        cannot evict legitimate ones. Identical re-publishes are idempotent.
        """
        now = int(time.time())
        expires = now + int(ttl)
        with self._lock:
            entries = self._records.setdefault(name, [])
            for i, (v, _exp, _ts) in enumerate(entries):
                if v == value:
                    # Refresh TTL + stored_ts, same as the sqlite store's
                    # INSERT OR REPLACE.
                    entries[i] = (v, expires, now)
                    return True
            entries.append((value, expires, now))
        return True

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        with self._lock:
            if name not in self._records:
                return False
            if value is None:
                del self._records[name]
                return True
            self._records[name] = [
                (v, exp, ts) for (v, exp, ts) in self._records[name] if v != value
            ]
            if not self._records[name]:
                del self._records[name]
            return True

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        now = int(time.time())
        with self._lock:
            entries = self._records.get(name)
            if not entries:
                return None
            live = [v for (v, exp, _ts) in entries if exp > now]
        return live if live else None

    # Testing helpers (not part of DNSRecordStore contract)

    def list_names(self) -> List[str]:
        with self._lock:
            return sorted(self._records.keys())

    def clear(self) -> None:
        with self._lock:
            self._records.clear()

    # ---- anti-entropy support (parity with SqliteMailboxStore) -----------

    def iter_records_since(
        self, since_ts: int, *, limit: Optional[int] = None
    ) -> List[StoredRecord]:
        now = int(time.time())
        rows: List[StoredRecord] = []
        with self._lock:
            for name, entries in self._records.items():
                for value, exp, ts in entries:
                    if ts > since_ts and exp > now:
                        rows.append(
                            StoredRecord(
                                name=name,
                                value=value,
                                ttl_remaining=max(0, exp - now),
                                stored_ts=ts,
                            )
                        )
        rows.sort(key=lambda r: (r.stored_ts, r.name, r.value))
        if limit is not None:
            rows = rows[:limit]
        return rows

    def get_records_by_name(self, names: Iterable[str]) -> List[StoredRecord]:
        unique = list(dict.fromkeys(names))
        if not unique:
            return []
        now = int(time.time())
        out: List[StoredRecord] = []
        with self._lock:
            for name in unique:
                entries = self._records.get(name)
                if not entries:
                    continue
                for value, exp, ts in entries:
                    if exp <= now:
                        continue
                    out.append(
                        StoredRecord(
                            name=name,
                            value=value,
                            ttl_remaining=max(0, exp - now),
                            stored_ts=ts,
                        )
                    )
        out.sort(key=lambda r: (r.stored_ts, r.name, r.value))
        return out
