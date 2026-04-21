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
        # name -> list[(value, expires_at_seconds, stored_ts_ms)]. We carry
        # the same metadata SqliteMailboxStore does so the anti-entropy
        # sync worker can run in unit tests against this store. Note the
        # mixed resolutions: expires_at stays in seconds (it's compared
        # against time.time() as a cutoff); stored_ts is milliseconds so
        # that same-second bursts paginate cleanly.
        self._records: Dict[str, List[Tuple[str, int, int]]] = {}

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Append to the RRset at `name`. Duplicates are collapsed.

        DNS allows multiple TXT records at one name (an RRset). A publish at
        an already-occupied name ADDS to the set rather than replacing it,
        so an attacker who reaches the publish endpoint can add records but
        cannot evict legitimate ones. Identical re-publishes are idempotent.
        """
        now_s = int(time.time())
        now_ms = int(time.time() * 1000)
        expires = now_s + int(ttl)
        with self._lock:
            entries = self._records.setdefault(name, [])
            for i, (v, _exp, _ts) in enumerate(entries):
                if v == value:
                    # Refresh TTL + stored_ts (ms), same as the sqlite
                    # store's INSERT OR REPLACE.
                    entries[i] = (v, expires, now_ms)
                    return True
            entries.append((value, expires, now_ms))
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
        self,
        since_ts: int = 0,
        *,
        limit: Optional[int] = None,
        cursor: Optional[Tuple[int, str]] = None,
    ) -> List[StoredRecord]:
        """Same semantics as ``SqliteMailboxStore.iter_records_since``.

        Either ``cursor=(ts, name)`` (compound, M2.4-followup) or
        ``since_ts=<ms>`` (legacy; equivalent to ``cursor=(since_ts, "")``)
        may be passed — not both.
        """
        if cursor is not None and since_ts:
            raise ValueError("pass cursor OR since_ts, not both")
        if cursor is None:
            cursor = (int(since_ts), "")
        cur_ts, cur_name = int(cursor[0]), str(cursor[1])
        now = int(time.time())
        rows: List[StoredRecord] = []
        with self._lock:
            for name, entries in self._records.items():
                for value, exp, ts in entries:
                    if exp <= now:
                        continue
                    # (ts, name) > (cur_ts, cur_name) in lexicographic
                    # order — match the SQL predicate exactly.
                    if ts > cur_ts or (ts == cur_ts and name > cur_name):
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
