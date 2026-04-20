"""In-memory DNS store for tests and local development.

Not suitable for anything that leaves a single Python process. It fakes
the authoritative-write / recursive-read split with a single dict, so
writes are instantly visible to reads.
"""

from threading import RLock
from typing import Dict, List, Optional

from dmp.network.base import DNSRecordStore


class InMemoryDNSStore(DNSRecordStore):
    """Dict-backed DNS store. Thread-safe for single-process tests."""

    def __init__(self) -> None:
        self._lock = RLock()
        # name -> list[str] (TXT records can hold multiple strings per RRset)
        self._records: Dict[str, List[str]] = {}

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Append to the RRset at `name`. Duplicates are collapsed.

        DNS allows multiple TXT records at one name (an RRset). A publish at
        an already-occupied name ADDS to the set rather than replacing it,
        so an attacker who reaches the publish endpoint can add records but
        cannot evict legitimate ones. Identical re-publishes are idempotent.
        """
        with self._lock:
            values = self._records.setdefault(name, [])
            if value not in values:
                values.append(value)
        return True

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        with self._lock:
            if name not in self._records:
                return False
            if value is None:
                del self._records[name]
                return True
            self._records[name] = [v for v in self._records[name] if v != value]
            if not self._records[name]:
                del self._records[name]
            return True

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        with self._lock:
            records = self._records.get(name)
            return list(records) if records else None

    # Testing helpers (not part of DNSRecordStore contract)

    def list_names(self) -> List[str]:
        with self._lock:
            return sorted(self._records.keys())

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
