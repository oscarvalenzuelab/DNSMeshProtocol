"""Abstract base classes for DNS record publishing and querying.

Reading and writing DNS records are two different concerns:
- Writing requires authoritative control over a zone (Cloudflare API, BIND
  RFC 2136 UPDATE, etc.) and is eventually consistent across caches.
- Reading goes through a recursive resolver, with its own caching semantics
  and failure modes (NXDOMAIN vs. NoAnswer vs. transport error).

Keeping the interfaces separate lets a backend implement one side without
implying the other. InMemoryDNSStore implements both for testing.
"""

from abc import ABC, abstractmethod
from typing import List, Optional


class DNSRecordWriter(ABC):
    """Publish TXT records to an authoritative DNS zone."""

    @abstractmethod
    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Create or update a TXT record at fully-qualified `name`.

        Returns True if the write was accepted by the authoritative source.
        Propagation delay is the caller's problem.
        """

    @abstractmethod
    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        """Delete a TXT record at fully-qualified `name`.

        Some backends (Route53) require the record value to target an exact
        RRset; others (Cloudflare, BIND UPDATE) delete by name alone. Callers
        should pass `value` when known; backends that don't need it ignore it.
        """


class DNSRecordReader(ABC):
    """Query TXT records via a resolver."""

    @abstractmethod
    def query_txt_record(self, name: str) -> Optional[List[str]]:
        """Return the list of TXT strings at `name`, or None if no record.

        None means the record is absent or unreachable. Backends may coalesce
        NXDOMAIN / NoAnswer / transport errors to None; callers that need to
        distinguish should use a richer backend interface.
        """


class DNSRecordStore(DNSRecordWriter, DNSRecordReader, ABC):
    """A backend that supports both reading and writing TXT records.

    Real production deployments typically use separate reader and writer
    backends (resolver vs. authoritative API). DNSRecordStore is primarily
    for InMemoryDNSStore and for backends that genuinely own both sides,
    like a local BIND zone you query through its own resolver.
    """
