"""DNS transport layer for DMP."""

from dmp.network.base import DNSRecordWriter, DNSRecordReader, DNSRecordStore
from dmp.network.memory import InMemoryDNSStore
from dmp.network.resolver_pool import ResolverPool, WELL_KNOWN_RESOLVERS

__all__ = [
    "DNSRecordWriter",
    "DNSRecordReader",
    "DNSRecordStore",
    "InMemoryDNSStore",
    "ResolverPool",
    "WELL_KNOWN_RESOLVERS",
]
