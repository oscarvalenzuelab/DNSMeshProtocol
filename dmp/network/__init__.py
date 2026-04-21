"""DNS transport layer for DMP."""

from dmp.network.base import DNSRecordWriter, DNSRecordReader, DNSRecordStore
from dmp.network.composite_reader import CompositeReader
from dmp.network.memory import InMemoryDNSStore
from dmp.network.resolver_pool import ResolverPool, WELL_KNOWN_RESOLVERS
from dmp.network.union_reader import UnionReader

__all__ = [
    "CompositeReader",
    "DNSRecordWriter",
    "DNSRecordReader",
    "DNSRecordStore",
    "InMemoryDNSStore",
    "ResolverPool",
    "UnionReader",
    "WELL_KNOWN_RESOLVERS",
]
