"""Tests for the DNS transport abstraction layer."""

import pytest

from dmp.network import (
    DNSRecordReader,
    DNSRecordStore,
    DNSRecordWriter,
    InMemoryDNSStore,
)


class TestInMemoryDNSStore:
    def test_publish_and_query(self):
        store = InMemoryDNSStore()
        assert store.publish_txt_record("mb-abc.example.com", "v=dmp1;t=chunk;d=xxx")
        assert store.query_txt_record("mb-abc.example.com") == [
            "v=dmp1;t=chunk;d=xxx"
        ]

    def test_missing_returns_none(self):
        store = InMemoryDNSStore()
        assert store.query_txt_record("nope.example.com") is None

    def test_overwrite_replaces_record(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("a.example.com", "first")
        store.publish_txt_record("a.example.com", "second")
        assert store.query_txt_record("a.example.com") == ["second"]

    def test_delete_by_name(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("a.example.com", "v1")
        assert store.delete_txt_record("a.example.com")
        assert store.query_txt_record("a.example.com") is None

    def test_delete_missing_returns_false(self):
        store = InMemoryDNSStore()
        assert not store.delete_txt_record("ghost.example.com")

    def test_delete_by_value_leaves_other_values(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("multi.example.com", "v1")
        # An RRset with a single value — deleting a non-matching value is a no-op
        # but still reports success because the name exists.
        assert store.delete_txt_record("multi.example.com", value="does-not-match")
        assert store.query_txt_record("multi.example.com") == ["v1"]

    def test_implements_both_abcs(self):
        store = InMemoryDNSStore()
        assert isinstance(store, DNSRecordReader)
        assert isinstance(store, DNSRecordWriter)
        assert isinstance(store, DNSRecordStore)

    def test_list_names_for_inspection(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("b.example.com", "x")
        store.publish_txt_record("a.example.com", "y")
        assert store.list_names() == ["a.example.com", "b.example.com"]


class TestDNSPublisherInheritance:
    """Concrete publishers must satisfy the DNSRecordWriter contract."""

    def test_cloudflare_is_writer(self):
        from dmp.network.dns_publisher import CloudflarePublisher
        pub = CloudflarePublisher(zone_id="zzz", api_token="t")
        assert isinstance(pub, DNSRecordWriter)

    def test_local_is_writer(self):
        from dmp.network.dns_publisher import LocalDNSPublisher
        pub = LocalDNSPublisher(config_file="/tmp/nonexistent")
        assert isinstance(pub, DNSRecordWriter)

    def test_multi_provider_aggregates(self):
        from dmp.network.dns_publisher import MultiProviderPublisher
        multi = MultiProviderPublisher()
        mem_a = InMemoryDNSStore()
        mem_b = InMemoryDNSStore()
        multi.add_provider(mem_a)
        multi.add_provider(mem_b)
        assert multi.publish_txt_record("x.example.com", "shared")
        assert mem_a.query_txt_record("x.example.com") == ["shared"]
        assert mem_b.query_txt_record("x.example.com") == ["shared"]
