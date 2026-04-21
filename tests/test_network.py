"""Tests for the DNS transport abstraction layer."""

import socket
from unittest.mock import MagicMock, patch

import dns.message
import dns.query
import dns.rdatatype
import pytest

from dmp.network import (
    DNSRecordReader,
    DNSRecordStore,
    DNSRecordWriter,
    InMemoryDNSStore,
)
from dmp.network.dns_publisher import (
    DNSUpdatePublisher,
    _split_txt_value,
)


class TestInMemoryDNSStore:
    def test_publish_and_query(self):
        store = InMemoryDNSStore()
        assert store.publish_txt_record("mb-abc.example.com", "v=dmp1;t=chunk;d=xxx")
        assert store.query_txt_record("mb-abc.example.com") == ["v=dmp1;t=chunk;d=xxx"]

    def test_missing_returns_none(self):
        store = InMemoryDNSStore()
        assert store.query_txt_record("nope.example.com") is None

    def test_distinct_values_append_to_rrset(self):
        """Two different values at the same name coexist (DNS RRset semantics).

        This is load-bearing: the prior overwrite semantics let an attacker
        who could reach the publish endpoint wipe another sender's manifest
        out of a recipient's mailbox slot.
        """
        store = InMemoryDNSStore()
        store.publish_txt_record("a.example.com", "first")
        store.publish_txt_record("a.example.com", "second")
        assert store.query_txt_record("a.example.com") == ["first", "second"]

    def test_identical_publish_is_idempotent(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("a.example.com", "same")
        store.publish_txt_record("a.example.com", "same")
        assert store.query_txt_record("a.example.com") == ["same"]

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


class TestSplitTxtValue:
    """The RFC 1035 TXT character-string cap is 255 bytes. M2.1 cluster
    manifests run up to 1200 bytes post-base64, so every writer has to
    split before handing the value off to its backend. _split_txt_value
    is the single source of truth for that split.
    """

    def test_short_value_returns_single_chunk(self):
        # A value that fits in one character-string returns a
        # single-element list — callers stay on the same quoted-string
        # wire form they always used for short records.
        assert _split_txt_value("hello") == ["hello"]

    def test_exactly_255_bytes_single_chunk(self):
        value = "a" * 255
        assert _split_txt_value(value) == [value]

    def test_300_bytes_splits_255_45(self):
        value = "a" * 300
        chunks = _split_txt_value(value)
        assert len(chunks) == 2
        assert [len(c.encode("utf-8")) for c in chunks] == [255, 45]
        assert "".join(chunks) == value

    def test_600_bytes_splits_three_ways(self):
        value = "b" * 600
        chunks = _split_txt_value(value)
        assert len(chunks) == 3
        assert [len(c.encode("utf-8")) for c in chunks] == [255, 255, 90]
        assert "".join(chunks) == value

    def test_exact_multiple_of_chunk_size_no_empty_tail(self):
        # 510 bytes = 2 x 255. The result should be exactly 2 chunks —
        # no trailing empty string.
        value = "c" * 510
        chunks = _split_txt_value(value)
        assert len(chunks) == 2
        assert all(len(c.encode("utf-8")) == 255 for c in chunks)

    def test_custom_chunk_size(self):
        # A test-only override so tests can exercise split logic with a
        # smaller cap without constructing kilobyte values.
        value = "abcdefghij"  # 10 bytes
        chunks = _split_txt_value(value, chunk_bytes=3)
        assert chunks == ["abc", "def", "ghi", "j"]

    def test_short_non_ascii_accepted_single_chunk(self):
        # Under the cap, non-ASCII passes through unchanged — it's only
        # the split path that requires ASCII safety.
        value = "café"
        assert _split_txt_value(value) == [value]

    def test_long_non_ascii_rejected(self):
        # A naive byte split could land mid-codepoint and break UTF-8
        # decoding downstream; rather than silently corrupt the record
        # or emit provider-specific failures, we reject explicitly so
        # the caller can base64-encode first.
        value = "ñ" * 200  # 400 utf-8 bytes, every byte non-ASCII
        with pytest.raises(ValueError, match="ASCII-safe"):
            _split_txt_value(value)


class TestDNSUpdatePublisherMultiString:
    """RFC 2136 UPDATE path must hand dnspython multi-string RDATA for
    values > 255 bytes. dnspython parses space-separated quoted strings
    in the rdata text as a multi-string TXT RR; a single > 255-byte
    string would be rejected at wire-encode time.
    """

    def _capture_add(self, publisher, name, value, ttl=300):
        """Run publish_txt_record with the network stack mocked out,
        capture the (ttl, rdtype, rdata_text) args passed to
        ``dns.update.Update.add``.
        """
        captured = {}

        class _FakeUpdate:
            def __init__(self, *args, **kwargs):
                pass

            def delete(self, *args, **kwargs):
                pass

            def add(self, rel, ttl, rdtype, rdata_text):
                captured["rel"] = rel
                captured["ttl"] = ttl
                captured["rdtype"] = rdtype
                captured["rdata_text"] = rdata_text

        fake_response = MagicMock()
        fake_response.rcode.return_value = 0  # NOERROR

        with patch("dmp.network.dns_publisher.dns.update.Update", _FakeUpdate):
            with patch(
                "dmp.network.dns_publisher.dns.query.tcp",
                return_value=fake_response,
            ):
                ok = publisher.publish_txt_record(name, value, ttl=ttl)
        return ok, captured

    def test_short_value_is_single_quoted_string(self):
        pub = DNSUpdatePublisher(zone="example.com", nameserver="127.0.0.1")
        ok, captured = self._capture_add(pub, "x.example.com", "hi")
        assert ok
        # Exactly one quoted chunk for short values — back-compat with
        # the prior wire form.
        assert captured["rdata_text"] == '"hi"'

    def test_long_value_is_multi_string(self):
        pub = DNSUpdatePublisher(zone="example.com", nameserver="127.0.0.1")
        value = "A" * 500  # needs 2 chunks (255 + 245)
        ok, captured = self._capture_add(pub, "x.example.com", value)
        assert ok
        # rdata_text has the form `"chunk1" "chunk2"`; dnspython parses
        # that as a multi-string TXT RR at wire-encode time.
        rdata = captured["rdata_text"]
        # Exactly two space-separated quoted chunks.
        assert rdata.count('"') == 4
        # Reassembled content matches the original.
        chunks = [
            c[1:-1] for c in rdata.split(" ") if c.startswith('"') and c.endswith('"')
        ]
        assert "".join(chunks) == value
        assert [len(c) for c in chunks] == [255, 245]

    def test_1200_byte_value_multi_string(self):
        # The absolute M2.1 ceiling. Needs 5 chunks (255*4 + 180).
        pub = DNSUpdatePublisher(zone="example.com", nameserver="127.0.0.1")
        value = "Z" * 1200
        ok, captured = self._capture_add(pub, "x.example.com", value)
        assert ok
        rdata = captured["rdata_text"]
        chunks = [
            c[1:-1] for c in rdata.split(" ") if c.startswith('"') and c.endswith('"')
        ]
        assert len(chunks) == 5
        assert [len(c) for c in chunks] == [255, 255, 255, 255, 180]
        assert "".join(chunks) == value


class TestInMemoryDnsServerLongTxtRoundtrip:
    """End-to-end: write a 500-byte value into the in-memory store,
    serve it via the real UDP DMPDnsServer, query over UDP with
    dnspython, and confirm the reassembled value matches.

    This is the load-bearing path for cluster manifests in local /
    test deployments — if this breaks, no manifest > 255 bytes is
    reachable via UDP from an InMemoryDNSStore-backed node.
    """

    def _free_port(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_500_byte_value_roundtrips_via_udp(self):
        from dmp.server.dns_server import DMPDnsServer

        store = InMemoryDNSStore()
        long_value = "v=dmp1;t=cluster;" + ("X" * 483)  # 500 bytes total
        assert len(long_value.encode("utf-8")) == 500
        store.publish_txt_record("cluster.mesh.test", long_value)

        port = self._free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query("cluster.mesh.test", dns.rdatatype.TXT)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        rdata = response.answer[0][0]
        # Multi-string on the wire...
        assert len(rdata.strings) >= 2
        assert all(len(s) <= 255 for s in rdata.strings)
        # ...but concatenates back to the original value.
        assert b"".join(rdata.strings).decode("utf-8") == long_value

    def test_1200_byte_value_roundtrips_via_udp(self):
        """Real MAX_WIRE_LEN payload across the wire."""
        from dmp.server.dns_server import DMPDnsServer

        store = InMemoryDNSStore()
        long_value = "v=dmp1;t=cluster;" + ("Y" * 1183)  # 1200 bytes
        assert len(long_value.encode("utf-8")) == 1200
        store.publish_txt_record("cluster.big.test", long_value)

        port = self._free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query("cluster.big.test", dns.rdatatype.TXT)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)
        assert response.rcode() == 0
        rdata = response.answer[0][0]
        assert b"".join(rdata.strings).decode("utf-8") == long_value
