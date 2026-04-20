"""Tests for the UDP DNS server."""

import socket
import time

import dns.message
import dns.query
import dns.rdatatype
import pytest

from dmp.network.memory import InMemoryDNSStore
from dmp.server.dns_server import DMPDnsServer, _split_for_txt_strings


def _free_port() -> int:
    # Bind UDP port 0, read back assigned port, release. A race is possible
    # but the window is small for a per-test random port.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestTxtSplitting:
    def test_short_value_single_string(self):
        chunks = _split_for_txt_strings("hello")
        assert chunks == [b"hello"]

    def test_long_value_splits_at_255(self):
        value = "A" * 500
        chunks = _split_for_txt_strings(value)
        assert [len(c) for c in chunks] == [255, 245]

    def test_empty_value_has_one_empty_chunk(self):
        assert _split_for_txt_strings("") == [b""]


class TestDMPDnsServer:
    def _query(self, qname: str, host: str, port: int) -> dns.message.Message:
        request = dns.message.make_query(qname, dns.rdatatype.TXT)
        return dns.query.udp(request, host, port=port, timeout=2.0)

    def test_resolves_txt_record(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("alice.mesh.test", "v=dmp1;t=identity")

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query("alice.mesh.test", "127.0.0.1", port)

        assert response.rcode() == 0  # NOERROR
        assert len(response.answer) == 1
        rdata = response.answer[0][0]
        assert b"".join(rdata.strings) == b"v=dmp1;t=identity"

    def test_missing_name_returns_nxdomain(self):
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query("ghost.mesh.test", "127.0.0.1", port)
        assert response.rcode() == 3  # NXDOMAIN

    def test_non_txt_query_returns_empty_answer(self):
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query("alice.mesh.test", dns.rdatatype.A)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)
        # We don't serve A records; return an empty NOERROR.
        assert response.rcode() == 0
        assert response.answer == []

    def test_long_value_served_as_multi_string_txt(self):
        """Values > 255 bytes get emitted as multi-string TXT records."""
        store = InMemoryDNSStore()
        long_value = "B" * 600
        store.publish_txt_record("long.mesh.test", long_value)

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query("long.mesh.test", "127.0.0.1", port)

        assert response.rcode() == 0
        rdata = response.answer[0][0]
        assert len(rdata.strings) >= 3
        for s in rdata.strings:
            assert len(s) <= 255
        assert b"".join(rdata.strings) == long_value.encode("utf-8")

    def test_server_is_restartable(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("r.mesh.test", "value")
        port = _free_port()

        server = DMPDnsServer(store, host="127.0.0.1", port=port)
        server.start()
        try:
            response = self._query("r.mesh.test", "127.0.0.1", port)
            assert response.rcode() == 0
        finally:
            server.stop()

        # Second life: bind a different free port (socketserver can keep the
        # old one busy momentarily even with SO_REUSEADDR on some platforms).
        port2 = _free_port()
        server2 = DMPDnsServer(store, host="127.0.0.1", port=port2)
        server2.start()
        try:
            response2 = self._query("r.mesh.test", "127.0.0.1", port2)
            assert response2.rcode() == 0
        finally:
            server2.stop()
