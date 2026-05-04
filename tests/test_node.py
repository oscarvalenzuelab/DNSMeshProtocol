"""End-to-end test for the orchestrated DMPNode."""

import os
import socket
import time

import dns.message
import dns.query
import dns.rdatatype
import pytest
import requests

from dmp.client.client import DMPClient
from dmp.server.node import DMPNode, DMPNodeConfig


def _free_port(kind=socket.SOCK_STREAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def node(tmp_path):
    cfg = DMPNodeConfig(
        db_path=str(tmp_path / "node.db"),
        dns_host="127.0.0.1",
        dns_port=_free_port(socket.SOCK_DGRAM),
        http_host="127.0.0.1",
        http_port=_free_port(socket.SOCK_STREAM),
        cleanup_interval=0.1,
    )
    n = DMPNode(cfg)
    n.start()
    try:
        yield n
    finally:
        n.stop()


class TestDMPNode:
    def test_dns_and_http_both_up(self, node):
        # HTTP health
        r = requests.get(f"http://127.0.0.1:{node.config.http_port}/health", timeout=2)
        assert r.status_code == 200

        # DNS answer for a record we publish via HTTP
        requests.post(
            f"http://127.0.0.1:{node.config.http_port}/v1/records/alice.mesh.test",
            json={"value": "v=dmp1;t=identity", "ttl": 60},
            timeout=2,
        )
        request = dns.message.make_query("alice.mesh.test", dns.rdatatype.TXT)
        response = dns.query.udp(
            request, "127.0.0.1", port=node.config.dns_port, timeout=2.0
        )
        assert response.rcode() == 0
        assert b"".join(response.answer[0][0].strings) == b"v=dmp1;t=identity"

    def test_cleanup_worker_prunes_expired(self, node):
        requests.post(
            f"http://127.0.0.1:{node.config.http_port}/v1/records/tmp.mesh.test",
            json={"value": "gone", "ttl": 1},
            timeout=2,
        )
        # Wait past the 1s TTL and the 0.1s cleanup interval.
        time.sleep(1.5)
        # Expired records are filtered at query time; the worker additionally
        # purges from disk. We verify both: query returns empty AND a direct
        # store read shows zero rows.
        assert node.store is not None
        assert node.store.query_txt_record("tmp.mesh.test") is None
        assert node.store.record_count(include_expired=True) == 0

    def test_client_roundtrip_over_node_store(self, node):
        # Drive the client directly against the node's sqlite store. Exercises
        # the full send -> chunk -> publish -> poll -> decrypt path through a
        # real persistent store behind the same API the DNS + HTTP layers use.
        alice = DMPClient(
            "alice",
            "apass",
            domain="mesh.test",
            store=node.store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        bob = DMPClient(
            "bob",
            "bpass",
            domain="mesh.test",
            store=node.store,
            intro_queue_path=":memory:",
            prekey_store_path=":memory:",
        )
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.get_signing_public_key_hex(),
        )
        # bob must pin alice so receive_messages doesn't fall into TOFU
        # (default-deny after P0-3).
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.get_signing_public_key_hex(),
        )

        assert alice.send_message("bob", "via node store")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"via node store"

    def test_node_stop_is_idempotent(self, node):
        node.stop()
        node.stop()  # must not raise


class TestHeartbeatDnsReaderDnssecGate:
    """``DMP_HEARTBEAT_DNSSEC_REQUIRED=1`` opts the heartbeat worker's
    DNS reader into AD-bit enforcement on both code paths: the
    ResolverPool built from ``DMP_HEARTBEAT_DNS_RESOLVERS`` and the
    fallback system resolver."""

    def test_pool_path_propagates_dnssec_required(self, monkeypatch):
        from dmp.network.resolver_pool import ResolverPool
        from dmp.server.node import _build_heartbeat_dns_reader

        monkeypatch.setenv("DMP_HEARTBEAT_DNS_RESOLVERS", "1.1.1.1,9.9.9.9")
        monkeypatch.setenv("DMP_HEARTBEAT_DNSSEC_REQUIRED", "1")

        reader = _build_heartbeat_dns_reader()
        assert isinstance(reader, ResolverPool)
        assert reader._dnssec_required is True

    def test_pool_path_default_off(self, monkeypatch):
        from dmp.network.resolver_pool import ResolverPool
        from dmp.server.node import _build_heartbeat_dns_reader

        monkeypatch.setenv("DMP_HEARTBEAT_DNS_RESOLVERS", "1.1.1.1")
        monkeypatch.delenv("DMP_HEARTBEAT_DNSSEC_REQUIRED", raising=False)

        reader = _build_heartbeat_dns_reader()
        assert isinstance(reader, ResolverPool)
        assert reader._dnssec_required is False

    def test_system_resolver_path_drops_ad_less_answer(self, monkeypatch):
        """Fallback system-resolver path must also enforce AD when the
        env var is set. AD-less answers return None — the worker
        treats that as "nothing to harvest" (graceful degradation)
        rather than passing unvalidated records through."""
        import dns.flags
        import dns.resolver

        from dmp.server.node import _build_heartbeat_dns_reader

        monkeypatch.delenv("DMP_HEARTBEAT_DNS_RESOLVERS", raising=False)
        monkeypatch.setenv("DMP_HEARTBEAT_DNSSEC_REQUIRED", "1")

        # Stub Resolver.resolve so we control the AD bit on the response.
        class _FakeRdata:
            def __init__(self, s):
                self.strings = [s.encode("utf-8")]

        class _FakeResponse:
            def __init__(self, ad: bool):
                self.flags = dns.flags.AD if ad else 0

        class _FakeAnswer(list):
            def __init__(self, vals, ad: bool):
                super().__init__(_FakeRdata(v) for v in vals)
                self.response = _FakeResponse(ad)

        def fake_resolve(self, name, rdtype):
            return _FakeAnswer(["unvalidated"], ad=False)

        monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
        reader = _build_heartbeat_dns_reader()
        assert reader.query_txt_record("x.example.com") is None

    def test_system_resolver_path_passes_ad_set(self, monkeypatch):
        import dns.flags
        import dns.resolver

        from dmp.server.node import _build_heartbeat_dns_reader

        monkeypatch.delenv("DMP_HEARTBEAT_DNS_RESOLVERS", raising=False)
        monkeypatch.setenv("DMP_HEARTBEAT_DNSSEC_REQUIRED", "1")

        class _FakeRdata:
            def __init__(self, s):
                self.strings = [s.encode("utf-8")]

        class _FakeResponse:
            def __init__(self, ad: bool):
                self.flags = dns.flags.AD if ad else 0

        class _FakeAnswer(list):
            def __init__(self, vals, ad: bool):
                super().__init__(_FakeRdata(v) for v in vals)
                self.response = _FakeResponse(ad)

        def fake_resolve(self, name, rdtype):
            return _FakeAnswer(["validated"], ad=True)

        monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
        reader = _build_heartbeat_dns_reader()
        assert reader.query_txt_record("x.example.com") == ["validated"]
