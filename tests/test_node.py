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
        alice = DMPClient("alice", "apass", domain="mesh.test", store=node.store)
        bob = DMPClient("bob", "bpass", domain="mesh.test", store=node.store)
        alice.add_contact("bob", bob.get_public_key_hex())

        assert alice.send_message("bob", "via node store")
        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"via node store"

    def test_node_stop_is_idempotent(self, node):
        node.stop()
        node.stop()  # must not raise
