"""End-to-end integration test for the M2.wire ClusterClient.

Spins up two live `DMPDnsServer` + `InMemoryDNSStore` pairs as cluster
nodes, publishes a signed cluster manifest naming both, builds a
ClusterClient from it, and exercises write + read through the live
fanout/union path. The HTTP writer path is faked (no real HTTP
server) so the test stays hermetic; the DNS read path talks over
real UDP sockets into the `DMPDnsServer`s.

This is the "both halves actually work together" proof for M2.wire.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Dict, List, Optional

import pytest

from dmp.client.cluster_bootstrap import ClusterClient, fetch_cluster_manifest
from dmp.core.cluster import ClusterManifest, ClusterNode, cluster_rrset_name
from dmp.core.crypto import DMPCrypto
from dmp.network.base import DNSRecordReader, DNSRecordWriter
from dmp.network.memory import InMemoryDNSStore
from dmp.server.dns_server import DMPDnsServer


def _free_udp_port() -> int:
    """Bind UDP port 0, read back the assigned port, release it.

    A race is possible but the window is small for a per-test port.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _StoreBackedWriter(DNSRecordWriter):
    """Simulates a node's HTTP publish endpoint by writing to its store.

    In production the FanoutWriter's per-node writer is a `_HttpWriter`
    talking to the node's /v1/records API, which persists under the
    hood to the store the DNS server also reads from. For tests we
    short-circuit straight to the store — the result is the same: a
    successful publish becomes visible to that node's DNS server.
    """

    def __init__(self, store: InMemoryDNSStore) -> None:
        self._store = store

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        return self._store.publish_txt_record(name, value, ttl)

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        return self._store.delete_txt_record(name, value)


@pytest.fixture
def two_node_cluster():
    """Start two DMPDnsServer + InMemoryDNSStore pairs on free UDP ports.

    Yields a dict of per-node {store, dns_server, port, writer}
    entries plus teardown registered via fixture finalization.
    """
    nodes: Dict[str, Dict] = {}
    servers: List[DMPDnsServer] = []
    for node_id, label in [("n01", "node1"), ("n02", "node2")]:
        store = InMemoryDNSStore()
        port = _free_udp_port()
        server = DMPDnsServer(store, host="127.0.0.1", port=port)
        server.start()
        servers.append(server)
        nodes[node_id] = {
            "store": store,
            "server": server,
            "port": port,
            "writer": _StoreBackedWriter(store),
        }
    yield nodes
    for server in servers:
        server.stop()


def _build_cluster_manifest(
    nodes: Dict[str, Dict], operator: DMPCrypto
) -> ClusterManifest:
    cluster_nodes = [
        ClusterNode(
            node_id=node_id,
            http_endpoint=f"http://127.0.0.1:{info['port']}",
            dns_endpoint=f"127.0.0.1:{info['port']}",
        )
        for node_id, info in nodes.items()
    ]
    return ClusterManifest(
        cluster_name="mesh.example.com",
        operator_spk=operator.get_signing_public_key_bytes(),
        nodes=cluster_nodes,
        seq=1,
        exp=int(time.time()) + 3600,
    )


class TestClusterClientEndToEnd:
    def test_write_fans_out_to_both_nodes(self, two_node_cluster):
        """A write via the cluster client should land on both node stores."""
        nodes = two_node_cluster
        operator = DMPCrypto()
        manifest = _build_cluster_manifest(nodes, operator)

        # Bootstrap store: holds the signed cluster manifest so
        # fetch_cluster_manifest has something to find. We publish
        # under the real RRset name so fetch_cluster_manifest's own
        # cluster_rrset_name("mesh.example.com") resolves.
        bootstrap_store = InMemoryDNSStore()
        bootstrap_store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest.sign(operator),
        )

        fetched = fetch_cluster_manifest(
            "mesh.example.com",
            operator.get_signing_public_key_bytes(),
            bootstrap_store,
        )
        assert fetched is not None

        def writer_factory(node: ClusterNode) -> DNSRecordWriter:
            return nodes[node.node_id]["writer"]

        def reader_factory(node: ClusterNode) -> DNSRecordReader:
            # Real UDP DNS reader, pointed at the node's DMPDnsServer.
            from dmp.cli import _NodeDnsReader

            assert node.dns_endpoint is not None
            return _NodeDnsReader(node.dns_endpoint)

        cc = ClusterClient(
            fetched,
            operator_spk=operator.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=bootstrap_store,
            writer_factory=writer_factory,
            reader_factory=reader_factory,
        )
        try:
            ok = cc.writer.publish_txt_record("hello.mesh.example.com", "world")
            assert ok is True
            # Both stores received the record (quorum hit but all
            # nodes actually completed the write).
            for node_id, info in nodes.items():
                records = info["store"].query_txt_record("hello.mesh.example.com")
                assert records == ["world"], f"{node_id} missing record"
        finally:
            cc.close()

    def test_read_unions_across_both_nodes(self, two_node_cluster):
        """A read via the cluster client returns the record seen by any node."""
        nodes = two_node_cluster
        operator = DMPCrypto()
        manifest = _build_cluster_manifest(nodes, operator)

        bootstrap_store = InMemoryDNSStore()
        bootstrap_store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest.sign(operator),
        )

        # Pre-seed node1 only — node2 is empty. UnionReader should
        # still return the record because node1 has it.
        nodes["n01"]["store"].publish_txt_record("partial.mesh.example.com", "one-side")

        def writer_factory(node: ClusterNode) -> DNSRecordWriter:
            return nodes[node.node_id]["writer"]

        def reader_factory(node: ClusterNode) -> DNSRecordReader:
            from dmp.cli import _NodeDnsReader

            assert node.dns_endpoint is not None
            return _NodeDnsReader(node.dns_endpoint)

        cc = ClusterClient(
            manifest,
            operator_spk=operator.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=bootstrap_store,
            writer_factory=writer_factory,
            reader_factory=reader_factory,
        )
        try:
            got = cc.reader.query_txt_record("partial.mesh.example.com")
            assert got is not None
            # Union dedups, so "one-side" appears exactly once even
            # though node2 contributed None.
            assert got == ["one-side"]
        finally:
            cc.close()

    def test_union_dedups_when_both_nodes_have_same_record(self, two_node_cluster):
        """Write via fanout, then read via union; the record appears once."""
        nodes = two_node_cluster
        operator = DMPCrypto()
        manifest = _build_cluster_manifest(nodes, operator)

        bootstrap_store = InMemoryDNSStore()
        bootstrap_store.publish_txt_record(
            cluster_rrset_name("mesh.example.com"),
            manifest.sign(operator),
        )

        def writer_factory(node: ClusterNode) -> DNSRecordWriter:
            return nodes[node.node_id]["writer"]

        def reader_factory(node: ClusterNode) -> DNSRecordReader:
            from dmp.cli import _NodeDnsReader

            assert node.dns_endpoint is not None
            return _NodeDnsReader(node.dns_endpoint)

        cc = ClusterClient(
            manifest,
            operator_spk=operator.get_signing_public_key_bytes(),
            base_domain="mesh.example.com",
            bootstrap_reader=bootstrap_store,
            writer_factory=writer_factory,
            reader_factory=reader_factory,
        )
        try:
            assert cc.writer.publish_txt_record("roundtrip.mesh.example.com", "echo")
            got = cc.reader.query_txt_record("roundtrip.mesh.example.com")
            assert got == ["echo"]  # exactly once despite both nodes having it
        finally:
            cc.close()
