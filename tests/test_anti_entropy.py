"""Unit tests for dmp.server.anti_entropy.

Everything here runs in-process against InMemoryDNSStore and a fake HTTP
transport, so it's fast and deterministic. The HTTP-level tests live in
tests/test_node_http_sync.py; two-node integration is in TestTwoNode below.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Dict, List, Optional, Tuple

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.cluster import ClusterManifest, ClusterNode
from dmp.core.identity import IdentityRecord, make_record
from dmp.core.manifest import NO_PREKEY, SlotManifest
from dmp.network.memory import InMemoryDNSStore
from dmp.server.anti_entropy import (
    AntiEntropyWorker,
    SyncPeer,
    load_peers_from_cluster_json,
    verify_record,
)
from dmp.storage.sqlite_store import StoredRecord

# ---- verify_record -------------------------------------------------------


def _signed_manifest() -> Tuple[str, SlotManifest]:
    sender = DMPCrypto()
    m = SlotManifest(
        msg_id=b"\x01" * 16,
        sender_spk=sender.get_signing_public_key_bytes(),
        recipient_id=b"\x02" * 32,
        total_chunks=1,
        data_chunks=1,
        prekey_id=NO_PREKEY,
        ts=int(time.time()),
        exp=int(time.time()) + 600,
    )
    return m.sign(sender), m


def _signed_identity() -> str:
    c = DMPCrypto()
    rec = make_record(c, "alice")
    return rec.sign(c)


def _signed_cluster() -> Tuple[str, DMPCrypto]:
    op = DMPCrypto()
    manifest = ClusterManifest(
        cluster_name="mesh.example.com",
        operator_spk=op.get_signing_public_key_bytes(),
        nodes=[
            ClusterNode(node_id="n1", http_endpoint="https://n1.example.com:8053"),
            ClusterNode(node_id="n2", http_endpoint="https://n2.example.com:8053"),
        ],
        seq=1,
        exp=int(time.time()) + 3600,
    )
    return manifest.sign(op), op


class TestVerifyRecord:
    def test_valid_manifest_passes(self):
        wire, _ = _signed_manifest()
        assert verify_record(wire) is True

    def test_tampered_manifest_fails(self):
        wire, _ = _signed_manifest()
        # Flip one bit in the base64 payload (not the prefix).
        tampered = wire[:-5] + "AAAAA"
        assert verify_record(tampered) is False

    def test_valid_identity_passes(self):
        wire = _signed_identity()
        assert verify_record(wire) is True

    def test_tampered_identity_fails(self):
        wire = _signed_identity()
        tampered = wire[:-5] + "AAAAA"
        assert verify_record(tampered) is False

    def test_cluster_manifest_full_verify_with_operator_spk(self):
        wire, op = _signed_cluster()
        assert (
            verify_record(
                wire,
                cluster_operator_spk=op.get_signing_public_key_bytes(),
            )
            is True
        )

    def test_cluster_manifest_wrong_operator_spk_rejected(self):
        wire, _ = _signed_cluster()
        other = DMPCrypto()
        assert (
            verify_record(
                wire,
                cluster_operator_spk=other.get_signing_public_key_bytes(),
            )
            is False
        )

    def test_cluster_manifest_structural_only_when_no_key(self):
        wire, _ = _signed_cluster()
        assert verify_record(wire) is True  # structural-only accepts valid wire

    def test_chunk_accepted_as_opaque(self):
        assert verify_record("v=dmp1;t=chunk;d=YWJj") is True

    def test_unknown_prefix_accepted(self):
        assert verify_record("random-string") is True

    def test_empty_rejected(self):
        assert verify_record("") is False

    def test_prekey_structural_too_short_rejected(self):
        assert verify_record("v=dmp1;t=prekey;d=YWI=") is False

    def test_bootstrap_structural_b64_invalid_rejected(self):
        assert verify_record("v=dmp1;t=bootstrap;$$$") is False


# ---- load_peers_from_cluster_json ---------------------------------------


class TestLoadPeers:
    def test_missing_file_returns_empty(self, tmp_path):
        assert load_peers_from_cluster_json(str(tmp_path / "nope.json")) == []

    def test_empty_file_returns_empty(self, tmp_path):
        p = tmp_path / "c.json"
        p.write_text("")
        assert load_peers_from_cluster_json(str(p)) == []

    def test_raw_wire_format(self, tmp_path):
        wire, _ = _signed_cluster()
        p = tmp_path / "c.json"
        p.write_text(wire)
        peers = load_peers_from_cluster_json(str(p))
        assert [pr.node_id for pr in peers] == ["n1", "n2"]

    def test_self_node_filtered(self, tmp_path):
        wire, _ = _signed_cluster()
        p = tmp_path / "c.json"
        p.write_text(wire)
        peers = load_peers_from_cluster_json(str(p), self_node_id="n1")
        assert [pr.node_id for pr in peers] == ["n2"]

    def test_wrapped_wire_format(self, tmp_path):
        wire, _ = _signed_cluster()
        p = tmp_path / "c.json"
        p.write_text(json.dumps({"wire": wire}))
        peers = load_peers_from_cluster_json(str(p))
        assert [pr.node_id for pr in peers] == ["n1", "n2"]

    def test_raw_nodes_list(self, tmp_path):
        p = tmp_path / "c.json"
        p.write_text(
            json.dumps(
                {
                    "nodes": [
                        {
                            "node_id": "nA",
                            "http_endpoint": "https://a.example.com:8053",
                        },
                        {
                            "node_id": "nB",
                            "http_endpoint": "https://b.example.com:8053",
                        },
                    ]
                }
            )
        )
        peers = load_peers_from_cluster_json(str(p))
        assert [pr.node_id for pr in peers] == ["nA", "nB"]

    def test_malformed_json_returns_empty(self, tmp_path):
        p = tmp_path / "c.json"
        p.write_text("{not json")
        assert load_peers_from_cluster_json(str(p)) == []


# ---- worker with fake HTTP transport ------------------------------------


class FakePeerHTTP:
    """Stand-in for a peer node's HTTP surface.

    Carries its own InMemoryDNSStore and implements just enough of the
    sync protocol to exercise the worker. The worker talks to it via the
    injected http_get / http_post callables on AntiEntropyWorker.
    """

    def __init__(
        self,
        peer_id: str,
        token: str = "peer-token",
        *,
        lie_extra: bool = False,
        forge_manifest: Optional[str] = None,
    ):
        self.peer_id = peer_id
        self.token = token
        self.store = InMemoryDNSStore()
        self.lie_extra = lie_extra
        self.forge_manifest = forge_manifest
        self.digest_calls = 0
        self.pull_calls = 0

    def get(self, url: str, token: Optional[str], timeout: float) -> Tuple[int, bytes]:
        if token != self.token:
            return (403, b'{"error":"forbidden"}')
        if "/v1/sync/digest" in url:
            self.digest_calls += 1
            # Parse ?since=&limit=
            q = url.split("?", 1)[1] if "?" in url else ""
            since = 0
            limit = 1000
            for kv in q.split("&"):
                if kv.startswith("since="):
                    since = int(kv[len("since=") :])
                elif kv.startswith("limit="):
                    limit = int(kv[len("limit=") :])
            rows = self.store.iter_records_since(since, limit=limit + 1)
            has_more = len(rows) > limit
            rows = rows[:limit]
            entries = [
                {"name": r.name, "hash": r.record_hash, "ts": r.stored_ts} for r in rows
            ]
            body = json.dumps({"records": entries, "has_more": has_more}).encode(
                "utf-8"
            )
            return (200, body)
        return (404, b'{"error":"not found"}')

    def post(
        self, url: str, token: Optional[str], body: bytes, timeout: float
    ) -> Tuple[int, bytes]:
        if token != self.token:
            return (403, b'{"error":"forbidden"}')
        if "/v1/sync/pull" in url:
            self.pull_calls += 1
            doc = json.loads(body.decode("utf-8"))
            names = doc["names"]
            rows = self.store.get_records_by_name(names)
            out = []
            for r in rows:
                value = r.value
                # If configured to forge, swap the first slot-manifest value
                # for a tampered version.
                if self.forge_manifest is not None and value.startswith(
                    "v=dmp1;t=manifest;d="
                ):
                    value = self.forge_manifest
                out.append({"name": r.name, "value": value, "ttl": r.ttl_remaining})
            if self.lie_extra:
                # Include a name the client did not ask for — the worker
                # must reject this.
                out.append(
                    {
                        "name": "extra.mesh.test",
                        "value": "v=dmp1;t=chunk;d=YWJj",
                        "ttl": 60,
                    }
                )
            return (200, json.dumps({"records": out}).encode("utf-8"))
        return (404, b'{"error":"not found"}')


def _make_worker(
    local_store: InMemoryDNSStore,
    peers: List[Tuple[SyncPeer, FakePeerHTTP]],
    *,
    token: str = "peer-token",
    **kwargs,
) -> AntiEntropyWorker:
    by_endpoint: Dict[str, FakePeerHTTP] = {p.http_endpoint: fake for p, fake in peers}

    def http_get(url, tok, timeout):
        for ep, fake in by_endpoint.items():
            if url.startswith(ep):
                return fake.get(url, tok, timeout)
        return (0, b"")

    def http_post(url, tok, body, timeout):
        for ep, fake in by_endpoint.items():
            if url.startswith(ep):
                return fake.post(url, tok, body, timeout)
        return (0, b"")

    return AntiEntropyWorker(
        store=local_store,
        peers=[p for p, _ in peers],
        sync_token=token,
        interval_seconds=kwargs.pop("interval_seconds", 1.0),
        http_get=http_get,
        http_post=http_post,
        **kwargs,
    )


class TestWorkerTick:
    def test_pulls_missing_records(self):
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        peer_fake.store.publish_txt_record("alice.mesh.test", "value-1", ttl=300)
        peer_fake.store.publish_txt_record("bob.mesh.test", "value-2", ttl=300)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])

        worker.tick_once()

        assert local.query_txt_record("alice.mesh.test") == ["value-1"]
        assert local.query_txt_record("bob.mesh.test") == ["value-2"]
        assert worker.stats.records_written == 2
        assert peer_fake.digest_calls == 1
        assert peer_fake.pull_calls == 1

    def test_skips_already_present_records(self):
        local = InMemoryDNSStore()
        local.publish_txt_record("alice.mesh.test", "value-1", ttl=300)
        peer_fake = FakePeerHTTP("n2")
        peer_fake.store.publish_txt_record("alice.mesh.test", "value-1", ttl=300)
        peer_fake.store.publish_txt_record("new.mesh.test", "value-new", ttl=300)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])

        worker.tick_once()

        # Only new.mesh.test should have been pulled.
        assert local.query_txt_record("alice.mesh.test") == ["value-1"]
        assert local.query_txt_record("new.mesh.test") == ["value-new"]
        assert worker.stats.records_written == 1

    def test_watermark_advances(self):
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        peer_fake.store.publish_txt_record("a.mesh.test", "v", ttl=300)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])
        assert worker.watermark("n2") == 0

        worker.tick_once()
        assert worker.watermark("n2") > 0

    def test_second_tick_only_gets_new_records(self):
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        peer_fake.store.publish_txt_record("a.mesh.test", "v1", ttl=300)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])

        worker.tick_once()
        assert worker.stats.records_written == 1

        # Need to advance time so the NEXT record has stored_ts > watermark.
        time.sleep(1.1)
        peer_fake.store.publish_txt_record("b.mesh.test", "v2", ttl=300)

        worker.tick_once()
        # Only b was new.
        assert worker.stats.records_written == 2
        assert local.query_txt_record("b.mesh.test") == ["v2"]

    def test_unsolicited_record_rejected(self):
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2", lie_extra=True)
        peer_fake.store.publish_txt_record("asked.mesh.test", "ok", ttl=300)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])

        worker.tick_once()

        # asked.mesh.test was written; extra.mesh.test was rejected.
        assert local.query_txt_record("asked.mesh.test") == ["ok"]
        assert local.query_txt_record("extra.mesh.test") is None
        assert worker.stats.records_rejected >= 1

    def test_forged_signed_manifest_rejected(self):
        """A peer that returns a tampered slot-manifest must be rejected."""
        local = InMemoryDNSStore()

        # Prepare a real manifest and its tampered sibling.
        wire, _ = _signed_manifest()
        forged = wire[:-5] + "AAAAA"  # bit-flip a b64 suffix

        peer_fake = FakePeerHTTP("n2", forge_manifest=forged)
        peer_fake.store.publish_txt_record("slot-0.mb-abcd.mesh.test", wire, ttl=300)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])

        worker.tick_once()

        # Forged manifest should not have been stored.
        assert local.query_txt_record("slot-0.mb-abcd.mesh.test") is None
        assert worker.stats.records_rejected >= 1
        assert worker.stats.records_written == 0

    def test_round_robins_across_peers(self):
        local = InMemoryDNSStore()
        p1 = FakePeerHTTP("n2")
        p2 = FakePeerHTTP("n3")
        peers = [
            (SyncPeer(node_id="n2", http_endpoint="http://n2.example"), p1),
            (SyncPeer(node_id="n3", http_endpoint="http://n3.example"), p2),
        ]
        worker = _make_worker(local, peers)

        worker.tick_once()
        worker.tick_once()
        worker.tick_once()
        worker.tick_once()
        # Each peer should have been called at least once.
        assert p1.digest_calls >= 1
        assert p2.digest_calls >= 1

    def test_peer_403_counted_as_error(self):
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2", token="right-token")
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)], token="wrong-token")

        worker.tick_once()
        assert worker.stats.errors >= 1
        assert worker.stats.records_written == 0

    def test_empty_peer_list_is_idle(self):
        local = InMemoryDNSStore()
        worker = AntiEntropyWorker(
            store=local,
            peers=[],
            sync_token="x",
            interval_seconds=0.5,
        )
        worker.tick_once()  # no-op, no crash
        assert worker.stats.records_written == 0

    def test_start_stop_lifecycle(self):
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        peer_fake.store.publish_txt_record("x.mesh.test", "v", ttl=300)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)], interval_seconds=0.1)

        worker.start()
        time.sleep(0.4)  # allow at least one tick
        worker.stop(timeout=2.0)

        assert worker.stats.ticks >= 1
        assert local.query_txt_record("x.mesh.test") == ["v"]

    def test_stop_idempotent(self):
        local = InMemoryDNSStore()
        worker = AntiEntropyWorker(
            store=local,
            peers=[],
            sync_token="x",
            interval_seconds=0.2,
        )
        worker.start()
        worker.stop()
        worker.stop()  # must not raise
