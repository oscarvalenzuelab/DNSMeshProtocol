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

    ``cluster_manifest_wire`` controls the /v1/sync/cluster-manifest
    response (M3.3 gossip). Default None → 204 "no content"; setting a
    string returns it verbatim in a 200. ``cluster_manifest_raw_body``
    overrides the entire response body (used to test malformed /
    garbage payloads).
    """

    def __init__(
        self,
        peer_id: str,
        token: str = "peer-token",
        *,
        lie_extra: bool = False,
        forge_manifest: Optional[str] = None,
        cluster_manifest_wire: Optional[str] = None,
        cluster_manifest_raw_body: Optional[bytes] = None,
    ):
        self.peer_id = peer_id
        self.token = token
        self.store = InMemoryDNSStore()
        self.lie_extra = lie_extra
        self.forge_manifest = forge_manifest
        self.cluster_manifest_wire = cluster_manifest_wire
        self.cluster_manifest_raw_body = cluster_manifest_raw_body
        self.digest_calls = 0
        self.pull_calls = 0
        self.cluster_manifest_calls = 0

    def get(self, url: str, token: Optional[str], timeout: float) -> Tuple[int, bytes]:
        if token != self.token:
            return (403, b'{"error":"forbidden"}')
        if "/v1/sync/cluster-manifest" in url:
            self.cluster_manifest_calls += 1
            if self.cluster_manifest_raw_body is not None:
                return (200, self.cluster_manifest_raw_body)
            if self.cluster_manifest_wire is None:
                return (204, b"")
            # Shape the body the same way the real endpoint does.
            import base64 as _b64

            wire = self.cluster_manifest_wire
            try:
                blob = _b64.b64decode(wire[len("v=dmp1;t=cluster;") :], validate=True)
                body_bytes = blob[:-64]
                seq = int.from_bytes(body_bytes[7:15], "big")
                exp = int.from_bytes(body_bytes[15:23], "big")
                name_len = body_bytes[55]
                cluster_name = (
                    body_bytes[56 : 56 + name_len].decode("utf-8").rstrip(".")
                )
            except Exception:
                seq = 0
                exp = 0
                cluster_name = ""
            doc = {
                "wire": wire,
                "seq": seq,
                "exp": exp,
                "cluster_name": cluster_name,
            }
            return (200, json.dumps(doc).encode("utf-8"))
        if "/v1/sync/digest" in url:
            self.digest_calls += 1
            # Parse ?cursor=&limit= (primary) or legacy ?since=&limit=.
            q = url.split("?", 1)[1] if "?" in url else ""
            cursor: Tuple[int, str, str] = (0, "", "")
            limit = 1000
            for kv in q.split("&"):
                if kv.startswith("cursor="):
                    raw = kv[len("cursor=") :]
                    # Accept either "<ts>:<name>" (legacy) or
                    # "<ts>:<name>:<value_hash>" (followup-2).
                    parts = raw.split(":", 2)
                    if len(parts) == 2:
                        cursor = (int(parts[0]), parts[1], "")
                    elif len(parts) == 3:
                        cursor = (int(parts[0]), parts[1], parts[2])
                elif kv.startswith("since="):
                    cursor = (int(kv[len("since=") :]), "", "")
                elif kv.startswith("limit="):
                    limit = int(kv[len("limit=") :])
            rows = self.store.iter_records_since(cursor=cursor, limit=limit + 1)
            has_more = len(rows) > limit
            rows = rows[:limit]
            entries = [
                {
                    "name": r.name,
                    "hash": r.record_hash,
                    "ts": r.stored_ts,
                    "ttl": max(1, int(r.ttl_remaining)),
                }
                for r in rows
            ]
            if entries:
                last = entries[-1]
                next_cursor = f"{int(last['ts'])}:{last['name']}:{last['hash']}"
            else:
                next_cursor = f"{int(cursor[0])}:{cursor[1]}:{cursor[2]}"
            body = json.dumps(
                {
                    "records": entries,
                    "has_more": has_more,
                    "next_cursor": next_cursor,
                }
            ).encode("utf-8")
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
        # Initial watermark is the compound sentinel (0, "", "").
        assert worker.watermark("n2") == (0, "", "")

        worker.tick_once()
        # After the tick the watermark must have moved past the sentinel;
        # comparing tuples gives us strict monotonicity in
        # (ts, name, value_hash).
        wm = worker.watermark("n2")
        assert isinstance(wm, tuple) and len(wm) == 3
        assert wm > (0, "", "")
        assert wm[0] > 0
        assert wm[1] == "a.mesh.test"
        # value_hash is sha256(value) — 64 hex chars for the one real row
        assert len(wm[2]) == 64
        assert wm[2] == hashlib.sha256(b"v").hexdigest()

    def test_second_tick_only_gets_new_records(self):
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        peer_fake.store.publish_txt_record("a.mesh.test", "v1", ttl=300)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])

        worker.tick_once()
        assert worker.stats.records_written == 1

        # Publish a second record. stored_ts is millisecond-resolution so
        # a short sleep is enough for it to land above the watermark.
        time.sleep(0.01)
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

    def test_watermark_does_not_skip_unpulled_names_past_limit(self):
        """Regression: many same-ms records with >pull_limit missing.

        Pre-fix, the watermark advanced to max(digest.ts) even though we
        only pulled the first `pull_batch_limit` names, dropping the rest
        forever. Now it must cap strictly below the first deferred ts so
        subsequent ticks can catch up.
        """
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        # Populate the peer with more rows than a single pull request
        # can carry. The ms-resolution stored_ts means pagination also
        # can't rely on second-granularity cursor safety.
        total = 300
        for i in range(total):
            peer_fake.store.publish_txt_record(f"r{i:04d}.mesh.test", f"v{i}", ttl=300)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        # Use a small pull_batch_limit to force the deferred path.
        worker = _make_worker(
            local,
            [(peer, peer_fake)],
            pull_batch_limit=64,
            digest_batch_limit=total + 10,
        )

        # Bounded retries to account for the digest limit + pagination.
        for _ in range(10):
            worker.tick_once()
            if len(local.list_names()) >= total:
                break

        # All rows should have landed.
        for i in range(total):
            assert local.query_txt_record(f"r{i:04d}.mesh.test") == [f"v{i}"]

    def test_ttl_refresh_triggers_pull(self):
        """Peer republishes an identical value with a fresher TTL.

        The old hash-only diff missed this (hash(value) is identical),
        leaving the offline node with the stale expiry. With TTL carried
        alongside the hash, the worker detects the drift and issues a
        pull that refreshes the local expiry.
        """
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        # Both sides publish the same value with a short ttl.
        peer_fake.store.publish_txt_record("x.mesh.test", "shared", ttl=60)
        local.publish_txt_record("x.mesh.test", "shared", ttl=60)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])

        # First tick: hashes match and ttls match, so nothing to pull.
        worker.tick_once()
        assert peer_fake.pull_calls == 0

        # Peer republishes the SAME value with a much bigger ttl — the
        # new expiry is what the anti-entropy loop must propagate. Sleep
        # a tick so the refreshed stored_ts is strictly above the
        # watermark the worker captured on the previous digest.
        time.sleep(0.01)
        peer_fake.store.publish_txt_record("x.mesh.test", "shared", ttl=600)
        pulls_before = peer_fake.pull_calls

        worker.tick_once()

        # Second tick must notice the TTL jump and pull.
        assert peer_fake.pull_calls == pulls_before + 1
        # Local expiry should have been refreshed — remaining TTL comfortably
        # above the original 60s cap.
        rows = local.get_records_by_name(["x.mesh.test"])
        assert len(rows) == 1
        assert rows[0].ttl_remaining > 120

    def test_cursor_advances_across_same_ms_burst(self):
        """Regression: >pull_limit records published within the same ms.

        Pre-fix, the watermark was a plain ms. Advancing past the ms
        dropped the tail; holding the ms replayed the same page forever.
        The compound (ts, name) cursor now keeps pagination correct
        because the name half breaks ties within one millisecond.
        """
        import time as _time

        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        # Force every publish onto the same millisecond by monkey-patching
        # time.time for the duration of the burst. InMemoryDNSStore reads
        # time.time() once per publish so one fixed value pins them all
        # to one stored_ts.
        pinned_ms = int(_time.time() * 1000)
        real_time = _time.time

        def _pinned_time() -> float:
            return pinned_ms / 1000.0

        total = 200  # > pull_batch_limit below
        _time.time = _pinned_time
        try:
            for i in range(total):
                peer_fake.store.publish_txt_record(
                    f"r{i:04d}.mesh.test", f"v{i}", ttl=300
                )
        finally:
            _time.time = real_time

        # Sanity: all rows share the same stored_ts.
        stored_ts_set = {
            row.stored_ts for row in peer_fake.store.iter_records_since(cursor=(0, ""))
        }
        assert len(stored_ts_set) == 1

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(
            local,
            [(peer, peer_fake)],
            pull_batch_limit=64,
            digest_batch_limit=total + 10,
            interval_seconds=0.5,  # used only as a lower bound on sleep
        )

        # With interval_seconds=0.5 and the spec's "2 * sync_interval"
        # budget we have 1.0s; tick_once is synchronous so do the loop
        # directly for determinism. Bound retries so a regression fails
        # loudly instead of hanging.
        for _ in range(20):
            worker.tick_once()
            if len(local.list_names()) >= total:
                break

        for i in range(total):
            assert local.query_txt_record(f"r{i:04d}.mesh.test") == [f"v{i}"]

    def test_malformed_digest_entry_does_not_advance_watermark(self):
        """Peer returns a digest entry with a far-future ts and an
        unparseable name/hash. The local watermark MUST NOT advance to
        that ts — if it did, legitimate lower-ts updates would live
        forever below the poisoned cutoff."""
        from typing import Optional

        local = InMemoryDNSStore()

        # Build a fake that returns a single malformed entry regardless
        # of what we ask for.
        far_future_ms = int(time.time() * 1000) + 10 * 365 * 24 * 3600 * 1000

        def bad_get(url: str, token: Optional[str], timeout: float):
            body = json.dumps(
                {
                    "records": [
                        {
                            "name": "bogus name with spaces!!!",
                            "hash": "notsha256",
                            "ts": far_future_ms,
                            "ttl": 300,
                        }
                    ],
                    "has_more": False,
                    "next_cursor": f"{far_future_ms}:bogus name with spaces!!!",
                }
            ).encode("utf-8")
            return (200, body)

        def bad_post(url: str, token: Optional[str], body: bytes, timeout: float):
            return (200, b'{"records": []}')

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = AntiEntropyWorker(
            store=local,
            peers=[peer],
            sync_token="tok",
            interval_seconds=1.0,
            http_get=bad_get,
            http_post=bad_post,
        )

        worker.tick_once()

        # Watermark must still be the sentinel — peer poisoned it with
        # unvalidated junk, so we refuse to move.
        wm = worker.watermark("n2")
        assert wm == (0, "", ""), (
            f"watermark advanced past malformed entry: {wm}; "
            f"far_future_ms was {far_future_ms}"
        )
        # The malformed entry should have been counted as rejected.
        assert worker.stats.records_rejected >= 1

    def test_peer_lying_about_next_cursor_ignored(self):
        """Peer returns legitimate records but lies about next_cursor
        pointing far past the last record. We must advance only to the
        max (ts, name) of validated-and-handled records, never to the
        peer's fabricated cursor."""
        from typing import Optional

        local = InMemoryDNSStore()
        # The real-record ts the peer actually has.
        real_ts_ms = int(time.time() * 1000)
        # The lie: a cursor far past real_ts but still inside the
        # clock-skew window (otherwise _parse_next_cursor would drop it
        # entirely — we want to test the "cursor past validated set"
        # branch, not the "cursor rejected as forged future" branch).
        lying_ts_ms = real_ts_ms + 30_000  # +30s, inside 60s skew cap

        # sha256("valid-value-1").hexdigest()
        h1 = hashlib.sha256(b"valid-value-1").hexdigest()

        def get_handler(url: str, token: Optional[str], timeout: float):
            body = json.dumps(
                {
                    "records": [
                        {
                            "name": "real.mesh.test",
                            "hash": h1,
                            "ts": real_ts_ms,
                            "ttl": 300,
                        }
                    ],
                    "has_more": False,
                    # Peer claims there's a much later cursor to
                    # fast-forward past.
                    "next_cursor": f"{lying_ts_ms}:xxxxx.mesh.test",
                }
            ).encode("utf-8")
            return (200, body)

        def post_handler(url: str, token: Optional[str], body: bytes, timeout: float):
            doc = json.loads(body.decode("utf-8"))
            out = []
            for name in doc["names"]:
                if name == "real.mesh.test":
                    out.append({"name": name, "value": "valid-value-1", "ttl": 300})
            return (200, json.dumps({"records": out}).encode("utf-8"))

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = AntiEntropyWorker(
            store=local,
            peers=[peer],
            sync_token="tok",
            interval_seconds=1.0,
            http_get=get_handler,
            http_post=post_handler,
        )

        worker.tick_once()

        # The record was written.
        assert local.query_txt_record("real.mesh.test") == ["valid-value-1"]
        # And the watermark must have advanced to AT MOST the validated
        # record's (ts, name), never to the lying cursor. The peer's
        # next_cursor points to `(lying_ts_ms, "xxxxx.mesh.test")` which
        # compares strictly greater than `(real_ts_ms, "real.mesh.test")`.
        # Because all records were handled and next_cursor is past
        # max_handled AND len(handled)==len(valid_entries), the current
        # code *would* accept next_cursor... but the hard property is
        # that a lying peer cannot push us past REAL data. Assert the
        # watermark is not greater than what the real record could
        # justify PLUS a safety margin: it must be <= (lying_ts_ms,
        # "xxxxx.mesh.test") — but critically NOT advance by ts alone
        # ahead of any record we actually saw. The safest contract is:
        # if everything in the page was handled, trust next_cursor IF
        # AND ONLY IF has_more=false. But the peer can still lie there.
        # The test enforces that the watermark stays at or below the
        # max of validated-and-handled entries.
        wm = worker.watermark("n2")
        # Compare 3-tuples: the watermark now carries (ts, name,
        # value_hash). It MUST be pinned to the real record — anything
        # past that would mean the peer's lying next_cursor was trusted.
        expected_hash = hashlib.sha256(b"valid-value-1").hexdigest()
        assert wm == (real_ts_ms, "real.mesh.test", expected_hash), (
            f"watermark {wm} did not land at the validated record; "
            f"expected ({real_ts_ms}, 'real.mesh.test', {expected_hash!r})"
        )

    # ---- M2.4 follow-up-2: multi-value RRset cursor pagination ---------

    def test_cursor_with_valuehash_paginates_same_name_burst(self):
        """Regression for Codex P2 (cursor value_hash tiebreaker).

        Force > ``limit`` distinct values at the SAME
        ``(stored_ts, name)`` — a multi-value RRset burst all landing
        inside one ms at one name — and make the store emit them across
        multiple pages via a small ``limit``. Pre-fix the cursor was
        (ts, name); the next page started with ``name > cur_name`` and
        silently dropped the remaining values at that very (ts, name).
        Post-fix the cursor carries value_hash too, so
        ``value_hash > cur_hash`` keeps pagination correct.

        This hits the store's ``iter_records_since`` directly because
        that is where the cursor tiebreaker lives — the worker-level
        test_multi_value_rrset_all_values_synced exercises the Codex-P1
        (name, hash) diff in tandem.
        """
        import time as _time

        peer_store = InMemoryDNSStore()
        pinned_ms = int(_time.time() * 1000)
        real_time = _time.time

        def _pinned_time() -> float:
            return pinned_ms / 1000.0

        shared_name = "burst.mesh.test"
        total = 50

        _time.time = _pinned_time
        try:
            for i in range(total):
                peer_store.publish_txt_record(shared_name, f"value-{i:04d}", ttl=300)
        finally:
            _time.time = real_time

        # Sanity: all rows share one (stored_ts, name) but different
        # value_hashes.
        all_rows = peer_store.iter_records_since(cursor=(0, "", ""))
        assert len(all_rows) == total
        assert {r.stored_ts for r in all_rows} == {pinned_ms}
        assert {r.name for r in all_rows} == {shared_name}

        # Walk the cursor across multiple small pages, same as a peer
        # worker would. Pre-fix this loop would drop values at the
        # same (ts, name) on every page boundary.
        page_limit = 7
        collected: List[str] = []
        cursor: Tuple[int, str, str] = (0, "", "")
        for _ in range(50):  # bounded
            page = peer_store.iter_records_since(cursor=cursor, limit=page_limit)
            if not page:
                break
            for r in page:
                collected.append(r.value)
            last = page[-1]
            # Advance to the last row's (ts, name, value_hash).
            last_hash = hashlib.sha256(last.value.encode("utf-8")).hexdigest()
            cursor = (last.stored_ts, last.name, last_hash)
            if len(page) < page_limit:
                break

        assert sorted(collected) == sorted(
            f"value-{i:04d}" for i in range(total)
        ), f"paginated walk lost values: got {len(collected)} of {total}"

    def test_multi_value_rrset_all_values_synced(self):
        """Regression for Codex P1 (diff on (name, hash) pairs).

        A name with multiple TXT values under it (e.g. a prekey set:
        5 entries at ``prekeys.id-xxx``) must sync *every* value to
        the offline node, not just the first one. Pre-fix, the diff
        keyed on ``name`` alone — so the second through fifth digest
        entries for the same name were marked "seen" by the first
        and silently dropped.
        """
        local = InMemoryDNSStore()
        peer_fake = FakePeerHTTP("n2")
        # Publish one name with five distinct TXT values at node A.
        prekey_name = "prekeys.id-xxx.mesh.test"
        values = [f"prekey-value-{i}" for i in range(5)]
        for v in values:
            peer_fake.store.publish_txt_record(prekey_name, v, ttl=300)
            # Space writes so stored_ts differs — in the real sqlite
            # path writes inside one ms collapse to one stored_ts but
            # each sits at a distinct value_hash so pagination still
            # orders them.
            time.sleep(0.001)

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_worker(local, [(peer, peer_fake)])

        worker.tick_once()

        local_vals = local.query_txt_record(prekey_name)
        assert local_vals is not None
        assert sorted(local_vals) == sorted(
            values
        ), f"expected all 5 values synced; got {local_vals}"
        assert worker.stats.records_written == 5

    def test_peer_returns_wrong_value_rejected(self):
        """Regression for Codex P1 (hash-verify pulled value vs digest).

        A buggy/malicious peer that advertises hash H1 for a name and
        returns a value hashing to H2 on /pull must be rejected.
        Accepting would both write the wrong value AND advance the
        watermark past H1 (the write's stored_ts would leap forward),
        so H1 would never be retried.
        """
        local = InMemoryDNSStore()
        # real_ts inside the clock-skew window so _valid_digest_entry
        # accepts the entry as structurally sound.
        real_ts_ms = int(time.time() * 1000)
        # Peer *advertises* hash H1 (sha256("real-value")) — what the
        # digest wire says the name carries.
        h1 = hashlib.sha256(b"real-value").hexdigest()

        def get_handler(url, token, timeout):
            body = json.dumps(
                {
                    "records": [
                        {
                            "name": "target.mesh.test",
                            "hash": h1,
                            "ts": real_ts_ms,
                            "ttl": 300,
                        }
                    ],
                    "has_more": False,
                    "next_cursor": f"{real_ts_ms}:target.mesh.test:{h1}",
                }
            ).encode("utf-8")
            return (200, body)

        # Peer *returns* a different value (whose hash is H2) on /pull.
        def post_handler(url, token, body, timeout):
            doc = json.loads(body.decode("utf-8"))
            out = []
            for name in doc["names"]:
                if name == "target.mesh.test":
                    out.append(
                        {
                            "name": name,
                            "value": "WRONG-VALUE-hash-mismatch",
                            "ttl": 300,
                        }
                    )
            return (200, json.dumps({"records": out}).encode("utf-8"))

        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = AntiEntropyWorker(
            store=local,
            peers=[peer],
            sync_token="tok",
            interval_seconds=1.0,
            http_get=get_handler,
            http_post=post_handler,
        )

        worker.tick_once()

        # Local write did NOT happen. The wrong value was rejected.
        assert local.query_txt_record("target.mesh.test") is None
        assert worker.stats.records_written == 0
        assert worker.stats.records_rejected >= 1

        # Watermark did NOT advance past the unhandled pair. Pre-fix
        # it would have sat at (real_ts_ms, "target.mesh.test", h1);
        # post-fix it must stay at the initial sentinel because the
        # only digest entry went unhandled.
        wm = worker.watermark("n2")
        # Strict: the watermark cannot have advanced to anything at or
        # past (real_ts_ms, "target.mesh.test", h1).
        assert wm < (real_ts_ms, "target.mesh.test", h1), (
            f"watermark {wm} advanced past a pair we never actually "
            f"wrote — next tick will never retry that (name, hash)"
        )


# ---- M3.3 manifest gossip ------------------------------------------------


def _make_cluster(
    op: DMPCrypto,
    *,
    seq: int,
    cluster_name: str = "mesh.example.com",
    nodes: Optional[List[ClusterNode]] = None,
    exp_in: int = 3600,
) -> Tuple[str, ClusterManifest]:
    manifest = ClusterManifest(
        cluster_name=cluster_name,
        operator_spk=op.get_signing_public_key_bytes(),
        nodes=nodes
        or [
            ClusterNode(node_id="node-a", http_endpoint="http://n-a.example:8053"),
            ClusterNode(node_id="node-b", http_endpoint="http://n-b.example:8053"),
            ClusterNode(node_id="node-c", http_endpoint="http://n-c.example:8053"),
        ],
        seq=seq,
        exp=int(time.time()) + exp_in,
    )
    return manifest.sign(op), manifest


def _make_gossip_worker(
    local_store: InMemoryDNSStore,
    peers: List[Tuple[SyncPeer, FakePeerHTTP]],
    *,
    operator_spk: Optional[bytes] = None,
    base_domain: Optional[str] = "mesh.example.com",
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
        cluster_operator_spk=operator_spk,
        base_domain=base_domain,
        http_get=http_get,
        http_post=http_post,
        **kwargs,
    )


class TestGossipManifest:
    """Manifest gossip — M3.3 node-to-node rollout."""

    def test_gossip_installs_higher_seq_manifest(self):
        """Peer serves seq=5; local has seq=3; install and republish."""
        from dmp.core.cluster import cluster_rrset_name

        local = InMemoryDNSStore()
        op = DMPCrypto()

        # Seed local with seq=3 manifest.
        wire_local, _ = _make_cluster(op, seq=3)
        rrset = cluster_rrset_name("mesh.example.com")
        local.publish_txt_record(rrset, wire_local, ttl=300)

        # Peer holds seq=5 manifest to gossip.
        wire_peer, _ = _make_cluster(op, seq=5)
        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=wire_peer)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=op.get_signing_public_key_bytes(),
        )

        worker.tick_once()

        # Local must now serve BOTH the old (append-semantics kept it)
        # and the new wire. Highest-seq is the peer's.
        values = local.query_txt_record(rrset) or []
        assert wire_peer in values

    def test_gossip_rejects_lower_seq_manifest(self):
        """Peer at seq=2; local at seq=5 — no-op."""
        from dmp.core.cluster import cluster_rrset_name

        local = InMemoryDNSStore()
        op = DMPCrypto()
        wire_local, _ = _make_cluster(op, seq=5)
        rrset = cluster_rrset_name("mesh.example.com")
        local.publish_txt_record(rrset, wire_local, ttl=300)

        wire_peer, _ = _make_cluster(op, seq=2)
        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=wire_peer)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=op.get_signing_public_key_bytes(),
        )

        worker.tick_once()

        values = local.query_txt_record(rrset) or []
        # Peer's older wire must NOT have been installed.
        assert wire_peer not in values
        assert wire_local in values

    def test_gossip_rejects_unsigned_wire(self):
        """Peer returns garbage — no install."""
        from dmp.core.cluster import cluster_rrset_name

        local = InMemoryDNSStore()
        op = DMPCrypto()

        # Raw body returns total junk where the wire field is garbage.
        garbage_body = json.dumps(
            {
                "wire": "not-a-wire-record",
                "seq": 99,
                "exp": int(time.time()) + 3600,
                "cluster_name": "mesh.example.com",
            }
        ).encode("utf-8")
        peer_fake = FakePeerHTTP("n2", cluster_manifest_raw_body=garbage_body)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=op.get_signing_public_key_bytes(),
        )

        worker.tick_once()

        rrset = cluster_rrset_name("mesh.example.com")
        assert local.query_txt_record(rrset) in (None, [])
        # The peer must not have poked the worker's installed seq.
        assert worker.peers == [peer]

    def test_gossip_rejects_wrong_operator_key(self):
        """Manifest signed by DIFFERENT key — rejected."""
        from dmp.core.cluster import cluster_rrset_name

        local = InMemoryDNSStore()
        pinned = DMPCrypto()  # worker pins this key
        other = DMPCrypto()  # peer serves a manifest signed by THIS key

        wire_peer, _ = _make_cluster(other, seq=99)
        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=wire_peer)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=pinned.get_signing_public_key_bytes(),
        )

        worker.tick_once()

        rrset = cluster_rrset_name("mesh.example.com")
        # The wrong-key manifest was NOT installed.
        assert wire_peer not in (local.query_txt_record(rrset) or [])

    def test_gossip_rejects_expired_manifest(self):
        """Manifest past its expiry — rejected even if seq is high."""
        from dmp.core.cluster import cluster_rrset_name

        local = InMemoryDNSStore()
        op = DMPCrypto()

        # Expiry 10s in the past.
        wire_peer, _ = _make_cluster(op, seq=99, exp_in=-10)
        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=wire_peer)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=op.get_signing_public_key_bytes(),
        )

        worker.tick_once()

        rrset = cluster_rrset_name("mesh.example.com")
        assert wire_peer not in (local.query_txt_record(rrset) or [])

    def test_gossip_rejects_wrong_cluster_name(self):
        """Manifest bound to a DIFFERENT cluster_name — rejected."""
        from dmp.core.cluster import cluster_rrset_name

        local = InMemoryDNSStore()
        op = DMPCrypto()

        # Peer serves a manifest for cluster "other.example.com" when
        # the worker is pinned to "mesh.example.com".
        wire_peer, _ = _make_cluster(op, seq=99, cluster_name="other.example.com")
        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=wire_peer)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=op.get_signing_public_key_bytes(),
        )

        worker.tick_once()

        rrset = cluster_rrset_name("mesh.example.com")
        assert wire_peer not in (local.query_txt_record(rrset) or [])

    def test_gossip_updates_peer_list_on_manifest_change(self):
        """New manifest adds node-d; worker's peer list grows."""
        local = InMemoryDNSStore()
        op = DMPCrypto()

        # Seed local with 3-node manifest at seq=1.
        wire_local, _ = _make_cluster(op, seq=1)
        from dmp.core.cluster import cluster_rrset_name

        local.publish_txt_record(
            cluster_rrset_name("mesh.example.com"), wire_local, ttl=300
        )

        # Peer's newer manifest has 4 nodes.
        new_nodes = [
            ClusterNode(node_id="node-a", http_endpoint="http://n-a.example:8053"),
            ClusterNode(node_id="node-b", http_endpoint="http://n-b.example:8053"),
            ClusterNode(node_id="node-c", http_endpoint="http://n-c.example:8053"),
            ClusterNode(node_id="node-d", http_endpoint="http://n-d.example:8053"),
        ]
        wire_peer, _ = _make_cluster(op, seq=2, nodes=new_nodes)
        # Worker's initial peer is "peer-b" at a different URL; peer
        # faking the response is the one it talks to.
        peer_a = SyncPeer(node_id="node-b", http_endpoint="http://n-b.example:8053")
        peer_fake_a = FakePeerHTTP("node-b", cluster_manifest_wire=wire_peer)

        worker = _make_gossip_worker(
            local,
            [(peer_a, peer_fake_a)],
            operator_spk=op.get_signing_public_key_bytes(),
            self_node_id="node-a",  # this node is node-a
        )
        # Worker starts with one peer (node-b).
        assert [p.node_id for p in worker.peers] == ["node-b"]

        worker.tick_once()

        # After gossip: node-a (self) excluded, node-b/c/d present.
        ids = {p.node_id for p in worker.peers}
        assert "node-a" not in ids  # self filtered
        assert ids == {"node-b", "node-c", "node-d"}

    def test_gossip_removes_peer_on_manifest_change(self):
        """New manifest drops node-c; worker's peer list shrinks."""
        local = InMemoryDNSStore()
        op = DMPCrypto()

        # Seed local with 3-node manifest.
        wire_local, _ = _make_cluster(op, seq=1)
        from dmp.core.cluster import cluster_rrset_name

        local.publish_txt_record(
            cluster_rrset_name("mesh.example.com"), wire_local, ttl=300
        )

        # New manifest has only node-a and node-b (node-c removed).
        new_nodes = [
            ClusterNode(node_id="node-a", http_endpoint="http://n-a.example:8053"),
            ClusterNode(node_id="node-b", http_endpoint="http://n-b.example:8053"),
        ]
        wire_peer, _ = _make_cluster(op, seq=2, nodes=new_nodes)
        peer_b = SyncPeer(node_id="node-b", http_endpoint="http://n-b.example:8053")
        peer_c = SyncPeer(node_id="node-c", http_endpoint="http://n-c.example:8053")
        peer_fake_b = FakePeerHTTP("node-b", cluster_manifest_wire=wire_peer)
        peer_fake_c = FakePeerHTTP("node-c", cluster_manifest_wire=wire_peer)

        worker = _make_gossip_worker(
            local,
            [(peer_b, peer_fake_b), (peer_c, peer_fake_c)],
            operator_spk=op.get_signing_public_key_bytes(),
            self_node_id="node-a",
        )
        # Seed a watermark for node-c so we can assert it's cleared.
        worker.set_watermark("node-c", (999, "some.name", "a" * 64))
        assert worker.watermark("node-c") == (999, "some.name", "a" * 64)

        # First tick talks to node-b (round-robin index 0) and installs
        # the new manifest — which drops node-c.
        worker.tick_once()

        ids = {p.node_id for p in worker.peers}
        assert "node-c" not in ids
        assert ids == {"node-b"}

        # Watermark for node-c was cleared by the peer swap.
        assert worker.watermark("node-c") == (0, "", "")

    def test_gossip_disabled_without_operator_spk(self):
        """Worker without an operator_spk never fetches /cluster-manifest."""
        local = InMemoryDNSStore()
        op = DMPCrypto()
        wire_peer, _ = _make_cluster(op, seq=5)
        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=wire_peer)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")

        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=None,  # explicitly disabled
        )

        worker.tick_once()
        worker.tick_once()

        # The gossip endpoint was never called.
        assert peer_fake.cluster_manifest_calls == 0

    def test_gossip_disabled_without_base_domain(self):
        """Worker with operator_spk but no base_domain cannot verify
        cluster_name binding; gossip stays off."""
        local = InMemoryDNSStore()
        op = DMPCrypto()
        wire_peer, _ = _make_cluster(op, seq=5)
        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=wire_peer)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")

        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=op.get_signing_public_key_bytes(),
            base_domain=None,
        )

        worker.tick_once()
        assert peer_fake.cluster_manifest_calls == 0

    def test_self_exclusion_by_node_id(self):
        """A peer entry with node_id matching self_node_id is dropped
        on construction."""
        local = InMemoryDNSStore()
        peer_self = SyncPeer(node_id="me", http_endpoint="http://self.example:8053")
        peer_other = SyncPeer(
            node_id="other", http_endpoint="http://other.example:8053"
        )
        worker = AntiEntropyWorker(
            store=local,
            peers=[peer_self, peer_other],
            sync_token="tok",
            interval_seconds=1.0,
            self_node_id="me",
        )
        assert [p.node_id for p in worker.peers] == ["other"]

    def test_self_exclusion_by_http_endpoint(self):
        """A peer entry with http_endpoint matching self_http_endpoint is
        dropped — a future manifest-generator writing self into the list
        cannot wedge the worker on a self-sync loop."""
        local = InMemoryDNSStore()
        # Note: the self endpoint has a trailing slash, the peer entry
        # does not. Normalization must make them match.
        peer_self = SyncPeer(node_id="twin-a", http_endpoint="http://self.example:8053")
        peer_other = SyncPeer(
            node_id="other", http_endpoint="http://other.example:8053"
        )
        worker = AntiEntropyWorker(
            store=local,
            peers=[peer_self, peer_other],
            sync_token="tok",
            interval_seconds=1.0,
            self_http_endpoint="http://self.example:8053/",
        )
        assert [p.node_id for p in worker.peers] == ["other"]

    def test_replace_peers_preserves_watermarks_for_retained(self):
        """replace_peers keeps watermarks for peers still in the new set."""
        local = InMemoryDNSStore()
        p_a = SyncPeer(node_id="a", http_endpoint="http://a.example:8053")
        p_b = SyncPeer(node_id="b", http_endpoint="http://b.example:8053")
        worker = AntiEntropyWorker(
            store=local,
            peers=[p_a, p_b],
            sync_token="tok",
            interval_seconds=1.0,
        )
        worker.set_watermark("a", (1000, "alice", "f" * 64))
        worker.set_watermark("b", (2000, "bob", "e" * 64))

        # Swap: keep a, drop b, add c.
        p_c = SyncPeer(node_id="c", http_endpoint="http://c.example:8053")
        worker.replace_peers([p_a, p_c])

        ids = {p.node_id for p in worker.peers}
        assert ids == {"a", "c"}
        # a's watermark preserved.
        assert worker.watermark("a") == (1000, "alice", "f" * 64)
        # b's watermark dropped.
        assert worker.watermark("b") == (0, "", "")
        # c is fresh.
        assert worker.watermark("c") == (0, "", "")

    def test_gossip_no_op_when_peer_has_same_seq(self):
        """Peer and local both at seq=5 — no install, no peer swap."""
        from dmp.core.cluster import cluster_rrset_name

        local = InMemoryDNSStore()
        op = DMPCrypto()
        wire, _ = _make_cluster(op, seq=5)
        local.publish_txt_record(cluster_rrset_name("mesh.example.com"), wire, ttl=300)

        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=wire)
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=op.get_signing_public_key_bytes(),
        )

        # Initial peer list is just the one synthetic peer; if gossip
        # installed a "same-seq" manifest the list would mutate.
        before = [p.node_id for p in worker.peers]
        worker.tick_once()
        after = [p.node_id for p in worker.peers]
        assert before == after

    def test_gossip_peer_returns_204(self):
        """Peer has no manifest to share — gossip returns silently."""
        local = InMemoryDNSStore()
        op = DMPCrypto()

        peer_fake = FakePeerHTTP("n2", cluster_manifest_wire=None)  # 204
        peer = SyncPeer(node_id="n2", http_endpoint="http://n2.example")
        worker = _make_gossip_worker(
            local,
            [(peer, peer_fake)],
            operator_spk=op.get_signing_public_key_bytes(),
        )

        worker.tick_once()
        assert peer_fake.cluster_manifest_calls == 1
        # No peer-set changes.
        assert [p.node_id for p in worker.peers] == ["n2"]
