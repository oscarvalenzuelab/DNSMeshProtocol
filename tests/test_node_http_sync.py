"""HTTP-level tests for /v1/sync/digest and /v1/sync/pull.

These hit the real http.server in a background thread with the sqlite
store so the full wire behavior (including auth, query parsing, and body
shape) is exercised end-to-end.
"""

from __future__ import annotations

import hashlib
import socket
import time
from typing import List

import pytest
import requests

from dmp.network.memory import InMemoryDNSStore
from dmp.server.anti_entropy import AntiEntropyWorker, SyncPeer
from dmp.server.http_api import DMPHttpApi
from dmp.storage.sqlite_store import SqliteMailboxStore


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def api_store_with_sync(tmp_path):
    store = SqliteMailboxStore(str(tmp_path / "n.db"))
    api = DMPHttpApi(
        store,
        host="127.0.0.1",
        port=_free_port(),
        sync_peer_token="sync-token",
    )
    api.start()
    try:
        yield api, store
    finally:
        api.stop()
        store.close()


@pytest.fixture
def api_store_no_sync(tmp_path):
    # sync_peer_token = None: endpoints should reject everyone.
    store = SqliteMailboxStore(str(tmp_path / "n.db"))
    api = DMPHttpApi(store, host="127.0.0.1", port=_free_port())
    api.start()
    try:
        yield api, store
    finally:
        api.stop()
        store.close()


def _base(api: DMPHttpApi) -> str:
    return f"http://127.0.0.1:{api.port}"


def _auth_hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestAuth:
    def test_digest_rejects_missing_token(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.get(f"{_base(api)}/v1/sync/digest?since=0", timeout=2)
        assert r.status_code == 403

    def test_digest_rejects_wrong_token(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since=0",
            headers=_auth_hdr("nope"),
            timeout=2,
        )
        assert r.status_code == 403

    def test_digest_rejects_when_no_token_configured(self, api_store_no_sync):
        api, _ = api_store_no_sync
        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since=0",
            headers=_auth_hdr("anything"),
            timeout=2,
        )
        assert r.status_code == 403

    def test_pull_rejects_missing_token(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.post(f"{_base(api)}/v1/sync/pull", json={"names": []}, timeout=2)
        assert r.status_code == 403

    def test_pull_rejects_wrong_token(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.post(
            f"{_base(api)}/v1/sync/pull",
            json={"names": []},
            headers=_auth_hdr("nope"),
            timeout=2,
        )
        assert r.status_code == 403


class TestDigest:
    def test_empty_store_returns_empty(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since=0",
            headers=_auth_hdr("sync-token"),
            timeout=2,
        )
        assert r.status_code == 200
        doc = r.json()
        assert doc["records"] == []
        assert doc["has_more"] is False

    def test_returns_records_since_watermark(self, api_store_with_sync):
        api, store = api_store_with_sync
        store.publish_txt_record("a.mesh.test", "v1", ttl=300)
        store.publish_txt_record("b.mesh.test", "v2", ttl=300)
        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since=0",
            headers=_auth_hdr("sync-token"),
            timeout=2,
        )
        assert r.status_code == 200
        doc = r.json()
        names = {e["name"] for e in doc["records"]}
        assert names == {"a.mesh.test", "b.mesh.test"}
        # hash == sha256(value)
        for e in doc["records"]:
            if e["name"] == "a.mesh.test":
                assert e["hash"] == hashlib.sha256(b"v1").hexdigest()
            elif e["name"] == "b.mesh.test":
                assert e["hash"] == hashlib.sha256(b"v2").hexdigest()
            # ts is ms-resolution since M2.4-followup; a fresh row must
            # have well more than 10^12 (year 2001 in ms) on any clock.
            assert isinstance(e["ts"], int) and e["ts"] > 1_000_000_000_000

    def test_filters_by_since(self, api_store_with_sync):
        api, store = api_store_with_sync
        store.publish_txt_record("old.mesh.test", "old", ttl=300)
        # stored_ts is ms-resolution; a short sleep is enough to get a
        # cursor strictly between the two writes. iter_records_since uses
        # strict >, so the pre-cursor row is excluded.
        time.sleep(0.01)
        cursor = int(time.time() * 1000)
        time.sleep(0.01)
        store.publish_txt_record("new.mesh.test", "new", ttl=300)

        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since={cursor}",
            headers=_auth_hdr("sync-token"),
            timeout=2,
        )
        assert r.status_code == 200
        names = {e["name"] for e in r.json()["records"]}
        assert "new.mesh.test" in names
        assert "old.mesh.test" not in names

    def test_limit_caps_and_has_more(self, api_store_with_sync):
        api, store = api_store_with_sync
        for i in range(5):
            store.publish_txt_record(f"r{i}.mesh.test", f"v{i}", ttl=300)
        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since=0&limit=2",
            headers=_auth_hdr("sync-token"),
            timeout=2,
        )
        assert r.status_code == 200
        doc = r.json()
        assert len(doc["records"]) == 2
        assert doc["has_more"] is True

    def test_negative_since_rejected(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since=-1",
            headers=_auth_hdr("sync-token"),
            timeout=2,
        )
        assert r.status_code == 400

    def test_bad_since_rejected(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since=abc",
            headers=_auth_hdr("sync-token"),
            timeout=2,
        )
        assert r.status_code == 400

    def test_expired_records_excluded(self, api_store_with_sync):
        api, store = api_store_with_sync
        store.publish_txt_record("expired.mesh.test", "gone", ttl=1)
        store.publish_txt_record("live.mesh.test", "here", ttl=300)
        time.sleep(1.2)
        r = requests.get(
            f"{_base(api)}/v1/sync/digest?since=0",
            headers=_auth_hdr("sync-token"),
            timeout=2,
        )
        names = {e["name"] for e in r.json()["records"]}
        assert "expired.mesh.test" not in names
        assert "live.mesh.test" in names


class TestPull:
    def test_returns_requested_values(self, api_store_with_sync):
        api, store = api_store_with_sync
        store.publish_txt_record("a.mesh.test", "val-a", ttl=300)
        store.publish_txt_record("b.mesh.test", "val-b", ttl=300)
        r = requests.post(
            f"{_base(api)}/v1/sync/pull",
            headers=_auth_hdr("sync-token"),
            json={"names": ["a.mesh.test", "b.mesh.test"]},
            timeout=2,
        )
        assert r.status_code == 200
        recs = r.json()["records"]
        by_name = {rec["name"]: rec for rec in recs}
        assert by_name["a.mesh.test"]["value"] == "val-a"
        assert by_name["b.mesh.test"]["value"] == "val-b"
        assert by_name["a.mesh.test"]["ttl"] > 0

    def test_missing_names_silently_omitted(self, api_store_with_sync):
        api, store = api_store_with_sync
        store.publish_txt_record("a.mesh.test", "val-a", ttl=300)
        r = requests.post(
            f"{_base(api)}/v1/sync/pull",
            headers=_auth_hdr("sync-token"),
            json={"names": ["a.mesh.test", "ghost.mesh.test"]},
            timeout=2,
        )
        assert r.status_code == 200
        names = {rec["name"] for rec in r.json()["records"]}
        assert names == {"a.mesh.test"}

    def test_expired_names_silently_omitted(self, api_store_with_sync):
        api, store = api_store_with_sync
        store.publish_txt_record("fresh.mesh.test", "v", ttl=300)
        store.publish_txt_record("expired.mesh.test", "v", ttl=1)
        time.sleep(1.2)
        r = requests.post(
            f"{_base(api)}/v1/sync/pull",
            headers=_auth_hdr("sync-token"),
            json={"names": ["fresh.mesh.test", "expired.mesh.test"]},
            timeout=2,
        )
        assert r.status_code == 200
        names = {rec["name"] for rec in r.json()["records"]}
        assert names == {"fresh.mesh.test"}

    def test_overflow_rejected(self, api_store_with_sync):
        api, _ = api_store_with_sync
        names = [f"n{i}.mesh.test" for i in range(300)]
        r = requests.post(
            f"{_base(api)}/v1/sync/pull",
            headers=_auth_hdr("sync-token"),
            json={"names": names},
            timeout=2,
        )
        assert r.status_code == 400

    def test_names_non_list_rejected(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.post(
            f"{_base(api)}/v1/sync/pull",
            headers=_auth_hdr("sync-token"),
            json={"names": "not-a-list"},
            timeout=2,
        )
        assert r.status_code == 400

    def test_names_with_non_strings_rejected(self, api_store_with_sync):
        api, _ = api_store_with_sync
        r = requests.post(
            f"{_base(api)}/v1/sync/pull",
            headers=_auth_hdr("sync-token"),
            json={"names": ["ok", 42]},
            timeout=2,
        )
        assert r.status_code == 400

    def test_rrset_multi_value_all_returned(self, api_store_with_sync):
        api, store = api_store_with_sync
        store.publish_txt_record("rrset.mesh.test", "v1", ttl=300)
        store.publish_txt_record("rrset.mesh.test", "v2", ttl=300)
        r = requests.post(
            f"{_base(api)}/v1/sync/pull",
            headers=_auth_hdr("sync-token"),
            json={"names": ["rrset.mesh.test"]},
            timeout=2,
        )
        assert r.status_code == 200
        recs = r.json()["records"]
        assert len(recs) == 2
        values = sorted(r["value"] for r in recs)
        assert values == ["v1", "v2"]


# ---- two-node in-process integration ------------------------------------


class TestTwoNode:
    def test_offline_node_catches_up(self, tmp_path):
        """Node B was offline when A got a write; it should catch up.

        Simulates the offline scenario by just writing to A's store
        directly (bypassing the fan-out write). B's anti-entropy worker
        should pull the missing record from A within a couple of ticks.
        """
        # Node A — full HTTP stack, acts as the digest/pull source.
        store_a = SqliteMailboxStore(str(tmp_path / "a.db"))
        api_a = DMPHttpApi(
            store_a,
            host="127.0.0.1",
            port=_free_port(),
            sync_peer_token="cluster-token",
        )
        api_a.start()

        # Node B — just a store plus a worker pointing at A.
        store_b = SqliteMailboxStore(str(tmp_path / "b.db"))
        peer = SyncPeer(node_id="a", http_endpoint=f"http://127.0.0.1:{api_a.port}")
        worker_b = AntiEntropyWorker(
            store=store_b,
            peers=[peer],
            sync_token="cluster-token",
            interval_seconds=0.2,
        )
        worker_b.start()

        try:
            # Simulate a write to A that B missed.
            store_a.publish_txt_record("alice.mesh.test", "offline-catchup", ttl=300)
            store_a.publish_txt_record("bob.mesh.test", "offline-catchup-2", ttl=300)

            # Wait up to 2 * sync_interval for B to catch up.
            deadline = time.time() + 2.0
            while time.time() < deadline:
                if store_b.query_txt_record(
                    "alice.mesh.test"
                ) and store_b.query_txt_record("bob.mesh.test"):
                    break
                time.sleep(0.1)

            assert store_b.query_txt_record("alice.mesh.test") == ["offline-catchup"]
            assert store_b.query_txt_record("bob.mesh.test") == ["offline-catchup-2"]
        finally:
            worker_b.stop()
            api_a.stop()
            store_a.close()
            store_b.close()
