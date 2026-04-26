"""Tests for the HTTP API exposing DMP records."""

import socket
import time
from pathlib import Path

import pytest
import requests

from dmp.core.crypto import DMPCrypto
from dmp.core.heartbeat import HeartbeatRecord
from dmp.network.memory import InMemoryDNSStore
from dmp.server.heartbeat_store import SeenStore
from dmp.server.http_api import DMPHttpApi


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def api_store():
    store = InMemoryDNSStore()
    api = DMPHttpApi(store, host="127.0.0.1", port=_free_port())
    api.start()
    try:
        yield api, store
    finally:
        api.stop()


@pytest.fixture
def auth_api_store():
    store = InMemoryDNSStore()
    api = DMPHttpApi(store, host="127.0.0.1", port=_free_port(), bearer_token="s3cret")
    api.start()
    try:
        yield api, store
    finally:
        api.stop()


def _base(api: DMPHttpApi) -> str:
    return f"http://127.0.0.1:{api.port}"


class TestHealthAndStats:
    def test_health_endpoint(self, api_store):
        api, _ = api_store
        r = requests.get(f"{_base(api)}/health", timeout=2)
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    def test_stats_endpoint(self, api_store):
        api, store = api_store
        store.publish_txt_record("x.example.com", "v")
        r = requests.get(f"{_base(api)}/stats", timeout=2)
        assert r.status_code == 200


class TestRecordsCrud:
    def test_post_publishes_record(self, api_store):
        api, store = api_store
        r = requests.post(
            f"{_base(api)}/v1/records/alice.mesh.test",
            json={"value": "v=dmp1;t=id;d=abc", "ttl": 60},
            timeout=2,
        )
        assert r.status_code == 201
        assert store.query_txt_record("alice.mesh.test") == ["v=dmp1;t=id;d=abc"]

    def test_get_returns_stored_values(self, api_store):
        api, store = api_store
        store.publish_txt_record("alice.mesh.test", "payload")
        r = requests.get(f"{_base(api)}/v1/records/alice.mesh.test", timeout=2)
        assert r.status_code == 200
        assert r.json()["values"] == ["payload"]

    def test_get_missing_returns_404(self, api_store):
        api, _ = api_store
        r = requests.get(f"{_base(api)}/v1/records/ghost.mesh.test", timeout=2)
        assert r.status_code == 404

    def test_delete_removes_record(self, api_store):
        api, store = api_store
        store.publish_txt_record("alice.mesh.test", "bye")
        r = requests.delete(f"{_base(api)}/v1/records/alice.mesh.test", timeout=2)
        assert r.status_code == 204
        assert store.query_txt_record("alice.mesh.test") is None

    def test_post_rejects_invalid_body(self, api_store):
        api, _ = api_store
        r = requests.post(
            f"{_base(api)}/v1/records/x.example.com",
            data="not-json",
            timeout=2,
        )
        assert r.status_code == 400

    def test_post_rejects_zero_ttl(self, api_store):
        api, _ = api_store
        r = requests.post(
            f"{_base(api)}/v1/records/x.example.com",
            json={"value": "v", "ttl": 0},
            timeout=2,
        )
        assert r.status_code == 400


class TestResourceCaps:
    def test_post_rejects_ttl_over_cap(self):
        store = InMemoryDNSStore()
        api = DMPHttpApi(store, host="127.0.0.1", port=_free_port(), max_ttl=300)
        api.start()
        try:
            r = requests.post(
                f"http://127.0.0.1:{api.port}/v1/records/x.example.com",
                json={"value": "v", "ttl": 3600},
                timeout=2,
            )
            assert r.status_code == 400
            assert "ttl exceeds cap" in r.text
        finally:
            api.stop()

    def test_post_rejects_oversized_value(self):
        store = InMemoryDNSStore()
        api = DMPHttpApi(
            store, host="127.0.0.1", port=_free_port(), max_value_bytes=100
        )
        api.start()
        try:
            r = requests.post(
                f"http://127.0.0.1:{api.port}/v1/records/x.example.com",
                json={"value": "A" * 1000, "ttl": 60},
                timeout=2,
            )
            assert r.status_code == 400
            assert "value exceeds cap" in r.text
        finally:
            api.stop()

    def test_post_rejects_rrset_past_cardinality_cap(self):
        store = InMemoryDNSStore()
        api = DMPHttpApi(
            store, host="127.0.0.1", port=_free_port(), max_values_per_name=3
        )
        api.start()
        try:
            base = f"http://127.0.0.1:{api.port}"
            # Fill the RRset up to the cap.
            for i in range(3):
                r = requests.post(
                    f"{base}/v1/records/full.example.com",
                    json={"value": f"v{i}", "ttl": 60},
                    timeout=2,
                )
                assert r.status_code == 201
            # Next distinct value is rejected.
            r = requests.post(
                f"{base}/v1/records/full.example.com",
                json={"value": "v-overflow", "ttl": 60},
                timeout=2,
            )
            assert r.status_code == 413
            # Re-publishing an existing value is idempotent and NOT rejected.
            r = requests.post(
                f"{base}/v1/records/full.example.com",
                json={"value": "v0", "ttl": 60},
                timeout=2,
            )
            assert r.status_code == 201
        finally:
            api.stop()


class TestAuth:
    def test_unauth_request_rejected(self, auth_api_store):
        api, _ = auth_api_store
        r = requests.post(
            f"{_base(api)}/v1/records/x.example.com",
            json={"value": "v", "ttl": 60},
            timeout=2,
        )
        assert r.status_code == 401

    def test_bearer_accepted(self, auth_api_store):
        api, store = auth_api_store
        r = requests.post(
            f"{_base(api)}/v1/records/x.example.com",
            json={"value": "v", "ttl": 60},
            headers={"Authorization": "Bearer s3cret"},
            timeout=2,
        )
        assert r.status_code == 201
        assert store.query_txt_record("x.example.com") == ["v"]

    def test_wrong_bearer_rejected(self, auth_api_store):
        api, _ = auth_api_store
        r = requests.post(
            f"{_base(api)}/v1/records/x.example.com",
            json={"value": "v", "ttl": 60},
            headers={"Authorization": "Bearer wrong"},
            timeout=2,
        )
        assert r.status_code == 401

    def test_health_still_open_without_token(self, auth_api_store):
        api, _ = auth_api_store
        r = requests.get(f"{_base(api)}/health", timeout=2)
        assert r.status_code == 200


class TestSelfRowSynthesisOverridesGossipped:
    """Codex round-22 P2 — the synthesized self-row at /  must
    overwrite any peer-gossipped self entry. Pre-fix: a peer's
    stale self-wire (e.g. version 0.5.0 from before an upgrade)
    was kept in ``merged`` and the synthesized row was skipped,
    so the operator's own /nodes page lied about the running
    version after every upgrade until peer harvest cycles caught
    up. Post-fix: synthesized self always wins; peer-gossipped
    self is only consulted for the ``sources`` count."""

    def test_self_row_uses_running_version_not_gossipped(self, tmp_path: Path):
        # Boot a SeenStore + ingest a peer-gossipped self-wire
        # at an old version. (Same operator key as self, since
        # peers gossip what they harvested from us.)
        seen_store = SeenStore(str(tmp_path / "seen.db"))
        try:
            crypto = DMPCrypto.from_passphrase("operator-A", salt=b"A" * 32)
            spk_hex = crypto.get_signing_public_key_bytes().hex()
            now = int(time.time())
            stale = HeartbeatRecord(
                endpoint="https://self.example.com",
                operator_spk=crypto.get_signing_public_key_bytes(),
                version="0.4.9",  # pre-upgrade — what a peer would still gossip
                ts=now - 90,  # within the freshness gate
                exp=now - 90 + 86400,
            )
            wire = stale.sign(crypto)
            seen_store.accept(wire, now=now)

            api = DMPHttpApi(
                InMemoryDNSStore(),
                host="127.0.0.1",
                port=_free_port(),
                heartbeat_store=seen_store,
                heartbeat_self_endpoint="https://self.example.com",
                heartbeat_self_spk_hex=spk_hex,
            )
            api.start()
            try:
                r = requests.get(f"{_base(api)}/", timeout=3)
                assert r.status_code == 200
                # Pull the running package version — that's what
                # synthesis MUST report on the self row.
                from dmp import __version__ as pkg_version

                # The HTML table has one row keyed by (spk, endpoint).
                # The stale 0.4.9 wire MUST NOT appear; the running
                # version MUST.
                assert (
                    "0.4.9" not in r.text
                ), "stale peer-gossipped self version leaked into render"
                assert pkg_version in r.text, (
                    f"synthesized self-row should report running "
                    f"version {pkg_version}"
                )
            finally:
                api.stop()
        finally:
            seen_store.close()

    def test_self_row_present_when_no_peer_gossip(self, tmp_path: Path):
        """A solo node with no peer harvest still gets a self-row
        — the synthesized one ensures the page never looks empty."""
        seen_store = SeenStore(str(tmp_path / "seen.db"))
        try:
            crypto = DMPCrypto.from_passphrase("solo-op", salt=b"S" * 32)
            spk_hex = crypto.get_signing_public_key_bytes().hex()
            api = DMPHttpApi(
                InMemoryDNSStore(),
                host="127.0.0.1",
                port=_free_port(),
                heartbeat_store=seen_store,
                heartbeat_self_endpoint="https://solo.example.com",
                heartbeat_self_spk_hex=spk_hex,
            )
            api.start()
            try:
                r = requests.get(f"{_base(api)}/", timeout=3)
                assert r.status_code == 200
                assert "https://solo.example.com" in r.text
                from dmp import __version__ as pkg_version

                assert pkg_version in r.text
            finally:
                api.stop()
        finally:
            seen_store.close()
