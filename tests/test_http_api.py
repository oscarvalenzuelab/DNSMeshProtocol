"""Tests for the HTTP API exposing DMP records."""

import socket

import pytest
import requests

from dmp.network.memory import InMemoryDNSStore
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
    api = DMPHttpApi(
        store, host="127.0.0.1", port=_free_port(), bearer_token="s3cret"
    )
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
