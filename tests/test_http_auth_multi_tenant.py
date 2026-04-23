"""Integration tests for M5.5 multi-tenant auth on /v1/records/*.

Exercises the real HTTP server + real TokenStore + real InMemoryDNSStore
together — the three pieces a production deployment stacks. Goal is to
prove that phase-2 wire-in actually enforces the scope rules on live
HTTP requests, not just in unit tests of the primitives.

Three axes:
  * auth_mode = open / legacy / multi-tenant
  * token presented = operator / user-for-correct-subject / user-for-other-subject / none
  * record = identity (owner-exclusive) / chunk (shared-pool) / cluster (operator-only)
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
import requests

from dmp.network.memory import InMemoryDNSStore
from dmp.server.http_api import DMPHttpApi
from dmp.server.tokens import TokenStore


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def mt_setup(tmp_path: Path):
    """Multi-tenant mode: operator token + token store, both set."""
    store = InMemoryDNSStore()
    tokens = TokenStore(str(tmp_path / "tokens.db"))
    api = DMPHttpApi(
        store,
        host="127.0.0.1",
        port=_free_port(),
        bearer_token="op-token",
        auth_mode="multi-tenant",
        token_store=tokens,
    )
    api.start()
    try:
        yield api, store, tokens
    finally:
        api.stop()
        tokens.close()


def _url(api: DMPHttpApi, name: str) -> str:
    return f"http://127.0.0.1:{api.port}/v1/records/{name}"


def _post(api: DMPHttpApi, name: str, token: str = "", value: str = "v") -> int:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = requests.post(
        _url(api, name),
        json={"value": value, "ttl": 60},
        headers=headers,
        timeout=2,
    )
    return r.status_code


# ---------------------------------------------------------------------------


class TestMultiTenantOwnerExclusive:
    def test_user_can_post_own_identity(self, mt_setup):
        api, _, tokens = mt_setup
        token, _ = tokens.issue("alice@example.com")
        assert _post(api, "dmp.alice.example.com", token) == 201

    def test_user_cannot_post_other_identity(self, mt_setup):
        api, _, tokens = mt_setup
        alice_token, _ = tokens.issue("alice@example.com")
        # Alice tries to impersonate Bob — must be rejected.
        assert _post(api, "dmp.bob.example.com", alice_token) == 401

    def test_user_can_post_own_rotation(self, mt_setup):
        api, _, tokens = mt_setup
        token, _ = tokens.issue("alice@example.com")
        assert _post(api, "rotate.dmp.alice.example.com", token) == 201

    def test_user_cannot_post_other_rotation(self, mt_setup):
        api, _, tokens = mt_setup
        alice_token, _ = tokens.issue("alice@example.com")
        assert _post(api, "rotate.dmp.bob.example.com", alice_token) == 401


class TestMultiTenantSharedPool:
    def test_any_user_can_post_chunk(self, mt_setup):
        api, _, tokens = mt_setup
        alice_token, _ = tokens.issue("alice@example.com")
        # Alice publishes a chunk addressed to someone else — allowed.
        assert _post(api, "chunk-0001-abcdef012345.example.com", alice_token) == 201

    def test_any_user_can_post_mailbox_slot(self, mt_setup):
        api, _, tokens = mt_setup
        alice_token, _ = tokens.issue("alice@example.com")
        # Deliver to Bob's mailbox — allowed; sender anonymity at the
        # audit layer is already tested at the TokenStore level.
        assert _post(api, "slot-3.mb-abcdef012345.example.com", alice_token) == 201

    def test_revoked_token_cannot_post_chunk(self, mt_setup):
        api, _, tokens = mt_setup
        token, row = tokens.issue("alice@example.com")
        tokens.revoke(row.token_hash)
        assert _post(api, "chunk-0001-abcdef012345.example.com", token) == 401


class TestMultiTenantOperatorOnly:
    def test_user_token_cannot_publish_cluster_record(self, mt_setup):
        api, _, tokens = mt_setup
        alice_token, _ = tokens.issue("alice@example.com")
        # Cluster / bootstrap / anything unrecognized stays operator-only.
        assert _post(api, "cluster.mesh.example.com", alice_token) == 401

    def test_operator_token_can_publish_anywhere(self, mt_setup):
        api, _, _ = mt_setup
        assert _post(api, "cluster.mesh.example.com", "op-token") == 201
        assert _post(api, "dmp.alice.example.com", "op-token") == 201
        assert _post(api, "chunk-0001-abcdef012345.example.com", "op-token") == 201


class TestMultiTenantMissingCreds:
    def test_no_token_rejected(self, mt_setup):
        api, _, _ = mt_setup
        assert _post(api, "dmp.alice.example.com") == 401

    def test_malformed_token_rejected(self, mt_setup):
        api, _, _ = mt_setup
        assert _post(api, "dmp.alice.example.com", "not-a-real-token") == 401


class TestMultiTenantDelete:
    def test_user_can_delete_own_identity(self, mt_setup):
        api, store, tokens = mt_setup
        token, _ = tokens.issue("alice@example.com")
        # Seed a record first so DELETE has something to remove.
        assert _post(api, "dmp.alice.example.com", token, "v1") == 201
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.delete(
            _url(api, "dmp.alice.example.com"),
            headers=headers, timeout=2,
        )
        assert r.status_code == 204

    def test_user_cannot_delete_other_identity(self, mt_setup):
        api, store, tokens = mt_setup
        # Operator seeds Bob's record.
        assert _post(api, "dmp.bob.example.com", "op-token", "bob") == 201
        alice_token, _ = tokens.issue("alice@example.com")
        headers = {"Authorization": f"Bearer {alice_token}"}
        r = requests.delete(
            _url(api, "dmp.bob.example.com"),
            headers=headers, timeout=2,
        )
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# Back-compat: legacy + open modes must still behave like pre-M5.5.
# ---------------------------------------------------------------------------


@pytest.fixture
def legacy_setup(tmp_path: Path):
    store = InMemoryDNSStore()
    api = DMPHttpApi(
        store, host="127.0.0.1", port=_free_port(),
        bearer_token="legacy-token",  # auth_mode derived to "legacy"
    )
    api.start()
    try:
        yield api, store
    finally:
        api.stop()


@pytest.fixture
def open_setup(tmp_path: Path):
    store = InMemoryDNSStore()
    api = DMPHttpApi(store, host="127.0.0.1", port=_free_port())  # no token, mode="open"
    api.start()
    try:
        yield api, store
    finally:
        api.stop()


class TestLegacyModeBackCompat:
    def test_operator_token_required(self, legacy_setup):
        api, _ = legacy_setup
        assert _post(api, "dmp.alice.example.com") == 401
        assert _post(api, "dmp.alice.example.com", "wrong-token") == 401
        assert _post(api, "dmp.alice.example.com", "legacy-token") == 201

    def test_end_user_token_rejected_without_store(self, legacy_setup):
        """Legacy mode with a TokenStore-style token but no store wired
        must reject — a legacy deployment hasn't opted into multi-tenant."""
        api, _ = legacy_setup
        # Even a token in the right FORMAT is rejected without multi-tenant mode.
        fake_token = "dmp_v1_" + "A" * 52
        assert _post(api, "dmp.alice.example.com", fake_token) == 401


class TestOpenModeBackCompat:
    def test_no_token_required(self, open_setup):
        api, _ = open_setup
        # Entirely unauthenticated — pre-M5.5 behavior preserved.
        assert _post(api, "dmp.alice.example.com") == 201
        assert _post(api, "chunk-0001-abcdef012345.example.com") == 201
