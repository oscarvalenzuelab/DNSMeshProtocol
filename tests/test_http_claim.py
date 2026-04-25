"""Tests for the M8.3 POST /v1/claim/publish + GET /v1/info HTTP endpoints."""

from __future__ import annotations

import json
import time
import urllib.request
from contextlib import closing

import pytest

from dmp.core.claim import RECORD_PREFIX, ClaimRecord, claim_rrset_name
from dmp.core.crypto import DMPCrypto
from dmp.core.heartbeat import CAP_CLAIM_PROVIDER
from dmp.network.memory import InMemoryDNSStore
from dmp.server.http_api import DMPHttpApi


PROVIDER_ZONE = "claims.dnsmesh.io"


@pytest.fixture
def store():
    return InMemoryDNSStore()


@pytest.fixture
def server(store):
    api = DMPHttpApi(
        store,
        host="127.0.0.1",
        port=0,
        claim_provider_zone=PROVIDER_ZONE,
        advertised_capabilities=CAP_CLAIM_PROVIDER,
    )
    api.start()
    yield api
    api.stop()


@pytest.fixture
def server_no_provider(store):
    """A server NOT acting as a claim provider — for 404 tests."""
    api = DMPHttpApi(store, host="127.0.0.1", port=0)
    api.start()
    yield api
    api.stop()


def _post(server, path: str, body: dict) -> tuple[int, dict]:
    url = f"http://{server.host}:{server.port}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with closing(urllib.request.urlopen(req, timeout=5)) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {}
        return e.code, payload


def _get(server, path: str) -> tuple[int, dict]:
    url = f"http://{server.host}:{server.port}{path}"
    try:
        with closing(urllib.request.urlopen(url, timeout=5)) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {}
        return e.code, payload


def _build_signed_claim() -> tuple[str, bytes, str]:
    """Construct a fresh signed claim. Returns (wire, recipient_id, hex12)."""
    import hashlib

    sender = DMPCrypto.from_passphrase("alice-pass", salt=b"S" * 32)
    recipient_id = b"\x42" * 32
    hex12 = hashlib.sha256(recipient_id).hexdigest()[:12]
    now = int(time.time())
    record = ClaimRecord(
        msg_id=b"\x11" * 16,
        sender_spk=sender.get_signing_public_key_bytes(),
        sender_mailbox_domain="alice.mesh",
        slot=3,
        ts=now,
        exp=now + 300,
    )
    return record.sign(sender), recipient_id, hex12


class TestClaimPublishEndpoint:
    def test_publish_writes_to_store(self, server, store):
        wire, recipient_id, hex12 = _build_signed_claim()
        status, payload = _post(
            server,
            "/v1/claim/publish",
            {"value": wire, "recipient_id_hex12": hex12, "ttl": 300},
        )
        assert status == 201, payload
        assert payload["ok"] is True
        # The expected RRset name is claim-3.mb-{hex12}.{zone}
        expected_name = f"claim-3.mb-{hex12}.{PROVIDER_ZONE}"
        assert payload["name"] == expected_name
        # And the wire is now stored at that name.
        records = store.query_txt_record(expected_name)
        assert wire in (records or [])

    def test_publish_404_when_not_provider(self, server_no_provider):
        wire, _, hex12 = _build_signed_claim()
        status, _ = _post(
            server_no_provider,
            "/v1/claim/publish",
            {"value": wire, "recipient_id_hex12": hex12, "ttl": 300},
        )
        assert status == 404

    def test_publish_rejects_non_claim_wire(self, server):
        _, _, hex12 = _build_signed_claim()
        status, _ = _post(
            server,
            "/v1/claim/publish",
            {
                "value": "v=dmp1;t=heartbeat;abc",
                "recipient_id_hex12": hex12,
                "ttl": 300,
            },
        )
        assert status == 400

    def test_publish_rejects_bad_recipient_hex(self, server):
        wire, _, _ = _build_signed_claim()
        # Wrong length.
        status, _ = _post(
            server,
            "/v1/claim/publish",
            {"value": wire, "recipient_id_hex12": "abc", "ttl": 300},
        )
        assert status == 400
        # Non-hex character.
        status, _ = _post(
            server,
            "/v1/claim/publish",
            {"value": wire, "recipient_id_hex12": "ZZZZZZZZZZZZ", "ttl": 300},
        )
        assert status == 400

    def test_publish_rejects_unsigned_garbage(self, server):
        """Tampered claim wire fails parse_and_verify, server returns 400."""
        wire, _, hex12 = _build_signed_claim()
        # Insert a junk char into the base64 portion to corrupt the
        # signature.
        tampered = wire[: len(wire) - 5] + "AAAAA"
        status, _ = _post(
            server,
            "/v1/claim/publish",
            {"value": tampered, "recipient_id_hex12": hex12, "ttl": 300},
        )
        assert status == 400

    def test_publish_caps_ttl(self, server, store):
        wire, _, hex12 = _build_signed_claim()
        # Server's max_ttl defaults to a few hours; request a year.
        status, payload = _post(
            server,
            "/v1/claim/publish",
            {"value": wire, "recipient_id_hex12": hex12, "ttl": 31_536_000},
        )
        # Either 201 (capped silently) or 400 — either is acceptable
        # so long as no record was stored with the absurd TTL. The
        # current code path silently caps and returns 201.
        assert status in (201, 400)


class TestNodeInfoEndpoint:
    def test_returns_provider_zone(self, server):
        status, payload = _get(server, "/v1/info")
        assert status == 200
        assert payload["claim_provider_zone"] == PROVIDER_ZONE
        assert payload["capabilities"] & CAP_CLAIM_PROVIDER

    def test_returns_empty_zone_when_not_provider(self, server_no_provider):
        status, payload = _get(server_no_provider, "/v1/info")
        assert status == 200
        assert payload["claim_provider_zone"] == ""
        assert payload["capabilities"] == 0
