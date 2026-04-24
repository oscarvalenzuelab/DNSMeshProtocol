"""Integration tests for M5.8 phase 3: POST /v1/heartbeat + GET /v1/nodes/seen."""

from __future__ import annotations

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
from dmp.server.rate_limit import RateLimit


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _signer(passphrase: str = "op", salt: bytes = b"A" * 32) -> DMPCrypto:
    return DMPCrypto.from_passphrase(passphrase, salt=salt)


def _heartbeat(
    signer: DMPCrypto,
    *,
    endpoint: str = "https://dmp.example.com",
    version: str = "0.1.0",
    ts: int | None = None,
    exp_delta: int = 86400,
) -> str:
    ts = ts if ts is not None else int(time.time())
    hb = HeartbeatRecord(
        endpoint=endpoint,
        operator_spk=signer.get_signing_public_key_bytes(),
        version=version,
        ts=ts,
        exp=ts + exp_delta,
    )
    return hb.sign(signer)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def hb_api(tmp_path: Path):
    """API with heartbeat enabled + in-memory rate limit disabled (so
    tests don't hit 429 on rapid submission)."""
    store = SeenStore(str(tmp_path / "hb.db"))
    api = DMPHttpApi(
        InMemoryDNSStore(),
        host="127.0.0.1",
        port=_free_port(),
        heartbeat_store=store,
        heartbeat_self_endpoint="https://dmp.self.example.com",
        heartbeat_self_spk_hex="ab" * 32,
    )
    api.start()
    try:
        yield api, store
    finally:
        api.stop()
        store.close()


@pytest.fixture
def hb_api_disabled(tmp_path: Path):
    """API without heartbeat plumbing — both endpoints must 404."""
    api = DMPHttpApi(InMemoryDNSStore(), host="127.0.0.1", port=_free_port())
    api.start()
    try:
        yield api
    finally:
        api.stop()


@pytest.fixture
def hb_api_rate_limited(tmp_path: Path):
    """API with tight heartbeat rate limits on BOTH endpoints so
    the basic rate-limit tests can demonstrate 429 on each."""
    store = SeenStore(str(tmp_path / "hb.db"))
    api = DMPHttpApi(
        InMemoryDNSStore(),
        host="127.0.0.1",
        port=_free_port(),
        heartbeat_store=store,
        heartbeat_submit_rate_limit=RateLimit(rate_per_second=0.001, burst=1.0),
        heartbeat_seen_rate_limit=RateLimit(rate_per_second=0.001, burst=1.0),
    )
    api.start()
    try:
        yield api, store
    finally:
        api.stop()
        store.close()


@pytest.fixture
def hb_api_split_buckets(tmp_path: Path):
    """API where the SEEN bucket is tight (burst=1) but the SUBMIT
    bucket is generous. Proves the two limiters are independent —
    hammering /v1/nodes/seen until 429 must NOT affect
    /v1/heartbeat's bucket."""
    store = SeenStore(str(tmp_path / "hb.db"))
    api = DMPHttpApi(
        InMemoryDNSStore(),
        host="127.0.0.1",
        port=_free_port(),
        heartbeat_store=store,
        heartbeat_submit_rate_limit=RateLimit(rate_per_second=100.0, burst=100.0),
        heartbeat_seen_rate_limit=RateLimit(rate_per_second=0.001, burst=1.0),
    )
    api.start()
    try:
        yield api, store
    finally:
        api.stop()
        store.close()


def _base(api: DMPHttpApi) -> str:
    return f"http://127.0.0.1:{api.port}"


# ---------------------------------------------------------------------------
# POST /v1/heartbeat — happy path + gossip
# ---------------------------------------------------------------------------


class TestSubmit:
    def test_accept_mints_row(self, hb_api) -> None:
        api, store = hb_api
        signer = _signer()
        wire = _heartbeat(signer)
        r = requests.post(f"{_base(api)}/v1/heartbeat", json={"wire": wire}, timeout=2)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True
        assert (
            body["accepted_operator_spk_hex"]
            == signer.get_signing_public_key_bytes().hex()
        )
        # Store now has one row.
        assert store.count() == 1

    def test_tampered_wire_rejected_with_400(self, hb_api) -> None:
        api, store = hb_api
        signer = _signer()
        wire = _heartbeat(signer)
        bad = wire[:-4] + ("A" if wire[-4] != "A" else "B") + wire[-3:]
        r = requests.post(f"{_base(api)}/v1/heartbeat", json={"wire": bad}, timeout=2)
        assert r.status_code == 400
        assert store.count() == 0

    def test_missing_wire_returns_400(self, hb_api) -> None:
        api, _ = hb_api
        r = requests.post(
            f"{_base(api)}/v1/heartbeat", json={"not_wire": "x"}, timeout=2
        )
        assert r.status_code == 400

    def test_invalid_body_returns_400(self, hb_api) -> None:
        api, _ = hb_api
        r = requests.post(
            f"{_base(api)}/v1/heartbeat",
            data="not-json",
            headers={"Content-Type": "application/json"},
            timeout=2,
        )
        assert r.status_code == 400


class TestGossipResponse:
    def test_response_shape_matches_design_doc(self, hb_api) -> None:
        """Codex phase-3 P2 regression: design doc specifies the
        gossip field on POST /v1/heartbeat is named `seen`
        (matching the GET /v1/nodes/seen shape). Ensure the POST
        response uses `seen` and does NOT use `gossip`."""
        api, _ = hb_api
        signer = _signer()
        wire = _heartbeat(signer)
        r = requests.post(f"{_base(api)}/v1/heartbeat", json={"wire": wire}, timeout=2)
        body = r.json()
        assert "seen" in body, f"expected 'seen' field in {body}"
        assert (
            "gossip" not in body
        ), "response must NOT use 'gossip' — field is 'seen' per design doc"

    def test_submit_returns_other_nodes_as_seen(self, hb_api) -> None:
        api, store = hb_api
        # Pre-populate the store with a few distinct nodes.
        for i in range(3):
            s = _signer(f"n{i}", bytes([i + 1]) * 32)
            store.accept(_heartbeat(s, endpoint=f"https://n{i}.example.com"))

        # Now a fourth node submits its own heartbeat.
        fourth = _signer("fourth", b"F" * 32)
        wire = _heartbeat(fourth, endpoint="https://fourth.example.com")
        r = requests.post(f"{_base(api)}/v1/heartbeat", json={"wire": wire}, timeout=2)
        assert r.status_code == 200
        body = r.json()
        # Seen list should contain the 3 other nodes' wires, not the
        # submitter's own.
        seen_wires = body["seen"]
        seen_spks = set()
        for w in seen_wires:
            parsed = HeartbeatRecord.parse_and_verify(w)
            assert parsed is not None
            seen_spks.add(bytes(parsed.operator_spk).hex())
        assert fourth.get_signing_public_key_bytes().hex() not in seen_spks
        # All 3 pre-populated nodes should appear.
        assert len(seen_spks) == 3

    def test_gossip_respects_limit(self, tmp_path: Path) -> None:
        store = SeenStore(str(tmp_path / "hb.db"))
        api = DMPHttpApi(
            InMemoryDNSStore(),
            host="127.0.0.1",
            port=_free_port(),
            heartbeat_store=store,
            heartbeat_gossip_limit=2,
        )
        api.start()
        try:
            # Seed 5 distinct nodes.
            for i in range(5):
                s = _signer(f"p{i}", bytes([i + 1]) * 32)
                store.accept(_heartbeat(s, endpoint=f"https://p{i}.example.com"))
            # A 6th submits.
            sixth = _signer("sixth", b"X" * 32)
            r = requests.post(
                f"{_base(api)}/v1/heartbeat",
                json={"wire": _heartbeat(sixth, endpoint="https://sixth.example.com")},
                timeout=2,
            )
            assert r.status_code == 200
            assert len(r.json()["seen"]) == 2
        finally:
            api.stop()
            store.close()


# ---------------------------------------------------------------------------
# GET /v1/nodes/seen
# ---------------------------------------------------------------------------


class TestNodesSeen:
    def test_returns_verified_wires(self, hb_api) -> None:
        api, store = hb_api
        signer = _signer()
        store.accept(_heartbeat(signer))
        r = requests.get(f"{_base(api)}/v1/nodes/seen", timeout=2)
        assert r.status_code == 200
        body = r.json()
        assert body["version"] == 1
        assert body["self"]["endpoint"] == "https://dmp.self.example.com"
        assert body["self"]["operator_spk_hex"] == "ab" * 32
        assert body["self"]["enabled"] is True
        assert len(body["seen"]) == 1
        # Consumer re-verifies — the wire string must survive a
        # parse_and_verify round-trip.
        parsed = HeartbeatRecord.parse_and_verify(body["seen"][0]["wire"])
        assert parsed is not None
        assert parsed.operator_spk == signer.get_signing_public_key_bytes()

    def test_empty_store_returns_empty_seen(self, hb_api) -> None:
        api, _ = hb_api
        r = requests.get(f"{_base(api)}/v1/nodes/seen", timeout=2)
        assert r.status_code == 200
        assert r.json()["seen"] == []


# ---------------------------------------------------------------------------
# Disabled node — both endpoints 404
# ---------------------------------------------------------------------------


class TestDisabled:
    def test_post_heartbeat_returns_404(self, hb_api_disabled) -> None:
        api = hb_api_disabled
        r = requests.post(f"{_base(api)}/v1/heartbeat", json={"wire": "x"}, timeout=2)
        assert r.status_code == 404

    def test_get_nodes_seen_returns_404(self, hb_api_disabled) -> None:
        api = hb_api_disabled
        r = requests.get(f"{_base(api)}/v1/nodes/seen", timeout=2)
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Rate limit
# ---------------------------------------------------------------------------


class TestRateLimit:
    def test_submit_rate_limited(self, hb_api_rate_limited) -> None:
        api, _ = hb_api_rate_limited
        signer = _signer()
        w1 = _heartbeat(signer, endpoint="https://a.example.com")
        w2 = _heartbeat(signer, endpoint="https://b.example.com")
        r1 = requests.post(f"{_base(api)}/v1/heartbeat", json={"wire": w1}, timeout=2)
        r2 = requests.post(f"{_base(api)}/v1/heartbeat", json={"wire": w2}, timeout=2)
        # Rate limiter burst=1 → first passes (200 or 400 depending
        # on verify), second hits 429.
        assert r1.status_code in (200, 400)
        assert r2.status_code == 429

    def test_seen_rate_limited(self, hb_api_rate_limited) -> None:
        api, _ = hb_api_rate_limited
        r1 = requests.get(f"{_base(api)}/v1/nodes/seen", timeout=2)
        r2 = requests.get(f"{_base(api)}/v1/nodes/seen", timeout=2)
        assert r1.status_code == 200
        assert r2.status_code == 429

    def test_submit_and_seen_buckets_are_independent(
        self, hb_api_split_buckets
    ) -> None:
        """Codex phase-3 P2 regression: hammering /v1/nodes/seen
        until 429 must NOT steal from the /v1/heartbeat submit
        budget on the same IP. The two buckets are separate."""
        api, _ = hb_api_split_buckets
        # Burn the seen bucket (burst=1).
        r1 = requests.get(f"{_base(api)}/v1/nodes/seen", timeout=2)
        r2 = requests.get(f"{_base(api)}/v1/nodes/seen", timeout=2)
        assert r1.status_code == 200
        assert r2.status_code == 429

        # A submit against the same IP must still pass — the submit
        # limiter has its own generous bucket.
        signer = _signer()
        r3 = requests.post(
            f"{_base(api)}/v1/heartbeat",
            json={"wire": _heartbeat(signer)},
            timeout=2,
        )
        assert r3.status_code == 200, r3.text
