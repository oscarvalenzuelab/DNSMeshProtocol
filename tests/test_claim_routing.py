"""Tests for the M8.3 claim provider selection (`claim_routing.py`)."""

from __future__ import annotations

import time

import pytest

from dmp.client.claim_routing import (
    DEFAULT_K,
    ClaimProvider,
    parse_seen_feed,
    select_providers,
    _zone_from_endpoint,
)
from dmp.core.crypto import DMPCrypto
from dmp.core.heartbeat import CAP_CLAIM_PROVIDER, HeartbeatRecord


def _hb(
    *,
    endpoint: str = "https://node.example.com",
    capabilities: int = CAP_CLAIM_PROVIDER,
    ts_offset: int = 0,
    operator_passphrase: str = "operator-pass",
    operator_salt: bytes = b"S" * 32,
) -> HeartbeatRecord:
    """Build a fresh signed heartbeat. ts_offset shifts ts for ranking tests."""
    crypto = DMPCrypto.from_passphrase(operator_passphrase, salt=operator_salt)
    now = int(time.time()) + ts_offset
    return HeartbeatRecord(
        endpoint=endpoint,
        operator_spk=crypto.get_signing_public_key_bytes(),
        version="dev",
        ts=now,
        exp=now + 86400,
        capabilities=capabilities,
    )


class TestZoneFromEndpoint:
    def test_simple_https(self):
        assert _zone_from_endpoint("https://dnsmesh.io") == "dnsmesh.io"

    def test_with_port(self):
        assert (
            _zone_from_endpoint("https://node.example.com:8053") == "node.example.com"
        )

    def test_uppercase_normalized(self):
        assert _zone_from_endpoint("https://DnsMesh.IO") == "dnsmesh.io"

    def test_ip_literal_rejected(self):
        assert _zone_from_endpoint("https://192.168.1.1") is None
        assert _zone_from_endpoint("https://[::1]") is None

    def test_localhost_rejected(self):
        assert _zone_from_endpoint("https://localhost") is None
        assert _zone_from_endpoint("https://localhost:8053") is None

    def test_garbage_returns_none(self):
        assert _zone_from_endpoint("not a url") is None
        assert _zone_from_endpoint("") is None


class TestSelectProviders:
    def test_picks_top_k_by_recency(self):
        # Three providers, descending freshness.
        oldest = _hb(
            endpoint="https://stale.example",
            ts_offset=-100,
            operator_passphrase="p1",
        )
        middle = _hb(
            endpoint="https://middle.example",
            ts_offset=-50,
            operator_passphrase="p2",
        )
        freshest = _hb(
            endpoint="https://fresh.example",
            ts_offset=-1,
            operator_passphrase="p3",
        )
        out = select_providers([oldest, middle, freshest], k=2)
        assert len(out) == 2
        assert out[0].endpoint == "https://fresh.example"
        assert out[1].endpoint == "https://middle.example"

    def test_filters_non_provider_nodes(self):
        provider = _hb(
            endpoint="https://provider.example",
            capabilities=CAP_CLAIM_PROVIDER,
            operator_passphrase="p1",
        )
        non_provider = _hb(
            endpoint="https://leaf.example",
            capabilities=0,
            operator_passphrase="p2",
        )
        out = select_providers([provider, non_provider])
        assert len(out) == 1
        assert out[0].endpoint == "https://provider.example"

    def test_dedupes_same_operator(self):
        # Same operator key, two endpoints — should appear once
        # (whichever wins the ranking).
        first = _hb(
            endpoint="https://node-a.example",
            operator_passphrase="same",
            ts_offset=-10,
        )
        second = _hb(
            endpoint="https://node-b.example",
            operator_passphrase="same",
            ts_offset=-1,
        )
        out = select_providers([first, second])
        assert len(out) == 1

    def test_empty_input_returns_empty(self):
        assert select_providers([]) == []

    def test_zero_k_returns_empty(self):
        out = select_providers([_hb()], k=0)
        assert out == []

    def test_provider_zone_derived_from_endpoint(self):
        hb = _hb(endpoint="https://node.example.com:8053")
        out = select_providers([hb])
        assert out[0].zone == "node.example.com"

    def test_ip_literal_endpoint_kept_with_empty_zone(self):
        """Codex P2 round 4 fix: IP-literal endpoints stay in the
        candidate list with zone="". The CLI's /v1/info hop is what
        fills in the real zone (or drops the candidate when /v1/info
        is unreachable). Filtering here would make valid public-IP
        nodes invisible as claim providers."""
        # Public IP literals (private ranges fail the heartbeat
        # endpoint validator at construction time) — but for unit
        # testing, the validator only blocks loopback/private/etc.
        # We use a route-able example IP from RFC 5737.
        good = _hb(endpoint="https://good.example", operator_passphrase="p1")
        ip_literal = _hb(endpoint="https://203.0.113.10:8053", operator_passphrase="p2")
        out = select_providers([good, ip_literal])
        assert len(out) == 2
        endpoints = {p.endpoint for p in out}
        assert "https://good.example" in endpoints
        assert "https://203.0.113.10:8053" in endpoints
        # The IP-literal candidate has empty zone — the caller's
        # /v1/info upgrade is responsible for filling it in.
        ip_provider = next(p for p in out if p.endpoint.endswith(":8053"))
        assert ip_provider.zone == ""

    def test_claim_provider_zone_overrides_host_derivation(self):
        """M9.1.1 — when the operator advertises ``claim_provider_zone``
        in the signed wire, it wins over the URL-host inference. Lets
        a provider serve claims under a zone that doesn't match its
        HTTP host (e.g. a CDN-fronted endpoint with operator-controlled
        DNS for the claim records)."""
        hb = _hb(endpoint="https://cdn-fronted.example.net")
        # Splice in the operator-advertised zone (immutable dataclass —
        # rebuild). A real wire would carry this from sign().
        hb_with_zone = HeartbeatRecord(
            endpoint=hb.endpoint,
            operator_spk=hb.operator_spk,
            version=hb.version,
            ts=hb.ts,
            exp=hb.exp,
            capabilities=hb.capabilities,
            claim_provider_zone="my-claims.example.com",
        )
        out = select_providers([hb_with_zone])
        assert len(out) == 1
        assert out[0].zone == "my-claims.example.com"
        # Endpoint stays the URL — only the claim-record zone moves.
        assert out[0].endpoint == "https://cdn-fronted.example.net"

    def test_falls_back_to_host_when_advertised_zone_empty(self):
        """Wires from older nodes (or providers that haven't enabled
        the field) leave ``claim_provider_zone`` blank — host
        derivation is the back-compat path."""
        hb = _hb(endpoint="https://node.example.com")
        # No claim_provider_zone splice — defaults to "".
        out = select_providers([hb])
        assert out[0].zone == "node.example.com"

    def test_default_k(self):
        # Generate K+2 fresh providers; only K come back.
        hbs = [
            _hb(
                endpoint=f"https://node-{i}.example",
                operator_passphrase=f"p{i}",
                ts_offset=-i,
            )
            for i in range(DEFAULT_K + 2)
        ]
        out = select_providers(hbs)
        assert len(out) == DEFAULT_K


class TestOverride:
    def test_override_returns_only_that(self):
        hb = _hb()  # would otherwise be picked
        out = select_providers([hb], override="https://override.example")
        assert len(out) == 1
        assert out[0].endpoint == "https://override.example"
        assert out[0].zone == "override.example"

    def test_override_zone_explicit(self):
        out = select_providers(
            [],
            override="https://node.example",
            override_zone="claims.elsewhere.com",
        )
        assert len(out) == 1
        assert out[0].zone == "claims.elsewhere.com"

    def test_override_with_no_derivable_zone_returns_empty(self):
        out = select_providers([], override="https://192.168.1.1")
        assert out == []


class TestParseSeenFeed:
    def test_skips_invalid_wires(self):
        good = _hb().sign(DMPCrypto.from_passphrase("operator-pass", salt=b"S" * 32))
        bad = "v=dmp1;t=heartbeat;not-base64!!!"
        out = parse_seen_feed([good, bad])
        # Good is signed by passing its own operator key — it should
        # round-trip; bad should be silently skipped.
        # Note: parse_and_verify also checks freshness — the test
        # heartbeat has ts=now and exp=now+86400 so it parses fine.
        assert len(out) == 1
