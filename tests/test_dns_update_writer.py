"""Tests for the M9.2.4 client-side DNS UPDATE writer.

End-to-end against a real ``DMPDnsServer`` plus an in-memory record
store and an in-memory TSIG keystore. The writer contract matches the
generic ``DNSRecordWriter`` shape so the same fixtures we use for
``InMemoryDNSStore`` apply.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from dmp.network.dns_update_writer import _DnsUpdateWriter, _resolve_to_ip
from dmp.network.memory import InMemoryDNSStore
from dmp.server.dns_server import DMPDnsServer
from dmp.server.tsig_keystore import TSIGKeyStore


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def keystore(tmp_path: Path) -> TSIGKeyStore:
    s = TSIGKeyStore(str(tmp_path / "tsig.db"))
    yield s
    s.close()


@pytest.fixture
def record_store() -> InMemoryDNSStore:
    return InMemoryDNSStore()


def _start_server(record_store: InMemoryDNSStore, keystore: TSIGKeyStore):
    """Boot a DNS server with the keystore live so newly-minted keys
    authorize on the very next packet."""
    port = _free_udp_port()
    server = DMPDnsServer(
        record_store,
        host="127.0.0.1",
        port=port,
        writer=record_store,
        tsig_keystore=keystore,
        allowed_zones=("example.com",),
    )
    server.start()
    return server, port


def _mint_key(keystore: TSIGKeyStore, name: str, allowed_suffixes):
    return keystore.mint(name=name, allowed_suffixes=allowed_suffixes)


class TestPublish:
    def test_publish_lands_in_record_store(self, record_store, keystore):
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.publish_txt_record("alice.example.com", "v=dmp1;t=identity")
        finally:
            server.stop()
        assert ok is True
        # The signed UPDATE landed in the same store the reader serves.
        assert record_store.query_txt_record("alice.example.com") == [
            "v=dmp1;t=identity"
        ]

    def test_publish_under_subtree(self, record_store, keystore):
        """Owner names beneath the user's scope are accepted — a key
        scoped to ``alice.example.com`` covers everything below it."""
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.publish_txt_record("prekey.alice.example.com", "v=dmp1;k=abc")
        finally:
            server.stop()
        assert ok is True
        assert record_store.query_txt_record("prekey.alice.example.com") == [
            "v=dmp1;k=abc"
        ]

    def test_publish_with_special_chars_in_value(self, record_store, keystore):
        """TXT values containing ``;`` (the DNS comment delimiter) and
        ``"`` must round-trip cleanly. The DMP heartbeat wire is
        full of semicolons."""
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        wire = 'v=dmp1;t=heartbeat;data="quoted"'
        try:
            ok = writer.publish_txt_record("alice.example.com", wire)
        finally:
            server.stop()
        assert ok is True
        got = record_store.query_txt_record("alice.example.com")
        assert got == [wire]


class TestDelete:
    def test_delete_specific_value(self, record_store, keystore):
        record_store.publish_txt_record("alice.example.com", "keep")
        record_store.publish_txt_record("alice.example.com", "drop")
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.delete_txt_record("alice.example.com", value="drop")
        finally:
            server.stop()
        assert ok is True
        assert record_store.query_txt_record("alice.example.com") == ["keep"]

    def test_delete_whole_rrset(self, record_store, keystore):
        record_store.publish_txt_record("alice.example.com", "a")
        record_store.publish_txt_record("alice.example.com", "b")
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.delete_txt_record("alice.example.com")
        finally:
            server.stop()
        assert ok is True
        assert record_store.query_txt_record("alice.example.com") is None


class TestRejection:
    def test_out_of_scope_owner_returns_false(self, record_store, keystore):
        """A write outside the key's scope bounces as REFUSED on the
        server side — the writer surfaces that as False so the caller
        can fall back. No exception."""
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.publish_txt_record("bob.example.com", "x")
        finally:
            server.stop()
        assert ok is False
        assert record_store.query_txt_record("bob.example.com") is None

    def test_owner_outside_zone_returns_false(self, record_store, keystore):
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            # Owner is in a different zone — the server returns NOTZONE,
            # which we surface as False.
            ok = writer.publish_txt_record("alice.other.com", "x")
        finally:
            server.stop()
        assert ok is False

    def test_revoked_key_returns_false(self, record_store, keystore):
        """Revoke between mint and write — the next UPDATE fails TSIG
        verification (key drops out of the live keyring) and the writer
        returns False without raising."""
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            keystore.revoke(key.name)
            ok = writer.publish_txt_record("alice.example.com", "x")
        finally:
            server.stop()
        assert ok is False


class TestConstructorValidation:
    def test_empty_zone_raises(self):
        with pytest.raises(ValueError):
            _DnsUpdateWriter(
                zone="",
                server="127.0.0.1",
                tsig_key_name="x.",
                tsig_secret=b"\x01" * 32,
            )

    def test_empty_secret_raises(self):
        with pytest.raises(ValueError):
            _DnsUpdateWriter(
                zone="example.com",
                server="127.0.0.1",
                tsig_key_name="x.",
                tsig_secret=b"",
            )

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError):
            _DnsUpdateWriter(
                zone="example.com",
                server="127.0.0.1",
                tsig_key_name="x.",
                tsig_secret=b"\x01" * 32,
                tsig_algorithm="not-a-real-algorithm",
            )


class TestResolveToIp:
    """``_resolve_to_ip`` shields callers from dnspython's IP-only
    destination requirement — every UPDATE path resolves once at
    construction so operators can configure a hostname."""

    def test_ipv4_literal_passes_through(self):
        assert _resolve_to_ip("127.0.0.1") == "127.0.0.1"
        assert _resolve_to_ip("8.8.8.8") == "8.8.8.8"

    def test_ipv6_literal_passes_through(self):
        assert _resolve_to_ip("::1") == "::1"
        assert _resolve_to_ip("2001:4860:4860::8888") == "2001:4860:4860::8888"

    def test_localhost_resolves_to_loopback(self):
        # ``localhost`` is the one hostname every test environment
        # resolves the same way (loopback, AF_INET preferred).
        out = _resolve_to_ip("localhost")
        assert out in {"127.0.0.1", "::1"}

    def test_unresolvable_returns_none(self):
        # Codex round-21 P2 fix: returning the original hostname on
        # gaierror would leak it through to dns.query.udp(), which
        # raises ValueError that _send() doesn't catch. Returning
        # None lets _send return False per the writer contract.
        out = _resolve_to_ip("this-host-does-not-exist.invalid")
        assert out is None

    def test_none_input_returns_none(self):
        # Defensive: callers shouldn't pass None, but if they do
        # we shouldn't crash inside dns.inet.af_for_address.
        assert _resolve_to_ip(None) is None

    def test_empty_string_returns_none(self):
        assert _resolve_to_ip("") is None

    def test_nul_byte_rejected(self):
        # NUL bytes confuse downstream socket/DNS calls; reject so a
        # typo can't produce inconsistent failure modes across paths.
        assert _resolve_to_ip("dns\x00mesh.io") is None

    def test_resolver_pool_preferred_over_system(self):
        """When a pool is passed, resolve via it first — that's the
        codex round-21 P1 fix. The pool's view is what governs DNS
        reads (DMP_HEARTBEAT_DNS_RESOLVERS); UDP-destination lookups
        must agree, otherwise a stale system-resolver NXDOMAIN
        breaks writes during a delegation move."""

        class _StubPool:
            def __init__(self, ip):
                self._ip = ip
                self.calls = []

            def resolve_address(self, host):
                self.calls.append(host)
                return self._ip

        pool = _StubPool("203.0.113.7")
        out = _resolve_to_ip("anything.example", resolver_pool=pool)
        assert out == "203.0.113.7"
        assert pool.calls == ["anything.example"]

    def test_resolver_pool_failure_falls_back_to_system(self):
        """Pool returning None doesn't permanently fail — system
        resolver is the last-resort fallback so a misconfigured pool
        doesn't lock us out entirely."""

        class _DeadPool:
            def resolve_address(self, host):
                return None

        # ``localhost`` resolves via the system resolver in any test
        # environment, so this exercises the fallback cleanly.
        out = _resolve_to_ip("localhost", resolver_pool=_DeadPool())
        assert out in {"127.0.0.1", "::1"}

    def test_resolver_pool_exception_does_not_propagate(self):
        """A resolver pool that raises (e.g. all upstreams down)
        falls back to the system resolver instead of crashing the
        publish path."""

        class _BadPool:
            def resolve_address(self, host):
                raise RuntimeError("simulated transport storm")

        out = _resolve_to_ip("localhost", resolver_pool=_BadPool())
        assert out in {"127.0.0.1", "::1"}

    def test_writer_construction_resolves_hostname(self):
        """End-to-end: passing a hostname to the writer no longer
        produces an IP-literal-required error at publish time."""
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="localhost",
            tsig_key_name="x.",
            tsig_secret=b"\x01" * 32,
        )
        import dns.inet

        dns.inet.af_for_address(writer._server)  # no exception

    def test_writer_with_unresolvable_server_returns_false_not_raises(self):
        """Codex round-21 P2: previously a hostname with no A/AAAA
        record left ``_server`` as the original string, which made
        ``dns.query.udp`` raise ValueError that ``_send`` didn't
        catch. ``publish_txt_record`` MUST return False instead of
        bubbling — that's the DNSRecordWriter contract every other
        writer honors."""
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="this-host-does-not-exist.invalid",
            tsig_key_name="x.",
            tsig_secret=b"\x01" * 32,
        )
        assert writer._server is None
        # publish_txt_record returns False without raising — even
        # though _send would have hit dns.query.udp with a non-
        # literal under the old behavior.
        ok = writer.publish_txt_record("foo.example.com", "v=dmp1;t=identity")
        assert ok is False
        ok = writer.delete_txt_record("foo.example.com")
        assert ok is False


class TestNsFallbackUsesResolverPool:
    """Codex round-7 P2: the NS-chain fallback in ``_resolve_to_ip``
    MUST route through ``resolver_pool`` when the caller has one. On
    split-horizon / pinned-recursor deployments the pool IS the
    operator's trusted DNS view; punting to the host's system
    resolver here would defeat that trust model."""

    class _StubPool:
        """Minimal duck-typed ResolverPool stand-in — records calls
        and returns scripted answers."""

        def __init__(
            self,
            address_map: dict,
            ns_map: dict,
        ) -> None:
            self.address_map = address_map
            self.ns_map = ns_map
            self.address_calls: list = []
            self.ns_calls: list = []

        def resolve_address(self, host: str):
            self.address_calls.append(host)
            return self.address_map.get(host)

        def resolve_ns_hosts(self, zone: str):
            self.ns_calls.append(zone)
            return list(self.ns_map.get(zone, ()))

    def test_apex_with_no_a_falls_through_pool_ns_chain(self):
        """Zone apex with no A record → pool's resolve_ns_hosts is
        consulted, then the NS hostname resolves via the same pool."""
        pool = self._StubPool(
            address_map={
                # Zone apex has no A — pool returns None.
                "split-host.example": None,
                # NS hostname resolves to the auth server's IP.
                "ns1.split-host.example": "203.0.113.7",
            },
            ns_map={
                "split-host.example": [
                    "ns1.split-host.example",
                ],
            },
        )
        ip = _resolve_to_ip("split-host.example", resolver_pool=pool)
        assert ip == "203.0.113.7"
        assert pool.ns_calls == ["split-host.example"]
        # resolve_address called for the apex (failed) AND the NS host
        # (succeeded).
        assert "split-host.example" in pool.address_calls
        assert "ns1.split-host.example" in pool.address_calls

    def test_apex_with_a_record_skips_ns_chain(self):
        """When the apex resolves directly via the pool, NS-chain MUST
        NOT fire — that's only a fallback for split-host setups."""
        pool = self._StubPool(
            address_map={"normal.example": "203.0.113.42"},
            ns_map={},
        )
        ip = _resolve_to_ip("normal.example", resolver_pool=pool)
        assert ip == "203.0.113.42"
        assert (
            pool.ns_calls == []
        ), "NS-chain should not fire when the apex has an A record"

    def test_pooled_chase_fails_closed_when_pool_has_no_ns(self):
        """Codex round-8 P1: when ``resolver_pool`` is configured but
        returns no NS records, ``_resolve_to_ip`` MUST fail closed
        (return None) rather than fall back to the host system
        resolver. Pinned-recursor operators chose the pool precisely
        so DMP's DNS view doesn't leak."""
        pool = self._StubPool(
            address_map={
                # Apex A/AAAA fails through the pool.
                "lone-zone.example": None,
            },
            ns_map={
                # Pool can't find NS records either.
                "lone-zone.example": [],
            },
        )
        ip = _resolve_to_ip("lone-zone.example", resolver_pool=pool)
        assert (
            ip is None
        ), "pooled NS chase must fail closed, not leak to system resolver"

    def test_pooled_chase_fails_closed_when_ns_host_unresolvable(self):
        """Round-8 P1: even when the pool returns NS hostnames, if the
        pool can't resolve those NS hosts to IPs, the function MUST
        NOT fall through to ``socket.getaddrinfo``."""
        pool = self._StubPool(
            address_map={
                # Apex fails.
                "split-host.example": None,
                # NS host also fails through the pool (returns None).
                "ns1.split-host.example": None,
            },
            ns_map={
                "split-host.example": ["ns1.split-host.example"],
            },
        )
        ip = _resolve_to_ip("split-host.example", resolver_pool=pool)
        assert ip is None, (
            "pooled NS-host A lookup must fail closed, not leak to "
            "socket.getaddrinfo"
        )

    def test_env_var_opts_into_system_fallback(self, monkeypatch):
        """Codex round-10 P2: production callers (TSIG writer + un-TSIG'd
        claim publish) don't thread ``allow_system_fallback`` through,
        so the opt-in MUST also be reachable via
        ``DMP_ALLOW_SYSTEM_DNS_FALLBACK=1``. Without this, an operator
        running a hybrid authoritative-only pool can't enable the
        round-9 escape hatch from real call sites."""
        sentinel_ip = "203.0.113.99"

        def fake_getaddrinfo(host, port, *args, **kwargs):
            if host == "ns1.envvar.example":
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_DGRAM,
                        0,
                        "",
                        (sentinel_ip, 0),
                    )
                ]
            raise socket.gaierror(socket.EAI_NONAME, "no")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        monkeypatch.setenv("DMP_ALLOW_SYSTEM_DNS_FALLBACK", "1")

        pool = self._StubPool(
            address_map={
                "envvar.example": None,
                "ns1.envvar.example": None,
            },
            ns_map={"envvar.example": ["ns1.envvar.example"]},
        )
        # No explicit kwarg — env var alone should opt in.
        ip = _resolve_to_ip("envvar.example", resolver_pool=pool)
        assert ip == sentinel_ip

        # Removing the env var restores strict-default behavior.
        monkeypatch.delenv("DMP_ALLOW_SYSTEM_DNS_FALLBACK")
        ip_strict = _resolve_to_ip("envvar.example", resolver_pool=pool)
        assert ip_strict is None

    def test_allow_system_fallback_resolves_external_ns_host(self, monkeypatch):
        """Codex round-9 P1: ``allow_system_fallback=True`` is the
        explicit opt-in for hybrid split-host deployments where the
        pool can answer the NS RRset query but cannot recurse on
        the returned NS hostnames (typical of authoritative-only
        pools). With the flag, the NS-host A lookup falls through
        to ``socket.getaddrinfo``; without it, the strict default
        (round-8) keeps the trust boundary closed."""

        # Stub getaddrinfo so the test doesn't hit real DNS. The
        # function gets called twice: once for the apex (which fails
        # in our scenario) and once for the NS hostname (which
        # succeeds because allow_system_fallback=True).
        sentinel_ip = "198.51.100.42"

        def fake_getaddrinfo(host, port, *args, **kwargs):
            if host == "ns1.partial-pool.example":
                return [
                    (
                        socket.AF_INET,
                        socket.SOCK_DGRAM,
                        0,
                        "",
                        (sentinel_ip, 0),
                    )
                ]
            # Anything else (the apex) — pretend NXDOMAIN.
            raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

        pool = self._StubPool(
            address_map={
                # Pool can't resolve apex OR the external NS host —
                # it's authoritative-only for the operator's zones.
                "partial-pool.example": None,
                "ns1.partial-pool.example": None,
            },
            ns_map={
                "partial-pool.example": ["ns1.partial-pool.example"],
            },
        )
        ip = _resolve_to_ip(
            "partial-pool.example",
            resolver_pool=pool,
            allow_system_fallback=True,
        )
        assert ip == sentinel_ip
        # Sanity: without the opt-in the same setup fails closed.
        ip_strict = _resolve_to_ip("partial-pool.example", resolver_pool=pool)
        assert ip_strict is None
