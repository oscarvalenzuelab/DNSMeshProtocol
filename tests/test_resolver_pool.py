"""Tests for ResolverPool — priority ordering, failover, cooldown."""

import ipaddress
import logging
import socket
from unittest.mock import patch

import dns.exception
import dns.flags
import dns.name
import dns.resolver
import pytest

from dmp.network import DNSRecordReader, ResolverPool, WELL_KNOWN_RESOLVERS

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


class _FakeRdata:
    """Mimic a dnspython TXT rdata object — just exposes `.strings`."""

    def __init__(self, strings):
        self.strings = strings


class _FakeResponse:
    """Mimic a dnspython Message; only the AD/DO flag word matters here."""

    def __init__(self, flags: int):
        self.flags = flags


class _FakeAnswer(list):
    """A dnspython Answer is iterable over rdata objects.

    P0-4: ResolverPool reads ``answer.response.flags`` to gate on the
    AD bit when ``dnssec_required=True``. Default constructor produces
    an answer with AD set (the upstream-validated common case) so
    existing tests that construct via ``_answer(...)`` keep passing.
    """

    def __init__(self, *args, ad: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        flags = dns.flags.AD if ad else 0
        self.response = _FakeResponse(flags)


def _answer(*txt_values: str, ad: bool = True) -> _FakeAnswer:
    """Build a fake dnspython answer for the given TXT string(s).

    ``ad`` controls whether the synthetic response carries the AD flag
    (P0-4 DNSSEC gate); default True matches a validating-recursor
    happy path so existing tests don't have to opt in.
    """
    return _FakeAnswer(
        (_FakeRdata([v.encode("utf-8")]) for v in txt_values),
        ad=ad,
    )


def _route_by_nameserver(routes):
    """Return a side_effect that dispatches on the calling resolver's host.

    `routes` maps `host_ip` -> callable(name, rdtype) -> answer/raises.
    """

    def side_effect(self, name, rdtype="A", *args, **kwargs):
        host = self.nameservers[0]
        handler = routes.get(host)
        if handler is None:
            raise AssertionError(f"unexpected resolver host: {host}")
        return handler(name, rdtype)

    return side_effect


# ---------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------


class TestResolverPoolConstruction:
    def test_implements_dns_record_reader(self):
        pool = ResolverPool(["1.1.1.1"])
        assert isinstance(pool, DNSRecordReader)

    def test_rejects_empty_host_list(self):
        with pytest.raises(ValueError):
            ResolverPool([])

    def test_rejects_zero_failure_threshold(self):
        with pytest.raises(ValueError):
            ResolverPool(["1.1.1.1"], failure_threshold=0)

    def test_defaults_to_port_53(self):
        pool = ResolverPool(["1.1.1.1"])
        snapshot = pool.snapshot()
        assert snapshot[0]["host"] == "1.1.1.1"

    def test_custom_port_propagates_to_resolvers(self):
        pool = ResolverPool(["1.1.1.1"], port=5353)
        # The per-host Resolver should have been configured with the
        # custom port; we reach in through the private state for this
        # one assertion since the public surface doesn't expose it.
        assert pool._states[0].resolver.port == 5353

    def test_constructor_rejects_non_ip_host(self):
        """Hostnames are not accepted — dnspython requires IP literals.

        Resolving the hostname up front would reintroduce the very DNS
        ordering problem the pool exists to solve, so we narrow the
        contract and fail fast with a clear message.
        """
        with pytest.raises(ValueError, match="not a valid IPv4 or IPv6 literal"):
            ResolverPool(["dns.google"])

    def test_constructor_accepts_ipv6_literal(self):
        """IPv6 literals are valid upstreams and must not be rejected."""
        pool = ResolverPool(["2001:4860:4860::8888"])
        assert pool.snapshot()[0]["host"] == "2001:4860:4860::8888"
        assert pool._states[0].resolver.nameservers == ["2001:4860:4860::8888"]

    def test_constructor_rejects_non_ip_host_in_second_position(self):
        """Every entry is validated, not just the first."""
        with pytest.raises(ValueError, match="not a valid IPv4 or IPv6 literal"):
            ResolverPool(["1.1.1.1", "dns.google"])


class TestResolverPoolPerHostPorts:
    """`hosts=` accepts `(ip, port)` tuples so each upstream can carry
    its own port (M1.5). Bare IPs still inherit the pool-wide `port=`
    default for back-compat."""

    def test_tuple_entries_apply_per_host_ports(self):
        """Two `(ip, port)` tuples each produce a resolver on its own port."""
        pool = ResolverPool([("1.2.3.4", 53), ("5.6.7.8", 5353)])
        assert pool._states[0].host == "1.2.3.4"
        assert pool._states[0].resolver.port == 53
        assert pool._states[1].host == "5.6.7.8"
        assert pool._states[1].resolver.port == 5353

    def test_mixed_bare_and_tuple_with_custom_default_port(self):
        """A bare entry inherits `port=` default; the tuple overrides it.

        The mixed shape is the common case when a caller wants to
        override the port for only one upstream: the rest of the pool
        keeps the pool-wide default.
        """
        pool = ResolverPool(["1.2.3.4", ("5.6.7.8", 5353)], port=5300)
        # Bare entry picked up the pool-wide default.
        assert pool._states[0].host == "1.2.3.4"
        assert pool._states[0].resolver.port == 5300
        # Tuple entry carries its own explicit port.
        assert pool._states[1].host == "5.6.7.8"
        assert pool._states[1].resolver.port == 5353

    def test_tuple_entries_preserve_insertion_order(self):
        """Priority-by-insertion-order must survive the tuple shape."""
        pool = ResolverPool([("1.1.1.1", 53), ("9.9.9.9", 5353)])
        hosts = [s["host"] for s in pool.snapshot()]
        assert hosts == ["1.1.1.1", "9.9.9.9"]

    def test_tuple_with_hostname_is_rejected(self):
        """IP-literal-only policy applies inside tuples too."""
        with pytest.raises(ValueError, match="not a valid IPv4 or IPv6 literal"):
            ResolverPool([("dns.google", 53)])

    def test_tuple_with_non_string_host_is_rejected(self):
        """A tuple whose first element isn't a string is a programming error."""
        with pytest.raises(ValueError, match="must be a string IP literal"):
            ResolverPool([(123, 53)])  # type: ignore[list-item]

    def test_tuple_with_non_int_port_is_rejected(self):
        with pytest.raises(ValueError, match="port must be an int"):
            ResolverPool([("1.1.1.1", "53")])  # type: ignore[list-item]

    def test_tuple_with_bool_port_is_rejected(self):
        """`True` is an int subclass — reject it explicitly so callers
        don't accidentally end up on port 1."""
        with pytest.raises(ValueError, match="port must be an int"):
            ResolverPool([("1.1.1.1", True)])  # type: ignore[list-item]

    def test_tuple_with_port_out_of_range_is_rejected(self):
        with pytest.raises(ValueError, match="out of range"):
            ResolverPool([("1.1.1.1", 0)])
        with pytest.raises(ValueError, match="out of range"):
            ResolverPool([("1.1.1.1", 70000)])

    def test_tuple_of_wrong_arity_is_rejected(self):
        with pytest.raises(ValueError, match="must be .*ip, port"):
            ResolverPool([("1.1.1.1", 53, "extra")])  # type: ignore[list-item]

    def test_non_string_non_tuple_entry_rejected(self):
        """Future-proofing: exotic inputs shouldn't silently coerce."""
        with pytest.raises(ValueError, match="must be a string IP literal"):
            ResolverPool([12345])  # type: ignore[list-item]

    def test_tuple_ipv6_literal_with_port(self):
        """IPv6 literal inside a tuple is accepted; no bracket syntax needed."""
        pool = ResolverPool([("2001:4860:4860::8888", 5353)])
        assert pool._states[0].host == "2001:4860:4860::8888"
        assert pool._states[0].resolver.port == 5353

    def test_snapshot_includes_port_per_entry(self):
        """`snapshot()` surfaces the per-host port so debuggers / CLI
        output can disambiguate two states sharing an IP.

        A pool built with ``[("127.0.0.1", 5353), ("127.0.0.1", 5354)]``
        produces two entries indistinguishable by host alone; the
        ``"port"`` field is what tells them apart.
        """
        pool = ResolverPool([("127.0.0.1", 5353), ("127.0.0.1", 5354)])
        snap = pool.snapshot()
        assert len(snap) == 2
        assert snap[0]["host"] == "127.0.0.1"
        assert snap[0]["port"] == 5353
        assert snap[1]["host"] == "127.0.0.1"
        assert snap[1]["port"] == 5354

    def test_snapshot_port_matches_pool_wide_default_for_bare_entries(self):
        """Bare-IP entries record the pool-wide `port=` default in snapshot."""
        pool = ResolverPool(["8.8.8.8", "1.1.1.1"], port=5300)
        snap = pool.snapshot()
        assert snap[0]["port"] == 5300
        assert snap[1]["port"] == 5300

    def test_healthy_upstreams_returns_ip_port_tuples(self):
        """Port-aware variant of `healthy_hosts()` preserves both halves.

        `healthy_hosts()` deliberately returns bare IPs for back-compat;
        this test pins the new `healthy_upstreams()` surface that
        callers reach for when they need the full upstream identity.
        """
        pool = ResolverPool([("127.0.0.1", 5353), ("127.0.0.1", 5354)])
        upstreams = pool.healthy_upstreams()
        assert upstreams == [("127.0.0.1", 5353), ("127.0.0.1", 5354)]

    def test_healthy_hosts_unchanged_returns_strings(self):
        """Back-compat: `healthy_hosts()` still yields bare host strings.

        Callers that stringify or compare against IPs keep working
        after the M1.5 snapshot-port addition; two loopback entries on
        different ports do collapse in this view, which is why
        `healthy_upstreams()` exists.
        """
        pool = ResolverPool(["8.8.8.8", "1.1.1.1"])
        hosts = pool.healthy_hosts()
        assert hosts == ["8.8.8.8", "1.1.1.1"]
        # Every entry is a plain string, not a tuple.
        assert all(isinstance(h, str) for h in hosts)


# ---------------------------------------------------------------------
# Happy path + failover
# ---------------------------------------------------------------------


class TestResolverPoolQuery:
    def test_all_good_happy_path_uses_primary(self):
        """When the primary resolver answers, secondaries aren't hit."""
        routes = {
            "1.1.1.1": lambda n, t: _answer("v=dmp1;t=chunk;d=aGk="),
            "9.9.9.9": lambda n, t: pytest.fail("secondary should not be queried"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"])
            result = pool.query_txt_record("mb-abc.example.com")

        assert result == ["v=dmp1;t=chunk;d=aGk="]

    def test_primary_nxdomain_fails_over_to_secondary(self):
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
            "9.9.9.9": lambda n, t: _answer("from-secondary"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"])
            result = pool.query_txt_record("mb-abc.example.com")

        assert result == ["from-secondary"]

    def test_nxdomain_does_not_demote_resolver(self):
        """NXDOMAIN describes the name, not the resolver's health.

        A lookup for a name that genuinely doesn't exist must leave
        the primary resolver's health counters untouched — otherwise
        a single absent-mailbox query would poison the pool and
        divert every subsequent lookup to the secondary (or, with a
        one-host pool, return None until cooldown_seconds expired).
        """
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
            "9.9.9.9": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=1)
            # All resolvers agree the name doesn't exist -> None.
            assert pool.query_txt_record("absent.example.com") is None

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 0
        assert snap["9.9.9.9"]["consecutive_failures"] == 0
        # Both resolvers remain healthy after a legitimate NXDOMAIN.
        assert pool.healthy_hosts() == ["1.1.1.1", "9.9.9.9"]

    def test_noanswer_does_not_demote_resolver(self):
        """NoAnswer (RRset empty) is a normal DNS outcome, not a fault."""
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NoAnswer()),
            "9.9.9.9": lambda n, t: (_ for _ in ()).throw(dns.resolver.NoAnswer()),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=1)
            assert pool.query_txt_record("x.example.com") is None

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 0
        assert snap["9.9.9.9"]["consecutive_failures"] == 0
        assert pool.healthy_hosts() == ["1.1.1.1", "9.9.9.9"]

    def test_timeout_does_demote_resolver(self):
        """A Timeout IS a resolver fault and must increment failures."""
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.exception.Timeout()),
            "9.9.9.9": lambda n, t: _answer("ok"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=1)
            assert pool.query_txt_record("x.example.com") == ["ok"]

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 1
        # Primary exceeded its failure_threshold and is now in cooldown.
        assert "1.1.1.1" not in pool.healthy_hosts()
        assert "9.9.9.9" in pool.healthy_hosts()

    def test_primary_noanswer_fails_over(self):
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NoAnswer()),
            "9.9.9.9": lambda n, t: _answer("ok"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"])
            assert pool.query_txt_record("x.example.com") == ["ok"]

    def test_primary_timeout_fails_over(self):
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.exception.Timeout()),
            "9.9.9.9": lambda n, t: _answer("ok"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"])
            assert pool.query_txt_record("x.example.com") == ["ok"]

    def test_primary_socket_timeout_fails_over(self):
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(socket.timeout()),
            "9.9.9.9": lambda n, t: _answer("ok"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"])
            assert pool.query_txt_record("x.example.com") == ["ok"]

    def test_malformed_name_does_not_demote_resolvers(self):
        """A caller-side error (bad query name) must not poison the pool.

        `dns.name.LabelTooLong` and friends describe a bug in the
        caller's input, not resolver health. Blanket-catching them
        would let a single malformed lookup put every upstream into
        cooldown. The exception must propagate, and every resolver's
        `consecutive_failures` must stay at zero.
        """

        def boom(n, t):
            raise dns.name.LabelTooLong()

        routes = {"1.1.1.1": boom, "9.9.9.9": boom}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=1)
            with pytest.raises(dns.name.LabelTooLong):
                pool.query_txt_record("x" * 64 + ".example.com")

        # The exception propagated before any health bookkeeping ran,
        # so every resolver is still healthy with zero failures. In
        # particular, only the primary even got the call — the
        # secondary must not have been touched.
        for snap in pool.snapshot():
            assert snap["consecutive_failures"] == 0
        assert pool.healthy_hosts() == ["1.1.1.1", "9.9.9.9"]

    def test_empty_label_name_does_not_demote_resolvers(self):
        """Same contract for `dns.name.EmptyLabel` — also caller-side."""

        def boom(n, t):
            raise dns.name.EmptyLabel()

        routes = {"1.1.1.1": boom, "9.9.9.9": boom}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=1)
            with pytest.raises(dns.name.EmptyLabel):
                pool.query_txt_record("..example.com")

        for snap in pool.snapshot():
            assert snap["consecutive_failures"] == 0

    def test_primary_generic_os_error_fails_over(self):
        """A connection-refused or similar transport error still demotes."""
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(
                OSError("connection refused")
            ),
            "9.9.9.9": lambda n, t: _answer("ok"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"])
            assert pool.query_txt_record("x.example.com") == ["ok"]

    def test_all_resolvers_nxdomain_returns_none(self):
        """When every resolver authoritatively says "no such name," return None."""

        def boom(n, t):
            raise dns.resolver.NXDOMAIN()

        routes = {"1.1.1.1": boom, "9.9.9.9": boom, "8.8.8.8": boom}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9", "8.8.8.8"])
            assert pool.query_txt_record("x.example.com") is None

    def test_all_resolvers_timeout_returns_none(self):
        """When every resolver is unreachable, return None (and demote them)."""

        def boom(n, t):
            raise dns.exception.Timeout()

        routes = {"1.1.1.1": boom, "9.9.9.9": boom, "8.8.8.8": boom}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9", "8.8.8.8"], failure_threshold=1)
            assert pool.query_txt_record("x.example.com") is None

        # Every resolver recorded one transport failure.
        for snap in pool.snapshot():
            assert snap["consecutive_failures"] == 1
        assert pool.healthy_hosts() == []

    def test_multi_string_rdata_is_concatenated(self):
        """DNS allows multiple strings per TXT rdata; we join them."""
        rdata = _FakeRdata([b"part-a;", b"part-b"])
        routes = {"1.1.1.1": lambda n, t: _FakeAnswer([rdata])}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1"])
            assert pool.query_txt_record("x.example.com") == ["part-a;part-b"]


# ---------------------------------------------------------------------
# DNSSEC AD-bit policy (P0-4)
# ---------------------------------------------------------------------


class TestResolverPoolDnssecGate:
    """``ResolverPool(..., dnssec_required=True)`` rejects answers without
    the AD (Authenticated Data) flag — i.e. the upstream recursor did not
    DNSSEC-validate. The trust boundary is the channel between the client
    and the recursor; this gate is meaningful only over DoT/DoH or a
    trusted local recursor (an on-path attacker on plaintext UDP can flip
    AD). That caveat is documented on the constructor; tested here is the
    in-process behavior given a recursor whose answers either do or do
    not carry AD.
    """

    def test_default_off_does_not_require_ad(self):
        """Back-compat: ``dnssec_required=False`` (default) accepts an
        AD-less answer. Existing deployments must keep working."""
        routes = {
            "1.1.1.1": lambda n, t: _answer("v=dmp1;t=chunk;d=aGk=", ad=False),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1"])
            assert pool.query_txt_record("mb-x.example.com") == [
                "v=dmp1;t=chunk;d=aGk="
            ]

    def test_required_passes_when_ad_set(self):
        """The validating-recursor happy path: AD set on the response,
        the answer is delivered."""
        routes = {
            "1.1.1.1": lambda n, t: _answer("ad-validated", ad=True),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1"], dnssec_required=True)
            assert pool.query_txt_record("mb-x.example.com") == ["ad-validated"]

    def test_required_drops_when_ad_unset(self):
        """A non-validating recursor (or a stripped/forged answer) does
        not set AD. The answer must NOT reach the caller, and the
        upstream is demoted on its health counter so subsequent queries
        prefer a different resolver."""
        routes = {
            "1.1.1.1": lambda n, t: _answer("not-validated", ad=False),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1"], dnssec_required=True)
            # No fallback resolver, so query_txt_record returns None —
            # but the important assertion is "not the bypassed answer".
            assert pool.query_txt_record("mb-x.example.com") is None

    def test_required_falls_over_to_validating_resolver(self):
        """Two-resolver pool: first returns an AD-less answer (rejected),
        second returns AD-validated. Caller sees the validating answer.
        """
        routes = {
            "1.1.1.1": lambda n, t: _answer("not-validated", ad=False),
            "9.9.9.9": lambda n, t: _answer("validated", ad=True),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], dnssec_required=True)
            assert pool.query_txt_record("mb-x.example.com") == ["validated"]

    def test_required_failover_demotes_ad_less_resolver(self):
        """The AD-less resolver should land in cooldown after a failover —
        it counts against its health, like any transport-class failure.
        """
        routes = {
            "1.1.1.1": lambda n, t: _answer("not-validated", ad=False),
            "9.9.9.9": lambda n, t: _answer("validated", ad=True),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(
                ["1.1.1.1", "9.9.9.9"],
                dnssec_required=True,
                failure_threshold=1,
            )
            pool.query_txt_record("a.example.com")
            healthy = pool.healthy_hosts()
        # The AD-less resolver is demoted; the validator stays healthy.
        assert "9.9.9.9" in healthy
        assert "1.1.1.1" not in healthy

    def test_required_uses_edns_do_bit(self):
        """The pool must enable EDNS0 + DO so the recursor knows we want
        DNSSEC processing — without DO many recursors strip RRSIGs and
        never set AD, which would make every answer fail the gate even
        from a validating resolver. We assert the dnspython-level flag
        is set on each per-host resolver."""
        pool = ResolverPool(["1.1.1.1", "9.9.9.9"], dnssec_required=True)
        for state in pool._states:
            options = state.resolver.edns
            # dnspython exposes EDNS state through .edns (>=0 means enabled).
            # Use ednsflags to inspect the requested DNSSEC OK bit.
            assert options >= 0, "EDNS not enabled on dnssec_required resolver"
            assert state.resolver.ednsflags & dns.flags.DO


# ---------------------------------------------------------------------
# Health tracking & cooldown
# ---------------------------------------------------------------------


class TestResolverPoolHealth:
    def test_success_resets_failure_counter(self):
        call_count = {"1.1.1.1": 0}

        def flaky(n, t):
            call_count["1.1.1.1"] += 1
            if call_count["1.1.1.1"] == 1:
                raise dns.exception.Timeout()
            return _answer("ok")

        routes = {"1.1.1.1": flaky, "9.9.9.9": lambda n, t: _answer("fallback")}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(
                ["1.1.1.1", "9.9.9.9"],
                cooldown_seconds=60.0,
                failure_threshold=2,  # tolerate one blip before cooldown
            )
            # First query: 1.1.1.1 blips, 9.9.9.9 answers.
            assert pool.query_txt_record("x") == ["fallback"]
            # Second query: 1.1.1.1 returns to service and answers directly.
            assert pool.query_txt_record("x") == ["ok"]

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 0

    def test_bad_resolver_is_deprioritized_during_cooldown(self):
        """A cooled-down host is still reachable, but only after preferred hosts.

        Cooldown is a priority signal, not a hard ban: we never want a
        single host's cooldown to blackhole lookups, so a cooled-down
        resolver stays in the iteration — it just moves to the
        fallback tier behind every preferred (not-cooled-down) host.

        Here the primary always fails and the secondary always answers.
        After the primary enters cooldown, subsequent queries must be
        served by the secondary *first* (preferred tier), and the
        primary must never be reached on those queries because the
        secondary already satisfied the request.
        """
        call_log = []

        def always_fail(n, t):
            call_log.append("1.1.1.1")
            raise dns.exception.Timeout()

        def always_ok(n, t):
            call_log.append("9.9.9.9")
            return _answer("ok")

        routes = {"1.1.1.1": always_fail, "9.9.9.9": always_ok}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(
                ["1.1.1.1", "9.9.9.9"],
                cooldown_seconds=60.0,
                failure_threshold=1,
            )
            # First query: primary fails (1 call), secondary wins.
            assert pool.query_txt_record("x") == ["ok"]
            # Second query within cooldown: secondary is preferred-tier
            # and answers first, so the primary is never reached.
            assert pool.query_txt_record("x") == ["ok"]
            # Third query: same story.
            assert pool.query_txt_record("x") == ["ok"]

        # Primary was only ever called once — the initial failure.
        # On subsequent queries the preferred-tier secondary answered
        # before the fallback tier was consulted.
        assert call_log.count("1.1.1.1") == 1, (
            "primary should be deprioritized after cooldown, only reached "
            "if the preferred tier is exhausted"
        )
        assert call_log.count("9.9.9.9") == 3
        assert "9.9.9.9" in pool.healthy_hosts()
        assert "1.1.1.1" not in pool.healthy_hosts()

    def test_all_resolvers_cooled_down_still_tries_them(self):
        """If every preferred host is in cooldown, fall back to them.

        A transient failure across all resolvers must not blackhole
        lookups for the full cooldown window. When one of the
        cooled-down hosts recovers, the next query should succeed via
        the fallback tier and promote that host back to the preferred
        tier.
        """
        primary_behavior = {"1.1.1.1": "fail", "9.9.9.9": "fail"}

        def route(n, t):
            # Dispatch through the actual caller's nameserver — set
            # up below with autospec so `self` is the Resolver.
            raise AssertionError  # pragma: no cover (replaced per-call)

        def make_handler(host):
            def handler(n, t):
                mode = primary_behavior[host]
                if mode == "fail":
                    raise dns.exception.Timeout()
                return _answer(f"from-{host}")

            return handler

        routes = {
            "1.1.1.1": make_handler("1.1.1.1"),
            "9.9.9.9": make_handler("9.9.9.9"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(
                ["1.1.1.1", "9.9.9.9"],
                cooldown_seconds=60.0,
                failure_threshold=1,
            )
            # First query: both fail, both enter cooldown, None returned.
            assert pool.query_txt_record("x") is None
            assert pool.healthy_hosts() == []

            # Now 9.9.9.9 recovers — before the cooldown elapses. The
            # old behavior would have returned None without sending any
            # query. New behavior: the fallback tier is consulted and
            # the lookup succeeds.
            primary_behavior["9.9.9.9"] = "ok"
            assert pool.query_txt_record("x") == ["from-9.9.9.9"]

        # The successful call reset 9.9.9.9's failure counter and
        # promoted it back to the preferred tier.
        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["9.9.9.9"]["consecutive_failures"] == 0
        assert "9.9.9.9" in pool.healthy_hosts()

    def test_single_resolver_pool_never_blackholes(self):
        """A single-host pool must not blackhole lookups during cooldown.

        With only one resolver, the preferred tier is empty the moment
        it enters cooldown. The fallback tier (that same resolver) is
        the only way to ever get an answer before the cooldown elapses,
        and the pool must still try it rather than returning None
        unconditionally.
        """
        call_log = []
        behavior = {"mode": "fail"}

        def handler(n, t):
            call_log.append("1.1.1.1")
            if behavior["mode"] == "fail":
                raise dns.exception.Timeout()
            return _answer("ok")

        routes = {"1.1.1.1": handler}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(
                ["1.1.1.1"],
                cooldown_seconds=60.0,
                failure_threshold=1,
            )
            # First query: the resolver fails, enters cooldown.
            assert pool.query_txt_record("x") is None
            assert pool.healthy_hosts() == []
            assert len(call_log) == 1

            # Resolver recovers. Next query must still reach it even
            # though it's in cooldown (single-host pool).
            behavior["mode"] = "ok"
            assert pool.query_txt_record("x") == ["ok"]
            assert len(call_log) == 2

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 0
        assert "1.1.1.1" in pool.healthy_hosts()

    def test_fallback_tier_ordered_by_least_recent_failure(self):
        """Among cooled-down hosts, the oldest failure is tried first.

        Rationale: the resolver whose failure is farthest in the past
        has had the most time to recover, so it's the most promising
        candidate in the fallback tier. We freeze `last_failure_ts`
        values via the internal state so the test is deterministic.
        """
        call_log = []

        def make_handler(host, response):
            def handler(n, t):
                call_log.append(host)
                if response == "timeout":
                    raise dns.exception.Timeout()
                return _answer(response)

            return handler

        routes = {
            "1.1.1.1": make_handler("1.1.1.1", "timeout"),
            "2.2.2.2": make_handler("2.2.2.2", "from-2.2.2.2"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(
                ["1.1.1.1", "2.2.2.2"],
                cooldown_seconds=60.0,
                failure_threshold=1,
            )

            # Manually construct the scenario: both hosts in cooldown,
            # but 2.2.2.2 has the OLDER failure timestamp. Higher
            # priority in the configured order (1.1.1.1 first) must
            # NOT dictate fallback order — "least recent failure" wins.
            now = __import__("time").monotonic()
            for state in pool._states:
                state.consecutive_failures = 1  # trips threshold
            # 1.1.1.1 failed recently (t = now - 1s); 2.2.2.2 long ago
            # (t = now - 30s). Both still in cooldown (< 60s).
            states_by_host = {s.host: s for s in pool._states}
            states_by_host["1.1.1.1"].last_failure_ts = now - 1.0
            states_by_host["2.2.2.2"].last_failure_ts = now - 30.0

            # Preferred tier is empty; fallback tier should visit
            # 2.2.2.2 first (older failure) and succeed, never
            # reaching 1.1.1.1.
            assert pool.query_txt_record("x") == ["from-2.2.2.2"]

        assert call_log == ["2.2.2.2"], (
            f"expected only the older-failure resolver to be called, "
            f"got {call_log!r}"
        )

    def test_cooldown_expiration_promotes_resolver_back(self):
        """After cooldown elapses, a previously-bad resolver is tried again.

        A fresh success on the primary must also reset its failure counter
        so it resumes normal priority ordering.
        """
        primary_calls = {"n": 0}

        def primary_behavior(n, t):
            primary_calls["n"] += 1
            if primary_calls["n"] == 1:
                raise dns.exception.Timeout()
            return _answer("primary-back")

        routes = {
            "1.1.1.1": primary_behavior,
            "9.9.9.9": lambda n, t: _answer("fallback"),
        }

        # Fake monotonic clock so we can fast-forward past the cooldown.
        fake_now = {"t": 1000.0}

        def fake_monotonic():
            return fake_now["t"]

        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve, patch(
            "dmp.network.resolver_pool.time.monotonic", side_effect=fake_monotonic
        ):
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(
                ["1.1.1.1", "9.9.9.9"],
                cooldown_seconds=60.0,
                failure_threshold=1,
            )
            # Primary fails at t=1000, falls back to secondary.
            assert pool.query_txt_record("x") == ["fallback"]
            assert "1.1.1.1" not in pool.healthy_hosts()

            # Still in cooldown at t=1030 -> skipped, secondary used.
            fake_now["t"] = 1030.0
            assert pool.query_txt_record("x") == ["fallback"]
            assert "1.1.1.1" not in pool.healthy_hosts()

            # Cooldown expired at t=1061 -> primary retried, succeeds,
            # returns to priority-one slot.
            fake_now["t"] = 1061.0
            assert "1.1.1.1" in pool.healthy_hosts()
            assert pool.query_txt_record("x") == ["primary-back"]

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 0
        assert snap["1.1.1.1"]["last_success_ts"] > 0

    def test_empty_answer_falls_through_to_next_resolver(self):
        """A resolver returning zero rdatas is treated like NoAnswer.

        It doesn't disprove anyone and it doesn't count as a real hit,
        so we continue down the priority list. If a later resolver
        actually returns records, they win.
        """

        def empty(n, t):
            return _FakeAnswer()  # zero-length iterable

        routes = {"1.1.1.1": empty, "9.9.9.9": lambda n, t: _answer("ok")}
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"])
            assert pool.query_txt_record("x") == ["ok"]


# ---------------------------------------------------------------------
# Oracle-based demotion: NXDOMAIN is a health failure only if a later
# resolver disproves it with a real answer.
# ---------------------------------------------------------------------


class TestOracleDemotion:
    def test_lying_primary_demoted_when_secondary_succeeds(self):
        """Primary says NXDOMAIN; secondary returns TXT. Primary is wrong.

        The later-resolver oracle proves the primary was lying,
        stale, or censoring. Its `consecutive_failures` must tick up
        and it must drop out of `healthy_hosts()` so subsequent
        queries skip it while in cooldown.
        """
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
            "9.9.9.9": lambda n, t: _answer("real-record"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=1)
            assert pool.query_txt_record("name.example.com") == ["real-record"]

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 1
        assert snap["9.9.9.9"]["consecutive_failures"] == 0
        assert "1.1.1.1" not in pool.healthy_hosts()
        assert "9.9.9.9" in pool.healthy_hosts()

    def test_lying_primary_demoted_when_secondary_succeeds_via_noanswer(self):
        """Same as above but the primary raises NoAnswer instead of NXDOMAIN."""
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NoAnswer()),
            "9.9.9.9": lambda n, t: _answer("real-record"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=1)
            assert pool.query_txt_record("name.example.com") == ["real-record"]

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 1
        assert "1.1.1.1" not in pool.healthy_hosts()

    def test_all_nxdomain_still_does_not_demote(self):
        """Every resolver says NXDOMAIN: nobody oracled anybody.

        This pins the "true missing record" behavior the r1 fix
        introduced. Without the oracle, a benign absent-mailbox lookup
        would poison the pool on every call.
        """
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
            "9.9.9.9": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
            "8.8.8.8": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9", "8.8.8.8"], failure_threshold=1)
            assert pool.query_txt_record("absent.example.com") is None

        for snap in pool.snapshot():
            assert snap["consecutive_failures"] == 0
        assert pool.healthy_hosts() == ["1.1.1.1", "9.9.9.9", "8.8.8.8"]

    def test_nxdomain_resets_consecutive_failures_when_no_oracle(self):
        """A legitimate not-found response resets any stale failure streak.

        With `failure_threshold > 1`, a resolver that had an earlier
        transport blip accumulates `consecutive_failures = 1`. If it
        later serves a genuine NXDOMAIN (no later resolver disproves
        it), that IS a healthy response — it successfully returned
        authoritative "no such record" data. Without a reset, a future
        unrelated timeout would count as the "second consecutive"
        failure and demote a resolver that served correctly in between.
        """
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
            "9.9.9.9": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=2)

            # Simulate a prior transport failure that left the streak
            # at 1 but below the threshold (still preferred).
            pool._states[0].consecutive_failures = 1
            pool._states[1].consecutive_failures = 1

            # All-NXDOMAIN query — nobody oracled anybody.
            assert pool.query_txt_record("absent.example.com") is None

        snap = {s["host"]: s for s in pool.snapshot()}
        # The legitimate not-found reset both streaks to 0.
        assert snap["1.1.1.1"]["consecutive_failures"] == 0
        assert snap["9.9.9.9"]["consecutive_failures"] == 0

    def test_nxdomain_does_not_reset_when_oracle_demotes(self):
        """When a later resolver returns TXT, the not-found primary is demoted.

        The oracle-demote path must take precedence over the all-
        not-found reset path: if we reset first and then demote, we'd
        net out to `consecutive_failures = 1` which is the same as
        plain demotion — but the two paths are mutually exclusive by
        construction, so this test pins that.
        """
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
            "9.9.9.9": lambda n, t: _answer("real-record"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "9.9.9.9"], failure_threshold=2)

            # Primary starts with streak = 0 (clean). Secondary too.
            assert pool.query_txt_record("name.example.com") == ["real-record"]

        snap = {s["host"]: s for s in pool.snapshot()}
        # Primary was oracle-demoted (+1), NOT reset to 0.
        assert snap["1.1.1.1"]["consecutive_failures"] == 1
        # Secondary's success reset its own streak.
        assert snap["9.9.9.9"]["consecutive_failures"] == 0

    def test_multi_failure_threshold_streak_semantics(self):
        """With `failure_threshold=2`, a mid-success breaks the streak.

        Timeline:
          1. Timeout from 1.1.1.1 -> streak goes to 1 (still preferred,
             below threshold of 2).
          2. TXT hit from 1.1.1.1 -> streak resets to 0.
          3. Timeout from 1.1.1.1 -> streak goes to 1.

        End state: streak = 1, NOT 2. This already holds via the
        existing `_mark_success` call on a TXT hit, but we lock it in
        to catch any regression in the spirit of "consecutive" — and
        to pair with the new all-not-found reset path for the same
        reason.
        """
        behavior = {"mode": "timeout"}
        call_log = []

        def handler(n, t):
            call_log.append(behavior["mode"])
            mode = behavior["mode"]
            if mode == "timeout":
                raise dns.exception.Timeout()
            return _answer("ok")

        routes = {
            "1.1.1.1": handler,
            "9.9.9.9": lambda n, t: _answer("fallback"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(
                ["1.1.1.1", "9.9.9.9"],
                failure_threshold=2,
                cooldown_seconds=60.0,
            )

            # Step 1: timeout -> streak = 1.
            assert pool.query_txt_record("x") == ["fallback"]
            assert pool.snapshot()[0]["consecutive_failures"] == 1

            # Step 2: success -> streak resets to 0.
            behavior["mode"] = "ok"
            assert pool.query_txt_record("x") == ["ok"]
            assert pool.snapshot()[0]["consecutive_failures"] == 0

            # Step 3: timeout again -> streak goes back to 1, NOT 2.
            behavior["mode"] = "timeout"
            assert pool.query_txt_record("x") == ["fallback"]

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 1
        # Still preferred (below threshold of 2).
        assert "1.1.1.1" in pool.healthy_hosts()

    def test_multiple_lying_primaries_all_demoted_by_one_oracle(self):
        """Two primaries lie; third succeeds. Both liars get demoted.

        Ensures the retroactive demotion walks the whole deferred
        list, not just the immediate predecessor.
        """
        routes = {
            "1.1.1.1": lambda n, t: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()),
            "2.2.2.2": lambda n, t: (_ for _ in ()).throw(dns.resolver.NoAnswer()),
            "9.9.9.9": lambda n, t: _answer("real"),
        }
        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True
        ) as mock_resolve:
            mock_resolve.side_effect = _route_by_nameserver(routes)
            pool = ResolverPool(["1.1.1.1", "2.2.2.2", "9.9.9.9"], failure_threshold=1)
            assert pool.query_txt_record("x.example.com") == ["real"]

        snap = {s["host"]: s for s in pool.snapshot()}
        assert snap["1.1.1.1"]["consecutive_failures"] == 1
        assert snap["2.2.2.2"]["consecutive_failures"] == 1
        assert snap["9.9.9.9"]["consecutive_failures"] == 0
        healthy = pool.healthy_hosts()
        assert "1.1.1.1" not in healthy
        assert "2.2.2.2" not in healthy
        assert "9.9.9.9" in healthy


# ---------------------------------------------------------------------
# Discovery (classmethod) + WELL_KNOWN_RESOLVERS constant.
# ---------------------------------------------------------------------


class TestWellKnownResolvers:
    def test_has_at_least_four_entries(self):
        """Operator diversity requires ≥4 entries (Google, Cloudflare,
        Quad9, OpenDNS at minimum) so a single provider's outage doesn't
        take the whole pool down."""
        assert len(WELL_KNOWN_RESOLVERS) >= 4

    def test_all_entries_are_ipv4_literals(self):
        """IPv4 only: a silently-unreachable v6 literal on a v4-only
        network would burn discovery budget without paying back."""
        for host in WELL_KNOWN_RESOLVERS:
            addr = ipaddress.ip_address(host)
            assert isinstance(addr, ipaddress.IPv4Address), f"{host!r} is not IPv4"

    def test_includes_major_providers(self):
        """The four-operator balance is a contract, not an accident."""
        hosts = set(WELL_KNOWN_RESOLVERS)
        assert "8.8.8.8" in hosts  # Google
        assert "1.1.1.1" in hosts  # Cloudflare
        assert "9.9.9.9" in hosts  # Quad9
        assert "208.67.222.222" in hosts  # OpenDNS


class TestResolverPoolDiscover:
    def test_keeps_only_successful_candidates(self):
        """A candidate that answers is in, one that times out is out."""

        def router(self, name, rdtype="A", *args, **kwargs):
            host = self.nameservers[0]
            if host == "1.1.1.1":
                return _answer("ok")
            if host == "9.9.9.9":
                raise dns.exception.Timeout()
            raise AssertionError(f"unexpected host {host!r}")

        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True, side_effect=router
        ):
            pool = ResolverPool.discover(["1.1.1.1", "9.9.9.9"], timeout=0.5)

        hosts = [s["host"] for s in pool.snapshot()]
        assert hosts == ["1.1.1.1"]

    def test_preserves_candidate_order(self):
        """Successful candidates retain the caller's insertion order.

        Priority in a ResolverPool is insertion order — discovery is
        usually called with a list the caller implicitly ordered by
        preference, so shuffling would silently change failover
        behavior downstream.
        """

        def router(self, name, rdtype="A", *args, **kwargs):
            # Everybody but 9.9.9.9 answers.
            host = self.nameservers[0]
            if host == "9.9.9.9":
                raise dns.exception.Timeout()
            return _answer("ok")

        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True, side_effect=router
        ):
            pool = ResolverPool.discover(["8.8.8.8", "9.9.9.9", "1.1.1.1"], timeout=0.5)

        assert [s["host"] for s in pool.snapshot()] == ["8.8.8.8", "1.1.1.1"]

    def test_deduplicates_candidates(self):
        """Duplicate candidates are probed (and kept) once."""
        call_count = {"1.1.1.1": 0}

        def router(self, name, rdtype="A", *args, **kwargs):
            host = self.nameservers[0]
            call_count[host] = call_count.get(host, 0) + 1
            return _answer("ok")

        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True, side_effect=router
        ):
            pool = ResolverPool.discover(["1.1.1.1", "1.1.1.1", "1.1.1.1"], timeout=0.5)

        assert [s["host"] for s in pool.snapshot()] == ["1.1.1.1"]
        assert call_count["1.1.1.1"] == 1

    def test_all_timeouts_raise_value_error(self):
        """Every candidate times out: discover raises rather than
        building an empty pool that would fail every future query.

        Empty-pool-prohibited is the design choice — a pool with zero
        hosts is indistinguishable at construction from one with a
        valid list, but every query would return None, so callers
        would much rather see the failure at the discovery boundary.
        """

        def router(self, name, rdtype="A", *args, **kwargs):
            raise dns.exception.Timeout()

        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True, side_effect=router
        ):
            with pytest.raises(ValueError, match="no candidates answered"):
                ResolverPool.discover(["1.1.1.1", "9.9.9.9"], timeout=0.1)

    def test_non_ip_entries_are_filtered_with_warning(self, caplog):
        """Hostnames / typos are skipped with a log warning, not rejected."""

        def router(self, name, rdtype="A", *args, **kwargs):
            return _answer("ok")

        with caplog.at_level(logging.WARNING, logger="dmp.network.resolver_pool"):
            with patch.object(
                dns.resolver.Resolver,
                "resolve",
                autospec=True,
                side_effect=router,
            ):
                pool = ResolverPool.discover(
                    ["1.1.1.1", "dns.google", "not-an-ip", "9.9.9.9"],
                    timeout=0.5,
                )

        # Only the valid IP literals made it into the pool.
        assert [s["host"] for s in pool.snapshot()] == ["1.1.1.1", "9.9.9.9"]

        warnings = [
            r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING
        ]
        # One warning per skipped non-literal.
        assert any("dns.google" in msg for msg in warnings), warnings
        assert any("not-an-ip" in msg for msg in warnings), warnings

    def test_only_non_ip_entries_raises_value_error(self):
        """No valid IP literals at all -> same empty-pool prohibition."""
        with pytest.raises(ValueError, match="no candidates answered"):
            ResolverPool.discover(["dns.google", "example.com"], timeout=0.1)

    def test_nxdomain_probe_counts_as_responding(self):
        """A resolver that authoritatively says "no record" is still
        reachable and behaving — keep it in the pool.

        The probe name is meant to be universally resolvable, but a
        resolver returning NXDOMAIN for it is a weird case (split
        horizon, lying resolver), and the oracle-demotion logic in the
        normal query path will handle that later. Discovery only cares
        about reachability.
        """

        def router(self, name, rdtype="A", *args, **kwargs):
            host = self.nameservers[0]
            if host == "1.1.1.1":
                raise dns.resolver.NXDOMAIN()
            raise AssertionError(f"unexpected {host!r}")

        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True, side_effect=router
        ):
            pool = ResolverPool.discover(["1.1.1.1"], timeout=0.5)

        assert [s["host"] for s in pool.snapshot()] == ["1.1.1.1"]

    def test_noanswer_probe_rejects_resolver(self):
        """NoAnswer on the TXT probe means "this resolver won't serve TXT."

        `google.com` TXT resolves cleanly on every major public
        resolver; a NoAnswer here is a strong signal the resolver is
        policy-filtering or stripping TXT records. Keeping it would
        make every DMP read through it return empty, so drop it at
        discovery time.

        NXDOMAIN is treated differently (see
        `test_nxdomain_probe_counts_as_responding`) because it's a
        weirder split-horizon case rather than a clean
        "wouldn't-serve-TXT" signal.
        """

        def router(self, name, rdtype="A", *args, **kwargs):
            host = self.nameservers[0]
            if host == "1.1.1.1":
                raise dns.resolver.NoAnswer()
            if host == "9.9.9.9":
                return _answer("ok")
            raise AssertionError(f"unexpected {host!r}")

        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True, side_effect=router
        ):
            pool = ResolverPool.discover(["1.1.1.1", "9.9.9.9"], timeout=0.5)

        # Only the resolver that actually served the probe made it in.
        assert [s["host"] for s in pool.snapshot()] == ["9.9.9.9"]

    def test_returns_working_resolverpool_instance(self):
        """Successful discovery returns a fully wired ResolverPool."""

        def router(self, name, rdtype="A", *args, **kwargs):
            return _answer("ok")

        with patch.object(
            dns.resolver.Resolver, "resolve", autospec=True, side_effect=router
        ):
            pool = ResolverPool.discover(["1.1.1.1", "9.9.9.9"], timeout=0.5)

        assert isinstance(pool, ResolverPool)
        assert isinstance(pool, DNSRecordReader)
        assert pool.healthy_hosts() == ["1.1.1.1", "9.9.9.9"]
