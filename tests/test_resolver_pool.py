"""Tests for ResolverPool — priority ordering, failover, cooldown."""

import socket
from unittest.mock import patch

import dns.exception
import dns.name
import dns.resolver
import pytest

from dmp.network import DNSRecordReader, ResolverPool

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


class _FakeRdata:
    """Mimic a dnspython TXT rdata object — just exposes `.strings`."""

    def __init__(self, strings):
        self.strings = strings


class _FakeAnswer(list):
    """A dnspython Answer is iterable over rdata objects."""


def _answer(*txt_values: str) -> _FakeAnswer:
    """Build a fake dnspython answer for the given TXT string(s)."""
    return _FakeAnswer(_FakeRdata([v.encode("utf-8")]) for v in txt_values)


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

    def test_bad_resolver_is_skipped_during_cooldown(self):
        """Once cooldown is active, the bad host is not re-queried."""
        down_call_count = {"n": 0}

        def always_fail(n, t):
            down_call_count["n"] += 1
            raise dns.exception.Timeout()

        routes = {
            "1.1.1.1": always_fail,
            "9.9.9.9": lambda n, t: _answer("ok"),
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
            # First query: primary fails (1 call), secondary wins.
            assert pool.query_txt_record("x") == ["ok"]
            # Second query within cooldown: primary must NOT be retried.
            assert pool.query_txt_record("x") == ["ok"]

        assert (
            down_call_count["n"] == 1
        ), "primary should be skipped during cooldown, not re-queried"
        assert "9.9.9.9" in pool.healthy_hosts()
        assert "1.1.1.1" not in pool.healthy_hosts()

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
