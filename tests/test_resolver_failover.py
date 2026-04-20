"""Integration tests for ResolverPool failover under partial upstream block.

These tests exercise the full UDP path: two real `DMPDnsServer` instances
act as "DNS stubs" on ephemeral loopback ports, and a `ResolverPool`
fans TXT queries across them. One stub serves real DMP records; the
other returns NXDOMAIN for every query (simulating censorship, split-
horizon staleness, or a lying recursive resolver).

Port handling note
------------------
`ResolverPool.__init__` accepts a single `port` shared across all
upstreams — see TASKS.md M1.5 (per-host ports) in the backlog. Our two
stubs need distinct ephemeral UDP ports, so we can't drive a real
`ResolverPool` directly without resolving that limitation.

Options considered:
  (a) Bind the two stubs to 127.0.0.1 and 127.0.0.2 on the same port.
      Works on darwin but not portable; CI Linux containers often don't
      have 127.0.0.2 configured.
  (b) Monkey-patch `dns.resolver.Resolver` per-instance to carry a
      per-host port. Fragile — couples the test to dnspython internals.
  (c) Define a thin test-only subclass of `ResolverPool` that accepts
      per-host ports. Explicitly permitted by the M1.4 task brief:
      "a minimal test-only subclass of ResolverPool that accepts
      per-host ports is acceptable inside tests/test_resolver_failover.py."

We pick (c): `_PerHostPortResolverPool` below. It is strictly additive
— it reuses the base class's health model, iteration logic, NXDOMAIN
oracle, and cooldown semantics unchanged. Only the construction of
each underlying `dns.resolver.Resolver` is specialized to carry a
per-host port.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from typing import List, Sequence, Tuple

import dns.flags
import dns.message
import dns.rcode
import dns.resolver
import pytest

from dmp.client.client import DMPClient
from dmp.network.memory import InMemoryDNSStore
from dmp.network.resolver_pool import ResolverPool, _HostState
from dmp.server.dns_server import DMPDnsServer

# ---------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------


def _free_udp_port() -> int:
    """Bind UDP port 0 on loopback, read assigned port, release.

    A small race window exists between close() and re-bind, but it is
    negligible for test setup where the caller re-binds within a few
    microseconds.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _PerHostPortResolverPool(ResolverPool):
    """Test-only ResolverPool that accepts `(host, port)` pairs.

    The production `ResolverPool` shares a single port across all
    upstreams (M1.5 backlog). For integration tests we need two stubs
    on distinct ephemeral UDP ports, so we specialize the per-host
    `dns.resolver.Resolver` construction to carry the port alongside
    its host.

    Everything else — health bookkeeping, iteration order, oracle
    demotion, cooldown, snapshot(), healthy_hosts() — is inherited
    untouched. This keeps the test honest: we're exercising the real
    failover state machine, not a reimplementation.
    """

    def __init__(
        self,
        hosts_with_ports: Sequence[Tuple[str, int]],
        *,
        timeout: float = 5.0,
        lifetime: float = 10.0,
        cooldown_seconds: float = 60.0,
        failure_threshold: int = 1,
    ) -> None:
        if not hosts_with_ports:
            raise ValueError("requires at least one host")
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")

        for host, _port in hosts_with_ports:
            # Mirror the parent's IP-literal guard so misuse in tests
            # fails fast with the same message shape.
            ipaddress.ip_address(host)

        # We intentionally do NOT call super().__init__: it would build
        # resolvers using its single-port assumption. Instead we set
        # up the same attributes directly with per-host ports.
        self._port = hosts_with_ports[0][1]  # cosmetic; unused by us
        self._cooldown_seconds = cooldown_seconds
        self._failure_threshold = failure_threshold
        self._lock = threading.Lock()

        self._states: List[_HostState] = []
        for host, port in hosts_with_ports:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [host]
            resolver.port = port
            resolver.timeout = timeout
            resolver.lifetime = lifetime
            self._states.append(_HostState(host=host, resolver=resolver))


class _NxdomainServer:
    """A minimal UDP DNS server that answers NXDOMAIN for every query.

    We don't use `DMPDnsServer` with an empty `InMemoryDNSStore` for
    this role because the `InMemoryDNSStore` empty-name path returns
    None which `DMPDnsServer` already maps to NXDOMAIN — which would
    work, but building a dedicated stub makes the test's intent
    obvious and keeps us from coupling the test to the empty-store
    behavior of the happy-path server class.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.query_count = 0
        self._count_lock = threading.Lock()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.1)  # short timeout so the loop can observe _stop
        self.port = sock.getsockname()[1]
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._serve, name="nxdomain-stub", daemon=True
        )
        self._thread.start()

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                query = dns.message.from_wire(data)
                response = dns.message.make_response(query)
                response.flags |= dns.flags.AA
                response.set_rcode(dns.rcode.NXDOMAIN)
                self._sock.sendto(response.to_wire(), addr)
            except Exception:
                # Drop malformed packets silently; production DMP server
                # does the same.
                continue
            with self._count_lock:
                self.query_count += 1

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._sock is not None:
            self._sock.close()
        self._sock = None
        self._thread = None

    def __enter__(self) -> "_NxdomainServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------


@pytest.fixture
def shared_store():
    """Shared in-memory DNS store used as the 'good' stub's backing data."""
    return InMemoryDNSStore()


@pytest.fixture
def good_stub(shared_store):
    """DMPDnsServer instance serving real TXT records from shared_store."""
    port = _free_udp_port()
    server = DMPDnsServer(shared_store, host="127.0.0.1", port=port)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def bad_stub():
    """UDP server that returns NXDOMAIN for every query."""
    server = _NxdomainServer(host="127.0.0.1", port=_free_udp_port())
    server.start()
    yield server
    server.stop()


# ---------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------


class TestResolverFailoverAcceptance:
    """The three acceptance criteria from TASKS.md M1.4."""

    def test_two_local_udp_stubs_serve_opposite_answers(
        self, good_stub, bad_stub, shared_store
    ):
        """Pre-flight sanity: the two stubs disagree about the same name.

        Confirms the stubs are reachable and independently wired before
        any failover assertion depends on them. Without this sanity
        check a silent bind failure could masquerade as a failover
        success.
        """
        shared_store.publish_txt_record("hello.mesh.test", "v=dmp1;t=chunk")

        good = _PerHostPortResolverPool([("127.0.0.1", good_stub.port)])
        bad = _PerHostPortResolverPool(
            [("127.0.0.1", bad_stub.port)], failure_threshold=1
        )

        # Good stub serves what we published.
        assert good.query_txt_record("hello.mesh.test") == ["v=dmp1;t=chunk"]
        # Bad stub answers NXDOMAIN (which the pool reports as None).
        assert bad.query_txt_record("hello.mesh.test") is None

    def test_client_delivers_message_with_bad_stub_first(
        self, good_stub, bad_stub, shared_store
    ):
        """Client configured bad-first still delivers a message end-to-end.

        Asserts the second acceptance criterion: a DMPClient whose
        reader is a ResolverPool with the NXDOMAIN stub in the primary
        slot and the real stub in the fallback slot can still send
        and receive a message successfully. This is the core failover
        promise — "partial block by any single resolver doesn't take
        delivery down."
        """
        # Bad resolver in the preferred slot; good resolver behind it.
        pool = _PerHostPortResolverPool(
            [
                ("127.0.0.1", bad_stub.port),
                ("127.0.0.1", good_stub.port),
            ],
            failure_threshold=1,
            cooldown_seconds=60.0,
        )

        # Alice and Bob share a writer (the in-memory store the good
        # stub serves from) but read DNS through the two-stub pool.
        alice = DMPClient(
            "alice",
            "alice-pass",
            domain="mesh.test",
            writer=shared_store,
            reader=pool,
        )
        bob = DMPClient(
            "bob",
            "bob-pass",
            domain="mesh.test",
            writer=shared_store,
            reader=pool,
        )
        alice.add_contact("bob", bob.get_public_key_hex())
        bob.add_contact("alice", alice.get_public_key_hex())

        assert alice.send_message("bob", "hello over failover")

        inbox = bob.receive_messages()
        assert len(inbox) == 1
        assert inbox[0].plaintext == b"hello over failover"

        # The bad stub must have been queried at least once (failover
        # path was actually exercised, not accidentally skipped).
        assert bad_stub.query_count >= 1

    def test_bad_stub_demoted_after_cooldown(self, good_stub, bad_stub, shared_store):
        """After N failover queries, the bad stub is demoted and skipped.

        Asserts the third acceptance criterion. The oracle-demotion
        rule (NXDOMAIN that a later resolver disproves is a health
        failure) should drive the bad stub into cooldown on the first
        successful query that publishes records. Subsequent queries
        should skip the bad stub entirely — observable via both
        `ResolverPool.healthy_hosts()` and the bad stub's own query
        counter not increasing.
        """
        shared_store.publish_txt_record("named.mesh.test", "v=dmp1;t=chunk;d=a")

        pool = _PerHostPortResolverPool(
            [
                ("127.0.0.1", bad_stub.port),
                ("127.0.0.1", good_stub.port),
            ],
            failure_threshold=1,
            cooldown_seconds=60.0,
        )

        # First query: bad stub says NXDOMAIN, good stub serves the
        # record. The oracle fires, demoting the bad stub.
        assert pool.query_txt_record("named.mesh.test") == ["v=dmp1;t=chunk;d=a"]
        assert bad_stub.query_count == 1

        # Bad stub is out of the preferred tier; good stub stays in.
        healthy = pool.healthy_hosts()
        assert healthy == ["127.0.0.1"]  # only one host entry; matches good
        # Concretely: the primary upstream entry (index 0) is the bad
        # one and is NOT healthy; the secondary (index 1) is.
        snap = pool.snapshot()
        assert snap[0]["consecutive_failures"] >= 1  # bad stub demoted
        assert snap[1]["consecutive_failures"] == 0  # good stub clean

        # Drive several more queries. Every one must succeed, and the
        # bad stub's counter must NOT tick further — it's cooled down
        # and the preferred-tier good stub answers first.
        pre_count = bad_stub.query_count
        for _ in range(5):
            assert pool.query_txt_record("named.mesh.test") == ["v=dmp1;t=chunk;d=a"]
        assert bad_stub.query_count == pre_count, (
            "demoted bad stub was reached during cooldown — preferred-tier "
            "good stub should have answered first"
        )


class TestResolverFailoverTiming:
    """Semantic guarantees beyond the bare acceptance criteria."""

    def test_subsequent_queries_faster_after_demotion(
        self, good_stub, bad_stub, shared_store
    ):
        """After cooldown, subsequent queries skip the bad stub entirely.

        The "queries succeed faster" clause of the third acceptance
        criterion. We assert the causal fact behind the speedup —
        the bad stub's query counter stops advancing — which is both
        tighter than a wall-clock assertion and immune to CI jitter.
        A timing-based assertion would either flake or require a
        large safety margin; counting is deterministic.
        """
        shared_store.publish_txt_record("timing.mesh.test", "v=dmp1;t=chunk;d=b")

        pool = _PerHostPortResolverPool(
            [
                ("127.0.0.1", bad_stub.port),
                ("127.0.0.1", good_stub.port),
            ],
            failure_threshold=1,
            cooldown_seconds=60.0,
        )

        # First query: both stubs touched, bad stub oracle-demoted.
        t_first = time.monotonic()
        assert pool.query_txt_record("timing.mesh.test") == ["v=dmp1;t=chunk;d=b"]
        first_elapsed = time.monotonic() - t_first
        bad_calls_after_first = bad_stub.query_count
        assert bad_calls_after_first == 1

        # Second query: bad stub is cooled down, good stub answers
        # straight away. No second visit to the bad stub.
        t_second = time.monotonic()
        assert pool.query_txt_record("timing.mesh.test") == ["v=dmp1;t=chunk;d=b"]
        second_elapsed = time.monotonic() - t_second
        assert bad_stub.query_count == bad_calls_after_first

        # Soft timing assertion: second query must be at most the
        # duration of the first (no extra stub hop). Use an ample
        # allowance to avoid CI flakes — the semantic guarantee above
        # (bad_stub.query_count unchanged) is what we really care
        # about; this is a belt-and-suspenders check that the
        # skipped-stub path genuinely shortcut the wire work.
        assert second_elapsed <= first_elapsed + 0.5

    def test_only_bad_stub_configured_returns_none_without_blackhole(self, bad_stub):
        """A pool whose only upstream is the bad stub returns None, not a hang.

        Pins the single-host-pool invariant from the ResolverPool
        design: even with zero healthy fallbacks, a query must not
        blackhole — it resolves promptly to None so the caller can
        surface "not found."
        """
        pool = _PerHostPortResolverPool(
            [("127.0.0.1", bad_stub.port)],
            failure_threshold=1,
            cooldown_seconds=60.0,
        )
        t = time.monotonic()
        assert pool.query_txt_record("anything.mesh.test") is None
        # Bounded by the per-query lifetime (default 10s) well under
        # the pytest timeout; we just want to confirm no deadlock.
        assert time.monotonic() - t < 5.0

    def test_good_stub_primary_does_not_touch_bad_stub(
        self, good_stub, bad_stub, shared_store
    ):
        """With good-first order, the bad stub is never consulted.

        The happy-path mirror of the failover tests above. When the
        primary resolver answers, the failover tier is not visited —
        no opportunity for the bad stub to even log a query. This
        guards against a regression where we would eagerly poll every
        upstream on every query.
        """
        shared_store.publish_txt_record("primary.mesh.test", "v=dmp1;t=chunk;d=c")

        pool = _PerHostPortResolverPool(
            [
                ("127.0.0.1", good_stub.port),
                ("127.0.0.1", bad_stub.port),
            ],
            failure_threshold=1,
        )

        for _ in range(3):
            assert pool.query_txt_record("primary.mesh.test") == ["v=dmp1;t=chunk;d=c"]

        assert bad_stub.query_count == 0


class TestResolverFailoverOracle:
    """The NXDOMAIN-oracle rule under real UDP, not mocks."""

    def test_benign_all_nxdomain_does_not_demote_anyone(self, bad_stub):
        """Two NXDOMAIN-returning stubs querying a truly absent name.

        When NO later resolver disproves a not-found answer, the
        oracle does not fire and no health bookkeeping kicks in. This
        is the "absent mailbox" safety net — a lookup for a name that
        really doesn't exist anywhere must not poison the pool.
        """
        # Spin up a SECOND NXDOMAIN stub so we have two.
        second_bad = _NxdomainServer(host="127.0.0.1", port=_free_udp_port())
        second_bad.start()
        try:
            pool = _PerHostPortResolverPool(
                [
                    ("127.0.0.1", bad_stub.port),
                    ("127.0.0.1", second_bad.port),
                ],
                failure_threshold=1,
                cooldown_seconds=60.0,
            )

            assert pool.query_txt_record("absent.mesh.test") is None

            # Neither stub was demoted — both still healthy.
            snap = pool.snapshot()
            assert snap[0]["consecutive_failures"] == 0
            assert snap[1]["consecutive_failures"] == 0
            assert len(pool.healthy_hosts()) == 2
        finally:
            second_bad.stop()

    def test_oracle_demotes_lying_resolver_across_real_udp(
        self, good_stub, bad_stub, shared_store
    ):
        """Real UDP reproduction of `test_lying_primary_demoted_when_secondary_succeeds`.

        The unit-test suite covers this path with mocks; this test
        is the integration-level counterpart, exercising real
        `dns.query.udp` against real listeners. If the oracle logic
        ever regresses to only working on mocked resolvers, this
        test catches it.
        """
        shared_store.publish_txt_record("oracle.mesh.test", "v=dmp1;t=chunk;d=d")

        pool = _PerHostPortResolverPool(
            [
                ("127.0.0.1", bad_stub.port),
                ("127.0.0.1", good_stub.port),
            ],
            failure_threshold=1,
        )

        # One query is enough: bad stub says NXDOMAIN, good stub
        # disproves it with a real record, oracle fires.
        assert pool.query_txt_record("oracle.mesh.test") == ["v=dmp1;t=chunk;d=d"]

        snap = pool.snapshot()
        # Primary entry (bad stub) took a +1 failure from the oracle.
        assert snap[0]["consecutive_failures"] == 1
        # Secondary entry (good stub) successful, counter reset/zero.
        assert snap[1]["consecutive_failures"] == 0
