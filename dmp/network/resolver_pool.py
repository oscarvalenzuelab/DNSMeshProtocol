"""Resolver pool with per-host health tracking and automatic failover.

Recursive resolvers fail in several ways — NXDOMAIN when a name is
absent (or censored via lying resolver), NoAnswer when the RRset is
empty, transport timeouts when the resolver is down, and
`NoNameservers` when dnspython gives up after its internal retries.
Callers of `DNSRecordReader.query_txt_record` want a single boolean
answer: "did I get records back?" — not a taxonomy of DNS failure
modes. `ResolverPool` provides that by trying a list of upstream
resolvers in priority order and demoting ones that misbehave.

Health model
------------
- Each host keeps `consecutive_failures` and `last_failure_ts`.
- A host with `consecutive_failures >= failure_threshold` is skipped
  while `now - last_failure_ts < cooldown_seconds`.
- Once the cooldown elapses, the host is re-tried on the next query.
  A success zeroes its failure counter; another failure just refreshes
  the cooldown without stacking further.
- Iteration is always in the original priority order; demotion is a
  *skip*, not a permanent reorder. This keeps the "primary comes back
  after cooldown" behavior the Milestone-1 spec asks for.

NXDOMAIN/NoAnswer: the oracle rule
----------------------------------
A lone NXDOMAIN or NoAnswer is NOT a health failure on its own — the
name might genuinely not exist, and demoting a resolver for
authoritatively answering "no such record" would poison the pool on
every absent-mailbox lookup.

But "this resolver said NXDOMAIN while a later resolver returned a
valid TXT for the same query" IS a health failure: the later
resolver's success is an oracle that proves the earlier one was
lying, stale, or censoring. So we buffer each not-found answer during
a query, and only apply failure marks *retroactively* if a
lower-priority resolver disproves them with a real answer. If every
resolver says not-found, nobody disproved anybody, and no demotions
happen — preserving the "true missing record" behavior.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional

import dns.exception
import dns.resolver

from dmp.network.base import DNSRecordReader


@dataclass
class _HostState:
    """Mutable health state for one upstream resolver."""

    host: str
    resolver: dns.resolver.Resolver
    consecutive_failures: int = 0
    last_failure_ts: float = 0.0
    last_success_ts: float = 0.0

    def record_success(self, now: float) -> None:
        self.consecutive_failures = 0
        self.last_success_ts = now

    def record_failure(self, now: float) -> None:
        self.consecutive_failures += 1
        self.last_failure_ts = now


class ResolverPool(DNSRecordReader):
    """A `DNSRecordReader` that fans a query across multiple upstreams.

    Tries each host in priority order (insertion order), returning the
    first `OK` answer. Hosts with recent failures are skipped until
    their cooldown elapses.

    Parameters
    ----------
    hosts:
        List of resolver IP literals (v4 or v6) to query, in priority
        order. Hostnames are NOT accepted — resolving them at startup
        would reintroduce the DNS-ordering problem the pool exists to
        solve. An empty list is rejected, as is any entry that is not
        a valid IP literal.
    port:
        UDP/TCP port for every upstream. Defaults to 53.
    timeout:
        Per-query socket timeout forwarded to `dns.resolver.Resolver`.
    lifetime:
        Total time `dns.resolver` may spend retrying a single query
        before raising `Timeout`.
    cooldown_seconds:
        How long a demoted host is skipped before being re-tried.
    failure_threshold:
        Number of consecutive failures before a host is considered
        "bad" and put into cooldown. `1` means fail-fast.
    """

    # Name-not-found answers describe the *queried name*, not the
    # resolver's health — in isolation. We defer the demotion decision
    # until the whole query completes: if a later, lower-priority
    # resolver returns a real answer for the same name, that serves as
    # an oracle proving each earlier not-found response was wrong, and
    # we retroactively demote those resolvers. If everyone agrees the
    # name is absent, nobody gets demoted (see module docstring).
    _NAME_NOT_FOUND_ERRORS = (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
    )

    # Transport-level faults: the resolver is unreachable, slow, or
    # otherwise misbehaving. These DO count against its health.
    #
    # We deliberately do NOT catch the base `dns.exception.DNSException`
    # here. That class is the parent of name-syntax errors like
    # `dns.name.LabelTooLong` and `dns.name.EmptyLabel`, which describe
    # a bug in the *caller's* query name, not resolver health. Swallowing
    # them would let one malformed lookup poison every upstream into
    # cooldown. Unexpected DNS exceptions propagate to the caller so the
    # bug surfaces rather than silently degrading the pool; if a new
    # exception turns out to be a real transport fault, we add it here
    # explicitly after observing it.
    _TRANSPORT_ERRORS = (
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        socket.timeout,
        OSError,
    )

    def __init__(
        self,
        hosts: List[str],
        port: int = 53,
        timeout: float = 5.0,
        lifetime: float = 10.0,
        cooldown_seconds: float = 60.0,
        failure_threshold: int = 1,
    ) -> None:
        if not hosts:
            raise ValueError("ResolverPool requires at least one host")
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")

        # `dns.resolver.Resolver.nameservers` accepts IP literals only.
        # Reject hostnames at construction time with a clear message
        # rather than failing later inside dnspython — and rather than
        # resolving them via the system stub, which would reintroduce
        # the DNS-ordering problem this pool exists to solve.
        for host in hosts:
            try:
                ipaddress.ip_address(host)
            except ValueError as exc:
                raise ValueError(
                    f"ResolverPool host {host!r} is not a valid IPv4 or "
                    f"IPv6 literal; hostnames are not accepted"
                ) from exc

        self._port = port
        self._cooldown_seconds = cooldown_seconds
        self._failure_threshold = failure_threshold
        self._lock = threading.Lock()

        self._states: List[_HostState] = []
        for host in hosts:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [host]
            resolver.port = port
            resolver.timeout = timeout
            resolver.lifetime = lifetime
            self._states.append(_HostState(host=host, resolver=resolver))

    # ---------------------------------------------------------------
    # DNSRecordReader contract
    # ---------------------------------------------------------------

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        """Query `name` across all healthy upstreams in priority order.

        Returns the first non-empty TXT answer. If every upstream
        fails (or is in cooldown and all cooldowns have not yet
        elapsed), returns None.

        Demotion uses a later-resolver oracle: NXDOMAIN/NoAnswer from
        an earlier resolver is a health failure *only if* a
        lower-priority resolver produces a real TXT answer for the
        same query. Otherwise the name is presumed genuinely absent
        and no health bookkeeping touches the not-found resolvers.
        """
        tried_not_found: List[_HostState] = []

        for state in self._iter_eligible():
            try:
                answers = state.resolver.resolve(name, "TXT")
            except self._NAME_NOT_FOUND_ERRORS:
                # Defer the health decision: if a later resolver
                # returns a real record, this one was wrong and we'll
                # demote it retroactively. If everyone agrees the name
                # is missing, we leave it alone.
                tried_not_found.append(state)
                continue
            except self._TRANSPORT_ERRORS:
                self._mark_failure(state)
                continue
            # Any other exception (e.g. `dns.name.LabelTooLong` from a
            # malformed query name, or a genuine caller-side bug)
            # propagates up. Blanket-catching here would let one bad
            # lookup demote every upstream into cooldown.

            records: List[str] = []
            for rdata in answers:
                # dnspython exposes each TXT rdata as a tuple of byte
                # strings; DNS itself concatenates them on the wire.
                records.append(
                    "".join(s.decode("utf-8", errors="replace") for s in rdata.strings)
                )

            if records:
                # Oracle fires: every earlier resolver that claimed
                # the name was absent just got disproven. Mark each
                # one unhealthy so subsequent queries skip them while
                # in cooldown.
                for lying_state in tried_not_found:
                    self._mark_failure(lying_state)
                self._mark_success(state)
                return records

            # Zero-length answer: treat like NoAnswer for this
            # resolver (it didn't disprove the earlier ones) and
            # continue looking. Its own health is unchanged.
            tried_not_found.append(state)
            continue

        # Every resolver either returned not-found or a transport
        # error. The not-found resolvers stay un-demoted — nothing
        # oracled them.
        return None

    # ---------------------------------------------------------------
    # Introspection helpers (not part of DNSRecordReader)
    # ---------------------------------------------------------------

    def healthy_hosts(self) -> List[str]:
        """Return the subset of hosts currently eligible for queries."""
        now = time.monotonic()
        with self._lock:
            return [s.host for s in self._states if self._is_eligible(s, now)]

    def snapshot(self) -> List[dict]:
        """Return a copy of per-host health for debugging / CLI display."""
        with self._lock:
            return [
                {
                    "host": s.host,
                    "consecutive_failures": s.consecutive_failures,
                    "last_failure_ts": s.last_failure_ts,
                    "last_success_ts": s.last_success_ts,
                }
                for s in self._states
            ]

    # ---------------------------------------------------------------
    # Internals
    # ---------------------------------------------------------------

    def _iter_eligible(self):
        """Yield host states whose cooldown has elapsed, primary first.

        We hold the lock only to snapshot the state list, not while
        the network I/O happens — otherwise one slow resolver would
        serialize every query.
        """
        now = time.monotonic()
        with self._lock:
            eligible = [s for s in self._states if self._is_eligible(s, now)]
        for state in eligible:
            yield state

    def _is_eligible(self, state: _HostState, now: float) -> bool:
        if state.consecutive_failures < self._failure_threshold:
            return True
        return (now - state.last_failure_ts) >= self._cooldown_seconds

    def _mark_success(self, state: _HostState) -> None:
        with self._lock:
            state.record_success(time.monotonic())

    def _mark_failure(self, state: _HostState) -> None:
        with self._lock:
            state.record_failure(time.monotonic())
