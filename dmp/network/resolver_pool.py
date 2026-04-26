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
- A host with `consecutive_failures >= failure_threshold` is
  *deprioritized* while `now - last_failure_ts < cooldown_seconds` —
  it still gets tried, but only after every non-cooled-down host has
  been exhausted.
- Once the cooldown elapses, the host returns to its normal priority
  slot on the next query. A success zeroes its failure counter;
  another failure just refreshes the cooldown without stacking further.
- Cooldown is a *priority signal*, not a hard ban. If every resolver
  is cooled down (or the pool has only one host), the lookup still
  reaches them rather than blackholing for the full cooldown window.
  Fallback-tier order is "least recent failure first," on the theory
  that the resolver whose failure is oldest is most likely to have
  recovered.

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
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple, Union

# One entry in the `hosts=` argument to `ResolverPool`. Either a bare IP
# literal (inherits the pool-wide `port=` default) or an (ip, port) tuple
# that carries its own port. See `__init__` docstring for examples.
HostSpec = Union[str, Tuple[str, int]]

import dns.exception
import dns.resolver

from dmp.network.base import DNSRecordReader

log = logging.getLogger(__name__)


# Four operator-diverse public resolvers, IPv4 only. Discovery probes each
# one with a TXT lookup for a stable well-known name and keeps only the
# ones that answer quickly. Operator diversity is the point: if one
# provider is blocked or tampering, the others provide independent paths.
# IPv6 entries are deliberately excluded — many networks still lack
# IPv6 connectivity, and a silently unreachable v6 literal would burn
# the probe budget for no gain.
WELL_KNOWN_RESOLVERS: tuple[str, ...] = (
    "8.8.8.8",  # Google
    "8.8.4.4",  # Google
    "1.1.1.1",  # Cloudflare
    "1.0.0.1",  # Cloudflare
    "9.9.9.9",  # Quad9
    "149.112.112.112",  # Quad9
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",  # OpenDNS
)

# A query name with stable TXT records on every big public resolver. We
# don't care about the answer's content — just that the resolver
# responded without erroring or timing out.
_DISCOVER_PROBE_NAME = "google.com"


@dataclass
class _HostState:
    """Mutable health state for one upstream resolver.

    `host` + `port` together identify the upstream: a pool built with
    ``[("127.0.0.1", 5353), ("127.0.0.1", 5354)]`` produces two states
    sharing an IP, and anything that keys off `host` alone would conflate
    them. `snapshot()` surfaces both so debuggers / CLI output can
    disambiguate.
    """

    host: str
    port: int
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
        List of resolver upstreams in priority order. Each entry is
        either a bare IP literal (v4 or v6) that inherits the pool-wide
        ``port=`` default, or an ``(ip, port)`` tuple that carries its
        own port. The two shapes mix freely so callers can override the
        port for only some upstreams::

            # back-compat: all share the same port
            ResolverPool(["8.8.8.8", "1.1.1.1"])                       # port=53
            ResolverPool(["8.8.8.8", "1.1.1.1"], port=5353)

            # per-host ports
            ResolverPool([("8.8.8.8", 53), ("1.1.1.1", 5353)])

            # mixed: bare entry inherits the `port=` default
            ResolverPool(["8.8.8.8", ("1.1.1.1", 5353)], port=5300)
            # -> 8.8.8.8 uses 5300, 1.1.1.1 uses 5353

        Hostnames are NOT accepted (bare or inside a tuple) — resolving
        them at startup would reintroduce the DNS-ordering problem the
        pool exists to solve. An empty list is rejected, as is any
        entry that is not a valid IP literal.
    port:
        UDP/TCP port used for any bare-host entry in ``hosts``. Tuple
        entries override this per-upstream. Defaults to 53.
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
        hosts: Sequence[HostSpec],
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

        # Normalize every entry to `(ip, port)`. Bare strings inherit the
        # pool-wide `port=` default; tuples override it per-upstream.
        # `dns.resolver.Resolver.nameservers` accepts IP literals only,
        # so we reject hostnames at construction time (bare OR inside a
        # tuple) with a clear message rather than failing later inside
        # dnspython — and rather than resolving them via the system
        # stub, which would reintroduce the DNS-ordering problem this
        # pool exists to solve.
        normalized: List[Tuple[str, int]] = []
        for entry in hosts:
            host, host_port = self._normalize_entry(entry, port)
            normalized.append((host, host_port))

        self._port = port
        self._cooldown_seconds = cooldown_seconds
        self._failure_threshold = failure_threshold
        self._lock = threading.Lock()

        self._states: List[_HostState] = []
        for host, host_port in normalized:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [host]
            resolver.port = host_port
            resolver.timeout = timeout
            resolver.lifetime = lifetime
            self._states.append(
                _HostState(host=host, port=host_port, resolver=resolver)
            )

    @staticmethod
    def _normalize_entry(entry: HostSpec, default_port: int) -> Tuple[str, int]:
        """Validate and normalize one `hosts=` entry to `(ip, port)`.

        Accepts either a bare IP-literal string (inherits `default_port`)
        or a `(ip, port)` tuple. Anything else — hostname string, tuple
        of wrong arity, non-integer port, port out of range — raises
        ValueError with a user-facing message.
        """
        if isinstance(entry, tuple):
            if len(entry) != 2:
                raise ValueError(
                    f"ResolverPool host entry {entry!r} must be (ip, port); "
                    f"got a tuple of length {len(entry)}"
                )
            host, host_port = entry
            if not isinstance(host, str):
                raise ValueError(
                    f"ResolverPool host entry {entry!r}: first element must "
                    f"be a string IP literal"
                )
            # bool is a subclass of int — reject it explicitly so
            # `(ip, True)` doesn't silently become port 1.
            if not isinstance(host_port, int) or isinstance(host_port, bool):
                raise ValueError(
                    f"ResolverPool host entry {entry!r}: port must be an int"
                )
            if not 1 <= host_port <= 65535:
                raise ValueError(
                    f"ResolverPool host entry {entry!r}: port {host_port} "
                    f"out of range (1-65535)"
                )
        elif isinstance(entry, str):
            host = entry
            host_port = default_port
        else:
            raise ValueError(
                f"ResolverPool host entry {entry!r} must be a string IP "
                f"literal or an (ip, port) tuple"
            )

        try:
            ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError(
                f"ResolverPool host {host!r} is not a valid IPv4 or "
                f"IPv6 literal; hostnames are not accepted"
            ) from exc

        return host, host_port

    # ---------------------------------------------------------------
    # DNSRecordReader contract
    # ---------------------------------------------------------------

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        """Query `name` across all upstreams in two-tier priority order.

        Returns the first non-empty TXT answer. Tries preferred
        (not-cooled-down) resolvers first; if every one returns
        not-found or errors, falls through to the cooled-down fallback
        tier rather than blackholing. Returns None only if *every*
        resolver — preferred and fallback combined — fails to produce
        records.

        Demotion uses a later-resolver oracle: NXDOMAIN/NoAnswer from
        an earlier resolver is a health failure *only if* a later
        resolver produces a real TXT answer for the same query.
        Otherwise the name is presumed genuinely absent and no health
        bookkeeping touches the not-found resolvers.

        A genuine not-found answer (one that nobody later oracle-
        demotes) is itself a healthy response — the resolver
        successfully served authoritative "no such record" data. So
        when we reach the end of the pool with every resolver agreeing
        the name is absent, we reset the streak for each not-found
        resolver the same way a successful TXT hit would. Otherwise,
        with `failure_threshold > 1`, a prior transport timeout would
        silently persist across healthy NXDOMAIN answers, and the next
        unrelated timeout would count as the "second consecutive"
        failure and demote a resolver that had been serving correctly
        in between.
        """
        tried_not_found: List[_HostState] = []

        for state in self._iter_ordered():
            try:
                answers = state.resolver.resolve(name, "TXT")
            except self._NAME_NOT_FOUND_ERRORS:
                # Defer the health decision: if a later resolver
                # returns a real record, this one was wrong and we'll
                # demote it retroactively. If everyone agrees the name
                # is missing, we treat it as a healthy "no such record"
                # answer and reset the streak below.
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
            # continue looking. Its own health is unchanged for now;
            # if no later resolver oracles it, the not-found reset
            # below covers it.
            tried_not_found.append(state)
            continue

        # Every resolver either returned not-found or a transport
        # error, and no oracle fired. Not-found resolvers served a
        # legitimate "no such record" response, which IS a healthy
        # answer — reset their streaks so a stale earlier transport
        # failure doesn't combine with a future one into a spurious
        # "consecutive" demotion. Transport-error resolvers already
        # got `_mark_failure` above.
        for healthy_state in tried_not_found:
            self._mark_success(healthy_state)
        return None

    def resolve_address(self, host: str) -> Optional[str]:
        """Resolve ``host`` to an IPv4 (preferred) or IPv6 literal.

        Used by the DNS UPDATE writer to find a usable destination IP
        for dnspython without falling back to the host's system
        resolver. The pool already knows which upstreams the operator
        trusts (via ``DMP_HEARTBEAT_DNS_RESOLVERS``); routing the A /
        AAAA lookup through them keeps writes consistent with reads
        during a delegation move (system resolver may still hold a
        stale NXDOMAIN while the pinned recursors have refreshed).

        Tries A first, then AAAA. Returns ``None`` if no upstream
        produces an answer for either rdtype.

        Health bookkeeping is intentionally lighter than
        ``query_txt_record``: a transport error demotes the resolver,
        but NXDOMAIN does not (we'd need an oracle, which we don't
        have for a single A/AAAA lookup).
        """
        for rdtype in ("A", "AAAA"):
            for state in self._iter_ordered():
                try:
                    answers = state.resolver.resolve(host, rdtype)
                except self._NAME_NOT_FOUND_ERRORS:
                    continue
                except self._TRANSPORT_ERRORS:
                    self._mark_failure(state)
                    continue
                for rdata in answers:
                    self._mark_success(state)
                    addr = getattr(rdata, "address", None)
                    if addr:
                        return str(addr)
        return None

    # ---------------------------------------------------------------
    # Introspection helpers (not part of DNSRecordReader)
    # ---------------------------------------------------------------

    def healthy_hosts(self) -> List[str]:
        """Return the hosts (IP literals) currently in the preferred tier.

        Returns bare host strings, not `(ip, port)` tuples — this keeps
        back-compat with callers that key off IPs for display. For a
        port-aware view (two states sharing one IP on different ports
        would collapse in the string list), use `healthy_upstreams()`.

        "Preferred tier" matches "the ones we'd pick first if we had a
        choice." A cooled-down host is *still reachable* via the
        fallback tier (see `_iter_ordered`), but it is not "healthy" in
        the sense reported here — the pool would rather route around it
        if any other host can answer.
        """
        now = time.monotonic()
        with self._lock:
            return [s.host for s in self._states if self._is_preferred(s, now)]

    def healthy_upstreams(self) -> List[Tuple[str, int]]:
        """Port-aware variant of `healthy_hosts()`.

        Returns `(ip, port)` tuples so callers keying off the full
        upstream identity can distinguish e.g. two loopback resolvers
        on different ports. Same preferred-tier semantics as
        `healthy_hosts()`.
        """
        now = time.monotonic()
        with self._lock:
            return [
                (s.host, s.port) for s in self._states if self._is_preferred(s, now)
            ]

    def snapshot(self) -> List[dict]:
        """Return a copy of per-host health for debugging / CLI display.

        The `"port"` field (added in M1.5) disambiguates two states
        sharing a host IP; callers that only ever read `"host"`
        continue to work unchanged.
        """
        with self._lock:
            return [
                {
                    "host": s.host,
                    "port": s.port,
                    "consecutive_failures": s.consecutive_failures,
                    "last_failure_ts": s.last_failure_ts,
                    "last_success_ts": s.last_success_ts,
                }
                for s in self._states
            ]

    # ---------------------------------------------------------------
    # Internals
    # ---------------------------------------------------------------

    def _iter_ordered(self):
        """Yield host states in priority order: preferred tier, then fallback.

        Preferred tier = resolvers not currently in cooldown, in
        configured priority (insertion) order.

        Fallback tier = resolvers currently in cooldown, ordered by
        `last_failure_ts` ascending so the one that failed longest ago
        is tried first (most likely to have recovered). The pool falls
        through to this tier only after every preferred resolver
        returned not-found or errored — cooldown is a deprioritization
        signal, not a hard ban, so we never blackhole a lookup when
        every host happens to be cooling down.

        We hold the lock only to snapshot the state list, not while
        the network I/O happens — otherwise one slow resolver would
        serialize every query.
        """
        now = time.monotonic()
        with self._lock:
            preferred: List[_HostState] = []
            fallback: List[_HostState] = []
            for state in self._states:
                if self._is_preferred(state, now):
                    preferred.append(state)
                else:
                    fallback.append(state)
            # Oldest failure first: that resolver has had the most time
            # to recover, so it's the most promising of the cooled-down
            # set.
            fallback.sort(key=lambda s: s.last_failure_ts)
        for state in preferred:
            yield state
        for state in fallback:
            yield state

    def _is_preferred(self, state: _HostState, now: float) -> bool:
        """True iff `state` is in the preferred tier (not cooled down)."""
        if state.consecutive_failures < self._failure_threshold:
            return True
        return (now - state.last_failure_ts) >= self._cooldown_seconds

    def _mark_success(self, state: _HostState) -> None:
        with self._lock:
            state.record_success(time.monotonic())

    def _mark_failure(self, state: _HostState) -> None:
        with self._lock:
            state.record_failure(time.monotonic())

    # ---------------------------------------------------------------
    # Discovery
    # ---------------------------------------------------------------

    @classmethod
    def discover(
        cls,
        candidates: Iterable[str],
        timeout: float = 2.0,
    ) -> "ResolverPool":
        """Probe `candidates` and return a pool of the ones that answered.

        Each candidate is asked for the TXT records of a well-known
        name (`google.com` by default — it has stable TXT records on
        every big public resolver). A candidate that returns without
        erroring within `timeout` seconds is considered working.

        Candidates that are not IPv4/IPv6 literals are skipped with a
        logged warning rather than rejecting the whole batch; callers
        commonly pass mixed-provenance lists (CLI flag, config file,
        `WELL_KNOWN_RESOLVERS` hardcoded list) and one typo shouldn't
        abort discovery entirely.

        Raises `ValueError` if zero candidates pass (either because
        none were valid IP literals, or every probe failed). An empty
        pool would construct successfully only to fail every future
        query — callers would much rather see the failure now, at the
        discovery boundary, than silently at first use.
        """
        # `dict.fromkeys` preserves order while deduplicating — keeping
        # the caller's implied priority and skipping wasted probes if
        # the same host appears twice.
        valid_hosts: List[str] = []
        for candidate in dict.fromkeys(candidates):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                log.warning(
                    "ResolverPool.discover: skipping %r (not a valid IPv4 "
                    "or IPv6 literal)",
                    candidate,
                )
                continue
            valid_hosts.append(candidate)

        working: List[str] = []
        for host in valid_hosts:
            probe = dns.resolver.Resolver(configure=False)
            probe.nameservers = [host]
            probe.timeout = timeout
            # lifetime bounds the total wall-clock budget dnspython will
            # spend retrying before giving up; match it to `timeout` so a
            # slow resolver can't stretch discovery well past the caller's
            # expected window.
            probe.lifetime = timeout
            try:
                probe.resolve(_DISCOVER_PROBE_NAME, "TXT")
            except cls._TRANSPORT_ERRORS:
                # Resolver is unreachable, too slow, or otherwise
                # misbehaving — drop it from the pool.
                continue
            except dns.resolver.NoAnswer:
                # NoAnswer means "the name exists, but not for this
                # rdtype" — for a probe against `google.com` TXT, the
                # probe name is precisely chosen to have stable TXT
                # records on every major public resolver. A NoAnswer
                # here means this resolver is stripping or filtering
                # TXT answers (policy filter, captive-portal rewriter,
                # buggy middlebox). Every DMP read through that
                # resolver would come back empty, so reject it.
                continue
            except dns.resolver.NXDOMAIN:
                # A resolver that authoritatively says "no such record"
                # for `google.com` is a weird split-horizon / lying
                # case, but it IS still responding healthily to DNS —
                # we keep it in the pool so the normal query path's
                # oracle-demotion logic can catch real misbehavior
                # against the *actual* DMP query surface in production.
                # NoAnswer above is stricter because it's a clean
                # "wouldn't serve TXT" signal.
                pass
            except dns.exception.DNSException:
                # Any other dnspython error (malformed response,
                # unexpected EDNS failure, etc.) means this resolver
                # isn't giving us clean answers — skip it.
                continue
            working.append(host)

        if not working:
            raise ValueError(
                "ResolverPool.discover: no candidates answered within "
                f"{timeout}s (of {len(valid_hosts)} valid IP literals out "
                f"of the batch)"
            )
        return cls(working)
