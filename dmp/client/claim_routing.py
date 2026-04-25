"""Claim provider selection from SeenStore-recency (M8.3).

The recipient's home node ships a federated view of the network in
the form of recently-heard heartbeats (M5.8 / `seen_store.py`).  This
module turns that view into a concrete list of claim providers the
sender or recipient should poll, using the model the user articulated
during M8 design: *proximity is recency-weighted gossip-reachability*,
not graph-shortest-path. A provider that has heartbeated recently
through this node's gossip fan-out is "near" us; a provider whose ts
has gone stale is "far."

The whole module is pure-data; it takes a list of heartbeat-record
JSON entries (typically the response payload from
``GET /v1/nodes/seen``) and returns a ranked list of provider URLs +
zones. It does not perform any HTTP itself — the caller fetches the
SeenStore feed and the caller publishes / polls. Keeping this layer
side-effect-free makes it straightforward to test against a fixture
JSON without standing up a real node.

Provider zone derivation
------------------------
A claim record's RRset name is ``claim-{slot}.mb-{hash12(recipient)}.
{provider_zone}`` — both the publisher (sender) and the resolver
(recipient) need ``provider_zone`` to compute the same name. We
derive it from the heartbeat's ``endpoint`` URL by stripping scheme
and port and using the bare hostname:

    https://dnsmesh.io          ->  dnsmesh.io
    https://node.example.com:8053 -> node.example.com

This is a convention, not a wire-format requirement: a provider
operator who serves claims under a different zone than their HTTP
host can override via a future ``provider_zone`` heartbeat field.
M8.2 deliberately keeps the heartbeat record at one varying field
to bound the wire-format surface; M8.3 inherits that and treats
``hostname == zone`` as the working assumption.

Override
--------
``select_providers`` accepts an explicit ``override`` URL. When set,
it bypasses the SeenStore ranking entirely and returns just that one
provider — the use case is the operator who wants to pin all claim
traffic through a specific node (typically ``https://dnsmesh.io``
as the public reference). Unset (the common path), the function
falls back to recency ranking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional, Sequence
from urllib.parse import urlsplit

from dmp.core.heartbeat import CAP_CLAIM_PROVIDER, HeartbeatRecord

log = logging.getLogger(__name__)

DEFAULT_K = 3


@dataclass(frozen=True)
class ClaimProvider:
    """A discovered claim-provider node.

    ``endpoint`` is the HTTP base URL (used for publishing claims).
    ``zone`` is the DNS zone the provider serves claim records under
    (used by the recipient to construct the DNS query name).
    ``operator_spk_hex`` is informational — useful for logging, not
    load-bearing for protocol correctness.
    ``ts`` is the heartbeat timestamp; higher = more recent.
    """

    endpoint: str
    zone: str
    operator_spk_hex: str
    ts: int


def _zone_from_endpoint(endpoint: str) -> Optional[str]:
    """Return the DNS zone implied by an HTTPS endpoint, or None.

    Convention: the bare hostname is the zone. IP literals are
    rejected (no plausible authoritative DNS zone). Localhost
    aliases are rejected (already filtered upstream by the
    heartbeat validator, but defense-in-depth).
    """
    try:
        parts = urlsplit(endpoint)
    except ValueError:
        return None
    host = (parts.hostname or "").strip().lower()
    if not host:
        return None
    # IP literal sanity. urllib parses bracketed v6, returning the
    # interior; v4 comes through verbatim. Either way a literal isn't
    # a usable claim zone.
    if host.replace(".", "").isdigit() or ":" in host:
        return None
    if host in ("localhost", "localhost.localdomain", "ip6-localhost"):
        return None
    return host


def parse_seen_feed(seen_wires: Sequence[str]) -> List[HeartbeatRecord]:
    """Parse a list of heartbeat wire strings, dropping invalid entries.

    Mirrors the verification policy ``HeartbeatRecord.parse_and_verify``
    enforces: signature must verify, ts must be within skew window,
    exp must be in the future. Anything that fails comes back as a
    silent omission, never as an exception — a malformed entry from
    one peer must not break the whole provider-selection pass.
    """
    out: List[HeartbeatRecord] = []
    for wire in seen_wires:
        try:
            rec = HeartbeatRecord.parse_and_verify(wire)
        except Exception:
            # parse_and_verify is documented as never-raising, but
            # belt-and-braces: a future bug should not break the
            # caller's receive loop.
            continue
        if rec is not None:
            out.append(rec)
    return out


def select_providers(
    heartbeats: Sequence[HeartbeatRecord],
    *,
    k: int = DEFAULT_K,
    override: Optional[str] = None,
    override_zone: Optional[str] = None,
) -> List[ClaimProvider]:
    """Rank claim-providers by recency, return top ``k`` (or override).

    When ``override`` is set, it takes precedence and ``heartbeats``
    is ignored. The override is returned as a single ``ClaimProvider``
    with zone derived from the URL (or ``override_zone`` if explicitly
    given — useful when the override URL's host doesn't match the
    served zone).

    Otherwise, filter heartbeats to those that:

      - advertise ``CAP_CLAIM_PROVIDER``,
      - have a derivable DNS zone (via ``_zone_from_endpoint``),
      - have an ``operator_spk`` we haven't already counted (dedup
        — a single operator can heartbeat from multiple endpoints).

    Sort descending by ``ts`` (most recent first), take the top ``k``.
    The order is stable across calls with the same input, so a
    sender and a recipient who fetch the same SeenStore snapshot
    pick the same providers — that's the load-bearing property
    behind first-message reach without anti-entropy gossip (M8.4
    reduces residual mismatch when the snapshots diverge).
    """
    if k <= 0:
        return []

    if override:
        zone = override_zone or _zone_from_endpoint(override)
        if not zone:
            log.warning(
                "claim-provider override %r has no derivable zone; ignoring",
                override,
            )
            return []
        return [
            ClaimProvider(
                endpoint=override,
                zone=zone,
                operator_spk_hex="",
                ts=0,
            )
        ]

    # Codex P2 round 7 fix: sort by ts BEFORE deduplicating by
    # operator. Otherwise an older heartbeat earlier in the input
    # marks the operator "seen" first, locking us onto its stale
    # endpoint even when a fresher heartbeat for the same operator
    # appears later. Build full candidate list first, sort
    # descending by ts, then dedupe — the highest-ts entry wins.
    raw: List[ClaimProvider] = []
    for hb in heartbeats:
        if not (hb.capabilities & CAP_CLAIM_PROVIDER):
            continue
        zone = _zone_from_endpoint(hb.endpoint)
        # IP-literal endpoints don't expose a DNS zone via host
        # derivation, but the caller's /v1/info upgrade pass can
        # still discover the served zone. Keep with zone="".
        if zone is None:
            zone = ""
        raw.append(
            ClaimProvider(
                endpoint=hb.endpoint,
                zone=zone,
                operator_spk_hex=bytes(hb.operator_spk).hex(),
                ts=int(hb.ts),
            )
        )

    raw.sort(key=lambda p: p.ts, reverse=True)
    candidates: List[ClaimProvider] = []
    seen_operators: set = set()
    for p in raw:
        if p.operator_spk_hex in seen_operators:
            continue
        seen_operators.add(p.operator_spk_hex)
        candidates.append(p)
    return candidates[:k]
