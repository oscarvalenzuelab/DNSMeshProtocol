#!/usr/bin/env python3
"""Directory aggregator for M5.8 heartbeats (DNS-native, post-M9).

Reads a list of seed zone names, queries ``_dnsmesh-heartbeat.<zone>``
and ``_dnsmesh-seen.<zone>`` for each over the public recursive DNS
chain, verifies every returned ``HeartbeatRecord``, and writes:

  - ``$OUT_DIR/feed.json`` — signed, deterministic JSON feed.
  - ``$OUT_DIR/index.html`` — static directory page with a node
    overview, geo + hosting metadata, a federation topology graph
    (heartbeat-discovery edges, NOT message traffic), and a public-
    resolver reachability matrix.

The aggregator is fully deterministic: same seeds + same upstream
state produces byte-identical outputs (modulo the
``generated_at`` timestamp). Anyone can run their own off the same
signed P2P data, so the project-hosted directory is one consumer,
not a trust anchor.

Typical deployment: cron or a CI workflow calls this every N
minutes, writes the output to a directory served by your static
hosting of choice (GitHub Pages, S3, nginx).

Usage:

  python examples/directory_aggregator.py \\
      --seed dmp.example.com \\
      --seed other.example.org \\
      --out-dir ./public

Run ``--help`` for the full argument list. Seeds may also be given
in legacy ``https://...`` form for back-compat with older
``directory/seeds.txt`` files; the host part is extracted as the
zone.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html import escape as html_escape
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

# Allow running from a checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dmp.core.heartbeat import HeartbeatRecord  # noqa: E402
from dmp.network.resolver_pool import ResolverPool  # noqa: E402
from dmp.server.heartbeat_worker import (  # noqa: E402
    heartbeat_rrset_name,
    seen_rrset_name,
)

log = logging.getLogger("dmp-directory-aggregator")


# Curated public resolvers for the reachability matrix. The set is
# picked for geographic + operator diversity, not "best resolvers"
# — the point is to show DMP records resolve through the public
# recursive chain regardless of where in the world the client is or
# which provider they trust. Any internet-connected resolver can do
# the same query; this list is illustrative, not exhaustive.
#
# Layout:
#   - Major US-anycast (Cloudflare, Google, Quad9, OpenDNS, Comodo,
#     Level3, Hurricane Electric, Verisign)
#   - Europe (Yandex, AdGuard)
#   - Asia (Alibaba, DNSPod / Tencent, KT Korea)
#
# Each entry is the canonical public IP. Resolver fleets are anycast,
# so the actual POP answering depends on where THIS aggregator is
# running — operators can re-render from a different VPS and watch
# the latency column shift accordingly. Level3 uses 4.2.2.1 rather
# than 4.2.2.2 — the former tracks delegation changes faster across
# their POP fleet (we observed 4.2.2.2 lagging by ~30 min on a
# delegation cleanup that 4.2.2.1 picked up immediately).
_RESOLVERS: List[Tuple[str, str]] = [
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
    ("Comodo", "8.26.56.26"),
    ("Level3", "4.2.2.1"),
    ("Hurricane Electric", "74.82.42.42"),
    ("Verisign", "64.6.64.6"),
    ("AdGuard", "94.140.14.14"),
    ("Yandex", "77.88.8.8"),
    ("Alibaba", "223.5.5.5"),
    ("DNSPod", "119.29.29.29"),
    ("KT Korea", "168.126.63.1"),
]


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AggregatedNode:
    """One deduped, verified listing entry the HTML + JSON render
    against. Verified = signature-verified at aggregation time, but
    consumers of feed.json MUST re-verify the embedded wire."""

    operator_spk_hex: str
    endpoint: str
    version: str
    ts: int
    exp: int
    wire: str
    last_seen_via: List[str]
    geo: Optional[Dict] = None
    host: Optional[Dict] = None


@dataclass(frozen=True)
class ResolverCheck:
    """One (resolver, zone) reachability test result."""

    resolver_name: str
    resolver_addr: str
    zone: str
    endpoint: Optional[str]
    ok: bool
    latency_ms: Optional[int]
    detail: str


# ---------------------------------------------------------------------------


def _normalize_seed_to_zone(seed: str) -> Optional[str]:
    """Accept either a zone (``dmp.example.com``) or the legacy URL
    form (``https://dmp.example.com``) and return the canonical zone
    name. Returns None if the input doesn't look like either."""
    s = seed.strip()
    if not s:
        return None
    if "://" in s:
        host = urlparse(s).hostname
        return host.lower() if host else None
    return s.rstrip("/").lower()


def _fetch_zone_wires(reader: ResolverPool, zone: str) -> Iterable[Tuple[str, str]]:
    """Yield ``(source_label, wire)`` for each HeartbeatRecord
    reachable from ``zone``.

    Sources, in order:
      - ``"heartbeat"`` — the seed's own self-row at
        ``_dnsmesh-heartbeat.<zone>``.
      - ``"seen"`` — the seed's republished view of OTHER peers at
        ``_dnsmesh-seen.<zone>``.

    Reading both is what the pre-M9 ``GET /v1/nodes/seen`` HTTP
    endpoint did before the route was removed. Reading only the
    seen-graph drops the seed itself when it has heard no peers.
    Source labels let the caller distinguish self-rows (no
    federation edge) from peer-discovery wires (an edge from this
    seed to that peer).
    """
    for name_fn, source_label, public_label in (
        (heartbeat_rrset_name, "heartbeat", "_dnsmesh-heartbeat"),
        (seen_rrset_name, "seen", "_dnsmesh-seen"),
    ):
        try:
            name = name_fn(zone)
        except ValueError:
            log.info("invalid seed zone: %r", zone)
            continue
        try:
            values = reader.query_txt_record(name)
        except Exception as exc:
            log.info("DNS query for %s failed: %s", name, exc)
            continue
        if not values:
            log.info("no %s records at %s", public_label, name)
            continue
        for v in values:
            if isinstance(v, str):
                yield (source_label, v)


def _lookup_geo(host_or_ip: str, *, timeout: float = 5.0) -> Optional[Dict]:
    """Resolve ``host_or_ip`` to lat/lon/country/city + ISP/org/AS via
    ip-api.com (free, no auth, ~45 req/min from one IP). Returns
    ``None`` on any error so the caller can fall back to a no-geo
    rendering."""
    try:
        ip = (
            host_or_ip
            if _looks_like_ip(host_or_ip)
            else socket.gethostbyname(host_or_ip)
        )
    except (socket.gaierror, OSError) as exc:
        log.info("DNS resolution for geo lookup of %s failed: %s", host_or_ip, exc)
        return None
    fields = "status,country,countryCode,regionName,city,lat,lon,isp,org,as"
    url = f"http://ip-api.com/json/{ip}?fields={fields}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "dnsmesh-aggregator"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        log.info("ip-api.com lookup for %s failed: %s", ip, exc)
        return None
    if data.get("status") != "success":
        log.info("ip-api.com returned non-success for %s: %s", ip, data)
        return None
    return {
        "ip": ip,
        "country": data.get("country") or "",
        "country_code": data.get("countryCode") or "",
        "region": data.get("regionName") or "",
        "city": data.get("city") or "",
        "lat": float(data.get("lat") or 0.0),
        "lon": float(data.get("lon") or 0.0),
        "isp": data.get("isp") or "",
        "org": data.get("org") or "",
        "asn": data.get("as") or "",
    }


def _looks_like_ip(s: str) -> bool:
    """Crude IPv4 / IPv6 detector — good enough to skip the DNS
    resolution step for inputs that are already addresses."""
    try:
        socket.inet_aton(s)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, s)
        return True
    except OSError:
        pass
    return False


def _resolver_reachability(
    resolvers: List[Tuple[str, str]], zones: List[str]
) -> List[ResolverCheck]:
    """For each (resolver, zone) pair, query the resolver directly for
    ``_dnsmesh-heartbeat.<zone>`` and record success + latency. The
    matrix that comes out of this is the "any major resolver can
    reach the nodes" demonstration on the directory page."""
    results: List[ResolverCheck] = []
    for resolver_name, resolver_addr in resolvers:
        pool = ResolverPool([resolver_addr])
        for zone in zones:
            try:
                name = heartbeat_rrset_name(zone)
            except ValueError:
                continue
            t0 = time.monotonic()
            try:
                values = pool.query_txt_record(name)
                latency_ms = int((time.monotonic() - t0) * 1000)
            except Exception as exc:
                results.append(
                    ResolverCheck(
                        resolver_name=resolver_name,
                        resolver_addr=resolver_addr,
                        zone=zone,
                        endpoint=None,
                        ok=False,
                        latency_ms=None,
                        detail=f"error: {type(exc).__name__}",
                    )
                )
                continue
            if not values:
                results.append(
                    ResolverCheck(
                        resolver_name=resolver_name,
                        resolver_addr=resolver_addr,
                        zone=zone,
                        endpoint=None,
                        ok=False,
                        latency_ms=latency_ms,
                        detail="empty answer",
                    )
                )
                continue
            # Verify the first wire to confirm it's a valid heartbeat
            # (a resolver returning an arbitrary TXT value for the
            # name shouldn't count as "reachable"). Generous skew:
            # the caller already filters on freshness elsewhere.
            rec = None
            for w in values:
                if isinstance(w, str):
                    rec = HeartbeatRecord.parse_and_verify(w, ts_skew_seconds=10**9)
                    if rec is not None:
                        break
            if rec is None:
                results.append(
                    ResolverCheck(
                        resolver_name=resolver_name,
                        resolver_addr=resolver_addr,
                        zone=zone,
                        endpoint=None,
                        ok=False,
                        latency_ms=latency_ms,
                        detail="answer did not verify",
                    )
                )
                continue
            results.append(
                ResolverCheck(
                    resolver_name=resolver_name,
                    resolver_addr=resolver_addr,
                    zone=zone,
                    endpoint=rec.endpoint,
                    ok=True,
                    latency_ms=latency_ms,
                    detail="ok",
                )
            )
    return results


# ---------------------------------------------------------------------------


@dataclass
class AggregateResult:
    """Everything the renderers need: the verified node list, the
    federation discovery edges, and the resolver reachability
    matrix."""

    nodes: List[AggregatedNode]
    seen_edges: List[Dict] = field(default_factory=list)
    resolver_checks: List[ResolverCheck] = field(default_factory=list)


def aggregate(seeds: List[str], *, now: Optional[int] = None) -> AggregateResult:
    """Query seed zones via DNS, verify, union, enrich. Returns the
    full data set the JSON + HTML renderers consume."""
    now_i = int(now) if now is not None else int(time.time())
    # Map (operator_spk_hex, endpoint) -> AggregatedNode (keep the
    # newest-ts wire on dedupe).
    pool: Dict[Tuple[str, str], AggregatedNode] = {}
    seed_self_spk: Dict[str, str] = {}  # zone -> operator_spk_hex
    edges: Dict[Tuple[str, str], int] = {}  # (from_spk, to_spk) -> max ts

    # Public-resolver pool — Cloudflare + Google + Quad9. Used for
    # the main aggregation pass; the reachability matrix uses one
    # resolver per query.
    reader = ResolverPool(["1.1.1.1", "8.8.8.8", "9.9.9.9"])

    valid_seed_zones: List[str] = []
    for seed in seeds:
        zone = _normalize_seed_to_zone(seed)
        if zone is None:
            continue
        valid_seed_zones.append(zone)
        for source, wire in _fetch_zone_wires(reader, zone):
            record = HeartbeatRecord.parse_and_verify(wire, now=now_i)
            if record is None:
                continue
            spk_hex = bytes(record.operator_spk).hex()
            key = (spk_hex, record.endpoint)
            existing = pool.get(key)
            if existing is None:
                pool[key] = AggregatedNode(
                    operator_spk_hex=spk_hex,
                    endpoint=record.endpoint,
                    version=record.version,
                    ts=record.ts,
                    exp=record.exp,
                    wire=wire,
                    last_seen_via=[zone],
                )
            else:
                sources = list(existing.last_seen_via)
                if zone not in sources:
                    sources.append(zone)
                if record.ts > existing.ts:
                    pool[key] = AggregatedNode(
                        operator_spk_hex=spk_hex,
                        endpoint=record.endpoint,
                        version=record.version,
                        ts=record.ts,
                        exp=record.exp,
                        wire=wire,
                        last_seen_via=sources,
                    )
                else:
                    pool[key] = AggregatedNode(
                        operator_spk_hex=existing.operator_spk_hex,
                        endpoint=existing.endpoint,
                        version=existing.version,
                        ts=existing.ts,
                        exp=existing.exp,
                        wire=existing.wire,
                        last_seen_via=sources,
                    )
            # Source-aware bookkeeping.
            if source == "heartbeat":
                # _fetch_zone_wires yields heartbeat before seen, so
                # this fires first and lets us tag downstream `seen`
                # wires with the right "from" operator.
                seed_self_spk[zone] = spk_hex
            elif source == "seen":
                from_spk = seed_self_spk.get(zone)
                if from_spk and from_spk != spk_hex:
                    edges[(from_spk, spk_hex)] = max(
                        edges.get((from_spk, spk_hex), 0), int(record.ts)
                    )

    # Enrich each node with geo + host info.
    enriched: List[AggregatedNode] = []
    for n in sorted(pool.values(), key=lambda x: x.ts, reverse=True):
        host = urlparse(n.endpoint).hostname or n.endpoint
        geo = _lookup_geo(host)
        host_block = None
        if geo is not None:
            host_block = {
                "ip": geo.get("ip", ""),
                "isp": geo.get("isp", ""),
                "org": geo.get("org", ""),
                "asn": geo.get("asn", ""),
            }
        enriched.append(
            AggregatedNode(
                operator_spk_hex=n.operator_spk_hex,
                endpoint=n.endpoint,
                version=n.version,
                ts=n.ts,
                exp=n.exp,
                wire=n.wire,
                last_seen_via=n.last_seen_via,
                geo=geo,
                host=host_block,
            )
        )

    seen_edges = [
        {"from_spk": a, "to_spk": b, "last_seen_ts": ts}
        for (a, b), ts in sorted(edges.items())
    ]
    resolver_checks = _resolver_reachability(_RESOLVERS, valid_seed_zones)

    return AggregateResult(
        nodes=enriched,
        seen_edges=seen_edges,
        resolver_checks=resolver_checks,
    )


# ---------------------------------------------------------------------------
# Output — deterministic JSON + static HTML.
# ---------------------------------------------------------------------------


def emit_json(result: AggregateResult, out: Path, *, now: int) -> None:
    feed = {
        "version": 2,
        "generated_at": now,
        "node_count": len(result.nodes),
        "nodes": [
            {
                "operator_spk_hex": n.operator_spk_hex,
                "endpoint": n.endpoint,
                "version": n.version,
                "ts": n.ts,
                "exp": n.exp,
                "wire": n.wire,
                "last_seen_via": n.last_seen_via,
                "geo": n.geo,
                "host": n.host,
            }
            for n in result.nodes
        ],
        "seen_edges": result.seen_edges,
        "resolvers": [
            {
                "name": c.resolver_name,
                "addr": c.resolver_addr,
                "zone": c.zone,
                "endpoint": c.endpoint,
                "ok": c.ok,
                "latency_ms": c.latency_ms,
                "detail": c.detail,
            }
            for c in result.resolver_checks
        ],
    }
    out.write_text(json.dumps(feed, indent=2) + "\n")


# Jekyll front matter at the top — Just-the-Docs picks up `title` for the
# sidebar entry, `nav_order` controls position, `layout: default` wraps the
# generated content in the standard chrome (sidebar, header, footer).
# `permalink` keeps the URL at /directory/ regardless of how the source file
# is named so existing links don't break.
#
# All HTML class names are prefixed ``dir-`` to avoid colliding with
# Just-the-Docs's own classes — most painfully ``.label``, which the theme
# uses for its blue pill badges and which previously turned every
# ``Status / Version / Operator key / …`` row-label into a glaring blue
# button. Colors inherit from the parent theme via ``inherit`` /
# ``currentColor`` where possible so the directory page follows whatever
# color scheme the docs site is configured for (currently ``dark`` per
# ``docs/_config.yml``).
_HTML_TEMPLATE = """---
title: Directory
layout: default
nav_order: 8
permalink: /directory/
---
<style>
.dmp-directory h2 {{ margin: 1.6em 0 0.4em; font-size: 1.15em; }}
.dmp-directory h2 small {{ font-weight: normal; opacity: 0.75; margin-left: 0.5em; }}
.dmp-directory small {{ opacity: 0.75; }}
.dmp-directory .dir-cards {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 0.8em;
}}
.dmp-directory .dir-card {{
  border: 1px solid currentColor; border-color: rgba(127,127,127,0.3);
  border-radius: 6px; padding: 0.9em 1em;
}}
.dmp-directory .dir-card h3 {{ margin: 0 0 0.4em; font-size: 1em; }}
.dmp-directory .dir-row {{ display: flex; justify-content: space-between; gap: 1em; margin: 0.18em 0; font-size: 0.92em; }}
.dmp-directory .dir-row-label {{ opacity: 0.7; flex-shrink: 0; font-weight: normal; }}
.dmp-directory .dir-row-val {{ text-align: right; word-break: break-all; }}
.dmp-directory .dir-pill {{
  font-size: 0.8em; padding: 1px 8px; border-radius: 10px;
  border: 1px solid currentColor; display: inline-block;
}}
.dmp-directory .dir-pill.fresh {{ color: #3fb950; }}
.dmp-directory .dir-pill.stale {{ color: #d29922; }}
.dmp-directory .dir-pill.expired {{ color: #f85149; }}
.dmp-directory table {{
  border-collapse: collapse; width: 100%; margin-top: 0.6em;
  font-size: 0.92em;
}}
.dmp-directory th, .dmp-directory td {{
  border: 1px solid rgba(127,127,127,0.3);
  padding: 0.4em 0.7em; text-align: left;
}}
.dmp-directory th {{ font-weight: 600; }}
.dmp-directory td.dir-ok {{ color: #3fb950; }}
.dmp-directory td.dir-fail {{ color: #f85149; }}
.dmp-directory .dir-svg-wrap {{
  border: 1px solid rgba(127,127,127,0.3);
  border-radius: 6px; padding: 1em; margin-top: 0.4em;
  text-align: center; overflow-x: auto;
}}
.dmp-directory svg.dir-topology text {{ fill: currentColor; font: 11px ui-monospace, monospace; }}
.dmp-directory svg.dir-topology circle.dir-node {{ fill: transparent; stroke: currentColor; stroke-width: 2; opacity: 0.8; }}
.dmp-directory svg.dir-topology line {{ stroke: currentColor; stroke-width: 1.4; opacity: 0.55; }}
.dmp-directory svg.dir-topology .dir-svg-label {{ font: 11px system-ui, sans-serif; fill: currentColor; }}
.dmp-directory svg.dir-topology .dir-arrow {{ fill: currentColor; opacity: 0.7; }}
.dmp-directory .dir-section-note {{ font-size: 0.88em; opacity: 0.75; margin-top: 0.3em; }}
</style>

<div class="dmp-directory">

<p>
  <small>Generated {generated} · {node_count} known nodes ·
  <a href="feed.json">feed.json</a> carries the raw signed wires
  for independent re-verification.</small>
</p>

<h2>Federation topology <small>· heartbeat-discovery, not message traffic</small></h2>
<div class="dir-svg-wrap">
{topology_svg}
</div>
<p class="dir-section-note">
  An arrow from A → B means A's seen-graph
  (<code>_dnsmesh-seen.&lt;A-zone&gt;</code>) carries a verified
  heartbeat from B. This is the federation discovery view —
  who has heard from whom over the public DNS chain. Message
  traffic is private (E2E encrypted) and is NOT shown here.
</p>

<h2>Public-resolver reachability <small>· can major resolvers find these nodes?</small></h2>
{resolver_table}
<p class="dir-section-note">
  Tested at build time from a GitHub Actions runner: each row is a
  curated public DNS resolver, each column is a node. A green cell
  means the resolver answered <code>_dnsmesh-heartbeat.&lt;zone&gt;</code>
  with a wire that verifies under Ed25519. Your client can do the
  same lookup with the same result. The list is illustrative — every
  internet-connected DNS resolver can perform the same query.
</p>

<h2>Known nodes <small>· geo + hosting</small></h2>
<div class="dir-cards">
{node_cards}
</div>
<p class="dir-section-note">
  Geo and ASN data via ip-api.com lookup at build time. Each node is
  the same self-signed <code>HeartbeatRecord</code> wire that lives at
  <code>_dnsmesh-heartbeat.&lt;zone&gt;</code> on the public DNS
  chain — the geo block is descriptive metadata for humans and is
  NOT signed.
</p>

</div>
"""


def emit_html(result: AggregateResult, out: Path, *, now: int) -> None:
    out.write_text(
        _HTML_TEMPLATE.format(
            generated=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now)),
            node_count=len(result.nodes),
            node_cards=_render_node_cards(result.nodes, now=now),
            topology_svg=_render_topology_svg(result.nodes, result.seen_edges, now=now),
            resolver_table=_render_resolver_table(result.nodes, result.resolver_checks),
        )
    )


def _format_age(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _liveness_pill(age_seconds: int, exp: int, now: int) -> Tuple[str, str]:
    if exp <= now:
        return ("expired", "expired")
    if age_seconds < 600:  # < 10 min
        return ("fresh", _format_age(age_seconds))
    if age_seconds < 3600:  # < 1 h
        return ("stale", _format_age(age_seconds))
    return ("stale", _format_age(age_seconds))


def _render_node_cards(nodes: List[AggregatedNode], *, now: int) -> str:
    if not nodes:
        return '<div class="dir-card"><em>(no nodes seen)</em></div>'
    out: List[str] = []
    for n in nodes:
        age = now - n.ts
        cls, label = _liveness_pill(age, n.exp, now)
        spk_short = n.operator_spk_hex[:8] + "…" + n.operator_spk_hex[-4:]
        host_text = ""
        if n.host:
            # Just the short org / ISP name. The ASN block (e.g.
            # "AS24940 Hetzner Online GmbH") was visually noisy and
            # didn't add information beyond the short name. Operators
            # who want the full ASN can pull it from feed.json.
            host_text = html_escape(n.host.get("org") or n.host.get("isp") or "")
        geo_text = ""
        if n.geo:
            parts = [
                n.geo.get("city") or "",
                n.geo.get("region") or "",
                n.geo.get("country") or "",
            ]
            geo_text = ", ".join(p for p in parts if p)
        endpoint_safe = html_escape(n.endpoint)
        out.append(f"""<div class="dir-card">
<h3><a href="{endpoint_safe}">{endpoint_safe}</a></h3>
<div class="dir-row"><span class="dir-row-label">Status</span><span class="dir-row-val"><span class="dir-pill {cls}">{html_escape(label)}</span></span></div>
<div class="dir-row"><span class="dir-row-label">Version</span><span class="dir-row-val">{html_escape(n.version or '?')}</span></div>
<div class="dir-row"><span class="dir-row-label">Operator key</span><span class="dir-row-val"><code>{html_escape(spk_short)}</code></span></div>
<div class="dir-row"><span class="dir-row-label">Hosting</span><span class="dir-row-val">{host_text or '<em>—</em>'}</span></div>
<div class="dir-row"><span class="dir-row-label">Region</span><span class="dir-row-val">{html_escape(geo_text) or '<em>—</em>'}</span></div>
<div class="dir-row"><span class="dir-row-label">IP</span><span class="dir-row-val"><code>{html_escape((n.host or dict()).get('ip', '') or '—')}</code></span></div>
<div class="dir-row"><span class="dir-row-label">Heard via</span><span class="dir-row-val">{', '.join(html_escape(z) for z in n.last_seen_via) or '—'}</span></div>
</div>""")
    return "\n".join(out)


def _render_topology_svg(
    nodes: List[AggregatedNode], edges: List[Dict], *, now: int
) -> str:
    """A small SVG with one circle per node and arrows for the
    seen-graph edges. Layout: nodes on a horizontal line; edges
    drawn as curved arrows so bidirectional pairs don't overlap.

    Kept deliberately simple — for >6 nodes the layout will get
    cramped, but for the current 2-3-node federation it reads
    cleanly. A force-directed layout with d3 is an option if/when
    the federation grows past that scale.
    """
    if not nodes:
        return "<em>(no nodes to plot)</em>"
    width = 720
    height = max(220, 120 + 70 * (len(nodes) // 3))
    margin_x = 90
    spacing = (width - 2 * margin_x) / max(1, len(nodes) - 1) if len(nodes) > 1 else 0
    # Place nodes left-to-right, alternating slight y-offset so labels
    # don't collide.
    coords: Dict[str, Tuple[int, int]] = {}
    parts: List[str] = [
        f'<svg class="dir-topology" width="{width}" height="{height}" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">'
    ]
    parts.append(
        '<defs><marker id="arrowhead" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" class="dir-arrow"/></marker></defs>'
    )
    for i, n in enumerate(nodes):
        x = int(margin_x + i * spacing) if len(nodes) > 1 else width // 2
        y = height // 2 + (-25 if i % 2 == 0 else 25)
        coords[n.operator_spk_hex] = (x, y)
    # Edges first (so circles render on top).
    for e in edges:
        a = coords.get(e["from_spk"])
        b = coords.get(e["to_spk"])
        if a is None or b is None:
            continue
        # Slight curve so reverse edges don't overlap.
        ctrl_y_offset = 30 if a[0] < b[0] else -30
        cx = (a[0] + b[0]) // 2
        cy = (a[1] + b[1]) // 2 + ctrl_y_offset
        parts.append(
            f'<path d="M {a[0]} {a[1]} Q {cx} {cy} {b[0]} {b[1]}" '
            f'fill="none" stroke="currentColor" stroke-width="1.4" '
            f'opacity="0.55" marker-end="url(#arrowhead)"/>'
        )
    # Node circles + labels.
    for n in nodes:
        x, y = coords[n.operator_spk_hex]
        host = urlparse(n.endpoint).hostname or n.endpoint
        country = (n.geo or {}).get("country_code") or ""
        parts.append(
            f'<circle class="dir-node" cx="{x}" cy="{y}" r="22"/>'
            f'<text class="dir-svg-label" x="{x}" y="{y + 4}" text-anchor="middle" '
            f'font-size="11">{html_escape((country or "?"))}</text>'
            f'<text class="dir-svg-label" x="{x}" y="{y + 42}" text-anchor="middle" '
            f'font-size="11">{html_escape(host)}</text>'
            f'<text class="dir-svg-label" x="{x}" y="{y + 56}" text-anchor="middle" '
            f'font-size="10" opacity="0.7">{html_escape(n.version or "")}</text>'
        )
    parts.append("</svg>")
    return "".join(parts)


def _render_resolver_table(
    nodes: List[AggregatedNode], checks: List[ResolverCheck]
) -> str:
    if not checks:
        return "<p><em>(no reachability checks recorded)</em></p>"
    # Group checks by resolver, then by zone — output rows = resolver,
    # cols = each known zone (one per node).
    zones = sorted({c.zone for c in checks})
    by_key: Dict[Tuple[str, str], ResolverCheck] = {
        (c.resolver_name, c.zone): c for c in checks
    }
    resolver_names: List[Tuple[str, str]] = []
    seen_resolver_keys = set()
    for c in checks:
        key = (c.resolver_name, c.resolver_addr)
        if key not in seen_resolver_keys:
            resolver_names.append(key)
            seen_resolver_keys.add(key)
    parts: List[str] = ["<table><thead><tr><th>Resolver</th>"]
    for z in zones:
        parts.append(f"<th>{html_escape(z)}</th>")
    parts.append("</tr></thead><tbody>")
    for r_name, r_addr in resolver_names:
        parts.append(
            f"<tr><td><strong>{html_escape(r_name)}</strong> "
            f"<small><code>{html_escape(r_addr)}</code></small></td>"
        )
        for z in zones:
            c = by_key.get((r_name, z))
            if c is None:
                parts.append("<td>—</td>")
                continue
            if c.ok:
                lat = f"{c.latency_ms} ms" if c.latency_ms is not None else ""
                parts.append(
                    f'<td class="dir-ok">✓ <small>{html_escape(lat)}</small></td>'
                )
            else:
                parts.append(
                    f'<td class="dir-fail">✗ <small>{html_escape(c.detail)}</small></td>'
                )
        parts.append("</tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument(
        "--seed",
        action="append",
        default=[],
        help="seed node DNS zone, e.g. ``dmp.example.com`` (repeatable). "
        "Each seed's ``_dnsmesh-seen.<zone>`` TXT RRset is queried; "
        "results are unioned and verified. Legacy ``https://...`` form "
        "also accepted for back-compat — the host is extracted.",
    )
    p.add_argument(
        "--seeds-file",
        type=Path,
        help="text file with one seed zone per line. Lines starting with "
        "'#' and blank lines are ignored. Stacks with --seed.",
    )
    p.add_argument(
        "--out-dir",
        type=Path,
        default=Path("./public"),
        help="directory to write feed.json + index.html to "
        "(default: ./public, created if missing).",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    args = p.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    seeds = list(args.seed)
    if args.seeds_file:
        for line in args.seeds_file.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            seeds.append(stripped)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    result = aggregate(seeds, now=now) if seeds else AggregateResult(nodes=[])
    emit_json(result, args.out_dir / "feed.json", now=now)
    emit_html(result, args.out_dir / "index.html", now=now)
    log.info(
        "wrote %d nodes from %d seeds to %s (edges: %d, resolver checks: %d)",
        len(result.nodes),
        len(seeds),
        args.out_dir,
        len(result.seen_edges),
        len(result.resolver_checks),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
