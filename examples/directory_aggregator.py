#!/usr/bin/env python3
"""Simple directory aggregator for M5.8 heartbeats (DNS-native, post-M9).

Reads a list of seed zone names, queries ``_dnsmesh-seen.<zone>``
for each over the public recursive DNS chain, verifies every
returned HeartbeatRecord, unions them by (operator_spk, endpoint),
and emits:

  - A signed JSON feed at ``$OUT_DIR/feed.json``.
  - A static HTML index at ``$OUT_DIR/index.html`` grouping nodes by
    last-seen age.

The aggregator is fully deterministic — same seeds + same input
wires produces byte-identical outputs. Anyone can run one off the
same signed P2P data, so the operator-hosted central directory is
one consumer, not a trust anchor.

This used to fetch ``GET /v1/nodes/seen`` over HTTPS; M9 (0.5.0)
removed that route and moved the seen-graph onto the DNS side at
``_dnsmesh-seen.<zone>`` (multi-value TXT, each value a signed
HeartbeatRecord wire). This script is the matching DNS-native
consumer.

Typical deployment: cron or systemd timer calls this every N
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
import sys
import time
from dataclasses import dataclass
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


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AggregatedNode:
    """One deduped, verified listing entry the HTML + JSON render
    against. Verified = signature-verified at aggregation time,
    but consumers of feed.json MUST re-verify the embedded wire."""

    operator_spk_hex: str
    endpoint: str
    version: str
    ts: int
    exp: int
    wire: str
    last_seen_via: List[str]  # source nodes that reported this entry


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
    # Strip a trailing slash if someone wrote `dmp.example.com/`.
    return s.rstrip("/").lower()


def _fetch_zone_wires(reader: ResolverPool, zone: str) -> Iterable[str]:
    """Yield every HeartbeatRecord wire reachable from ``zone`` —
    BOTH the seed's own self-row at ``_dnsmesh-heartbeat.<zone>``
    AND the seed's republished seen-graph at
    ``_dnsmesh-seen.<zone>``.

    Why both: the seen-graph republishes only OTHER peers the seed
    has heard from. A healthy single-node seed (or a seed during a
    partition where it hears nobody) leaves the seen RRset empty,
    so reading only that path silently drops the seed itself from
    the directory. The heartbeat RRset is where the seed publishes
    its own self-signed wire on every tick. Reading both is what
    the old HTTP ``/v1/nodes/seen`` endpoint did before M9 removed
    it.
    """
    for name_fn, label in (
        (heartbeat_rrset_name, "_dnsmesh-heartbeat"),
        (seen_rrset_name, "_dnsmesh-seen"),
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
            log.info("no %s records at %s", label, name)
            continue
        for v in values:
            if isinstance(v, str):
                yield v


def aggregate(seeds: List[str], *, now: Optional[int] = None) -> List[AggregatedNode]:
    """Query seed zones via DNS, verify, union. Returns the deduped
    node list."""
    now_i = int(now) if now is not None else int(time.time())
    # Map (operator_spk_hex, endpoint) -> AggregatedNode (keep the
    # newest-ts wire on dedupe).
    pool: Dict[Tuple[str, str], AggregatedNode] = {}

    # Public-resolver pool — Cloudflare + Google + Quad9. The
    # aggregator queries _dnsmesh-seen.<seed-zone> over the public
    # recursive chain; using a multi-upstream pool means a flaky
    # resolver doesn't take down a refresh cycle.
    reader = ResolverPool(["1.1.1.1", "8.8.8.8", "9.9.9.9"])

    for seed in seeds:
        zone = _normalize_seed_to_zone(seed)
        if zone is None:
            continue
        for wire in _fetch_zone_wires(reader, zone):
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
                # If this source reports a NEWER ts for the same
                # node, take the newer wire. Always record the
                # source seed so the HTML can show "heard via N
                # sources".
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

    return sorted(pool.values(), key=lambda n: n.ts, reverse=True)


# ---------------------------------------------------------------------------
# Output — deterministic JSON + static HTML.
# ---------------------------------------------------------------------------


def emit_json(nodes: List[AggregatedNode], out: Path, *, now: int) -> None:
    feed = {
        "version": 1,
        "generated_at": now,
        "node_count": len(nodes),
        "nodes": [
            {
                "operator_spk_hex": n.operator_spk_hex,
                "endpoint": n.endpoint,
                "version": n.version,
                "ts": n.ts,
                "exp": n.exp,
                "wire": n.wire,
                "last_seen_via": n.last_seen_via,
            }
            for n in nodes
        ],
    }
    out.write_text(json.dumps(feed, indent=2) + "\n")


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DMP node directory</title>
<style>
body {{ font: 14px/1.5 system-ui, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
th, td {{ border: 1px solid #ccc; padding: 0.4em 0.6em; text-align: left; }}
th {{ background: #f5f5f5; }}
td.fresh {{ color: #0a0; }}
td.stale {{ color: #a60; }}
small {{ color: #666; }}
</style>
</head>
<body>
<h1>DMP node directory</h1>
<p>
  <small>Generated {generated} · {count} nodes heard in the last 72h.
  Every row is a signed HeartbeatRecord; <a href="feed.json">feed.json</a>
  carries the raw wire strings so consumers can re-verify independently.</small>
</p>
<table>
<thead>
<tr>
  <th>Endpoint</th>
  <th>Operator pubkey</th>
  <th>Version</th>
  <th>Last heard</th>
  <th>Sources</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"""


def emit_html(nodes: List[AggregatedNode], out: Path, *, now: int) -> None:
    def _row(n: AggregatedNode) -> str:
        age = now - n.ts
        cls = "fresh" if age < 3600 else "stale"
        age_str = (
            f"{age}s ago"
            if age < 60
            else f"{age // 60}m ago" if age < 3600 else f"{age // 3600}h ago"
        )
        spk_short = n.operator_spk_hex[:8] + "…" + n.operator_spk_hex[-4:]
        return (
            f'<tr><td><a href="{n.endpoint}">{n.endpoint}</a></td>'
            f"<td><code>{spk_short}</code></td>"
            f"<td>{n.version or '-'}</td>"
            f'<td class="{cls}">{age_str}</td>'
            f"<td>{len(n.last_seen_via)}</td></tr>"
        )

    rows = "\n".join(_row(n) for n in nodes)
    html = _HTML_TEMPLATE.format(
        generated=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now)),
        count=len(nodes),
        rows=rows or '<tr><td colspan="5">(no nodes seen)</td></tr>',
    )
    out.write_text(html)


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
    nodes = aggregate(seeds, now=now) if seeds else []
    emit_json(nodes, args.out_dir / "feed.json", now=now)
    emit_html(nodes, args.out_dir / "index.html", now=now)
    log.info(
        "wrote %d nodes from %d seeds to %s", len(nodes), len(seeds), args.out_dir
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
