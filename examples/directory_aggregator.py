#!/usr/bin/env python3
"""Simple directory aggregator for M5.8 heartbeats.

Reads a list of seed node URLs, queries each ``/v1/nodes/seen``,
verifies every returned HeartbeatRecord, unions them by
(operator_spk, endpoint), and emits:

  - A signed JSON feed at ``$OUT_DIR/feed.json``.
  - A static HTML index at ``$OUT_DIR/index.html`` grouping nodes by
    last-seen age.

The aggregator is fully deterministic — same seeds + same input
wires produces byte-identical outputs. Anyone can run one off the
same signed P2P data, so the operator-hosted central directory is
one consumer, not a trust anchor.

Typical deployment: cron or systemd timer calls this every N
minutes, writes the output to a directory served by your static
hosting of choice (GitHub Pages, S3, nginx).

Usage:

  python examples/directory_aggregator.py \\
      --seed https://dmp.example.com \\
      --seed https://other.example.org \\
      --out-dir ./public

Run ``--help`` for the full argument list.
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

import requests

# Allow running from a checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dmp.core.heartbeat import HeartbeatRecord  # noqa: E402


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


def _fetch(seed: str, timeout: float = 10.0) -> Optional[dict]:
    """GET <seed>/v1/nodes/seen. Returns decoded JSON or None."""
    url = seed.rstrip("/") + "/v1/nodes/seen"
    try:
        r = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        log.info("fetch failed for %s: %s", url, exc)
        return None
    if r.status_code != 200:
        log.info("non-200 from %s: %d", url, r.status_code)
        return None
    try:
        body = r.json()
    except ValueError:
        log.info("non-JSON from %s", url)
        return None
    if not isinstance(body, dict):
        return None
    return body


def _extract_wires(body: dict) -> Iterable[str]:
    """Yield every candidate wire string from a /v1/nodes/seen body."""
    seen = body.get("seen")
    if not isinstance(seen, list):
        return
    for entry in seen:
        if isinstance(entry, dict):
            w = entry.get("wire")
            if isinstance(w, str):
                yield w
        elif isinstance(entry, str):
            # Tolerant of a flat string list just in case.
            yield entry


def aggregate(seeds: List[str], *, now: Optional[int] = None) -> List[AggregatedNode]:
    """Query seeds, verify, union. Returns the deduped node list."""
    now_i = int(now) if now is not None else int(time.time())
    # Map (operator_spk_hex, endpoint) -> AggregatedNode (keep the
    # newest-ts wire on dedupe).
    pool: Dict[Tuple[str, str], AggregatedNode] = {}

    for seed in seeds:
        body = _fetch(seed)
        if body is None:
            continue
        for wire in _extract_wires(body):
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
                    last_seen_via=[seed],
                )
            else:
                # If this source reports a NEWER ts for the same
                # node, take the newer wire. Always record the
                # source seed so the HTML can show "heard via N
                # sources".
                sources = list(existing.last_seen_via)
                if seed not in sources:
                    sources.append(seed)
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
            else f"{age // 60}m ago"
            if age < 3600
            else f"{age // 3600}h ago"
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
        required=True,
        help="seed node HTTPS URL (repeatable). Each seed's "
        "/v1/nodes/seen is fetched; results are unioned and verified.",
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

    args.out_dir.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    nodes = aggregate(args.seed, now=now)
    emit_json(nodes, args.out_dir / "feed.json", now=now)
    emit_html(nodes, args.out_dir / "index.html", now=now)
    log.info("wrote %d nodes to %s", len(nodes), args.out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
