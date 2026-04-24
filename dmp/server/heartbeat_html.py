"""HTML rendering for the heartbeat-discovery directory.

Single source of truth so the in-node ``GET /nodes`` view and the
out-of-process aggregator (``examples/directory_aggregator.py``) both
emit the same shape. Pure functions, no I/O — callers decide whether
to write the result to a file or stream it to an HTTP client.
"""

from __future__ import annotations

import html as _html
import time
from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class DirectoryRow:
    """One node in the rendered directory.

    Both the aggregator and the in-node view normalize their inputs
    to a list of these so the renderer is agnostic to where the row
    came from (signed wire from a peer's /v1/nodes/seen, or the
    aggregator's union of many such feeds).
    """

    endpoint: str
    operator_spk_hex: str
    version: Optional[str]
    ts: int
    sources: int = 1


_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
body {{ font: 14px/1.5 system-ui, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1em; }}
th, td {{ border: 1px solid #ccc; padding: 0.4em 0.6em; text-align: left; }}
th {{ background: #f5f5f5; }}
td.fresh {{ color: #0a0; }}
td.stale {{ color: #a60; }}
small {{ color: #666; }}
code {{ font: 12px/1 ui-monospace, Menlo, Consolas, monospace; }}
.self-block {{ background: #f9fafb; border: 1px solid #e5e7eb; padding: 0.6em 0.8em; margin-top: 1em; border-radius: 4px; }}
</style>
</head>
<body>
<h1>{title}</h1>
{header_html}
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


def _format_age(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _short_spk(spk_hex: str) -> str:
    if len(spk_hex) > 16:
        return spk_hex[:8] + "..." + spk_hex[-4:]
    return spk_hex


def _row_html(row: DirectoryRow, *, now: int) -> str:
    age = max(0, now - row.ts)
    cls = "fresh" if age < 3600 else "stale"
    endpoint_e = _html.escape(row.endpoint, quote=True)
    return (
        f'<tr><td><a href="{endpoint_e}">{_html.escape(row.endpoint)}</a></td>'
        f"<td><code>{_html.escape(_short_spk(row.operator_spk_hex))}</code></td>"
        f"<td>{_html.escape(row.version or '-')}</td>"
        f'<td class="{cls}">{_format_age(age)}</td>'
        f"<td>{row.sources}</td></tr>"
    )


def render(
    rows: List[DirectoryRow],
    *,
    title: str = "DMP node directory",
    header_html: str = "",
    now: Optional[int] = None,
) -> str:
    """Render a list of DirectoryRow objects to a complete HTML document.

    ``header_html`` is injected verbatim under the ``<h1>``; callers
    that want to surface the local node's identity (in-node view) or
    aggregator metadata (cron-rendered view) build it themselves and
    are responsible for HTML-escaping anything user-supplied.
    """
    if now is None:
        now = int(time.time())
    body = "\n".join(_row_html(r, now=now) for r in rows)
    if not body:
        body = '<tr><td colspan="5">(no nodes seen)</td></tr>'
    generated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))
    if not header_html:
        header_html = (
            f"<p><small>Generated {generated} · {len(rows)} nodes.</small></p>"
        )
    return _TEMPLATE.format(
        title=_html.escape(title),
        header_html=header_html,
        rows=body,
    )
