"""HTTP API for publishing DMP records to a node.

Intended for clients that don't have direct write access to an authoritative
DNS zone (e.g. individual users without a Cloudflare API token). The node
operator runs this service and exposes the endpoint; clients POST records
which the node then serves via its DNS side.

Endpoints:
    POST   /v1/records/{name}           body: {"value": "...", "ttl": 300}
    DELETE /v1/records/{name}           optional body: {"value": "..."}
    GET    /v1/records/{name}           debug; returns {"values": [...]}
    GET    /v1/sync/digest              anti-entropy: (name, hash, ts) index
    POST   /v1/sync/pull                anti-entropy: pull values by name list
    GET    /v1/sync/cluster-manifest    gossip: current signed manifest wire
    GET    /health
    GET    /stats

Auth (optional): if `bearer_token` is set, all /v1/records/* endpoints
AND /metrics require `Authorization: Bearer <token>`. /health and
/stats stay open. The /v1/sync/* endpoints use a SEPARATE shared token
(`sync_peer_token`) so an operator can leave the publish API open to
users while gating the bulk-dump sync surface to peer nodes only. If
no sync token is configured the sync endpoints return 403.

/metrics gating rationale: the endpoint leaks operational metadata
(publish rate, per-operation error rates, rate-limit hits, concurrency
saturation). For a privacy-oriented protocol that's an activity
indicator we don't want open to the world. When no `bearer_token` is
configured (dev / local mode), `/metrics` stays open and the server
logs a startup WARNING so operators can't silently ship an
unauthenticated node to the public internet.

Zero third-party deps — stdlib http.server only. Not a production webserver;
front it with nginx or caddy if you care about performance or TLS.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Optional
from urllib.parse import parse_qs, unquote, urlsplit

from dmp.network.base import DNSRecordReader, DNSRecordStore, DNSRecordWriter
from dmp.server.metrics import REGISTRY
from dmp.server.rate_limit import RateLimit, TokenBucketLimiter

log = logging.getLogger(__name__)

_NAME_PATH_RE = re.compile(r"^/v1/records/(?P<name>[^/]+)/?$")

# Anti-entropy sync — caps mirror dmp.server.anti_entropy so a reasonable
# operator misconfig (e.g. accidental limit=10_000_000) doesn't DoS the node.
_SYNC_DIGEST_DEFAULT_LIMIT = 1000
_SYNC_DIGEST_MAX_LIMIT = 10_000
_SYNC_PULL_MAX_NAMES = 256

# Cap request body size to catch obviously-abusive clients before JSON parsing.
MAX_BODY_BYTES = 16 * 1024

# Default resource caps. Each is adjustable per-node via DMPHttpApi kwargs
# (and DMP_MAX_* env vars in DMPNode). Defaults chosen so a single writer
# can't silently bloat the sqlite store through one legitimate-looking
# series of publishes.
DEFAULT_MAX_TTL = 86_400  # 1 day
DEFAULT_MAX_VALUE_BYTES = 2_048  # ~8× a single 255-byte TXT string
DEFAULT_MAX_VALUES_PER_NAME = 64  # per-RRset cardinality cap on publish


class _DMPHttpHandler(BaseHTTPRequestHandler):
    # HTTPServer sets server attribute; we attach store + token there.
    server: "_DMPHttpServer"

    # Silence default stderr access logging; integrate with our logger instead.
    def log_message(self, fmt: str, *args) -> None:
        log.debug("%s - - %s", self.address_string(), fmt % args)

    # ---- plumbing ---------------------------------------------------------

    def _send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorized(self) -> bool:
        """Check the OPERATOR bearer token only.

        Used for operator-reserved endpoints (metrics, operator-only
        record namespaces). The per-user token path for
        ``/v1/records/*`` goes through :meth:`_authorize_record_write`.
        """
        token = self.server.operator_token
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        expected = f"Bearer {token}"
        # Use constant-time compare to keep token-guessing timing-free.
        return len(header) == len(expected) and _consteq(header, expected)

    def _auth_failure_response(self) -> tuple:
        """Pick the right status + body when _authorize_record_write()
        returned False. AuthResult.throttled -> 429; anything else -> 401."""
        result = getattr(self, "_last_auth_result", None)
        if result is not None and getattr(result, "throttled", False):
            return 429, {"error": "per-token rate limit exceeded"}
        return 401, {"error": "unauthorized"}

    def _extract_presented_token(self) -> str:
        """Return the raw token material from the Authorization header,
        or '' if none was presented. The 'Bearer ' prefix is stripped."""
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return ""
        return header[len("Bearer ") :]

    def _authorize_record_write(self, record_name: str) -> bool:
        """Mode-aware authorization for ``/v1/records/{name}`` writes.

        ``auth_mode == "open"``: accept everything. Dev / trusted LAN only.
        ``auth_mode == "legacy"``: only the operator token is accepted
            (backward-compatible with pre-M5.5 deploys).
        ``auth_mode == "multi-tenant"``: operator token short-circuits for
            any scope (operators can always write). Otherwise the
            presented token is consulted against the :class:`TokenStore`
            via :meth:`TokenStore.authorize_write` — that call enforces
            scope rules, rate-limit freshness, and the split audit
            policy. If no ``token_store`` is wired, multi-tenant mode
            fails closed on every write.
        """
        mode = self.server.auth_mode
        if mode == "open":
            return True

        presented = self._extract_presented_token()
        op_token = self.server.operator_token

        # Operator token short-circuit: an operator can always write.
        # Constant-time compare even when the operator token is unset
        # so timing doesn't leak presence.
        if op_token:
            expected = op_token
            if len(presented) == len(expected) and _consteq(presented, expected):
                return True

        if mode == "legacy":
            return False  # only the operator token is accepted in legacy mode

        if mode != "multi-tenant":
            # Unknown mode — fail closed rather than silently widening.
            return False

        store = self.server.token_store
        if store is None:
            return False
        result = store.authorize_write(
            presented,
            record_name,
            remote_addr=self.client_address[0] if self.client_address else "",
        )
        # Stash the AuthResult on the handler so the POST/DELETE
        # caller can translate ``throttled`` to HTTP 429 rather than
        # the default 401. AuthResult.throttled implies the token was
        # otherwise valid and scoped correctly — the failure is a
        # per-token rate limit, not an authz rejection.
        self._last_auth_result = result
        return bool(result.ok)

    def _sync_authorized(self) -> bool:
        """Check the cluster-operator shared token for peer-to-peer sync.

        Separate from the public publish token: an operator can leave the
        publish endpoint open to their users while locking sync to known
        peers only. If no sync token is configured we refuse — the sync
        endpoints leak bulk record data (hashes + values) and should not
        be open to anonymous callers in any deployment.
        """
        token = self.server.sync_peer_token
        if not token:
            return False
        header = self.headers.get("Authorization", "")
        expected = f"Bearer {token}"
        return len(header) == len(expected) and _consteq(header, expected)

    def _read_json_body(self) -> Optional[dict]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY_BYTES:
            return None
        try:
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return None

    def _match_name(self) -> Optional[str]:
        m = _NAME_PATH_RE.match(self.path)
        if not m:
            return None
        return unquote(m.group("name")).strip().rstrip(".")

    # ---- routes -----------------------------------------------------------

    def do_GET(self) -> None:
        status = self._handle_get()
        self._record_request("GET", status)

    def do_HEAD(self) -> None:
        # Route HEAD through the same dispatcher as GET so monitors,
        # link-checkers, and `curl -I` get a real status code (and the
        # right Content-Type / Content-Length headers) instead of the
        # 501 the BaseHTTPRequestHandler default returns when the
        # handler is missing.
        #
        # The body still gets written to wfile by the GET handlers —
        # HEAD clients close the connection after reading status +
        # headers, so the unread body is harmless. Wasted bandwidth on
        # the heaviest path (the rendered '/' landing page) is single-
        # digit KB; not worth a refactor of every handler to suppress.
        status = self._handle_get()
        self._record_request("HEAD", status)

    def _handle_get(self) -> int:
        if self.path == "/" or self.path == "/index.html":
            return self._handle_root()
        if self.path == "/health":
            return self._handle_health()
        if self.path == "/metrics":
            # Metrics leak operational metadata — publish rate, per-operation
            # error rates, rate-limit hits, concurrency ceilings. For a
            # privacy-oriented messaging protocol that's an activity
            # indicator we do not want open to the world. If a bearer
            # token is configured, require it on /metrics too (same token
            # as /v1/records/*). If no token is configured (dev mode),
            # leave it open — the DMPHttpApi constructor logs a WARNING
            # at startup so operators know the endpoint is unauthenticated.
            if not self._authorized():
                self._send_json(401, {"error": "unauthorized"})
                return 401
            text = REGISTRY.render().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(text)))
            self.end_headers()
            self.wfile.write(text)
            return 200
        if self.path == "/stats":
            count = getattr(self.server.store, "record_count", lambda: None)()
            self._send_json(200, {"records": count})
            return 200
        if self.path == "/v1/registration/challenge":
            return self._handle_registration_challenge()
        if self.path == "/v1/nodes/seen":
            return self._handle_nodes_seen()
        if self.path == "/nodes":
            return self._handle_nodes_html()
        parsed = urlsplit(self.path)
        if parsed.path == "/v1/sync/digest":
            return self._handle_sync_digest(parsed.query)
        if parsed.path == "/v1/sync/cluster-manifest":
            return self._handle_sync_cluster_manifest()
        if self._match_name() is not None:
            if not self._check_rate_limit():
                return 429
            if not self._authorized():
                self._send_json(401, {"error": "unauthorized"})
                return 401
            name = self._match_name()
            reader = self._reader()
            if reader is None:
                self._send_json(501, {"error": "reader not configured"})
                return 501
            values = reader.query_txt_record(name)
            if values is None:
                self._send_json(404, {"name": name, "values": []})
                return 404
            self._send_json(200, {"name": name, "values": values})
            return 200
        self._send_json(404, {"error": "not found"})
        return 404

    def _handle_root(self) -> int:
        """GET /  -- friendly landing page.

        First-time visitors who hit https://<node>/ shouldn't see a
        404. They should see (a) that the node is up, (b) what the
        node is, (c) where to look for peers if the operator opted
        into the discovery layer. The page degrades gracefully when
        heartbeat is disabled — it tells the operator how to enable
        it instead of leaving the page empty.
        """
        import html as _html

        store = self.server.store
        record_count: Optional[int] = None
        getter = getattr(store, "record_count", None)
        if callable(getter):
            try:
                record_count = getter()
            except Exception:
                record_count = None

        heartbeat_on = self._heartbeat_enabled()
        self_endpoint = getattr(self.server, "heartbeat_self_endpoint", None) or ""
        self_spk_hex = getattr(self.server, "heartbeat_self_spk_hex", None) or ""

        # Identity block: show heartbeat self_endpoint when set, fall
        # back to the Host: header so visitors hitting this from a
        # browser at least see the address they came in on.
        host_header = self.headers.get("Host", "") or ""
        identity = self_endpoint or (
            f"https://{host_header}" if host_header else "this node"
        )

        # Discovery block: a real peer table if heartbeat is on, an
        # operator-facing hint if it isn't.
        if heartbeat_on:
            from dmp.core.heartbeat import HeartbeatRecord
            from dmp.server.heartbeat_html import DirectoryRow

            store_hb = self.server.heartbeat_store
            limit = int(getattr(self.server, "heartbeat_seen_limit", 500))
            rows = store_hb.list_recent(limit=limit)
            directory_rows = []
            for r in rows:
                try:
                    rec = HeartbeatRecord.parse_and_verify(r.wire)
                except Exception:
                    continue
                if rec is None:
                    continue
                directory_rows.append(
                    DirectoryRow(
                        endpoint=rec.endpoint,
                        operator_spk_hex=rec.operator_spk.hex(),
                        version=rec.version,
                        ts=int(rec.ts),
                        sources=1,
                    )
                )

            from dmp.server.heartbeat_html import _row_html as _hb_row_html

            now = int(__import__("time").time())
            peer_rows = "\n".join(_hb_row_html(r, now=now) for r in directory_rows)
            if not peer_rows:
                peer_rows = (
                    '<tr><td colspan="5">(no peers heard yet — '
                    "this node has not seen any heartbeats)</td></tr>"
                )
            discovery_block = (
                f"<h2>Recent peers ({len(directory_rows)})</h2>"
                "<table>"
                "<thead><tr>"
                "<th>Endpoint</th><th>Operator pubkey</th><th>Version</th>"
                "<th>Last heard</th><th>Sources</th>"
                "</tr></thead>"
                f"<tbody>{peer_rows}</tbody>"
                "</table>"
                '<p><small><a href="/v1/nodes/seen">Raw signed feed</a> '
                ' &middot; <a href="/nodes">/nodes view</a></small></p>'
            )
        else:
            discovery_block = (
                "<h2>Discovery</h2>"
                "<p>Discovery is <strong>off</strong> on this node. To make "
                "this node discoverable and to surface peers it has heard "
                "from, the operator can set the following env vars and "
                "restart the service:</p>"
                "<pre>DMP_HEARTBEAT_ENABLED=1\n"
                "DMP_HEARTBEAT_SELF_ENDPOINT=https://your-public-host\n"
                "DMP_HEARTBEAT_OPERATOR_KEY_PATH=/path/to/operator-ed25519.hex</pre>"
                "<p><small>See the "
                '<a href="https://ovalenzuela.com/DNSMeshProtocol/deployment/heartbeat">'
                "heartbeat deployment guide</a> "
                "for a full walkthrough.</small></p>"
            )

        records_line = (
            f"<li><strong>Records served:</strong> {record_count}</li>"
            if record_count is not None
            else ""
        )
        spk_line = (
            f"<li><strong>Operator pubkey:</strong> "
            f"<code>{_html.escape(self_spk_hex)}</code></li>"
            if self_spk_hex
            else ""
        )

        body = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_html.escape(identity)} — dnsmesh-node</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body {{ font: 14px/1.5 system-ui, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; color: #1f2328; }}
h1 {{ margin-bottom: 0.2em; }}
h1 small {{ font: normal 14px/1 system-ui, sans-serif; color: #59636e; }}
h2 {{ margin-top: 2em; border-bottom: 1px solid #d1d9e0; padding-bottom: 0.3em; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 0.6em; }}
th, td {{ border: 1px solid #ccc; padding: 0.4em 0.6em; text-align: left; }}
th {{ background: #f5f5f5; }}
td.fresh {{ color: #0a0; }}
td.stale {{ color: #a60; }}
small {{ color: #59636e; }}
code {{ font: 12px/1 ui-monospace, Menlo, Consolas, monospace; word-break: break-all; }}
ul {{ padding-left: 1.2em; }}
pre {{ background: #f6f8fa; border: 1px solid #d1d9e0; padding: 0.6em 0.8em; border-radius: 4px; overflow-x: auto; }}
.status {{ display: inline-block; padding: 0.1em 0.6em; background: #e6ffec; color: #1a7f37; border-radius: 4px; font-size: 12px; }}
</style>
</head>
<body>
<h1>{_html.escape(identity)} <small>dnsmesh-node</small></h1>
<p><span class="status">healthy</span></p>

<h2>About this node</h2>
<ul>
<li><strong>Endpoint:</strong> <code>{_html.escape(identity)}</code></li>
{records_line}
{spk_line}
<li><strong>API:</strong> <a href="/health">/health</a> &middot; <a href="/stats">/stats</a></li>
</ul>

{discovery_block}

<h2>About DNS Mesh Protocol</h2>
<p>Federated end-to-end encrypted messaging delivered over DNS. Identity = DNS name.
No central directory, no phone numbers, no servers to trust.</p>
<ul>
<li><a href="https://ovalenzuela.com/DNSMeshProtocol/">Documentation</a></li>
<li><a href="https://github.com/oscarvalenzuelab/DNSMeshProtocol">Source on GitHub</a></li>
<li><a href="https://pypi.org/project/dnsmesh/">Python client (<code>pip install dnsmesh</code>)</a></li>
</ul>
</body>
</html>
"""
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=30")
        self.end_headers()
        self.wfile.write(data)
        return 200

    def _handle_health(self) -> int:
        store = self.server.store
        # Deep health: exercise the store. A plain "process is alive" check
        # lets a wedged sqlite or a stale file handle look healthy to k8s/DO
        # probes and traffic keeps flowing to a broken node.
        try:
            values = store.query_txt_record("__dmp_health_probe__")
            # Absence is fine; we only care the call returned without raising.
            _ = values
        except Exception as e:
            self._send_json(503, {"status": "degraded", "store": str(e)})
            return 503
        self._send_json(200, {"status": "ok"})
        return 200

    def do_POST(self) -> None:
        status = self._handle_post()
        self._record_request("POST", status)

    def _handle_post(self) -> int:
        parsed = urlsplit(self.path)
        if parsed.path == "/v1/sync/pull":
            return self._handle_sync_pull()
        if parsed.path == "/v1/registration/confirm":
            return self._handle_registration_confirm()
        if parsed.path == "/v1/heartbeat":
            return self._handle_heartbeat_submit()
        name = self._match_name()
        if name is None:
            self._send_json(404, {"error": "not found"})
            return 404
        if not self._check_rate_limit():
            return 429
        # Mode-aware auth: in multi-tenant mode the token's scope is
        # checked against the record name; in legacy / open modes the
        # record name is ignored but the check still happens.
        if not self._authorize_record_write(name):
            status, payload = self._auth_failure_response()
            self._send_json(status, payload)
            return status
        writer = self._writer()
        if writer is None:
            self._send_json(501, {"error": "writer not configured"})
            return 501
        body = self._read_json_body()
        if body is None:
            self._send_json(400, {"error": "invalid body"})
            return 400
        value = body.get("value")
        ttl = body.get("ttl", 300)
        if not isinstance(value, str) or not isinstance(ttl, int) or ttl <= 0:
            self._send_json(400, {"error": "value (str) and ttl (int > 0) required"})
            return 400

        # Resource caps — enforced before touching the store so a single
        # malicious request can't silently burn disk.
        max_ttl = self.server.max_ttl
        if ttl > max_ttl:
            self._send_json(
                400,
                {"error": f"ttl exceeds cap of {max_ttl}s"},
            )
            return 400
        max_value = self.server.max_value_bytes
        if len(value.encode("utf-8")) > max_value:
            self._send_json(
                400,
                {"error": f"value exceeds cap of {max_value} bytes"},
            )
            return 400

        # `name` was captured above (before auth) so the scope check
        # could consult it. Re-use that value instead of re-parsing.

        # Per-RRset cardinality cap. Count *existing* distinct values at
        # this name; reject only when we'd add a new one past the cap.
        max_rrset = self.server.max_values_per_name
        if max_rrset > 0:
            reader = self._reader()
            existing = reader.query_txt_record(name) if reader else None
            if (
                existing is not None
                and len(existing) >= max_rrset
                and value not in existing
            ):
                self._send_json(
                    413,
                    {"error": f"RRset at {name} already holds {max_rrset} values"},
                )
                return 413

        ok = writer.publish_txt_record(name, value, ttl=ttl)
        status = 201 if ok else 502
        self._send_json(status, {"ok": ok})
        return status

    def do_DELETE(self) -> None:
        status = self._handle_delete()
        self._record_request("DELETE", status)

    def _handle_delete(self) -> int:
        name = self._match_name()
        if name is None:
            self._send_json(404, {"error": "not found"})
            return 404
        if not self._check_rate_limit():
            return 429
        if not self._authorize_record_write(name):
            status, payload = self._auth_failure_response()
            self._send_json(status, payload)
            return status
        writer = self._writer()
        if writer is None:
            self._send_json(501, {"error": "writer not configured"})
            return 501
        body = self._read_json_body() or {}
        value = body.get("value") if isinstance(body, dict) else None
        ok = writer.delete_txt_record(name, value=value)
        status = 204 if ok else 404
        self._send_empty(status)
        return status

    # ---- M5.5 self-service registration -----------------------------------

    def _registration_enabled(self) -> bool:
        """Return True iff the node is configured for self-service.

        Requires auth_mode=multi-tenant + DMP_REGISTRATION_ENABLED=1 +
        a node hostname. Returns False silently — the GET/POST
        handlers translate that into 404 so a disabled node doesn't
        even advertise the endpoint.
        """
        cfg = getattr(self.server, "registration_config", None)
        if cfg is None or not cfg.enabled:
            return False
        if self.server.auth_mode != "multi-tenant":
            return False
        if not self.server.token_store:
            return False
        return bool(cfg.node_hostname)

    def _registration_rate_ok(self) -> bool:
        """Per-IP limiter specifically for the registration endpoints.

        Separate from the general publish limiter because the budgets
        are very different — you want generous publish limits but a
        tight registration limit to discourage subject-squatting.
        """
        limiter = getattr(self.server, "registration_rate_limiter", None)
        if limiter is None:
            return True
        key = self.client_address[0] if self.client_address else "?"
        return limiter.allow(key)

    def _handle_registration_challenge(self) -> int:
        if not self._registration_enabled():
            self._send_json(404, {"error": "not found"})
            return 404
        if not self._registration_rate_ok():
            self._send_json(429, {"error": "registration rate limit exceeded"})
            return 429
        store = self.server.challenge_store
        cfg = self.server.registration_config
        pc = store.issue(cfg.node_hostname)
        self._send_json(
            200,
            {
                "challenge": pc.challenge_hex,
                "node": pc.node,
                "expires_at": pc.expires_at,
                "version": 1,
            },
        )
        return 200

    def _handle_registration_confirm(self) -> int:
        if not self._registration_enabled():
            self._send_json(404, {"error": "not found"})
            return 404
        if not self._registration_rate_ok():
            self._send_json(429, {"error": "registration rate limit exceeded"})
            return 429
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json(400, {"error": "invalid body"})
            return 400
        from dmp.server.registration import RegistrationError, confirm_registration

        remote_addr = self.client_address[0] if self.client_address else ""
        try:
            token, row = confirm_registration(
                store=self.server.token_store,
                challenges=self.server.challenge_store,
                config=self.server.registration_config,
                body=body,
                remote_addr=remote_addr,
            )
        except RegistrationError as exc:
            self._send_json(exc.http_status, {"error": exc.reason})
            return exc.http_status
        except Exception:
            # Defensive — don't leak internal stack traces over the wire.
            self._send_json(500, {"error": "internal error"})
            return 500

        self._send_json(
            200,
            {
                "token": token,
                "subject": row.subject,
                "expires_at": row.expires_at,
                "rate_per_sec": row.rate_per_sec,
                "rate_burst": row.rate_burst,
            },
        )
        return 200

    # ---- M5.8 heartbeat + discovery directory -----------------------------

    def _heartbeat_enabled(self) -> bool:
        """Return True iff the node has opted into the heartbeat
        layer. Disabled = both endpoints 404."""
        return bool(getattr(self.server, "heartbeat_store", None))

    def _heartbeat_rate_ok(self, *, endpoint: str) -> bool:
        """Per-IP rate limiter for heartbeat endpoints.

        Two separate buckets, keyed by endpoint role:

          - ``submit``  — gates ``POST /v1/heartbeat``. Peers write
            one heartbeat per tick (~5 min); budget is tight and
            per-IP limits discourage runaway submitters.
          - ``seen``    — gates ``GET /v1/nodes/seen``. An aggregator
            scraping every 30-60s is legitimate; budget is generous.

        Splitting the buckets means heavy read traffic from a
        scraper on a shared NAT / reverse-proxy IP does not burn
        the submit budget for legitimate peer ingestion.
        """
        if endpoint == "submit":
            limiter = getattr(self.server, "heartbeat_submit_rate_limiter", None)
        else:
            limiter = getattr(self.server, "heartbeat_seen_rate_limiter", None)
        if limiter is None:
            return True
        key = self.client_address[0] if self.client_address else "?"
        return limiter.allow(key)

    def _handle_heartbeat_submit(self) -> int:
        """POST /v1/heartbeat: peer pushes a signed heartbeat.

        Verifies + stores via SeenStore.accept(). Responds with
        ``{"ok": true, "seen": [<wire>, ...]}`` — up to N of the
        most-recently-seen OTHER heartbeats, which the caller adds
        to its own ping list. Gossip-on-ping is how the mesh
        bootstraps without a centralized peer registry.

        The response field is ``seen`` (not ``gossip``) to match the
        design doc and the GET /v1/nodes/seen schema — a client that
        consumes both endpoints parses the same key name in both.
        """
        if not self._heartbeat_enabled():
            self._send_json(404, {"error": "not found"})
            return 404
        if not self._heartbeat_rate_ok(endpoint="submit"):
            self._send_json(429, {"error": "heartbeat rate limit exceeded"})
            return 429
        body = self._read_json_body()
        if not isinstance(body, dict):
            self._send_json(400, {"error": "invalid body"})
            return 400
        wire = body.get("wire")
        if not isinstance(wire, str) or not wire:
            self._send_json(400, {"error": "wire (string) required"})
            return 400

        remote_addr = self.client_address[0] if self.client_address else ""
        store = self.server.heartbeat_store
        record = store.accept(wire, remote_addr=remote_addr)
        if record is None:
            # Covers: wrong prefix / too big / bad base64 / bad magic /
            # bad sig / low-order pubkey / ts outside skew / expired.
            # Returning 400 rather than 401 because the caller isn't
            # claiming an identity here — they're submitting a wire
            # that's self-authenticating, and we just disagreed.
            self._send_json(
                400,
                {"error": "heartbeat verification failed"},
            )
            return 400

        gossip_limit = int(getattr(self.server, "heartbeat_gossip_limit", 10))
        # Gossip-on-ping response: recent heartbeats from OTHER
        # operators. Exclude the submitter's own spk so A never tells
        # B about A's own heartbeat; also excludes any other wire
        # under the same operator key (same-operator concurrent
        # submits don't echo each other).
        own_spk_hex = bytes(record.operator_spk).hex()
        rows = store.list_recent(now=None, limit=gossip_limit + 1)
        seen = [r.wire for r in rows if r.operator_spk_hex != own_spk_hex][
            :gossip_limit
        ]
        self._send_json(
            200,
            {
                "ok": True,
                "accepted_operator_spk_hex": own_spk_hex,
                "seen": seen,
            },
        )
        return 200

    def _handle_nodes_html(self) -> int:
        """GET /nodes: human-readable HTML view of this node's heartbeat
        directory. Same data as /v1/nodes/seen but rendered for a
        browser, so an operator can point a teammate at the URL without
        having to explain JSON parsing.

        Returns 404 when the heartbeat layer is disabled — the route
        only makes sense when the node is opted into discovery.
        """
        if not self._heartbeat_enabled():
            self._send_json(404, {"error": "discovery disabled on this node"})
            return 404
        if not self._heartbeat_rate_ok(endpoint="seen"):
            self._send_json(429, {"error": "heartbeat rate limit exceeded"})
            return 429

        from dmp.core.heartbeat import HeartbeatRecord
        from dmp.server.heartbeat_html import DirectoryRow, render

        store = self.server.heartbeat_store
        limit = int(getattr(self.server, "heartbeat_seen_limit", 500))
        rows = store.list_recent(limit=limit)
        directory_rows = []
        for r in rows:
            try:
                rec = HeartbeatRecord.parse_and_verify(r.wire)
            except Exception:
                # Malformed/expired records are skipped silently — the
                # store accepted them at write-time, so a verify failure
                # here means clock drift or an in-flight rotation. Don't
                # take down the directory page over it.
                continue
            if rec is None:
                continue
            directory_rows.append(
                DirectoryRow(
                    endpoint=rec.endpoint,
                    operator_spk_hex=rec.operator_spk.hex(),
                    version=rec.version,
                    ts=int(rec.ts),
                    sources=1,
                )
            )

        self_endpoint = getattr(self.server, "heartbeat_self_endpoint", None) or ""
        self_spk_hex = getattr(self.server, "heartbeat_self_spk_hex", None) or ""

        import html as _html

        header = (
            '<div class="self-block">'
            f"<strong>This node:</strong> "
            f'<a href="{_html.escape(self_endpoint, quote=True)}">'
            f"{_html.escape(self_endpoint)}</a><br>"
            f"<small>operator pubkey: <code>{_html.escape(self_spk_hex)}</code></small>"
            f"<br><small>{len(directory_rows)} peers in the last 72h · "
            f'<a href="/v1/nodes/seen">raw JSON feed</a></small>'
            "</div>"
        )
        body = render(
            directory_rows,
            title="DMP node directory",
            header_html=header,
        )
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=30")
        self.end_headers()
        self.wfile.write(data)
        return 200

    def _handle_nodes_seen(self) -> int:
        """GET /v1/nodes/seen: public snapshot of verified heartbeats
        this node has accumulated. Used by directory aggregators."""
        if not self._heartbeat_enabled():
            self._send_json(404, {"error": "not found"})
            return 404
        if not self._heartbeat_rate_ok(endpoint="seen"):
            self._send_json(429, {"error": "heartbeat rate limit exceeded"})
            return 429
        store = self.server.heartbeat_store
        limit = int(getattr(self.server, "heartbeat_seen_limit", 500))
        rows = store.list_recent(limit=limit)
        self_endpoint = getattr(self.server, "heartbeat_self_endpoint", None)
        self_spk_hex = getattr(self.server, "heartbeat_self_spk_hex", None)
        self._send_json(
            200,
            {
                "version": 1,
                "self": {
                    "endpoint": self_endpoint,
                    "operator_spk_hex": self_spk_hex,
                    "enabled": True,
                },
                "seen": [{"wire": r.wire} for r in rows],
            },
        )
        return 200

    # ---- anti-entropy sync routes -----------------------------------------

    def _handle_sync_digest(self, query_string: str) -> int:
        """GET /v1/sync/digest?cursor=<opaque>&limit=<int>

        Preferred entry point for the M2.4-followup worker. ``cursor`` is
        an opaque ``"<ts>:<name>:<value_hash>"`` string the server
        previously emitted as ``next_cursor`` in a digest response —
        carrying all three halves of the compound
        ``(stored_ts, name, value_hash)`` watermark makes pagination
        correct even when > ``limit`` values land at the same
        ``(stored_ts, name)`` (a multi-value RRset burst: e.g. 5 prekey
        TXT entries under ``prekeys.id-xxx``).

        Legacy ``?since=<ts>`` is still accepted (the original M2.4 shape);
        it is equivalent to ``cursor="<ts>::"`` and logs a one-line warning
        so operators can see when a stale peer is still calling it. The
        ``"<ts>:<name>"`` (two-field) cursor shape emitted by the
        followup-1 worker is also still accepted — treated as
        ``"<ts>:<name>:"`` — so mid-upgrade peers aren't broken.

        Returns compact hash-per-record entries the peer can diff against.
        ``next_cursor`` is always emitted — terminal pages carry the
        cursor of the last row so the peer can persist it as the final
        watermark. Expired records are not returned (same cutoff as
        query_txt_record). Rate limiting applies to the caller's IP.
        """
        if not self._check_rate_limit():
            return 429
        if not self._sync_authorized():
            self._send_json(403, {"error": "forbidden"})
            return 403

        store = self.server.store
        iter_fn = getattr(store, "iter_records_since", None)
        if iter_fn is None:
            # Store predates M2.4. A public gate rather than 500 lets an
            # operator swap in a new store without downtime.
            self._send_json(501, {"error": "store does not support sync"})
            return 501

        params = parse_qs(query_string or "")
        cursor_tuple: Optional[tuple] = None
        if "cursor" in params:
            raw = params["cursor"][0]
            parsed = _parse_digest_cursor(raw)
            if parsed is None:
                self._send_json(
                    400,
                    {"error": "cursor must be '<ts>:<name>:<value_hash>'"},
                )
                return 400
            cursor_tuple = parsed
        elif "since" in params:
            # Legacy shape. Still supported, but warn so an operator can
            # see when their peer is still on the old wire.
            try:
                since = int(params.get("since", ["0"])[0])
            except (ValueError, TypeError):
                self._send_json(400, {"error": "since must be an integer"})
                return 400
            if since < 0:
                self._send_json(400, {"error": "since must be >= 0"})
                return 400
            log.warning(
                "anti-entropy: legacy since=<ts> digest call from %s; "
                "peer should upgrade to cursor=<opaque>",
                self.address_string(),
            )
            # Legacy `since` carries strict-greater-than semantics —
            # rows AT `since` must be excluded. With the compound
            # cursor (ts, name, value_hash), a tuple of (since, "", "")
            # would instead match anything at stored_ts == since AND
            # name > "" — i.e. any real row, effectively >= since.
            # Use sentinel values that sort greater than any real
            # DNS name (0xFF byte) and any real value_hash (hex chars
            # max out at 'f', so 'g' is a clean upper bound). This
            # forces the OR-branches to never match same-ts rows.
            cursor_tuple = (since, "\xff", "g")
        else:
            cursor_tuple = (0, "", "")

        try:
            limit = int(params.get("limit", [_SYNC_DIGEST_DEFAULT_LIMIT])[0])
        except (ValueError, TypeError):
            self._send_json(400, {"error": "limit must be an integer"})
            return 400
        if limit <= 0:
            self._send_json(400, {"error": "limit must be > 0"})
            return 400
        if limit > _SYNC_DIGEST_MAX_LIMIT:
            limit = _SYNC_DIGEST_MAX_LIMIT

        # Over-fetch by one to detect whether more rows exist without
        # paying for a count query. Trim before serializing.
        rows = iter_fn(cursor=cursor_tuple, limit=limit + 1)
        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]

        entries = []
        for r in rows:
            # Use StoredRecord.record_hash when available (sqlite + memory
            # stores both expose it); fall back to hashing the value here
            # for defensive portability against a future store.
            h = getattr(r, "record_hash", None)
            if not h:
                h = hashlib.sha256(r.value.encode("utf-8")).hexdigest()
            # `ttl` is carried separately from `hash` so the diff can
            # detect TTL-refresh-only republishes (identical value, fresh
            # expiry). Hashing (value, ttl) would collapse them in a way
            # that's harder to debug via the digest response.
            entries.append(
                {
                    "name": r.name,
                    "hash": h,
                    "ts": r.stored_ts,
                    "ttl": max(1, int(r.ttl_remaining)),
                }
            )

        # next_cursor: the (ts, name, value_hash) of the last row emitted,
        # encoded as "<ts>:<name>:<value_hash>". Emitted even on the
        # terminal page so the worker persists it as its watermark. If
        # the store was empty, echo the caller's input cursor back —
        # there is nowhere newer to advance.
        if entries:
            last = entries[-1]
            next_cursor = f"{int(last['ts'])}:{last['name']}:{last['hash']}"
        else:
            cur_hash = cursor_tuple[2] if len(cursor_tuple) >= 3 else ""
            next_cursor = f"{int(cursor_tuple[0])}:{cursor_tuple[1]}:{cur_hash}"

        self._send_json(
            200,
            {
                "records": entries,
                "has_more": has_more,
                "next_cursor": next_cursor,
            },
        )
        return 200

    def _handle_sync_cluster_manifest(self) -> int:
        """GET /v1/sync/cluster-manifest

        Returns the signed cluster manifest wire this node currently
        serves under ``cluster.<cluster_base_domain>`` TXT — the same
        record it publishes on startup from a mounted manifest file and
        refreshes via gossip. Peer gossip workers fetch this to learn
        whether the operator has rolled out a higher-seq manifest.

        Response:
            200 ``{"wire": "...", "seq": N, "exp": N, "cluster_name": "..."}``
                when a parseable manifest wire is present at
                ``cluster.<cluster_base_domain>``. If multiple TXT
                values co-reside (rollout window), we return the
                highest-seq that parses structurally — the caller
                re-verifies the signature against its pinned
                ``operator_spk`` and decides whether to install.
            204 no content, when no manifest is known to this node
                (file never mounted, not yet installed via gossip, or
                ``cluster_base_domain`` was not configured).
            403 wrong / missing sync token.
            429 rate-limited.

        Auth: shares ``sync_peer_token`` with /v1/sync/digest and
        /v1/sync/pull. The manifest wire is a signed, publishable
        record — but the peer-to-peer channel is still cluster-private
        and an anonymous caller has no business hitting this surface.

        The server does NOT verify the signature or enforce an expected
        operator key here. The gossip worker does both with its pinned
        trust anchor; the server is just a cache of whatever wire was
        last installed locally, and re-verifying here would only mask a
        local-state inconsistency (the node would 204 on a manifest it
        has in-store). A compromised server can at worst serve an older
        or unrelated manifest, which ``parse_and_verify`` rejects
        client-side.
        """
        if not self._check_rate_limit():
            return 429
        if not self._sync_authorized():
            self._send_json(403, {"error": "forbidden"})
            return 403

        base = self.server.cluster_base_domain
        if not base:
            # No base domain configured → the server doesn't know which
            # RRset to read. Treated as "no manifest known to this node".
            self._send_empty(204)
            return 204

        # Derive the RRset the node publishes under. Mirror the same
        # cluster.<base> convention used by `_publish_cluster_manifest_from_file`.
        from dmp.core.cluster import RECORD_PREFIX as _CLUSTER_PREFIX
        from dmp.core.cluster import cluster_rrset_name

        try:
            rrset = cluster_rrset_name(base)
        except ValueError:
            # Operator misconfigured cluster_base_domain; a 204 beats a
            # 500 here — gossip will simply never install from this node.
            self._send_empty(204)
            return 204

        reader = self._reader()
        if reader is None:
            self._send_empty(204)
            return 204

        values = reader.query_txt_record(rrset)
        if not values:
            self._send_empty(204)
            return 204

        # Pick the highest-seq wire that (a) parses structurally AND
        # (b) verifies under the pinned operator_spk when one is set.
        # Without the verification filter, a stray TXT value with a
        # higher seq (bad key, malformed body, wrong cluster) would
        # mask every valid manifest below it — the gossip client
        # rejects the bad wire in parse_and_verify() and never falls
        # back to the next candidate, so rollout stalls until the bad
        # TXT expires. Filtering server-side means only a verified
        # wire ever wins the highest-seq race.
        #
        # If no operator_spk is configured (back-compat: older nodes
        # without DMP_SYNC_OPERATOR_SPK), fall back to the prior
        # structural-only behavior. Gossip is disabled in that mode
        # anyway (see _make_anti_entropy_worker), so correctness of
        # the highest-seq pick only matters for manually-issued
        # diagnostic curls and we keep those working.
        operator_spk: Optional[bytes] = getattr(
            self.server, "sync_cluster_operator_spk", None
        )
        from dmp.core.cluster import ClusterManifest as _ClusterManifest

        best_wire: Optional[str] = None
        best_seq = -1
        best_exp = 0
        best_name = ""
        import base64 as _b64

        for wire in values:
            if not isinstance(wire, str) or not wire.startswith(_CLUSTER_PREFIX):
                continue
            try:
                blob = _b64.b64decode(wire[len(_CLUSTER_PREFIX) :], validate=True)
            except Exception:
                continue
            # magic(7) + seq(8) + exp(8) + spk(32) + name_len(1) = 56
            # + 64-byte sig trailer.
            if len(blob) < 56 + 64:
                continue
            body = blob[:-64]
            try:
                seq = int.from_bytes(body[7:15], "big")
                exp = int.from_bytes(body[15:23], "big")
                name_len = body[55]
                cluster_name = body[56 : 56 + name_len].decode("utf-8").rstrip(".")
            except Exception:
                continue
            if operator_spk is not None:
                # Signature + cluster-name binding. Skip silently on
                # failure — peer-view is informational, not authoritative.
                if (
                    _ClusterManifest.parse_and_verify(
                        wire,
                        operator_spk,
                        expected_cluster_name=base if base else None,
                    )
                    is None
                ):
                    continue
            if seq > best_seq:
                best_wire = wire
                best_seq = seq
                best_exp = exp
                best_name = cluster_name

        if best_wire is None:
            self._send_empty(204)
            return 204

        self._send_json(
            200,
            {
                "wire": best_wire,
                "seq": best_seq,
                "exp": best_exp,
                "cluster_name": best_name,
            },
        )
        return 200

    def _handle_sync_pull(self) -> int:
        """POST /v1/sync/pull {"names": [...]} -> TXT values for those names.

        Expired / unknown names are silently omitted. Cap is
        _SYNC_PULL_MAX_NAMES; requests over the cap return 400 (not
        truncated) so the caller knows to paginate.
        """
        if not self._check_rate_limit():
            return 429
        if not self._sync_authorized():
            self._send_json(403, {"error": "forbidden"})
            return 403

        store = self.server.store
        getter = getattr(store, "get_records_by_name", None)
        if getter is None:
            self._send_json(501, {"error": "store does not support sync"})
            return 501

        body = self._read_json_body()
        if body is None:
            self._send_json(400, {"error": "invalid body"})
            return 400
        names = body.get("names") if isinstance(body, dict) else None
        if not isinstance(names, list):
            self._send_json(400, {"error": "names must be a list"})
            return 400
        if len(names) > _SYNC_PULL_MAX_NAMES:
            self._send_json(
                400,
                {"error": f"at most {_SYNC_PULL_MAX_NAMES} names per request"},
            )
            return 400
        clean_names = []
        for n in names:
            if not isinstance(n, str):
                self._send_json(400, {"error": "names must be strings"})
                return 400
            clean_names.append(n.strip().rstrip("."))

        rows = getter(clean_names)
        out = []
        for r in rows:
            out.append(
                {
                    "name": r.name,
                    "value": r.value,
                    "ttl": max(1, int(r.ttl_remaining)),
                }
            )
        self._send_json(200, {"records": out})
        return 200

    def _check_rate_limit(self) -> bool:
        limiter: Optional[TokenBucketLimiter] = self.server.rate_limiter
        if limiter is None or not limiter.enabled:
            return True
        client_ip = self.client_address[0]
        if limiter.allow(client_ip):
            return True
        self._send_json(429, {"error": "rate limit exceeded"})
        return False

    def _record_request(self, method: str, status: int) -> None:
        try:
            REGISTRY.counter(
                "dmp_http_requests_total",
                "Total DMP HTTP API requests, by method and status",
                labels={"method": method, "status": str(status)},
            )
        except Exception:
            pass

    # ---- introspection helpers for handler ---------------------------------

    def _writer(self) -> Optional[DNSRecordWriter]:
        store = self.server.store
        return store if isinstance(store, DNSRecordWriter) else None

    def _reader(self) -> Optional[DNSRecordReader]:
        store = self.server.store
        return store if isinstance(store, DNSRecordReader) else None


def _parse_digest_cursor(raw: str) -> Optional[tuple]:
    """Parse an opaque digest cursor into ``(int, str, str)``.

    Accepted shapes (in order of preference):

    - ``"<ts>:<name>:<value_hash>"`` — the followup-2 shape. value_hash
      is 64 hex chars (sha256 of the row's TXT value).
    - ``"<ts>:<name>"`` — the followup-1 shape, treated as
      ``"<ts>:<name>:"`` (empty hash sorts below any real digest, so
      the next page starts at the first value_hash for that name).

    Returns ``None`` on malformed input so callers can 400. The ``:``
    delimiter is safe because DNS names never contain colons (labels are
    ``[a-zA-Z0-9-]`` separated by ``.``) and value_hash is lowercase hex.
    We split on the first two colons only (``maxsplit=2``) so a stray
    ``:`` can't silently corrupt the ts field; any further colons would
    end up inside the value_hash check, which then rejects it as
    non-hex.
    """
    if not isinstance(raw, str):
        return None
    parts = raw.split(":", 2)
    if len(parts) == 2:
        ts_str, name = parts
        value_hash = ""
    elif len(parts) == 3:
        ts_str, name, value_hash = parts
    else:
        return None
    try:
        ts = int(ts_str)
    except (ValueError, TypeError):
        return None
    if ts < 0:
        return None
    # name may be empty — that's the "from the beginning of this ms" form
    # used by legacy since-only callers.
    if len(name) > 253:
        return None
    # value_hash is either empty (start-of-name sentinel) or a 64-char
    # lowercase hex digest. Anything else is garbage.
    if value_hash and not _VALUE_HASH_RE.match(value_hash):
        return None
    return (ts, name, value_hash)


# Cached regex for the hash half of the cursor. Module-level so every
# digest request doesn't recompile it.
_VALUE_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _consteq(a: str, b: str) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0


class _BoundedThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTPServer with a per-process cap on concurrent handler threads.

    Vanilla `ThreadingMixIn.process_request` spawns a thread per request
    with no ceiling. Under a socket flood, thread creation happens before
    the handler's token-bucket rate limiter gets a chance to run — and
    you can exhaust address space, file descriptors, or memory well
    before per-IP limits engage. We gate every new handler on a semaphore
    whose initial value is `max_concurrency`; once saturated, new
    connections are closed immediately instead of stacking threads.
    """

    allow_reuse_address = True
    daemon_threads = True
    max_concurrency = 64

    def __init__(
        self,
        addr,
        handler,
        store,
        bearer_token,
        rate_limiter,
        max_ttl,
        max_value_bytes,
        max_values_per_name,
        max_concurrency,
        sync_peer_token=None,
        cluster_base_domain=None,
        sync_cluster_operator_spk=None,
        auth_mode: str = "legacy",
        token_store=None,
        registration_config=None,
        challenge_store=None,
        registration_rate_limiter=None,
        heartbeat_store=None,
        heartbeat_submit_rate_limiter=None,
        heartbeat_seen_rate_limiter=None,
        heartbeat_self_endpoint=None,
        heartbeat_self_spk_hex=None,
        heartbeat_gossip_limit: int = 10,
        heartbeat_seen_limit: int = 500,
    ):
        super().__init__(addr, handler)
        self.store = store
        # `operator_token` is the preferred name as of M5.5 (the old
        # `bearer_token` kwarg still works for back-compat). It's the
        # admin-scoped token that can write anywhere, including
        # operator-only namespaces.
        self.operator_token = bearer_token
        # Expose under the old name too so any existing code reading
        # `server.bearer_token` keeps working during the transition.
        self.bearer_token = bearer_token
        self.rate_limiter = rate_limiter
        self.max_ttl = max_ttl
        self.max_value_bytes = max_value_bytes
        self.max_values_per_name = max_values_per_name
        self.max_concurrency = max_concurrency
        self.sync_peer_token = sync_peer_token
        self.cluster_base_domain = cluster_base_domain
        self.sync_cluster_operator_spk = sync_cluster_operator_spk
        self.auth_mode = auth_mode
        self.token_store = token_store
        self.registration_config = registration_config
        self.challenge_store = challenge_store
        self.registration_rate_limiter = registration_rate_limiter
        # M5.8 heartbeat plumbing. All None when disabled — handlers
        # 404 on _heartbeat_enabled()==False. Submit + seen buckets
        # are separate per codex phase-3 P2: heavy scraper traffic on
        # /v1/nodes/seen must NOT burn the ingestion budget for
        # POST /v1/heartbeat.
        self.heartbeat_store = heartbeat_store
        self.heartbeat_submit_rate_limiter = heartbeat_submit_rate_limiter
        self.heartbeat_seen_rate_limiter = heartbeat_seen_rate_limiter
        self.heartbeat_self_endpoint = heartbeat_self_endpoint
        self.heartbeat_self_spk_hex = heartbeat_self_spk_hex
        self.heartbeat_gossip_limit = int(heartbeat_gossip_limit)
        self.heartbeat_seen_limit = int(heartbeat_seen_limit)
        self._semaphore = threading.Semaphore(max_concurrency)

    def process_request(self, request, client_address):
        if not self._semaphore.acquire(blocking=False):
            # At the concurrency ceiling — drop the connection rather
            # than queue another thread.
            try:
                self.shutdown_request(request)
            except Exception:
                pass
            return
        t = threading.Thread(
            target=self._handle_with_release,
            args=(request, client_address),
            name="dmp-http-handler",
            daemon=self.daemon_threads,
        )
        t.start()

    def _handle_with_release(self, request, client_address):
        try:
            self.process_request_thread(request, client_address)
        finally:
            self._semaphore.release()


# Back-compat alias; tests and old callers imported the old class name.
_DMPHttpServer = _BoundedThreadingHTTPServer


class DMPHttpApi:
    """Background HTTP server exposing publish/query/delete over REST."""

    def __init__(
        self,
        store: DNSRecordStore,
        *,
        host: str = "0.0.0.0",
        port: int = 8053,
        bearer_token: Optional[str] = None,
        rate_limit: Optional[RateLimit] = None,
        max_ttl: int = DEFAULT_MAX_TTL,
        max_value_bytes: int = DEFAULT_MAX_VALUE_BYTES,
        max_values_per_name: int = DEFAULT_MAX_VALUES_PER_NAME,
        max_concurrency: int = 64,
        sync_peer_token: Optional[str] = None,
        cluster_base_domain: Optional[str] = None,
        sync_cluster_operator_spk: Optional[bytes] = None,
        auth_mode: Optional[str] = None,
        token_store=None,
        registration_config=None,
        heartbeat_store=None,
        heartbeat_submit_rate_limit: Optional[RateLimit] = None,
        heartbeat_seen_rate_limit: Optional[RateLimit] = None,
        heartbeat_self_endpoint: Optional[str] = None,
        heartbeat_self_spk_hex: Optional[str] = None,
        heartbeat_gossip_limit: int = 10,
        heartbeat_seen_limit: int = 500,
    ):
        self.store = store
        self.host = host
        self.port = port
        self.bearer_token = bearer_token
        self.operator_token = bearer_token
        # Default auth mode derivation, preserving pre-M5.5 behavior:
        #   no bearer_token  -> "open"   (the old unauthenticated path)
        #   bearer_token set -> "legacy" (the old shared-token path)
        # Callers who want multi-tenant pass it explicitly.
        if auth_mode is None:
            auth_mode = "open" if not bearer_token else "legacy"
        self.auth_mode = auth_mode
        self.rate_limiter = (
            TokenBucketLimiter(rate_limit)
            if rate_limit and rate_limit.enabled
            else None
        )
        self.max_ttl = int(max_ttl)
        self.max_value_bytes = int(max_value_bytes)
        self.max_values_per_name = int(max_values_per_name)
        self.max_concurrency = int(max_concurrency)
        self.sync_peer_token = sync_peer_token
        self.cluster_base_domain = cluster_base_domain
        self.sync_cluster_operator_spk = sync_cluster_operator_spk
        self.token_store = token_store
        # Lazy: these are set up iff registration_config.enabled + we're
        # in multi-tenant mode with a token_store. Created in start().
        self.registration_config = registration_config
        self.challenge_store = None
        self.registration_rate_limiter = None
        # M5.8 heartbeat wiring. The store is the opt-in signal — if
        # the caller didn't pass one, the endpoints 404. Self-identity
        # (endpoint + spk hex) is surfaced on GET /v1/nodes/seen so
        # aggregators know who to attribute THIS node's listing to.
        # Two independent rate limits: submit + seen. Splitting them
        # keeps heavy scraper traffic on /v1/nodes/seen from burning
        # the budget for legitimate peer POSTs to /v1/heartbeat.
        self.heartbeat_store = heartbeat_store
        self.heartbeat_submit_rate_limit = heartbeat_submit_rate_limit
        self.heartbeat_seen_rate_limit = heartbeat_seen_rate_limit
        self.heartbeat_submit_rate_limiter = None  # materialized in start()
        self.heartbeat_seen_rate_limiter = None
        self.heartbeat_self_endpoint = heartbeat_self_endpoint
        self.heartbeat_self_spk_hex = heartbeat_self_spk_hex
        self.heartbeat_gossip_limit = int(heartbeat_gossip_limit)
        self.heartbeat_seen_limit = int(heartbeat_seen_limit)
        self._server: Optional[_DMPHttpServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def server_address(self) -> tuple[str, int]:
        if self._server is None:
            return (self.host, self.port)
        return self._server.server_address

    def start(self) -> None:
        if self._server is not None:
            return

        # Lazily materialize registration plumbing iff enabled + prereqs
        # met. Keeps open / legacy deployments zero-cost (no extra
        # threads, no extra memory).
        if (
            self.registration_config is not None
            and self.registration_config.enabled
            and self.auth_mode == "multi-tenant"
            and self.token_store is not None
        ):
            from dmp.server.registration import ChallengeStore

            self.challenge_store = ChallengeStore()
            self.registration_rate_limiter = TokenBucketLimiter(
                RateLimit(
                    rate_per_second=self.registration_config.endpoint_rate_per_sec,
                    burst=self.registration_config.endpoint_rate_burst,
                )
            )

        # M5.8 heartbeat rate limiters — materialized only when the
        # operator wired a heartbeat_store in AND supplied a
        # RateLimit for the corresponding endpoint. Submit + seen
        # are independent per codex phase-3 P2.
        if self.heartbeat_store is not None:
            if (
                self.heartbeat_submit_rate_limit is not None
                and self.heartbeat_submit_rate_limit.enabled
            ):
                self.heartbeat_submit_rate_limiter = TokenBucketLimiter(
                    self.heartbeat_submit_rate_limit
                )
            if (
                self.heartbeat_seen_rate_limit is not None
                and self.heartbeat_seen_rate_limit.enabled
            ):
                self.heartbeat_seen_rate_limiter = TokenBucketLimiter(
                    self.heartbeat_seen_rate_limit
                )

        self._server = _DMPHttpServer(
            (self.host, self.port),
            _DMPHttpHandler,
            self.store,
            self.bearer_token,
            self.rate_limiter,
            self.max_ttl,
            self.max_value_bytes,
            self.max_values_per_name,
            self.max_concurrency,
            sync_peer_token=self.sync_peer_token,
            cluster_base_domain=self.cluster_base_domain,
            sync_cluster_operator_spk=self.sync_cluster_operator_spk,
            auth_mode=self.auth_mode,
            token_store=self.token_store,
            registration_config=self.registration_config,
            challenge_store=self.challenge_store,
            registration_rate_limiter=self.registration_rate_limiter,
            heartbeat_store=self.heartbeat_store,
            heartbeat_submit_rate_limiter=self.heartbeat_submit_rate_limiter,
            heartbeat_seen_rate_limiter=self.heartbeat_seen_rate_limiter,
            heartbeat_self_endpoint=self.heartbeat_self_endpoint,
            heartbeat_self_spk_hex=self.heartbeat_self_spk_hex,
            heartbeat_gossip_limit=self.heartbeat_gossip_limit,
            heartbeat_seen_limit=self.heartbeat_seen_limit,
        )
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="dmp-http-api",
            daemon=True,
        )
        self._thread.start()
        log.info("DMP HTTP API listening on http://%s:%d", self.host, self.port)
        if not self.bearer_token:
            # Dev / local path is fine, but loud enough that nobody ships
            # a node to the open internet without noticing. /metrics
            # leaks operational metadata (publish rate, rate-limit hits,
            # error counters) which is an activity indicator for a
            # privacy-oriented protocol.
            log.warning(
                "metrics endpoint unauthenticated; do not expose this node "
                "to the public internet without setting DMP_HTTP_TOKEN."
            )

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def __enter__(self) -> "DMPHttpApi":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
