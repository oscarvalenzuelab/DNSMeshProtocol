"""HTTP API for publishing DMP records to a node.

Intended for clients that don't have direct write access to an authoritative
DNS zone (e.g. individual users without a Cloudflare API token). The node
operator runs this service and exposes the endpoint; clients POST records
which the node then serves via its DNS side.

Endpoints:
    POST   /v1/records/{name}    body: {"value": "...", "ttl": 300}
    DELETE /v1/records/{name}    optional body: {"value": "..."}
    GET    /v1/records/{name}    debug; returns {"values": [...]}
    GET    /health
    GET    /stats

Auth (optional): if `bearer_token` is set, all /v1/* endpoints require
`Authorization: Bearer <token>`. /health and /stats stay open.

Zero third-party deps — stdlib http.server only. Not a production webserver;
front it with nginx or caddy if you care about performance or TLS.
"""

from __future__ import annotations

import json
import logging
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Optional
from urllib.parse import unquote

from dmp.network.base import DNSRecordReader, DNSRecordStore, DNSRecordWriter
from dmp.server.metrics import REGISTRY
from dmp.server.rate_limit import RateLimit, TokenBucketLimiter


log = logging.getLogger(__name__)

_NAME_PATH_RE = re.compile(r"^/v1/records/(?P<name>[^/]+)/?$")

# Cap request body size to catch obviously-abusive clients before JSON parsing.
MAX_BODY_BYTES = 16 * 1024

# Default resource caps. Each is adjustable per-node via DMPHttpApi kwargs
# (and DMP_MAX_* env vars in DMPNode). Defaults chosen so a single writer
# can't silently bloat the sqlite store through one legitimate-looking
# series of publishes.
DEFAULT_MAX_TTL = 86_400          # 1 day
DEFAULT_MAX_VALUE_BYTES = 2_048   # ~8× a single 255-byte TXT string
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
        token = self.server.bearer_token
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        expected = f"Bearer {token}"
        # Use constant-time compare to keep token-guessing timing-free.
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

    def _handle_get(self) -> int:
        if self.path == "/health":
            return self._handle_health()
        if self.path == "/metrics":
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
        if self._match_name() is None:
            self._send_json(404, {"error": "not found"})
            return 404
        if not self._check_rate_limit():
            return 429
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return 401
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

        name = self._match_name()

        # Per-RRset cardinality cap. Count *existing* distinct values at
        # this name; reject only when we'd add a new one past the cap.
        max_rrset = self.server.max_values_per_name
        if max_rrset > 0:
            reader = self._reader()
            existing = reader.query_txt_record(name) if reader else None
            if existing is not None and len(existing) >= max_rrset and value not in existing:
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
        if self._match_name() is None:
            self._send_json(404, {"error": "not found"})
            return 404
        if not self._check_rate_limit():
            return 429
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return 401
        writer = self._writer()
        if writer is None:
            self._send_json(501, {"error": "writer not configured"})
            return 501
        body = self._read_json_body() or {}
        value = body.get("value") if isinstance(body, dict) else None
        ok = writer.delete_txt_record(self._match_name(), value=value)
        status = 204 if ok else 404
        self._send_empty(status)
        return status

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
    ):
        super().__init__(addr, handler)
        self.store = store
        self.bearer_token = bearer_token
        self.rate_limiter = rate_limiter
        self.max_ttl = max_ttl
        self.max_value_bytes = max_value_bytes
        self.max_values_per_name = max_values_per_name
        self.max_concurrency = max_concurrency
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
    ):
        self.store = store
        self.host = host
        self.port = port
        self.bearer_token = bearer_token
        self.rate_limiter = (
            TokenBucketLimiter(rate_limit) if rate_limit and rate_limit.enabled else None
        )
        self.max_ttl = int(max_ttl)
        self.max_value_bytes = int(max_value_bytes)
        self.max_values_per_name = int(max_values_per_name)
        self.max_concurrency = int(max_concurrency)
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
        )
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="dmp-http-api",
            daemon=True,
        )
        self._thread.start()
        log.info("DMP HTTP API listening on http://%s:%d", self.host, self.port)

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
