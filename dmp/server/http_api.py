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


log = logging.getLogger(__name__)

_NAME_PATH_RE = re.compile(r"^/v1/records/(?P<name>[^/]+)/?$")

# Cap request body size to catch obviously-abusive clients before JSON parsing.
MAX_BODY_BYTES = 16 * 1024


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
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        if self.path == "/stats":
            count = getattr(self.server.store, "record_count", lambda: None)()
            self._send_json(200, {"records": count})
            return
        if self._match_name() is not None:
            if not self._authorized():
                self._send_json(401, {"error": "unauthorized"})
                return
            name = self._match_name()
            reader = self._reader()
            if reader is None:
                self._send_json(501, {"error": "reader not configured"})
                return
            values = reader.query_txt_record(name)
            if values is None:
                self._send_json(404, {"name": name, "values": []})
                return
            self._send_json(200, {"name": name, "values": values})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self._match_name() is None:
            self._send_json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return
        writer = self._writer()
        if writer is None:
            self._send_json(501, {"error": "writer not configured"})
            return
        body = self._read_json_body()
        if body is None:
            self._send_json(400, {"error": "invalid body"})
            return
        value = body.get("value")
        ttl = body.get("ttl", 300)
        if not isinstance(value, str) or not isinstance(ttl, int) or ttl <= 0:
            self._send_json(400, {"error": "value (str) and ttl (int > 0) required"})
            return
        name = self._match_name()
        ok = writer.publish_txt_record(name, value, ttl=ttl)
        self._send_json(201 if ok else 502, {"ok": ok})

    def do_DELETE(self) -> None:
        if self._match_name() is None:
            self._send_json(404, {"error": "not found"})
            return
        if not self._authorized():
            self._send_json(401, {"error": "unauthorized"})
            return
        writer = self._writer()
        if writer is None:
            self._send_json(501, {"error": "writer not configured"})
            return
        body = self._read_json_body() or {}
        value = body.get("value") if isinstance(body, dict) else None
        ok = writer.delete_txt_record(self._match_name(), value=value)
        self._send_empty(204 if ok else 404)

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


class _DMPHttpServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, store, bearer_token):
        super().__init__(addr, handler)
        self.store = store
        self.bearer_token = bearer_token


class DMPHttpApi:
    """Background HTTP server exposing publish/query/delete over REST."""

    def __init__(
        self,
        store: DNSRecordStore,
        *,
        host: str = "0.0.0.0",
        port: int = 8053,
        bearer_token: Optional[str] = None,
    ):
        self.store = store
        self.host = host
        self.port = port
        self.bearer_token = bearer_token
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
