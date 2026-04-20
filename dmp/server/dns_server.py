"""Minimal UDP DNS server for DMP.

Answers TXT queries from a DNSRecordReader. Not a full recursive or
authoritative server — it only handles the one RR type DMP uses (TXT) and
returns NXDOMAIN or empty answers for everything else.

Values longer than 255 bytes are split across multiple TXT strings per record,
which is the wire-format way to carry >255-byte data in a TXT record. Most
clients (including dnspython's resolver) concatenate multi-string TXT values
transparently.

Port 53 is privileged on Linux. Default port is 5353 (dev-friendly); operators
can remap in Docker with `-p 53:5353/udp` or grant CAP_NET_BIND_SERVICE.
"""

from __future__ import annotations

import logging
import socketserver
import threading
from typing import Optional

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.rrset

from dmp.network.base import DNSRecordReader
from dmp.server.metrics import REGISTRY
from dmp.server.rate_limit import RateLimit, TokenBucketLimiter


log = logging.getLogger(__name__)

MAX_TXT_STRING = 255
DEFAULT_TTL = 60


def _split_for_txt_strings(value: str, max_len: int = MAX_TXT_STRING) -> list[bytes]:
    """Split a long value into ≤255-byte pieces so it fits TXT wire format."""
    raw = value.encode("utf-8")
    return [raw[i : i + max_len] for i in range(0, len(raw), max_len)] or [b""]


class _DMPRequestHandler(socketserver.DatagramRequestHandler):
    """Handles one UDP DNS query per call."""

    server: "_ThreadingUDPServer"  # set by socketserver

    def handle(self) -> None:
        data, sock = self.request
        limiter = self.server.rate_limiter
        client_ip = self.client_address[0]
        if limiter is not None and not limiter.allow(client_ip):
            REGISTRY.counter(
                "dmp_dns_queries_total",
                "DMP DNS queries by outcome",
                labels={"outcome": "rate_limited"},
            )
            return  # UDP — just drop.

        try:
            query = dns.message.from_wire(data)
        except dns.exception.DNSException as e:
            log.debug("unparseable DNS packet: %s", e)
            REGISTRY.counter(
                "dmp_dns_queries_total",
                labels={"outcome": "malformed"},
            )
            return

        try:
            response = self._build_response(query)
        except Exception:
            log.exception("error building DNS response")
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)

        rcode_name = dns.rcode.to_text(response.rcode())
        REGISTRY.counter(
            "dmp_dns_queries_total",
            "DMP DNS queries by outcome",
            labels={"outcome": rcode_name.lower()},
        )
        sock.sendto(response.to_wire(), self.client_address)

    def _build_response(self, query: dns.message.Message) -> dns.message.Message:
        reader: DNSRecordReader = self.server.reader
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA  # authoritative answer

        if not query.question:
            response.set_rcode(dns.rcode.FORMERR)
            return response

        # Only handle the first question (standard DNS behavior).
        question = query.question[0]
        qname = question.name.to_text(omit_final_dot=True)

        if question.rdtype != dns.rdatatype.TXT:
            # We only serve TXT. Everything else → NOERROR with empty answer.
            return response

        values = reader.query_txt_record(qname)
        if not values:
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response

        ttl = self.server.ttl
        strings_per_record = [_split_for_txt_strings(v) for v in values]
        rrset = dns.rrset.from_rdata_list(
            name=question.name,
            ttl=ttl,
            rdatas=[
                dns.rdtypes.ANY.TXT.TXT(
                    rdclass=dns.rdataclass.IN,
                    rdtype=dns.rdatatype.TXT,
                    strings=strings,
                )
                for strings in strings_per_record
            ],
        )
        response.answer.append(rrset)
        return response


class _ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Per-request threaded UDP server; carries the reader + ttl on self."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_cls, reader, ttl, rate_limiter):
        super().__init__(server_address, handler_cls)
        self.reader = reader
        self.ttl = ttl
        self.rate_limiter = rate_limiter


class DMPDnsServer:
    """UDP DNS server that serves TXT records from a DNSRecordReader.

    Use as a context manager or manage start/stop directly. The server runs
    on a background thread so it doesn't block the caller.
    """

    def __init__(
        self,
        reader: DNSRecordReader,
        *,
        host: str = "0.0.0.0",
        port: int = 5353,
        ttl: int = DEFAULT_TTL,
        rate_limit: Optional[RateLimit] = None,
    ):
        self.reader = reader
        self.host = host
        self.port = port
        self.ttl = ttl
        self.rate_limiter = (
            TokenBucketLimiter(rate_limit) if rate_limit and rate_limit.enabled else None
        )
        self._server: Optional[_ThreadingUDPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def server_address(self) -> tuple[str, int]:
        if self._server is None:
            return (self.host, self.port)
        return self._server.server_address  # type: ignore[return-value]

    def start(self) -> None:
        if self._server is not None:
            return
        self._server = _ThreadingUDPServer(
            (self.host, self.port),
            _DMPRequestHandler,
            self.reader,
            self.ttl,
            self.rate_limiter,
        )
        # If the caller asked for port 0, pick up the actual bound port.
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="dmp-dns-server",
            daemon=True,
        )
        self._thread.start()
        log.info("DMP DNS server listening on %s:%d/udp", self.host, self.port)

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def __enter__(self) -> "DMPDnsServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
