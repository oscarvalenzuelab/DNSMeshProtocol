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

M9.2.1 — DNS UPDATE
-------------------
When the server is constructed with both a ``writer`` and a ``tsig_keyring``,
it also accepts RFC 2136 UPDATE messages signed with TSIG (RFC 8945). The
update flow:

  1. Parse incoming wire under the supplied keyring. dnspython raises on any
     TSIG failure (bad key, bad signature, bad time) — we map those to
     NOTAUTH and never touch the writer.
  2. Validate the zone in the UPDATE's zone section against ``allowed_zones``.
     A request to update a zone we don't claim authority for gets NOTAUTH.
  3. For each TXT RR in the update section, optionally consult
     ``update_authorizer`` (key_name, op, name) to gate per-key scope. M9.2.2
     plugs a real authorizer in here; without one, every record is allowed
     once TSIG passed.
  4. Apply ADD / DELETE through the supplied ``DNSRecordWriter``. Non-TXT RRs
     are ignored (we only manage TXT).

Updates without TSIG are REFUSED. Updates with a key the keyring doesn't
recognize land as NOTAUTH (TSIG verification failure path).
"""

from __future__ import annotations

import logging
import socketserver
import threading
from typing import Callable, List, Optional, Sequence, Tuple

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.rrset
import dns.tsig

from dmp.network.base import DNSRecordReader, DNSRecordWriter
from dmp.server.metrics import REGISTRY
from dmp.server.rate_limit import RateLimit, TokenBucketLimiter

log = logging.getLogger(__name__)

MAX_TXT_STRING = 255
DEFAULT_TTL = 60


def _split_for_txt_strings(value: str, max_len: int = MAX_TXT_STRING) -> list[bytes]:
    """Split a long value into ≤255-byte pieces so it fits TXT wire format."""
    raw = value.encode("utf-8")
    return [raw[i : i + max_len] for i in range(0, len(raw), max_len)] or [b""]


# M9.2.1 — UPDATE authorizer signature.
#
# Called once per RR in an incoming UPDATE after TSIG passed and the zone
# was accepted. ``key_name`` is the dnspython Name of the TSIG key used to
# authenticate the request (so the authorizer can scope a key to a subject
# / zone subtree). ``op`` is one of "add" or "delete". ``name`` is the
# fully-qualified owner name being modified. Returning False rejects just
# that RR with REFUSED for the whole UPDATE — partial application would
# leave the zone in an unpredictable state.
UpdateAuthorizer = Callable[[dns.name.Name, str, str], bool]


def _normalize_zone(zone: str) -> str:
    """Lowercase, strip trailing dots — matches the way owner names land
    after ``dns.name.Name.to_text(omit_final_dot=True)``."""
    return (zone or "").strip().rstrip(".").lower()


def _name_under_zone(name: str, zone: str) -> bool:
    """True iff ``name`` is the zone itself or a strict subdomain of it."""
    n = _normalize_zone(name)
    z = _normalize_zone(zone)
    if not z:
        return False
    return n == z or n.endswith("." + z)


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

        # Pass the keyring into ``from_wire`` so any TSIG signature on the
        # incoming message is verified at parse time. dnspython raises:
        #   - dns.tsig.PeerError (bad signature / time / truncation)
        #   - dns.message.UnknownTSIGKey (key name not in keyring)
        #   - dns.message.BadTSIG (malformed TSIG record)
        # All three map to NOTAUTH — the request was authenticated by
        # someone we can't or won't trust.
        #
        # When a keystore is wired in, build a fresh keyring per packet
        # so newly-minted keys authorize without restarting the server.
        # (Common case: a user just registered, dnspython needs to know
        # their key name on the very next UPDATE.) Stored keyrings stay
        # supported for tests that pass a static dict.
        keystore = self.server.tsig_keystore
        if keystore is not None:
            keyring = keystore.build_keyring()
        else:
            keyring = self.server.tsig_keyring
        try:
            query = dns.message.from_wire(data, keyring=keyring)
        except (
            dns.tsig.PeerError,
            dns.message.UnknownTSIGKey,
            dns.message.BadTSIG,
        ) as e:
            log.debug("TSIG verification failed: %s", e)
            REGISTRY.counter(
                "dmp_dns_queries_total",
                labels={"outcome": "tsig_failed"},
            )
            try:
                bounced = self._stub_response(data, dns.rcode.NOTAUTH)
            except Exception:
                return
            if bounced is not None:
                sock.sendto(bounced, self.client_address)
            return
        except dns.exception.DNSException as e:
            log.debug("unparseable DNS packet: %s", e)
            REGISTRY.counter(
                "dmp_dns_queries_total",
                labels={"outcome": "malformed"},
            )
            return

        try:
            if query.opcode() == dns.opcode.UPDATE:
                response = self._build_update_response(query)
            else:
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

    @staticmethod
    def _stub_response(data: bytes, rcode_value: int) -> Optional[bytes]:
        """Build a minimal response wire from a request whose body we
        couldn't fully parse (e.g. TSIG verification rejected it).

        We can't ``make_response`` on a parsed message because dnspython
        refused to parse the request — it raises rather than handing us
        a partial ``Message``. So we construct the 12-byte DNS header by
        hand: same ID and opcode as the request, QR=1, AA=0, all section
        counts zero, RCODE set to the supplied value. No question or
        answer payload — that's a valid NOTAUTH response per RFC 2136
        §3.8.
        """
        if len(data) < 12:
            return None
        msg_id = data[0:2]
        # Byte 2 carries QR (top bit) and opcode (next 4 bits) and AA,TC,RD.
        opcode = (data[2] >> 3) & 0x0F
        flag0 = 0x80 | (opcode << 3)  # QR=1, opcode=opcode, AA=0, TC=0, RD=0
        flag1 = rcode_value & 0x0F
        return bytes(msg_id) + bytes([flag0, flag1, 0, 0, 0, 0, 0, 0, 0, 0])

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

    # ------------------------------------------------------------------
    # M9.2.1 — UPDATE handling
    # ------------------------------------------------------------------

    def _build_update_response(
        self, query: dns.message.Message
    ) -> dns.message.Message:
        """Apply an RFC 2136 UPDATE to the writer.

        Preconditions checked here:
          - server has a writer + keyring (else REFUSED).
          - request carried a verified TSIG (else REFUSED — without TSIG
            an UPDATE is ambient-authority and we won't honor it).
          - request's zone section is in ``allowed_zones`` (else NOTAUTH).

        Per-RR checks:
          - non-TXT RR types are silently skipped (we only manage TXT).
          - per-RR ``update_authorizer(key_name, op, name)`` is consulted
            when set; a False result rejects the entire UPDATE so we
            never apply a partial change.

        Currently supported operations (RFC 2136 §2.5):
          - 2.5.1 Add to an RRset: TXT class IN, ttl > 0, with rdata
          - 2.5.4 Delete an RR from an RRset: TXT class NONE with rdata
          - 2.5.2 Delete an RRset: TXT class ANY with no rdata

        Prerequisite section (zone state assertions) is ignored for now
        — DMP records are append-only-by-content (publish_txt_record is
        idempotent), so a client doesn't need prereqs to write safely.
        """
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA

        writer = self.server.writer
        # Either a static keyring or a keystore qualifies — both unlock
        # the UPDATE path. The keystore's per-packet build runs in the
        # outer ``handle()`` for parse-time TSIG verification; we just
        # need to confirm one is wired here.
        keyring_present = (
            self.server.tsig_keystore is not None
            or self.server.tsig_keyring is not None
        )
        if writer is None or not keyring_present:
            response.set_rcode(dns.rcode.REFUSED)
            return response
        # Without a verified TSIG, we won't accept any update. dnspython
        # surfaces the verified key name on ``query.keyname``.
        key_name = getattr(query, "keyname", None)
        if not getattr(query, "had_tsig", False) or key_name is None:
            response.set_rcode(dns.rcode.REFUSED)
            return response

        zone_rrset = query.question  # UPDATE message reuses .question
        if not zone_rrset:
            response.set_rcode(dns.rcode.FORMERR)
            return response
        zone_text = _normalize_zone(zone_rrset[0].name.to_text(omit_final_dot=True))
        allowed = self.server.allowed_zones or ()
        if not any(zone_text == _normalize_zone(z) for z in allowed):
            response.set_rcode(dns.rcode.NOTAUTH)
            return response

        # Static authorizer wins (tests use this). Otherwise build a
        # fresh authorizer from the keystore so revokes and scope
        # updates land without a server restart.
        authorizer: Optional[UpdateAuthorizer] = self.server.update_authorizer
        if authorizer is None and self.server.tsig_keystore is not None:
            authorizer = self.server.tsig_keystore.build_authorizer()
        # Collect ops first so we can authorize all of them before
        # applying any. Halts on first auth failure.
        ops: List[Tuple[str, str, Optional[str], int]] = []
        for rrset in query.update:
            owner = rrset.name.to_text(omit_final_dot=True)
            # Owner names must be inside the UPDATE's declared zone
            # (RFC 2136 §3.4.1.3). Reject if not.
            if not _name_under_zone(owner, zone_text):
                response.set_rcode(dns.rcode.NOTZONE)
                return response
            if rrset.rdtype != dns.rdatatype.TXT:
                # We only manage TXT. Skip silently — a benign non-TXT
                # add/delete in a mixed UPDATE is ignored, not rejected.
                continue
            # dnspython parses UPDATE update-section RRs with the zone's
            # class (typically IN) and surfaces the wire class (NONE for
            # "delete RR from RRset", ANY for "delete RRset") on the
            # ``rrset.deleting`` attribute. ``None`` means "add".
            deleting = getattr(rrset, "deleting", None)
            if deleting is None:
                for rdata in rrset:
                    value = b"".join(rdata.strings).decode(
                        "utf-8", errors="replace"
                    )
                    ops.append(("add", owner, value, int(rrset.ttl) or DEFAULT_TTL))
            elif deleting == dns.rdataclass.NONE:
                # Delete a specific RR from the RRset (rdata must match).
                for rdata in rrset:
                    value = b"".join(rdata.strings).decode(
                        "utf-8", errors="replace"
                    )
                    ops.append(("delete", owner, value, 0))
            elif deleting == dns.rdataclass.ANY:
                # Delete the entire RRset at this owner.
                ops.append(("delete", owner, None, 0))
            else:
                response.set_rcode(dns.rcode.FORMERR)
                return response

        if authorizer is not None:
            for op, owner, _value, _ttl in ops:
                try:
                    if not authorizer(key_name, op, owner):
                        response.set_rcode(dns.rcode.REFUSED)
                        return response
                except Exception:
                    log.exception("update_authorizer raised; rejecting UPDATE")
                    response.set_rcode(dns.rcode.SERVFAIL)
                    return response

        for op, owner, value, ttl in ops:
            try:
                if op == "add" and value is not None:
                    writer.publish_txt_record(owner, value, ttl=ttl)
                elif op == "delete":
                    writer.delete_txt_record(owner, value=value)
            except Exception:
                log.exception("writer raised during UPDATE apply; SERVFAIL")
                response.set_rcode(dns.rcode.SERVFAIL)
                return response

        # NOERROR; an UPDATE response carries no answer/authority/etc.
        return response


class _ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Per-packet threaded UDP server with a bounded worker semaphore.

    Same rationale as the HTTP server: a raw `ThreadingMixIn` makes a
    thread per packet. A UDP flood (amplified off this server or just
    ordinary spam) would pre-create threads before the rate limiter
    runs. The semaphore caps concurrent handler threads; when saturated
    we drop the packet. On UDP there's no connection to close, so
    "drop" just means we don't spawn a handler.
    """

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address,
        handler_cls,
        reader,
        ttl,
        rate_limiter,
        max_concurrency,
        *,
        writer=None,
        tsig_keyring=None,
        tsig_keystore=None,
        allowed_zones=None,
        update_authorizer=None,
    ):
        super().__init__(server_address, handler_cls)
        self.reader = reader
        self.ttl = ttl
        self.rate_limiter = rate_limiter
        self.max_concurrency = max_concurrency
        self.writer = writer
        self.tsig_keyring = tsig_keyring
        self.tsig_keystore = tsig_keystore
        self.allowed_zones = allowed_zones or ()
        self.update_authorizer = update_authorizer
        self._semaphore = threading.Semaphore(max_concurrency)

    def process_request(self, request, client_address):
        if not self._semaphore.acquire(blocking=False):
            return
        t = threading.Thread(
            target=self._handle_with_release,
            args=(request, client_address),
            name="dmp-dns-handler",
            daemon=self.daemon_threads,
        )
        t.start()

    def _handle_with_release(self, request, client_address):
        try:
            self.process_request_thread(request, client_address)
        finally:
            self._semaphore.release()


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
        max_concurrency: int = 128,
        writer: Optional[DNSRecordWriter] = None,
        tsig_keyring=None,
        tsig_keystore=None,
        allowed_zones: Optional[Sequence[str]] = None,
        update_authorizer: Optional[UpdateAuthorizer] = None,
    ):
        """``writer``, a TSIG source, and ``allowed_zones`` together
        switch on RFC 2136 UPDATE handling. With any of them missing
        the server still answers TXT queries but REFUSES updates.

        TSIG sources (mutually exclusive — pass at most one):
          - ``tsig_keyring``: static dict[Name, Key] for tests.
          - ``tsig_keystore``: an object exposing ``build_keyring()`` +
            ``build_authorizer()`` (e.g. :class:`TSIGKeyStore`). The
            handler calls these per UPDATE so newly-minted keys
            authorize without restarting the server.

        ``update_authorizer`` is an optional per-RR gate that overrides
        whatever the keystore returns. Tests pass it directly; in
        production the keystore-built authorizer is preferred.
        """
        self.reader = reader
        self.host = host
        self.port = port
        self.ttl = ttl
        self.rate_limiter = (
            TokenBucketLimiter(rate_limit)
            if rate_limit and rate_limit.enabled
            else None
        )
        self.max_concurrency = int(max_concurrency)
        self.writer = writer
        self.tsig_keyring = tsig_keyring
        self.tsig_keystore = tsig_keystore
        self.allowed_zones = tuple(allowed_zones or ())
        self.update_authorizer = update_authorizer
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
            self.max_concurrency,
            writer=self.writer,
            tsig_keyring=self.tsig_keyring,
            tsig_keystore=self.tsig_keystore,
            allowed_zones=self.allowed_zones,
            update_authorizer=self.update_authorizer,
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
