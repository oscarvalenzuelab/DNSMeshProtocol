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
import time
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
# Cap on the lifetime an anonymous claim record may be published with.
# Mirrors the operator's HTTP-side ``max_ttl`` (M5.5 default 1 day) so
# a sender can't write a far-future ``exp`` and have the provider host
# the record indefinitely. Operator override via DMP_CLAIM_MAX_TTL.
DEFAULT_CLAIM_MAX_TTL = 86_400
# Resource caps applied to TSIG-authorized UPDATE writes — same
# defaults the HTTP /v1/records publish path uses (M5.5 history).
# Codex round-16 P1: without these, a registered user could bypass
# operator storage policy via DNS UPDATE.
DEFAULT_UPDATE_MAX_TTL = 86_400 * 7
DEFAULT_UPDATE_MAX_VALUE_BYTES = 16_384
DEFAULT_UPDATE_MAX_VALUES_PER_NAME = 256


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


# ---------------------------------------------------------------------------
# M9.2.6 — un-TSIG'd claim-record publish surface.
#
# The on-zone owner pattern for first-contact claim records is
# ``claim-{slot}.mb-{hash12(recipient_id)}.{provider_zone}``. The TXT
# value is a signed ``ClaimRecord`` — the Ed25519 sender signature
# IS the on-zone authentication, so requiring TSIG on top of that
# would be redundant AND would break first-contact reach (a sender
# almost never has a TSIG account on the recipient's claim provider).
# Other write surfaces stay TSIG-only; the unauthenticated path is
# narrowed to claim-record ADDs whose wire actually verifies.
# ---------------------------------------------------------------------------


def _is_claim_owner(owner: str, zone: str) -> bool:
    """True iff ``owner`` matches ``claim-<slot>.mb-<hash12>.<zone>``."""
    return _claim_owner_hash12(owner, zone) is not None


def _claim_owner_hash12(owner: str, zone: str) -> Optional[str]:
    """Return the recipient hash12 from a claim owner, or None on shape mismatch.

    Used both as the owner-shape gate (M8.3 + M10) and as the rate-limit
    bucket key — per-recipient throttling needs the hash so a noisy
    sender targeting one recipient can't burn the whole zone's budget.
    """
    n = _normalize_zone(owner)
    z = _normalize_zone(zone)
    if not z or not (n == z or n.endswith("." + z)):
        return None
    relative = n[: -len("." + z)] if n.endswith("." + z) else ""
    parts = relative.split(".")
    if len(parts) != 2:
        return None
    slot_label, mailbox_label = parts
    if not slot_label.startswith("claim-"):
        return None
    slot = slot_label[len("claim-") :]
    if not slot.isdigit():
        return None
    if not mailbox_label.startswith("mb-"):
        return None
    h = mailbox_label[len("mb-") :]
    if len(h) != 12 or not all(c in "0123456789abcdef" for c in h):
        return None
    return h


def _is_signed_claim_wire(value: Optional[str]) -> bool:
    """True iff ``value`` parses as a signed ``ClaimRecord`` wire.

    Imports ``dmp.core.claim`` lazily so the dns_server module stays
    usable in environments that haven't installed the claim layer
    (tests, minimal-build images).
    """
    return _verified_claim_record(value) is not None


def _verified_claim_record(value: Optional[str]):
    """Parse + verify a claim wire. Returns the ``ClaimRecord`` or None."""
    if not isinstance(value, str) or not value:
        return None
    try:
        from dmp.core.claim import ClaimRecord
    except Exception:
        return None
    try:
        return ClaimRecord.parse_and_verify(value)
    except Exception:
        return None


def _claim_within_lifetime_cap(value: str, *, max_ttl: int, now: int) -> bool:
    """True iff the wire's ``exp - now`` and the requested DNS TTL
    both stay under ``max_ttl``.

    Stops a sender from publishing a 10-year claim that pins a
    provider's RRset until expiry. Mirrors the M5.5 HTTP path's
    ``max_ttl`` enforcement (codex round-9 P2).
    """
    rec = _verified_claim_record(value)
    if rec is None:
        return False
    if max_ttl <= 0:
        return True
    return int(rec.exp) - int(now) <= int(max_ttl)


class _DMPRequestHandler(socketserver.DatagramRequestHandler):
    """Handles one UDP DNS query per call."""

    server: "_ThreadingUDPServer"  # set by socketserver

    def handle(self) -> None:
        # Thin: framing-specific (UDP datagram → bytes). Heavy
        # lifting (rate-limit, TSIG verify, response building) is in
        # ``_process_dns_query`` so the TCP handler can share it.
        data, sock = self.request
        client_ip = self.client_address[0]
        response_bytes = _process_dns_query(self, data, client_ip, transport="udp")
        if response_bytes is not None:
            sock.sendto(response_bytes, self.client_address)

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

    def _build_update_response(self, query: dns.message.Message) -> dns.message.Message:
        """Apply an RFC 2136 UPDATE to the writer.

        Auth model (after M9.2.6):

          - The default path requires TSIG. Verified key + per-key
            scope governs which owner names the UPDATE may mutate.
          - One narrow exception: claim records at
            ``claim-N.mb-<hash12>.<zone>``. The wire ITSELF is a
            signed ``ClaimRecord`` (Ed25519); the on-zone authority
            is delegated to that signature. We accept un-TSIG'd
            UPDATEs whose ops are exclusively claim-record adds with
            verifiable wires. This lets a sender publish a first-
            contact claim at a provider it has no account on,
            without weakening any other write surface.

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
        if writer is None:
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

        # Collect ops up front so we can decide auth disposition based
        # on the FULL set, not just the first op.
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
                    value = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    ops.append(("add", owner, value, int(rrset.ttl) or DEFAULT_TTL))
            elif deleting == dns.rdataclass.NONE:
                # Delete a specific RR from the RRset (rdata must match).
                for rdata in rrset:
                    value = b"".join(rdata.strings).decode("utf-8", errors="replace")
                    ops.append(("delete", owner, value, 0))
            elif deleting == dns.rdataclass.ANY:
                # Delete the entire RRset at this owner.
                ops.append(("delete", owner, None, 0))
            else:
                response.set_rcode(dns.rcode.FORMERR)
                return response

        # Resource limits — apply to ADD ops on every UPDATE path
        # (TSIG'd or not). Codex round-16 P1: an authenticated user
        # could otherwise bypass operator storage policy
        # (max_ttl, max_value_bytes, max_values_per_name) via the
        # DNS UPDATE write surface.
        max_ttl = int(getattr(self.server, "update_max_ttl", DEFAULT_UPDATE_MAX_TTL))
        max_value_bytes = int(
            getattr(
                self.server,
                "update_max_value_bytes",
                DEFAULT_UPDATE_MAX_VALUE_BYTES,
            )
        )
        max_values_per_name = int(
            getattr(
                self.server,
                "update_max_values_per_name",
                DEFAULT_UPDATE_MAX_VALUES_PER_NAME,
            )
        )
        adds_per_owner: dict = {}

        # Codex round-17 P2: ``max_values_per_name`` must include
        # records ALREADY at this owner, not just the adds in the
        # current packet. Otherwise N single-record UPDATEs grow the
        # RRset past the cap. We probe the writer-as-reader (most
        # writers also implement ``DNSRecordReader``) for the
        # existing count; backends that don't expose a query path
        # gracefully fall back to per-packet counting. We also check
        # the server's primary reader as a secondary source.
        def _existing_count(owner_name: str) -> int:
            for src in (writer, getattr(self.server, "reader", None)):
                if src is None:
                    continue
                q = getattr(src, "query_txt_record", None)
                if not callable(q):
                    continue
                try:
                    values = q(owner_name)
                except Exception:
                    continue
                if values is not None:
                    return len(values)
            return 0

        for op, owner, value, ttl in ops:
            if op != "add":
                continue
            if max_value_bytes > 0 and value is not None:
                if len(value.encode("utf-8")) > max_value_bytes:
                    response.set_rcode(dns.rcode.REFUSED)
                    return response
            if max_ttl > 0 and ttl > max_ttl:
                response.set_rcode(dns.rcode.REFUSED)
                return response
            if max_values_per_name > 0:
                if owner not in adds_per_owner:
                    # First time we see this owner in this UPDATE —
                    # seed the running count with whatever's in the
                    # store today (including duplicates we'd dedupe).
                    adds_per_owner[owner] = _existing_count(owner)
                # Distinct-value adds count toward the cap. Repeated
                # adds of an existing value collapse on the writer
                # side (publish_txt_record dedupes), so they
                # technically don't grow the RRset — but counting
                # them stays conservative and matches what the HTTP
                # publish path historically did.
                adds_per_owner[owner] += 1
                if adds_per_owner[owner] > max_values_per_name:
                    response.set_rcode(dns.rcode.REFUSED)
                    return response

        # Auth disposition.
        had_tsig = bool(getattr(query, "had_tsig", False))
        key_name = getattr(query, "keyname", None)
        keyring_present = (
            self.server.tsig_keystore is not None
            or self.server.tsig_keyring is not None
        )

        if had_tsig and key_name is not None and keyring_present:
            # Standard TSIG path: per-key scope authorization.
            authorizer: Optional[UpdateAuthorizer] = self.server.update_authorizer
            if authorizer is None and self.server.tsig_keystore is not None:
                authorizer = self.server.tsig_keystore.build_authorizer()
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
        else:
            # Un-TSIG'd path: only the self-authenticating claim
            # surface is acceptable, AND only when the operator has
            # opted into one of the two claim-acceptance roles:
            #   - CAP_CLAIM_PROVIDER  (M8.3 first-contact provider tier;
            #     gated on DMP_CLAIM_PROVIDER)
            #   - M10 receiver-zone notifications (gated on
            #     DMP_RECEIVER_CLAIM_NOTIFICATIONS)
            #
            # Both modes use the same owner-name shape
            # ``claim-{slot}.mb-{hash12}.<served-zone>`` and the same
            # signed wire — what differs is which zone the records
            # land in (provider zone vs the recipient's home zone).
            # A node with neither flag must NOT silently become an
            # anonymous claim sink just because DNS UPDATE was turned
            # on for its own TSIG'd users (codex round-9 P2).
            claim_provider_on = bool(
                getattr(self.server, "claim_publish_enabled", False)
            )
            receiver_claim_on = bool(
                getattr(self.server, "receiver_claim_publish_enabled", False)
            )
            if not (claim_provider_on or receiver_claim_on):
                response.set_rcode(dns.rcode.REFUSED)
                return response
            if not ops:
                response.set_rcode(dns.rcode.REFUSED)
                return response
            cap = int(getattr(self.server, "claim_max_ttl", DEFAULT_CLAIM_MAX_TTL))
            now_i = int(time.time())
            claim_limiter = getattr(self.server, "claim_rate_limiter", None)
            # Codex round-3 P1: when the operator opted OUT of the M8.3
            # public first-contact provider role (DMP_CLAIM_PROVIDER=0)
            # but opted IN to M10 receiver-zone notifications, the
            # un-TSIG'd accept path MUST restrict writes to recipient
            # hashes that correspond to registered users on this zone.
            # Without that, M10 would silently re-open the public
            # write surface that DMP_CLAIM_PROVIDER=0 was supposed to
            # close. The keystore tracks the registered hash12 set
            # (each user's TSIG scope includes ``mb-{hash12}.{zone}``).
            # When BOTH flags are on (operator wants the open M8.3
            # provider tier AND M10 for their own users), the open
            # provider role wins and any signed claim is acceptable.
            allowed_recipient_hashes: Optional[set] = None
            if receiver_claim_on and not claim_provider_on:
                keystore = getattr(self.server, "tsig_keystore", None)
                if keystore is not None and hasattr(
                    keystore, "registered_recipient_hashes"
                ):
                    try:
                        allowed_recipient_hashes = keystore.registered_recipient_hashes(
                            zone_text
                        )
                    except Exception:
                        log.exception(
                            "tsig_keystore.registered_recipient_hashes raised; "
                            "treating as empty set (claim writes will be REFUSED)"
                        )
                        allowed_recipient_hashes = set()
                else:
                    # No keystore → no notion of registered users →
                    # nothing to admit. Refuse all writes rather than
                    # silently accept (defense-in-depth: M10-only mode
                    # without a registry is misconfigured).
                    allowed_recipient_hashes = set()
            applied: List[Tuple[str, str, Optional[str], int]] = []
            for op, owner, value, ttl in ops:
                if op != "add":
                    response.set_rcode(dns.rcode.REFUSED)
                    return response
                hash12 = _claim_owner_hash12(owner, zone_text)
                if hash12 is None:
                    response.set_rcode(dns.rcode.REFUSED)
                    return response
                if (
                    allowed_recipient_hashes is not None
                    and hash12 not in allowed_recipient_hashes
                ):
                    log.info(
                        "M10-only claim UPDATE rejected: hash %s not "
                        "in registered users for zone=%s",
                        hash12,
                        zone_text,
                    )
                    response.set_rcode(dns.rcode.REFUSED)
                    return response
                if not _claim_within_lifetime_cap(value, max_ttl=cap, now=now_i):
                    # Wire wasn't a verifiable claim OR claim's exp is
                    # past the operator's lifetime cap — REFUSE rather
                    # than silently accept a far-future record that
                    # would pin the RRset against retention policy
                    # (codex round-9 P2).
                    response.set_rcode(dns.rcode.REFUSED)
                    return response
                # Per-recipient-hash rate limit (M10 spec). Keyed on
                # the hash12 in the owner name so a single noisy sender
                # / recipient combo can't burn the whole zone's budget.
                # Exhaustion is SERVFAIL (transient backoff signal),
                # distinct from REFUSED for shape violations — a
                # legitimate sender can retry later, a forgery cannot.
                if claim_limiter is not None and not claim_limiter.allow(hash12):
                    log.info(
                        "claim UPDATE rate-limited for recipient hash %s "
                        "(zone=%s) — answering SERVFAIL",
                        hash12,
                        zone_text,
                    )
                    response.set_rcode(dns.rcode.SERVFAIL)
                    return response
                # Clamp the requested DNS TTL to the operator's cap so a
                # client can't request a 10-year cache lifetime.
                clamped_ttl = (
                    min(int(ttl) if ttl else DEFAULT_TTL, cap) if cap else int(ttl)
                )
                applied.append((op, owner, value, clamped_ttl))
            ops = applied

        for op, owner, value, ttl in ops:
            try:
                if op == "add" and value is not None:
                    ok = writer.publish_txt_record(owner, value, ttl=ttl)
                elif op == "delete":
                    ok = writer.delete_txt_record(owner, value=value)
                else:
                    ok = False
            except Exception:
                log.exception("writer raised during UPDATE apply; SERVFAIL")
                response.set_rcode(dns.rcode.SERVFAIL)
                return response
            # Codex round-12 P1 + round-16 P2: a writer that returns
            # False (e.g. cluster fanout missing quorum, transport
            # error against a peer) means the record DID NOT persist.
            # Returning NOERROR would silently lose the write — the
            # sender treats the UPDATE as committed and never retries.
            # Surface the failure as SERVFAIL on BOTH adds and deletes
            # so the caller can fall back / retry.
            #
            # The InMemoryDNSStore returns False on
            # ``delete_txt_record`` for "no record matched" (a benign
            # no-op), but the SqliteMailboxStore + FanoutWriter return
            # False only on real failures — the conservative choice
            # is SERVFAIL across the board and let the writer
            # implementation distinguish if needed.
            if not ok:
                log.info(
                    "writer.%s returned False for %s — answering "
                    "SERVFAIL so the client can retry",
                    "publish_txt_record" if op == "add" else "delete_txt_record",
                    owner,
                )
                response.set_rcode(dns.rcode.SERVFAIL)
                return response

        # NOERROR; an UPDATE response carries no answer/authority/etc.
        return response


def _recv_exact(sock, n: int) -> Optional[bytes]:
    """Read exactly ``n`` bytes from a stream socket or return None on
    EOF / short read. Caller is responsible for setting the socket
    timeout."""
    chunks: List[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _process_dns_query(
    handler, data: bytes, client_ip: str, *, transport: str = "udp"
) -> Optional[bytes]:
    """Shared core for the UDP and TCP handlers.

    Validates rate limit, parses the wire (with TSIG verification when
    a keyring is configured), routes to the appropriate response
    builder, increments the metrics counter, and returns the
    wire-format response bytes. Returns ``None`` when the request
    should be silently dropped (rate-limited, malformed past the
    point where we can build a stub response, etc.). Callers are
    responsible for transport-specific framing — UDP sends the bytes
    directly; TCP prefixes them with a 2-byte length.

    ``transport`` distinguishes UDP from TCP. UDP responses that
    exceed the requester's advertised payload size are truncated to
    a header-only stub with the ``TC`` (truncation) flag set —
    standard DNS signaling that tells RFC-compliant resolvers to
    retry the query over TCP. Without this signal, recursors with
    DNSSEC-validation or strict-RFC behavior (Google 8.8.8.8,
    Level3) just see an oversized UDP datagram and return empty to
    their caller, defeating the whole point of having a TCP
    listener. TCP responses are never truncated — by spec, TCP
    framing already supports up to 65535 bytes.

    ``handler`` is whichever request handler is calling us. Both
    handlers expose a compatible ``self.server`` (configured by
    ``_ThreadingUDPServer`` / ``_ThreadingTCPServer``) and the same
    ``_build_response`` / ``_build_update_response`` methods, so the
    same function works for either transport.
    """
    server = handler.server
    limiter = server.rate_limiter
    if limiter is not None and not limiter.allow(client_ip):
        REGISTRY.counter(
            "dmp_dns_queries_total",
            "DMP DNS queries by outcome",
            labels={"outcome": "rate_limited"},
        )
        return None

    # Pass the keyring into ``from_wire`` so any TSIG signature on
    # the incoming message is verified at parse time. dnspython raises:
    #   - dns.tsig.PeerError (bad signature / time / truncation)
    #   - dns.message.UnknownTSIGKey (key name not in keyring)
    #   - dns.message.BadTSIG (malformed TSIG record)
    # All three map to NOTAUTH — the request was authenticated by
    # someone we can't or won't trust.
    #
    # When a keystore is wired in, build a fresh keyring per packet
    # so newly-minted keys authorize without restarting the server.
    keystore = server.tsig_keystore
    if keystore is not None:
        keyring = keystore.build_keyring()
    else:
        keyring = server.tsig_keyring
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
            return _DMPRequestHandler._stub_response(data, dns.rcode.NOTAUTH)
        except Exception:
            return None
    except dns.exception.DNSException as e:
        log.debug("unparseable DNS packet: %s", e)
        REGISTRY.counter(
            "dmp_dns_queries_total",
            labels={"outcome": "malformed"},
        )
        return None

    try:
        if query.opcode() == dns.opcode.UPDATE:
            response = handler._build_update_response(query)
        else:
            response = handler._build_response(query)
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
    return _serialize_response(response, query, transport)


def _serialize_response(
    response: dns.message.Message, query: dns.message.Message, transport: str
) -> bytes:
    """Wire-serialize ``response`` with transport-aware truncation.

    UDP: cap at the requester's advertised payload size (EDNS0 OPT
    record's UDP buffer, or the RFC 1035 default of 512 bytes if no
    OPT was present). If the full response wouldn't fit, replace it
    with a header-only stub carrying ``TC=1`` so the requester knows
    to retry over TCP.

    TCP: no cap. DNS-over-TCP framing supports messages up to
    65535 bytes per RFC 1035 §4.2.2.
    """
    if transport == "tcp":
        return response.to_wire()

    # UDP. EDNS0 advertised buffer size, with sensible fallbacks.
    udp_size = getattr(query, "payload", None)
    if not isinstance(udp_size, int) or udp_size <= 0:
        # No EDNS0 OPT record → RFC 1035 hard limit of 512.
        udp_size = 512
    try:
        return response.to_wire(max_size=udp_size)
    except dns.exception.TooBig:
        truncated = dns.message.make_response(query)
        truncated.flags |= dns.flags.TC
        # Don't echo any answer / authority / additional — by spec
        # the resolver should retry over TCP and ignore everything
        # except the header.
        return truncated.to_wire()


class _DMPTCPRequestHandler(socketserver.BaseRequestHandler):
    """Handles one DNS-over-TCP query per connection.

    DNS over TCP (RFC 1035 §4.2.2 + RFC 7766) frames every message
    with a 2-byte big-endian length prefix. We support the simplest
    one-query-per-connection path: read the length prefix, read the
    message body, route through ``_process_dns_query``, write back
    the length-prefixed response, close.

    RFC 7766 also allows pipelining multiple queries on a single
    connection; we don't implement that — recursive resolvers fall
    back to TCP only when UDP truncates, and in that fallback path
    they typically issue one query per connection. Pipelining is a
    pure-throughput optimization for the high-traffic case and not
    on the critical path for correctness.
    """

    server: "_ThreadingTCPServer"  # set by socketserver

    # Reuse the same response-building logic the UDP handler has.
    # The build methods only read from ``self.server.*``, which both
    # ``_ThreadingUDPServer`` and ``_ThreadingTCPServer`` expose with
    # the same attribute names. Aliasing at class level binds them
    # like normal methods when called on an instance.
    _build_response = _DMPRequestHandler._build_response
    _build_update_response = _DMPRequestHandler._build_update_response

    # Bound the per-connection read so a slow / hostile client can't
    # tie up a worker thread waiting for bytes that never come.
    _CONNECTION_READ_TIMEOUT_S = 5.0
    # Cap the message length we'll accept. RFC 1035 says DNS messages
    # are at most 65535 bytes anyway; this is just defense in depth.
    _MAX_MESSAGE_BYTES = 65535

    def handle(self) -> None:
        try:
            self.request.settimeout(self._CONNECTION_READ_TIMEOUT_S)
        except Exception:
            pass
        client_ip = self.client_address[0]

        try:
            length_prefix = _recv_exact(self.request, 2)
        except (TimeoutError, ConnectionError, OSError):
            return
        if length_prefix is None or len(length_prefix) < 2:
            return
        length = int.from_bytes(length_prefix, "big")
        if length == 0 or length > self._MAX_MESSAGE_BYTES:
            return

        try:
            data = _recv_exact(self.request, length)
        except (TimeoutError, ConnectionError, OSError):
            return
        if data is None or len(data) != length:
            return

        response_bytes = _process_dns_query(self, data, client_ip, transport="tcp")
        if response_bytes is None:
            return
        try:
            self.request.sendall(
                len(response_bytes).to_bytes(2, "big") + response_bytes
            )
        except (ConnectionError, OSError):
            return


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
        claim_publish_enabled=False,
        receiver_claim_publish_enabled=False,
        claim_max_ttl=DEFAULT_CLAIM_MAX_TTL,
        claim_rate_limiter=None,
        update_max_ttl=DEFAULT_UPDATE_MAX_TTL,
        update_max_value_bytes=DEFAULT_UPDATE_MAX_VALUE_BYTES,
        update_max_values_per_name=DEFAULT_UPDATE_MAX_VALUES_PER_NAME,
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
        self.claim_publish_enabled = bool(claim_publish_enabled)
        self.receiver_claim_publish_enabled = bool(receiver_claim_publish_enabled)
        self.claim_max_ttl = int(claim_max_ttl)
        self.claim_rate_limiter = claim_rate_limiter
        self.update_max_ttl = int(update_max_ttl)
        self.update_max_value_bytes = int(update_max_value_bytes)
        self.update_max_values_per_name = int(update_max_values_per_name)
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


class _ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Per-connection threaded TCP server with the same bounded
    worker semaphore as the UDP variant.

    DNS over TCP exists primarily as the fallback path when a UDP
    response would exceed the negotiated buffer (TC=1 → retry over
    TCP). Recursive resolvers expect this to work; without it,
    large RRsets like ``_dnsmesh-seen.<zone>`` can't propagate
    through any RFC-strict resolver.

    Mirror of ``_ThreadingUDPServer`` so callers can reuse the same
    state attributes (``reader``, ``rate_limiter``, ``tsig_*``,
    ``allowed_zones``, ``writer``, claim/update caps). The handler
    classes read these attributes off ``self.server.*``, transport-
    agnostic.
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
        claim_publish_enabled=False,
        receiver_claim_publish_enabled=False,
        claim_max_ttl=DEFAULT_CLAIM_MAX_TTL,
        claim_rate_limiter=None,
        update_max_ttl=DEFAULT_UPDATE_MAX_TTL,
        update_max_value_bytes=DEFAULT_UPDATE_MAX_VALUE_BYTES,
        update_max_values_per_name=DEFAULT_UPDATE_MAX_VALUES_PER_NAME,
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
        self.claim_publish_enabled = bool(claim_publish_enabled)
        self.receiver_claim_publish_enabled = bool(receiver_claim_publish_enabled)
        self.claim_max_ttl = int(claim_max_ttl)
        self.claim_rate_limiter = claim_rate_limiter
        self.update_max_ttl = int(update_max_ttl)
        self.update_max_value_bytes = int(update_max_value_bytes)
        self.update_max_values_per_name = int(update_max_values_per_name)
        self._semaphore = threading.Semaphore(max_concurrency)

    def process_request(self, request, client_address):
        if not self._semaphore.acquire(blocking=False):
            try:
                request.close()
            except Exception:
                pass
            return
        t = threading.Thread(
            target=self._handle_with_release,
            args=(request, client_address),
            name="dmp-dns-tcp-handler",
            daemon=self.daemon_threads,
        )
        t.start()

    def _handle_with_release(self, request, client_address):
        try:
            self.process_request_thread(request, client_address)
        finally:
            self._semaphore.release()


class DMPDnsServer:
    """DNS server that serves TXT records from a DNSRecordReader.

    Listens on UDP and (by default) TCP at the same port. UDP is the
    primary path for almost all queries; TCP handles the fallback
    when UDP responses are truncated (RFC 1035 §4.2.2 + RFC 7766) —
    notably, large RRsets like ``_dnsmesh-seen.<zone>`` that exceed
    the negotiated UDP buffer. Set ``tcp_enabled=False`` to skip the
    TCP listener (e.g. tests that don't exercise the TCP path).

    Use as a context manager or manage start/stop directly. The
    server runs on background threads so it doesn't block the
    caller.
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
        claim_publish_enabled: bool = False,
        receiver_claim_publish_enabled: bool = False,
        claim_max_ttl: int = DEFAULT_CLAIM_MAX_TTL,
        claim_rate_limit: Optional[RateLimit] = None,
        update_max_ttl: int = DEFAULT_UPDATE_MAX_TTL,
        update_max_value_bytes: int = DEFAULT_UPDATE_MAX_VALUE_BYTES,
        update_max_values_per_name: int = DEFAULT_UPDATE_MAX_VALUES_PER_NAME,
        tcp_enabled: bool = True,
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
        # M9.2.6 round-9 P2: anonymous claim-record UPDATE writes are
        # gated on this opt-in flag. DMPNode wires it on iff the
        # operator has CAP_CLAIM_PROVIDER enabled (claim_provider_zone
        # non-empty AND DMP_CLAIM_PROVIDER not set to off). A node
        # that wants DNS UPDATE for its own users but does NOT want to
        # accept first-contact claims from arbitrary senders leaves
        # this False and the un-TSIG'd path stays REFUSED.
        self.claim_publish_enabled = bool(claim_publish_enabled)
        # M10 — receiver-zone claim notifications (DMP_RECEIVER_CLAIM_NOTIFICATIONS).
        # Independent of CAP_CLAIM_PROVIDER: a node can serve M10 claims for
        # its own users without taking on the M8.3 first-contact provider
        # role for arbitrary recipients (or vice versa).
        self.receiver_claim_publish_enabled = bool(receiver_claim_publish_enabled)
        self.claim_max_ttl = int(claim_max_ttl)
        # Per-recipient-hash token bucket on un-TSIG'd claim writes
        # (covers both M8.3 and M10 surfaces). Hash12 from the owner
        # name is the bucket key. Disabled rate limit → no throttling.
        self.claim_rate_limiter = (
            TokenBucketLimiter(claim_rate_limit)
            if claim_rate_limit and claim_rate_limit.enabled
            else None
        )
        self.update_max_ttl = int(update_max_ttl)
        self.update_max_value_bytes = int(update_max_value_bytes)
        self.update_max_values_per_name = int(update_max_values_per_name)
        self.tcp_enabled = bool(tcp_enabled)
        self._server: Optional[_ThreadingUDPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._tcp_server: Optional[_ThreadingTCPServer] = None
        self._tcp_thread: Optional[threading.Thread] = None

    @property
    def server_address(self) -> tuple[str, int]:
        if self._server is None:
            return (self.host, self.port)
        return self._server.server_address  # type: ignore[return-value]

    def _server_kwargs(self) -> dict:
        """Common ``__init__`` kwargs shared by the UDP + TCP server
        constructors. Both reuse the same state attributes that the
        request handlers read off ``self.server.*``."""
        return {
            "writer": self.writer,
            "tsig_keyring": self.tsig_keyring,
            "tsig_keystore": self.tsig_keystore,
            "allowed_zones": self.allowed_zones,
            "update_authorizer": self.update_authorizer,
            "claim_publish_enabled": self.claim_publish_enabled,
            "receiver_claim_publish_enabled": self.receiver_claim_publish_enabled,
            "claim_max_ttl": self.claim_max_ttl,
            "claim_rate_limiter": self.claim_rate_limiter,
            "update_max_ttl": self.update_max_ttl,
            "update_max_value_bytes": self.update_max_value_bytes,
            "update_max_values_per_name": self.update_max_values_per_name,
        }

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
            **self._server_kwargs(),
        )
        # If the caller asked for port 0, pick up the actual bound port.
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="dmp-dns-server",
            daemon=True,
        )
        self._thread.start()

        if self.tcp_enabled:
            # TCP listens on the same host:port. The OS allows UDP +
            # TCP to coexist on the same port — they're separate
            # protocol families. We bind to the resolved port so that
            # if the caller passed port=0 we use whatever UDP picked
            # (otherwise we'd get two random ports).
            try:
                self._tcp_server = _ThreadingTCPServer(
                    (self.host, self.port),
                    _DMPTCPRequestHandler,
                    self.reader,
                    self.ttl,
                    self.rate_limiter,
                    self.max_concurrency,
                    **self._server_kwargs(),
                )
            except OSError as exc:
                # TCP bind failure is non-fatal — UDP keeps running.
                # Operators with TCP 53 explicitly blocked at a lower
                # layer (kernel, container, firewall doing in-kernel
                # filtering) shouldn't have the whole node fail to
                # start. Log and continue.
                log.warning(
                    "DMP DNS TCP listener failed to bind on %s:%d (%s); "
                    "continuing with UDP only. Recursive resolvers that "
                    "fall back to TCP for large RRsets will get empty "
                    "answers.",
                    self.host,
                    self.port,
                    exc,
                )
                self._tcp_server = None
            else:
                self._tcp_thread = threading.Thread(
                    target=self._tcp_server.serve_forever,
                    name="dmp-dns-tcp-server",
                    daemon=True,
                )
                self._tcp_thread.start()

        listening = "udp+tcp" if self._tcp_server is not None else "udp"
        log.info(
            "DMP DNS server listening on %s:%d/%s", self.host, self.port, listening
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
        if self._tcp_server is not None:
            self._tcp_server.shutdown()
            self._tcp_server.server_close()
            if self._tcp_thread is not None:
                self._tcp_thread.join(timeout=5)
            self._tcp_server = None
            self._tcp_thread = None

    def __enter__(self) -> "DMPDnsServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
