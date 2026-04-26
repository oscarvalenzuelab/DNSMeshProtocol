"""Client-side DNS UPDATE writer (M9.2.4).

Implements :class:`dmp.network.base.DNSRecordWriter` against a remote
authoritative DNS server using RFC 2136 UPDATE + RFC 8945 TSIG. The CLI
uses this in place of HTTP POSTs to ``/v1/records/*`` once the user has
registered for a TSIG key via M9.2.3.

Design notes:

- One-shot UPDATE per call. We don't batch publishes, on purpose —
  the caller's flow (e.g. ``identity refresh-prekeys --count 50``)
  already understands per-record progress, and one UPDATE per record
  keeps the failure granularity matching the existing HTTP path.
- UDP first, TCP fallback when the response comes back truncated
  (TC=1) or when dnspython raises ``Truncated``. A signed UPDATE +
  response can blow past 512 bytes pretty quickly with a 32-byte
  HMAC tag plus the rdata; sane DNS servers signal via TC and we
  retry on TCP.
- Failures don't raise — we surface ``False`` to match the M9.1
  ``DNSRecordWriter`` contract. The HTTP writer pattern returns
  False on retryable errors and lets the caller try the next
  endpoint; the DNS UPDATE writer keeps the same shape so the
  swap is purely a wiring change.
- Errors come with structured logging at INFO so an operator can
  trace why a publish silently dropped without re-running with
  debug verbosity.
"""

from __future__ import annotations

import logging
import socket
from typing import Optional

import dns.exception
import dns.flags
import dns.inet
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update

from dmp.network.base import DNSRecordWriter

log = logging.getLogger(__name__)


def _resolve_to_ip(host, resolver_pool=None):
    """Return ``host`` if it's already an IPv4/IPv6 literal, else resolve.

    dnspython's ``dns.query.udp`` / ``dns.query.tcp`` accept only IP
    literals — passing a hostname raises ``ValueError`` deep in
    ``dns.inet.af_for_address``. Operators naturally configure DMP
    with hostnames (``tsig_dns_server: dnsmesh.io``), so we resolve
    here.

    Resolution order (codex round-21 P1):
      1. ``resolver_pool`` — when the caller has a configured
         :class:`ResolverPool` (i.e. ``DMP_HEARTBEAT_DNS_RESOLVERS``
         is set), use it first. This keeps UDP-destination lookups
         consistent with the rest of DMP's reads — during a zone
         delegation move, the host's system resolver may still
         cache a stale NXDOMAIN while the pinned recursors have
         already refreshed.
      2. ``socket.getaddrinfo`` — last-resort fallback when no
         pool is configured (single-host dev setups).

    Returns ``None`` on failure rather than the original hostname.
    The caller is then responsible for surfacing ``False`` per the
    :class:`DNSRecordWriter` contract; passing a non-literal back
    into ``dns.query.udp`` would raise an uncaught ``ValueError``.

    Defensive against ``None`` / non-string / empty input — those
    are treated as unresolvable.
    """
    if not isinstance(host, str) or not host:
        return None
    if "\x00" in host:
        # NUL bytes confuse downstream socket / DNS calls; reject up front
        # so a typo can't produce inconsistent failure modes across paths.
        return None

    try:
        dns.inet.af_for_address(host)
        return host
    except (ValueError, dns.exception.SyntaxError):
        pass

    if resolver_pool is not None and hasattr(resolver_pool, "resolve_address"):
        try:
            ip = resolver_pool.resolve_address(host)
        except Exception:
            ip = None
        if ip:
            return ip
        # Pool exhausted without an answer — fall through to the system
        # resolver as a last resort. An operator with strict policies
        # (``--no-default-resolvers``) is fine here: getaddrinfo would
        # use whatever resolv.conf points at, which is what they
        # already accepted by setting that flag.

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_DGRAM)
    except (socket.gaierror, UnicodeError):
        return None
    for af, _, _, _, sockaddr in infos:
        if af == socket.AF_INET:
            return sockaddr[0]
    for af, _, _, _, sockaddr in infos:
        if af == socket.AF_INET6:
            return sockaddr[0]
    return None


DEFAULT_TIMEOUT = 5.0
DEFAULT_PORT = 53
DEFAULT_ALGORITHM = "hmac-sha256"

# RFC 8945 algorithms dnspython exposes. We validate at writer
# construction so a typo surfaces as a clear ValueError rather than
# silently failing at packet send-time.
SUPPORTED_TSIG_ALGORITHMS = (
    "hmac-md5",
    "hmac-sha1",
    "hmac-sha224",
    "hmac-sha256",
    "hmac-sha256-128",
    "hmac-sha384",
    "hmac-sha384-192",
    "hmac-sha512",
    "hmac-sha512-256",
)


def _quote_txt(value: str) -> str:
    """Wrap a TXT value in quotes and escape internal quotes / backslashes.

    dnspython parses the rdata strings we hand to ``UpdateMessage.add``
    in DNS presentation format, where ``;`` introduces a comment and
    ``"`` delimits strings. A naked DMP wire ``v=dmp1;t=identity``
    silently truncates at the semicolon without quoting. Matches the
    test-side helper in ``test_dns_server.py``.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"' + escaped + '"'


class _DnsUpdateWriter(DNSRecordWriter):
    """Send TSIG-signed UPDATE messages to an authoritative DNS server.

    Construction is cheap (no network I/O); each ``publish_txt_record``
    / ``delete_txt_record`` call sends one UDP packet (with TCP
    fall-back) and returns True iff the server answered NOERROR.

    The caller is responsible for ensuring the records they publish
    are within the TSIG key's authorized scope — out-of-scope writes
    bounce as REFUSED on the server side, which we surface as False.
    """

    def __init__(
        self,
        *,
        zone: str,
        server: str,
        tsig_key_name: str,
        tsig_secret: bytes,
        tsig_algorithm: str = DEFAULT_ALGORITHM,
        port: int = DEFAULT_PORT,
        timeout: float = DEFAULT_TIMEOUT,
        resolver_pool=None,
    ) -> None:
        if not zone:
            raise ValueError("zone must be non-empty")
        if not server:
            raise ValueError("server must be non-empty")
        if not tsig_key_name:
            raise ValueError("tsig_key_name must be non-empty")
        if not isinstance(tsig_secret, (bytes, bytearray)) or not tsig_secret:
            raise ValueError("tsig_secret must be non-empty bytes")

        self._zone = zone.strip().rstrip(".").lower()
        # Resolve hostnames at construction so each publish doesn't
        # repay the lookup cost. dnspython requires IP literals for
        # the UDP/TCP destination — without this, every operator
        # would have to hand-edit ``tsig_dns_server`` to an IP.
        # ``resolver_pool`` (typically the CLI's configured pool of
        # ``DMP_HEARTBEAT_DNS_RESOLVERS``) keeps UDP-destination
        # lookups on the same recursors as record reads, so a stale
        # NXDOMAIN at the system resolver doesn't break writes.
        # ``_server`` may be ``None`` if resolution fails — ``_send``
        # checks for that and returns ``False`` per the
        # ``DNSRecordWriter`` contract.
        self._server_input = server
        self._server = _resolve_to_ip(server, resolver_pool=resolver_pool)
        self._port = int(port)
        self._timeout = float(timeout)

        algo_norm = (tsig_algorithm or "").strip().lower()
        if algo_norm not in SUPPORTED_TSIG_ALGORITHMS:
            raise ValueError(f"unsupported TSIG algorithm: {tsig_algorithm!r}")
        # dnspython's keyring API takes either a dict[Name, bytes] or
        # dict[Name, dns.tsig.Key]. We use ``dns.tsig.Key`` to pin the
        # algorithm explicitly (the bytes-only form defaults to
        # hmac-sha256 today but the algorithm is part of TSIG semantics
        # and we don't want a future dnspython default change to silently
        # mismatch the server).
        kname = dns.name.from_text(tsig_key_name)
        key = dns.tsig.Key(
            name=kname,
            secret=bytes(tsig_secret),
            algorithm=algo_norm,
        )
        self._keyring = {kname: key}
        self._keyname = kname
        self._algorithm = algo_norm

    # ------------------------------------------------------------------
    # DNSRecordWriter
    # ------------------------------------------------------------------

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        """Send an UPDATE that adds (name, TXT, value) under our zone."""
        if not name or not isinstance(value, str):
            return False
        upd = dns.update.UpdateMessage(self._zone)
        try:
            upd.add(
                dns.name.from_text(name.rstrip(".") + "."),
                int(ttl),
                "TXT",
                _quote_txt(value),
            )
        except Exception:
            log.exception("could not assemble UPDATE add for %s", name)
            return False
        return self._send(upd, op="add", name=name)

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        """Send an UPDATE that deletes a TXT RR (or the whole RRset)."""
        if not name:
            return False
        upd = dns.update.UpdateMessage(self._zone)
        try:
            owner = dns.name.from_text(name.rstrip(".") + ".")
            if value is None:
                # Delete the whole RRset at this name.
                upd.delete(owner, "TXT")
            else:
                upd.delete(owner, "TXT", _quote_txt(value))
        except Exception:
            log.exception("could not assemble UPDATE delete for %s", name)
            return False
        return self._send(upd, op="delete", name=name)

    # ------------------------------------------------------------------
    # transport
    # ------------------------------------------------------------------

    def _send(self, upd: dns.update.UpdateMessage, *, op: str, name: str) -> bool:
        if self._server is None:
            # Construction-time resolution failed — surface as a clean
            # False rather than letting ``dns.query.udp`` raise
            # ``ValueError`` on a non-literal host string. The log
            # carries the original input so an operator can see WHY
            # nothing left the box.
            log.info(
                "DNS UPDATE %s for %s aborted: cannot resolve server %r",
                op,
                name,
                self._server_input,
            )
            return False
        try:
            upd.use_tsig(
                self._keyring,
                keyname=self._keyname,
                algorithm=self._algorithm,
            )
        except Exception:
            log.exception("could not sign UPDATE for %s", name)
            return False

        # UDP first, TCP fallback when the response comes back
        # truncated. Real servers may also force TCP for large
        # signed UPDATEs (the HMAC tag pushes the on-wire size).
        # dnspython's ``dns.query.udp()`` does NOT raise on TC=1 by
        # default — it returns the truncated response with the TC
        # flag set. ``raise_on_truncation=True`` flips that to an
        # exception we can catch (codex round-5 P2). The except block
        # is kept as belt-and-suspenders for older dnspython versions
        # that may surface truncation differently.
        try:
            response = dns.query.udp(
                upd,
                self._server,
                port=self._port,
                timeout=self._timeout,
                raise_on_truncation=True,
            )
        except dns.message.Truncated:
            try:
                response = dns.query.tcp(
                    upd, self._server, port=self._port, timeout=self._timeout
                )
            except (dns.exception.DNSException, OSError):
                log.exception("DNS UPDATE TCP retry failed for %s/%s", op, name)
                return False
        except (dns.exception.DNSException, OSError):
            log.exception("DNS UPDATE UDP failed for %s/%s", op, name)
            return False
        else:
            # Defensive: some dnspython versions / configurations may
            # still hand back a TC=1 response without raising. Retry
            # over TCP in that case.
            if response.flags & dns.flags.TC:
                try:
                    response = dns.query.tcp(
                        upd,
                        self._server,
                        port=self._port,
                        timeout=self._timeout,
                    )
                except (dns.exception.DNSException, OSError):
                    log.exception("DNS UPDATE TCP retry failed for %s/%s", op, name)
                    return False

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            log.info(
                "DNS UPDATE %s for %s rejected by %s: rcode=%s",
                op,
                name,
                self._server,
                dns.rcode.to_text(rcode),
            )
            return False
        return True
