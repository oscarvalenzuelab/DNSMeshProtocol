"""Tests for the UDP DNS server."""

import base64
import socket
import time

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring
import dns.update
import pytest

from dmp.network.memory import InMemoryDNSStore
from dmp.server.dns_server import DMPDnsServer, _split_for_txt_strings


def _free_port() -> int:
    # Bind UDP port 0, read back assigned port, release. A race is possible
    # but the window is small for a per-test random port.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestTxtSplitting:
    def test_short_value_single_string(self):
        chunks = _split_for_txt_strings("hello")
        assert chunks == [b"hello"]

    def test_long_value_splits_at_255(self):
        value = "A" * 500
        chunks = _split_for_txt_strings(value)
        assert [len(c) for c in chunks] == [255, 245]

    def test_empty_value_has_one_empty_chunk(self):
        assert _split_for_txt_strings("") == [b""]


class TestDMPDnsServer:
    def _query(self, qname: str, host: str, port: int) -> dns.message.Message:
        request = dns.message.make_query(qname, dns.rdatatype.TXT)
        return dns.query.udp(request, host, port=port, timeout=2.0)

    def test_resolves_txt_record(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("alice.mesh.test", "v=dmp1;t=identity")

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query("alice.mesh.test", "127.0.0.1", port)

        assert response.rcode() == 0  # NOERROR
        assert len(response.answer) == 1
        rdata = response.answer[0][0]
        assert b"".join(rdata.strings) == b"v=dmp1;t=identity"

    def test_txt_lookup_is_case_insensitive(self):
        """Recursive resolvers may apply DNS 0x20 case randomization.

        Owner names are case-insensitive, so an authoritative lookup
        for a mixed-case QNAME must hit the lower-case stored record
        instead of returning NXDOMAIN.
        """
        store = InMemoryDNSStore()
        store.publish_txt_record(
            "_dnsmesh-heartbeat.dmp.dnsmesh.io", "v=dmp1;t=heartbeat"
        )

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query(
                "_DNSMESH-HEARTBEAT.dMp.DnSmEsH.iO", "127.0.0.1", port
            )

        assert response.rcode() == 0
        assert len(response.answer) == 1
        rdata = response.answer[0][0]
        assert b"".join(rdata.strings) == b"v=dmp1;t=heartbeat"

    def test_missing_name_returns_nxdomain(self):
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query("ghost.mesh.test", "127.0.0.1", port)
        assert response.rcode() == 3  # NXDOMAIN

    def test_non_txt_query_returns_empty_answer(self):
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query("alice.mesh.test", dns.rdatatype.A)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)
        # We don't serve A records; return an empty NOERROR.
        assert response.rcode() == 0
        assert response.answer == []

    def test_long_value_served_as_multi_string_txt(self):
        """Values > 255 bytes get emitted as multi-string TXT records.

        Uses EDNS0 with a 4 KB buffer so the response (a 600-byte
        TXT record) fits in a single UDP datagram. Without EDNS the
        UDP path correctly truncates to TC=1 — see
        TestDMPDnsServerTruncation for that path."""
        store = InMemoryDNSStore()
        long_value = "B" * 600
        store.publish_txt_record("long.mesh.test", long_value)

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query(
                "long.mesh.test", dns.rdatatype.TXT, use_edns=0, payload=4096
            )
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        rdata = response.answer[0][0]
        assert len(rdata.strings) >= 3
        for s in rdata.strings:
            assert len(s) <= 255
        assert b"".join(rdata.strings) == long_value.encode("utf-8")

    def test_server_is_restartable(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("r.mesh.test", "value")
        port = _free_port()

        server = DMPDnsServer(store, host="127.0.0.1", port=port)
        server.start()
        try:
            response = self._query("r.mesh.test", "127.0.0.1", port)
            assert response.rcode() == 0
        finally:
            server.stop()

        # Second life: bind a different free port (socketserver can keep the
        # old one busy momentarily even with SO_REUSEADDR on some platforms).
        port2 = _free_port()
        server2 = DMPDnsServer(store, host="127.0.0.1", port=port2)
        server2.start()
        try:
            response2 = self._query("r.mesh.test", "127.0.0.1", port2)
            assert response2.rcode() == 0
        finally:
            server2.stop()


class TestDMPDnsServerApexAddressRecords:
    """Operators on a self-glued subzone delegation
    (``<sub> NS <sub>`` with parent-side glue A) need the node to
    answer A queries for its OWN apex name. Strict resolvers
    (Google 8.8.8.8, Level3 4.2.2.x) re-resolve the NS-target
    out-of-bailiwick rather than trusting the parent-zone glue;
    if we don't answer, they NXDOMAIN every name under the zone.

    Without ``apex_zone``+``apex_a`` configured, behavior is
    unchanged from prior releases (A → NOERROR with empty answer).
    """

    def test_apex_a_returned_for_zone_apex(self):
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_a="203.0.113.42",
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.A)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        assert str(response.answer[0][0]) == "203.0.113.42"

    def test_apex_aaaa_returned_for_zone_apex(self):
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_aaaa="2001:db8::42",
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.AAAA)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        assert str(response.answer[0][0]) == "2001:db8::42"

    def test_apex_a_case_insensitive(self):
        """DNS names are case-insensitive — a query for ``DMP.Mesh.Test``
        must hit the same apex code path as ``dmp.mesh.test``."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_a="203.0.113.42",
        ):
            request = dns.message.make_query("DMP.Mesh.Test", dns.rdatatype.A)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        assert str(response.answer[0][0]) == "203.0.113.42"

    def test_a_query_for_non_apex_name_returns_empty(self):
        """A records are ONLY served at the configured apex. A query
        for any other name under the zone (e.g. a TXT-bearing owner
        like ``_dnsmesh-heartbeat.dmp.mesh.test``) gets the legacy
        NOERROR-empty response — we don't accidentally start serving
        every name in the world."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_a="203.0.113.42",
        ):
            request = dns.message.make_query(
                "_dnsmesh-heartbeat.dmp.mesh.test", dns.rdatatype.A
            )
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []

    def test_aaaa_at_apex_without_aaaa_config_returns_empty(self):
        """Apex configured with A only — AAAA query at apex returns
        NOERROR-empty (not NXDOMAIN). DNS protocol semantics: a name
        that exists with one type but not another should NOT NXDOMAIN."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_a="203.0.113.42",
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.AAAA)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []

    def test_apex_txt_still_routes_to_store(self):
        """Apex A configuration must NOT mask TXT queries at the same
        apex name. TXT continues to dispatch through the record store
        — operators may publish records at the zone apex (e.g.
        ``v=spf1 -all``) and we must serve them."""
        store = InMemoryDNSStore()
        store.publish_txt_record("dmp.mesh.test", "v=spf1 -all")
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_a="203.0.113.42",
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.TXT)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        rdata = response.answer[0][0]
        assert b"".join(rdata.strings) == b"v=spf1 -all"

    def test_apex_unconfigured_a_returns_empty_answer(self):
        """Without apex_zone configured, an A query at the would-be
        apex name returns the legacy NOERROR-empty — the apex
        fast-path stays disabled. Backward-compat invariant for
        operators on a conventional NS-out-of-bailiwick delegation."""
        store = InMemoryDNSStore()
        port = _free_port()
        # No apex_zone / apex_a passed → fast-path inactive.
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.A)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []

    def test_apex_a_via_tcp(self):
        """A queries arriving over TCP (recursors that go straight
        to TCP, or after TC=1) must hit the same apex path."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_a="203.0.113.42",
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.A)
            response = dns.query.tcp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        assert str(response.answer[0][0]) == "203.0.113.42"


class TestDMPDnsServerApexSoaNs:
    """Strict recursive resolvers (Google 8.8.8.8, Level3 4.2.2.x)
    validate a delegation by querying the configured authoritative
    server for SOA + NS at the zone apex. If either query returns
    NOERROR with an empty answer, they conclude the auth doesn't
    actually own the zone, mark it "lame delegation", and NXDOMAIN
    every name under it. Lenient resolvers (Cloudflare, Quad9) skip
    this check, which is why the bug hides until Google's involved.

    DMP_DNS_APEX_NS + DMP_DNS_APEX_SOA_RNAME flip this on. SOA needs
    both (RFC 1035 §3.3.13 requires MNAME and RNAME); NS only needs
    apex_ns. Without either, the dispatcher falls through to the
    legacy NOERROR-empty branch.
    """

    def test_apex_ns_returned_for_zone_apex(self):
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.NS)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        rdata = response.answer[0][0]
        assert rdata.rdtype == dns.rdatatype.NS
        # NS target is dnspython Name; compare lowercase no-trailing-dot.
        assert rdata.target.to_text(omit_final_dot=True).lower() == "ns1.mesh.test"

    def test_apex_soa_returned_for_zone_apex(self):
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
            apex_soa_rname="hostmaster.mesh.test",
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.SOA)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        soa = response.answer[0][0]
        assert soa.rdtype == dns.rdatatype.SOA
        assert soa.mname.to_text(omit_final_dot=True).lower() == "ns1.mesh.test"
        assert soa.rname.to_text(omit_final_dot=True).lower() == "hostmaster.mesh.test"
        # SERIAL is wall-clock based; just verify it's a sane recent value.
        assert soa.serial > 1_700_000_000  # after 2023-11-15
        assert soa.refresh == 3600
        assert soa.retry == 600
        assert soa.expire == 604800

    def test_apex_soa_unconfigured_rname_returns_empty(self):
        """SOA RFC requires both MNAME (apex_ns) AND RNAME
        (apex_soa_rname). If only one is set we DON'T half-construct
        an SOA — return NOERROR-empty so the resolver doesn't cache
        a malformed record."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
            # apex_soa_rname intentionally unset
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.SOA)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []

    def test_apex_ns_unconfigured_returns_empty(self):
        """No apex_ns → NS query at apex returns NOERROR-empty."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store, host="127.0.0.1", port=port, apex_zone="dmp.mesh.test"
        ):
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.NS)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []

    def test_ns_at_non_apex_returns_empty(self):
        """NS at a sub-name (not the apex) returns empty, not the
        apex NS. We only serve NS at exactly the configured apex."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
        ):
            request = dns.message.make_query(
                "_dnsmesh-heartbeat.dmp.mesh.test", dns.rdatatype.NS
            )
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []

    def test_soa_at_non_apex_returns_empty(self):
        """Same property for SOA — only at the apex name."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
            apex_soa_rname="hostmaster.mesh.test",
        ):
            request = dns.message.make_query(
                "_dnsmesh-heartbeat.dmp.mesh.test", dns.rdatatype.SOA
            )
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []

    def test_apex_records_combined_a_ns_soa(self):
        """A node with the full apex bundle answers all three RR
        types correctly at the same name. Sanity check that no two
        config paths fight each other."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_a="203.0.113.42",
            apex_ns="ns1.mesh.test",
            apex_soa_rname="hostmaster.mesh.test",
        ):
            for rdtype, expected_present in [
                (dns.rdatatype.A, True),
                (dns.rdatatype.NS, True),
                (dns.rdatatype.SOA, True),
                (dns.rdatatype.AAAA, False),  # no apex_aaaa configured
            ]:
                request = dns.message.make_query("dmp.mesh.test", rdtype)
                response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)
                assert response.rcode() == 0
                if expected_present:
                    assert (
                        len(response.answer) == 1
                    ), f"{dns.rdatatype.to_text(rdtype)} expected 1 answer, got {len(response.answer)}"
                else:
                    assert (
                        response.answer == []
                    ), f"{dns.rdatatype.to_text(rdtype)} unexpected answer"

    def test_apex_soa_serial_is_monotonic(self):
        """SOA SERIAL must increase across queries so slaves (or
        operators sanity-checking the zone) see a fresh value. We
        don't have AXFR slaves but a manually-tuned tooling chain
        depends on the property."""
        import time as _time

        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
            apex_soa_rname="hostmaster.mesh.test",
        ):
            r1 = dns.query.udp(
                dns.message.make_query("dmp.mesh.test", dns.rdatatype.SOA),
                "127.0.0.1",
                port=port,
                timeout=2.0,
            )
            _time.sleep(1.05)
            r2 = dns.query.udp(
                dns.message.make_query("dmp.mesh.test", dns.rdatatype.SOA),
                "127.0.0.1",
                port=port,
                timeout=2.0,
            )

        s1 = r1.answer[0][0].serial
        s2 = r2.answer[0][0].serial
        assert s2 > s1, f"SOA serial should advance: {s1} -> {s2}"


class TestDMPDnsServerNegativeResponses:
    """RFC 2308 + RFC 8020 compliance.

    Hit in production: Google Public DNS NXDOMAIN'd every name under
    a healthy DMP zone for 9+ hours after a delegation cleanup. Root
    cause turned out to be two intertwined bugs:

    1. The DMP server returned NXDOMAIN at the zone apex for
       record types it didn't have (e.g., TXT at apex when no TXT
       records exist there). The apex name DOES exist (the zone
       has SOA/NS/A there), so the correct response is NODATA
       (NOERROR with empty answer), not NXDOMAIN. Per RFC 8020
       "NXDOMAIN cut", a strict resolver caches NXDOMAIN at an
       ancestor and SYNTHESIZES NXDOMAIN for every descendant
       without re-querying — so a single bad NXDOMAIN at the apex
       poisons the entire zone for the resolver's cache lifetime.

    2. NXDOMAIN AND NODATA responses lacked the apex SOA in their
       AUTHORITY section. RFC 2308 §3 requires SOA in negative
       responses so the resolver knows the negative-caching TTL.
       Without it, RFC 2308 §5 says the response SHOULD NOT be
       cached, and Google in particular treats the whole exchange
       as suspect.

    Both fixes ship together — there's no point fixing one without
    the other since the symptom requires both to manifest.
    """

    def _apex_server(self):
        return DMPDnsServer(
            InMemoryDNSStore(),
            host="127.0.0.1",
            port=_free_port(),
            apex_zone="dmp.mesh.test",
            apex_a="203.0.113.42",
            apex_ns="ns1.mesh.test",
            apex_soa_rname="hostmaster.mesh.test",
        )

    def test_apex_txt_with_no_records_returns_nodata_not_nxdomain(self):
        """The exact bug that caused 9+ hours of Google NXDOMAINing.
        Apex name exists (we serve A/NS/SOA there), so a TXT query
        at the apex with no TXT records should be NODATA (NOERROR +
        0 answer), NOT NXDOMAIN."""
        with self._apex_server() as srv:
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.TXT)
            response = dns.query.udp(request, "127.0.0.1", port=srv.port, timeout=2.0)

        assert (
            response.rcode() == 0
        ), "MUST be NOERROR; NXDOMAIN poisons zone via RFC 8020 cut"
        assert response.answer == []

    def test_apex_unconfigured_type_returns_nodata(self):
        """Same property for any other type the operator hasn't
        configured at the apex. CAA, MX, etc. → NODATA."""
        with self._apex_server() as srv:
            for rdtype in (dns.rdatatype.CAA, dns.rdatatype.MX, dns.rdatatype.SRV):
                request = dns.message.make_query("dmp.mesh.test", rdtype)
                response = dns.query.udp(
                    request, "127.0.0.1", port=srv.port, timeout=2.0
                )
                assert (
                    response.rcode() == 0
                ), f"{dns.rdatatype.to_text(rdtype)} at apex MUST NOT NXDOMAIN"
                assert response.answer == []

    def test_nxdomain_response_includes_soa_in_authority(self):
        """RFC 2308 §3 — negative responses MUST carry the zone SOA
        in AUTHORITY for negative-caching TTL. Without it RFC 2308
        §5 says the answer SHOULD NOT be cached."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
            apex_soa_rname="hostmaster.mesh.test",
        ):
            request = dns.message.make_query("_typo.dmp.mesh.test", dns.rdatatype.TXT)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        # Genuine sub-name nonexistence → NXDOMAIN.
        assert response.rcode() == 3
        # And SOA in authority.
        assert len(response.authority) == 1
        soa = response.authority[0][0]
        assert soa.rdtype == dns.rdatatype.SOA
        assert soa.mname.to_text(omit_final_dot=True).lower() == "ns1.mesh.test"

    def test_nodata_response_includes_soa_in_authority(self):
        """RFC 2308 §3 also covers NOERROR-empty (NODATA) responses.
        A non-TXT query on a sub-name (where we don't track non-TXT
        records) returns NODATA + SOA, not naked NOERROR-empty."""
        store = InMemoryDNSStore()
        store.publish_txt_record(
            "_dnsmesh-heartbeat.dmp.mesh.test", "v=dmp1;t=heartbeat;..."
        )
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
            apex_soa_rname="hostmaster.mesh.test",
        ):
            # AAAA on a name we have TXT for → NODATA.
            request = dns.message.make_query(
                "_dnsmesh-heartbeat.dmp.mesh.test", dns.rdatatype.AAAA
            )
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []
        assert len(response.authority) == 1
        assert response.authority[0][0].rdtype == dns.rdatatype.SOA

    def test_apex_nodata_includes_soa_in_authority(self):
        """The apex case from bug #1 also needs SOA — the response
        is NODATA, and RFC 2308 §3 still applies."""
        with self._apex_server() as srv:
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.TXT)
            response = dns.query.udp(request, "127.0.0.1", port=srv.port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []
        assert len(response.authority) == 1
        assert response.authority[0][0].rdtype == dns.rdatatype.SOA

    def test_subname_non_txt_returns_nodata_not_nxdomain(self):
        """A query for AAAA at a random sub-name like
        ``_typo.dmp.mesh.test`` returns NODATA, not NXDOMAIN —
        because we can't tell whether the name "exists" for some
        type we don't manage. The conservative answer (NODATA) is
        safer than NXDOMAIN, which would propagate via NXDOMAIN-cut
        to any TXT lookups under the same prefix."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            apex_zone="dmp.mesh.test",
            apex_ns="ns1.mesh.test",
            apex_soa_rname="hostmaster.mesh.test",
        ):
            request = dns.message.make_query("_typo.dmp.mesh.test", dns.rdatatype.AAAA)
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == 0
        assert response.answer == []
        # SOA still required.
        assert len(response.authority) == 1
        assert response.authority[0][0].rdtype == dns.rdatatype.SOA

    def test_negative_responses_unconfigured_apex_no_soa(self):
        """Backward compat: when the operator hasn't set
        ``apex_zone``/``apex_ns``/``apex_soa_rname``, the server has
        no SOA to attach. Negative responses fall back to the legacy
        naked behavior — RFC-non-compliant, but no regression
        relative to 0.6.4 and earlier for operators who haven't
        opted into the new env vars."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query(
                "_typo.unmanaged.example", dns.rdatatype.TXT
            )
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        # Sub-name with no records, no apex configured → NXDOMAIN
        # with no SOA (legacy behavior).
        assert response.rcode() == 3
        assert response.authority == []

    def test_apex_soa_query_unaffected_by_no_records(self):
        """SOA at the apex must still ANSWER (not return NODATA).
        Sanity check that the apex-meta path isn't accidentally
        falling through to the negative branch."""
        with self._apex_server() as srv:
            request = dns.message.make_query("dmp.mesh.test", dns.rdatatype.SOA)
            response = dns.query.udp(request, "127.0.0.1", port=srv.port, timeout=2.0)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        assert response.answer[0][0].rdtype == dns.rdatatype.SOA


class TestDMPDnsServerRateLimitAndConcurrency:
    """Regressions caught by codex review of the TCP listener PR.

    Both are subtle correctness issues that don't crash anything but
    weaken the protections operators expect: TCP fallback must not
    be rate-limited out of existence, and ``max_concurrency`` has
    to remain a single global cap across UDP + TCP."""

    def test_tcp_retry_not_rate_limited(self):
        """A resolver doing UDP→TC=1→TCP retry has already been
        admitted at the UDP layer. The TCP retry must not double-
        charge the per-IP rate limiter, otherwise small bursts
        silently drop the answer for oversized RRsets."""
        from dmp.server.rate_limit import RateLimit

        store = InMemoryDNSStore()
        # Large RRset to force the truncate path.
        for i in range(10):
            store.publish_txt_record("big.mesh.test", "X" * 240 + f"-{i:03d}")

        port = _free_port()
        # Small non-zero rate so RateLimit.enabled is True (it
        # checks rate>0 AND burst>0); refill is glacial relative to
        # the test, effectively burst=1 per IP per transport.
        # Without per-transport buckets, the UDP query consumes the
        # bucket's token and the TCP retry would silently drop.
        rl = RateLimit(rate_per_second=0.001, burst=1)
        with DMPDnsServer(store, host="127.0.0.1", port=port, rate_limit=rl):
            request = dns.message.make_query("big.mesh.test", dns.rdatatype.TXT)
            response, used_tcp = dns.query.udp_with_fallback(
                request, "127.0.0.1", port=port, timeout=2.0
            )
        assert used_tcp
        assert response.rcode() == 0
        assert len(response.answer[0]) == 10

    def test_direct_tcp_traffic_is_rate_limited(self):
        """Direct TCP traffic (not a UDP→TC=1→TCP retry) must still
        hit the per-IP throttle. Otherwise an attacker bypasses
        rate-limiting entirely by switching to TCP.

        Codex round-3 P1: an earlier fix exempted ALL TCP from the
        limiter; this test ensures the per-transport-bucket fix
        keeps direct TCP queries throttled at the configured rate.
        """
        from dmp.server.rate_limit import RateLimit

        store = InMemoryDNSStore()
        store.publish_txt_record("alice.mesh.test", "v=dmp1;t=identity")
        port = _free_port()
        # Burst of 1, no refill: only one TCP query per IP per minute.
        # rate=0 disables the limiter entirely (RateLimit.enabled
        # checks rate>0 AND burst>0). Use a small non-zero rate so
        # the limiter is active; refill is glacial relative to the
        # test's wall-clock duration.
        rl = RateLimit(rate_per_second=0.001, burst=1)
        with DMPDnsServer(store, host="127.0.0.1", port=port, rate_limit=rl):
            # First TCP query consumes the burst-1 token.
            r1 = dns.query.tcp(
                dns.message.make_query("alice.mesh.test", dns.rdatatype.TXT),
                "127.0.0.1",
                port=port,
                timeout=2.0,
            )
            assert r1.rcode() == 0

            # Second TCP query from the same IP must drop (server
            # closes connection without a response). Open a raw
            # socket since dns.query.tcp would block waiting for an
            # answer that never comes.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(("127.0.0.1", port))
                req = dns.message.make_query(
                    "alice.mesh.test", dns.rdatatype.TXT
                ).to_wire()
                s.sendall(len(req).to_bytes(2, "big") + req)
                # Server drops the rate-limited query → connection
                # closes with no response.
                received = s.recv(4096)
            assert received == b"", (
                "Direct TCP query past the burst should be dropped "
                "by the per-IP rate limiter, not answered"
            )

    def test_tcp_accept_cap_bounds_open_connections(self):
        """Slow-loris bound: connection accept itself is bounded by
        a separate, larger semaphore so a flood of idle TCP
        connections can't exhaust host threads/memory.

        Codex round-5 P1: under the previous implementation the
        TCP server spawned a handler thread for every accepted
        socket, with no cap on connection count. An attacker
        opening 10k slow-loris connections would burn ~80 GB of
        thread stacks. The accept-cap (8 × max_concurrency, with a
        256 floor) bounds that.
        """
        store = InMemoryDNSStore()
        port = _free_port()
        srv = DMPDnsServer(store, host="127.0.0.1", port=port, max_concurrency=4)
        srv.start()
        try:
            accept_sem = srv._tcp_server._accept_semaphore
            # Drain the accept budget directly to confirm the cap.
            count = 0
            while accept_sem.acquire(blocking=False):
                count += 1
                if count > 1024:
                    break
            # max(8 * max_concurrency, 256) → 8*4=32, floor 256.
            assert count == 256, f"expected 256 accept slots, got {count}"
            # Restore for clean shutdown.
            for _ in range(count):
                accept_sem.release()
        finally:
            srv.stop()

    def test_idle_tcp_connections_dont_block_udp(self):
        """Slow-loris regression: a client opening many idle TCP
        connections must not starve the UDP listener.

        Codex round-4 P1: under the previous "acquire permit at
        connect" implementation, a client could open
        ``max_concurrency`` TCP sockets, send no bytes, and tie up
        every permit for the 5-second read timeout — blocking UDP
        queries entirely during that window. Lazy acquisition (only
        after the message body is in hand) preserves the global
        concurrency cap without making UDP service vulnerable to
        connect-only floods.
        """
        store = InMemoryDNSStore()
        store.publish_txt_record("alice.test", "hi")
        port = _free_port()
        srv = DMPDnsServer(store, host="127.0.0.1", port=port, max_concurrency=2)
        srv.start()
        try:
            # Open more idle TCP connections than the max_concurrency
            # cap, send zero bytes — classic slow-loris.
            idle_socks = []
            for _ in range(5):
                c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                c.connect(("127.0.0.1", port))
                idle_socks.append(c)
            try:
                # UDP query should still be served.
                request = dns.message.make_query("alice.test", dns.rdatatype.TXT)
                response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)
                assert response.rcode() == 0
            finally:
                for c in idle_socks:
                    c.close()
        finally:
            srv.stop()

    def test_udp_and_tcp_share_one_concurrency_semaphore(self):
        """``max_concurrency`` must be a single global cap, not
        one cap per transport. Without sharing, a node configured
        for max=128 silently allows ~256 handler threads."""
        store = InMemoryDNSStore()
        port = _free_port()
        srv = DMPDnsServer(store, host="127.0.0.1", port=port, max_concurrency=4)
        srv.start()
        try:
            assert srv._server is not None
            assert srv._tcp_server is not None
            assert srv._server._semaphore is srv._tcp_server._semaphore, (
                "UDP and TCP listeners must share one Semaphore so "
                "max_concurrency is a global cap, not per-transport"
            )
        finally:
            srv.stop()


class TestDMPDnsServerTruncation:
    """UDP truncation + TCP fallback — the actual recursor flow.

    A response that exceeds the requester's advertised UDP buffer
    (RFC 1035 default 512 bytes, or whatever EDNS0 advertised)
    must come back as a header-only stub with TC=1. The recursor
    then retries over TCP. Without that signal, recursors with
    strict RFC behavior (Google 8.8.8.8, Level3) just return empty
    to their caller. This was caught by codex review of PR #14
    after the TCP listener landed."""

    def _large_store(self) -> InMemoryDNSStore:
        store = InMemoryDNSStore()
        # 10 entries × 240 bytes ≈ 2.4 KB plus DNS framing — well
        # over the 512-byte RFC 1035 floor, well over typical
        # 1232-byte EDNS defaults too.
        for i in range(10):
            store.publish_txt_record("big.mesh.test", "X" * 240 + f"-{i:03d}")
        return store

    def test_udp_no_edns_oversized_returns_truncated_stub(self):
        """No EDNS in the query → 512-byte UDP cap. Oversized
        response should come back as TC=1 with empty answer."""
        store = self._large_store()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query("big.mesh.test", dns.rdatatype.TXT)
            # Note: dns.query.udp() raises if it sees TC=1 by default;
            # use ignore_trailing=True or call to_wire / from_wire
            # directly to inspect the truncated answer.
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            try:
                sock.sendto(request.to_wire(), ("127.0.0.1", port))
                data, _ = sock.recvfrom(4096)
            finally:
                sock.close()
            response = dns.message.from_wire(data)

        assert response.flags & dns.flags.TC, (
            "TC bit should be set on oversized UDP response so the "
            "recursor knows to retry over TCP"
        )
        # Header-only stub: no answers carried in the truncated reply.
        assert response.answer == []

    def test_udp_with_edns_carries_full_response(self):
        """Query with EDNS0 advertising a 4 KB buffer → full
        answer fits, no truncation."""
        store = self._large_store()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query(
                "big.mesh.test", dns.rdatatype.TXT, use_edns=0, payload=4096
            )
            response = dns.query.udp(request, "127.0.0.1", port=port, timeout=2.0)

        assert not (response.flags & dns.flags.TC)
        assert len(response.answer) == 1
        assert len(response.answer[0]) == 10

    def test_udp_then_tcp_fallback(self):
        """The full recursor flow: UDP query without EDNS gets a
        truncated reply, retry over TCP succeeds with the full
        answer. dnspython's dns.query.udp_with_fallback() exists
        precisely to model this."""
        store = self._large_store()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            request = dns.message.make_query("big.mesh.test", dns.rdatatype.TXT)
            response, used_tcp = dns.query.udp_with_fallback(
                request, "127.0.0.1", port=port, timeout=2.0
            )

        assert used_tcp, "expected fallback to TCP after TC=1 on UDP"
        assert response.rcode() == 0
        assert len(response.answer) == 1
        assert len(response.answer[0]) == 10


class TestDMPDnsServerTCP:
    """DNS-over-TCP — RFC 1035 §4.2.2 + RFC 7766. Covers the
    fallback path recursive resolvers take when a UDP response would
    exceed the negotiated buffer (TC=1). Without TCP, large RRsets
    like ``_dnsmesh-seen.<zone>`` can't propagate through any
    RFC-strict resolver."""

    def _query_tcp(self, qname: str, host: str, port: int) -> dns.message.Message:
        request = dns.message.make_query(qname, dns.rdatatype.TXT)
        return dns.query.tcp(request, host, port=port, timeout=2.0)

    def test_tcp_resolves_txt_record(self):
        store = InMemoryDNSStore()
        store.publish_txt_record("alice.mesh.test", "v=dmp1;t=identity")

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query_tcp("alice.mesh.test", "127.0.0.1", port)

        assert response.rcode() == 0
        assert len(response.answer) == 1
        rdata = response.answer[0][0]
        assert b"".join(rdata.strings) == b"v=dmp1;t=identity"

    def test_tcp_large_response_passes_through(self):
        """The whole point of TCP support: responses that exceed the
        UDP buffer come through cleanly over TCP. Build an RRset
        large enough that a 512-byte UDP datagram cannot carry it,
        then assert TCP returns the full set."""
        store = InMemoryDNSStore()
        # Each value ~250 bytes; ten of them well exceeds 4 KB even
        # before DNS framing overhead.
        for i in range(10):
            store.publish_txt_record("big.mesh.test", "X" * 240 + f"-{i:03d}")

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query_tcp("big.mesh.test", "127.0.0.1", port)

        assert response.rcode() == 0
        # All 10 values come back.
        assert len(response.answer) == 1
        rrset = response.answer[0]
        assert len(rrset) == 10

    def test_tcp_can_be_disabled(self):
        """``tcp_enabled=False`` skips the TCP listener — UDP keeps
        working, TCP connection attempts refuse cleanly."""
        store = InMemoryDNSStore()
        store.publish_txt_record("alice.mesh.test", "v=dmp1;t=identity")

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port, tcp_enabled=False):
            # UDP still works.
            udp_request = dns.message.make_query("alice.mesh.test", dns.rdatatype.TXT)
            udp_response = dns.query.udp(
                udp_request, "127.0.0.1", port=port, timeout=2.0
            )
            assert udp_response.rcode() == 0

            # TCP is not listening — connection refused (kernel RST).
            with pytest.raises((ConnectionRefusedError, OSError)):
                tcp_request = dns.message.make_query(
                    "alice.mesh.test", dns.rdatatype.TXT
                )
                dns.query.tcp(tcp_request, "127.0.0.1", port=port, timeout=1.0)

    def test_tcp_oversized_length_prefix_dropped(self):
        """A length prefix above MAX_MESSAGE_BYTES (65535 — though
        DNS itself caps at that anyway) is rejected without the
        server attempting to read the body. Open the socket
        manually to send a hand-crafted bad frame."""
        store = InMemoryDNSStore()
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(("127.0.0.1", port))
                # Length 0 — server should drop & close.
                s.sendall(b"\x00\x00")
                # Server closes the connection without a response.
                response = s.recv(4096)
                assert response == b""

    def test_tcp_short_message_body_closes_cleanly(self):
        """If the client announces a length but disconnects before
        sending that many bytes, the server should not crash and
        should not block other connections."""
        store = InMemoryDNSStore()
        store.publish_txt_record("alice.mesh.test", "v=dmp1;t=identity")
        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            # Open a connection, send length-prefix promising 100 bytes,
            # then close without sending them.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(("127.0.0.1", port))
                s.sendall((100).to_bytes(2, "big"))
                # Don't send the 100 bytes; close.
            # A subsequent legitimate query still succeeds — the server
            # didn't get stuck on the truncated connection.
            response = self._query_tcp("alice.mesh.test", "127.0.0.1", port)
            assert response.rcode() == 0


# ---------------------------------------------------------------------------
# M9.2.1 — RFC 2136 UPDATE + TSIG
# ---------------------------------------------------------------------------


def _keyring(name: str = "client.", secret: bytes = b"\x10" * 32):
    """Build a one-key TSIG keyring (HMAC-SHA256, 32-byte secret)."""
    return dns.tsigkeyring.from_text({name: base64.b64encode(secret).decode("ascii")})


def _send_update(update: dns.update.UpdateMessage, port: int):
    return dns.query.udp(update, "127.0.0.1", port=port, timeout=2.0)


class TestDnsUpdate:
    """End-to-end coverage of the UPDATE path: build a signed UPDATE on
    the client side, send it via UDP, assert the writer received the
    publish (or rejection codes when the request shouldn't be honored).
    """

    def _server(self, store, **kwargs):
        port = _free_port()
        defaults = dict(
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring=_keyring(),
            allowed_zones=("example.com",),
        )
        defaults.update(kwargs)
        return DMPDnsServer(store, **defaults), port

    def _build_add(self, owner: str, value: str, zone: str = "example.com"):
        upd = dns.update.UpdateMessage(zone)
        # dnspython relativizes a non-FQDN owner against the zone, so pass
        # an absolute name. Quote the TXT value: presentation-format TXT
        # treats ``;`` as a comment delimiter, which would silently
        # truncate ``v=dmp1;t=...`` wires otherwise.
        upd.add(
            dns.name.from_text(owner.rstrip(".") + "."),
            300,
            "TXT",
            '"' + value.replace('"', r"\"") + '"',
        )
        upd.use_tsig(_keyring(), keyname=dns.name.from_text("client."))
        return upd

    def test_signed_update_writes_record(self):
        """The happy path: TSIG-signed UPDATE → store gets the value
        and the response is NOERROR."""
        store = InMemoryDNSStore()
        server, port = self._server(store)
        with server:
            response = _send_update(
                self._build_add("foo.example.com", "v=dmp1;t=test"), port
            )
        assert response.rcode() == dns.rcode.NOERROR
        assert store.query_txt_record("foo.example.com") == ["v=dmp1;t=test"]

    def test_unsigned_update_is_refused(self):
        """An UPDATE that doesn't carry TSIG must not write anything."""
        store = InMemoryDNSStore()
        server, port = self._server(store)
        upd = dns.update.UpdateMessage("example.com")
        upd.add(
            dns.name.from_text("foo.example.com."),
            300,
            "TXT",
            '"should-not-write"',
        )
        with server:
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED
        assert store.query_txt_record("foo.example.com") is None

    def test_wrong_key_is_notauth(self):
        """An UPDATE signed with a key the server doesn't know fails
        TSIG verification at parse time → NOTAUTH, no write."""
        store = InMemoryDNSStore()
        server, port = self._server(store)
        upd = dns.update.UpdateMessage("example.com")
        upd.add(dns.name.from_text("foo.example.com."), 300, "TXT", '"intruder"')
        upd.use_tsig(
            _keyring(name="other.", secret=b"\xff" * 32),
            keyname=dns.name.from_text("other."),
        )
        with server:
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.NOTAUTH
        assert store.query_txt_record("foo.example.com") is None

    def test_zone_outside_allowed_list_is_notauth(self):
        """A signed UPDATE for a zone we don't claim authority for
        must be rejected even when the TSIG key is valid."""
        store = InMemoryDNSStore()
        server, port = self._server(store)
        with server:
            response = _send_update(
                self._build_add("foo.other.com", "x", zone="other.com"),
                port,
            )
        assert response.rcode() == dns.rcode.NOTAUTH
        assert store.query_txt_record("foo.other.com") is None

    def test_owner_outside_zone_is_notzone(self):
        """RFC 2136 §3.4.1.3 — an owner outside the declared zone must
        be rejected."""
        store = InMemoryDNSStore()
        server, port = self._server(store)
        # Zone in UPDATE is example.com but the owner is in other.com.
        upd = dns.update.UpdateMessage("example.com")
        upd.add(dns.name.from_text("foo.other.com."), 300, "TXT", '"bad"')
        upd.use_tsig(_keyring(), keyname=dns.name.from_text("client."))
        with server:
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.NOTZONE
        assert store.query_txt_record("foo.other.com") is None

    def test_delete_specific_value(self):
        """Delete-RR-from-RRset: TXT class NONE with the rdata to drop."""
        store = InMemoryDNSStore()
        store.publish_txt_record("foo.example.com", "keep")
        store.publish_txt_record("foo.example.com", "drop")
        server, port = self._server(store)

        upd = dns.update.UpdateMessage("example.com")
        upd.delete(dns.name.from_text("foo.example.com."), "TXT", '"drop"')
        upd.use_tsig(_keyring(), keyname=dns.name.from_text("client."))
        with server:
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.NOERROR
        remaining = store.query_txt_record("foo.example.com")
        assert remaining == ["keep"]

    def test_authorizer_rejects_per_rr_scope(self):
        """The per-RR authorizer can refuse one record, which rejects
        the entire UPDATE so we never apply a partial change."""
        store = InMemoryDNSStore()

        def authorizer(key_name, op, owner):
            return owner.startswith("allowed.")

        server, port = self._server(store, update_authorizer=authorizer)
        upd = dns.update.UpdateMessage("example.com")
        upd.add(dns.name.from_text("allowed.example.com."), 300, "TXT", '"ok"')
        upd.add(dns.name.from_text("denied.example.com."), 300, "TXT", '"no"')
        upd.use_tsig(_keyring(), keyname=dns.name.from_text("client."))
        with server:
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED
        # All-or-nothing: even the allowed name didn't land.
        assert store.query_txt_record("allowed.example.com") is None
        assert store.query_txt_record("denied.example.com") is None

    def test_authorizer_passes_through_when_all_allowed(self):
        store = InMemoryDNSStore()

        seen_calls = []

        def authorizer(key_name, op, owner):
            seen_calls.append((str(key_name), op, owner))
            return True

        server, port = self._server(store, update_authorizer=authorizer)
        with server:
            response = _send_update(self._build_add("ok.example.com", "v"), port)
        assert response.rcode() == dns.rcode.NOERROR
        assert store.query_txt_record("ok.example.com") == ["v"]
        # Authorizer received the verified TSIG key name.
        assert seen_calls and seen_calls[0][0].rstrip(".") == "client"
        assert seen_calls[0][1] == "add"

    def test_anonymous_claim_publish_when_enabled(self):
        """M9.2.6: an un-TSIG'd UPDATE for a claim-record owner with a
        verified ClaimRecord wire is accepted ONLY when the server is
        configured with claim_publish_enabled=True."""
        import hashlib

        from dmp.core.claim import ClaimRecord
        from dmp.core.crypto import DMPCrypto

        store = InMemoryDNSStore()
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring=_keyring(),
            allowed_zones=("example.com",),
            claim_publish_enabled=True,
        )
        # Build a signed ClaimRecord wire.
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        hex12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        now = int(time.time())
        claim = ClaimRecord(
            msg_id=b"\x42" * 16,
            sender_spk=sender.get_signing_public_key_bytes(),
            sender_mailbox_domain="alice.example.com",
            slot=0,
            ts=now,
            exp=now + 300,
        )
        wire = claim.sign(sender)
        owner = f"claim-0.mb-{hex12}.example.com."

        with server:
            upd = dns.update.UpdateMessage("example.com")
            upd.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.NOERROR
        stored = store.query_txt_record(owner.rstrip("."))
        assert stored == [wire]

    def test_anonymous_claim_publish_refuses_overlong_lifetime(self):
        """Codex round-9 P2: claims with exp far past the operator's
        ``claim_max_ttl`` are REFUSED, even when the wire verifies.
        Stops a sender from pinning the RRset against retention."""
        import hashlib

        from dmp.core.claim import ClaimRecord
        from dmp.core.crypto import DMPCrypto

        store = InMemoryDNSStore()
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring=_keyring(),
            allowed_zones=("example.com",),
            claim_publish_enabled=True,
            claim_max_ttl=600,  # 10 minutes
        )
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        hex12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        now = int(time.time())
        # exp 24 hours ahead — well past 10-minute cap.
        claim = ClaimRecord(
            msg_id=b"\x42" * 16,
            sender_spk=sender.get_signing_public_key_bytes(),
            sender_mailbox_domain="alice.example.com",
            slot=0,
            ts=now,
            exp=now + 86400,
        )
        wire = claim.sign(sender)
        owner = f"claim-0.mb-{hex12}.example.com."

        with server:
            upd = dns.update.UpdateMessage("example.com")
            upd.add(
                dns.name.from_text(owner),
                86400,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED
        assert store.query_txt_record(owner.rstrip(".")) is None

    def test_anonymous_claim_publish_refused_when_disabled(self):
        """A node with claim_publish_enabled=False must REFUSE the
        un-TSIG'd claim publish path even for verified wires. Mirrors
        the operator's DMP_CLAIM_PROVIDER=0 intent."""
        import hashlib

        from dmp.core.claim import ClaimRecord
        from dmp.core.crypto import DMPCrypto

        store = InMemoryDNSStore()
        port = _free_port()
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            writer=store,
            tsig_keyring=_keyring(),
            allowed_zones=("example.com",),
            claim_publish_enabled=False,  # opt-out
        )
        sender = DMPCrypto.from_passphrase("alice", salt=b"S" * 32)
        recipient_id = hashlib.sha256(b"recipient").digest()
        hex12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        now = int(time.time())
        claim = ClaimRecord(
            msg_id=b"\x42" * 16,
            sender_spk=sender.get_signing_public_key_bytes(),
            sender_mailbox_domain="alice.example.com",
            slot=0,
            ts=now,
            exp=now + 300,
        )
        wire = claim.sign(sender)
        owner = f"claim-0.mb-{hex12}.example.com."

        with server:
            upd = dns.update.UpdateMessage("example.com")
            upd.add(
                dns.name.from_text(owner),
                300,
                "TXT",
                '"' + wire.replace('"', r"\"") + '"',
            )
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED
        assert store.query_txt_record(owner.rstrip(".")) is None

    def test_oversized_value_refused(self):
        """Codex round-16 P1: max_value_bytes must apply to TSIG UPDATEs
        too. A 600-byte value with the cap at 256 bytes bounces.
        DNS TXT values >255 octets are split into multi-string rdata
        so dnspython accepts them; the server still measures the
        decoded total and enforces the cap."""
        store = InMemoryDNSStore()
        server, port = self._server(store, update_max_value_bytes=256)
        # Three quoted 200-byte strings = 600 bytes when concatenated.
        long_rdata = " ".join(['"' + ("a" * 200) + '"' for _ in range(3)])
        with server:
            upd = dns.update.UpdateMessage("example.com")
            upd.add(
                dns.name.from_text("foo.example.com."),
                300,
                "TXT",
                long_rdata,
            )
            upd.use_tsig(_keyring(), keyname=dns.name.from_text("client."))
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED
        assert store.query_txt_record("foo.example.com") is None

    def test_overlong_ttl_refused(self):
        """update_max_ttl caps the requested DNS RR TTL on UPDATEs."""
        store = InMemoryDNSStore()
        server, port = self._server(store, update_max_ttl=300)
        with server:
            upd = dns.update.UpdateMessage("example.com")
            upd.add(
                dns.name.from_text("foo.example.com."),
                86400,  # 1 day, > cap
                "TXT",
                '"v"',
            )
            upd.use_tsig(_keyring(), keyname=dns.name.from_text("client."))
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED

    def test_too_many_values_for_owner_refused(self):
        """update_max_values_per_name caps the multi-value RRset size
        per UPDATE message."""
        store = InMemoryDNSStore()
        server, port = self._server(store, update_max_values_per_name=2)
        with server:
            upd = dns.update.UpdateMessage("example.com")
            for i in range(3):
                upd.add(
                    dns.name.from_text("foo.example.com."),
                    300,
                    "TXT",
                    f'"v{i}"',
                )
            upd.use_tsig(_keyring(), keyname=dns.name.from_text("client."))
            response = _send_update(upd, port)
        assert response.rcode() == dns.rcode.REFUSED

    def test_cumulative_rrset_cap_across_updates(self):
        """Codex round-17 P2: ``max_values_per_name`` must include
        records ALREADY in the store, not just the adds in the
        current packet. A client sending N single-record UPDATEs
        used to bypass the cap."""
        store = InMemoryDNSStore()
        # Pre-populate two values at the owner.
        store.publish_txt_record("foo.example.com", "v0")
        store.publish_txt_record("foo.example.com", "v1")
        server, port = self._server(store, update_max_values_per_name=2)
        with server:
            upd = dns.update.UpdateMessage("example.com")
            upd.add(
                dns.name.from_text("foo.example.com."),
                300,
                "TXT",
                '"v2"',
            )
            upd.use_tsig(_keyring(), keyname=dns.name.from_text("client."))
            response = _send_update(upd, port)
        # Adding v2 would push the RRset to 3 entries — over the
        # cap of 2. REFUSED.
        assert response.rcode() == dns.rcode.REFUSED
        # And the existing values stayed intact.
        assert sorted(store.query_txt_record("foo.example.com")) == ["v0", "v1"]

    def test_no_writer_means_refused(self):
        """A server constructed without a writer (read-only) refuses
        any UPDATE regardless of TSIG."""
        store = InMemoryDNSStore()
        port = _free_port()
        # writer left unset; server is read-only.
        server = DMPDnsServer(
            store,
            host="127.0.0.1",
            port=port,
            tsig_keyring=_keyring(),
            allowed_zones=("example.com",),
        )
        with server:
            response = _send_update(self._build_add("foo.example.com", "v"), port)
        assert response.rcode() == dns.rcode.REFUSED
        assert store.query_txt_record("foo.example.com") is None
