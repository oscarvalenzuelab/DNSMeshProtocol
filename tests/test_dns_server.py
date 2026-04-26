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
        """Values > 255 bytes get emitted as multi-string TXT records."""
        store = InMemoryDNSStore()
        long_value = "B" * 600
        store.publish_txt_record("long.mesh.test", long_value)

        port = _free_port()
        with DMPDnsServer(store, host="127.0.0.1", port=port):
            response = self._query("long.mesh.test", "127.0.0.1", port)

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
