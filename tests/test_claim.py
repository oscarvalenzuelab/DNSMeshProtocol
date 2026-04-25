"""Tests for the M8.2 claim record wire format."""

import base64
import hashlib
import os
import struct
import time

import pytest

from dmp.core.claim import (
    MAX_MAILBOX_DOMAIN_LEN,
    MAX_SLOT,
    MAX_WIRE_LEN,
    RECORD_PREFIX,
    ClaimRecord,
    claim_rrset_name,
)
from dmp.core.crypto import DMPCrypto


def _crypto() -> DMPCrypto:
    return DMPCrypto.from_passphrase("alice-pass")


def _claim(
    *,
    sender_spk: bytes = None,
    sender_mailbox_domain: str = "alice.mesh",
    slot: int = 3,
    msg_id: bytes = None,
    ts: int = None,
    exp: int = None,
) -> ClaimRecord:
    if sender_spk is None:
        sender_spk = _crypto().get_signing_public_key_bytes()
    if msg_id is None:
        msg_id = b"\x11" * 16
    if ts is None:
        ts = int(time.time())
    if exp is None:
        exp = ts + 300
    return ClaimRecord(
        msg_id=msg_id,
        sender_spk=sender_spk,
        sender_mailbox_domain=sender_mailbox_domain,
        slot=slot,
        ts=ts,
        exp=exp,
    )


class TestRoundtrip:
    def test_sign_parse_roundtrip(self):
        c = _crypto()
        record = _claim(sender_spk=c.get_signing_public_key_bytes())
        wire = record.sign(c)
        parsed = ClaimRecord.parse_and_verify(wire)
        assert parsed is not None
        assert parsed.msg_id == record.msg_id
        assert parsed.sender_spk == record.sender_spk
        assert parsed.sender_mailbox_domain == record.sender_mailbox_domain
        assert parsed.slot == record.slot
        assert parsed.ts == record.ts
        assert parsed.exp == record.exp

    def test_wire_starts_with_prefix(self):
        c = _crypto()
        record = _claim(sender_spk=c.get_signing_public_key_bytes())
        wire = record.sign(c)
        assert wire.startswith(RECORD_PREFIX)

    def test_wire_under_dns_limit(self):
        """A claim must fit a single DNS TXT string (255 bytes)."""
        c = _crypto()
        record = _claim(
            sender_spk=c.get_signing_public_key_bytes(),
            sender_mailbox_domain="x" * MAX_MAILBOX_DOMAIN_LEN,
        )
        wire = record.sign(c)
        assert len(wire.encode("utf-8")) <= MAX_WIRE_LEN

    def test_wire_under_dns_limit_typical(self):
        c = _crypto()
        record = _claim(
            sender_spk=c.get_signing_public_key_bytes(),
            sender_mailbox_domain="alice.dnsmesh.io",
        )
        wire = record.sign(c)
        assert len(wire.encode("utf-8")) <= MAX_WIRE_LEN


class TestSignatureVerification:
    def test_wrong_key_in_sign_raises(self):
        record = _claim()
        # The crypto signing this is alice's; record claims spk = b'\x00'*32
        with pytest.raises(ValueError, match="does not match"):
            record_wrong = ClaimRecord(
                msg_id=record.msg_id,
                sender_spk=b"\x00" * 32,
                sender_mailbox_domain=record.sender_mailbox_domain,
                slot=record.slot,
                ts=record.ts,
                exp=record.exp,
            )
            record_wrong.sign(_crypto())

    def test_tampered_body_rejected(self):
        c = _crypto()
        record = _claim(sender_spk=c.get_signing_public_key_bytes())
        wire = record.sign(c)
        # Decode, flip a bit in the body (not the signature), re-encode.
        blob = base64.b64decode(wire[len(RECORD_PREFIX) :])
        body = bytearray(blob[:-64])
        sig = blob[-64:]
        # Flip a bit in the magic byte.
        body[0] ^= 0x01
        tampered = base64.b64encode(bytes(body) + sig).decode("ascii")
        bad_wire = f"{RECORD_PREFIX}{tampered}"
        assert ClaimRecord.parse_and_verify(bad_wire) is None

    def test_signature_by_other_key_rejected(self):
        c1 = DMPCrypto.from_passphrase("alice-pass")
        c2 = DMPCrypto.from_passphrase("eve-pass")
        record = ClaimRecord(
            msg_id=b"\x11" * 16,
            sender_spk=c1.get_signing_public_key_bytes(),
            sender_mailbox_domain="alice.mesh",
            slot=0,
            ts=int(time.time()),
            exp=int(time.time()) + 300,
        )
        # The dataclass declares spk = c1; if eve signs, parse_and_verify
        # will fail signature check (eve's sig over a body declaring c1
        # as sender_spk doesn't verify against c1's pubkey).
        body = record.to_body_bytes()
        sig = c2.sign_data(body)
        wire = f"{RECORD_PREFIX}{base64.b64encode(body + sig).decode('ascii')}"
        assert ClaimRecord.parse_and_verify(wire) is None


class TestParserRejections:
    def test_wrong_prefix_returns_none(self):
        assert ClaimRecord.parse_and_verify("v=dmp1;t=heartbeat;abc") is None

    def test_garbage_returns_none(self):
        assert ClaimRecord.parse_and_verify("not a wire record") is None
        assert ClaimRecord.parse_and_verify("") is None
        assert ClaimRecord.parse_and_verify(None) is None  # type: ignore

    def test_oversize_returns_none(self):
        oversized = RECORD_PREFIX + "A" * (MAX_WIRE_LEN + 1)
        assert ClaimRecord.parse_and_verify(oversized) is None

    def test_bad_base64_returns_none(self):
        wire = f"{RECORD_PREFIX}!!!not-base64!!!"
        assert ClaimRecord.parse_and_verify(wire) is None

    def test_too_short_blob_returns_none(self):
        # A 2-byte blob can't even hold a full signature.
        wire = f"{RECORD_PREFIX}{base64.b64encode(b'aa').decode('ascii')}"
        assert ClaimRecord.parse_and_verify(wire) is None


class TestFreshness:
    def test_expired_returns_none(self):
        c = _crypto()
        ts = int(time.time()) - 1000
        record = _claim(
            sender_spk=c.get_signing_public_key_bytes(),
            ts=ts,
            exp=ts + 300,  # exp well in the past
        )
        wire = record.sign(c)
        assert ClaimRecord.parse_and_verify(wire) is None

    def test_far_future_ts_rejected(self):
        c = _crypto()
        ts = int(time.time()) + 86400  # well past the 5-min skew
        record = _claim(
            sender_spk=c.get_signing_public_key_bytes(),
            ts=ts,
            exp=ts + 300,
        )
        wire = record.sign(c)
        assert ClaimRecord.parse_and_verify(wire) is None

    def test_within_skew_accepted(self):
        c = _crypto()
        ts = int(time.time()) - 60  # 1 minute ago, well within skew
        record = _claim(
            sender_spk=c.get_signing_public_key_bytes(),
            ts=ts,
            exp=ts + 600,
        )
        wire = record.sign(c)
        assert ClaimRecord.parse_and_verify(wire) is not None


class TestFieldValidation:
    def test_msg_id_wrong_length_rejected(self):
        with pytest.raises(ValueError, match="msg_id"):
            ClaimRecord(
                msg_id=b"\x11" * 8,
                sender_spk=b"\x33" * 32,
                sender_mailbox_domain="x.mesh",
                slot=0,
                ts=1,
                exp=2,
            ).to_body_bytes()

    def test_slot_out_of_range_rejected(self):
        with pytest.raises(ValueError, match="slot"):
            ClaimRecord(
                msg_id=b"\x11" * 16,
                sender_spk=b"\x33" * 32,
                sender_mailbox_domain="x.mesh",
                slot=MAX_SLOT + 1,
                ts=1,
                exp=2,
            ).to_body_bytes()

    def test_empty_mailbox_domain_rejected(self):
        with pytest.raises(ValueError, match="sender_mailbox_domain"):
            ClaimRecord(
                msg_id=b"\x11" * 16,
                sender_spk=b"\x33" * 32,
                sender_mailbox_domain="",
                slot=0,
                ts=1,
                exp=2,
            ).to_body_bytes()

    def test_oversized_mailbox_domain_rejected(self):
        with pytest.raises(ValueError, match="sender_mailbox_domain"):
            ClaimRecord(
                msg_id=b"\x11" * 16,
                sender_spk=b"\x33" * 32,
                sender_mailbox_domain="x" * (MAX_MAILBOX_DOMAIN_LEN + 1),
                slot=0,
                ts=1,
                exp=2,
            ).to_body_bytes()

    def test_control_chars_in_mailbox_domain_rejected(self):
        """Defends against `a.mesh\nslot-0...` injection into chunk-zone derivation."""
        with pytest.raises(ValueError, match="whitespace or control"):
            ClaimRecord(
                msg_id=b"\x11" * 16,
                sender_spk=b"\x33" * 32,
                sender_mailbox_domain="evil.mesh\nslot-0",
                slot=0,
                ts=1,
                exp=2,
            ).to_body_bytes()


class TestRRsetName:
    def test_rrset_name_shape(self):
        recipient_id = b"\x42" * 32
        h12 = hashlib.sha256(recipient_id).hexdigest()[:12]
        name = claim_rrset_name(recipient_id, slot=3, provider_zone="claims.mesh")
        assert name == f"claim-3.mb-{h12}.claims.mesh"

    def test_rrset_name_rejects_bad_recipient_id(self):
        with pytest.raises(ValueError, match="recipient_id"):
            claim_rrset_name(b"too-short", 0, "claims.mesh")

    def test_rrset_name_rejects_bad_slot(self):
        with pytest.raises(ValueError, match="slot"):
            claim_rrset_name(b"\x42" * 32, slot=MAX_SLOT + 1, provider_zone="claims.mesh")

    def test_rrset_name_rejects_empty_zone(self):
        with pytest.raises(ValueError, match="provider_zone"):
            claim_rrset_name(b"\x42" * 32, 0, "")
