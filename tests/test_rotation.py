"""Tests for RotationRecord + RevocationRecord wire types (M5.4).

EXPERIMENTAL wire types. See ``dmp/core/rotation.py`` and
``docs/protocol/rotation.md``.

Covers:
- RotationRecord round-trip
- RotationRecord co-signing (both sigs required; single-sig rejected;
  wrong-key rejected on sign; forged second sig rejected on verify)
- RotationRecord security (tampered fields, expected_* binding, expiry,
  invalid subject_type, max-size boundary, truncation)
- RevocationRecord round-trip + security (same shape, single sig)
- RRset naming helpers
"""

from __future__ import annotations

import base64
import time

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.rotation import (
    MAX_SUBJECT_LEN,
    MAX_WIRE_LEN,
    REASON_COMPROMISE,
    REASON_ROUTINE,
    REASON_OTHER,
    RECORD_PREFIX_REVOCATION,
    RECORD_PREFIX_ROTATION,
    SUBJECT_TYPE_BOOTSTRAP_SIGNER,
    SUBJECT_TYPE_CLUSTER_OPERATOR,
    SUBJECT_TYPE_USER_IDENTITY,
    RevocationRecord,
    RotationRecord,
    rotation_rrset_name_bootstrap,
    rotation_rrset_name_cluster,
    rotation_rrset_name_user_identity,
    rotation_rrset_name_zone_anchored,
)

# ---- fixtures / helpers ----------------------------------------------------


def _crypto() -> DMPCrypto:
    return DMPCrypto()


def _make_rotation(
    *,
    old_crypto: DMPCrypto,
    new_crypto: DMPCrypto,
    subject: str = "alice@example.com",
    subject_type: int = SUBJECT_TYPE_USER_IDENTITY,
    seq: int = 1,
    ts: int | None = None,
    exp_delta: int = 3600,
) -> RotationRecord:
    now = int(time.time()) if ts is None else ts
    return RotationRecord(
        subject_type=subject_type,
        subject=subject,
        old_spk=old_crypto.get_signing_public_key_bytes(),
        new_spk=new_crypto.get_signing_public_key_bytes(),
        seq=seq,
        ts=now,
        exp=now + exp_delta,
    )


def _make_revocation(
    *,
    revoked_crypto: DMPCrypto,
    subject: str = "alice@example.com",
    subject_type: int = SUBJECT_TYPE_USER_IDENTITY,
    reason_code: int = REASON_COMPROMISE,
    ts: int | None = None,
) -> RevocationRecord:
    return RevocationRecord(
        subject_type=subject_type,
        subject=subject,
        revoked_spk=revoked_crypto.get_signing_public_key_bytes(),
        reason_code=reason_code,
        ts=int(time.time()) if ts is None else ts,
    )


# ---- RotationRecord round-trip --------------------------------------------


class TestRotationRecordRoundtrip:
    def test_sign_parse_preserves_all_fields(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new, seq=42)
        wire = rec.sign(old, new)
        assert wire.startswith(RECORD_PREFIX_ROTATION)
        parsed = RotationRecord.parse_and_verify(wire)
        assert parsed is not None
        assert parsed.subject_type == rec.subject_type
        assert parsed.subject == rec.subject
        assert parsed.old_spk == rec.old_spk
        assert parsed.new_spk == rec.new_spk
        assert parsed.seq == rec.seq
        assert parsed.ts == rec.ts
        assert parsed.exp == rec.exp

    def test_cluster_subject_roundtrip(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(
            old_crypto=old,
            new_crypto=new,
            subject="mesh.example.com",
            subject_type=SUBJECT_TYPE_CLUSTER_OPERATOR,
        )
        wire = rec.sign(old, new)
        parsed = RotationRecord.parse_and_verify(wire)
        assert parsed is not None
        assert parsed.subject_type == SUBJECT_TYPE_CLUSTER_OPERATOR

    def test_bootstrap_subject_roundtrip(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(
            old_crypto=old,
            new_crypto=new,
            subject="example.com",
            subject_type=SUBJECT_TYPE_BOOTSTRAP_SIGNER,
        )
        wire = rec.sign(old, new)
        parsed = RotationRecord.parse_and_verify(wire)
        assert parsed is not None
        assert parsed.subject_type == SUBJECT_TYPE_BOOTSTRAP_SIGNER


# ---- Co-signing ------------------------------------------------------------


class TestRotationRecordCoSigning:
    def test_sign_rejects_wrong_old_keypair(self):
        old = _crypto()
        new = _crypto()
        imposter = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        with pytest.raises(ValueError, match="old_crypto"):
            rec.sign(imposter, new)

    def test_sign_rejects_wrong_new_keypair(self):
        old = _crypto()
        new = _crypto()
        imposter = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        with pytest.raises(ValueError, match="new_crypto"):
            rec.sign(old, imposter)

    def test_only_old_sig_present_rejected(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        body = rec.to_body_bytes()
        sig_old = old.sign_data(body)
        # Pretend the publisher forgot the new sig and padded with zeros.
        forged = body + sig_old + b"\x00" * 64
        wire = RECORD_PREFIX_ROTATION + base64.b64encode(forged).decode("ascii")
        assert RotationRecord.parse_and_verify(wire) is None

    def test_only_new_sig_present_rejected(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        body = rec.to_body_bytes()
        sig_new = new.sign_data(body)
        forged = body + b"\x00" * 64 + sig_new
        wire = RECORD_PREFIX_ROTATION + base64.b64encode(forged).decode("ascii")
        assert RotationRecord.parse_and_verify(wire) is None

    def test_forged_old_sig_rejected(self):
        old = _crypto()
        new = _crypto()
        imposter = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        body = rec.to_body_bytes()
        # Imposter signs the same body pretending to be old_spk.
        sig_forged = imposter.sign_data(body)
        sig_new = new.sign_data(body)
        forged = body + sig_forged + sig_new
        wire = RECORD_PREFIX_ROTATION + base64.b64encode(forged).decode("ascii")
        assert RotationRecord.parse_and_verify(wire) is None

    def test_forged_new_sig_rejected(self):
        old = _crypto()
        new = _crypto()
        imposter = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        body = rec.to_body_bytes()
        sig_old = old.sign_data(body)
        sig_forged = imposter.sign_data(body)
        forged = body + sig_old + sig_forged
        wire = RECORD_PREFIX_ROTATION + base64.b64encode(forged).decode("ascii")
        assert RotationRecord.parse_and_verify(wire) is None


# ---- Security / binding ----------------------------------------------------


class TestRotationRecordSecurity:
    def _signed(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        return old, new, rec, rec.sign(old, new)

    def test_tamper_old_spk_breaks_verify(self):
        old, new, rec, wire = self._signed()
        blob = base64.b64decode(wire[len(RECORD_PREFIX_ROTATION) :])
        # Flip one byte inside old_spk (at a deterministic offset).
        # Layout: 7 (magic) + 1 (st) + 1 (slen) + len(subject) + 32 (old)
        subject_bytes = rec.subject.encode("utf-8")
        off = 7 + 1 + 1 + len(subject_bytes)
        tampered = bytearray(blob)
        tampered[off] ^= 0x01
        tampered_wire = RECORD_PREFIX_ROTATION + base64.b64encode(
            bytes(tampered)
        ).decode("ascii")
        assert RotationRecord.parse_and_verify(tampered_wire) is None

    def test_tamper_new_spk_breaks_verify(self):
        old, new, rec, wire = self._signed()
        blob = base64.b64decode(wire[len(RECORD_PREFIX_ROTATION) :])
        subject_bytes = rec.subject.encode("utf-8")
        off = 7 + 1 + 1 + len(subject_bytes) + 32
        tampered = bytearray(blob)
        tampered[off] ^= 0x01
        tampered_wire = RECORD_PREFIX_ROTATION + base64.b64encode(
            bytes(tampered)
        ).decode("ascii")
        assert RotationRecord.parse_and_verify(tampered_wire) is None

    def test_tamper_subject_breaks_verify(self):
        old, new, rec, wire = self._signed()
        blob = base64.b64decode(wire[len(RECORD_PREFIX_ROTATION) :])
        off = 7 + 1 + 1  # first byte of subject
        tampered = bytearray(blob)
        tampered[off] ^= 0x01
        tampered_wire = RECORD_PREFIX_ROTATION + base64.b64encode(
            bytes(tampered)
        ).decode("ascii")
        assert RotationRecord.parse_and_verify(tampered_wire) is None

    def test_expected_old_spk_mismatch_rejected(self):
        old, new, rec, wire = self._signed()
        wrong = _crypto().get_signing_public_key_bytes()
        assert RotationRecord.parse_and_verify(wire, expected_old_spk=wrong) is None

    def test_expected_old_spk_match_accepted(self):
        old, new, rec, wire = self._signed()
        assert (
            RotationRecord.parse_and_verify(wire, expected_old_spk=rec.old_spk)
            is not None
        )

    def test_expected_subject_mismatch_rejected(self):
        old, new, rec, wire = self._signed()
        assert (
            RotationRecord.parse_and_verify(wire, expected_subject="eve@example.com")
            is None
        )

    def test_expected_subject_case_insensitive_host(self):
        old, new, rec, wire = self._signed()
        # user@HOST should still match user@host (DNS case-insensitive).
        assert (
            RotationRecord.parse_and_verify(wire, expected_subject="alice@EXAMPLE.COM")
            is not None
        )

    def test_expected_subject_trailing_dot_normalized(self):
        # Cluster subject with trailing dot binds to no-dot form.
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(
            old_crypto=old,
            new_crypto=new,
            subject="mesh.example.com",
            subject_type=SUBJECT_TYPE_CLUSTER_OPERATOR,
        )
        wire = rec.sign(old, new)
        assert (
            RotationRecord.parse_and_verify(
                wire,
                expected_subject="mesh.example.com.",
            )
            is not None
        )

    def test_expired_rejected(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new, exp_delta=-10)
        wire = rec.sign(old, new)
        assert RotationRecord.parse_and_verify(wire) is None

    def test_invalid_subject_type_enum_rejected_on_sign(self):
        old = _crypto()
        new = _crypto()
        bad = RotationRecord(
            subject_type=99,
            subject="alice@example.com",
            old_spk=old.get_signing_public_key_bytes(),
            new_spk=new.get_signing_public_key_bytes(),
            seq=1,
            ts=int(time.time()),
            exp=int(time.time()) + 100,
        )
        with pytest.raises(ValueError, match="subject_type"):
            bad.to_body_bytes()

    def test_same_old_and_new_spk_rejected(self):
        old = _crypto()
        rec = RotationRecord(
            subject_type=SUBJECT_TYPE_USER_IDENTITY,
            subject="alice@example.com",
            old_spk=old.get_signing_public_key_bytes(),
            new_spk=old.get_signing_public_key_bytes(),
            seq=1,
            ts=int(time.time()),
            exp=int(time.time()) + 100,
        )
        with pytest.raises(ValueError, match="differ"):
            rec.to_body_bytes()

    def test_garbage_input_returns_none(self):
        assert RotationRecord.parse_and_verify("not a valid record") is None
        assert RotationRecord.parse_and_verify("") is None
        # Just the prefix.
        assert RotationRecord.parse_and_verify(RECORD_PREFIX_ROTATION) is None
        # Valid prefix, invalid base64.
        assert (
            RotationRecord.parse_and_verify(RECORD_PREFIX_ROTATION + "!!not_b64!!")
            is None
        )

    def test_wire_exceeds_max_wire_len_rejected(self):
        # Valid prefix + enormous base64 body. Must reject, not raise.
        giant = RECORD_PREFIX_ROTATION + ("A" * (MAX_WIRE_LEN + 100))
        assert RotationRecord.parse_and_verify(giant) is None


# ---- Size / boundary -------------------------------------------------------


class TestRotationRecordSize:
    def test_max_subject_64_fits_under_max_wire(self):
        old = _crypto()
        new = _crypto()
        # Build a 64-byte subject that is still user@host valid.
        # "u" * 32 + "@" + "a" * 15 + ".example.com" = 64 bytes (32+1+15+12 = 60)
        # Need 64 exactly. Build: "u"*25 + "@" + label = ...
        # Simpler: use the cluster subject_type and a 64-byte DNS name.
        label15 = "a" * 15
        long_name = ".".join([label15] * 4)  # 63 chars
        long_name = long_name + "b"  # 64 bytes
        assert len(long_name.encode("utf-8")) == MAX_SUBJECT_LEN
        rec = _make_rotation(
            old_crypto=old,
            new_crypto=new,
            subject=long_name,
            subject_type=SUBJECT_TYPE_CLUSTER_OPERATOR,
        )
        wire = rec.sign(old, new)
        assert len(wire.encode("utf-8")) <= MAX_WIRE_LEN

    def test_truncated_wire_rejected(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        wire = rec.sign(old, new)
        # Chop the last ~10 base64 chars (wipes sig_new's tail).
        truncated = wire[:-12]
        assert RotationRecord.parse_and_verify(truncated) is None

    def test_trailing_bytes_after_body_rejected(self):
        old = _crypto()
        new = _crypto()
        rec = _make_rotation(old_crypto=old, new_crypto=new)
        body = rec.to_body_bytes()
        sig_old = old.sign_data(body)
        sig_new = new.sign_data(body)
        # Append a stray byte to the BODY and re-sign; trailing bytes
        # in the body should be rejected even with valid sigs.
        body_with_trailer = body + b"\x00"
        sig_old_t = old.sign_data(body_with_trailer)
        sig_new_t = new.sign_data(body_with_trailer)
        wire = RECORD_PREFIX_ROTATION + base64.b64encode(
            body_with_trailer + sig_old_t + sig_new_t
        ).decode("ascii")
        assert RotationRecord.parse_and_verify(wire) is None


# ---- RevocationRecord ------------------------------------------------------


class TestRevocationRecordRoundtrip:
    def test_sign_parse_preserves_all_fields(self):
        revoked = _crypto()
        rec = _make_revocation(revoked_crypto=revoked, reason_code=REASON_ROUTINE)
        wire = rec.sign(revoked)
        assert wire.startswith(RECORD_PREFIX_REVOCATION)
        parsed = RevocationRecord.parse_and_verify(wire)
        assert parsed is not None
        assert parsed.subject_type == rec.subject_type
        assert parsed.subject == rec.subject
        assert parsed.revoked_spk == rec.revoked_spk
        assert parsed.reason_code == rec.reason_code
        assert parsed.ts == rec.ts

    def test_cluster_subject_roundtrip(self):
        revoked = _crypto()
        rec = _make_revocation(
            revoked_crypto=revoked,
            subject="mesh.example.com",
            subject_type=SUBJECT_TYPE_CLUSTER_OPERATOR,
        )
        wire = rec.sign(revoked)
        parsed = RevocationRecord.parse_and_verify(wire)
        assert parsed is not None
        assert parsed.subject == "mesh.example.com"


class TestRevocationRecordSecurity:
    def test_sign_rejects_wrong_keypair(self):
        revoked = _crypto()
        imposter = _crypto()
        rec = _make_revocation(revoked_crypto=revoked)
        with pytest.raises(ValueError, match="revoked_crypto"):
            rec.sign(imposter)

    def test_tampered_wire_rejected(self):
        revoked = _crypto()
        rec = _make_revocation(revoked_crypto=revoked)
        wire = rec.sign(revoked)
        blob = bytearray(base64.b64decode(wire[len(RECORD_PREFIX_REVOCATION) :]))
        # Flip a bit in the body (inside revoked_spk).
        off = 7 + 1 + 1 + len(rec.subject.encode("utf-8"))
        blob[off] ^= 0x01
        tampered = RECORD_PREFIX_REVOCATION + base64.b64encode(bytes(blob)).decode(
            "ascii"
        )
        assert RevocationRecord.parse_and_verify(tampered) is None

    def test_expected_revoked_spk_mismatch_rejected(self):
        revoked = _crypto()
        rec = _make_revocation(revoked_crypto=revoked)
        wire = rec.sign(revoked)
        wrong = _crypto().get_signing_public_key_bytes()
        assert (
            RevocationRecord.parse_and_verify(wire, expected_revoked_spk=wrong) is None
        )

    def test_expected_subject_mismatch_rejected(self):
        revoked = _crypto()
        rec = _make_revocation(revoked_crypto=revoked)
        wire = rec.sign(revoked)
        assert (
            RevocationRecord.parse_and_verify(wire, expected_subject="eve@example.com")
            is None
        )

    def test_stale_revocation_rejected(self):
        revoked = _crypto()
        now = int(time.time())
        # Revocation from 2 years ago with default 1-year max_age.
        rec = _make_revocation(revoked_crypto=revoked, ts=now - 86400 * 365 * 2)
        wire = rec.sign(revoked)
        assert RevocationRecord.parse_and_verify(wire) is None

    def test_future_ts_rejected(self):
        revoked = _crypto()
        now = int(time.time())
        rec = _make_revocation(revoked_crypto=revoked, ts=now + 86400)
        wire = rec.sign(revoked)
        assert RevocationRecord.parse_and_verify(wire) is None

    def test_invalid_reason_code_rejected(self):
        revoked = _crypto()
        bad = RevocationRecord(
            subject_type=SUBJECT_TYPE_USER_IDENTITY,
            subject="alice@example.com",
            revoked_spk=revoked.get_signing_public_key_bytes(),
            reason_code=99,
            ts=int(time.time()),
        )
        with pytest.raises(ValueError, match="reason_code"):
            bad.to_body_bytes()

    def test_all_reason_codes_valid(self):
        revoked = _crypto()
        for code in (
            REASON_COMPROMISE,
            REASON_ROUTINE,
            # REASON_LOST_KEY accepted on the wire even though a truly
            # lost key cannot self-sign — an operator might still
            # document the loss via a backup key that was recorded
            # out-of-band before the loss.
            3,
            REASON_OTHER,
        ):
            rec = _make_revocation(revoked_crypto=revoked, reason_code=code)
            wire = rec.sign(revoked)
            parsed = RevocationRecord.parse_and_verify(wire)
            assert parsed is not None
            assert parsed.reason_code == code

    def test_garbage_input_returns_none(self):
        assert RevocationRecord.parse_and_verify("not a record") is None
        assert RevocationRecord.parse_and_verify("") is None
        assert RevocationRecord.parse_and_verify(RECORD_PREFIX_REVOCATION) is None
        assert (
            RevocationRecord.parse_and_verify(RECORD_PREFIX_REVOCATION + "!!bad!!")
            is None
        )


# ---- RRset naming ----------------------------------------------------------


class TestRotationRRsetNames:
    def test_user_identity_name_stable(self):
        n = rotation_rrset_name_user_identity("alice", "example.com")
        # Convention is `rotate.dmp.<hash>.<domain>`; don't hard-code the
        # hash, just check it includes the parent zone.
        assert n.startswith("rotate.")
        assert n.endswith(".example.com")

    def test_zone_anchored_name(self):
        assert (
            rotation_rrset_name_zone_anchored("alice.example.com")
            == "rotate.dmp.alice.example.com"
        )

    def test_cluster_name(self):
        assert (
            rotation_rrset_name_cluster("mesh.example.com")
            == "rotate.cluster.mesh.example.com"
        )

    def test_bootstrap_name(self):
        assert rotation_rrset_name_bootstrap("example.com") == "rotate._dmp.example.com"

    def test_cluster_name_rejects_invalid(self):
        with pytest.raises(ValueError):
            rotation_rrset_name_cluster("")
        with pytest.raises(ValueError):
            rotation_rrset_name_cluster("bad..label")

    def test_bootstrap_name_normalizes_trailing_dot(self):
        assert (
            rotation_rrset_name_bootstrap("example.com.") == "rotate._dmp.example.com"
        )
