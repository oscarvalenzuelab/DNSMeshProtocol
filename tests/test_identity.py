"""Tests for signed identity records."""

import base64
import time

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.identity import (
    IdentityRecord,
    RECORD_PREFIX,
    identity_domain,
    make_record,
)


class TestIdentityRecord:
    def test_sign_parse_roundtrip(self):
        crypto = DMPCrypto()
        rec = make_record(crypto, "alice")

        wire = rec.sign(crypto)
        assert wire.startswith(RECORD_PREFIX)
        assert len(wire.encode("utf-8")) <= 255  # fits a single DNS TXT string

        result = IdentityRecord.parse_and_verify(wire)
        assert result is not None
        parsed, _ = result
        assert parsed.username == "alice"
        assert parsed.x25519_pk == crypto.get_public_key_bytes()
        assert parsed.ed25519_spk == crypto.get_signing_public_key_bytes()

    def test_tampered_body_rejected(self):
        crypto = DMPCrypto()
        rec = make_record(crypto, "alice")
        wire = rec.sign(crypto)

        body_sig = bytearray(base64.b64decode(wire[len(RECORD_PREFIX):]))
        body_sig[1] ^= 0xFF  # flip a bit inside the username
        tampered = RECORD_PREFIX + base64.b64encode(bytes(body_sig)).decode("ascii")
        assert IdentityRecord.parse_and_verify(tampered) is None

    def test_wrong_signer_rejected(self):
        real = DMPCrypto()
        impostor = DMPCrypto()
        rec = make_record(real, "alice")
        # Build a wire record whose embedded ed25519_spk is real's but whose
        # signature is impostor's — verification must fail.
        body = rec.to_body_bytes()
        sig = impostor.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        assert IdentityRecord.parse_and_verify(wire) is None

    def test_empty_username_rejected(self):
        crypto = DMPCrypto()
        rec = IdentityRecord(
            username="",
            x25519_pk=crypto.get_public_key_bytes(),
            ed25519_spk=crypto.get_signing_public_key_bytes(),
            ts=int(time.time()),
        )
        with pytest.raises(ValueError):
            rec.to_body_bytes()

    def test_long_username_rejected(self):
        crypto = DMPCrypto()
        rec = IdentityRecord(
            username="x" * 100,
            x25519_pk=crypto.get_public_key_bytes(),
            ed25519_spk=crypto.get_signing_public_key_bytes(),
            ts=int(time.time()),
        )
        with pytest.raises(ValueError):
            rec.to_body_bytes()

    def test_malformed_wire_returns_none(self):
        assert IdentityRecord.parse_and_verify("not-a-dmp-record") is None
        assert IdentityRecord.parse_and_verify(RECORD_PREFIX + "not-base64!") is None
        # Correct prefix, valid base64, but too short.
        too_short = base64.b64encode(b"x").decode("ascii")
        assert IdentityRecord.parse_and_verify(RECORD_PREFIX + too_short) is None


class TestIdentityDomain:
    def test_domain_stable_per_username(self):
        a = identity_domain("alice", "mesh.example.com")
        b = identity_domain("alice", "mesh.example.com")
        assert a == b

    def test_different_usernames_differ(self):
        assert identity_domain("alice", "mesh.example.com") != identity_domain(
            "bob", "mesh.example.com"
        )

    def test_hides_plaintext_username(self):
        d = identity_domain("alice", "mesh.example.com")
        # DNS label should be the sha256 hex prefix, not the plaintext name.
        assert "alice" not in d
        assert d.startswith("id-")
