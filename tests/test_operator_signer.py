"""Tests for dmp.core.operator_signer — lightweight Ed25519 signer."""

from __future__ import annotations

import secrets

import pytest

from dmp.core.heartbeat import HeartbeatRecord
from dmp.core.operator_signer import OperatorSigner


class TestConstruction:
    def test_accepts_32_bytes(self) -> None:
        s = OperatorSigner(b"\x00" * 32)
        assert len(s.get_signing_public_key_bytes()) == 32

    def test_rejects_wrong_length(self) -> None:
        for bad in (b"", b"a", b"a" * 31, b"a" * 33, b"a" * 64):
            with pytest.raises(ValueError, match="32 bytes"):
                OperatorSigner(bad)

    def test_rejects_non_bytes(self) -> None:
        with pytest.raises(ValueError):
            OperatorSigner("string not bytes")  # type: ignore[arg-type]

    def test_from_hex_accepts_64_chars(self) -> None:
        seed_hex = "aa" * 32
        s = OperatorSigner.from_hex(seed_hex)
        assert isinstance(s.get_signing_public_key_bytes(), bytes)

    def test_from_hex_rejects_wrong_length(self) -> None:
        for bad in ("", "a", "a" * 63, "a" * 65):
            with pytest.raises(ValueError, match="64 hex chars"):
                OperatorSigner.from_hex(bad)

    def test_from_hex_rejects_non_hex(self) -> None:
        with pytest.raises(ValueError, match="not valid hex"):
            OperatorSigner.from_hex("z" * 64)

    def test_from_hex_strips_whitespace(self) -> None:
        # A trailing newline from a file-read must not break the loader.
        seed_hex = "aa" * 32
        s = OperatorSigner.from_hex(seed_hex + "\n")
        assert (
            s.get_signing_public_key_bytes()
            == OperatorSigner.from_hex(seed_hex).get_signing_public_key_bytes()
        )


class TestSign:
    def test_sign_produces_64_byte_signature(self) -> None:
        s = OperatorSigner(b"\x11" * 32)
        sig = s.sign_data(b"hello")
        assert len(sig) == 64

    def test_sign_rejects_non_bytes(self) -> None:
        s = OperatorSigner(b"\x11" * 32)
        with pytest.raises(TypeError, match="bytes"):
            s.sign_data("not bytes")  # type: ignore[arg-type]

    def test_different_seeds_produce_different_pubkeys(self) -> None:
        s1 = OperatorSigner(b"\x01" * 32)
        s2 = OperatorSigner(b"\x02" * 32)
        assert s1.get_signing_public_key_bytes() != s2.get_signing_public_key_bytes()

    def test_same_seed_deterministic_pubkey(self) -> None:
        seed = secrets.token_bytes(32)
        a = OperatorSigner(seed)
        b = OperatorSigner(seed)
        assert a.get_signing_public_key_bytes() == b.get_signing_public_key_bytes()


class TestIntegrationWithHeartbeat:
    """The real test: OperatorSigner must be acceptable as the
    `operator_crypto` argument to ``HeartbeatRecord.sign``."""

    def test_sign_and_verify_heartbeat(self) -> None:
        seed = b"\x42" * 32
        signer = OperatorSigner(seed)
        spk = signer.get_signing_public_key_bytes()

        import time

        hb = HeartbeatRecord(
            endpoint="https://dmp.example.com",
            operator_spk=spk,
            version="0.1.0",
            ts=int(time.time()),
            exp=int(time.time()) + 86400,
        )
        wire = hb.sign(signer)
        parsed = HeartbeatRecord.parse_and_verify(wire)
        assert parsed is not None
        assert parsed.operator_spk == spk
