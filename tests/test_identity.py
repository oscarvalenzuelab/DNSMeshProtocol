"""Tests for signed identity records."""

import base64
import time

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.identity import (
    IdentityRecord,
    RECORD_PREFIX,
    SUPPORTED_VERSIONS,
    identity_domain,
    make_record,
    parse_address,
    zone_anchored_identity_name,
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

        body_sig = bytearray(base64.b64decode(wire[len(RECORD_PREFIX) :]))
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


class TestIdentityRecordVersions:
    """Backward-compat + roundtrip for the optional `versions` suffix."""

    def test_default_make_record_is_v1_compatible(self):
        """``make_record`` defaults to ``versions=(1,)`` so the wire bytes
        produced on disk are byte-identical to the pre-versions historical
        encoding. Pre-this-PR parsers still reject any body with extra
        trailing bytes, so silently flipping the default would break
        every un-upgraded peer's ability to fetch the record. Senders
        that want to advertise v2 must opt in explicitly via
        ``versions=SUPPORTED_VERSIONS``."""
        crypto = DMPCrypto()
        rec = make_record(crypto, "alice")
        assert rec.versions == (1,)
        # SUPPORTED_VERSIONS is what an opt-in caller would pass.
        assert 1 in SUPPORTED_VERSIONS and 2 in SUPPORTED_VERSIONS

    def test_explicit_supported_versions_opts_in(self):
        crypto = DMPCrypto()
        rec = make_record(crypto, "alice", versions=SUPPORTED_VERSIONS)
        assert rec.versions == SUPPORTED_VERSIONS

    def test_v1_only_record_has_no_suffix_on_wire(self):
        """A record explicitly publishing versions=(1,) must be
        bit-identical to the pre-versions historical encoding so old
        verifiers and pre-versions body-hash caches continue to match."""
        crypto = DMPCrypto()
        rec = IdentityRecord(
            username="alice",
            x25519_pk=crypto.get_public_key_bytes(),
            ed25519_spk=crypto.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=(1,),
        )
        body = rec.to_body_bytes()
        # Body length = 1 (name_len) + 5 (name) + 32 + 32 + 8 = 78. No suffix.
        assert len(body) == 1 + 5 + 32 + 32 + 8

    def test_multi_version_record_appends_suffix(self):
        crypto = DMPCrypto()
        rec = IdentityRecord(
            username="alice",
            x25519_pk=crypto.get_public_key_bytes(),
            ed25519_spk=crypto.get_signing_public_key_bytes(),
            ts=1_700_000_000,
            versions=(1, 2),
        )
        body = rec.to_body_bytes()
        # Body length = 78 (base) + 1 (versions_len) + 2 (two version bytes) = 81.
        assert len(body) == 78 + 1 + 2
        # Last 3 bytes are the suffix: len=2 then [1, 2] sorted.
        assert body[-3:] == bytes([2, 1, 2])

    def test_roundtrip_multi_version(self):
        crypto = DMPCrypto()
        rec = make_record(crypto, "alice", versions=(1, 2, 7))
        wire = rec.sign(crypto)
        parsed, _ = IdentityRecord.parse_and_verify(wire)
        assert parsed.versions == (1, 2, 7)

    def test_old_record_parses_as_v1_only(self):
        """A record published before the versions field existed has no
        suffix on the wire. Parsing must default to (1,)."""
        crypto = DMPCrypto()
        # Build a body in the pre-versions format (no suffix at all).
        username = "alice".encode("utf-8")
        body = (
            len(username).to_bytes(1, "big")
            + username
            + crypto.get_public_key_bytes()
            + crypto.get_signing_public_key_bytes()
            + (1_700_000_000).to_bytes(8, "big")
        )
        sig = crypto.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        result = IdentityRecord.parse_and_verify(wire)
        assert result is not None
        parsed, _ = result
        assert parsed.versions == (1,)

    def test_versions_constructor_normalizes(self):
        """Out-of-order or duplicate versions are sorted+deduped."""
        crypto = DMPCrypto()
        rec = make_record(crypto, "alice", versions=(2, 1, 2, 7))
        assert rec.versions == (1, 2, 7)

    def test_empty_versions_rejected(self):
        crypto = DMPCrypto()
        with pytest.raises(ValueError):
            make_record(crypto, "alice", versions=())

    def test_out_of_range_version_rejected(self):
        crypto = DMPCrypto()
        with pytest.raises(ValueError):
            make_record(crypto, "alice", versions=(1, 256))

    def test_unsorted_wire_suffix_rejected(self):
        """A wire suffix where versions are not sorted must reject —
        forces senders to use the canonical (sorted+unique) encoding."""
        crypto = DMPCrypto()
        username = "alice".encode("utf-8")
        body = (
            len(username).to_bytes(1, "big")
            + username
            + crypto.get_public_key_bytes()
            + crypto.get_signing_public_key_bytes()
            + (1_700_000_000).to_bytes(8, "big")
            + (2).to_bytes(1, "big")  # versions_len = 2
            + bytes([2, 1])  # unsorted
        )
        sig = crypto.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        # parse_and_verify returns None on any from_body_bytes ValueError.
        assert IdentityRecord.parse_and_verify(wire) is None

    def test_empty_versions_suffix_on_wire_rejected(self):
        """A versions_len of 0 in the wire suffix must reject."""
        crypto = DMPCrypto()
        username = "alice".encode("utf-8")
        body = (
            len(username).to_bytes(1, "big")
            + username
            + crypto.get_public_key_bytes()
            + crypto.get_signing_public_key_bytes()
            + (1_700_000_000).to_bytes(8, "big")
            + b"\x00"  # versions_len = 0 (illegal)
        )
        sig = crypto.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        assert IdentityRecord.parse_and_verify(wire) is None


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


class TestZoneAnchoredIdentity:
    def test_zone_anchored_name_format(self):
        assert (
            zone_anchored_identity_name("alice.example.com") == "dmp.alice.example.com"
        )

    def test_zone_anchored_strips_trailing_dot(self):
        assert (
            zone_anchored_identity_name("alice.example.com.") == "dmp.alice.example.com"
        )

    def test_parse_address_splits_user_and_host(self):
        assert parse_address("alice@alice.example.com") == (
            "alice",
            "alice.example.com",
        )

    def test_parse_address_strips_whitespace_and_dot(self):
        assert parse_address("  alice @ alice.example.com. ") == (
            "alice",
            "alice.example.com",
        )

    def test_parse_address_rejects_malformed(self):
        assert parse_address("no-at-sign") is None
        assert parse_address("@nohost.example.com") is None
        assert parse_address("nouser@") is None
        assert parse_address("@") is None
        assert parse_address("") is None
