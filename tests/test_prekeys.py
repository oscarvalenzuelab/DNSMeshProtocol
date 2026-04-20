"""Tests for X3DH-style prekey records and the local prekey store."""

import base64
import time

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.prekeys import (
    Prekey,
    PrekeyStore,
    RECORD_PREFIX,
    prekey_rrset_name,
)


class TestPrekeyRecord:
    def test_sign_parse_roundtrip(self):
        identity = DMPCrypto()
        sk = DMPCrypto()
        pk = Prekey(
            prekey_id=42,
            public_key=sk.get_public_key_bytes(),
            exp=int(time.time()) + 86400,
        )
        wire = pk.sign(identity)
        assert wire.startswith(RECORD_PREFIX)
        assert len(wire.encode("utf-8")) <= 255

        parsed = Prekey.parse_and_verify(wire, identity.get_signing_public_key_bytes())
        assert parsed is not None
        assert parsed.prekey_id == 42
        assert parsed.public_key == sk.get_public_key_bytes()

    def test_wrong_signer_rejected(self):
        real = DMPCrypto()
        impostor = DMPCrypto()
        sk = DMPCrypto()
        pk = Prekey(
            prekey_id=1,
            public_key=sk.get_public_key_bytes(),
            exp=int(time.time()) + 86400,
        )
        wire = pk.sign(real)
        # Verify against the wrong Ed25519 key → None.
        assert (
            Prekey.parse_and_verify(wire, impostor.get_signing_public_key_bytes())
            is None
        )

    def test_tampered_wire_rejected(self):
        identity = DMPCrypto()
        sk = DMPCrypto()
        pk = Prekey(
            prekey_id=1,
            public_key=sk.get_public_key_bytes(),
            exp=int(time.time()) + 86400,
        )
        wire = pk.sign(identity)
        # Flip a byte inside the signed body.
        mangled = bytearray(base64.b64decode(wire[len(RECORD_PREFIX) :]))
        mangled[0] ^= 0xFF
        tampered = RECORD_PREFIX + base64.b64encode(bytes(mangled)).decode("ascii")
        assert (
            Prekey.parse_and_verify(tampered, identity.get_signing_public_key_bytes())
            is None
        )

    def test_malformed_wire_returns_none(self):
        identity = DMPCrypto()
        assert (
            Prekey.parse_and_verify("garbage", identity.get_signing_public_key_bytes())
            is None
        )
        assert (
            Prekey.parse_and_verify(
                RECORD_PREFIX + "not-base64!!",
                identity.get_signing_public_key_bytes(),
            )
            is None
        )
        short = base64.b64encode(b"too short").decode("ascii")
        assert (
            Prekey.parse_and_verify(
                RECORD_PREFIX + short, identity.get_signing_public_key_bytes()
            )
            is None
        )

    def test_expiry_flag(self):
        now = int(time.time())
        past = Prekey(prekey_id=0, public_key=b"\x00" * 32, exp=now - 1)
        future = Prekey(prekey_id=0, public_key=b"\x00" * 32, exp=now + 60)
        assert past.is_expired()
        assert not future.is_expired()


class TestPrekeyStore:
    def test_generate_and_lookup(self, tmp_path):
        store = PrekeyStore(str(tmp_path / "prekeys.db"))
        try:
            pool = store.generate_pool(count=5, ttl_seconds=3600)
            assert len(pool) == 5
            assert store.count_live() == 5

            # Lookup each sk.
            for prekey, sk in pool:
                fetched = store.get_private_key(prekey.prekey_id)
                assert fetched is not None
                # Can't compare X25519PrivateKey instances directly; compare
                # via their derived pubkeys.
                from cryptography.hazmat.primitives import serialization

                fetched_pub = fetched.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                assert fetched_pub == prekey.public_key
        finally:
            store.close()

    def test_consume_deletes_private_key(self, tmp_path):
        store = PrekeyStore(str(tmp_path / "p.db"))
        try:
            pool = store.generate_pool(count=1, ttl_seconds=3600)
            pid = pool[0][0].prekey_id
            assert store.get_private_key(pid) is not None
            assert store.consume(pid)
            assert store.get_private_key(pid) is None
            assert not store.consume(pid)  # idempotent second delete
        finally:
            store.close()

    def test_expired_row_filtered_from_lookup(self, tmp_path):
        store = PrekeyStore(str(tmp_path / "p.db"))
        try:
            pool = store.generate_pool(count=1, ttl_seconds=0)
            # ttl=0 → exp == now; the query uses strict ">".
            assert store.get_private_key(pool[0][0].prekey_id) is None
        finally:
            store.close()

    def test_cleanup_expired(self, tmp_path):
        store = PrekeyStore(str(tmp_path / "p.db"))
        try:
            store.generate_pool(count=3, ttl_seconds=0)  # expired
            store.generate_pool(count=2, ttl_seconds=3600)  # live
            deleted = store.cleanup_expired()
            assert deleted == 3
            assert store.count_live() == 2
        finally:
            store.close()

    def test_persistence_across_reopen(self, tmp_path):
        db = str(tmp_path / "p.db")
        s1 = PrekeyStore(db)
        pool = s1.generate_pool(count=2, ttl_seconds=3600)
        pid = pool[0][0].prekey_id
        s1.close()

        s2 = PrekeyStore(db)
        try:
            assert s2.get_private_key(pid) is not None
        finally:
            s2.close()


class TestRrsetNaming:
    def test_hashed_label(self):
        name = prekey_rrset_name("alice", "mesh.example.com")
        assert name.startswith("prekeys.id-")
        assert name.endswith(".mesh.example.com")
        # Hash is stable.
        assert name == prekey_rrset_name("alice", "mesh.example.com")
        assert name != prekey_rrset_name("bob", "mesh.example.com")
