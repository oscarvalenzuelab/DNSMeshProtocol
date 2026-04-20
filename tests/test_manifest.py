"""Tests for signed slot manifests and replay cache."""

import time
import uuid

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.manifest import ReplayCache, SlotManifest


def _make_manifest(sender: DMPCrypto, recipient: DMPCrypto, now: int) -> SlotManifest:
    import hashlib
    return SlotManifest(
        msg_id=uuid.uuid4().bytes,
        sender_spk=sender.get_signing_public_key_bytes(),
        recipient_id=hashlib.sha256(recipient.get_public_key_bytes()).digest(),
        total_chunks=4,
        data_chunks=3,
        prekey_id=0,
        ts=now,
        exp=now + 300,
    )


class TestSlotManifest:
    def test_sign_parse_roundtrip(self):
        sender = DMPCrypto()
        recipient = DMPCrypto()
        now = int(time.time())
        manifest = _make_manifest(sender, recipient, now)

        record = manifest.sign(sender)
        assert record.startswith("v=dmp1;t=manifest")

        result = SlotManifest.parse_and_verify(record)
        assert result is not None
        parsed, _ = result
        assert parsed.msg_id == manifest.msg_id
        assert parsed.total_chunks == manifest.total_chunks
        assert parsed.sender_spk == sender.get_signing_public_key_bytes()

    def test_tampered_payload_rejected(self):
        import base64
        sender = DMPCrypto()
        recipient = DMPCrypto()
        now = int(time.time())
        manifest = _make_manifest(sender, recipient, now)

        record = manifest.sign(sender)
        # Flip one byte in the signed wire payload. Signature will no longer
        # verify against the sender_spk embedded in the body.
        prefix = "v=dmp1;t=manifest;d="
        wire = bytearray(base64.b64decode(record[len(prefix):]))
        wire[80] ^= 0xFF  # inside the total_chunks field
        tampered = prefix + base64.b64encode(bytes(wire)).decode("ascii")
        assert SlotManifest.parse_and_verify(tampered) is None

    def test_wrong_signer_rejected(self):
        real_sender = DMPCrypto()
        impostor = DMPCrypto()
        recipient = DMPCrypto()
        now = int(time.time())
        manifest = _make_manifest(real_sender, recipient, now)
        # Keep real_sender's spk in the manifest, but sign with impostor — verify
        # will fail because the embedded spk won't match the impostor's signature.
        record = manifest.sign(impostor)
        assert SlotManifest.parse_and_verify(record) is None

    def test_malformed_record_returns_none(self):
        assert SlotManifest.parse_and_verify("not-a-dmp-record") is None
        assert SlotManifest.parse_and_verify("v=dmp1;t=manifest") is None
        assert SlotManifest.parse_and_verify("v=dmp1;t=manifest;d=notbase64") is None
        # Correct prefix, decodable base64, but wrong length.
        import base64
        short = base64.b64encode(b"too short").decode("ascii")
        assert SlotManifest.parse_and_verify(f"v=dmp1;t=manifest;d={short}") is None

    def test_expiry(self):
        sender = DMPCrypto()
        recipient = DMPCrypto()
        now = int(time.time())
        manifest = SlotManifest(
            msg_id=uuid.uuid4().bytes,
            sender_spk=sender.get_signing_public_key_bytes(),
            recipient_id=b'\x01' * 32,
            total_chunks=1,
            data_chunks=1,
            prekey_id=0,
            ts=now - 1000,
            exp=now - 500,
        )
        assert manifest.is_expired()
        # Round-trip still works; expiry is a separate concern from signature.
        record = manifest.sign(sender)
        result = SlotManifest.parse_and_verify(record)
        assert result is not None
        parsed, _ = result
        assert parsed.is_expired()


class TestReplayCache:
    def test_first_seen_accepted(self):
        cache = ReplayCache()
        assert cache.check_and_record(b'A' * 32, b'M' * 16)

    def test_second_seen_rejected(self):
        cache = ReplayCache()
        sender = b'A' * 32
        msg_id = b'M' * 16
        assert cache.check_and_record(sender, msg_id)
        assert not cache.check_and_record(sender, msg_id)

    def test_different_senders_are_independent(self):
        cache = ReplayCache()
        msg_id = b'M' * 16
        assert cache.check_and_record(b'A' * 32, msg_id)
        assert cache.check_and_record(b'B' * 32, msg_id)

    def test_expired_entry_is_forgotten(self):
        cache = ReplayCache()
        sender = b'A' * 32
        msg_id = b'M' * 16
        # Record with an expiry already in the past
        assert cache.check_and_record(sender, msg_id, expiry=int(time.time()) - 1)
        # Next call purges the expired entry and accepts the pair again
        assert cache.check_and_record(sender, msg_id)

    def test_size_tracks_live_entries(self):
        cache = ReplayCache()
        cache.check_and_record(b'A' * 32, b'M' * 16, expiry=int(time.time()) + 10)
        cache.check_and_record(b'B' * 32, b'M' * 16, expiry=int(time.time()) + 10)
        assert cache.size() == 2


class TestReplayCachePersistence:
    def test_record_persists_across_instances(self, tmp_path):
        path = str(tmp_path / "replay.json")
        c1 = ReplayCache(persist_path=path)
        c1.record(b'A' * 32, b'M' * 16, expiry=int(time.time()) + 300)

        c2 = ReplayCache(persist_path=path)
        assert c2.has_seen(b'A' * 32, b'M' * 16)

    def test_expired_entries_dropped_on_load(self, tmp_path):
        path = str(tmp_path / "replay.json")
        c1 = ReplayCache(persist_path=path)
        c1.record(b'A' * 32, b'M' * 16, expiry=int(time.time()) - 1)

        c2 = ReplayCache(persist_path=path)
        assert not c2.has_seen(b'A' * 32, b'M' * 16)
        assert c2.size() == 0

    def test_corrupt_persistence_file_ignored(self, tmp_path):
        path = tmp_path / "replay.json"
        path.write_text("not json")
        cache = ReplayCache(persist_path=str(path))
        # Corrupt file doesn't crash — cache just starts empty and overwrites.
        assert cache.size() == 0
        cache.record(b'A' * 32, b'M' * 16, expiry=int(time.time()) + 300)

        # Next load reads the fresh file written on that record().
        c2 = ReplayCache(persist_path=str(path))
        assert c2.has_seen(b'A' * 32, b'M' * 16)

    def test_missing_persistence_file_starts_empty(self, tmp_path):
        path = str(tmp_path / "does-not-exist.json")
        cache = ReplayCache(persist_path=path)
        assert cache.size() == 0

    def test_atomic_write_no_torn_file(self, tmp_path):
        # The implementation writes to <path>.tmp and renames. We can at least
        # verify the tmp file doesn't leak after successful writes.
        path = tmp_path / "replay.json"
        cache = ReplayCache(persist_path=str(path))
        cache.record(b'A' * 32, b'M' * 16, expiry=int(time.time()) + 300)
        assert path.exists()
        assert not (tmp_path / "replay.json.tmp").exists()

    def test_purge_rewrites_persistence(self, tmp_path):
        path = str(tmp_path / "replay.json")
        cache = ReplayCache(persist_path=path)
        cache.record(b'A' * 32, b'M' * 16, expiry=int(time.time()) - 1)
        cache.record(b'B' * 32, b'M' * 16, expiry=int(time.time()) + 300)

        # Trigger a purge via a read-side call.
        cache.has_seen(b'A' * 32, b'M' * 16)

        c2 = ReplayCache(persist_path=path)
        assert not c2.has_seen(b'A' * 32, b'M' * 16)
        assert c2.has_seen(b'B' * 32, b'M' * 16)
