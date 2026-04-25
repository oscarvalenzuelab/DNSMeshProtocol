"""Tests for the M8.3 IntroQueue (`intro_queue.py`)."""

from __future__ import annotations

import os
import tempfile

import pytest

from dmp.client.intro_queue import IntroQueue, PendingIntro


def _seed(q: IntroQueue, *, sender_spk: bytes = b"\x33" * 32, msg_id: bytes = None):
    if msg_id is None:
        msg_id = os.urandom(16)
    return q.add_intro(
        sender_spk=sender_spk,
        msg_id=msg_id,
        plaintext=b"hello stranger",
        sender_mailbox_domain="alice.mesh",
        msg_exp=2_000_000_000,
    )


class TestIntroBasics:
    def test_add_and_list(self):
        q = IntroQueue()
        intro_id = _seed(q)
        assert intro_id is not None
        rows = q.list_intros()
        assert len(rows) == 1
        assert rows[0].intro_id == intro_id
        assert rows[0].plaintext == b"hello stranger"

    def test_get_intro_round_trip(self):
        q = IntroQueue()
        intro_id = _seed(q)
        got = q.get_intro(intro_id)
        assert got is not None
        assert got.intro_id == intro_id
        assert got.plaintext == b"hello stranger"

    def test_get_missing_returns_none(self):
        q = IntroQueue()
        assert q.get_intro(999) is None

    def test_remove_intro(self):
        q = IntroQueue()
        intro_id = _seed(q)
        assert q.remove_intro(intro_id) is True
        assert q.list_intros() == []
        # Removing again returns False.
        assert q.remove_intro(intro_id) is False

    def test_dedupe_same_sender_and_msg(self):
        """A re-poll that re-discovers the same claim must not duplicate."""
        q = IntroQueue()
        spk = b"\x44" * 32
        msg_id = b"\x55" * 16
        first = _seed(q, sender_spk=spk, msg_id=msg_id)
        second = _seed(q, sender_spk=spk, msg_id=msg_id)
        assert first is not None
        assert second is None  # blocked by UNIQUE
        assert len(q.list_intros()) == 1

    def test_has_intro(self):
        q = IntroQueue()
        spk = b"\x77" * 32
        msg_id = b"\x88" * 16
        assert q.has_intro(spk, msg_id) is False
        _seed(q, sender_spk=spk, msg_id=msg_id)
        assert q.has_intro(spk, msg_id) is True


class TestDenylist:
    def test_block_then_add_drops(self):
        q = IntroQueue()
        spk = b"\xaa" * 32
        q.block_sender(spk, note="spam")
        assert q.is_blocked(spk) is True
        # add_intro silently returns None when sender is blocked.
        new_id = _seed(q, sender_spk=spk)
        assert new_id is None
        assert q.list_intros() == []

    def test_unblock_allows_again(self):
        q = IntroQueue()
        spk = b"\xbb" * 32
        q.block_sender(spk)
        assert q.unblock_sender(spk) is True
        assert q.is_blocked(spk) is False
        assert _seed(q, sender_spk=spk) is not None

    def test_block_idempotent(self):
        q = IntroQueue()
        spk = b"\xcc" * 32
        q.block_sender(spk, note="first")
        q.block_sender(spk, note="second")  # no-op
        assert q.list_denylist() == [spk]

    def test_denylist_preserves_existing_intros(self):
        """Blocking does NOT auto-remove already-pending intros.

        The CLI typically pairs `block_sender(spk)` with `remove_intro(id)`
        for the specific message; the queue layer doesn't make that
        decision implicitly.
        """
        q = IntroQueue()
        intro_id = _seed(q)
        spk = q.list_intros()[0].sender_spk
        q.block_sender(spk)
        assert len(q.list_intros()) == 1
        # But future additions are blocked.
        next_id = _seed(q, sender_spk=spk)
        assert next_id is None


class TestPersistence:
    def test_disk_path_survives_close_reopen(self, tmp_path):
        path = str(tmp_path / "intros.db")
        q = IntroQueue(path)
        intro_id = _seed(q)
        q.close()

        q2 = IntroQueue(path)
        rows = q2.list_intros()
        assert len(rows) == 1
        assert rows[0].intro_id == intro_id
        assert rows[0].plaintext == b"hello stranger"
        q2.close()

    def test_db_file_is_0600(self, tmp_path):
        """Codex P2 round 3 fix: intro DB stores decrypted plaintext;
        must not be world-readable on a default-umask system."""
        import stat

        path = str(tmp_path / "intros.db")
        q = IntroQueue(path)
        _seed(q)
        q.close()
        # File mode masking the high bits — only the owner-rw bits
        # should be set (0o600).
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode & 0o077 == 0, f"intros.db is too permissive: 0o{mode:o}"
