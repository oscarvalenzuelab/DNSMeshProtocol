"""Tests for the M8.3 IntroQueue (`intro_queue.py`)."""

from __future__ import annotations

import inspect
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
        q = IntroQueue(":memory:")
        intro_id = _seed(q)
        assert intro_id is not None
        rows = q.list_intros()
        assert len(rows) == 1
        assert rows[0].intro_id == intro_id
        assert rows[0].plaintext == b"hello stranger"

    def test_get_intro_round_trip(self):
        q = IntroQueue(":memory:")
        intro_id = _seed(q)
        got = q.get_intro(intro_id)
        assert got is not None
        assert got.intro_id == intro_id
        assert got.plaintext == b"hello stranger"

    def test_get_missing_returns_none(self):
        q = IntroQueue(":memory:")
        assert q.get_intro(999) is None

    def test_remove_intro(self):
        q = IntroQueue(":memory:")
        intro_id = _seed(q)
        assert q.remove_intro(intro_id) is True
        assert q.list_intros() == []
        # Removing again returns False.
        assert q.remove_intro(intro_id) is False

    def test_dedupe_same_sender_and_msg(self):
        """A re-poll that re-discovers the same claim must not duplicate."""
        q = IntroQueue(":memory:")
        spk = b"\x44" * 32
        msg_id = b"\x55" * 16
        first = _seed(q, sender_spk=spk, msg_id=msg_id)
        second = _seed(q, sender_spk=spk, msg_id=msg_id)
        assert first is not None
        assert second is None  # blocked by UNIQUE
        assert len(q.list_intros()) == 1

    def test_has_intro(self):
        q = IntroQueue(":memory:")
        spk = b"\x77" * 32
        msg_id = b"\x88" * 16
        assert q.has_intro(spk, msg_id) is False
        _seed(q, sender_spk=spk, msg_id=msg_id)
        assert q.has_intro(spk, msg_id) is True


class TestDenylist:
    def test_block_then_add_drops(self):
        q = IntroQueue(":memory:")
        spk = b"\xaa" * 32
        q.block_sender(spk, note="spam")
        assert q.is_blocked(spk) is True
        # add_intro silently returns None when sender is blocked.
        new_id = _seed(q, sender_spk=spk)
        assert new_id is None
        assert q.list_intros() == []

    def test_unblock_allows_again(self):
        q = IntroQueue(":memory:")
        spk = b"\xbb" * 32
        q.block_sender(spk)
        assert q.unblock_sender(spk) is True
        assert q.is_blocked(spk) is False
        assert _seed(q, sender_spk=spk) is not None

    def test_block_idempotent(self):
        q = IntroQueue(":memory:")
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
        q = IntroQueue(":memory:")
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


class TestSchemaVersioning:
    """``PRAGMA user_version`` migration ladder. Without versioning, a
    schema bump that adds a column (or worse, drops one) silently
    misalligns deployed databases against the running code. The
    versioning makes upgrades + downgrades explicit failures."""

    def test_fresh_db_is_stamped_at_current_version(self, tmp_path):
        """A brand-new database lands at the latest schema version, so
        future migrations know they only need to apply the v(N→N+1) step
        rather than re-running the v0→v1 baseline."""
        import sqlite3

        path = str(tmp_path / "fresh.db")
        q = IntroQueue(path)
        try:
            stored = q._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == IntroQueue._SCHEMA_VERSION
        finally:
            q.close()

    def test_legacy_unversioned_db_migrates_to_current(self, tmp_path):
        """An existing database created by a pre-versioning binary
        (user_version=0, bare CREATE TABLE schema) opens cleanly: the
        v0→v1 step re-runs CREATE TABLE IF NOT EXISTS (idempotent) and
        stamps the version. Existing rows are preserved.
        """
        import sqlite3

        path = str(tmp_path / "legacy.db")
        # Simulate the pre-versioning shape: bare schema, user_version
        # never stamped (still 0, sqlite default).
        legacy = sqlite3.connect(path, isolation_level=None)
        for stmt in IntroQueue._SCHEMA_V1_STATEMENTS:
            legacy.execute(stmt)
        legacy.execute(
            "INSERT INTO intros(sender_spk, msg_id, plaintext, "
            "sender_mailbox_domain, received_at, msg_exp) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (b"\xaa" * 32, b"\xbb" * 16, b"legacy intro", "old.host", 100, 200),
        )
        legacy.close()

        q = IntroQueue(path)
        try:
            stored = q._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == 1
            rows = q.list_intros()
            assert len(rows) == 1
            assert rows[0].plaintext == b"legacy intro"
        finally:
            q.close()

    def test_future_version_db_refuses_to_open(self, tmp_path):
        """A database whose stored version is HIGHER than this code
        understands must NOT open silently — running an older binary
        against a newer schema would risk dropping fields the binary
        doesn't know about. Hard error with the version mismatch.
        """
        import sqlite3

        path = str(tmp_path / "future.db")
        future = sqlite3.connect(path, isolation_level=None)
        for stmt in IntroQueue._SCHEMA_V1_STATEMENTS:
            future.execute(stmt)
        # Stamp a version higher than the code knows.
        future.execute(f"PRAGMA user_version = {IntroQueue._SCHEMA_VERSION + 5}")
        future.close()

        with pytest.raises(RuntimeError, match="schema version"):
            IntroQueue(path)

    def test_reopen_existing_versioned_db_is_idempotent(self, tmp_path):
        """A database already at the current version opens without
        re-running migrations or bumping the stamp."""
        path = str(tmp_path / "stable.db")
        q1 = IntroQueue(path)
        intro_id = _seed(q1)
        v_after_first = q1._conn.execute("PRAGMA user_version").fetchone()[0]
        q1.close()

        q2 = IntroQueue(path)
        try:
            v_after_reopen = q2._conn.execute("PRAGMA user_version").fetchone()[0]
            assert v_after_reopen == v_after_first
            # Data intact.
            rows = q2.list_intros()
            assert len(rows) == 1
            assert rows[0].intro_id == intro_id
        finally:
            q2.close()


class TestPathRequired:
    def test_construct_without_path_raises(self):
        # Pending intros silently disappeared on every restart when
        # the constructor accepted a default ``:memory:`` path. The
        # argument is now mandatory: callers that genuinely want an
        # ephemeral queue pass ``":memory:"`` explicitly.
        with pytest.raises(TypeError):
            IntroQueue()  # type: ignore[call-arg]

    def test_path_parameter_has_no_default(self):
        # Pin the contract at the signature level so a future change
        # that adds a new required positional in front of ``path``
        # cannot silently re-introduce a default for ``path`` itself.
        sig = inspect.signature(IntroQueue)
        assert sig.parameters["path"].default is inspect.Parameter.empty
