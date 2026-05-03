"""Pending-intro queue + sender denylist (M8.3).

When a claim-discovered manifest is signed by a sender_spk that is
NOT in the recipient's pinned-contact set, the recv path lands the
fully-decrypted message into a quarantine queue rather than
delivering it directly into the inbox. The user reviews the queue
with ``dnsmesh intro list`` and chooses one of:

  - ``accept``  — deliver this one message; do not pin the sender.
  - ``trust``   — pin sender_spk + deliver; future messages from this
                  sender go straight to the inbox.
  - ``block``   — drop this message and add sender_spk to the
                  denylist; future claims signed by that key are
                  silently dropped at parse time.

This module owns:

  - the ``intros`` sqlite table (pending entries waiting on review),
  - the ``denylist`` sqlite table (blocked sender_spks),
  - the methods the receive path and the CLI use to add / list /
    accept / trust / block intros.

Storage is intentionally *local-only* for M8.3. Multi-device intro
or denylist sync (your phone ``block`` propagating to your laptop)
needs a separate signed publish format and is tracked as future
work in M8 design notes.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class PendingIntro:
    """A single quarantined first-contact message awaiting user review."""

    intro_id: int
    sender_spk: bytes
    msg_id: bytes
    plaintext: bytes
    sender_mailbox_domain: str
    received_at: int  # unix seconds when the recv path queued it
    msg_exp: int  # claim/manifest exp; intro is unrecoverable past this
    sender_label: str = ""  # username if known via fetched identity, else ""


class IntroQueue:
    """Sqlite-backed pending-intro queue + denylist.

    Thread-safe via per-call connection (sqlite's default behavior
    when ``check_same_thread=False`` is used) — the same client
    process may have a CLI thread and a background poller writing
    concurrently. Uses WAL journaling for non-blocking reads.

    Pass ``":memory:"`` for tests; pass a real path in CLI use so
    pending intros survive across CLI invocations.

    Schema versioning (P1): the schema is stamped via
    ``PRAGMA user_version``. Each schema bump appends a step to
    ``_migrate`` and increments ``_SCHEMA_VERSION``. Opening a
    database whose stored version is HIGHER than this code knows
    raises — refusing a silent downgrade prevents data loss when an
    older binary points at a newer database.
    """

    # Schema v1 as individual statements (NOT a script). ``executescript``
    # does an implicit COMMIT before running, which would end the
    # ``BEGIN IMMEDIATE`` transaction in ``_migrate``. Issue each
    # statement via ``execute`` to stay inside the explicit transaction.
    _SCHEMA_V1_STATEMENTS = (
        """
        CREATE TABLE IF NOT EXISTS intros (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_spk BLOB NOT NULL,
            msg_id BLOB NOT NULL,
            plaintext BLOB NOT NULL,
            sender_mailbox_domain TEXT NOT NULL,
            sender_label TEXT NOT NULL DEFAULT '',
            received_at INTEGER NOT NULL,
            msg_exp INTEGER NOT NULL,
            UNIQUE(sender_spk, msg_id)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_intros_received_at
            ON intros(received_at DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS denylist (
            sender_spk BLOB PRIMARY KEY,
            blocked_at INTEGER NOT NULL,
            note TEXT NOT NULL DEFAULT ''
        )
        """,
    )

    # Latest schema version this code understands. Bump on every
    # schema-affecting change and append the migration to ``_MIGRATIONS``.
    _SCHEMA_VERSION = 1

    def __init__(self, path: str = ":memory:") -> None:
        self._path = path
        # On-disk paths: ensure the parent directory exists with
        # tight permissions BEFORE creating the file, then chmod
        # the file too. The intro queue stores fully decrypted
        # plaintext (codex P2 round 3 caught the confidentiality
        # regression: previously a default umask-022 system left
        # this world-readable). Mirror the PrekeyStore + replay-
        # cache pattern: 0o700 on the dir, 0o600 on the file.
        if path != ":memory:":
            try:
                parent = Path(path).expanduser().resolve().parent
                parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.chmod(parent, 0o700)
                except OSError:
                    pass
            except OSError:
                pass
        # check_same_thread=False so the CLI and the receive worker
        # can both write. WAL mode keeps reads non-blocking against
        # writers.
        self._conn = sqlite3.connect(
            path,
            check_same_thread=False,
            isolation_level=None,  # autocommit
        )
        self._migrate()
        if path != ":memory:":
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
            # Tighten the file itself, plus any WAL/SHM siblings
            # sqlite materializes alongside it.
            for suffix in ("", "-wal", "-shm"):
                try:
                    sibling = Path(path + suffix)
                    if sibling.exists():
                        os.chmod(sibling, 0o600)
                except OSError:
                    pass

    def _migrate(self) -> None:
        """Apply schema migrations atomically and stamp ``user_version``.

        Reads the current ``PRAGMA user_version`` (0 for fresh databases
        and for older databases that predate this versioning scheme).
        The v0→v1 step is a CREATE TABLE IF NOT EXISTS pass — idempotent
        for both cases — and stamps ``user_version=1``. Future schema
        changes append a v1→v2 step (etc.) and bump ``_SCHEMA_VERSION``.

        Refuses to open a database whose stored version is higher than
        ``_SCHEMA_VERSION``: that means an older binary opened a
        newer-schema file, and silently doing nothing would risk
        downgrading the schema (or worse, writing old-shape rows into
        a newer-shape table).

        Concurrency: ``BEGIN IMMEDIATE`` makes the read-then-write
        atomic against another connection on the same file. The current
        v0→v1 step is idempotent so two racers wouldn't corrupt each
        other today, but future migrations that ALTER columns would,
        so the lock is in place from the start.
        """
        # autocommit isolation_level=None means we drive txs explicitly.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur_version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if cur_version > self._SCHEMA_VERSION:
                raise RuntimeError(
                    f"intro_queue at {self._path!r} has schema version "
                    f"{cur_version}, but this binary only understands up to "
                    f"{self._SCHEMA_VERSION}. Refusing to open — using an "
                    f"older client against a newer database would risk "
                    f"silently dropping fields."
                )
            if cur_version < 1:
                for stmt in self._SCHEMA_V1_STATEMENTS:
                    self._conn.execute(stmt)
                self._conn.execute("PRAGMA user_version = 1")
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.DatabaseError:
            pass

    # ------------------------------------------------------------------
    # intros
    # ------------------------------------------------------------------

    def add_intro(
        self,
        *,
        sender_spk: bytes,
        msg_id: bytes,
        plaintext: bytes,
        sender_mailbox_domain: str,
        msg_exp: int,
        sender_label: str = "",
        now: Optional[int] = None,
    ) -> Optional[int]:
        """Insert a pending intro. Returns the new intro_id or ``None``.

        Returns ``None`` (no insert) when:

          - the same (sender_spk, msg_id) already exists (deduplication;
            a poll that re-discovers the same claim won't grow the
            queue),
          - the sender_spk is on the denylist (silent drop — caller
            does not need to surface anything to the user).

        ``msg_exp`` is the claim/manifest exp the recv path verified;
        once now > msg_exp the intro is shown but ``accept_intro``
        returns the plaintext only if it was already captured at
        recv time (which it is — we store the decrypted plaintext,
        not a re-fetch hint).
        """
        if self.is_blocked(sender_spk):
            return None
        now_i = now if now is not None else int(time.time())
        try:
            cur = self._conn.execute(
                """
                INSERT INTO intros (
                    sender_spk, msg_id, plaintext, sender_mailbox_domain,
                    sender_label, received_at, msg_exp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    bytes(sender_spk),
                    bytes(msg_id),
                    bytes(plaintext),
                    sender_mailbox_domain,
                    sender_label,
                    now_i,
                    int(msg_exp),
                ),
            )
            return cur.lastrowid
        except sqlite3.IntegrityError:
            # UNIQUE(sender_spk, msg_id) already populated.
            return None

    def list_intros(self) -> List[PendingIntro]:
        """Return all pending intros, newest first."""
        rows = self._conn.execute(
            """
            SELECT id, sender_spk, msg_id, plaintext, sender_mailbox_domain,
                   sender_label, received_at, msg_exp
            FROM intros
            ORDER BY received_at DESC
            """,
        ).fetchall()
        return [
            PendingIntro(
                intro_id=r[0],
                sender_spk=bytes(r[1]),
                msg_id=bytes(r[2]),
                plaintext=bytes(r[3]),
                sender_mailbox_domain=r[4],
                sender_label=r[5],
                received_at=r[6],
                msg_exp=r[7],
            )
            for r in rows
        ]

    def get_intro(self, intro_id: int) -> Optional[PendingIntro]:
        row = self._conn.execute(
            """
            SELECT id, sender_spk, msg_id, plaintext, sender_mailbox_domain,
                   sender_label, received_at, msg_exp
            FROM intros WHERE id = ?
            """,
            (int(intro_id),),
        ).fetchone()
        if row is None:
            return None
        return PendingIntro(
            intro_id=row[0],
            sender_spk=bytes(row[1]),
            msg_id=bytes(row[2]),
            plaintext=bytes(row[3]),
            sender_mailbox_domain=row[4],
            sender_label=row[5],
            received_at=row[6],
            msg_exp=row[7],
        )

    def remove_intro(self, intro_id: int) -> bool:
        cur = self._conn.execute("DELETE FROM intros WHERE id = ?", (int(intro_id),))
        return cur.rowcount > 0

    def has_intro(self, sender_spk: bytes, msg_id: bytes) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM intros WHERE sender_spk = ? AND msg_id = ? LIMIT 1",
            (bytes(sender_spk), bytes(msg_id)),
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------------
    # denylist
    # ------------------------------------------------------------------

    def block_sender(
        self, sender_spk: bytes, *, note: str = "", now: Optional[int] = None
    ) -> None:
        """Add ``sender_spk`` to the denylist (no-op if already present).

        Subsequent ``add_intro`` calls for this sender silently drop.
        Existing pending intros from this sender are NOT auto-removed
        — the caller's CLI flow typically pairs ``block_sender(spk)``
        with ``remove_intro(id)`` for the specific message.
        """
        now_i = now if now is not None else int(time.time())
        self._conn.execute(
            """
            INSERT OR IGNORE INTO denylist (sender_spk, blocked_at, note)
            VALUES (?, ?, ?)
            """,
            (bytes(sender_spk), now_i, note),
        )

    def unblock_sender(self, sender_spk: bytes) -> bool:
        cur = self._conn.execute(
            "DELETE FROM denylist WHERE sender_spk = ?", (bytes(sender_spk),)
        )
        return cur.rowcount > 0

    def is_blocked(self, sender_spk: bytes) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM denylist WHERE sender_spk = ? LIMIT 1",
            (bytes(sender_spk),),
        ).fetchone()
        return row is not None

    def list_denylist(self) -> List[bytes]:
        rows = self._conn.execute(
            "SELECT sender_spk FROM denylist ORDER BY blocked_at DESC"
        ).fetchall()
        return [bytes(r[0]) for r in rows]
