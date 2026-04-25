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

import sqlite3
import time
from dataclasses import dataclass
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
    """

    _SCHEMA = """
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
        );
        CREATE INDEX IF NOT EXISTS idx_intros_received_at
            ON intros(received_at DESC);
        CREATE TABLE IF NOT EXISTS denylist (
            sender_spk BLOB PRIMARY KEY,
            blocked_at INTEGER NOT NULL,
            note TEXT NOT NULL DEFAULT ''
        );
    """

    def __init__(self, path: str = ":memory:") -> None:
        self._path = path
        # check_same_thread=False so the CLI and the receive worker
        # can both write. WAL mode keeps reads non-blocking against
        # writers.
        self._conn = sqlite3.connect(
            path,
            check_same_thread=False,
            isolation_level=None,  # autocommit
        )
        self._conn.executescript(self._SCHEMA)
        if path != ":memory:":
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass

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
        cur = self._conn.execute(
            "DELETE FROM intros WHERE id = ?", (int(intro_id),)
        )
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
