"""Persistent TSIG key store with per-key scope (M9.2.2).

The DMP node serves DNS UPDATE for one or more zones. Each user
authorized to write into the zone holds a TSIG key minted by the
node during the M9.2.3 registration flow. This module is the
sqlite-backed store of those keys plus the per-key scope rules.

A key entry carries:

  - ``name``: dnspython-style key name, ending in a dot
    (e.g. ``alice-7d2f.example.com.``). Acts as the keyring lookup
    handle the UPDATE handler matches against.
  - ``secret``: raw key bytes (HMAC-SHA256 default — 32 bytes).
  - ``algorithm``: TSIG algorithm name (default ``hmac-sha256``).
  - ``allowed_suffixes``: tuple of fully-qualified owner-name
    suffixes the key is authorized to mutate. An UPDATE for owner
    ``foo.alice.example.com`` is authorized iff one of the suffixes
    is a tail of that owner. The empty tuple disallows everything
    (a key with no scope is dead weight, on purpose — call sites
    should always set scope at mint time).
  - ``created_at`` / ``expires_at`` (epoch seconds; 0 = no expiry).
  - ``revoked``: boolean kill switch.

Two surfaces consume the store:

  - :meth:`build_keyring` projects active (non-revoked, non-expired)
    keys into the ``keyring`` argument the dns_server module passes
    into ``dns.message.from_wire``. dnspython does TSIG verification
    against this mapping at parse time.
  - :meth:`build_authorizer` returns an ``update_authorizer`` callable
    matching the contract in :mod:`dmp.server.dns_server` — given a
    verified key name and the owner being touched, decide whether
    the key is in scope.

Both surfaces walk the SAME set of active keys, so a revoke takes
effect on the next UPDATE without restarting the DNS server (the
keyring is rebuilt per UPDATE — cost is negligible at our key
counts and removes a class of stale-keyring bugs).
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

import dns.name
import dns.tsig

DEFAULT_ALGORITHM = "hmac-sha256"
DEFAULT_SECRET_BYTES = 32

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tsig_keys (
    name             TEXT PRIMARY KEY,
    algorithm        TEXT NOT NULL DEFAULT 'hmac-sha256',
    secret           BLOB NOT NULL,
    allowed_suffixes TEXT NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL DEFAULT 0,
    revoked          INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_tsig_active ON tsig_keys(revoked, expires_at);
"""


def _normalize_name(name: str) -> str:
    """Match dnspython's expectation: lowercase, trailing dot."""
    n = (name or "").strip().lower()
    if not n:
        raise ValueError("TSIG key name must be non-empty")
    if not n.endswith("."):
        n += "."
    return n


def _normalize_suffix(suffix: str) -> str:
    """Owner suffixes match against the owner text returned by
    ``Name.to_text(omit_final_dot=True)``: lowercase, no trailing
    dot, leading dot stripped."""
    s = (suffix or "").strip().lower().rstrip(".")
    if s.startswith("."):
        s = s[1:]
    return s


def _suffix_match(owner: str, suffix: str) -> bool:
    """Owner is in scope iff it equals the suffix or is a strict
    subdomain of it. Exact-match guards a key scoped to a single
    owner; subdomain match supports wildcard-style scopes like
    ``alice.example.com`` granting everything beneath."""
    if not suffix:
        return False
    o = (owner or "").strip().lower().rstrip(".")
    s = _normalize_suffix(suffix)
    return o == s or o.endswith("." + s)


@dataclass(frozen=True)
class TSIGKey:
    """One row in the key store."""

    name: str  # dnspython key name (with trailing dot)
    algorithm: str
    secret: bytes
    allowed_suffixes: Tuple[str, ...]
    created_at: int
    expires_at: int  # 0 = no expiry
    revoked: bool

    def is_active(self, now: Optional[int] = None) -> bool:
        if self.revoked:
            return False
        if self.expires_at and self.expires_at <= int(
            time.time() if now is None else now
        ):
            return False
        return True

    def covers(self, owner: str) -> bool:
        """True iff `owner` is in scope for this key."""
        for suffix in self.allowed_suffixes:
            if _suffix_match(owner, suffix):
                return True
        return False


class TSIGKeyStore:
    """Sqlite-backed TSIG key store.

    Concurrency model matches the rest of the codebase: a single
    sqlite connection guarded by a lock, WAL mode for reads not
    blocking writes, ``check_same_thread=False`` so the DNS UPDATE
    handler thread can use the same connection the registration
    flow created. Per-key inserts are infrequent — we don't try to
    optimize for write QPS.
    """

    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # writes
    # ------------------------------------------------------------------

    def put(
        self,
        *,
        name: str,
        secret: bytes,
        allowed_suffixes: Iterable[str],
        algorithm: str = DEFAULT_ALGORITHM,
        expires_at: int = 0,
        now: Optional[int] = None,
    ) -> TSIGKey:
        """Insert or replace a key. Replacing is intentional — the
        registration flow may re-issue a key for a user who lost
        theirs; the new key carries fresh secret bytes and the same
        scope. Old key bytes are unrecoverable from the row."""
        canonical = _normalize_name(name)
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise ValueError("secret must be non-empty bytes")
        suffixes = tuple(
            sorted({_normalize_suffix(s) for s in allowed_suffixes if s})
        )
        if not suffixes:
            raise ValueError("at least one non-empty allowed suffix is required")
        created_at = int(time.time() if now is None else now)
        with self._lock:
            self._conn.execute(
                """INSERT INTO tsig_keys
                   (name, algorithm, secret, allowed_suffixes,
                    created_at, expires_at, revoked)
                   VALUES (?, ?, ?, ?, ?, ?, 0)
                   ON CONFLICT(name) DO UPDATE SET
                     algorithm = excluded.algorithm,
                     secret = excluded.secret,
                     allowed_suffixes = excluded.allowed_suffixes,
                     created_at = excluded.created_at,
                     expires_at = excluded.expires_at,
                     revoked = 0""",
                (
                    canonical,
                    algorithm,
                    bytes(secret),
                    "\n".join(suffixes),
                    created_at,
                    int(expires_at),
                ),
            )
            self._conn.commit()
        return TSIGKey(
            name=canonical,
            algorithm=algorithm,
            secret=bytes(secret),
            allowed_suffixes=suffixes,
            created_at=created_at,
            expires_at=int(expires_at),
            revoked=False,
        )

    def mint(
        self,
        *,
        name: str,
        allowed_suffixes: Iterable[str],
        algorithm: str = DEFAULT_ALGORITHM,
        secret_bytes: int = DEFAULT_SECRET_BYTES,
        expires_at: int = 0,
        now: Optional[int] = None,
    ) -> TSIGKey:
        """Generate a fresh secret and store the key. Returns the
        full ``TSIGKey`` (including ``secret``) so the caller can hand
        it to the user — the secret never leaves this call's stack
        otherwise.
        """
        secret = secrets.token_bytes(int(secret_bytes))
        return self.put(
            name=name,
            secret=secret,
            allowed_suffixes=allowed_suffixes,
            algorithm=algorithm,
            expires_at=expires_at,
            now=now,
        )

    def revoke(self, name: str) -> bool:
        """Mark a key revoked. Returns True iff the key existed."""
        canonical = _normalize_name(name)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE tsig_keys SET revoked = 1 WHERE name = ?",
                (canonical,),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def delete(self, name: str) -> bool:
        """Permanently remove a key. Used only by tests / operator
        cleanup; runtime code should ``revoke`` so we keep an audit
        trail of historical keys."""
        canonical = _normalize_name(name)
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM tsig_keys WHERE name = ?", (canonical,)
            )
            self._conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # reads
    # ------------------------------------------------------------------

    def get(self, name: str) -> Optional[TSIGKey]:
        canonical = _normalize_name(name)
        # Hold the lock around reads even though sqlite is technically
        # safe with check_same_thread=False — concurrent put/revoke
        # from the HTTP thread can interleave with build_keyring /
        # build_authorizer calls from DNS-server packet threads, and
        # a single shared connection raises ProgrammingError or
        # OperationalError under that contention. Codex P2 — every
        # public method now serializes through the same lock.
        with self._lock:
            row = self._conn.execute(
                """SELECT name, algorithm, secret, allowed_suffixes,
                          created_at, expires_at, revoked
                   FROM tsig_keys WHERE name = ?""",
                (canonical,),
            ).fetchone()
        return _row_to_key(row) if row else None

    def list_active(self, now: Optional[int] = None) -> List[TSIGKey]:
        now_i = int(time.time() if now is None else now)
        with self._lock:
            rows = self._conn.execute(
                """SELECT name, algorithm, secret, allowed_suffixes,
                          created_at, expires_at, revoked
                   FROM tsig_keys
                   WHERE revoked = 0
                     AND (expires_at = 0 OR expires_at > ?)
                   ORDER BY created_at ASC""",
                (now_i,),
            ).fetchall()
        return [_row_to_key(r) for r in rows]

    def list_all(self) -> List[TSIGKey]:
        with self._lock:
            rows = self._conn.execute(
                """SELECT name, algorithm, secret, allowed_suffixes,
                          created_at, expires_at, revoked
                   FROM tsig_keys ORDER BY created_at ASC"""
            ).fetchall()
        return [_row_to_key(r) for r in rows]

    # ------------------------------------------------------------------
    # projections used by dns_server
    # ------------------------------------------------------------------

    def build_keyring(self, now: Optional[int] = None) -> dict:
        """Project the active keys into a dnspython keyring.

        dnspython accepts a mapping of ``dns.name.Name`` → ``dns.tsig.Key``
        (or ``bytes`` secret with default algorithm). We emit explicit
        ``Key`` objects so each entry pins its algorithm.
        """
        out: dict = {}
        for row in self.list_active(now=now):
            try:
                kname = dns.name.from_text(row.name)
            except Exception:
                continue
            try:
                key = dns.tsig.Key(name=kname, secret=row.secret, algorithm=row.algorithm)
            except Exception:
                # Unsupported algorithm — skip rather than fail the
                # whole keyring build.
                continue
            out[kname] = key
        return out

    def build_authorizer(self, now: Optional[int] = None):
        """Return an ``update_authorizer`` for ``DMPDnsServer``.

        The closure captures the active key set at construction time
        but each call re-queries scope through ``self.get`` so a
        revoke that happens mid-tick rejects the next RR. (dnspython
        verified the key bytes against an earlier snapshot at parse
        time — that's fine, since revoking AFTER successful TSIG
        verification but BEFORE applying the writes is exactly the
        race the authorizer covers.)
        """
        store = self

        def authorize(key_name: dns.name.Name, op: str, owner: str) -> bool:
            try:
                name_text = key_name.to_text()
            except Exception:
                return False
            row = store.get(name_text)
            if row is None or not row.is_active(now=now):
                return False
            return row.covers(owner)

        return authorize

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "TSIGKeyStore":  # pragma: no cover
        return self

    def __exit__(self, *_a) -> None:  # pragma: no cover
        self.close()


def _row_to_key(row) -> TSIGKey:
    name, algorithm, secret, suffixes_blob, created_at, expires_at, revoked = row
    suffixes = tuple(s for s in (suffixes_blob or "").split("\n") if s)
    return TSIGKey(
        name=name,
        algorithm=algorithm,
        secret=bytes(secret),
        allowed_suffixes=suffixes,
        created_at=int(created_at),
        expires_at=int(expires_at),
        revoked=bool(revoked),
    )
