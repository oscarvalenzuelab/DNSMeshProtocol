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


class SubjectAlreadyOwnedError(Exception):
    """Raised by ``TSIGKeyStore.mint_for_subject`` when the subject
    already has an active key under a different ``registered_spk``.

    Surfaces the anti-takeover decision atomically with the mint so
    callers don't have to do a separate non-atomic existence check.
    Translated to ``SubjectAlreadyOwned`` (and HTTP 409) in the
    registration layer.
    """

    def __init__(self, subject: str) -> None:
        super().__init__(f"subject already owned: {subject}")
        self.subject = subject


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tsig_keys (
    name             TEXT PRIMARY KEY,
    algorithm        TEXT NOT NULL DEFAULT 'hmac-sha256',
    secret           BLOB NOT NULL,
    allowed_suffixes TEXT NOT NULL DEFAULT '',
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL DEFAULT 0,
    revoked          INTEGER NOT NULL DEFAULT 0,
    subject          TEXT NOT NULL DEFAULT '',
    registered_spk   TEXT NOT NULL DEFAULT '',
    registered_x25519_pub TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_tsig_active ON tsig_keys(revoked, expires_at);
CREATE INDEX IF NOT EXISTS idx_tsig_subject ON tsig_keys(subject);
"""

# Schema migration for keystores created before later columns landed.
# ALTER TABLE IF NOT EXISTS is sqlite 3.35+, which we don't depend on,
# so we add the columns idempotently via try/except. Each ADD COLUMN
# raises OperationalError if the column already exists; swallow that
# and continue.
_MIGRATIONS = (
    "ALTER TABLE tsig_keys ADD COLUMN subject TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE tsig_keys ADD COLUMN registered_spk TEXT NOT NULL DEFAULT ''",
    # Codex round-4 P1: M10's registered-recipient gate needs to
    # recompute hash12(recipient_id) for upgraded keystores whose
    # stored ``allowed_suffixes`` predate the corrected mailbox-hash
    # convention. Persisting the user's X25519 pub at registration
    # time lets the gate derive the canonical hash regardless of
    # what suffixes the scope contains — and also covers
    # ``DMP_TSIG_LOOSE_SCOPE=1`` users whose scope is just the bare
    # zone (no ``mb-{hash}.{zone}`` entry to extract).
    "ALTER TABLE tsig_keys ADD COLUMN registered_x25519_pub TEXT NOT NULL DEFAULT ''",
)


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
    ``alice.example.com`` granting everything beneath.

    Codex round-14: ``suffix`` may also contain ``*`` wildcards in
    label positions to match content-addressed DMP record names. A
    suffix like ``slot-*.mb-*.alice.test`` matches
    ``slot-3.mb-abcdef012345.alice.test`` but NOT
    ``slot-3.mb-abcdef012345.bob.test``. This lets a TSIG key
    authorize the per-recipient and per-message names that
    ``DMPClient.send_message`` writes without granting full-zone
    authority. ``*`` only matches within a single label (no dots).
    """
    if not suffix:
        return False
    s = _normalize_suffix(suffix)
    o = (owner or "").strip().lower().rstrip(".")
    if "*" in s:
        return _glob_suffix_match(o, s)
    return o == s or o.endswith("." + s)


def _glob_suffix_match(owner: str, pattern: str) -> bool:
    """Per-label glob match. ``*`` matches one or more chars within a
    single label; dots are label separators and never matched by ``*``.

    The pattern is treated as a SUFFIX — ``slot-*.mb-*.alice.test``
    matches owner ``slot-3.mb-abc.alice.test`` AND
    ``foo.slot-3.mb-abc.alice.test`` (subdomain extension), so the
    same "covers everything beneath" semantic as plain suffixes is
    preserved. Pattern labels are right-aligned with owner labels.
    """
    pattern_labels = pattern.split(".")
    owner_labels = owner.split(".")
    if len(owner_labels) < len(pattern_labels):
        return False
    # Right-align: compare last len(pattern_labels) owner labels.
    aligned = owner_labels[-len(pattern_labels) :]
    for pl, ol in zip(pattern_labels, aligned):
        if not _label_glob(pl, ol):
            return False
    return True


def _label_glob(pattern_label: str, owner_label: str) -> bool:
    """Match one label with a single ``*`` wildcard at most. Order
    keeps complexity O(label length); we don't support ``**`` or
    multi-wildcard patterns yet — the DMP record names we need
    (``slot-N``, ``mb-<hash>``, ``chunk-N-<hash>``) all have at
    most one variable segment per label."""
    if "*" not in pattern_label:
        return pattern_label == owner_label
    parts = pattern_label.split("*")
    # Reconstruct: parts[0] + <wildcard> + parts[1] + <wildcard> + ...
    pos = 0
    for i, part in enumerate(parts):
        if i == 0:
            if not owner_label.startswith(part):
                return False
            pos = len(part)
        elif i == len(parts) - 1:
            if not owner_label.endswith(part):
                return False
            if pos > len(owner_label) - len(part):
                return False
        else:
            idx = owner_label.find(part, pos)
            if idx < 0:
                return False
            pos = idx + len(part)
    return True


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
    # M9.2.3 anti-takeover: when the key was minted via
    # mint_tsig_via_registration, ``subject`` is the canonical
    # ``user@host`` and ``registered_spk`` is the hex Ed25519 spk
    # that proved ownership. A second registrant for the same
    # subject must sign with the same spk OR the existing key must
    # be revoked first. Empty values (legacy / admin-issued) skip
    # the anti-takeover check.
    subject: str = ""
    registered_spk: str = ""
    # Codex round-4 P1: persist the user's X25519 pub (hex) at
    # registration time so M10's registered-recipient gate can
    # recompute the canonical mailbox hash on demand, regardless of
    # what shape the stored ``allowed_suffixes`` happen to take
    # (legacy single-round mailbox hashes, loose-scope bare-zone-only
    # entries, etc.). Empty for ancient registrations that predate
    # this column.
    registered_x25519_pub: str = ""

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
        # Best-effort column adds for keystores created before the
        # subject + registered_spk columns landed. SQLite raises on
        # duplicate ADD COLUMN, which we swallow.
        for stmt in _MIGRATIONS:
            try:
                self._conn.execute(stmt)
            except sqlite3.OperationalError:
                pass
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
        subject: str = "",
        registered_spk: str = "",
        registered_x25519_pub: str = "",
        now: Optional[int] = None,
    ) -> TSIGKey:
        """Insert or replace a key. Replacing is intentional — the
        registration flow may re-issue a key for a user who lost
        theirs; the new key carries fresh secret bytes and the same
        scope. Old key bytes are unrecoverable from the row.

        ``subject`` + ``registered_spk`` are persisted so the
        anti-takeover check in ``ensure_subject_owner`` can reject a
        second registrant attempting to mint a key for an already-
        owned subject. ``registered_x25519_pub`` (codex round-4 P1)
        is the user's X25519 pub at registration time, stored so the
        M10 registered-recipient gate can recompute the canonical
        mailbox hash regardless of what shape the stored scope takes.
        """
        canonical = _normalize_name(name)
        if not isinstance(secret, (bytes, bytearray)) or not secret:
            raise ValueError("secret must be non-empty bytes")
        suffixes = tuple(sorted({_normalize_suffix(s) for s in allowed_suffixes if s}))
        if not suffixes:
            raise ValueError("at least one non-empty allowed suffix is required")
        subject_norm = (subject or "").strip().lower()
        spk_norm = (registered_spk or "").strip().lower()
        x_norm = (registered_x25519_pub or "").strip().lower()
        created_at = int(time.time() if now is None else now)
        with self._lock:
            self._conn.execute(
                """INSERT INTO tsig_keys
                   (name, algorithm, secret, allowed_suffixes,
                    created_at, expires_at, revoked, subject,
                    registered_spk, registered_x25519_pub)
                   VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                     algorithm = excluded.algorithm,
                     secret = excluded.secret,
                     allowed_suffixes = excluded.allowed_suffixes,
                     created_at = excluded.created_at,
                     expires_at = excluded.expires_at,
                     revoked = 0,
                     subject = excluded.subject,
                     registered_spk = excluded.registered_spk,
                     registered_x25519_pub = excluded.registered_x25519_pub""",
                (
                    canonical,
                    algorithm,
                    bytes(secret),
                    "\n".join(suffixes),
                    created_at,
                    int(expires_at),
                    subject_norm,
                    spk_norm,
                    x_norm,
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
            subject=subject_norm,
            registered_spk=spk_norm,
            registered_x25519_pub=x_norm,
        )

    def mint(
        self,
        *,
        name: str,
        allowed_suffixes: Iterable[str],
        algorithm: str = DEFAULT_ALGORITHM,
        secret_bytes: int = DEFAULT_SECRET_BYTES,
        expires_at: int = 0,
        subject: str = "",
        registered_spk: str = "",
        registered_x25519_pub: str = "",
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
            subject=subject,
            registered_spk=registered_spk,
            registered_x25519_pub=registered_x25519_pub,
            now=now,
        )

    def mint_for_subject(
        self,
        *,
        name: str,
        allowed_suffixes: Iterable[str],
        subject: str,
        registered_spk: str,
        registered_x25519_pub: str = "",
        algorithm: str = DEFAULT_ALGORITHM,
        secret_bytes: int = DEFAULT_SECRET_BYTES,
        expires_at: int = 0,
        now: Optional[int] = None,
    ) -> TSIGKey:
        """Atomic anti-takeover mint: under the store lock, check for
        an existing live key bound to the same ``subject`` under a
        DIFFERENT ``registered_spk``; raise ``SubjectAlreadyOwnedError``
        if found. Otherwise mint a fresh secret and persist.

        Codex round-7 P1: a separate ``get_active_for_subject`` +
        ``mint`` flow has a TOCTOU race — two concurrent
        ``POST /v1/registration/tsig-confirm`` requests with different
        SPKs for the same subject both pass the existence check, then
        both insert (different key names because spk-derived), and
        the subject ends up with parallel live credentials. The atomic
        version closes the race by serializing the existence check
        and insert through the same lock.
        """
        canonical = _normalize_name(name)
        if not isinstance(registered_spk, str) or not registered_spk:
            raise ValueError("registered_spk must be a non-empty hex string")
        suffixes = tuple(sorted({_normalize_suffix(s) for s in allowed_suffixes if s}))
        if not suffixes:
            raise ValueError("at least one non-empty allowed suffix is required")
        subject_norm = (subject or "").strip().lower()
        spk_norm = registered_spk.strip().lower()
        x_norm = (registered_x25519_pub or "").strip().lower()
        if not subject_norm:
            raise ValueError("subject must be non-empty for atomic mint")
        secret = secrets.token_bytes(int(secret_bytes))
        created_at = int(time.time() if now is None else now)
        with self._lock:
            existing = self._conn.execute(
                """SELECT registered_spk
                   FROM tsig_keys
                   WHERE subject = ?
                     AND revoked = 0
                     AND (expires_at = 0 OR expires_at > ?)""",
                (subject_norm, created_at),
            ).fetchall()
            for (existing_spk,) in existing:
                if existing_spk and existing_spk != spk_norm:
                    raise SubjectAlreadyOwnedError(subject_norm)
            self._conn.execute(
                """INSERT INTO tsig_keys
                   (name, algorithm, secret, allowed_suffixes,
                    created_at, expires_at, revoked, subject,
                    registered_spk, registered_x25519_pub)
                   VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                   ON CONFLICT(name) DO UPDATE SET
                     algorithm = excluded.algorithm,
                     secret = excluded.secret,
                     allowed_suffixes = excluded.allowed_suffixes,
                     created_at = excluded.created_at,
                     expires_at = excluded.expires_at,
                     revoked = 0,
                     subject = excluded.subject,
                     registered_spk = excluded.registered_spk,
                     registered_x25519_pub = excluded.registered_x25519_pub""",
                (
                    canonical,
                    algorithm,
                    secret,
                    "\n".join(suffixes),
                    created_at,
                    int(expires_at),
                    subject_norm,
                    spk_norm,
                    x_norm,
                ),
            )
            self._conn.commit()
        return TSIGKey(
            name=canonical,
            algorithm=algorithm,
            secret=secret,
            allowed_suffixes=suffixes,
            created_at=created_at,
            expires_at=int(expires_at),
            revoked=False,
            subject=subject_norm,
            registered_spk=spk_norm,
            registered_x25519_pub=x_norm,
        )

    # ------------------------------------------------------------------
    # subject ownership
    # ------------------------------------------------------------------

    def get_active_for_subject(
        self, subject: str, now: Optional[int] = None
    ) -> Optional[TSIGKey]:
        """Return the live key minted for ``subject`` (if any).

        Used by the anti-takeover check in ``mint_tsig_via_registration``.
        Skips revoked / expired rows so a previously-revoked key for
        the same subject doesn't block a fresh registration with a
        different signing identity (the legitimate user can revoke
        their compromised key and re-register).
        """
        subject_norm = (subject or "").strip().lower()
        if not subject_norm:
            return None
        now_i = int(time.time() if now is None else now)
        with self._lock:
            row = self._conn.execute(
                """SELECT name, algorithm, secret, allowed_suffixes,
                          created_at, expires_at, revoked, subject,
                          registered_spk, registered_x25519_pub
                   FROM tsig_keys
                   WHERE subject = ?
                     AND revoked = 0
                     AND (expires_at = 0 OR expires_at > ?)
                   ORDER BY created_at DESC
                   LIMIT 1""",
                (subject_norm, now_i),
            ).fetchone()
        return _row_to_key(row) if row else None

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
                          created_at, expires_at, revoked, subject,
                          registered_spk, registered_x25519_pub
                   FROM tsig_keys WHERE name = ?""",
                (canonical,),
            ).fetchone()
        return _row_to_key(row) if row else None

    def list_active(self, now: Optional[int] = None) -> List[TSIGKey]:
        now_i = int(time.time() if now is None else now)
        with self._lock:
            rows = self._conn.execute(
                """SELECT name, algorithm, secret, allowed_suffixes,
                          created_at, expires_at, revoked, subject,
                          registered_spk, registered_x25519_pub
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
                          created_at, expires_at, revoked, subject,
                          registered_spk, registered_x25519_pub
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
                key = dns.tsig.Key(
                    name=kname, secret=row.secret, algorithm=row.algorithm
                )
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

    def registered_recipient_hashes(self, zone: str, now: Optional[int] = None) -> set:
        """Return the set of mailbox hash12s registered under ``zone``.

        M10 (codex round-3 P1) uses this set to gate un-TSIG'd claim
        writes when ``DMP_RECEIVER_CLAIM_NOTIFICATIONS=1`` and
        ``DMP_CLAIM_PROVIDER=0`` — the operator opted out of the
        public first-contact write surface, so M10 must accept claim
        records ONLY for users who actually live on this node's zone.

        Resolution order (codex round-4 P1 + P2 #1):

          1. ``registered_x25519_pub`` — the canonical source. Recompute
             ``hash12(sha256(x_pub))`` directly so the registered set
             is correct regardless of what shape ``allowed_suffixes``
             takes. Covers (a) keystores upgraded from pre-M10 builds
             whose mailbox-hash suffix used the old single-round
             formulation, and (b) ``DMP_TSIG_LOOSE_SCOPE=1`` users
             whose scope is just the bare zone with no
             ``mb-{hash}.{zone}`` entry to extract.
          2. Fall back to scanning ``allowed_suffixes`` for
             ``mb-{hex12}.{zone}`` entries — covers ancient keystores
             that predate the ``registered_x25519_pub`` column AND
             admin-issued keys that didn't go through the
             ``/v1/registration/tsig-confirm`` flow.

        Returns a fresh set each call (built from the current active
        key set) so a revoke / register that happens mid-tick takes
        effect on the next packet without restarting the server.
        """
        import hashlib

        z = (zone or "").strip().lower().rstrip(".")
        if not z:
            return set()
        prefix = "mb-"
        suffix = "." + z
        hashes: set = set()
        for row in self.list_active(now=now):
            # Preferred path: recompute from the persisted X25519 pub.
            x_hex = (row.registered_x25519_pub or "").strip().lower()
            if x_hex:
                try:
                    x_bytes = bytes.fromhex(x_hex)
                except ValueError:
                    x_bytes = b""
                if len(x_bytes) == 32:
                    recipient_id = hashlib.sha256(x_bytes).digest()
                    hashes.add(hashlib.sha256(recipient_id).hexdigest()[:12])
                    # Continue to scope-scanning below in case the
                    # operator issued an extra mb-{hash}.{zone} suffix
                    # by hand — defense in depth, not load-bearing.
            for s in row.allowed_suffixes:
                norm = (s or "").strip().lower().rstrip(".")
                # Look for ``mb-{hex12}.{zone}``. Skip wildcards
                # (``mb-*.{zone}``) — those grant authority but don't
                # identify a registered user.
                if not norm.endswith(suffix):
                    continue
                head = norm[: -len(suffix)]
                if not head.startswith(prefix):
                    continue
                h = head[len(prefix) :]
                if "*" in h:
                    continue
                if len(h) == 12 and all(c in "0123456789abcdef" for c in h):
                    hashes.add(h)
        return hashes

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
    (
        name,
        algorithm,
        secret,
        suffixes_blob,
        created_at,
        expires_at,
        revoked,
        subject,
        registered_spk,
        registered_x25519_pub,
    ) = row
    suffixes = tuple(s for s in (suffixes_blob or "").split("\n") if s)
    return TSIGKey(
        name=name,
        algorithm=algorithm,
        secret=bytes(secret),
        allowed_suffixes=suffixes,
        created_at=int(created_at),
        expires_at=int(expires_at),
        revoked=bool(revoked),
        subject=str(subject or ""),
        registered_spk=str(registered_spk or ""),
        registered_x25519_pub=str(registered_x25519_pub or ""),
    )
