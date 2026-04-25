"""Per-user publish tokens for multi-tenant node deployments (M5.5).

Complements (does not replace) ``DMP_OPERATOR_TOKEN`` — the operator
token still gates the cluster / bootstrap / peer-sync namespaces.
End-user tokens live in this module and gate publishes to
user-identity, rotation, prekey, mailbox, and chunk records.

Design anchor: ``docs/design/multi-tenant-auth.md``.

Token material is never persisted. The store keeps only
``sha256(token)`` so a DB dump doesn't leak live credentials. The
full token is shown to the user exactly once (at issuance time) and
then held client-side in ``~/.dmp/tokens/<node-hostname>``.

Two scope classes, enforced by :class:`TokenStore.authorize_write`:

* **owner-exclusive** — identity / rotation / prekey records. The
  token's ``subject`` must match the record owner, derived by the
  caller from the record name.
* **shared-pool** — mailbox slot + chunk records. Any active,
  non-revoked, non-expired token is accepted. Audit rows for
  shared-pool writes deliberately do NOT record ``subject`` or
  ``token_hash`` — see "Audit policy is split" section of the
  design doc.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

# Subject types. Mirrors dmp.core.rotation constants to keep the
# two databases in sync; we re-declare here so the server package
# doesn't take a cross-package import for an int.
SUBJECT_TYPE_USER_IDENTITY = 1
SUBJECT_TYPE_CLUSTER_OPERATOR = 2  # reserved — M5.5 does not issue these
SUBJECT_TYPE_BOOTSTRAP_SIGNER = 3  # reserved

# Token wire format: a short magic prefix so leaked tokens are
# grep-able in logs and users can recognize them at a glance.
# v1 = current scheme: 32 random bytes, base32-no-pad encoded.
_TOKEN_PREFIX = "dmp_v1_"
_TOKEN_RANDOM_BYTES = 32
_TOKEN_BODY_LEN = 52  # base32 of 32 bytes = 52 chars without padding

# Default per-token rate limit. Applies AFTER the per-IP limiter,
# so a token holder has their own budget that doesn't steal from
# everyone else on the same NAT.
DEFAULT_RATE_PER_SEC = 10.0
DEFAULT_RATE_BURST = 50


# ASCII-only subject policy (security-critical):
#
# Token subjects are stored and compared as lowercase ASCII. Unicode
# subjects are rejected at issuance time. Motivation: Python's
# ``str.lower()`` is not Unicode-safe for equality — some compatibility
# characters collapse to the same casefold (e.g. fullwidth Latin letters,
# mathematical script letters, certain Greek / Cyrillic homoglyphs).
# Allowing non-ASCII here would let a token issued to
# ``a\ufo15ce@example.com`` authorize writes under ``alice@example.com``.
#
# Since DMP record names also traverse DNS (case-insensitive, ASCII for
# non-IDN zones), restricting subjects to ASCII is the pragmatic choice
# for v1. Internationalized subjects are a future milestone and will need
# IDNA encoding + NFC normalization at issuance + comparison.
_SUBJECT_ASCII_RE = re.compile(
    r"^[a-z0-9][a-z0-9._+-]*@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)


def canonicalize_subject(raw: str) -> str:
    """Return the canonical ASCII-lowercase form of a subject, or raise.

    Policy: NFKC-normalize input to expose compatibility-character
    collisions, then require the result is pure ASCII and matches the
    ``<local>@<fqdn>`` shape. Callers who want to reject non-ASCII at
    their layer should catch :class:`ValueError` here.
    """
    if not isinstance(raw, str) or not raw:
        raise ValueError("subject must be a non-empty string")
    norm = unicodedata.normalize("NFKC", raw).strip().lower()
    # Re-encode through ASCII to catch any non-ASCII that survives the
    # NFKC pass (rare but possible for scripts with no ASCII mapping).
    try:
        norm.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"subject must be ASCII; got non-ASCII character at position {exc.start}"
        ) from exc
    if not _SUBJECT_ASCII_RE.match(norm):
        raise ValueError(f"subject does not match <local>@<fqdn> shape: {raw!r}")
    return norm


def _b32_no_pad(raw: bytes) -> str:
    """base32 without padding, uppercase.

    We use base32 over hex to keep tokens short and over base64url
    to avoid accidental URL-decoding surprises if someone puts a
    token in a query string. Copy-pasting into curl is safe.
    """
    return base64.b32encode(raw).rstrip(b"=").decode("ascii")


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def generate_token() -> str:
    """Generate a fresh token. Show to the user once; never log."""
    body = _b32_no_pad(secrets.token_bytes(_TOKEN_RANDOM_BYTES))
    return _TOKEN_PREFIX + body


def token_looks_valid(token: str) -> bool:
    """Fast shape check before a DB roundtrip. Guards against
    accidentally hashing the Authorization header prefix."""
    if not token.startswith(_TOKEN_PREFIX):
        return False
    body = token[len(_TOKEN_PREFIX) :]
    return len(body) == _TOKEN_BODY_LEN and body.isalnum() and body.isupper()


# ---------------------------------------------------------------------------


class ScopeClass:
    """Classification of a record name against the M5.5 scope rules.

    Instances are lightweight — classify() returns one of the
    module-level singletons so identity comparisons work.
    """

    __slots__ = ("kind", "subject", "reason")

    OWNER_EXCLUSIVE = "owner_exclusive"
    SHARED_POOL = "shared_pool"
    OPERATOR_ONLY = "operator_only"
    UNKNOWN = "unknown"

    def __init__(self, kind: str, subject: Optional[str] = None, reason: str = ""):
        self.kind = kind
        self.subject = subject  # only set for OWNER_EXCLUSIVE
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScopeClass(kind={self.kind!r}, subject={self.subject!r})"


# Record-name patterns, fail-closed.
#
# SECURITY: strict-shape matches only. `startswith("slot-")` on the
# first label without validating the REST of the name lets a crafted
# name like `slot-1..example.com` or `slot-x.bootstrap.example.com`
# smuggle itself through as SHARED_POOL. Anything that doesn't match
# the full expected shape falls through to OPERATOR_ONLY (or UNKNOWN
# when malformed), so a classifier gap widens nothing.
#
# ASCII-only at the classifier level for the same reason we enforce
# it on subjects: Unicode label equality is not safe. DNS labels in
# any non-IDN zone are ASCII anyway; IDN support is a future milestone.
#
# Shapes:
#   Identity:  dmp.<user>.<domain>
#   Rotation:  rotate.dmp.<user>.<domain>
#              rotate.dmp.id-<hash12>.<domain>   (operator-only in v1)
#   Prekey:    pk-<id>.<hash12>.<domain>
#   Mailbox:   slot-<N>.mb-<hash12>.<domain>
#   Chunk:     chunk-<NNNN>-<msgkey12>.<domain>
#
# All record names are the concatenation of ASCII labels (0-9, a-z,
# '-') separated by single dots, with no empty labels. The patterns
# below enforce that explicitly — no relying on "just split and
# check the first element".

# Single DNS label: ASCII letters/digits/hyphen, neither starts nor
# ends with '-', 1..63 chars. The FQDN is >=1 such label joined by
# single dots; we use a non-anchored sub-pattern so we can compose it.
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_HASH12 = r"[0-9a-f]{12}"
_HASH16 = r"[0-9a-f]{16}"

# Username is a SINGLE label; domain is everything after it (>=2
# labels to form a real FQDN). This matches how DMPClient addresses
# identities: `dmp.<username>.<domain>` where username cannot contain
# dots. Permitting a multi-label username would make the user/domain
# split ambiguous (e.g. `dmp.alice.sub.example.co.uk` could be
# alice@sub.example.co.uk or alice.sub.example@co.uk).
_IDENTITY_RE = re.compile(
    rf"^dmp\.(?P<user>{_LABEL})\.(?P<domain>{_LABEL}(?:\.{_LABEL})+)$"
)
_ROTATION_ZONE_RE = re.compile(
    rf"^rotate\.dmp\.(?P<user>{_LABEL})\.(?P<domain>{_LABEL}(?:\.{_LABEL})+)$"
)
_ROTATION_HASH_RE = re.compile(rf"^rotate\.dmp\.id-{_HASH12}\.{_LABEL}(?:\.{_LABEL})+$")
_PREKEY_RE = re.compile(rf"^pk-[0-9]+\.(?P<hash12>{_HASH12})\.{_LABEL}(?:\.{_LABEL})+$")
_MAILBOX_RE = re.compile(rf"^slot-[0-9]+\.mb-{_HASH12}\.{_LABEL}(?:\.{_LABEL})+$")
_CHUNK_RE = re.compile(rf"^chunk-[0-9]+-{_HASH12}\.{_LABEL}(?:\.{_LABEL})+$")
# Unanchored identity record published by `dnsmesh identity publish` when no
# `identity_domain` is set. Hash16 = sha256(username)[:16] — matches
# `dmp.core.identity.identity_domain`. Authorized via on-the-fly recompute
# from the token's subject (no schema column needed).
_IDENTITY_HASH_RE = re.compile(
    rf"^id-(?P<hash16>{_HASH16})\.(?P<domain>{_LABEL}(?:\.{_LABEL})+)$"
)
# Prekey pool RRset published by `dnsmesh identity refresh-prekeys`.
# Hash12 = sha256(username)[:12] — matches `dmp.core.prekeys.prekey_rrset_name`.
_PREKEY_POOL_RE = re.compile(
    rf"^prekeys\.id-(?P<hash12>{_HASH12})\.(?P<domain>{_LABEL}(?:\.{_LABEL})+)$"
)


def classify_name(name: str) -> ScopeClass:
    """Classify a record name for auth scope enforcement.

    Strict-shape match, ASCII-only, fail-closed: any name that
    doesn't fully match one of the recognized record patterns falls
    to OPERATOR_ONLY (reserved prefix / unknown) or UNKNOWN
    (malformed / empty labels).

    This function does NOT hit the database. The returned
    :class:`ScopeClass` is then handed to
    :meth:`TokenStore.authorize_write`.
    """
    if not name or not isinstance(name, str):
        return ScopeClass(ScopeClass.UNKNOWN, reason="empty name")

    n = name.rstrip(".").lower()
    if not n:
        return ScopeClass(ScopeClass.UNKNOWN, reason="name was only dots")

    # Reject anything outside the ASCII label alphabet (letters,
    # digits, hyphen, dot). Catches Unicode labels that would slip
    # past a more permissive classifier.
    if not re.fullmatch(r"[a-z0-9.\-]+", n):
        return ScopeClass(ScopeClass.UNKNOWN, reason="non-ASCII or disallowed chars")

    # Empty labels (consecutive dots) are a fast-path reject. Every
    # shape-specific regex also enforces this, but rejecting early
    # means we don't accidentally classify something like
    # `slot-1..example.com` based on a partial prefix match.
    if ".." in n or n.startswith(".") or n.endswith("."):
        return ScopeClass(ScopeClass.UNKNOWN, reason="empty label(s) in name")

    # Not an FQDN at all (no dot) — malformed rather than merely
    # reserved. Classify as UNKNOWN so the rejection path reports
    # the root cause and we don't silently treat bare labels as
    # operator-reserved names.
    if "." not in n:
        return ScopeClass(ScopeClass.UNKNOWN, reason="no dots — not an FQDN")

    # Identity: dmp.<user>.<domain>  (enforced: user + at least 2 domain labels)
    m = _IDENTITY_RE.match(n)
    if m:
        return ScopeClass(
            ScopeClass.OWNER_EXCLUSIVE,
            subject=f"{m.group('user')}@{m.group('domain')}",
        )

    # Identity (unanchored hash form): id-<hash16>.<domain>
    # Subject sentinel encodes both the hash and the domain so
    # authorize_write can verify both halves against row.subject.
    m = _IDENTITY_HASH_RE.match(n)
    if m:
        return ScopeClass(
            ScopeClass.OWNER_EXCLUSIVE,
            subject=f"#id16:{m.group('hash16')}@{m.group('domain')}",
            reason="hashed identity",
        )

    # Prekey pool: prekeys.id-<hash12>.<domain>
    m = _PREKEY_POOL_RE.match(n)
    if m:
        return ScopeClass(
            ScopeClass.OWNER_EXCLUSIVE,
            subject=f"#prekeys:{m.group('hash12')}@{m.group('domain')}",
            reason="prekey pool hash-scoped",
        )

    # Rotation hash form is operator-only in v1; check before the zone form
    # because both match 'rotate.dmp....' but the hash form has the id-*
    # label at a fixed position.
    if _ROTATION_HASH_RE.match(n):
        return ScopeClass(
            ScopeClass.OPERATOR_ONLY,
            reason="hash-form rotation not issuable to end-user tokens in v1",
        )

    # Rotation zone-anchored: rotate.dmp.<user>.<domain>
    m = _ROTATION_ZONE_RE.match(n)
    if m:
        return ScopeClass(
            ScopeClass.OWNER_EXCLUSIVE,
            subject=f"{m.group('user')}@{m.group('domain')}",
        )

    # Prekey: pk-<id>.<hash12>.<domain>
    m = _PREKEY_RE.match(n)
    if m:
        return ScopeClass(
            ScopeClass.OWNER_EXCLUSIVE,
            subject=f"#{m.group('hash12')}",
            reason="prekey hash-scoped",
        )

    # Mailbox: slot-<N>.mb-<hash12>.<domain>
    if _MAILBOX_RE.match(n):
        return ScopeClass(ScopeClass.SHARED_POOL, reason="mailbox slot")

    # Chunk: chunk-<NNNN>-<msgkey12>.<domain>
    if _CHUNK_RE.match(n):
        return ScopeClass(ScopeClass.SHARED_POOL, reason="message chunk")

    # Anything else is reserved for the operator token. Includes
    # cluster.*, bootstrap.*, and any future prefix we haven't
    # taught the classifier yet. Fail closed — widening this table
    # is a deliberate change, not a classifier oversight.
    return ScopeClass(
        ScopeClass.OPERATOR_ONLY,
        reason="reserved or unrecognized record namespace",
    )


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenRow:
    """Decoded row from the tokens table. Never carries secret material."""

    token_hash: str
    subject: str
    subject_type: int
    subject_hash12: Optional[str]  # sha256(subject)[:12] for prekey namespace checks
    rate_per_sec: float
    rate_burst: int
    issued_at: int
    expires_at: Optional[int]
    revoked_at: Optional[int]
    issuer: str
    note: str
    # Hex-encoded 32-byte Ed25519 public key presented at registration.
    # None for operator-issued (admin CLI) tokens; set for self-service.
    registered_spk: Optional[str] = None

    def is_live(self, now: Optional[int] = None) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None:
            now = now if now is not None else int(time.time())
            if now >= self.expires_at:
                return False
        return True


class AuthResult:
    """Outcome of TokenStore.authorize_write. Exposes:

    - ``ok``: True iff the request is authorized AND not rate-limited.
    - ``throttled``: True iff authorization succeeded but the token's
      per-token rate-limit bucket is empty. Distinguishes 401-worthy
      failures from 429-worthy ones on the HTTP side.
    - ``row``: the live TokenRow that authorized it (or None).
    - ``scope``: the ScopeClass classification that applied.
    - ``reason``: human-readable rejection reason when ``ok`` is False.
    - ``is_shared_pool``: convenience for the caller to decide whether
      to log the subject in audit.
    """

    __slots__ = ("ok", "throttled", "row", "scope", "reason")

    def __init__(
        self,
        ok: bool,
        *,
        throttled: bool = False,
        row: Optional[TokenRow] = None,
        scope: Optional[ScopeClass] = None,
        reason: str = "",
    ):
        self.ok = ok
        self.throttled = throttled
        self.row = row
        self.scope = scope
        self.reason = reason

    @property
    def is_shared_pool(self) -> bool:
        return self.scope is not None and self.scope.kind == ScopeClass.SHARED_POOL

    def __bool__(self) -> bool:  # pragma: no cover — convenience
        return self.ok


# ---------------------------------------------------------------------------


class _SubjectLocked(Exception):
    """Internal marker raised by TokenStore.rotate_self_service when
    anti-takeover blocks the rotation. The registration layer
    translates it to a SubjectAlreadyOwned HTTP error."""


# ---------------------------------------------------------------------------
# Per-token rate limiter — independent of the per-IP limiter in
# dmp.server.rate_limit. Buckets are keyed by token_hash so a token with
# rate_per_sec=1 throttles at 1 rps regardless of source IP.
# ---------------------------------------------------------------------------


class _PerTokenBucket:
    """Minimal thread-safe token-bucket keyed by token_hash.

    The per-IP ``TokenBucketLimiter`` in dmp.server.rate_limit uses a
    single ``RateLimit`` for all keys. We need per-key rate + burst
    because each issued token carries its own ``rate_per_sec`` and
    ``rate_burst``. Rather than extend that limiter's surface, keep a
    purpose-built one here — small, obvious, and scoped to M5.5.
    """

    __slots__ = ("_lock", "_buckets", "_max_tracked")

    def __init__(self, max_tracked: int = 10_000) -> None:
        self._lock = threading.Lock()
        # token_hash -> (tokens_remaining, last_refill_monotonic)
        self._buckets: dict = {}
        self._max_tracked = max_tracked

    def allow(self, token_hash: str, rate_per_sec: float, burst: int) -> bool:
        """Spend 1 unit against the bucket. Return False if throttled.

        Disabled (always-allow) when rate_per_sec <= 0 OR burst <= 0 —
        mirroring the semantics of RateLimit.enabled in rate_limit.py.
        """
        if rate_per_sec <= 0 or burst <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(token_hash, (float(burst), now))
            tokens = min(float(burst), tokens + (now - last) * rate_per_sec)
            if tokens < 1.0:
                # Store the refilled-but-still-empty state so rapid
                # retries don't refill from the original timestamp.
                self._buckets[token_hash] = (tokens, now)
                self._evict_if_needed()
                return False
            self._buckets[token_hash] = (tokens - 1.0, now)
            self._evict_if_needed()
            return True

    def forget(self, token_hash: str) -> None:
        """Drop a bucket — called on revoke so revoked tokens don't
        hold memory."""
        with self._lock:
            self._buckets.pop(token_hash, None)

    def _evict_if_needed(self) -> None:
        # LRU-ish: just trim arbitrary entries when we hit the ceiling.
        # Simpler than OrderedDict housekeeping and the bucket cap is
        # a memory guard, not a correctness guarantee.
        if len(self._buckets) > self._max_tracked:
            for k in list(self._buckets.keys())[
                : len(self._buckets) - self._max_tracked
            ]:
                self._buckets.pop(k, None)


# ---------------------------------------------------------------------------


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    token_hash     TEXT PRIMARY KEY,
    subject        TEXT NOT NULL,
    subject_type   INTEGER NOT NULL,
    subject_hash12 TEXT,
    rate_per_sec   REAL    NOT NULL DEFAULT 10.0,
    rate_burst     INTEGER NOT NULL DEFAULT 50,
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER,
    revoked_at     INTEGER,
    issuer         TEXT NOT NULL DEFAULT '',
    note           TEXT NOT NULL DEFAULT '',
    -- M5.5 phase 3: Ed25519 signing pubkey (32-byte hex) that registered
    -- this token via POST /v1/registration/confirm. NULL for operator-
    -- issued (dnsmesh-node-admin) tokens, which don't go through a signed
    -- challenge. Used by the anti-takeover rule: self-service re-
    -- registration for an existing subject must sign the new challenge
    -- with the SAME key the prior token was registered under, so an
    -- attacker who guesses a subject string can't silently claim it.
    registered_spk TEXT
);

CREATE INDEX IF NOT EXISTS idx_tokens_subject
    ON tokens(subject) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS token_audit (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             INTEGER NOT NULL,
    event          TEXT NOT NULL,
    token_hash     TEXT,
    subject        TEXT,
    remote_addr    TEXT,
    detail         TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON token_audit(ts);
"""

# One-off migration for deployments that predate phase 3. Adding a
# column at runtime is cheaper than bumping the schema_version and the
# `tokens` table is single-owner (no migrations of in-flight data).
_MIGRATION_ADD_REGISTERED_SPK = """
ALTER TABLE tokens ADD COLUMN registered_spk TEXT
"""


class TokenStore:
    """SQLite-backed token store. Thread-safe (module-level lock).

    Connection per instance. The sqlite3 module's default check_same_thread
    guard is disabled and a threading.Lock serializes writes; the node's
    HTTP server spawns worker threads and must share a store.
    """

    def __init__(self, db_path: str):
        self._path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        # Best-effort additive migration for the phase-3 column.
        # sqlite rejects "ADD COLUMN if already exists"; catch the
        # duplicate-column error and move on.
        try:
            self._conn.execute(_MIGRATION_ADD_REGISTERED_SPK)
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc).lower():
                raise
        self._conn.commit()
        # Per-token rate limiter. In-memory, ephemeral by design —
        # rate state doesn't survive a node restart, matching how the
        # per-IP limiter behaves. Reissuing a throttled token via a
        # restart is a documented failure mode in the operator guide.
        self._rate_limiter = _PerTokenBucket()

    # ---- issuance ----------------------------------------------------------

    def issue(
        self,
        subject: str,
        *,
        subject_type: int = SUBJECT_TYPE_USER_IDENTITY,
        subject_hash12: Optional[str] = None,
        rate_per_sec: float = DEFAULT_RATE_PER_SEC,
        rate_burst: int = DEFAULT_RATE_BURST,
        expires_in_seconds: Optional[int] = None,
        issuer: str = "",
        note: str = "",
        remote_addr: str = "",
        registered_spk: Optional[str] = None,
    ) -> Tuple[str, TokenRow]:
        """Mint a new token for ``subject``. Returns ``(token, row)``.

        The token string is returned ONLY here — it cannot be fetched
        back later (we never persist it). Caller shows it to the user
        and lets them persist client-side.

        Does NOT atomically revoke a pre-existing live token for the
        same subject; callers who want "one live token per subject"
        semantics should revoke first. The self-service registration
        flow enforces this via its challenge-verify step.

        The ``subject`` is NFKC-normalized, lowercased, and required
        to match the ASCII ``<local>@<fqdn>`` shape — this closes
        the Unicode-homoglyph bypass where
        ``a４ce@example.com`` and ``alice@example.com`` would
        compare equal under plain ``.lower()``.
        """
        subject = canonicalize_subject(subject)
        token = generate_token()
        token_hash = _sha256_hex(token)
        now = int(time.time())
        expires_at = now + expires_in_seconds if expires_in_seconds else None

        row = TokenRow(
            token_hash=token_hash,
            subject=subject,
            subject_type=subject_type,
            subject_hash12=subject_hash12,
            rate_per_sec=rate_per_sec,
            rate_burst=rate_burst,
            issued_at=now,
            expires_at=expires_at,
            revoked_at=None,
            issuer=issuer,
            note=note,
            registered_spk=registered_spk,
        )

        with self._lock:
            self._conn.execute(
                """INSERT INTO tokens(token_hash, subject, subject_type,
                   subject_hash12, rate_per_sec, rate_burst, issued_at,
                   expires_at, revoked_at, issuer, note, registered_spk)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row.token_hash,
                    row.subject,
                    row.subject_type,
                    row.subject_hash12,
                    row.rate_per_sec,
                    row.rate_burst,
                    row.issued_at,
                    row.expires_at,
                    None,
                    row.issuer,
                    row.note,
                    row.registered_spk,
                ),
            )
            self._audit(
                "issued",
                token_hash=token_hash,
                subject=subject,
                remote_addr=remote_addr,
                detail=f"issuer={issuer!r} note={note!r}",
                now=now,
            )
            self._conn.commit()

        return token, row

    # ---- revocation --------------------------------------------------------

    def revoke(self, token_hash: str, *, remote_addr: str = "") -> bool:
        """Mark a token revoked. Idempotent."""
        now = int(time.time())
        with self._lock:
            cur = self._conn.execute(
                "UPDATE tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL",
                (now, token_hash),
            )
            updated = cur.rowcount > 0
            if updated:
                # Fetch subject for the audit row.
                r = self._conn.execute(
                    "SELECT subject FROM tokens WHERE token_hash=?",
                    (token_hash,),
                ).fetchone()
                subj = r[0] if r else None
                self._audit(
                    "revoked",
                    token_hash=token_hash,
                    subject=subj,
                    remote_addr=remote_addr,
                    now=now,
                )
            self._conn.commit()
        if updated:
            # Drop the in-memory rate bucket so a revoked token doesn't
            # leave state hanging around. Outside the DB lock because
            # the rate limiter has its own lock.
            self._rate_limiter.forget(token_hash)
        return updated

    def rotate_self_service(
        self,
        subject: str,
        *,
        registered_spk: str,
        expires_in_seconds: Optional[int] = None,
        rate_per_sec: float = DEFAULT_RATE_PER_SEC,
        rate_burst: int = DEFAULT_RATE_BURST,
        remote_addr: str = "",
    ) -> Tuple[str, TokenRow, bool]:
        """Atomic revoke-then-issue for self-service registration.

        Single lock, single commit: read the subject's current live
        rows under the store lock, enforce the anti-takeover rule,
        revoke any prior self-service tokens, and insert a new one —
        all before any other thread can read or mutate state for
        this subject. Closes the "two concurrent valid confirms both
        mint" race that revoke()+issue() would otherwise have.

        Returns ``(token, row, anti_takeover_ok)``. When the third
        element is ``False``, NOTHING has been written — the caller
        should treat it as a 409 SubjectAlreadyOwned and return the
        other two values as None sentinels... but for caller
        simplicity we instead raise in the `False` case so the happy
        path is clean. The tuple shape stays backwards-compatible
        with earlier sketches.

        Admin-issued rows (registered_spk IS NULL) are left alone —
        they represent an independent channel and do not lock the
        subject.
        """
        try:
            subject = canonicalize_subject(subject)
        except ValueError as exc:
            raise ValueError(f"subject invalid: {exc}") from exc
        if not isinstance(registered_spk, str) or len(registered_spk) != 64:
            raise ValueError("registered_spk must be a 64-char hex string")
        registered_spk = registered_spk.lower()

        token = generate_token()
        token_hash = _sha256_hex(token)
        now = int(time.time())
        expires_at = now + expires_in_seconds if expires_in_seconds else None

        freed_hashes: List[str] = []

        with self._lock:
            # Snapshot current live self-service rows for this subject.
            rows = [
                TokenRow(*r)
                for r in self._conn.execute(
                    f"""SELECT {self._SELECT_COLS} FROM tokens
                        WHERE subject=? AND revoked_at IS NULL
                          AND registered_spk IS NOT NULL""",
                    (subject,),
                ).fetchall()
            ]
            # Include expiry in the liveness check — is_live() reads the
            # row's timestamps, not the DB's.
            live_locking = [r for r in rows if r.is_live(now=now)]
            if live_locking and not all(
                r.registered_spk == registered_spk for r in live_locking
            ):
                # Re-registration while another key holds the subject.
                # Caller translates this into 409 SubjectAlreadyOwned.
                # Nothing written yet — atomic.
                raise _SubjectLocked()

            # Revoke every prior self-service row for this subject
            # (same-key rotations + any stale liveness-expired rows
            # the cleanup sweep hasn't picked up yet).
            for r in rows:
                self._conn.execute(
                    "UPDATE tokens SET revoked_at=? "
                    "WHERE token_hash=? AND revoked_at IS NULL",
                    (now, r.token_hash),
                )
                self._audit(
                    "revoked",
                    token_hash=r.token_hash,
                    subject=subject,
                    remote_addr=remote_addr,
                    detail="self-service rotate: superseded",
                    now=now,
                )
                freed_hashes.append(r.token_hash)

            # Mint the new row in the SAME transaction.
            self._conn.execute(
                """INSERT INTO tokens(token_hash, subject, subject_type,
                   subject_hash12, rate_per_sec, rate_burst, issued_at,
                   expires_at, revoked_at, issuer, note, registered_spk)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    token_hash,
                    subject,
                    SUBJECT_TYPE_USER_IDENTITY,
                    None,
                    rate_per_sec,
                    rate_burst,
                    now,
                    expires_at,
                    None,
                    "self-service",
                    "",
                    registered_spk,
                ),
            )
            self._audit(
                "issued",
                token_hash=token_hash,
                subject=subject,
                remote_addr=remote_addr,
                detail="self-service",
                now=now,
            )
            self._conn.commit()

        # Drop in-memory rate buckets for the revoked tokens (outside
        # the DB lock — the limiter has its own).
        for h in freed_hashes:
            self._rate_limiter.forget(h)

        # Re-fetch the canonical row so the caller gets an accurate
        # is_live() / expires_at. Cheap, one row by PK.
        row = self._row_by_hash(token_hash)
        assert row is not None, "inserted row disappeared — sqlite corruption?"
        return token, row, True

    def revoke_by_subject(self, subject: str, *, remote_addr: str = "") -> int:
        """Revoke every live token for ``subject``. Returns the count revoked.

        The subject is canonicalized before lookup so a lookup of
        ``Alice@Example.com`` matches rows issued as ``alice@example.com``.
        Malformed / non-ASCII subjects raise before touching the DB.
        """
        try:
            subject = canonicalize_subject(subject)
        except ValueError:
            return 0
        now = int(time.time())
        with self._lock:
            cur = self._conn.execute(
                "UPDATE tokens SET revoked_at=? WHERE subject=? AND revoked_at IS NULL",
                (now, subject),
            )
            count = cur.rowcount
            if count:
                self._audit(
                    "revoked",
                    subject=subject,
                    remote_addr=remote_addr,
                    detail=f"by_subject count={count}",
                    now=now,
                )
            self._conn.commit()
            return count

    # ---- lookup ------------------------------------------------------------

    _SELECT_COLS = (
        "token_hash, subject, subject_type, subject_hash12, "
        "rate_per_sec, rate_burst, issued_at, expires_at, "
        "revoked_at, issuer, note, registered_spk"
    )

    def _row_by_hash(self, token_hash: str) -> Optional[TokenRow]:
        r = self._conn.execute(
            f"SELECT {self._SELECT_COLS} FROM tokens WHERE token_hash=?",
            (token_hash,),
        ).fetchone()
        return None if r is None else TokenRow(*r)

    def list(
        self, *, include_revoked: bool = False, subject: Optional[str] = None
    ) -> List[TokenRow]:
        sql = f"SELECT {self._SELECT_COLS} FROM tokens"
        clauses = []
        args: List = []
        if not include_revoked:
            clauses.append("revoked_at IS NULL")
        if subject:
            try:
                subject = canonicalize_subject(subject)
            except ValueError:
                # An invalid subject filter matches nothing, not
                # every row. Add an impossible clause so the query
                # returns [] without us special-casing the return.
                clauses.append("1=0")
            else:
                clauses.append("subject = ?")
                args.append(subject)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY issued_at DESC"
        return [TokenRow(*r) for r in self._conn.execute(sql, args).fetchall()]

    # ---- authorization -----------------------------------------------------

    def authorize_write(
        self,
        token: str,
        record_name: str,
        *,
        remote_addr: str = "",
        log_use: bool = True,
    ) -> AuthResult:
        """Classify ``record_name`` and check ``token`` against the scope.

        Returns an :class:`AuthResult`. When ``log_use`` is True (the
        default), a successful authorization writes a row to the
        audit table — with subject/token_hash for owner-exclusive
        writes, with neither column populated for shared-pool writes
        (the split-audit policy).
        """
        if not token_looks_valid(token):
            return AuthResult(False, reason="malformed token")

        token_hash = _sha256_hex(token)
        scope = classify_name(record_name)

        with self._lock:
            row = self._row_by_hash(token_hash)
            if row is None:
                self._audit(
                    "rejected",
                    remote_addr=remote_addr,
                    detail="no such token",
                )
                self._conn.commit()
                return AuthResult(False, scope=scope, reason="unknown token")
            if not row.is_live():
                self._audit(
                    "rejected",
                    remote_addr=remote_addr,
                    detail="token expired or revoked",
                )
                self._conn.commit()
                return AuthResult(
                    False,
                    row=row,
                    scope=scope,
                    reason="token revoked or expired",
                )

            if scope.kind == ScopeClass.OPERATOR_ONLY:
                self._audit(
                    "rejected",
                    remote_addr=remote_addr,
                    detail=f"operator-only scope: {scope.reason}",
                )
                self._conn.commit()
                return AuthResult(
                    False,
                    row=row,
                    scope=scope,
                    reason="operator-only record namespace",
                )
            if scope.kind == ScopeClass.UNKNOWN:
                self._audit(
                    "rejected",
                    remote_addr=remote_addr,
                    detail=f"unknown scope: {scope.reason}",
                )
                self._conn.commit()
                return AuthResult(
                    False,
                    row=row,
                    scope=scope,
                    reason="unclassified record name",
                )

            if scope.kind == ScopeClass.OWNER_EXCLUSIVE:
                expected = scope.subject or ""
                if expected.startswith("#id16:") or expected.startswith("#prekeys:"):
                    # Recompute the expected hash from row.subject's
                    # user-half. row.subject is already canonicalized
                    # (lowercase ASCII), so plain bytes hashing matches
                    # the client-side `sha256(username)[:N]`. The sentinel
                    # carries both the hash and the domain so we verify
                    # both: an alkamod@mesh.local token must not be able
                    # to publish id-<hash(alkamod)>.evil.com.
                    prefix, _, payload = expected.partition(":")
                    want_hash, _, want_domain = payload.partition("@")
                    user, _, dom = row.subject.partition("@")
                    hash_len = 16 if prefix == "#id16" else 12
                    got_hash = hashlib.sha256(user.encode("utf-8")).hexdigest()[
                        :hash_len
                    ]
                    if got_hash != want_hash or dom != want_domain:
                        self._audit(
                            "rejected",
                            token_hash=token_hash,
                            subject=row.subject,
                            remote_addr=remote_addr,
                            detail=f"hashed-namespace mismatch: want {expected}",
                        )
                        self._conn.commit()
                        return AuthResult(
                            False,
                            row=row,
                            scope=scope,
                            reason="subject does not own this hashed record namespace",
                        )
                elif expected.startswith("#"):
                    # Hash-form check (prekey-per-key namespace, legacy).
                    if not row.subject_hash12 or row.subject_hash12 != expected[1:]:
                        self._audit(
                            "rejected",
                            token_hash=token_hash,
                            subject=row.subject,
                            remote_addr=remote_addr,
                            detail=f"subject_hash12 mismatch: want {expected}",
                        )
                        self._conn.commit()
                        return AuthResult(
                            False,
                            row=row,
                            scope=scope,
                            reason="subject hash does not match record namespace",
                        )
                else:
                    # Both sides already canonical: row.subject went
                    # through canonicalize_subject at issuance, and
                    # `expected` comes from classify_name which is
                    # already ASCII-lowercase (non-ASCII names fall
                    # to UNKNOWN earlier in this function). Plain
                    # equality is sufficient; no .lower() needed.
                    if row.subject != expected:
                        self._audit(
                            "rejected",
                            token_hash=token_hash,
                            subject=row.subject,
                            remote_addr=remote_addr,
                            detail=f"subject mismatch: want {expected}",
                        )
                        self._conn.commit()
                        return AuthResult(
                            False,
                            row=row,
                            scope=scope,
                            reason="subject does not match record owner",
                        )

                # Per-token rate limit: check AFTER the authz decision
                # so a rejected auth still logs 'rejected' (not
                # 'throttled'). If the bucket is empty we log
                # 'throttled' and return ok=False, throttled=True —
                # the HTTP layer translates to 429.
                if not self._rate_limiter.allow(
                    token_hash, row.rate_per_sec, row.rate_burst
                ):
                    if log_use:
                        self._audit(
                            "throttled",
                            token_hash=token_hash,
                            subject=row.subject,
                            remote_addr=remote_addr,
                            detail="owner-exclusive",
                        )
                        self._conn.commit()
                    return AuthResult(
                        False,
                        throttled=True,
                        row=row,
                        scope=scope,
                        reason="per-token rate limit exceeded",
                    )

                if log_use:
                    self._audit(
                        "used",
                        token_hash=token_hash,
                        subject=row.subject,
                        remote_addr=remote_addr,
                        detail="owner-exclusive",
                    )
                    self._conn.commit()
                return AuthResult(True, row=row, scope=scope)

            # Shared pool: any live token is fine. Deliberately do
            # NOT populate token_hash / subject on the audit row —
            # that's the split-audit policy. Per-token rate limit is
            # enforced the same way as for owner-exclusive, but the
            # throttled audit row ALSO drops token_hash/subject to
            # keep the split-audit invariant: an operator with the DB
            # cannot tell which user was throttled on a chunk write.
            if not self._rate_limiter.allow(
                token_hash, row.rate_per_sec, row.rate_burst
            ):
                if log_use:
                    self._audit(
                        "throttled",
                        remote_addr=remote_addr,
                        detail="shared-pool",
                    )
                    self._conn.commit()
                return AuthResult(
                    False,
                    throttled=True,
                    row=row,
                    scope=scope,
                    reason="per-token rate limit exceeded",
                )
            if log_use:
                self._audit(
                    "used",
                    remote_addr=remote_addr,
                    detail="shared-pool",
                )
                self._conn.commit()
            return AuthResult(True, row=row, scope=scope)

    # ---- audit -------------------------------------------------------------

    def _audit(
        self,
        event: str,
        *,
        token_hash: Optional[str] = None,
        subject: Optional[str] = None,
        remote_addr: str = "",
        detail: str = "",
        now: Optional[int] = None,
    ) -> None:
        """Append an audit row. Caller owns commit()."""
        ts = now if now is not None else int(time.time())
        self._conn.execute(
            """INSERT INTO token_audit(ts, event, token_hash, subject,
               remote_addr, detail) VALUES(?,?,?,?,?,?)""",
            (ts, event, token_hash, subject, remote_addr or None, detail or None),
        )

    def audit_rows(
        self, *, limit: int = 100, event: Optional[str] = None
    ) -> List[Tuple]:
        """Return recent audit rows for operator inspection. For ad-hoc use;
        production operators should pull from the DB directly."""
        sql = "SELECT ts, event, token_hash, subject, remote_addr, detail FROM token_audit"
        args: List = []
        if event:
            sql += " WHERE event = ?"
            args.append(event)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return [tuple(r) for r in self._conn.execute(sql, args).fetchall()]

    # ---- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "TokenStore":  # pragma: no cover
        return self

    def __exit__(self, *_a) -> None:  # pragma: no cover
        self.close()


# ---------------------------------------------------------------------------


def subject_hash12_for_x25519(x25519_pubkey: bytes) -> str:
    """Derive the hash12 used in prekey record names from an X25519 pubkey.

    Matches DMPClient._hash12 (sha256 prefix, 12 hex chars). Placed
    here so the server package doesn't have to import the client
    module just to check a token's prekey scope.
    """
    return hashlib.sha256(x25519_pubkey).hexdigest()[:12]
