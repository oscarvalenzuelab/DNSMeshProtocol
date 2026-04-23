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
import secrets
import sqlite3
import threading
import time
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


# Record-name patterns. Kept narrow on purpose — anything the
# classifier doesn't explicitly recognize falls to OPERATOR_ONLY,
# so forgetting to extend this table fails closed, not open.
#
# Identity: dmp.<user>.<domain>
#   We accept both zone-anchored (single label 'dmp' prefix) and
#   any deeper qualifier the CLI might choose to use; the rule is
#   "starts with dmp." and isn't one of the other reserved
#   prefixes.
#
# Rotation: rotate.dmp.<user>.<domain> or rotate.dmp.id-<hash12>.<domain>
#
# Prekeys: pk-<id>.<hash12>.<domain>  (hash12 == first 12 hex of
#   sha256(x25519_pubkey))
#
# Mailbox: slot-<N>.mb-<hash12>.<domain>
#
# Chunks: chunk-<NNNN>-<msgkey12>.<domain>


def classify_name(name: str) -> ScopeClass:
    """Classify a record name for auth scope enforcement.

    Parse-only: this does NOT hit the database. The returned
    :class:`ScopeClass` is then handed to
    :meth:`TokenStore.authorize_write` along with the caller's
    token to make the auth decision.
    """
    if not name:
        return ScopeClass(ScopeClass.UNKNOWN, reason="empty name")

    # Strip trailing dot; lowercase for consistent matching. DNS
    # names are case-insensitive.
    n = name.rstrip(".").lower()

    parts = n.split(".")
    if len(parts) < 2:
        return ScopeClass(ScopeClass.UNKNOWN, reason="too few labels")

    first = parts[0]

    # Rotation is a two-label prefix: rotate.dmp.<rest>
    if first == "rotate":
        if len(parts) < 3 or parts[1] != "dmp":
            return ScopeClass(
                ScopeClass.UNKNOWN, reason="rotate.* without dmp label"
            )
        # Subject = everything after 'rotate.dmp.' — either
        # '<user>.<domain>' (zone-anchored) or 'id-<hash12>.<domain>'
        # (hash form). The hash form cannot be mapped to a specific
        # subject string without a lookup; we treat it as owner-
        # exclusive with subject=None and let authorize_write
        # reject unless the token explicitly covers it. M5.5 v1
        # rejects hash-form rotation publishes from end-user tokens
        # to keep the auth model simple; operators can still publish
        # them via DMP_OPERATOR_TOKEN.
        rest = parts[2:]
        if rest and rest[0].startswith("id-"):
            return ScopeClass(
                ScopeClass.OPERATOR_ONLY,
                reason="hash-form rotation not issuable to end-user tokens in v1",
            )
        if len(rest) < 2:
            return ScopeClass(ScopeClass.UNKNOWN, reason="rotate.dmp.<user>.<domain> missing")
        user = rest[0]
        domain = ".".join(rest[1:])
        return ScopeClass(
            ScopeClass.OWNER_EXCLUSIVE, subject=f"{user}@{domain}",
        )

    if first == "dmp":
        # Identity record: dmp.<user>.<domain>
        if len(parts) < 3:
            return ScopeClass(ScopeClass.UNKNOWN, reason="dmp.* missing user/domain")
        user = parts[1]
        domain = ".".join(parts[2:])
        return ScopeClass(
            ScopeClass.OWNER_EXCLUSIVE, subject=f"{user}@{domain}",
        )

    if first.startswith("pk-"):
        # Prekey: pk-<id>.<hash12>.<domain>. We can't map hash12 back
        # to a subject without a DB lookup, but we CAN require that
        # the token presents itself as the owner by including a
        # subject-derived hash12 on the token (added in the store
        # at issuance). The caller passes the expected hash12 in;
        # classify_name only extracts the name's hash12.
        if len(parts) < 3:
            return ScopeClass(ScopeClass.UNKNOWN, reason="pk-* missing hash12/domain")
        hash12 = parts[1]
        # Flag as owner-exclusive with the HASH in subject; the
        # TokenStore checks subject-hash equality.
        return ScopeClass(
            ScopeClass.OWNER_EXCLUSIVE, subject=f"#{hash12}",
            reason="prekey hash-scoped",
        )

    if first.startswith("slot-"):
        return ScopeClass(ScopeClass.SHARED_POOL, reason="mailbox slot")
    if first.startswith("chunk-"):
        return ScopeClass(ScopeClass.SHARED_POOL, reason="message chunk")

    # cluster.<base> / bootstrap.<zone> / anything else reserved
    return ScopeClass(ScopeClass.OPERATOR_ONLY, reason=f"reserved prefix: {first}")


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

    - ``ok``: True iff the request is authorized.
    - ``row``: the live TokenRow that authorized it (or None).
    - ``scope``: the ScopeClass classification that applied.
    - ``reason``: human-readable rejection reason when ``ok`` is False.
    - ``is_shared_pool``: convenience for the caller to decide whether
      to log the subject in audit.
    """

    __slots__ = ("ok", "row", "scope", "reason")

    def __init__(
        self,
        ok: bool,
        *,
        row: Optional[TokenRow] = None,
        scope: Optional[ScopeClass] = None,
        reason: str = "",
    ):
        self.ok = ok
        self.row = row
        self.scope = scope
        self.reason = reason

    @property
    def is_shared_pool(self) -> bool:
        return self.scope is not None and self.scope.kind == ScopeClass.SHARED_POOL

    def __bool__(self) -> bool:  # pragma: no cover — convenience
        return self.ok


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
    note           TEXT NOT NULL DEFAULT ''
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
        self._conn.commit()

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
    ) -> Tuple[str, TokenRow]:
        """Mint a new token for ``subject``. Returns ``(token, row)``.

        The token string is returned ONLY here — it cannot be fetched
        back later (we never persist it). Caller shows it to the user
        and lets them persist client-side.

        Does NOT atomically revoke a pre-existing live token for the
        same subject; callers who want "one live token per subject"
        semantics should revoke first. The self-service registration
        flow enforces this via its challenge-verify step.
        """
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
        )

        with self._lock:
            self._conn.execute(
                """INSERT INTO tokens(token_hash, subject, subject_type,
                   subject_hash12, rate_per_sec, rate_burst, issued_at,
                   expires_at, revoked_at, issuer, note)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    row.token_hash, row.subject, row.subject_type,
                    row.subject_hash12, row.rate_per_sec, row.rate_burst,
                    row.issued_at, row.expires_at, None,
                    row.issuer, row.note,
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
                    "SELECT subject FROM tokens WHERE token_hash=?", (token_hash,),
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
            return updated

    def revoke_by_subject(self, subject: str, *, remote_addr: str = "") -> int:
        """Revoke every live token for ``subject``. Returns the count revoked."""
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

    def _row_by_hash(self, token_hash: str) -> Optional[TokenRow]:
        r = self._conn.execute(
            """SELECT token_hash, subject, subject_type, subject_hash12,
                      rate_per_sec, rate_burst, issued_at, expires_at,
                      revoked_at, issuer, note
               FROM tokens WHERE token_hash=?""",
            (token_hash,),
        ).fetchone()
        return None if r is None else TokenRow(*r)

    def list(
        self, *, include_revoked: bool = False, subject: Optional[str] = None
    ) -> List[TokenRow]:
        sql = """SELECT token_hash, subject, subject_type, subject_hash12,
                        rate_per_sec, rate_burst, issued_at, expires_at,
                        revoked_at, issuer, note FROM tokens"""
        clauses = []
        args: List = []
        if not include_revoked:
            clauses.append("revoked_at IS NULL")
        if subject:
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
                    "rejected", remote_addr=remote_addr,
                    detail="no such token",
                )
                self._conn.commit()
                return AuthResult(False, scope=scope, reason="unknown token")
            if not row.is_live():
                self._audit(
                    "rejected", remote_addr=remote_addr,
                    detail="token expired or revoked",
                )
                self._conn.commit()
                return AuthResult(
                    False, row=row, scope=scope,
                    reason="token revoked or expired",
                )

            if scope.kind == ScopeClass.OPERATOR_ONLY:
                self._audit(
                    "rejected", remote_addr=remote_addr,
                    detail=f"operator-only scope: {scope.reason}",
                )
                self._conn.commit()
                return AuthResult(
                    False, row=row, scope=scope,
                    reason="operator-only record namespace",
                )
            if scope.kind == ScopeClass.UNKNOWN:
                self._audit(
                    "rejected", remote_addr=remote_addr,
                    detail=f"unknown scope: {scope.reason}",
                )
                self._conn.commit()
                return AuthResult(
                    False, row=row, scope=scope,
                    reason="unclassified record name",
                )

            if scope.kind == ScopeClass.OWNER_EXCLUSIVE:
                expected = scope.subject or ""
                if expected.startswith("#"):
                    # Hash-form check (prekey namespace).
                    if not row.subject_hash12 or row.subject_hash12 != expected[1:]:
                        self._audit(
                            "rejected",
                            token_hash=token_hash, subject=row.subject,
                            remote_addr=remote_addr,
                            detail=f"subject_hash12 mismatch: want {expected}",
                        )
                        self._conn.commit()
                        return AuthResult(
                            False, row=row, scope=scope,
                            reason="subject hash does not match record namespace",
                        )
                else:
                    if row.subject.lower() != expected.lower():
                        self._audit(
                            "rejected",
                            token_hash=token_hash, subject=row.subject,
                            remote_addr=remote_addr,
                            detail=f"subject mismatch: want {expected}",
                        )
                        self._conn.commit()
                        return AuthResult(
                            False, row=row, scope=scope,
                            reason="subject does not match record owner",
                        )

                if log_use:
                    self._audit(
                        "used",
                        token_hash=token_hash, subject=row.subject,
                        remote_addr=remote_addr,
                        detail="owner-exclusive",
                    )
                    self._conn.commit()
                return AuthResult(True, row=row, scope=scope)

            # Shared pool: any live token is fine. Deliberately do
            # NOT populate token_hash / subject on the audit row —
            # that's the split-audit policy.
            if log_use:
                self._audit(
                    "used", remote_addr=remote_addr, detail="shared-pool",
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
