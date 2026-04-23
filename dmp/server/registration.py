"""Self-service token registration (M5.5 phase 3).

HTTP flow:

    GET  /v1/registration/challenge       -> { challenge, node, expires_at }
    POST /v1/registration/confirm         -> { token, subject, expires_at, ... }

The challenge is a 32-byte random nonce, single-use, expiring in 60s.
The confirm endpoint verifies an Ed25519 signature over
``challenge || subject || node || version`` and mints a token bound
to the presented subject + spk on success.

Abuse controls:

- Per-IP rate limit on ``/confirm`` (default 5 / hour).
- Optional operator allowlist of subject domains.
- Anti-takeover: if a live token already exists for the subject,
  the new registration must be signed by the spk registered with
  that prior token — an attacker who guesses a subject can't claim
  it while the rightful holder still has a token.

All of this is behind ``auth_mode == "multi-tenant"`` and
``DMP_REGISTRATION_ENABLED=1``. Default is OFF because a
misconfigured open-registration node is an attractive spam target.
"""

from __future__ import annotations

import binascii
import os
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from dmp.server.tokens import (
    DEFAULT_RATE_BURST,
    DEFAULT_RATE_PER_SEC,
    SUBJECT_TYPE_USER_IDENTITY,
    TokenStore,
    _SubjectLocked,
    canonicalize_subject,
)

# Ed25519 low-order / small-subgroup public key encodings. Holding any
# of these as A lets an attacker forge a signature that the permissive
# RFC-8032 verify accepts — critically, the identity point (01 00..00)
# with sig = A||0 verifies on every message. Block set mirrors the one
# in https://pkg.go.dev/c2sp.org/CCTV/ed25519 (canonical eight plus the
# six non-canonical aliases cryptography still accepts as valid
# encodings). Anyone who legitimately derives one of these from a
# passphrase has done so by astronomically unlikely accident; we are
# not losing real users by blocking them.
_LOW_ORDER_ED25519_PUBKEYS = frozenset(
    bytes.fromhex(h)
    for h in (
        # Canonical encodings (order 1, 2, 4, 8 points, each sign).
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        # Non-canonical aliases that cryptography/OpenSSL still parses.
        "0100000000000000000000000000000000000000000000000000000000000080",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    )
)

# Version byte embedded in the signed message. Bump if we change the
# signing-payload layout so old and new signatures can't collide.
_PROTOCOL_VERSION = b"\x01"

# Challenge lifetime. Short enough that a leaked challenge is useless
# fast; long enough that a normal round-trip fits.
CHALLENGE_TTL_SECONDS = 60

# Default token lifetime issued via self-service. 90 days — rotate or
# re-register before expiry. Admins who want a different default can
# mint via dmp-node-admin which accepts --expires.
DEFAULT_SELF_SERVICE_EXPIRY_SECONDS = 90 * 86400


class RegistrationError(Exception):
    """Base class for registration failures that map to HTTP errors.

    ``http_status`` is the code the handler should return; ``reason``
    is the body message (already safe to echo — includes no secrets).
    """

    http_status: int = 400

    def __init__(self, reason: str, *, http_status: int = 400):
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status


class ChallengeExpired(RegistrationError):
    def __init__(self, reason: str = "challenge expired or unknown"):
        super().__init__(reason, http_status=400)


class SignatureInvalid(RegistrationError):
    def __init__(self, reason: str = "signature verification failed"):
        super().__init__(reason, http_status=401)


class SubjectNotAllowed(RegistrationError):
    def __init__(self, reason: str = "subject not in registration allowlist"):
        super().__init__(reason, http_status=403)


class SubjectAlreadyOwned(RegistrationError):
    def __init__(
        self,
        reason: str = (
            "subject already has a live token; re-registration must be signed "
            "with the previously-registered Ed25519 key"
        ),
    ):
        super().__init__(reason, http_status=409)


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PendingChallenge:
    challenge_hex: str
    node: str
    expires_at: int


class ChallengeStore:
    """In-memory store of pending challenges.

    Not persisted: challenges are ephemeral (60s TTL) and a restart-
    induced invalidation is fine — clients retry transparently. Saves
    us from putting a second sqlite table in the hot path.

    Thread-safe. Opportunistic cleanup on each access so a malicious
    actor can't fill memory by spamming challenge requests (also
    bounded by ``max_pending``).
    """

    __slots__ = ("_lock", "_pending", "_max_pending")

    def __init__(self, max_pending: int = 10_000) -> None:
        self._lock = threading.Lock()
        self._pending: dict = {}  # challenge_hex -> PendingChallenge
        self._max_pending = max_pending

    def issue(self, node: str, now: Optional[int] = None) -> PendingChallenge:
        now = now if now is not None else int(time.time())
        challenge_hex = secrets.token_bytes(32).hex()
        pc = PendingChallenge(
            challenge_hex=challenge_hex,
            node=node,
            expires_at=now + CHALLENGE_TTL_SECONDS,
        )
        with self._lock:
            self._pending[challenge_hex] = pc
            self._cleanup_locked(now)
        return pc

    def consume(
        self, challenge_hex: str, now: Optional[int] = None
    ) -> PendingChallenge:
        """Pop the challenge; raise :class:`ChallengeExpired` if missing/expired.

        Single-use: a successful consume removes the challenge so
        a replay of the same confirm fails.
        """
        now = now if now is not None else int(time.time())
        with self._lock:
            pc = self._pending.pop(challenge_hex, None)
            self._cleanup_locked(now)
        if pc is None or pc.expires_at <= now:
            raise ChallengeExpired()
        return pc

    def _cleanup_locked(self, now: int) -> None:
        # Drop expired entries first.
        for k, pc in list(self._pending.items()):
            if pc.expires_at <= now:
                self._pending.pop(k, None)
        # Then enforce the ceiling. Oldest-issued first.
        if len(self._pending) > self._max_pending:
            ordered = sorted(self._pending.items(), key=lambda kv: kv[1].expires_at)
            drop = len(ordered) - self._max_pending
            for k, _ in ordered[:drop]:
                self._pending.pop(k, None)

    def size(self) -> int:
        with self._lock:
            return len(self._pending)


# ---------------------------------------------------------------------------


def _parse_hex(value: str, expected_bytes: int, field: str) -> bytes:
    try:
        raw = binascii.unhexlify(value)
    except binascii.Error as exc:
        raise RegistrationError(
            f"{field}: not valid hex",
            http_status=400,
        ) from exc
    if len(raw) != expected_bytes:
        raise RegistrationError(
            f"{field}: expected {expected_bytes} bytes, got {len(raw)}",
            http_status=400,
        )
    return raw


def _build_signing_payload(
    challenge_hex: str,
    subject: str,
    node: str,
) -> bytes:
    """Return the bytes the client must sign on /confirm.

    Format: ``challenge || subject || node || version_byte`` where all
    string components are UTF-8 encoded. Kept deliberately flat —
    length-prefix or ASN.1 framing would be more robust but adds
    wire complexity, and the components can't collide here because
    ``challenge`` is fixed 32 bytes (64 hex chars) and we reject
    non-ASCII subjects before reaching this point.
    """
    return (
        bytes.fromhex(challenge_hex)
        + subject.encode("utf-8")
        + node.encode("utf-8")
        + _PROTOCOL_VERSION
    )


def _domain_allowed(subject: str, allowlist: Iterable[str]) -> bool:
    """Return True if ``subject``'s domain is allowed.

    Empty allowlist means "no restriction". Comparison is case-
    insensitive on the domain (subject is already canonical
    lowercase).
    """
    allow = {a.strip().lower().rstrip(".") for a in allowlist if a.strip()}
    if not allow:
        return True
    try:
        _, domain = subject.rsplit("@", 1)
    except ValueError:
        return False
    return domain in allow


# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegistrationConfig:
    enabled: bool = False
    node_hostname: str = ""
    allowlist: Tuple[str, ...] = ()
    # Lifetime of tokens MINTED via self-service. Admin-issued tokens
    # get their own --expires CLI flag and ignore this.
    expires_in_seconds: int = DEFAULT_SELF_SERVICE_EXPIRY_SECONDS
    # Rate limit STAMPED ONTO each minted token (per-token bucket used
    # at /v1/records/* time).
    issued_rate_per_sec: float = DEFAULT_RATE_PER_SEC
    issued_rate_burst: int = DEFAULT_RATE_BURST
    # Per-IP rate limit enforced on /v1/registration/* itself.
    # Deliberately tight (5 / hour by default) so a would-be subject-
    # squatter can't churn through subjects at line rate.
    endpoint_rate_per_sec: float = 5.0 / 3600.0
    endpoint_rate_burst: float = 5.0

    @classmethod
    def from_env(cls) -> "RegistrationConfig":
        enabled = os.environ.get("DMP_REGISTRATION_ENABLED", "").strip() in (
            "1",
            "true",
            "yes",
            "on",
        )
        hostname = os.environ.get("DMP_NODE_HOSTNAME", "").strip()
        allow_raw = os.environ.get("DMP_REGISTRATION_ALLOWLIST", "")
        allowlist = tuple(
            a.strip().lower().rstrip(".") for a in allow_raw.split(",") if a.strip()
        )
        expiry = int(
            os.environ.get(
                "DMP_REGISTRATION_TOKEN_TTL_SECONDS",
                DEFAULT_SELF_SERVICE_EXPIRY_SECONDS,
            )
        )
        issued_rate = float(
            os.environ.get(
                "DMP_REGISTRATION_ISSUED_RATE_PER_SEC",
                DEFAULT_RATE_PER_SEC,
            )
        )
        issued_burst = int(
            os.environ.get(
                "DMP_REGISTRATION_ISSUED_RATE_BURST",
                DEFAULT_RATE_BURST,
            )
        )
        endpoint_rate = float(
            os.environ.get(
                "DMP_REGISTRATION_ENDPOINT_RATE_PER_SEC",
                5.0 / 3600.0,
            )
        )
        endpoint_burst = float(
            os.environ.get("DMP_REGISTRATION_ENDPOINT_RATE_BURST", 5.0)
        )
        return cls(
            enabled=enabled,
            node_hostname=hostname,
            allowlist=allowlist,
            expires_in_seconds=expiry,
            issued_rate_per_sec=issued_rate,
            issued_rate_burst=issued_burst,
            endpoint_rate_per_sec=endpoint_rate,
            endpoint_rate_burst=endpoint_burst,
        )


# ---------------------------------------------------------------------------


def confirm_registration(
    *,
    store: TokenStore,
    challenges: ChallengeStore,
    config: RegistrationConfig,
    body: dict,
    remote_addr: str = "",
    now: Optional[int] = None,
) -> Tuple[str, object]:
    """Verify a confirm request end-to-end. Returns ``(token, row)``.

    Raises a subclass of :class:`RegistrationError` on any failure.

    Order of checks (matters for the "no subject-existence oracle"
    property):

      1. Feature-gate + config sanity (404 / 500).
      2. Parse + canonicalize inputs (400).
      3. Consume challenge (400 if expired/unknown — single-use).
      4. VERIFY SIGNATURE (401). An attacker without the private key
         never reaches steps 5-7, so allowlist-membership and
         subject-ownership state are NOT observable via HTTP status
         codes by unsigned requests.
      5. Allowlist check (403) — only visible to signed requests.
      6. Anti-takeover + mint (atomic, single TokenStore method;
         returns 409 if another key already owns the subject).

    The challenge is consumed at step 3 regardless of whether steps
    4-6 succeed. That's deliberate: a signed request that proves key
    control still consumes one nonce, preventing a signer from
    trivially spamming the rest of the pipeline.
    """
    if not config.enabled:
        raise RegistrationError(
            "self-service registration is disabled on this node",
            http_status=404,
        )
    if not config.node_hostname:
        raise RegistrationError(
            "node misconfigured: DMP_NODE_HOSTNAME is required for registration",
            http_status=500,
        )

    subject_raw = body.get("subject")
    spk_hex = body.get("ed25519_spk")
    challenge_hex = body.get("challenge")
    signature_hex = body.get("signature")

    for name, value in (
        ("subject", subject_raw),
        ("ed25519_spk", spk_hex),
        ("challenge", challenge_hex),
        ("signature", signature_hex),
    ):
        if not isinstance(value, str) or not value:
            raise RegistrationError(f"missing or non-string field: {name}")

    # Canonicalize subject (ASCII, lowercase, shape). Fail-closed.
    try:
        subject = canonicalize_subject(subject_raw)
    except ValueError as exc:
        raise RegistrationError(f"subject invalid: {exc}") from exc

    # Parse cryptographic inputs.
    spk_bytes = _parse_hex(spk_hex, 32, "ed25519_spk")
    sig_bytes = _parse_hex(signature_hex, 64, "signature")
    # Challenge is a 32-byte nonce; verify shape before any DB ops.
    _parse_hex(challenge_hex, 32, "challenge")

    # Reject Ed25519 low-order / small-subgroup public keys. With
    # the identity point (01 00..00) as A and sig = identity || 00*32,
    # Ed25519 verification succeeds on EVERY message — a complete
    # signature-forgery bypass that lets an attacker reach the
    # anti-takeover / allowlist policy layer without holding any
    # private key. Other small-order points (orders 2 / 4 / 8) allow
    # forgery on subsets of messages, which is still grindable.
    # cryptography's Ed25519PublicKey.from_public_bytes does NOT
    # reject these — the cryptography lib's default verify is the
    # permissive (non-cofactored) algorithm per RFC 8032.
    #
    # The block set is the canonical + non-canonical low-order
    # encodings. References: RFC 8032,
    # https://pkg.go.dev/c2sp.org/CCTV/ed25519.
    if spk_bytes in _LOW_ORDER_ED25519_PUBKEYS:
        raise SignatureInvalid("low-order public key rejected")

    # Single-use challenge. Raises ChallengeExpired on miss/expired.
    pc = challenges.consume(challenge_hex, now=now)

    # Signature FIRST — this is the gate that decides whether an
    # unauthenticated attacker gets to see any other policy
    # feedback. Codex review called out that checking allowlist /
    # anti-takeover before the signature turned /confirm into an
    # oracle for "does subject X exist" and "is domain Y
    # allowlisted". After reordering, an attacker without the
    # private key sees only 401 (or 400 on parse failures) and
    # cannot distinguish 403 / 409.
    payload = _build_signing_payload(challenge_hex, subject, pc.node)
    try:
        Ed25519PublicKey.from_public_bytes(spk_bytes).verify(sig_bytes, payload)
    except InvalidSignature as exc:
        raise SignatureInvalid() from exc

    # The signer proved key control. Now apply policy.
    if not _domain_allowed(subject, config.allowlist):
        raise SubjectNotAllowed()

    # Atomic revoke-old-self-service + issue-new. The method holds the
    # DB lock for the duration so two concurrent valid confirms for
    # the same subject cannot both mint — codex review found a race
    # here in the previous implementation where revoke() and issue()
    # took separate locks.
    try:
        token, row, _ = store.rotate_self_service(
            subject,
            registered_spk=spk_hex.lower(),
            expires_in_seconds=config.expires_in_seconds,
            rate_per_sec=config.issued_rate_per_sec,
            rate_burst=config.issued_rate_burst,
            remote_addr=remote_addr,
        )
    except _SubjectLocked as exc:
        raise SubjectAlreadyOwned() from exc

    return token, row
