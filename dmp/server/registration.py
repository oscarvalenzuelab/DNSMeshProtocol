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

# Low-order Ed25519 block list — shared source of truth at
# dmp.core.ed25519_points so registration, heartbeat, and any future
# signed-record consumer all stay in sync.
from dmp.core.ed25519_points import (
    LOW_ORDER_ED25519_PUBKEYS as _LOW_ORDER_ED25519_PUBKEYS,
)  # noqa: E402,F401

# Version byte embedded in the signed message. Bump if we change the
# signing-payload layout so old and new signatures can't collide.
_PROTOCOL_VERSION = b"\x01"

# Challenge lifetime. Short enough that a leaked challenge is useless
# fast; long enough that a normal round-trip fits.
CHALLENGE_TTL_SECONDS = 60

# Default token lifetime issued via self-service. 90 days — rotate or
# re-register before expiry. Admins who want a different default can
# mint via dnsmesh-node-admin which accepts --expires.
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
    # M9.2.3 — DNS zone the node is authoritative for. Distinct from
    # ``node_hostname`` because the node's HTTP hostname may sit BENEATH
    # the served zone (e.g. ``api.example.com`` serving records in
    # ``example.com``). Minted TSIG keys are scoped to subtrees of this
    # zone, not the hostname. Empty falls back to ``node_hostname`` for
    # back-compat with single-host deployments where the two match.
    served_zone: str = ""
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
        # ``DMP_SERVED_ZONE`` overrides; otherwise fall back through the
        # zone-discovery chain (cluster base, DMP_DOMAIN), and finally
        # to ``node_hostname`` so the existing single-host setups keep
        # working without touching their env.
        served = (
            os.environ.get("DMP_SERVED_ZONE", "").strip()
            or os.environ.get("DMP_CLAIM_PROVIDER_ZONE", "").strip()
            or os.environ.get("DMP_CLUSTER_BASE_DOMAIN", "").strip()
            or os.environ.get("DMP_DOMAIN", "").strip()
            or hostname
        )
        served = served.lower().rstrip(".")
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
            served_zone=served,
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


# ---------------------------------------------------------------------------
# M9.2.3 — TSIG-key minting via the same Ed25519 challenge/confirm protocol.
#
# The DMP-on-DNS write path (DNS UPDATE / RFC 2136) needs symmetric TSIG keys
# instead of bearer tokens. ``mint_tsig_via_registration`` reuses the
# challenge ceremony from ``confirm_registration`` — same crypto, same anti-
# squat policy — but the deliverable is a TSIG key the user installs in
# their CLI config and uses to sign ``DNS UPDATE`` to the operator's zone.
#
# This is the operator-side counterpart of M9.2.4's ``_DnsUpdateWriter``.
# The user→own-node hop here is HTTPS (the one HTTPS exchange the user
# explicitly authorizes); every later cross-node step is DNS UPDATE under
# the minted key.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MintedTSIGKey:
    """The deliverable of a successful TSIG registration.

    The HTTP layer ships these fields back to the client; the client's
    CLI persists them as the TSIG-key block in its config.
    """

    name: str  # dnspython key name, with trailing dot
    secret_hex: str  # raw secret bytes, hex-encoded
    algorithm: str
    allowed_suffixes: Tuple[str, ...]
    subject: str  # canonical "user@host"
    zone: str  # zone the suffixes are anchored under
    expires_at: int  # 0 = no expiry


def _spk_short(spk_hex: str, *, length: int = 8) -> str:
    """First N chars of the spk hex — fits into a DNS label and gives
    the key name a human-recognizable handle."""
    return (spk_hex or "").lower()[:length]


# DNS labels are capped at 63 octets (RFC 1035). The TSIG key name's
# first label is ``<local_part>-<spk8>``; we have to validate the
# composite so a 60-character username doesn't mint a key whose
# Name parsing fails downstream and whose UPDATEs silently fail.
_MAX_DNS_LABEL = 63
_KEY_NAME_LABEL_OVERHEAD = 1 + 8  # `-<spk8>`


def _suffixes_for(
    subject: str,
    local_part: str,
    spk_hex: str,
    zone: str,
    *,
    x25519_pub_hex: str = "",
) -> Tuple[str, ...]:
    """Compute the per-user suffix scope for the minted TSIG key.

    Codex round-6 P1: the scope must match the actual owner names
    DMP records use. Concretely:

      - identity / prekeys: ``id-<sha256(subject)[:16]>.<zone>``
        and ``prekeys.id-<hash16>.<zone>`` (the suffix
        ``id-<hash16>.<zone>`` covers both via tail match).
      - mailbox slots / claims: ``slot-N.mb-<hash12>.<zone>`` and
        ``claim-N.mb-<hash12>.<zone>`` — both end with
        ``.mb-<hash12>.<zone>``. The hash is sha256 of the user's
        X25519 public key, which the registration body MAY supply
        as ``x25519_pub``. Without it, mailbox writes won't
        authorize and the user is limited to identity / prekey /
        legacy claim publication.
      - legacy claim records: ``_dnsmesh-claim-<spk16>.<zone>``
        — kept for the pre-M9 claim publishing path.

    Returns the tuple of allowed suffixes, all canonicalized
    lowercase with no trailing dot.
    """
    import hashlib

    z = (zone or "").strip().lower().rstrip(".")
    subj = (subject or "").strip().lower()
    spk16 = _spk_short(spk_hex, length=16)
    if not z or not subj or not spk16:
        return ()
    # Three scope modes:
    #
    #   - DEFAULT (single-user-per-zone — M9's design target). Per-user
    #     identity hashes + the user's spk-prefixed claim record PLUS
    #     wildcard owner patterns (``slot-*.mb-*.<zone>``,
    #     ``chunk-*-*.<zone>``, ``_dnsmesh-claim-*.<zone>``) so
    #     ``send_message`` works DNS-only out of the box. Each user
    #     runs their own node and their served zone is their personal
    #     zone — the wildcards don't grant authority over other users
    #     because no other users live on this zone.
    #
    #   - DMP_TSIG_TIGHT_SCOPE=1 (multi-tenant — shared zone). Drops
    #     the wildcards. Multiple users share one zone (e.g. mail.
    #     example.com hosts alice@…  + bob@…); the operator opts into
    #     this mode so Alice can't overwrite Bob's slot- / chunk-
    #     records. ``send_message`` UPDATEs WILL be REFUSED in this
    #     mode — message sends across multi-tenant zones is a known
    #     limitation tracked for a future release that anchors
    #     per-sender prefixes in the record naming itself.
    #
    #   - DMP_TSIG_LOOSE_SCOPE=1 (solo / dev). Whole zone. The
    #     escape hatch — single-user node where the operator wants
    #     no scope-checking at all.
    if os.environ.get("DMP_TSIG_LOOSE_SCOPE", "0").strip().lower() in (
        "1", "true", "yes", "on",
    ):
        return (z,)

    tight_scope = os.environ.get(
        "DMP_TSIG_TIGHT_SCOPE", "0"
    ).strip().lower() in ("1", "true", "yes", "on")
    suffixes = []
    # Identity + prekey owner hashes are derived from
    # ``cfg.username`` (the LOCAL PART of subject), not the full
    # subject. ``dmp.core.identity`` and ``dmp.core.prekeys`` both
    # hash that. Using the full subject here would mint a key that
    # doesn't authorize the names ``identity publish`` actually
    # writes — codex round-17 P1.1.
    local_norm = (local_part or "").strip().lower()
    username_hash16 = hashlib.sha256(local_norm.encode("utf-8")).hexdigest()[:16]
    suffixes.append(f"id-{username_hash16}.{z}")
    username_hash12 = hashlib.sha256(local_norm.encode("utf-8")).hexdigest()[:12]
    suffixes.append(f"id-{username_hash12}.{z}")
    # User's own claim-record prefix (always granted — addresses the
    # user's own spk).
    suffixes.append(f"_dnsmesh-claim-{spk16}.{z}")

    # Single-user-per-zone wildcards: granted by default, dropped
    # ONLY when the operator declares this is a multi-tenant shared
    # zone (DMP_TSIG_TIGHT_SCOPE=1). On shared zones, these
    # suffixes would authorize ANY user's mailbox / chunk / claim
    # writes — the per-sender record-name anchoring needed to fix
    # that is tracked as future work.
    if not tight_scope:
        suffixes.append(f"_dnsmesh-claim-*.{z}")
        suffixes.append(f"slot-*.mb-*.{z}")
        suffixes.append(f"chunk-*-*.{z}")
        # M9.2.6 same-zone claim path: when the user IS their own
        # provider (single-node deployment), publish_claim writes
        # ``claim-N.mb-<hash12>.<zone>`` through ``self.writer``,
        # which after ``dnsmesh tsig register`` is the DNS UPDATE
        # writer. Without this suffix that publish would be
        # REFUSED. Codex round-20 P2.
        suffixes.append(f"claim-*.mb-*.{z}")
    x_norm = (x25519_pub_hex or "").strip().lower()
    if x_norm:
        try:
            x_bytes = bytes.fromhex(x_norm)
        except ValueError:
            x_bytes = b""
        if len(x_bytes) == 32:
            mailbox_hash = hashlib.sha256(x_bytes).hexdigest()[:12]
            suffixes.append(f"mb-{mailbox_hash}.{z}")
    return tuple(suffixes)


def _key_name_for(
    local_part: str, spk_hex: str, zone: str, *, subject: str = ""
) -> Optional[str]:
    """Stable per-user TSIG key name.

    Codex round-13 P2: two subjects with the same local part on
    different domains (``alice@foo.example`` vs
    ``alice@bar.example``) used to collide into the same key name
    when re-using a signing key, and ``mint_for_subject``'s upsert
    silently overwrote one with the other. Including a hash of the
    canonical subject (``user@host``) in the label disambiguates
    them. The spk prefix is kept for human readability.

    Returns None when the resulting first label would exceed the
    63-octet DNS label limit (codex round-6 P2).
    """
    import hashlib as _hashlib

    z = (zone or "").strip().lower().rstrip(".")
    lp = (local_part or "").strip().lower()
    if not z or not lp:
        return None
    spk8 = _spk_short(spk_hex)
    # Subject hash: 6 hex chars of sha256(subject) — enough to make
    # the key name unique across (local_part, host) pairs without
    # exploding the label length. Falls back to an empty string for
    # legacy callers that didn't pass a subject (admin tooling).
    subj_norm = (subject or "").strip().lower()
    subj_tag = ""
    if subj_norm:
        subj_tag = _hashlib.sha256(subj_norm.encode("utf-8")).hexdigest()[:6]
    label = f"{lp}-{spk8}" + (f"-{subj_tag}" if subj_tag else "")
    if len(label) > _MAX_DNS_LABEL:
        return None
    return f"{label}.{z}."


def mint_tsig_via_registration(
    *,
    keystore,
    challenges: ChallengeStore,
    config: RegistrationConfig,
    body: dict,
    remote_addr: str = "",
    now: Optional[int] = None,
) -> MintedTSIGKey:
    """Same Ed25519 challenge/confirm flow as ``confirm_registration``,
    but the deliverable is a TSIG key persisted in ``keystore`` and
    returned to the caller.

    Order of checks mirrors ``confirm_registration`` so an attacker
    without the private key sees the same 400/401/403/404 surface and
    cannot distinguish the token-mint and tsig-mint endpoints by
    behavior.

    Required body fields (same names as ``/v1/registration/confirm``
    so the client side can reuse the existing challenge plumbing):

      - ``subject`` — canonical ``user@host``.
      - ``ed25519_spk`` — 32-byte hex public key.
      - ``challenge`` — 32-byte hex nonce from ``GET .../challenge``.
      - ``signature`` — 64-byte hex signature over the same payload
        the token-mint flow signs. The DMP CLI signs once and can
        try whichever endpoint succeeds first.
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

    try:
        subject = canonicalize_subject(subject_raw)
    except ValueError as exc:
        raise RegistrationError(f"subject invalid: {exc}") from exc

    spk_bytes = _parse_hex(spk_hex, 32, "ed25519_spk")
    sig_bytes = _parse_hex(signature_hex, 64, "signature")
    _parse_hex(challenge_hex, 32, "challenge")

    if spk_bytes in _LOW_ORDER_ED25519_PUBKEYS:
        raise SignatureInvalid("low-order public key rejected")

    pc = challenges.consume(challenge_hex, now=now)

    payload = _build_signing_payload(challenge_hex, subject, pc.node)
    try:
        Ed25519PublicKey.from_public_bytes(spk_bytes).verify(sig_bytes, payload)
    except InvalidSignature as exc:
        raise SignatureInvalid() from exc

    if not _domain_allowed(subject, config.allowlist):
        raise SubjectNotAllowed()

    # Subject has already passed canonicalize_subject, which guarantees
    # exactly one '@'. The user's records live under the zone the node
    # is authoritative for — NOT under the node's hostname, which can be
    # a subdomain. (Codex P1: deriving from node_hostname produced
    # scopes like ``alice.api.example.com`` that the DNS server then
    # rejected because every normal write targets ``alice.example.com``.)
    try:
        local_part, _ = subject.rsplit("@", 1)
    except ValueError as exc:
        raise RegistrationError("subject missing local part") from exc

    zone = (config.served_zone or config.node_hostname).strip().lower().rstrip(".")
    # ``x25519_pub`` is optional — when supplied, the scope can include
    # the user's mailbox subtree ``mb-<sha256(x25519_pub)[:12]>.<zone>``.
    # Without it, the minted key works for identity + prekey + legacy
    # claim publishing but mailbox writes will be rejected by the DNS
    # server. Documented limitation; CLI passes the pubkey by default.
    x_pub_raw = body.get("x25519_pub")
    x_pub_hex = x_pub_raw.strip().lower() if isinstance(x_pub_raw, str) else ""
    suffixes = _suffixes_for(
        subject, local_part, spk_hex, zone, x25519_pub_hex=x_pub_hex
    )
    if not suffixes:
        raise RegistrationError(
            "could not derive TSIG scope from subject + zone",
            http_status=500,
        )
    key_name = _key_name_for(local_part, spk_hex, zone, subject=subject)
    if key_name is None:
        # Local part too long for a single DNS label after the
        # ``-<spk8>`` suffix — refuse rather than mint a key whose
        # Name parsing later fails silently in build_keyring.
        raise RegistrationError(
            "subject local part too long for TSIG key label "
            f"(max {_MAX_DNS_LABEL - _KEY_NAME_LABEL_OVERHEAD} chars)",
            http_status=400,
        )

    # Anti-takeover (codex round-3 P1, made atomic in round-7):
    # ``mint_for_subject`` performs the existence check + insert under
    # a single store lock so two concurrent confirms with different
    # SPKs for the same subject can't both pass. The non-atomic
    # ``get_active_for_subject`` + ``mint`` pattern raced — both
    # callers saw "no existing key" and inserted, producing parallel
    # live credentials whose key names differed because they're
    # spk-derived.
    from dmp.server.tsig_keystore import SubjectAlreadyOwnedError

    spk_lower = spk_hex.lower()
    expires_at = (
        int(time.time() if now is None else now) + int(config.expires_in_seconds)
        if config.expires_in_seconds
        else 0
    )

    try:
        minted = keystore.mint_for_subject(
            name=key_name,
            allowed_suffixes=suffixes,
            subject=subject,
            registered_spk=spk_lower,
            expires_at=expires_at,
            now=now,
        )
    except SubjectAlreadyOwnedError as exc:
        raise SubjectAlreadyOwned() from exc
    return MintedTSIGKey(
        name=minted.name,
        secret_hex=minted.secret.hex(),
        algorithm=minted.algorithm,
        allowed_suffixes=minted.allowed_suffixes,
        subject=subject,
        zone=zone,
        expires_at=minted.expires_at,
    )
