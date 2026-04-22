"""Signed rotation + revocation records for DMP key lifecycle (M5.4).

Three rotation scenarios motivate this module:

1. **User identity key rotation** — a user derives a new Ed25519/X25519
   identity from a new passphrase and wants every pinned contact to
   follow over to the new key without re-pinning out of band.
2. **Cluster operator key rotation** — an operator rotates the Ed25519
   key that signs the cluster manifest, and the cluster's clients need
   to pick up the new key without a flag day.
3. **Bootstrap zone signer rotation** — the zone operator rotates the
   key that signs the ``_dmp.<user_domain>`` bootstrap record.

All three are handled by a single pair of wire types:

- ``RotationRecord`` — "the holder of ``old_spk`` authorizes that
  ``new_spk`` succeeds it for ``subject``". Co-signed by BOTH keys;
  neither alone can forge it.
- ``RevocationRecord`` — "the holder of ``revoked_spk`` declares it
  permanently invalid". Self-signed by the revoked key itself.

**DRAFT status.** These wire types ship ahead of the M4 external crypto
audit. The audit may recommend structural changes, in which case v0.3.0
is permitted to introduce ``v=dmp2;t=rotation;``. See
``docs/protocol/rotation.md`` for the full design and threat model.

Wire format — mirrors ``ClusterManifest`` / ``BootstrapRecord``: a
``v=dmp1;t=rotation;`` or ``v=dmp1;t=revocation;`` prefix followed by
base64'd ``body || sig(s)``. Body layouts documented under each record
type below.

Co-signing rationale (full treatment in rotation.md):

- Attacker with only the NEW key: cannot forge a rotation claiming an
  old key endorsed the new one without the old key's signature.
- Attacker with only the recently-compromised OLD key: cannot unilaterally
  rotate to an attacker-chosen new key because the real user would never
  cosign it with their fresh new key.

Cosign body ordering: ``old_spk`` comes BEFORE ``new_spk`` in the body.
Reasoning: the signing flow is "prove you authorized leaving the old
identity, then prove you're the one picking up the new one" — reading the
body left-to-right mirrors that chronological story. Both orderings would
verify; this one is documented so auditors can reason about ordering
attacks without first reverse-engineering the intent.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Optional

from dmp.core.crypto import DMPCrypto

RECORD_PREFIX_ROTATION = "v=dmp1;t=rotation;"
RECORD_PREFIX_REVOCATION = "v=dmp1;t=revocation;"

_MAGIC_ROTATION = b"DMPROT1"
_MAGIC_REVOCATION = b"DMPRV01"
_SIG_LEN = 64
_SPK_LEN = 32

# Subject-type enum. Shared between RotationRecord and RevocationRecord.
SUBJECT_TYPE_USER_IDENTITY = 1
SUBJECT_TYPE_CLUSTER_OPERATOR = 2
SUBJECT_TYPE_BOOTSTRAP_SIGNER = 3

_SUBJECT_TYPES = (
    SUBJECT_TYPE_USER_IDENTITY,
    SUBJECT_TYPE_CLUSTER_OPERATOR,
    SUBJECT_TYPE_BOOTSTRAP_SIGNER,
)

# Reason codes for RevocationRecord. 1 = assumed compromise (most urgent;
# chain walk aborts immediately). 2 = routine rotation (the replacement
# was already published). 3 = lost key (the user cannot self-sign — this
# is documented as a v1 limitation; see rotation.md "Revocation model").
# 4 = other / unspecified.
REASON_COMPROMISE = 1
REASON_ROUTINE = 2
REASON_LOST_KEY = 3
REASON_OTHER = 4

_REASON_CODES = (REASON_COMPROMISE, REASON_ROUTINE, REASON_LOST_KEY, REASON_OTHER)

# Per-field caps. MAX_SUBJECT_LEN matches the other hardened records
# (ClusterManifest, BootstrapRecord) at 64 bytes.
MAX_SUBJECT_LEN = 64

# Absolute wire-length cap, symmetric with the other hardened records.
# 1200 bytes is ~4 TXT strings of 255 chars + small headroom.
MAX_WIRE_LEN = 1200


def _validate_subject(subject_type: int, subject: str) -> None:
    """Validate subject matches the declared subject_type.

    - user_identity: ``"user@host"`` form. ``_validate_user_subject`` enforces
      non-empty user + host halves; host is case-insensitive per DNS but we
      store as-written and casefold on comparison.
    - cluster_operator / bootstrap_signer: a DNS name under the rules
      shared with ClusterManifest.cluster_name and BootstrapRecord.user_domain.
    """
    if not isinstance(subject, str) or not subject:
        raise ValueError("subject must be a non-empty string")
    if subject_type not in _SUBJECT_TYPES:
        raise ValueError(
            f"invalid subject_type {subject_type}; must be one of {_SUBJECT_TYPES}"
        )
    subject_bytes = subject.encode("utf-8")
    if len(subject_bytes) == 0 or len(subject_bytes) > MAX_SUBJECT_LEN:
        raise ValueError(f"subject too long (max {MAX_SUBJECT_LEN} utf-8 bytes)")

    if subject_type == SUBJECT_TYPE_USER_IDENTITY:
        _validate_user_subject(subject)
    else:
        # DNS-name validation for cluster + bootstrap subjects. Re-use the
        # hardened validator from the cluster module to stay in lockstep.
        from dmp.core.cluster import _validate_dns_name

        normalized = subject[:-1] if subject.endswith(".") else subject
        if not normalized:
            raise ValueError("subject must have at least one label")
        _validate_dns_name(normalized)


def _validate_user_subject(subject: str) -> None:
    """A user-identity subject is ``user@host``.

    Accepts anything that ``dmp.core.identity.parse_address`` would
    accept. The user half is a free-form utf-8 string (matches what
    IdentityRecord.username allows — 64 bytes, non-empty); the host
    half is a DNS name.
    """
    if "@" not in subject:
        raise ValueError("user-identity subject must be in user@host form")
    user, _, host = subject.partition("@")
    user = user.strip()
    host = host.strip()
    if not user or not host:
        raise ValueError("user-identity subject must have non-empty user and host")
    # The host half must be a valid DNS name (same rules as cluster/bootstrap).
    from dmp.core.cluster import _validate_dns_name

    normalized_host = host[:-1] if host.endswith(".") else host
    if not normalized_host:
        raise ValueError("user-identity host must have at least one label")
    _validate_dns_name(normalized_host)


def _normalize_subject(subject_type: int, subject: str) -> str:
    """Normalize a subject for comparison (trailing-dot / case).

    - user_identity: strip trailing dot from host, casefold host; keep
      user as-written (usernames are typically case-sensitive in mailbox
      conventions).
    - cluster / bootstrap: strip trailing dot, casefold (DNS names are
      case-insensitive).
    """
    if subject_type == SUBJECT_TYPE_USER_IDENTITY:
        if "@" not in subject:
            return subject
        user, _, host = subject.partition("@")
        host = host.strip()
        if host.endswith("."):
            host = host[:-1]
        return f"{user.strip()}@{host.casefold()}"
    else:
        norm = subject[:-1] if subject.endswith(".") else subject
        return norm.casefold()


# --------------------------------------------------------------------------
# RotationRecord
# --------------------------------------------------------------------------


@dataclass
class RotationRecord:
    """Signed statement that ``new_spk`` succeeds ``old_spk`` for ``subject``.

    Co-signed by BOTH keys. Either alone is rejection. See module
    docstring for the rationale.

    Body layout:
        magic:              b"DMPROT1"              (7 bytes)
        subject_type:       uint8                   (1 byte)
        subject_len:        uint8                   (1 byte)
        subject:            utf-8 bytes             (var, <= 64)
        old_spk:            32 bytes
        new_spk:            32 bytes
        seq:                uint64 big-endian       (8 bytes)
        ts:                 uint64 big-endian       (8 bytes)
        exp:                uint64 big-endian       (8 bytes)

    Trailing signatures:
        sig_old:            64 bytes (Ed25519 over body by old_spk)
        sig_new:            64 bytes (Ed25519 over body by new_spk)
    """

    subject_type: int
    subject: str
    old_spk: bytes
    new_spk: bytes
    seq: int
    ts: int
    exp: int

    def _validate(self) -> None:
        _validate_subject(self.subject_type, self.subject)
        if (
            not isinstance(self.old_spk, (bytes, bytearray))
            or len(self.old_spk) != _SPK_LEN
        ):
            raise ValueError("old_spk must be 32 bytes")
        if (
            not isinstance(self.new_spk, (bytes, bytearray))
            or len(self.new_spk) != _SPK_LEN
        ):
            raise ValueError("new_spk must be 32 bytes")
        # A rotation to the same key is either a bug (publisher typo) or
        # a replay attempt; either way it has no legitimate meaning and
        # we reject it here rather than let a client walk a trivial
        # self-loop.
        if bytes(self.old_spk) == bytes(self.new_spk):
            raise ValueError("old_spk and new_spk must differ")
        if not (0 <= self.seq < (1 << 64)):
            raise ValueError("seq out of range")
        if not (0 <= self.ts < (1 << 64)):
            raise ValueError("ts out of range")
        if not (0 <= self.exp < (1 << 64)):
            raise ValueError("exp out of range")

    def to_body_bytes(self) -> bytes:
        self._validate()
        subject_bytes = self.subject.encode("utf-8")
        parts = [
            _MAGIC_ROTATION,
            self.subject_type.to_bytes(1, "big"),
            len(subject_bytes).to_bytes(1, "big"),
            subject_bytes,
            bytes(self.old_spk),
            bytes(self.new_spk),
            self.seq.to_bytes(8, "big"),
            self.ts.to_bytes(8, "big"),
            self.exp.to_bytes(8, "big"),
        ]
        return b"".join(parts)

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "RotationRecord":
        # Fixed layout: magic(7) + subject_type(1) + subject_len(1)
        #   + subject(var) + old_spk(32) + new_spk(32)
        #   + seq(8) + ts(8) + exp(8)
        min_len = len(_MAGIC_ROTATION) + 1 + 1 + _SPK_LEN + _SPK_LEN + 8 + 8 + 8
        if len(body) < min_len:
            raise ValueError("body too short for header")
        off = 0
        if body[off : off + len(_MAGIC_ROTATION)] != _MAGIC_ROTATION:
            raise ValueError("bad magic")
        off += len(_MAGIC_ROTATION)
        subject_type = body[off]
        off += 1
        if subject_type not in _SUBJECT_TYPES:
            raise ValueError("invalid subject_type")
        subject_len = body[off]
        off += 1
        if subject_len == 0 or subject_len > MAX_SUBJECT_LEN:
            raise ValueError("invalid subject length")
        if off + subject_len > len(body):
            raise ValueError("truncated subject")
        try:
            subject = body[off : off + subject_len].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("subject not utf-8") from e
        off += subject_len
        if off + _SPK_LEN + _SPK_LEN + 8 + 8 + 8 != len(body):
            raise ValueError("trailing bytes or truncated tail")
        old_spk = bytes(body[off : off + _SPK_LEN])
        off += _SPK_LEN
        new_spk = bytes(body[off : off + _SPK_LEN])
        off += _SPK_LEN
        seq = int.from_bytes(body[off : off + 8], "big")
        off += 8
        ts = int.from_bytes(body[off : off + 8], "big")
        off += 8
        exp = int.from_bytes(body[off : off + 8], "big")
        off += 8
        # Mirror sign-side subject validation on receive. A correctly
        # signed record from a buggy publisher may carry an otherwise-
        # plausible-looking subject that is not publishable; reject here.
        _validate_subject(subject_type, subject)
        if old_spk == new_spk:
            raise ValueError("old_spk and new_spk must differ")
        return cls(
            subject_type=subject_type,
            subject=subject,
            old_spk=old_spk,
            new_spk=new_spk,
            seq=seq,
            ts=ts,
            exp=exp,
        )

    def sign(self, old_crypto: DMPCrypto, new_crypto: DMPCrypto) -> str:
        """Serialize, co-sign by old + new keys, return TXT wire string.

        Both keypairs must match the declared spks in the body. This
        catches a footgun where a caller accidentally passes the wrong
        DMPCrypto for one side — a common rotation-flow bug.
        """
        if old_crypto.get_signing_public_key_bytes() != bytes(self.old_spk):
            raise ValueError("old_crypto signing key does not match declared old_spk")
        if new_crypto.get_signing_public_key_bytes() != bytes(self.new_spk):
            raise ValueError("new_crypto signing key does not match declared new_spk")
        body = self.to_body_bytes()
        sig_old = old_crypto.sign_data(body)
        sig_new = new_crypto.sign_data(body)
        encoded = base64.b64encode(body + sig_old + sig_new).decode("ascii")
        wire = f"{RECORD_PREFIX_ROTATION}{encoded}"
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            raise ValueError(
                f"rotation record wire size {len(wire.encode('utf-8'))} "
                f"exceeds MAX_WIRE_LEN {MAX_WIRE_LEN}"
            )
        return wire

    @classmethod
    def parse_and_verify(
        cls,
        wire: str,
        expected_old_spk: Optional[bytes] = None,
        expected_subject: Optional[str] = None,
        *,
        now: Optional[int] = None,
    ) -> Optional["RotationRecord"]:
        """Parse, verify BOTH signatures, enforce expiry. Never raises.

        Returns None on:
        - Missing/wrong prefix
        - Wire exceeds MAX_WIRE_LEN
        - Base64 decode errors
        - Either signature fails
        - Embedded old_spk != expected_old_spk (when caller pins one)
        - Embedded subject doesn't match expected_subject (normalized)
        - Body malformed / truncated / trailing bytes
        - Expired (exp < now)
        - Invalid subject_type value
        - Invalid signature-length tail
        """
        # 1. Prefix.
        if not isinstance(wire, str) or not wire.startswith(RECORD_PREFIX_ROTATION):
            return None

        # 1a. Wire-length cap.
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            return None

        # 2. Base64.
        try:
            blob = base64.b64decode(wire[len(RECORD_PREFIX_ROTATION) :], validate=True)
        except Exception:
            return None

        # 3. Split body | sig_old | sig_new.
        if len(blob) < len(_MAGIC_ROTATION) + 2 * _SIG_LEN:
            return None
        body = blob[: -2 * _SIG_LEN]
        sig_old = blob[-2 * _SIG_LEN : -_SIG_LEN]
        sig_new = blob[-_SIG_LEN:]

        # 4. Unpack body first (we need old_spk + new_spk to verify).
        # Structural failures here are indistinguishable from malicious
        # tampering; both return None.
        try:
            record = cls.from_body_bytes(body)
        except ValueError:
            return None

        # 5. Verify BOTH signatures. Either alone is rejection.
        if not DMPCrypto.verify_signature(body, sig_old, bytes(record.old_spk)):
            return None
        if not DMPCrypto.verify_signature(body, sig_new, bytes(record.new_spk)):
            return None

        # 6. Embedded old_spk must match the caller's expectation when pinned.
        if expected_old_spk is not None:
            if (
                not isinstance(expected_old_spk, (bytes, bytearray))
                or len(expected_old_spk) != _SPK_LEN
            ):
                return None
            if bytes(record.old_spk) != bytes(expected_old_spk):
                return None

        # 7. Expected subject binding (case-insensitive, trailing-dot
        # normalized for cluster/bootstrap subjects; user@host casefolds
        # the host half only for user identities).
        if expected_subject is not None:
            if _normalize_subject(
                record.subject_type, record.subject
            ) != _normalize_subject(record.subject_type, expected_subject):
                return None

        # 8. Expiry.
        now_ts = int(time.time()) if now is None else int(now)
        if record.exp < now_ts:
            return None

        return record

    def is_expired(self, now: Optional[int] = None) -> bool:
        now_ts = int(time.time()) if now is None else int(now)
        return now_ts > self.exp


# --------------------------------------------------------------------------
# RevocationRecord
# --------------------------------------------------------------------------


@dataclass
class RevocationRecord:
    """Signed declaration that ``revoked_spk`` is permanently invalid.

    Self-signed by ``revoked_spk`` itself. Weaker than a designated-
    revocation-key model: a compromised key can forge the revocation and
    a lost key cannot revoke itself. This is a v1 simplification; see
    rotation.md "Revocation model" for the explicit trade-off and the
    v2 evolution path (designated revocation keys specified at identity
    creation).

    Body layout:
        magic:              b"DMPRV01"              (7 bytes)
        subject_type:       uint8                   (1 byte)
        subject_len:        uint8                   (1 byte)
        subject:            utf-8 bytes             (var, <= 64)
        revoked_spk:        32 bytes
        reason_code:        uint8                   (1 byte)
        ts:                 uint64 big-endian       (8 bytes)

    Trailing signature:
        sig:                64 bytes (Ed25519 over body by revoked_spk)
    """

    subject_type: int
    subject: str
    revoked_spk: bytes
    reason_code: int
    ts: int

    def _validate(self) -> None:
        _validate_subject(self.subject_type, self.subject)
        if (
            not isinstance(self.revoked_spk, (bytes, bytearray))
            or len(self.revoked_spk) != _SPK_LEN
        ):
            raise ValueError("revoked_spk must be 32 bytes")
        if self.reason_code not in _REASON_CODES:
            raise ValueError(
                f"invalid reason_code {self.reason_code}; "
                f"must be one of {_REASON_CODES}"
            )
        if not (0 <= self.ts < (1 << 64)):
            raise ValueError("ts out of range")

    def to_body_bytes(self) -> bytes:
        self._validate()
        subject_bytes = self.subject.encode("utf-8")
        parts = [
            _MAGIC_REVOCATION,
            self.subject_type.to_bytes(1, "big"),
            len(subject_bytes).to_bytes(1, "big"),
            subject_bytes,
            bytes(self.revoked_spk),
            self.reason_code.to_bytes(1, "big"),
            self.ts.to_bytes(8, "big"),
        ]
        return b"".join(parts)

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "RevocationRecord":
        min_len = len(_MAGIC_REVOCATION) + 1 + 1 + _SPK_LEN + 1 + 8
        if len(body) < min_len:
            raise ValueError("body too short for header")
        off = 0
        if body[off : off + len(_MAGIC_REVOCATION)] != _MAGIC_REVOCATION:
            raise ValueError("bad magic")
        off += len(_MAGIC_REVOCATION)
        subject_type = body[off]
        off += 1
        if subject_type not in _SUBJECT_TYPES:
            raise ValueError("invalid subject_type")
        subject_len = body[off]
        off += 1
        if subject_len == 0 or subject_len > MAX_SUBJECT_LEN:
            raise ValueError("invalid subject length")
        if off + subject_len > len(body):
            raise ValueError("truncated subject")
        try:
            subject = body[off : off + subject_len].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError("subject not utf-8") from e
        off += subject_len
        if off + _SPK_LEN + 1 + 8 != len(body):
            raise ValueError("trailing bytes or truncated tail")
        revoked_spk = bytes(body[off : off + _SPK_LEN])
        off += _SPK_LEN
        reason_code = body[off]
        off += 1
        if reason_code not in _REASON_CODES:
            raise ValueError("invalid reason_code")
        ts = int.from_bytes(body[off : off + 8], "big")
        off += 8
        _validate_subject(subject_type, subject)
        return cls(
            subject_type=subject_type,
            subject=subject,
            revoked_spk=revoked_spk,
            reason_code=reason_code,
            ts=ts,
        )

    def sign(self, revoked_crypto: DMPCrypto) -> str:
        """Serialize and self-sign. ``revoked_crypto`` must hold ``revoked_spk``."""
        if revoked_crypto.get_signing_public_key_bytes() != bytes(self.revoked_spk):
            raise ValueError(
                "revoked_crypto signing key does not match declared revoked_spk"
            )
        body = self.to_body_bytes()
        sig = revoked_crypto.sign_data(body)
        encoded = base64.b64encode(body + sig).decode("ascii")
        wire = f"{RECORD_PREFIX_REVOCATION}{encoded}"
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            raise ValueError(
                f"revocation record wire size {len(wire.encode('utf-8'))} "
                f"exceeds MAX_WIRE_LEN {MAX_WIRE_LEN}"
            )
        return wire

    @classmethod
    def parse_and_verify(
        cls,
        wire: str,
        expected_revoked_spk: Optional[bytes] = None,
        expected_subject: Optional[str] = None,
        *,
        now: Optional[int] = None,
        max_age_seconds: int = 86_400 * 365,
    ) -> Optional["RevocationRecord"]:
        """Parse, verify single signature. Never raises.

        ``max_age_seconds`` bounds how old a revocation we accept. A year
        is the default — old enough to catch a client that was offline
        across a rotation cycle, short enough that an attacker cannot
        replay a stale revocation indefinitely. Callers that want to
        accept arbitrarily old revocations (e.g. a forensic audit tool)
        can pass a large value.
        """
        if not isinstance(wire, str) or not wire.startswith(RECORD_PREFIX_REVOCATION):
            return None
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            return None
        try:
            blob = base64.b64decode(
                wire[len(RECORD_PREFIX_REVOCATION) :], validate=True
            )
        except Exception:
            return None
        if len(blob) < len(_MAGIC_REVOCATION) + _SIG_LEN:
            return None
        body = blob[:-_SIG_LEN]
        sig = blob[-_SIG_LEN:]

        try:
            record = cls.from_body_bytes(body)
        except ValueError:
            return None

        if not DMPCrypto.verify_signature(body, sig, bytes(record.revoked_spk)):
            return None

        if expected_revoked_spk is not None:
            if (
                not isinstance(expected_revoked_spk, (bytes, bytearray))
                or len(expected_revoked_spk) != _SPK_LEN
            ):
                return None
            if bytes(record.revoked_spk) != bytes(expected_revoked_spk):
                return None

        if expected_subject is not None:
            if _normalize_subject(
                record.subject_type, record.subject
            ) != _normalize_subject(record.subject_type, expected_subject):
                return None

        # Freshness window. Reject stale revocations to limit an attacker's
        # ability to re-inject an old revocation long after the fact. Also
        # reject revocations whose ts is absurdly in the future (clock-skew
        # attacks that could extend the freshness window).
        now_ts = int(time.time()) if now is None else int(now)
        if record.ts + int(max_age_seconds) < now_ts:
            return None
        # Allow a small positive clock drift (300s, matching typical Kerberos
        # defaults). Beyond that, reject — a future-ts record is either
        # a clock problem or a replay-protection attack.
        if record.ts > now_ts + 300:
            return None

        return record


# --------------------------------------------------------------------------
# RRset naming conventions
# --------------------------------------------------------------------------


def rotation_rrset_name_user_identity(username: str, user_domain: str) -> str:
    """Where to publish / query user-identity rotations for ``user@user_domain``.

    Convention: ``rotate.dmp.<username-hash>.<user_domain>`` — mirrors
    ``identity_domain`` under ``dmp/core/identity.py`` and keeps the
    rotation records alongside the identity zone. See rotation.md for
    the full publishing convention.
    """
    from dmp.core.identity import identity_domain

    # Reuse the identity hash-label so rotation records sit parallel to
    # the identity TXT record (both under dmp.<hash>.<domain>).
    base = identity_domain(username, user_domain)
    return f"rotate.{base}"


def rotation_rrset_name_zone_anchored(identity_domain_str: str) -> str:
    """Zone-anchored user-identity rotation name: ``rotate.dmp.<zone>``.

    When the user publishes their identity at ``dmp.<zone>`` (see
    ``zone_anchored_identity_name``), rotations live at ``rotate.dmp.<zone>``.
    """
    return f"rotate.dmp.{identity_domain_str.rstrip('.')}"


def rotation_rrset_name_cluster(cluster_base_domain: str) -> str:
    """Where to publish / query cluster-operator rotations."""
    from dmp.core.cluster import _validate_dns_name

    _validate_dns_name(cluster_base_domain)
    normalized = (
        cluster_base_domain[:-1]
        if cluster_base_domain.endswith(".")
        else cluster_base_domain
    )
    return f"rotate.cluster.{normalized}"


def rotation_rrset_name_bootstrap(user_domain: str) -> str:
    """Where to publish / query bootstrap-signer rotations."""
    from dmp.core.cluster import _validate_dns_name

    _validate_dns_name(user_domain)
    normalized = user_domain[:-1] if user_domain.endswith(".") else user_domain
    return f"rotate._dmp.{normalized}"
