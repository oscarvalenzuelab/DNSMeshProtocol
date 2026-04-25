"""Signed claim records for first-message reach (M8.2).

A *claim* is a tiny recipient-keyed pointer published by a sender to a
*claim provider node*, asserting "I have mail for {recipient_id} at
{my mailbox zone}, slot {N}, signed by {sender_spk}, valid until
{exp}." The provider hosts the claim — it does NOT store the
ciphertext. The recipient polls one or more claim providers, verifies
the Ed25519 signature, then fetches the actual manifest+chunks from
``sender_mailbox_domain`` via the normal cross-zone receive path
(M8.1).

This is the missing piece for unpinned-stranger reach: without
claims, a stranger who knows Bob's address has no way to be
discovered by Bob's recv loop, because Bob only walks zones of
contacts he has already pinned. Claims let any sender-recipient pair
rendezvous through a shared provider tier without putting Bob's home
node on the open-write hot path (cf. the "knock inbox" alternative
that codex rejected on DoS grounds).

Trust model
-----------
- The claim is signed by ``sender_spk``. The provider hosts but does
  not vouch — a malicious provider can drop or reorder, but cannot
  forge. M8.4 anti-entropy gossip closes drop-by-single-provider.
- The recipient verifies the signature on receive. An unsigned or
  forged claim is dropped at parse time.
- Recipients deliver pinned-sender claims to the normal inbox; claims
  from un-pinned senders land in a quarantine ``pending_intro``
  queue (M8.3) that the user can review with the ``dnsmesh intro``
  CLI subcommand. NEVER auto-pin from a claim.

Wire format
-----------
Mirrors ``HeartbeatRecord`` and ``BootstrapRecord``: base64 of
``body || sig`` with a ``v=dmp1;t=claim;`` prefix. Fits in a single
DNS TXT (under 255 bytes when sender_mailbox_domain stays modest).

Body layout (all integers big-endian):

    magic                        b"DMPCL01"        7 bytes
    msg_id                       16 bytes          16 bytes (uuid4)
    sender_spk                   32 bytes          32 bytes (Ed25519 pubkey)
    sender_mailbox_domain_len    uint8             1 byte
    sender_mailbox_domain        utf-8 bytes       var, 1..MAX_MAILBOX_DOMAIN_LEN
    slot                         uint8             1 byte (0..9)
    ts                           uint64            8 bytes (unix seconds)
    exp                          uint64            8 bytes (unix seconds)
    signature                    bytes             64 bytes (Ed25519 over body)

The recipient is identified by the RRset name's ``mb-{hash12(recipient_id)}``
component — only a recipient whose ``self.user_id`` matches that hash12
queries the name in the first place. The full 32-byte recipient_id is
NOT in the claim body, which keeps the wire under the 255-byte single-
DNS-string limit even with realistic mailbox-domain lengths. Cross-
recipient replay (a malicious provider rebroadcasting a captured claim
to a different recipient's hash12) cannot recover the underlying
message: the sender's manifest+chunks live at
``slot-N.mb-{hash12(real_recipient_id)}.{sender_zone}`` and the wrong
recipient's hash12 doesn't match. The replay leaks polling traffic, not
plaintext.

Replay / freshness
------------------
``exp`` governs lifetime: a claim with ``exp <= now`` is rejected.
``ts`` must not be far in the FUTURE — a claim arriving with
``ts > now + ts_skew_seconds`` is rejected as a forward-dated forgery
(used to extend lifetime past what the operator's TTL cap allows).
Past ts is accepted as long as ``exp`` is still in the future, so a
sender publishing with a long TTL and a recipient polling several
minutes later doesn't lose the message — codex round 2 P2 caught a
prior version that wrongly capped lifetime at 5 minutes by also
rejecting past-skewed ts.

Replay protection inside the recipient's pipeline is the existing
``ReplayCache`` keyed on (sender_spk, msg_id) — once a claim leads
to a successful decrypt, the underlying message's replay protection
takes over.
"""

from __future__ import annotations

import base64
import struct
import time
from dataclasses import dataclass
from typing import Optional

from dmp.core.crypto import DMPCrypto
from dmp.core.ed25519_points import is_low_order as _is_low_order

RECORD_PREFIX = "v=dmp1;t=claim;"

_MAGIC = b"DMPCL01"
_MSG_ID_LEN = 16
_SPK_LEN = 32
_SIG_LEN = 64

# A claim must fit in a single 255-byte DNS TXT string, matching the
# rest of DMP's wire records. With magic (7) + msg_id (16) + spk (32)
# + len byte (1) + slot (1) + ts/exp (16) + sig (64) = 137 bytes
# fixed, the variable mailbox domain can be at most:
#   floor((255 - len(prefix)) * 3/4) - 137 = 180 - 137 = 43 bytes.
# 43 bytes covers all realistic deployment names ("alice.dnsmesh.io",
# "alice.mesh.example.com", etc.). Operators with longer zones either
# shorten the user-facing label or wait for multi-string TXT support
# (out of scope for M8.2).
MAX_MAILBOX_DOMAIN_LEN = 43
MAX_WIRE_LEN = 255

# Slot numbers are bounded by SLOT_COUNT in dmp.client.client. We
# reject out-of-range values at the parser to keep wire shape
# predictable; if SLOT_COUNT ever changes there's exactly one place
# to follow.
MAX_SLOT = 9

# Freshness window. Same value as HeartbeatRecord — caught replays
# of captured claims, tolerates clock drift + queuing.
_DEFAULT_TS_SKEW_SECONDS = 300


@dataclass(frozen=True)
class ClaimRecord:
    """Signed first-contact pointer published to a claim provider.

    Immutable; construct via ``__init__`` + ``sign()``, or parse via
    :meth:`parse_and_verify`. The record is signed by ``sender_spk``
    (the Ed25519 identity key of whoever wants to message the
    recipient).
    """

    msg_id: bytes
    sender_spk: bytes
    sender_mailbox_domain: str
    slot: int
    ts: int
    exp: int

    # ------------------------------------------------------------------
    # body layout
    # ------------------------------------------------------------------

    def to_body_bytes(self) -> bytes:
        """Serialize the signable body (everything except the signature)."""
        if not isinstance(self.msg_id, (bytes, bytearray)):
            raise ValueError("msg_id must be bytes")
        if len(self.msg_id) != _MSG_ID_LEN:
            raise ValueError(
                f"msg_id must be {_MSG_ID_LEN} bytes, got {len(self.msg_id)}"
            )
        if not isinstance(self.sender_spk, (bytes, bytearray)):
            raise ValueError("sender_spk must be bytes")
        if len(self.sender_spk) != _SPK_LEN:
            raise ValueError(
                f"sender_spk must be {_SPK_LEN} bytes, got {len(self.sender_spk)}"
            )
        if not isinstance(self.sender_mailbox_domain, str):
            raise ValueError("sender_mailbox_domain must be a string")
        if not self.sender_mailbox_domain:
            raise ValueError("sender_mailbox_domain must be non-empty")
        if len(self.sender_mailbox_domain) > MAX_MAILBOX_DOMAIN_LEN:
            raise ValueError(
                f"sender_mailbox_domain length {len(self.sender_mailbox_domain)} "
                f"> MAX_MAILBOX_DOMAIN_LEN {MAX_MAILBOX_DOMAIN_LEN}"
            )
        try:
            domain_bytes = self.sender_mailbox_domain.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError(
                f"sender_mailbox_domain must be utf-8 encodable: {exc}"
            ) from exc
        # Refuse whitespace / control chars in the zone name. A claim
        # whose sender_mailbox_domain looks like "a.b.com\nslot-0..."
        # is trying to confuse the recipient's downstream DNS query
        # construction. Reject at the wire layer.
        if any(ord(c) < 0x21 or ord(c) == 0x7F for c in self.sender_mailbox_domain):
            raise ValueError(
                "sender_mailbox_domain contains whitespace or control characters"
            )

        if not isinstance(self.slot, int) or self.slot < 0 or self.slot > MAX_SLOT:
            raise ValueError(f"slot must be 0..{MAX_SLOT}, got {self.slot!r}")
        if not isinstance(self.ts, int) or self.ts < 0 or self.ts >= (1 << 63):
            raise ValueError("ts must be a non-negative int64")
        if not isinstance(self.exp, int) or self.exp < 0 or self.exp >= (1 << 63):
            raise ValueError("exp must be a non-negative int64")
        if self.exp <= self.ts:
            raise ValueError("exp must be strictly greater than ts")

        return (
            _MAGIC
            + bytes(self.msg_id)
            + bytes(self.sender_spk)
            + struct.pack(">B", len(domain_bytes))
            + domain_bytes
            + struct.pack(">B", self.slot)
            + struct.pack(">Q", self.ts)
            + struct.pack(">Q", self.exp)
        )

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "ClaimRecord":
        """Parse the signable body. Raises ValueError on structural issues.

        Does NOT verify the signature — caller is responsible. Use
        :meth:`parse_and_verify` for the complete check.
        """
        min_len = len(_MAGIC) + _MSG_ID_LEN + _SPK_LEN + 1 + 1 + 1 + 16
        if len(body) < min_len:
            raise ValueError("body too short for fixed claim fields")
        if body[: len(_MAGIC)] != _MAGIC:
            raise ValueError("bad magic")
        off = len(_MAGIC)

        msg_id = bytes(body[off : off + _MSG_ID_LEN])
        off += _MSG_ID_LEN
        sender_spk = bytes(body[off : off + _SPK_LEN])
        off += _SPK_LEN

        (domain_len,) = struct.unpack(">B", body[off : off + 1])
        off += 1
        if domain_len == 0 or domain_len > MAX_MAILBOX_DOMAIN_LEN:
            raise ValueError(f"sender_mailbox_domain_len out of range: {domain_len}")
        if off + domain_len > len(body):
            raise ValueError("body truncated in sender_mailbox_domain")
        try:
            sender_mailbox_domain = body[off : off + domain_len].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"sender_mailbox_domain not valid utf-8: {exc}") from exc
        off += domain_len

        if off + 1 > len(body):
            raise ValueError("body truncated in slot")
        (slot,) = struct.unpack(">B", body[off : off + 1])
        off += 1
        if slot > MAX_SLOT:
            raise ValueError(f"slot out of range: {slot}")

        if off + 16 > len(body):
            raise ValueError("body truncated in ts/exp")
        (ts,) = struct.unpack(">Q", body[off : off + 8])
        off += 8
        (exp,) = struct.unpack(">Q", body[off : off + 8])
        off += 8

        if off != len(body):
            raise ValueError(f"trailing body bytes: off={off} len={len(body)}")

        if exp <= ts:
            raise ValueError("exp must be strictly greater than ts")

        # Re-validate through the constructor checks so a parsed body
        # can never produce a Python-level ClaimRecord that fails
        # downstream invariants.
        record = cls(
            msg_id=msg_id,
            sender_spk=sender_spk,
            sender_mailbox_domain=sender_mailbox_domain,
            slot=slot,
            ts=ts,
            exp=exp,
        )
        # Touch to_body_bytes so any string-validity rule (control
        # chars, etc.) raises before we hand the record back.
        record.to_body_bytes()
        return record

    # ------------------------------------------------------------------
    # sign / verify
    # ------------------------------------------------------------------

    def sign(self, sender_crypto: DMPCrypto) -> str:
        """Serialize, sign with ``sender_crypto``, return wire text.

        ``sender_crypto`` must hold the private half of ``self.sender_spk``;
        a mismatch is caught here and refused.
        """
        if sender_crypto.get_signing_public_key_bytes() != bytes(self.sender_spk):
            raise ValueError(
                "sender_crypto signing key does not match declared sender_spk"
            )
        body = self.to_body_bytes()
        sig = sender_crypto.sign_data(body)
        encoded = base64.b64encode(body + sig).decode("ascii")
        wire = f"{RECORD_PREFIX}{encoded}"
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            raise ValueError(
                f"claim wire size {len(wire.encode('utf-8'))} "
                f"exceeds MAX_WIRE_LEN {MAX_WIRE_LEN}"
            )
        return wire

    @classmethod
    def parse_and_verify(
        cls,
        wire: str,
        *,
        now: Optional[int] = None,
        ts_skew_seconds: int = _DEFAULT_TS_SKEW_SECONDS,
    ) -> Optional["ClaimRecord"]:
        """Parse + verify signature + enforce freshness. Never raises.

        Returns ``None`` on:
          - Wrong prefix / magic / shape / truncation / trailing bytes.
          - Wire exceeds ``MAX_WIRE_LEN``.
          - Base64 decode failure.
          - ``sender_spk`` is an Ed25519 low-order point (degenerate).
          - Signature verification failure.
          - ``ts`` is more than ``ts_skew_seconds`` in the FUTURE
            relative to ``now`` (forward-dated forgery defense).
            Past-skewed ts is accepted; ``exp`` governs lifetime.
          - ``exp`` is at or before ``now`` (claim is expired).
        """
        if not isinstance(wire, str) or not wire.startswith(RECORD_PREFIX):
            return None
        if len(wire.encode("utf-8")) > MAX_WIRE_LEN:
            return None
        try:
            blob = base64.b64decode(wire[len(RECORD_PREFIX) :], validate=True)
        except Exception:
            return None
        if len(blob) < _SIG_LEN + 1:
            return None
        body = blob[:-_SIG_LEN]
        sig = blob[-_SIG_LEN:]

        try:
            record = cls.from_body_bytes(body)
        except ValueError:
            return None

        # Low-order Ed25519 pubkey guard — same defense as heartbeat
        # / registration. The identity point (01 00..00) verifies
        # every message under permissive RFC 8032 implementations;
        # other small-order points permit grinding forgeries.
        if _is_low_order(bytes(record.sender_spk)):
            return None

        if not DMPCrypto.verify_signature(body, sig, bytes(record.sender_spk)):
            return None

        now = now if now is not None else int(time.time())
        # Future-skew only: a claim signed in the future is suspicious
        # (forward-dated forgery to extend lifetime past TTL caps).
        # A claim signed in the past is fine — `exp` is what bounds
        # how long it stays valid, and a recipient polling minutes
        # after a sender publishes must not lose the claim.
        if record.ts - now > ts_skew_seconds:
            return None
        if record.exp <= now:
            return None

        return record


# ---------------------------------------------------------------------------
# RRset name helper
# ---------------------------------------------------------------------------


def claim_rrset_name(recipient_id: bytes, slot: int, provider_zone: str) -> str:
    """Return the RRset name for a claim addressed to ``recipient_id``.

    Format: ``claim-{slot}.mb-{hash12(recipient_id)}.{provider_zone}``.

    Mirrors the mailbox slot RRset naming convention so a provider
    operator can run claim-server alongside a normal mailbox node
    without colliding namespaces (the ``claim-`` prefix vs ``slot-``
    keeps the two spaces distinct).
    """
    import hashlib

    if not isinstance(recipient_id, (bytes, bytearray)) or len(recipient_id) != 32:
        raise ValueError("recipient_id must be 32 bytes")
    if not isinstance(slot, int) or slot < 0 or slot > MAX_SLOT:
        raise ValueError(f"slot must be 0..{MAX_SLOT}")
    if not isinstance(provider_zone, str) or not provider_zone:
        raise ValueError("provider_zone must be a non-empty string")
    h12 = hashlib.sha256(bytes(recipient_id)).hexdigest()[:12]
    return f"claim-{slot}.mb-{h12}.{provider_zone}"
