"""Client-side rotation chain walking (M5.4).

**EXPERIMENTAL.** Disabled by default on ``DMPClient``; enable with
``rotation_chain_enabled=True``. Wire format subject to audit-driven
revision in v0.3.0 — see ``docs/protocol/rotation.md``.

When a direct signature check fails (a contact we pinned as ``old_spk``
appears to have stopped signing), this module walks the public rotation
chain published at ``rotate.<subject-path>`` to discover whether the
contact rotated to a new key. The walk is bounded, revocation-aware,
and refuses to follow ambiguous forks.

Chain-walk algorithm (pseudo code):

1. Fetch every TXT record at the rotation RRset.
2. Partition into ``rotations`` (``v=dmp1;t=rotation;``) and
   ``revocations`` (``v=dmp1;t=revocation;``). Drop everything else.
3. Verify every record (both sigs for rotation, one for revocation).
   Discard any that fail to verify OR whose subject doesn't match.
4. If any revocation targets the pinned key, abort trust — the caller
   must re-pin out-of-band.
5. Starting from ``pinned_spk``, follow the rotation chain forward:
   - Find the rotation whose ``old_spk`` == current head.
   - If any revocation targets the *new* key, abort trust.
   - If there are two rotations from the same head with the same ``seq``,
     abort trust (ambiguous fork — a legitimate chain is linear).
   - If sequence numbers regress or repeat along the walk, abort trust.
   - Advance head to ``new_spk``. Repeat.
6. Stop when no rotation exists from the current head, or when
   ``max_hops`` is exceeded (abort trust in the latter case).

Returning ``None`` is the signal to the caller: "I couldn't produce a
trustworthy current key; don't trust any message from this subject
until the user re-pins out-of-band." This is deliberately conservative:
walk failures are treated as revocations for the purposes of trust.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from dmp.core.rotation import (
    RECORD_PREFIX_REVOCATION,
    RECORD_PREFIX_ROTATION,
    RotationRecord,
    RevocationRecord,
    SUBJECT_TYPE_USER_IDENTITY,
    SUBJECT_TYPE_CLUSTER_OPERATOR,
    SUBJECT_TYPE_BOOTSTRAP_SIGNER,
    _normalize_subject,
    rotation_rrset_name_bootstrap,
    rotation_rrset_name_cluster,
    rotation_rrset_name_user_identity,
    rotation_rrset_name_zone_anchored,
)
from dmp.network.base import DNSRecordReader


class RotationChain:
    """Walk a rotation chain to translate a pinned key to the current head.

    Enable on DMPClient with ``rotation_chain_enabled=True``. Defaults to
    ``max_hops=4``, which is large enough for several years of routine
    rotations yet small enough that a pathologically long chain
    (compromise artifact or attacker-constructed loop) fails fast.

    This class talks ONLY to a ``DNSRecordReader``. It never publishes.
    """

    def __init__(self, reader: DNSRecordReader, *, max_hops: int = 4) -> None:
        if max_hops < 1:
            raise ValueError("max_hops must be >= 1")
        self._reader = reader
        self._max_hops = max_hops

    # ---- public API -------------------------------------------------------

    def resolve_current_spk(
        self,
        pinned_spk: bytes,
        subject: str,
        subject_type: int,
        *,
        rrset_name: Optional[str] = None,
    ) -> Optional[bytes]:
        """Walk the rotation chain from ``pinned_spk``; return the current head.

        Returns ``None`` if:
        - No rotation records found (caller re-checks against ``pinned_spk``
          directly — there's nothing to follow).
        - ``max_hops`` exceeded.
        - A revocation targets any key on the walked path (including
          ``pinned_spk``).
        - Ambiguous fork detected (two rotations from the same key at
          the same seq).
        - Sequence numbers regress or repeat along the walk.

        Returns ``pinned_spk`` when a chain exists but no rotation starts
        from ``pinned_spk`` itself — i.e. the pinned key is still the head.
        """
        if not isinstance(pinned_spk, (bytes, bytearray)) or len(pinned_spk) != 32:
            return None

        name = rrset_name or self._derive_rrset_name(subject, subject_type)
        if name is None:
            return None

        # 1. Fetch.
        try:
            records = self._reader.query_txt_record(name)
        except Exception:
            return None
        if not records:
            # No chain records published; caller falls back to pinned_spk.
            return None

        # 2. Partition + verify.
        rotations, revocations = self._partition(records, subject, subject_type)

        # 3. Any revocation of the pinned key aborts trust immediately.
        pinned = bytes(pinned_spk)
        if any(bytes(r.revoked_spk) == pinned for r in revocations):
            return None

        # 4. Build an index keyed by old_spk for O(1) lookup during the walk.
        # If multiple rotations share an old_spk, they must have the same
        # new_spk (same replacement) AND distinct seq values — otherwise
        # it's an ambiguous fork. We collect all, validate on walk.
        by_old: Dict[bytes, List[RotationRecord]] = {}
        for rot in rotations:
            by_old.setdefault(bytes(rot.old_spk), []).append(rot)

        # 5. Walk.
        head = pinned
        visited: set[bytes] = {head}
        last_seq: Optional[int] = None
        revoked_spks = {bytes(r.revoked_spk) for r in revocations}
        for hop in range(self._max_hops):
            candidates = by_old.get(head, [])
            if not candidates:
                # No further rotation from head: it's the current one.
                # The first hop (hop=0) with no candidates means the
                # pinned key is still the head and no chain existed for
                # us to follow past it. Return None in that case (caller
                # re-checks against pinned directly); otherwise return
                # the head we walked to.
                if hop == 0:
                    return None
                return head

            # Ambiguous-fork detection: two distinct new_spks from the
            # same old_spk is a hard fail, regardless of seq. Treating
            # same-seq differently from different-seq would let an
            # attacker craft a "higher seq wins" tiebreaker that races
            # the legitimate rotation.
            distinct_new = {bytes(r.new_spk) for r in candidates}
            if len(distinct_new) > 1:
                return None

            # Same-seq duplicates with the same new_spk are harmless
            # duplication; a publisher might reissue a record with the
            # same data. Pick the lowest-seq candidate — ties on seq
            # pick the first one. We reject seq regressions below.
            candidates.sort(key=lambda r: r.seq)
            # Repeat-seq with the SAME new_spk: pick one, advance. Two
            # rotations from the same head with different new_spks at
            # the same seq has already been caught by the len(distinct_new)
            # check above.
            rot = candidates[0]

            # 5a. Sequence monotonicity. Seq numbers must strictly
            # increase along the walk. A regression or repeat means a
            # publisher typo or a replay attack; either way, abort.
            if last_seq is not None and rot.seq <= last_seq:
                return None
            last_seq = rot.seq

            # 5b. Revocation of the next-hop key.
            next_spk = bytes(rot.new_spk)
            if next_spk in revoked_spks:
                return None

            # 5c. Cycle detection (a revocation-free cycle is structurally
            # impossible given monotonic seq, but belt-and-suspenders
            # against an attacker who somehow gets monotonic seq to bend).
            if next_spk in visited:
                return None
            visited.add(next_spk)

            head = next_spk

        # Reached max_hops without finding the chain end. Refuse to walk
        # blindly past the bound — a legitimate chain of 4 rotations in
        # one polling window is already unusually active.
        # Exception: if head has NO further rotations (we reached max_hops
        # EXACTLY at the tail), we would've returned inside the loop via
        # the `candidates not found` branch. So reaching here means there
        # IS a hop available but we exhausted our budget. Abort trust.
        candidates = by_old.get(head, [])
        if not candidates:
            return head
        return None

    # ---- helpers ----------------------------------------------------------

    def _derive_rrset_name(self, subject: str, subject_type: int) -> Optional[str]:
        """Map (subject_type, subject) → rotation RRset owner name.

        Uses the publishing convention from ``dmp.core.rotation``.
        Returns None on unknown subject_type. Callers that fetched the
        RRset themselves (e.g. because they published under an unusual
        name) should pass ``rrset_name=`` directly to ``resolve_current_spk``.
        """
        try:
            if subject_type == SUBJECT_TYPE_USER_IDENTITY:
                # user@host form
                if "@" not in subject:
                    return None
                user, _, host = subject.partition("@")
                return rotation_rrset_name_user_identity(user.strip(), host.strip())
            if subject_type == SUBJECT_TYPE_CLUSTER_OPERATOR:
                return rotation_rrset_name_cluster(subject)
            if subject_type == SUBJECT_TYPE_BOOTSTRAP_SIGNER:
                return rotation_rrset_name_bootstrap(subject)
        except ValueError:
            return None
        return None

    def _partition(
        self,
        records: List[str],
        subject: str,
        subject_type: int,
    ) -> Tuple[List[RotationRecord], List[RevocationRecord]]:
        """Verify + filter records by subject match. Drop junk silently.

        A single corrupt record in a valid RRset must not prevent the
        walk from succeeding — the caller gets only the verified subset.
        """
        rotations: List[RotationRecord] = []
        revocations: List[RevocationRecord] = []
        norm_subject = _normalize_subject(subject_type, subject)

        for txt in records:
            if not isinstance(txt, str):
                continue
            if txt.startswith(RECORD_PREFIX_ROTATION):
                rot = RotationRecord.parse_and_verify(txt)
                if rot is None:
                    continue
                if rot.subject_type != subject_type:
                    continue
                if _normalize_subject(rot.subject_type, rot.subject) != norm_subject:
                    continue
                rotations.append(rot)
            elif txt.startswith(RECORD_PREFIX_REVOCATION):
                rev = RevocationRecord.parse_and_verify(txt)
                if rev is None:
                    continue
                if rev.subject_type != subject_type:
                    continue
                if _normalize_subject(rev.subject_type, rev.subject) != norm_subject:
                    continue
                revocations.append(rev)
            # Anything else (slot manifests, identity records, etc.) is
            # ignored — the rotation RRset is dedicated to rotation +
            # revocation content per the publishing convention, but a
            # buggy publisher adding unrelated records must not break us.

        return rotations, revocations
