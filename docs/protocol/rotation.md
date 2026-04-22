---
title: Key rotation + revocation
layout: default
parent: Protocol
nav_order: 7
---

# Key rotation and revocation records (M5.4)
{: .no_toc }

> **DRAFT — subject to auditor feedback.**
>
> This spec ships ahead of the external cryptographic audit scheduled
> for the post-`v0.2.0-beta` certification backlog. The wire types
> `v=dmp1;t=rotation;` and `v=dmp1;t=revocation;` are provisional. If
> the audit recommends structural changes, `v0.3.0` will introduce a
> breaking `v=dmp2;t=rotation;` replacement. Implementers SHOULD treat
> this page as a reference for the current Python implementation, not
> as a frozen interop contract.
>
> Every CLI surface that publishes or consumes rotation records is
> guarded behind an explicit `--experimental` flag or a
> `rotation_chain_enabled=True` constructor kwarg; neither is set by
> default. Legacy clients are byte-identical to the pre-M5.4 behavior.

1. TOC
{:toc}

## 1. Purpose and threat model

Three rotation scenarios motivate this module:

1. **User identity key rotation** — Alice derives a new X25519/Ed25519
   pair from a new passphrase and wants every pinned contact to follow
   over to the new key without a manual re-pin round trip.
2. **Cluster operator key rotation** — the operator rotates the Ed25519
   key that signs the cluster manifest (`cluster.<base>` TXT) and the
   cluster's clients need to pick up the new key without a flag day.
3. **Bootstrap zone signer rotation** — the zone operator rotates the
   Ed25519 key that signs the `_dmp.<user_domain>` bootstrap record.

A naive approach — "just publish a new IdentityRecord with the new
key" — fails for every pinned contact: a pinned contact trusts the
*old* signing key, so an unsigned swap is indistinguishable from an
attacker publishing a new IdentityRecord at the same DNS name. The
contact correctly rejects the new record. M5.4 solves this by
publishing a signed, co-signed *succession statement* that links old
to new.

### 1.1 Attacker capability model

- **Network-observer.** Sees every published TXT record. Cannot mint
  Ed25519 signatures for keys it does not hold.
- **DNS publisher.** Can write arbitrary TXT records at owner names
  under its control (the user's zone, the cluster's zone). Cannot
  silently delete records from competitors — DMP uses append-semantics
  stores on the node side (see [cluster.md](cluster.md)).
- **One-key compromise.** Either the *old* or the *new* key is
  compromised, but not both simultaneously. The co-signing requirement
  below is designed around this adversary.
- **Not modelled.** Both keys compromised simultaneously, zone
  operator fully hostile (they can always publish an attacker
  IdentityRecord under their zone), DNS resolver MITM on a single
  query (hide behind DNSSEC or the resolver pool).

## 2. Wire format

Both record types follow the hardened pattern established by
`ClusterManifest` and `BootstrapRecord`: an ASCII prefix, a base64'd
`body || sig(s)` trailer, with a trailing 64-byte Ed25519 signature
(two signatures, for `RotationRecord`).

### 2.1 `RotationRecord` — `v=dmp1;t=rotation;`

```
magic:              b"DMPROT1"              (7 bytes)
subject_type:       uint8                   (1 byte)
subject_len:        uint8                   (1 byte)
subject:            utf-8 bytes             (var, <= 64)
old_spk:            32 bytes                (Ed25519 key being rotated FROM)
new_spk:            32 bytes                (Ed25519 key being rotated TO)
seq:                uint64 big-endian       (8 bytes; strictly increasing along a chain — see §2.1.1)
ts:                 uint64 big-endian       (8 bytes; unix epoch seconds)
exp:                uint64 big-endian       (8 bytes; unix epoch seconds)

sig_old:            64 bytes                (Ed25519(body) by old_spk)
sig_new:            64 bytes                (Ed25519(body) by new_spk)
```

Total overhead: 7 + 1 + 1 + 32 + 32 + 8 + 8 + 8 + 64 + 64 = 225 bytes
plus the subject (variable, 1..64 bytes). Well under the 1200-byte
`MAX_WIRE_LEN` cap.

`subject_type` is one of:

| Value | Meaning                          | Subject format                          |
|-------|----------------------------------|-----------------------------------------|
| `1`   | `SUBJECT_TYPE_USER_IDENTITY`     | `"user@host"` (e.g. `alice@example.com`) |
| `2`   | `SUBJECT_TYPE_CLUSTER_OPERATOR`  | DNS name of the cluster base (e.g. `mesh.example.com`) |
| `3`   | `SUBJECT_TYPE_BOOTSTRAP_SIGNER`  | DNS name of the user domain (e.g. `example.com`) |

**Body ordering note.** `old_spk` comes before `new_spk` in the body.
The rationale is "prove you authorized leaving the old identity, then
prove you're the one picking up the new one" — left-to-right the body
reads as a chronological succession. Both orderings would verify; this
one is documented so auditors can reason about ordering-dependent
attacks without first reverse-engineering the intent.

#### 2.1.1 `seq` is millisecond-resolution unix time

The reference CLI sets `seq = int(time.time() * 1000)` — that is,
milliseconds since the unix epoch. It is a monotonic ordering number
that happens to be clock-derived; it is **not** a wall-clock
timestamp. The wall-clock timestamp is `ts` (seconds since epoch).

Motivation: the chain walker requires `seq` to **strictly** increase
between hops (see §5). A second-resolution `seq` would make two
rotations fired within the same wall-clock second collide — the
second rotation's hop would be rejected, and contacts would not
follow to the new key without re-pinning manually. Millisecond
resolution gives >1000 distinct values per second, which is more
than sufficient for test re-rotations, scripted disaster recovery
cutovers, and any other rapid-fire scenarios. uint64 ms epoch does
not overflow until the year ~292M, which is acceptable headroom.

A third-party publisher is free to use any monotonically-increasing
uint64 for `seq` — a store-backed counter, hybrid logical clock, etc.
The wire format places no semantics on `seq` beyond "strictly
increases along a chain"; the ms-epoch choice is a policy decision
inside the reference CLI.

### 2.2 `RevocationRecord` — `v=dmp1;t=revocation;`

```
magic:              b"DMPRV01"              (7 bytes)
subject_type:       uint8                   (1 byte)
subject_len:        uint8                   (1 byte)
subject:            utf-8 bytes             (var, <= 64)
revoked_spk:        32 bytes                (Ed25519 key being revoked)
reason_code:        uint8                   (1 byte)
ts:                 uint64 big-endian       (8 bytes)

sig:                64 bytes                (Ed25519(body) by revoked_spk)
```

`reason_code` values:

| Value | Meaning                    | Client behavior                            |
|-------|----------------------------|--------------------------------------------|
| `1`   | `REASON_COMPROMISE`        | Most urgent; chain walk aborts immediately.|
| `2`   | `REASON_ROUTINE`           | Replacement is already published.          |
| `3`   | `REASON_LOST_KEY`          | See §7 — self-sign limitation applies.     |
| `4`   | `REASON_OTHER`             | Unspecified; treated as compromise.        |

## 3. Co-signing rationale

A legitimate rotation requires the authorization of **both** keys:

```
sig_old = Ed25519(body, old_spk_private)
sig_new = Ed25519(body, new_spk_private)
```

Neither signature alone is sufficient. This blocks two otherwise-
plausible attacks:

**Attack A: attacker has only the new key.** They construct a
`RotationRecord` from some legitimate `old_spk` to their
attacker-controlled `new_spk`. They cannot produce `sig_old`. Record
is rejected.

**Attack B: attacker has only the recently-compromised old key.**
They construct a rotation from `old_spk` to an attacker-chosen new
key. They can produce `sig_old` but not `sig_new` for the
attacker-chosen new key — wait, they control the new key, so they CAN
sign with it. But the real user would never independently sign a
rotation to that attacker-chosen new key. So the attacker's co-signed
record is a valid rotation *from the attacker's point of view*
(both keys they hold consent). This is why the threat model explicitly
names "recently compromised" for the old key: a fully-compromised old
key is effectively revoked already.

What co-signing blocks in Attack B is the *interleaved* scenario: the
real user rotates to `new_spk` while the attacker has a stolen copy
of `old_spk`. Without co-signing, the attacker could post their own
competing `RotationRecord` picking a different destination; clients
walking the chain would face an ambiguous fork. With co-signing, the
attacker also needs access to a new_spk they can coax into signing —
and by construction, they don't have the real user's new_spk and the
real user would never sign for an attacker-picked one.

Prior art:

- Signal's **Safety Numbers / double-check on key change** prompt the
  user when a contact's identity key rotates, surfacing it rather than
  auto-trusting it. DMP's co-sign + chain-walk is the programmatic
  analogue: the walk lets auto-trust happen only when both old + new
  authorize the succession.
- **GPG key transition statements** ask the user to sign a statement
  with *both* the old and new keys saying "this new key is me". DMP
  formalizes that same construction in a wire record.

## 4. DNS publishing convention

Rotation and revocation records are published at well-known names
derived from the subject:

| Subject type       | RRset name                                |
|--------------------|-------------------------------------------|
| User identity      | `rotate.dmp.<hash16(username)>.<user_domain>` (matches `identity_domain`'s hash scheme) |
| User identity, zone-anchored | `rotate.dmp.<identity_domain>` (matches `zone_anchored_identity_name`) |
| Cluster operator   | `rotate.cluster.<cluster_base_domain>`    |
| Bootstrap signer   | `rotate._dmp.<user_domain>`               |

The RRset at each name holds BOTH rotation AND revocation records for
that subject. Clients fetch once, partition by prefix
(`RECORD_PREFIX_ROTATION` vs `RECORD_PREFIX_REVOCATION`), then walk
rotations from the pinned key forward while cross-checking every step
against the revocations list.

**Append-semantics required.** The rotation RRset is meant to grow
over time (old rotations stay visible so a slow-polling contact can
still trace the chain from their outdated pin to the current head).
DMP node-side stores honor append semantics by default; a publisher
that deletes old rotations is a liveness problem, not a correctness
problem — the walk fails closed.

**Do not publish unrelated rotations at the same name.** The append
store can technically hold multiple subjects; clients MUST drop any
record whose `subject` doesn't match the expected subject during the
walk. Implementations are free to reject on parse a mismatched
subject (the reference implementation does).

## 5. Client walk algorithm

The reference client (`dmp.client.rotation_chain.RotationChain`)
implements this algorithm; see module docstring for the canonical
source. Pseudo code:

```
resolve_current_spk(pinned_spk, subject, subject_type, max_hops=4):
    records = reader.query(derive_rrset(subject, subject_type))
    if not records: return None                          # caller falls back to pinned

    rotations, revocations = [], []
    for r in records:
        if r starts with "v=dmp1;t=rotation;":
            rot = RotationRecord.parse_and_verify(r)     # verifies BOTH sigs
            if rot and subjects_match(rot, subject, subject_type):
                rotations.append(rot)
        elif r starts with "v=dmp1;t=revocation;":
            rev = RevocationRecord.parse_and_verify(r)
            if rev and subjects_match(rev, subject, subject_type):
                revocations.append(rev)

    revoked = {rev.revoked_spk for rev in revocations}
    if pinned_spk in revoked: return None                # abort trust

    by_old = {rot.old_spk: [rotations from that old_spk]}
    head = pinned_spk
    visited = {head}
    last_seq = None
    for hop in range(max_hops):
        candidates = by_old.get(head, [])
        if not candidates:
            return None if hop == 0 else head            # tail reached

        distinct_new = {c.new_spk for c in candidates}
        if len(distinct_new) > 1: return None            # ambiguous fork

        rot = min(candidates, key=lambda c: c.seq)
        if last_seq is not None and rot.seq <= last_seq:
            return None                                   # seq regression/repeat
        last_seq = rot.seq

        if rot.new_spk in revoked: return None           # mid-chain revocation
        if rot.new_spk in visited: return None           # cycle
        visited.add(rot.new_spk)
        head = rot.new_spk

    # max_hops exhausted. Only return head if no further hop is pending.
    return head if not by_old.get(head) else None
```

### 5.1 Ambiguous-fork handling

The reference implementation aborts the walk whenever two rotations
from the same `old_spk` specify **different** `new_spk` values —
regardless of their `seq` values. A "higher seq wins" tiebreaker would
create a race attackers could exploit: the attacker posts their
malicious rotation with seq+1 and wins the head.

Two rotations with the **same** `old_spk`, **same** `new_spk`, and
**same** `seq` are treated as innocent duplicates (a publisher may
reissue the record). The walk accepts them.

### 5.2 `max_hops` bound

A legitimate chain is short — 1 or 2 hops per year for routine
rotation, briefly more if a key is compromised. The default bound is
`max_hops=4`. A longer chain is either a compromise artifact (the user
had to rotate three times in quick succession), a legitimate slow
consumer catching up years of rotations (uncommon enough to require a
CLI override), or an attacker-constructed chain trying to exhaust
resolver time. Walking past the bound fails closed — the caller must
re-pin out-of-band.

## 6. Revocation model

Revocations are **self-signed by the revoked key itself**. This is
weaker than a designated-revocation-key approach. Two explicit
limitations the audit is asked to review:

1. **A compromised key can forge its own revocation.** An attacker
   who learned `revoked_spk`'s secret can sign a plausible-looking
   revocation — with whatever reason and timestamp they want. The
   client has no cryptographic way to distinguish the real user's
   revocation from the attacker's. Mitigation: the client aborts trust
   on *any* valid revocation of the pinned key (§5), so an attacker
   can only *forbid* traffic, not redirect it.
2. **A lost key cannot self-revoke.** If the user loses
   `revoked_spk`'s secret (passphrase forgotten, device wiped, cloud
   backup gone), no legitimate revocation can be produced. The
   reference implementation still accepts `reason_code=3` (lost key) on
   the wire because an operator might hold an out-of-band backup; in
   practice, the user must publish the loss via a separate channel
   (blog post, signed notice on another account) and contacts must
   re-pin manually.

Both limitations are known and accepted for v1. A natural v2 evolution
is to add a **designated revocation key** field to `IdentityRecord`
(declared at identity creation, rotated into via the same mechanism as
the main key). The audit is expected to evaluate whether to mandate
that evolution as part of the breaking `v=dmp2` bump.

### 6.1 Freshness window

`RevocationRecord.parse_and_verify` enforces a
`max_age_seconds` (default: one year). Revocations older than the
window are dropped. This bounds how long an attacker can replay a
stale revocation of the real user's key against a newly-joining
client. Callers that need indefinite revocation (forensic tools) can
pass a much larger value.

A 300-second positive clock drift is tolerated on the `ts` field.
Revocations with `ts` more than 300 s in the future are rejected —
otherwise an attacker with skewed clocks could extend the freshness
window arbitrarily.

## 7. Audit scope

The external cryptographic audit is asked to review, at minimum:

1. **Co-sign ordering.** Body puts `old_spk` before `new_spk`. Does the
   ordering enable any bind-to-wrong-key attack? Could a future
   `v=dmp2` benefit from a merkle-tree construction that permits O(1)
   membership proofs for multi-hop chains?
2. **Chain-length attacks.** `max_hops=4` is the default. Is this too
   permissive? Too restrictive? Can an attacker who controls a zone
   still exhaust client resources with sub-bound chains?
3. **Rotation-vs-revocation ordering.** If a rotation and a revocation
   of the SAME key arrive in the same RRset, we abort trust. Is this
   correct under all scenarios? (It is for compromise; for routine
   rotation the replacement is the non-revoked successor — but we
   still abort, because the client cannot distinguish routine from
   compromise without trusting the signer of the revocation, who is
   the same keyholder as the rotator.)
4. **Cross-layer attacks.** User rotation (subject_type 1) does not
   directly interact with cluster rotation (subject_type 2) or
   bootstrap signer rotation (subject_type 3). Are there indirect
   interactions — e.g. an attacker who takes over a cluster operator
   key can publish a fresh IdentityRecord for any user under the
   cluster's zone — that the current design handles correctly?
5. **Expiry drift.** `RotationRecord.exp` defaults to 1 year; the
   client drops expired rotations from the walk. Does this fail-open
   on a long-offline client in a bad way? (The walk ignores expired
   rotations, treating them as absent. The effect is that a long-
   offline client sees no chain and falls back to the pinned key —
   which is the same "safe" failure mode as no rotation ever
   happening, so no; but the audit should confirm.)
6. **Designated-revocation-key migration path.** If the audit
   recommends upgrading revocation to a designated-key scheme, is the
   current wire format forward-compatible via a `v=dmp2` bump, or
   does the rotation record itself need to gain an upfront
   "designated revoker" field?

## 8. CLI integration scope in M5.4

Only **user identity rotation** has a CLI subcommand in M5.4:

```
dmp identity rotate --experimental [--new-passphrase-file <path>] [--yes]
```

- Without `--experimental`, the command errors out with a clear
  message pointing at the audit caveat.
- The command prompts for the current passphrase (or reads via
  `DMP_PASSPHRASE`), loads the NEW passphrase from
  `--new-passphrase-file` or `DMP_NEW_PASSPHRASE`, derives both
  identities using the SAME kdf_salt from config, then co-signs and
  publishes the RotationRecord plus a fresh IdentityRecord for the
  new key.
- The on-disk identity is **not** rotated automatically. This is
  deliberate: until all pinned contacts are known to have migrated
  (manually re-pinned or rotation-chain-enabled), the user still needs
  the old passphrase to send with the key their contacts trust. Manual
  step: re-run `dmp init --force` with the new passphrase once the
  migration is complete.

**Cluster operator and bootstrap-signer rotation** have a wire format
and a reference parser but no dedicated CLI subcommand in M5.4. An
operator who wants to rotate those keys today can construct a
`RotationRecord` with subject_type 2 or 3 via a small Python script
and publish it through the normal DNS-update path. Dedicated CLI
plumbing for those subject_types is deferred to v0.3.0, when the
audit feedback lands. Publishing the wire format now — even without
CLI — lets the audit review the protocol uniformly.

## 9. Interop

Canonical test vectors live at
[vectors/rotation_record.json](vectors/rotation_record.json) and
[vectors/revocation_record.json](vectors/revocation_record.json). Each
file carries round-trip + signature-failure + expired / stale cases
generated deterministically by `vectors/_generate.py`. Third-party
implementations verify by reproducing the `expected_wire_hex` bytes
from the structured `inputs` and the named seed.

## 10. Related reading

- [spec.md](spec.md) — protocol overview, record-type registry.
- [wire-encoding.md](wire-encoding.md) — base64 + signature layout
  shared across all signed record types.
- [identity.md](../identity.md) — the `IdentityRecord` wire format
  that rotation chains reference in the user-identity subject_type.
- [cluster.md](cluster.md) — the `ClusterManifest`; rotation of the
  operator signing key lives at `rotate.cluster.<base>` per §4.
- [bootstrap.md](bootstrap.md) — the `BootstrapRecord`; zone-signer
  rotation lives at `rotate._dmp.<user_domain>` per §4.
