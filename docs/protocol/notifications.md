---
title: Notifications (M10)
layout: default
parent: Protocol
nav_order: 8
---

# Notifications — receiver-zone claim records (M10)
{: .no_toc }

A protocol-level mechanism for receivers to learn that they have new
mail without polling every pinned contact's zone on every tick. The
sender writes a tiny signed pointer ("claim") to the receiver's home
node alongside the actual chunks on the sender's own zone. The
receiver's home node becomes the canonical "any new mail for me?"
lookup. No new HTTP between operators; no push primitive. Pure DNS,
end-to-end signed, best-effort.

This page is the wire-level + operational spec.

1. TOC
{:toc}

## Status and milestone

- **Spec milestone:** M10
- **Builds on:** M8.2 `ClaimRecord` wire format ([`dmp/core/claim.py`](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/dmp/core/claim.py)),
  M8.3 un-TSIG'd UPDATE accept path on claim providers,
  M9 DNS-native federation.
- **Wire format change:** none (reuses the M8.2 `DMPCL01` claim wire).
- **Behavior change:** sender emits a claim per send (was: only on
  first-contact reach). Receiver's primary read path becomes
  "poll own zone for claims," with the per-contact slot walk
  retained as fallback.

## Purpose

Today's M9 receive flow walks each pinned contact's zone for ten
mailbox slots every tick. With *N* pinned contacts and a *T*-second
poll interval, that's `N × 10 / T` queries per second steady state,
the bulk of which return empty. M10 collapses the steady-state cost
to roughly one query per tick, plus one fetch per actual incoming
message.

The mechanism is a deliberate generalization of the existing M8.2
claim layer. M8.2 was designed for *first-contact reach*: an unpinned
sender drops a tiny signed pointer at a shared claim-provider zone so
the recipient's intro queue can find it. M10 applies the same
mechanism, with one routing change: the claim is published at the
**recipient's own home node** rather than at a shared provider. Both
modes coexist; neither replaces the other.

The two modes serve different purposes:

| Mode | Owner-name pattern | Purpose |
|---|---|---|
| **M8.2 first-contact** | `claim-{N}.mb-{hash12}.<provider-zone>` | Unpinned-stranger reach. Recipient discovers the claim via the shared provider tier. |
| **M10 receiver-zone** | `claim-{N}.mb-{hash12}.<recipient-zone>` | Pinned-contact wake-up signal. Recipient queries own zone for any pending claims. |

A sender MAY publish to both. A recipient SHOULD poll both. The
underlying record is byte-identical.

## Wire format

Reuses the M8.2 `DMPCL01` claim record. No format change. From
[`dmp/core/claim.py`](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/dmp/core/claim.py):

```
RECORD_PREFIX  = "v=dmp1;t=claim;"
body layout (all integers big-endian):
    magic                     b"DMPCL01"   7 bytes
    msg_id                    uuid4        16 bytes
    sender_spk                Ed25519 pk   32 bytes
    sender_mailbox_domain_len uint8        1 byte
    sender_mailbox_domain     utf-8        var, 1..43 bytes
    slot                      uint8        1 byte (0..9)
    ts                        uint64       8 bytes (unix seconds)
    exp                       uint64       8 bytes (unix seconds)
    signature                 Ed25519      64 bytes (over body)
```

`signature` is computed by the sender over the entire body bytes
preceding it. Verified by the recipient using `sender_spk` (which
must match a pinned contact's signing key).

Reused unchanged so existing parsers, signers, and verifiers work
without modification.

## Owner-name conventions

```
claim-{slot}.mb-{hash12(recipient_id)}.<recipient-zone>
```

Where:

- `{slot}` is the message slot (0..9), matching the chunk-publish
  slot on the sender's own zone (`slot-{N}.mb-...`).
- `{hash12(recipient_id)}` is the first 12 hex chars of
  `sha256(recipient_id)`. Provides recipient-keyed scoping without
  putting the full 32-byte hash in the owner name.
- `<recipient-zone>` is the served zone of the recipient's home
  node (e.g. `dmp.dnsmesh.pro`).

The recipient's home node MUST be authoritative for `<recipient-zone>`.
The DNS chain finds it via the same NS records that delegate the
zone to the dnsmesh-node.

For comparison, the M8.2 first-contact form is identical except the
suffix is `<provider-zone>` instead of `<recipient-zone>`.

## Sender behavior

After a successful chunk-and-manifest publish to the sender's own
zone, the CLI MUST attempt a claim publish to the recipient's
zone.

```
1. dnsmesh send bob@dmp.dnsmesh.pro "msg"
2. CLI builds + signs SlotManifest, writes manifest + chunks to
   slot-{N}.mb-{hash12(bob_id)}.dmp.dnsmesh.io        (own zone, TSIG)
3. CLI builds + signs ClaimRecord, writes to
   claim-{N}.mb-{hash12(bob_id)}.dmp.dnsmesh.pro      (bob's zone, un-TSIG'd)
4. (Optional) CLI also writes a first-contact claim to
   claim-{N}.mb-{hash12(bob_id)}.<provider-zone>      (M8.2, for unpinned)
```

The recipient's zone is derived from the contact's persisted
`domain` field (already stored by `dnsmesh identity fetch
user@host --add`).

Step 3 is **best-effort.** Failures (recipient's node unreachable,
opt-out, rate-limited, refused) MUST NOT block the send — the chunks
already landed at the sender's zone, and the recipient's slot-poll
fallback covers the missed notification within one fallback
interval. The CLI logs the outcome for operator visibility but
exits 0 on partial success.

Routing target: the un-TSIG'd UPDATE goes to the recipient zone's
apex hostname on the configured DNS port (53 in production, override
via `DMP_PROVIDER_DNS_PORT` for dev). The reference implementation
piggybacks on the existing `_provider_dns_target` helper, which
prefers an explicit endpoint URL host when given and falls back to
zone-as-host otherwise; M10 sends pass an empty endpoint so the
zone apex is always used.

Same-zone deployments (sender + recipient share a home node) SHOULD
skip the M10 publish entirely. Phase 2's slot walk on the own zone
(which is also the recipient's zone in this case) already covers
delivery without an extra round-trip, and an M10 publish here
would write a claim record into the SENDER's own zone where neither
the sender's own recv (different hash12) nor the recipient's
cross-zone recv ever queries it. The reference implementation
gates on `contact.domain != self.domain`. This also covers the
legacy back-compat case where pre-M5.4 contacts without a stored
domain are backfilled to the local effective domain at client-build
time — those contacts MUST NOT trigger an M10 publish to the
sender's own zone.

Cross-zone publishes (the M10 happy path) MUST go through the
un-TSIG'd UPDATE path so the recipient's home node enforces the
`DMP_RECEIVER_CLAIM_NOTIFICATIONS` opt-in gate AND the per-recipient
rate limit. A library caller that supplies an authorized writer
override MUST NOT bypass that path: the writer override is a test
escape hatch for in-process fixtures, not a production contract.

**Routing limitation (split-host deployments).** The current routing
target derivation (zone apex on the configured DNS port) assumes
the recipient's home node serves DNS at the zone apex. Operators
running a split-host setup — zone delegated via NS records to a
different hostname — are not yet supported by the M10 publish path;
the un-TSIG'd UPDATE will fail to find a destination IP and the
sender's slot-walk fallback (phase 2) covers delivery instead.
A follow-up will add NS-chain or per-contact endpoint resolution.

Implementation note: the existing
[`_publish_claim_via_dns_update`](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/dmp/client/client.py)
helper already handles this exact UPDATE shape; M10 adds a second
call with the recipient's zone as `target` and `provider_zone`.

## Receiver behavior

Two-phase poll, replacing the single-phase "walk all contact zones"
loop.

### Phase 1 — Primary (claim-poll on own zone)

Every `T_primary` seconds (default: 30):

```
query claim-{0..9}.mb-{hash12(self.user_id)}.<own-zone>  TXT
for each ClaimRecord c returned:
    verify c against any pinned contact's signing key
    if c verifies AND c.exp > now AND c.ts within ts_skew:
        if msg_id seen in replay cache: drop (no-op)
        else:
            fetch slot-{c.slot}.mb-{hash12(self.user_id)}.{c.sender_mailbox_domain}
            (existing per-message receive flow continues from here)
```

Claims that fail signature verification (sender_spk doesn't match
any pinned contact) are NOT auto-pinned. They land in the
quarantined intro queue (M8.3) and surface via `dnsmesh intro list`.

### Phase 2 — Secondary (slot walk on contact zones)

Every `T_secondary` seconds (default: 600 — every 10th primary
tick by default):

```
for each pinned contact c in cfg.contacts:
    query slot-{0..9}.mb-{hash12(self.user_id)}.{c.domain}  TXT
    for each manifest m returned:
        if msg_id seen in replay cache: drop (no-op)
        else: fetch chunks, decrypt, deliver
```

Phase 2 is the existing M9 receive path, run less frequently as a
defense-in-depth fallback. It catches:

- Senders whose claim publish failed (recipient's node was offline
  at send time).
- Senders running pre-M10 clients that don't emit claims.
- Recipient's home node operator silently dropping incoming claims.

The replay cache keyed on `(sender_spk, msg_id)` ensures a message
delivered through phase 1 isn't redelivered when phase 2 finds the
same manifest later.

### Orthogonal: M8.3 first-contact claim_providers

The M8.3 first-contact provider channel (`claim_providers` poll on a
shared provider tier) is independent of the M10 phase-1/phase-2
split and MUST run on every receive pass regardless of which phase
toggles are set. Phase 1 is the M10 own-zone latency optimization;
phase 2 is the M9 slot-walk fallback; the provider channel is the
M8.3 stranger-reach surface. Disabling phase 1 or phase 2 (whether
via `--primary-only`, `--skip-primary`, or
`recv_secondary_disable=true`) MUST NOT silently turn off
first-contact discovery — an unpinned-stranger intro that arrives
through a shared provider tier still needs to land in the intro
queue. The reference implementation polls all configured
`claim_providers` after the phase-2 slot walk, before returning to
the caller.

### Tunable cadence

| Config field | Default | Purpose |
|---|---|---|
| `recv_primary_interval_seconds` | `30` | Phase 1 cadence. |
| `recv_secondary_interval_seconds` | `600` | Phase 2 cadence (slot walk). |
| `recv_secondary_disable` | `false` | Set to `true` to skip phase 2 entirely (high-trust deployments where the receiver's home node is fully trusted). |

A receiver running phase 1 only with `recv_secondary_disable=true`
loses defense-in-depth but minimizes query overhead — appropriate
for a node operator running their own home node.

The persisted `recv_secondary_disable=true` knob MUST respect the
[pure-TOFU phase-1 skip rule](#receiver-migration). On a fresh
install or any config with zero pinned signing keys, the knob
becomes a no-op (phase 2 stays enabled) so legacy callers without
any pin still deliver signature-valid manifests to the inbox. Once
the user pins any contact, the knob engages and short-circuits to
phase 1 only. Implementations MAY surface a one-line diagnostic
when the knob is configured but the no-op condition holds, so the
operator can tell the knob is currently inert.

## Server config

The recipient's home node must accept un-TSIG'd UPDATE writes
under `claim-*.mb-*.<own-served-zone>`. The exact same mechanism
already exists for M8.3 claim providers; M10 enables it for every
served zone the node owns.

| Env var | Default | Purpose |
|---|---|---|
| `DMP_RECEIVER_CLAIM_NOTIFICATIONS` | `0` | Set to `1` to accept M10 claims for users on this node's served zone. |
| `DMP_CLAIM_PROVIDER` | `0` | Unchanged. M8.3 first-contact provider role. |
| `DMP_CLAIM_RATE_PER_USER_PER_SEC` | `0.5` | Per-recipient-hash rate limit on un-TSIG'd claim writes. |
| `DMP_CLAIM_RATE_BURST` | `30` | Burst allowance paired with the above. |
| `DMP_CLAIM_MAX_AGE_SECONDS` | `86400` | Maximum `exp - now` accepted at write time. |

A node MAY enable both `DMP_RECEIVER_CLAIM_NOTIFICATIONS` and
`DMP_CLAIM_PROVIDER` simultaneously — the two roles operate on
disjoint owner-name patterns (provider role uses
`<provider-zone>`, receiver role uses `<own-zone>`).

The per-recipient rate limit (`DMP_CLAIM_RATE_PER_USER_PER_SEC` /
`DMP_CLAIM_RATE_BURST`) is keyed on the `hash12` extracted from the
incoming owner name and applies uniformly to **both** un-TSIG'd
claim surfaces (M8.3 first-contact provider AND M10 receiver-zone).
A single noisy sender targeting one recipient cannot burn the whole
zone's budget; legitimate cross-recipient traffic is unaffected.

The `claim-*.mb-*.<own-zone>` accept path enforces the same
record-shape validation as the M8.3 path:

1. Owner name MUST match `claim-{slot}.mb-{hash12}.<served-zone>`.
2. Wire MUST start with `v=dmp1;t=claim;` and decode to a valid
   `DMPCL01` body.
3. Ed25519 signature over body MUST verify under the embedded
   `sender_spk`.
4. `ts` MUST be within ±5 minutes of server time.
5. `exp` MUST be ≤ `DMP_CLAIM_MAX_AGE_SECONDS` from server time.
6. Per-recipient rate limit (token bucket) MUST allow.

Out-of-pattern writes (any other owner name under the served zone,
DELETE ops, missing/bad signature) are REFUSED. Rate-limit
exhaustion returns SERVFAIL with a logged INFO event.

## CLI surface

### `dnsmesh recv` defaults

The default flow runs phase 1 + phase 2 with the cadence above.
Backwards compatible: a CLI built before M10 and a CLI built
after M10 will both deliver every message correctly. The post-M10
CLI is just faster on average.

### Diagnostic flags

| Flag | Purpose |
|---|---|
| `dnsmesh recv --primary-only` | Run phase 1 only. Diagnoses primary-path latency in isolation. |
| `dnsmesh recv --skip-primary` | Run phase 2 only. Diagnoses missed claims (compare delivered set against `--primary-only`'s set). |

`dnsmesh recv` is a one-shot per invocation; cadences in the
[Tunable cadence](#tunable-cadence) table are consumed by external
schedulers (cron, systemd timers) calling `dnsmesh recv` and
`dnsmesh recv --skip-primary` at different rates. A persisted
`recv_secondary_disable=true` short-circuits to the same behavior
as `--primary-only` so a high-trust deployment doesn't have to
re-pass the flag on every invocation.

### Visibility

`dnsmesh contacts list` MAY annotate each contact with its
last-delivered path (`primary` / `secondary`) and last-delivered
timestamp, so an operator can spot a contact whose primary path
is consistently failing.

## Failure modes

| Failure | What happens | Recovery |
|---|---|---|
| Sender's claim UPDATE fails (recipient's node down / refusing / rate-limited) | Chunks landed on sender's zone. No notification at recipient. | Recipient's phase-2 slot walk delivers the message within `recv_secondary_interval_seconds` (default 10 min). |
| Recipient's home node operator silently drops a claim | Recipient never sees it via phase 1. | Phase 2 slot walk delivers from sender's zone. |
| Recipient's home node is fully unreachable | Phase 1 returns nothing. | Phase 2 still works via public DNS to sender's zones. |
| Sender's auth zone is unreachable when recipient fetches | Recipient sees the claim via phase 1 but can't fetch chunks. | Recipient's CLI surfaces a "pending — can't reach sender's zone" entry; retries on next tick. |
| Replay attack (claim re-injected) | First arrival delivers. Subsequent duplicates dedupe at the replay cache. | Automatic. |
| Forgery attempt (claim with wrong signature) | Server REFUSES at write time. | Automatic. |
| Cross-recipient replay (claim rebroadcast at wrong recipient hash) | Recipient hash12 doesn't match; recipient never queries that name. | Automatic. |

The protocol is designed so **the worst any actor can do is delay
or block delivery, never substitute a wrong message.** This holds
both at the network layer (sigs gate forgery) and at the operator
layer (the chunks are signed too; lying operators get caught at
the manifest-verify step).

## Compatibility and migration

### Wire compatibility

`DMPCL01` is unchanged. Any client or server that handles M8.2
claims handles M10 claims byte-identically. The only difference
is the routing target.

### Sender migration

A pre-M10 sender that doesn't emit claims to the recipient's
zone is fully interoperable. Recipients fall through to phase 2,
which is the existing M9 receive path. Senders see no behavioral
change beyond the second UPDATE call per send.

### Receiver migration

A pre-M10 receiver that doesn't run phase 1 misses the latency
improvement but doesn't miss any messages. Phase 2 is the
existing M9 receive path.

**Pure-TOFU receivers** (zero pinned signing keys — the legacy
default before any contact has been added) MUST skip phase 1 even
when both flags would otherwise enable it. The M8.3 claim path
deposits non-pinned senders into the intro queue, which is the
correct behavior for first-contact-via-provider; but in pure
TOFU mode the M9 receive contract is "trust any signature-valid
manifest, deliver to the inbox", and phase 1 quarantining would
shadow phase 2's TOFU delivery via the replay cache. The reference
implementation skips phase 1 unless `len(known_spks) > 0`; once
the user pins any contact, phase 1 re-engages and the M8.3
intro-queue semantics apply to non-pinned senders. The `recv
--primary-only` diagnostic flag overrides the skip — an operator
who explicitly asks for phase 1 gets it, regardless of pin state.

### Operator migration

`DMP_RECEIVER_CLAIM_NOTIFICATIONS` defaults to `0`. Operators opt
in explicitly. Existing 0.5.x deployments are unaffected until
the operator flips the flag.

Recommended rollout sequence:

1. Operator sets `DMP_RECEIVER_CLAIM_NOTIFICATIONS=1`, restarts.
2. Operator's users update CLI to a version that emits claims on send.
3. Other operators do the same on their nodes.
4. Receivers see latency drops only when both ends have migrated;
   isolated migrations get the slot-walk fallback.

## Threat-model deltas vs M8.3

The M8.3 claim layer threat model applies; M10 adds three
specific deltas worth naming:

1. **Recipient's home node operator gains visibility into incoming
   message timing.** Pre-M10 the operator sees only the recipient's
   own writes (identity, prekeys, outbound chunks). Post-M10 the
   operator additionally sees claim records arriving — knows when,
   from which sender_zone, and approximately how often. This is a
   metadata expansion, not a confidentiality break (chunk plaintext
   never lands at the operator's node).

2. **Sender's claim publish reveals the sender's zone to the
   recipient's node operator at write time.** The `sender_spk` is
   in the wire (required for signature verification at the operator
   level). A future revision MAY encrypt `sender_spk` to the
   recipient's X25519 pubkey — operator sees an opaque blob, signature
   mechanics still work via per-recipient keying. Out of scope for
   M10's first cut; tracked as a follow-up.

3. **Asymmetric availability requirements.** Pre-M10 the recipient
   only needed reachability to *senders'* auth zones. Post-M10 the
   primary path additionally needs the recipient's home node to be
   up. Phase 2 restores the pre-M10 availability shape as fallback,
   but the operational property "your home node is now in the
   message-delivery hot path" is real and worth telling operators
   about explicitly.

For all three, the pre-existing slot-walk fallback (phase 2) is
the dial — running phase 1 + phase 2 keeps latency low without
giving up the M9 availability guarantee, and a privacy-conscious
recipient can disable phase 1 entirely while leaving the slot
walk on (`recv_primary_disable=true`, symmetric with the
secondary disable above).

## Sample sequences

### Pinned-contact send + receive (the M10 happy path)

```
ALICE                   ALICE'S NODE              BOB'S NODE              BOB
(sender)                (dmp.dnsmesh.io)          (dmp.dnsmesh.pro)       (receiver)

dnsmesh send
  │
  │── DNS UPDATE + TSIG ──►   ADD slot-N.mb-...
  │  (chunks + manifest)      ADD chunk-NNNN-...
  │
  │── DNS UPDATE (un-TSIG'd) ─────────────────────► ADD claim-N.mb-...
  │  (signed claim wire)                            (verify sig, rate-check, accept)
  │
  ▼
exit 0

                                                                          dnsmesh recv
                                                                            │
                                                                            │── TXT? claim-{0..9}.mb-{hash12(bob)}.dmp.dnsmesh.pro
                                                                            │   ◄── 1 claim record
                                                                            │
                                                                            │── verify sig under alice's pinned spk
                                                                            │   ✓ msg_id not in replay cache
                                                                            │
                                                                            │── TXT? slot-N.mb-{hash12(bob)}.dmp.dnsmesh.io
                                                                            │   (via public DNS recursive chain)
                                                                            │   ◄── manifest
                                                                            │── TXT? chunk-NNNN-...dmp.dnsmesh.io
                                                                            │   ◄── chunks
                                                                            │── decrypt + deliver
                                                                            ▼
                                                                          plaintext
```

### Notification dropped, slot-walk recovers

```
ALICE          ALICE'S NODE         BOB'S NODE                       BOB
                                    (rejecting un-TSIG'd writes
                                     OR temporarily unreachable)

send ──► chunks land on alice's zone        ✗   claim UPDATE fails

                                                                  (no claim arrives)

                                                                  recv (phase 1):
                                                                    no claims
                                                                    return
                                                                  ...wait ~10 min...
                                                                  recv (phase 2):
                                                                    walk pinned contacts
                                                                    finds alice's slot
                                                                    fetches manifest
                                                                    decrypts + delivers
```

## Implementation scope

Estimated code surface for the reference implementation:

- `dmp/core/claim.py` — no change (DMPCL01 unchanged).
- `dmp/server/dns_server.py` — extend the existing un-TSIG'd UPDATE
  accept path to recognize the new owner-name pattern when
  `DMP_RECEIVER_CLAIM_NOTIFICATIONS=1`. ~40 lines.
- `dmp/server/node.py` — env var parsing + wiring. ~10 lines.
- `dmp/client/client.py` — second `_publish_claim_via_dns_update`
  call in `send_message` for the recipient's zone. ~30 lines.
  New `receive_claims_from_own_zone` method for phase 1. ~80 lines.
  Two-phase scheduling in `receive_messages`. ~30 lines.
- `dmp/cli.py` — `recv --primary-only` / `--skip-primary` flags.
  ~20 lines. Config knobs for cadence + disable. ~30 lines.
- Tests — round-trip via primary, fallback to secondary, dedup
  across both, signature failure, rate-limit, recipient zone
  unreachable, sender zone unreachable. ~12 cases, ~400 lines.

Total estimate: ~600 lines + tests. Slots cleanly into existing
M8.3 plumbing; no new wire format, no new HTTP routes, no
operator-to-operator paths.

## Open questions

- **Sender-spk encryption** (operator-side metadata reduction). Should
  the wire encrypt `sender_spk` to the recipient's X25519 pubkey so
  the receiver's operator sees only an opaque blob? Tradeoff: the
  operator can no longer pre-validate signatures at write time —
  every accepted record incurs an X25519 ECDH at the recipient.
  Tracked as a follow-up; not blocking M10.

- **Per-recipient quota / abuse.** A spammy sender writing many
  claims to bob's node burns the per-recipient rate limit. Should
  the CLI surface "rejected by recipient's node — abuse?" as a
  visible signal to the recipient? Or is that the operator's job?

- **Default `recv_secondary_interval`.** 600s is a defense-in-depth
  cadence; some deployments may want shorter (60s) for catching
  silent claim drops faster, others longer (3600s) for low-volume
  privacy-conscious users. Document but ship `600` as the safe
  default.

These are post-M10 polish, not blockers.
