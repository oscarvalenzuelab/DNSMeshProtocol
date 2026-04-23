---
title: Threat model
layout: default
parent: Protocol
nav_order: 4
---

# Threat model
{: .no_toc }

This page is the protocol-level enumeration of adversaries DMP defends
against, residual risks the protocol does NOT mitigate, and items
explicitly out of scope. It complements
[security-model.md](security-model.md) (the short pointer to the
authoritative `SECURITY.md` at the repo root) and extends the
per-record security properties documented in
[cluster §Security properties](cluster.md#security-properties) and
[bootstrap §Security properties](bootstrap.md#security-properties).

Back-reference: [spec.md §5 Trust model](spec.md#5-trust-model).

1. TOC
{:toc}

## Trust anchors

DMP's end-to-end security reduces to three out-of-band-pinned Ed25519
keys:

1. **Bootstrap signer** (zone operator). Authority over
   `_dmp.<user_domain>` TXT. Pinned via
   `dmp bootstrap pin <user_domain> <fingerprint>`. Compromise → an
   attacker can redirect a user domain to a hostile cluster.
2. **Cluster operator**. Authority over
   `cluster.<cluster_base_domain>` TXT. Pinned out-of-band, or
   discovered via a verified bootstrap record and then pinned via
   `dmp cluster pin` / `--auto-pin`. Compromise → an attacker can
   serve forged records inside that cluster.
3. **User signing identity** (Ed25519 identity key). Signs slot
   manifests, identity records, and prekeys. Pinned out-of-band by
   contacts (`dmp contacts add --signing-key <hex>`) or first-use.
   Compromise → an attacker can forge messages as that user.

The three trust anchors are **independent**: compromise of one does
not imply compromise of another. See
[spec.md §5](spec.md#5-trust-model) for the full chain.

## Defended against

### Passive eavesdropping (message content)

ChaCha20-Poly1305 AEAD encrypts every message. The key is derived from
`HKDF-SHA256(ECDH(ephemeral_sk, recipient_pubkey))` where
`recipient_pubkey` is either a one-time X25519 prekey (forward-secret
path) or the recipient's long-term X25519 key (fallback). An on-path
observer sees ciphertext; they do not see plaintext, sender identity
of an unpinned sender, or message semantics.

Detail: [crypto.md §Message encryption](crypto.md#message-encryption).

### Signature forgery

Every signed record (slot manifest, identity, prekey, cluster
manifest, bootstrap record) carries a trailing 64-byte Ed25519
signature over its body. Forging a record without the private half of
the signing key is as hard as forging Ed25519 itself.

Detail: [wire-encoding §Base64 + signature layout](wire-encoding.md#base64-and-signature-layout).

### Replay attacks (mailbox)

Every recipient keeps a persistent `(sender_spk, msg_id)` replay
cache (`dmp/core/manifest.py::ReplayCache`). A manifest whose
`(sender_spk, msg_id)` pair is already in the cache is dropped before
any decrypt attempt. Cache entries expire at the manifest's `exp` (not
at the recipient's arbitrary clock); a manifest that outlives its
`exp` is rejected at parse time anyway, so an expired cache entry
cannot unlock a re-publication.

Source: `dmp/core/manifest.py:180-294`, `dmp/client/client.py:458-469`.

### Mailbox squatting (signed-manifest semantics)

DNS TXT RRsets in DMP are append-oriented: multiple signed manifests
can co-reside at the same owner name, and the receive path iterates
every one. A squatter who publishes a manifest at
`slot-<N>.mb-<hash12(victim)>.<domain>` cannot suppress the real
sender's manifest — both land in the RRset, and only the one signed
by a pinned contact decrypts. An unpinned client falls back to TOFU
and is squat-vulnerable at the first delivery; pin your contacts.

### Single-resolver censorship

The `ResolverPool` (`dmp/network/resolver_pool.py`) tracks per-host
health, demotes resolvers that fail an oracle lookup, and preferentially
uses healthy resolvers. A censor blocking one recursive resolver does
not kill DMP as long as at least one path-reachable resolver is live.

In cluster mode, the `UnionReader` additionally fans reads across
every cluster node — loss of a node does not lose a read. A censor
would need to block every cluster node AND every resolver in the
pool to suppress a record.

### Single-node failure

`FanoutWriter` fans writes across every node in the cluster manifest
and returns `True` iff `ceil(N/2)` nodes acknowledge. Loss of up to
`floor(N/2)` nodes does not lose a write.

`UnionReader` fans reads across every node and unions dedup'd TXT
answers. Loss of any subset of nodes with at least one surviving node
does not lose a read. These are the M2.2 + M2.3 modules respectively.

### Cluster-manifest rollback

`ClusterManifest.seq` is enforced on install: a fetched manifest with
`seq <= installed.seq` is rejected (`dmp/network/fanout_writer.py`,
`union_reader.py` `install_manifest`). An attacker who captures an
older, valid-signature manifest cannot roll back a client to an older
node set — the client-side `seq` monotonicity check is the guard. The
signature alone does **not** stop rollback; the `seq` check is the
guard.

### Bootstrap-record rollback

Symmetric: `fetch_bootstrap_record` selects the verifying record with
the highest `seq`. An attacker cannot pin a client to an older entry
list than the zone operator has published.

### Key-distribution hijack during rotation

The bootstrap record supports up to 16 entries, priority-sorted. An
operator rotating the cluster operator key can publish the old and
new clusters as two entries during the rollout window; clients try
the top-priority entry first and fall back to the next on failure.
Lower-priority entries cannot be promoted by an attacker because the
record is signed.

## Does NOT defend against

### Global passive adversary: traffic correlation

DNS queries and responses are plaintext on the wire (base64 is an
encoding, not encryption). An adversary with visibility over DMP
clients' DNS traffic can:

- Infer **recipient** from the mailbox owner name (`mb-<hash12>`) by
  enumerating `hash12` values of targets.
- Infer **sender** from the slot's RRset publisher if the
  publishing path is observable.
- Infer **timing** (when a message was published, when a manifest
  was polled, when chunks were fetched).

DMP does not implement mix-net-style onion routing, padding, or cover
traffic. A global passive adversary learns who-talks-to-whom-and-when
(though not the message content).

### Compromise of pinned signer keys

Each trust anchor (bootstrap signer, cluster operator, user identity)
is a single point of failure. Compromise of any of them enables
signature-valid forgery within that anchor's scope — the protocol
treats signature-verified records as authoritative by design.

Mitigations (operator policy, not protocol):

- Keep signing keys offline; sign records on an airgap machine.
- Rotate keys on a fixed schedule; publish new fingerprints
  out-of-band.
- Pin multiple trust anchors where possible (e.g. pin the cluster
  operator key directly even when bootstrap-discovered).

DMP does not implement multisig, key-transparency logs, or post-
compromise-secure ratchets today.

### DNS poisoning of the bootstrap zone

Bootstrap records are signed, which defends against an in-flight
rewrite by an intermediate resolver. But a cache-poisoning attack
that persuades a recursive resolver to serve an attacker-chosen
response would make the resolver return `None` (the attacker has no
valid signature) rather than serving a forged record — so the
immediate failure mode is **denial of service**, not silent
redirection. DNSSEC would strengthen the resolver-integrity story
but is out of scope for DMP (see below).

### Metadata leakage: recipient identity

The mailbox owner name is `slot-<N>.mb-<sha256(sha256(recipient_x25519_pub))[:12]>.<domain>`
(48-bit truncation). For a targeted victim whose X25519 public key
is known to the attacker, deriving the owner name is cheap
(one hash). For an attacker with a candidate list of public keys,
enumerating owner names is cheap (one hash per candidate).

The truncation raises the cost of exhaustive-enumeration against
arbitrary `hash12` values (`2^48` preimage search) but is NOT
designed to hide recipient identity from an adversary who already
knows the target's pubkey. Treat the owner name as public metadata.

### Covert-channel analysis of DNS traffic volume

A cluster that sees its TXT query volume spike correlates with an
in-progress message send (chunks published + polled). Query-
volume-based traffic analysis is not defended against.

### Forward secrecy for pre-prekey messages

The prekey pool is the forward-secrecy mechanism. A message is
forward-secret **only if** the sender successfully fetched a
signature-verifying prekey, used it in ECDH, and the recipient
deleted the matching `prekey_sk` after decrypt.

Paths that are **not** forward-secret:

- **Prekey pool exhausted**. Sender queries
  `prekeys.id-<hash12>.<domain>`, gets zero verifying entries,
  falls back to the recipient's long-term X25519 key. The message's
  `manifest.prekey_id` is `NO_PREKEY` (0). A later leak of the
  recipient's long-term X25519 key decrypts this message.
- **Unpinned contact**. If the sender has not pinned the recipient's
  Ed25519 signing key (`contact.signing_key_bytes == b""`), the
  sender cannot verify prekey signatures and falls back to the
  long-term key. Same result: no FS.
- **Process crash between decrypt and `consume`**. The recipient
  decrypts, then the process crashes before `_consume_prekey` runs.
  The `sk` is still on disk; a later leak of the disk image can
  re-derive the same session key. This is a best-effort property —
  the window between decrypt and consume is small but non-zero.

The `prekey_id` field of every slot manifest discloses which case
applies: `prekey_id == 0` → no FS; `prekey_id != 0` → FS attempted.

Senders SHOULD surface the no-FS case to the user (current client:
the dataclass comment at `dmp/core/manifest.py:31-34` documents this;
the CLI does not presently warn on send but MAY in a future release).

### Post-compromise security

DMP does not implement a Signal-style double-ratchet. Compromise of
a user's Ed25519 signing key + long-term X25519 key + prekey `sk`s
decrypts every past message those keys touch AND allows forgery of
new messages until the keys are rotated.

Rotation IS in-band as of M5.4 (`dmp identity rotate --experimental`).
The CLI publishes a co-signed `RotationRecord` (new key ← old) plus
a fresh `IdentityRecord` signed by the new key; with `--reason
compromise` or `--reason lost_key` it also publishes a self-signed
`RevocationRecord` of the compromised key. Rotation-aware contacts
(`rotation_chain_enabled=True`) walk the chain from their pinned key
to the current head automatically; a revocation aborts trust on any
path that touches the revoked key. Contacts running pre-M5.4
clients still need out-of-band re-pin. Wire format details +
limits are in [`rotation.md`](rotation.md); wire is DRAFT and may
be bumped to `v=dmp2;t=rotation;` after the external audit.

### Traffic analysis of who-talks-to-whom-and-when

Same as "global passive adversary" above. Worth calling out
separately because it's the most common misunderstanding of what
DMP protects: content yes, metadata no.

### Username ownership under the shared mesh domain

The hashed identity form `id-<hash16(username)>.<domain>` is squat-
vulnerable: anyone with publish access to the shared `<domain>` can
publish an identity record claiming any username. The signature is
valid against *their* Ed25519 key, so a fetcher using TOFU accepts
the squatter's record. Mitigations:

- Use the [zone-anchored form](routing.md#zone-anchored-form)
  `dmp.<identity_domain>` where the fetcher additionally requires
  `record.username == address.user` and zone-ownership is the
  squat gate.
- Pin contacts out-of-band before treating any delivered message as
  authenticated.

### Unreviewed cryptography

DMP is **alpha** software. The protocol has not been through a
third-party audit. Do not rely on it for life-safety communications.

## Out of scope (explicit)

Items the DMP protocol deliberately does NOT address, to keep the
surface area small and auditable:

- **Group messaging.** All traffic is 1:1 sender → recipient. No
  broadcast, no rooms, no moderation.
- **File transfer.** Records are capped at 1200 wire bytes
  ([wire-encoding §Wire length caps](wire-encoding.md#wire-length-caps)).
  Multi-KiB text messages are supported via chunked manifests; multi-
  MiB media is not.
- **Real-time synchronous messaging.** DMP is delay-tolerant by
  design. DNS caching and polling cadence introduce latency
  measurable in minutes; the protocol has no concept of "online
  presence" or "typing indicator".
- **Offline identity recovery.** Identities derive from `passphrase +
  salt` via Argon2id. Losing either makes identities unrecoverable.
  There is no trusted-third-party recovery, no social recovery, no
  shamir-split passphrase scheme.
- **DNSSEC-anchored trust.** DMP verifies signatures inside the
  TXT record body; it does not verify DNSSEC RRSIG chains on the
  containing DNS zone. DNSSEC deployment would strengthen the
  resolver-integrity story but the protocol treats the resolver as
  untrusted regardless.
- **Reproducible builds / transparency log.** Out of scope for the
  protocol; relevant to the operator's deployment story.
- **Correlation-resistance layer** (mixnet / Tor-style). Out of
  scope. Operators who need it can run DMP over a mixnet-routed
  resolver.

## Cross-references

- [spec.md §5 Trust model](spec.md#5-trust-model) — the normative
  trust-anchor layering.
- [security-model.md](security-model.md) — short pointer to
  `SECURITY.md` at the repo root.
- [cluster §Security properties](cluster.md#security-properties).
- [bootstrap §Security properties](bootstrap.md#security-properties).
- [crypto.md](crypto.md) — AEAD, HKDF, Ed25519, Argon2id primitive
  details.
- [flows.md](flows.md) — where in each sequence a given invariant is
  enforced.
