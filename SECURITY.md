# Security

This is **non-certified, pre-external-audit software**. **Don't route secrets
through DMP until the external cryptographic audit is done.**

The codebase has had ~40+ rounds of automated code review (OpenAI Codex)
across every milestone, plus a design review of the protocol. That
automated review surfaced and closed many real issues — but **automated
review is not a substitute for professional cryptanalysis**. A human
auditor catches a different class of defect:

- **Crypto composition errors** — our stack composes X25519 ECDH +
  HKDF + ChaCha20-Poly1305 AEAD + Ed25519 + Argon2id. Each primitive
  is fine in isolation; the composition may have subtle bugs that
  require expert cryptanalysis to find (see, e.g., Signal's early
  domain-separation issues).
- **Side channels** — timing, cache, memory-dump recoverability of
  ephemeral keys. Auditors run timing harnesses.
- **Protocol-level attacks** — cross-record replay, key reuse across
  rotation, trust-chain shortcuts. LLM review is local; adversarial
  reasoning across the full protocol surface is not what it does.
- **Spec-vs-implementation drift** — the protocol spec says "bind AAD
  to the header"; an auditor verifies the code actually does it
  under every edge case.
- **Novel mechanisms** — DMP's chunking + Reed-Solomon + zfec erasure
  composition is unusual for a messaging protocol. Original research
  surface that only human cryptanalysis covers.

Until the external audit is published, treat DMP as non-certified
for confidentiality-critical traffic.

## Reporting a vulnerability

Use
[GitHub's private vulnerability reporting](https://github.com/oscarvalenzuelab/DNSMeshProtocol/security/advisories/new)
to file privately. The advisory thread stays confidential between
reporter and maintainers until it's resolved and disclosed.

Include in the report:
- Affected version (commit SHA, release tag, or PyPI version).
- Minimum reproduction.
- Your assessment of impact.

For non-security questions, open a regular GitHub issue. Please
don't open a public issue for an unpatched security bug — the
private advisory channel above is what to use instead.

## Threat model

The protocol assumes:

- An active network attacker who can observe, drop, inject, and modify DNS
  traffic between the client, resolvers, and the authoritative node.
- An attacker who can run their own DMP clients and nodes on the mesh.
- Individual DNS resolvers and even individual DMP nodes are untrusted;
  clients should tolerate some fraction being hostile.
- The attacker does **not** have the recipient's X25519 private key or the
  sender's Ed25519 private key.
- The attacker does **not** control the recipient's process at the moment
  a message is being delivered (no local-machine adversary).

## What's protected

- **Confidentiality:** X25519 ECDH + ChaCha20-Poly1305. The sender
  generates a fresh ephemeral keypair per message, which means two
  messages to the same recipient don't share a session key and an
  observer can't correlate them by key material. The node sees
  ciphertext, not plaintext.
- **Header integrity (partial):** AEAD AAD binds a canonical subset of
  the `DMPHeader` — `version`, `message_type`, `message_id`, `sender_id`,
  `recipient_id`, `timestamp`, `ttl`. Flipping any of these in transit
  breaks decryption. `total_chunks` and `chunk_number` are NOT in AAD
  (they're set after encryption and bound separately via the signed
  manifest).
- **Manifest integrity + binding:** every slot manifest carries an
  Ed25519 signature over `(msg_id, sender_spk, recipient_id,
  total_chunks, ts, exp)`. Forged manifests fail verification, and on
  receive the client cross-checks `outer.header.message_id ==
  manifest.msg_id` and `recipient_id == manifest.recipient_id` so a
  legitimate sender can't lie about which message the manifest is for.
- **Sender-identity binding to contacts:** a received manifest is
  accepted only when its `sender_spk` matches a pinned signing key in
  the recipient's contact list (see the unknown-sender section below
  for TOFU / unpinned behavior).
- **Replay:** a per-recipient `(sender_spk, msg_id)` cache rejects
  re-delivered manifests within its memory window.
- **Freshness:** the inner header's `timestamp + ttl` is enforced on
  receive. Stale messages are dropped.

- **Forward secrecy (best-effort, prekey-based).** Recipients publish a
  pool of signed one-time X25519 prekeys. Senders do ECDH against a
  prekey instead of the long-term key and embed `prekey_id` in the
  signed manifest. On successful decrypt the recipient deletes the
  matching private key, so a later leak of the long-term X25519 key
  cannot recover that message's session. The fallback path — no
  pinned signing key or no live prekey pool — uses the long-term key
  and does NOT give forward secrecy for those messages. This is not
  Signal-grade: no double ratchet, no post-compromise security, and a
  crash between decrypt and deletion leaves the prekey sk on disk.

## What is NOT protected

- **Post-compromise sender authentication (partial — M5.4).** If the
  sender's Ed25519 signing key leaks, an attacker can sign arbitrary
  messages as that sender *until the sender rotates*. M5.4 ships
  `dnsmesh identity rotate --experimental --reason compromise`, which
  publishes a co-signed `RotationRecord` (new key ← old) plus a
  self-signed `RevocationRecord` of the leaked key. Rotation-aware
  contacts chain-walk from the pinned old key to the new head
  automatically; the revocation aborts trust on any path that
  touches the revoked key. Caveats: the rotation wire format is
  draft (post-audit revision may bump it to `v=dmp2;t=rotation;`),
  and contacts running pre-M5.4 clients still need an out-of-band
  notification to re-pin. See [docs/protocol/rotation.md](docs/protocol/rotation.md)
  for the threat model.
- **Traffic analysis.** Message timing, approximate size (chunk
  count), and the existence of a `(sender, recipient)` relationship
  are all visible to anyone who watches the mesh domain's DNS.
- **Username ownership under the shared mesh domain.** Identity
  records at `id-{sha256(username)[:16]}.{domain}` are publish-append.
  A squatter who publishes first has a valid self-signed record; a
  later legitimate publisher adds a second record. `dnsmesh identity
  fetch` refuses `--add` when multiple valid records exist and
  prints fingerprints for out-of-band verification. For real
  squat resistance, publish under a DNS zone you control and use
  zone-anchored addresses — see below.

## Zone-anchored identity (recommended for real deployments)

Passing `--identity-domain alice.example.com` at `dnsmesh init` switches
identity publishing from the hash-based path under the shared mesh
domain to `dmp.alice.example.com`. Addresses take the form
`alice@alice.example.com`. Because only the owner of
`alice.example.com` can write records in that zone, squatting requires
compromising DNS for that zone — the same trust model email has had
for decades. The inner record body still carries the username, and
`dnsmesh identity fetch` rejects records whose internal username doesn't
match the address (so a zone owner can't publish
`dmp.alice.example.com` with a body naming someone else).

## Known limits

1. **Replay cache persists per-identity to disk.** The CLI writes to
   `$DMP_CONFIG_HOME/replay_cache.json` on every `record()`; library
   callers opt in via `replay_cache_path`. A long-lived server process
   keeps its state in memory and survives as long as the process does.
   Persistence is best-effort — a crash mid-write can't corrupt state
   (atomic rename) but a crash mid-purge will keep an expired entry one
   cycle longer than intended. The persisted cache is sized-bounded only
   by the message TTL, not by an explicit cap.
2. **Slot DoS surface narrowed.** Mailbox slots now have append
   (RRset) semantics, so an attacker can *add* manifests but cannot
   *evict* legitimate ones. Signed manifests ensure forged entries
   fail verification. A per-name RRset cardinality cap
   (`DMP_MAX_VALUES_PER_NAME`, default 64) and per-IP token-bucket
   rate limits on the HTTP + DNS surfaces are shipped. M5.5 adds
   per-token rate limits on top (`DMP_AUTH_MODE=multi-tenant`) so a
   single user can't burn the shared per-IP budget for everyone
   behind the same NAT. Remaining volumetric surface: a well-funded
   attacker across many source IPs can still fill the store with
   valid-but-irrelevant manifests — operators facing that threat
   should front the publish API with a reverse proxy
   (Caddy / nginx / Cloudflare) that imposes its own limits, and set
   `DMP_OPERATOR_TOKEN` (fka `DMP_HTTP_TOKEN`, alias preserved) or
   enable multi-tenant auth with `DMP_REGISTRATION_ALLOWLIST` so
   only approved domains can self-register.
3. **Erasure decode happens in-process**. Cross-chunk erasure coding
   landed (k-of-n via zfec); any k of n chunks reconstruct, default
   ~30% redundancy. The decoder trusts well-formed zfec share blocks —
   a malformed block that passes the per-chunk RS checksum layer and
   then confuses zfec would still return None rather than garbage, but
   exotic zfec edge cases haven't been fuzzed.
4. **Traffic analysis.** The protocol does not hide message timing, size,
   or `(sender, recipient)` correlation at the DNS-query level. A passive
   observer of a mailbox domain can count messages and infer their size.
   Random delays and dummy traffic are documented in the spec but not
   implemented.
5. **`DMPMessage.signature` field is vestigial.** The real sender
   signature lives in the slot manifest. The legacy 32-byte field on
   `DMPMessage` is unused and should be considered untrusted.
6. **Key-rotation story (M5.4, draft wire format).** Identities are
   long-term Ed25519 + X25519 pairs derived from a passphrase.
   `dnsmesh identity rotate --experimental` publishes a co-signed
   `RotationRecord` + fresh `IdentityRecord`; rotation-aware
   contacts (`rotation_chain_enabled=True`) chain-walk to the new
   key without re-pinning. Pre-M5.4 contacts still need out-of-band
   re-pin. The wire format is DRAFT — subject to revision in
   v0.3.0 after the external audit; a breaking
   `v=dmp2;t=rotation;` shape is on the table.
7. **No transport-level authentication for the node's HTTP API**
   beyond bearer tokens. The node supports three auth modes
   (`DMP_AUTH_MODE=open|legacy|multi-tenant`): `open` is
   unauthenticated (dev only); `legacy` is the pre-M5.5 single
   shared `DMP_OPERATOR_TOKEN` (alias `DMP_HTTP_TOKEN` for
   back-compat); `multi-tenant` enables per-user tokens with scope
   enforcement. There is no TLS in the container; operators must
   front with nginx/caddy or run inside a trusted network.
8. **`InMemoryDNSStore` is process-local.** It's a mock for tests; do not
   use it for anything exposed to real users.
9. **Bounded per-request threading.** Both the HTTP API and UDP DNS
   server use `ThreadingMixIn` with an explicit concurrency ceiling
   via a `threading.Semaphore` (`DMP_HTTP_MAX_CONCURRENCY`, default
   64; `DMP_DNS_MAX_CONCURRENCY`, default 128). Once saturated, new
   connections/packets are dropped rather than spawning unbounded
   threads. Operators running a public node should still front it
   with a reverse proxy that imposes connection caps (nginx
   `worker_connections`, Caddy defaults) for defense in depth;
   async I/O remains an option on the roadmap if single-node
   throughput becomes a bottleneck.

## Cryptographic primitives

- X25519 (RFC 7748) via `cryptography.hazmat.primitives.asymmetric.x25519`
- Ed25519 (RFC 8032) via `cryptography.hazmat.primitives.asymmetric.ed25519`
- ChaCha20-Poly1305 AEAD (RFC 8439) via `cryptography.hazmat.primitives.ciphers.aead`
- HKDF-SHA256 (RFC 5869) via `cryptography.hazmat.primitives.kdf.hkdf`
- SHA-256 via `hashlib`

Passphrase → X25519 seed uses Argon2id (memory-hard, 32 MiB, t=2, p=2,
32-byte output). The `dnsmesh` CLI generates a 32-byte random salt at
`dnsmesh init` and stores it in the config file next to the username. Two
users who pick the same passphrase still derive independent keys, and
an attacker who captures a public identity has to repeat the memory-hard
derivation per guess rather than precompute a rainbow table.

When `DMPCrypto.from_passphrase` is called without a `salt` argument
(library callers doing quick demos), it falls back to a fixed sentinel
`DMP-default-v2-argon2id`. That path is weaker against targeted
offline attack and is a footgun — production deployments must go
through the CLI or pass their own salt.

The Ed25519 signing seed is derived from the X25519 private bytes via
`SHA-256(x25519_priv || b'DMP-v1-Ed25519-signing-key')`.
