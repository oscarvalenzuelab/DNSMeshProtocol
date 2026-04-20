# Security

This is **alpha, pre-audit software**. The protocol has had a design review
and an independent code review of the current implementation, but it has not
been through a professional audit. Don't use it for anything whose secrecy
actually matters until that changes.

## Reporting a vulnerability

Email: oscar.valenzuela.b@gmail.com

Include:
- Affected version (commit SHA).
- Minimum reproduction.
- Your assessment of impact.

Please do not open a public GitHub issue for unpatched security bugs.

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

## What is NOT protected

- **Forward secrecy.** This was previously overclaimed. The recipient
  decrypts with their long-term X25519 private key, so compromise of
  that key allows decryption of past stored ciphertexts. We do not
  implement prekeys or a double ratchet.
- **Post-compromise sender authentication.** If the sender's Ed25519
  signing key leaks, an attacker can sign arbitrary future manifests
  as that sender. There is no key rotation or revocation channel.
- **Traffic analysis.** Message timing, approximate size (chunk
  count), and the existence of a `(sender, recipient)` relationship
  are all visible to anyone who watches the mesh domain's DNS.
- **Username ownership.** Identity records at
  `id-{sha256(username)[:16]}.{domain}` are publish-append. A
  squatter who publishes first has a valid self-signed record; a
  later legitimate publisher adds a second record. `dmp identity
  fetch` refuses `--add` when multiple valid records exist and
  prints fingerprints for out-of-band verification.

## Known limits

1. **Replay cache persists per-identity to disk.** The CLI writes to
   `$DMP_CONFIG_HOME/replay_cache.json` on every `record()`; library
   callers opt in via `replay_cache_path`. A long-lived server process
   keeps its state in memory and survives as long as the process does.
   Persistence is best-effort — a crash mid-write can't corrupt state
   (atomic rename) but a crash mid-purge will keep an expired entry one
   cycle longer than intended. The persisted cache is sized-bounded only
   by the message TTL, not by an explicit cap.
2. **Slot DoS surface narrowed but not eliminated.** Mailbox slots now
   have append (RRset) semantics, so an attacker can *add* manifests
   but cannot *evict* legitimate ones. Signed manifests ensure forged
   entries fail verification. What remains: a volumetric attacker can
   still fill the sqlite store with valid-but-irrelevant manifests until
   disk is full. HTTP rate limiting and a per-name RRset size cap are
   future work; for now, operators should run the HTTP API with a
   bearer token (`DMP_HTTP_TOKEN`) and a reverse proxy rate limit.
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
6. **No formal key-rotation story.** Identities are long-term Ed25519 +
   X25519 pairs derived from a passphrase. Rotation requires republishing
   identity and reaching contacts out of band.
7. **No transport-level authentication for the node's HTTP API**
   beyond an optional bearer token. No TLS in the container; operators
   must front with nginx/caddy or run inside a trusted network.
8. **`InMemoryDNSStore` is process-local.** It's a mock for tests; do not
   use it for anything exposed to real users.
9. **Unbounded per-request threading.** Both the HTTP API and the UDP DNS
   server use `ThreadingMixIn` and spawn a thread per request with no
   concurrency ceiling. A socket flood can exhaust threads and memory
   before the token-bucket rate limiter kicks in. Operators running a
   public node should front it with a reverse proxy that imposes its
   own connection cap (nginx `worker_connections`, Caddy defaults, a
   dedicated DNS frontend for UDP). Moving to bounded worker pools or
   async I/O is on the roadmap.

## Cryptographic primitives

- X25519 (RFC 7748) via `cryptography.hazmat.primitives.asymmetric.x25519`
- Ed25519 (RFC 8032) via `cryptography.hazmat.primitives.asymmetric.ed25519`
- ChaCha20-Poly1305 AEAD (RFC 8439) via `cryptography.hazmat.primitives.ciphers.aead`
- HKDF-SHA256 (RFC 5869) via `cryptography.hazmat.primitives.kdf.hkdf`
- SHA-256 via `hashlib`

Passphrase → X25519 seed uses Argon2id (memory-hard, 32 MiB, t=2, p=2,
32-byte output). The `dmp` CLI generates a 32-byte random salt at
`dmp init` and stores it in the config file next to the username. Two
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
