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

- **Confidentiality:** X25519 ECDH + ChaCha20-Poly1305, ephemeral key per
  message. The node sees ciphertext, not plaintext.
- **Forward secrecy:** compromise of a long-term X25519 private key does
  not decrypt past messages (ephemeral keys are discarded).
- **Header integrity:** AEAD AAD binds the canonical DMPHeader
  (`sender_id`, `recipient_id`, `msg_id`, `timestamp`, `ttl`). Flipping
  any of these fields breaks decryption.
- **Sender authentication:** every slot manifest carries an Ed25519
  signature over a binary body that names the sender. Forged manifests
  fail verification.
- **Replay:** a per-recipient `(sender_spk, msg_id)` cache rejects
  re-delivered manifests within its memory window.

## Known limits

1. **Replay cache persists per-identity to disk.** The CLI writes to
   `$DMP_CONFIG_HOME/replay_cache.json` on every `record()`; library
   callers opt in via `replay_cache_path`. A long-lived server process
   keeps its state in memory and survives as long as the process does.
   Persistence is best-effort — a crash mid-write can't corrupt state
   (atomic rename) but a crash mid-purge will keep an expired entry one
   cycle longer than intended. The persisted cache is sized-bounded only
   by the message TTL, not by an explicit cap.
2. **Slot squatting DoS.** Signed manifests prevent impersonation but not
   denial-of-service: an attacker can publish their own valid manifest
   in every mailbox slot and block real messages until expiry. Real slot
   leasing with per-slot priority / allowlists is future work.
3. **Cross-chunk erasure coding is missing.** Reed-Solomon is per-chunk
   only; it repairs bit errors inside a received chunk but a lost chunk
   still kills the message. Real RS(k,n) across chunks is future work.
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

## Cryptographic primitives

- X25519 (RFC 7748) via `cryptography.hazmat.primitives.asymmetric.x25519`
- Ed25519 (RFC 8032) via `cryptography.hazmat.primitives.asymmetric.ed25519`
- ChaCha20-Poly1305 AEAD (RFC 8439) via `cryptography.hazmat.primitives.ciphers.aead`
- HKDF-SHA256 (RFC 5869) via `cryptography.hazmat.primitives.kdf.hkdf`
- SHA-256 via `hashlib`

Passphrase → X25519 seed uses PBKDF2-HMAC-SHA256, 100_000 iterations,
fixed salt `DMP-DEFAULT-SALT`. The fixed salt is a weakness for
low-entropy passphrases — an attacker who captures a public identity can
try offline password guesses. Use high-entropy passphrases until we
switch to Argon2 or an identity-specific salt.

The Ed25519 signing seed is derived from the X25519 private bytes via
`SHA-256(x25519_priv || b'DMP-v1-Ed25519-signing-key')`.
