---
title: Cryptography
layout: default
parent: Protocol
nav_order: 2
---

# Cryptography
{: .no_toc }

1. TOC
{:toc}

## Primitives

| Purpose | Primitive | Library |
|---|---|---|
| Key agreement | X25519 ECDH | `cryptography.hazmat.primitives.asymmetric.x25519` |
| Signatures | Ed25519 | `cryptography.hazmat.primitives.asymmetric.ed25519` |
| AEAD | ChaCha20-Poly1305 | `cryptography.hazmat.primitives.ciphers.aead` |
| KDF (session) | HKDF-SHA256 | `cryptography.hazmat.primitives.kdf.hkdf` |
| KDF (passphrase) | Argon2id | `argon2-cffi` |
| Erasure coding | Reed-Solomon `k-of-n` | `zfec` |
| Per-chunk ECC | Reed-Solomon 32-symbol | `reedsolo` |

## Identity derivation

A passphrase + 32-byte per-identity salt goes through **Argon2id**
with `t=2, m=32 MiB, p=2, length=32` to produce the X25519 private
key bytes. Argon2's memory-hardness means offline brute force is
dramatically more expensive than PBKDF2 at any realistic iteration
count.

The **Ed25519** signing key is derived from the X25519 private key
bytes via:

```
ed25519_seed = SHA-256(x25519_priv || b"DMP-v1-Ed25519-signing-key")
```

Both keys are therefore reconstructible from passphrase + salt, and
the CLI stores the salt in `config.yaml` so a lost config is
unrecoverable even with the passphrase.

## Message encryption

One encrypt per message:

1. Sender generates an ephemeral X25519 keypair.
2. Sender does `ECDH(ephemeral_sk, recipient_pubkey)`, where
   `recipient_pubkey` is either a one-time prekey (FS path) or
   recipient's long-term key (fallback).
3. `HKDF-SHA256(shared_secret, salt=b"DMP-v1",
   info=b"DMP-Message-Encryption", length=32)` → AEAD key.
4. `ChaCha20-Poly1305.encrypt(nonce=random 12 bytes, plaintext,
   associated_data=AAD)` → ciphertext.

The `EncryptedMessage` wire struct carries `ephemeral_pub || nonce ||
ciphertext`.

### AAD binding

AAD is the canonical DMPHeader subset (version, message_type,
message_id, sender_id, recipient_id, timestamp, ttl) with
`total_chunks = chunk_number = 0` as sentinels, followed by the
4-byte `prekey_id` used.

Any mutation of:

- a bound header field,
- or the claimed `prekey_id`,

makes AEAD verification fail on receive.

## Receive-side verification

1. Fetch + parse the slot manifest. Verify Ed25519 signature against
   embedded `sender_spk`.
2. Enforce `total_chunks ≤ MAX_TOTAL_CHUNKS = 1024`.
3. Verify `recipient_id == self.user_id`.
4. Check `manifest.exp` freshness.
5. Pinned-contact check: `manifest.sender_spk` must be a signing key
   in our contact list (TOFU fallback if no contacts are pinned at all).
6. Replay cache lookup: `(sender_spk, msg_id)` must not be previously
   recorded.
7. Fetch chunks, unwrap per-chunk RS, collect `k` valid shares.
8. `zfec.decode(shares, k, n)` → plaintext DMPMessage bytes.
9. Parse the `DMPMessage`. Enforce:
   - `outer.header.message_id == manifest.msg_id`
   - `outer.header.recipient_id == manifest.recipient_id`
   - `outer.header.is_expired() == False`
10. Look up `prekey_sk` by `manifest.prekey_id` if ≠ 0; else use
    long-term X25519 key.
11. `ECDH` + HKDF + ChaCha20-Poly1305.decrypt with the same AAD
    the sender bound.
12. On success: record `(sender_spk, msg_id)` in the replay cache,
    consume the prekey_sk (delete locally + from DNS).

## DMPv2 plaintext envelope

The AEAD plaintext may carry an optional **versioned envelope** before
the body, currently used to surface the sender's human-readable
`user@host` address to the recipient on first contact.

### Wire format (inside the AEAD ciphertext)

```
DMPV2_PREFIX(6) || canonical_json(header) || b"\n" || body
```

- `DMPV2_PREFIX = b"DMPV2:"` — discriminates a v1 plaintext (no
  envelope, body bytes only) from a v2 plaintext (envelope present).
- `header` is a JSON object serialized with `sort_keys=True` and
  `separators=(",", ":")` (deterministic). Required key `from` carries
  the sender's canonical `user@host`. Receivers MUST ignore unknown
  keys so future fields don't break old receivers.
- Header bytes are capped at 256 bytes total (`MAX_HEADER_BYTES`). A
  larger header rejects.
- The single `\n` byte terminates the header. Empty body is legal.

### Confidentiality

The envelope lives **inside** the ChaCha20-Poly1305 ciphertext bound
to `DMPHeader` as AAD. An attacker who scrapes the erasure-coded DNS
chunks sees only the AEAD blob; they cannot recover `from` without
breaking the AEAD or the per-recipient X25519 ECDH. The DMPHeader
itself (visible on the wire) is unchanged and still leaks
`sender_id`, `recipient_id`, `timestamp`, `ttl` — same as v1.

### Address canonicalization

`from` is canonicalized both on encode and on decode. Rules:

- ASCII only. Non-ASCII rejects.
- Lowercased.
- Trailing dots on host stripped.
- Local-part: starts alphanumeric, then `a-z0-9_-.`, up to 64 chars.
  Must not start or end with `.`, no `..`.
- Host: dot-separated labels, each `a-z0-9-` not starting/ending with
  `-`, label ≤63 chars, total ≤253 chars.

Receivers MUST canonicalize before lookup AND before display. Never
render the raw bytes the sender wrote — homograph/confusable
defenses depend on the canonical form being stable.

### Trust (the SPK-binding check)

The `from` claim by itself is unauthenticated — the sender wrote
whatever they wanted. Before populating `sender_label` (intro queue or
inbox), the receiver:

1. Canonicalizes `from`.
2. Fetches the identity record at that address (zone-anchored name
   first, then TOFU-hash fallback).
3. Verifies the record's Ed25519 signature against the embedded
   `ed25519_spk`.
4. Compares the record's `ed25519_spk` to the manifest's `sender_spk`
   (the AEAD signer, already trusted by every other receive-path
   gate).
5. Compares `record.username == address.user`.

Match → `sender_label = canonical_from`. Mismatch / NXDOMAIN / parse
failure → `sender_label = ""` (UI falls back to SPK fingerprint).

Positive bindings are cached in memory (`(canonical_from, sender_spk)
→ canonical_from`). Negative results are NOT cached — a transient
DNS failure must not evict a previously-verified binding. Per codex
consult 2026-05-13.

### Capability gating (no leaked wrappers)

Senders MUST consult the recipient's `IdentityRecord.versions` before
emitting a wrapper. The wrapper is only emitted when `2 ∈ versions`.
Receivers that haven't published `versions=[…2…]` are treated as
v1-only (the missing-suffix default), so a wrapped plaintext never
reaches a receiver that would render it as a literal `DMPV2:` prefix
in the message body.

### Cross-version matrix

| Sender publishes | Recipient publishes | Sender emits | Receiver sees |
|---|---|---|---|
| versions=[1] | versions=[1] | v1 (no wrapper) | v1 body, no label |
| versions=[1,2] | versions=[1] / missing | v1 (gated) | v1 body, no label |
| versions=[1,2] | versions=[1,2] | v2 (wrapper) | clean body, verified label |
| versions=[1] | versions=[1,2] | v2 (wrapper)* | clean body, verified label |

\* The sender's own `versions` field advertises **receive** capability;
it does not gate **send**. Codex-validated 2026-05-13.

## Forward secrecy (X3DH-style prekeys)

See [the user guide]({{ site.baseurl }}/guide/forward-secrecy) for the
flow and tradeoffs. The one-sentence version: recipient publishes a
pool of signed one-time X25519 prekeys, sender uses one per message,
recipient deletes the matching sk on decrypt — so a later leak of
either party's long-term key can't decrypt that message.

## Reed-Solomon layers

Two independent layers, easy to confuse:

1. **Per-chunk RS** (32 parity bytes over each data block). Repairs
   bit-errors *inside* a received chunk. Applied to the erasure share,
   not the plaintext.
2. **Cross-chunk erasure** (k-of-n via zfec). Split length-prefixed
   plaintext into k data blocks, compute `n-k` parity blocks. Any k
   received reconstructs. Loss tolerance per message: `n-k` chunks.

The two compose: bit-errors inside a survived chunk are repaired at
layer 1 before the share reaches layer 2.
