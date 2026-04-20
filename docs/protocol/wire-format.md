---
title: Wire format
layout: default
parent: Protocol
nav_order: 1
---

# Wire format
{: .no_toc }

Every DMP record fits one 255-byte DNS TXT string by design. No
multi-string splitting needed in the common path — records are
sized so the binary body plus signature plus base64 plus protocol
prefix lands under 255 bytes.

1. TOC
{:toc}

## Chunks

```
chunk-<NNNN>-<msg_key12>.<mesh_domain>   IN TXT  "v=dmp1;t=chunk;d=<b64>"
```

- `<NNNN>` — zero-padded 4-digit chunk index.
- `<msg_key12>` — first 12 hex chars of
  `sha256(msg_id + recipient_id + sender_spk)`. Senders and recipients
  derive the same path without the recipient needing to know the
  sender's X25519 pubkey up front.

Each chunk carries one erasure share plus per-chunk Reed-Solomon
parity:

| Bytes | Meaning |
|---|---|
| 8 | SHA-256 prefix checksum over the **decoded** data block |
| 128 | Data block (DATA_PER_CHUNK) |
| 32 | Reed-Solomon parity (RS_SYMBOLS) over the data block |

Recipient: RS-decode first, then verify checksum. RS repairs up to 16
byte-errors per chunk *inside* the received data.

## Slot manifests

```
slot-<N>.mb-<recipient_hash12>.<mesh_domain>
    IN TXT  "v=dmp1;t=manifest;d=<b64(body || sig)>"
```

- `<N>` ∈ 0..9 — there are 10 slots per recipient.
- `<recipient_hash12>` — `sha256(recipient_user_id)[:12]`. Recipient's
  `user_id` is itself `sha256(recipient_x25519_pub)`.

Binary body = 108 bytes:

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 16 | `msg_id` | UUIDv4 bytes |
| 16 | 32 | `sender_spk` | Ed25519 signing pubkey |
| 48 | 32 | `recipient_id` | sha256(recipient_x25519_pub) |
| 80 | 4 | `total_chunks` | n; capped at `MAX_TOTAL_CHUNKS = 1024` |
| 84 | 4 | `data_chunks` | k; erasure threshold |
| 88 | 4 | `prekey_id` | 0 = long-term X25519 key (no FS) |
| 92 | 8 | `ts` | Unix seconds — publication time |
| 100 | 8 | `exp` | Unix seconds — drop after |

Followed by a 64-byte Ed25519 signature over `body`. Total wire:
108 + 64 = 172 bytes → 232 base64 chars → 252 total prefix+b64.

Append semantics — mailbox slots hold multiple manifests at once;
the receive path iterates all of them at each slot.

## Identity records

### Hashed form (shared mesh domain)

```
id-<sha256(username)[:16]>.<mesh_domain>
    IN TXT  "v=dmp1;t=identity;d=<b64(body || sig)>"
```

### Zone-anchored form

```
dmp.<identity_domain>
    IN TXT  "v=dmp1;t=identity;d=<b64(body || sig)>"
```

Body (variable length, capped):

| Field | Size |
|---|---|
| `username_len` | 1 byte |
| `username` | up to 64 utf-8 bytes |
| `x25519_pk` | 32 bytes |
| `ed25519_spk` | 32 bytes |
| `ts` | 8 bytes |

Signed by the identity's Ed25519 key. The fetcher verifies the
signature against the embedded `ed25519_spk` (the record is
self-authenticating).

In zone-anchored form the fetcher *also* requires
`record.username == address.user` so a zone owner can't publish a
body naming someone else under their zone.

## Prekeys

```
prekeys.id-<sha256(username)[:12]>.<mesh_domain>
    IN TXT  "v=dmp1;t=prekey;d=<b64(body || sig)>" (one RRset, many values)
```

Body = 44 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `prekey_id` |
| 4 | 32 | `x25519_pub` |
| 36 | 8 | `exp` |

Followed by the 64-byte Ed25519 signature. Total wire: 108 + prefix
= 162 chars.

Many prekey records share the same DNS name (RRset semantics); the
sender gets all of them in one query and picks a random verified
one.

## Magic prefixes

Every DMP TXT value starts with `v=dmp1;t=<type>;` so a DMP-aware
resolver can filter on prefix. Types seen on the wire:

| `t=` | Meaning |
|---|---|
| `chunk` | Erasure share of an encrypted message |
| `manifest` | Signed slot manifest |
| `identity` | Signed identity record |
| `prekey` | Signed one-time prekey |
