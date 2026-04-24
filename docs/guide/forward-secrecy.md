---
title: Forward secrecy and prekeys
layout: default
parent: User Guide
nav_order: 3
---

# Forward secrecy and prekeys

Forward secrecy means: if someone leaks your long-term X25519 private
key *tomorrow*, they still can't decrypt the messages you received
*yesterday*. DMP achieves this with a simplified X3DH-style one-time
prekey pool.

## How it works

1. Bob runs `dnsmesh identity refresh-prekeys`. The client:
   - Generates 25 one-time X25519 keypairs (count is configurable).
   - Signs each one with bob's Ed25519 identity key.
   - Publishes the signed public halves as a TXT RRset at
     `prekeys.id-{sha256(bob)[:12]}.<mesh_domain>`.
   - Stores the private halves in a local sqlite file at
     `$DMP_CONFIG_HOME/prekeys.db` (0600 perms).
2. Alice pins bob as a contact (her config has bob's Ed25519 signing
   key). When she sends, her client:
   - Fetches bob's prekey pool from DNS.
   - Verifies each signature against the pinned Ed25519 key.
   - Picks one random verified prekey.
   - Does ECDH(sender_ephemeral_sk, prekey_pub).
   - Writes `prekey_id` into the signed slot manifest.
3. Bob's `dnsmesh recv`:
   - Parses the manifest, finds `prekey_id`.
   - Looks up the matching private key in his local store.
   - Does ECDH(prekey_sk, sender_ephemeral_pk) — same shared secret.
   - Decrypts.
   - **Deletes** the prekey private key locally.
   - **Deletes** the prekey_pub TXT record from DNS so future senders
     don't pick a prekey whose sk is already gone.

Once step 4 completes, the session key is unrecoverable — even with
bob's long-term X25519 private key. That is the forward-secrecy
property.

## Keeping the pool healthy

Senders pick randomly from the live RRset. If the pool drains to zero
(everyone consumed everything and nobody refreshed), new senders fall
back to bob's long-term key — which is *not* forward-secret.

Run `dnsmesh identity refresh-prekeys` periodically, or before you expect
a burst of traffic. The default of 25 stays under the node's default
HTTP rate limit (burst 100) so one command publishes the whole pool.

## When you don't have FS

Three cases:

1. **The recipient never published prekeys.** Sender falls back to
   long-term ECDH; manifest carries `prekey_id = 0`. No FS.
2. **The contact is unpinned** (no Ed25519 key stored). Sender can't
   verify the prekey pool's signatures, so it skips them and uses the
   long-term key. No FS.
3. **The pool is empty or fully consumed.** Same outcome: fallback to
   long-term key. No FS.

The protocol's `prekey_id` is visible on the wire, so you can
retrospectively check whether a given message was FS-protected.

## Crash window

If bob's process dies between **decrypt succeeded** and **delete
succeeded**, the prekey_sk stays on disk (and possibly in DNS). A
later compromise of the disk exposes that one session's key. Not a
fatal flaw, but an honest limit — see
[SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md).

## Not Signal

DMP's prekey scheme is deliberately simpler than Signal's X3DH:

- No double ratchet. Each message is independently keyed; there is no
  session state that advances per message.
- No post-compromise security. A leaked Ed25519 signing key stays
  valid until rotated (and rotation is manual, not automated).
- Prekey pool is flat, not classified into "signed prekey" + "one-time
  prekey" tiers.

The tradeoff is operational simplicity against the strongest possible
security property. For a messenger that most users will treat as
"like email, but encrypted", the simpler model fits.
