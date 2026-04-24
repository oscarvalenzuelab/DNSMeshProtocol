---
title: End-to-end flows
layout: default
parent: Protocol
nav_order: 3
---

# End-to-end flows
{: .no_toc }

This page describes the five message-level sequences a DMP client
executes: send, receive, identity publish / fetch, and cluster
discovery. Each sequence is described in terms of the DNS owner names
from [routing.md](routing.md), the record wire forms from
[wire-encoding.md](wire-encoding.md), and the record-specific invariants
from [spec.md](spec.md).

1. TOC
{:toc}

## Message send

Pre-conditions:

- Alice has a `Contact` for Bob pinning (at minimum) his
  `public_key_bytes` (32-byte X25519). Pinning
  `signing_key_bytes` (32-byte Ed25519) additionally enables the
  prekey path.
- Alice and Bob share a `domain` (or Alice knows Bob's
  `contact.domain`).

Steps:

1. **Resolve recipient**. Compute
   `recipient_id = sha256(contact.public_key_bytes)`
   (`dmp/client/client.py:306`).

2. **Pick a prekey** (forward-secrecy path).
   Alice queries
   `prekeys.id-<hash12(contact.username)>.<contact.domain>` TXT
   ([routing §Prekeys](routing.md#prekeys)). For each returned record
   she calls `Prekey.parse_and_verify(record, contact.signing_key_bytes)`
   — the prekey is accepted iff it:
   - carries the `v=dmp1;t=prekey;d=` prefix,
   - verifies against Bob's pinned Ed25519 signing key,
   - is not expired.
   A random verifying prekey is chosen
   (`dmp/client/client.py:227`). If the contact has no pinned signing
   key, or no verifying prekey is reachable, Alice falls back to
   `contact.public_key_bytes` (the long-term X25519) and sets
   `prekey_id = 0` (`NO_PREKEY`) — **no forward secrecy for this
   message**.

3. **Key agreement + AEAD**.
   - Generate an ephemeral X25519 keypair (`EphemeralPk, EphemeralSk`).
   - `shared = ECDH(EphemeralSk, recipient_pubkey)` where
     `recipient_pubkey` is either the chosen prekey pub or Bob's
     long-term key.
   - `key = HKDF-SHA256(shared, salt=b"DMP-v1", info=b"DMP-Message-Encryption", length=32)`.
   - `ciphertext = ChaCha20-Poly1305.encrypt(key, nonce=random 12B, plaintext, aad)`.
   - AAD binds the DMPHeader subset (version, message_type, message_id,
     sender_id, recipient_id, timestamp, ttl, with `total_chunks = 0`
     and `chunk_number = 0` as sentinels) plus the 4-byte
     `prekey_id` in use. Details in
     [crypto.md §AAD binding](crypto.md#aad-binding); source at
     `dmp/client/client.py:349-365`.

4. **Chunk + erasure-code**.
   - Wrap the DMPMessage in an outer struct, serialize to bytes.
   - `shares, k, n = erasure.encode(outer_bytes)` — split into `k`
     data blocks + `n-k` parity blocks (cross-chunk `k-of-n`).
   - For each `share` in `shares`, wrap with per-chunk Reed-Solomon:
     `wire_chunk = chunker.wrap_block(share)` which produces
     `sha256(share)[:8] || RS_encode(share)` (see
     `dmp/core/chunking.py:54-72`).

5. **Publish chunks**. For each `chunk_num in 0..n-1`, compute
   `msg_key = sha256(msg_id || recipient_id || sender_spk)[:12]`
   ([routing §Message chunks](routing.md#message-chunks)) and
   `publish_txt_record("chunk-<NNNN>-<msg_key>.<domain>", "v=dmp1;t=chunk;d=<b64(wire_chunk)>", ttl)`.
   (`dmp/client/client.py:386-400`).

6. **Sign + publish the manifest**.
   - Construct `SlotManifest(msg_id, sender_spk, recipient_id,
     total_chunks=n, data_chunks=k, prekey_id, ts=now, exp=now+ttl)`.
   - `wire = manifest.sign(alice_crypto)` yields
     `"v=dmp1;t=manifest;d=" + b64(body || ed25519_sig_over_body)`.
   - Pick a slot deterministically:
     `slot = int.from_bytes(msg_id[:4], "big") % SLOT_COUNT`
     where `SLOT_COUNT = 10`.
   - `publish_txt_record("slot-<N>.mb-<hash12(recipient_id)>.<domain>", wire, ttl)`.

7. **Consumed-prekey bookkeeping**. When the recipient decrypts (§2.7
   below), they delete the matching `prekey_sk` locally and DELETE the
   published prekey record from DNS so later senders do not pick a
   prekey whose `sk` is gone. Best effort: a DELETE failure leaves the
   prekey record rotting until its `exp` elapses.

## Message receive

Bob's poll loop (`DMPClient.receive_messages`, `dmp/client/client.py:427`):

1. **Enumerate slots**. For each `slot in 0..SLOT_COUNT-1`:
   `records = reader.query_txt_record("slot-<slot>.mb-<hash12(user_id)>.<domain>")`.

2. **Per-record verify**. For each TXT record in the RRset:
   1. `SlotManifest.parse_and_verify(record)` → requires the
      `v=dmp1;t=manifest;d=` prefix, valid base64, 172-byte blob
      (108-byte body + 64-byte Ed25519 sig), and signature verification
      against the embedded `sender_spk`. Returns `None` on any failure;
      the record is silently dropped.
   2. **Recipient bind**: `manifest.recipient_id == self.user_id`.
   3. **Freshness**: `not manifest.is_expired()`.
   4. **Pinned-contact filter**. If Bob has at least one pinned Ed25519
      contact, only manifests whose `sender_spk` is in
      `known_spks = {c.signing_key_bytes for c in contacts.values() if c.signing_key_bytes}`
      are accepted. Unknown signers are dropped. Bob with zero pinned
      contacts falls back to TOFU (any signature-valid manifest
      delivers). Verified at `dmp/client/client.py:454-456`.
   5. **Replay-cache check**. `if replay_cache.has_seen(sender_spk,
      msg_id): continue`. Check only — Bob does not `record` until
      after a successful decrypt, so a transient DNS miss mid-flow does
      not permanently blacklist a still-valid manifest
      (`dmp/client/client.py:458-462`).

3. **Fetch chunks**. Compute
   `msg_key = sha256(msg_id || recipient_id || sender_spk)[:12]`
   and query each `chunk-<NNNN>-<msg_key>.<domain>` up to
   `manifest.total_chunks`. For each returned TXT record:
   - Strip the `v=dmp1;t=chunk;d=` prefix (via `DMPDNSRecord.from_txt_record`).
   - `block = chunker.unwrap_block(data)` — RS-decode, then verify
     the 8-byte checksum over the decoded share.
   - On failure the share is dropped; the loop continues to the next
     chunk position until either `k` shares are collected or every
     position has been tried.

4. **Erasure-decode**. `assembled = erasure.decode(shares,
   manifest.data_chunks, manifest.total_chunks)` returns the
   length-prefixed DMPMessage bytes (or `None` if `< k` shares survive).

5. **Cross-check inner header against manifest**
   (`dmp/client/client.py:540-546`):
   - `outer.header.message_id == manifest.msg_id`
   - `outer.header.recipient_id == manifest.recipient_id`
   - `not outer.header.is_expired()` (inner-header freshness via `ts + ttl`)

6. **AEAD decrypt**. Rebuild the same AAD the sender bound (the
   header subset plus `manifest.prekey_id`). If
   `manifest.prekey_id != NO_PREKEY`, look up `prekey_sk` in the local
   `PrekeyStore` by `prekey_id` — `None` means the `sk` is already
   gone (delivery failure, not security failure; return). Otherwise
   use Bob's long-term X25519 key. `ChaCha20-Poly1305.decrypt` the
   ciphertext.

7. **Deliver + record replay + consume prekey**
   (`dmp/client/client.py:581-588`):
   - `replay_cache.record(sender_spk, msg_id, manifest.exp)`.
   - If `prekey_id != NO_PREKEY`, call `_consume_prekey(prekey_id)`
     which (a) DELETEs the published prekey TXT record from DNS and
     (b) removes the sqlite row carrying the `sk`.
   - Return the decrypted `InboxMessage` to the caller.

## Identity publish

Source: `dmp/cli.py:849-870` (`cmd_identity_publish`).

1. **Build the record**. Call
   `make_record(alice_crypto, username, ts=int(time.time()))`
   (`dmp/core/identity.py:179`) which fills in `x25519_pk` and
   `ed25519_spk` from the crypto object.
2. **Sign**. `wire = record.sign(alice_crypto)` yields
   `"v=dmp1;t=identity;d=" + b64(body || ed25519_sig)`.
3. **Pick owner name**:
   - **Zone-anchored** (preferred): `dmp.<cfg.identity_domain>` via
     `zone_anchored_identity_name`. Used when the user has configured
     `identity_domain` — i.e. they operate their own zone.
   - **Hashed** (legacy / shared mesh):
     `id-<hash16(username)>.<effective_domain>` via `identity_domain()`.
4. **Publish**. `writer.publish_txt_record(name, wire, ttl)`.

## Identity fetch

Source: `dmp/cli.py:1055-1100` (`cmd_identity_fetch`) plus the
`--via-bootstrap` flag that auto-discovers the zone-anchored form.

1. **Parse the address**. `parse_address("alice@alice.example.com")`
   returns `("alice", "alice.example.com")` or `None` on malformed
   input.
2. **Choose owner name**:
   - `alice@host` with `host` present → zone-anchored form
     `dmp.<host>`.
   - Username without a host → hashed form
     `id-<hash16(username)>.<domain>`.
3. **Query + parse**. `records = reader.query_txt_record(name)`. For
   each TXT record in the RRset:
   `IdentityRecord.parse_and_verify(record)` returns
   `(record, signature)` on success — verifies against the
   `ed25519_spk` embedded in the body (self-authenticating).
4. **Username bind** (zone-anchored only). If the owner name is
   `dmp.<host>`, the fetcher requires `record.username == address.user`
   so a zone owner cannot publish a body naming someone else under
   their zone.
5. **Trust-policy** dispatch:
   - **Exactly one verifying record** → present the `(username,
     x25519_pk, ed25519_spk, fingerprint)` tuple and let the caller
     pin it (TOFU on first delivery).
   - **Zero verifying records** → fetch failure.
   - **Multiple verifying records with differing keys** → ambiguous;
     surface all fingerprints and require the user to resolve (e.g.
     `dnsmesh identity fetch --accept-fingerprint <hex>`).

## Cluster discovery

Source: `dmp/client/bootstrap_discovery.py`,
`dmp/client/cluster_bootstrap.py`, and `dmp/cli.py` (`cmd_bootstrap_discover`).

Pre-condition: the user has pinned the **bootstrap signer**
(zone operator's Ed25519 public key) out-of-band via
`dnsmesh bootstrap pin <user_domain> <fingerprint>`. See
[bootstrap §Threat model](bootstrap.md#threat-model).

1. **Fetch the bootstrap record**. Given address
   `alice@example.com`:
   - `rrset_name = bootstrap_rrset_name("example.com")` →
     `_dmp.example.com`.
   - `records = bootstrap_reader.query_txt_record(rrset_name)`.
   - For each TXT record: `record =
     BootstrapRecord.parse_and_verify(wire, signer_spk,
     expected_user_domain="example.com")`. Select the verifying record
     with the highest `seq` (handles staged rollout).
   - On any failure (no records, all signature-invalid, all expired,
     wrong user-domain): return `None` and let the caller fall back.

2. **Walk entries in priority order**. `record.best_entry()` returns
   `entries[0]` (sorted ascending by `priority` at sign + parse time).
   For each entry `(priority, cluster_base_domain, operator_spk)` in
   priority order:

   a. **Fetch the cluster manifest**. `manifest =
      fetch_cluster_manifest(cluster_base_domain, operator_spk,
      bootstrap_reader)`:
      - Query `cluster.<cluster_base_domain>` TXT.
      - For each record: `ClusterManifest.parse_and_verify(wire,
        operator_spk, expected_cluster_name=cluster_base_domain)`.
        Select the highest-seq verifying manifest.

   b. **Factory dry-run**. Before pinning, the caller constructs per-
      node `writer_factory(node)` and `reader_factory(node)` for every
      node in the new manifest. If any factory raises (malformed
      endpoint, unreachable port), neither side advances — the client
      backs off to the next bootstrap entry rather than cutting over
      to a partially-built cluster. See `ClusterClient.refresh_now`
      for the corresponding in-session check.

   c. **First verifying + factory-buildable entry wins**. The client
      pins `(cluster_base_domain, operator_spk)` and proceeds.
      Lower-priority entries are ignored on success; on failure the
      loop continues.

3. **Build the cluster-mode reader / writer**:
   - `FanoutWriter(manifest, writer_factory, timeout, max_workers)` —
     fans publish / delete across every node, returns `True` iff
     `ceil(N/2)` nodes acknowledge before the timeout.
   - `UnionReader(manifest, reader_factory, timeout, max_workers)` —
     queries every node concurrently, unions dedup'd TXT answers.
   - `CompositeReader(cluster_base_domain, cluster=union_reader,
     external=bootstrap_reader)` — routes queries by owner-name
     suffix: names ending in `.<cluster_base_domain>` go to the
     `UnionReader`; names outside fall through to the external
     bootstrap resolver so cross-zone identity / prekey lookups still
     work. Label-boundary-safe suffix match
     (`dmp/network/composite_reader.py:52-72`).

4. **Auto-pin** (CLI convenience). With `--auto-pin`, the CLI writes
   the discovered `(cluster_base_domain, operator_spk)` pair to
   `config.yaml` as the new pinned anchors. A scope-guard ensures the
   CLI only auto-pins a discovered host that matches the already-
   pinned `bootstrap_user_domain` — defense against a mid-flight
   bootstrap-signer compromise redirecting a different user's
   discovery at an attacker cluster.

5. **Background refresh**. A `ClusterClient` with a positive
   `refresh_interval` spawns a daemon thread that re-runs step 2a
   periodically. Refresh installs the new manifest only when:
   - the new manifest's `seq` is strictly greater than the installed
     one (rollback resistance), AND
   - every new-manifest node's factories construct without raising
     (atomic cutover — no split-brain between reader and writer on
     malformed endpoints).

## Cross-references

- [spec.md](spec.md) — top-level reference for invariants cited above.
- [wire-encoding.md](wire-encoding.md) — byte-level rules for the
  records named above.
- [routing.md](routing.md) — owner-name helpers for every step.
- [threat-model.md](threat-model.md) — what each signature check
  defends against (and what it doesn't).
- [cluster.md](cluster.md) — the signed record type the cluster
  discovery flow consumes.
- [bootstrap.md](bootstrap.md) — the signed record type that
  anchors the cluster discovery flow.
- [crypto.md](crypto.md) — AEAD, KDF, and signature primitive details
  referenced in the send / receive steps.
