---
title: Identity and contacts
layout: default
parent: User Guide
nav_order: 2
---

# Identity and contacts

An identity in DMP is **two keypairs**:

- An **X25519** keypair for ECDH-based encryption.
- An **Ed25519** signing keypair used to sign slot manifests, identity
  records, and one-time prekeys.

Both are deterministically derived from the passphrase via Argon2id
plus a per-identity 32-byte random salt stored in the CLI config.

## Publishing your identity

```bash
dnsmesh identity publish
```

This writes a signed `IdentityRecord` (108 signed bytes plus a 64-byte
Ed25519 signature) to DNS. The exact name depends on whether you
configured a zone you control:

### Shared mesh domain (TOFU)

Without `--identity-domain` at `dnsmesh init`, the record goes to
`id-{sha256(username)[:16]}.<mesh_domain>`. Anyone can publish at any
username — the hash is only a name-to-label mapping, not a trust root.
Squatting is possible and mitigated only at fetch time by the
`--accept-fingerprint` dance.

### Zone-anchored (recommended for real use)

Initialize with a DNS zone you control:

```bash
dnsmesh init alice --identity-domain alice.example.com \
               --domain mesh.local --endpoint ...
dnsmesh identity publish
```

The record now goes to `dmp.alice.example.com`. Squatting requires
compromising DNS for `alice.example.com`. Addresses take the form
`alice@alice.example.com` — the same trust model email has had for
decades.

{: .note }
The mesh domain (`--domain`) is where chunks, slots, and prekey
RRsets live, and it is shared across the network. The **identity
domain** (`--identity-domain`) is per-user and anchors name ownership.
You can use both together.

## Resolving another user

```bash
# Legacy hash-based (TOFU) resolve
dnsmesh identity fetch alice --add

# Zone-anchored resolve
dnsmesh identity fetch alice@alice.example.com --add
```

Fetch verifies the Ed25519 signature on the record. `--add` saves the
resolved pubkeys as a pinned contact.

When multiple valid records coexist at the resolver target, `--add` is
refused and fingerprints are printed on stderr:

```
ambiguous: 2 valid identity records at id-2bd806c97f0e00af.mesh.local
  fingerprint=a1b2c3d4e5f60718  x25519=3f...  ed25519=ab...  ts=1776721000
  fingerprint=9988776655443322  x25519=12...  ed25519=cd...  ts=1776721200
verify out-of-band and rerun with --accept-fingerprint=<16-hex>
```

This is a squat-resistance guardrail under the shared mesh domain.
Zone-anchored records have exactly one valid publisher by definition,
so the guardrail rarely fires there.

## Pinned vs unpinned contacts

`dnsmesh contacts list` labels each contact:

```
alice   3f…            (pinned)
random  aa…            (UNPINNED)
```

**Pinned** means both the X25519 encryption pubkey *and* the Ed25519
signing pubkey are stored. On receive, only manifests signed by a
pinned signer are delivered.

**Unpinned** means the signing key isn't stored. If every contact is
unpinned, receive falls back to trust-on-first-use and accepts any
signature-valid manifest. Useful for bootstrap, dangerous once you're
actively messaging.

{: .warning }
Always re-add contacts with `--signing-key` (or bootstrap via
`dnsmesh identity fetch <user> --add`) before treating delivered messages
as authenticated. The unpinned path is documented in
[SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md)
as an explicit TOFU exception.

## Rotation

Rotation shipped in M5.4. Two record types live at
`rotate.dmp.<user>.<domain>`:

- **`RotationRecord`** — co-signed by the old and new key, asserts
  that the holder of the old key authorizes the new one as its
  successor. Routine rotations publish only this.
- **`RevocationRecord`** — self-signed by the revoked key, declares
  it dead. Used for compromise scenarios where an attacker may also
  hold the key; rotation-aware fetchers refuse the revoked key
  forever.

Run a routine rotation:

```bash
dnsmesh identity rotate --experimental
```

Run a compromise rotation (publishes both records):

```bash
dnsmesh identity rotate --experimental --reason compromise
```

Contacts who pinned you with `rotation_chain_enabled=True` chain-walk
the rotation RRset on every fetch and pick up the new key
automatically. Pre-M5.4 contacts and contacts pinned without
rotation-chain support need an out-of-band re-pin
(`dnsmesh identity fetch <user> --add`).

The wire format is a draft (`v=dmp1;t=rotation;`) and may bump to
`v=dmp2;t=rotation;` after the external audit (M4.2-M4.4). The
`--experimental` flag is intentional: it gates publication so a
v0.3.0+ flag-flip is needed before rotated keys ride into a stable
release. See [`docs/protocol/rotation.md`]({{ site.baseurl }}/protocol/rotation)
for the wire format, co-signing rationale, and walk algorithm.
