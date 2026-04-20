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
dmp identity publish
```

This writes a signed `IdentityRecord` (108 signed bytes plus a 64-byte
Ed25519 signature) to DNS. The exact name depends on whether you
configured a zone you control:

### Shared mesh domain (TOFU)

Without `--identity-domain` at `dmp init`, the record goes to
`id-{sha256(username)[:16]}.<mesh_domain>`. Anyone can publish at any
username — the hash is only a name-to-label mapping, not a trust root.
Squatting is possible and mitigated only at fetch time by the
`--accept-fingerprint` dance.

### Zone-anchored (recommended for real use)

Initialize with a DNS zone you control:

```bash
dmp init alice --identity-domain alice.example.com \
               --domain mesh.local --endpoint ...
dmp identity publish
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
dmp identity fetch alice --add

# Zone-anchored resolve
dmp identity fetch alice@alice.example.com --add
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

`dmp contacts list` labels each contact:

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
`dmp identity fetch <user> --add`) before treating delivered messages
as authenticated. The unpinned path is documented in
[SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md)
as an explicit TOFU exception.

## Rotation

There is no automatic rotation. If a key leaks:

1. Generate a new identity with a fresh config (`dmp init --force` or
   a new `$DMP_CONFIG_HOME`).
2. Publish the new identity.
3. Contact everyone out of band, tell them to re-`dmp identity fetch`.

Proper key-rotation records are on the roadmap but not shipping in
the current alpha.
