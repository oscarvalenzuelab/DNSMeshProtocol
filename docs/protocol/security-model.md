---
title: Security model
layout: default
parent: Protocol
nav_order: 3
---

# Security model

The authoritative threat model, what's protected, and the honest list
of limits lives in
[SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md)
at the repo root. This page is a short pointer — read that file before
making any trust decision.

## At a glance

### What's protected

- **Confidentiality.** Only the intended recipient reads message
  content.
- **Forward secrecy.** Past messages stay safe after long-term key
  compromise, when the prekey path was taken.
- **Header integrity.** Canonical header subset + `prekey_id` are
  bound into AEAD AAD.
- **Manifest integrity + cross-binding.** Manifest is Ed25519-signed;
  recipient cross-checks the decrypted inner header against it.
- **Sender-identity binding.** With at least one pinned contact, only
  manifests from pinned signers deliver.
- **Replay protection.** Persistent `(sender_spk, msg_id)` cache per
  recipient.
- **Freshness.** Inner-header `ts + ttl` is enforced on receive.

### What's not

- **Post-compromise security.** No ratchet. A leaked signing key can
  sign new manifests until rotated (and rotation is manual).
- **Traffic analysis.** Who-talks-to-whom-and-when is visible on the
  mesh domain.
- **Username ownership under the shared mesh domain.** TOFU only. Use
  zone-anchored identity for real squat resistance.
- **Unreviewed cryptography.** Non-certified — the protocol hasn't
  been through a third-party audit yet.

## Reporting a vulnerability

File via
[GitHub's private vulnerability reporting](https://github.com/oscarvalenzuelab/DNSMeshProtocol/security/advisories/new)
with a minimum repro and your assessment of impact. The advisory
thread stays confidential until it's resolved. Please don't open a
public GitHub issue for an unpatched security bug.
