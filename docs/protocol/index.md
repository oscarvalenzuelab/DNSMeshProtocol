---
title: Protocol
layout: default
nav_order: 5
has_children: true
permalink: /protocol
---

# Protocol

The DMP wire format, crypto primitives, and threat model.

Start here:

- [Spec overview]({{ site.baseurl }}/protocol/spec) — the top-level
  reference: versioning, record-type registry, common invariants,
  trust model.

Deep dives:

- [Wire encoding conventions]({{ site.baseurl }}/protocol/wire-encoding)
  — prefix, base64, Ed25519 placement, magic bytes, multi-string TXT,
  DNS-name rules.
- [DNS name routing]({{ site.baseurl }}/protocol/routing) — how
  every record's DNS owner name is computed.
- [End-to-end flows]({{ site.baseurl }}/protocol/flows) — send,
  receive, identity publish/fetch, cluster discovery.
- [Threat model]({{ site.baseurl }}/protocol/threat-model) —
  adversaries, defenses, out-of-scope items.

Per-record-type references:

- [Wire format]({{ site.baseurl }}/protocol/wire-format) — exact TXT
  record layouts for chunks, manifests, identities, and prekeys.
- [Cluster manifests]({{ site.baseurl }}/protocol/cluster).
- [Bootstrap records]({{ site.baseurl }}/protocol/bootstrap).

Supporting material:

- [Cryptography]({{ site.baseurl }}/protocol/crypto) — X25519, Ed25519,
  ChaCha20-Poly1305, Argon2id, and how they compose.
- [Security model]({{ site.baseurl }}/protocol/security-model) — what
  the protocol protects, what it doesn't, and a pointer to the full
  SECURITY.md.
