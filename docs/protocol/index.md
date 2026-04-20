---
title: Protocol
layout: default
nav_order: 5
has_children: true
permalink: /protocol
---

# Protocol

The DMP wire format, crypto primitives, and threat model.

- [Wire format]({{ site.baseurl }}/protocol/wire-format) — exact TXT
  record layouts for chunks, manifests, identities, and prekeys.
- [Cryptography]({{ site.baseurl }}/protocol/crypto) — X25519, Ed25519,
  ChaCha20-Poly1305, Argon2id, and how they compose.
- [Security model]({{ site.baseurl }}/protocol/security-model) — what
  the protocol protects, what it doesn't, and a pointer to the full
  SECURITY.md.
