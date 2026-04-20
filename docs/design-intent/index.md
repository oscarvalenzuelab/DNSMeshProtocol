---
title: Design Intent
layout: default
nav_order: 6
has_children: true
permalink: /design-intent
---

# Design Intent

{: .warning }
The documents under this section describe what the original spec
envisioned — a multi-node mesh with peer discovery, resolver pools,
store relays, 3× redundancy, and bootstrap gossip. The currently
shipping code is smaller and more conservative than that. Treat
everything here as *future work and historical context*, not as
the protocol you're actually running.

For what ships today, read:

- [Home]({{ site.baseurl }}/) — overview of current capabilities
- [Getting Started]({{ site.baseurl }}/getting-started) — how to use
  what ships
- [Protocol]({{ site.baseurl }}/protocol) — wire format and crypto
  as implemented
- [SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md) —
  honest list of what's protected and what isn't

## The documents

- [Protocol overview (aspirational)]({{ site.baseurl }}/design-intent/protocol) —
  original mesh / peer-discovery architecture.
- [Implementation requirements (aspirational)]({{ site.baseurl }}/design-intent/implementation-requirements) —
  the full spec from the start of the project.

Items present here that **do** match current code:

- DNS TXT record encoding strategy (still how things work).
- ChaCha20-Poly1305 + X25519 identity (still used).
- DNS chunking approach (still used, with different chunk sizing).

Items here that **do not** match current code:

- Mesh routing / peer discovery / resolver pools (not implemented).
- 3× storage redundancy (not implemented).
- Bootstrap-domain gossip (not implemented).
- "30% redundancy" from whole-message RS (replaced by per-chunk RS
  plus cross-chunk `zfec` erasure — same spirit, different mechanism).
- Forward secrecy via ephemeral-only sender keys (now actually FS via
  recipient one-time prekeys).
