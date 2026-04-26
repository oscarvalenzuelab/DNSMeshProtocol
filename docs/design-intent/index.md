---
title: Design Intent
layout: default
nav_order: 7
has_children: true
permalink: /design-intent
---

# Design Intent

{: .note }
The documents under this section are the **original project spec** —
written before any code existed. Much of what they describe has since
been built; some has been replaced with a different mechanism in the
same spirit; a few items are deliberately deferred. The per-bullet
status below tells you which is which. For ground-truth on what ships
today, use the links in ["For what ships today"](#for-what-ships-today).

For what ships today
{: #for-what-ships-today }

- [How It Works]({{ site.baseurl }}/how-it-works) — mental model +
  deployment paths (current implementation, not draft).
- [Getting Started]({{ site.baseurl }}/getting-started) — hands-on
  install + first message.
- [Protocol]({{ site.baseurl }}/protocol) — wire format + crypto as
  implemented.
- [CHANGELOG.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/CHANGELOG.md) —
  release-by-release log of what shipped, with commit references.
- [SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md) —
  honest list of what's protected and what isn't.

## The documents

- [Protocol overview (historical spec)]({{ site.baseurl }}/design-intent/protocol)
- [Implementation requirements (historical spec)]({{ site.baseurl }}/design-intent/implementation-requirements)

## Spec → ship delta

Items from the original spec that **ship today**:

- DNS TXT encoding of identity + chunks — ships, same shape.
- ChaCha20-Poly1305 + X25519 message encryption — ships.
- DNS chunking — ships (chunk sizing tuned from the spec's proposal).
- **Resolver pool with per-host health and failover** — ships (M1:
  `dmp/client/resolver_pool.py` + `dnsmesh resolvers discover / list`).
- **Multi-node storage with write redundancy** — ships (M2:
  `FanoutWriter` writes to a quorum of cluster nodes;
  `UnionReader` reads from all; 3-node compose cluster with
  integration tests). The spec's "3× redundancy" is a config
  choice over this mechanism, not a separate system.
- **Anti-entropy sync between nodes** — ships (M2.4: digest-and-pull
  worker so a node that was offline backfills on return).
- **Peer discovery between nodes** — ships (M3.3: signed
  cluster-manifest gossip over the same HTTP channel the nodes use
  for record sync).
- **Bootstrap-domain gossip** — ships (M3.1 `BootstrapRecord` +
  M3.2 `dnsmesh bootstrap discover` + M3.3 cluster-manifest gossip).
- **User-identity key rotation + revocation** — ships (M5.4: co-
  signed `RotationRecord` and self-signed `RevocationRecord`,
  client-side chain-walker, docker e2e coverage).

Items from the original spec that were **replaced with different
mechanisms**:

- "30% whole-message Reed–Solomon redundancy" → per-chunk RS + cross-
  chunk `zfec` erasure (same durability goal; chunk-granular).
- "Forward secrecy via ephemeral sender keys only" → real FS via
  recipient one-time prekeys (Signal/X3DH-shaped, not ephemeral-
  sender-only).

Items from the original spec that are **deliberately deferred**:

- **Dijkstra-style mesh routing** — out of scope. With the M2 +
  M3 cluster model, routing reduces to "which cluster nodes to
  query," and mature mesh libraries (Yggdrasil, cjdns) address
  multi-hop IP-layer routing better than a message-layer protocol
  could.
- **Using DMP as a relay for non-DMP traffic** — also deferred; DMP
  is an application-layer protocol, not an overlay network.
