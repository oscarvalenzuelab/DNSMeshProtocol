---
title: Spec → Ship
layout: default
nav_order: 7
permalink: /design-intent
---

# Spec → Ship

What the original DMP spec proposed (written before any code
existed) versus what actually shipped. Some items shipped as
specified, some shipped under a different mechanism in the same
spirit, and some were deliberately deferred. Use this page to map
between the original design language and the current implementation;
for ground-truth on what ships today, follow the per-item links into
the protocol docs and CHANGELOG.

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
