---
title: Protocol overview (aspirational)
layout: default
parent: Design Intent
nav_order: 1
---

# DNS Mesh Protocol Technical Overview

{: .warning }
This document describes the *aspirational* DMP design — a multi-node mesh
with peer discovery, resolver pools, store relays, and 3× redundancy. The
current implementation is considerably smaller: one client, one node, one
sqlite store, one UDP DNS server.
Treat this file as **design intent**, not current behavior. For what
actually ships, see the [Protocol]({{ site.baseurl }}/protocol) section
and [SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md).

## Core Concept

The DNS Mesh Protocol enables peer to peer messaging by encoding encrypted messages as DNS queries and responses. Since DNS traffic operates on port 53 and is fundamental to internet operation, it typically bypasses firewalls and content filters. The protocol transforms any DNS resolver into a message relay node, creating a globally distributed, censorship resistant communication network.

## How It Works

### Message Flow

When Alice wants to send a message to Bob, her client first encrypts the message using Bob's public key. The encrypted payload gets split into small chunks that fit within DNS TXT record size limits. Each chunk becomes a DNS query to a domain like chunk0001.alice.mesh.network. These queries propagate through the global DNS infrastructure, where participating nodes store and forward them.

Bob's client continuously polls DNS for messages addressed to him by querying his mailbox domains. When chunks arrive, his client reassembles them, verifies integrity using Reed Solomon error correction, and decrypts the message using his private key. The entire exchange appears as normal DNS traffic to network observers.

### Encryption Architecture

Every message uses an ephemeral sender keypair. The sender generates a temporary X25519 keypair per message and performs ECDH with the recipient's long-term X25519 public key. This produces a shared secret used to derive encryption keys via HKDF. The message is then encrypted with ChaCha20-Poly1305 AEAD.

The per-message ephemeral sender key means two messages to the same recipient don't share a session key, which prevents trivial key-material correlation. It does NOT provide forward secrecy against recipient key compromise: anyone who later obtains the recipient's long-term X25519 private key can decrypt recorded historical ciphertexts. Real forward secrecy would require the recipient to publish ephemeral prekeys (Signal-style) or a ratchet, which this protocol does not currently implement.

### DNS Encoding Strategy

DNS has strict limitations that the protocol must respect. Domain names cannot exceed 253 characters total, with individual labels limited to 63 characters. TXT records can hold up to 255 bytes of data. The protocol works within these constraints by encoding binary data as base64 and structuring it as key value pairs that resemble legitimate DNS records.

A typical DMP record looks like v=dmp1;t=chunk;d=base64data;m=metadata. This format allows the protocol to blend with existing DNS traffic patterns while carrying encrypted payloads. The chunking system ensures large messages get split across multiple DNS queries, each appearing independent to observers.

### Mesh Network Topology

The network operates without central servers. Every participating node can act as a relay, storage node, or both. Nodes announce their presence by publishing DNS records at known discovery domains. When a node receives a message not intended for it, it forwards the message to other nodes, creating multiple paths through the network.

This mesh topology provides resilience against node failures and network partitions. If one path becomes unavailable, messages automatically route through alternative paths. The protocol includes TTL values to prevent infinite loops and manages hop counts to optimize routing efficiency.

### Identity Management

Users generate cryptographic key pairs that serve as their identities. The public key becomes the user's address on the network, while the private key remains secret. A user publishes their identity by creating DNS records that map human readable usernames to public keys. These identity records get replicated across multiple DNS zones for redundancy.

To find another user, a client queries DNS for their identity record, retrieves their public key, and verifies the cryptographic signature. This federated identity system requires no central authority or certificate infrastructure; each zone operator is independent.

### Offline Message Handling

When recipients are offline, messages get stored at designated storage nodes. The protocol deterministically selects storage nodes based on the recipient's public key hash, ensuring senders and recipients independently arrive at the same storage locations. Messages remain stored for seven days before automatic deletion.

Storage nodes maintain mailbox slots for each user, with messages rotating through numbered slots. Recipients check all their designated storage nodes when coming online, retrieving any waiting messages. The protocol ensures three way redundancy by storing each message on multiple nodes.

### Resolver Management

The protocol dynamically discovers and manages DNS resolvers. It starts with well known public resolvers like Google, Cloudflare, and Quad9, then discovers additional resolvers through the network. The system monitors resolver performance, automatically failing over when resolvers become slow or unresponsive.

Each chunk gets sent through multiple resolvers for redundancy. The protocol tracks which resolvers successfully delivered messages and maintains a reputation system. Problematic resolvers get blacklisted temporarily, while reliable ones get preferred for future messages.

### Error Correction

Each chunk carries its own Reed Solomon parity bytes, so bit level corruption inside a received chunk can be repaired. This is per chunk protection, not cross chunk erasure coding: a chunk that is lost entirely still kills the message, and the recipient must get every chunk to reassemble. True erasure coding across chunks is future work.

Chunks carry SHA 256 prefix checksums for integrity; the assembler rejects any chunk whose body does not match, as well as chunks whose number falls outside the manifest's stated range. Reassembly requires a contiguous set of chunk indexes, so a malformed or attacker injected chunk cannot poison the buffer.

### Traffic Analysis Resistance

The protocol design allows for random delays between DNS queries, dummy traffic generation, and message padding to resist timing and size based correlation attacks. The current implementation does not yet include these. A passive observer of a mailbox domain can still count messages and infer their approximate size from the number of chunk subdomains. Hardening this is tracked as future work.

### Network Bootstrap

New nodes join the network by querying bootstrap domains that publish lists of active nodes. These bootstrap domains rotate regularly to prevent blocking. Nodes can also exchange peer lists directly, allowing the network to self organize even if bootstrap domains become unavailable.

Once connected, nodes participate in a gossip protocol that shares network topology information. This allows efficient routing decisions and helps nodes discover new peers. The network continuously adapts its topology based on node availability and performance metrics.

## Scalability Considerations

The protocol scales horizontally by adding more nodes and DNS resolvers. Since DNS infrastructure already handles billions of queries daily, the underlying transport can support significant message volume. The chunking system allows messages of any size, though larger messages take proportionally longer to transmit.

Storage scales through the distributed storage node system. As more nodes join, storage capacity increases linearly. The deterministic storage selection ensures even distribution of messages across available nodes, preventing hot spots that could overwhelm individual nodes.

## Security Properties

The protocol provides end to end encryption, ensuring only intended recipients can read messages. Forward secrecy protects past prekey-consumed communications even if long term keys get compromised (pool exhaustion falls back to the long-term key path). Message authentication prevents tampering and forgery. The federated architecture with user-sovereign trust anchors eliminates the single-company single-point-of-failure that centralized platforms expose to surveillance or censorship pressure.

The use of standard DNS makes the protocol difficult to block without disrupting internet functionality. Even sophisticated deep packet inspection struggles to distinguish DMP traffic from legitimate DNS queries. The mesh topology ensures multiple paths exist for message delivery, requiring widespread blocking to prevent communication.

## Practical Deployment

Organizations can deploy DMP nodes using existing DNS infrastructure. A node requires only a domain name and the ability to serve TXT records. Cloud providers, content delivery networks, and even home servers can host nodes. The protocol's lightweight requirements allow deployment on resource constrained devices.

Users need only the client software to participate. The client handles all cryptographic operations, DNS queries, and message management. No special network configuration or permissions are required beyond standard DNS access. This ease of deployment encourages widespread adoption and network growth.