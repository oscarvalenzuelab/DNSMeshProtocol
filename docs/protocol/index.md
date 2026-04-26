---
title: Protocol
layout: default
nav_order: 5
has_children: true
permalink: /protocol
---

# DMP Protocol Specification

The normative reference for the DNS Mesh Protocol — wire format, DNS
naming conventions, end-to-end flows, threat model. A third-party
implementation should be buildable from these pages plus the interop
test vectors under
[`tests/test_vectors.py`](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/tests/test_vectors.py).

## Top-level reference

- [Spec overview]({{ site.baseurl }}/protocol/spec) — versioning,
  record-type registry, common invariants, trust model.
- [Wire encoding conventions]({{ site.baseurl }}/protocol/wire-encoding)
  — `v=dmp1;t=<type>;` prefix, base64 rules, Ed25519 signature
  placement, magic bytes, multi-string TXT splitting, DNS-name
  validation.
- [DNS name routing]({{ site.baseurl }}/protocol/routing) — how
  every record type's DNS owner name is computed (mailbox slots,
  chunks, identity, prekey, cluster, bootstrap).
- [End-to-end flows]({{ site.baseurl }}/protocol/flows) — message
  send/receive, identity publish/fetch, cluster discovery.
- [Threat model]({{ site.baseurl }}/protocol/threat-model) —
  defended attacks, residual risks, explicit out-of-scope items.

## Per-record-type references

- [Slot manifest]({{ site.baseurl }}/protocol/wire-format#slot-manifests)
  — per-message mailbox pointer (`v=dmp1;t=manifest;`).
- [Signed identity record]({{ site.baseurl }}/protocol/wire-format#identity-records)
  — binds `(username, x25519_pk, ed25519_spk)` (`v=dmp1;t=identity;`).
- [One-time prekey]({{ site.baseurl }}/protocol/wire-format#prekeys) —
  signed pool of ephemeral X25519 keys (`v=dmp1;t=prekey;`).
- [Cluster manifest]({{ site.baseurl }}/protocol/cluster) — signed
  node-set for a cluster (`v=dmp1;t=cluster;`).
- [Bootstrap record]({{ site.baseurl }}/protocol/bootstrap) — signed
  user-domain → cluster pointer (`v=dmp1;t=bootstrap;`).

## Adjacent documents

- [Cryptography]({{ site.baseurl }}/protocol/crypto) — primitives, key
  derivation, AEAD AAD construction.
- [Security model]({{ site.baseurl }}/protocol/security-model) — short
  pointer to [SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md)
  at the repo root (the authoritative threat statement).
- [Key rotation]({{ site.baseurl }}/protocol/rotation) — co-signed
  rotation chain + revocation records.
