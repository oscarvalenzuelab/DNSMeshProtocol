---
title: Protocol
layout: default
nav_order: 5
has_children: true
permalink: /protocol
---

# DMP Protocol Specification

This directory is the normative reference for the DNS Mesh Protocol (DMP)
wire format, DNS naming conventions, end-to-end flows, and threat model.
A third-party implementation should be buildable from these pages plus
the interop test vectors under `tests/`.

## Top-level reference

- [Spec overview](spec.md) — versioning, record-type registry, common
  invariants, trust model.
- [Wire encoding conventions](wire-encoding.md) — `v=dmp1;t=<type>;`
  prefix, base64 rules, Ed25519 signature placement, magic bytes,
  multi-string TXT splitting, DNS-name validation.
- [DNS name routing](routing.md) — how every record type's DNS owner
  name is computed (mailbox slots, chunks, identity, prekey, cluster,
  bootstrap).
- [End-to-end flows](flows.md) — message send/receive, identity
  publish/fetch, cluster discovery.
- [Threat model](threat-model.md) — defended attacks, residual risks,
  explicit out-of-scope items.

## Per-record-type references

- [Slot manifest](wire-format.md#slot-manifests) — per-message mailbox
  pointer (`v=dmp1;t=manifest;`).
- [Signed identity record](wire-format.md#identity-records) — binds
  `(username, x25519_pk, ed25519_spk)` (`v=dmp1;t=identity;`).
- [One-time prekey](wire-format.md#prekeys) — signed pool of ephemeral
  X25519 keys (`v=dmp1;t=prekey;`).
- [Cluster manifest](cluster.md) — signed node-set for a cluster
  (`v=dmp1;t=cluster;`).
- [Bootstrap record](bootstrap.md) — signed user-domain → cluster
  pointer (`v=dmp1;t=bootstrap;`).

## Adjacent documents

- [Cryptography](crypto.md) — primitives, key derivation, AEAD AAD
  construction.
- [Security model](security-model.md) — short pointer to `SECURITY.md`
  at the repo root (the authoritative threat statement).
- [Legacy wire-format summary](wire-format.md) — the original
  per-record TXT table; still current, referenced by [spec.md](spec.md).
