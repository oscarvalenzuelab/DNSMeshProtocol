---
title: Bootstrap records
layout: default
parent: Protocol
nav_order: 6
---

# Bootstrap records
{: .no_toc }

A *bootstrap record* is a DNS-discoverable pointer from a user's domain
to one or more DMP clusters. Given an address like `alice@example.com`,
a client can query DNS once — `_dmp.example.com` TXT — and learn which
cluster(s) serve that domain, without any out-of-band configuration
beyond the zone operator's signing key. It is the MX analogue for
DMP: the user's domain tells you which mesh they live on.

M3.1 defines this record type. M3.2 wires it into the client so the
cluster-mode handshake can start from an email address rather than a
pre-pinned `(cluster_base_domain, operator_spk)` pair.

1. TOC
{:toc}

## Purpose

Before M3.1, a client configured in cluster mode needed two pieces of
out-of-band information: the cluster base domain (`mesh.example.com`)
and the cluster operator's Ed25519 public key. For a user address like
`alice@example.com`, there was no programmatic way to discover which
cluster handles `example.com` — operators pinned by hand.

A bootstrap record lets a client:

- Discover N cluster candidates (priority-ordered like SMTP MX) from
  one pinned DNS pointer under the user's domain.
- Pin the best cluster's `(cluster_base_domain, operator_spk)` and
  proceed to the normal cluster-mode fetch
  (`ClusterManifest` at `cluster.<cluster_base_domain>`).
- Fall back to lower-priority clusters on failure.

## Threat model

**Trust anchor.** The signer of a bootstrap record is the *zone
operator* of the user's domain — the party with authority to publish
under `_dmp.example.com`. This is distinct from the cluster operator,
whose key signs the `ClusterManifest` at
`cluster.<cluster_base_domain>`. In a self-hosted deployment the two
keys may be the same; in a multi-tenant deployment the zone operator
lists clusters run by third parties.

**Key distribution is out of scope.** This record type assumes the
client already knows the zone operator's Ed25519 public key by some
out-of-band mechanism: a published fingerprint on a website, a
shared-secret handshake at sign-up, a DNSSEC-anchored extension, etc.
The record itself cannot bootstrap its own trust anchor. M3.2 will
address how operators publish this key in practice.

**What a compromise of the zone's signing key grants.** An attacker
with that key publishes a signature-valid bootstrap record naming
their own cluster, and pinned clients accept it. Every user under that
domain can be redirected to a hostile cluster. The signature protects
integrity and source of the record; it does **not** guarantee the zone
operator chose an honest cluster — a malicious or coerced operator can
point at a cluster they control.

Operators running high-value deployments should:

- Keep the zone's signing key offline and rotate it on a clear
  schedule.
- Publish a key fingerprint out-of-band (website, printed material) so
  a compromise is detectable.
- Consider pinning the ClusterManifest operator key independently — a
  bootstrap-record redirect then still requires the cluster key also
  being compromised to serve forged records under the expected name.

## Publishing convention

```
_dmp.<user_domain>   IN TXT  "v=dmp1;t=bootstrap;<b64(body || sig)>"
```

- `<user_domain>` — the user's email/address domain, e.g.
  `example.com`. Matches the `user_domain` field inside the signed
  body. Validation rules (ASCII, labels 1..63 chars of
  letters/digits/`-`, no empty labels, no IDN, byte cap 64) are
  identical to `ClusterManifest.cluster_name`; the two share a single
  `_validate_dns_name` implementation imported from
  `dmp.core.cluster`.
- The `bootstrap_rrset_name("example.com")` helper returns
  `_dmp.example.com`. Kept as a function so the convention can evolve
  without churning call sites.

The base64 payload is allowed to span multiple TXT strings within the
same RRset, same as `ClusterManifest`. All the built-in publishers
already split values longer than 255 bytes into multi-string TXT RDATA
on publish.

## Wire format

`v=dmp1;t=bootstrap;` prefix (19 bytes) followed by base64-encoded
`body || sig` where `sig` is a 64-byte Ed25519 signature over `body`.

Body layout (big-endian integers):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 7 | `magic` | `b"DMPBS01"` — version tag; wrong magic → reject |
| 7 | 8 | `seq` | Monotonic sequence; higher wins when two records surface |
| 15 | 8 | `exp` | Unix seconds; record rejected if past |
| 23 | 32 | `signer_spk` | Ed25519 pubkey echoed for sanity; must equal caller arg |
| 55 | 1 | `user_domain_len` | 1..64 |
| 56 | var | `user_domain` | UTF-8 |
| — | 1 | `entry_count` | 1..16 |
| — | — | per entry (below) | `entry_count` entries |

Per-entry layout:

| Size | Field | Notes |
|---|---|---|
| 2 | `priority` | 0..65535; lower is preferred (SMTP MX semantics) |
| 1 | `base_domain_len` | 1..64 |
| var | `cluster_base_domain` | UTF-8; a valid DNS name |
| 32 | `operator_spk` | Ed25519 pubkey to trust for that cluster |

Absolute wire-length cap: **1200 bytes** (post-base64, post-prefix),
same as `ClusterManifest`. `sign()` raises `ValueError` if the
encoded record exceeds it, and `parse_and_verify` returns `None` for
any oversized wire. A 16-entry record with short cluster base domains
(~12 bytes each) fits comfortably; a 16-entry record with
near-maximum-width base domains requires sharding.

## Client flow

1. Given an address like `alice@example.com`, extract the user domain
   (`example.com`).
2. Fetch `_dmp.example.com` TXT.
3. Call `BootstrapRecord.parse_and_verify(wire, signer_spk,
   expected_user_domain="example.com")`. Returns the record on
   success, `None` on any failure (wrong signer, tampered bytes,
   expired, malformed, user-domain mismatch, oversized). Never trust
   any body field that `parse_and_verify` rejects.
4. Call `record.best_entry()` — returns the lowest-priority entry
   (`entries[0]`). On priority ties, stable-sort order preserves
   insertion order; clients facing ties should try `entries[0]` first
   and fall back to `entries[1]` on connection failure.
5. Pin `(entry.cluster_base_domain, entry.operator_spk)` as the
   cluster anchors and proceed to the normal M2.wire cluster-mode
   handshake: fetch `cluster.<cluster_base_domain>` TXT, call
   `ClusterManifest.parse_and_verify`, install manifest, etc.

If the best entry fails (cluster unreachable, manifest won't verify),
the client should walk down the priority list before giving up.

## Security properties

The Ed25519 signature covers the entire body, including the entry
list. An attacker without the zone operator's signing key cannot:

- Add, remove, or reorder entries.
- Rewrite a `cluster_base_domain` or `operator_spk` to a value they
  control.
- Lower `priority` on a hostile cluster to promote it above the
  intended primary.
- Extend the expiry to keep a revoked record alive.
- Lower `seq` to roll back to an older record. (The *client-side*
  seq compare is the check — the signature alone doesn't stop
  rollback.)

The `signer_spk` field inside the signed body is cross-checked against
the caller-supplied pubkey arg in `parse_and_verify` as defense in
depth: a record whose embedded key disagrees with the expected one is
rejected, even if the signature would otherwise verify against some
other key.

The signature does **not** protect against:

- Compromise of the zone's Ed25519 signing key (see Threat model).
- A malicious zone operator pointing at a hostile cluster — the record
  only proves the zone operator made a choice, not that the choice is
  honest.
- Correlation of who is reading the record. The wire is plaintext
  (base64 is an encoding, not encryption).

## Rollout semantics

Mirrors `ClusterManifest`:

- **Higher `seq` wins.** When multiple bootstrap records surface for
  the same `_dmp.<user_domain>` (staged rollout across authoritative
  nameservers), the client picks the signed record with the highest
  `seq` whose signature verifies and whose `exp` is in the future.
- **Expiry enforced.** Records with `exp < now` are rejected at
  `parse_and_verify`. The default now is `time.time()`; callers can
  override via the `now=` kwarg.
- **Entries sorted by priority on both sign and parse.** `best_entry()`
  is deterministic: `entries[0]` after the sort. A buggy publisher
  that serializes out-of-order entries does not cause clients to
  pick the wrong best choice.

## Related records

- [Spec overview]({{ site.baseurl }}/protocol/spec) — cross-cutting
  invariants every signed record (including this one) respects:
  `v=dmp1;t=<type>;` prefix, trailing 64-byte Ed25519 signature,
  embedded-signer cross-check, 1200-byte wire cap, multi-string TXT,
  DNS-name validation.
- [Wire encoding conventions]({{ site.baseurl }}/protocol/wire-encoding)
  — byte-level details on the `v=dmp1;t=bootstrap;` prefix, `DMPBS01`
  magic, base64 + signature placement.
- [DNS name routing]({{ site.baseurl }}/protocol/routing#bootstrap-record)
  — why the owner name is `_dmp.<user_domain>`.
- [End-to-end flows]({{ site.baseurl }}/protocol/flows#cluster-discovery-bootstrap--cluster-manifest--client)
  — how a client fetches + verifies + walks entries from this record.
- [Threat model]({{ site.baseurl }}/protocol/threat-model) — what a
  zone-operator compromise does (and does not) enable.
- [Cluster manifests]({{ site.baseurl }}/protocol/cluster) — the
  record a bootstrap entry points at. A client fetches the bootstrap
  record first, takes `best_entry()`, then fetches the matching
  cluster manifest.
- [Identity records]({{ site.baseurl }}/protocol/wire-format#identity-records)
  — per-user records, orthogonal to both bootstrap and cluster
  manifests.
