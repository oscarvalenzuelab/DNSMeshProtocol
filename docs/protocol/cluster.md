---
title: Cluster manifests
layout: default
parent: Protocol
nav_order: 5
---

# Cluster manifests
{: .no_toc }

A *cluster* is a set of DMP nodes run by one or more operators that
collectively serve the same mailbox data. A client pins a cluster
operator's Ed25519 public key once, fetches the cluster manifest from a
well-known DNS name, and learns the current node set — HTTP endpoints
for writes, optional DNS endpoints for reads. Sequence numbers drive
rollout; expiry kills stale node sets.

M2.1 defines this record. M2.2 (fan-out writer) and M2.3 (union reader)
consume it.

1. TOC
{:toc}

## Purpose

Single-node clients depend on one operator. If that node is down,
compromised, or censored, the client has no recourse. A cluster
manifest lets a client:

- Discover N nodes from one pinned DNS pointer.
- Detect node-set changes (the operator rotates in a new node, drops
  a dead one) without reconfiguration.
- Reject stale or forged lists — the manifest is signed, and clients
  pin the operator's public key out-of-band.

## Publishing convention

```
cluster.<cluster_name>   IN TXT  "v=dmp1;t=cluster;<b64(body || sig)>"
```

- `<cluster_name>` — the display/log name of the cluster, e.g.
  `mesh.example.com`. Matches the `cluster_name` field inside the
  signed body.
- The `cluster_rrset_name("mesh.example.com")` helper returns
  `cluster.mesh.example.com`. This is kept as a function so we can
  evolve the convention (e.g. to `_dmp-cluster.<name>` SRV-style)
  without churning call sites.

The base64 payload is allowed to span multiple TXT strings within the
same RRset. dnspython callers already reassemble with
`b"".join(rdata.strings)`. Operators publishing via zone files must
split at any 255-byte boundary; readers do not care where the splits
land.

## Wire format

`v=dmp1;t=cluster;` prefix (17 bytes) followed by base64-encoded
`body || sig` where `sig` is a 64-byte Ed25519 signature over `body`.

Body layout (big-endian integers):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 7 | `magic` | `b"DMPCL01"` — version tag; wrong magic → reject |
| 7 | 8 | `seq` | Monotonic sequence; higher wins when two manifests surface |
| 15 | 8 | `exp` | Unix seconds; manifest rejected if past |
| 23 | 32 | `operator_spk` | Ed25519 pubkey echoed for sanity; must equal caller arg |
| 55 | 1 | `cluster_name_len` | 1..64 |
| 56 | var | `cluster_name` | UTF-8 |
| — | 1 | `node_count` | 0..32 |
| — | — | per node (below) | `node_count` entries |

Per-node entry:

| Size | Field | Notes |
|---|---|---|
| 1 | `node_id_len` | 1..16 |
| var | `node_id` | ASCII |
| 2 | `http_endpoint_len` | 1..128 (uint16 BE) |
| var | `http_endpoint` | UTF-8 |
| 2 | `dns_endpoint_len` | 0..64 (uint16 BE; 0 = absent) |
| var | `dns_endpoint` | UTF-8; omitted when length is 0 |

Absolute wire-length cap: **1200 bytes** (post-base64, post-prefix).
`sign()` raises `ValueError` if the encoded record exceeds it.
Operators who genuinely need larger clusters should shard across
multiple manifests (M3 territory).

A realistic 6-node manifest
(cluster_name=`mesh.example.com`, node_ids=`n01..n06`,
http=`https://nX.mesh.example.com:8053`, dns=`203.0.113.X:53`)
serializes to ~633 wire bytes.

## Client behavior

1. **Pin the operator public key out-of-band.** The whole security
   model rests on the client trusting a specific Ed25519 key for a
   specific cluster. Fetching the key from DNS itself is a bootstrap
   problem that M3 will address; for M2, clients hard-code or config-
   file the key.
2. **Fetch** `cluster.<cluster_name>` TXT.
3. **Call** `ClusterManifest.parse_and_verify(wire, operator_spk)`.
   It returns a `ClusterManifest` on success, `None` on any failure
   (wrong signer, tampered bytes, expired, malformed, missing prefix).
   Never trust any field of a manifest that `parse_and_verify` rejects.
4. **Refetch on seq bump.** If a fetch returns a higher `seq` than
   the cached copy, replace. Lower `seq` is ignored — rollback
   resistance without a heavier consensus layer.
5. **Drop expired manifests.** The receiver's default is to reject
   expired records at `parse_and_verify`; callers passing their own
   `now=` get to decide.

## Security properties

The Ed25519 signature covers the entire body, including the node list.
An attacker cannot:

- Add, remove, or reorder node entries.
- Rewrite an endpoint URL to a host they control.
- Extend the expiry to keep a revoked node set alive.
- Lower the `seq` to roll back to an older, compromised node set that
  the client has already moved past (the *client-side* `seq` compare
  is the check — the signature alone doesn't stop rollback).

The signature does **not** protect against:

- **Compromise of the operator's Ed25519 key.** If the key leaks, an
  attacker publishes a signature-valid manifest naming their own
  nodes, and pinned clients accept it. Operators should keep the
  signing key offline and rotate it (via a new cluster name; there is
  no in-band key rotation in M2.1).
- **Correlation of who is reading the manifest.** The manifest is
  plaintext on the wire (base64 is just an encoding). Anyone on path
  learns the node set from a packet capture.
- **Traffic-analysis of which nodes a client then talks to.** That
  is the reader/writer modules' concern — M2.2 and M2.3.

The `operator_spk` field inside the signed body is cross-checked
against the caller-supplied pubkey arg in `parse_and_verify` as
defense in depth: a manifest whose embedded key disagrees with the
expected one is rejected, even if the signature would otherwise
verify against some other key. This guards against accidental
misuse of `parse_and_verify` (passing the wrong pubkey because of a
config typo) producing a false-accept.

## Related records

- [Slot manifests]({{ site.baseurl }}/protocol/wire-format#slot-manifests)
  — per-message records that sit *inside* a cluster.
- [Identity records]({{ site.baseurl }}/protocol/wire-format#identity-records)
  — per-user records. Orthogonal to cluster manifests; a user's
  identity is not tied to a particular cluster.
