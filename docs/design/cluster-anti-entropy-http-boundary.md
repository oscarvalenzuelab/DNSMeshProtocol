# Cluster anti-entropy: the HTTP boundary

**Status:** decided 2026-04-25 for the 0.5.0 release.
**Issue:** [#6](https://github.com/oscarvalenzuelab/DNSMeshProtocol/issues/6)
**Decision:** option (C) — accept HTTP for cluster-internal sync,
document the boundary, defer a DNS-native redesign to a future major
version.

## The trust boundary, stated plainly

> **Federation and first-contact are DNS-only; cluster replication is
> an operator-scoped HA mechanism and the only remaining inter-node
> HTTP path.**

Federation paths run between nodes that don't trust each other —
two independent operators, two zones — and use DNS so neither side
exposes an authenticated HTTP surface to the other. Cluster
replication runs between nodes the **same operator** runs to scale
or survive failures; those peers verify each other through one
signed cluster manifest, share credentials, and exist inside one
administrative trust domain. The threat model is different, so the
transport choice is different.

## Where the boundary sits

After M9 the DMP code path table looks like this:

| Surface | Direction | Transport |
|---|---|---|
| User → own node | Auth (challenge / TSIG mint) | HTTPS |
| User → own node | Record writes | DNS UPDATE + TSIG |
| Sender → claim provider (foreign zone) | Claim publish | DNS UPDATE (un-TSIG'd, Ed25519-signed wire) |
| Node → peer node (different zone) | Heartbeat / discovery / seen-graph | DNS query |
| **Cluster peer → cluster peer** | **Anti-entropy (digest + pull)** | **HTTP** |

Everything except the last row is DNS-only. The last row stays HTTP
**by design** for 0.5.0.

## Why cluster sync is the documented exception

Cluster peers are **not** mutually-untrusting. The operator publishes
a signed cluster manifest at `cluster.<base-zone>`; every cluster node
verifies sibling identity through the same pinned operator key. They
share one administrative domain.

The "no HTTP between independent federation peers" rule that drives
M9 is about defending against a hostile peer in a federation
deployment where nodes don't trust each other. That threat model
doesn't fit a single operator's HA cluster.

Other reasons HTTP stays here:

- The digest/pull protocol uses a `(ts, name, value_hash)` cursor
  for incremental pagination and per-name hash selection on pull.
  Translating that into DNS query/response without losing the
  cursor semantics needs custom RRset encoding and adds wire
  complexity that doesn't change the trust boundary.
- Cluster operators already run an HTTP path between cluster peers
  for ops surfaces (health, metrics) they rely on. Adding DNS as a
  parallel inter-cluster transport doesn't simplify operations.
- Anti-entropy is an HA implementation detail, not a protocol
  primitive. Other DMP installations don't need to interoperate
  with a cluster's internal sync; only the cluster operator does.

## What's NOT changed by this decision

- Heartbeat / discovery / seen-graph — DNS-only between any two
  nodes regardless of cluster membership. Unaffected.
- Claim publish from arbitrary senders to a provider — DNS-only,
  un-TSIG'd UPDATE gated by the wire's Ed25519 signature.
  Unaffected.
- TSIG-authorized record writes (identity / prekeys / mailbox /
  chunk) — DNS-only via `_DnsUpdateWriter`. Unaffected.
- A user with a registered TSIG key against a cluster node uses
  DNS UPDATE for their own writes; the cluster's anti-entropy
  worker propagates that write across cluster peers via HTTP.
  The user-facing path stays DNS; only the post-write replication
  uses HTTP.

## Single-node operators

If you're running one DMP node (not a cluster), the anti-entropy
worker isn't wired in at all — there are no peers to sync with —
and this exception doesn't apply to your deployment.

## Future work

A future major version may move cluster sync to DNS via one of:

1. **Pure-DNS sync via custom RRsets** — publish digests at
   `_dnsmesh-digest.<peer-zone>` as multi-value TXT; consumers
   query and diff locally. Tradeoff: full digest read every tick,
   no incremental cursor — acceptable at ≤ ~5 nodes per cluster,
   doesn't scale to hundreds.

2. **DNS UPDATE-based push** — every local write fans out via DNS
   UPDATE signed with a cluster-shared TSIG key. Eliminates the
   pull dance; convergence happens on write. Tradeoff: cold-start
   resync needs a separate "give me everything" path that DNS
   doesn't model well.

Issue [#6](https://github.com/oscarvalenzuelab/DNSMeshProtocol/issues/6)
tracks both designs. They're deferred until there's a concrete
operational reason to bridge the boundary further.

## Code references

- `dmp/server/anti_entropy.py` — the worker. Module docstring
  carries this boundary explanation.
- `dmp/cli.py` — `_build_cluster_writer_factory` constructs the
  per-node `_HttpWriter`. Docstring points back here.
- `dmp/cli.py` — `_make_client` already prefers `_DnsUpdateWriter`
  when the user has a TSIG block configured, so user-originated
  writes are DNS even in cluster mode (round-11 P1 fix).
