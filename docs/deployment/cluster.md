---
title: Clustered deployment
layout: default
parent: Deployment
nav_order: 3
---

# Clustered deployment
{: .no_toc }

1. TOC
{:toc}

The single-node setup in [Docker]({{ site.baseurl }}/deployment/docker) is
simple and enough for many use cases, but it has a single point of
failure: if the one node is down, nobody can publish or resolve. This
page walks through running a **three-node federated cluster** with
node-side anti-entropy so records propagate across peers and survive
individual node failure.

## What you get vs single-node

| Property | Single-node | 3-node cluster |
|---|---|---|
| Node survives one instance failure | No | Yes (with quorum client writes) |
| Records propagate across peers automatically | N/A | Yes, via anti-entropy (M2.4) |
| Ops overhead | Minimal | Signed cluster manifest + shared peer token |
| Use case | Personal node, low availability | Operator-scale deployment |

The cluster still has a single trust anchor — the Ed25519 **operator
key** that signs the cluster manifest. Compromising that key lets an
attacker redirect clients; rotate it out-of-band if you suspect
exposure.

## Starting point: `docker-compose.cluster.yml`

The repo ships `docker-compose.cluster.yml` plus a `docker/cluster/`
directory with per-node env files. It stands up three containers:

- `dmp-node-a` on host ports `127.0.0.1:5301` (DNS) + `127.0.0.1:8101` (HTTP)
- `dmp-node-b` on `127.0.0.1:5302` + `127.0.0.1:8102`
- `dmp-node-c` on `127.0.0.1:5303` + `127.0.0.1:8103`

All three share an internal docker network `dmp-cluster` so they can
reach each other as `http://dmp-node-a:8053`, `http://dmp-node-b:8053`,
`http://dmp-node-c:8053`. The host-side port bindings are `127.0.0.1`
only — **sync endpoints MUST NOT be exposed publicly**. A real
production deployment adds a reverse-proxy layer (see
[`docker-compose.prod.yml`]({{ site.baseurl }}/deployment/production))
and only publishes the public DNS + HTTP API ports.

## Step 1 — generate a cluster manifest

The cluster manifest names the three nodes and is signed by the
operator key. A helper script generates both:

```bash
python docker/cluster/generate-cluster-manifest.py \
    --cluster-name mesh.example.com \
    --manifest-out docker/cluster/cluster-manifest.wire \
    --operator-key-out docker/cluster/operator-ed25519.hex
```

The script **generates a fresh Ed25519 keypair** and prints a warning.
The emitted file `operator-ed25519.hex` contains the seed from which
both the X25519 and Ed25519 keypairs derive — treat it like any other
secret.

{: .warning }
**The script's key is dev-only.** Real deployments must manage the
operator signing key through a KMS / HSM / offline-signing workflow
— not a hex file on disk. The repo-shipped script is a convenience
for getting the sample cluster up, not a production key-management
story.

{: .note }
`docker/cluster/operator-ed25519.hex` and
`docker/cluster/cluster-manifest.wire` are listed in the repo's
`.gitignore` so a generated operator seed cannot be committed by
accident. For extra safety, operators can point `--operator-key-out`
and `--manifest-out` at paths OUTSIDE the checkout (e.g.
`~/.dmp/operator-ed25519.hex`) and mount them into the compose
services via a bind-mount override rather than the default relative
path.

## Step 2 — wire the peer anchor into each node env file

Each `docker/cluster/node-{a,b,c}.env` has a commented-out
`DMP_SYNC_OPERATOR_SPK` line. Paste the public key the generator
printed into all three files:

```bash
DMP_SYNC_OPERATOR_SPK=__paste_operator_public_hex_here__
```

Also change `DMP_SYNC_PEER_TOKEN` from the placeholder
`dev-cluster-token-change-me` to a strong random string. The same
value in all three node env files — every node must be able to
authenticate to every other.

## Step 3 — bring up the cluster

```bash
docker compose -f docker-compose.cluster.yml up -d
```

Verify all three are healthy:

```bash
for port in 8101 8102 8103; do
    curl -s http://127.0.0.1:${port}/health | jq .
done
```

## How anti-entropy works

Each node runs a background thread (`AntiEntropyWorker`) that every
`DMP_SYNC_INTERVAL_SECONDS` seconds:

1. Picks a peer and GETs `http://<peer>/v1/sync/digest?cursor=<opaque>`
   with the shared `DMP_SYNC_PEER_TOKEN`. Returns a compact list of
   `(name, hash, ts, ttl)` for records written since the last tick.
2. Compares against its own store. Any `(name, hash)` pair missing
   locally — OR present but with a stale TTL — goes on the pull list.
3. POSTs `http://<peer>/v1/sync/pull` with the pull list. The peer
   returns the full TXT values.
4. **Re-verifies signatures** on signed record types
   (`ClusterManifest`, `IdentityRecord`, `Prekey`, `SlotManifest`,
   `BootstrapRecord`) before writing. Peers are untrusted.
5. Writes validated records to the local store and advances the
   per-peer watermark (compound cursor `(ts, name, value_hash)`).

## Gossip and manifest rotation (M3.3)

Before M3.3, rolling out a new signed manifest meant pushing the
`cluster-manifest.wire` file to every node's disk and restarting — or
at minimum re-publishing the manifest on every node out-of-band.
Operators of larger clusters will rotate endpoints or add/drop nodes
often enough that the manual push is a footgun.

With M3.3, the anti-entropy worker **also gossips the signed cluster
manifest** every tick. Operators push the new manifest to ONE node;
the rest pick it up within one or two `DMP_SYNC_INTERVAL_SECONDS` and
install it automatically.

### Requirements to enable gossip

All three must be set on every node:

- `DMP_SYNC_OPERATOR_SPK` — hex-encoded Ed25519 operator public key.
  **This is the trust anchor.** A gossiped manifest that does not
  verify under this key is silently dropped. Without a pinned
  operator key, gossip stays off entirely — trust-on-first-use for a
  new cluster operator would be a security leak.
- `DMP_CLUSTER_BASE_DOMAIN` — the cluster name (e.g.
  `mesh.example.com`). Binds each gossiped manifest to the expected
  cluster; a manifest correctly signed by the operator but naming a
  different cluster is rejected. If unset, the node derives the
  base_domain from (in order): the on-disk cluster manifest file
  (verified under `DMP_SYNC_OPERATOR_SPK`), then the highest-seq
  verifying manifest already persisted in the local sqlite store
  (restart-recovery for gossip-only nodes). Existing compose
  deployments get gossip for free once they pin
  `DMP_SYNC_OPERATOR_SPK`.
- `DMP_SYNC_PEER_TOKEN` — as for other sync endpoints. The
  `/v1/sync/cluster-manifest` endpoint shares this token with
  `/v1/sync/digest` and `/v1/sync/pull`.

`DMP_SYNC_SELF_ENDPOINT` is optional but recommended: it lists this
node's own HTTP URL on the peer network so a manifest that includes
self in the node set never produces a self-sync loop. The
`node_id`-based self filter covers the compose-sample case already;
this is belt-and-suspenders.

### How a manifest rolls through the cluster

```
                 seq=5, signed                    seq=5
                 by operator                      (gossiped)
    operator ────────────────▶ node-a ──────────▶ node-b
                                │                    │
                                │ seq=5 (gossiped)   │ seq=5
                                ▼                    ▼
                              node-c              node-c
```

1. Operator regenerates the manifest with a bumped `seq` (and any
   endpoint or node-list changes) using
   `docker/cluster/generate-cluster-manifest.py`.
2. Operator pushes the new wire to ONE node — for example by writing
   it to that node's `cluster.<base>` TXT via the HTTP publish API,
   or by replacing the mounted manifest file and sending SIGHUP.
3. Within one or two `DMP_SYNC_INTERVAL_SECONDS`, every peer gossip
   worker:
   - GETs `/v1/sync/cluster-manifest` from its round-robin peer,
   - verifies the returned wire under the pinned operator key and
     expected cluster name,
   - checks that `seq` is strictly higher than any manifest it has
     seen before (downgrades silently rejected),
   - republishes the wire under `cluster.<base>` TXT in the local
     store (append-semantics keeps the old wire during the TTL
     window — clients pick highest-seq that verifies),
   - swaps the live anti-entropy peer set to the new node list.
     Retained peers keep their watermarks. New peers start at the
     `(0, "", "")` sentinel. Dropped peers have their state cleared.

### Rotation playbook

```bash
# 1. Bump seq and rotate (example: add node-d, drop node-c).
python docker/cluster/generate-cluster-manifest.py \
    --cluster-name mesh.example.com \
    --manifest-out /tmp/cluster-manifest.wire \
    --operator-key-in ~/.dmp/operator-ed25519.hex \
    --node node-a,http://dmp-node-a:8053 \
    --node node-b,http://dmp-node-b:8053 \
    --node node-d,http://dmp-node-d:8053

# 2. Push to ONE node via the HTTP publish API. The bearer token is
#    the node's DMP_HTTP_TOKEN, not DMP_SYNC_PEER_TOKEN.
curl -X POST \
    -H "Authorization: Bearer $NODE_A_HTTP_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"value\": \"$(cat /tmp/cluster-manifest.wire)\", \"ttl\": 300}" \
    http://127.0.0.1:8101/v1/records/cluster.mesh.example.com

# 3. Wait one or two DMP_SYNC_INTERVAL_SECONDS and verify convergence:
for port in 8101 8102 8103; do
    curl -s \
        -H "Authorization: Bearer $DMP_SYNC_PEER_TOKEN" \
        http://127.0.0.1:${port}/v1/sync/cluster-manifest \
        | jq '.seq'
done
# All three should print the new seq.
```

### Gossip security invariants

| Property | Enforced where |
|---|---|
| A gossiped manifest must verify under the **pinned** operator key | `ClusterManifest.parse_and_verify` with `operator_spk` arg |
| A gossiped manifest must bind to the **expected** cluster_name | `parse_and_verify` with `expected_cluster_name=base_domain` |
| A gossiped manifest must have `seq` **strictly greater** than the highest seen locally | Worker `_current_installed_seq` check before install |
| A gossiped manifest must not be **expired** | `parse_and_verify` checks `exp > now` |
| Gossip is **OFF** when operator key is not pinned | Worker `_gossip_enabled()` short-circuits |
| A node **cannot sync with itself** | `_filter_self` drops any peer entry matching `self_node_id` or `self_http_endpoint` |

A compromised peer can at worst serve an older or unrelated manifest,
which `parse_and_verify` rejects. It cannot install a forged
manifest — the signature is checked against the locally-pinned
operator key.

## Trust model and failure modes

| Failure | Behavior |
|---|---|
| One node down | Remaining two stay authoritative; clients in cluster mode quorum at `ceil(2/2) = 1`. Restart catches up via anti-entropy. |
| Two nodes down | Cluster writes still succeed (quorum = 1) to the surviving node; reads are served from it only. |
| Peer lies in `/digest` or `/pull` | Hash mismatch between digest-advertised and pull-returned value → record rejected, watermark not advanced. |
| Peer returns records you didn't ask for | Rejected. |
| Peer fabricates a `next_cursor` | Ignored; watermark only advances to the max of validated-and-handled entries. |
| Shared `DMP_SYNC_PEER_TOKEN` leaks | An attacker who reaches the peer HTTP ports can read and inject. Rotate immediately and firewall-restrict peer access to the cluster network. |
| Operator key leaks | An attacker can sign a forged cluster manifest pointing at their nodes. Rotate out-of-band; clients that have pinned the old operator key must re-pin. |
| Peer serves an older manifest via `/v1/sync/cluster-manifest` | Rejected by `seq <= current_local_seq` check — gossip never downgrades. |
| Peer serves a manifest signed by a different key | Rejected by signature verification against the pinned `DMP_SYNC_OPERATOR_SPK`. |
| Peer serves a manifest bound to a different cluster | Rejected by `expected_cluster_name` binding. |

## Test suite

`tests/test_compose_cluster.py` provides an integration suite that
boots the compose cluster, publishes a record at one node, and
verifies convergence at the other two. It also exercises the
kill-and-rejoin flow and checks peer-auth enforcement. The tests
skip cleanly when docker is unavailable.

```bash
pytest tests/test_compose_cluster.py -v
```

## Related reading

- [Docker (single-node)]({{ site.baseurl }}/deployment/docker) — the
  starting point this guide builds on.
- [Production]({{ site.baseurl }}/deployment/production) — TLS,
  env-var reference, Prometheus metrics.
- [Cluster manifest protocol]({{ site.baseurl }}/protocol/cluster) —
  wire format of the signed cluster record.
