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
