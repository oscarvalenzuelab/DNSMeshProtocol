---
title: Node heartbeat + discovery directory
layout: default
parent: Deployment
nav_order: 5
---

# Running the heartbeat layer (M5.8)
{: .no_toc }

{: .warning }
**This page describes the M5.8 HTTP-gossip heartbeat, which was
replaced in M9 (0.5.0).** The HTTP routes documented below
(`POST /v1/heartbeat`, `GET /v1/nodes/seen`) no longer exist —
they return 404 on every 0.5.x node. M9's DNS-native replacement:
nodes publish their signed heartbeat at `_dnsmesh-heartbeat.<zone>`
as a TXT record and republish their harvested seen-graph at
`_dnsmesh-seen.<zone>`. Discovery happens through the recursive
DNS chain. Configuration env vars
(`DMP_HEARTBEAT_ENABLED`, `DMP_HEARTBEAT_SELF_ENDPOINT`,
`DMP_HEARTBEAT_OPERATOR_KEY_PATH`, `DMP_HEARTBEAT_SEEDS`,
`DMP_HEARTBEAT_DNS_RESOLVERS`) carry the same names but the seeds
are now DNS zones (e.g. `dmp.dnsmesh.io`), not HTTPS URLs. See
[Getting Started]({{ site.baseurl }}/getting-started) for the
canonical M9 flow. This page is kept as historical reference for
operators upgrading from pre-0.5.0 deployments.

1. TOC
{:toc}

DMP's heartbeat layer lets nodes discover each other without any
central registry. Each opted-in node emits a signed
`HeartbeatRecord` every few minutes and pushes it to a small
rotating set of peers. Every received-and-verified heartbeat
lands in a local `heartbeats_seen` sqlite table, which the node
re-exports at `GET /v1/nodes/seen` so any aggregator (including
a central directory website) can union the public state
deterministically.

If you don't want to be listed in any public directory: don't
enable heartbeat. The feature is fully opt-in and nothing on the
protocol's critical path depends on it.

## Minimum setup

Three env vars flip it on. All optional — a misconfigured enable
logs an ERROR and disables the layer rather than starting broken.

```bash
# Turn the worker + endpoints on.
DMP_HEARTBEAT_ENABLED=1

# The HTTPS URL peers will use to reach THIS node. Must match
# the hostname clients can actually connect to from the public
# internet — typically the same as DMP_NODE_HOSTNAME.
DMP_HEARTBEAT_SELF_ENDPOINT=https://dmp.example.com

# Path to a file containing the operator's 32-byte Ed25519 private
# seed. Accepts either raw bytes (32 bytes) or 64-char hex. You
# already have this if you've signed a cluster manifest — the
# generate-cluster-manifest.py script emits it to
# docker/cluster/operator-ed25519.hex.
DMP_HEARTBEAT_OPERATOR_KEY_PATH=/etc/dmp/operator-ed25519.hex
```

Mount the key file read-only. The node only needs read access and
never modifies it.

```bash
docker run -d --name dnsmesh-node \
  -e DMP_HEARTBEAT_ENABLED=1 \
  -e DMP_HEARTBEAT_SELF_ENDPOINT=https://dmp.example.com \
  -e DMP_HEARTBEAT_OPERATOR_KEY_PATH=/etc/dmp/operator.hex \
  -e DMP_HEARTBEAT_SEEDS=https://seed1.example.com,https://seed2.example.com \
  -v $(pwd)/operator-ed25519.hex:/etc/dmp/operator.hex:ro \
  -v dnsmesh-data:/var/lib/dmp \
  -p 53:5353/udp -p 8053:8053/tcp \
  ovalenzuela/dnsmesh-node:latest
```

## Env reference

| Variable | Default | Purpose |
|---|---|---|
| `DMP_HEARTBEAT_ENABLED` | `0` | Truthy (`1` / `true` / `yes` / `on`) opts the node in. |
| `DMP_HEARTBEAT_SELF_ENDPOINT` | *(required)* | Public HTTPS URL of this node. No trailing slash. |
| `DMP_HEARTBEAT_OPERATOR_KEY_PATH` | *(required)* | File with Ed25519 seed (32 raw bytes OR 64-char hex). |
| `DMP_HEARTBEAT_SEEDS` | *(empty)* | Comma-list of peer HTTPS URLs to bootstrap gossip from. Empty is valid (relies on cluster peers + inbound gossip). |
| `DMP_HEARTBEAT_INTERVAL_SECONDS` | `300` | Tick cadence. |
| `DMP_HEARTBEAT_TTL_SECONDS` | `86400` | `exp - ts` on emitted heartbeats. |
| `DMP_HEARTBEAT_MAX_PEERS` | `25` | Outbound fan-out cap per tick. |
| `DMP_HEARTBEAT_DB_PATH` | sibling of `DMP_DB_PATH` (`..._heartbeats.db`) | Seen-store location. |
| `DMP_HEARTBEAT_SEEN_MAX_ROWS` | `10000` | Row cap on the seen-store. |
| `DMP_HEARTBEAT_RETENTION_HOURS` | `72` | How long past `exp` a stale row is kept before the sweep evicts. |
| `DMP_HEARTBEAT_VERSION` | `dev` | Free-form version string emitted in outgoing heartbeats. |
| `DMP_HEARTBEAT_SUBMIT_RATE_PER_SEC` / `_BURST` | `1.0` / `30` | Per-IP rate limit on `POST /v1/heartbeat`. |
| `DMP_HEARTBEAT_SEEN_RATE_PER_SEC` / `_BURST` | `5.0` / `60` | Per-IP rate limit on `GET /v1/nodes/seen`. Separate bucket — heavy scraper traffic does not steal the submit budget. |

## Operator key hygiene

The heartbeat worker uses the same Ed25519 key the operator already
uses to sign `ClusterManifest` / `BootstrapRecord` records. A
leaked operator key lets an attacker:

- Sign arbitrary heartbeats under the operator's identity (they can
  list any `endpoint` string as belonging to this operator).
- Already-existing impact of cluster-key leak: forge cluster
  manifests. Heartbeat does not increase this blast radius.

Practical consequences:

- Store the seed offline when possible. Mount read-only into the
  node; never commit to version control (the repo's `.gitignore`
  already covers `docker/cluster/operator-ed25519.hex`).
- Rotating the operator key means pushing a new cluster manifest
  and restarting the node with the new seed. Contacts listed in
  heartbeats will re-pick you up on the next tick since only the
  `operator_spk` field changes.

## What the endpoints do

### `POST /v1/heartbeat`

A peer submits its own signed heartbeat. Body:
`{"wire": "v=dmp1;t=heartbeat;..."}`. Server verifies +
ts-skew-checks + low-order-pubkey-checks, stores, and responds:

```json
{
  "ok": true,
  "accepted_operator_spk_hex": "...",
  "seen": [
    "v=dmp1;t=heartbeat;...",
    "..."
  ]
}
```

The `seen` array is up to `DMP_HEARTBEAT_GOSSIP_LIMIT` (default 10)
recent heartbeats from OTHER operators — this is how a fresh
submitter learns the rest of the mesh in one round trip.

### `GET /v1/nodes/seen`

Public read. No auth. Returns:

```json
{
  "version": 1,
  "self": {
    "endpoint": "https://dmp.example.com",
    "operator_spk_hex": "...",
    "enabled": true
  },
  "seen": [
    {"wire": "v=dmp1;t=heartbeat;..."},
    {"wire": "..."}
  ]
}
```

Consumers MUST re-verify every wire — the whole point is that an
aggregator adds no trust. Signature failure / ts-skew / low-order
pubkey all fail closed in `HeartbeatRecord.parse_and_verify`, so
the worst a hostile source can do is omit entries.

## Running a directory website

`examples/directory_aggregator.py` is a reference implementation.
It:

1. Queries N seed URLs' `GET /v1/nodes/seen`.
2. Runs `HeartbeatRecord.parse_and_verify` on every wire.
3. Unions by `(operator_spk, endpoint)`, newest `ts` wins.
4. Writes `public/feed.json` + `public/index.html`.

Typical cron:

```cron
# Every 5 minutes, rebuild the directory.
*/5 * * * * /usr/local/bin/python /opt/dmp/examples/directory_aggregator.py \
    --seed https://dmp.example.com \
    --seed https://dmp.otherop.org \
    --out-dir /var/www/dnsmesh-directory
```

Serve `/var/www/dnsmesh-directory/` with nginx / Caddy / GitHub Pages /
wherever. `feed.json` is re-verifiable by any downstream consumer
without re-fetching the seeds — it just carries the original
signed wires.

## Threat model recap

- **A hostile peer can't forge listings.** Each heartbeat is signed
  by its operator's Ed25519 key; re-exporting someone else's
  heartbeat requires handing over bytes that still verify under
  that key.
- **A hostile peer can omit.** Gossip + multi-source aggregation
  make this recoverable — a consumer querying 5 different seeds
  sees a node unless all 5 collude.
- **Replay is bounded.** `ts` must verify within ±5 min of "now",
  and each `(operator_spk, endpoint)` key holds one live row at a
  time.
- **Fabrication of non-existent nodes is expensive.** An attacker
  would need to control Ed25519 keys; they could publish their own
  heartbeats but can't pretend to be anyone else.
- **A hostile aggregator can lie about what it heard.** That's
  why any consumer who cares should run their own aggregator off
  the same underlying `/v1/nodes/seen` sources and compare.
