---
title: Node heartbeat + discovery directory
layout: default
parent: Design Intent
nav_order: 11
---

# M5.8 — Node heartbeat + discovery directory

{: .no_toc }

1. TOC
{:toc}

## Problem

There is no way today for a would-be user on the internet to discover
which DMP nodes exist and which are healthy. Every DMP discovery
primitive currently shipped (`dnsmesh bootstrap discover <zone>`,
`dnsmesh cluster fetch`, cluster-manifest gossip in M3.3) resolves *a
specific operator's* nodes from a zone the user already knows.
Bootstrapping from zero — "I want to try DMP, which nodes exist?" —
requires out-of-band knowledge.

M5.8 adds a **peer-to-peer heartbeat** layer. Every opted-in node
emits a signed heartbeat periodically and pushes it to a set of
seed peers + peers learned via gossip. Each node maintains a local
"recently seen" table of the heartbeats it has received and verified.
That table is exposed as a read-only HTTP endpoint so anyone can
aggregate it — including a central directory website, which is just
one possible consumer rather than a protocol-mandated trust anchor.

## Non-goals

- **Privacy for listed nodes.** Listing a node is explicitly opt-in
  and public. A node operator who wants anonymity simply doesn't
  enable heartbeat (`DMP_HEARTBEAT_ENABLED=0`, the default).
- **Central trust.** The directory website aggregates data; it does
  not *certify* it. Every listed entry is a signed `HeartbeatRecord`;
  clients verify signatures independently.
- **Real-time liveness.** Heartbeat interval is minutes, not seconds.
  "Recently heard from" is a coarse signal, not a health probe.
- **User discovery.** Heartbeat lists *nodes*, never *users*.
  User-facing identity proofs are M5.7 (Keyoxide-style).

## Wire format

New signed record type `HeartbeatRecord` (`v=dmp1;t=heartbeat;`).
Kept deliberately flat — no JSON, no length-prefixed multi-field
frames — because DMP wire records are parsed by TXT-record
consumers that already live in tight stdlib-only code paths.

Binary layout (all integers big-endian):

```
  magic            b"DMPHB01"          7 bytes
  endpoint_len     uint16              2 bytes
  endpoint         utf-8 bytes         var, <= 255
  operator_spk     bytes               32 bytes (Ed25519 pubkey)
  version_len      uint8               1 byte
  version          utf-8 bytes         var, <= 32 (semver string)
  ts               uint64              8 bytes  (issued-at, unix seconds)
  exp              uint64              8 bytes  (expiry, unix seconds)
  signature        bytes               64 bytes (Ed25519 over all above)
                                       ----
  total                                123 + endpoint_len + version_len
                                       max ≈ 410 bytes
```

Wire prefix: `v=dmp1;t=heartbeat;` followed by standard base64 of
the binary (same encoding the other signed DMP record types —
`ClusterManifest`, `RotationRecord`, `BootstrapRecord` — use for
consistency across the wire surface). Fits comfortably in a single
DNS TXT record.

### What `endpoint` is

The fully-qualified HTTPS URL of the publish surface:
`https://dmp.example.com`. No trailing slash, no path. Consumers
append their own `/v1/nodes/seen` or `/v1/heartbeat`.

### What `operator_spk` is

The Ed25519 signing key the node operator uses for all operator-
scoped records (cluster manifests, bootstrap records). Reusing the
existing operator key means:

- A client that already pins an operator's cluster can verify their
  heartbeat without adding a new trust anchor.
- A leaked operator key compromise affects heartbeats the same way
  it affects cluster manifests — no new blast radius.

### Freshness

`ts` must be within ±5 minutes of "now" at verify time to limit
replay windows. `exp` is enforced at list-export time (expired
entries are dropped). Default `exp - ts` is 24 hours; the
sliding-window retention on the seen-store is 72 hours so a node
that re-emits slightly late isn't immediately evicted.

### Parse-and-verify

Single entry point, ``HeartbeatRecord.parse_and_verify(wire_text)``,
following the M3 / M5.4 hardened pattern:

- Never raises on malformed input — returns ``None``.
- Verifies the signature before constructing the Python dataclass
  (bad signature ⇒ None).
- Enforces `ts` / `exp` / `endpoint_len` / `version_len` bounds.
- `MAX_WIRE_LEN = 1200` same as the other record types.

## Delivery

Two HTTP endpoints added to the node API:

### `POST /v1/heartbeat`

Accept a heartbeat. Body: JSON `{"wire": "v=dmp1;t=heartbeat;..."}`.
Server:

1. Shape-checks the body.
2. Calls `HeartbeatRecord.parse_and_verify`; on ``None``, reject 400.
3. Rejects if `operator_spk` is all-zero or a low-order Ed25519 point
   (same block list used in `dmp.server.registration`).
4. Rejects if `ts` is > 5 minutes from "now".
5. Rejects if `endpoint` fails basic URL shape (scheme + hostname).
6. Writes the verified wire to the seen-store keyed by
   `(operator_spk, endpoint)`; a repeat from the same key replaces the
   older entry (keeps the store bounded).
7. Returns 200 with up to N recent heartbeats from OTHER nodes as
   `{"seen": [<wire>, <wire>, ...]}` — this is the **gossip-on-ping**
   response. The caller adds those to its own ping list.

Rate-limited per-IP (default 10/min, same limiter style as the
registration endpoints). No auth required — the signatures are the
auth.

### `GET /v1/nodes/seen`

Return the public snapshot. Response:

```json
{
  "version": 1,
  "self": {
    "endpoint": "https://dmp.this-node.example.com",
    "operator_spk_hex": "...",
    "enabled": true
  },
  "seen": [
    {"wire": "v=dmp1;t=heartbeat;..."},
    ...
  ]
}
```

Consumers re-verify every entry; never trust unsigned fields.
Stale (expired) entries are filtered out server-side as a courtesy,
but the verifier must enforce again.

Always open (no auth). Rate-limited per-IP (default 60/min).

## Seen-store

sqlite table beside the token DB:

```sql
CREATE TABLE heartbeats_seen (
    operator_spk   TEXT NOT NULL,     -- hex, 64 chars
    endpoint       TEXT NOT NULL,
    wire           TEXT NOT NULL,     -- the full v=dmp1;t=heartbeat;... string
    ts             INTEGER NOT NULL,
    exp            INTEGER NOT NULL,
    received_at    INTEGER NOT NULL,
    PRIMARY KEY (operator_spk, endpoint)
);

CREATE INDEX idx_heartbeats_ts  ON heartbeats_seen(ts DESC);
CREATE INDEX idx_heartbeats_exp ON heartbeats_seen(exp);
```

Retention sweep every 60s drops rows where `exp < now - 72h`
(long sliding window in case an operator has a brief hiccup).
Entry cap: 10,000 live rows; new-row insert when full evicts the
oldest by `received_at`.

## Worker

A `HeartbeatWorker` runs inside each node when `DMP_HEARTBEAT_ENABLED=1`.
Every `DMP_HEARTBEAT_INTERVAL_SECONDS` (default 300 = 5 min):

1. Build + sign the node's own `HeartbeatRecord` using the
   operator key (same key used to sign cluster manifests).
2. For each peer in the current ping list: `POST /v1/heartbeat`
   with the wire, capture the gossip response, merge returned
   heartbeats into the seen-store after signature verification.
3. Peer list = seed list (`DMP_HEARTBEAT_SEEDS`) ∪ cluster peers
   (from current cluster manifest if applicable) ∪ known-active
   peers from the seen-store (top N by `ts DESC`).
4. Cap ping list at `DMP_HEARTBEAT_MAX_PEERS` (default 25) to
   bound fan-out.

Failures are logged at INFO and don't stop the worker. A peer that
returns 4xx/5xx stays in the list but gets lower priority on the
next tick (simple round-robin with cooldown on error).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DMP_HEARTBEAT_ENABLED` | `0` | Turn the worker + endpoints on. Opt-in. |
| `DMP_HEARTBEAT_SEEDS` | *(empty)* | Comma-separated HTTPS URLs of seed nodes. Empty = rely on cluster peers + gossip. |
| `DMP_HEARTBEAT_INTERVAL_SECONDS` | `300` | Worker tick. |
| `DMP_HEARTBEAT_TTL_SECONDS` | `86400` | `exp - ts` on emitted heartbeats. |
| `DMP_HEARTBEAT_MAX_PEERS` | `25` | Cap on outbound ping targets per tick. |
| `DMP_HEARTBEAT_SEEN_MAX_ROWS` | `10000` | Cap on seen-store size. |
| `DMP_HEARTBEAT_RETENTION_HOURS` | `72` | Sliding retention window. |
| `DMP_NODE_OPERATOR_KEY_PATH` | *(infer from cluster manifest)* | Where to load the Ed25519 signing key the worker uses. If unset and no cluster manifest is signed by this node's key, the worker refuses to start. |

## Central directory website

The aggregator is a separate, tiny program living at
``examples/directory_aggregator/``. It:

1. Reads a config file listing N seed nodes to query.
2. `GET /v1/nodes/seen` on each, unions the signed heartbeats.
3. Verifies every signature; drops any stale / malformed / low-order
   entries.
4. Renders a static HTML page grouping nodes by last-seen age,
   linking to each operator's documentation URL.
5. Emits a signed JSON feed so downstream consumers (other
   directories, monitoring, clients) can re-verify without
   re-fetching.

Run via cron or a systemd timer. No database, no auth — it's a
deterministic fold over the signed P2P data. Anyone can run one.

The operator-hosted central page is expected to live at
`https://directory.dmp.example.com/` (TBD), but the protocol does
not depend on that URL existing.

## Trust model

- **A heartbeat's contents can't be forged.** Each entry is signed
  by its operator key; a hostile node re-exporting someone else's
  heartbeat can only hand out bytes that still verify under that
  operator's signature.
- **A hostile node can omit.** Nothing forces node B to report node
  X's heartbeat to node A. Solution: gossip + multiple sources. A
  consumer aggregating across five nodes sees X unless all five are
  colluding.
- **A hostile node can fabricate listings of non-existent nodes.**
  Only if it can forge those nodes' signatures, which it can't
  without their Ed25519 keys. The worst it can do is submit its own
  valid-but-unhelpful heartbeat.
- **A hostile consumer can lie about what it heard.** The directory
  website's job is to aggregate; if the website's operator wants to
  censor, they can omit entries. Mitigation: the signed aggregate
  can be re-verified by any second consumer querying the same
  source nodes.
- **Replay.** `ts ± 5min` window + single-use-per-`(spk, endpoint)`
  key in the seen-store (newer entry replaces older) limits replay.

## Rollout

Five phases, each its own commit on this branch:

1. **Wire type + crypto.** `dmp.core.heartbeat.HeartbeatRecord`
   with sign / parse_and_verify + fuzz harness + golden vectors.
2. **Seen store.** sqlite schema + in-process API.
3. **HTTP endpoints.** `POST /v1/heartbeat` (with gossip response)
   and `GET /v1/nodes/seen`. Per-IP rate limits.
4. **Worker.** `HeartbeatWorker` with seed list + gossip + cluster
   peer integration. Opt-in via `DMP_HEARTBEAT_ENABLED=1`.
5. **Aggregator example + docs.** `examples/directory_aggregator/`
   and operator / user guide pages.
