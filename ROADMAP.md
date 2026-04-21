# DNS Mesh Protocol — Roadmap

This is the honest gap between what ships today and what the
[design-intent documents](docs/design-intent/) describe. It is also the
critical path for tagging `v0.2.0-beta` and then a `v1.0` that earns the
word "decentralized" in the tagline.

**Status (2026-04-21):** `v0.1.0-alpha`, pre-external-audit. M1, M2
(full, incl. node-side anti-entropy + compose cluster), M3.1/M3.2-wire,
and M4.1 are shipped. Node-to-node gossip (M3.3) and the external
cryptographic audit (M4.2–M4.4) are the remaining gates to
`v0.2.0-beta`. See the per-milestone status below.

Atomic tasks for the current sprint live in [`TASKS.md`](TASKS.md);
long-horizon items stay here until they get lifted into a sprint.

## Milestones

### M1 — Resolver resilience — SHIPPED

Client-side resolver pool with multi-upstream failover. `dmp` keeps
working when the primary configured resolver starts returning NXDOMAIN
or SERVFAIL for DMP-shaped names.

- [x] **M1.1** `ResolverPool` with per-host health, oracle-based
      demotion, cooldown-as-preference fallback — commits `7cb8d7f..12376a4`.
- [x] **M1.2** CLI `--dns-resolvers 8.8.8.8,1.1.1.1,9.9.9.9`, falls
      back to legacy single-host — commit `3096eb0`.
- [x] **M1.3** Dynamic resolver discovery (`dmp resolvers discover
      [--save]` / `dmp resolvers list`) — commit `d39cb56`.
- [x] **M1.4** Integration tests: two local UDP DNS stubs, one serving
      correctly, one NXDOMAIN'ing; client survives — commits `29c5c44`,
      `6108c66`.
- [x] **M1.5** Per-host ports in `ResolverPool` + retroactive Codex
      cleanup on M1.2 / M1.3 — commits `9bfab67..f9d3dfa`.

### M2 — Federation (client AND node side) — SHIPPED

Clients fan writes across multiple nodes and read-union across them.
Nodes themselves also run pull-based anti-entropy against their
peers: a node that was offline comes back and catches up via
digest-and-pull. A 3-node compose cluster is a checked-in operator
starting point and is covered by integration tests that exercise
convergence, kill-and-rejoin backfill, and peer-auth enforcement.

- [x] **M2.1** `ClusterManifest` record type — signed TXT at
      `cluster.<base>` listing the cluster's nodes — commits
      `548c5b7..b3bc8be`.
- [x] **M2.2** `FanoutWriter`: publish/delete to every node in parallel;
      return True iff ≥ `ceil(N/2)` ack within timeout — commits
      `9c71332..b55c93b`.
- [x] **M2.3** `UnionReader`: query every node concurrently, union
      dedup'd TXT answers — commits `7a0340e..f5e3776`.
- [x] **M2.wire** CLI + client integration (`dmp cluster pin/fetch/
      enable/disable/status`, cluster-mode in `_make_client`) — commits
      `94964d9..31eba4e`; plus polish (`M2.wire-polish`) +
      `cluster-composite-reader` (cross-domain reads) +
      `cluster-atomic-refresh` (no split-brain on manifest refresh).
- [x] **M2.4** Inter-node anti-entropy: pull-based digest/pull worker
      with compound `(ts, name, value_hash)` cursor, TTL-refresh
      detection, contiguous-prefix watermark advancement, re-verify
      of signed records against cluster operator key — merged as
      `06405ce`. +50 tests.
- [x] **M2.5** Federation integration test: `tests/test_compose_cluster.py`
      boots the compose cluster, verifies convergence + kill-and-rejoin
      backfill + peer-auth enforcement. Skips cleanly when docker is
      unavailable — merged as `8f9ce95`.
- [x] **M2.6** `docker-compose.cluster.yml` + `docker/cluster/*` env
      files + `generate-cluster-manifest.py` operator helper +
      `docs/deployment/cluster.md` guide. The compose file carries
      `build: .` so a clean checkout can `up` without pre-building —
      merged as `8f9ce95`.

**Exit criteria for M2 *complete*:** three-node compose cluster; killing
any one node at any time still delivers every message AND a node that
rejoins catches up. **MET.**

### M3 — Bootstrap and discovery — SHIPPED (partial; see M3.3)

A user given just `alice@example.com` can auto-discover the cluster
serving that domain. The two-hop trust chain (bootstrap signer →
cluster operator) verifies before any config is written.

- [x] **M3.1** `BootstrapRecord` at `_dmp.<user_domain>` — signed pointer
      from a user domain to one or more clusters with priority-ordered
      fallback — commits `cd2f383..5c33cd5`, plus `81f1dd7`.
- [x] **M3.2-wire** `dmp bootstrap pin/fetch/discover [--auto-pin]` +
      `identity fetch --via-bootstrap` — commits `20a83fe..d21c305`.
- [ ] **M3.3** *(NOT SHIPPED)* Node-to-node gossip: nodes periodically
      exchange peer lists so a warmed-up node knows about newcomers
      within minutes. Currently the node set is static — operators
      update the signed cluster manifest manually.

**Exit criteria for M3 *complete*:** a fresh client with only
`--bootstrap <one-name>` can onboard AND the node set can evolve
without manual manifest republishing per change.

### M4 — Formal spec + external audit — SHIPPED M4.1; M4.2–M4.4 BLOCKING BETA

- [x] **M4.1** Formal wire-format + protocol spec under
      `docs/protocol/` (spec.md, wire-encoding.md, routing.md, flows.md,
      threat-model.md, README.md — ~1500 lines, every constant
      cross-verified against source) — commits `4380469..c4f18fc`.
- [ ] **M4.2** *(NOT SHIPPED)* Freeze the protocol surface for audit
      (tag `v0.2.0-rc1`).
- [ ] **M4.3** *(NOT SHIPPED)* Engage an independent cryptographic
      auditor. Recommended scope: crypto composition, replay +
      forward-secrecy claims, DoS surfaces, erasure-coding soundness,
      cluster-mode trust model.
- [ ] **M4.4** *(NOT SHIPPED)* Address findings. Retest. Publish the
      report.

**Exit criteria:** independent auditor's report published and acted on.
This is the `v0.2.0-beta` gate.

### M5 — Reach — NOT SHIPPED (post-beta work)

- [ ] **M5.1** PyPI release. `setup.py` exists; package is not yet
      published on pypi.org. (1 day once the beta gate opens.)
- [ ] **M5.2** React Native shell app wrapping the protocol core over
      gRPC or a local HTTP daemon. (2–3 months.)
- [ ] **M5.3** Web client using WASM crypto + Fetch for HTTP API.
      (1 month.)
- [ ] **M5.4** Key rotation + revocation records. (2 weeks.)

### M6 — Traffic-analysis resistance — NOT SHIPPED (research track)

- [ ] **M6.1** Random per-message publish delays in a configurable
      window.
- [ ] **M6.2** Fixed-size dummy chunks published on a schedule so the
      RRset size of a slot doesn't reveal message activity.
- [ ] **M6.3** Chunk-ordering randomization (publish order ≠ chunk
      index).

**Honest caveat:** strong traffic-analysis resistance against a
state-level adversary is a research category, not a deliverable. M6 is
best-effort.

## Deferred / unlikely

These appear in the design-intent docs but are unlikely to ship as-spec:

- **Mesh routing with Dijkstra / flooding fallback.** With M2/M3 in
  place the routing problem reduces to "which cluster nodes to query."
  Existing mesh libraries (Yggdrasil, cjdns) address the multi-hop case
  better than a message-layer protocol could.
- **All of DMP behaving as a relay for non-DMP traffic.** Out of scope
  — DMP is an application-layer protocol, not an overlay network.

## Critical path to `v0.2.0-beta`

The shortest remaining path:

1. **M3.3** — node-to-node gossip for peer discovery. Optional if
   operators are OK managing the peer set manually via cluster
   manifest + env files.
2. **M4.2 → M4.4** — engage an auditor, fix findings, publish report.
3. **M5.1** — PyPI release.

Item 1 is days of focused work; item 2 is calendar time bounded by
the auditor's schedule. Item 3 is a day once items 1–2 are done.
