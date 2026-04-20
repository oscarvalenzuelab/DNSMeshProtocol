# DNS Mesh Protocol — Roadmap

This is the honest gap between what ships today and what the
[design-intent documents](docs/design-intent/) describe. It is also the
critical path for tagging `v0.2.0-beta` and then a `v1.0` that earns the
word "decentralized" in the tagline.

**Status:** `v0.1.0-alpha`, pre-audit. Two rounds of automated code review
(Codex) completed. Third-party cryptographic audit is the gate for
`v0.2.0-beta`.

## Milestones

### M1 — Resolver resilience (1.5 weeks)

Turn "works where you configured it" into "works wherever DNS works." Small
and high-value.

- [ ] **M1.1** `ResolverPool` class: multiple upstream resolvers, per-host
      health, automatic failover on NXDOMAIN/SERVFAIL/timeout. (2 days)
- [ ] **M1.2** CLI exposes `--dns-resolvers 8.8.8.8,1.1.1.1,9.9.9.9`,
      falls back to system. (1 day)
- [ ] **M1.3** Dynamic resolver discovery: probe a set of well-known public
      resolvers, add working ones to the pool. (3 days)
- [ ] **M1.4** Integration tests: simulate one resolver blocking DMP
      names, confirm the client recovers via another. (2 days)

**Exit criteria:** client continues to work when the primary configured
resolver starts returning NXDOMAIN for DMP-shaped names.

### M2 — Multi-node federation + 3× redundancy (6–8 weeks)

This is the milestone that makes "decentralized" honest. Without it, a
single node is the single point of failure.

- [ ] **M2.1** Node cluster manifest: each node publishes a signed record
      naming the other nodes it replicates with. (1 week)
- [ ] **M2.2** Write-fan-out: `DMPClient.send_message` picks `r_w` nodes
      (default 3) from its configured set and publishes each chunk/manifest
      to all of them. Fail only if fewer than `r_w / 2` succeed. (1.5 weeks)
- [ ] **M2.3** Read-union: `receive_messages` queries all known nodes for
      each mailbox slot, dedupes by `(sender_spk, msg_id)`. (1 week)
- [ ] **M2.4** Inter-node sync: lightweight anti-entropy protocol so a
      node that was offline catches up on records it missed. (2 weeks)
- [ ] **M2.5** Federation integration test suite: spin up 3 nodes in
      compose, kill one, verify no message is lost. (1 week)
- [ ] **M2.6** `docker-compose.cluster.yml` sample for operators. (3 days)

**Exit criteria:** three-node compose cluster; killing any one node at
any time still delivers every message.

### M3 — Bootstrap and discovery (1–2 weeks)

Federation without discovery means every client is a manual configuration
exercise. This closes the usability gap.

- [ ] **M3.1** Bootstrap-domain record type: a signed TXT at a well-known
      name listing currently-live nodes with their DNS + HTTP endpoints.
      (3 days)
- [ ] **M3.2** Client `dmp bootstrap <bootstrap.example.com>` pulls the
      list and appends to config. (1 day)
- [ ] **M3.3** Node-to-node gossip: nodes periodically exchange peer
      lists so a warmed-up node knows about newcomers within minutes.
      (4 days)

**Exit criteria:** a fresh client with only `--bootstrap <one-name>` can
send and receive messages without any further manual setup.

### M4 — External cryptographic audit (calendar time, ~8–12 weeks)

Not code work, but blocking for `v0.2.0-beta`. Parallel with M2 and M3
where possible.

- [ ] **M4.1** Write a formal wire-format + protocol spec document
      separate from the code (expanded from `docs/protocol/`).
- [ ] **M4.2** Freeze the protocol surface for audit (tag `v0.2.0-rc1`).
- [ ] **M4.3** Engage an auditor. Recommended scope: crypto composition,
      replay + forward-secrecy claims, DoS surfaces, erasure-coding
      soundness.
- [ ] **M4.4** Address findings. Retest. Publish the report.

**Exit criteria:** independent auditor's report published and acted on.
This is the `v0.2.0-beta` gate.

### M5 — Reach (3–6 months, post-beta)

- [ ] **M5.1** PyPI release (1 day).
- [ ] **M5.2** React Native shell app wrapping the protocol core over
      gRPC or a local HTTP daemon. (2–3 months)
- [ ] **M5.3** Web client using WASM crypto + Fetch for HTTP API. Works
      anywhere a browser runs. (1 month)
- [ ] **M5.4** Key rotation + revocation records. (2 weeks)

### M6 — Traffic-analysis resistance (ongoing research)

- [ ] **M6.1** Random per-message publish delays in a configurable window.
- [ ] **M6.2** Fixed-size dummy chunks published on a schedule so the
      RRset size of a slot doesn't reveal message activity.
- [ ] **M6.3** Chunk-ordering randomization (publish order ≠ chunk index).

**Honest caveat:** strong traffic-analysis resistance against a
state-level adversary is a research category, not a deliverable. M6 is
best-effort.

## Deferred / unlikely

These appear in the design-intent docs but are unlikely to ship as-spec:

- **Mesh routing with Dijkstra / flooding fallback.** If M2 federation
  works, there is no routing problem to solve beyond "which nodes to
  query." Existing mesh libraries (Yggdrasil, cjdns) address the
  multi-hop case better than a message-layer protocol could.
- **All of DMP behaving as a relay for non-DMP traffic.** Out of
  scope — DMP is an application-layer protocol, not an overlay
  network.

## Critical path to "fully functional"

If I had to pick the shortest path from alpha to a DMP that matches the
README's claims:

1. **M1** — resolver pool (1.5 weeks)
2. **M2** — federation + redundancy (6–8 weeks)
3. **M3** — bootstrap/discovery (1–2 weeks)
4. **M4** — external audit (calendar time, parallel with M2/M3)
5. **M5.1** — PyPI release (1 day, ≥ beta)

Total: **3–4 months of focused work** plus the audit's calendar time.

## Tracking

Atomic tasks for the current sprint live in [`TASKS.md`](TASKS.md).
Long-horizon items stay here until they're lifted into a sprint.
