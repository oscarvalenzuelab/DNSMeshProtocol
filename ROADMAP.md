# DNS Mesh Protocol — Roadmap

Two tracks live on this roadmap:

1. **Shipped** — the functional surface that exists in the codebase
   today, tested and documented.
2. **Certification backlog** — the work that lands on the path to
   `v1.0`. The external cryptographic audit, reach (mobile / web /
   PyPI), long-term identity management (key rotation), and
   traffic-analysis research. Post-beta by design: each piece is
   work we intend to do, not a gap we failed to close.

**Status (2026-04-21):** `v0.1.0-alpha`. M1, M2 (full, incl.
node-side anti-entropy + compose cluster), M3 (full, incl. bootstrap
discovery + cluster manifest gossip), and M4.1 (formal protocol
spec) are shipped. The certification backlog (M4.2–M6) lands after
the `v0.2.0-beta` tag. See per-milestone status below.

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
- [x] **M3.3** Node-to-node gossip of the signed cluster manifest.
      Operator pushes a seq++ manifest to ONE node (disk, HTTP POST, or
      curl); every other node picks it up within 1-2 sync ticks via
      `GET /v1/sync/cluster-manifest` against peers, verifies under the
      pinned operator Ed25519 key with expected_cluster_name binding,
      swaps the live anti-entropy peer set to match (preserving cursors
      across the synthetic→operator id handoff), and republishes at
      `cluster.<base>` TXT. 22 new tests, 7 Codex review rounds —
      merged as `7ffad67`.

**Exit criteria for M3 *complete*:** a fresh client with only
`--bootstrap <one-name>` can onboard AND the node set can evolve
without manual manifest republishing per change. **MET.**

### M4 — Formal spec + external audit — M4.1 SHIPPED; M4.2–M4.4 in certification backlog

- [x] **M4.1** Formal wire-format + protocol spec under
      `docs/protocol/` (spec.md, wire-encoding.md, routing.md, flows.md,
      threat-model.md, README.md — ~1500 lines, every constant
      cross-verified against source) — commits `4380469..c4f18fc`.

The remaining M4 work lands after `v0.2.0-beta` as part of the
certification path:

- [ ] **M4.2** Freeze the protocol surface for audit (tag
      `v0.2.0-rc1`).
- [ ] **M4.3** Engage an independent cryptographic auditor.
      Recommended scope: crypto composition, replay + forward-secrecy
      claims, DoS surfaces, erasure-coding soundness, cluster-mode
      trust model.
- [ ] **M4.4** Address findings. Retest. Publish the report.

**Certification outcome:** independent auditor's report published and
acted on. This is what earns the `v1.0` tag.

### M5 — Reach (certification backlog, post-beta)

- [ ] **M5.1** PyPI release. `setup.py` exists; package is not yet
      published on pypi.org. (1 day once the beta tag is cut.)
- [ ] **M5.2** React Native shell app wrapping the protocol core over
      gRPC or a local HTTP daemon. (2–3 months.)
- [ ] **M5.3** Web client using WASM crypto + Fetch for HTTP API.
      (1 month.)
- [x] **M5.4** Key rotation + revocation records — shipped in PR #2
      (`fdd455f`); wire formats covered by unit + fuzz + golden
      vectors, end-to-end docker coverage in
      `tests/test_docker_integration.py` and the two demos under
      `examples/`. Wire format is draft — may be bumped to
      `v=dmp2;t=rotation;` after the M4 external audit.
- [ ] **M5.6** Standalone binaries for the `dmp` CLI: PyInstaller-
      built single-file executables for Windows (`.exe`), macOS (Intel
      + Apple Silicon), and Linux (x86_64 + arm64). Ships alongside
      the PyPI release in M5.1 for users who don't want a Python
      runtime. CI job cross-builds on every release tag. (1 week.)
- [ ] **M5.7** Cross-platform identity proofs (Keyoxide-style). New
      signed record type (`v=dmp1;t=proof;`) that links a DMP
      identity to an external account — GitHub / GitLab / Mastodon /
      domain-via-.well-known / DNSSEC-anchored TXT. Alice publishes
      a challenge on the external platform that references her DMP
      subject; she then publishes a signed DMP `ProofRecord`
      pointing at that external URL + a fingerprint of the
      expected content. Verifiers fetch both sides out-of-band and
      confirm the cross-reference. Defends against the first-fetch
      TOFU substitution attack: even if a malicious node swaps
      Alice's `IdentityRecord`, Bob's client can cross-check via
      GitHub (or wherever), which the node doesn't control.
      Pure-additive on top of M5.4 — no protocol break, existing
      clients just ignore proofs they don't understand. Prior art:
      [Keyoxide](https://keyoxide.org/), [keybase.io](https://keybase.io/)
      (defunct in this form but the claim model is the reference).
      (3–5 weeks: schema + verifier plumbing + at least 3 adapter
      platforms + CLI UX for publish / verify.)

### M5.5 — Multi-tenant node auth (new, post-M5.4)

Today the node's HTTP publish API has a single shared bearer token
(`DMP_HTTP_TOKEN`). Fine for teams / small communities, wrong for
a community node where strangers co-tenant. Per-user tokens turn
the node from "one trust zone" into proper multi-tenant
infrastructure.

- [ ] **M5.5.1** Token schema: sqlite table
      `tokens(hash, subject, scope, rate_limit, expires_at)` with
      audit-logged issuance / revocation.
- [ ] **M5.5.2** Scoped authorization: publish requests must target
      a record namespace that matches the token's `subject`
      (e.g. `alice@example.com` can only write under
      `dmp.alice.example.com` and her mailbox / chunk namespaces).
      Leaking Alice's token must not let anyone publish as Bob.
- [ ] **M5.5.3** Self-service registration endpoint
      (`POST /v1/tokens/register`) that accepts an Ed25519-signed
      challenge proving control of the subject; node mints a token
      bound to that subject. Gated by per-IP rate limits + optional
      operator allowlist.
- [ ] **M5.5.4** Operator CLI (`dmp-node admin token {issue,revoke,list}`)
      for environments that prefer issuing tokens out-of-band.
- [ ] **M5.5.5** Per-token rate limits that stack with the existing
      per-IP limiters.
- [ ] **M5.5.6** Token rotation + expiry with overlap windows so
      clients can rotate without an offline window.

(Undecided: self-service first or operator-issued first. Operator-
issued is ~half the work and sufficient for "team/org" deployments;
self-service is the real mesh story.)

### M6 — Traffic-analysis resistance (certification backlog, research track)

- [ ] **M6.1** Random per-message publish delays in a configurable
      window.
- [ ] **M6.2** Fixed-size dummy chunks published on a schedule so the
      RRset size of a slot doesn't reveal message activity.
- [ ] **M6.3** Chunk-ordering randomization (publish order ≠ chunk
      index).

**Scope note:** strong traffic-analysis resistance against a
state-level adversary is a research program, not a product
deliverable. M6 defines concrete hardenings we commit to shipping;
full resistance is an ongoing research track beyond `v1.0`.

### M7 — Applications on top of the protocol (long-term, post-v1.0)

Reference applications built on the DMP transport. The protocol
stops at "here's a send/receive library"; M7 is the work to make
DMP *feel* like a product people use every day, not infrastructure
people configure.

- [ ] **M7.1** Desktop chat client — think ICQ / IRC client in the
      2000s: persistent contact list, online / offline presence
      (via periodically-refreshed lightweight records), 1:1 message
      history, typing indicators, optional rich content (images,
      file attachments). Cross-platform via Electron or Tauri;
      signed releases per OS. (3–6 months of product work; depends
      on M5.5 multi-tenant auth so friends can use a shared
      community node without stepping on each other.)
- [ ] **M7.2** Group chats — M7.1 is 1:1 only. Groups need either a
      shared group key (simple, not FS-preserving under member
      churn) or proper MLS-style continuous group key agreement
      (complex, right answer). Both require protocol extensions
      beyond the current 1:1 X3DH-style handshake.
- [ ] **M7.3** Native mobile chat apps — the "full chat mode"
      equivalent of M7.1 on iOS / Android. Likely builds on top of
      M5.2 (React Native shell), not parallel to it.
- [ ] **M7.4** Plugin / bot API — HTTP webhook surface for
      integrations (bridges to Matrix / XMPP, CI build-notifications,
      etc.). Depends on M5.5 token scoping so bots can hold narrow-
      scope credentials.

**Scope note:** M7 is explicitly long-horizon. The protocol is the
primary deliverable up to `v1.0`; applications ship afterwards and
on their own cadence. Contributors interested in any M7 item are
welcome to prototype in a separate repo and reconverge.

## Deferred / unlikely

These appear in the design-intent docs but are unlikely to ship as-spec:

- **Mesh routing with Dijkstra / flooding fallback.** With M2/M3 in
  place the routing problem reduces to "which cluster nodes to query."
  Existing mesh libraries (Yggdrasil, cjdns) address the multi-hop case
  better than a message-layer protocol could.
- **All of DMP behaving as a relay for non-DMP traffic.** Out of scope
  — DMP is an application-layer protocol, not an overlay network.

## Critical path

**To `v0.2.0-beta`** (imminent): flip the repo public, publish the
alpha to PyPI as a pre-release package, tag `v0.2.0-beta`. Functional
scope is already shipped; this is a release-engineering step, not a
code gate.

**To `v1.0` (certification backlog)**: execute the items in M4.2–M6
after beta is out and real users are exercising it.

1. **M4.2 → M4.4** — freeze protocol surface, engage an auditor,
   address findings, publish the report.
2. **M5.2 / M5.3** — reach clients (React Native shell, WASM/web).
3. **M6** — traffic-analysis hardening.

M4 is calendar time bounded by the auditor's schedule; the rest
parallelize. Individual post-beta items are tracked as GitHub
issues under the `certification-backlog` label (e.g. key rotation
is [issue #1](https://github.com/oscarvalenzuelab/DNSMeshProtocol/issues/1)).
