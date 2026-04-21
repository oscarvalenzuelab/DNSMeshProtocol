# Current sprint

**Sprint status:** M2 — federation — **CLOSED** (2026-04-20).
All three M2 tasks (cluster manifest, fan-out writer, union reader)
merged. 502 tests passing on main. Next sprint TBD from the ROADMAP
backlog — M3 (bootstrap), M4 (protocol spec), or client wiring of
M2.x are the candidates.

See `ROADMAP.md` for the long-horizon view. This file is the active
work queue.

## Conventions

- `pending` → not started, available to claim
- `in-progress` → an Implementer owns it; `owner` field names the session
- `in-review` → PR open against `main`
- `blocked` → open P1 finding or failing Validator
- `done` → merged; commit SHA recorded

## Active

_No tasks currently active. Promote from Backlog to open the next sprint._

## Backlog (promoted to active as bandwidth allows)

### Ready to start (unblocked, small)

- **M2.wire** — Wire `FanoutWriter` + `UnionReader` into `DMPClient` / `dmp/cli.py`. Today both modules are installed but no client call site uses them. A client that pins a cluster-operator pubkey + cluster base domain should: resolve `cluster.<base>` TXT via the existing `DNSRecordReader`, call `ClusterManifest.parse_and_verify(wire, operator_spk, expected_cluster_name=...)`, construct `FanoutWriter` + `UnionReader` from the manifest, install both on the client, and refresh on a configurable interval. Estimated effort: 1-2 days. Touch zones: `dmp/client/client.py`, `dmp/cli.py`, new `tests/test_cluster_client.py`. This is what turns M2.1/M2.2/M2.3 from foundation into end-user value.
- **M1.retro-codex-final** — Final retro Codex review of M1.1, M1.2, M1.3, M1.4, M1.5 commits. Most findings already landed via M1.5 polish; cheap insurance.

### Milestones

- **M3.1** — Bootstrap-domain record type (SRV-like discovery so clients find the cluster manifest name given just a user's email/address domain).
- **M4.1** — Formal protocol spec document (expand `docs/protocol/`).

### Known gaps to track

- **M2.2-polish / M2.3-polish** — both fan-out writer and union reader have "stragglers can saturate the executor pool" behavior when per-node writers/readers lack their own request timeouts. Mitigated by pending-future cancellation; not eliminated. Recommendation: document in the module docstrings that callers should pass writers/readers with per-request timeouts. If a real deployment hits the issue, revisit with per-request timeouts in the common factories.

## Done

- **M1.1** — `ResolverPool` with per-host health tracking, oracle-based demotion, cooldown-as-preference fallback — commits `7cb8d7f..12376a4`.
- **M1.2** — CLI `--dns-resolvers` + `_make_reader` factory + IP-literal parser + config persistence — commit `3096eb0`.
- **M1.3** — `ResolverPool.discover()` + `WELL_KNOWN_RESOLVERS` + `dmp resolvers discover [--save]` + `dmp resolvers list` CLI — commit `d39cb56`.
- **M1.4** — Integration test: resolver failover under partial block (8 tests) — commits `29c5c44`, `6108c66`.
- **M1.5** — Per-host ports in `ResolverPool` + retro-Codex cleanup on M1.2/M1.3 — commits `9bfab67..f9d3dfa` plus `50ba3d7`, `8ab60e7`, `6267686`, `f9d3dfa`.
- **M2.1** — Cluster manifest record type: signed node-list TXT record, wire format, `parse_and_verify` with operator-key + expected-cluster-name binding, DNS-name validation, multi-string TXT support across publishers (dnsupdate/Cloudflare/Route53/dnsmasq/in-memory) — commits `548c5b7..b3bc8be` (14 commits, 10 Codex review rounds).
- **M2.2** — Quorum write fan-out: `FanoutWriter` fans publish/delete across cluster nodes, returns True iff ≥ `ceil(N/2)` ack within timeout. Health tracking, manifest refresh with seq monotonicity + expiry + closed checks, fresh `_NodeState` on endpoint change (http OR dns), retired-writer retention list drained on `close()` after `shutdown(wait=True)`, user `max_workers` preserved across growth, submit-under-lock to avoid close/submit race, deepcopy of installed manifest, cancel pending futures on timeout/quorum — commits `9c71332..b55c93b` (7 commits, 5 Codex review rounds). 53 tests.
- **M2.3** — Read union across cluster nodes: `UnionReader` queries every node concurrently, unions dedup'd TXT answers with first-completed-first ordering. Same manifest-refresh semantics as M2.2. None is healthy; only exceptions/timeouts count as failures. Expired/closed/seq-stale rejection on install. Deepcopy; drain-before-close; max_workers honored; pending futures cancelled on timeout — commits `7a0340e..f5e3776`, merged as `3e50b39`. 44 tests.
