# Current sprint

**Sprint status:** M2 — federation — **active**. M2.1 foundation
merged (2026-04-20); M2.2 (write fan-out) is the next unblocked task.

See `ROADMAP.md` for the long-horizon view. This file is the active
work queue.

## Conventions

- `pending` → not started, available to claim
- `in-progress` → an Implementer owns it; `owner` field names the session
- `in-review` → PR open against `main`
- `blocked` → open P1 finding or failing Validator
- `done` → merged; commit SHA recorded

## Active

### M2.2 — Client write fan-out across cluster nodes

| Field | Value |
|---|---|
| **ID** | `M2.2` |
| **Status** | `pending` |
| **Owner** | — |
| **Depends on** | `M2.1` (done) |
| **Blocks** | end-to-end federation |
| **Estimated effort** | 2-3 days |
| **Touch zones** | `dmp/network/fanout_writer.py` (new), `dmp/client/client.py`, `tests/test_fanout_writer.py` (new), possibly `docs/protocol/cluster.md` for semantics |

**Goal:** a `DNSRecordWriter` implementation that fans each publish across the nodes listed in a `ClusterManifest` and returns success iff at least `r_w = ceil(N/2)` nodes ack. Failed nodes are tracked for health reporting but don't block the caller.

**Acceptance criteria:**

- [ ] `FanoutWriter(cluster_manifest, writer_factory)` wraps a list of per-node writers. `writer_factory(http_endpoint) -> DNSRecordWriter`.
- [ ] `publish_txt_record` fans out concurrently; returns True if ≥ `r_w` succeed within a per-call timeout.
- [ ] `delete_txt_record` same semantics.
- [ ] Tracks per-node failure counts + last error; exposes via `snapshot()`.
- [ ] Refresh on manifest update: when the caller pushes a new `ClusterManifest` (higher seq), rebuilds the per-node writers.
- [ ] Respects `expected_cluster_name` binding on manifest install.
- [ ] Tests: all-succeed, partial-fail-above-quorum, partial-fail-below-quorum, all-fail, timeout, manifest refresh.

### M2.3 — Read union across cluster nodes with dedup

| Field | Value |
|---|---|
| **ID** | `M2.3` |
| **Status** | `pending` |
| **Owner** | — |
| **Depends on** | `M2.1` (done) |
| **Blocks** | end-to-end federation |
| **Estimated effort** | 2 days |
| **Touch zones** | `dmp/network/union_reader.py` (new), `dmp/client/client.py`, `tests/test_union_reader.py` (new) |

**Goal:** a `DNSRecordReader` that queries every node in a cluster and unions the TXT answers, dedup'd by full string value. Complements the M2.2 write-quorum model.

## Backlog (promoted to active as bandwidth allows)

- **M1.retro-codex-final** — Final retro Codex review of M1.1, M1.2, M1.3, M1.4, M1.5 commits now that OpenAI API is stable. Most findings already landed via M1.5 polish, but a final pass is cheap insurance.
- **M3.1** — Bootstrap-domain record type (SRV-like discovery for cluster entry point).
- **M4.1** — Formal protocol spec document (expand `docs/protocol/`).

## Done

- **M1.1** — `ResolverPool` with per-host health tracking, oracle-based demotion, cooldown-as-preference fallback — commits `7cb8d7f..12376a4`.
- **M1.2** — CLI `--dns-resolvers` + `_make_reader` factory + IP-literal parser + config persistence — commit `3096eb0`.
- **M1.3** — `ResolverPool.discover()` + `WELL_KNOWN_RESOLVERS` + `dmp resolvers discover [--save]` + `dmp resolvers list` CLI — commit `d39cb56`.
- **M1.4** — Integration test: resolver failover under partial block (8 tests) — commits `29c5c44`, `6108c66`.
- **M1.5** — Per-host ports in `ResolverPool` + retro-Codex cleanup on M1.2/M1.3 — commits `9bfab67..f9d3dfa` (base) plus `50ba3d7`, `8ab60e7`, `6267686`, `f9d3dfa` (follow-ups).
- **M2.1** — Cluster manifest record type: signed node-list TXT record, wire format, parse_and_verify with binding to expected cluster name, cluster_rrset_name, multi-string TXT support across publishers — commits `548c5b7..b3bc8be` (14 commits, 10 Codex review rounds, final clean pass). 75 tests added; 405 total passing. Core deliverables: ClusterManifest, ClusterNode, DNS-name validation, duplicate node_id rejection, symmetric wire-cap enforcement, multi-string TXT publishing, case-insensitive + trailing-dot-normalized name binding.
