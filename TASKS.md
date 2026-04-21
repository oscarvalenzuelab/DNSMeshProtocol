# Current sprint

**Sprint status:** **M1 + M2 + M3.1/M3.2-wire + M4.1 COMPLETE**
(2026-04-21). Node-side federation (M2.4 anti-entropy + M2.5/M2.6
compose cluster) closed the gap surfaced in the doc-honesty audit.

- **M1** — resolver resilience (failover, discovery, per-host ports)
- **M2** — full federation: cluster manifest + fan-out writer + union
  reader + wire integration + 3 audit follow-ups + node-side
  anti-entropy + 3-node compose cluster (operator-facing)
- **M3.1 + M3.2-wire** — discovery (bootstrap record + CLI integration
  with two-hop trust and priority-ordered fallback)
- **M4.1** — formal protocol spec

737 non-docker tests + 3 docker-compose cluster integration tests
all passing on main. The project now delivers end-to-end zero-config
onboarding AND real node-side federation (kill-and-rejoin tested
against the compose cluster).

Remaining ROADMAP items: M3.3 (node-to-node gossip), M4.2-M4.4
(external cryptographic audit), M5 (PyPI, mobile, web, key rotation),
M6 (traffic-analysis resistance).

See `ROADMAP.md` for the long-horizon view. Any new sprint should be
drafted against that plan.

## Conventions

- `pending` → not started, available to claim
- `in-progress` → an Implementer owns it; `owner` field names the session
- `in-review` → PR open against `main`
- `blocked` → open P1 finding or failing Validator
- `done` → merged; commit SHA recorded

## Active

_No tasks currently active. The original roadmap is complete._

## Backlog (known gaps, not yet prioritized)

- **M2.2-polish / M2.3-polish** — both fan-out writer and union reader have "stragglers can saturate the executor pool" behavior when per-node writers/readers lack their own request timeouts. Mitigated by pending-future cancellation; not eliminated. Recommendation: document in the module docstrings that callers should pass writers/readers with per-request timeouts. If a real deployment hits the issue, revisit with per-request timeouts in the common factories.
- **Spec ambiguities flagged during M4.1** (for a future refactor if desired):
  - Wire-prefix asymmetry: `v=dmp1;t=cluster;` / `v=dmp1;t=bootstrap;` terminate at `;`; the older types carry an explicit `d=<b64>` key. Documented in `docs/protocol/spec.md §3` and `wire-encoding.md`. Unifying on one convention would be a v2 wire-break.
  - Legacy `DNSEncoder.encode_mailbox_domain` (`dmp/core/dns.py`) returns `mb-<hash12>-<slot:02d>` but production uses `slot-<N>.mb-<hash12>`. The legacy form is unused; consider removing.
  - Hash-truncation width mismatch: identity uses `[:16]` hex, prekey uses `[:12]`. Reason lost to history; unifying would be a routing-name change.

## Done

- **M1.1** — `ResolverPool` with per-host health tracking, oracle-based demotion, cooldown-as-preference fallback — commits `7cb8d7f..12376a4`.
- **M1.2** — CLI `--dns-resolvers` + `_make_reader` factory + IP-literal parser + config persistence — commit `3096eb0`.
- **M1.3** — `ResolverPool.discover()` + `WELL_KNOWN_RESOLVERS` + `dmp resolvers discover [--save]` + `dmp resolvers list` CLI — commit `d39cb56`.
- **M1.4** — Integration test: resolver failover under partial block (8 tests) — commits `29c5c44`, `6108c66`.
- **M1.5** — Per-host ports in `ResolverPool` + retro-Codex cleanup on M1.2/M1.3 — commits `9bfab67..f9d3dfa` plus `50ba3d7`, `8ab60e7`, `6267686`, `f9d3dfa`.
- **M1.retro-codex-final** — Final retro Codex review across M1.1..M1.5 on 2026-04-21. No new findings.
- **M2.1** — Cluster manifest record type: signed node-list TXT record, wire format, `parse_and_verify` with operator-key + expected-cluster-name binding, DNS-name validation, multi-string TXT support across publishers (dnsupdate/Cloudflare/Route53/dnsmasq/in-memory) — commits `548c5b7..b3bc8be` (14 commits, 10 Codex review rounds).
- **M2.2** — Quorum write fan-out: `FanoutWriter` fans publish/delete across cluster nodes, returns True iff ≥ `ceil(N/2)` ack within timeout. Health tracking, manifest refresh with seq monotonicity + expiry + closed checks, fresh `_NodeState` on endpoint change (http OR dns), retired-writer retention list drained on `close()` after `shutdown(wait=True)`, user `max_workers` preserved across growth, submit-under-lock to avoid close/submit race, deepcopy of installed manifest, cancel pending futures on timeout/quorum — commits `9c71332..b55c93b` (7 commits, 5 Codex review rounds). 53 tests.
- **M2.3** — Read union across cluster nodes: `UnionReader` queries every node concurrently, unions dedup'd TXT answers with first-completed-first ordering. Same manifest-refresh semantics as M2.2. None is healthy; only exceptions/timeouts count as failures. Expired/closed/seq-stale rejection on install. Deepcopy; drain-before-close; max_workers honored; pending futures cancelled on timeout — commits `7a0340e..f5e3776`, merged as `3e50b39`. 44 tests.
- **M2.wire** — Cluster-mode client integration: new `dmp.client.cluster_bootstrap` with `fetch_cluster_manifest` + `ClusterClient` (background refresh thread). CLI gains `cluster pin`, `cluster fetch [--save]`, `cluster status` commands. `_make_client` switches to cluster mode when both anchors pinned; effective domain (mailbox/identity/prekey RRsets) uses `cluster_base_domain` consistently. `_NodeDnsReader` with UDP→TCP retry on TC flag. Local-only commands (`identity show`) skip the bootstrap fetch so offline usage still works. `fetch_cluster_manifest` picks the highest-seq verifying manifest to handle operator rollout with multiple co-resident records — commits `94964d9..31eba4e` (8 commits, 7 Codex review rounds), merged as `cbacf82`. 45 new tests (20 bootstrap + 3 e2e + 22 cli cluster).
- **M2.wire-polish** — Decoupled `dmp cluster pin` from cluster-mode activation. New `cluster_enabled: bool` flag (default False, back-compat for existing configs requires explicit `cluster enable`). New `dmp cluster enable` / `dmp cluster disable` commands; enable runs a live manifest fetch before flipping. `dmp cluster fetch` / `status` work regardless of enable state as pre-enable diagnostics — commits `775c22b..3879663`, merged as `012552a`. 11 new tests.
- **cluster-composite-reader** — `CompositeReader` routes cluster-local names (suffix match on `cluster_base_domain`) to the union reader and external names to the bootstrap resolver. Fixes cross-domain identity/prekey lookups in cluster mode. Label-boundary-safe suffix match (casefold + trailing-dot normalized). Wired into both `_make_client` and `cmd_identity_fetch` — commits `ef5dee4..a47a78c`, merged as `6060bbf`. 20 new tests.
- **cluster-atomic-refresh** — `ClusterClient.refresh_now` pre-runs both factories across every node in the new manifest before touching either `install_manifest`. If any factory raises, neither side advances; no more split-brain between reader and writer on malformed endpoints. Probe outputs are not closed (factories may return shared instances) — commits `bd2fb03..32a2553`, merged as `3ee9d6a`. 4 new tests.
- **M3.1** — Bootstrap record type: signed DNS-discoverable pointer from a user domain to one or more clusters. Published at `_dmp.<user_domain>` TXT; carries sorted entries of (priority, cluster_base_domain, operator_spk). Mirrors the hardened `ClusterManifest` pattern: multi-string TXT support, wire-cap on both sides, embedded-signer-cross-check, expected_user_domain binding with casefold + trailing-dot normalization, DNS-name validation, empty-list rejection, duplicate-entry rejection — commits `cd2f383..5c33cd5`, merged as `441f58b`. Plus `81f1dd7` for parse-side 64-byte-FQDN boundary fix. 66 new tests.
- **M3.2-wire** — Bootstrap CLI integration: `dmp bootstrap pin / fetch / discover [--auto-pin]` command group, `identity fetch --via-bootstrap` flag, `dmp.client.bootstrap_discovery.fetch_bootstrap_record`. Two-hop trust chain (bootstrap signer verifies the record → cluster operator verifies the manifest), priority-ordered fallback with factory dry-run, clears `cluster_node_token` + `http_token` on repin to avoid cross-trust-domain credential leaks, `--auto-pin` scope-guard requires discovered host to match pinned `bootstrap_user_domain`, DNS-name normalization for anchor comparisons. Shared `_pick_usable_bootstrap_entry` helper across discover/auto-pin/via-bootstrap so fallback semantics stay aligned — commits `20a83fe..d21c305` (8 commits, 7 Codex review rounds), merged as `7aae84e`. 31 new tests (12 bootstrap_discovery + 19 TestBootstrapCommand).
- **M4.1** — Formal protocol specification: six new pages under `docs/protocol/` — `spec.md` (top-level), `wire-encoding.md`, `routing.md`, `flows.md`, `threat-model.md`, `README.md` (landing). ~1500 lines total. Every magic byte, wire cap, and trust invariant cross-verified against the source. Three implementation ambiguities flagged inline for future cleanup — commits `4380469..c4f18fc`, merged as `f317cc7`.
- **M2.4** — Node-side anti-entropy: pull-based digest/pull worker with compound `(ts, name, value_hash)` cursor, TTL-refresh detection, contiguous-prefix watermark advancement, signed-record re-verify on receive, millisecond `stored_ts` with migration-safe ALTER TABLE on existing DBs. New `/v1/sync/digest` + `/v1/sync/pull` HTTP endpoints protected by `DMP_SYNC_PEER_TOKEN`. 50 new tests + 6 Codex review rounds — merged as `06405ce`.
- **M2.5 + M2.6** — 3-node compose cluster: `docker-compose.cluster.yml` with `build:` fallback, `docker/cluster/node-{a,b,c}.env` per-node env files, `generate-cluster-manifest.py` operator helper (seq auto-increment, dev-only key warning), `.gitignore` for operator secrets, `docs/deployment/cluster.md` guide. Integration test `tests/test_compose_cluster.py` exercises convergence + kill-and-rejoin backfill + peer auth against real docker containers. Dockerfile fix: added argon2-cffi + zfec + build-essential so the image actually builds. Node startup now publishes the mounted cluster manifest at `cluster.<base>` TXT for DNS bootstrap. Unique peer IDs by full URL so same-host different-port peers don't collapse watermarks. 4 Codex review rounds — merged as `8f9ce95`.
