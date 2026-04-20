# Current sprint

**Sprint status:** M1 — resolver resilience — **CLOSED + POLISHED**
(2026-04-20). All four M1 tasks merged, plus the M1.5 per-host-port
follow-up and the M1-retro-codex findings cleanup. 317 tests passing.

Next sprint: opening **M2 — federation** (client fan-out across
multiple node operators).

See `ROADMAP.md` for the long-horizon view. This file is the active
work queue.

## Conventions

- `pending` → not started, available to claim
- `in-progress` → an Implementer owns it; `owner` field names the session
- `in-review` → PR open against `main`
- `blocked` → open P1 finding or failing Validator
- `done` → merged; commit SHA recorded

## Active

### M2.1 — Node cluster manifest (signed node list record)

| Field | Value |
|---|---|
| **ID** | `M2.1` |
| **Status** | `pending` |
| **Owner** | — |
| **Depends on** | — |
| **Blocks** | `M2.2`, `M2.3` |
| **Estimated effort** | 2-3 days |
| **Touch zones** | `dmp/core/cluster.py` (new), `dmp/core/identity.py` (possibly — reuse signed-record patterns), `tests/test_cluster.py` (new), `docs/protocol/cluster.md` (new or add to existing) |

**Goal:** define a signed, DNS-publishable record type listing the set
of DMP nodes that make up a cluster. A client points at one
bootstrap name, reads this manifest, and gets the full node set.

**Acceptance criteria:**

- [ ] New `ClusterManifest` dataclass with binary wire format.
      Must fit in one 255-byte DNS TXT string OR split across multiple
      TXT strings within one RRset (document the choice).
- [ ] Ed25519-signed by a cluster-operator key. Signature verified on
      parse (reject tampered or wrong-signer records).
- [ ] Carries: cluster name, node list (host + HTTP endpoint + optional
      DNS endpoint, one entry per node), sequence number, expiry.
- [ ] `parse_and_verify(wire, operator_pubkey)` returns
      `(ClusterManifest, metadata)` or `None`.
- [ ] Round-trip unit tests: sign → wire → parse → verify; tamper
      rejection; wrong-signer rejection; malformed input returns None.
- [ ] Docs page under `docs/protocol/` describing the record format
      alongside `manifest.md`, `identity.md`, `prekey.md`.

## Backlog (promoted to active as bandwidth allows)

- **M2.2** — Client write-fan-out to N nodes with `r_w / 2` success rule.
  Depends on M2.1. Touch zones: `dmp/client/client.py`, new
  `dmp/network/fanout_writer.py`, tests.
- **M2.3** — Read-union across configured node set + dedupe.
  Depends on M2.1. Touch zones: new `dmp/network/union_reader.py`,
  `dmp/client/client.py`, tests.
- **M3.1** — Bootstrap-domain record type (SRV-like discovery for
  cluster entry point).
- **M4.1** — Formal protocol spec document (expand `docs/protocol/`).

## Done

- **M1.1** — `ResolverPool` with per-host health tracking, oracle-based
  demotion, and cooldown-as-preference fallback — commits `7cb8d7f`
  through `12376a4` (6 Codex review rounds, final clean pass).
- **M1.2** — CLI `--dns-resolvers` multi-resolver pool wiring +
  `_make_reader` factory + IP-literal parser (`host`, `ip:port`,
  `[ipv6]:port`) + config persistence + back-compat with single-host
  `--dns-host` — commit `3096eb0`. 12 new test cases. Retroactive
  Codex review clean after the `8ab60e7` scalar-dns_resolvers fix
  landed with M1.5.
- **M1.3** — `ResolverPool.discover()` classmethod + `WELL_KNOWN_RESOLVERS`
  + `dmp resolvers discover [--save]` + `dmp resolvers list` CLI —
  commit `d39cb56`. 18 new test cases. Retroactive Codex review clean
  after `6267686` (reject NoAnswer during discover) and `f9d3dfa`
  (resolvers list handles missing config) landed with M1.5.
- **M1.4** — Integration test: resolver failover under partial block.
  Real-UDP stubs (good `DMPDnsServer` + handcrafted NXDOMAIN server),
  8 tests — commits `29c5c44` (impl) + `6108c66` (atomic port-bind
  fix from Codex P2). Final Codex review: clean.
- **M1.5** — Per-host ports in `ResolverPool` (accepts
  `[(ip, port), ...]` or bare IPs). Dropped the "first explicit port
  wins" workaround in `_make_reader`. Dropped the test-only
  `_PerHostPortResolverPool` subclass from `test_resolver_failover`.
  `_HostState` + `snapshot()` now carry per-host port; new
  `healthy_upstreams()` returns `(ip, port)` tuples — commits
  `9bfab67`, `5fe2425`, `4ebcb9f`, plus the four retro/follow-up
  fixes `50ba3d7`, `8ab60e7`, `6267686`, `f9d3dfa`. 317 tests passing.
  Final Codex review: clean.
