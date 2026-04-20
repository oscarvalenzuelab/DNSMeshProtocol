# Current sprint

**Sprint status:** M1 — resolver resilience — **CLOSED** (2026-04-20).
All four tasks merged to `main`. Next sprint to be opened from
`ROADMAP.md` backlog (M2 federation is the natural follow-on, but M1.5
and M1.retro-codex are smaller unblocked items that can slot in first).

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

Small follow-ups surfaced during M1, plus items pulled from `ROADMAP.md`.

- **M1.5** — Per-host ports in `ResolverPool`. Extend the pool to accept
  `List[Tuple[str, int]]` (or parallel `ports` list) so each upstream can
  carry its own port. Drops the "first explicit port wins" workaround in
  `dmp/cli.py::_make_reader` and lets the M1.4 integration test drop its
  test-only `_PerHostPortResolverPool` subclass. Effort: ~0.5 day. Touch
  zones: `dmp/network/resolver_pool.py`, `tests/test_resolver_pool.py`,
  `tests/test_resolver_failover.py`, `dmp/cli.py`. Surfaced during M1.2
  and reinforced during M1.4.
- **M1.retro-codex** — Retroactive Codex review of M1.2 (commit
  `3096eb0`) and M1.3 (commit `d39cb56`). OpenAI API was returning 503
  at merge time; self-review served as a reasonable substitute but
  having an independent run is still valuable. Rerun once the API
  recovers; file any findings as follow-up tasks.
- **M2.1** Node cluster manifest (new record type, signed node list).
- **M2.2** Client write-fan-out to N nodes with `r_w / 2` success rule.
- **M2.3** Read-union across configured node set + dedupe.
- **M3.1** Bootstrap-domain record type.
- **M4.1** Formal protocol spec document (expand `docs/protocol/`).

## Done

- **M1.1** — `ResolverPool` with per-host health tracking, oracle-based
  demotion, and cooldown-as-preference fallback — commits `7cb8d7f`
  through `12376a4` (6 Codex review rounds, final clean pass).
- **M1.2** — CLI `--dns-resolvers` multi-resolver pool wiring +
  `_make_reader` factory + IP-literal parser (`host`, `ip:port`,
  `[ipv6]:port`) + config persistence + back-compat with single-host
  `--dns-host` — commit `3096eb0`. 12 new test cases. Codex review
  pending (API unavailable at merge time; tracked under M1.retro-codex
  in Backlog).
- **M1.3** — `ResolverPool.discover()` classmethod + `WELL_KNOWN_RESOLVERS`
  + `dmp resolvers discover [--save]` + `dmp resolvers list` CLI —
  commit `d39cb56`. 18 new test cases. Codex review pending (see
  M1.retro-codex).
- **M1.4** — Integration test: resolver failover under partial block.
  Real-UDP stubs (good `DMPDnsServer` + handcrafted NXDOMAIN server),
  8 tests covering the three TASKS.md acceptance criteria plus oracle
  semantics under real UDP — commits `29c5c44` (impl) + `6108c66`
  (atomic port-bind fix from Codex P2). Final Codex review: clean.
