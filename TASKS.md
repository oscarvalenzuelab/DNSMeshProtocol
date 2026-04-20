# Current sprint

**Sprint goal:** deliver M1 — resolver resilience. Turn "works where you
configured it" into "works wherever DNS works."

See `ROADMAP.md` for the long-horizon view. This file is the active
work queue.

## Conventions

- `pending` → not started, available to claim
- `in-progress` → an Implementer owns it; `owner` field names the session
- `in-review` → PR open against `main`
- `blocked` → open P1 finding or failing Validator
- `done` → merged; commit SHA recorded

## Active

### M1.1 — `ResolverPool` class with failover — DONE (→ see Done section)

---

### M1.2 — DONE (→ Done section)
### M1.3 — DONE (→ Done section)

---

### M1.4 — Integration test: resolver failover under partial block

| Field | Value |
|---|---|
| **ID** | `M1.4` |
| **Status** | `pending` |
| **Owner** | — |
| **Depends on** | `M1.1`, `M1.2` |
| **Blocks** | — |
| **Estimated effort** | 2 days |
| **Touch zones** | `tests/test_resolver_failover.py` (new) |

**Acceptance criteria:**

- [ ] Spins up two local UDP "DNS stubs": one that serves DMP records
      correctly and one that returns NXDOMAIN for everything.
- [ ] A client configured with the NXDOMAIN stub first, real stub
      second, still delivers a message.
- [ ] Cooldown: after N NXDOMAIN answers, the bad stub is demoted;
      queries succeed faster on subsequent calls.

## Backlog (promoted to active as bandwidth allows)

These come from `ROADMAP.md`. Pull only after M1 sprint closes.

- **M1.5** — Per-host ports in `ResolverPool`. Extend the pool to accept
  `List[Tuple[str, int]]` (or parallel `ports` list) so each upstream can
  carry its own port. Drops the "first explicit port wins" workaround in
  `dmp/cli.py::_make_reader`. Effort: ~0.5 day. Touch zones:
  `dmp/network/resolver_pool.py`, `tests/test_resolver_pool.py`,
  `dmp/cli.py`. Surfaced during M1.2 implementation.
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
