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

### M1.1 — `ResolverPool` class with failover

| Field | Value |
|---|---|
| **ID** | `M1.1` |
| **Status** | `pending` |
| **Owner** | — |
| **Depends on** | — |
| **Blocks** | `M1.2`, `M1.4` |
| **Estimated effort** | 2 days |
| **Touch zones** | `dmp/network/resolver_pool.py` (new), `dmp/network/base.py` (add reader interface tweaks if needed), `tests/test_resolver_pool.py` (new) |

**Acceptance criteria:**

- [ ] New `dmp.network.resolver_pool.ResolverPool` implements
      `DNSRecordReader`.
- [ ] Constructor takes a list of resolver hosts + an optional port
      (default 53).
- [ ] On `query_txt_record`, tries resolvers in priority order, failing
      over on `NXDOMAIN` / `NoAnswer` / socket timeout / transport error.
- [ ] Tracks per-resolver health: successful queries refresh a "good"
      timestamp; consecutive failures demote the resolver to the back
      of the queue for a cooldown window (60 s default).
- [ ] Tests cover: all-good happy path, first-resolver-down failover,
      all-resolvers-down returns `None`, cooldown promotion back to
      primary after success.
- [ ] `docs/guide/cli.md` updated if the CLI surface changes.

---

### M1.2 — CLI flag `--dns-resolvers`

| Field | Value |
|---|---|
| **ID** | `M1.2` |
| **Status** | `pending` |
| **Owner** | — |
| **Depends on** | `M1.1` |
| **Blocks** | — |
| **Estimated effort** | 1 day |
| **Touch zones** | `dmp/cli.py`, `tests/test_cli.py` |

**Acceptance criteria:**

- [ ] `dmp init` accepts `--dns-resolvers host[:port],host[:port],...`.
- [ ] Config file persists the list; single-host `--dns-host` still
      supported for back-compat.
- [ ] `_make_client` wires a `ResolverPool` when the config contains a
      multi-resolver list; falls back to current `_DnsReader` otherwise.
- [ ] Test covers list parsing + `_make_client` wiring the pool.

---

### M1.3 — Dynamic resolver discovery

| Field | Value |
|---|---|
| **ID** | `M1.3` |
| **Status** | `pending` |
| **Owner** | — |
| **Depends on** | `M1.1` |
| **Blocks** | — |
| **Estimated effort** | 3 days |
| **Touch zones** | `dmp/network/resolver_pool.py`, `tests/test_resolver_pool.py` |

**Acceptance criteria:**

- [ ] `ResolverPool.discover()` probes a set of well-known public
      resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9, 208.67.222.222) with a
      short TTL test query.
- [ ] Returns the working subset.
- [ ] CLI exposes `dmp resolvers discover` which prints the pool and
      optionally writes it to config via `--save`.

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

- **M2.1** Node cluster manifest (new record type, signed node list).
- **M2.2** Client write-fan-out to N nodes with `r_w / 2` success rule.
- **M2.3** Read-union across configured node set + dedupe.
- **M3.1** Bootstrap-domain record type.
- **M4.1** Formal protocol spec document (expand `docs/protocol/`).

## Done

*(Tasks migrate here on merge. Format: `<TASK-ID>` — one-line summary — commit `<sha>`.)*
