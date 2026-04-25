---
title: Multi-tenant node
layout: default
parent: Deployment
nav_order: 4
---

# Running a multi-tenant node (M5.5)
{: .no_toc }

1. TOC
{:toc}

A **multi-tenant** DMP node issues a separate bearer token to each
user and enforces, on every publish, that Alice's token can only
write Alice's identity / rotation / prekey records. This page is
the operator setup.

If you're running a personal node (one user, probably yourself),
skip this — use `DMP_AUTH_MODE=open` (the default without any
token) or `legacy` (one shared `DMP_OPERATOR_TOKEN`). Multi-tenant
is for the "friends & family node" and "community node" scenarios
where you want per-user audit, per-user rate limits, per-user
revocation, and the anonymity property below.

## Enabling multi-tenant mode

Three env vars, minimum:

```bash
DMP_AUTH_MODE=multi-tenant
DMP_OPERATOR_TOKEN=<operator-secret>     # for operator-reserved writes
DMP_NODE_HOSTNAME=dmp.example.com        # required for registration
```

Plus, to enable self-service registration (users running
`dnsmesh register` instead of you handing out tokens):

```bash
DMP_REGISTRATION_ENABLED=1
```

On startup, the node creates (or opens) `tokens.db` alongside the
main record DB. Override the path via `DMP_TOKEN_DB_PATH`.

### Where these env vars actually live

The node binary reads env vars only — there's no config file
format of its own. *But* every real deployment puts those vars
in a file somewhere and the supervisor (systemd / docker) loads
them. Which file depends on how you installed:

| Install method | File to edit | Apply with |
|---|---|---|
| `install-ubuntu.sh` (systemd, native) | `/etc/dnsmesh/node.env` | `sudo systemctl restart dnsmesh-node` |
| `install-digitalocean.sh` (docker compose) | `/opt/dnsmesh/.env` | `cd /opt/dnsmesh && docker compose up -d` |
| Hand-rolled `docker-compose.yml` | the `environment:` block of the `dnsmesh-node` service (or an `env_file:` you point at) | `docker compose up -d` |
| `docker run` directly | `-e DMP_AUTH_MODE=multi-tenant` flags on the command line | re-run the container |
| Running `dnsmesh-node` from the shell (dev) | `export DMP_AUTH_MODE=...` in your shell, or a `.env` you `source` | restart the process |

Example, for the systemd install:

```bash
sudo nano /etc/dnsmesh/node.env
# add the lines from "Enabling multi-tenant mode" above, save
sudo systemctl restart dnsmesh-node
sudo systemctl status dnsmesh-node    # confirm it came back up
journalctl -u dnsmesh-node -n 50      # check for "auth_mode=multi-tenant"
```

If you don't know which install you have: `systemctl status
dnsmesh-node` succeeds → systemd; `docker ps | grep dnsmesh` shows
a container → docker compose. The two are mutually exclusive on
the same host.

## Admin CLI cheatsheet

Every `dnsmesh-node-admin` command runs directly against the token
sqlite DB. On a docker deploy, run it via `docker exec`:

```bash
docker exec dnsmesh-node dnsmesh-node-admin token issue alice@example.com \
    --expires 90d --note "onboarded via Signal"
```

| Command | Purpose |
|---|---|
| `token issue <subject>` | Mint a token. Prints the value ONCE. `--expires 90d`, `--rate N`, `--burst N`, `--note TEXT`. |
| `token list [--subject S] [--include-revoked] [--json]` | Who's registered, what's live, what's expired. Never prints token material. |
| `token revoke <subject-or-hash-prefix>` | Revoke by exact subject (all live tokens) or unambiguous hash prefix. |
| `token rotate <subject>` | Revoke + re-issue in one go. |
| `audit tail [--event E] [--limit N]` | Recent lifecycle events (issued / revoked / used / throttled / rejected). |

The admin CLI doesn't talk to the HTTP server, so it works even
when the server is wedged.

## Opting into self-service registration

Self-service (`dnsmesh register`) lets users mint their own tokens
without the operator. The flow is signature-gated: the user proves
control of an Ed25519 key over a one-shot challenge bound to *this*
node's hostname. Exactly one live self-service token per subject
at any time.

Three env knobs worth knowing:

| Variable | Default | Purpose |
|---|---|---|
| `DMP_REGISTRATION_ENABLED` | `0` | Turn the endpoints on. |
| `DMP_REGISTRATION_ALLOWLIST` | `(empty = any)` | Comma-separated list of domains. If set, only subjects ending in one of these can register. |
| `DMP_REGISTRATION_ENDPOINT_RATE_PER_SEC` | `5/3600` | Per-IP rate limit on `/v1/registration/*`. Default: 5 attempts per hour. |
| `DMP_REGISTRATION_ENDPOINT_RATE_BURST` | `5.0` | Burst allowance paired with the above. |
| `DMP_REGISTRATION_TOKEN_TTL_SECONDS` | `90d` | Lifetime of tokens minted via self-service. |
| `DMP_REGISTRATION_ISSUED_RATE_PER_SEC` | `10.0` | Stamp for the per-token rate limit on minted tokens. |
| `DMP_REGISTRATION_ISSUED_RATE_BURST` | `50` | Same. |

Registration is a free subject-claim endpoint by default — anyone
who can reach your HTTPS port can try to register. Defenses shipped
out of the box:

1. **Signature required** — an attacker without the Ed25519 private
   key cannot produce a confirm that passes verification. They also
   cannot distinguish 403 (disallowed domain) / 409 (subject owned)
   from 401 — the order is sig-first, policy-second.
2. **Challenge is single-use and node-scoped** — a confirm signed
   for node X can't be replayed at node Y.
3. **Per-IP rate limit** — 5 attempts / hour by default. Operator
   can tighten or loosen.
4. **Optional allowlist** — restrict registration to domains you
   control.
5. **Low-order-point block** — prevents the classic Ed25519
   identity-point forgery where a degenerate pubkey verifies any
   signature.

### "Closed community node"

```bash
DMP_AUTH_MODE=multi-tenant
DMP_OPERATOR_TOKEN=<secret>
DMP_NODE_HOSTNAME=dmp.example.com
# No DMP_REGISTRATION_ENABLED. Only dnsmesh-node-admin issues tokens.
```

### "Open community node, my domain only"

```bash
DMP_AUTH_MODE=multi-tenant
DMP_OPERATOR_TOKEN=<secret>
DMP_NODE_HOSTNAME=dmp.example.com
DMP_REGISTRATION_ENABLED=1
DMP_REGISTRATION_ALLOWLIST=example.com
```

### "Open-internet node, anyone welcome"

```bash
DMP_AUTH_MODE=multi-tenant
DMP_OPERATOR_TOKEN=<secret>
DMP_NODE_HOSTNAME=dmp.example.com
DMP_REGISTRATION_ENABLED=1
# No allowlist. Bring your own anti-abuse story — consider pairing
# with Caddy/nginx rate limits in front, and monitoring the audit
# log for bursts of failed signatures.
```

## Scope rules (what a user token can write)

Every POST / DELETE on `/v1/records/{name}` is classified:

| Name shape | Scope | Who can write |
|---|---|---|
| `dmp.<user>.<domain>` | owner-exclusive | token whose subject is `<user>@<domain>` |
| `rotate.dmp.<user>.<domain>` | owner-exclusive | same |
| `pk-*.<hash12>.<domain>` | owner-exclusive | token with matching `subject_hash12` (set via `--with-prekey-scope`) |
| `slot-N.mb-<hash12>.<domain>` | shared-pool | any live token |
| `chunk-NNNN-<msgkey>.<domain>` | shared-pool | any live token |
| Anything else (cluster, bootstrap, …) | operator-only | `DMP_OPERATOR_TOKEN` only |

Shared-pool is the SMTP "deliver to anyone's inbox" model — any
authenticated sender can write chunks and mailbox deliveries,
because those records are *addressed to the recipient*, not the
sender. Rate-limited per-token (not per-IP) so one user spamming
chunks doesn't exhaust the shared per-IP budget for everyone
behind the same NAT.

## The split-audit / anonymity property

This is load-bearing and worth knowing before you advertise the
node to anyone:

- **Token lifecycle events** (issued / revoked / rotated) log
  `subject` + `token_hash` + `remote_addr`. That's identity-bound
  by nature.
- **Owner-exclusive writes** (identity / rotation / prekey) log
  the same. The write *is* the identity assertion.
- **Shared-pool writes** (chunks + mailbox deliveries) log only
  `timestamp` + `remote_addr`. **No token_hash, no subject.**
  Rate-limiting and revocation still work via the in-memory limiter
  and the live DB state — but an operator handed the token DB
  **cannot, from it alone, reconstruct a send/receive transcript
  for any user.**

Caveats:

- Timing correlation between lifecycle events + shared-pool
  timestamps still exists. "Alice's token was seen at 14:03:07 + a
  chunk was written at 14:03:07" is a guess, not a proof, but a
  guess is enough for some adversaries.
- The reverse proxy (Caddy / nginx / Cloudflare) also logs IPs.
  Matching those against audit timestamps is a second correlation
  vector.
- Full sender anonymity against a determined operator / network
  adversary requires Tor or a mixnet in front of the node. That's
  a separate milestone (M6, traffic-analysis resistance).

If "node cannot prove who talked to whom" is a property you want
to advertise, these caveats need to be part of the advertisement.

## Rate limits

Three stacked limiters, deliberately:

1. **Per-IP on `/v1/records/*`** (existing, pre-M5.5).
   `DMP_HTTP_RATE` / `DMP_HTTP_BURST`. Catches a single source IP
   flooding.
2. **Per-IP on `/v1/registration/*`** (M5.5 new). Very tight
   default (5 / hour). Catches a would-be subject-squatter.
3. **Per-token on `/v1/records/*`** (M5.5 new). Each minted token
   has its own `rate_per_sec` + `rate_burst` stamped at issue
   time. Catches a user who publishes too aggressively without
   affecting others.

Legitimate `dnsmesh identity publish` + `dnsmesh identity refresh-prekeys
--count 50` + a typical send fits under the defaults comfortably.

## Migration path from legacy

Existing deploys keep working unchanged. `DMP_HTTP_TOKEN` is still
honored as a fallback for `DMP_OPERATOR_TOKEN`. The `tokens.db`
file is created only when `DMP_AUTH_MODE=multi-tenant` (or you
explicitly set `DMP_TOKEN_DB_PATH`).

Rollout order we suggest:

1. Ship `DMP_AUTH_MODE=multi-tenant` + `DMP_OPERATOR_TOKEN=<same
   value you already had>`. Publish API behaves as before:
   operator token writes anywhere.
2. Issue tokens to your existing users one at a time via
   `dnsmesh-node-admin token issue`. Hand them out through a trusted
   channel.
3. Users switch their `DMP_HTTP_TOKEN` env to their per-user token,
   OR run `dnsmesh register` once and let `~/.dmp/tokens/<node>.json`
   take over.
4. Once everyone's migrated, you can tighten the operator token —
   or rotate it, since it's no longer in every user's shell.

## Related

- [User Guide — Registering on a multi-tenant node]({{ site.baseurl }}/guide/registration)
- [How It Works — three auth modes]({{ site.baseurl }}/how-it-works#trust-model--three-auth-modes)
- Design doc (full threat model + rollout plan):
  `docs/design/multi-tenant-auth.md` in the repo.
