---
title: Registering on a multi-tenant node
layout: default
parent: User Guide
nav_order: 5
---

# Registering on a multi-tenant node (M5.5)
{: .no_toc }

{: .warning }
**This page covers the legacy HTTP-token registration flow
(`dnsmesh register`).** M9 (0.5.0) replaced it with `dnsmesh tsig
register` — same Ed25519 challenge/confirm ceremony, but the node
returns a TSIG key instead of a bearer token, and every subsequent
record write goes over DNS UPDATE rather than HTTPS POST. New
deployments should use TSIG; see
[CLI reference → `dnsmesh tsig`]({{ site.baseurl }}/guide/cli#dnsmesh-tsig)
or [Getting Started]({{ site.baseurl }}/getting-started). The
HTTP-token flow below remains valid when DNS UPDATE isn't reachable
(network blocks UDP 53 outbound, etc.) and on operators who haven't
opted into `DMP_DNS_UPDATE_ENABLED`.

1. TOC
{:toc}

On a **multi-tenant** node — one that serves more than one user's
identity — every publisher needs their own credential. This page is
how you get one via the legacy HTTP-token path.

If the operator told you "the node is open" or handed you a single
shared secret, you're not on a multi-tenant node; just export
`DMP_OPERATOR_TOKEN=<value>` (or `DMP_HTTP_TOKEN` on an older
deploy) and use the CLI normally.

## Self-service (`dnsmesh register`)

Prerequisites:

- You've run `dnsmesh init <username>` — your local Ed25519 signing key
  is what the node will verify against.
- The operator has given you the node hostname.
- The operator has enabled registration on the node
  (`DMP_REGISTRATION_ENABLED=1`).

```bash
# One command, signs a challenge with your local key, saves the
# resulting token under ~/.dmp/tokens/dmp.example.com.json.
dnsmesh register --node dmp.example.com
```

Subject defaults to `<username>@<effective-domain>` from your
config. Override with `--subject` if you're claiming a different
address (e.g. a zone-anchored identity under a domain you control).

On success, the CLI prints:

```
registered alice@example.com on dmp.example.com
  token saved to /Users/alice/.dmp/tokens/dmp.example.com.json (mode 0600)
  expires at 2026-07-22T00:00:00Z
  subsequent `dnsmesh identity publish` / `dnsmesh send` to this node will
  use this token automatically.
```

Every subsequent `dnsmesh identity publish`, `dnsmesh send`, and
`dnsmesh identity refresh-prekeys` to that node auto-attaches the token
as the `Authorization: Bearer …` header. No env var to export, no
flags to remember.

## What can go wrong

| CLI error | What happened | Fix |
|---|---|---|
| `cannot reach <node>` | Network / TLS / hostname problem. | `curl -v https://<node>/v1/registration/challenge` to narrow down. |
| `did not accept the challenge request (404)` | Node doesn't have registration on, or isn't in multi-tenant mode. | Ask the operator to set `DMP_REGISTRATION_ENABLED=1` + `DMP_AUTH_MODE=multi-tenant`. |
| `rate-limited (429)` | You hit the per-IP registration throttle (default 5 / hour). | Wait an hour, or ask the operator to loosen `DMP_REGISTRATION_ENDPOINT_RATE_PER_SEC`. |
| `node rejected the signature (401)` | Your local Ed25519 key doesn't match what you claimed. Usually a wrong passphrase. | `dnsmesh identity show` — the `signing_pk` should match what you expected. |
| `subject not in allowlist (403)` | The operator restricted self-service to specific domains, and yours isn't on the list. | Use `--subject alice@<allowed-domain>`, or ask the operator. |
| `subject already held by a different key (409)` | Someone else registered that subject first, OR you registered previously on a different machine and this one has a different key. | Re-run on the machine that has the original passphrase, or ask the operator to revoke: `dnsmesh-node-admin token revoke <subject>`. |

## Rotating your token

`dnsmesh register` is idempotent. Re-running it on the same machine
with the same key rotates the token: the old one is revoked at the
node and a fresh one is saved locally in one atomic DB transaction
(no window where both are live, no window where neither is).

```bash
dnsmesh register --node dmp.example.com
# output: registered alice@example.com on dmp.example.com
#         (old token for the same subject was revoked)
```

## Inspecting what you have

```bash
dnsmesh token list
# NODE                            SUBJECT                        EXPIRES
# dmp.example.com                 alice@example.com              2026-07-22T00:00:00Z
# node-b.other.org                alice@other.org                -
```

The raw token material is never printed on stdout — only the node,
subject, and expiry. `--json` adds a truncated prefix + length for
scripting, still never the full token.

```bash
dnsmesh token forget <node>
# removes ~/.dmp/tokens/<node>.json. Handy if the operator has
# revoked your token and you want to start fresh with `dnsmesh register`.
```

## Operator-issued path (no `dnsmesh register`)

If the operator prefers to hand out tokens directly:

```bash
# They'll run on the node:
dnsmesh-node-admin token issue alice@example.com \
    --expires 90d --note "alice onboarded via Signal"

# Output (shown to the operator once):
#   token: dmp_v1_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#   subject: alice@example.com
#   expires_at: 2026-07-22T00:00:00Z
```

They'll pass the token to you via whatever channel you already trust
(Signal, a secure paste, a sealed envelope). On your side, save it:

```bash
echo '{
  "version": 1,
  "node": "dmp.example.com",
  "subject": "alice@example.com",
  "token": "dmp_v1_XXXXXXXXXXXX..."
}' > ~/.dmp/tokens/dmp.example.com.json
chmod 0600 ~/.dmp/tokens/dmp.example.com.json
```

A CLI sugar command `dnsmesh token add` for this step is a future nice-
to-have; the manual version is fine for now because the file format
is stable.

## Scope summary (what the token lets you publish)

A token for `alice@example.com` can POST / DELETE:

- `dmp.alice.example.com` — your identity record.
- `rotate.dmp.alice.example.com` — your rotation / revocation RRset.
- `pk-*.<your-hash12>.example.com` — your prekeys (when issued
  with `--with-prekey-scope <your-x25519-pubkey-hex>`).
- `slot-*.mb-*.<any-recipient-hash>.example.com` — any recipient's
  mailbox (you deliver messages here).
- `chunk-*.example.com` — any message chunk.

It **cannot** publish:

- Anyone else's identity / rotation / prekey records.
- Cluster / bootstrap / other operator-reserved namespaces.

Rate-limited per-token, independent of per-IP limits. If you get
unexpected 429s after a burst of publishes, it's your own
per-token bucket refilling; wait a second and retry.

## Related

- [How It Works]({{ site.baseurl }}/how-it-works) — the three auth
  modes (open / legacy / multi-tenant) at a higher level.
- [Deployment — Multi-tenant node]({{ site.baseurl }}/deployment/multi-tenant)
  — how operators turn this on.
