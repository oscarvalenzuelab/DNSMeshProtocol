---
title: Multi-tenant node auth
layout: default
parent: Design Intent
nav_order: 10
---

# M5.5 — Multi-tenant node auth (per-user tokens)

{: .no_toc }

{: .note }
**Historical design doc.** M5.5 introduced per-user HTTP bearer
tokens; M9 (0.5.0) carried the threat model forward but replaced
the network primitive with **per-user TSIG keys** (RFC 8945) over
RFC 2136 DNS UPDATE — same subject-bound write authorization,
same anti-takeover semantics, same scope rules, but writes now
travel as signed DNS UPDATE messages rather than authenticated
HTTPS POSTs. The threat-model analysis below applies unchanged to
both primitives; only the wire-level mechanism evolved. See the
[CLI tsig reference]({{ site.baseurl }}/guide/cli#dnsmesh-tsig)
for the M9 happy path.

1. TOC
{:toc}

## Problem

The node's `/v1/records/*` publish API is gated today by a single
shared bearer token (`DMP_HTTP_TOKEN`). Either the caller has the
token (full write access across every record name the node stores)
or they don't.

That's fine for **one trust zone** — a team, a small community, a
self-host where the same person writes and reads. It breaks for
**multi-tenant community nodes** because:

1. The token leaks trivially — anyone the operator onboards gets
   publish rights to *every* user's namespace.
2. There's no way to rate-limit a specific user, revoke a specific
   user, or audit who wrote what.
3. Rotating the token requires coordinating with every onboarded
   user simultaneously.

M5.5 introduces **per-user tokens**, bound to a DMP subject
(e.g. `alice@example.com`), with scoped authorization on every
write.

## Threat model additions

What per-user tokens defend against that the shared token does
not:

- **Identity spoofing by a co-tenant.** With a shared token,
  compromising one user's token (via malware on their laptop,
  shoulder-surfing, etc.) lets the attacker republish any other
  user's `IdentityRecord` — the signature check stops the attacker
  from *forging* the record, but nothing stops them from publishing
  a garbage TXT record at the right name and breaking DNS resolution
  for Bob. Per-user tokens with strict ownership on identity names
  eliminate this.
- **Cross-user denial-of-service via rate limit exhaustion.** Per-IP
  rate limits today; a malicious co-tenant behind CGNAT can spend
  the publish budget shared by legitimate users on the same NAT.
  Per-token rate limits give each user an isolated quota.
- **Audit gaps.** Today's node logs who-published-what by IP; with
  tokens we log by subject. Operators can answer "who flooded me at
  3am" with a single SQL query.

What per-user tokens **do not** defend against, by design:

- **Crypto-level spoofing.** Identity records are already signed.
  A bad token lets you publish garbage, not forge Alice.
- **Metadata privacy against the operator.** The operator still
  sees who-talks-to-whom (message chunk timing). This is a separate
  milestone (M6, traffic-analysis resistance).

## Token schema

```sql
CREATE TABLE tokens (
    token_hash     TEXT PRIMARY KEY,  -- sha256(token) hex; the token itself is never stored
    subject        TEXT NOT NULL,     -- 'alice@example.com' or 'alice' for zone-anchored
    subject_type   INTEGER NOT NULL,  -- 1 = user_identity (future: 2 = cluster_operator)
    rate_per_sec   REAL    NOT NULL DEFAULT 10.0,
    rate_burst     INTEGER NOT NULL DEFAULT 50,
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER,           -- NULL = no expiry (operator-issued, rotate manually)
    revoked_at     INTEGER,           -- NULL = active
    issuer         TEXT,              -- 'self-service' or 'admin:<operator-id>'
    note           TEXT               -- free-form operator annotation
);

CREATE TABLE token_audit (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             INTEGER NOT NULL,
    event          TEXT NOT NULL,     -- 'issued' | 'revoked' | 'used' | 'rejected'
    token_hash     TEXT,              -- only populated for lifecycle + owner-scope events
    subject        TEXT,              -- only populated for lifecycle + owner-scope events
    remote_addr    TEXT,
    detail         TEXT               -- JSON blob, event-specific
);
```

Notes:

- Token **material is never stored** — only `sha256(token)` in
  hex. A leaked DB doesn't compromise active tokens.
- No `secret` column on the `tokens` row — the token is
  transmitted to the user once at issuance, and from that point
  forward the user holds it and the node only verifies hash
  matches.
- `rate_per_sec` + `rate_burst` sit alongside the existing per-IP
  limiters; both must pass. A token-level rate limit prevents one
  user from DoS-ing the whole node; the per-IP limiter prevents an
  IP with many stolen tokens from doing the same.

## Scope rules

Every publish request targets a record name. The auth layer parses
the name and classifies it:

| Name shape | Scope type | Who can write |
|---|---|---|
| `dmp.<user>.<domain>` | **owner-exclusive** | only the token whose `subject` matches `<user>@<domain>` |
| `rotate.dmp.<user>.<domain>` or `rotate.dmp.id-<hash12>.<domain>` | **owner-exclusive** | same |
| `pk-*.<hash12>.<domain>` (prekeys) | **owner-exclusive** | same; hash12 derived from the subject's x25519 key |
| `slot-N.mb-<hash12>.<domain>` (mailbox delivery) | **shared-pool** | any active, non-revoked token |
| `chunk-NNNN-<msgkey>.<domain>` (message chunks) | **shared-pool** | any active, non-revoked token |
| `cluster.<base>` / `bootstrap.<user>` / others | **operator-only** | reserved scope; M5.5 does not issue these to end users |

"Owner-exclusive" is the SMTP "read your own mail" analogy.
"Shared-pool" is the "deliver to any mailbox" analogy — any
authenticated sender can write a chunk or a mailbox manifest,
because those records are *addressed to the recipient* not the
sender. Signatures on the manifest (`sender_spk` field) and
encryption of the chunk content prevent a malicious sender from
impersonating someone else *at the protocol layer* — the token
only controls who can put bytes on the node.

### Audit policy is split to preserve sender anonymity

Shared-pool writes have a natural privacy property worth
protecting: the record name itself encodes only the recipient's
hash, never the sender. We preserve that at the audit layer too:

| Event source | Columns logged | Rationale |
|---|---|---|
| Token lifecycle (issue / revoke / rotate) | `ts`, `event`, `token_hash`, `subject`, `remote_addr` | No sender anonymity at stake — these are explicit identity operations. |
| **Owner-exclusive write** (identity / rotation / prekey) | `ts`, `event`, `token_hash`, `subject`, `remote_addr` | The write itself is identity-bound. Attribution is the whole point. |
| **Shared-pool write** (mailbox slot / chunk) | `ts`, `event`, `remote_addr` *only* — **no `token_hash`, no `subject`** | From-the-node's-records you cannot tell *which user delivered to whom*. Rate limiting still works (the in-memory limiter holds the mapping ephemerally); revocation still works (the verification path checks the token). Only the durable log drops the link. |
| Rejected requests | `ts`, `event`, `remote_addr`, `detail` | Enough to diagnose abuse without leaking a user's failed attempts. |

Realistic caveat: timing correlation between "Alice's token was
seen at 14:03:07" in token lifecycle + "some chunk was written at
14:03:07" in shared-pool audit can still deanonymize. Plus the
reverse-proxy (Caddy / nginx) logs IPs. Full sender-anonymity
needs Tor / a mixnet — that's M6 territory, not M5.5.

The split audit policy is the *minimum useful anonymity story* at
the node layer: an operator compelled to hand over their SQLite
database cannot, from that database alone, produce a send-receive
transcript for any user.

### Why chunks aren't owner-scoped

A sender writes chunks addressed to a recipient under a name
derived from `sha256(msg_id || recipient_id || sender_spk)[:12]`.
The sender's identity is hashed in, so two senders can't collide
on the same chunk name, but the name itself doesn't reveal the
sender and can't be re-derived from the token's subject without a
signed envelope we don't have.

Adding a signed "intent to publish" envelope would close this gap
but doubles the publish cost and complicates the wire. Deferred.
Until then, per-token rate limits are the main defense against a
token holder spamming chunks at everyone.

### Operator namespace

Cluster manifests, bootstrap records, and other operator-signed
records stay on `DMP_HTTP_TOKEN` (renamed for clarity to
`DMP_OPERATOR_TOKEN` in the migration). End-user tokens cannot
publish into these namespaces at all.

## Registration flow (self-service)

```
Client                                Node
------                                ----
                                      (knows its hostname, e.g. dmp.example.com)

GET /v1/registration/challenge
                                      <- 200 {
                                             "challenge": "<32-byte random, hex>",
                                             "node": "dmp.example.com",
                                             "expires_at": <ts+60>
                                         }

(client signs challenge with its Ed25519 key)

POST /v1/registration/confirm
body: {
  "subject": "alice@example.com",
  "ed25519_spk": "<hex>",
  "challenge": "<hex from step 1>",
  "signature": "<hex>",    # sig over challenge||subject||node
  "requested_scope": "user_identity"
}
                                      # node verifies:
                                      # - challenge exists, not consumed, not expired
                                      # - signature verifies under ed25519_spk
                                      # - subject matches rate-limit budget
                                      # - if an existing token for subject is live,
                                      #   it is atomically revoked (one active token
                                      #   per subject)

                                      <- 200 {
                                             "token": "<token-material, shown once>",
                                             "subject": "alice@example.com",
                                             "expires_at": <ts+90d>,
                                             "rate_per_sec": 10.0
                                         }
```

Why the two-step (challenge then confirm): prevents replay of a
pre-signed confirm across nodes. The challenge binds the signature
to *this* node's hostname and a fresh nonce; an attacker who steals
Alice's signed confirm from node X can't replay it at node Y.

### Rate limits on registration itself

A naive `POST /v1/registration/confirm` is a free subject-claim
endpoint — an attacker could spam `bob@example.com`, `carol@...`
etc. to deny service to real users trying to register. Mitigations
shipped with M5.5:

1. **Per-IP registration rate limit** (default: 5 attempts / hour,
   tunable via `DMP_REGISTRATION_RATE`).
2. **Operator allowlist** (optional, env
   `DMP_REGISTRATION_ALLOWLIST=example.com,other.com`): if set,
   only subjects ending in one of the listed domains can self-
   register. Lets operators run closed communities without
   switching to admin-issued-only.
3. **Existing-subject rule**: if a subject already has a live
   token, self-service registration for that subject requires the
   request to be signed with the *previous* token's registered
   `ed25519_spk`. Prevents takeover of a subject after first-
   registration without physical access to the prior keyholder.

## Operator-issued flow

```bash
dnsmesh-node admin token issue alice@example.com \
    --rate-per-sec 20 \
    --expires 90d \
    --note "onboarded via Telegram DM"
# Prints:
#   token: dmp_v1_<base32-encoded 32-byte random>
#   subject: alice@example.com
#   expires_at: 2026-07-22T00:00:00Z
# Operator shares the token with Alice out-of-band.

dnsmesh-node admin token list
dnsmesh-node admin token revoke <token-prefix-or-subject>
dnsmesh-node admin token rotate <subject>  # issues a new one, revokes the old after grace window
```

The admin CLI is a subcommand of the node binary (not the `dnsmesh`
client CLI) because it needs direct access to the token database.
In the Docker deploy, operators run it via `docker exec`.

## Client-side onboarding

```bash
# Self-service path:
dnsmesh register --node dmp.example.com
# Prompts for subject (defaults to <username>@<domain> from config),
# generates keys if not present, does the 2-step dance, writes the
# returned token to ~/.dmp/tokens/<node-hostname>. `dnsmesh identity
# publish` etc. auto-read that file.

# Operator-issued path:
dnsmesh token add dmp.example.com <token-from-operator>
```

Tokens live at `~/.dmp/tokens/<node-hostname>` (mode 0600, one
file per node so a user with identities on multiple nodes can
manage them independently). The file contains the token material
plus metadata (subject, expiry). CLI commands that publish attach
the bearer header automatically.

## Migration

`DMP_HTTP_TOKEN` stays supported and continues to work for backward
compatibility, but is deprecated in favor of `DMP_OPERATOR_TOKEN`
(same behavior, clearer name — it's the operator's write-anything
token). Existing deploys change nothing; new installs use per-user
tokens.

A node can be configured in one of three modes via
`DMP_AUTH_MODE`:

| Mode | Behavior |
|---|---|
| `open` (default, dev-only) | No auth on publish. Warning printed at startup. |
| `legacy` | Only `DMP_OPERATOR_TOKEN` accepted (M5.5 behavior compatible with existing deploys). |
| `multi-tenant` | Per-user tokens accepted + `DMP_OPERATOR_TOKEN` for operator namespace. Registration endpoint enabled if `DMP_REGISTRATION_ENABLED=1`. |

## Rollout plan

1. **Schema + operator CLI** — smallest shippable slice. Operators
   can issue / list / revoke tokens; the HTTP API accepts them
   alongside `DMP_OPERATOR_TOKEN`. No scope enforcement yet.
2. **Scope enforcement** — the security core. Identity / rotation /
   prekey writes checked against the token's subject. Shared-pool
   writes gated by "any active token". Unit tests + fuzz.
3. **Self-service registration** — `/v1/registration/challenge` +
   `/confirm` endpoints. Per-IP rate limits. Allowlist support.
4. **Client CLI** — `dnsmesh register`, `dnsmesh token add/list/rotate`.
   Updates to `dnsmesh identity publish` / `dnsmesh send` to auto-attach
   bearer headers from `~/.dmp/tokens/`.
5. **Docs** — user guide section, operator deployment doc, How It
   Works update to reflect new trust model.

Each phase is a separate commit on `feature/m5.5-multi-tenant-auth`
and reviewable independently. Phase 1+2 is the minimum to unblock
demoing with other users; 3–5 complete the milestone.
