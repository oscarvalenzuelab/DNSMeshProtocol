---
title: CLI reference
layout: default
parent: User Guide
nav_order: 1
---

# CLI reference
{: .no_toc }

1. TOC
{:toc}

## Config and passphrase

The CLI stores its per-identity config at `$DMP_CONFIG_HOME/config.yaml`
(default `~/.dmp/config.yaml`), with file mode 0600. The config holds
everything *except* the passphrase — that's read from:

1. `DMP_PASSPHRASE` environment variable (preferred for scripting)
2. `passphrase_file` entry in config pointing at a 0600 file
3. Interactive prompt via `getpass` as a last resort

The passphrase drives Argon2id key derivation against a per-identity
random salt stored in the config. Losing the config means losing the
identity even if you remember the passphrase.

### Config fields of note

- `dns_host` / `dns_port`: legacy single-resolver config. Used by both
  `_make_client` (for send/recv) and `dnsmesh identity fetch` when
  `dns_resolvers` is empty.
- `dns_resolvers`: list of IP literals (optionally with port) that
  populates a `ResolverPool` across failover-eligible upstreams. When
  non-empty it takes precedence over `dns_host` / `dns_port` for reads.
  Persisted in canonical form: bare IP for portless entries,
  `ip:port` for IPv4, `[ip]:port` for IPv6.
- `cluster_base_domain` + `cluster_operator_spk`: anchors for
  cluster (federation) mode. Setting them is the first of two steps —
  they pin *what* the client trusts but do not flip cluster mode on.
  See `cluster_enabled` below and [Cluster mode](#cluster-mode).
- `cluster_enabled`: explicit activation switch for cluster mode.
  When True **and** both anchors are pinned, the client resolves
  `cluster.<cluster_base_domain>` TXT, verifies the signed
  `ClusterManifest` under the operator pubkey, and builds a
  `FanoutWriter` + `UnionReader` across the named nodes. When False
  (the default on a fresh pin, and on any older config missing the
  field), the client uses the legacy single-endpoint path regardless
  of pinned anchors. Flip this on via `dnsmesh cluster enable` (runs a
  live manifest fetch sanity check first) and off via
  `dnsmesh cluster disable`.
- `cluster_refresh_interval`: seconds between background manifest
  refresh ticks. Default 3600 (once/hour). Set to 0 to disable the
  refresh thread (a manual `dnsmesh cluster fetch` / restart is then
  needed to pick up node-set changes).
- `cluster_node_token`: optional bearer token for the per-node HTTP
  publish writers. Falls back to `http_token` when empty.
- `bootstrap_user_domain` + `bootstrap_signer_spk`: anchors for
  bootstrap discovery (M3.2-wire). Pinning these with
  `dnsmesh bootstrap pin <user_domain> <signer_spk_hex>` lets the client
  translate `alice@<user_domain>` addresses into concrete cluster
  anchors via a signed TXT record at `_dmp.<user_domain>`. See
  [Bootstrap discovery](#bootstrap-discovery). This is a **separate
  trust domain** from `cluster_*`: the zone operator signing the
  bootstrap record and the cluster operator signing the cluster
  manifest are distinct keys, and the client verifies each
  independently during discovery.

## Subcommands

### `dnsmesh init`

Create a fresh config.

```
dnsmesh init <username> [--domain D] [--endpoint URL] [--http-token T]
                    [--dns-host H] [--dns-port P]
                    [--dns-resolvers IP[:PORT],IP[:PORT],...]
                    [--identity-domain ZONE]
                    [--force]
```

| Flag | Default | Purpose |
|---|---|---|
| `--domain` | `mesh.local` | Shared mesh domain; slots/chunks live here |
| `--endpoint` | — | HTTP API URL of the node you publish to |
| `--http-token` | — | Bearer token for the HTTP API (optional) |
| `--dns-host` | system | DNS resolver IP for queries (single-host, legacy) |
| `--dns-port` | 5353 | DNS resolver port (single-host, legacy) |
| `--dns-resolvers` | — | Comma-separated IP literals with optional ports; enables `ResolverPool` failover |
| `--identity-domain` | — | DNS zone you control — enables zone-anchored addresses |
| `--force` | off | Overwrite existing config |

`--dns-resolvers` takes a comma-separated list of IPv4 or IPv6 literals,
each optionally carrying a port (`8.8.8.8:53`, `[2001:4860:4860::8888]:53`).
Hostnames are rejected — the pool refuses to do an unconfigured DNS
lookup at startup, which would reintroduce the resolver-ordering
problem the pool exists to solve.

When `--dns-resolvers` is set, the CLI wires a `ResolverPool` with
per-host health tracking and automatic failover; `--dns-host` /
`--dns-port` are ignored for reads. When it is absent, the CLI falls
back to the single-host reader for back-compat. Bad parses (non-IP
literal, malformed `host:port`, port out of range) fail `dnsmesh init`
with exit code 1 before any config is written.

Pool-port caveat: `ResolverPool` today takes a single port for every
upstream. If the parsed entries carry mixed ports, the first explicit
port wins and the rest of the pool inherits it. Pools of same-port
resolvers (all `:53`, or all default) are unaffected.

### `dnsmesh identity`

| Subcommand | Purpose |
|---|---|
| `dnsmesh identity show [--json]` | Print this identity's public keys |
| `dnsmesh identity publish [--ttl N]` | Publish the signed identity record to DNS |
| `dnsmesh identity refresh-prekeys [--count N] [--ttl S]` | Generate and publish a one-time prekey pool |
| `dnsmesh identity fetch <user> [--domain D] [--add] [--accept-fingerprint F] [--via-bootstrap] [--json]` | Resolve someone else's identity |

`dnsmesh identity fetch` accepts either a plain `<user>` (hash-based lookup
under the shared mesh domain — TOFU) or a zone-anchored
`<user>@<zone>` (queries `dmp.<zone>` — anchored to that DNS zone's
ownership).

When two valid identity records coexist at the same name, `--add` is
refused and fingerprints are printed on stderr. Re-run with
`--accept-fingerprint <16-hex>` after verifying out of band.

`--via-bootstrap` (M3.2-wire): when the address is in `<user>@<host>`
form and a bootstrap signer is pinned for `<host>` via
`dnsmesh bootstrap pin`, the command discovers the cluster serving that
host on-the-fly and routes the identity query through a one-shot
cluster client. No config is written — this is a lookup convenience.
For a permanent cluster pin, use `dnsmesh bootstrap discover --auto-pin`
instead.

### `dnsmesh contacts`

| Subcommand | Purpose |
|---|---|
| `dnsmesh contacts add <name> <x25519_hex> [--signing-key <ed25519_hex>]` | Pin a contact |
| `dnsmesh contacts list` | Show pinned contacts; marks each pinned or UNPINNED |

Adding a contact **without** `--signing-key` prints a stderr warning
and leaves the client in TOFU mode for incoming messages. Prefer
`dnsmesh identity fetch <user> --add`, which pins both keys automatically.

### `dnsmesh send` / `dnsmesh recv`

```
dnsmesh send <recipient> <message>
dnsmesh recv
```

`send` auto-selects a forward-secret path when the contact has a
pinned Ed25519 signing key and a live prekey pool; otherwise it
falls back to the recipient's long-term X25519 key.

`recv` polls every mailbox slot, verifies signatures, checks the
replay cache, fetches chunks, runs cross-chunk erasure decode, and
decrypts. Messages that pass all checks are printed; everything else
is silently dropped.

### `dnsmesh resolvers`

Manage the upstream DNS resolver list the client uses to read chunks,
manifests, and identity records.

| Subcommand | Purpose |
|---|---|
| `dnsmesh resolvers discover [--save] [--timeout S]` | Probe well-known public resolvers (Google, Cloudflare, Quad9, OpenDNS — 8 IPv4 hosts total) and print the working set |
| `dnsmesh resolvers list` | Print the currently configured `dns_resolvers` |

`discover` sends a cheap TXT query for a stable well-known name to
each candidate with a `--timeout` (default 2.0 s) budget. Resolvers
that don't answer within that window are dropped. If every candidate
fails, the command exits with code 2 rather than writing an empty
list that would break every future query.

Without `--save`, discover is a read-only diagnostic — useful on a
captive or restricted network to sanity-check which upstreams are
reachable. With `--save`, the working list is written to
`config.yaml` as `dns_resolvers`. Once M1.2 lands, the normal read
path wires a multi-resolver `ResolverPool` over that list instead of
the single `--dns-host` upstream, so `dnsmesh send` / `dnsmesh recv` benefit
automatically.

Example:

```
$ dnsmesh resolvers discover
discovered 4 working resolver(s):
  1.1.1.1
  8.8.8.8
  9.9.9.9
  208.67.222.222

$ dnsmesh resolvers discover --save
discovered 4 working resolver(s):
  1.1.1.1
  8.8.8.8
  9.9.9.9
  208.67.222.222
saved 4 resolvers to /home/alice/.dmp/config.yaml

$ dnsmesh resolvers list
1.1.1.1
8.8.8.8
9.9.9.9
208.67.222.222
```

### `dnsmesh cluster`

Federation mode (M2.wire). A cluster is a set of nodes collectively
serving the same mailbox data; a client that pins the operator's
Ed25519 pubkey + the cluster base domain fans every write to a
majority of nodes and unions every read across all of them. Single
nodes can go down without the client caring.

| Subcommand | Purpose |
|---|---|
| `dnsmesh cluster pin <operator_spk_hex> <base_domain>` | Store trust anchors in config (does NOT activate cluster mode) |
| `dnsmesh cluster fetch [--save]` | One-shot fetch + verify of the cluster manifest; print summary |
| `dnsmesh cluster enable` | Activate cluster mode after a successful manifest fetch (flips `cluster_enabled=True`) |
| `dnsmesh cluster disable` | Deactivate cluster mode without clearing the pinned anchors (flips `cluster_enabled=False`) |
| `dnsmesh cluster status` | Build the cluster client; print per-node fan-out/union health + activation flag |

Activation is a two-step process so that pinning an operator whose
manifest isn't yet published doesn't wedge every subsequent
networked command. The flow is:

1. `dnsmesh cluster pin` — write the anchors. Leaves `cluster_enabled`
   at its default (False).
2. `dnsmesh cluster fetch` — confirm the manifest is published, signed
   by the pinned key, and not expired. Pure diagnostic; no state
   change.
3. `dnsmesh cluster enable` — re-runs the fetch as a sanity check and,
   on success, flips `cluster_enabled=True`. On failure, exits 2
   and leaves the flag unchanged, so a failed enable never locks
   the CLI out of its legacy endpoint.

`pin` writes `cluster_operator_spk` and `cluster_base_domain` to
config. The operator SPK must be 64 hex chars (32 bytes).
`base_domain` is the DNS zone where the manifest lives; the actual
TXT RRset is `cluster.<base_domain>`. `pin` also resets
`cluster_enabled` to False even on an already-enabled config, so
repinning against a new operator forces a fresh `cluster enable`
sanity check before the cutover.

`fetch` resolves that RRset via the same reader the CLI uses for
other reads (`ResolverPool` when `dns_resolvers` is set, otherwise
`_DnsReader`), then calls `ClusterManifest.parse_and_verify` to
confirm the signature binds to the pinned operator key AND the
signed cluster name matches the pinned base domain. `--save`
caches the signed manifest wire to `cluster_manifest.wire` in the
config dir (future offline-bootstrap use). `fetch` works regardless
of `cluster_enabled` — it only needs the anchors pinned, since its
whole purpose is pre-enable verification.

`enable` is idempotent: running it on an already-enabled config
re-runs the fetch, prints the manifest summary, and reports
"cluster mode already enabled" without changing state. Use this as
a quick post-rollover health check.

`disable` is also idempotent and leaves the pinned anchors alone.
Running it is the fastest way back to the legacy single-endpoint
path if cluster mode misbehaves; re-enabling later is a single
`dnsmesh cluster enable` call.

`status` builds a short-lived `ClusterClient` (no background
refresh thread) and prints the activation flag (`cluster_enabled:
True|False`) plus both the `FanoutWriter.snapshot()` and
`UnionReader.snapshot()` rows — one line per node with consecutive
failure count, last error, and endpoint. Works regardless of
`cluster_enabled`, so operators can inspect the cluster before
cutting over.

Mode switch: `_make_client` (called by `dnsmesh send`, `dnsmesh recv`,
`dnsmesh identity publish`, etc.) reads `cluster_base_domain`,
`cluster_operator_spk`, AND `cluster_enabled` at every invocation.
When all three are set it fetches + verifies the manifest on the
spot and wires a cluster client into the DMPClient. When any is
missing it falls back to the legacy single-endpoint path.

Refresh semantics: when `cluster_refresh_interval > 0` (default
3600 seconds), a daemon thread re-fetches the manifest and installs
it iff the `seq` is strictly higher than the currently installed
one. A failed fetch (transport error, empty RRset, signature
failure) logs a warning and leaves the previous manifest active —
reads and writes keep working against the last known node set.

Example:

```
$ dnsmesh cluster pin 3c6a... mesh.example.com
pinned cluster operator key and base domain mesh.example.com
next:
  1. `dnsmesh cluster fetch` to verify the manifest resolves
  2. `dnsmesh cluster enable` to cut over from the legacy endpoint

$ dnsmesh cluster fetch
cluster: mesh.example.com
  seq:   7
  exp:   1816000000
  nodes: 3
    n01  http=https://n1.mesh.example.com:8053  dns=203.0.113.10:53
    n02  http=https://n2.mesh.example.com:8053  dns=203.0.113.11:53
    n03  http=https://n3.mesh.example.com:8053  dns=(via bootstrap reader)

$ dnsmesh cluster enable
cluster: mesh.example.com
  seq:   7
  exp:   1816000000
  nodes: 3
cluster mode enabled.

$ dnsmesh cluster status
cluster: mesh.example.com (seq=7, exp=1816000000)
cluster_enabled: True
fan-out writer snapshot:
  n01  http=https://n1.mesh.example.com:8053  fails=0  err=None
  n02  http=https://n2.mesh.example.com:8053  fails=0  err=None
  n03  http=https://n3.mesh.example.com:8053  fails=0  err=None
union reader snapshot:
  n01  http=https://n1.mesh.example.com:8053  fails=0  err=None
  n02  http=https://n2.mesh.example.com:8053  fails=0  err=None
  n03  http=https://n3.mesh.example.com:8053  fails=0  err=None

$ dnsmesh cluster disable
cluster mode disabled — next commands will use the legacy endpoint path.
```

#### Migration note: pre-polish configs

An earlier version of this CLI flipped cluster mode on the moment
both anchors were pinned — there was no `cluster_enabled` field.
Upgrading a config from that era does **not** silently activate
cluster mode. The CLI loads such configs with `cluster_enabled=False`,
which means:

- `dnsmesh send` / `dnsmesh recv` / `dnsmesh identity publish` keep using the
  legacy single-endpoint path (`config.endpoint`) even with both
  cluster anchors present.
- The operator must run `dnsmesh cluster enable` once to cut over. That
  call re-verifies the manifest against the pinned anchors; on
  success it flips `cluster_enabled=True` and persists, so the
  next networked command uses the cluster path.

This deliberate one-time migration step avoids the "upgrade
bricks every command if the manifest isn't reachable right now"
failure mode the field was introduced to fix.

#### Migration note: bootstrap fields are additive

The M3.2-wire `bootstrap_user_domain` / `bootstrap_signer_spk`
fields are purely additive. An existing cluster-only config (both
`cluster_*` anchors pinned, `cluster_enabled=True`) is unchanged by
the upgrade — it continues to use the pinned cluster path. The
bootstrap-discovery commands (`dnsmesh bootstrap pin / fetch / discover`)
are opt-in; until you pin a bootstrap signer, the CLI behavior is
identical to pre-M3.2.

#### Cluster mode

When the two anchors above are set, publishes go to `ceil(N/2)`
nodes (quorum write; `FanoutWriter`) and reads query every node
concurrently and union-dedup the TXT answers (`UnionReader`). The
per-node writer is an HTTP writer pointed at `node.http_endpoint`
(authed by `cluster_node_token` if set, else `http_token`, else
unauthenticated). The per-node reader is a UDP DNS reader pointed at
`node.dns_endpoint`; nodes whose manifest entries omit
`dns_endpoint` fall back to the configured bootstrap reader (the
same resolver pool used to fetch the manifest).

### `dnsmesh bootstrap`

Bootstrap discovery (M3.2-wire). A bootstrap record is a signed TXT
record at `_dmp.<user_domain>` that points the user domain at one or
more clusters. It is the analogue of an SMTP MX record: given an
address like `alice@example.com`, a client queries DNS once, verifies
the record under the **zone operator**'s pinned pubkey, and learns
which cluster's `cluster.<base>` TXT to fetch next. No prior
knowledge of the cluster's base domain is needed — only the zone
operator's Ed25519 key, obtained out-of-band.

| Subcommand | Purpose |
|---|---|
| `dnsmesh bootstrap pin <user_domain> <signer_spk_hex>` | Store the zone operator's trust anchor in config |
| `dnsmesh bootstrap fetch [--user-domain X] [--signer-spk hex]` | One-shot fetch + verify; print the entry summary |
| `dnsmesh bootstrap discover <user@host> [--signer-spk hex] [--auto-pin]` | End-to-end discovery; print `cluster pin` guidance or auto-commit |

#### Trust model

The discovery flow crosses **two independent trust boundaries**.
`bootstrap_signer_spk` authorizes the zone operator to say "domain X
is served by cluster Y" but gives them no authority over cluster Y
itself. The cluster's own `operator_spk` (carried inside the
bootstrap entry and verified against the cluster manifest) gates
anything published there. Compromising one does not imply
compromising the other — a stolen zone-operator key can redirect
users to a different cluster but cannot forge records inside any
legitimate one, and a stolen cluster-operator key can tamper with
mailbox data on that cluster but cannot rewrite which cluster a user
domain points at.

`dnsmesh bootstrap discover --auto-pin` makes this two-hop verification
visible: it first verifies the bootstrap record against the pinned
`bootstrap_signer_spk`, THEN verifies the cluster manifest at the
returned anchor against the entry's `operator_spk`. Only after
**both** succeed does it write anything to config. A failure at
either step exits 2 and leaves the config untouched — a half-written
config (bootstrap pinned but no cluster) is worse than none.

#### `pin`

```
dnsmesh bootstrap pin example.com 3c6a...
pinned bootstrap signer for example.com
next:
  1. `dnsmesh bootstrap fetch` to verify the record at _dmp.example.com resolves
  2. `dnsmesh bootstrap discover <user>@example.com` to see which cluster(s) the domain points at
```

Pin writes `bootstrap_user_domain` + `bootstrap_signer_spk` to
config. Does **not** fetch — pinning an operator whose record isn't
yet published is safe (the command never touches DNS, so it never
wedges). The same decoupling `dnsmesh cluster pin` uses.

#### `fetch`

```
dnsmesh bootstrap fetch
user_domain: example.com
seq:         3
expires:     1816000000
entries (sorted by priority):
  priority=10  cluster=mesh.example.com  operator_spk=7f3b2a89b4e5c6d1...
  priority=20  cluster=backup.example.com  operator_spk=2c1e9a3f8d0b74a5...
```

One-shot diagnostic: resolves `_dmp.<user_domain>` TXT, returns the
highest-seq record that verifies and binds to the expected user
domain, and prints entries sorted by priority (lowest first, SMTP
MX semantics). CLI flags override pinned config for pre-pin
verification.

Exit codes: 1 for a missing pin or bad hex; 2 for DNS unreachable
or no verifying record.

#### `discover`

```
dnsmesh bootstrap discover alice@example.com
address:     alice@example.com
user_domain: example.com  (seq=3, exp=1816000000)
best entry:  priority=10
  cluster_base_domain: mesh.example.com
  operator_spk:        7f3b2a89b4e5c6d1...

to pin this cluster manually, run:
  dnsmesh cluster pin 7f3b2a89b4e5c6d1... mesh.example.com
  dnsmesh cluster fetch  # verify manifest
  dnsmesh cluster enable # activate cluster mode

or re-run with --auto-pin to do all of the above atomically.
```

Without `--auto-pin`, discover is a diagnostic that shows the
operator exactly what an end-to-end pin would do — no state is
written, trust decisions stay explicit.

With `--auto-pin`, discover performs the full two-hop verification
(bootstrap → cluster manifest), then writes both the bootstrap and
cluster anchors and sets `cluster_enabled=True` in a single atomic
step. If either verification fails, the command exits 2 and leaves
the config untouched.

### `dnsmesh node`

Convenience launcher for a foreground DMP node, reading config from
env vars.

```
dnsmesh node [--db-path PATH] [--dns-port P] [--http-port P]
```

For real deployments use the docker-compose files — see
[Deployment]({{ site.baseurl }}/deployment).

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `DMP_CONFIG_HOME` | `~/.dmp` | Where the CLI stores config, replay cache, and prekey DB |
| `DMP_PASSPHRASE` | — | Identity passphrase; feeds Argon2id KDF |

Node env vars are documented separately under
[Deployment → Production]({{ site.baseurl }}/deployment/production).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | User / config error (missing config, bad flag, invalid hex) |
| 2 | Network / backend error (publish failed, nothing to fetch) |
