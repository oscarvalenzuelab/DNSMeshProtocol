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
  `_make_client` (for send/recv) and `dmp identity fetch` when
  `dns_resolvers` is empty.
- `dns_resolvers`: list of IP literals (optionally with port) that
  populates a `ResolverPool` across failover-eligible upstreams. When
  non-empty it takes precedence over `dns_host` / `dns_port` for reads.
  Persisted in canonical form: bare IP for portless entries,
  `ip:port` for IPv4, `[ip]:port` for IPv6.

## Subcommands

### `dmp init`

Create a fresh config.

```
dmp init <username> [--domain D] [--endpoint URL] [--http-token T]
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
literal, malformed `host:port`, port out of range) fail `dmp init`
with exit code 1 before any config is written.

Pool-port caveat: `ResolverPool` today takes a single port for every
upstream. If the parsed entries carry mixed ports, the first explicit
port wins and the rest of the pool inherits it. Pools of same-port
resolvers (all `:53`, or all default) are unaffected.

### `dmp identity`

| Subcommand | Purpose |
|---|---|
| `dmp identity show [--json]` | Print this identity's public keys |
| `dmp identity publish [--ttl N]` | Publish the signed identity record to DNS |
| `dmp identity refresh-prekeys [--count N] [--ttl S]` | Generate and publish a one-time prekey pool |
| `dmp identity fetch <user> [--domain D] [--add] [--accept-fingerprint F] [--json]` | Resolve someone else's identity |

`dmp identity fetch` accepts either a plain `<user>` (hash-based lookup
under the shared mesh domain — TOFU) or a zone-anchored
`<user>@<zone>` (queries `dmp.<zone>` — anchored to that DNS zone's
ownership).

When two valid identity records coexist at the same name, `--add` is
refused and fingerprints are printed on stderr. Re-run with
`--accept-fingerprint <16-hex>` after verifying out of band.

### `dmp contacts`

| Subcommand | Purpose |
|---|---|
| `dmp contacts add <name> <x25519_hex> [--signing-key <ed25519_hex>]` | Pin a contact |
| `dmp contacts list` | Show pinned contacts; marks each pinned or UNPINNED |

Adding a contact **without** `--signing-key` prints a stderr warning
and leaves the client in TOFU mode for incoming messages. Prefer
`dmp identity fetch <user> --add`, which pins both keys automatically.

### `dmp send` / `dmp recv`

```
dmp send <recipient> <message>
dmp recv
```

`send` auto-selects a forward-secret path when the contact has a
pinned Ed25519 signing key and a live prekey pool; otherwise it
falls back to the recipient's long-term X25519 key.

`recv` polls every mailbox slot, verifies signatures, checks the
replay cache, fetches chunks, runs cross-chunk erasure decode, and
decrypts. Messages that pass all checks are printed; everything else
is silently dropped.

### `dmp resolvers`

Manage the upstream DNS resolver list the client uses to read chunks,
manifests, and identity records.

| Subcommand | Purpose |
|---|---|
| `dmp resolvers discover [--save] [--timeout S]` | Probe well-known public resolvers (Google, Cloudflare, Quad9, OpenDNS — 8 IPv4 hosts total) and print the working set |
| `dmp resolvers list` | Print the currently configured `dns_resolvers` |

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
the single `--dns-host` upstream, so `dmp send` / `dmp recv` benefit
automatically.

Example:

```
$ dmp resolvers discover
discovered 4 working resolver(s):
  1.1.1.1
  8.8.8.8
  9.9.9.9
  208.67.222.222

$ dmp resolvers discover --save
discovered 4 working resolver(s):
  1.1.1.1
  8.8.8.8
  9.9.9.9
  208.67.222.222
saved 4 resolvers to /home/alice/.dmp/config.yaml

$ dmp resolvers list
1.1.1.1
8.8.8.8
9.9.9.9
208.67.222.222
```

### `dmp node`

Convenience launcher for a foreground DMP node, reading config from
env vars.

```
dmp node [--db-path PATH] [--dns-port P] [--http-port P]
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
