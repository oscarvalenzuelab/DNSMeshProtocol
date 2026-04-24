# DigitalOcean quickstart

One-shot bootstrap for a single-node `dnsmesh-node` deployment on a
fresh DigitalOcean Droplet (or any apt-based VPS with a public IP).

## What it does

`quickstart.sh` runs as root on a fresh Ubuntu / Debian VPS and:

1. Installs Docker Engine + the Compose plugin if missing.
2. Opens `UDP 53`, `TCP 80`, `TCP/UDP 443` on `ufw` if active.
3. Lays down `/opt/dnsmesh/` with the production compose recipe and
   `Caddyfile` pulled from this repo.
4. Generates a strong operator bearer token if you didn't supply one.
5. Boots the stack and waits for `/health` to return ok.

Idempotency: the script refuses to clobber an existing `/opt/dnsmesh`.
Move it aside (or follow the upgrade path in
[docs/deployment/digitalocean.md](../../docs/deployment/digitalocean.md))
to re-run.

## Run it

```bash
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/digitalocean/quickstart.sh \
    | sudo DMP_NODE_HOSTNAME=dmp.example.com bash
```

Or interactive (the script prompts for the hostname):

```bash
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/digitalocean/quickstart.sh \
    | sudo bash
```

## Prerequisites

- A Droplet running Ubuntu 22.04 LTS or newer (24.04 also fine).
  Smallest sizing that works comfortably is the $6/mo `s-1vcpu-1gb`
  Basic Droplet. Anything bigger is overkill for a personal node.
- A DNS A (and ideally AAAA) record pointing at the Droplet's public
  IP. Caddy uses the HTTP-01 ACME challenge, which means the hostname
  has to resolve to this server *before* the script runs.
- Ports `UDP 53`, `TCP 80`, `TCP 443`, `UDP 443` open in your DO
  Cloud Firewall (if you have one) and on `ufw` (the script handles
  `ufw` automatically when active).

## Tunable env vars

| Var                    | Default                                           | What it does                                    |
|------------------------|---------------------------------------------------|-------------------------------------------------|
| `DMP_NODE_HOSTNAME`    | (prompted)                                        | FQDN that points at this Droplet.               |
| `DMP_OPERATOR_TOKEN`   | (auto-generated, 256-bit hex)                     | Bearer token gating `/v1/records/*` writes.     |
| `DNSMESH_REPO`         | `oscarvalenzuelab/DNSMeshProtocol`                | Source repo (override for forks).               |
| `DNSMESH_BRANCH`       | `main`                                            | Branch to fetch compose.yml + Caddyfile from.   |
| `DNSMESH_INSTALL_DIR`  | `/opt/dnsmesh`                                    | Where compose.yml + .env live.                  |

## After it finishes

The script prints the operator token and the hostname. Save the token.
It is the only secret gating writes to your node, and the script does
not store it in any persistent log.

To verify TLS came up, hit the health endpoint over HTTPS:

```bash
curl -sI https://$DMP_NODE_HOSTNAME/health
```

Then point a `dnsmesh` client at the node:

```bash
pip install dnsmesh
dnsmesh init alice --domain $DMP_NODE_HOSTNAME --endpoint https://$DMP_NODE_HOSTNAME
```

For production, follow the
[hardening guide](https://ovalenzuela.com/DNSMeshProtocol/deployment/hardening).

## Why not App Platform?

DigitalOcean App Platform does not support UDP, and `dnsmesh-node`
serves authoritative DNS over UDP 53. App Platform deployments will
appear to work but no client will ever resolve a record from them.

Use Droplets (or any UDP-capable host) for `dnsmesh-node`.

## Why not a Marketplace 1-Click?

Tracked as a future improvement once there's enough operator demand to
justify the per-release Packer-template maintenance + DigitalOcean
Marketplace review cycle. Until then, this script gets you to the same
end state in under a minute.
