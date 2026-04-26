---
title: DigitalOcean
layout: default
parent: Deployment
nav_order: 2
---

# DigitalOcean
{: .no_toc }

1. TOC
{:toc}

The fastest way to put a `dnsmesh-node` on the public internet. This
guide walks through a single-node production deploy on a Droplet using
the bundled quickstart script.

The same script works on any apt-based VPS with a public IP (Hetzner,
Linode/Akamai, AWS Lightsail, bare metal). DigitalOcean is highlighted
because the defaults match their stock Ubuntu images.

{: .warning }
**App Platform does not work.** It cannot expose UDP, and `dnsmesh-node`
serves authoritative DNS over UDP 53. Use a Droplet.

## What you'll end up with

- One Droplet running:
  - `dnsmesh-node` listening on UDP 53 (DMP DNS) and internal TCP 8053 (HTTP API)
  - `caddy` fronting the HTTP API on TCP 443 with auto Let's Encrypt
- A bearer token gating publish writes
- A health endpoint reachable at `https://<your-host>/health`

Cost: about $6/month on the smallest Basic Droplet (`s-1vcpu-1gb`).
Plenty for a personal or small-group node.

## Prerequisites

You need three things before you start:

1. **A Droplet running Ubuntu 22.04 LTS or newer.** 24.04 also fine.
   The smallest Basic Droplet (`s-1vcpu-1gb`, $6/mo) is enough for a
   personal node.
2. **A DNS A record (and ideally AAAA) pointing at the Droplet's
   public IP.** Caddy uses the ACME HTTP-01 challenge, so the
   hostname has to resolve correctly *before* the script runs. If
   you're using DigitalOcean's DNS, set this up under
   `Networking → Domains` first.
3. **Open ports `UDP 53`, `TCP 80`, `TCP 443`, `UDP 443`** on any
   DigitalOcean Cloud Firewall protecting the Droplet. The script
   handles `ufw` automatically; the cloud-firewall layer is separate
   and only you can change it.

## Run the quickstart

SSH into the Droplet as root (or a sudoer) and run:

```bash
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/digitalocean/quickstart.sh \
    | sudo DMP_NODE_HOSTNAME=dmp.example.com bash
```

What happens, in order:

1. Sanity-checks root, apt, and that `/opt/dnsmesh` doesn't already exist.
2. Installs Docker Engine and the Compose plugin if missing.
3. Opens the four required ports on `ufw` if active.
4. Pulls `compose.yml` and `Caddyfile` from this repo into `/opt/dnsmesh/`.
5. Generates a 256-bit operator bearer token (or reuses
   `DMP_OPERATOR_TOKEN` if you set it).
6. Boots the stack with `docker compose up -d`.
7. Waits up to a minute for `/health` to return ok, then prints the
   token and next-step commands.

The token is the only secret gating publish writes to your node. The
script writes it to `/opt/dnsmesh/.env` (mode 0600) and prints it once;
save it somewhere safe.

## Verify it works

From any machine, hit the public health endpoint:

```bash
curl -sI https://dmp.example.com/health
# HTTP/2 200
# content-type: application/json
```

Caddy obtains the TLS cert on first request to `:443`, so the very
first call may take a few seconds while it talks to Let's Encrypt.
Subsequent calls are immediate.

To prove the DNS plane is reachable, query a non-existent name from
any machine that can hit UDP 53:

```bash
dig @dmp.example.com test-resolution-only.invalid TXT +short
# (empty response, but no SERVFAIL)
```

## Use it from a client

Install the CLI and point it at the node:

```bash
pip install dnsmesh
dnsmesh init alice --domain dmp.example.com --endpoint dmp.example.com
dnsmesh identity show
```

The CLI auto-prepends `https://` to bare hostnames. Pass a full
`http://host:port` URL when pointing at a local-dev node.

If multi-tenant auth is enabled (recommended for any node serving
people you don't personally run), users register once to mint a
per-user TSIG key. After that, every record write goes over RFC 2136
DNS UPDATE under that key — no more HTTPS to the node:

```bash
dnsmesh tsig register --node dmp.example.com
dnsmesh identity publish
```

See [Multi-tenant deployment]({{ site.baseurl }}/deployment/multi-tenant)
for how to enable registration on the node side. The legacy
HTTP-token flow (`dnsmesh register`) still works for back-compat
but new deployments should use TSIG — see
[Getting Started]({{ site.baseurl }}/getting-started) for the
canonical flow.

## Production hardening

The quickstart gets you to a working node. Before pointing real
identities at it, walk the
[hardening guide]({{ site.baseurl }}/deployment/hardening). It
covers TLS posture, token rotation, operator signing-key handling,
DNS zone hygiene, file permissions, and network exposure. Missing an
item there is the most common way a DMP node gets owned.

## Backups

`/opt/dnsmesh/` contains everything the node needs to boot:
- `.env` (the operator token; treat as a secret)
- `compose.yml` + `Caddyfile` (regeneratable from the repo, but
  pinning your known-good copy is wise)

The actual record state lives in a Docker volume named `dnsmesh-data`.
For a single-node deploy, enable
[DigitalOcean's automated Droplet backups](https://docs.digitalocean.com/products/droplets/how-to/back-up/)
(weekly, +20% cost). For something more aggressive, snapshot
`dnsmesh-data` to Spaces:

```bash
docker run --rm -v dnsmesh-data:/data:ro -v "$(pwd):/out" alpine \
    tar czf /out/dnsmesh-data-$(date +%F).tar.gz -C /data .
```

## Upgrading

The quickstart refuses to overwrite an existing `/opt/dnsmesh`. To
upgrade in place:

```bash
cd /opt/dnsmesh
docker compose pull
docker compose up -d
```

That picks up the latest `ovalenzuela/dnsmesh-node:latest` (which
auto-updates on every push to `main`) without touching your token or
state.

For a reproducible deploy, pin a specific version in `compose.yml`:

```yaml
image: ovalenzuela/dnsmesh-node:0.2.0
```

Then `docker compose up -d` only ever pulls that version.

## When to graduate to a cluster

A single Droplet is fine for personal and small-team use. When you
want survival across individual node failure (e.g., the Droplet is
deleted, the region has an outage), step up to a 3-node federated
cluster. See [Clustered deployment]({{ site.baseurl }}/deployment/cluster).

## Troubleshooting

**`/health` returns 502 from Caddy.** The dnsmesh-node container
isn't healthy yet. Check `docker compose -f /opt/dnsmesh/compose.yml logs dnsmesh-node`.

**Cert never issues.** Either DNS isn't pointing at the Droplet, or
TCP 80 is blocked at the cloud-firewall layer (Caddy's HTTP-01
challenge happens on port 80, even when the final cert serves 443).
Run `dig +short dmp.example.com` from outside and confirm it returns
your Droplet's public IP, then check the DigitalOcean Cloud Firewall
config.

**`dnsmesh init` succeeds but `identity publish` returns 401 / REFUSED.**
The CLI's TSIG key (or legacy bearer token) doesn't match what the
node expects. Re-mint:

- **M9 default:** `dnsmesh tsig register --node <hostname>` to get a
  fresh TSIG key. Then `identity publish` again.
- **Legacy multi-tenant token mode:** `dnsmesh register --node <hostname>`
  if the operator runs `DMP_AUTH_MODE=multi-tenant` without TSIG, or
  copy `DMP_OPERATOR_TOKEN` from `/opt/dnsmesh/.env` manually for a
  single-user laptop deploy.

**UDP 53 is closed.** Either `ufw` is rejecting it or the DigitalOcean
Cloud Firewall is. `ufw status` should show `53/udp ALLOW`. If you
have a Cloud Firewall, add an inbound rule allowing UDP 53 from
`0.0.0.0/0` (or the world).
