---
title: Native Ubuntu (no Docker)
layout: default
parent: Deployment
nav_order: 3
---

# Native Ubuntu install
{: .no_toc }

1. TOC
{:toc}

Install `dnsmesh-node` directly on Ubuntu / Debian as a systemd unit,
fronted by Caddy for auto-TLS. No Docker daemon required.

This is an alternative to the Docker recipe at
[Deployment → Docker]({{ site.baseurl }}/deployment/docker), aimed at
operators who don't want a container runtime on the host. The Docker
path stays canonical for cluster deploys; native is a single-node
choice.

{: .note }
Both paths are first-class. Pick the one whose ergonomics match how
you operate the rest of your infrastructure. Trade-offs are
summarized at the end of this page.

## When to pick native

- **Tiny VMs.** Docker daemon idles around ~150 MB; the native path
  runs in ~50 MB. On a `s-1vcpu-512mb` or `s-1vcpu-1gb` Droplet that
  difference matters.
- **Distro-native operations.** systemd lifecycle, journald logs,
  apt-pinned Caddy.
- **No container runtime.** Some hardened hosts disallow the kernel
  features Docker needs.

When to pick Docker instead:

- **Cluster deploys.** `docker-compose.cluster.yml` is the path of
  least resistance for a 3-node federated setup.
- **Reproducibility.** Pinning `:X.Y.Z` tags is more rigorous than
  pinning a `pip install dnsmesh==X.Y.Z` against a moving distro
  Python.

## What you'll end up with

- A `dnsmesh` system user with no login shell.
- The package installed in a venv at `/opt/dnsmesh/venv`.
- A systemd unit `dnsmesh-node.service` running as the `dnsmesh` user
  with `CAP_NET_BIND_SERVICE` (the only capability it needs, to bind
  UDP 53).
- Caddy fronting the HTTP API on TCP 443 with auto Let's Encrypt.
- Persistent state at `/var/lib/dmp/dmp.db`.
- ufw rules for `UDP 53`, `TCP 80`, `TCP 443`, `UDP 443` (when ufw is
  active).

## Prerequisites

1. **Ubuntu 22.04 LTS or newer / Debian 12 or newer.**
2. **A DNS A (and ideally AAAA) record** pointing at the machine's
   public IP. Caddy uses the HTTP-01 ACME challenge, so the hostname
   has to resolve here *before* the script runs.
3. **Open inbound:** `UDP 53`, `TCP 80`, `TCP 443`, `UDP 443`. The
   script handles `ufw` automatically; cloud-firewall layers
   (DigitalOcean Cloud Firewall, AWS Security Group, etc.) you set
   yourself.

## Run the install

SSH into the machine as root (or a sudoer):

```bash
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/native-ubuntu/install.sh \
    | sudo DMP_NODE_HOSTNAME=dmp.example.com bash
```

What it does, in order:

1. Sanity checks (root, apt, no prior install at the standard paths).
2. Installs `python3`, `python3-venv`, `caddy` (from the upstream apt
   repo for fresh versions on LTS), `ufw`, `openssl`.
3. Creates the `dnsmesh` system user and the directory layout.
4. `pip install dnsmesh` into `/opt/dnsmesh/venv`.
5. Generates a 256-bit operator bearer token (or reuses
   `DMP_OPERATOR_TOKEN` if you set it).
6. Writes `/etc/dnsmesh/node.env` (mode 0640, root:dnsmesh).
7. Drops the systemd unit, runs `daemon-reload`.
8. Configures `/etc/caddy/Caddyfile` with the hostname.
9. Opens the four required ports on `ufw` if active.
10. `systemctl enable --now dnsmesh-node` and reloads Caddy.
11. Waits up to 30 seconds for `/health` to return ok.

The token is the only secret gating publish writes. It's written to
`/etc/dnsmesh/node.env` (mode 0640) and printed once; save it.

## Verify

From any machine:

```bash
curl -sI https://dmp.example.com/health
# HTTP/2 200
```

Caddy obtains the TLS cert on first request to port 443, so the very
first call may take a few seconds. Subsequent calls are immediate.

To prove DNS works:

```bash
dig @dmp.example.com test-resolution.invalid TXT +short
# (empty response, but no SERVFAIL)
```

## Operating it

### Service control

```bash
sudo systemctl status dnsmesh-node
sudo systemctl restart dnsmesh-node
journalctl -u dnsmesh-node -f
```

The startup log includes the discovery surface (whether the
heartbeat layer is on, and where peers can see this node):

```
INFO dmp.server.node: DMP node up: dns=0.0.0.0:53/udp http=127.0.0.1:8053 db=/var/lib/dmp/dmp.db peers=0
INFO dmp.server.node: discovery: heartbeat disabled (this node is private). Set DMP_HEARTBEAT_ENABLED=1 + ...
```

### Upgrade

```bash
sudo /opt/dnsmesh/venv/bin/pip install -U dnsmesh
sudo systemctl restart dnsmesh-node
```

Persistent state survives the upgrade; only the venv contents change.
Pin a specific version with `dnsmesh==X.Y.Z`.

### Token rotation

```bash
sudo nano /etc/dnsmesh/node.env   # replace DMP_OPERATOR_TOKEN
sudo systemctl restart dnsmesh-node
```

Existing client-side credentials need to be re-minted:

- **M9 default (TSIG):** the per-user TSIG key sits in the
  `tsig_*` block of `~/.dmp/config.yaml`. Re-mint with
  `dnsmesh tsig register --node <host>` — the new key replaces
  the in-config block atomically.
- **Legacy HTTP-token path:** the bearer token sits at
  `~/.dmp/tokens/<host>.json`. Re-issue with
  `dnsmesh register --node <host>` or have the operator hand out
  a fresh token via `dnsmesh-node-admin token rotate`.

### Enabling multi-tenant auth

Add to `/etc/dnsmesh/node.env`:

```
DMP_AUTH_MODE=multi-tenant
DMP_REGISTRATION_ENABLED=1
```

Restart. See [Multi-tenant deployment]({{ site.baseurl }}/deployment/multi-tenant)
for the full operator surface.

### Enabling discovery

```
DMP_HEARTBEAT_ENABLED=1
DMP_HEARTBEAT_SELF_ENDPOINT=https://dmp.example.com
DMP_HEARTBEAT_OPERATOR_KEY_PATH=/etc/dnsmesh/operator-ed25519.hex
```

Generate the operator key (32 random bytes hex, mode 0440 root:dnsmesh):

```bash
openssl rand -hex 32 | sudo tee /etc/dnsmesh/operator-ed25519.hex >/dev/null
sudo chown root:dnsmesh /etc/dnsmesh/operator-ed25519.hex
sudo chmod 0440 /etc/dnsmesh/operator-ed25519.hex
sudo systemctl restart dnsmesh-node
```

Once on, your node publishes its signed heartbeat at the DNS owner
name `_dnsmesh-heartbeat.<DMP_DOMAIN>` and republishes the harvested
seen-graph at `_dnsmesh-seen.<DMP_DOMAIN>` — both queryable via the
public DNS chain. The node's HTML landing page at `/` includes a
"Recent peers" table rendered from the seen-store. (The legacy
M5.8 HTTP routes `/v1/nodes/seen` and `/v1/heartbeat` were removed
in M9.)

## Sandboxing

The systemd unit applies the standard hardening directives a normal
unprivileged process doesn't need to bypass: `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`,
`RestrictAddressFamilies`, `LockPersonality`, `RestrictRealtime`,
`RestrictSUIDSGID`, `MemoryDenyWriteExecute`.

`ReadWritePaths=/var/lib/dmp` is the only writable path on disk.

The single capability the service holds is `CAP_NET_BIND_SERVICE`,
needed to bind UDP 53. Everything else runs as the unprivileged
`dnsmesh` user.

## Uninstall

```bash
sudo systemctl disable --now dnsmesh-node
sudo rm /etc/systemd/system/dnsmesh-node.service
sudo systemctl daemon-reload
sudo rm -rf /opt/dnsmesh /etc/dnsmesh
# Optionally also: sudo rm -rf /var/lib/dmp
sudo userdel dnsmesh
```

## Troubleshooting

**TLS cert never issues.** Either DNS isn't pointing at this host,
or `TCP 80` is blocked at the cloud-firewall layer (Caddy's HTTP-01
challenge happens on port 80, even when the cert serves 443). Run
`dig +short dmp.example.com` from outside and check it resolves to
this machine's public IP. Then `journalctl -u caddy` for the
acme-issuer logs.

**`systemctl status dnsmesh-node` shows the unit failed to bind UDP
53.** The `AmbientCapabilities=CAP_NET_BIND_SERVICE` line in the
unit handles this on systemd ≥ 229 (anything LTS-supported). If it
still fails, check that the kernel hasn't disabled ambient
capabilities, or fall back to running on a non-privileged port and
using iptables to redirect 53.

**`/health` returns 502 from Caddy.** dnsmesh-node isn't listening
on `127.0.0.1:8053`. `sudo systemctl status dnsmesh-node` and
`journalctl -u dnsmesh-node` will say why.

**`pip install dnsmesh` fails on a fresh Droplet.** The cryptography
+ argon2-cffi wheels usually ship for amd64 / arm64 + the major
glibc lines. If your distro ships a too-new openssl that breaks the
wheel, install `build-essential libssl-dev libffi-dev` and retry.
