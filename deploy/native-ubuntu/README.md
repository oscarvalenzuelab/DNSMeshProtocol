# Native Ubuntu install (no Docker)

Bare-metal install for `dnsmesh-node`. Runs as a systemd unit under a
dedicated `dnsmesh` user, fronted by Caddy for auto Let's Encrypt TLS.
Targets Ubuntu / Debian.

Use this when you don't want a Docker daemon on the host, when the
$5/mo Droplet RAM headroom matters, or when you want native systemd
lifecycle and journald log integration.

## What it lays down

| Path                                              | Purpose                                       |
|---------------------------------------------------|-----------------------------------------------|
| `/opt/dnsmesh/venv/`                              | Python venv with the `dnsmesh` package.       |
| `/etc/dnsmesh/node.env`                           | Operator config + bearer token (mode 0640).   |
| `/etc/systemd/system/dnsmesh-node.service`        | Systemd unit with sandboxing directives.      |
| `/etc/caddy/Caddyfile`                            | Caddy reverse-proxy + auto-TLS for 443.       |
| `/var/lib/dmp/`                                   | Persistent state (sqlite store).              |
| `dnsmesh` user + group                            | Service identity. No login shell, no home.    |

## Run it

```bash
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/native-ubuntu/install.sh \
    | sudo DMP_NODE_HOSTNAME=dmp.example.com bash
```

Or interactive (the script prompts for the hostname):

```bash
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/native-ubuntu/install.sh \
    | sudo bash
```

Idempotency: the script refuses to clobber an existing install.
`/opt/dnsmesh`, `/etc/dnsmesh`, the systemd unit, and any existing
`/var/lib/dmp/dmp.db` all trip the early-abort check.

## Prerequisites

- Ubuntu 22.04 LTS (or newer) / Debian 12 (or newer). Other apt-based
  distros work but aren't tested in CI.
- A DNS A (and ideally AAAA) record pointing at the machine's public
  IP. Caddy uses the HTTP-01 ACME challenge, which means the hostname
  has to resolve here *before* the script runs.
- Open inbound: `UDP 53`, `TCP 80`, `TCP 443`, `UDP 443`. The script
  configures `ufw` automatically when active. If you have a separate
  cloud-firewall layer (DigitalOcean Cloud Firewall, AWS Security
  Group, etc.), you have to open those ports there yourself.

## Tunables (env vars)

| Var                    | Default                                | What it does                                |
|------------------------|----------------------------------------|---------------------------------------------|
| `DMP_NODE_HOSTNAME`    | (prompted)                             | FQDN that points at this machine.           |
| `DMP_OPERATOR_TOKEN`   | (auto-generated, 256-bit hex)          | Bearer token gating `/v1/records/*`.        |
| `DNSMESH_USER`         | `dnsmesh`                              | System user the service runs as.            |
| `DNSMESH_INSTALL_DIR`  | `/opt/dnsmesh`                         | Where the venv lives.                       |
| `DNSMESH_ETC_DIR`      | `/etc/dnsmesh`                         | Where node.env lives.                       |
| `DNSMESH_DATA_DIR`     | `/var/lib/dmp`                         | sqlite store.                               |
| `DNSMESH_REPO`         | `oscarvalenzuelab/DNSMeshProtocol`     | Source repo (override for forks).           |
| `DNSMESH_BRANCH`       | `main`                                 | Branch to fetch the systemd unit from.      |

## Operating it

### Service control

```bash
sudo systemctl status dnsmesh-node
sudo systemctl restart dnsmesh-node
sudo systemctl stop dnsmesh-node
journalctl -u dnsmesh-node -f
```

### Upgrade

```bash
sudo /opt/dnsmesh/venv/bin/pip install -U dnsmesh
sudo systemctl restart dnsmesh-node
```

The state in `/var/lib/dmp/dmp.db` survives upgrades; only the venv
contents change.

### Token rotation

Edit `/etc/dnsmesh/node.env`, replace the `DMP_OPERATOR_TOKEN` line,
restart:

```bash
sudo nano /etc/dnsmesh/node.env
sudo systemctl restart dnsmesh-node
```

The new token applies on next request. Existing client tokens stored
under `~/.dmp/tokens/<host>.json` need to be re-issued (run
`dnsmesh register --node <host>` again from the client side).

### Multi-tenant / heartbeat / cluster

These features are env-driven on top of the same install. Add the
relevant `DMP_*` vars to `/etc/dnsmesh/node.env` and restart:

- Multi-tenant auth: see
  [docs/deployment/multi-tenant.md](../../docs/deployment/multi-tenant.md).
  Key vars: `DMP_AUTH_MODE=multi-tenant`, `DMP_REGISTRATION_ENABLED=1`.
- Heartbeat / discovery: see
  [docs/deployment/heartbeat.md](../../docs/deployment/heartbeat.md).
  Key vars: `DMP_HEARTBEAT_ENABLED=1`,
  `DMP_HEARTBEAT_SELF_ENDPOINT=https://...`,
  `DMP_HEARTBEAT_OPERATOR_KEY_PATH=/etc/dnsmesh/operator.hex`.
- Cluster / anti-entropy: see
  [docs/deployment/cluster.md](../../docs/deployment/cluster.md).

## Sandboxing

The systemd unit applies the standard hardening directives that an
unprivileged process should not need to bypass: `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome`, `ProtectKernelTunables`,
`ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`,
`RestrictAddressFamilies`, `LockPersonality`, `RestrictRealtime`,
`RestrictSUIDSGID`, `MemoryDenyWriteExecute`, plus a tight
`ReadWritePaths=/var/lib/dmp` so the only writable path on disk is
the sqlite store.

The single capability the service holds is `CAP_NET_BIND_SERVICE`
(needed to bind UDP 53). Everything else runs as the unprivileged
`dnsmesh` user.

If you ever extend the server to write somewhere new, edit the
unit's `ReadWritePaths=` line. Hardening removed under duress
should be re-added once the underlying issue is fixed.

## Uninstall

```bash
sudo systemctl disable --now dnsmesh-node
sudo rm /etc/systemd/system/dnsmesh-node.service
sudo systemctl daemon-reload
sudo rm -rf /opt/dnsmesh /etc/dnsmesh
# Keep /var/lib/dmp if you want to preserve the sqlite store; rm -rf
# it if you're starting clean.
sudo userdel dnsmesh
```

Leave Caddy installed if anything else uses it; otherwise
`sudo apt-get remove caddy`.

## Native vs Docker — which to pick

| Concern                          | Native systemd               | Docker                           |
|----------------------------------|------------------------------|----------------------------------|
| RAM idle                         | ~50 MB                       | ~150 MB (daemon + container)     |
| Upgrade ergonomics               | `pip install -U`             | `docker pull && compose up -d`   |
| Reproducibility / pinning        | `dnsmesh==X.Y.Z` in pip      | `:X.Y.Z` image tag               |
| Sandbox surface                  | systemd directives           | Docker namespaces (broader)      |
| Distro-version drift risk        | Yes (Python ABI)             | No                               |
| Cluster-of-N convenience         | One unit per host            | `docker-compose.cluster.yml`     |

Single-node small deploys lean native. Cluster / multi-node setups
lean Docker. Both are first-class — pick the one whose ergonomics
match how you operate the rest of your infra.
