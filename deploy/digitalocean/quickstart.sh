#!/usr/bin/env bash
# Bootstrap a single-node `dnsmesh-node` deployment on a fresh Ubuntu /
# Debian VPS. Targets DigitalOcean Droplets specifically (defaults match
# their stock images), but works on any apt-based VPS with a public IP.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/digitalocean/quickstart.sh \
#       | sudo DMP_NODE_HOSTNAME=dmp.example.com bash
#
# Or interactive:
#   curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/digitalocean/quickstart.sh \
#       | sudo bash
#
# What it does:
#   1. Verifies root, apt, and a public-routable address.
#   2. Installs Docker Engine + Compose plugin if missing.
#   3. Opens UDP 53, TCP 80, TCP/UDP 443 on `ufw` if active.
#   4. Lays down /opt/dnsmesh with the production compose.yml + Caddyfile
#      pulled from the upstream repo (pinned to the configured branch).
#   5. Generates a strong operator bearer token if you didn't supply one.
#   6. Boots the stack with `docker compose up -d` and waits for `/health`.
#
# Re-runnable. Refusing the script if /opt/dnsmesh already exists keeps it
# from clobbering your live config. To upgrade an existing install, follow
# the steps in docs/deployment/digitalocean.md instead.

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# Tunables (override via env)
# ──────────────────────────────────────────────────────────────────────

REPO="${DNSMESH_REPO:-oscarvalenzuelab/DNSMeshProtocol}"
BRANCH="${DNSMESH_BRANCH:-main}"
INSTALL_DIR="${DNSMESH_INSTALL_DIR:-/opt/dnsmesh}"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

# ──────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GREEN=$'\033[32m'
    YELLOW=$'\033[33m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
else
    BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi

step()  { printf "${CYAN}==>${RESET} ${BOLD}%s${RESET}\n" "$*"; }
ok()    { printf "${GREEN}    ✓${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}    !${RESET} %s\n" "$*" >&2; }
die()   { printf "${RED}error:${RESET} %s\n" "$*" >&2; exit 1; }

# ──────────────────────────────────────────────────────────────────────
# Sanity checks
# ──────────────────────────────────────────────────────────────────────

step "Sanity checks"

[[ $EUID -eq 0 ]] || die "this script needs root (run via sudo)"
command -v apt-get >/dev/null || die "apt-get not found; this script targets Ubuntu / Debian"
command -v curl >/dev/null    || die "curl not found; install it first: apt-get install -y curl"
ok "running as root on apt-based system"

if [[ -d "$INSTALL_DIR" ]]; then
    die "$INSTALL_DIR already exists. Refusing to clobber an existing install. \
Move it aside or follow the upgrade path in docs/deployment/digitalocean.md."
fi

# ──────────────────────────────────────────────────────────────────────
# Hostname (interactive if not preset)
# ──────────────────────────────────────────────────────────────────────

if [[ -z "${DMP_NODE_HOSTNAME:-}" ]]; then
    step "Hostname"
    printf "  Fully-qualified DNS name pointing at this Droplet's public IP\n"
    printf "  (e.g. dmp.example.com). The Caddy sidecar uses it to obtain\n"
    printf "  a Let's Encrypt cert via the HTTP-01 challenge.\n\n"
    printf "  ${BOLD}DMP_NODE_HOSTNAME:${RESET} "
    read -r DMP_NODE_HOSTNAME </dev/tty
fi

[[ -n "${DMP_NODE_HOSTNAME:-}" ]] || die "DMP_NODE_HOSTNAME is required"
[[ "$DMP_NODE_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] \
    || die "'$DMP_NODE_HOSTNAME' doesn't look like a hostname"
ok "hostname: $DMP_NODE_HOSTNAME"

# ──────────────────────────────────────────────────────────────────────
# Operator token (generate if not preset)
# ──────────────────────────────────────────────────────────────────────

if [[ -z "${DMP_OPERATOR_TOKEN:-}" ]]; then
    DMP_OPERATOR_TOKEN=$(openssl rand -hex 32 2>/dev/null \
        || head -c 32 /dev/urandom | xxd -p | tr -d '\n')
fi
[[ -n "$DMP_OPERATOR_TOKEN" ]] || die "could not generate an operator token"

# ──────────────────────────────────────────────────────────────────────
# Install Docker if missing
# ──────────────────────────────────────────────────────────────────────

if ! command -v docker >/dev/null; then
    step "Installing Docker Engine"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg lsb-release >/dev/null

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    . /etc/os-release
    DISTRO="${ID:-ubuntu}"
    CODENAME="${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null || echo jammy)}"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${DISTRO} ${CODENAME} stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq \
        docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin >/dev/null
    ok "docker $(docker --version | awk '{print $3}' | tr -d ',')"
else
    ok "docker already installed: $(docker --version | awk '{print $3}' | tr -d ',')"
fi

# Confirm compose plugin works (older docker-compose v1 binaries don't count)
if ! docker compose version >/dev/null 2>&1; then
    die "docker compose plugin missing. Install: apt-get install -y docker-compose-plugin"
fi

# ──────────────────────────────────────────────────────────────────────
# Firewall (best-effort; only adjusts ufw if it's active)
# ──────────────────────────────────────────────────────────────────────

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    step "Opening firewall ports (ufw active)"
    ufw allow 53/udp comment 'dnsmesh authoritative DNS' >/dev/null
    ufw allow 80/tcp comment 'ACME HTTP-01 challenge' >/dev/null
    ufw allow 443/tcp comment 'dnsmesh HTTPS publish API' >/dev/null
    ufw allow 443/udp comment 'dnsmesh HTTPS / HTTP-3' >/dev/null
    ok "ufw rules added"
else
    warn "ufw not active; skipping firewall config (verify your DO Droplet \
firewall allows UDP 53, TCP 80, TCP 443, UDP 443)"
fi

# ──────────────────────────────────────────────────────────────────────
# Lay down /opt/dnsmesh
# ──────────────────────────────────────────────────────────────────────

step "Provisioning $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

curl -fsSL "$RAW_BASE/deploy/docker/compose.yml" -o compose.yml
curl -fsSL "$RAW_BASE/Caddyfile" -o Caddyfile
ok "fetched compose.yml + Caddyfile from $REPO@$BRANCH"

cat > .env <<EOF
# Generated by deploy/digitalocean/quickstart.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Treat DMP_OPERATOR_TOKEN as a secret. Required by clients to publish.
DMP_NODE_HOSTNAME=${DMP_NODE_HOSTNAME}
DMP_OPERATOR_TOKEN=${DMP_OPERATOR_TOKEN}
DMP_HTTP_TOKEN=${DMP_OPERATOR_TOKEN}

# Heartbeat / discovery (M5.8). Off by default — uncomment + drop an
# operator key file alongside compose.yml to be discoverable in the
# federated directory: https://ovalenzuela.com/DNSMeshProtocol/directory/
#
# Key generation:
#   openssl rand -hex 32 | tee ${INSTALL_DIR}/operator-ed25519.hex >/dev/null
#   chmod 0440 ${INSTALL_DIR}/operator-ed25519.hex
# Then under the dnsmesh-node service in compose.yml, add to volumes:
#   - ./operator-ed25519.hex:/etc/dmp/operator-ed25519.hex:ro
#
#DMP_HEARTBEAT_ENABLED=1
#DMP_HEARTBEAT_SELF_ENDPOINT=https://${DMP_NODE_HOSTNAME}
#DMP_HEARTBEAT_OPERATOR_KEY_PATH=/etc/dmp/operator-ed25519.hex

# Bootstrap seeds. dnsmesh.io is the canonical bootstrap so a fresh
# node sees the federation on its first heartbeat tick. Comma-separated.
DMP_HEARTBEAT_SEEDS=https://dnsmesh.io
EOF
chmod 600 .env
ok "wrote .env (mode 0600)"

# ──────────────────────────────────────────────────────────────────────
# Boot the stack
# ──────────────────────────────────────────────────────────────────────

step "Starting dnsmesh-node + caddy"
docker compose --env-file "$INSTALL_DIR/.env" \
    -f "$INSTALL_DIR/compose.yml" pull --quiet
docker compose --env-file "$INSTALL_DIR/.env" \
    -f "$INSTALL_DIR/compose.yml" up -d

# Wait for /health on the in-container port (mapped or via the caddy sidecar).
# The compose recipe doesn't expose 8053 to the host (caddy fronts it),
# so probe the container directly via `docker exec`.
HEALTH_OK=0
for _ in $(seq 1 30); do
    if docker compose -f "$INSTALL_DIR/compose.yml" \
            exec -T dnsmesh-node sh -c \
            "wget -qO- http://127.0.0.1:8053/health 2>/dev/null \
                || curl -fsS http://127.0.0.1:8053/health 2>/dev/null" \
            | grep -q '"status": *"ok"'; then
        HEALTH_OK=1; break
    fi
    sleep 2
done
[[ "$HEALTH_OK" -eq 1 ]] || warn "health check didn't return ok; check 'docker compose logs'"

# ──────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────

cat <<EOF

${GREEN}${BOLD}dnsmesh-node is up.${RESET}

${BOLD}Hostname:${RESET}        $DMP_NODE_HOSTNAME
${BOLD}Operator token:${RESET}  $DMP_OPERATOR_TOKEN
${BOLD}Install dir:${RESET}     $INSTALL_DIR
${BOLD}Health:${RESET}          $([[ $HEALTH_OK -eq 1 ]] && echo "${GREEN}ok${RESET}" || echo "${YELLOW}pending${RESET}")

${DIM}The token is the only thing gating publish writes. Save it somewhere safe;
operators hand it to users (or use it themselves to register).${RESET}

${BOLD}Next steps:${RESET}
  ${DIM}# Verify TLS cert is issued (Caddy obtains it on first request to 443):${RESET}
  curl -sI https://$DMP_NODE_HOSTNAME/health

  ${DIM}# From a client machine (with the dnsmesh CLI installed):${RESET}
  pip install dnsmesh
  dnsmesh init alice --domain $DMP_NODE_HOSTNAME --endpoint https://$DMP_NODE_HOSTNAME

  ${DIM}# Operator hardening checklist (TLS, token hygiene, DNS hygiene):${RESET}
  https://ovalenzuela.com/DNSMeshProtocol/deployment/hardening
EOF
