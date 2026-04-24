#!/usr/bin/env bash
# Install dnsmesh-node directly on Ubuntu / Debian (no Docker). The
# DMP server runs as a systemd unit under a dedicated `dnsmesh` user,
# fronted by Caddy for auto Let's Encrypt TLS.
#
# Use this when:
#   - You don't want a Docker daemon on the host.
#   - You're running on a small Droplet ($5/mo tier) where the Docker
#     overhead matters.
#   - You want native systemd lifecycle / journald log integration.
#
# Use the Docker recipe instead when you'd rather treat the node as
# an opaque image you can pull-and-replace, or when you want the
# strict-sandbox guarantees Docker gives for free.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/native-ubuntu/install.sh \
#       | sudo DMP_NODE_HOSTNAME=dmp.example.com bash
#
# Or interactive:
#   curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/native-ubuntu/install.sh \
#       | sudo bash
#
# Re-runnable: refuses to clobber an existing install so you don't
# accidentally wipe an operator token. Upgrade via:
#   sudo /opt/dnsmesh/venv/bin/pip install -U dnsmesh
#   sudo systemctl restart dnsmesh-node

set -euo pipefail

# ──────────────────────────────────────────────────────────────────────
# Tunables
# ──────────────────────────────────────────────────────────────────────

DNSMESH_USER="${DNSMESH_USER:-dnsmesh}"
INSTALL_DIR="${DNSMESH_INSTALL_DIR:-/opt/dnsmesh}"
VENV_DIR="${INSTALL_DIR}/venv"
ETC_DIR="${DNSMESH_ETC_DIR:-/etc/dnsmesh}"
DATA_DIR="${DNSMESH_DATA_DIR:-/var/lib/dmp}"
SERVICE_NAME="dnsmesh-node"
REPO="${DNSMESH_REPO:-oscarvalenzuelab/DNSMeshProtocol}"
BRANCH="${DNSMESH_BRANCH:-main}"
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
[[ -d "$INSTALL_DIR" ]]                                  && die "$INSTALL_DIR already exists. Refusing to clobber."
[[ -d "$ETC_DIR" ]]                                      && die "$ETC_DIR already exists. Refusing to clobber."
[[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]   && die "${SERVICE_NAME}.service already installed. Refusing to clobber."
[[ -f "${DATA_DIR}/dmp.db" ]]                            && die "${DATA_DIR}/dmp.db already exists. Move it aside first."
ok "running as root on apt-based system"
ok "no prior install detected"

# ──────────────────────────────────────────────────────────────────────
# Hostname (interactive if not preset)
# ──────────────────────────────────────────────────────────────────────

if [[ -z "${DMP_NODE_HOSTNAME:-}" ]]; then
    step "Hostname"
    printf "  Fully-qualified DNS name pointing at this machine's public IP\n"
    printf "  (e.g. dmp.example.com). Caddy uses the HTTP-01 ACME challenge,\n"
    printf "  so the hostname has to resolve here BEFORE this script runs.\n\n"
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
# apt: Python 3.10+, build deps, Caddy, ufw
# ──────────────────────────────────────────────────────────────────────

step "Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

# Python: rely on the distro python3 (Ubuntu 22.04 → 3.10, 24.04 → 3.12).
# Cryptography wheels ship for amd64+arm64, so build-essential is only
# a fallback for exotic arches. Including it cheaply unblocks weird
# Droplet variants without bloating amd64/arm64 installs much.
apt-get install -y -qq \
    python3 python3-venv python3-pip \
    ca-certificates curl gnupg lsb-release \
    ufw openssl >/dev/null
ok "python $(python3 --version | awk '{print $2}')"

# Caddy: official upstream apt repo (the Ubuntu repo's `caddy` is years
# stale on LTS releases).
if ! command -v caddy >/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/caddy.gpg
    chmod a+r /etc/apt/keyrings/caddy.gpg
    echo "deb [signed-by=/etc/apt/keyrings/caddy.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy >/dev/null
    ok "caddy $(caddy version | awk '{print $1}')"
else
    ok "caddy already installed: $(caddy version | awk '{print $1}')"
fi

# ──────────────────────────────────────────────────────────────────────
# System user + directories
# ──────────────────────────────────────────────────────────────────────

step "Provisioning system user + directories"

if ! id "$DNSMESH_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --home-dir "$DATA_DIR" "$DNSMESH_USER"
    ok "created user $DNSMESH_USER"
else
    ok "user $DNSMESH_USER already exists"
fi

mkdir -p "$INSTALL_DIR" "$ETC_DIR" "$DATA_DIR"
chown "$DNSMESH_USER:$DNSMESH_USER" "$DATA_DIR"
chmod 0750 "$DATA_DIR"
ok "directories: $INSTALL_DIR, $ETC_DIR, $DATA_DIR"

# ──────────────────────────────────────────────────────────────────────
# Python venv + dnsmesh package
# ──────────────────────────────────────────────────────────────────────

step "Installing dnsmesh into $VENV_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet dnsmesh
INSTALLED_VERSION=$("$VENV_DIR/bin/pip" show dnsmesh | awk '/^Version:/ {print $2}')
ok "dnsmesh ${INSTALLED_VERSION} installed"

# Lock down the venv tree so the dnsmesh user can read but not write
# (immutable runtime; upgrades go through `sudo pip install -U`).
chown -R root:root "$INSTALL_DIR"
chmod -R go+rX "$INSTALL_DIR"

# ──────────────────────────────────────────────────────────────────────
# Operator config
# ──────────────────────────────────────────────────────────────────────

step "Writing $ETC_DIR/node.env"
cat > "$ETC_DIR/node.env" <<EOF
# Generated by deploy/native-ubuntu/install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Treat DMP_OPERATOR_TOKEN as a secret. Required by clients to publish.

# DNS plane: bind to UDP 53 on the public interface (the systemd unit
# grants CAP_NET_BIND_SERVICE so this is allowed without running the
# process as root).
DMP_DNS_HOST=0.0.0.0
DMP_DNS_PORT=53

# HTTP plane: bind only to localhost — Caddy fronts it on 443 with TLS.
DMP_HTTP_HOST=127.0.0.1
DMP_HTTP_PORT=8053

# Persistent state. Owned by the dnsmesh user (see ReadWritePaths in
# the systemd unit).
DMP_DB_PATH=${DATA_DIR}/dmp.db

# Operator bearer token gating /v1/records/*. The two names are
# aliases — DMP_OPERATOR_TOKEN is the M5.5 preferred spelling and
# DMP_HTTP_TOKEN is kept for back-compat.
DMP_OPERATOR_TOKEN=${DMP_OPERATOR_TOKEN}
DMP_HTTP_TOKEN=${DMP_OPERATOR_TOKEN}

DMP_LOG_LEVEL=INFO
DMP_LOG_FORMAT=text
EOF
chown root:"$DNSMESH_USER" "$ETC_DIR/node.env"
chmod 0640 "$ETC_DIR/node.env"
ok "wrote $ETC_DIR/node.env (mode 0640, root:$DNSMESH_USER)"

# ──────────────────────────────────────────────────────────────────────
# Systemd unit
# ──────────────────────────────────────────────────────────────────────

step "Installing systemd unit"
curl -fsSL "$RAW_BASE/deploy/native-ubuntu/dnsmesh-node.service" \
    -o "/etc/systemd/system/${SERVICE_NAME}.service"
chmod 0644 "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload
ok "/etc/systemd/system/${SERVICE_NAME}.service installed"

# ──────────────────────────────────────────────────────────────────────
# Caddy: front the HTTP plane with auto-TLS
# ──────────────────────────────────────────────────────────────────────

step "Configuring Caddy"

CADDYFILE="/etc/caddy/Caddyfile"
if [[ -f "$CADDYFILE" ]] && grep -q "reverse_proxy" "$CADDYFILE" 2>/dev/null; then
    cp "$CADDYFILE" "${CADDYFILE}.pre-dnsmesh"
    warn "existing Caddyfile backed up to ${CADDYFILE}.pre-dnsmesh"
fi

cat > "$CADDYFILE" <<EOF
# Managed by deploy/native-ubuntu/install.sh. Edits will not be
# overwritten on upgrade (the upgrade path is documented in
# deploy/native-ubuntu/README.md).

${DMP_NODE_HOSTNAME} {
    encode gzip zstd

    reverse_proxy 127.0.0.1:8053 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
    }

    log {
        output stdout
        format json
    }
}
EOF
ok "$CADDYFILE configured for $DMP_NODE_HOSTNAME"

# ──────────────────────────────────────────────────────────────────────
# Firewall (best-effort; only if ufw active)
# ──────────────────────────────────────────────────────────────────────

if ufw status | grep -q "Status: active"; then
    step "Opening firewall ports (ufw active)"
    ufw allow 53/udp comment 'dnsmesh authoritative DNS' >/dev/null
    ufw allow 80/tcp comment 'ACME HTTP-01 challenge' >/dev/null
    ufw allow 443/tcp comment 'dnsmesh HTTPS publish API' >/dev/null
    ufw allow 443/udp comment 'dnsmesh HTTPS / HTTP-3' >/dev/null
    ok "ufw rules added"
else
    warn "ufw not active; skipping firewall config (verify your DigitalOcean \
Cloud Firewall allows UDP 53, TCP 80, TCP 443, UDP 443)"
fi

# ──────────────────────────────────────────────────────────────────────
# Boot
# ──────────────────────────────────────────────────────────────────────

step "Starting services"
systemctl enable --now "$SERVICE_NAME" >/dev/null
systemctl reload-or-restart caddy

# Wait for the dmp HTTP plane on 127.0.0.1.
HEALTH_OK=0
for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8053/health 2>/dev/null | grep -q '"status": *"ok"'; then
        HEALTH_OK=1; break
    fi
    sleep 1
done
[[ "$HEALTH_OK" -eq 1 ]] || warn "health check didn't return ok; check 'journalctl -u dnsmesh-node'"

# ──────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────

cat <<EOF

${GREEN}${BOLD}dnsmesh-node is up.${RESET}

${BOLD}Hostname:${RESET}        $DMP_NODE_HOSTNAME
${BOLD}Operator token:${RESET}  $DMP_OPERATOR_TOKEN
${BOLD}Version:${RESET}         $INSTALLED_VERSION
${BOLD}Service:${RESET}         $SERVICE_NAME (systemctl status $SERVICE_NAME)
${BOLD}Logs:${RESET}            journalctl -u $SERVICE_NAME -f
${BOLD}State:${RESET}           $DATA_DIR
${BOLD}Config:${RESET}          $ETC_DIR/node.env
${BOLD}Health:${RESET}          $([[ $HEALTH_OK -eq 1 ]] && echo "${GREEN}ok${RESET}" || echo "${YELLOW}pending${RESET}")

${DIM}The token is the only thing gating publish writes. Save it somewhere
safe; operators hand it to users (or use it themselves to register).${RESET}

${BOLD}Next steps:${RESET}
  ${DIM}# Verify TLS cert is issued (Caddy obtains it on first request to 443):${RESET}
  curl -sI https://$DMP_NODE_HOSTNAME/health

  ${DIM}# Upgrade later:${RESET}
  sudo /opt/dnsmesh/venv/bin/pip install -U dnsmesh
  sudo systemctl restart $SERVICE_NAME

  ${DIM}# Operator hardening checklist:${RESET}
  https://ovalenzuela.com/DNSMeshProtocol/deployment/hardening
EOF
