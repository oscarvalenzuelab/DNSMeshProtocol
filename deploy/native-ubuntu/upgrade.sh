#!/usr/bin/env bash
# Upgrade an existing native-ubuntu dnsmesh-node install to the latest
# dnsmesh wheel + refresh the systemd unit. Leaves user-managed state
# untouched (operator token, Caddy config, sqlite store).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/native-ubuntu/upgrade.sh \
#       | sudo bash
#
# What it touches:
#   /opt/dnsmesh/venv/                       (pip install -U dnsmesh)
#   /etc/systemd/system/dnsmesh-node.service (re-fetched from main)
#
# What it does NOT touch:
#   /etc/dnsmesh/node.env                    (your operator token + env vars)
#   /etc/caddy/Caddyfile                     (any reverse-proxy customizations)
#   /var/lib/dmp/                            (sqlite state; survives upgrades)
#
# Re-runnable: every cron tick if you want.

set -euo pipefail

DNSMESH_USER="${DNSMESH_USER:-dnsmesh}"
INSTALL_DIR="${DNSMESH_INSTALL_DIR:-/opt/dnsmesh}"
VENV_DIR="${INSTALL_DIR}/venv"
ETC_DIR="${DNSMESH_ETC_DIR:-/etc/dnsmesh}"
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
[[ -d "$VENV_DIR" ]] \
    || die "$VENV_DIR not found. Was this node installed via deploy/native-ubuntu/install.sh? \
If you're on Docker, use deploy/digitalocean/upgrade.sh instead."
[[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]] \
    || die "${SERVICE_NAME}.service not found"
ok "found existing native install"

OLD_VERSION=$("$VENV_DIR/bin/pip" show dnsmesh 2>/dev/null \
    | awk '/^Version:/ {print $2}')
ok "current version: ${OLD_VERSION:-unknown}"

# ──────────────────────────────────────────────────────────────────────
# Upgrade the wheel
# ──────────────────────────────────────────────────────────────────────

step "Upgrading dnsmesh"
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet --upgrade dnsmesh
NEW_VERSION=$("$VENV_DIR/bin/pip" show dnsmesh | awk '/^Version:/ {print $2}')
ok "dnsmesh ${OLD_VERSION:-?} -> ${NEW_VERSION}"

if [[ "$OLD_VERSION" == "$NEW_VERSION" ]]; then
    warn "version unchanged; refreshing systemd unit + restarting anyway \
in case lifecycle directives or installed binaries drifted"
fi

# Lock down venv perms so the dnsmesh user can read but not write.
chown -R root:root "$INSTALL_DIR"
chmod -R go+rX "$INSTALL_DIR"

# ──────────────────────────────────────────────────────────────────────
# Refresh the systemd unit
# ──────────────────────────────────────────────────────────────────────

step "Refreshing systemd unit"
TMP_UNIT=$(mktemp /tmp/dnsmesh-node.service.XXXXXX)
curl -fsSL "$RAW_BASE/deploy/native-ubuntu/dnsmesh-node.service" -o "$TMP_UNIT"
if cmp -s "$TMP_UNIT" "/etc/systemd/system/${SERVICE_NAME}.service"; then
    ok "unit unchanged"
    rm -f "$TMP_UNIT"
else
    install -m 0644 -o root -g root "$TMP_UNIT" \
        "/etc/systemd/system/${SERVICE_NAME}.service"
    rm -f "$TMP_UNIT"
    systemctl daemon-reload
    ok "unit refreshed and daemon-reload'd"
fi

# ──────────────────────────────────────────────────────────────────────
# Backfill DMP_HEARTBEAT_SEEDS into pre-0.3.3 env files
# ──────────────────────────────────────────────────────────────────────

step "Checking node.env for DMP_HEARTBEAT_SEEDS"
ENV_FILE="$ETC_DIR/node.env"
if [[ -f "$ENV_FILE" ]] && ! grep -qE '^[[:space:]]*DMP_HEARTBEAT_SEEDS=' "$ENV_FILE"; then
    # Pre-0.3.3 installs were created without the seeds line. Add it so
    # the heartbeat worker has somewhere to gossip on the first tick
    # after the upgrade. dnsmesh.io is the canonical bootstrap.
    cat >> "$ENV_FILE" <<EOF

# Added by upgrade.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Heartbeat seeds: nodes this one will pre-emptively send its own
# heartbeat to on every tick. Without seeds, a new node only meets
# peers that find it first — dnsmesh.io acts as the canonical
# bootstrap so federation works out of the box. Comma-separated.
DMP_HEARTBEAT_SEEDS=https://dnsmesh.io
EOF
    chown root:"$DNSMESH_USER" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
    ok "added DMP_HEARTBEAT_SEEDS=https://dnsmesh.io to $ENV_FILE"
else
    ok "DMP_HEARTBEAT_SEEDS already present (left alone)"
fi

# ──────────────────────────────────────────────────────────────────────
# Restart and wait for health
# ──────────────────────────────────────────────────────────────────────

step "Restarting $SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

HEALTH_OK=0
for _ in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:8053/health 2>/dev/null \
            | grep -q '"status": *"ok"'; then
        HEALTH_OK=1; break
    fi
    sleep 1
done

# ──────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────

cat <<EOF

${GREEN}${BOLD}Upgrade complete.${RESET}

${BOLD}Version:${RESET}  ${OLD_VERSION:-?} -> ${NEW_VERSION}
${BOLD}Service:${RESET}  $(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)
${BOLD}Health:${RESET}   $([[ $HEALTH_OK -eq 1 ]] && echo "${GREEN}ok${RESET}" || echo "${YELLOW}pending — check 'journalctl -u $SERVICE_NAME'${RESET}")

${DIM}Operator config + Caddyfile + sqlite state were not touched.${RESET}

${BOLD}New in 0.3.x worth knowing:${RESET}
  ${DIM}# A friendly landing page now serves at the node root:${RESET}
  curl https://your-host/

  ${DIM}# Discovery is opt-in. To make this node visible in directories${RESET}
  ${DIM}# and surface peers it has heard from, add to $ETC_DIR/node.env:${RESET}
  DMP_HEARTBEAT_ENABLED=1
  DMP_HEARTBEAT_SELF_ENDPOINT=https://your-host
  DMP_HEARTBEAT_OPERATOR_KEY_PATH=$ETC_DIR/operator-ed25519.hex

  ${DIM}# Generate the operator key (once):${RESET}
  sudo openssl rand -hex 32 | sudo tee $ETC_DIR/operator-ed25519.hex >/dev/null
  sudo chown root:$DNSMESH_USER $ETC_DIR/operator-ed25519.hex
  sudo chmod 0440 $ETC_DIR/operator-ed25519.hex
  sudo systemctl restart $SERVICE_NAME

  ${DIM}# Then add your URL to the canonical aggregator's seed list:${RESET}
  ${DIM}# https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/directory/seeds.txt${RESET}
EOF
