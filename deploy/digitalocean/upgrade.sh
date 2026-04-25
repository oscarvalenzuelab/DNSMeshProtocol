#!/usr/bin/env bash
# Upgrade an existing Docker dnsmesh-node deploy (the one
# deploy/digitalocean/quickstart.sh sets up under /opt/dnsmesh).
# Pulls the latest image, re-creates the container, waits for health.
# Operator config + sqlite volume survive untouched.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/digitalocean/upgrade.sh \
#       | sudo bash
#
# Or for a specific version:
#   curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/digitalocean/upgrade.sh \
#       | sudo DMP_IMAGE_TAG=0.3.0 bash
#
# What it touches:
#   /opt/dnsmesh/compose.yml   (re-fetched from main if changed)
#   /opt/dnsmesh/Caddyfile     (re-fetched from main if unmodified locally)
#   running containers         (recreated to pick up the new image)
#
# What it does NOT touch:
#   /opt/dnsmesh/.env          (your operator token + hostname)
#   docker volumes             (sqlite store survives)

set -euo pipefail

INSTALL_DIR="${DNSMESH_INSTALL_DIR:-/opt/dnsmesh}"
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
command -v docker >/dev/null || die "docker not installed; this script is for the Docker quickstart path"
docker compose version >/dev/null 2>&1 \
    || die "docker compose plugin missing"
[[ -d "$INSTALL_DIR" ]] || die "$INSTALL_DIR not found. Was this set up via deploy/digitalocean/quickstart.sh?"
[[ -f "$INSTALL_DIR/.env" ]] || die "$INSTALL_DIR/.env missing; can't tell which hostname to upgrade"
[[ -f "$INSTALL_DIR/compose.yml" ]] || die "$INSTALL_DIR/compose.yml missing"
ok "found existing Docker install at $INSTALL_DIR"

cd "$INSTALL_DIR"

# Capture current image digest so we can report what changed.
OLD_DIGEST=$(docker compose images --format json 2>/dev/null \
    | python3 -c 'import json,sys
try:
    for line in sys.stdin:
        d = json.loads(line)
        if "dnsmesh-node" in d.get("Repository",""):
            print(d.get("ID","")[:12])
            break
except Exception:
    pass' 2>/dev/null || true)
ok "current image: ${OLD_DIGEST:-unknown}"

# ──────────────────────────────────────────────────────────────────────
# Refresh compose.yml + Caddyfile (only if upstream changed)
# ──────────────────────────────────────────────────────────────────────

step "Refreshing compose.yml + Caddyfile"
TMP_DIR=$(mktemp -d)
curl -fsSL "$RAW_BASE/deploy/docker/compose.yml" -o "$TMP_DIR/compose.yml"
curl -fsSL "$RAW_BASE/Caddyfile"               -o "$TMP_DIR/Caddyfile"

if cmp -s "$TMP_DIR/compose.yml" "$INSTALL_DIR/compose.yml"; then
    ok "compose.yml unchanged"
else
    cp "$INSTALL_DIR/compose.yml" "$INSTALL_DIR/compose.yml.bak"
    install -m 0644 "$TMP_DIR/compose.yml" "$INSTALL_DIR/compose.yml"
    ok "compose.yml refreshed (backup at compose.yml.bak)"
fi

if cmp -s "$TMP_DIR/Caddyfile" "$INSTALL_DIR/Caddyfile"; then
    ok "Caddyfile unchanged"
else
    cp "$INSTALL_DIR/Caddyfile" "$INSTALL_DIR/Caddyfile.bak"
    install -m 0644 "$TMP_DIR/Caddyfile" "$INSTALL_DIR/Caddyfile"
    ok "Caddyfile refreshed (backup at Caddyfile.bak)"
fi
rm -rf "$TMP_DIR"

# ──────────────────────────────────────────────────────────────────────
# Pull + recreate
# ──────────────────────────────────────────────────────────────────────

step "Pulling latest image"
docker compose --env-file "$INSTALL_DIR/.env" \
    -f "$INSTALL_DIR/compose.yml" pull --quiet
ok "pulled"

step "Recreating containers"
docker compose --env-file "$INSTALL_DIR/.env" \
    -f "$INSTALL_DIR/compose.yml" up -d
ok "compose up -d done"

# ──────────────────────────────────────────────────────────────────────
# Wait for health
# ──────────────────────────────────────────────────────────────────────

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

NEW_DIGEST=$(docker compose images --format json 2>/dev/null \
    | python3 -c 'import json,sys
try:
    for line in sys.stdin:
        d = json.loads(line)
        if "dnsmesh-node" in d.get("Repository",""):
            print(d.get("ID","")[:12])
            break
except Exception:
    pass' 2>/dev/null || true)

# Source the hostname for the summary.
DMP_NODE_HOSTNAME=$(grep -E '^DMP_NODE_HOSTNAME=' "$INSTALL_DIR/.env" 2>/dev/null \
    | cut -d= -f2- | tr -d '"' | tr -d "'" || true)

# ──────────────────────────────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────────────────────────────

cat <<EOF

${GREEN}${BOLD}Upgrade complete.${RESET}

${BOLD}Hostname:${RESET}   ${DMP_NODE_HOSTNAME:-?}
${BOLD}Image:${RESET}      ${OLD_DIGEST:-?} -> ${NEW_DIGEST:-?}
${BOLD}Health:${RESET}     $([[ $HEALTH_OK -eq 1 ]] && echo "${GREEN}ok${RESET}" || echo "${YELLOW}pending — check 'docker compose logs'${RESET}")

${DIM}Operator config + sqlite volume were not touched.${RESET}

${BOLD}New in 0.3.x worth knowing:${RESET}
  ${DIM}# A friendly landing page now serves at the node root:${RESET}
  curl https://${DMP_NODE_HOSTNAME:-your-host}/

  ${DIM}# Discovery is opt-in. To make this node visible in directories${RESET}
  ${DIM}# and surface peers it has heard from, add to $INSTALL_DIR/.env:${RESET}
  DMP_HEARTBEAT_ENABLED=1
  DMP_HEARTBEAT_SELF_ENDPOINT=https://${DMP_NODE_HOSTNAME:-your-host}
  DMP_HEARTBEAT_OPERATOR_KEY_PATH=/etc/dmp/operator-ed25519.hex

  ${DIM}# Generate the operator key + mount it (once):${RESET}
  openssl rand -hex 32 | sudo tee $INSTALL_DIR/operator-ed25519.hex >/dev/null
  sudo chmod 0440 $INSTALL_DIR/operator-ed25519.hex
  ${DIM}# then in $INSTALL_DIR/compose.yml under the dnsmesh-node 'volumes:' list, add:${RESET}
  ${DIM}#   - ./operator-ed25519.hex:/etc/dmp/operator-ed25519.hex:ro${RESET}
  sudo docker compose -f $INSTALL_DIR/compose.yml up -d

  ${DIM}# Then add your URL to the canonical aggregator's seed list:${RESET}
  ${DIM}# https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/directory/seeds.txt${RESET}
EOF
