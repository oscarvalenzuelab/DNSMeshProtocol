#!/usr/bin/env bash
#
# DMP node firewall helper (optional).
#
# Configures ufw with the ports a DMP node needs:
#
#   SSH 22/tcp       — admin access (default; override with --ssh-port)
#   DNS 53/udp       — DMP authoritative DNS, primary path
#   DNS 53/tcp       — DNS TCP fallback (RFC 1035 §4.2.2 + RFC 7766);
#                      required when responses exceed UDP buffer size,
#                      most visibly for _dnsmesh-seen.<zone> RRsets
#   HTTP 80/tcp      — Let's Encrypt HTTP-01 ACME challenge
#   HTTPS 443/tcp    — Caddy front-end (TSIG registration handshake +
#                      node landing page)
#   HTTPS 443/udp    — HTTP/3 (QUIC); optional, harmless to leave open
#
# Usage:
#
#   sudo ./firewall.sh                # add the rules above + show status
#   sudo ./firewall.sh --check        # print the rules and ufw state, change nothing
#   sudo ./firewall.sh --enable       # also `ufw enable` if disabled
#   sudo ./firewall.sh --ssh-port 2222
#
# This script only configures the host-level firewall (ufw). Cloud
# providers run a SEPARATE firewall in front of your droplet — DO Cloud
# Firewall, AWS Security Group, GCP firewall rules, etc. You'll need
# to allow the same ports there too. Check your provider's docs.
#
# Idempotent: re-running adds rules that don't exist, leaves the rest
# alone. Safe to use on a host with existing ufw config.

set -euo pipefail

SSH_PORT=22
MODE="apply"  # apply | check | apply-and-enable

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)         MODE="check"; shift ;;
        --enable)        MODE="apply-and-enable"; shift ;;
        --ssh-port)      SSH_PORT="$2"; shift 2 ;;
        --ssh-port=*)    SSH_PORT="${1#*=}"; shift ;;
        -h|--help)       usage ;;
        *)
            echo "unknown arg: $1" >&2
            echo "see --help" >&2
            exit 2
            ;;
    esac
done

# Color helpers (only when stderr is a terminal).
if [[ -t 2 ]]; then
    BOLD=$'\e[1m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi

step() { echo "${BOLD}==>${RESET} $*" >&2; }
ok()   { echo "${GREEN}ok${RESET}    $*" >&2; }
warn() { echo "${YELLOW}warn${RESET}  $*" >&2; }
fail() { echo "${RED}error${RESET} $*" >&2; exit 1; }

# Must run as root for any ufw mutation; --check can run unprivileged
# but the status command itself needs root on most Ubuntu setups.
if [[ $EUID -ne 0 ]]; then
    fail "must be run as root (try: sudo $0 ${MODE/apply-and-enable/--enable})"
fi

if ! command -v ufw >/dev/null 2>&1; then
    fail "ufw not installed. run: apt install ufw"
fi

# Show current state up front so the operator sees what they're starting with.
step "Current ufw state"
ufw status verbose 2>&1 | sed 's/^/    /' >&2

if [[ "$MODE" == "check" ]]; then
    exit 0
fi

# Rules to apply: (port/proto, comment).
RULES=(
    "${SSH_PORT}/tcp::SSH"
    "53/udp::dnsmesh authoritative DNS (UDP)"
    "53/tcp::dnsmesh DNS TCP fallback"
    "80/tcp::ACME HTTP-01 challenge (Let's Encrypt)"
    "443/tcp::dnsmesh HTTPS (Caddy / TSIG registration / landing page)"
    "443/udp::dnsmesh HTTPS HTTP/3 (QUIC, optional)"
)

step "Applying ufw rules"
for rule in "${RULES[@]}"; do
    spec="${rule%%::*}"
    comment="${rule##*::}"
    if ufw status | grep -qE "^${spec}\s+ALLOW\b"; then
        ok "${spec} already allowed"
    else
        ufw allow "${spec}" comment "${comment}" >/dev/null
        ok "${spec} added (${comment})"
    fi
done

# Optionally enable ufw. NEVER auto-enable without --enable: if SSH
# isn't already in the rule set when ufw flips on, the operator gets
# locked out. Adding the SSH rule above doesn't help if they typo'd
# --ssh-port. Make them say so explicitly.
if [[ "$MODE" == "apply-and-enable" ]]; then
    if ufw status | grep -q "^Status: active"; then
        ok "ufw already enabled"
    else
        step "Enabling ufw (be sure SSH is in the rules above)"
        # `ufw enable` prompts on TTY; --force skips it.
        ufw --force enable >/dev/null
        ok "ufw enabled"
    fi
elif ! ufw status | grep -q "^Status: active"; then
    warn "ufw is INACTIVE. The rules above are configured but not enforced."
    warn "Re-run with --enable once you've confirmed SSH (port ${SSH_PORT}) is correct."
fi

# Final state.
step "Resulting ufw state"
ufw status verbose 2>&1 | sed 's/^/    /' >&2

# Reminder about cloud-firewall layer that this script can't touch.
echo "" >&2
echo "${BOLD}Reminder:${RESET} most cloud providers run a SEPARATE firewall in" >&2
echo "front of your VM. Allow the same ports there too:" >&2
echo "  - DigitalOcean: Networking → Firewalls → your firewall →" >&2
echo "    Inbound rules → Add SSH + 53/udp + 53/tcp + 80/tcp +" >&2
echo "    443/tcp + 443/udp" >&2
echo "  - AWS:           Security Group inbound rules" >&2
echo "  - GCP:           VPC firewall rules" >&2
