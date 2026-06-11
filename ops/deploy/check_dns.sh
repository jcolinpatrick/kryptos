#!/usr/bin/env bash
#
# check_dns.sh — Monitors kryptosbot.com A record vs actual WAN IP
#
# Alerts via ntfy.sh when:
#   1. DNS no longer resolves to this host's WAN IP (Verizon changed it)
#   2. DNS resolution fails entirely
#   3. WAN IP cannot be determined (connectivity issue)
#
# Design:
#   - Uses a state file to avoid spamming: alerts once per incident,
#     then sends a recovery notice when the issue resolves.
#   - Requires 2 consecutive mismatches before alerting (transient tolerance).
#   - No external dependencies beyond curl and Python 3 stdlib.
#
# Crontab entry (every 15 min):
#   */15 * * * * /home/cpatrick/kryptos/deploy/check_dns.sh
#
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
DOMAIN="kryptosbot.com"
STATE_DIR="/home/cpatrick/kryptos/logs"
STATE_FILE="${STATE_DIR}/.dns_check_state"
LOG_FILE="${STATE_DIR}/dns_check.log"
ENV_FILE="/home/cpatrick/kryptos/.env"

# Load notification topic from the standard repo .env used by the other
# scheduled scripts. Falling back to empty disables notifications but keeps
# logging/state transitions intact.
NTFY_TOPIC=""
if [[ -f "$ENV_FILE" ]]; then
    NTFY_TOPIC=$(grep -oP '^NTFY_TOPIC=\K.*' "$ENV_FILE" 2>/dev/null || true)
fi

# WAN IP services (tried in order; first success wins)
WAN_SERVICES=(
    "https://api.ipify.org"
    "https://ifconfig.me"
    "https://icanhazip.com"
)

# ── Helpers ──────────────────────────────────────────────────────────────────
ts() { date '+%Y-%m-%d %H:%M:%S'; }

log() {
    echo "[$(ts)] $*" >> "$LOG_FILE"
}

notify() {
    local title="$1"
    local message="$2"
    local priority="${3:-default}"
    local tags="${4:-warning}"

    if [[ -z "$NTFY_TOPIC" ]]; then
        log "WARN: NTFY_TOPIC unset; skipping notification: ${title}"
        return 0
    fi

    curl -s \
        -H "Title: ${title}" \
        -H "Priority: ${priority}" \
        -H "Tags: ${tags}" \
        -d "${message}" \
        "https://ntfy.sh/${NTFY_TOPIC}" \
        >/dev/null 2>&1 || log "WARN: ntfy.sh notification failed"
}

get_wan_ip() {
    local ip=""
    for svc in "${WAN_SERVICES[@]}"; do
        ip=$(curl -4 -s --max-time 10 "$svc" 2>/dev/null | tr -d '[:space:]')
        # Validate: must look like an IPv4 address
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

resolve_domain() {
    python3 -c "
import socket, sys
try:
    ip = socket.gethostbyname('${DOMAIN}')
    print(ip)
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

# ── State management ─────────────────────────────────────────────────────────
# State file format: STATUS CONSECUTIVE_FAILS LAST_WAN_IP LAST_DNS_IP
# STATUS: ok | mismatch | down
read_state() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE"
    else
        echo "ok 0 unknown unknown"
    fi
}

write_state() {
    echo "$1 $2 $3 $4" > "$STATE_FILE"
}

# ── Main ─────────────────────────────────────────────────────────────────────
mkdir -p "$STATE_DIR"

# Rotate log if > 1MB
if [[ -f "$LOG_FILE" ]] && (( $(stat --format=%s "$LOG_FILE" 2>/dev/null || echo 0) > 1048576 )); then
    mv "$LOG_FILE" "${LOG_FILE}.1"
fi

# Get current state
read -r PREV_STATUS PREV_FAILS PREV_WAN PREV_DNS <<< "$(read_state)"

# Resolve WAN IP
WAN_IP=$(get_wan_ip) || {
    log "ERROR: Could not determine WAN IP (all services failed)"
    FAILS=$((PREV_FAILS + 1))
    if (( FAILS >= 2 )) && [[ "$PREV_STATUS" != "down" ]]; then
        notify \
            "kryptosbot.com — WAN IP unknown" \
            "Cannot determine WAN IP after ${FAILS} consecutive checks. Internet connectivity may be down." \
            "high" \
            "rotating_light"
        write_state "down" "$FAILS" "unknown" "$PREV_DNS"
        log "ALERT: WAN IP unknown (${FAILS} consecutive failures)"
    else
        write_state "$PREV_STATUS" "$FAILS" "unknown" "$PREV_DNS"
        log "WARN: WAN IP unknown (attempt ${FAILS})"
    fi
    exit 0
}

# Resolve domain
DNS_IP=$(resolve_domain) || {
    log "ERROR: DNS resolution failed for ${DOMAIN}"
    FAILS=$((PREV_FAILS + 1))
    if (( FAILS >= 2 )) && [[ "$PREV_STATUS" != "down" ]]; then
        notify \
            "kryptosbot.com — DNS resolution failed" \
            "Cannot resolve ${DOMAIN}. GoDaddy A record may be missing or DNS is down. WAN IP is ${WAN_IP}." \
            "urgent" \
            "rotating_light"
        write_state "down" "$FAILS" "$WAN_IP" "unresolvable"
        log "ALERT: DNS resolution failed (${FAILS} consecutive failures)"
    else
        write_state "$PREV_STATUS" "$FAILS" "$WAN_IP" "unresolvable"
        log "WARN: DNS resolution failed (attempt ${FAILS})"
    fi
    exit 0
}

# Compare
if [[ "$WAN_IP" == "$DNS_IP" ]]; then
    # Match — all good
    if [[ "$PREV_STATUS" != "ok" ]]; then
        # Recovery from a previous alert
        notify \
            "kryptosbot.com — recovered" \
            "DNS (${DNS_IP}) matches WAN IP again. Site should be reachable." \
            "default" \
            "white_check_mark"
        log "RECOVERY: DNS=${DNS_IP} matches WAN=${WAN_IP} (was: ${PREV_STATUS})"
    else
        log "OK: DNS=${DNS_IP} == WAN=${WAN_IP}"
    fi
    write_state "ok" "0" "$WAN_IP" "$DNS_IP"
else
    # Mismatch
    FAILS=$((PREV_FAILS + 1))
    log "MISMATCH: DNS=${DNS_IP} != WAN=${WAN_IP} (attempt ${FAILS})"

    if (( FAILS >= 2 )) && [[ "$PREV_STATUS" != "mismatch" ]]; then
        notify \
            "kryptosbot.com — IP mismatch!" \
            "DNS A record points to ${DNS_IP} but WAN IP is ${WAN_IP}. Verizon likely changed your public IP. Update the GoDaddy A record to ${WAN_IP}." \
            "urgent" \
            "rotating_light,globe_with_meridians"
        write_state "mismatch" "$FAILS" "$WAN_IP" "$DNS_IP"
        log "ALERT: IP mismatch — DNS=${DNS_IP}, WAN=${WAN_IP}"
    else
        write_state "${PREV_STATUS}" "$FAILS" "$WAN_IP" "$DNS_IP"
    fi
fi
