#!/usr/bin/env bash
#
# uptime-monitor.sh — Check kryptosbot.com every 5 min, alert via ntfy if down
#
# Crontab entry:
#   */5 * * * * /home/cpatrick/kryptos/ops/scheduled/uptime-monitor.sh
#
# Uses a state file to avoid repeated alerts. Sends:
#   - "DOWN" alert on first failure
#   - "RECOVERED" alert when it comes back
#   - No alert while continuously up (zero noise)
#
set -euo pipefail

REPO_DIR="/home/cpatrick/kryptos"
STATE_FILE="/tmp/kryptosbot-uptime.state"
LOG_FILE="${REPO_DIR}/logs/uptime-monitor.log"

mkdir -p "${REPO_DIR}/logs"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Load NTFY_TOPIC from .env
NTFY_TOPIC=""
if [[ -f "${REPO_DIR}/.env" ]]; then
    NTFY_TOPIC=$(grep -oP '^NTFY_TOPIC=\K.*' "${REPO_DIR}/.env" 2>/dev/null || true)
fi

notify() {
    local title="$1" message="$2" priority="${3:-default}" tags="${4:-white_check_mark}"
    if [[ -n "$NTFY_TOPIC" ]]; then
        curl -s -H "Title: ${title}" -H "Priority: ${priority}" -H "Tags: ${tags}" \
            -d "${message}" "https://ntfy.sh/${NTFY_TOPIC}" >/dev/null 2>&1 || true
    fi
}

# Check both nginx and the API backend
FAILED=()

# 1. Public-facing site (via nginx)
HTTP_PUBLIC=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 https://kryptosbot.com/ 2>/dev/null || echo "000")
if [[ "$HTTP_PUBLIC" != "200" && "$HTTP_PUBLIC" != "301" && "$HTTP_PUBLIC" != "302" ]]; then
    FAILED+=("public HTTPS=${HTTP_PUBLIC}")
fi

# 2. Local API backend
HTTP_LOCAL=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:8321/ 2>/dev/null || echo "000")
if [[ "$HTTP_LOCAL" != "200" ]]; then
    FAILED+=("API localhost=${HTTP_LOCAL}")
fi

# 3. Nginx process running
if ! pgrep -x nginx >/dev/null 2>&1; then
    FAILED+=("nginx not running")
fi

# Read previous state (up/down)
PREV_STATE="up"
if [[ -f "$STATE_FILE" ]]; then
    PREV_STATE=$(cat "$STATE_FILE")
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
    DETAIL=$(IFS=', '; echo "${FAILED[*]}")
    echo "[$(ts)] DOWN: ${DETAIL}" >> "$LOG_FILE"

    if [[ "$PREV_STATE" == "up" ]]; then
        # Transition: up -> down — send alert
        notify "kryptosbot.com is DOWN" "${DETAIL}" "urgent" "rotating_light"
        echo "[$(ts)] ALERT SENT: DOWN" >> "$LOG_FILE"
    fi
    echo "down" > "$STATE_FILE"
else
    if [[ "$PREV_STATE" == "down" ]]; then
        # Transition: down -> up — send recovery
        notify "kryptosbot.com is back UP" "Public: ${HTTP_PUBLIC}, API: ${HTTP_LOCAL}" "default" "white_check_mark"
        echo "[$(ts)] ALERT SENT: RECOVERED" >> "$LOG_FILE"
    fi
    echo "up" > "$STATE_FILE"
fi
