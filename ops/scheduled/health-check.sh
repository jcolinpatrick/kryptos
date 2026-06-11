#!/usr/bin/env bash
#
# health-check.sh — Lightweight morning health check for kryptosbot.com
#
# Replaces the Claude-powered morning briefing with a zero-cost,
# 100% reliable shell script. Reports via ntfy.sh.
#
# Crontab entry (7 AM daily):
#   0 7 * * * /home/cpatrick/kryptos/ops/scheduled/health-check.sh
#
set -euo pipefail

REPO_DIR="/home/cpatrick/kryptos"
LOG_DIR="${REPO_DIR}/logs"
LOG_FILE="${LOG_DIR}/health-check.log"
NTFY_TOPIC_FILE="${REPO_DIR}/.env"

mkdir -p "$LOG_DIR"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Load NTFY_TOPIC from .env if available
NTFY_TOPIC=""
if [[ -f "$NTFY_TOPIC_FILE" ]]; then
    NTFY_TOPIC=$(grep -oP '^NTFY_TOPIC=\K.*' "$NTFY_TOPIC_FILE" 2>/dev/null || true)
fi

notify() {
    local title="$1" message="$2" priority="${3:-default}" tags="${4:-white_check_mark}"
    if [[ -n "$NTFY_TOPIC" ]]; then
        curl -s -H "Title: ${title}" -H "Priority: ${priority}" -H "Tags: ${tags}" \
            -d "${message}" "https://ntfy.sh/${NTFY_TOPIC}" >/dev/null 2>&1 || true
    fi
}

# --- Checks ---
ISSUES=()

# 1. API service
API_STATUS=$(systemctl is-active kryptosbot-api 2>/dev/null || echo "inactive")
if [[ "$API_STATUS" != "active" ]]; then
    ISSUES+=("API service: ${API_STATUS}")
fi

# 2. Site reachable
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 http://localhost:8321/ 2>/dev/null || echo "000")
if [[ "$HTTP_CODE" != "200" ]]; then
    ISSUES+=("Site HTTP: ${HTTP_CODE}")
fi

# 3. Classify endpoint (the critical user-facing feature)
CLASSIFY_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 \
    -X POST http://localhost:8321/api/classify \
    -H "Content-Type: application/json" \
    -d '{"theory":"Health check: testing a simple Caesar shift cipher on K4"}' \
    2>/dev/null || echo "000")
if [[ "$CLASSIFY_CODE" != "200" ]]; then
    ISSUES+=("Classify API: HTTP ${CLASSIFY_CODE}")
fi

# 4. db/ symlink intact (required by classify endpoint)
if [[ ! -d "${REPO_DIR}/db" ]]; then
    ISSUES+=("db/ symlink missing or broken")
fi

# 5. Disk space
DISK_FREE=$(df -h /home/cpatrick | tail -1 | awk '{print $4}')
DISK_PCT=$(df /home/cpatrick | tail -1 | awk '{print $5}' | tr -d '%')
if (( DISK_PCT > 90 )); then
    ISSUES+=("Disk ${DISK_PCT}% used (${DISK_FREE} free)")
fi

# 6. Site freshness
if [[ -f "${REPO_DIR}/site/index.html" ]]; then
    SITE_AGE_HOURS=$(( ($(date +%s) - $(stat --format=%Y "${REPO_DIR}/site/index.html")) / 3600 ))
    if (( SITE_AGE_HOURS > 48 )); then
        ISSUES+=("Site build ${SITE_AGE_HOURS}h old")
    fi
else
    ISSUES+=("site/index.html missing")
fi

# --- Report ---
DATE=$(date '+%Y-%m-%d')
if [[ ${#ISSUES[@]} -eq 0 ]]; then
    MSG="kryptosbot.com — All OK. API: active, HTTP: ${HTTP_CODE}, Disk: ${DISK_FREE} free"
    echo "[$(ts)] OK: ${MSG}" >> "$LOG_FILE"
    # Only notify on issues, not on success (reduce noise)
else
    MSG="kryptosbot.com — ${#ISSUES[@]} issue(s): $(IFS='; '; echo "${ISSUES[*]}")"
    echo "[$(ts)] WARN: ${MSG}" >> "$LOG_FILE"
    notify "kryptosbot.com — Health Check" "$MSG" "high" "warning"
fi
