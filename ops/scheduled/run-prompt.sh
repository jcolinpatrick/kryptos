#!/bin/bash
# Run a Claude Code prompt non-interactively
# Usage: ./run-prompt.sh <prompt-file>

set -euo pipefail

# Cron runs with minimal PATH — ensure claude CLI is reachable
export PATH="$HOME/.local/bin:$PATH"

PROMPT_FILE="$1"
PROJECT_DIR="$HOME/kryptos"
LOG_DIR="$PROJECT_DIR/logs"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')

mkdir -p "$LOG_DIR"

if [ ! -f "$PROMPT_FILE" ]; then
    echo "[$TIMESTAMP] ERROR: Prompt file not found: $PROMPT_FILE" \
        >> "$LOG_DIR/scheduler.log"
    exit 1
fi

PROMPT=$(cat "$PROMPT_FILE")

echo "[$TIMESTAMP] START: $PROMPT_FILE" >> "$LOG_DIR/scheduler.log"

cd "$PROJECT_DIR"
if echo "$PROMPT" | claude --print \
    >> "$LOG_DIR/scheduled_output_$TIMESTAMP.log" 2>&1; then
    echo "[$TIMESTAMP] DONE: $PROMPT_FILE" >> "$LOG_DIR/scheduler.log"
else
    EXIT_CODE=$?
    echo "[$TIMESTAMP] FAILED: $PROMPT_FILE (exit $EXIT_CODE)" \
        >> "$LOG_DIR/scheduler.log"
    # Notify on failure via ntfy.sh (best-effort)
    NTFY_TOPIC=$(grep -oP '^NTFY_TOPIC=\K.*' "$PROJECT_DIR/.env" 2>/dev/null || true)
    if [ -n "$NTFY_TOPIC" ]; then
        curl -s -H "Title: Scheduled prompt failed" -H "Priority: high" -H "Tags: warning" \
            -d "$(basename "$PROMPT_FILE") exited $EXIT_CODE" \
            "https://ntfy.sh/$NTFY_TOPIC" >/dev/null 2>&1 || true
    fi
fi
