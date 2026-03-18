#!/bin/bash
# Run a Claude Code prompt non-interactively
# Usage: ./run-prompt.sh <prompt-file>

set -euo pipefail

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
echo "$PROMPT" | claude --print \
    >> "$LOG_DIR/scheduled_output_$TIMESTAMP.log" 2>&1 \
    || echo "[$TIMESTAMP] FAILED: $PROMPT_FILE (exit $?)" \
        >> "$LOG_DIR/scheduler.log"

echo "[$TIMESTAMP] DONE: $PROMPT_FILE" >> "$LOG_DIR/scheduler.log"
