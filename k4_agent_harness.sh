#!/usr/bin/env bash
# Usage: ./k4_agent_harness.sh <agent_id> <agent_role>
# Example: ./k4_agent_harness.sh trans TRANS
#
# Prerequisites:
#   - Git worktree exists at $K4_AGENTS_DIR/agent_${AGENT_ID}
#   - Python 3.12+ available
#   - pytest installed (pip install --user pytest)

set -uo pipefail

AGENT_ID="${1:?Usage: $0 <agent_id> <agent_role>}"
AGENT_ROLE="${2:?Usage: $0 <agent_id> <agent_role>}"

export K4_AGENT_ID="$AGENT_ID"
export K4_AGENT_ROLE="$AGENT_ROLE"
export K4_BASE_DIR="/home/cpatrick/kryptos"
export K4_AGENTS_DIR="/home/cpatrick/kryptos_agents"
export K4_WORK_DIR="${K4_AGENTS_DIR}/agent_${AGENT_ID}"
export K4_MAX_RUNTIME=7200  # 2 hours per task
export PYTHONPATH=src

LOG_DIR="${K4_WORK_DIR}/agent_logs"
mkdir -p "$LOG_DIR"

cd "$K4_WORK_DIR"

ITERATION=0
while true; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
    LOGFILE="${LOG_DIR}/session_${TIMESTAMP}.log"

    echo "=== Agent ${AGENT_ID} iteration ${ITERATION} @ ${TIMESTAMP} ===" | tee "$LOGFILE"

    # Pull latest changes before each session
    git pull --rebase upstream main >> "$LOGFILE" 2>&1 || {
        echo "ERROR: git pull failed. Sleeping 60s and retrying." | tee -a "$LOGFILE"
        sleep 60
        continue
    }

    # Run Claude Code with the agent prompt
    claude --dangerously-skip-permissions \
           -p "You are agent '${AGENT_ID}' with role '${AGENT_ROLE}'. Read CLAUDE.md fully, then read PROGRESS.md, then begin your next task following the Multi-Agent Mode protocol. Your worktree is ${K4_WORK_DIR}. Max runtime per task: ${K4_MAX_RUNTIME}s." \
           --model claude-opus-4-6 \
           >> "$LOGFILE" 2>&1

    echo "Session complete @ $(date -u +%Y%m%dT%H%M%SZ)" | tee -a "$LOGFILE"

    # Brief pause to avoid hammering the API
    sleep 10
done
