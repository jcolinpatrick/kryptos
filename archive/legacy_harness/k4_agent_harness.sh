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

# Unset CLAUDECODE to allow nested Claude Code sessions from within an active session
unset CLAUDECODE

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

# sync_with_upstream: pull latest, auto-resolve conflicts in shared files
sync_with_upstream() {
    local logfile="$1"

    # Try normal pull --rebase first
    if git pull --rebase upstream main >> "$logfile" 2>&1; then
        return 0
    fi

    echo "WARN: git pull --rebase failed — attempting auto-recovery." | tee -a "$logfile"

    # Check if we're in a conflicted rebase
    if [ -d ".git/rebase-merge" ] || [ -d ".git/rebase-apply" ] || \
       [ -f "$(git rev-parse --git-dir)/rebase-merge/head-name" ] 2>/dev/null; then

        # Try to resolve by accepting upstream for known shared files
        local resolved=true
        for conflict_file in $(git diff --name-only --diff-filter=U 2>/dev/null); do
            case "$conflict_file" in
                PROGRESS.md|docs/elimination_tiers.md|docs/research_questions.md)
                    echo "  Auto-resolving $conflict_file (accepting upstream)" | tee -a "$logfile"
                    git checkout --theirs "$conflict_file" >> "$logfile" 2>&1
                    git add "$conflict_file" >> "$logfile" 2>&1
                    ;;
                *)
                    echo "  Cannot auto-resolve $conflict_file — aborting rebase" | tee -a "$logfile"
                    resolved=false
                    break
                    ;;
            esac
        done

        if $resolved; then
            # Continue the rebase after resolving
            if GIT_EDITOR=true git rebase --continue >> "$logfile" 2>&1; then
                echo "  Rebase recovered successfully." | tee -a "$logfile"
                return 0
            fi
        fi

        # If resolution failed, abort and hard-reset
        echo "  Auto-resolution failed. Aborting rebase and resetting to upstream/main." | tee -a "$logfile"
        git rebase --abort >> "$logfile" 2>&1
    fi

    # Last resort: hard reset to upstream/main
    echo "  Hard-resetting to upstream/main (local unpushed commits lost)." | tee -a "$logfile"
    git fetch upstream >> "$logfile" 2>&1
    git reset --hard upstream/main >> "$logfile" 2>&1
    return 0
}

ITERATION=0
while true; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
    LOGFILE="${LOG_DIR}/session_${TIMESTAMP}.log"

    echo "=== Agent ${AGENT_ID} iteration ${ITERATION} @ ${TIMESTAMP} ===" | tee "$LOGFILE"

    # Pull latest changes before each session (with auto-conflict resolution)
    sync_with_upstream "$LOGFILE" || {
        echo "ERROR: sync failed even after recovery. Sleeping 60s and retrying." | tee -a "$LOGFILE"
        sleep 60
        continue
    }

    # Run Claude Code with the agent prompt (|| true to prevent pipefail from killing the loop)
    claude --dangerously-skip-permissions \
           -p "You are agent '${AGENT_ID}' with role '${AGENT_ROLE}'. Read CLAUDE.md fully, then read PROGRESS.md, then begin your next task following the Multi-Agent Mode protocol. Your worktree is ${K4_WORK_DIR}. Max runtime per task: ${K4_MAX_RUNTIME}s." \
           --model claude-opus-4-6 \
           >> "$LOGFILE" 2>&1 || {
        echo "WARN: Claude exited with code $?. Will retry next iteration." | tee -a "$LOGFILE"
    }

    echo "Session complete @ $(date -u +%Y%m%dT%H%M%SZ)" | tee -a "$LOGFILE"

    # Brief pause to avoid hammering the API
    sleep 10
done
