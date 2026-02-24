#!/usr/bin/env bash
# Launch all 6 agents in separate tmux sessions.
# Run from the main repo directory.

set -euo pipefail

K4_BASE_DIR="$(pwd)"

declare -A ROLES=(
    [trans]="TRANS"
    [bespoke]="BESPOKE"
    [jts]="JTS"
    [frac]="FRAC"
    [tableau]="TABLEAU"
    [qa]="QA"
)

# Launch order matters — QA first, JTS last
LAUNCH_ORDER=("qa" "trans" "bespoke" "frac" "tableau" "jts")

for AGENT in "${LAUNCH_ORDER[@]}"; do
    ROLE="${ROLES[$AGENT]}"
    SESSION="k4_${AGENT}"

    if tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "Session $SESSION already running — skipping."
        continue
    fi

    echo "Launching agent $AGENT (role: $ROLE) in tmux session $SESSION..."
    tmux new-session -d -s "$SESSION" \
        "${K4_BASE_DIR}/k4_agent_harness.sh ${AGENT} ${ROLE}"

    sleep 5  # stagger launches to avoid git contention
done

echo ""
echo "All agents launched. Monitor with:"
echo "  tmux ls                    # list sessions"
echo "  tmux attach -t k4_trans    # watch an agent"
echo "  tail -f /home/cpatrick/kryptos_agents/agent_trans/agent_logs/*.log"
echo ""
echo "  cat PROGRESS.md            # see shared state"
echo "  ls current_tasks/          # see active locks"
