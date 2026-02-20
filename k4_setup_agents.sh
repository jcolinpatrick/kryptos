#!/usr/bin/env bash
# Run once to create git worktrees for all agents.
# Must be run from the main repo directory.

set -euo pipefail

K4_BASE_DIR="$(pwd)"
K4_AGENTS_DIR="/home/cpatrick/kryptos_agents"

AGENTS=("trans" "bespoke" "jts" "frac" "tableau" "qa")

# Ensure the main repo is on branch 'main'
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    echo "ERROR: must be on branch 'main'. Currently on '$BRANCH'."
    exit 1
fi

mkdir -p "$K4_AGENTS_DIR"
mkdir -p current_tasks

for AGENT in "${AGENTS[@]}"; do
    WORKTREE="${K4_AGENTS_DIR}/agent_${AGENT}"
    BRANCH_NAME="agent/${AGENT}"

    if [ -d "$WORKTREE" ]; then
        echo "Worktree for $AGENT already exists at $WORKTREE — skipping."
        continue
    fi

    # Create a branch for the agent (branched from main)
    git branch "$BRANCH_NAME" main 2>/dev/null || true

    # Create the worktree
    git worktree add "$WORKTREE" "$BRANCH_NAME"

    # Create agent-specific directories
    mkdir -p "${WORKTREE}/agent_logs"
    mkdir -p "${WORKTREE}/results/${AGENT}"

    echo "Created worktree for agent $AGENT at $WORKTREE (branch: $BRANCH_NAME)"
done

# Initialize PROGRESS.md if it doesn't exist
if [ ! -f PROGRESS.md ]; then
    cat > PROGRESS.md << 'EOF'
# K4 Agent Team — Progress Tracker
Last updated: (not yet started)

## ALERTS
<!-- Scores ≥18/24 go here. If this section is non-empty, ALL agents should read it. -->
(none)

## Active Tasks
| Agent | Task | Started | Status |
|-------|------|---------|--------|

## Completed (reverse chronological)
(no completed tasks yet)
EOF
    git add PROGRESS.md current_tasks/.gitkeep
    git commit -m "Initialize multi-agent infrastructure"
    echo "Created PROGRESS.md"
fi

echo ""
echo "Setup complete. To start an agent:"
echo "  cd ${K4_AGENTS_DIR}/agent_<name>"
echo "  tmux new -s k4_<name> '${K4_BASE_DIR}/k4_agent_harness.sh <name> <ROLE>'"
echo ""
echo "Recommended tmux launch order:"
echo "  1. qa      (let it run doctor + regression first)"
echo "  2. trans   (highest-priority hypothesis)"
echo "  3. bespoke (creative search, low compute)"
echo "  4. frac    (independent hypothesis branch)"
echo "  5. tableau (low-compute structural analysis)"
echo "  6. jts     (wait for TRANS to produce 3+ results first)"
