#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
K4_BASE_DIR="${K4_BASE_DIR:-$REPO_ROOT}"
K4_AGENT_ID="${K4_AGENT_ID:-solo}"
mkdir -p "$K4_BASE_DIR/agent_logs" "$K4_BASE_DIR/work" "$K4_BASE_DIR/results"

LOG="$K4_BASE_DIR/agent_logs/verify_${K4_AGENT_ID}.log"

# Run your existing pipeline in "fast" mode if available.
# If no fast mode exists yet, run the smallest meaningful subset.
# Example:
# ./scripts/k4_run_pipeline.sh --fast &>> "$LOG"

# Temporary placeholder:
echo "ERROR verifier not wired yet" | tee -a "$LOG"
exit 1
