#!/usr/bin/env bash
# k4_job_runner.sh — Executes sweep scripts from jobs/pending/ on full CPU.
# No LLM involved. Pure compute.
#
# Usage: tmux new -d -s k4_runner './k4_job_runner.sh'
#
# Flow: jobs/pending/*.py → jobs/running/ → jobs/done/ (or jobs/failed/)
# Results written to results/<job_name>.log
# Scripts MUST accept --workers N and print a final RESULT: line.

set -uo pipefail
cd "$(dirname "$0")"

WORKERS="${K4_SWEEP_WORKERS:-14}"
mkdir -p jobs/{pending,running,done,failed} results

echo "[$(date -u +%H:%M:%S)] Job runner started (${WORKERS} workers). Watching jobs/pending/..."

while true; do
    for script in jobs/pending/*.py; do
        [ -f "$script" ] || continue

        NAME=$(basename "$script" .py)
        echo "[$(date -u +%H:%M:%S)] Starting: $NAME"

        mv "$script" "jobs/running/${NAME}.py"

        PYTHONPATH=src timeout 7200 python3 -u "jobs/running/${NAME}.py" \
            --workers "$WORKERS" \
            > "results/${NAME}.log" 2>&1
        EXIT_CODE=$?

        if [ $EXIT_CODE -eq 0 ]; then
            mv "jobs/running/${NAME}.py" "jobs/done/${NAME}.py"
            echo "[$(date -u +%H:%M:%S)] Done: $NAME"
        elif [ $EXIT_CODE -eq 124 ]; then
            mv "jobs/running/${NAME}.py" "jobs/failed/${NAME}.py"
            echo "[$(date -u +%H:%M:%S)] TIMEOUT: $NAME (hit 7200s limit)"
        else
            mv "jobs/running/${NAME}.py" "jobs/failed/${NAME}.py"
            echo "[$(date -u +%H:%M:%S)] FAILED: $NAME (exit code $EXIT_CODE)"
        fi

        # Print the RESULT line if present
        grep "^RESULT:" "results/${NAME}.log" 2>/dev/null || true
        echo ""
    done
    sleep 10
done
