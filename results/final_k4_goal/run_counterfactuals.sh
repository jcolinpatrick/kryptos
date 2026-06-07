#!/usr/bin/env bash
# Orchestrator: wait for the primary controller (PID passed as $1) to finish,
# then run the two directed counterfactual controller runs sequentially.
# Counterfactuals use 12 cycles (sensitivity check on anchor dependence, not a
# solve attempt — the primary 50-cycle run is the solve attempt). Separate DBs.
set -u
cd /home/cpatrick/kryptos
export PYTHONPATH=src
PRIMARY_PID="${1:-}"
OUT=results/final_k4_goal

echo "[orchestrator] waiting for primary controller PID=$PRIMARY_PID to finish..."
if [ -n "$PRIMARY_PID" ]; then
  while kill -0 "$PRIMARY_PID" 2>/dev/null; do sleep 30; done
fi
echo "[orchestrator] primary finished at $(date -u +%H:%M:%S)Z; starting counterfactuals"

echo "[orchestrator] === counterfactual 1: --no-oranchak-corpora ==="
python3 -u kryptosbot/run_controller.py --no-oranchak-corpora \
  --cycles 12 --theories 8 --workers 4 --timeout 60 \
  --alert-on signal --db db/final_k4_goal_noor.sqlite \
  > "$OUT/controller_noor.log" 2>&1
echo "[orchestrator] counterfactual 1 done (exit $?)"

echo "[orchestrator] === counterfactual 2: --no-serpentine-anchor ==="
python3 -u kryptosbot/run_controller.py --no-serpentine-anchor \
  --cycles 12 --theories 8 --workers 4 --timeout 60 \
  --alert-on signal --db db/final_k4_goal_noserp.sqlite \
  > "$OUT/controller_noserp.log" 2>&1
echo "[orchestrator] counterfactual 2 done (exit $?)"

touch "$OUT/.counterfactuals_complete"
echo "[orchestrator] ALL CONTROLLER RUNS COMPLETE at $(date -u +%H:%M:%S)Z"
