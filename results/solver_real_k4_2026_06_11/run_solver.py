"""First clue-bounded solver run against real K4.

Prereg: docs/campaigns/solver_clue_bounded_real_k4_2026_06_11.md
"""
import dataclasses
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from kryptosbot.solver import solve_real_k4

t0 = time.time()
res = solve_real_k4(max_rounds=2, max_keywords=12)
elapsed = time.time() - t0

out = dataclasses.asdict(res)
out["wall_time_sec"] = elapsed
out["git_head"] = subprocess.run(
    ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True
).stdout.strip()
out["prereg"] = "docs/campaigns/solver_clue_bounded_real_k4_2026_06_11.md"
out["campaign_id"] = "f_solver_clue_bounded_real_k4_2026_06_11"

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "solve_result.json")
with open(path, "w") as f:
    json.dump(out, f, indent=2)
print(json.dumps({k: out[k] for k in ("solved", "best_score", "n_cribs", "specs_tried", "configs_tried", "rounds", "wall_time_sec")}, indent=2))
print("written:", path)
