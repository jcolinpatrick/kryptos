#!/usr/bin/env python3
"""Profile Bean INEQ rejection rate across periods 1-26 for TABP.

Determines where the Bean INEQ filter stops discriminating, to set
MAX_PERIOD intelligently. Also profiles missing-residue counts per period
to understand enumeration cost at larger periods.
"""
from __future__ import annotations

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CRIB_POSITIONS, CT_LEN
from kryptos.kernel.constraints.bean import rederive_bean_for_transposition

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from f_tabp_transposition_outer_v1 import enumerate_all_transpositions


def profile(sample_size: int = 500) -> None:
    all_ts = enumerate_all_transpositions()[:sample_size]
    print(f"Profiling {len(all_ts)} Ts across periods 1..26\n")

    per_period_stats = {p: {"total": 0, "bean_pass": 0, "missing_hist": [0] * 6}
                        for p in range(1, 27)}

    for label, pt_to_ct in all_ts:
        try:
            _eq, ineq = rederive_bean_for_transposition(pt_to_ct)
        except Exception:
            continue

        # Displaced crib positions in CT coordinates
        displaced = [pt_to_ct[k] for k in sorted(CRIB_POSITIONS)]

        for period in range(1, 27):
            per_period_stats[period]["total"] += 1
            # Bean INEQ check
            violated = any((a % period) == (b % period) for a, b in ineq)
            if violated:
                continue
            per_period_stats[period]["bean_pass"] += 1

            # Count how many residue classes are covered by crib positions
            covered = set(d % period for d in displaced)
            missing = period - len(covered)
            if missing < 6:
                per_period_stats[period]["missing_hist"][missing] += 1

    print(f"{'Period':>6}  {'Total':>6}  {'BeanPass':>9}  {'Pct':>7}  "
          f"{'Missing residues (0,1,2,3,4,5+)':<40}")
    print("-" * 80)
    for p in range(1, 27):
        s = per_period_stats[p]
        pct = 100 * s["bean_pass"] / max(1, s["total"])
        hist = "  ".join(f"{c:>4}" for c in s["missing_hist"])
        print(f"{p:>6}  {s['total']:>6}  {s['bean_pass']:>9}  {pct:>6.2f}%  {hist}")


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--sample", type=int, default=500)
    args = p.parse_args()
    profile(args.sample)
