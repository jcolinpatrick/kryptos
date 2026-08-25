#!/usr/bin/env python3
"""
e_crib_31_filter_power_analysis
===============================

FAMILY: crib_analysis
STATUS: active

WHY THIS EXISTS
---------------
A mechanism sweep using the attainable-crib-ceiling filter reported ZERO
survivors at every hypothesised crib level (L1-L5) across ~3.5 billion
configurations spanning direct-periodic, columnar, keyword-transposition and
geometric-route families. Read naively that says "the extended crib set
eliminates the entire classical mechanism space".

That reading is wrong, and this script is the control that shows why.

Survival requires EVERY residue class to be internally consistent. With n cribs
spread over p residue classes, roughly (n - p) independent coincidences at 1/26
each are needed, so the expected number of survivors is about

    N_configs * 26^-(n - n_classes)

At L0 (n=24) with period >= 26 every crib lands in its own class and the
ceiling is 24 automatically: the filter is VACUOUS there, which is what the
"millions of L0 survivors" actually are. At L1 (n=42) and L4/L5 (n=74) the
swept periods (mostly <= 30) sit far below n, so zero survivors is exactly what
a UNIFORM RANDOM PERMUTATION produces.

WHAT SURVIVES THE CORRECTION, AND WHAT DOES NOT
-----------------------------------------------
NOT VALID:  "the extended cribs eliminate the columnar family" (or routes, or
            keyword transposition). Everything is eliminated, including things
            that were never candidates, so no family-specific claim is earned.

STILL VALID: the disjunction. The true configuration would survive by
            construction, because ceiling == n holds identically for the truth.
            This is confirmed empirically on real data in
            scripts/lib/test_crib_filter_real_panels.py, where at n=42 the
            filter recovers K1's true period 10 and K2's true period 8 while
            leaving only 0.53% of configurations standing. So:

                either K4's mechanism lies outside the swept space,
                or the plaintext hypothesis is false.

CONSTRUCTIVE COROLLARY (the actually useful output)
---------------------------------------------------
If the opening hypothesis is TRUE, then K4 cannot be a single periodic additive
layer of period <= ~42 behind any transposition in the swept set, because such a
mechanism would have been found. That pushes K4 toward a long or aperiodic key
(finite tape), a null mask (which changes the alignment itself), or a
non-additive mechanism -- which is precisely the repo's stated open frontier.

Repro:
  PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_31_filter_power_analysis.py
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import ceiling, sub_outer  # noqa: E402
from crib_sets import DESCRIPTIONS, level  # noqa: E402
from kryptos.kernel.constants import CT  # noqa: E402

LEVELS = ("L0_released", "L1_opening", "L3_layoutB_x34", "L4_layoutA_reset")
PERIODS = (10, 20, 26, 30, 42, 45, 60, 74, 80)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=4000)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    print("=" * 92)
    print("FILTER POWER ANALYSIS — is a zero-survivor result informative?")
    print("=" * 92)
    print(f"  matched null: {args.trials:,} uniform random 97-permutations per cell")
    print("  NOTE: the 'classes' and '26^-(n-cls)' columns are computed for the DIRECT")
    print("  alignment and are a rough guide only. Under a random permutation the crib")
    print("  indices scatter over 0..96 and collide more, so the empirical random-survival")
    print("  column is the authoritative one -- e.g. L4 p=74 shows classes=74 yet 0% survival.")
    print()
    print(f"  {'level':<18} {'n':>3} {'period':>7} {'classes':>8} {'26^-(n-cls)':>12} "
          f"{'random survival':>18}")
    print("  " + "-" * 78)
    out = {}
    for lname in LEVELS:
        d = level(lname)
        n = len(d)
        for p in PERIODS:
            cls = len({q % p for q in d})
            exp = 26.0 ** (-(n - cls)) if n > cls else 1.0
            surv = 0
            for _ in range(args.trials):
                wp = list(range(97))
                rng.shuffle(wp)
                a, c = sub_outer(wp, p)
                cc, _ = ceiling(CT, d, a, c)
                if cc == n:
                    surv += 1
            out[f"{lname}|p{p}"] = {"n": n, "classes": cls, "expected_factor": exp,
                                    "random_survivors": surv, "trials": args.trials}
            print(f"  {lname:<18} {n:>3} {p:>7} {cls:>8} {exp:>12.2e} "
                  f"{surv:>8}/{args.trials} = {surv/args.trials:>7.4f}")
        print()

    print("=" * 92)
    print("CONCLUSION")
    print("=" * 92)
    print("  A sweep that reports zero survivors at a (level, period) cell whose")
    print("  RANDOM survival rate is also zero has learned nothing family-specific.")
    print("  It has, however, still established the disjunction: the truth would")
    print("  have survived. Both statements must be reported together.")
    print()
    print("  Operational rule: never report a ceiling-filter elimination without the")
    print("  matched random-permutation survival rate for the same (n_cribs, period).")

    art = os.path.join(_ROOT, "results", "e_crib_31_filter_power_analysis.json")
    with open(art, "w") as fh:
        json.dump({"cells": out, "trials": args.trials,
                   "levels": {k: DESCRIPTIONS[k] for k in LEVELS}}, fh, indent=2)
    print(f"\nartifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
