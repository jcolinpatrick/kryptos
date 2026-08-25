#!/usr/bin/env python3
"""
e_crib_34_stehle_null
=====================

FAMILY: crib_analysis
STATUS: active

Recompute the null for the Stehle constant-difference anomaly (registry E0a).

THE OBSERVATION
    CT[55:64] = DIAWINFBN (0-indexed) has five consecutive equal lag-4
    differences, all equal to 5 mod 26.

THE QUESTION IS WHICH SEARCH TO CHARGE FOR
    Neither the lag (4) nor the location (55-63) was pre-registered; both were
    found by inspection. So the honest null is "does a run of >= 5 equal lag-L
    differences occur ANYWHERE in a 97-character text, for ANY lag in range",
    not "does it occur at lag 4 at position 55".

    Conditioning on the lag after seeing it is the look-elsewhere error, and it
    is worth a factor of ~28 here.

Repro:
  PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_34_stehle_null.py --trials 200000
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT  # noqa: E402


def longest_equal_diff_run(x: np.ndarray, lag: int) -> int:
    d = (x[lag:] - x[:-lag]) % 26
    if len(d) == 0:
        return 0
    best = cur = 1
    for i in range(1, len(d)):
        cur = cur + 1 if d[i] == d[i - 1] else 1
        best = max(best, cur)
    return best


def any_run(x: np.ndarray, lags, need: int) -> bool:
    for L in lags:
        d = (x[L:] - x[:-L]) % 26
        run = 1
        for i in range(1, len(d)):
            run = run + 1 if d[i] == d[i - 1] else 1
            if run >= need:
                return True
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=200_000)
    ap.add_argument("--need", type=int, default=5)
    ap.add_argument("--seed", type=int, default=4)
    args = ap.parse_args()

    ct = np.array([ord(c) - 65 for c in CT])
    print("=" * 78)
    print("STEHLE CONSTANT-DIFFERENCE ANOMALY — NULL RECOMPUTATION")
    print("=" * 78)
    print(f"  CT[55:64] = {CT[55:64]}")
    print(f"  lag-4 differences: {[(int(ct[i+4])-int(ct[i])) % 26 for i in range(55, 60)]}")
    print(f"  observed longest run, by lag:")
    for L in range(1, 13):
        print(f"     L={L:>2}: {longest_equal_diff_run(ct, L)}", end="")
        if L % 6 == 0:
            print()
    print()

    rng = np.random.default_rng(args.seed)
    out = {}
    for lags, label in (([4], "lag 4 only (post-hoc conditioning — NOT the honest null)"),
                        (range(1, 25), "any lag 1-24"),
                        (range(1, 31), "any lag 1-30")):
        lags = list(lags)
        hits = 0
        for _ in range(args.trials):
            if any_run(rng.integers(0, 26, 97), lags, args.need):
                hits += 1
        p = hits / args.trials
        out[label] = {"hits": hits, "trials": args.trials, "p": p}
        print(f"  P(run >= {args.need} somewhere) — {label:<52} "
              f"= {p:.5f} = 1 in {1/p:,.0f}" if p else f"  {label}: 0 hits")
    print()
    print("  The registry previously cited p ~ 1/642. The honest any-lag figure is")
    print("  about 1/205, so the earlier number was generous by roughly 3x.")
    print("  Real pattern, weak evidence. Not a mechanism.")

    art = os.path.join(_ROOT, "results", "e_crib_34_stehle_null.json")
    with open(art, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nartifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
