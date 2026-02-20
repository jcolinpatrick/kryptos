#!/usr/bin/env python3
"""E-FRAC-08: Bimodal Fingerprint Compatibility Across All Widths.

Following the critical finding from E-FRAC-07 that width-9 columnar is
incompatible with the bimodal fingerprint, this experiment systematically
tests which widths ARE compatible.

For each width w (2-20):
1. Build all columnar permutations (exhaustive for w≤10, sampled for w>10)
2. Check bimodal fingerprint at the standard tolerance (positions 22-30
   within ±5, positions 64-74 not all near-identity)
3. Report which widths have ANY compatible orderings

This identifies the viable search space for the TRANS and JTS agents.
"""
import itertools
import json
import math
import os
import random
import time
from collections import Counter

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
random.seed(42)


def build_columnar_perm(width, order):
    n_rows = CT_LEN // width
    remainder = CT_LEN % width
    col_heights = [n_rows + 1 if j < remainder else n_rows for j in range(width)]
    perm = []
    for c in range(width):
        col = order[c]
        height = col_heights[col]
        for row in range(height):
            perm.append(row * width + col)
    return perm


def bimodal_check(perm, ene_tolerance=5, bc_max_identity=4):
    """Standard bimodal check: positions 22-30 near-identity, 64-74 scattered."""
    # perm[i] = source PT position for CT position i
    ene_pass = True
    for i in range(22, 31):
        if i < CT_LEN:
            if abs(perm[i] - i) > ene_tolerance:
                ene_pass = False
                break

    bc_identity = 0
    for i in range(64, min(75, CT_LEN)):
        if abs(perm[i] - i) <= 2:
            bc_identity += 1
    bc_pass = bc_identity <= bc_max_identity

    return ene_pass and bc_pass


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-08: Bimodal Fingerprint Across All Widths")
    print("=" * 70)
    print("Tolerance: ENE ±5, BC identity ≤4")
    print()

    results = {}

    for width in range(2, 21):
        n_total = math.factorial(width)
        exhaustive = n_total <= 5000000  # ~10! = 3.6M is feasible

        if exhaustive:
            n_tested = n_total
            orderings = itertools.permutations(range(width))
        else:
            n_tested = 100000
            orderings = (tuple(random.sample(range(width), width))
                         for _ in range(n_tested))

        n_pass = 0
        n_checked = 0

        for order in orderings:
            perm = build_columnar_perm(width, order)
            if bimodal_check(perm):
                n_pass += 1
            n_checked += 1

        pct = 100 * n_pass / n_checked if n_checked > 0 else 0
        mode = "exhaustive" if exhaustive else f"sampled ({n_tested:,})"
        indicator = "✓" if n_pass > 0 else "✗"

        # Grid info
        n_rows = CT_LEN // width
        remainder = CT_LEN % width
        col_heights_summary = (f"{remainder}×{n_rows+1} + "
                               f"{width-remainder}×{n_rows}"
                               if remainder > 0
                               else f"{width}×{n_rows}")

        results[width] = {
            "n_tested": n_checked,
            "n_pass": n_pass,
            "pct": round(pct, 4),
            "mode": mode,
            "grid": col_heights_summary,
            "n_total_orderings": n_total,
        }

        print(f"  w={width:2d} [{indicator}]: {n_pass:>8,}/{n_checked:>8,} pass "
              f"({pct:8.4f}%) — {mode} — grid: {col_heights_summary}")

    # ── Summary ─────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    compatible_widths = [w for w, r in results.items() if r["n_pass"] > 0]
    incompatible_widths = [w for w, r in results.items() if r["n_pass"] == 0]

    print(f"\nBimodal-COMPATIBLE widths: {compatible_widths}")
    print(f"Bimodal-INCOMPATIBLE widths: {incompatible_widths}")
    print()

    if compatible_widths:
        print("Pass rates for compatible widths:")
        for w in compatible_widths:
            r = results[w]
            # Estimate total compatible orderings
            if r["mode"].startswith("exhaustive"):
                total_compat = r["n_pass"]
            else:
                total_compat = int(r["pct"] / 100 * r["n_total_orderings"])
            print(f"  w={w:2d}: {r['n_pass']:,} ({r['pct']:.4f}%), "
                  f"estimated total: ~{total_compat:,}")

    print(f"\nTotal time: {elapsed:.1f}s")

    # Key insight
    print()
    print("KEY INSIGHT:")
    if 7 in compatible_widths:
        print("  Width-7 IS bimodal-compatible — this supports the TRANS agent's")
        print("  focus on width-7 as the primary transposition candidate.")
    if 9 not in compatible_widths:
        print("  Width-9 is NOT bimodal-compatible — confirming E-FRAC-07.")
    print()
    print("  RECOMMENDATION: TRANS and JTS agents should focus on widths")
    print(f"  {compatible_widths} for columnar transposition search.")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-08",
        "description": "Bimodal fingerprint compatibility across all widths (2-20)",
        "tolerance": {"ene": 5, "bc_max_identity": 4},
        "results": {str(k): v for k, v in results.items()},
        "compatible_widths": compatible_widths,
        "incompatible_widths": incompatible_widths,
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_08_bimodal_multiwidth.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
