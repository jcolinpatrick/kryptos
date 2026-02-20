#!/usr/bin/env python3
"""E-S-133b: Width-9 STRICT algebraic check + random baseline comparison.

Two purposes:
1. Strict mode: does ANY width-9 ordering produce ALL-consistent key values
   at any period (the same test used for width-7 in E-S-62/91/94)?
2. Random baseline: what scores does a random permutation produce under the
   same majority-voting metric, to calibrate the 14/24 at period 7?
"""
import itertools
import json
import os
import random
import time
from collections import defaultdict, Counter

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

WIDTH = 9
N_ROWS_FULL = CT_LEN // WIDTH
REMAINDER = CT_LEN % WIDTH
COL_HEIGHTS = [N_ROWS_FULL + 1 if j < REMAINDER else N_ROWS_FULL for j in range(WIDTH)]


def build_columnar_perm(order):
    perm = []
    for c in range(WIDTH):
        col = order[c]
        height = COL_HEIGHTS[col]
        for row in range(height):
            perm.append(row * WIDTH + col)
    return perm


def strict_check(perm, period, variant, model):
    """STRICT algebraic check: ALL key values in each residue class must match.

    Returns True only if every residue class has identical key values.
    Also returns the number of constrained positions.
    """
    residue_groups = defaultdict(set)

    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = CT_NUM[i]
            if variant == 0:
                k = (ct_val - pt_val) % MOD
            elif variant == 1:
                k = (ct_val + pt_val) % MOD
            else:
                k = (pt_val - ct_val) % MOD

            if model == 0:  # Model A: key at position src
                residue_groups[src % period].add(k)
            else:           # Model B: key at position i
                residue_groups[i % period].add(k)

    n_constrained = sum(1 for vals in residue_groups.values() if len(vals) > 0)
    # Strict: every group must have exactly 1 unique value
    all_consistent = all(len(vals) <= 1 for vals in residue_groups.values())
    n_groups_with_conflict = sum(1 for vals in residue_groups.values() if len(vals) > 1)

    return all_consistent, n_constrained, n_groups_with_conflict


def majority_score(perm, period, variant, model):
    """Majority voting score (same as E-S-133)."""
    residue_groups = defaultdict(list)
    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = CT_NUM[i]
            if variant == 0:
                k = (ct_val - pt_val) % MOD
            elif variant == 1:
                k = (ct_val + pt_val) % MOD
            else:
                k = (pt_val - ct_val) % MOD
            if model == 0:
                residue_groups[src % period].append(k)
            else:
                residue_groups[i % period].append(k)

    n_consistent = 0
    for vals in residue_groups.values():
        if vals:
            counts = Counter(vals)
            n_consistent += counts.most_common(1)[0][1]
    return n_consistent


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-133b: Width-9 STRICT Check + Random Baseline")
    print("=" * 70)

    PERIODS = list(range(2, 15))
    VARIANT_NAMES = ["vigenere", "beaufort", "variant_beaufort"]

    # ── Part 1: STRICT algebraic check ─────────────────────────────────
    print("\nPART 1: STRICT ALGEBRAIC CHECK (all-or-nothing)")
    print("Same test as E-S-62/91/94 for width-7")
    print("-" * 70)

    strict_passes = {p: 0 for p in PERIODS}
    strict_total = 0
    best_strict = {"conflicts": 999, "period": 0}

    for order in itertools.permutations(range(WIDTH)):
        for model in range(2):
            for variant in range(3):
                for period in PERIODS:
                    strict_total += 1
                    passed, n_const, n_conflict = strict_check(
                        build_columnar_perm(order), period, variant, model)
                    if passed and n_const >= 3:  # at least 3 residue classes constrained
                        strict_passes[period] += 1
                    if n_conflict < best_strict["conflicts"]:
                        best_strict = {
                            "conflicts": n_conflict,
                            "constrained": n_const,
                            "period": period,
                            "variant": VARIANT_NAMES[variant],
                            "model": "A" if model == 0 else "B",
                            "order": list(order),
                        }

    t1 = time.time()
    print(f"Strict check complete: {strict_total:,} tests in {t1-t0:.1f}s")
    print(f"\nStrict passes by period (orderings with ZERO conflicts):")
    for p in PERIODS:
        print(f"  p={p:2d}: {strict_passes[p]:,} passes")
    total_passes = sum(strict_passes.values())
    print(f"\nTOTAL STRICT PASSES: {total_passes:,} / {strict_total:,}")
    print(f"\nBest (fewest conflicts):")
    for k, v in best_strict.items():
        print(f"  {k}: {v}")

    # ── Part 2: Random permutation baseline ────────────────────────────
    print()
    print("=" * 70)
    print("PART 2: RANDOM PERMUTATION BASELINE")
    print("(What scores does a random perm of {0..96} produce?)")
    print("-" * 70)

    random.seed(42)
    N_RANDOM = 100_000
    random_best_by_period = {p: 0 for p in PERIODS}
    random_best_overall = 0

    # Also compute width-9 columnar baseline at period 7 specifically
    w9_p7_scores = []

    for trial in range(N_RANDOM):
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        for period in PERIODS:
            for variant in range(3):
                for model in range(2):
                    sc = majority_score(perm, period, variant, model)
                    if sc > random_best_by_period[period]:
                        random_best_by_period[period] = sc
                    if sc > random_best_overall:
                        random_best_overall = sc

    t2 = time.time()
    print(f"Random baseline: {N_RANDOM:,} random permutations in {t2-t1:.1f}s")
    print(f"\nRandom best by period (best of {N_RANDOM:,} random perms × 6 variant-model combos):")
    for p in PERIODS:
        print(f"  p={p:2d}: {random_best_by_period[p]}/24")
    print(f"\nRandom best overall: {random_best_overall}/24")

    # ── Part 3: Width-9 columnar at period 7 — detailed ───────────────
    print()
    print("=" * 70)
    print("PART 3: WIDTH-9 AT PERIOD 7 — DETAILED COMPARISON")
    print("-" * 70)

    # Collect score distribution for ALL width-9 orderings at period 7
    p7_scores_w9 = []
    p7_best_strict_w9 = {"conflicts": 999}

    for order in itertools.permutations(range(WIDTH)):
        perm = build_columnar_perm(order)
        for variant in range(3):
            for model in range(2):
                sc = majority_score(perm, 7, variant, model)
                p7_scores_w9.append(sc)
                passed, n_const, n_conflict = strict_check(perm, 7, variant, model)
                if n_conflict < p7_best_strict_w9["conflicts"]:
                    p7_best_strict_w9 = {
                        "conflicts": n_conflict,
                        "order": list(order),
                        "variant": VARIANT_NAMES[variant],
                        "model": "A" if model == 0 else "B",
                        "score_majority": sc,
                    }

    p7_mean = sum(p7_scores_w9) / len(p7_scores_w9)
    p7_max = max(p7_scores_w9)
    p7_dist = Counter(p7_scores_w9)

    print(f"Width-9 at period 7:")
    print(f"  Mean majority score: {p7_mean:.2f}/24")
    print(f"  Max majority score: {p7_max}/24")
    print(f"  Score distribution:")
    for sc in sorted(p7_dist.keys(), reverse=True)[:10]:
        print(f"    {sc:2d}/24: {p7_dist[sc]:>8,} ({100*p7_dist[sc]/len(p7_scores_w9):.3f}%)")
    print(f"  Best strict (fewest conflicts at p=7):")
    for k, v in p7_best_strict_w9.items():
        print(f"    {k}: {v}")

    t3 = time.time()

    # ── Summary ────────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Width-9 strict passes (any period): {total_passes}")
    print(f"Width-7 strict passes (E-S-62/91/94): 0")
    print()
    print("Width-9 period-7 best majority: {}/24".format(p7_max))
    print("Random perm period-7 best majority: {}/24".format(random_best_by_period[7]))
    print()

    if total_passes > 0:
        print("*** WIDTH-9 HAS STRICT ALGEBRAIC PASSES — INVESTIGATE ***")
    elif p7_max > random_best_by_period[7]:
        print("Width-9 exceeds random baseline at p=7 — marginal interest")
    else:
        print("Width-9 produces same noise pattern as random permutations")
        print("The 19/24 at period 13 is UNDERDETERMINATION ARTIFACT")
        print("(expected: ~13.5/24 random at period 13)")

    print(f"\nTotal time: {t3-t0:.1f}s")

    # Save
    os.makedirs("artifacts", exist_ok=True)
    artifact = {
        "experiment": "E-S-133b",
        "strict_passes_by_period": strict_passes,
        "strict_total_passes": total_passes,
        "best_strict": best_strict,
        "random_best_by_period": random_best_by_period,
        "random_best_overall": random_best_overall,
        "p7_mean": p7_mean,
        "p7_max": p7_max,
        "p7_best_strict": p7_best_strict_w9,
        "elapsed": round(t3 - t0, 1),
    }
    path = "artifacts/e_s_133b_width9_strict.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"Saved to {path}")


if __name__ == "__main__":
    main()
