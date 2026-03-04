#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-48: AMSCO / Nihilist / Swapped Columnar at Widths 8-13.

Prior test E-S-22 tested these families at widths 5-8 only (skipped 9+
due to exhaustive limits). This experiment extends coverage to widths 8-13
using FRAC methodology:
  1. Score at discriminating periods ONLY (2-7)
  2. Check Bean constraints (equality + 21 inequalities)
  3. Compare against random baseline (50K random perms)
  4. Apply multiple-testing correction

For each width, we sample column orderings and generate 3 variants:
  - AMSCO start_pattern=1 (alternating 1-2 cells, starting with 1)
  - AMSCO start_pattern=2 (alternating 1-2 cells, starting with 2)
  - Nihilist transposition (long cols in key order, short in reverse)
  - Swapped columnar (write by columns, read by rows)

Width 8: exhaustive (40,320 orderings × 4 variants = ~161K configs)
Width 9+: sample 10K orderings × 4 variants = ~40K configs each
"""
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN  # 97

DISC_PERIODS = [2, 3, 4, 5, 6, 7]


# ═══════════════════════════════════════════════════════════════
# Permutation generators (adapted from E-S-22)
# ═══════════════════════════════════════════════════════════════

def amsco_perm(width, col_order, length, start_pattern=1):
    """AMSCO transposition: alternating 1-2 character cells."""
    grid = []
    pos = 0
    row = 0
    while pos < length:
        row_cells = []
        cell_size = start_pattern if row % 2 == 0 else (3 - start_pattern)
        for col in range(width):
            if pos >= length:
                break
            actual_size = min(cell_size, length - pos)
            positions = list(range(pos, pos + actual_size))
            row_cells.append((col, positions))
            pos += actual_size
            cell_size = 3 - cell_size
        grid.append(row_cells)
        row += 1

    perm = []
    for target_col in col_order:
        for row_cells in grid:
            for col, positions in row_cells:
                if col == target_col:
                    perm.extend(positions)

    if len(perm) != length or sorted(perm) != list(range(length)):
        return None
    return perm


def nihilist_perm(width, col_order, length):
    """Nihilist transposition: long cols forward, short cols reverse."""
    n_rows = (length + width - 1) // width
    extra = length % width

    if extra == 0:
        return None  # Same as standard columnar

    long_cols = set(range(extra))
    perm = []

    for target_col in col_order:
        if target_col in long_cols:
            for r in range(n_rows):
                perm.append(r * width + target_col)

    for target_col in reversed(col_order):
        if target_col not in long_cols:
            for r in range(n_rows - 1):
                perm.append(r * width + target_col)

    if len(perm) != length or sorted(perm) != list(range(length)):
        return None
    return perm


def swapped_columnar_perm(width, col_order, length):
    """Swapped columnar: write by columns in key order, read by rows."""
    n_rows = (length + width - 1) // width
    extra = length % width

    grid = [[None] * width for _ in range(n_rows)]
    pos = 0
    for target_col in col_order:
        col_len = n_rows if (extra == 0 or target_col < extra) else n_rows - 1
        for r in range(col_len):
            grid[r][target_col] = pos
            pos += 1

    if pos != length:
        return None

    perm = []
    for r in range(n_rows):
        for c in range(width):
            if grid[r][c] is not None:
                perm.append(grid[r][c])

    if len(perm) != length or sorted(perm) != list(range(length)):
        return None
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ═══════════════════════════════════════════════════════════════
# Scoring (FRAC methodology: discriminating periods + Bean)
# ═══════════════════════════════════════════════════════════════

def strict_periodic_score(perm, period, variant="vig"):
    """Score transposition perm at given period using majority voting."""
    inv = invert_perm(perm)
    transposed_ct = [CT_NUM[inv[j]] for j in range(N)]

    residue_keys = defaultdict(list)
    for pt_pos in sorted(CRIB_SET):
        ct_val = transposed_ct[pt_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        res = pt_pos % period
        if variant == "vig":
            k = (ct_val - pt_val) % MOD
        else:
            k = (ct_val + pt_val) % MOD
        residue_keys[res].append((pt_pos, k))

    score = 0
    for res, entries in residue_keys.items():
        if not entries:
            continue
        key_counts = Counter(k for _, k in entries)
        majority_key, majority_count = key_counts.most_common(1)[0]
        score += majority_count

    return score


def check_bean(perm, period, variant="vig"):
    """Check Bean constraints for a given perm at given period/variant."""
    inv = invert_perm(perm)
    transposed_ct = [CT_NUM[inv[j]] for j in range(N)]

    key_at = {}
    for pt_pos in sorted(CRIB_SET):
        ct_val = transposed_ct[pt_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        res = pt_pos % period
        if variant == "vig":
            k = (ct_val - pt_val) % MOD
        else:
            k = (ct_val + pt_val) % MOD

        residue_keys = Counter()
        for pp in sorted(CRIB_SET):
            if pp % period == res:
                cv = transposed_ct[pp]
                pv = CRIB_PT_NUM[pp]
                if variant == "vig":
                    kk = (cv - pv) % MOD
                else:
                    kk = (cv + pv) % MOD
                residue_keys[kk] += 1
        majority_key = residue_keys.most_common(1)[0][0]
        key_at[pt_pos] = majority_key

    # Bean equality: k[27] == k[65]
    for eq_a, eq_b in BEAN_EQ:
        if eq_a in key_at and eq_b in key_at:
            if key_at[eq_a] != key_at[eq_b]:
                return False

    # Bean inequalities
    for ineq_a, ineq_b in BEAN_INEQ:
        if ineq_a in key_at and ineq_b in key_at:
            if key_at[ineq_a] == key_at[ineq_b]:
                return False

    return True


def best_score_across_configs(perm):
    """Get best (score, period, variant, bean_pass) across all configs."""
    best = (0, 0, "", False)
    for period in DISC_PERIODS:
        for variant in ["vig", "beau"]:
            score = strict_periodic_score(perm, period, variant)
            if score > best[0]:
                bean = check_bean(perm, period, variant)
                best = (score, period, variant, bean)
    return best


# ═══════════════════════════════════════════════════════════════
# Random baseline
# ═══════════════════════════════════════════════════════════════

def random_baseline(n_samples=50000):
    """Generate random baseline distribution."""
    print(f"\n  Random baseline: {n_samples:,} permutations...")
    scores = []
    base = list(range(N))
    for i in range(n_samples):
        perm = base[:]
        random.shuffle(perm)
        s, _, _, _ = best_score_across_configs(perm)
        scores.append(s)
        if (i + 1) % 10000 == 0:
            print(f"    {i+1:,}/{n_samples:,} done, max so far: {max(scores)}")
    return scores


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("E-FRAC-48: AMSCO / Nihilist / Swapped Columnar (widths 8-13)")
    print("=" * 60)
    print(f"CT length: {N}")
    print(f"Discriminating periods: {DISC_PERIODS}")
    print(f"Variants: Vigenère, Beaufort")
    print()

    random.seed(42)
    t0 = time.time()

    # Generate random baseline
    baseline_scores = random_baseline(50000)
    baseline_max = max(baseline_scores)
    baseline_dist = Counter(baseline_scores)
    print(f"  Baseline max: {baseline_max}/24")
    print(f"  Baseline distribution (top): ", end="")
    for s in sorted(baseline_dist.keys(), reverse=True)[:5]:
        print(f"{s}:{baseline_dist[s]} ", end="")
    print()

    results_by_width = {}
    total_perms = 0
    overall_best = (0, "", 0, "", False)  # (score, family, period, variant, bean)

    for width in range(8, 14):
        n_orderings = math.factorial(width)
        exhaustive = n_orderings <= 50000

        if exhaustive:
            n_sample = n_orderings
            print(f"\n{'='*60}")
            print(f"  Width {width}: EXHAUSTIVE ({n_orderings:,} orderings × 4 variants)")
            print(f"{'='*60}")
        else:
            n_sample = 10000
            print(f"\n{'='*60}")
            print(f"  Width {width}: SAMPLING {n_sample:,} of {n_orderings:,} orderings × 4 variants")
            print(f"{'='*60}")

        # Generate column orderings
        if exhaustive:
            from itertools import permutations as iter_perms
            orderings = [list(p) for p in iter_perms(range(width))]
        else:
            orderings = []
            seen = set()
            while len(orderings) < n_sample:
                order = list(range(width))
                random.shuffle(order)
                key = tuple(order)
                if key not in seen:
                    seen.add(key)
                    orderings.append(order)

        width_best = (0, "", 0, "", False)
        width_scores = []
        width_bean_pass = 0
        n_valid = 0

        for oi, col_order in enumerate(orderings):
            # Generate all variants
            variants = []

            p = amsco_perm(width, col_order, N, start_pattern=1)
            if p is not None:
                variants.append(("AMSCO_sp1", p))

            p = amsco_perm(width, col_order, N, start_pattern=2)
            if p is not None:
                variants.append(("AMSCO_sp2", p))

            p = nihilist_perm(width, col_order, N)
            if p is not None:
                variants.append(("Nihilist", p))

            p = swapped_columnar_perm(width, col_order, N)
            if p is not None:
                variants.append(("Swapped", p))

            for family, perm in variants:
                n_valid += 1
                s, per, var, bean = best_score_across_configs(perm)
                width_scores.append(s)
                if bean:
                    width_bean_pass += 1
                if s > width_best[0]:
                    width_best = (s, family, per, var, bean)

            if (oi + 1) % 5000 == 0:
                print(f"    {oi+1:,}/{len(orderings):,} orderings, "
                      f"best: {width_best[0]}/24 ({width_best[1]}, "
                      f"p{width_best[2]} {width_best[3]}), "
                      f"Bean pass: {width_bean_pass}")

        total_perms += n_valid
        score_dist = Counter(width_scores)

        # Multiple-testing correction
        p_trial = sum(1 for s in baseline_scores if s >= width_best[0]) / len(baseline_scores)
        p_corrected = 1.0 - (1.0 - p_trial) ** n_valid if p_trial < 1.0 else 1.0

        # Expected max from n_valid random draws
        p_baseline_exceed = sum(1 for s in baseline_scores if s >= width_best[0]) / len(baseline_scores)

        results_by_width[width] = {
            "n_orderings": len(orderings),
            "n_valid_perms": n_valid,
            "exhaustive": exhaustive,
            "best_score": width_best[0],
            "best_family": width_best[1],
            "best_period": width_best[2],
            "best_variant": width_best[3],
            "best_bean": width_best[4],
            "bean_pass_count": width_bean_pass,
            "bean_pass_rate": width_bean_pass / n_valid if n_valid > 0 else 0,
            "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
            "p_trial": p_trial,
            "p_corrected": p_corrected,
        }

        print(f"\n  Width {width} RESULT:")
        print(f"    Valid permutations tested: {n_valid:,}")
        print(f"    Best: {width_best[0]}/24 ({width_best[1]}, p{width_best[2]} {width_best[3]}, "
              f"Bean={'PASS' if width_best[4] else 'FAIL'})")
        print(f"    Bean pass: {width_bean_pass}/{n_valid} ({100*width_bean_pass/n_valid:.1f}%)")
        print(f"    Score distribution: ", end="")
        for s in sorted(score_dist.keys(), reverse=True)[:6]:
            print(f"{s}:{score_dist[s]} ", end="")
        print()
        print(f"    p(trial): {p_trial:.6f}, p(corrected): {p_corrected:.6f}")
        print(f"    Random baseline max: {baseline_max}/24")
        if width_best[0] <= baseline_max:
            print(f"    VERDICT: UNDERPERFORMS or matches random baseline → NOISE")
        else:
            print(f"    VERDICT: EXCEEDS random baseline — investigate further")

        if width_best[0] > overall_best[0]:
            overall_best = width_best

    elapsed = time.time() - t0

    # Final summary
    print(f"\n{'='*60}")
    print(f"FINAL SUMMARY")
    print(f"{'='*60}")
    print(f"Total permutations tested: {total_perms:,}")
    print(f"Overall best: {overall_best[0]}/24 ({overall_best[1]}, "
          f"p{overall_best[2]} {overall_best[3]}, "
          f"Bean={'PASS' if overall_best[4] else 'FAIL'})")
    print(f"Random baseline max: {baseline_max}/24")
    print(f"Time: {elapsed:.1f}s")
    print()

    if overall_best[0] <= baseline_max:
        print("CONCLUSION: AMSCO/Nihilist/Swapped at widths 8-13 produce AT MOST")
        print(f"  {overall_best[0]}/24 — same as or below random baseline ({baseline_max}/24).")
        print("  ALL families ELIMINATED as noise.")
    else:
        print(f"CONCLUSION: Best {overall_best[0]}/24 EXCEEDS baseline {baseline_max}/24 — investigate.")

    # Save results
    os.makedirs("results/frac", exist_ok=True)
    output = {
        "experiment": "E-FRAC-48",
        "description": "AMSCO/Nihilist/Swapped Columnar at widths 8-13",
        "methodology": "FRAC: discriminating periods 2-7, Bean constraints, random baseline, MTC",
        "total_perms_tested": total_perms,
        "overall_best_score": overall_best[0],
        "overall_best_family": overall_best[1],
        "overall_best_period": overall_best[2],
        "overall_best_variant": overall_best[3],
        "overall_best_bean": overall_best[4],
        "baseline_max": baseline_max,
        "baseline_distribution": {str(k): v for k, v in sorted(Counter(baseline_scores).items())},
        "results_by_width": results_by_width,
        "elapsed_seconds": elapsed,
        "conclusion": "ALL ELIMINATED" if overall_best[0] <= baseline_max else "INVESTIGATE",
    }

    with open("results/frac/e_frac_48_amsco_disrupted.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nArtifact: results/frac/e_frac_48_amsco_disrupted.json")


if __name__ == "__main__":
    main()
