#!/usr/bin/env python3
"""E-FRAC-06: Width-11 and Width-13 Structural Analysis + Periodic Sweep.

Tests columnar transposition at widths 11 and 13 — noted as having
"sparse prior coverage" in the TRANS agent's priority matrix.

97 = 11×8 + 9  → 11 columns (9 of height 9, 2 of height 8)
97 = 13×7 + 6  → 13 columns (6 of height 8, 7 of height 7)

For each width:
1. Structural analysis (same as E-FRAC-01): lag correlations,
   Bean constraint passes, per-column IC
2. Full exhaustive sweep of all orderings at low periods (2-7)
   with strict periodic consistency check
3. Random baseline comparison

Width-11: 11! = 39,916,800 orderings — too many for exhaustive.
  Strategy: sample 50,000 random orderings + keyword orderings.
Width-13: 13! = 6,227,020,800 — way too many.
  Strategy: sample 50,000 random orderings + keyword orderings.

Usage: PYTHONPATH=src python3 -u scripts/e_frac_06_w11w13_structural.py
"""
import itertools
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

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


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def compute_lag_matches(seq, lag):
    return sum(1 for i in range(len(seq) - lag) if seq[i] == seq[i + lag])


def compute_lag_z(matches, n, lag):
    expected = (n - lag) / 26.0
    variance = (n - lag) * (1.0 / 26.0) * (25.0 / 26.0)
    if variance <= 0:
        return 0.0
    return (matches - expected) / math.sqrt(variance)


def check_bean(perm, variant):
    inv = invert_perm(perm)
    ct_27 = inv[27]
    ct_65 = inv[65]
    pt27 = CRIB_PT_NUM[27]
    pt65 = CRIB_PT_NUM[65]
    if variant == 0:
        k27 = (CT_NUM[ct_27] - pt27) % MOD
        k65 = (CT_NUM[ct_65] - pt65) % MOD
    elif variant == 1:
        k27 = (CT_NUM[ct_27] + pt27) % MOD
        k65 = (CT_NUM[ct_65] + pt65) % MOD
    else:
        k27 = (pt27 - CT_NUM[ct_27]) % MOD
        k65 = (pt65 - CT_NUM[ct_65]) % MOD
    if k27 != k65:
        return False
    for a, b in BEAN_INEQ:
        if a in CRIB_SET and b in CRIB_SET:
            ct_a = inv[a]
            ct_b = inv[b]
            if variant == 0:
                ka = (CT_NUM[ct_a] - CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] - CRIB_PT_NUM[b]) % MOD
            elif variant == 1:
                ka = (CT_NUM[ct_a] + CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] + CRIB_PT_NUM[b]) % MOD
            else:
                ka = (CRIB_PT_NUM[a] - CT_NUM[ct_a]) % MOD
                kb = (CRIB_PT_NUM[b] - CT_NUM[ct_b]) % MOD
            if ka == kb:
                return False
    return True


def strict_periodic_check(perm, period, variant, model):
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
            if model == 0:
                residue_groups[src % period].add(k)
            else:
                residue_groups[i % period].add(k)
    n_constrained = sum(1 for vals in residue_groups.values() if vals)
    n_conflicts = sum(1 for vals in residue_groups.values() if len(vals) > 1)
    return n_conflicts == 0, n_constrained, n_conflicts


def majority_score(perm, period, variant, model):
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


def generate_keyword_orderings(width, keywords):
    """Generate column orderings from keywords."""
    orderings = set()
    for kw in keywords:
        kw = kw.upper()[:width]
        if len(kw) < width:
            # Pad with unique letters
            remaining = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if c not in kw]
            kw = kw + "".join(remaining[:width - len(kw)])
        order = tuple(sorted(range(width), key=lambda i: (kw[i], i)))
        orderings.add(order)
    return list(orderings)


def analyze_width(width, n_samples):
    """Run full analysis for a given width."""
    print(f"\n{'='*70}")
    print(f"WIDTH-{width} ANALYSIS")
    print(f"{'='*70}")

    n_rows = CT_LEN // width
    remainder = CT_LEN % width
    col_heights = [n_rows + 1 if j < remainder else n_rows for j in range(width)]
    print(f"Grid: {width} columns, rows: {n_rows}+1 partial")
    print(f"Column heights: {col_heights}")
    print(f"Verify: {sum(col_heights)} = {CT_LEN}")
    print(f"Total orderings: {width}! = {math.factorial(width):,}")
    print(f"Sample size: {n_samples:,}")
    print()

    # Generate orderings
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN",
                "SHADOWS", "CLOCK", "NORTHEAST", "LAYER",
                "NORTHWEST", "SOUTHEAST", "SOUTHWEST",
                "VIRTUALLY", "INVISIBLE", "UNDERGRUUND",
                "SLOWLY", "DESPARATLY"]
    kw_orderings = generate_keyword_orderings(width, keywords)

    # Sample random orderings
    all_possible = list(range(width))
    sampled = set()
    for _ in range(n_samples):
        order = tuple(random.sample(all_possible, width))
        sampled.add(order)
    for kw_order in kw_orderings:
        sampled.add(kw_order)

    orderings = list(sampled)
    print(f"Total orderings (incl. keywords): {len(orderings)}")

    # ── Part 1: Structural ──────────────────────────────────────────
    print(f"\n--- Structural Analysis ---")

    # Lag analysis for a few orderings
    lag_data = {}
    for lag in [width, width - 2, 7, 9]:
        raw_matches = compute_lag_matches(CT_NUM, lag)
        raw_z = compute_lag_z(raw_matches, CT_LEN, lag)

        # After undoing transposition
        untrans_lags = []
        for order in orderings[:1000]:  # Sample for speed
            perm = build_columnar_perm(width, order)
            inv = invert_perm(perm)
            untrans = [CT_NUM[inv[j]] for j in range(CT_LEN)]
            untrans_lags.append(compute_lag_matches(untrans, lag))

        mean_untrans = sum(untrans_lags) / len(untrans_lags)
        reduces = sum(1 for v in untrans_lags if v < raw_matches)
        pct_reduces = 100 * reduces / len(untrans_lags)

        lag_data[lag] = {
            "raw": raw_matches, "raw_z": round(raw_z, 2),
            "mean_untrans": round(mean_untrans, 2),
            "pct_reduces": round(pct_reduces, 1),
        }
        print(f"  lag-{lag}: raw={raw_matches} (z={raw_z:.2f}), "
              f"mean untrans={mean_untrans:.1f}, "
              f"{pct_reduces:.0f}% reduce")

    # ── Part 2: Bean constraint ──────────────────────────────────────
    print(f"\n--- Bean Constraint ---")
    bean_counts = {0: 0, 1: 0, 2: 0}
    for order in orderings:
        perm = build_columnar_perm(width, order)
        for v in range(3):
            if check_bean(perm, v):
                bean_counts[v] += 1

    vnames = ["Vig", "Beau", "VB"]
    for v in range(3):
        pct = 100 * bean_counts[v] / len(orderings)
        print(f"  Bean full passes ({vnames[v]}): {bean_counts[v]} / {len(orderings)} ({pct:.2f}%)")

    # ── Part 3: Periodic consistency sweep ───────────────────────────
    print(f"\n--- Periodic Consistency Sweep (periods 2-7) ---")
    PERIODS = list(range(2, 8))
    VARIANT_NAMES = ["vigenere", "beaufort", "variant_beaufort"]

    best_overall = {"score": 0}
    best_by_period = {p: {"score": 0} for p in PERIODS}
    strict_pass_count = 0
    score_dist = Counter()
    n_checked = 0
    t0 = time.time()
    last_report = t0

    for order in orderings:
        perm = build_columnar_perm(width, order)
        for variant in range(3):
            for model in range(2):
                for period in PERIODS:
                    n_checked += 1
                    sc = majority_score(perm, period, variant, model)
                    score_dist[sc] += 1

                    if sc > best_overall.get("score", 0):
                        best_overall = {
                            "score": sc,
                            "order": list(order),
                            "variant": VARIANT_NAMES[variant],
                            "model": "A" if model == 0 else "B",
                            "period": period,
                        }

                    if sc > best_by_period[period].get("score", 0):
                        best_by_period[period] = {
                            "score": sc,
                            "order": list(order),
                            "variant": VARIANT_NAMES[variant],
                            "model": "A" if model == 0 else "B",
                        }

                    passed, n_const, _ = strict_periodic_check(
                        perm, period, variant, model)
                    if passed and n_const >= 3:
                        strict_pass_count += 1

        now = time.time()
        if now - last_report > 30:
            pct = 100 * n_checked / (len(orderings) * 3 * 2 * 6)
            print(f"  [{pct:5.1f}%] best={best_overall['score']}/24")
            last_report = now

    elapsed = time.time() - t0

    print(f"\n  Checked: {n_checked:,} configs in {elapsed:.1f}s")
    print(f"  Best overall: {best_overall['score']}/24")
    for k, v in best_overall.items():
        print(f"    {k}: {v}")
    print(f"  Strict passes (period 2-7): {strict_pass_count}")
    print(f"\n  Best by period:")
    for p in PERIODS:
        bp = best_by_period[p]
        print(f"    p={p}: {bp['score']}/24 ({bp.get('variant','?')}, "
              f"model {bp.get('model','?')})")

    print(f"\n  Score distribution (top):")
    for sc in sorted(score_dist.keys(), reverse=True)[:8]:
        print(f"    {sc:2d}/24: {score_dist[sc]:,}")

    return {
        "width": width,
        "n_orderings": len(orderings),
        "lag_data": lag_data,
        "bean_counts": {str(v): bean_counts[v] for v in range(3)},
        "best_overall": best_overall,
        "best_by_period": {str(p): best_by_period[p] for p in PERIODS},
        "strict_passes": strict_pass_count,
        "n_checked": n_checked,
        "elapsed": round(elapsed, 1),
    }


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-06: Width-11 and Width-13 Structural Analysis")
    print("=" * 70)

    # Width-11: 11! = 39.9M → sample 50K
    result_11 = analyze_width(11, 50000)

    # Width-13: 13! = 6.2B → sample 50K
    result_13 = analyze_width(13, 50000)

    # ── Random baseline ─────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("RANDOM BASELINE (50,000 random permutations)")
    print(f"{'='*70}")

    random_best = {"score": 0}
    random_strict = 0
    random_scores = Counter()
    PERIODS = list(range(2, 8))

    for trial in range(50000):
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        for variant in range(3):
            for model in range(2):
                for period in PERIODS:
                    sc = majority_score(perm, period, variant, model)
                    random_scores[sc] += 1
                    if sc > random_best.get("score", 0):
                        random_best["score"] = sc
                    passed, n_const, _ = strict_periodic_check(
                        perm, period, variant, model)
                    if passed and n_const >= 3:
                        random_strict += 1

    print(f"  Random best: {random_best['score']}/24")
    print(f"  Random strict passes: {random_strict}")
    print(f"  Score distribution (top):")
    for sc in sorted(random_scores.keys(), reverse=True)[:8]:
        print(f"    {sc:2d}/24: {random_scores[sc]:,}")

    # ── Summary ─────────────────────────────────────────────────────
    total_elapsed = time.time() - t0
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Width-11 best (p≤7): {result_11['best_overall']['score']}/24")
    print(f"Width-13 best (p≤7): {result_13['best_overall']['score']}/24")
    print(f"Random best (p≤7):   {random_best['score']}/24")
    print(f"Total time: {total_elapsed:.1f}s")

    # Verdict
    w11_score = result_11["best_overall"]["score"]
    w13_score = result_13["best_overall"]["score"]
    r_score = random_best["score"]

    if max(w11_score, w13_score) >= 18:
        verdict = "SIGNAL — investigate further"
    elif max(w11_score, w13_score) > r_score + 2:
        verdict = "STORE — width-11/13 marginally above random, further testing needed"
    else:
        verdict = "NOISE — width-11/13 comparable to random baseline"

    print(f"\nVERDICT: {verdict}")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-06",
        "description": "Width-11 and width-13 structural analysis",
        "width_11": result_11,
        "width_13": result_13,
        "random_best": random_best["score"],
        "random_strict": random_strict,
        "total_elapsed": round(total_elapsed, 1),
        "verdict": verdict,
    }
    path = "results/frac/e_frac_06_w11w13.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")

    print(f"\nRESULT: w11_best={w11_score}/24 w13_best={w13_score}/24 "
          f"random_best={r_score}/24 verdict={'SIGNAL' if max(w11_score,w13_score)>=18 else 'ELIMINATED'}")


if __name__ == "__main__":
    main()
