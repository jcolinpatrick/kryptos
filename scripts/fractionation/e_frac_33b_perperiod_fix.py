#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-33b: Fix per-period correlation analysis from E-FRAC-33.

The main experiment had a data alignment bug in per-period correlations.
This script computes correct per-period parent-child correlations and also
checks what period the hill-climbing 24/24 results actually achieve at.
"""
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def strict_periodic_score(inv_perm, period, variant, model):
    residue_keys = defaultdict(list)
    for pt_pos in sorted(CRIB_SET):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        else:
            k = (pt_val - ct_val) % MOD
        if model == "A":
            residue = pt_pos % period
        else:
            residue = ct_pos % period
        residue_keys[residue].append(k)
    total = 0
    for keys in residue_keys.values():
        if len(keys) == 1:
            total += 1
        else:
            total += Counter(keys).most_common(1)[0][1]
    return total


def score_at_period(inv_perm, period, variants, models):
    best = 0
    for v in variants:
        for m in models:
            s = strict_periodic_score(inv_perm, period, v, m)
            if s > best:
                best = s
    return best


def best_score_with_period(inv_perm, periods, variants, models):
    best = 0
    best_p = 0
    for p in periods:
        for v in variants:
            for m in models:
                s = strict_periodic_score(inv_perm, p, v, m)
                if s > best:
                    best = s
                    best_p = p
    return best, best_p


def pearson_r(xs, ys):
    n = len(xs)
    mx = sum(xs) / n
    my = sum(ys) / n
    vx = sum((x - mx) ** 2 for x in xs) / n
    vy = sum((y - my) ** 2 for y in ys) / n
    cv = sum((xs[i] - mx) * (ys[i] - my) for i in range(n)) / n
    if vx > 0 and vy > 0:
        return cv / (math.sqrt(vx) * math.sqrt(vy))
    return 0.0


def main():
    t0 = time.time()
    random.seed(42)
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]

    print("=" * 70)
    print("E-FRAC-33b: Per-period correlation fix + hill-climbing period check")
    print("=" * 70)

    # ================================================================
    # Part 1: Correct per-period parent-child correlations
    # ================================================================
    print("\n--- Part 1: Correct per-period parent-child correlations ---")
    n_parents = 10000
    per_period_pairs = {p: {"parent": [], "child": []} for p in periods}

    for i in range(n_parents):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)

        # Score at each period
        parent_scores_per_period = {}
        for p in periods:
            parent_scores_per_period[p] = score_at_period(inv, p, variants, models)

        # Single child (1:1 pairing, no alignment issue)
        child_perm = list(perm)
        a, b = random.sample(range(N), 2)
        child_perm[a], child_perm[b] = child_perm[b], child_perm[a]
        child_inv = invert_perm(child_perm)

        for p in periods:
            cs = score_at_period(child_inv, p, variants, models)
            per_period_pairs[p]["parent"].append(parent_scores_per_period[p])
            per_period_pairs[p]["child"].append(cs)

        if (i + 1) % 2500 == 0:
            print(f"  {i+1}/{n_parents} pairs...")

    print("\n  Per-period parent-child correlations (1 swap, 1:1 pairing):")
    period_corrs = {}
    for p in periods:
        pp = per_period_pairs[p]["parent"]
        cc = per_period_pairs[p]["child"]
        r = pearson_r(pp, cc)
        period_corrs[p] = round(r, 4)

        # Also compute delta distribution
        deltas = [cc[i] - pp[i] for i in range(len(pp))]
        delta_dist = Counter(deltas)
        n_unchanged = delta_dist.get(0, 0)
        pct_unchanged = 100 * n_unchanged / len(deltas)

        print(f"  Period {p}: r = {r:.4f}  (unchanged: {pct_unchanged:.1f}%)")
        # Show delta distribution
        for d in sorted(delta_dist.keys()):
            print(f"    delta={d:+d}: {delta_dist[d]} ({100*delta_dist[d]/len(deltas):.1f}%)")

    # ================================================================
    # Part 2: What periods do hill-climbing 24/24 solutions use?
    # ================================================================
    print("\n--- Part 2: Hill-climbing to 24/24 — which period? ---")
    n_climbs = 30
    max_steps = 5000
    period_counts_at_24 = Counter()
    climb_stats = []

    for c in range(n_climbs):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        current_score, current_period = best_score_with_period(inv, periods, variants, models)

        for step in range(max_steps):
            candidate = list(perm)
            a, b = random.sample(range(N), 2)
            candidate[a], candidate[b] = candidate[b], candidate[a]
            cand_inv = invert_perm(candidate)
            cand_score, cand_period = best_score_with_period(cand_inv, periods, variants, models)

            if cand_score >= current_score:
                perm = candidate
                current_score = cand_score
                current_period = cand_period

        # Check scores at each period for the final permutation
        inv = invert_perm(perm)
        period_scores = {}
        for p in periods:
            period_scores[p] = score_at_period(inv, p, variants, models)

        best_period = max(periods, key=lambda p: period_scores[p])
        climb_stats.append({
            "final_score": current_score,
            "final_period": current_period,
            "per_period": dict(period_scores),
        })

        if current_score == 24:
            period_counts_at_24[current_period] += 1

        if (c + 1) % 10 == 0:
            print(f"  {c+1}/{n_climbs} climbs done (last: {current_score}/24 at p={current_period})")

    print(f"\n  Climbs reaching 24/24: {sum(1 for r in climb_stats if r['final_score'] == 24)}/{n_climbs}")
    print(f"  Period used for 24/24 solutions: {dict(period_counts_at_24)}")

    # Show per-period scores for 24/24 solutions
    print("\n  Per-period scores for solutions reaching 24/24:")
    for i, r in enumerate(climb_stats):
        if r["final_score"] >= 22:
            pp = r["per_period"]
            pp_str = ", ".join(f"p{p}={pp[p]}" for p in periods)
            print(f"    Climb {i}: final={r['final_score']}/24 at p={r['final_period']} — [{pp_str}]")

    # ================================================================
    # Part 3: Hill-climbing restricted to period 5 only
    # ================================================================
    print("\n--- Part 3: Hill-climbing restricted to period 5 only ---")
    n_climbs_p5 = 50
    max_steps_p5 = 5000
    p5_results = []

    for c in range(n_climbs_p5):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        current_score = score_at_period(inv, 5, variants, models)

        for step in range(max_steps_p5):
            candidate = list(perm)
            a, b = random.sample(range(N), 2)
            candidate[a], candidate[b] = candidate[b], candidate[a]
            cand_inv = invert_perm(candidate)
            cand_score = score_at_period(cand_inv, 5, variants, models)

            if cand_score >= current_score:
                perm = candidate
                current_score = cand_score

        p5_results.append(current_score)

    p5_dist = Counter(p5_results)
    p5_mean = sum(p5_results) / len(p5_results)
    p5_max = max(p5_results)

    print(f"  Climbs: {n_climbs_p5}, max steps: {max_steps_p5}")
    print(f"  Period 5 only: mean={p5_mean:.2f}, max={p5_max}/24")
    print(f"  Distribution: {dict(sorted(p5_dist.items()))}")

    # Compare to random period-5 baseline
    print("\n  Random baseline at period 5 (50K samples):")
    p5_random = []
    for _ in range(50000):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        s = score_at_period(inv, 5, variants, models)
        p5_random.append(s)
    p5_random_max = max(p5_random)
    p5_random_mean = sum(p5_random) / len(p5_random)
    print(f"  Random mean: {p5_random_mean:.3f}, max: {p5_random_max}/24")
    print(f"  Hill-climbing advantage at period 5: {p5_max - p5_random_max} points")

    # ================================================================
    # Summary
    # ================================================================
    total_time = time.time() - t0
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("Per-period parent-child correlations (CORRECTED):")
    for p in periods:
        print(f"  Period {p}: r = {period_corrs[p]:.4f}")

    pct_24 = sum(1 for r in climb_stats if r['final_score'] == 24) / n_climbs * 100
    print(f"\nHill-climbing (best across periods 2-7): {pct_24:.0f}% reach 24/24")
    print(f"Period used by 24/24 solutions: {dict(period_counts_at_24)}")
    print(f"\nHill-climbing at period 5 ONLY: max={p5_max}/24 (random max={p5_random_max}/24)")
    print(f"Advantage: {p5_max - p5_random_max} points")

    if p5_max - p5_random_max <= 2:
        p5_verdict = "SA at discriminating periods provides MINIMAL advantage over random"
    else:
        p5_verdict = "SA at discriminating periods provides MEANINGFUL advantage over random"

    print(f"\nVerdict: {p5_verdict}")
    print(f"Total runtime: {total_time:.1f}s")

    # Save
    out_dir = "results/frac"
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "e_frac_33b_perperiod_fix.json")
    output = {
        "experiment": "E-FRAC-33b",
        "period_correlations_corrected": period_corrs,
        "hill_climbing_24_period_counts": dict(period_counts_at_24),
        "hill_climbing_p5_only": {
            "max": p5_max,
            "mean": round(p5_mean, 2),
            "distribution": {str(k): v for k, v in sorted(p5_dist.items())},
        },
        "random_p5_baseline": {
            "max": p5_random_max,
            "mean": round(p5_random_mean, 3),
        },
        "p5_verdict": p5_verdict,
        "runtime_seconds": round(total_time, 1),
    }
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
