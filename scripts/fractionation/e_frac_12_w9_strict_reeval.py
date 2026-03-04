#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-12: Width-9 Re-evaluation with Strict Scoring (No Bimodal Filter).

Now that E-FRAC-11 has debunked the bimodal fingerprint, we re-examine
width-9 columnar with strict scoring. Previous tests (E-S-133/133b)
used the bimodal pre-filter or tested with underdetermined periods.

This experiment:
1. Tests all 362,880 width-9 orderings × 3 variants × 2 models × periods 2-7
2. Uses strict period-consistency check (majority voting per residue class)
3. Compares against a properly-calibrated random baseline
4. Focuses ONLY on discriminating periods (≤7)
5. Adds a new analysis: the "crib conflict graph" — for each ordering,
   which pairs of crib positions conflict under what conditions?

The goal: does width-9 produce any signal above random at discriminating periods?
"""
import itertools
import json
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

WIDTH = 9
N_ROWS = CT_LEN // WIDTH
REMAINDER = CT_LEN % WIDTH
COL_HEIGHTS = [N_ROWS + 1 if j < REMAINDER else N_ROWS for j in range(WIDTH)]


def build_columnar_perm(order):
    perm = []
    for c in range(WIDTH):
        col = order[c]
        height = COL_HEIGHTS[col]
        for row in range(height):
            perm.append(row * WIDTH + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean(perm, variant="vigenere"):
    """Check Bean equality and all 21 inequality constraints."""
    inv = invert_perm(perm)

    def key_at(pt_pos):
        ct_pos = inv[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            return (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            return (ct_val + pt_val) % MOD
        else:
            return (pt_val - ct_val) % MOD

    for eq_a, eq_b in BEAN_EQ:
        if key_at(eq_a) != key_at(eq_b):
            return False

    for ineq_a, ineq_b in BEAN_INEQ:
        if key_at(ineq_a) == key_at(ineq_b):
            return False

    return True


def strict_periodic_score(perm, period, variant, model):
    """Score with strict period consistency.

    For each residue class, take the majority key value.
    Count how many crib positions agree with the majority.
    """
    inv = invert_perm(perm)

    residue_keys = defaultdict(list)

    for pt_pos in sorted(CRIB_SET):
        ct_pos = inv[pt_pos]
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

    # For each residue, find majority and count matches
    total_matches = 0
    for residue, keys in residue_keys.items():
        if len(keys) == 1:
            total_matches += 1
        else:
            key_counts = Counter(keys)
            majority_val, majority_count = key_counts.most_common(1)[0]
            total_matches += majority_count

    return total_matches


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-12: Width-9 Re-evaluation (No Bimodal Filter, Strict Scoring)")
    print("=" * 70)
    print()

    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]  # ONLY discriminating periods

    # ── Part 1: Exhaustive width-9 scan ──────────────────────────────
    print("Part 1: Exhaustive Width-9 Columnar Scan (Periods 2-7 Only)")
    print("-" * 50)

    score_dist = Counter()
    top_results = []
    n_bean_pass = {v: 0 for v in variants}
    n_tested = 0
    last_report = t0

    for order in itertools.permutations(range(WIDTH)):
        perm = build_columnar_perm(order)
        n_tested += 1

        best_score = 0
        best_cfg = None

        for period in periods:
            for variant in variants:
                for model in models:
                    score = strict_periodic_score(perm, period, variant, model)
                    if score > best_score:
                        best_score = score
                        best_cfg = (period, variant, model)

        score_dist[best_score] += 1

        if best_score >= 12:
            bean_results = {}
            for v in variants:
                bean_ok = check_bean(perm, v)
                bean_results[v] = bean_ok
                if bean_ok:
                    n_bean_pass[v] += 1

            top_results.append({
                "order": list(order),
                "score": best_score,
                "config": best_cfg,
                "bean": bean_results,
            })

        now = time.time()
        if now - last_report > 30:
            pct = 100 * n_tested / 362880
            print(f"  [{pct:5.1f}%] tested={n_tested:,}, "
                  f"top={max(score_dist.keys()) if score_dist else 0}")
            last_report = now

    elapsed_w9 = time.time() - t0

    print(f"\n  Tested: {n_tested:,} orderings")
    print(f"  Time: {elapsed_w9:.1f}s")
    print(f"\n  Score distribution (best across p=2-7, all variants/models):")
    for s in sorted(score_dist.keys(), reverse=True):
        print(f"    score={s:2d}: {score_dist[s]:,}")

    if top_results:
        top_results.sort(key=lambda x: -x["score"])
        print(f"\n  Top results (score >= 12):")
        for r in top_results[:20]:
            bean_str = ", ".join(f"{v[:4]}:{'Y' if r['bean'][v] else 'N'}"
                                for v in variants)
            print(f"    score={r['score']}, order={r['order']}, "
                  f"cfg={r['config']}, Bean=[{bean_str}]")

    # ── Part 2: Random baseline ──────────────────────────────────────
    print()
    print("Part 2: Random Permutation Baseline (Periods 2-7 Only)")
    print("-" * 50)

    random.seed(42)
    N_RANDOM = 100_000
    random_score_dist = Counter()

    for trial in range(N_RANDOM):
        perm = list(range(CT_LEN))
        random.shuffle(perm)

        best_score = 0
        for period in periods:
            for variant in variants:
                for model in models:
                    score = strict_periodic_score(perm, period, variant, model)
                    if score > best_score:
                        best_score = score
        random_score_dist[best_score] += 1

    print(f"  Tested: {N_RANDOM:,} random permutations")
    print(f"\n  Score distribution:")
    for s in sorted(random_score_dist.keys(), reverse=True):
        print(f"    score={s:2d}: {random_score_dist[s]:,} "
              f"({100*random_score_dist[s]/N_RANDOM:.2f}%)")

    # Compute mean and percentiles
    all_scores = []
    for s, c in random_score_dist.items():
        all_scores.extend([s] * c)
    all_scores.sort()
    mean_random = sum(all_scores) / len(all_scores)
    p99 = all_scores[int(0.99 * len(all_scores))]
    p999 = all_scores[int(0.999 * len(all_scores))]
    max_random = max(all_scores)

    print(f"\n  Mean: {mean_random:.2f}")
    print(f"  99th percentile: {p99}")
    print(f"  99.9th percentile: {p999}")
    print(f"  Max: {max_random}")

    # ── Part 3: Comparison ───────────────────────────────────────────
    print()
    print("Part 3: Width-9 vs Random Comparison")
    print("-" * 50)

    w9_max = max(score_dist.keys()) if score_dist else 0

    # Distribution comparison
    print(f"\n  {'Score':>6s}  {'W9 count':>10s}  {'W9 %':>8s}  {'Rand count':>10s}  {'Rand %':>8s}  {'Ratio':>8s}")
    for s in sorted(set(list(score_dist.keys()) + list(random_score_dist.keys())), reverse=True):
        w9_c = score_dist.get(s, 0)
        w9_p = 100 * w9_c / n_tested
        r_c = random_score_dist.get(s, 0)
        r_p = 100 * r_c / N_RANDOM
        ratio = (w9_p / r_p) if r_p > 0 else float('inf')
        if w9_c > 0 or r_c > 0:
            print(f"  {s:6d}  {w9_c:10,}  {w9_p:7.3f}%  {r_c:10,}  {r_p:7.3f}%  {ratio:8.2f}x")

    # p-value: what fraction of random perms score >= w9_max?
    n_exceeding = sum(c for s, c in random_score_dist.items() if s >= w9_max)
    p_value = n_exceeding / N_RANDOM
    print(f"\n  Width-9 best: {w9_max}/24")
    print(f"  Random perms scoring >= {w9_max}: {n_exceeding}/{N_RANDOM} (p={p_value:.4f})")

    # ── Part 4: Per-period analysis ──────────────────────────────────
    print()
    print("Part 4: Per-Period Score Distribution (Width-9)")
    print("-" * 50)

    for period in periods:
        period_scores = Counter()
        for order in itertools.permutations(range(WIDTH)):
            perm = build_columnar_perm(order)
            best = 0
            for variant in variants:
                for model in models:
                    s = strict_periodic_score(perm, period, variant, model)
                    if s > best:
                        best = s
            period_scores[best] += 1

        max_s = max(period_scores.keys())
        mean_s = sum(s * c for s, c in period_scores.items()) / n_tested
        print(f"  Period {period}: max={max_s:2d}/24, mean={mean_s:.2f}/24, "
              f"scores>=10: {sum(c for s,c in period_scores.items() if s>=10):,}")

    # ── Part 5: Best width-9 orderings with Bean ─────────────────────
    print()
    print("Part 5: Best Width-9 Orderings with Bean Constraints")
    print("-" * 50)

    bean_top = [r for r in top_results if any(r["bean"].values())]
    if bean_top:
        print(f"  Top results with Bean pass (any variant):")
        for r in bean_top[:20]:
            bean_variants = [v[:4] for v, b in r["bean"].items() if b]
            print(f"    score={r['score']}, order={r['order']}, "
                  f"cfg={r['config']}, bean_variants={bean_variants}")
    else:
        print(f"  No results with score >= 12 AND Bean pass.")

    # Check all Bean-passing orderings at lower scores
    print(f"\n  Bean-passing orderings (any variant) at score >= 10:")
    bean_pass_at_10 = 0
    for order in itertools.permutations(range(WIDTH)):
        perm = build_columnar_perm(order)
        best_score = 0
        best_cfg = None
        for period in periods:
            for variant in variants:
                for model in models:
                    score = strict_periodic_score(perm, period, variant, model)
                    if score > best_score:
                        best_score = score
                        best_cfg = (period, variant, model)

        if best_score >= 10:
            for v in variants:
                if check_bean(perm, v):
                    bean_pass_at_10 += 1
                    if bean_pass_at_10 <= 10:
                        print(f"    score={best_score}, order={list(order)}, "
                              f"cfg={best_cfg}, bean_variant={v}")
                    break

    print(f"  Total: {bean_pass_at_10:,} orderings with score>=10 AND Bean pass")

    # ── Summary ──────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print()
    print("=" * 70)
    print("VERDICT")
    print("=" * 70)

    if w9_max > p999:
        verdict = (f"INTERESTING — width-9 best ({w9_max}) exceeds random 99.9th "
                   f"percentile ({p999})")
    elif w9_max > p99:
        verdict = (f"MARGINAL — width-9 best ({w9_max}) exceeds random 99th "
                   f"percentile ({p99}) but not 99.9th ({p999})")
    else:
        verdict = (f"NOISE — width-9 best ({w9_max}) within random noise range "
                   f"(99th={p99}, max={max_random})")

    print(f"\n  {verdict}")
    print(f"\n  Width-9 max: {w9_max}/24")
    print(f"  Random max: {max_random}/24 (N={N_RANDOM:,})")
    print(f"  Random mean: {mean_random:.2f}/24")
    print(f"  p-value for w9_max: {p_value:.4f}")

    print(f"\nTotal time: {elapsed:.1f}s")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-12",
        "description": "Width-9 re-evaluation, no bimodal filter, periods 2-7 only",
        "n_tested": n_tested,
        "w9_score_dist": {str(k): v for k, v in score_dist.items()},
        "w9_max": w9_max,
        "random_score_dist": {str(k): v for k, v in random_score_dist.items()},
        "random_max": max_random,
        "random_mean": round(mean_random, 2),
        "p99": p99,
        "p999": p999,
        "p_value": round(p_value, 4),
        "top_results": [
            {"order": r["order"], "score": r["score"],
             "config": list(r["config"]),
             "bean": r["bean"]}
            for r in top_results[:50]
        ],
        "bean_at_10_plus": bean_pass_at_10,
        "verdict": verdict,
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_12_w9_strict_reeval.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
