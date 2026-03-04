#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-29: Exhaustive Crib Scoring for Bean-Compatible Widths 6 and 8.

E-FRAC-27 identified Bean-compatible widths: 6, 8, 9, 10-15.
E-FRAC-12 exhaustively tested width-9 at discriminating periods (2-7):
  best 14/24, matching random (NOISE).

This experiment fills the gap: exhaustive crib scoring for widths 6 and 8
at discriminating periods (2-7), with Bean constraint filtering.

Width-6: 720 orderings (trivially exhaustive)
Width-8: 40,320 orderings (tractable exhaustive)

For each width:
1. All orderings × 3 cipher variants × 2 key models (PT-residue, CT-residue)
   × periods 2-7
2. Bean equality + full Bean constraint check
3. Compare score distributions to width-9 (E-FRAC-12) and random baseline

This completes the crib-scoring elimination chain for all small Bean-compatible
widths (5: Bean-eliminated, 6: this test, 7: Bean-eliminated, 8: this test,
9: E-FRAC-12).
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


def build_col_heights(width):
    n_rows = CT_LEN // width
    remainder = CT_LEN % width
    return [n_rows + 1 if j < remainder else n_rows for j in range(width)]


def build_columnar_perm(order, width, col_heights):
    """Build encryption permutation: perm[ct_pos] = pt_pos."""
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


def check_bean(inv_perm, variant="vigenere"):
    """Check Bean equality and all 21 inequality constraints."""
    def key_at(pt_pos):
        ct_pos = inv_perm[pt_pos]
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


def check_bean_eq_only(inv_perm):
    """Check ONLY Bean equality (variant-independent: CT[inv(27)] = CT[inv(65)])."""
    for eq_a, eq_b in BEAN_EQ:
        if CT_NUM[inv_perm[eq_a]] != CT_NUM[inv_perm[eq_b]]:
            return False
    return True


def strict_periodic_score(inv_perm, period, variant, model):
    """Strict period-consistency scoring.

    For each residue class, take majority key value.
    Count how many crib positions agree with majority.
    """
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

    total_matches = 0
    for residue, keys in residue_keys.items():
        if len(keys) == 1:
            total_matches += 1
        else:
            key_counts = Counter(keys)
            majority_val, majority_count = key_counts.most_common(1)[0]
            total_matches += majority_count

    return total_matches


def test_width(width):
    """Exhaustive test of a single width at discriminating periods."""
    col_heights = build_col_heights(width)
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]

    n_orderings = 1
    for i in range(1, width + 1):
        n_orderings *= i

    score_dist = Counter()
    top_results = []
    n_bean_eq = 0
    n_bean_full = {v: 0 for v in variants}
    n_tested = 0
    last_report = time.time()

    # Per-period score tracking
    period_score_dists = {p: Counter() for p in periods}

    for order in itertools.permutations(range(width)):
        perm = build_columnar_perm(order, width, col_heights)
        inv_perm = invert_perm(perm)
        n_tested += 1

        eq_pass = check_bean_eq_only(inv_perm)
        if eq_pass:
            n_bean_eq += 1

        best_score = 0
        best_cfg = None

        for period in periods:
            period_best = 0
            for variant in variants:
                for model in models:
                    score = strict_periodic_score(inv_perm, period, variant, model)
                    if score > period_best:
                        period_best = score
                    if score > best_score:
                        best_score = score
                        best_cfg = (period, variant, model)
            period_score_dists[period][period_best] += 1

        score_dist[best_score] += 1

        # Track Bean for high scorers
        if best_score >= 10:
            bean_results = {}
            for v in variants:
                bean_ok = check_bean(inv_perm, v)
                bean_results[v] = bean_ok
                if bean_ok:
                    n_bean_full[v] += 1

            top_results.append({
                "order": list(order),
                "score": best_score,
                "config": best_cfg,
                "bean_eq": eq_pass,
                "bean_full": bean_results,
            })
        else:
            # Still count Bean full for all orderings
            if eq_pass:
                for v in variants:
                    if check_bean(inv_perm, v):
                        n_bean_full[v] += 1

        now = time.time()
        if now - last_report > 30:
            pct = 100 * n_tested / n_orderings
            top_s = max(score_dist.keys()) if score_dist else 0
            print(f"    [{pct:5.1f}%] tested={n_tested:,}, top={top_s}")
            last_report = now

    top_results.sort(key=lambda x: -x["score"])

    return {
        "width": width,
        "n_orderings": n_orderings,
        "n_tested": n_tested,
        "score_dist": dict(score_dist),
        "top_results": top_results[:50],
        "n_bean_eq": n_bean_eq,
        "n_bean_full": dict(n_bean_full),
        "total_bean_full": sum(n_bean_full.values()),
        "period_score_dists": {
            p: dict(d) for p, d in period_score_dists.items()
        },
    }


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-29: Exhaustive Crib Scoring — Widths 6 and 8")
    print("=" * 70)
    print()
    print("Gap being filled: E-FRAC-27 showed widths 6 and 8 are Bean-compatible,")
    print("but they were never scored against cribs at discriminating periods (2-7).")
    print("Width-9 was tested in E-FRAC-12 (best 14/24, NOISE).")
    print()

    widths_to_test = [6, 8]
    all_results = {}

    for width in widths_to_test:
        print(f"\n{'='*60}")
        print(f"  Width {width}: Exhaustive Test")
        print(f"{'='*60}")

        tw = time.time()
        result = test_width(width)
        result["elapsed_seconds"] = round(time.time() - tw, 1)
        all_results[width] = result

        max_score = max(result["score_dist"].keys())
        mean_score = sum(s * c for s, c in result["score_dist"].items()) / result["n_tested"]

        print(f"\n  Tested: {result['n_tested']:,} orderings")
        print(f"  Time: {result['elapsed_seconds']}s")
        print(f"\n  Score distribution (best across p=2-7, all variants/models):")
        for s in sorted(result["score_dist"].keys(), reverse=True):
            c = result["score_dist"][s]
            print(f"    score={s:2d}: {c:,} ({100*c/result['n_tested']:.2f}%)")

        print(f"\n  Max score: {max_score}/24")
        print(f"  Mean score: {mean_score:.2f}/24")
        print(f"\n  Bean equality pass: {result['n_bean_eq']:,}/{result['n_tested']:,} "
              f"({100*result['n_bean_eq']/result['n_tested']:.2f}%)")
        total_full = result["total_bean_full"]
        print(f"  Bean full pass (across all variants): {total_full:,}")
        for v, c in result["n_bean_full"].items():
            print(f"    {v}: {c:,}")

        # Top results
        if result["top_results"]:
            print(f"\n  Top results (score >= 10):")
            for r in result["top_results"][:15]:
                bean_str = ""
                if "bean_full" in r:
                    bean_str = " Bean=[" + ",".join(
                        f"{v[:4]}:{'Y' if r['bean_full'][v] else 'N'}"
                        for v in ["vigenere", "beaufort", "variant_beaufort"]
                    ) + "]"
                print(f"    score={r['score']}, order={r['order']}, "
                      f"cfg={r['config']}{bean_str}")

        # Bean-passing with high scores
        bean_high = [r for r in result["top_results"]
                     if r.get("bean_full") and any(r["bean_full"].values())]
        if bean_high:
            print(f"\n  High-scoring Bean-passing orderings:")
            for r in bean_high[:10]:
                bean_vs = [v[:4] for v, b in r["bean_full"].items() if b]
                print(f"    score={r['score']}, order={r['order']}, "
                      f"cfg={r['config']}, bean_variants={bean_vs}")
        else:
            print(f"\n  No orderings with score >= 10 AND Bean pass.")

        # Per-period breakdown
        print(f"\n  Per-period max scores:")
        for period in [2, 3, 4, 5, 6, 7]:
            pd = result["period_score_dists"][period]
            p_max = max(pd.keys())
            p_mean = sum(s * c for s, c in pd.items()) / result["n_tested"]
            n_ge10 = sum(c for s, c in pd.items() if s >= 10)
            print(f"    period {period}: max={p_max:2d}/24, mean={p_mean:.2f}/24, "
                  f"score>=10: {n_ge10:,}")

    # ── Random baseline ────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  Random Permutation Baseline (Periods 2-7 Only)")
    print(f"{'='*60}")

    random.seed(42)
    N_RANDOM = 100_000
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]
    random_score_dist = Counter()
    t_rand = time.time()

    for trial in range(N_RANDOM):
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        inv_perm = invert_perm(perm)

        best_score = 0
        for period in periods:
            for variant in variants:
                for model in models:
                    score = strict_periodic_score(inv_perm, period, variant, model)
                    if score > best_score:
                        best_score = score
        random_score_dist[best_score] += 1

    rand_elapsed = time.time() - t_rand

    all_scores = []
    for s, c in random_score_dist.items():
        all_scores.extend([s] * c)
    all_scores.sort()
    mean_random = sum(all_scores) / len(all_scores)
    p99 = all_scores[int(0.99 * len(all_scores))]
    p999 = all_scores[int(0.999 * len(all_scores))]
    max_random = max(all_scores)

    print(f"\n  Tested: {N_RANDOM:,} random permutations")
    print(f"  Time: {rand_elapsed:.1f}s")
    print(f"\n  Score distribution:")
    for s in sorted(random_score_dist.keys(), reverse=True):
        c = random_score_dist[s]
        print(f"    score={s:2d}: {c:,} ({100*c/N_RANDOM:.2f}%)")
    print(f"\n  Mean: {mean_random:.2f}")
    print(f"  99th percentile: {p99}")
    print(f"  99.9th percentile: {p999}")
    print(f"  Max: {max_random}")

    # ── Cross-width comparison ─────────────────────────────────
    print(f"\n{'='*60}")
    print("  Cross-Width Comparison (w6, w8, w9=E-FRAC-12, random)")
    print(f"{'='*60}")

    # E-FRAC-12 reference: w9 best=14, random best=15, random mean=9.38
    print(f"\n  {'Width':>6s}  {'Tested':>10s}  {'Max':>4s}  {'Mean':>6s}  "
          f"{'>=10':>6s}  {'>=12':>6s}  {'>=14':>6s}  "
          f"{'BeanEq':>8s}  {'BeanFull':>8s}")
    print(f"  {'-'*6}  {'-'*10}  {'-'*4}  {'-'*6}  "
          f"{'-'*6}  {'-'*6}  {'-'*6}  "
          f"{'-'*8}  {'-'*8}")

    for width in widths_to_test:
        r = all_results[width]
        sd = r["score_dist"]
        n = r["n_tested"]
        mx = max(sd.keys())
        mn = sum(s * c for s, c in sd.items()) / n
        ge10 = sum(c for s, c in sd.items() if s >= 10)
        ge12 = sum(c for s, c in sd.items() if s >= 12)
        ge14 = sum(c for s, c in sd.items() if s >= 14)
        print(f"  {'w' + str(width):>6s}  {n:10,}  {mx:4d}  {mn:6.2f}  "
              f"{ge10:6,}  {ge12:6,}  {ge14:6,}  "
              f"{r['n_bean_eq']:8,}  {r['total_bean_full']:8,}")

    # Width-9 from E-FRAC-12
    print(f"  {'w9*':>6s}  {'362,880':>10s}  {'14':>4s}  {'~9.4':>6s}  "
          f"{'--':>6s}  {'20':>6s}  {'20':>6s}  "
          f"{'~15K':>8s}  {'~4.9K':>8s}")

    # Random
    rge10 = sum(c for s, c in random_score_dist.items() if s >= 10)
    rge12 = sum(c for s, c in random_score_dist.items() if s >= 12)
    rge14 = sum(c for s, c in random_score_dist.items() if s >= 14)
    print(f"  {'rand':>6s}  {N_RANDOM:10,}  {max_random:4d}  {mean_random:6.2f}  "
          f"{rge10:6,}  {rge12:6,}  {rge14:6,}  "
          f"{'--':>8s}  {'--':>8s}")

    # ── Statistical comparison ─────────────────────────────────
    print(f"\n  Statistical comparison:")
    for width in widths_to_test:
        r = all_results[width]
        w_max = max(r["score_dist"].keys())
        w_mean = sum(s * c for s, c in r["score_dist"].items()) / r["n_tested"]

        # p-value: fraction of random scoring >= w_max
        n_exceed = sum(c for s, c in random_score_dist.items() if s >= w_max)
        p_val = n_exceed / N_RANDOM

        print(f"\n  Width-{width}:")
        print(f"    Best score: {w_max}/24")
        print(f"    Mean score: {w_mean:.2f}/24")
        print(f"    Random perms scoring >= {w_max}: {n_exceed}/{N_RANDOM} (p={p_val:.4f})")

        if w_max <= max_random:
            print(f"    WITHIN random noise range (random max={max_random})")
        else:
            print(f"    EXCEEDS random max ({max_random}) — INVESTIGATE")

    # ── Verdict ────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("VERDICT")
    print(f"{'='*70}")

    all_noise = True
    verdicts = {}
    for width in widths_to_test:
        r = all_results[width]
        w_max = max(r["score_dist"].keys())
        if w_max > p999:
            v = f"INTERESTING — w{width} best ({w_max}) exceeds 99.9th pctile ({p999})"
            all_noise = False
        elif w_max > p99:
            v = f"MARGINAL — w{width} best ({w_max}) exceeds 99th pctile ({p99})"
            all_noise = False
        else:
            v = f"NOISE — w{width} best ({w_max}) within random range (99th={p99})"
        verdicts[width] = v
        print(f"\n  Width-{width}: {v}")

    if all_noise:
        print(f"\n  OVERALL: ALL tested widths are NOISE at discriminating periods.")
        print(f"  Combined with E-FRAC-12 (width-9=NOISE), E-FRAC-26/27 (widths 5,7=Bean-eliminated):")
        print(f"  → Widths 5-9 are COMPREHENSIVELY ELIMINATED for columnar + periodic sub.")
    else:
        print(f"\n  OVERALL: Some widths show signal — investigate further.")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")

    # ── Save artifacts ─────────────────────────────────────────
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-29",
        "description": "Exhaustive crib scoring for widths 6 and 8 at discriminating periods (2-7)",
        "width_results": {
            str(w): {
                "n_orderings": r["n_orderings"],
                "n_tested": r["n_tested"],
                "score_dist": {str(k): v for k, v in r["score_dist"].items()},
                "max_score": max(r["score_dist"].keys()),
                "mean_score": round(sum(s * c for s, c in r["score_dist"].items()) / r["n_tested"], 2),
                "n_bean_eq": r["n_bean_eq"],
                "n_bean_full": r["n_bean_full"],
                "total_bean_full": r["total_bean_full"],
                "elapsed_seconds": r["elapsed_seconds"],
                "top_results": r["top_results"][:20],
                "period_score_dists": {
                    str(p): {str(k): v for k, v in d.items()}
                    for p, d in r["period_score_dists"].items()
                },
            }
            for w, r in all_results.items()
        },
        "random_baseline": {
            "n_tested": N_RANDOM,
            "score_dist": {str(k): v for k, v in random_score_dist.items()},
            "mean": round(mean_random, 2),
            "p99": p99,
            "p999": p999,
            "max": max_random,
            "elapsed_seconds": round(rand_elapsed, 1),
        },
        "verdicts": verdicts,
        "all_noise": all_noise,
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_29_w6w8_crib_scoring.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
