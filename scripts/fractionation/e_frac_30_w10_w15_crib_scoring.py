#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-30: Sampled Crib Scoring for Widths 10-15 at Discriminating Periods.

E-FRAC-29 eliminated widths 6 and 8 (along with E-FRAC-12 for width 9,
E-FRAC-26/27 for widths 5 and 7). All columnar widths 5-9 are now eliminated.

This experiment extends to widths 10-15, which are Bean-compatible (E-FRAC-27)
but too large for exhaustive enumeration (10! = 3.6M through 15! = 1.3T).

For each width:
1. 100K sampled orderings × 3 variants × 2 models × periods 2-7
2. Bean equality + full Bean constraint check
3. Multiple-testing-corrected comparison to random baseline
4. Check whether widths 10-15 also underperform random (as widths 8-9 did)
"""
import itertools
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


def build_col_heights(width):
    n_rows = CT_LEN // width
    remainder = CT_LEN % width
    return [n_rows + 1 if j < remainder else n_rows for j in range(width)]


def build_columnar_inv_perm(order, width, col_heights):
    """Build inverse permutation: inv_perm[pt_pos] = ct_pos."""
    enc_perm = []
    for c in order:
        height = col_heights[c]
        for row in range(height):
            enc_perm.append(row * width + c)
    inv_perm = [0] * len(enc_perm)
    for k, pt_pos in enumerate(enc_perm):
        inv_perm[pt_pos] = k
    return inv_perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_eq_only(inv_perm):
    """Check ONLY Bean equality (variant-independent)."""
    for eq_a, eq_b in BEAN_EQ:
        if CT_NUM[inv_perm[eq_a]] != CT_NUM[inv_perm[eq_b]]:
            return False
    return True


def check_bean_full(inv_perm, variant):
    """Check Bean equality + all 21 inequalities."""
    for eq_a, eq_b in BEAN_EQ:
        if CT_NUM[inv_perm[eq_a]] != CT_NUM[inv_perm[eq_b]]:
            return False

    for ineq_a, ineq_b in BEAN_INEQ:
        ct_a = CT_NUM[inv_perm[ineq_a]]
        pt_a = CRIB_PT_NUM[ineq_a]
        ct_b = CT_NUM[inv_perm[ineq_b]]
        pt_b = CRIB_PT_NUM[ineq_b]

        if variant == "vigenere":
            k_a = (ct_a - pt_a) % MOD
            k_b = (ct_b - pt_b) % MOD
        elif variant == "beaufort":
            k_a = (ct_a + pt_a) % MOD
            k_b = (ct_b + pt_b) % MOD
        else:
            k_a = (pt_a - ct_a) % MOD
            k_b = (pt_b - ct_b) % MOD

        if k_a == k_b:
            return False
    return True


def strict_periodic_score(inv_perm, period, variant, model):
    """Strict period-consistency scoring."""
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


def test_width_sampled(width, n_samples=100_000, seed=42):
    """Test a width with sampled orderings at discriminating periods."""
    col_heights = build_col_heights(width)
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]

    rng = random.Random(seed + width)
    n_perms = math.factorial(width)

    score_dist = Counter()
    n_bean_eq = 0
    n_bean_full = {v: 0 for v in variants}
    top_results = []

    t0 = time.time()
    last_report = t0

    for trial in range(n_samples):
        order = list(range(width))
        rng.shuffle(order)
        inv_perm = build_columnar_inv_perm(tuple(order), width, col_heights)

        eq_pass = check_bean_eq_only(inv_perm)
        if eq_pass:
            n_bean_eq += 1

        best_score = 0
        best_cfg = None

        for period in periods:
            for variant in variants:
                for model in models:
                    score = strict_periodic_score(inv_perm, period, variant, model)
                    if score > best_score:
                        best_score = score
                        best_cfg = (period, variant, model)

        score_dist[best_score] += 1

        if best_score >= 12:
            bean_results = {}
            for v in variants:
                bean_ok = check_bean_full(inv_perm, v)
                bean_results[v] = bean_ok
                if bean_ok:
                    n_bean_full[v] += 1

            top_results.append({
                "order": list(order),
                "score": best_score,
                "config": list(best_cfg),
                "bean_eq": eq_pass,
                "bean_full": bean_results,
            })
        else:
            if eq_pass:
                for v in variants:
                    if check_bean_full(inv_perm, v):
                        n_bean_full[v] += 1

        now = time.time()
        if now - last_report > 30:
            pct = 100 * (trial + 1) / n_samples
            top_s = max(score_dist.keys()) if score_dist else 0
            print(f"    [{pct:5.1f}%] tested={trial+1:,}, top={top_s}")
            last_report = now

    elapsed = time.time() - t0
    top_results.sort(key=lambda x: -x["score"])

    return {
        "width": width,
        "n_perms_total": n_perms,
        "n_samples": n_samples,
        "score_dist": dict(score_dist),
        "n_bean_eq": n_bean_eq,
        "n_bean_full": dict(n_bean_full),
        "total_bean_full": sum(n_bean_full.values()),
        "top_results": top_results[:30],
        "elapsed_seconds": round(elapsed, 1),
    }


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-30: Sampled Crib Scoring — Widths 10-15")
    print("=" * 70)
    print()
    print("Widths 5-9 are eliminated (E-FRAC-12/26/27/29).")
    print("Testing widths 10-15 (Bean-compatible per E-FRAC-27).")
    print("100K samples per width at discriminating periods (2-7).")
    print()

    widths = list(range(10, 16))
    all_results = {}

    for width in widths:
        print(f"\n{'='*60}")
        print(f"  Width {width}: Sampled Test (100K of {math.factorial(width):,})")
        print(f"{'='*60}")

        result = test_width_sampled(width, n_samples=100_000)
        all_results[width] = result

        max_score = max(result["score_dist"].keys())
        mean_score = sum(s * c for s, c in result["score_dist"].items()) / result["n_samples"]

        print(f"\n  Tested: {result['n_samples']:,} orderings (of {result['n_perms_total']:,})")
        print(f"  Time: {result['elapsed_seconds']}s")
        print(f"\n  Score distribution:")
        for s in sorted(result["score_dist"].keys(), reverse=True):
            c = result["score_dist"][s]
            if c > 0:
                print(f"    score={s:2d}: {c:,} ({100*c/result['n_samples']:.2f}%)")

        print(f"\n  Max score: {max_score}/24")
        print(f"  Mean score: {mean_score:.2f}/24")
        print(f"\n  Bean equality pass: {result['n_bean_eq']:,}/{result['n_samples']:,} "
              f"({100*result['n_bean_eq']/result['n_samples']:.2f}%)")
        print(f"  Bean full pass: {result['total_bean_full']:,}")

        # Top results
        bean_top = [r for r in result["top_results"]
                    if r.get("bean_full") and any(r["bean_full"].values())]
        if bean_top:
            print(f"\n  High-scoring Bean-passing orderings:")
            for r in bean_top[:5]:
                bean_vs = [v[:4] for v, b in r["bean_full"].items() if b]
                print(f"    score={r['score']}, cfg={r['config']}, bean={bean_vs}")
        else:
            n_top = len(result["top_results"])
            print(f"\n  No orderings with score >= 12 AND Bean pass. ({n_top} scored >=12)")

    # ── Random baseline (reuse from E-FRAC-29) ────────────────
    print(f"\n{'='*60}")
    print("  Random Permutation Baseline (Periods 2-7, N=100K)")
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

    all_scores = sorted(s for s, c in random_score_dist.items() for _ in range(c))
    mean_random = sum(all_scores) / len(all_scores)
    p99 = all_scores[int(0.99 * len(all_scores))]
    p999 = all_scores[int(0.999 * len(all_scores))]
    max_random = max(all_scores)

    print(f"\n  Random: mean={mean_random:.2f}, p99={p99}, p999={p999}, max={max_random}")
    print(f"  Time: {rand_elapsed:.1f}s")

    # Per-trial p-values
    p_ge13 = sum(c for s, c in random_score_dist.items() if s >= 13) / N_RANDOM
    p_ge14 = sum(c for s, c in random_score_dist.items() if s >= 14) / N_RANDOM
    p_ge15 = sum(c for s, c in random_score_dist.items() if s >= 15) / N_RANDOM

    # ── Summary table ──────────────────────────────────────────
    print(f"\n{'='*70}")
    print("  Summary: All Widths 5-15 + Random")
    print(f"{'='*70}")
    print()
    print(f"  {'Width':>6s}  {'N':>10s}  {'Exh?':>4s}  {'Max':>4s}  {'Mean':>6s}  "
          f"{'CorrP':>8s}  {'BeanEq':>8s}  {'BeanFull':>8s}  {'Verdict':>12s}")
    print(f"  {'-'*6}  {'-'*10}  {'-'*4}  {'-'*4}  {'-'*6}  "
          f"{'-'*8}  {'-'*8}  {'-'*8}  {'-'*12}")

    # Reference data for widths 5-9
    ref_widths = [
        (5, 120, True, 0, 0, 0, "Bean-ELIM"),
        (6, 720, True, 13, 9.21, 84, "NOISE"),
        (7, 5040, True, 0, 0, 0, "Bean-ELIM"),
        (8, 40320, True, 13, 9.34, 1920, "NOISE"),
        (9, 362880, True, 14, 9.4, 15120, "NOISE"),
    ]

    for w, n, exh, mx, mn, beq, verdict in ref_widths:
        exh_str = "Y" if exh else "N"
        if mx == 0:
            corr_p = "N/A"
        elif mx == 13:
            corr_p_val = 1.0 - (1.0 - p_ge13) ** n
            corr_p = f"{corr_p_val:.3f}"
        elif mx == 14:
            corr_p_val = 1.0 - (1.0 - p_ge14) ** n
            corr_p = f"{corr_p_val:.3f}"
        else:
            corr_p = "?"
        print(f"  {'w'+str(w)+' *':>6s}  {n:10,}  {exh_str:>4s}  {mx:4d}  {mn:6.2f}  "
              f"{corr_p:>8s}  {beq:8,}  {'--':>8s}  {verdict:>12s}")

    # Widths 10-15
    for width in widths:
        r = all_results[width]
        sd = r["score_dist"]
        n = r["n_samples"]
        mx = max(sd.keys())
        mn = sum(s * c for s, c in sd.items()) / n

        if mx >= 15:
            p_trial = p_ge15
        elif mx >= 14:
            p_trial = p_ge14
        elif mx >= 13:
            p_trial = p_ge13
        else:
            p_trial = 1.0

        corr_p_val = 1.0 - (1.0 - p_trial) ** n
        corr_p = f"{corr_p_val:.3f}"

        if corr_p_val > 0.05:
            verdict = "NOISE"
        elif corr_p_val > 0.001:
            verdict = "MARGINAL"
        else:
            verdict = "SIGNAL"

        # Check if underperforming
        if mx == 13:
            p_would_higher = 1.0 - (1.0 - p_ge14) ** n
            if p_would_higher > 0.5:
                verdict += " (under)"
        elif mx == 14:
            p_would_higher = 1.0 - (1.0 - p_ge15) ** n
            if p_would_higher > 0.5:
                verdict += " (under)"

        print(f"  {'w'+str(width):>6s}  {n:10,}  {'N':>4s}  {mx:4d}  {mn:6.2f}  "
              f"{corr_p:>8s}  {r['n_bean_eq']:8,}  {r['total_bean_full']:8,}  {verdict:>12s}")

    # Random reference
    print(f"  {'rand':>6s}  {N_RANDOM:10,}  {'-':>4s}  {max_random:4d}  {mean_random:6.2f}  "
          f"{'ref':>8s}  {'--':>8s}  {'--':>8s}  {'baseline':>12s}")

    # ── Verdict ────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("VERDICT")
    print(f"{'='*70}")

    all_noise = True
    verdicts = {}
    for width in widths:
        r = all_results[width]
        mx = max(r["score_dist"].keys())
        mn = sum(s * c for s, c in r["score_dist"].items()) / r["n_samples"]

        if mx >= 15:
            p_trial = p_ge15
        elif mx >= 14:
            p_trial = p_ge14
        elif mx >= 13:
            p_trial = p_ge13
        else:
            p_trial = 1.0

        corr_p_val = 1.0 - (1.0 - p_trial) ** r["n_samples"]

        if corr_p_val > 0.05:
            v = f"NOISE (max={mx}, corrected p={corr_p_val:.3f})"
        else:
            v = f"POSSIBLE SIGNAL (max={mx}, corrected p={corr_p_val:.4f})"
            all_noise = False

        verdicts[width] = v
        print(f"\n  Width-{width}: {v}")

    if all_noise:
        print(f"\n  OVERALL: ALL widths 10-15 are NOISE.")
        print(f"  Combined with widths 5-9: ALL columnar widths 5-15 are ELIMINATED")
        print(f"  for columnar transposition + periodic substitution.")
    else:
        print(f"\n  OVERALL: Some widths show possible signal — investigate.")

    elapsed = time.time() - t0
    print(f"\nTotal time: {elapsed:.1f}s")

    # ── Save ───────────────────────────────────────────────────
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-30",
        "description": "Sampled crib scoring for widths 10-15 at discriminating periods (2-7)",
        "width_results": {
            str(w): {
                "n_perms_total": r["n_perms_total"],
                "n_samples": r["n_samples"],
                "score_dist": {str(k): v for k, v in r["score_dist"].items()},
                "max_score": max(r["score_dist"].keys()),
                "mean_score": round(sum(s*c for s,c in r["score_dist"].items()) / r["n_samples"], 2),
                "n_bean_eq": r["n_bean_eq"],
                "n_bean_full": r["n_bean_full"],
                "total_bean_full": r["total_bean_full"],
                "elapsed_seconds": r["elapsed_seconds"],
                "top_results": r["top_results"][:10],
            }
            for w, r in all_results.items()
        },
        "random_baseline": {
            "n_tested": N_RANDOM,
            "mean": round(mean_random, 2),
            "p99": p99,
            "p999": p999,
            "max": max_random,
            "p_ge13": round(p_ge13, 6),
            "p_ge14": round(p_ge14, 6),
            "p_ge15": round(p_ge15, 6),
        },
        "verdicts": verdicts,
        "all_noise": all_noise,
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_30_w10_w15_crib_scoring.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
