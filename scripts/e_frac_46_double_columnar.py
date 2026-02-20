#!/usr/bin/env python3
"""E-FRAC-46: Double Columnar Transposition at Bean-Compatible Width Pairs.

E-FRAC-04 tested width-9 × width-7 compound transposition, but width-7 is
Bean-INCOMPATIBLE (E-FRAC-26/27: ZERO orderings pass Bean equality). That
test was fundamentally flawed.

This experiment tests double columnar transposition at BEAN-COMPATIBLE width
pairs: {6, 8, 9}. These are the widths with non-trivial Bean pass rates
(E-FRAC-27) AND at practical sizes for K4.

For each width pair (w1, w2), we compose σ = σ_w1 ∘ σ_w2:
  1. First transposition σ_w2 (read columns in order 2)
  2. Second transposition σ_w1 (read columns in order 1)
  3. Composed permutation applied to CT
  4. Score against cribs at discriminating periods (2-7)
  5. Check Bean constraints on the composed permutation

Key insight from E-FRAC-44 (information-theoretic analysis):
  - For structured families with N < 2^30 options, expected FP = 0
  - w6×w8: 720 × 40,320 = 29M ≈ 2^24.8 compositions → oracle IS sufficient
  - w8×w9: 40,320 × 362,880 ≈ 14.6B ≈ 2^33.8 → oracle IS sufficient
  - If signal exists, we WILL detect it (no false positive problem)

Width pairs tested (all Bean-compatible):
  - w6×w8, w8×w6 (asymmetric)
  - w6×w9, w9×w6
  - w8×w9, w9×w8
  - w6×w6 (self-composition)
  - w8×w8
  - w9×w9

Sampling: w6 exhaustive (720), w8 sample 500, w9 sample 500.
Each composition scored at periods 2,3,5,7 × Vig/Beau = 8 configs.
Random baseline: 50K random permutations.
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

# ═══════════════════════════════════════════════════════════════
# Permutation utilities
# ═══════════════════════════════════════════════════════════════

def build_columnar_perm(order, width):
    """Build columnar transposition permutation for given width and column order."""
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


def compose_perms(perm1, perm2):
    """Compose: result[i] = perm1[perm2[i]]."""
    return [perm1[p] for p in perm2]


def validate_perm(perm):
    return len(perm) == CT_LEN and set(perm) == set(range(CT_LEN))


# ═══════════════════════════════════════════════════════════════
# Scoring functions
# ═══════════════════════════════════════════════════════════════

def check_bean_eq(perm, variant="vigenere"):
    """Check Bean equality only: k[27] = k[65]."""
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
    return True


def check_bean_full(perm, variant="vigenere"):
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
    """Score with strict period consistency (majority voting per residue)."""
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

    total = 0
    for keys in residue_keys.values():
        if len(keys) == 1:
            total += 1
        else:
            counts = Counter(keys)
            total += counts.most_common(1)[0][1]

    return total


def best_score_across_configs(perm):
    """Get best score across discriminating periods and variants."""
    best = 0
    best_config = None
    for period in [2, 3, 5, 7]:
        for variant in ["vigenere", "beaufort"]:
            for model in ["A", "B"]:
                s = strict_periodic_score(perm, period, variant, model)
                if s > best:
                    best = s
                    best_config = (period, variant, model)
    return best, best_config


# ═══════════════════════════════════════════════════════════════
# Generate orderings
# ═══════════════════════════════════════════════════════════════

def sample_orderings(width, n_samples):
    """Sample n random orderings for given width."""
    orderings = set()
    while len(orderings) < n_samples:
        order = list(range(width))
        random.shuffle(order)
        orderings.add(tuple(order))
    return [list(o) for o in orderings]


def all_orderings(width):
    """Return all orderings for given width (only practical for w <= 8)."""
    return [list(o) for o in itertools.permutations(range(width))]


# ═══════════════════════════════════════════════════════════════
# Main experiment
# ═══════════════════════════════════════════════════════════════

def test_double_columnar(w1, w2, orderings1, orderings2, label):
    """Test all compositions of orderings from two widths."""
    n_total = len(orderings1) * len(orderings2)
    print(f"\n{'='*70}")
    print(f"Testing {label}: {len(orderings1)} × {len(orderings2)} = {n_total} compositions")
    print(f"{'='*70}")

    score_dist = defaultdict(int)
    bean_eq_pass = 0
    bean_full_pass = 0
    top_results = []
    best_score = 0
    count = 0
    t0 = time.time()

    # Pre-build permutations for w2 to avoid recomputation
    perms2 = [(o2, build_columnar_perm(o2, w2)) for o2 in orderings2]

    for o1 in orderings1:
        perm1 = build_columnar_perm(o1, w1)

        for o2, perm2 in perms2:
            # Compose: first apply perm2, then perm1
            composed = compose_perms(perm1, perm2)
            assert len(composed) == CT_LEN

            score, config = best_score_across_configs(composed)
            score_dist[score] += 1
            count += 1

            if score > best_score:
                best_score = score

            # Check Bean on high-scoring compositions
            if score >= 10:
                bean_eq_v = check_bean_eq(composed, "vigenere")
                bean_eq_b = check_bean_eq(composed, "beaufort")
                bean_full_v = check_bean_full(composed, "vigenere") if bean_eq_v else False
                bean_full_b = check_bean_full(composed, "beaufort") if bean_eq_b else False

                top_results.append({
                    "w1": w1, "w2": w2,
                    "order1": o1, "order2": o2,
                    "score": score,
                    "config": {"period": config[0], "variant": config[1], "model": config[2]},
                    "bean_eq_vig": bean_eq_v,
                    "bean_eq_beau": bean_eq_b,
                    "bean_full_vig": bean_full_v,
                    "bean_full_beau": bean_full_b,
                })

            # Also check Bean equality on all compositions for pass rate
            if count <= 50000:  # Sample first 50K for Bean rate
                if check_bean_eq(composed, "vigenere") or check_bean_eq(composed, "beaufort"):
                    bean_eq_pass += 1
                if check_bean_full(composed, "vigenere") or check_bean_full(composed, "beaufort"):
                    bean_full_pass += 1

            if count % 100000 == 0:
                elapsed = time.time() - t0
                rate = count / elapsed
                print(f"  {count:,}/{n_total:,} ({100*count/n_total:.1f}%) "
                      f"best={best_score}/24 rate={rate:.0f}/s")

    elapsed = time.time() - t0
    bean_sample_n = min(count, 50000)

    # Sort top results by score descending
    top_results.sort(key=lambda x: x["score"], reverse=True)
    top_results = top_results[:50]  # Keep top 50

    result = {
        "label": label,
        "w1": w1, "w2": w2,
        "n_orderings1": len(orderings1),
        "n_orderings2": len(orderings2),
        "n_compositions": count,
        "best_score": best_score,
        "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
        "bean_eq_pass_rate": bean_eq_pass / bean_sample_n if bean_sample_n > 0 else 0,
        "bean_full_pass_rate": bean_full_pass / bean_sample_n if bean_sample_n > 0 else 0,
        "bean_sample_n": bean_sample_n,
        "top_results": top_results[:20],
        "elapsed_seconds": elapsed,
    }

    # Print summary
    print(f"\n  Results for {label}:")
    print(f"  Compositions tested: {count:,}")
    print(f"  Best score: {best_score}/24")
    print(f"  Score distribution (≥8): {', '.join(f'{k}:{v}' for k, v in sorted(score_dist.items()) if k >= 8)}")
    print(f"  Bean eq pass rate: {100*result['bean_eq_pass_rate']:.2f}% (from {bean_sample_n:,} samples)")
    print(f"  Bean full pass rate: {100*result['bean_full_pass_rate']:.2f}% (from {bean_sample_n:,} samples)")
    if top_results:
        best = top_results[0]
        print(f"  Best: score={best['score']}, p={best['config']['period']}, "
              f"var={best['config']['variant']}, model={best['config']['model']}")
        bean_any = any(r.get("bean_full_vig") or r.get("bean_full_beau") for r in top_results if r["score"] >= 12)
        print(f"  Any ≥12 with Bean full: {bean_any}")
    print(f"  Time: {elapsed:.1f}s")

    return result


def random_baseline(n_samples=50000):
    """Score random permutations as baseline."""
    print(f"\n{'='*70}")
    print(f"Random baseline: {n_samples:,} random permutations")
    print(f"{'='*70}")

    score_dist = defaultdict(int)
    best_score = 0
    t0 = time.time()

    for i in range(n_samples):
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        score, _ = best_score_across_configs(perm)
        score_dist[score] += 1
        if score > best_score:
            best_score = score

    elapsed = time.time() - t0

    print(f"  Random baseline: best={best_score}/24")
    print(f"  Distribution (≥8): {', '.join(f'{k}:{v}' for k, v in sorted(score_dist.items()) if k >= 8)}")
    print(f"  Time: {elapsed:.1f}s")

    return {
        "n_samples": n_samples,
        "best_score": best_score,
        "score_distribution": {str(k): v for k, v in sorted(score_dist.items())},
        "elapsed_seconds": elapsed,
    }


def main():
    print("=" * 70)
    print("E-FRAC-46: Double Columnar Transposition at Bean-Compatible Width Pairs")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Bean-compatible widths: 6, 8, 9")
    print(f"Bean-INCOMPATIBLE widths: 5, 7 (excluded)")
    print()

    random.seed(42)
    t_start = time.time()

    # ── Phase 0: Random baseline ──
    baseline = random_baseline(50000)

    # ── Phase 1: Generate orderings ──
    print("\nGenerating orderings...")
    w6_orders = all_orderings(6)  # 720 (exhaustive)
    w8_orders = sample_orderings(8, 500)  # 500 sampled from 40,320
    w9_orders = sample_orderings(9, 500)  # 500 sampled from 362,880
    print(f"  w6: {len(w6_orders)} (exhaustive)")
    print(f"  w8: {len(w8_orders)} (sampled from 40,320)")
    print(f"  w9: {len(w9_orders)} (sampled from 362,880)")

    results = {"experiment": "E-FRAC-46", "baseline": baseline, "pairs": {}}

    # ── Phase 2: Test all Bean-compatible width pairs ──
    pairs = [
        (6, 6, w6_orders, w6_orders, "w6×w6"),
        (6, 8, w6_orders, w8_orders, "w6×w8"),
        (8, 6, w8_orders, w6_orders, "w8×w6"),
        (6, 9, w6_orders, w9_orders, "w6×w9"),
        (9, 6, w9_orders, w6_orders, "w9×w6"),
        (8, 8, w8_orders, w8_orders, "w8×w8"),
        (8, 9, w8_orders, w9_orders, "w8×w9"),
        (9, 8, w9_orders, w8_orders, "w9×w8"),
        (9, 9, w9_orders, w9_orders, "w9×w9"),
    ]

    for w1, w2, orders1, orders2, label in pairs:
        pair_result = test_double_columnar(w1, w2, orders1, orders2, label)
        results["pairs"][label] = pair_result

    # ── Phase 3: Summary ──
    total_elapsed = time.time() - t_start

    print(f"\n{'='*70}")
    print(f"SUMMARY — E-FRAC-46")
    print(f"{'='*70}")
    print(f"\nRandom baseline: best={baseline['best_score']}/24")
    print(f"\nDouble columnar results:")
    print(f"{'Pair':<12} {'N comps':>12} {'Best':>6} {'Bean eq%':>10} {'Bean full%':>10}")
    print("-" * 60)

    global_best = 0
    for label in ["w6×w6", "w6×w8", "w8×w6", "w6×w9", "w9×w6",
                   "w8×w8", "w8×w9", "w9×w8", "w9×w9"]:
        r = results["pairs"][label]
        print(f"{label:<12} {r['n_compositions']:>12,} {r['best_score']:>5}/24 "
              f"{100*r['bean_eq_pass_rate']:>9.2f}% {100*r['bean_full_pass_rate']:>9.2f}%")
        if r["best_score"] > global_best:
            global_best = r["best_score"]

    # Compute total compositions tested
    total_comps = sum(r["n_compositions"] for r in results["pairs"].values())

    # Statistical comparison
    baseline_scores = baseline["score_distribution"]
    baseline_max = baseline["best_score"]
    # Count how many random trials score >= global_best
    n_at_or_above = sum(v for k, v in baseline_scores.items() if int(k) >= global_best)
    p_per_trial = n_at_or_above / baseline["n_samples"] if baseline["n_samples"] > 0 else 0
    # Corrected p for total_comps trials
    p_corrected = 1 - (1 - p_per_trial) ** total_comps if p_per_trial < 1 else 1.0

    # Check if best UNDERPERFORMS random
    underperforms = global_best < baseline_max

    print(f"\nGlobal best: {global_best}/24")
    print(f"Random baseline best: {baseline_max}/24")
    print(f"Total compositions: {total_comps:,}")
    print(f"p(random ≥ {global_best}): {p_per_trial:.6f}")
    print(f"Corrected p (for {total_comps:,} trials): {p_corrected:.6f}")
    print(f"Underperforms random: {underperforms}")

    # Check any Bean-passing results in top scores
    any_bean_top = False
    for label, r in results["pairs"].items():
        for tr in r.get("top_results", []):
            if tr["score"] >= 14 and (tr.get("bean_full_vig") or tr.get("bean_full_beau")):
                any_bean_top = True
                print(f"\n  *** Bean-passing ≥14: {label} score={tr['score']} "
                      f"p={tr['config']['period']} var={tr['config']['variant']}")

    # Verdict
    if global_best >= 18:
        verdict = "SIGNAL"
    elif global_best > baseline_max:
        verdict = "STORE"
    elif underperforms:
        verdict = "NOISE_UNDERPERFORMS"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")
    print(f"Total runtime: {total_elapsed:.1f}s")

    results["summary"] = {
        "global_best": global_best,
        "baseline_best": baseline_max,
        "total_compositions": total_comps,
        "p_per_trial": p_per_trial,
        "p_corrected": p_corrected,
        "underperforms_random": underperforms,
        "any_bean_top_14": any_bean_top,
        "verdict": verdict,
        "total_runtime_seconds": total_elapsed,
    }

    # Save results
    os.makedirs("results/frac", exist_ok=True)
    with open("results/frac/e_frac_46_double_columnar.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nResults saved to results/frac/e_frac_46_double_columnar.json")

    print(f"\nRESULT: best={global_best}/24 configs={total_comps} verdict={verdict}")


if __name__ == "__main__":
    main()
