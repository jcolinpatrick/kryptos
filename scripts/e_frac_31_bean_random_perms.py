#!/usr/bin/env python3
"""E-FRAC-31: Bean-Filtered Random Permutation Analysis.

E-FRAC-29/30 showed ALL columnar widths 5-15 are NOISE at discriminating periods.
A key question remains: is the Bean constraint itself informative as a filter?

This experiment tests: do Bean-passing ARBITRARY permutations (not just columnar)
score differently from non-Bean-passing ones at discriminating periods?

If Bean-passing permutations have higher max scores → Bean is informative,
suggesting the correct transposition (whatever it is) passes Bean.
If Bean-passing permutations score the same → Bean doesn't help filter.

Method:
1. Generate 1M random permutations
2. Split into Bean-passing and non-Bean-passing groups
3. Compare score distributions at discriminating periods (2-7)
4. Compute corrected p-values
"""
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


def check_bean_eq(perm):
    """Bean equality: CT[perm[27]] == CT[perm[65]] (gather convention: perm maps CT→PT)."""
    # We need inv_perm[pt_pos] = ct_pos
    # If perm is a random shuffle of 0..96, interpret as: perm[ct_pos] = pt_pos
    # Then inv_perm[pt_pos] = ct_pos where perm[ct_pos] = pt_pos
    # Actually, let's use the convention from other experiments:
    # inv_perm[pt_pos] = ct_pos
    # We pass inv_perm directly
    for eq_a, eq_b in BEAN_EQ:
        if CT_NUM[perm[eq_a]] != CT_NUM[perm[eq_b]]:
            return False
    return True


def check_bean_full(inv_perm, variant):
    """Full Bean check (equality + 21 inequalities)."""
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


def best_score(inv_perm):
    """Best score across all discriminating periods, variants, and models."""
    variants = ["vigenere", "beaufort", "variant_beaufort"]
    models = ["A", "B"]
    periods = [2, 3, 4, 5, 6, 7]

    best = 0
    best_cfg = None
    for period in periods:
        for variant in variants:
            for model in models:
                s = strict_periodic_score(inv_perm, period, variant, model)
                if s > best:
                    best = s
                    best_cfg = (period, variant, model)
    return best, best_cfg


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-31: Bean-Filtered Random Permutation Analysis")
    print("=" * 70)
    print()
    print("Question: Do Bean-passing random permutations score differently")
    print("from non-Bean-passing ones at discriminating periods?")
    print()

    N = 500_000
    random.seed(42)

    # Track scores for Bean-passing and non-passing groups
    bean_eq_scores = Counter()
    bean_full_scores = {v: Counter() for v in ["vigenere", "beaufort", "variant_beaufort"]}
    non_bean_scores = Counter()

    n_bean_eq = 0
    n_bean_full = {v: 0 for v in ["vigenere", "beaufort", "variant_beaufort"]}
    n_any_bean_full = 0

    # For combined group (any Bean full pass)
    bean_any_full_scores = Counter()

    top_bean = []

    last_report = t0

    for trial in range(N):
        # Generate random inverse permutation
        inv_perm = list(range(CT_LEN))
        random.shuffle(inv_perm)

        eq_pass = check_bean_eq(inv_perm)

        s, cfg = best_score(inv_perm)

        if eq_pass:
            n_bean_eq += 1
            bean_eq_scores[s] += 1

            any_full = False
            for v in ["vigenere", "beaufort", "variant_beaufort"]:
                if check_bean_full(inv_perm, v):
                    n_bean_full[v] += 1
                    bean_full_scores[v][s] += 1
                    any_full = True

            if any_full:
                n_any_bean_full += 1
                bean_any_full_scores[s] += 1
                if s >= 12:
                    top_bean.append({
                        "score": s,
                        "config": list(cfg),
                        "inv_perm_hash": hash(tuple(inv_perm)) % 10**8,
                    })
        else:
            non_bean_scores[s] += 1

        now = time.time()
        if now - last_report > 30:
            pct = 100 * (trial + 1) / N
            print(f"  [{pct:5.1f}%] tested={trial+1:,}, "
                  f"bean_eq={n_bean_eq:,}, "
                  f"any_full={n_any_bean_full:,}")
            last_report = now

    elapsed = time.time() - t0

    # ── Results ────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  Results")
    print(f"{'='*60}")

    n_non_bean = N - n_bean_eq
    print(f"\n  Total permutations: {N:,}")
    print(f"  Bean equality pass: {n_bean_eq:,} ({100*n_bean_eq/N:.2f}%)")
    print(f"  Any Bean full pass: {n_any_bean_full:,} ({100*n_any_bean_full/N:.2f}%)")
    for v, c in n_bean_full.items():
        print(f"    {v}: {c:,}")
    print(f"  Non-Bean: {n_non_bean:,}")

    # Score distributions
    for label, dist, n_group in [
        ("Non-Bean", non_bean_scores, n_non_bean),
        ("Bean-Eq", bean_eq_scores, n_bean_eq),
        ("Bean-Full (any)", bean_any_full_scores, n_any_bean_full),
    ]:
        if n_group == 0:
            continue
        max_s = max(dist.keys()) if dist else 0
        mean_s = sum(s * c for s, c in dist.items()) / n_group if n_group > 0 else 0
        ge10 = sum(c for s, c in dist.items() if s >= 10)
        ge12 = sum(c for s, c in dist.items() if s >= 12)
        ge14 = sum(c for s, c in dist.items() if s >= 14)

        print(f"\n  {label} (N={n_group:,}):")
        print(f"    Max: {max_s}/24, Mean: {mean_s:.2f}/24")
        print(f"    >=10: {ge10:,} ({100*ge10/n_group:.2f}%)")
        print(f"    >=12: {ge12:,} ({100*ge12/n_group:.3f}%)")
        print(f"    >=14: {ge14:,} ({100*ge14/n_group:.4f}%)")

        print(f"    Distribution (top):")
        for s in sorted(dist.keys(), reverse=True)[:8]:
            c = dist[s]
            print(f"      score={s:2d}: {c:,} ({100*c/n_group:.3f}%)")

    # ── Statistical comparison ─────────────────────────────────
    print(f"\n{'='*60}")
    print("  Statistical Comparison")
    print(f"{'='*60}")

    # Mean comparison
    if n_bean_eq > 0 and n_non_bean > 0:
        mean_bean = sum(s * c for s, c in bean_eq_scores.items()) / n_bean_eq
        mean_non = sum(s * c for s, c in non_bean_scores.items()) / n_non_bean
        diff = mean_bean - mean_non

        # Approximate z-test for difference in means
        var_bean = sum((s - mean_bean)**2 * c for s, c in bean_eq_scores.items()) / n_bean_eq
        var_non = sum((s - mean_non)**2 * c for s, c in non_bean_scores.items()) / n_non_bean

        se = (var_bean / n_bean_eq + var_non / n_non_bean) ** 0.5
        z = diff / se if se > 0 else 0

        print(f"\n  Mean comparison:")
        print(f"    Bean-Eq mean:   {mean_bean:.4f}")
        print(f"    Non-Bean mean:  {mean_non:.4f}")
        print(f"    Difference:     {diff:+.4f}")
        print(f"    z-score:        {z:.2f}")
        if abs(z) < 2:
            print(f"    → NOT significant (|z| < 2)")
        else:
            print(f"    → Significant (|z| >= 2)")

    # Max comparison (corrected)
    if n_any_bean_full > 0:
        max_bean = max(bean_any_full_scores.keys())
        max_non = max(non_bean_scores.keys())

        # What fraction of random N_bean-trial experiments get max >= max_bean?
        p_ge_max = sum(c for s, c in non_bean_scores.items() if s >= max_bean) / n_non_bean
        corrected_p = 1.0 - (1.0 - p_ge_max) ** n_any_bean_full

        print(f"\n  Max comparison:")
        print(f"    Bean-Full max: {max_bean}/24 (N={n_any_bean_full:,})")
        print(f"    Non-Bean max:  {max_non}/24 (N={n_non_bean:,})")
        print(f"    Per-trial P(>={max_bean}): {p_ge_max:.6f}")
        print(f"    Corrected P (N={n_any_bean_full:,}): {corrected_p:.4f}")

    # Top Bean-passing results
    if top_bean:
        top_bean.sort(key=lambda x: -x["score"])
        print(f"\n  Top Bean-passing results (score >= 12):")
        for r in top_bean[:10]:
            print(f"    score={r['score']}, cfg={r['config']}")

    # ── Verdict ────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print("VERDICT")
    print(f"{'='*70}")

    if n_any_bean_full > 0:
        max_bean = max(bean_any_full_scores.keys())
        mean_bean_full = (sum(s * c for s, c in bean_any_full_scores.items())
                         / n_any_bean_full)
        max_non = max(non_bean_scores.keys())
        mean_non = sum(s * c for s, c in non_bean_scores.items()) / n_non_bean

        if max_bean <= max_non and abs(mean_bean_full - mean_non) < 0.1:
            verdict = ("BEAN_NOT_INFORMATIVE — Bean-passing random permutations score "
                      "identically to non-Bean at discriminating periods. The Bean "
                      "constraint does not help identify the correct transposition.")
        elif max_bean > max_non:
            verdict = ("BEAN_POSSIBLY_INFORMATIVE — Bean-passing permutations score "
                      f"higher (max {max_bean} vs {max_non}). Investigate further.")
        else:
            verdict = ("BEAN_MARGINALLY_INFORMATIVE — small difference between Bean "
                      "and non-Bean groups.")
    else:
        verdict = "NO_BEAN_FULL_PASSES — cannot compare"

    print(f"\n  {verdict}")
    print(f"\n  Time: {elapsed:.1f}s")

    # ── Save ───────────────────────────────────────────────────
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-31",
        "description": "Bean-filtered random permutation analysis at discriminating periods",
        "n_total": N,
        "n_bean_eq": n_bean_eq,
        "n_any_bean_full": n_any_bean_full,
        "n_bean_full": dict(n_bean_full),
        "bean_eq_score_dist": {str(k): v for k, v in bean_eq_scores.items()},
        "bean_any_full_score_dist": {str(k): v for k, v in bean_any_full_scores.items()},
        "non_bean_score_dist": {str(k): v for k, v in non_bean_scores.items()},
        "top_bean_results": top_bean[:20],
        "verdict": verdict,
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_31_bean_random_perms.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
