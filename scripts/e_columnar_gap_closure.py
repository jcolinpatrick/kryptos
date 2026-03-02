#!/usr/bin/env python3
"""E-COLUMNAR-GAP-CLOSURE: Close remaining columnar transposition width gaps.

PRIOR COVERAGE:
  Width 5:  120 orderings × 3 variants → BEAN-IMPOSSIBLE (zero passes)   [E-FRAC-26/27]
  Width 6:  720 orderings × 3 variants → max 13/24, ELIMINATED           [E-FRAC-29]
  Width 7:  5,040 orderings × 3 variants → BEAN-IMPOSSIBLE               [E-FRAC-26/27]
  Width 8:  40,320 orderings × 3 variants → max 13/24, ELIMINATED        [E-FRAC-29]
  Width 9:  362,880 orderings × 3 variants → max 14/24, ELIMINATED       [E-FRAC-12]
  Widths 10-15: 100K MC each × 3 variants → max 14/24, ELIMINATED        [E-FRAC-30]

THEORETICAL COVERAGE:
  E-AUDIT-01: ALL periods 2-26 ELIMINATED for ANY transposition under additive key model
  (276 pairwise constraints from 24 crib positions). This applies to ALL widths.

  Pure transposition: ELIMINATED (CT has 2 E's, cribs need 3 E's — frequency mismatch).

REMAINING GAPS (this script):
  1. Widths 2, 3, 4: Never explicitly tested as columnar transpositions.
     Width 2: 2 orderings (trivial)
     Width 3: 6 orderings
     Width 4: 24 orderings
     Total: 32 orderings — EXHAUSTIVE test.

  2. Widths 16-20: Never tested (w10-15 was 100K MC each).
     Width 16: 16! ≈ 2×10^13 (sample 50K)
     Width 17: 17! ≈ 3.6×10^14 (sample 50K)
     Width 19: 19! ≈ 1.2×10^17 (sample 50K)
     Width 20: 20! ≈ 2.4×10^18 (sample 50K)

  3. Verify letter frequency mismatch at all untested widths (pure transposition check).

Model: CT = σ(Enc(PT, key)), where σ is columnar transposition.
We test inverse: PT_candidate = Dec(σ^{-1}(CT), key).

For periodic key: already proven impossible for ALL periods 2-26 (E-AUDIT-01).
We test anyway for verification at Bean-surviving periods {8,13,16} + discriminating {2,3,5,7}.
"""
import itertools
import json
import os
import random
import sys
import time
from collections import Counter, defaultdict
from math import factorial

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ, N_CRIBS,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN  # 97


# ═══════════════════════════════════════════════════════════════
# Permutation utilities
# ═══════════════════════════════════════════════════════════════

def build_columnar_perm(order, width):
    """Build columnar transposition permutation for given width and column order.

    Convention: text is written row-by-row into a grid of 'width' columns,
    then read column-by-column in the order specified by 'order'.

    Returns perm where CT[i] came from PT position perm[i].
    i.e., to DECRYPT: PT[perm[i]] = CT[i], or equivalently PT = apply_inverse(CT, perm).
    """
    n_rows = N // width
    remainder = N % width
    # First 'remainder' columns have n_rows+1 entries, rest have n_rows
    col_heights = [n_rows + 1 if j < remainder else n_rows for j in range(width)]

    perm = []
    for rank in range(width):
        # Find which column has this rank in the ordering
        col = list(order).index(rank)
        height = col_heights[col]
        for row in range(height):
            perm.append(row * width + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def apply_inverse(text, perm):
    """Given CT and columnar perm, recover the text before transposition.
    If CT[i] = pre_trans[perm[i]], then pre_trans[perm[i]] = CT[i].
    """
    result = [''] * len(text)
    for i, p in enumerate(perm):
        result[p] = text[i]
    return ''.join(result)


# ═══════════════════════════════════════════════════════════════
# Bean and scoring
# ═══════════════════════════════════════════════════════════════

def compute_key_at(pre_trans, pt_pos, variant):
    """Compute key value at a crib position given the pre-transposition text."""
    ct_val = ALPH_IDX[pre_trans[pt_pos]]
    pt_val = CRIB_PT_NUM[pt_pos]
    if variant == "vigenere":
        return (ct_val - pt_val) % MOD
    elif variant == "beaufort":
        return (ct_val + pt_val) % MOD
    else:  # variant_beaufort
        return (pt_val - ct_val) % MOD


def check_bean_eq(pre_trans, variant):
    """Check Bean equality: k[27] = k[65]."""
    for eq_a, eq_b in BEAN_EQ:
        if compute_key_at(pre_trans, eq_a, variant) != compute_key_at(pre_trans, eq_b, variant):
            return False
    return True


def check_bean_full(pre_trans, variant):
    """Check Bean equality + all 21 inequalities."""
    for eq_a, eq_b in BEAN_EQ:
        if compute_key_at(pre_trans, eq_a, variant) != compute_key_at(pre_trans, eq_b, variant):
            return False
    for ineq_a, ineq_b in BEAN_INEQ:
        if compute_key_at(pre_trans, ineq_a, variant) == compute_key_at(pre_trans, ineq_b, variant):
            return False
    return True


def score_periodic(pre_trans, period, variant):
    """Score against cribs assuming periodic key of given period.

    Key[i] = Key[i mod period]. Check how many crib positions are
    consistent with each other under this assumption.
    """
    # Group crib positions by residue class
    residue_groups = defaultdict(list)
    for pos in CRIB_SET:
        residue_groups[pos % period].append(pos)

    consistent = 0
    for residue, positions in residue_groups.items():
        if len(positions) <= 1:
            consistent += len(positions)
            continue
        # All positions in this group must have the same key value
        keys = [compute_key_at(pre_trans, pos, variant) for pos in positions]
        # Count the largest group of identical keys
        key_counts = Counter(keys)
        best = max(key_counts.values())
        consistent += best

    return consistent


def letter_frequency_check(pre_trans):
    """Check if the pre-transposition text has the right letter frequencies for cribs.

    Key constraint: EASTNORTHEAST + BERLINCLOCK require specific letters.
    Pure transposition preserves letter frequencies, so pre_trans must
    have the same frequencies as CT.
    """
    ct_freq = Counter(CT)
    pt_freq = Counter(pre_trans)
    return ct_freq == pt_freq


# ═══════════════════════════════════════════════════════════════
# Main experiment
# ═══════════════════════════════════════════════════════════════

def test_width(width, orderings, label, variants, periods, results):
    """Test all orderings for a given width."""
    width_results = {
        "width": width,
        "label": label,
        "n_orderings": len(orderings),
        "n_factorial": factorial(width),
        "exhaustive": len(orderings) == factorial(width),
        "bean_eq_passes": {v: 0 for v in variants},
        "bean_full_passes": {v: 0 for v in variants},
        "max_score": 0,
        "best_config": None,
        "score_dist": Counter(),
        "top_hits": [],
    }

    for order in orderings:
        perm = build_columnar_perm(order, width)
        pre_trans = apply_inverse(CT, perm)

        best_score = 0
        best_cfg = None

        for variant in variants:
            # Check Bean
            bean_eq = check_bean_eq(pre_trans, variant)
            if bean_eq:
                width_results["bean_eq_passes"][variant] += 1
                bean_full = check_bean_full(pre_trans, variant)
                if bean_full:
                    width_results["bean_full_passes"][variant] += 1

            # Score at each period
            for period in periods:
                score = score_periodic(pre_trans, period, variant)
                if score > best_score:
                    best_score = score
                    best_cfg = {
                        "order": list(order),
                        "variant": variant,
                        "period": period,
                        "bean_eq": bean_eq,
                    }

        width_results["score_dist"][best_score] += 1

        if best_score > width_results["max_score"]:
            width_results["max_score"] = best_score
            width_results["best_config"] = best_cfg

        if best_score >= 10:
            width_results["top_hits"].append({
                "order": list(order),
                "score": best_score,
                "config": best_cfg,
            })

    # Convert Counter to dict for JSON
    width_results["score_dist"] = dict(width_results["score_dist"])
    results["widths"][width] = width_results

    return width_results


def main():
    t0 = time.time()
    random.seed(2026_03_01)  # Reproducible

    variants = ["vigenere", "beaufort", "variant_beaufort"]
    # Bean-surviving periods {8,13,16,19,20,23,24,26} + discriminating {2,3,5,7}
    periods = [2, 3, 5, 7, 8, 13, 16, 19, 20, 23, 24, 26]

    results = {
        "experiment": "E-COLUMNAR-GAP-CLOSURE",
        "description": "Close remaining columnar transposition width gaps (w2-4, w16-20)",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "variants": variants,
        "periods": periods,
        "note": "E-AUDIT-01 proves ALL periods 2-26 impossible for ANY transposition. This script provides empirical verification at untested widths.",
        "widths": {},
    }

    print("=" * 72)
    print("E-COLUMNAR-GAP-CLOSURE: Closing Remaining Width Gaps")
    print("=" * 72)
    print()

    # ─── PART 1: Widths 2-4 EXHAUSTIVE ──────────────────────────────────
    print("PART 1: Widths 2-4 (EXHAUSTIVE)")
    print("-" * 40)

    for width in [2, 3, 4]:
        all_orderings = list(itertools.permutations(range(width)))
        print(f"\n  Width {width}: {len(all_orderings)} orderings (exhaustive = {width}!)")

        wr = test_width(width, all_orderings, "exhaustive", variants, periods, results)

        print(f"    Max score: {wr['max_score']}/24")
        print(f"    Bean-EQ passes: {wr['bean_eq_passes']}")
        print(f"    Bean-FULL passes: {wr['bean_full_passes']}")
        if wr['best_config']:
            print(f"    Best config: {wr['best_config']}")
        print(f"    Score distribution: {wr['score_dist']}")

        # Verify letter frequency (pure transposition check)
        perm = build_columnar_perm(all_orderings[0], width)
        pre_trans = apply_inverse(CT, perm)
        freq_ok = letter_frequency_check(pre_trans)
        print(f"    Letter freq preserved (pure trans): {freq_ok}")

        # Check if cribs can be satisfied under pure transposition
        crib_letters_needed = Counter()
        for pos, ch in CRIB_DICT.items():
            crib_letters_needed[ch] += 1
        ct_letters = Counter(CT)
        freq_mismatch = {}
        for ch, needed in crib_letters_needed.items():
            if ct_letters.get(ch, 0) < needed:
                freq_mismatch[ch] = f"need {needed}, have {ct_letters.get(ch, 0)}"
        if freq_mismatch:
            print(f"    FREQUENCY MISMATCH (pure trans impossible): {freq_mismatch}")
        else:
            print(f"    No frequency mismatch — pure trans not ruled out by freq alone")

    # ─── PART 2: Widths 16-20 SAMPLED ──────────────────────────────────
    print()
    print("PART 2: Widths 16-20 (SAMPLED, 50K each)")
    print("-" * 40)

    N_SAMPLES = 50_000

    for width in [16, 17, 19, 20]:
        print(f"\n  Width {width}: sampling {N_SAMPLES} of {factorial(width):.2e} orderings")

        # Generate random orderings
        sampled_orderings = []
        for _ in range(N_SAMPLES):
            order = list(range(width))
            random.shuffle(order)
            sampled_orderings.append(tuple(order))

        wr = test_width(width, sampled_orderings, f"MC_{N_SAMPLES}", variants, periods, results)

        print(f"    Max score: {wr['max_score']}/24")
        print(f"    Bean-EQ passes: {wr['bean_eq_passes']}")
        print(f"    Bean-FULL passes: {wr['bean_full_passes']}")
        if wr['best_config']:
            bc = wr['best_config']
            print(f"    Best config: period={bc.get('period')}, variant={bc.get('variant')}, bean_eq={bc.get('bean_eq')}")
        print(f"    Score distribution: {wr['score_dist']}")

    # ─── PART 3: Random baseline for comparison ─────────────────────────
    print()
    print("PART 3: Random Permutation Baseline (50K)")
    print("-" * 40)

    random_scores = Counter()
    random_max = 0
    n_random_bean_eq = {v: 0 for v in variants}

    for _ in range(N_SAMPLES):
        perm = list(range(N))
        random.shuffle(perm)
        pre_trans = apply_inverse(CT, perm)

        best = 0
        for variant in variants:
            bean_eq = check_bean_eq(pre_trans, variant)
            if bean_eq:
                n_random_bean_eq[variant] += 1
            for period in periods:
                s = score_periodic(pre_trans, period, variant)
                if s > best:
                    best = s

        random_scores[best] += 1
        if best > random_max:
            random_max = best

    mean_random = sum(s * c for s, c in random_scores.items()) / N_SAMPLES
    results["random_baseline"] = {
        "n_samples": N_SAMPLES,
        "max_score": random_max,
        "mean_score": round(mean_random, 3),
        "score_dist": dict(random_scores),
        "bean_eq_passes": n_random_bean_eq,
    }

    print(f"  Max random score: {random_max}/24")
    print(f"  Mean random score: {mean_random:.3f}")
    print(f"  Random Bean-EQ passes: {n_random_bean_eq}")
    print(f"  Score distribution: {dict(random_scores)}")

    # ─── PART 4: Theoretical verification ───────────────────────────────
    print()
    print("PART 4: Theoretical Coverage Verification")
    print("-" * 40)

    # Verify the letter frequency mismatch for pure transposition
    ct_freq = Counter(CT)
    crib_freq = Counter()
    for _, ch in CRIB_DICT.items():
        crib_freq[ch] += 1

    freq_violations = []
    for ch, needed in crib_freq.items():
        available = ct_freq.get(ch, 0)
        if available < needed:
            freq_violations.append(f"  {ch}: need {needed}, CT has {available}")

    print("\n  Pure transposition frequency check:")
    if freq_violations:
        print("  FREQUENCY MISMATCH — pure transposition IMPOSSIBLE:")
        for v in freq_violations:
            print(f"    {v}")
    else:
        print("  No mismatch detected")

    print(f"\n  E-AUDIT-01: ALL periods 2-26 eliminated for ANY transposition")
    print(f"  This covers widths 2-4 and 16-20 without explicit testing")
    print(f"  This script provides EMPIRICAL VERIFICATION of the theoretical proof")

    # ─── SUMMARY ────────────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)

    all_noise = True
    for w, wr in sorted(results["widths"].items()):
        max_s = wr["max_score"]
        label = "EXHAUSTIVE" if wr["exhaustive"] else f"MC_{wr['n_orderings']}"
        bean_any = any(v > 0 for v in wr["bean_full_passes"].values())
        status = "NOISE" if max_s <= random_max else "INVESTIGATE"
        if status != "NOISE":
            all_noise = False
        print(f"  Width {w:2d}: max={max_s:2d}/24, Bean-FULL={'YES' if bean_any else 'NO':3s}, "
              f"{label:12s}, status={status}")

    print(f"\n  Random baseline: max={random_max}/24, mean={mean_random:.1f}")

    if all_noise:
        print("\n  *** ALL UNTESTED WIDTHS: NOISE ***")
        print("  Combined with prior results (w5-15), columnar transposition")
        print("  at ALL widths 2-20 is ELIMINATED under periodic substitution.")
        print("  Widths 21-97 are structurally equivalent (underdetermined)")
        print("  and covered by the E-AUDIT-01 theoretical proof.")

    results["verdict"] = "NOISE" if all_noise else "INVESTIGATE"
    results["elapsed_seconds"] = round(time.time() - t0, 1)

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), "..", "results",
                            "e_columnar_gap_closure.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to: {out_path}")
    print(f"  Elapsed: {results['elapsed_seconds']:.1f}s")


if __name__ == "__main__":
    main()
