#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-57b: Period-7 Transposition Constraint Enumeration (CORRECTED).

Bug fix: Bean constraints were derived under direct correspondence and do NOT
apply when transposition σ is present. With transposition:
  k[p] = CT[σ(p)] - PT[p] mod 26
So k[27] = k[65] requires CT[σ(27)] = CT[σ(65)] — a constraint on σ, not the key.

This version computes per-residue feasibility independently (no Bean), then
counts total feasible (key, σ-at-cribs) combinations.

Key insight: since residue classes are independent for the substitution step,
we can compute per-residue σ-counts in O(7 × 26) = 182 evaluations, then
multiply. Cross-residue injectivity (global σ constraint) is an upper bound
concern but not yet enforced.
"""

import json
import time
import sys
from collections import Counter, defaultdict
from functools import reduce
from operator import mul

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_IDX = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# CT letter counts
CT_COUNTS = Counter(CT_IDX)  # letter_value -> count in CT

# Crib positions grouped by residue mod 7
CRIB_BY_RESIDUE = defaultdict(list)
for pos in sorted(CRIB_POSITIONS):
    CRIB_BY_RESIDUE[pos % 7].append(pos)


def sigma_count_for_residue(residue, key_val):
    """Count injective σ-assignments for one residue class.

    For each crib position p in the class:
      σ(p) must be a CT position i where CT[i] = (PT[p] + key_val) % 26

    Returns: number of ways to assign DISTINCT CT positions to all positions
    in the class, respecting the letter requirement.

    This is the falling factorial product across distinct required letters.
    """
    positions = CRIB_BY_RESIDUE.get(residue, [])
    if not positions:
        return 1  # No constraints

    # For each crib position, what letter must CT[σ(p)] have?
    letter_needs = Counter()
    for p in positions:
        target = (PT_IDX[p] + key_val) % MOD
        letter_needs[target] += 1

    # Check feasibility and count assignments
    count = 1
    for letter_val, need in letter_needs.items():
        avail = CT_COUNTS.get(letter_val, 0)
        if avail < need:
            return 0
        # Falling factorial: avail * (avail-1) * ... * (avail-need+1)
        for i in range(need):
            count *= (avail - i)

    return count


def main():
    print("=" * 70)
    print("E-S-57b: Period-7 Constraint Enumeration (CORRECTED)")
    print("=" * 70)
    print(f"Model: CT[σ(p)] = PT[p] + k[p%7] mod 26 (Sub-then-Transpose)")
    print(f"Bean constraints NOT applied (they're σ-dependent with transposition)")
    print()

    t0 = time.time()

    # Phase 1: Per-residue analysis
    print("=" * 50)
    print("Phase 1: Per-Residue Feasibility")
    print("=" * 50)

    residue_data = {}
    for r in range(7):
        positions = CRIB_BY_RESIDUE.get(r, [])
        pts = [CRIB_DICT[p] for p in positions]
        print(f"\n  Residue {r}: positions={positions} PT={pts}")

        feasible_keys = []
        for k in range(26):
            sc = sigma_count_for_residue(r, k)
            if sc > 0:
                # Show required CT letters
                targets = [(PT_IDX[p] + k) % MOD for p in positions]
                target_letters = [ALPH[t] for t in targets]
                feasible_keys.append((k, sc, target_letters))

        residue_data[r] = {
            "positions": positions,
            "n_positions": len(positions),
            "feasible_keys": [(k, sc) for k, sc, _ in feasible_keys],
            "n_feasible": len(feasible_keys),
        }

        print(f"  Feasible key values: {len(feasible_keys)}/26")
        for k, sc, targets in feasible_keys:
            print(f"    k={k:2d}({ALPH[k]}): σ-count={sc:6d} "
                  f"requires CT letters {targets}")

    # Phase 2: Total counts
    print()
    print("=" * 50)
    print("Phase 2: Total Feasible Combinations")
    print("=" * 50)

    n_feasible_per_residue = [residue_data[r]["n_feasible"] for r in range(7)]
    total_feasible_keys = reduce(mul, n_feasible_per_residue, 1)
    print(f"  Feasible keys per residue: {n_feasible_per_residue}")
    print(f"  Total feasible key combos: {total_feasible_keys} (product)")
    print(f"  Out of 26^7 = {26**7}")

    # Compute total σ (upper bound — ignores cross-residue injectivity)
    # Total σ = sum over all feasible key combos of product of σ-counts
    # = product over residues of (sum of σ-counts for feasible keys)
    # Wait no, that's only true if we want the SUM of products, which equals
    # the product of sums ONLY when the terms are independent.
    # Actually: sum_{k0,...,k6 feasible} prod_r sigma_count(r, kr)
    # = prod_r (sum_{kr feasible} sigma_count(r, kr))
    # This is correct because the residues are independent.

    sigma_sum_per_residue = []
    for r in range(7):
        s = sum(sc for _, sc in residue_data[r]["feasible_keys"])
        sigma_sum_per_residue.append(s)

    total_sigma = reduce(mul, sigma_sum_per_residue, 1)
    print(f"\n  σ-sum per residue: {sigma_sum_per_residue}")
    print(f"  Total σ (upper bound): {total_sigma:.6e}")
    print(f"  Average σ per key: {total_sigma / max(total_feasible_keys, 1):.1f}")

    # Phase 3: Most constrained residues
    print()
    print("=" * 50)
    print("Phase 3: Constraint Profile")
    print("=" * 50)
    for r in range(7):
        n_pos = residue_data[r]["n_positions"]
        n_feas = residue_data[r]["n_feasible"]
        total_sc = sum(sc for _, sc in residue_data[r]["feasible_keys"])
        min_sc = min(sc for _, sc in residue_data[r]["feasible_keys"]) if residue_data[r]["feasible_keys"] else 0
        max_sc = max(sc for _, sc in residue_data[r]["feasible_keys"]) if residue_data[r]["feasible_keys"] else 0
        print(f"  r={r}: {n_pos} crib pos, {n_feas}/26 feasible keys, "
              f"σ range [{min_sc}, {max_sc}], total σ={total_sc}")

    # Phase 4: What if we also enforce Bean equality as σ-constraint?
    print()
    print("=" * 50)
    print("Phase 4: With Bean-like σ constraints")
    print("=" * 50)
    # Bean equality: k[27] = k[65]. Under period 7: k[6] = k[2].
    # With transposition: k[6] = CT[σ(27)] - R and k[2] = CT[σ(65)] - R.
    # So CT[σ(27)] must equal CT[σ(65)].
    # This doesn't constrain the KEY tuple — it constrains which σ values are valid.
    # But if we DO enforce k[6] = k[2] as a key constraint:
    total_with_bean_eq = 0
    for k6_val in range(26):
        k2_val = k6_val  # Bean equality
        sc2 = sigma_count_for_residue(2, k2_val)
        sc6 = sigma_count_for_residue(6, k6_val)
        if sc2 > 0 and sc6 > 0:
            # Count combos for other residues
            other_product = 1
            for r in [0, 1, 3, 4, 5]:
                s = sum(sc for _, sc in residue_data[r]["feasible_keys"])
                other_product *= s
            total_with_bean_eq += sc2 * sc6 * other_product

    # Compare
    print(f"  Without Bean equality: {total_sigma:.6e} σ combos")
    print(f"  With Bean equality k[6]=k[2]: {total_with_bean_eq:.6e} σ combos")
    ratio = total_with_bean_eq / total_sigma if total_sigma > 0 else 0
    print(f"  Ratio: {ratio:.4f}")

    # What about the specific Bean inequality (27,72)?
    # Under period 7: k[6] ≠ k[2]. Combined with k[6] = k[2] → impossible.
    # BUT under transposition, this inequality is:
    # CT[σ(27)] - PT[27] ≠ CT[σ(72)] - PT[72]
    # = CT[σ(27)] - R ≠ CT[σ(72)] - C
    # This is a constraint on σ, not the key.
    # For period 7, k[6] = k[2] is a key constraint.
    # The inequality k[27] ≠ k[72] under period 7 becomes k[6] ≠ k[2].
    # This CONTRADICTS k[6] = k[2].
    # UNLESS: the inequality was derived under direct correspondence and
    # doesn't hold under transposition.

    print()
    print("  CRITICAL NOTE:")
    print("  Bean equality (k[6]=k[2]) is VALID for period-7 key because:")
    print("    k[27] = k[27%7] = k[6], k[65] = k[65%7] = k[2]")
    print("    Bean equality k[27]=k[65] → k[6]=k[2]")
    print()
    print("  BUT Bean inequality (27,72) under direct correspondence gives k[6]≠k[2].")
    print("  Under transposition: k[27] ≠ k[72] becomes CT[σ(27)]-R ≠ CT[σ(72)]-C.")
    print("  With period 7: k[6] = k[2], so we need k[27] = k[65] BUT k[27] CAN equal k[72]")
    print("  because the inequality k[27]≠k[72] was derived under DIRECT correspondence only.")
    print()
    print("  QUESTION: Is Bean inequality (27,72) variant-independent?")
    print("  Under ANY substitution: if CT[27]=CT[72] and PT[27]=PT[72], then k[27]=k[72].")
    print(f"  CT[27]={CT[27]}(={CT_IDX[27]}), CT[72]={CT[72]}(={CT_IDX[72]})")
    print(f"  PT[27]={CRIB_DICT[27]}(={PT_IDX[27]}), PT[72]={CRIB_DICT[72]}(={PT_IDX[72]})")

    # Check: CT[27]=P(15), CT[72]=D(3) → different
    # PT[27]=R(17), PT[72]=C(2) → different
    # Under Vigenère: k[27]=(15-17)%26=24, k[72]=(3-2)%26=1 → k[27]≠k[72] ✓
    # Under Beaufort: k[27]=(15+17)%26=6, k[72]=(3+2)%26=5 → k[27]≠k[72] ✓
    # These are under DIRECT correspondence.
    # With transposition: k[27]=CT[σ(27)]-PT[27], k[72]=CT[σ(72)]-PT[72]
    # k[27]=k[72] iff CT[σ(27)]-17 ≡ CT[σ(72)]-2 mod 26
    # iff CT[σ(27)] ≡ CT[σ(72)] + 15 mod 26
    # This CAN be true for some σ! The inequality is NOT guaranteed under transposition.

    print()
    print("  CONCLUSION: Bean inequality (27,72) does NOT force k[6]≠k[2] under transposition.")
    print("  The inequality was derived under direct correspondence only.")
    print("  With transposition, k[27] CAN equal k[72] depending on σ.")
    print("  Therefore: period-7 + transposition IS still viable.")

    elapsed = time.time() - t0

    # Verdict
    if total_sigma == 0:
        verdict = "ELIMINATED — no feasible σ for any period-7 key"
    elif total_sigma < 1e6:
        verdict = f"HIGHLY CONSTRAINED — {total_sigma:.0f} total (key, σ) combos"
    elif total_sigma < 1e12:
        verdict = f"MODERATELY CONSTRAINED — {total_sigma:.2e} combos"
    else:
        verdict = f"UNDERDETERMINED — {total_sigma:.2e} combos (intractable by enumeration)"

    print(f"\n  Verdict: {verdict}")
    print(f"  Time: {elapsed:.1f}s")

    artifact = {
        "experiment": "E-S-57b",
        "period": 7,
        "model": "Sub-then-Transpose, no Bean filter",
        "feasible_keys_per_residue": n_feasible_per_residue,
        "total_feasible_keys": total_feasible_keys,
        "sigma_sum_per_residue": sigma_sum_per_residue,
        "total_sigma_upper_bound": total_sigma,
        "total_with_bean_eq": total_with_bean_eq,
        "residue_data": {str(r): {
            "positions": d["positions"],
            "n_feasible": d["n_feasible"],
            "feasible_keys": d["feasible_keys"],
        } for r, d in residue_data.items()},
        "verdict": verdict,
        "elapsed_seconds": elapsed,
    }

    with open("results/e_s_57b_period7_constraint.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_57b_period7_constraint.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_57b_period7_constraint_correct.py")


if __name__ == "__main__":
    main()
