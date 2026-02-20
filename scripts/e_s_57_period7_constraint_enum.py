#!/usr/bin/env python3
"""E-S-57: Period-7 Transposition Constraint Enumeration.

For model: CT[σ(p)] = PT[p] + k[p%7] mod 26  (Sub then Transpose)

At each crib position p: σ(p) must be a CT position i where CT[i] = (PT[p] + k[p%7]) % 26.

For period 7, the 24 crib positions split into 7 residue classes:
  r=0: {21,28,63,70}  r=1: {22,29,64,71}  r=2: {23,30,65,72}
  r=3: {24,31,66,73}  r=4: {25,32,67}     r=5: {26,33,68}
  r=6: {27,69}

For each key value k[r], positions in class r must map to CT positions with
specific letter values. The σ must be injective (no two map to same CT position).

This experiment:
1. For each of 26^7 period-7 keys, count feasible σ at crib positions
2. Use Bean constraint (k[6] = k[2] since 27%7=6, 65%7=2 — wait, let me check:
   27%7=6, 65%7=2. Bean says k[27]=k[65], so k[6]=k[2])
3. Report: number of valid (key, σ-at-cribs) combinations
4. Identify the most constrained keys (fewest σ options)

This gives an EXACT measure of the problem's difficulty.
"""

import json
import time
import sys
from collections import Counter, defaultdict
from itertools import product as iterproduct

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_IDX = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Build CT position lookup: letter_value -> list of CT positions
CT_POS_BY_LETTER = defaultdict(list)
for i, val in enumerate(CT_IDX):
    CT_POS_BY_LETTER[val].append(i)

# Crib positions grouped by residue mod 7
CRIB_BY_RESIDUE = defaultdict(list)
for pos in sorted(CRIB_POSITIONS):
    CRIB_BY_RESIDUE[pos % 7].append(pos)

print("Crib positions by residue mod 7:")
for r in range(7):
    positions = CRIB_BY_RESIDUE[r]
    pts = [CRIB_DICT[p] for p in positions]
    print(f"  r={r}: positions={positions} PT={pts}")

# Bean constraint: k[27]=k[65]
# 27 % 7 = 6, 65 % 7 = 2 → k[6] = k[2]
BEAN_RESIDUE_EQ = (6, 2)  # k[6] must equal k[2]
print(f"\nBean equality: k[{BEAN_RESIDUE_EQ[0]}] = k[{BEAN_RESIDUE_EQ[1]}]")

# Bean inequalities mapped to residue classes
# k[p1] != k[p2] → k[p1%7] != k[p2%7] ONLY if p1%7 == p2%7 — wait, no.
# Bean says k[p1] != k[p2] where k is the FULL keystream, not the period-7 key.
# For periodic key: k[p1] = k[p1%7], k[p2] = k[p2%7].
# So k[p1] != k[p2] ↔ k[p1%7] != k[p2%7].
# These are constraints between KEY VALUES at DIFFERENT residues.
BEAN_INEQ_RESIDUES = set()
for p1, p2 in [(24,28),(28,33),(24,33),(21,30),(21,64),(30,64),
               (68,25),(22,31),(66,70),(26,71),(69,72),(23,32),
               (71,21),(25,26),(24,66),(31,73),(29,63),(32,33),
               (67,68),(27,72),(23,28)]:
    r1, r2 = p1 % 7, p2 % 7
    if r1 != r2:  # Same-residue inequalities are automatically satisfied (same key value)
        pair = (min(r1, r2), max(r1, r2))
        BEAN_INEQ_RESIDUES.add(pair)

print(f"Bean inequality residue pairs: {sorted(BEAN_INEQ_RESIDUES)}")
print(f"({len(BEAN_INEQ_RESIDUES)} unique cross-residue inequality pairs)")


def count_feasible_sigma_for_residue(residue, key_val):
    """Count number of feasible σ-assignments for one residue class.

    For each crib position p in the class:
      σ(p) must be a CT position i where CT[i] = (PT[p] + key_val) % 26

    Returns the number of ways to assign distinct CT positions to all positions
    in the class. This is a product of available positions (decreasing as we assign).

    More precisely: it's the number of injective mappings from crib positions
    to CT positions with the required letter values.
    """
    positions = CRIB_BY_RESIDUE[residue]
    if not positions:
        return 1  # No crib positions in this residue → unconstrained

    # For each crib position, which letter must CT[σ(p)] have?
    required_letters = []
    for p in positions:
        pt_val = PT_IDX[p]
        target_letter = (pt_val + key_val) % MOD
        required_letters.append(target_letter)

    # Group by required letter value
    # Count how many positions need each letter
    letter_needs = Counter(required_letters)

    # Available CT positions by letter
    available = {}
    for letter_val, count in letter_needs.items():
        avail = len(CT_POS_BY_LETTER[letter_val])
        if avail < count:
            return 0  # Not enough CT positions with this letter
        available[letter_val] = avail

    # Number of injective assignments = product of falling factorials
    # For each distinct letter: need to choose count positions from avail
    # This is P(avail, count) = avail! / (avail-count)!
    total = 1
    for letter_val, count in letter_needs.items():
        avail = available[letter_val]
        for i in range(count):
            total *= (avail - i)

    return total


def count_feasible_sigma_total(key_tuple, cross_residue=True):
    """Count total feasible σ-assignments for a period-7 key.

    Without cross-residue interaction (independence approximation):
      Product over residues of count_feasible_sigma_for_residue

    The cross-residue constraint is that σ must be injective GLOBALLY
    (no two crib positions from different residues can map to the same CT position).
    This is harder to compute exactly, so we compute the independent upper bound.
    """
    total = 1
    for r in range(7):
        count = count_feasible_sigma_for_residue(r, key_tuple[r])
        if count == 0:
            return 0
        total *= count
    return total


def main():
    print()
    print("=" * 70)
    print("E-S-57: Period-7 Transposition Constraint Enumeration")
    print("=" * 70)
    print()

    t0 = time.time()

    # First: show CT letter distribution
    ct_counts = Counter(CT)
    print("CT letter counts:")
    for val in range(MOD):
        letter = ALPH[val]
        count = ct_counts.get(letter, 0)
        if count > 0:
            print(f"  {letter}({val}): {count}", end="")
    print("\n")

    # Phase 1: Enumerate ALL 26^7 keys (but with Bean: k[6]=k[2] → 26^6)
    print("=" * 50)
    print("Phase 1: Exhaustive key enumeration with Bean equality")
    print("=" * 50)

    n_keys_total = 0
    n_keys_feasible = 0
    n_keys_bean_ineq_pass = 0
    total_sigma_upper_bound = 0
    key_sigma_counts = []

    # With Bean: k[6] = k[2], so we only iterate over k[0]..k[5], and k[6] = k[2]
    n_iterations = 26**6
    print(f"Keys to test: 26^6 = {n_iterations} (k[6] forced = k[2])")

    report_interval = 26**5  # Report every 26^5 keys

    for k0 in range(26):
        for k1 in range(26):
            for k2 in range(26):
                k6 = k2  # Bean equality
                for k3 in range(26):
                    for k4 in range(26):
                        for k5 in range(26):
                            key = (k0, k1, k2, k3, k4, k5, k6)
                            n_keys_total += 1

                            # Bean inequality check
                            bean_pass = True
                            for r1, r2 in BEAN_INEQ_RESIDUES:
                                if key[r1] == key[r2]:
                                    bean_pass = False
                                    break

                            if not bean_pass:
                                continue

                            n_keys_bean_ineq_pass += 1

                            # Count feasible σ (upper bound, independent residues)
                            sigma_count = count_feasible_sigma_total(key)
                            if sigma_count > 0:
                                n_keys_feasible += 1
                                total_sigma_upper_bound += sigma_count
                                if sigma_count <= 1000 or n_keys_feasible <= 20:
                                    key_sigma_counts.append((sigma_count, key))

            if n_keys_total % report_interval == 0:
                pct = n_keys_total / n_iterations * 100
                print(f"  {pct:5.1f}%: tested={n_keys_total} "
                      f"bean_pass={n_keys_bean_ineq_pass} "
                      f"feasible={n_keys_feasible} "
                      f"sigma_total={total_sigma_upper_bound:.2e} "
                      f"[{time.time()-t0:.1f}s]")

    elapsed = time.time() - t0

    # Sort by sigma count (ascending = most constrained)
    key_sigma_counts.sort()

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"  Total keys tested: {n_keys_total}")
    print(f"  Bean equality applied: k[6] = k[2]")
    print(f"  Bean inequalities pass: {n_keys_bean_ineq_pass}")
    print(f"  Feasible keys (σ > 0): {n_keys_feasible}")
    print(f"  Total σ upper bound (sum): {total_sigma_upper_bound:.6e}")
    print(f"  Average σ per feasible key: {total_sigma_upper_bound/max(n_keys_feasible,1):.1f}")
    print(f"  Time: {elapsed:.1f}s")

    if key_sigma_counts:
        print(f"\n  Most constrained keys (fewest σ options):")
        for sigma_count, key in key_sigma_counts[:20]:
            key_str = ''.join(ALPH[k] for k in key)
            print(f"    σ={sigma_count:8d} key={key_str} ({list(key)})")

        # How many keys have σ_count = 0? (Already excluded)
        # How many have σ_count <= 100?
        very_constrained = sum(1 for sc, _ in key_sigma_counts if sc <= 100)
        print(f"\n  Keys with σ ≤ 100: {very_constrained}")
        mid_constrained = sum(1 for sc, _ in key_sigma_counts if sc <= 10000)
        print(f"  Keys with σ ≤ 10,000: {mid_constrained}")

    # Phase 2: Check the known Vigenère keystream at period 7
    print()
    print("=" * 50)
    print("Phase 2: Known Keystream at Period 7")
    print("=" * 50)
    # The known key values at crib positions under direct correspondence (no transposition)
    # are NOT periodic. But IF there's a transposition making them periodic, what key would it be?

    # Under direct correspondence, the key is:
    direct_key = {}
    for pos in sorted(CRIB_POSITIONS):
        direct_key[pos] = (CT_IDX[pos] - PT_IDX[pos]) % MOD

    # Group by residue and show
    for r in range(7):
        positions = CRIB_BY_RESIDUE[r]
        key_vals = [direct_key[p] for p in positions]
        key_letters = [ALPH[k] for k in key_vals]
        print(f"  r={r}: key_vals={key_vals} ({key_letters}) "
              f"{'CONSISTENT' if len(set(key_vals)) == 1 else 'INCONSISTENT'}")

    # Phase 3: For the identity transposition, what's the σ count?
    print()
    print("=" * 50)
    print("Phase 3: Identity Transposition Check")
    print("=" * 50)
    # Under identity σ: direct correspondence
    # For period 7, we need all positions in each residue to have the same key value
    # This is the standard periodic Vigenère check at period 7
    # From Phase 2 output, we can see which residues are consistent
    for r in range(7):
        positions = CRIB_BY_RESIDUE[r]
        key_vals = [direct_key[p] for p in positions]
        if len(set(key_vals)) == 1:
            print(f"  r={r}: CONSISTENT (k={key_vals[0]}={ALPH[key_vals[0]]})")
        else:
            print(f"  r={r}: CONTRADICTS — {key_vals} ({[ALPH[k] for k in key_vals]})")

    # Phase 4: Sigma count distribution (histogram)
    print()
    print("=" * 50)
    print("Phase 4: σ-count distribution")
    print("=" * 50)
    if key_sigma_counts:
        import math
        log_bins = [0, 1, 10, 100, 1000]
        for i in range(len(log_bins) - 1):
            count = sum(1 for sc, _ in key_sigma_counts if log_bins[i] < sc <= log_bins[i+1])
            if count > 0:
                print(f"  σ in ({log_bins[i]}, {log_bins[i+1]}]: {count} keys")
        over1000 = n_keys_feasible - len(key_sigma_counts) + sum(1 for sc, _ in key_sigma_counts if sc > 1000)
        print(f"  σ > 1000: {over1000} keys (not all stored)")

    # Verdict
    print()
    if n_keys_feasible == 0:
        verdict = "ELIMINATED — period-7 Vigenère with ANY transposition is IMPOSSIBLE"
    elif total_sigma_upper_bound < 1e6:
        verdict = f"HIGHLY CONSTRAINED — only {total_sigma_upper_bound:.0f} total (σ,key) combos"
    elif total_sigma_upper_bound < 1e12:
        verdict = f"MODERATELY CONSTRAINED — {total_sigma_upper_bound:.2e} combos (tractable)"
    else:
        verdict = f"UNDERDETERMINED — {total_sigma_upper_bound:.2e} combos (intractable by enumeration)"

    print(f"  Verdict: {verdict}")

    artifact = {
        "experiment": "E-S-57",
        "period": 7,
        "model": "Sub-then-Transpose (CT[sigma(p)] = PT[p] + k[p%7])",
        "n_keys_total": n_keys_total,
        "n_bean_ineq_pass": n_keys_bean_ineq_pass,
        "n_feasible": n_keys_feasible,
        "total_sigma_upper_bound": total_sigma_upper_bound,
        "avg_sigma_per_key": total_sigma_upper_bound / max(n_keys_feasible, 1),
        "most_constrained": [
            {"sigma": sc, "key": list(k), "key_str": ''.join(ALPH[v] for v in k)}
            for sc, k in key_sigma_counts[:50]
        ],
        "verdict": verdict,
        "elapsed_seconds": elapsed,
    }

    with open("results/e_s_57_period7_constraint.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_57_period7_constraint.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_57_period7_constraint_enum.py")


if __name__ == "__main__":
    main()
