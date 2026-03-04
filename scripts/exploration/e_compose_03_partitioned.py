#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-COMPOSE-03: Partitioned encryption — two systems on two message parts.

Sanborn: "two separate systems... a major clue in itself."

NOVEL HYPOTHESIS: The "two systems" aren't layered — they're PARTITIONED.
The K4 message is split at some boundary, and each half is encrypted with
a different cipher (potentially different periods, variants, or even
different cipher families).

This has NEVER been tested. All prior work assumed the two systems are
either layered (Sub→Trans) or the same cipher with one key.

Split point candidates:
  - Position 34 (after EASTNORTHEAST ends)
  - Position 48 (midpoint of 97)
  - Position 63 (before BERLINCLOCK starts)
  - Any point from 34 to 62 (between the two crib groups)

For each split, test:
  - Part 1 (contains EASTNORTHEAST): Vig/Beau/VarBeau at periods 2-13
  - Part 2 (contains BERLINCLOCK): Vig/Beau/VarBeau at periods 2-13
  - Cross-system Bean EQ: k1[27] = k2[65] (if both in different parts)
  - Cross-system Bean INEQ: check all pairs spanning the boundary

KEY INSIGHT: With a split, Bean constraints are relaxed because each
system has fewer crib positions. This allows SMALLER periods that are
otherwise impossible for the full 24-crib constraint set.
"""

import os
import sys
import time
import json
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_recover_key, beau_recover_key, varbeau_recover_key,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.aggregate import score_candidate

CT_IDX = [ALPH_IDX[c] for c in CT]
CRIB_LIST = sorted(CRIB_DICT.items())

KEY_RECOVERY = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}
DECRYPT = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


def test_partitioned_encryption(
    split_pos: int,
    period1: int,
    variant1: CipherVariant,
    period2: int,
    variant2: CipherVariant,
):
    """Test partitioned encryption with split at split_pos.

    Part 1: positions 0..split_pos-1, period=period1, variant=variant1
    Part 2: positions split_pos..96, period=period2, variant=variant2

    Returns (score, bean_pass, plaintext, summary, config) or None.
    """
    recover1 = KEY_RECOVERY[variant1]
    recover2 = KEY_RECOVERY[variant2]
    decrypt1 = DECRYPT[variant1]
    decrypt2 = DECRYPT[variant2]

    # Separate cribs by partition
    cribs1 = [(pos, ALPH_IDX[ch]) for pos, ch in CRIB_LIST if pos < split_pos]
    cribs2 = [(pos, ALPH_IDX[ch]) for pos, ch in CRIB_LIST if pos >= split_pos]

    if not cribs1 or not cribs2:
        return None  # One partition has no cribs → underdetermined

    # Check consistency for Part 1
    key1_constraints = defaultdict(list)
    for pos, pt_val in cribs1:
        residue = pos % period1
        k_val = recover1(CT_IDX[pos], pt_val)
        key1_constraints[residue].append(k_val)

    key1_vals = {}
    for residue, vals in key1_constraints.items():
        if len(set(vals)) > 1:
            return None
        key1_vals[residue] = vals[0]

    # Check consistency for Part 2
    key2_constraints = defaultdict(list)
    for pos, pt_val in cribs2:
        residue = (pos - split_pos) % period2  # Relative position within Part 2
        k_val = recover2(CT_IDX[pos], pt_val)
        key2_constraints[residue].append(k_val)

    key2_vals = {}
    for residue, vals in key2_constraints.items():
        if len(set(vals)) > 1:
            return None
        key2_vals[residue] = vals[0]

    # Cross-system Bean constraints
    for a, b in BEAN_EQ:
        a_in_1 = (a < split_pos)
        b_in_1 = (b < split_pos)

        if a_in_1 and b_in_1:
            # Both in Part 1
            ra, rb = a % period1, b % period1
            if ra in key1_vals and rb in key1_vals:
                if key1_vals[ra] != key1_vals[rb]:
                    return None
        elif not a_in_1 and not b_in_1:
            # Both in Part 2
            ra = (a - split_pos) % period2
            rb = (b - split_pos) % period2
            if ra in key2_vals and rb in key2_vals:
                if key2_vals[ra] != key2_vals[rb]:
                    return None
        else:
            # Across partitions: k1 at position a = k2 at position b (or vice versa)
            if a_in_1:
                ra = a % period1
                rb = (b - split_pos) % period2
                if ra in key1_vals and rb in key2_vals:
                    if key1_vals[ra] != key2_vals[rb]:
                        return None
            else:
                ra = (a - split_pos) % period2
                rb = b % period1
                if ra in key2_vals and rb in key1_vals:
                    if key2_vals[ra] != key1_vals[rb]:
                        return None

    for a, b in BEAN_INEQ:
        a_in_1 = (a < split_pos)
        b_in_1 = (b < split_pos)

        if a_in_1 and b_in_1:
            ra, rb = a % period1, b % period1
            if ra in key1_vals and rb in key1_vals:
                if key1_vals[ra] == key1_vals[rb]:
                    return None
        elif not a_in_1 and not b_in_1:
            ra = (a - split_pos) % period2
            rb = (b - split_pos) % period2
            if ra in key2_vals and rb in key2_vals:
                if key2_vals[ra] == key2_vals[rb]:
                    return None
        else:
            if a_in_1:
                ra = a % period1
                rb = (b - split_pos) % period2
                if ra in key1_vals and rb in key2_vals:
                    if key1_vals[ra] == key2_vals[rb]:
                        return None
            else:
                ra = (a - split_pos) % period2
                rb = b % period1
                if ra in key2_vals and rb in key1_vals:
                    if key2_vals[ra] == key1_vals[rb]:
                        return None

    # All checks passed — decrypt full text
    plaintext_chars = []
    for i in range(CT_LEN):
        if i < split_pos:
            k = key1_vals.get(i % period1, 0)
            pt = decrypt1(CT_IDX[i], k)
        else:
            k = key2_vals.get((i - split_pos) % period2, 0)
            pt = decrypt2(CT_IDX[i], k)
        plaintext_chars.append(ALPH[pt])

    plaintext = ''.join(plaintext_chars)
    sc = score_candidate(plaintext)

    config = (f"split={split_pos}, P1:{variant1.value}@p{period1}, "
              f"P2:{variant2.value}@p{period2}")

    return (sc.crib_score, sc.bean_passed, plaintext, sc.summary, config,
            sc.ic_value)


def test_partitioned_absolute_key(
    split_pos: int,
    period1: int,
    variant1: CipherVariant,
    period2: int,
    variant2: CipherVariant,
):
    """Same as above but Part 2 key indexed from position 0 (absolute).

    Alternative: Part 2 key continues from same absolute position,
    not reset at the split boundary.
    """
    recover1 = KEY_RECOVERY[variant1]
    recover2 = KEY_RECOVERY[variant2]
    decrypt1 = DECRYPT[variant1]
    decrypt2 = DECRYPT[variant2]

    cribs1 = [(pos, ALPH_IDX[ch]) for pos, ch in CRIB_LIST if pos < split_pos]
    cribs2 = [(pos, ALPH_IDX[ch]) for pos, ch in CRIB_LIST if pos >= split_pos]

    if not cribs1 or not cribs2:
        return None

    key1_constraints = defaultdict(list)
    for pos, pt_val in cribs1:
        residue = pos % period1
        k_val = recover1(CT_IDX[pos], pt_val)
        key1_constraints[residue].append(k_val)

    key1_vals = {}
    for residue, vals in key1_constraints.items():
        if len(set(vals)) > 1:
            return None
        key1_vals[residue] = vals[0]

    # Part 2: key indexed by ABSOLUTE position
    key2_constraints = defaultdict(list)
    for pos, pt_val in cribs2:
        residue = pos % period2  # Absolute position
        k_val = recover2(CT_IDX[pos], pt_val)
        key2_constraints[residue].append(k_val)

    key2_vals = {}
    for residue, vals in key2_constraints.items():
        if len(set(vals)) > 1:
            return None
        key2_vals[residue] = vals[0]

    # Cross-system Bean
    for a, b in BEAN_EQ:
        a_in_1 = (a < split_pos)
        b_in_1 = (b < split_pos)
        if a_in_1 and b_in_1:
            ra, rb = a % period1, b % period1
            if ra in key1_vals and rb in key1_vals:
                if key1_vals[ra] != key1_vals[rb]:
                    return None
        elif not a_in_1 and not b_in_1:
            ra, rb = a % period2, b % period2
            if ra in key2_vals and rb in key2_vals:
                if key2_vals[ra] != key2_vals[rb]:
                    return None
        else:
            if a_in_1:
                ra = a % period1
                rb = b % period2
                if ra in key1_vals and rb in key2_vals:
                    if key1_vals[ra] != key2_vals[rb]:
                        return None
            else:
                ra = a % period2
                rb = b % period1
                if ra in key2_vals and rb in key1_vals:
                    if key2_vals[ra] != key1_vals[rb]:
                        return None

    for a, b in BEAN_INEQ:
        a_in_1 = (a < split_pos)
        b_in_1 = (b < split_pos)
        if a_in_1 and b_in_1:
            ra, rb = a % period1, b % period1
            if ra in key1_vals and rb in key1_vals:
                if key1_vals[ra] == key1_vals[rb]:
                    return None
        elif not a_in_1 and not b_in_1:
            ra, rb = a % period2, b % period2
            if ra in key2_vals and rb in key2_vals:
                if key2_vals[ra] == key2_vals[rb]:
                    return None
        else:
            if a_in_1:
                ra = a % period1
                rb = b % period2
                if ra in key1_vals and rb in key2_vals:
                    if key1_vals[ra] == key2_vals[rb]:
                        return None
            else:
                ra = a % period2
                rb = b % period1
                if ra in key2_vals and rb in key1_vals:
                    if key2_vals[ra] == key1_vals[rb]:
                        return None

    plaintext_chars = []
    for i in range(CT_LEN):
        if i < split_pos:
            k = key1_vals.get(i % period1, 0)
            pt = decrypt1(CT_IDX[i], k)
        else:
            k = key2_vals.get(i % period2, 0)
            pt = decrypt2(CT_IDX[i], k)
        plaintext_chars.append(ALPH[pt])

    plaintext = ''.join(plaintext_chars)
    sc = score_candidate(plaintext)
    config = (f"split={split_pos}[abs], P1:{variant1.value}@p{period1}, "
              f"P2:{variant2.value}@p{period2}")
    return (sc.crib_score, sc.bean_passed, plaintext, sc.summary, config,
            sc.ic_value)


def main():
    print("=" * 78)
    print("E-COMPOSE-03: Partitioned Encryption (Two Systems, Two Parts)")
    print("=" * 78)
    print("\nHypothesis: 'Two separate systems' = two ciphers on two message halves")
    t0 = time.time()

    # Split points between the two crib groups
    split_points = list(range(34, 63))  # After EASTNORTHEAST, before BERLINCLOCK

    # Periods to test (including small periods that might work within partitions)
    periods = list(range(2, 14))

    total_configs = 0
    consistent_count = 0
    all_results = []

    # Count diagnostics
    diag = {"inconsistent": 0, "bean_fail": 0, "bean_pass": 0}

    for split in split_points:
        for p1 in periods:
            for v1 in VARIANTS:
                for p2 in periods:
                    for v2 in VARIANTS:
                        total_configs += 1

                        # Test with relative key indexing
                        result = test_partitioned_encryption(
                            split, p1, v1, p2, v2
                        )
                        if result is not None:
                            consistent_count += 1
                            if result[1]:  # bean_pass
                                diag["bean_pass"] += 1
                            else:
                                diag["bean_fail"] += 1
                            if result[0] >= NOISE_FLOOR:
                                all_results.append(result)
                        else:
                            diag["inconsistent"] += 1

                        # Test with absolute key indexing
                        total_configs += 1
                        result2 = test_partitioned_absolute_key(
                            split, p1, v1, p2, v2
                        )
                        if result2 is not None:
                            consistent_count += 1
                            if result2[1]:
                                diag["bean_pass"] += 1
                            else:
                                diag["bean_fail"] += 1
                            if result2[0] >= NOISE_FLOOR:
                                all_results.append(result2)
                        else:
                            diag["inconsistent"] += 1

    elapsed = time.time() - t0

    print(f"\nTotal configurations: {total_configs:,}")
    print(f"Consistent: {consistent_count:,}")
    print(f"  Bean PASS: {diag['bean_pass']:,}")
    print(f"  Bean FAIL: {diag['bean_fail']:,}")
    print(f"Inconsistent: {diag['inconsistent']:,}")
    print(f"Elapsed: {elapsed:.1f}s")

    if all_results:
        all_results.sort(key=lambda r: (r[0], r[1]), reverse=True)
        print(f"\n{'─' * 78}")
        print(f"Results above noise floor ({NOISE_FLOOR}):")
        print(f"{'─' * 78}")
        for r in all_results[:20]:
            print(f"  [{r[0]:2d}/24] bean={'PASS' if r[1] else 'FAIL'} IC={r[5]:.4f} | {r[4]}")
            if r[0] >= STORE_THRESHOLD:
                print(f"    PT: {r[2]}")
            else:
                print(f"    PT: {r[2][:50]}...")
    else:
        print(f"\n  No results above noise floor ({NOISE_FLOOR}).")

    # ── Period-specific analysis ──────────────────────────────────────────
    # Check which period PAIRS have any consistent configs
    period_pair_counts = defaultdict(int)
    for split in split_points[:5]:  # Sample 5 splits
        for p1 in periods:
            for v1 in [CipherVariant.VIGENERE]:
                for p2 in periods:
                    for v2 in [CipherVariant.VIGENERE]:
                        result = test_partitioned_encryption(split, p1, v1, p2, v2)
                        if result is not None:
                            period_pair_counts[(p1, p2)] += 1

    if period_pair_counts:
        print(f"\n{'─' * 78}")
        print("Consistent period pairs (Vigenère only, 5 splits sampled):")
        for (p1, p2), count in sorted(period_pair_counts.items()):
            print(f"  p1={p1:2d}, p2={p2:2d}: {count} consistent")

    best_score = max((r[0] for r in all_results), default=0)
    print(f"\nBest score: {best_score}/24")
    print(f"Verdict: {'NOISE' if best_score <= 9 else 'INTERESTING'}")

    # Save
    results_dir = os.path.join(os.path.dirname(__file__), '..', 'results')
    os.makedirs(results_dir, exist_ok=True)
    output = {
        "experiment": "E-COMPOSE-03",
        "description": "Partitioned encryption — two systems on two message parts",
        "split_range": [34, 62],
        "periods_tested": periods,
        "total_configs": total_configs,
        "consistent": consistent_count,
        "bean_pass": diag["bean_pass"],
        "bean_fail": diag["bean_fail"],
        "inconsistent": diag["inconsistent"],
        "best_score": best_score,
        "elapsed": elapsed,
        "top_results": [
            {"score": r[0], "bean": r[1], "config": r[4], "ic": r[5]}
            for r in all_results[:10]
        ] if all_results else [],
    }
    with open(os.path.join(results_dir, "e_compose_03.json"), 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\nResults saved to results/e_compose_03.json")


if __name__ == "__main__":
    main()
