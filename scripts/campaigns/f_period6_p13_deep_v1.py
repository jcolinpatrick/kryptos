#!/usr/bin/env python3
"""
Deep analysis of the col6 + period-13 hits scoring 16/24.

Key questions:
1. Is 16/24 at period 13 above noise? (underdetermination check)
2. What are the actual plaintext fragments?
3. Do ANY permutations reach 17+ or 24/24?
4. Monte Carlo baseline for period-13 on 73-char text after random col6 trans
5. Detailed residue breakdown for the best hits
"""

import sys
import os
import json
import time
import itertools
import random
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, KEY_RECOVERY, DECRYPT_FN, decrypt_text
)
from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm

# Setup
CT97 = CT
MASK_24 = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59, 74, 75, 78, 84, 85, 88, 94, 96]
MASK_SET = set(MASK_24)

ct73_chars = []
ct73_to_ct97 = {}
for i in range(97):
    if i not in MASK_SET:
        ct73_to_ct97[len(ct73_chars)] = i
        ct73_chars.append(CT97[i])
CT73 = ''.join(ct73_chars)

ENE_CT97 = list(range(21, 34))
BCL_CT97 = list(range(63, 74))
ENE_TEXT = "EASTNORTHEAST"
BCL_TEXT = "BERLINCLOCK"

ct97_to_ct73 = {}
for ct73_idx, ct97_idx in ct73_to_ct97.items():
    ct97_to_ct73[ct97_idx] = ct73_idx

ENE_CT73 = [ct97_to_ct73[p] for p in ENE_CT97]
BCL_CT73 = [ct97_to_ct73[p] for p in BCL_CT97]

CRIB_CT73 = {}
for i, pos in enumerate(ENE_CT73):
    CRIB_CT73[pos] = ENE_TEXT[i]
for i, pos in enumerate(BCL_CT73):
    CRIB_CT73[pos] = BCL_TEXT[i]

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def apply_columnar_inverse(text, width, col_order):
    n = len(text)
    nrows = (n + width - 1) // width
    ncomplete = n - (nrows - 1) * width

    col_lengths = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        if col_idx < ncomplete:
            col_lengths.append(nrows)
        else:
            col_lengths.append(nrows - 1)

    columns_by_rank = {}
    pos = 0
    for rank in range(width):
        length = col_lengths[rank]
        columns_by_rank[rank] = text[pos:pos + length]
        pos += length

    columns_by_idx = {}
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        columns_by_idx[col_idx] = columns_by_rank[rank]

    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(columns_by_idx[col]):
                result.append(columns_by_idx[col][row])

    return ''.join(result)


def score_crib_consistency(ct_text, crib_dict, period, variant, use_ka=False):
    recover = KEY_RECOVERY[variant]
    residues = defaultdict(list)
    for pos, pt_ch in crib_dict.items():
        residues[pos % period].append((pos, pt_ch))

    total_consistent = 0
    key_values = {}
    conflicts = {}

    for r, positions in residues.items():
        keys_at_r = []
        for pos, pt_ch in positions:
            if use_ka:
                c_val = KA_IDX[ct_text[pos]]
                p_val = KA_IDX[pt_ch]
            else:
                c_val = ord(ct_text[pos]) - 65
                p_val = ord(pt_ch) - 65
            k = recover(c_val, p_val)
            keys_at_r.append((pos, k))

        key_counts = defaultdict(int)
        for _, k in keys_at_r:
            key_counts[k] += 1

        best_k = max(key_counts, key=key_counts.get)
        n_consistent = key_counts[best_k]
        total_consistent += n_consistent
        key_values[r] = best_k
        conflicts[r] = len(keys_at_r) - n_consistent

    return total_consistent, key_values, conflicts


def full_key_from_cribs(ct_text, crib_dict, period, variant, use_ka=False):
    recover = KEY_RECOVERY[variant]
    residues = defaultdict(list)
    for pos, pt_ch in crib_dict.items():
        residues[pos % period].append((pos, pt_ch))

    key = [None] * period
    total_consistent = 0
    total_conflicts = 0

    for r in range(period):
        if r not in residues:
            key[r] = 0
            continue
        positions = residues[r]
        keys_at_r = []
        for pos, pt_ch in positions:
            if use_ka:
                c_val = KA_IDX[ct_text[pos]]
                p_val = KA_IDX[pt_ch]
            else:
                c_val = ord(ct_text[pos]) - 65
                p_val = ord(pt_ch) - 65
            k = recover(c_val, p_val)
            keys_at_r.append(k)

        key_counts = defaultdict(int)
        for k in keys_at_r:
            key_counts[k] += 1

        best_k = max(key_counts, key=key_counts.get)
        key[r] = best_k
        total_consistent += key_counts[best_k]
        total_conflicts += len(keys_at_r) - key_counts[best_k]

    return key, total_consistent, total_conflicts


def map_cribs_through_transposition(crib_dict, width, col_order, text_len):
    perm = columnar_perm(width, col_order, text_len)
    inv = invert_perm(perm)
    mapped_cribs = {}
    for pos, ch in crib_dict.items():
        if pos < text_len:
            mapped_cribs[inv[pos]] = ch
    return mapped_cribs


# ============================================================
# 1. Monte Carlo baseline: period-13 on 73-char random text
# ============================================================

def mc_period13_baseline(n_trials=10000):
    """Estimate expected crib consistency score for period-13
    on 73-char text after random col-6 transposition."""
    print("=" * 70)
    print("MONTE CARLO: Period-13 on 73-char text (baseline)")
    print(f"  {n_trials} trials")
    print("=" * 70)

    variants = [
        ("vig_AZ", CipherVariant.VIGENERE, False),
        ("beau_AZ", CipherVariant.BEAUFORT, False),
        ("vig_KA", CipherVariant.VIGENERE, True),
        ("beau_KA", CipherVariant.BEAUFORT, True),
    ]

    all_perms = list(itertools.permutations(range(6)))

    for var_name, var, use_ka in variants:
        scores = []
        for _ in range(n_trials):
            # Random permutation
            perm = random.choice(all_perms)
            ct_int = apply_columnar_inverse(CT73, 6, list(perm))
            mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, list(perm), 73)

            score, _, _ = score_crib_consistency(ct_int, mapped_cribs, 13, var, use_ka)
            scores.append(score)

        mean_s = sum(scores) / len(scores)
        max_s = max(scores)
        p16 = sum(1 for s in scores if s >= 16) / len(scores)
        p17 = sum(1 for s in scores if s >= 17) / len(scores)
        p18 = sum(1 for s in scores if s >= 18) / len(scores)

        print(f"  {var_name}: mean={mean_s:.2f}, max={max_s}, P(>=16)={p16:.4f}, P(>=17)={p17:.4f}, P(>=18)={p18:.4f}")

    # Also test period-13 directly on CT73 (no transposition)
    print("\n  Direct (no transposition):")
    for var_name, var, use_ka in variants:
        score, _, _ = score_crib_consistency(CT73, CRIB_CT73, 13, var, use_ka)
        print(f"  {var_name}: score={score}/24")

    # Also period-13 on RANDOM 73-char text
    print("\n  Fully random 73-char text baseline:")
    for var_name, var, use_ka in variants:
        scores = []
        for _ in range(n_trials):
            random_ct = ''.join(random.choice(ALPH) for _ in range(73))
            score, _, _ = score_crib_consistency(random_ct, CRIB_CT73, 13, var, use_ka)
            scores.append(score)

        mean_s = sum(scores) / len(scores)
        max_s = max(scores)
        p16 = sum(1 for s in scores if s >= 16) / len(scores)

        print(f"  {var_name}: mean={mean_s:.2f}, max={max_s}, P(>=16)={p16:.4f}")


# ============================================================
# 2. Detailed analysis of the 16/24 hits
# ============================================================

def analyze_top_hits():
    """Detailed residue-by-residue breakdown of 16/24 hits."""
    print("\n" + "=" * 70)
    print("DETAILED ANALYSIS: All 16/24 hits at col6 + period-13")
    print("=" * 70)

    top_perms = [
        (0, 1, 3, 5, 2, 4),
        (1, 0, 4, 2, 5, 3),
        (3, 5, 0, 4, 1, 2),
        (4, 3, 0, 2, 1, 5),
    ]

    configs = [
        ("vig_KA", CipherVariant.VIGENERE, True),
        ("beau_KA", CipherVariant.BEAUFORT, True),
        ("vbeau_KA", CipherVariant.VAR_BEAUFORT, True),
    ]

    for perm in top_perms:
        ct_int = apply_columnar_inverse(CT73, 6, list(perm))
        mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, list(perm), 73)

        for var_name, var, use_ka in configs:
            score, key_vals, conflicts = score_crib_consistency(
                ct_int, mapped_cribs, 13, var, use_ka
            )

            if score >= 16:
                key, _, total_conflicts = full_key_from_cribs(
                    ct_int, mapped_cribs, 13, var, use_ka
                )

                # Decrypt
                fn = DECRYPT_FN[var]
                pt = []
                for i, c in enumerate(ct_int):
                    c_val = KA_IDX[c]
                    k_val = key[i % 13]
                    p_val = fn(c_val, k_val)
                    pt.append(KA[p_val])
                pt = ''.join(pt)

                key_str = ''.join(chr(k + 65) for k in key)

                print(f"\n  perm={perm} {var_name}: {score}/24, key={key_str}")
                print(f"  PT: {pt}")

                # Residue breakdown
                recover = KEY_RECOVERY[var]
                for r in range(13):
                    positions = [(p, ch) for p, ch in mapped_cribs.items() if p % 13 == r]
                    if positions:
                        detail = []
                        for pos, ch in positions:
                            c_val = KA_IDX[ct_int[pos]]
                            p_val = KA_IDX[ch]
                            k = recover(c_val, p_val)
                            detail.append(f"{chr(k+65)}@{pos}")
                        unique_keys = set(d.split('@')[0] for d in detail)
                        ok = "OK" if len(unique_keys) == 1 else f"CONFLICT({len(unique_keys)})"
                        print(f"    r={r:2d}: {', '.join(detail)} [{ok}]")
                    else:
                        print(f"    r={r:2d}: (no crib positions)")

                # Check how many residues have 0 cribs, 1 crib, 2+ cribs
                crib_per_residue = defaultdict(int)
                for p in mapped_cribs:
                    crib_per_residue[p % 13] += 1

                n_empty = sum(1 for r in range(13) if crib_per_residue[r] == 0)
                n_single = sum(1 for r in range(13) if crib_per_residue[r] == 1)
                n_multi = sum(1 for r in range(13) if crib_per_residue[r] >= 2)
                print(f"  Residue distribution: {n_empty} empty, {n_single} single, {n_multi} multi")
                print(f"  24 crib positions across 13 residues: avg {24/13:.1f}/residue")


# ============================================================
# 3. Exhaustive col6 + period-13 (ALL 720 perms, all configs)
# ============================================================

def exhaustive_col6_p13_worker(perm_tuple):
    """Check all col6 perms for period-13 scores."""
    col_order = list(perm_tuple)
    results = []

    ct_int = apply_columnar_inverse(CT73, 6, col_order)
    mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, col_order, 73)

    configs = [
        ("vig_AZ", CipherVariant.VIGENERE, False),
        ("beau_AZ", CipherVariant.BEAUFORT, False),
        ("vbeau_AZ", CipherVariant.VAR_BEAUFORT, False),
        ("vig_KA", CipherVariant.VIGENERE, True),
        ("beau_KA", CipherVariant.BEAUFORT, True),
        ("vbeau_KA", CipherVariant.VAR_BEAUFORT, True),
    ]

    for var_name, var, use_ka in configs:
        score, _, conflicts = score_crib_consistency(
            ct_int, mapped_cribs, 13, var, use_ka
        )
        total_c = sum(conflicts.values())

        results.append((score, total_c, perm_tuple, var_name))

    return results


def exhaustive_col6_p13():
    """Full 720 x 6 configs for period-13."""
    print("\n" + "=" * 70)
    print("EXHAUSTIVE: All 720 col6 perms x 6 configs at period-13")
    print("=" * 70)

    all_perms = list(itertools.permutations(range(6)))
    all_results = []

    with ProcessPoolExecutor(max_workers=28) as executor:
        futures = {executor.submit(exhaustive_col6_p13_worker, p): p for p in all_perms}
        for future in as_completed(futures):
            all_results.extend(future.result())

    # Score distribution
    score_dist = defaultdict(int)
    for score, _, _, _ in all_results:
        score_dist[score] += 1

    print("\n  Score distribution:")
    for s in sorted(score_dist.keys(), reverse=True):
        print(f"    {s}/24: {score_dist[s]} configs")

    # Top results
    all_results.sort(key=lambda x: x[0], reverse=True)
    print(f"\n  Top 30 results:")
    for score, conflicts, perm, var_name in all_results[:30]:
        print(f"    {score}/24 ({conflicts} conflicts): perm={perm} {var_name}")

    # Check if ANY reach 0 conflicts
    perfect = [r for r in all_results if r[1] == 0]
    if perfect:
        print(f"\n  !!! {len(perfect)} PERFECT (0-conflict) RESULTS !!!")
        for score, _, perm, var_name in perfect:
            print(f"    {score}/24: perm={perm} {var_name}")

    # Also check periods 6, 7, 23 for completeness
    print("\n  Also checking periods 6, 7, 23:")
    for period in [6, 7, 23]:
        best_score = 0
        best_info = ""
        for perm_tuple in all_perms:
            col_order = list(perm_tuple)
            ct_int = apply_columnar_inverse(CT73, 6, col_order)
            mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, col_order, 73)

            for var_name, var, use_ka in [
                ("vig_AZ", CipherVariant.VIGENERE, False),
                ("beau_AZ", CipherVariant.BEAUFORT, False),
                ("vig_KA", CipherVariant.VIGENERE, True),
                ("beau_KA", CipherVariant.BEAUFORT, True),
            ]:
                score, _, _ = score_crib_consistency(
                    ct_int, mapped_cribs, period, var, use_ka
                )
                if score > best_score:
                    best_score = score
                    best_info = f"perm={perm_tuple} {var_name}"

        print(f"    Period {period}: best={best_score}/24 ({best_info})")

    return all_results


# ============================================================
# 4. Period-6 direct: check if the col6 INTERACTS with period 6
# ============================================================

def col6_period6_interaction():
    """Check if width-6 columnar + period-6 sub gives better than
    period-6 alone (it should, if the transposition is real)."""
    print("\n" + "=" * 70)
    print("INTERACTION: Width-6 columnar + period-6 sub")
    print("=" * 70)

    all_perms = list(itertools.permutations(range(6)))
    best_results = []

    for perm_tuple in all_perms:
        col_order = list(perm_tuple)
        ct_int = apply_columnar_inverse(CT73, 6, col_order)
        mapped_cribs = map_cribs_through_transposition(CRIB_CT73, 6, col_order, 73)

        for var_name, var, use_ka in [
            ("vig_AZ", CipherVariant.VIGENERE, False),
            ("beau_AZ", CipherVariant.BEAUFORT, False),
            ("vig_KA", CipherVariant.VIGENERE, True),
            ("beau_KA", CipherVariant.BEAUFORT, True),
        ]:
            score, _, _ = score_crib_consistency(
                ct_int, mapped_cribs, 6, var, use_ka
            )
            best_results.append((score, perm_tuple, var_name))

    best_results.sort(key=lambda x: x[0], reverse=True)

    print(f"\n  Direct CT73 period-6 scores: 8-10/24 (from Attack 1)")
    print(f"  Best col6+p6: {best_results[0][0]}/24 ({best_results[0][1]} {best_results[0][2]})")
    print(f"  Top 20:")
    for score, perm, var_name in best_results[:20]:
        print(f"    {score}/24: perm={perm} {var_name}")

    # Score distribution
    score_dist = defaultdict(int)
    for score, _, _ in best_results:
        score_dist[score] += 1
    print(f"\n  Score distribution:")
    for s in sorted(score_dist.keys(), reverse=True):
        print(f"    {s}/24: {score_dist[s]} configs")


# ============================================================
# MAIN
# ============================================================

def main():
    start_time = time.time()
    print(f"Period-6/Period-13 Deep Analysis")
    print(f"Started: {datetime.now().isoformat()}")
    print(f"CT73 = {CT73}")
    print()

    # Monte Carlo baseline (critical to interpret 16/24)
    mc_period13_baseline(n_trials=50000)

    # Detailed analysis of top hits
    analyze_top_hits()

    # Exhaustive col6 + p13
    exhaustive_results = exhaustive_col6_p13()

    # Col6 + p6 interaction
    col6_period6_interaction()

    elapsed = time.time() - start_time
    print(f"\nTotal elapsed: {elapsed:.1f}s")

    # Save
    results_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'f_period6_p13_deep_v1.json')

    output = {
        'timestamp': datetime.now().isoformat(),
        'elapsed_seconds': elapsed,
        'ct73': CT73,
        'mask': MASK_24,
    }

    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)

    print(f"Results saved to: {results_path}")


if __name__ == '__main__':
    main()
