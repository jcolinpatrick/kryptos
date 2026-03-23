#!/usr/bin/env python3
"""
e_rowkey_ndyahr_k2.py — Search for mathematical relationships between
the 6-value row key sequence and NDYAHR / K2 coordinates.

Row key (Beaufort, KA grid rows):
  ENE: [4, 4, 1, 4, 1, 5, 0, 0, 5, 4, 1, 2, 1]
  BCL: [4, 2, 0, 1, 3, 3, 4, 2, 3, 1, 0]

NDYAHR letters: N, D, Y, A, H, R
  AZ indices: 13, 3, 24, 0, 7, 17
  KA indices: 18, 10, 2, 7, 14, 1
  KA rows:    3, 2, 0, 1, 2, 0
  KA cols:    3, 0, 2, 2, 4, 1

K2 coordinates: 38°57'6.5"N  77°8'44"W
  Numbers: 38, 57, 6, 77, 8, 44
  Also: 3, 8, 5, 7, 6, 5 (individual digits of 38,57,6.5)
  Also: 7, 7, 8, 4, 4 (individual digits of 77,8,44)

Tests:
  1. NDYAHR letter values (AZ, KA) mod 6 as cycling row key
  2. NDYAHR grid coordinates as row key pairs
  3. K2 numbers mod 6 as cycling row key
  4. K2 digit sequences mod 6
  5. Fibonacci/additive sequences seeded by NDYAHR or K2
  6. NDYAHR as Gromark-style primer generating row keys mod 6
  7. Running sums, differences, products of NDYAHR values mod 6
  8. Combined NDYAHR + K2 sequences
  9. Lagged Fibonacci mod 6 with various seeds from NDYAHR/K2
"""

import sys
import os
import json
import time
from itertools import product

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CRIB_DICT, KRYPTOS_ALPHABET, ALPH, ALPH_IDX,
)

GRID_COLS = 5
GRID_ROWS = 6

# ── Derived constants ────────────────────────────────────────────────────

KA_IDX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}

CRIB_POSITIONS = sorted(CRIB_DICT.keys())

# Row key targets (Beaufort: (CT_row + PT_row) mod 6 on KA grid)
def ka_row(ch):
    return KA_IDX[ch] // GRID_COLS

def ka_col(ch):
    return KA_IDX[ch] % GRID_COLS

TARGET_ROW_KEY_BEAU = []
TARGET_ROW_KEY_VIG = []
for pos in CRIB_POSITIONS:
    ct_r = ka_row(CT[pos])
    pt_r = ka_row(CRIB_DICT[pos])
    TARGET_ROW_KEY_BEAU.append((ct_r + pt_r) % GRID_ROWS)
    TARGET_ROW_KEY_VIG.append((ct_r - pt_r) % GRID_ROWS)

# NDYAHR values
NDYAHR = "NDYAHR"
NDYAHR_AZ = [ALPH_IDX[ch] for ch in NDYAHR]       # [13, 3, 24, 0, 7, 17]
NDYAHR_KA = [KA_IDX[ch] for ch in NDYAHR]          # [18, 10, 2, 7, 14, 1]
NDYAHR_ROWS = [ka_row(ch) for ch in NDYAHR]         # [3, 2, 0, 1, 2, 0]
NDYAHR_COLS = [ka_col(ch) for ch in NDYAHR]          # [3, 0, 2, 2, 4, 1]

# K2 coordinate numbers
K2_FULL = [38, 57, 6, 77, 8, 44]
K2_DIGITS_N = [3, 8, 5, 7, 6, 5]  # digits of 38°57'6.5"N
K2_DIGITS_W = [7, 7, 8, 4, 4]     # digits of 77°8'44"W
K2_ALL_DIGITS = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
K2_PAIRS = [38, 57, 65, 77, 84, 4]  # different groupings
K2_DMS_N = [38, 57, 6.5]  # degrees, minutes, seconds N
K2_DMS_W = [77, 8, 44]    # degrees, minutes, seconds W


def score_match(generated_key, target, positions):
    """Score how many positions match between generated key and target."""
    hits = 0
    for i, pos in enumerate(positions):
        if pos < len(generated_key) and generated_key[pos] == target[i]:
            hits += 1
    return hits


def expand_fibonacci_mod6(seed, length):
    """Expand a seed via lagged Fibonacci: k[i] = (k[i-len(seed)] + k[i-len(seed)+1]) mod 6."""
    seq = list(seed)
    lag = len(seed)
    while len(seq) < length:
        val = (seq[-lag] + seq[-lag + 1]) % 6
        seq.append(val)
    return seq


def expand_additive_mod6(seed, length):
    """Expand: k[i] = (k[i-1] + k[i-2]) mod 6."""
    seq = list(seed)
    while len(seq) < length:
        val = (seq[-1] + seq[-2]) % 6
        seq.append(val)
    return seq


def expand_gromark_mod6(seed, length, base=6):
    """Gromark-style: k[i] = (k[i-len(seed)] + k[i-len(seed)+1]) mod base."""
    seq = [s % base for s in seed]
    lag = len(seed)
    while len(seq) < length:
        val = (seq[-lag] + seq[-lag + 1]) % base
        seq.append(val)
    return seq


def expand_running_sum(seed, length, mod=6):
    """Running sum: k[i] = (k[i-1] + seed[i % len(seed)]) mod mod."""
    seq = [seed[0] % mod]
    for i in range(1, length):
        val = (seq[-1] + seed[i % len(seed)]) % mod
        seq.append(val)
    return seq


def expand_running_diff(seed, length, mod=6):
    """Running difference: k[i] = (seed[i % len(seed)] - k[i-1]) mod mod."""
    seq = [seed[0] % mod]
    for i in range(1, length):
        val = (seed[i % len(seed)] - seq[-1]) % mod
        seq.append(val)
    return seq


def main():
    print("=" * 70)
    print("ROW KEY vs NDYAHR / K2 COORDINATES")
    print("=" * 70)

    print(f"\nTarget row key (Beaufort): {TARGET_ROW_KEY_BEAU}")
    print(f"Target row key (Vigenère): {TARGET_ROW_KEY_VIG}")
    print(f"Crib positions: {CRIB_POSITIONS}")
    print(f"\nNDYAHR AZ indices: {NDYAHR_AZ}")
    print(f"NDYAHR KA indices: {NDYAHR_KA}")
    print(f"NDYAHR KA rows:    {NDYAHR_ROWS}")
    print(f"NDYAHR KA cols:    {NDYAHR_COLS}")
    print(f"K2 numbers:        {K2_FULL}")
    print(f"K2 all digits:     {K2_ALL_DIGITS}")

    NEED_LEN = max(CRIB_POSITIONS) + 1  # 74

    results = []
    best_score = 0
    best_detail = None

    def check(name, seq, target_name, target):
        nonlocal best_score, best_detail
        if len(seq) < NEED_LEN:
            return
        score = score_match(seq, target, CRIB_POSITIONS)
        if score >= 4:
            results.append({"name": name, "target": target_name,
                           "score": score, "seq_at_cribs": [seq[p] for p in CRIB_POSITIONS]})
        if score > best_score:
            best_score = score
            best_detail = {"name": name, "target": target_name, "score": score}

    # ── Test 1: Direct cycling ───────────────────────────────────────

    print("\n--- Test 1: Direct cycling of NDYAHR/K2 values mod 6 ---")

    seeds = {
        "NDYAHR_AZ": NDYAHR_AZ,
        "NDYAHR_KA": NDYAHR_KA,
        "NDYAHR_rows": NDYAHR_ROWS,
        "NDYAHR_cols": NDYAHR_COLS,
        "NDYAHR_AZ_mod6": [v % 6 for v in NDYAHR_AZ],
        "NDYAHR_KA_mod6": [v % 6 for v in NDYAHR_KA],
        "K2_full": K2_FULL,
        "K2_full_mod6": [v % 6 for v in K2_FULL],
        "K2_digits_N": K2_DIGITS_N,
        "K2_digits_W": K2_DIGITS_W,
        "K2_all_digits": K2_ALL_DIGITS,
        "K2_all_digits_mod6": [v % 6 for v in K2_ALL_DIGITS],
        "K2_DMS_N_mod6": [int(v) % 6 for v in K2_DMS_N],
        "K2_DMS_W_mod6": [int(v) % 6 for v in K2_DMS_W],
    }

    for seed_name, seed in seeds.items():
        if len(seed) == 0:
            continue
        cycling = [seed[i % len(seed)] % 6 for i in range(NEED_LEN)]
        for target_name, target in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
            check(f"cycle_{seed_name}", cycling, target_name, target)

        # Also try with offsets
        for offset in range(len(seed)):
            shifted = seed[offset:] + seed[:offset]
            cycling = [shifted[i % len(shifted)] % 6 for i in range(NEED_LEN)]
            for target_name, target in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
                check(f"cycle_{seed_name}_off{offset}", cycling, target_name, target)

    print(f"  Best so far: {best_score}/24")

    # ── Test 2: Fibonacci/Gromark expansion mod 6 ────────────────────

    print("\n--- Test 2: Fibonacci/Gromark expansion mod 6 ---")

    for seed_name, seed_vals in seeds.items():
        if len(seed_vals) < 2:
            continue
        seed_mod6 = [v % 6 for v in seed_vals]

        # Standard Fibonacci expansion
        seq = expand_fibonacci_mod6(seed_mod6, NEED_LEN)
        for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
            check(f"fib_{seed_name}", seq, tn, t)

        # Additive (lag-2) expansion
        for start_i in range(len(seed_mod6) - 1):
            pair = seed_mod6[start_i:start_i + 2]
            seq = expand_additive_mod6(pair, NEED_LEN)
            for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
                check(f"add2_{seed_name}_start{start_i}", seq, tn, t)

        # Gromark expansion (full seed as lag)
        seq = expand_gromark_mod6(seed_mod6, NEED_LEN)
        for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
            check(f"gromark_{seed_name}", seq, tn, t)

    print(f"  Best so far: {best_score}/24")

    # ── Test 3: Running sum/diff with NDYAHR/K2 ─────────────────────

    print("\n--- Test 3: Running sum/diff accumulators ---")

    for seed_name, seed_vals in seeds.items():
        if len(seed_vals) == 0:
            continue
        seed_mod6 = [v % 6 for v in seed_vals]

        seq = expand_running_sum(seed_mod6, NEED_LEN)
        for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
            check(f"runsum_{seed_name}", seq, tn, t)

        seq = expand_running_diff(seed_mod6, NEED_LEN)
        for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
            check(f"rundiff_{seed_name}", seq, tn, t)

    print(f"  Best so far: {best_score}/24")

    # ── Test 4: NDYAHR rows/cols as arithmetic on position ───────────

    print("\n--- Test 4: Position-dependent functions with NDYAHR/K2 ---")

    # k[pos] = (a * pos + b) mod 6 for all (a,b) from NDYAHR/K2 values
    all_params = set()
    for v in NDYAHR_AZ + NDYAHR_KA + NDYAHR_ROWS + NDYAHR_COLS + K2_FULL + K2_ALL_DIGITS:
        all_params.add(v)

    for a in all_params:
        for b in all_params:
            seq = [(a * pos + b) % 6 for pos in range(NEED_LEN)]
            for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
                check(f"linear_a{a}_b{b}", seq, tn, t)

    # k[pos] = (a * pos^2 + b * pos + c) mod 6
    small_params = [0, 1, 2, 3, 4, 5]
    for a in small_params:
        for b in small_params:
            for c in small_params:
                seq = [(a * pos * pos + b * pos + c) % 6 for pos in range(NEED_LEN)]
                for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
                    check(f"quad_a{a}_b{b}_c{c}", seq, tn, t)

    print(f"  Best so far: {best_score}/24")

    # ── Test 5: NDYAHR as row permutation applied cyclically ─────────

    print("\n--- Test 5: NDYAHR as permutation/substitution ---")

    # What if NDYAHR defines a substitution on {0,1,2,3,4,5}?
    # NDYAHR rows = [3,2,0,1,2,0] → partial permutation
    # NDYAHR cols = [3,0,2,2,4,1] → partial permutation

    # Use NDYAHR_AZ mod 6 = [1,3,0,0,1,5] as a substitution table
    # s[0]=1, s[1]=3, s[2]=0, s[3]=0, s[4]=1, s[5]=5
    for seed_name in ["NDYAHR_AZ_mod6", "NDYAHR_KA_mod6", "NDYAHR_rows", "NDYAHR_cols",
                        "K2_full_mod6", "K2_all_digits_mod6"]:
        sub_table = seeds[seed_name]
        if len(sub_table) < 6:
            # Pad to 6
            sub_table = (sub_table * ((6 // len(sub_table)) + 1))[:6]

        # Apply substitution iteratively: start with position mod 6, apply sub_table
        for start_val in range(6):
            seq = [start_val]
            for _ in range(NEED_LEN - 1):
                seq.append(sub_table[seq[-1] % len(sub_table)] % 6)
            for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
                check(f"sub_iter_{seed_name}_start{start_val}", seq, tn, t)

        # Position mod len(sub_table) → substitute
        seq = [sub_table[pos % len(sub_table)] % 6 for pos in range(NEED_LEN)]
        for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
            check(f"sub_pos_{seed_name}", seq, tn, t)

    print(f"  Best so far: {best_score}/24")

    # ── Test 6: Exhaustive 2-value lagged Fibonacci seeds mod 6 ──────

    print("\n--- Test 6: Exhaustive lag-2 Fibonacci seeds mod 6 ---")

    for s0 in range(6):
        for s1 in range(6):
            seq = expand_additive_mod6([s0, s1], NEED_LEN)
            for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
                check(f"fib2_{s0}_{s1}", seq, tn, t)

    print(f"  Best so far: {best_score}/24")

    # ── Test 7: NDYAHR/K2 combined sequences ─────────────────────────

    print("\n--- Test 7: Combined NDYAHR + K2 sequences ---")

    # Interleave NDYAHR and K2
    combined_1 = []
    for i in range(max(len(NDYAHR_AZ), len(K2_FULL))):
        if i < len(NDYAHR_AZ):
            combined_1.append(NDYAHR_AZ[i] % 6)
        if i < len(K2_FULL):
            combined_1.append(K2_FULL[i] % 6)

    seq = expand_fibonacci_mod6(combined_1[:6], NEED_LEN)
    for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
        check("fib_ndyahr_k2_interleave", seq, tn, t)

    # NDYAHR rows concatenated with K2 digits mod 6
    combined_2 = NDYAHR_ROWS + [v % 6 for v in K2_ALL_DIGITS]
    seq = [combined_2[i % len(combined_2)] for i in range(NEED_LEN)]
    for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
        check("cycle_ndyahr_rows_k2_digits", seq, tn, t)

    # Use K2 numbers as Fibonacci seed, NDYAHR as lag
    for lag in range(2, 7):
        seed = [v % 6 for v in K2_ALL_DIGITS[:lag]]
        if len(seed) < 2:
            continue
        seq = expand_gromark_mod6(seed, NEED_LEN)
        for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
            check(f"gromark_k2digits_lag{lag}", seq, tn, t)

    print(f"  Best so far: {best_score}/24")

    # ── Test 8: Exhaustive 3-6 value Gromark primers mod 6 ──────────

    print("\n--- Test 8: Exhaustive short Gromark primers mod 6 ---")

    for primer_len in [3, 4, 5]:
        count = 0
        for primer in product(range(6), repeat=primer_len):
            seq = expand_gromark_mod6(list(primer), NEED_LEN)
            for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
                check(f"gromark{primer_len}_{primer}", seq, tn, t)
            count += 1
        print(f"  Primer length {primer_len}: {count} primers tested, best {best_score}/24")

    # ── Test 9: LCG / multiplicative sequences ───────────────────────

    print("\n--- Test 9: LCG sequences mod 6 ---")

    for a in range(1, 6):
        for b in range(6):
            for s0 in range(6):
                seq = [s0]
                for _ in range(NEED_LEN - 1):
                    seq.append((a * seq[-1] + b) % 6)
                for tn, t in [("beau", TARGET_ROW_KEY_BEAU), ("vig", TARGET_ROW_KEY_VIG)]:
                    check(f"lcg_a{a}_b{b}_s{s0}", seq, tn, t)

    print(f"  Best so far: {best_score}/24")

    # ── Summary ──────────────────────────────────────────────────────

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Best score: {best_score}/24")
    print(f"Best config: {best_detail}")

    if results:
        print(f"\nAll results scoring >= 4:")
        for r in sorted(results, key=lambda x: -x["score"]):
            print(f"  {r['score']}/24 — {r['name']} ({r['target']})")
            if r['score'] >= 6:
                print(f"         seq: {r['seq_at_cribs']}")
    else:
        print("  No results >= 4")

    out = {
        "experiment": "e_rowkey_ndyahr_k2",
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "best_score": best_score,
        "best_detail": best_detail,
        "all_results": results,
        "target_beau": TARGET_ROW_KEY_BEAU,
        "target_vig": TARGET_ROW_KEY_VIG,
    }

    out_path = os.path.join(_ROOT, "results", "e_rowkey_ndyahr_k2.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults: {out_path}")


if __name__ == "__main__":
    main()
