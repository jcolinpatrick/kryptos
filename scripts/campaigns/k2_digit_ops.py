#!/usr/bin/env python3
"""
Cipher: K2 digit arithmetic as key/transposition — 3x8 grid, squared digits, affine mod 73
Family: campaigns
Status: active
Keyspace: ~2000 configs

KEY INSIGHT: 38 is UNIQUE two-digit number where d₁²+d₂²=73 AND d₁×d₂=24
  - 3² + 8² = 73 (PT length)
  - 3 × 8 = 24 (null count)
  - 3 + 8 = 11 (BERLINCLOCK length)
  → 3 and 8 are structural "basis" digits

Tests:
A) K2 digits SQUARED mod 26 as key stream: [3²,8²,5²,...] mod 26
B) K2 digit PAIRS as keys: products, sums, differences mod 26
C) 3×8 grid structure for null-position selection (24 positions in 3×8=24-cell grid)
D) Affine transposition y = ax+b (mod 73) on W-extracted 73-char text
   (W positions [20,36,48,58,74] = 5 nulls; pick 19 more by K2 arithmetic)
E) Polynomial key: p(x) = (3x² + 8x + offset) mod 73 or mod 26 as key stream
"""
import sys
from math import gcd
sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CRIB_DICT, CRIB_POSITIONS, ALPH, ALPH_IDX

def crib_score(pt: str) -> int:
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt) and pt[pos] == ch)

def vig_decrypt(ct: str, key: list) -> str:
    n = len(key)
    return "".join(ALPH[(ALPH_IDX[c] - key[i % n]) % 26] for i, c in enumerate(ct))

def beau_decrypt(ct: str, key: list) -> str:
    n = len(key)
    return "".join(ALPH[(key[i % n] - ALPH_IDX[c]) % 26] for i, c in enumerate(ct))

def vbeau_decrypt(ct: str, key: list) -> str:
    n = len(key)
    return "".join(ALPH[(ALPH_IDX[c] + key[i % n]) % 26] for i, c in enumerate(ct))

CRIB_SET = set(CRIB_POSITIONS)
DIGITS_11 = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
K2_NUMS = [38, 57, 6, 5, 77, 8, 44]

print("=" * 70)
print("K2 DIGIT ARITHMETIC — STRUCTURAL KEY ATTACK")
print("=" * 70)
print(f"CT: {CT}")
print(f"Key insight: 3²+8²=73, 3×8=24, 3+8=11\n")

results = []

# === A) Squared digits as key stream ===
print("--- A) K2 digits SQUARED mod 26 as key stream ---")
squared = [d * d % 26 for d in DIGITS_11]   # [9,12,25,23,10,25,23,23,12,16,16]
squared_mod73 = [d * d % 73 for d in DIGITS_11]  # mod 73 then mod 26
sq73_mod26 = [v % 26 for v in squared_mod73]
# [9,64%26=12, 25,49%26=23, 36%26=10, 25, 23,23,12,16,16]

digit_key_seqs = {
    "sq_mod26_11":   squared,
    "sq_mod73m26_11": sq73_mod26,
    "prod_pairs": [(DIGITS_11[i] * DIGITS_11[i+1]) % 26 for i in range(len(DIGITS_11)-1)],
    "sum_pairs":  [(DIGITS_11[i] + DIGITS_11[i+1]) % 26 for i in range(len(DIGITS_11)-1)],
    "diff_pairs": [(DIGITS_11[i] - DIGITS_11[i+1]) % 26 for i in range(len(DIGITS_11)-1)],
    "3x8_ops":    [3*3%26, 8*8%26, 3*8%26, (3+8)%26, (3*3+8*8)%26, 3%26, 8%26],
    "poly_3_8":   [(3*(i**2) + 8*i) % 26 for i in range(11)],  # p(x)=3x²+8x mod 26
    "poly_3_8_73":[(3*(i**2) + 8*i) % 73 % 26 for i in range(11)],
}

for kname, key in digit_key_seqs.items():
    if not key or len(set(key)) < 2:
        continue
    for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        pt = fn(CT, key)
        sc = crib_score(pt)
        results.append((sc, f"A_{cipher}_{kname}", pt))

# === B) All (digit_i × digit_j) and (digit_i + digit_j) pairs as 2-element keys ===
print("--- B) All digit pair operations as 2-element keys ---")
from itertools import combinations
unique_digits = list(set(DIGITS_11))
for d1, d2 in combinations(unique_digits, 2):
    for op_name, op_result in [
        ("prod", (d1 * d2) % 26),
        ("sum", (d1 + d2) % 26),
        ("sq_sum", (d1*d1 + d2*d2) % 26),
    ]:
        if op_result == 0:
            continue
        key2 = [d1 % 26, op_result]
        for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
            pt = fn(CT, key2)
            sc = crib_score(pt)
            results.append((sc, f"B_{cipher}_{op_name}({d1},{d2})=[{d1%26},{op_result}]", pt))

# Specifically test [3,8] and operations thereof
special_keys = {
    "3_8":      [3, 8],
    "8_3":      [8, 3],
    "3_24":     [3, 24],
    "8_24":     [8, 24],
    "3_8_24":   [3, 8, 24],
    "11_13":    [11, 13],
    "11_13_24": [11, 13, 24],
    "3_8_11":   [3, 8, 11],
    "3_8_11_13":[3, 8, 11, 13],
    "24_11_13": [24, 11, 13],
    "73mod26_24mod26": [73 % 26, 24 % 26],
}
for kname, key in special_keys.items():
    for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        pt = fn(CT, key)
        sc = crib_score(pt)
        results.append((sc, f"B2_{cipher}_{kname}", pt))

# === C) 3×8=24 grid for null positions ===
print("--- C) 3×8 grid null-position extraction + periodic sub ---")

# Place 97 chars in a grid; select rows/columns as nulls
# A 3×8=24 null mask would cover 24 positions
# Try: null mask = rows 0,1,2 of a width-n grid (or specific row/col pattern)
for grid_width in range(6, 16):
    nrows = (97 + grid_width - 1) // grid_width
    # Grid positions
    grid_pos = []
    for r in range(nrows):
        for c in range(grid_width):
            pos = r * grid_width + c
            if pos < 97:
                grid_pos.append((r, c, pos))

    # Try selecting every 3rd column and every 8th position as nulls
    # Null mask: positions in cols that are multiples of 3 (or 8)
    for col_skip in [3, 8]:
        null_pos = set(pos for r, c, pos in grid_pos if c % col_skip == 0 and pos not in CRIB_SET)
        if len(null_pos) == 24:
            ct73 = "".join(c for i, c in enumerate(CT) if i not in null_pos)
            # Score cribs in 73-char text
            orig_to_73 = {}
            p73 = 0
            for i in range(97):
                if i not in null_pos:
                    orig_to_73[i] = p73
                    p73 += 1

            def crib73(pt73):
                return sum(1 for op, ch in CRIB_DICT.items()
                           if op not in null_pos and op in orig_to_73
                           and orig_to_73[op] < len(pt73)
                           and pt73[orig_to_73[op]] == ch)

            for period in [7, 11, 13, 3, 8]:
                for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                    for kname, key in digit_key_seqs.items():
                        if not key:
                            continue
                        key_p = (key * (period // max(len(key), 1) + 1))[:period]
                        pt73 = fn(ct73, key_p)
                        sc = crib73(pt73)
                        results.append((sc, f"C_w{grid_width}_colskip{col_skip}_{cipher}_p{period}_{kname}", pt73))

# === D) Affine transposition mod 73 on W-masked 73-char text ===
print("--- D) Affine y=ax+b (mod 73) on W-masked 73-char text ---")

# W positions [20,36,48,58,74] = 5 definite nulls
W_POSITIONS = {20, 36, 48, 58, 74}

# 19 more nulls derived from K2 arithmetic: positions = 3,8,11,13,24 and combinations
# plus positions from 3×8 grid
additional_null_candidates = []
for v in [3, 8, 11, 13, 24, 38, 44, 57, 77 % 97, 6, 5]:
    if v not in CRIB_SET and v not in W_POSITIONS and v < 97:
        additional_null_candidates.append(v)
# Fill to 24 total
null_mask_w = set(W_POSITIONS)
for v in sorted(additional_null_candidates):
    if len(null_mask_w) == 24:
        break
    null_mask_w.add(v)

if len(null_mask_w) == 24:
    ct73_w = "".join(c for i, c in enumerate(CT) if i not in null_mask_w)
    print(f"  W+K2 null mask: {sorted(null_mask_w)}")
    print(f"  73-char CT: {ct73_w}")

    # Build crib shift map
    pos73w = 0
    orig_to_73w = {}
    for i in range(97):
        if i not in null_mask_w:
            orig_to_73w[i] = pos73w
            pos73w += 1

    def crib73w(pt73):
        return sum(1 for op, ch in CRIB_DICT.items()
                   if op not in null_mask_w and op in orig_to_73w
                   and orig_to_73w[op] < len(pt73)
                   and pt73[orig_to_73w[op]] == ch)

    # Test affine transposition y = ax+b (mod 73) on ct73_w
    a_vals = [v for v in [3, 5, 8, 11, 13, 24, 27, 38 % 73, 44, 57] if gcd(v, 73) == 1]
    b_vals = [0, 3, 8, 11, 13, 21, 24]  # 21 = ENE start
    for a in a_vals:
        for b in b_vals:
            perm = [(a * i + b) % 73 for i in range(73)]
            trans73 = "".join(ct73_w[perm[i]] for i in range(73))
            # Apply simple periodic sub
            for period in [7, 11, 13, 3, 8]:
                for kname, key in [("sq_mod26", squared), ("3_8_11_13", [3, 8, 11, 13])]:
                    for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
                        key_p = (key * (period // max(len(key), 1) + 1))[:period]
                        pt73 = fn(trans73, key_p)
                        sc = crib73w(pt73)
                        results.append((sc, f"D_affine_{a}x+{b}_mod73_{cipher}_p{period}_{kname}", pt73))

# === E) Polynomial key stream p(i) = (3i² + 8i + c) mod m ===
print("--- E) Polynomial key stream 3i²+8i+c ---")
for c_val in [0, 1, 3, 8, 11, 13, 21, 24]:
    for modulus in [26, 73]:
        key_poly = [(3 * i * i + 8 * i + c_val) % modulus % 26 for i in range(97)]
        if len(set(key_poly[:20])) < 4:
            continue
        for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
            pt = fn(CT, key_poly)
            sc = crib_score(pt)
            results.append((sc, f"E_{cipher}_poly(3x²+8x+{c_val})mod{modulus}", pt))

# === Summary ===
results.sort(key=lambda x: -x[0])
above_noise = [(s, l, p) for s, l, p in results if s > 6]
print(f"\nTotal configs: {len(results)}")
print(f"Above noise (>6): {len(above_noise)}")

if above_noise:
    print("\nABOVE-NOISE RESULTS:")
    for sc, label, pt in above_noise[:20]:
        matches = [(pos, CRIB_DICT[pos]) for pos in sorted(CRIB_POSITIONS)
                   if pos < len(pt) and pt[pos] == CRIB_DICT[pos]]
        print(f"  Score {sc:2d}/24: {label}")
        print(f"    PT: {pt[:60]}")
        print(f"    Matches: {matches}")
        print()

print("Top 10:")
for sc, label, pt in results[:10]:
    print(f"  {sc:2d}/24: {label} | {pt[:50]}")
print("\nDONE")
