#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CHART-04: K0 Morse E-group pattern as tableau row selector / key generator.

Theory: The 26 extra E's in K0 Morse code provide a structural pattern for K4.
"DIGETAL INTERPRETATIU" = "digital interpretation" = use these numbers as row
selectors in the KA tableau.

Tests:
  1. E-group sizes as periodic key (Vig/Beau/VB × AZ/KA)
  2. E-group as row selector in KA/AZ tableau
  3. E-group cumulative sums as cyclic key
  4. E-group + constant offset (0-25)
  5. E-group + YAR modulation (24,0,17)
  6. K0 full phrase concatenation as running key
  7. T=19 starting offset for E-group alignment
  8. E-positions in Morse stream as key values
  9. Combined E-group + K3 running key selector
 10. E-group as transposition pattern
 11. Top-5 configs through width-8 columnar (all 40,320 orderings)

Output: results/e_chart_04_morse.json
"""

import json
import os
import sys
import time
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR, N_CRIBS,
    KRYPTOS_ALPHABET, CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

# ═══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

CT_NUM = [ALPH_IDX[c] for c in CT]

AZ = ALPH
AZ_IDX = ALPH_IDX

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

E_GROUP_SIZES = [2, 1, 5, 1, 3, 2, 2, 5, 3, 1, 1]  # 11 groups, sum=26

# Cumulative sums of E-group sizes
E_GROUP_CUMSUMS = []
_s = 0
for _g in E_GROUP_SIZES:
    _s += _g
    E_GROUP_CUMSUMS.append(_s)
# [2, 3, 8, 9, 12, 14, 16, 21, 24, 25, 26]

# K0 Morse tokens (from E-S-144, community consensus)
MORSE_TOKENS = [
    'e', 'e',
    'V', 'I', 'R', 'T', 'U', 'A', 'L', 'L', 'Y',
    'e',
    'e', 'e', 'e', 'e', 'e',
    'I', 'N', 'V', 'I', 'S', 'I', 'B', 'L', 'E',
    'e',
    'D', 'I', 'G', 'E', 'T', 'A', 'L',
    'e', 'e', 'e',
    'I', 'N', 'T', 'E', 'R', 'P', 'R', 'E', 'T', 'A', 'T', 'I', 'U',
    'e', 'e',
    'S', 'H', 'A', 'D', 'O', 'W',
    'e', 'e',
    'F', 'O', 'R', 'C', 'E', 'S',
    'e', 'e', 'e', 'e', 'e',
    'L', 'U', 'C', 'I', 'D',
    'e', 'e', 'e',
    'M', 'E', 'M', 'O', 'R', 'Y',
    'e',
    'T', 'I', 'S', 'Y', 'O', 'U', 'R',
    'P', 'O', 'S', 'I', 'T', 'I', 'O', 'N',
    'e',
    'S', 'O', 'S',
    'R', 'Q',
]

# K0 decoded phrases (letters only, concatenated)
K0_PHRASES = [
    "VIRTUALLYINVISIBLE",
    "DIGETALINTERPRETATIU",
    "SHADOWFORCES",
    "LUCIDMEMORY",
    "TISYOURPOSITION",
    "SOS",
    "RQ",
]
K0_CONCAT = "".join(K0_PHRASES)  # Full concatenation

# K3 plaintext
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTH"
    "ATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITH"
    "TREMBLINGHANDSIMADEATINYBREACHINTHELEFTHANDCORNERA"
    "NDTHENWIDENINGTHEHOLEALITTLEIINSERTEDTHECANDLEANDP"
    "EEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER CAUSEDTHEFLA"
    "METOF LICKERANDPRESENTLY DETAILSOFTHEROOMWITHINEMERGED"
    "FROMTHEMISTXCANYOUSEEANYTHINGQ"
).replace(" ", "")

# YAR values
YAR = [24, 0, 17]  # Y=24, A=0, R=17 in A=0 numbering


# ═══════════════════════════════════════════════════════════════════════════
# CIPHER PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════

def vig_dec_nums(ct_nums, key_nums):
    """Vigenere decrypt: P = (C - K) mod 26."""
    p = len(key_nums)
    return [(ct_nums[i] - key_nums[i % p]) % MOD for i in range(len(ct_nums))]

def beau_dec_nums(ct_nums, key_nums):
    """Beaufort decrypt: P = (K - C) mod 26."""
    p = len(key_nums)
    return [(key_nums[i % p] - ct_nums[i]) % MOD for i in range(len(ct_nums))]

def varbeau_dec_nums(ct_nums, key_nums):
    """Variant Beaufort decrypt: P = (C + K) mod 26."""
    p = len(key_nums)
    return [(ct_nums[i] + key_nums[i % p]) % MOD for i in range(len(ct_nums))]

VARIANTS = [
    ("Vig", vig_dec_nums),
    ("Beau", beau_dec_nums),
    ("VB", varbeau_dec_nums),
]

def nums_to_text(nums):
    return ''.join(chr(ord('A') + n) for n in nums)

def text_to_nums_az(text):
    return [AZ_IDX[c] for c in text.upper() if c in AZ_IDX]

def text_to_nums_ka(text):
    return [KA_IDX[c] for c in text.upper() if c in KA_IDX]


# ═══════════════════════════════════════════════════════════════════════════
# KA-TABLEAU LOOKUP (position-dependent alphabet substitution)
# ═══════════════════════════════════════════════════════════════════════════

def build_ka_tableau():
    """Build KA Vigenere tableau: row r, col c = KA[(KA_IDX[row_letter] + KA_IDX[col_letter]) % 26].
    Returns 26x26 grid where tableau[r][c] gives the enciphered letter.
    """
    tableau = []
    for r in range(26):
        row = []
        for c in range(26):
            row.append(KA[(r + c) % 26])
        tableau.append(row)
    return tableau

def build_az_tableau():
    """Build standard AZ Vigenere tableau."""
    tableau = []
    for r in range(26):
        row = []
        for c in range(26):
            row.append(AZ[(r + c) % 26])
        tableau.append(row)
    return tableau

KA_TABLEAU = build_ka_tableau()
AZ_TABLEAU = build_az_tableau()


def tableau_decrypt(ct_char, row_idx, tableau, alpha_idx):
    """Given CT char and a row index, find the column index s.t. tableau[row][col] == ct_char.
    Returns the plaintext letter (column header).
    """
    row = tableau[row_idx % 26]
    for col in range(26):
        if row[col] == ct_char:
            return col
    return None  # Should not happen for valid input


# ═══════════════════════════════════════════════════════════════════════════
# SCORING
# ═══════════════════════════════════════════════════════════════════════════

def score_cribs_text(text):
    """Score plaintext string against known cribs."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            matches += 1
    return matches

def score_cribs_nums(pt_nums):
    """Score numeric plaintext against known cribs."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == AZ_IDX[ch]:
            matches += 1
    return matches


# ═══════════════════════════════════════════════════════════════════════════
# COLUMNAR TRANSPOSITION
# ═══════════════════════════════════════════════════════════════════════════

def columnar_perm(width, col_order, length):
    """Generate columnar transposition permutation.
    Fill row-by-row, read columns in col_order.
    Returns perm: output[i] = input[perm[i]].
    """
    from collections import defaultdict
    cols = defaultdict(list)
    for pos in range(length):
        c = pos % width
        cols[c].append(pos)
    perm = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        perm.extend(cols[col_idx])
    return perm

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def apply_perm(text, perm):
    return "".join(text[p] for p in perm)


# ═══════════════════════════════════════════════════════════════════════════
# TRACKING
# ═══════════════════════════════════════════════════════════════════════════

best_score = 0
best_tag = ""
best_pt = ""
total_configs = 0
results_log = []
top_configs = []  # Track top-5 for columnar follow-up

def test_and_log(tag, pt_text, key_info=None):
    global best_score, best_tag, best_pt, total_configs
    total_configs += 1
    if len(pt_text) < CT_LEN:
        pt_text = pt_text + 'X' * (CT_LEN - len(pt_text))
    score = score_cribs_text(pt_text[:CT_LEN])
    if score > best_score:
        best_score = score
        best_tag = tag
        best_pt = pt_text[:60]
        print(f"  NEW BEST: {score}/{N_CRIBS} -- {tag}")
        print(f"    PT: {pt_text[:60]}...")
    if score >= NOISE_FLOOR:
        entry = {"tag": tag, "score": score, "pt_prefix": pt_text[:50]}
        if key_info:
            entry["key_info"] = str(key_info)[:100]
        results_log.append(entry)
    # Track for top-5 columnar follow-up
    if len(top_configs) < 5 or score > top_configs[-1][0]:
        top_configs.append((score, tag, pt_text[:CT_LEN], key_info))
        top_configs.sort(key=lambda x: -x[0])
        if len(top_configs) > 5:
            top_configs.pop()
    return score


def test_and_log_nums(tag, pt_nums, key_info=None):
    pt_text = nums_to_text(pt_nums)
    return test_and_log(tag, pt_text, key_info)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN TESTS
# ═══════════════════════════════════════════════════════════════════════════

def main():
    global best_score, best_tag, total_configs
    t0 = time.time()

    print("=" * 72)
    print("E-CHART-04: K0 Morse E-group Pattern as Key/Selector for K4")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"E-group sizes: {E_GROUP_SIZES} (sum={sum(E_GROUP_SIZES)}, n={len(E_GROUP_SIZES)})")
    print(f"E-group cumsums: {E_GROUP_CUMSUMS}")
    print()

    # ──────────────────────────────────────────────────────────────────────
    # TEST 1: E-GROUP AS PERIODIC KEY
    # Repeat [2,1,5,1,3,2,2,5,3,1,1] to length 97. Use as key values.
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 1: E-group sizes as periodic key (period 11)")
    print("-" * 72)
    phase_start = total_configs

    key_egroup = E_GROUP_SIZES  # [2,1,5,1,3,2,2,5,3,1,1]

    # AZ alphabet
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_egroup)
        test_and_log_nums(f"T1_egroup_AZ_{vname}", pt_n, key_egroup)

    # KA alphabet: convert CT and key through KA indexing
    ct_ka = [KA_IDX[c] for c in CT]
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, key_egroup)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T1_egroup_KA_{vname}", pt_text, key_egroup)

    # Also test with 0-indexed values (subtract 1): [1,0,4,0,2,1,1,4,2,0,0]
    key_egroup_0 = [max(0, g - 1) for g in E_GROUP_SIZES]
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_egroup_0)
        test_and_log_nums(f"T1_egroup0_AZ_{vname}", pt_n, key_egroup_0)

    print(f"  Test 1: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 2: E-GROUP AS ROW SELECTOR IN TABLEAU
    # At position i, use tableau row group[i mod 11].
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 2: E-group as tableau row selector")
    print("-" * 72)
    phase_start = total_configs

    for tab_name, tableau, alpha, alpha_idx in [
        ("KA", KA_TABLEAU, KA, KA_IDX),
        ("AZ", AZ_TABLEAU, AZ, AZ_IDX),
    ]:
        # Direct: row = group_size value
        pt_chars = []
        for i in range(CT_LEN):
            row_idx = E_GROUP_SIZES[i % len(E_GROUP_SIZES)]
            col = tableau_decrypt(CT[i], row_idx, tableau, alpha_idx)
            if col is not None:
                pt_chars.append(alpha[col])
            else:
                pt_chars.append('X')
        test_and_log(f"T2_rowsel_{tab_name}", ''.join(pt_chars))

        # Reverse: column = group_size, find which row gives CT[i]
        # This means: for each position, the "key" is determined by the group
        # but we look up CT in the column instead of the row
        pt_chars2 = []
        for i in range(CT_LEN):
            col_idx = E_GROUP_SIZES[i % len(E_GROUP_SIZES)]
            # Find row where tableau[row][col_idx] == CT[i]
            found = False
            for r in range(26):
                if tableau[r][col_idx] == CT[i]:
                    pt_chars2.append(alpha[r])
                    found = True
                    break
            if not found:
                pt_chars2.append('X')
        test_and_log(f"T2_colsel_{tab_name}", ''.join(pt_chars2))

    print(f"  Test 2: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 3: E-GROUP CUMULATIVE SUMS AS CYCLIC KEY
    # [2, 3, 8, 9, 12, 14, 16, 21, 24, 25, 26] (mod 26 for last)
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 3: E-group cumulative sums as cyclic key")
    print("-" * 72)
    phase_start = total_configs

    key_cumsum = [c % 26 for c in E_GROUP_CUMSUMS]  # [2,3,8,9,12,14,16,21,24,25,0]

    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_cumsum)
        test_and_log_nums(f"T3_cumsum_AZ_{vname}", pt_n, key_cumsum)

    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, key_cumsum)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T3_cumsum_KA_{vname}", pt_text, key_cumsum)

    print(f"  Test 3: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 4: E-GROUP + OFFSET (0-25)
    # Add constant to each E-group value before using as key.
    # 26 offsets × 3 variants × 2 alphabets = 156 configs
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 4: E-group + constant offset (0-25)")
    print("-" * 72)
    phase_start = total_configs

    for offset in range(26):
        key_shifted = [(g + offset) % 26 for g in E_GROUP_SIZES]

        for vname, vfn in VARIANTS:
            pt_n = vfn(CT_NUM, key_shifted)
            test_and_log_nums(f"T4_off{offset}_AZ_{vname}", pt_n, key_shifted)

        for vname, vfn in VARIANTS:
            pt_n = vfn(ct_ka, key_shifted)
            pt_text = ''.join(KA[n] for n in pt_n)
            test_and_log(f"T4_off{offset}_KA_{vname}", pt_text, key_shifted)

    # Same for cumulative sums
    for offset in range(26):
        key_shifted = [(c + offset) % 26 for c in E_GROUP_CUMSUMS]

        for vname, vfn in VARIANTS:
            pt_n = vfn(CT_NUM, key_shifted)
            test_and_log_nums(f"T4_csoff{offset}_AZ_{vname}", pt_n, key_shifted)

        for vname, vfn in VARIANTS:
            pt_n = vfn(ct_ka, key_shifted)
            pt_text = ''.join(KA[n] for n in pt_n)
            test_and_log(f"T4_csoff{offset}_KA_{vname}", pt_text, key_shifted)

    print(f"  Test 4: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 5: E-GROUP + YAR MODULATION
    # Add YAR values (24,0,17) cyclically to the E-group pattern.
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 5: E-group + YAR modulation")
    print("-" * 72)
    phase_start = total_configs

    # Method A: Add YAR to E-group sizes cyclically
    key_yar_eg = [(E_GROUP_SIZES[i] + YAR[i % 3]) % 26 for i in range(len(E_GROUP_SIZES))]
    # [2+24, 1+0, 5+17, 1+24, 3+0, 2+17, 2+24, 5+0, 3+17, 1+24, 1+0] mod 26
    # = [0, 1, 22, 25, 3, 19, 0, 5, 20, 25, 1]

    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_yar_eg)
        test_and_log_nums(f"T5_yareg_AZ_{vname}", pt_n, key_yar_eg)
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, key_yar_eg)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T5_yareg_KA_{vname}", pt_text, key_yar_eg)

    # Method B: Add YAR to cumulative sums cyclically
    key_yar_cs = [(E_GROUP_CUMSUMS[i] + YAR[i % 3]) % 26 for i in range(len(E_GROUP_CUMSUMS))]

    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_yar_cs)
        test_and_log_nums(f"T5_yarcs_AZ_{vname}", pt_n, key_yar_cs)
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, key_yar_cs)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T5_yarcs_KA_{vname}", pt_text, key_yar_cs)

    # Method C: YAR as period-3 additive ON TOP of E-group
    # Position i gets key = E_GROUP[i%11] + YAR[i%3]
    key_yar_pos = [(E_GROUP_SIZES[i % 11] + YAR[i % 3]) % 26 for i in range(CT_LEN)]

    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_yar_pos)
        test_and_log_nums(f"T5_yarpos_AZ_{vname}", pt_n, key_yar_pos)
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, key_yar_pos)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T5_yarpos_KA_{vname}", pt_text, key_yar_pos)

    # Method D: DYAR values [3,24,0,17,14] as period-5 combined with E-group
    DYAR = [3, 24, 0, 17, 14]  # D=3, Y=24, A=0, R=17, O=14
    key_dyar_pos = [(E_GROUP_SIZES[i % 11] + DYAR[i % 5]) % 26 for i in range(CT_LEN)]

    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_dyar_pos)
        test_and_log_nums(f"T5_dyarpos_AZ_{vname}", pt_n, key_dyar_pos)
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, key_dyar_pos)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T5_dyarpos_KA_{vname}", pt_text, key_dyar_pos)

    # Method E: YAR alone as period-3 key
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, YAR)
        test_and_log_nums(f"T5_yar3_AZ_{vname}", pt_n, YAR)
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, YAR)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T5_yar3_KA_{vname}", pt_text, YAR)

    # DYAR alone as period-5 key
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, DYAR)
        test_and_log_nums(f"T5_dyar5_AZ_{vname}", pt_n, DYAR)
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, DYAR)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T5_dyar5_KA_{vname}", pt_text, DYAR)

    print(f"  Test 5: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 6: K0 FULL PHRASE CONCATENATION AS RUNNING KEY
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 6: K0 phrase concatenation as running key")
    print("-" * 72)
    phase_start = total_configs

    # K0_CONCAT = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIU..."
    k0_key_az = text_to_nums_az(K0_CONCAT)
    k0_key_ka = text_to_nums_ka(K0_CONCAT)

    # Full K0 concat (should be >= 97 chars)
    print(f"  K0 concat: {K0_CONCAT[:60]}... (len={len(K0_CONCAT)})")

    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, k0_key_az)
        test_and_log_nums(f"T6_k0concat_AZ_{vname}", pt_n, "K0_CONCAT_AZ")
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, k0_key_ka)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T6_k0concat_KA_{vname}", pt_text, "K0_CONCAT_KA")

    # Test all offsets into K0 concat (circular shift of key)
    for offset in range(len(K0_CONCAT)):
        shifted_key = K0_CONCAT[offset:] + K0_CONCAT[:offset]
        sk_az = text_to_nums_az(shifted_key)
        for vname, vfn in VARIANTS:
            pt_n = vfn(CT_NUM, sk_az)
            test_and_log_nums(f"T6_k0off{offset}_AZ_{vname}", pt_n, f"K0_off{offset}")

    # Test individual phrases as running keys
    for phrase in K0_PHRASES:
        pk_az = text_to_nums_az(phrase)
        pk_ka = text_to_nums_ka(phrase)
        for vname, vfn in VARIANTS:
            pt_n = vfn(CT_NUM, pk_az)
            test_and_log_nums(f"T6_{phrase[:8]}_AZ_{vname}", pt_n, phrase)
        for vname, vfn in VARIANTS:
            pt_n = vfn(ct_ka, pk_ka)
            pt_text = ''.join(KA[n] for n in pt_n)
            test_and_log(f"T6_{phrase[:8]}_KA_{vname}", pt_text, phrase)

    print(f"  Test 6: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 7: T=19 STARTING OFFSET
    # "T IS YOUR POSITION" = start the E-group pattern at position 19.
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 7: T=19 starting offset for E-group alignment")
    print("-" * 72)
    phase_start = total_configs

    for t_offset in [19, 20]:  # T=19 (A=0) and T=20 (A=1)
        # Method A: Shift the key alignment so position t_offset uses group[0]
        # Positions 0..t_offset-1 use later groups
        for vname, vfn in VARIANTS:
            # Build full key: position i uses E_GROUP_SIZES[(i - t_offset) % 11]
            key_shifted = [E_GROUP_SIZES[(i - t_offset) % 11] for i in range(CT_LEN)]
            pt_n = vfn(CT_NUM, key_shifted)
            test_and_log_nums(f"T7_toff{t_offset}_eg_AZ_{vname}", pt_n, f"egroup_shift_{t_offset}")

            key_cs_shifted = [E_GROUP_CUMSUMS[(i - t_offset) % 11] % 26 for i in range(CT_LEN)]
            pt_n = vfn(CT_NUM, key_cs_shifted)
            test_and_log_nums(f"T7_toff{t_offset}_cs_AZ_{vname}", pt_n, f"cumsum_shift_{t_offset}")

        # Method B: Circular shift of CT by t_offset, then apply E-group key
        ct_shifted = CT[t_offset:] + CT[:t_offset]
        ct_shifted_nums = [AZ_IDX[c] for c in ct_shifted]

        for vname, vfn in VARIANTS:
            pt_n = vfn(ct_shifted_nums, E_GROUP_SIZES)
            test_and_log_nums(f"T7_ctshift{t_offset}_eg_AZ_{vname}", pt_n, f"CT_rot{t_offset}+egroup")

            pt_n = vfn(ct_shifted_nums, key_cumsum)
            test_and_log_nums(f"T7_ctshift{t_offset}_cs_AZ_{vname}", pt_n, f"CT_rot{t_offset}+cumsum")

        # Method C: Start reading E-groups at position 19 in K4
        # Positions 0-18: identity (no key), positions 19+: E-group key
        for vname, vfn in VARIANTS:
            key_partial = [0] * t_offset + [E_GROUP_SIZES[(i - t_offset) % 11] for i in range(t_offset, CT_LEN)]
            pt_n = vfn(CT_NUM, key_partial[:CT_LEN])
            test_and_log_nums(f"T7_partial{t_offset}_AZ_{vname}", pt_n, f"partial_from_{t_offset}")

    print(f"  Test 7: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 8: E-POSITIONS IN MORSE STREAM AS KEY VALUES
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 8: E-positions in Morse stream as key values")
    print("-" * 72)
    phase_start = total_configs

    # Compute E positions: index of each 'e' within the token stream
    e_token_positions = [i for i, t in enumerate(MORSE_TOKENS) if t == 'e']
    print(f"  E token positions: {e_token_positions}")
    print(f"  Count: {len(e_token_positions)}")

    # E positions within message-letter stream (letters only, excluding e's)
    e_msg_positions = []
    msg_idx = 0
    for t in MORSE_TOKENS:
        if t == 'e':
            e_msg_positions.append(msg_idx)
        else:
            msg_idx += 1
    print(f"  E msg-stream positions: {e_msg_positions}")

    # Method A: Use e_token_positions (mod 26) as cyclic key
    key_etok = [p % 26 for p in e_token_positions]
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_etok)
        test_and_log_nums(f"T8_etokpos_AZ_{vname}", pt_n, key_etok)

    # Method B: Use e_msg_positions (mod 26) as cyclic key
    key_emsg = [p % 26 for p in e_msg_positions]
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_emsg)
        test_and_log_nums(f"T8_emsgpos_AZ_{vname}", pt_n, key_emsg)

    # Method C: Differences between consecutive E positions
    e_diffs = [e_token_positions[i+1] - e_token_positions[i] for i in range(len(e_token_positions)-1)]
    key_ediff = [d % 26 for d in e_diffs]
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_ediff)
        test_and_log_nums(f"T8_ediff_AZ_{vname}", pt_n, key_ediff)

    # Method D: Binary pattern from E's (E=1, letter=0), use as bitmask
    binary_pattern = [1 if t == 'e' else 0 for t in MORSE_TOKENS]
    # Use first 97 bits as additive key (0 or 1)
    key_binary = binary_pattern[:CT_LEN]
    if len(key_binary) < CT_LEN:
        key_binary.extend([0] * (CT_LEN - len(key_binary)))
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, key_binary)
        test_and_log_nums(f"T8_binary_AZ_{vname}", pt_n, "binary_e_pattern")

    # Method E: E positions mark positions to skip/null in K4 CT
    # Map 26 E positions to 26 K4 positions (mod 97 or directly 0-25)
    for mapping_name, null_positions in [
        ("first26", set(range(26))),
        ("epos_mod97", set(p % 97 for p in e_token_positions)),
        ("emsg_mod97", set(p % 97 for p in e_msg_positions)),
    ]:
        reduced = ''.join(CT[i] for i in range(CT_LEN) if i not in null_positions)
        # Score the reduced text against shifted cribs? That's complex.
        # Instead, test as-is and also pad to 97
        padded = reduced + 'X' * (CT_LEN - len(reduced))
        test_and_log(f"T8_null_{mapping_name}", padded, f"nulls={null_positions}")

    print(f"  Test 8: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 9: COMBINED E-GROUP + K3 RUNNING KEY
    # Use E-group sizes to SELECT characters from K3 plaintext.
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 9: E-group as selector into K3 plaintext")
    print("-" * 72)
    phase_start = total_configs
    print(f"  K3 PT length: {len(K3_PT)}")

    # Method A: Cumulative E-group positions select K3 chars
    # Take char at position cumsum[i % 11] from K3, use as key for position i
    k3_selected_key = []
    for i in range(CT_LEN):
        pos_in_k3 = E_GROUP_CUMSUMS[i % len(E_GROUP_CUMSUMS)] - 1  # 0-indexed
        if pos_in_k3 < len(K3_PT):
            k3_selected_key.append(AZ_IDX[K3_PT[pos_in_k3]])
        else:
            k3_selected_key.append(0)

    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, k3_selected_key)
        test_and_log_nums(f"T9_k3sel_cs_AZ_{vname}", pt_n, "k3_cumsum_select")

    # Method B: E-group sizes as step values through K3
    # Start at K3[0], step by E-group sizes cyclically
    k3_stepped_key = []
    k3_pos = 0
    for i in range(CT_LEN):
        if k3_pos < len(K3_PT):
            k3_stepped_key.append(AZ_IDX[K3_PT[k3_pos % len(K3_PT)]])
        else:
            k3_stepped_key.append(AZ_IDX[K3_PT[k3_pos % len(K3_PT)]])
        k3_pos += E_GROUP_SIZES[i % len(E_GROUP_SIZES)]

    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, k3_stepped_key)
        test_and_log_nums(f"T9_k3step_AZ_{vname}", pt_n, "k3_egroup_step")

    # Method C: K3 plaintext directly as running key
    k3_key_az = text_to_nums_az(K3_PT)
    for vname, vfn in VARIANTS:
        pt_n = vfn(CT_NUM, k3_key_az)
        test_and_log_nums(f"T9_k3direct_AZ_{vname}", pt_n, "k3_direct")

    # K3 through KA
    k3_key_ka = text_to_nums_ka(K3_PT)
    for vname, vfn in VARIANTS:
        pt_n = vfn(ct_ka, k3_key_ka)
        pt_text = ''.join(KA[n] for n in pt_n)
        test_and_log(f"T9_k3direct_KA_{vname}", pt_text, "k3_direct_KA")

    print(f"  Test 9: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 10: E-GROUP AS TRANSPOSITION PATTERN
    # Use the 11 E-group values to define short permutations.
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 10: E-group as transposition pattern")
    print("-" * 72)
    phase_start = total_configs

    # Method A: Use E-group sizes to chunk CT, then reverse within each chunk
    def chunk_and_reverse(text, sizes):
        result = []
        pos = 0
        size_idx = 0
        while pos < len(text):
            sz = sizes[size_idx % len(sizes)]
            chunk = text[pos:pos + sz]
            result.append(chunk[::-1])
            pos += sz
            size_idx += 1
        return ''.join(result)

    pt = chunk_and_reverse(CT, E_GROUP_SIZES)
    test_and_log("T10_chunk_rev", pt, "egroup_chunk_reverse")

    # Method B: Use E-group sizes as column widths for columnar-like reading
    # Write CT row-by-row into columns of varying width, read column-by-column
    def variable_width_columnar(text, widths):
        """Write text using variable-width rows defined by widths (cyclic).
        Then read column-by-column."""
        rows = []
        pos = 0
        w_idx = 0
        while pos < len(text):
            w = widths[w_idx % len(widths)]
            row = text[pos:pos + w]
            rows.append(row)
            pos += w
            w_idx += 1
        # Find max width
        max_w = max(len(r) for r in rows)
        # Read columns
        result = []
        for c in range(max_w):
            for r in rows:
                if c < len(r):
                    result.append(r[c])
        return ''.join(result)

    pt = variable_width_columnar(CT, E_GROUP_SIZES)
    test_and_log("T10_varwidth_col", pt, "variable_width_columnar")

    # Method C: E-group sizes define a period-11 permutation (rank order)
    # [2,1,5,1,3,2,2,5,3,1,1] -> rank by value (stable sort)
    # Values sorted: [1,1,1,1,2,2,2,3,3,5,5] at indices [1,3,9,10,0,5,6,4,8,2,7]
    # So rank = position when sorted by value
    indexed = sorted(range(11), key=lambda i: (E_GROUP_SIZES[i], i))
    perm_11 = [0] * 11
    for rank, idx in enumerate(indexed):
        perm_11[idx] = rank
    print(f"  E-group rank permutation: {perm_11}")

    # Apply as period-11 block permutation on CT
    result_chars = list('X' * CT_LEN)
    for block_start in range(0, CT_LEN, 11):
        block_end = min(block_start + 11, CT_LEN)
        block_len = block_end - block_start
        for i in range(block_len):
            target = perm_11[i]
            if target < block_len:
                result_chars[block_start + target] = CT[block_start + i]
    test_and_log("T10_rank_perm", ''.join(result_chars), perm_11)

    # Inverse of the rank permutation
    inv_perm_11 = [0] * 11
    for i, p in enumerate(perm_11):
        inv_perm_11[p] = i
    result_chars2 = list('X' * CT_LEN)
    for block_start in range(0, CT_LEN, 11):
        block_end = min(block_start + 11, CT_LEN)
        block_len = block_end - block_start
        for i in range(block_len):
            target = inv_perm_11[i]
            if target < block_len:
                result_chars2[block_start + target] = CT[block_start + i]
    test_and_log("T10_rank_inv_perm", ''.join(result_chars2), inv_perm_11)

    # Method D: Width-11 columnar with rank permutation
    perm_full = columnar_perm(11, perm_11, CT_LEN)
    inv_full = invert_perm(perm_full)
    pt = apply_perm(CT, inv_full)
    test_and_log("T10_col11_rank", pt, "w11_rank_perm")

    pt = apply_perm(CT, perm_full)
    test_and_log("T10_col11_rank_fwd", pt, "w11_rank_perm_fwd")

    # Then apply substitution on the transposed result
    for vname, vfn in VARIANTS:
        pt_nums = [AZ_IDX[c] for c in pt]
        for key_name, key_vals in [
            ("egroup", E_GROUP_SIZES),
            ("cumsum", key_cumsum),
            ("yar", YAR),
        ]:
            dec_n = vfn(pt_nums, key_vals)
            test_and_log_nums(f"T10_col11+{key_name}_{vname}", dec_n, f"w11_rank+{key_name}")

    print(f"  Test 10: {total_configs - phase_start} configs, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # TEST 11: TOP-5 CONFIGS THROUGH WIDTH-8 COLUMNAR (ALL 40,320 orderings)
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "-" * 72)
    print("TEST 11: Top-5 configs through width-8 columnar transposition")
    print("-" * 72)
    phase_start = total_configs

    # For each of the top-5 scoring configs, try all w8 columnar orderings
    # Width 8 = 8! = 40,320 permutations
    print(f"  Top-5 configs to test:")
    for rank, (sc, tag, pt_text, kinfo) in enumerate(top_configs):
        print(f"    #{rank+1}: score={sc}, tag={tag}")

    # Pre-compute all w8 columnar permutations (inverse)
    w8_inv_perms = []
    for col_order in itertools.permutations(range(8)):
        perm = columnar_perm(8, list(col_order), CT_LEN)
        w8_inv_perms.append((col_order, invert_perm(perm)))

    # For each top config: the "pt_text" from that config is actually the
    # intermediate result. We need the KEY that produced it, then apply
    # columnar BEFORE the substitution.
    # But since we track pt_text not the key, let's instead take a different
    # approach: apply w8 columnar to CT first, then the best substitution keys.

    # Collect the best key patterns from Tests 1-10
    best_keys = [
        ("egroup", E_GROUP_SIZES),
        ("cumsum", key_cumsum),
        ("yar_eg", key_yar_eg),
        ("yar_cs", key_yar_cs),
        ("yar3", YAR),
        ("k0concat", k0_key_az[:CT_LEN]),
    ]

    for col_order, inv_p in w8_inv_perms:
        ct_untrans = apply_perm(CT, inv_p)
        ct_untrans_nums = [AZ_IDX[c] for c in ct_untrans]

        for key_name, key_vals in best_keys:
            for vname, vfn in VARIANTS:
                pt_n = vfn(ct_untrans_nums, key_vals)
                sc = score_cribs_nums(pt_n)
                total_configs += 1
                if sc > best_score:
                    best_score = sc
                    pt_text = nums_to_text(pt_n)
                    best_tag = f"T11_w8_{col_order}_{key_name}_{vname}"
                    best_pt = pt_text[:60]
                    print(f"  NEW BEST: {sc}/{N_CRIBS} -- {best_tag}")
                    print(f"    PT: {pt_text[:60]}...")
                if sc >= NOISE_FLOOR:
                    results_log.append({
                        "tag": f"T11_w8_{col_order}_{key_name}_{vname}",
                        "score": sc,
                        "pt_prefix": nums_to_text(pt_n)[:50],
                    })

    print(f"  Test 11: {total_configs - phase_start} configs, best={best_score}")

    # ═══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configurations tested: {total_configs:,}")
    print(f"Above NOISE ({NOISE_FLOOR}): {len(results_log)}")
    print(f"Best score: {best_score}/{N_CRIBS} ({best_tag})")
    if best_pt:
        print(f"Best PT prefix: {best_pt}")
    print(f"Elapsed: {elapsed:.1f}s")

    if results_log:
        print("\nTop results:")
        for r in sorted(results_log, key=lambda x: -x["score"])[:20]:
            print(f"  score={r['score']}/{N_CRIBS} | {r['tag']}")

    verdict = "SIGNAL" if best_score >= 18 else ("STORE" if best_score > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    # Save results
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment_id": "E-CHART-04",
        "hypothesis": "K0 Morse E-group pattern as key/selector for K4",
        "e_group_sizes": E_GROUP_SIZES,
        "e_group_cumsums": E_GROUP_CUMSUMS,
        "total_configs": total_configs,
        "best_score": best_score,
        "best_tag": best_tag,
        "elapsed_seconds": elapsed,
        "verdict": verdict,
        "results_above_noise": sorted(results_log, key=lambda x: -x["score"])[:50],
        "tests_run": [
            "T1: E-group as periodic key",
            "T2: E-group as tableau row selector",
            "T3: E-group cumulative sums as key",
            "T4: E-group + constant offset (0-25)",
            "T5: E-group + YAR/DYAR modulation",
            "T6: K0 phrase concatenation as running key",
            "T7: T=19 starting offset",
            "T8: E-positions in Morse stream",
            "T9: Combined E-group + K3 running key",
            "T10: E-group as transposition pattern",
            "T11: Top-5 keys through w8 columnar (40,320 orderings)",
        ],
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_chart_04_morse_pattern.py",
    }

    with open("results/e_chart_04_morse.json", "w") as f:
        json.dump(artifact, f, indent=2, default=str)

    print(f"\nResults saved to results/e_chart_04_morse.json")


if __name__ == "__main__":
    main()
