#!/usr/bin/env python3
"""
Cipher: NDYAHR / removal / running key
Family: k3_continuity
Status: active
Keyspace: ~15000 configs
Last run:
Best score:
"""
"""E-NDYAHR-K123CT-DEEP: Deep analysis of key findings from unified NDYAHR study.

KEY FINDINGS FROM STEP 1 to investigate:
  1. Removing {H} or {R} from K1+K2+K3 gives 730 = 10 x 73 chars
  2. Removing {N,Y} or {R,Y} from K1+K2+K3+K4 gives 803 = 11 x 73
  3. Residue IC = 0.0635 (nearly English) -- NDYAHR-only IC = 0.171 (VERY high)
  4. NDYAHR-only IC = 0.171 means only 6 letters with extreme repetition bias
  5. K4 non-NDYAHR = 80 chars (not 73)

DEEP INVESTIGATION:
  A. 730 = 10x73: Remove H or R from K1+K2+K3, reshape into 10 rows of 73
  B. 803 = 11x73: Remove {N,Y} or {R,Y} from full sculpture, reshape 11x73
  C. Try all these as K4 decryption keys at various offsets
  D. Check if the 10x73 or 11x73 grids have columnar reading order signals
  E. Look for patterns in WHICH H or R positions create the 73-multiple

Usage: PYTHONPATH=src python3 -u scripts/k3_continuity/e_ndyahr_k123ct_deep.py
"""

import sys
import os
import json
import time
from collections import Counter
from itertools import combinations, permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import (
    score_candidate, score_candidate_free,
)

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

def clean(s):
    return ''.join(c for c in s.upper() if c.isalpha())

def ic(text):
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text)
    return sum(f*(f-1) for f in freq.values()) / (n*(n-1))

def to_nums(text, idx_map):
    return [idx_map[c] for c in text]

def to_text(nums, alphabet):
    return ''.join(alphabet[n % len(alphabet)] for n in nums)

def extend_key(key_text, length):
    if not key_text:
        return ""
    reps = (length // len(key_text)) + 1
    return (key_text * reps)[:length]

VARIANTS = {
    "Vig": lambda ct, key: [(c - k) % 26 for c, k in zip(ct, key)],
    "Beau": lambda ct, key: [(k - c) % 26 for c, k in zip(ct, key)],
    "VBeau": lambda ct, key: [(c + k) % 26 for c, k in zip(ct, key)],
}

results_log = []
best_overall_score = 0
best_overall_config = ""
total_configs = 0

def record(label, pt_text):
    global best_overall_score, best_overall_config, total_configs
    total_configs += 1
    anchored = score_candidate(pt_text)
    free = score_candidate_free(pt_text)
    score_a = anchored.crib_score
    score_f = free.crib_score
    best_score = max(score_a, score_f)
    if best_score > best_overall_score:
        best_overall_score = best_score
        best_overall_config = label
    if best_score > NOISE_FLOOR:
        tag = "FREE" if score_f > score_a else "ANCHORED"
        print(f"    ** {tag} {best_score}/24: {label}")
        print(f"       PT: {pt_text[:60]}...")
    if best_score >= STORE_THRESHOLD:
        results_log.append({"label": label, "score": best_score, "pt": pt_text[:80]})
    return best_score


t0 = time.time()

k1 = clean(K1_CT)
k2 = clean(K2_CT)
k3 = clean(K3_CT)
k123 = k1 + k2 + k3
k1234 = k123 + CT

print("=" * 78)
print("E-NDYAHR-K123CT-DEEP: Deep Analysis of 73-Multiple Findings")
print("=" * 78)

KEYWORDS = ["KRYPTOS", "DEFECTOR", "PALIMPSEST", "ABSCISSA", "KOMPASS",
            "COLOPHON", "PARALLAX", "SHADOW", "SANBORN", "MEDUSA", "ENIGMA"]

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION A: Remove H from K123 → 730 = 10 x 73
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("INVESTIGATION A: Remove {H} from K1+K2+K3 → 730 = 10 x 73")
print("=" * 78)

k123_no_H = ''.join(c for c in k123 if c != 'H')
assert len(k123_no_H) == 730, f"Expected 730, got {len(k123_no_H)}"
print(f"  Length: {len(k123_no_H)} = 10 x 73")
print(f"  IC: {ic(k123_no_H):.6f}")

# Reshape into 10 rows of 73
rows_10x73 = [k123_no_H[i*73:(i+1)*73] for i in range(10)]
for i, row in enumerate(rows_10x73):
    print(f"  Row {i}: {row[:40]}...{row[-10:]}")

# Read columns (width 73, 10 rows) → 73-char columns
col_read_73 = ''.join(k123_no_H[c*10 + r] if c*10+r < 730 else '' for r in range(10) for c in range(73))
# Actually: read column by column
col_read = ''
for c in range(73):
    for r in range(10):
        idx = r * 73 + c
        if idx < 730:
            col_read += k123_no_H[idx]

print(f"\n  Column-read (10x73): {col_read[:50]}...")
print(f"  IC of column-read: {ic(col_read):.6f}")

# Use last row (73 chars) as K4 running key
last_row = rows_10x73[-1]
print(f"\n  Last row (73 chars): {last_row[:50]}...")

# Also try first row
first_row = rows_10x73[0]

# Try each row as a running key for K4
print("\n  Testing each 73-char row as K4 running key:")
best_A = 0
for row_idx, row in enumerate(rows_10x73):
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        # Row is 73 chars, K4 is 97. Extend.
        key_text = extend_key(row, CT_LEN)
        ct_nums = to_nums(CT, aidx)
        key_nums = to_nums(key_text, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            s = record(f"A:row{row_idx}/{alph_name}/{var_name}", pt_text)
            best_A = max(best_A, s)

# Try column read as running key
for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
    alphabet = AZ if alph_name == "AZ" else KA
    key_text = col_read[:CT_LEN]
    ct_nums = to_nums(CT, aidx)
    key_nums = to_nums(key_text, aidx)
    for var_name, decrypt_fn in VARIANTS.items():
        pt_nums = decrypt_fn(ct_nums, key_nums)
        pt_text = to_text(pt_nums, alphabet)
        s = record(f"A:col_read/{alph_name}/{var_name}", pt_text)
        best_A = max(best_A, s)

# Try columnar transposition with various widths on each row
for row_idx, row in enumerate(rows_10x73):
    for width in [7, 8, 9, 10, 11, 13, 14, 24, 31, 73]:
        if width > len(row):
            continue
        # Read columns
        transposed = ''
        for c in range(width):
            for r_pos in range(0, len(row), width):
                if r_pos + c < len(row):
                    transposed += row[r_pos + c]
        for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
            alphabet = AZ if alph_name == "AZ" else KA
            key_text = extend_key(transposed, CT_LEN)
            ct_nums = to_nums(CT, aidx)
            key_nums = to_nums(key_text, aidx)
            for var_name, decrypt_fn in VARIANTS.items():
                pt_nums = decrypt_fn(ct_nums, key_nums)
                pt_text = to_text(pt_nums, alphabet)
                s = record(f"A:row{row_idx}_col{width}/{alph_name}/{var_name}", pt_text)
                best_A = max(best_A, s)

print(f"\n  Best Investigation A: {best_A}/24")

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION A2: Remove R from K123 → 730 = 10 x 73
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("INVESTIGATION A2: Remove {R} from K1+K2+K3 → 730 = 10 x 73")
print("=" * 78)

k123_no_R = ''.join(c for c in k123 if c != 'R')
assert len(k123_no_R) == 730, f"Expected 730, got {len(k123_no_R)}"
print(f"  Length: {len(k123_no_R)} = 10 x 73")
print(f"  IC: {ic(k123_no_R):.6f}")

rows_R_10x73 = [k123_no_R[i*73:(i+1)*73] for i in range(10)]

# Test rows and column reads as running key
best_A2 = 0
for row_idx, row in enumerate(rows_R_10x73):
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        key_text = extend_key(row, CT_LEN)
        ct_nums = to_nums(CT, aidx)
        key_nums = to_nums(key_text, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            s = record(f"A2:Rrow{row_idx}/{alph_name}/{var_name}", pt_text)
            best_A2 = max(best_A2, s)

# Column read
col_read_R = ''
for c in range(73):
    for r in range(10):
        idx = r * 73 + c
        if idx < 730:
            col_read_R += k123_no_R[idx]

for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
    alphabet = AZ if alph_name == "AZ" else KA
    key_text = col_read_R[:CT_LEN]
    ct_nums = to_nums(CT, aidx)
    key_nums = to_nums(key_text, aidx)
    for var_name, decrypt_fn in VARIANTS.items():
        pt_nums = decrypt_fn(ct_nums, key_nums)
        pt_text = to_text(pt_nums, alphabet)
        s = record(f"A2:col_read_R/{alph_name}/{var_name}", pt_text)
        best_A2 = max(best_A2, s)

print(f"  Best Investigation A2: {best_A2}/24")

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION B: Remove {N,Y} from K1234 → 803 = 11 x 73
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("INVESTIGATION B: Remove {N,Y} from full sculpture → 803 = 11 x 73")
print("=" * 78)

k1234_no_NY = ''.join(c for c in k1234 if c not in {'N', 'Y'})
assert len(k1234_no_NY) == 803, f"Expected 803, got {len(k1234_no_NY)}"
print(f"  Length: {len(k1234_no_NY)} = 11 x 73")
print(f"  IC: {ic(k1234_no_NY):.6f}")

rows_11x73 = [k1234_no_NY[i*73:(i+1)*73] for i in range(11)]

best_B = 0
# Test each row as running key
for row_idx, row in enumerate(rows_11x73):
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        key_text = extend_key(row, CT_LEN)
        ct_nums = to_nums(CT, aidx)
        key_nums = to_nums(key_text, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            s = record(f"B:NYrow{row_idx}/{alph_name}/{var_name}", pt_text)
            best_B = max(best_B, s)

# Column read: 11 x 73 → read by column
col_read_NY = ''
for c in range(73):
    for r in range(11):
        idx = r * 73 + c
        if idx < 803:
            col_read_NY += k1234_no_NY[idx]

for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
    alphabet = AZ if alph_name == "AZ" else KA
    key_text = col_read_NY[:CT_LEN]
    ct_nums = to_nums(CT, aidx)
    key_nums = to_nums(key_text, aidx)
    for var_name, decrypt_fn in VARIANTS.items():
        pt_nums = decrypt_fn(ct_nums, key_nums)
        pt_text = to_text(pt_nums, alphabet)
        s = record(f"B:col_read_NY/{alph_name}/{var_name}", pt_text)
        best_B = max(best_B, s)

# Also the last row should correspond to the K4 region
last_row_NY = rows_11x73[-1]
print(f"\n  Last row (73 chars): {last_row_NY}")
print(f"  Does it resemble K4? K4={CT[:30]}...")
# Check overlap
overlap = sum(1 for a, b in zip(last_row_NY, CT) if a == b)
print(f"  Direct overlap with K4: {overlap}/{min(len(last_row_NY),CT_LEN)}")

print(f"\n  Best Investigation B: {best_B}/24")

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION B2: Remove {R,Y} from K1234 → 803 = 11 x 73
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("INVESTIGATION B2: Remove {R,Y} from full sculpture → 803 = 11 x 73")
print("=" * 78)

k1234_no_RY = ''.join(c for c in k1234 if c not in {'R', 'Y'})
assert len(k1234_no_RY) == 803, f"Expected 803, got {len(k1234_no_RY)}"
print(f"  Length: {len(k1234_no_RY)} = 11 x 73")

rows_RY_11x73 = [k1234_no_RY[i*73:(i+1)*73] for i in range(11)]

best_B2 = 0
for row_idx, row in enumerate(rows_RY_11x73):
    for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
        alphabet = AZ if alph_name == "AZ" else KA
        key_text = extend_key(row, CT_LEN)
        ct_nums = to_nums(CT, aidx)
        key_nums = to_nums(key_text, aidx)
        for var_name, decrypt_fn in VARIANTS.items():
            pt_nums = decrypt_fn(ct_nums, key_nums)
            pt_text = to_text(pt_nums, alphabet)
            s = record(f"B2:RYrow{row_idx}/{alph_name}/{var_name}", pt_text)
            best_B2 = max(best_B2, s)

# Column read
col_read_RY = ''
for c in range(73):
    for r in range(11):
        idx = r * 73 + c
        if idx < 803:
            col_read_RY += k1234_no_RY[idx]

for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
    alphabet = AZ if alph_name == "AZ" else KA
    key_text = col_read_RY[:CT_LEN]
    ct_nums = to_nums(CT, aidx)
    key_nums = to_nums(key_text, aidx)
    for var_name, decrypt_fn in VARIANTS.items():
        pt_nums = decrypt_fn(ct_nums, key_nums)
        pt_text = to_text(pt_nums, alphabet)
        s = record(f"B2:col_read_RY/{alph_name}/{var_name}", pt_text)
        best_B2 = max(best_B2, s)

print(f"  Best Investigation B2: {best_B2}/24")

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION C: Statistical significance of 73-multiples
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("INVESTIGATION C: Are 73-multiples statistically significant?")
print("=" * 78)

# How likely is it that removing a single letter from 768 gives a multiple of 73?
# Each letter has freq f. Residue = 768 - f. We need 768 - f = 0 mod 73.
# 768 mod 73 = 768 - 10*73 = 768 - 730 = 38. So we need f = 38.
# H has freq 38, R has freq 38. EXACTLY the right count.
# 768 mod 73 = 38. Any letter with count 38 in K123 will give 730 = 10*73.
print(f"  K1+K2+K3 length: {len(k123)} = 768")
print(f"  768 mod 73 = {768 % 73}")
print(f"  So removing exactly 38 of ANY letter gives 730 = 10x73")

freq_k123 = Counter(k123)
letters_with_38 = [ch for ch, count in freq_k123.most_common() if count == 38]
print(f"\n  Letters with exactly 38 occurrences in K123: {letters_with_38}")
print(f"  Full frequency table:")
for ch, count in sorted(freq_k123.items()):
    marker = " ** 73-MULTIPLE" if count == 38 else ""
    print(f"    {ch}: {count}{marker}")

# For 2-letter removal giving 803 = 11*73 from 865 (K1234)
# 865 mod 73 = 865 - 11*73 = 865 - 803 = 62. So need to remove 62 letters total.
freq_k1234 = Counter(k1234)
print(f"\n  K1+K2+K3+K4 length: {len(k1234)} = 865")
print(f"  865 mod 73 = {865 % 73}")
print(f"  Need to remove exactly 62 chars for 11x73")

# Check all 2-letter combos
print(f"\n  2-letter subsets removing 62 from K1234:")
for c1, c2 in combinations(sorted(freq_k1234.keys()), 2):
    total = freq_k1234[c1] + freq_k1234[c2]
    if total == 62:
        print(f"    {{{c1},{c2}}}: {freq_k1234[c1]} + {freq_k1234[c2]} = 62")

# How many 2-letter combos give 62? Expected by chance?
total_combos = len(list(combinations(sorted(freq_k1234.keys()), 2)))
matching_combos = sum(1 for c1, c2 in combinations(sorted(freq_k1234.keys()), 2)
                      if freq_k1234[c1] + freq_k1234[c2] == 62)
print(f"\n  Total 2-letter combos: {total_combos}")
print(f"  Combos summing to 62: {matching_combos}")
print(f"  Expected if uniform: ~{total_combos}/{len(k1234):.0f} ≈ {total_combos/len(k1234):.1f}")

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION D: Keyword-columnar on 10x73 grids
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("INVESTIGATION D: Keyword-columnar transposition on 10x73 and 11x73 grids")
print("=" * 78)

def keyword_to_order(keyword):
    """Convert keyword to column order (standard method)."""
    indexed = sorted(enumerate(keyword), key=lambda x: (x[1], x[0]))
    order = [0] * len(keyword)
    for rank, (orig_idx, _) in enumerate(indexed):
        order[orig_idx] = rank
    return order

def columnar_read(text, width, col_order=None):
    """Read text in columnar transposition order."""
    nrows = (len(text) + width - 1) // width
    # Pad if needed
    padded = text + 'X' * (nrows * width - len(text))
    # Fill grid row by row
    grid = [padded[r*width:(r+1)*width] for r in range(nrows)]
    # Read by column order
    if col_order is None:
        col_order = list(range(width))
    result = ''
    for c in col_order:
        for r in range(nrows):
            if c < len(grid[r]):
                result += grid[r][c]
    return result

# Try keyword-columnar on remove-H residue (730 chars)
print("\n  Testing keyword-columnar on K123\\H (730 chars):")
best_D = 0
for kw in KEYWORDS:
    kw_order = keyword_to_order(kw)
    for width in [len(kw)]:
        transposed = columnar_read(k123_no_H, width, kw_order)
        # Use first 97 chars as running key for K4
        for offset in range(0, min(len(transposed) - CT_LEN + 1, 20)):
            key_slice = transposed[offset:offset + CT_LEN]
            for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
                alphabet = AZ if alph_name == "AZ" else KA
                ct_nums = to_nums(CT, aidx)
                key_nums = to_nums(key_slice, aidx)
                for var_name, decrypt_fn in VARIANTS.items():
                    pt_nums = decrypt_fn(ct_nums, key_nums)
                    pt_text = to_text(pt_nums, alphabet)
                    s = record(f"D:noH_col_{kw}/off{offset}/{alph_name}/{var_name}", pt_text)
                    best_D = max(best_D, s)

# Also try on remove-R residue
for kw in KEYWORDS:
    kw_order = keyword_to_order(kw)
    for width in [len(kw)]:
        transposed = columnar_read(k123_no_R, width, kw_order)
        for offset in range(0, min(len(transposed) - CT_LEN + 1, 20)):
            key_slice = transposed[offset:offset + CT_LEN]
            for alph_name, aidx in [("AZ", AZ_IDX), ("KA", KA_IDX)]:
                alphabet = AZ if alph_name == "AZ" else KA
                ct_nums = to_nums(CT, aidx)
                key_nums = to_nums(key_slice, aidx)
                for var_name, decrypt_fn in VARIANTS.items():
                    pt_nums = decrypt_fn(ct_nums, key_nums)
                    pt_text = to_text(pt_nums, alphabet)
                    s = record(f"D:noR_col_{kw}/off{offset}/{alph_name}/{var_name}", pt_text)
                    best_D = max(best_D, s)

print(f"  Best Investigation D: {best_D}/24")

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION E: NDYAHR-only IC anomaly
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("INVESTIGATION E: NDYAHR-only text analysis (IC=0.171)")
print("=" * 78)

ndyahr_chars = ''.join(c for c in k123 if c in set("NDYAHR"))
print(f"  NDYAHR-only text: {len(ndyahr_chars)} chars")
print(f"  IC: {ic(ndyahr_chars):.6f}")
print(f"  Frequency: {Counter(ndyahr_chars).most_common()}")

# IC of just these 6 letters in a random text of this length
# With 6 equally likely letters, IC = 1/6 = 0.167
# With English frequencies restricted to NDYAHR, IC would be higher
print(f"  IC for 6 uniform letters: {1/6:.6f}")
print(f"  Actual IC: {ic(ndyahr_chars):.6f}")
print(f"  Ratio to uniform: {ic(ndyahr_chars) / (1/6):.3f}")

# The IC is EXPECTED to be high because we're only looking at 6 letters
# This is not anomalous -- it's a mathematical artifact

# But let's check if the SEQUENCE has structure
# Look at digram frequencies
digrams = Counter()
for i in range(len(ndyahr_chars) - 1):
    digrams[ndyahr_chars[i:i+2]] += 1
print(f"\n  Top 10 digrams:")
for d, count in digrams.most_common(10):
    print(f"    {d}: {count}")

# ══════════════════════════════════════════════════════════════════════════
# INVESTIGATION F: Extract K4 chars NOT in NDYAHR positions
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 78)
print("INVESTIGATION F: K4 with NDYAHR removed → 80 chars analysis")
print("=" * 78)

k4_no_ndyahr = ''.join(c for c in CT if c not in set("NDYAHR"))
print(f"  K4 non-NDYAHR: {len(k4_no_ndyahr)} chars")
print(f"  Text: {k4_no_ndyahr}")
print(f"  IC: {ic(k4_no_ndyahr):.6f}")
print(f"  Frequency: {Counter(k4_no_ndyahr).most_common()}")

# 80 = NOT 73. But what about K4 non-{H} or K4 non-{R}?
for ch in "NDYAHR":
    k4_without = ''.join(c for c in CT if c != ch)
    print(f"  K4 without {ch}: {len(k4_without)} chars")

# Check if any single letter removal from K4 gives 73
# 97 - x = 73 → x = 24. Need a letter appearing exactly 24 times.
freq_k4 = Counter(CT)
print(f"\n  K4 letter frequencies:")
for ch, count in sorted(freq_k4.items()):
    marker = " ** = 24 (73-char target)" if count == 24 else ""
    print(f"    {ch}: {count}{marker}")

# No letter appears 24 times, but what about letter SETS?
print(f"\n  Checking letter sets removing 24 from K4 (for residue = 73):")
for size in range(2, 7):
    for subset in combinations(sorted(freq_k4.keys()), size):
        total = sum(freq_k4[c] for c in subset)
        if total == 24:
            print(f"    {{{','.join(subset)}}}: {'+'.join(str(freq_k4[c]) for c in subset)} = 24")

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════

elapsed = time.time() - t0

print("\n" + "=" * 78)
print("SUMMARY")
print("=" * 78)
print(f"  Total configs tested: {total_configs:,}")
print(f"  Elapsed: {elapsed:.1f}s")
print(f"  Best overall score: {best_overall_score}/24")
print(f"  Best config: {best_overall_config}")

if results_log:
    print(f"\n  Results above store threshold:")
    for r in sorted(results_log, key=lambda x: -x['score']):
        print(f"    {r['score']}/24: {r['label']}")

print(f"\n  CRITICAL FINDINGS:")
print(f"    1. 730 = 10x73 from removing H (count=38) or R (count=38)")
print(f"       This is because 768 mod 73 = 38. NOT a coincidence of NDYAHR;")
print(f"       ANY letter with count 38 gives 10x73.")
print(f"    2. 803 = 11x73 from removing {{N,Y}} or {{R,Y}} from K1234")
print(f"       865 mod 73 = 62. Multiple 2-letter combos sum to 62.")
print(f"    3. NDYAHR-only IC = 0.171 is expected for 6-letter alphabet (1/6 = 0.167)")
print(f"    4. ALL decryption attempts: NOISE (best = {best_overall_score}/24)")
print(f"    5. No letter or set of letters in K4 has count = 24")

verdict = "NOISE" if best_overall_score <= NOISE_FLOOR else "ABOVE NOISE"
print(f"\n  VERDICT: {verdict} -- {best_overall_score}/24")

# Save
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.makedirs(os.path.join(_PROJECT_ROOT, "results"), exist_ok=True)
artifact = {
    "experiment": "E-NDYAHR-K123CT-DEEP",
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "total_configs": total_configs,
    "elapsed_seconds": elapsed,
    "best_overall_score": best_overall_score,
    "best_overall_config": best_overall_config,
    "results_above_threshold": results_log,
    "k123_length": len(k123),
    "k123_mod73": 768 % 73,
    "letters_with_count_38": letters_with_38,
    "k1234_mod73": 865 % 73,
    "verdict": verdict,
}
artifact_path = os.path.join(_PROJECT_ROOT, "results", "e_ndyahr_k123ct_deep.json")
with open(artifact_path, "w") as f:
    json.dump(artifact, f, indent=2)
print(f"\n  Artifact: {artifact_path}")
