#!/usr/bin/env python3
"""
VIC Cipher with K2 Coordinate Digits as Direct Line-H.

Cipher:  VIC cipher (Line-H direct input + full key generation + double transposition)
Family:  analysis
Status:  active
Keyspace: ~29 Line-H candidates x 10 personal numbers x 6 top-row configs x 15 prefix pairs x 3 digit maps = ~230K+ configs
Last run: never
Best score: N/A

HYPOTHESIS: K2 coordinate digits 3,8,5,7,6,5,7,7,8,4,4 ARE VIC cipher's Line-H
directly. Sanborn embedded the master key in K2's plaintext. No phrase/date
derivation needed -- Line-H is the starting point for the full VIC key schedule.

WHAT IS NEW vs prior VIC work:
- e_full_vic_pipeline_k4.py tested full VIC with phrase+date+PN -> Line-H (1.8M configs).
  It derives Line-H from thematic phrases/dates, never uses K2 digits as Line-H directly.
- e_k2_checkerboard_decode.py tested K2 digits as checkerboard configuration (9.2M configs).
  It does NOT run the VIC key derivation from Line-H.
- e_vic_ndyar_keygroup.py tested NDYAHR as VIC keygroup (1.7M configs).
  Different VIC entry point (keygroup, not Line-H).

THIS SCRIPT:
1. Takes K2 digit arrangements as Line-H directly (bypassing phrase/date/PN)
2. Sequences Line-H -> Line-J
3. Chain-adds Line-H -> 50-digit block (Lines K through P)
4. Extracts transposition keys (Line-Q, Line-R) via Line-J column readoff
5. Derives checkerboard key (Line-S = sequencing of Line-P)
6. Builds straddling checkerboard
7. Tests full VIC decrypt (double transposition + checkerboard)
8. Also tests single-transposition variants
9. Also tests direct checkerboard-only (no transposition)
"""

import sys
import os
import json
import time
import math
from pathlib import Path
from collections import Counter
from itertools import combinations

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ========================================================================
# VIC KEY DERIVATION (from Line-H forward -- no phrase/date needed)
# ========================================================================

def sequence_digits(digits):
    """Sequence (rank) digits: numerical order (0=10 for sorting), ties left-to-right.
    Returns list of ranks 1..N. For N<=10, rank 10 becomes 0 (VIC convention).
    For N>10, ranks stay as-is (1..N)."""
    n = len(digits)
    indexed = [(d if d != 0 else 10, i) for i, d in enumerate(digits)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * n
    for rank_idx, (_, orig_pos) in enumerate(ranked):
        rank = rank_idx + 1  # 1-indexed
        if n <= 10:
            result[orig_pos] = rank % 10  # VIC convention: 10 -> 0
        else:
            result[orig_pos] = rank
    return result


def key_to_col_order(key):
    """Convert a sequenced key to column reading order.
    Returns list of column indices in the order they should be read.
    Works for any key length and value range."""
    return sorted(range(len(key)), key=lambda c: key[c])


def chain_add(digits, target_len):
    """Chain addition: repeatedly false-add consecutive pairs until target length."""
    result = list(digits)
    while len(result) < target_len:
        new_digit = (result[-2] + result[-1]) % 10
        result.append(new_digit)
    return result[:target_len]


def vic_keys_from_lineh(line_h, personal_number):
    """Complete VIC key generation starting from Line-H directly.

    Args:
        line_h: list of 10 digits (the core key)
        personal_number: integer 0-9

    Returns dict with all derived keys, or None if generation fails.
    """
    if len(line_h) != 10:
        return None

    # Step 1: Line-J = Sequencing of Line-H
    line_j = sequence_digits(line_h)

    # Step 2: Chain-add Line-H to produce 50 additional digits (Lines K-P)
    chain_60 = chain_add(line_h, 60)
    line_k = chain_60[10:20]
    line_l = chain_60[20:30]
    line_m = chain_60[30:40]
    line_n = chain_60[40:50]
    line_p = chain_60[50:60]

    # Step 3: Determine transposition key lengths from Line-P
    last_two_neq = []
    for d in reversed(line_p):
        if len(last_two_neq) == 0:
            last_two_neq.append(d)
        elif d != last_two_neq[0]:
            last_two_neq.insert(0, d)
            break

    if len(last_two_neq) < 2:
        last_two_neq = [line_p[-2], line_p[-1]]

    raw_a = last_two_neq[0] if last_two_neq[0] != 0 else 10
    raw_b = last_two_neq[1] if last_two_neq[1] != 0 else 10
    a = raw_a + personal_number
    b = raw_b + personal_number

    if a < 2 or a > 30 or b < 2 or b > 30:
        return None

    # Step 4: Line-Q and Line-R (transposition keys)
    kp_block = [line_k, line_l, line_m, line_n, line_p]

    # Read columns of KP block in Line-J order
    col_order_j = key_to_col_order(line_j)
    transposed_digits = []
    for ci in col_order_j:
        for row in range(5):
            transposed_digits.append(kp_block[row][ci])

    if a + b > len(transposed_digits):
        return None

    line_q = transposed_digits[:a]
    line_r = transposed_digits[a:a + b]

    # Step 5: Line-S = Sequencing of Line-P (checkerboard key)
    line_s = sequence_digits(line_p)

    return {
        'line_h': line_h,
        'line_j': line_j,
        'line_k': line_k,
        'line_l': line_l,
        'line_m': line_m,
        'line_n': line_n,
        'line_p': line_p,
        'a': a,
        'b': b,
        'trans1_key': sequence_digits(line_q),
        'trans2_key': sequence_digits(line_r),
        'line_q_raw': line_q,
        'line_r_raw': line_r,
        'line_s': line_s,
        'checkerboard_key': line_s,
        'personal_number': personal_number,
    }


# ========================================================================
# STRADDLING CHECKERBOARD
# ========================================================================

def build_checkerboard_with_prefixes(line_s, top_row_letters, prefix_cols):
    """Build checkerboard with specific prefix column positions.

    Args:
        line_s: list of 10 digits (column labels, sequenced)
        top_row_letters: 8 letters for top row (1-digit codes)
        prefix_cols: tuple of 2 column indices (0-9) that are blank in top row

    Returns:
        encode_table: dict letter -> digit string
        decode_table: dict digit string -> letter
        prefix_digits: set of prefix digit strings
    """
    top_row_letters = top_row_letters.upper()
    remaining = [c for c in ALPH if c not in top_row_letters]
    if len(remaining) != 18:
        return None, None, None

    row2 = remaining[:10]
    row3 = remaining[10:18]

    p1, p2 = prefix_cols

    encode_table = {}
    decode_table = {}

    # Top row: assign 8 letters to the 8 non-prefix columns
    top_col_idx = 0
    for col in range(10):
        if col in (p1, p2):
            continue
        label = str(line_s[col] % 10)
        letter = top_row_letters[top_col_idx]
        encode_table[letter] = label
        decode_table[label] = letter
        top_col_idx += 1

    # Row 2 (prefix = label of p1 column): 10 letters
    prefix1_label = str(line_s[p1] % 10)
    for col in range(10):
        label = prefix1_label + str(line_s[col] % 10)
        letter = row2[col]
        encode_table[letter] = label
        decode_table[label] = letter

    # Row 3 (prefix = label of p2 column): 8 letters
    prefix2_label = str(line_s[p2] % 10)
    col_idx = 0
    for col in range(10):
        if col_idx >= len(row3):
            break
        label = prefix2_label + str(line_s[col] % 10)
        letter = row3[col_idx]
        encode_table[letter] = label
        decode_table[label] = letter
        col_idx += 1

    prefix_digits = {prefix1_label, prefix2_label}
    return encode_table, decode_table, prefix_digits


def checkerboard_decode(digit_string, decode_table, prefix_digits):
    """Decode digit string -> plaintext using checkerboard."""
    result = []
    i = 0
    while i < len(digit_string):
        if digit_string[i] in prefix_digits:
            if i + 1 < len(digit_string):
                code = digit_string[i:i+2]
                if code in decode_table:
                    result.append(decode_table[code])
                else:
                    result.append('?')
                i += 2
            else:
                result.append('?')
                i += 1
        else:
            code = digit_string[i]
            if code in decode_table:
                result.append(decode_table[code])
            else:
                result.append('?')
            i += 1
    return ''.join(result)


def checkerboard_encode(plaintext, encode_table):
    """Encode plaintext -> digit string using checkerboard."""
    digits = []
    for ch in plaintext.upper():
        if ch in encode_table:
            digits.append(encode_table[ch])
    return ''.join(digits)


# ========================================================================
# TRANSPOSITIONS (using key_to_col_order for arbitrary key lengths)
# ========================================================================

def columnar_encrypt(text, key):
    """Standard columnar transposition encryption."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)

    grid = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(width):
            if idx < n:
                row.append(text[idx])
                idx += 1
            else:
                row.append(None)
        grid.append(row)

    col_order = key_to_col_order(key)
    result = []
    for col in col_order:
        for r in range(nrows):
            if grid[r][col] is not None:
                result.append(grid[r][col])

    if isinstance(text, str):
        return ''.join(result)
    return result


def columnar_decrypt(text, key):
    """Standard columnar transposition decryption (inverse)."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)
    short_cols = nrows * width - n

    # Determine column lengths (last short_cols columns are shorter)
    col_lens = {}
    for ci in range(width):
        if ci < width - short_cols:
            col_lens[ci] = nrows
        else:
            col_lens[ci] = nrows - 1

    col_order = key_to_col_order(key)
    cols = {}
    idx = 0
    for col in col_order:
        cl = col_lens[col]
        cols[col] = list(text[idx:idx + cl])
        idx += cl

    result = []
    for r in range(nrows):
        for c in range(width):
            if c in cols and r < len(cols[c]):
                result.append(cols[c][r])

    if isinstance(text, str):
        return ''.join(result)
    return result


def disrupted_diagonal_encrypt(text, key):
    """VIC-style disrupted diagonal transposition."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)

    grid = [[None] * width for _ in range(nrows)]

    # Find disruption column (column with highest key value)
    max_key_val = max(key)
    disrupt_col = None
    for ci in range(width):
        if key[ci] == max_key_val:
            disrupt_col = ci
            break

    # Phase 1: Fill triangle starting from disrupt_col
    idx = 0
    for row in range(nrows):
        end_col = min(disrupt_col + row + 1, width)
        for col in range(end_col):
            if idx < n:
                grid[row][col] = text[idx]
                idx += 1
        if end_col >= width:
            break

    # Phase 2: Fill remaining cells left-to-right, top-to-bottom
    for row in range(nrows):
        for col in range(width):
            if grid[row][col] is None and idx < n:
                grid[row][col] = text[idx]
                idx += 1

    # Read columns in key order
    col_order = key_to_col_order(key)
    result = []
    for col in col_order:
        for r in range(nrows):
            if grid[r][col] is not None:
                result.append(grid[r][col])

    if isinstance(text, str):
        return ''.join(result)
    return result


def disrupted_diagonal_decrypt(text, key):
    """Inverse of disrupted diagonal transposition."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)

    grid_filled = [[False] * width for _ in range(nrows)]

    max_key_val = max(key)
    disrupt_col = None
    for ci in range(width):
        if key[ci] == max_key_val:
            disrupt_col = ci
            break

    fill_order = []
    count = 0
    for row in range(nrows):
        end_col = min(disrupt_col + row + 1, width)
        for col in range(end_col):
            if count < n:
                grid_filled[row][col] = True
                fill_order.append((row, col))
                count += 1
        if end_col >= width:
            break

    for row in range(nrows):
        for col in range(width):
            if not grid_filled[row][col] and count < n:
                grid_filled[row][col] = True
                fill_order.append((row, col))
                count += 1

    col_counts = [0] * width
    for r in range(nrows):
        for c in range(width):
            if grid_filled[r][c]:
                col_counts[c] += 1

    col_order = key_to_col_order(key)
    cols = {}
    idx = 0
    for col in col_order:
        cl = col_counts[col]
        cols[col] = list(text[idx:idx + cl])
        idx += cl

    grid = [[None] * width for _ in range(nrows)]
    col_read_idx = [0] * width
    for r in range(nrows):
        for c in range(width):
            if grid_filled[r][c] and c in cols and col_read_idx[c] < len(cols[c]):
                grid[r][c] = cols[c][col_read_idx[c]]
                col_read_idx[c] += 1

    result = []
    for r, c in fill_order:
        if grid[r][c] is not None:
            result.append(grid[r][c])

    if isinstance(text, str):
        return ''.join(result)
    return result


# ========================================================================
# SCORING
# ========================================================================

QUADGRAMS = {}
QG_FLOOR = -10.0


def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qpath = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
    if qpath.exists():
        with open(qpath) as f:
            QUADGRAMS = json.load(f)
        QG_FLOOR = min(QUADGRAMS.values()) - 1.0
    else:
        print(f"WARNING: quadgrams not found at {qpath}")


def qg_score(text):
    """Quadgram score per character."""
    if len(text) < 4:
        return QG_FLOOR
    total = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        total += QUADGRAMS.get(qg, QG_FLOOR)
    return total / (len(text) - 3)


def score_result(plaintext):
    """Score a decryption result. Returns dict with scores."""
    pt = plaintext.upper().replace('?', '')

    # Fixed position crib check (0-indexed)
    fixed_score = 0
    ene_fixed = 0
    bc_fixed = 0
    if len(pt) >= 34:
        for i, ch in enumerate("EASTNORTHEAST"):
            if 21 + i < len(pt) and pt[21 + i] == ch:
                fixed_score += 1
                ene_fixed += 1
    if len(pt) >= 74:
        for i, ch in enumerate("BERLINCLOCK"):
            if 63 + i < len(pt) and pt[63 + i] == ch:
                fixed_score += 1
                bc_fixed += 1

    # Free crib search
    ene_pos = pt.find("EASTNORTHEAST")
    bc_pos = pt.find("BERLINCLOCK")

    # Partial crib matches
    best_ene_partial = 0
    for start in range(max(0, len(pt) - 4)):
        for length in range(5, min(14, len(pt) - start + 1)):
            sub = pt[start:start + length]
            if sub in "EASTNORTHEAST" and len(sub) > best_ene_partial:
                best_ene_partial = len(sub)

    best_bc_partial = 0
    for start in range(max(0, len(pt) - 4)):
        for length in range(5, min(12, len(pt) - start + 1)):
            sub = pt[start:start + length]
            if sub in "BERLINCLOCK" and len(sub) > best_bc_partial:
                best_bc_partial = len(sub)

    qg = qg_score(pt) if QUADGRAMS else -99.0

    free_score = 0
    if ene_pos >= 0:
        free_score += 13
    if bc_pos >= 0:
        free_score += 11

    return {
        'fixed_score': fixed_score,
        'ene_fixed': ene_fixed,
        'bc_fixed': bc_fixed,
        'free_score': free_score,
        'ene_pos': ene_pos,
        'bc_pos': bc_pos,
        'ene_partial': best_ene_partial,
        'bc_partial': best_bc_partial,
        'qg_per_char': qg,
        'pt_length': len(pt),
    }


# ========================================================================
# CT-TO-DIGIT MAPPINGS
# ========================================================================

def ct_to_digits_az_mod10(ct_text):
    return [ALPH_IDX[c] % 10 for c in ct_text]

def ct_to_digits_ka_mod10(ct_text):
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    return [ka_idx[c] % 10 for c in ct_text]

def ct_to_digits_az_plus1_mod10(ct_text):
    return [(ALPH_IDX[c] + 1) % 10 for c in ct_text]

DIGIT_MAPPINGS = [
    ("AZ_mod10", ct_to_digits_az_mod10),
    ("KA_mod10", ct_to_digits_ka_mod10),
    ("AZ_plus1_mod10", ct_to_digits_az_plus1_mod10),
]


# ========================================================================
# LINE-H CANDIDATES
# ========================================================================

K2_ALL_DIGITS = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

# Named candidates from the hypothesis
NAMED_LINEH_CANDIDATES = [
    ("first10_drop_last4", [3, 8, 5, 7, 6, 5, 7, 7, 8, 4]),
    ("drop_first3", [8, 5, 7, 6, 5, 7, 7, 8, 4, 4]),
    ("dedup_77", [3, 8, 5, 7, 6, 5, 7, 8, 4, 4]),
    ("dedup_44", [3, 8, 5, 7, 6, 5, 7, 7, 4, 8]),
    ("treat_65_as_6", [3, 8, 5, 6, 5, 7, 7, 8, 4, 4]),
    ("sep_65_0", [3, 8, 5, 7, 6, 5, 0, 7, 8, 4]),
    ("rotate_left2", [5, 7, 6, 5, 7, 7, 8, 4, 4, 3]),
    ("lon_first_778443857", [7, 7, 8, 4, 4, 3, 8, 5, 7, 6]),
    ("lon_first_v2", [7, 7, 8, 8, 4, 4, 3, 8, 5, 7]),
    ("decimal_degrees", [3, 8, 5, 7, 0, 6, 5, 7, 7, 8]),
    ("k2_plus_seq", [3, 8, 5, 7, 6, 5, 4, 0, 1, 2]),
    ("prepend_0", [0, 3, 8, 5, 7, 6, 5, 7, 7, 8]),
]

# All 11-choose-10: drop each digit one at a time
DROP_ONE_CANDIDATES = []
for drop_idx in range(11):
    candidate = K2_ALL_DIGITS[:drop_idx] + K2_ALL_DIGITS[drop_idx + 1:]
    label = f"drop_pos{drop_idx}_val{K2_ALL_DIGITS[drop_idx]}"
    DROP_ONE_CANDIDATES.append((label, candidate))

# Rotations of the 11 digits, taking first 10
ROTATION_CANDIDATES = []
for rot in range(11):
    rotated = K2_ALL_DIGITS[rot:] + K2_ALL_DIGITS[:rot]
    candidate = rotated[:10]
    label = f"rotate_{rot}"
    ROTATION_CANDIDATES.append((label, candidate))

# Additional creative candidates
EXTRA_CANDIDATES = [
    ("reversed", list(reversed(K2_ALL_DIGITS[:10]))),
    ("lat_lon_interleave", [3, 7, 8, 7, 5, 8, 7, 4, 6, 4]),
    ("all_unique_padded", [3, 8, 5, 7, 6, 4, 0, 1, 2, 9]),
    ("K2_sequenced", sequence_digits(K2_ALL_DIGITS[:10])),
    ("sum_pairs", [(3+8)%10, (5+7)%10, (6+5)%10, (7+7)%10, (8+4)%10, (4+3)%10, (8+5)%10, (7+6)%10, (5+7)%10, (7+8)%10]),
]

ALL_LINEH_CANDIDATES = NAMED_LINEH_CANDIDATES + DROP_ONE_CANDIDATES + ROTATION_CANDIDATES + EXTRA_CANDIDATES

# Deduplicate
seen_keys = set()
UNIQUE_CANDIDATES = []
for label, digits in ALL_LINEH_CANDIDATES:
    key = tuple(digits)
    if key not in seen_keys:
        seen_keys.add(key)
        UNIQUE_CANDIDATES.append((label, digits))

PERSONAL_NUMBERS = [5, 4, 6, 7, 0, 3, 2, 1, 8, 9]

TOP_ROW_CONFIGS = [
    ("ASINTOER", "ASINTOER"),
    ("ATONESIR", "ATONESIR"),
    ("ETAOINSH", "ETAOINSH"),
    ("KRYPTOSA", "KRYPTOSA"),
    ("SENORITA", "SENORITA"),
    ("ETAOIRNS", "ETAOIRNS"),
]

PREFIX_PAIRS = [
    (0, 1), (0, 5), (1, 2), (2, 7), (3, 7),
    (0, 9), (1, 8), (4, 9), (3, 8), (2, 6),
    (0, 3), (0, 8), (1, 5), (5, 8), (3, 9),
]


# ========================================================================
# DECRYPT PIPELINES
# ========================================================================

def vic_decrypt_full(ct_digit_str, trans1_key, trans2_key, decode_table, prefix_digits):
    """Full VIC decryption: undo trans2 -> undo trans1 -> checkerboard decode."""
    after_trans2 = disrupted_diagonal_decrypt(ct_digit_str, trans2_key)
    after_trans1 = columnar_decrypt(after_trans2, trans1_key)
    if isinstance(after_trans1, list):
        digit_str = ''.join(str(d) for d in after_trans1)
    else:
        digit_str = after_trans1
    return checkerboard_decode(digit_str, decode_table, prefix_digits)


def vic_decrypt_single_trans(ct_digit_str, trans_key, decode_table, prefix_digits, use_disrupted=False):
    """Simplified VIC with single transposition only."""
    if use_disrupted:
        after_trans = disrupted_diagonal_decrypt(ct_digit_str, trans_key)
    else:
        after_trans = columnar_decrypt(ct_digit_str, trans_key)
    if isinstance(after_trans, list):
        digit_str = ''.join(str(d) for d in after_trans)
    else:
        digit_str = after_trans
    return checkerboard_decode(digit_str, decode_table, prefix_digits)


def vic_decrypt_cb_only(ct_digit_str, decode_table, prefix_digits):
    """Checkerboard-only (no transposition)."""
    return checkerboard_decode(ct_digit_str, decode_table, prefix_digits)


# ========================================================================
# VERIFICATION
# ========================================================================

def verify_pipeline():
    """Verify the full VIC pipeline with a known test case."""
    print("PIPELINE VERIFICATION")
    print("-" * 40)

    test_lineh = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3]
    test_pn = 5
    keys = vic_keys_from_lineh(test_lineh, test_pn)
    if keys is None:
        print("  FAIL: Key generation returned None")
        return False

    a = keys['a']
    b = keys['b']
    print(f"  Line-H: {test_lineh}")
    print(f"  Line-J: {keys['line_j']}")
    print(f"  Line-P: {keys['line_p']}")
    print(f"  Line-S: {keys['line_s']}")
    print(f"  a={a}, b={b}")
    print(f"  Trans1 key: {keys['trans1_key']} (len={len(keys['trans1_key'])})")
    print(f"  Trans2 key: {keys['trans2_key']} (len={len(keys['trans2_key'])})")

    # Verify sequencing produces unique values
    t1_unique = len(set(keys['trans1_key'])) == len(keys['trans1_key'])
    t2_unique = len(set(keys['trans2_key'])) == len(keys['trans2_key'])
    print(f"  Trans1 key unique: {t1_unique}")
    print(f"  Trans2 key unique: {t2_unique}")
    if not t1_unique or not t2_unique:
        print("  FAIL: Non-unique transposition keys")
        return False

    enc_table, dec_table, prefix_d = build_checkerboard_with_prefixes(
        keys['checkerboard_key'], "ETAOINSH", (0, 5)
    )
    if enc_table is None:
        print("  FAIL: Checkerboard build failed")
        return False

    # Round-trip: encode -> trans1 -> trans2 -> decrypt
    test_pt = "THISISATESTMESSAGEFORKRYPTOS"
    step1 = checkerboard_encode(test_pt, enc_table)
    step2 = columnar_encrypt(step1, keys['trans1_key'])
    step3 = disrupted_diagonal_encrypt(step2, keys['trans2_key'])
    result = vic_decrypt_full(step3, keys['trans1_key'], keys['trans2_key'], dec_table, prefix_d)

    ok = result == test_pt
    print(f"  Full pipeline round-trip: {'PASS' if ok else 'FAIL'}")
    if not ok:
        print(f"    Expected: {test_pt}")
        print(f"    Got:      {result}")

    # Also test columnar-only round-trip
    step2b = columnar_encrypt(step1, keys['trans1_key'])
    step3b = columnar_decrypt(step2b, keys['trans1_key'])
    col_ok = step3b == step1
    print(f"  Columnar round-trip: {'PASS' if col_ok else 'FAIL'}")

    # Disrupted diagonal round-trip
    step2c = disrupted_diagonal_encrypt(step1, keys['trans2_key'])
    step3c = disrupted_diagonal_decrypt(step2c, keys['trans2_key'])
    disr_ok = step3c == step1
    print(f"  Disrupted diagonal round-trip: {'PASS' if disr_ok else 'FAIL'}")

    print()
    return ok and col_ok and disr_ok


# ========================================================================
# MAIN
# ========================================================================

def run():
    t0 = time.time()

    print("=" * 72)
    print("VIC CIPHER: K2 COORDINATE DIGITS AS DIRECT LINE-H")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"K2 digits: {K2_ALL_DIGITS}")
    print(f"Line-H candidates: {len(UNIQUE_CANDIDATES)} (after dedup)")
    print(f"Personal numbers: {len(PERSONAL_NUMBERS)}")
    print(f"Top-row configs: {len(TOP_ROW_CONFIGS)}")
    print(f"Prefix pairs: {len(PREFIX_PAIRS)}")
    print(f"Digit mappings: {len(DIGIT_MAPPINGS)}")
    print()

    load_quadgrams()
    print(f"Loaded {len(QUADGRAMS)} quadgrams")
    print()

    if not verify_pipeline():
        print("ABORTING: Pipeline verification failed!")
        return

    all_results = []
    top_results = []
    configs_tested = 0
    keys_generated = 0
    keys_failed = 0

    # ─── Phase 1: Full VIC (double transposition) ──────────────────
    print("=" * 72)
    print("PHASE 1: Full VIC decrypt (double transposition + checkerboard)")
    print("=" * 72)

    p1_start = time.time()
    p1_configs = 0
    p1_keys = 0

    for lh_name, line_h in UNIQUE_CANDIDATES:
        for pn in PERSONAL_NUMBERS:
            keys = vic_keys_from_lineh(line_h, pn)
            if keys is None:
                keys_failed += 1
                continue
            keys_generated += 1
            p1_keys += 1

            a = keys['a']
            b = keys['b']
            trans1_key = keys['trans1_key']
            trans2_key = keys['trans2_key']
            cb_key = keys['checkerboard_key']

            if len(trans1_key) < 3 or len(trans1_key) > 25:
                continue
            if len(trans2_key) < 3 or len(trans2_key) > 25:
                continue

            # Verify key uniqueness
            if len(set(trans1_key)) != len(trans1_key):
                continue
            if len(set(trans2_key)) != len(trans2_key):
                continue

            for tr_name, top_row in TOP_ROW_CONFIGS:
                for p1_col, p2_col in PREFIX_PAIRS:
                    enc_table, dec_table, prefix_d = build_checkerboard_with_prefixes(
                        cb_key, top_row, (p1_col, p2_col)
                    )
                    if enc_table is None or dec_table is None:
                        continue

                    for dm_name, dm_fn in DIGIT_MAPPINGS:
                        ct_digits = dm_fn(CT)
                        ct_digit_str = ''.join(str(d) for d in ct_digits)

                        configs_tested += 1
                        p1_configs += 1

                        try:
                            pt = vic_decrypt_full(
                                ct_digit_str, trans1_key, trans2_key,
                                dec_table, prefix_d
                            )
                        except Exception:
                            continue

                        scores = score_result(pt)
                        total = scores['fixed_score'] + scores['free_score']

                        if scores['fixed_score'] >= 8 or scores['free_score'] >= 10 or \
                           scores['ene_partial'] >= 8 or scores['bc_partial'] >= 7:
                            result = {
                                'phase': 'full_vic',
                                'lineh_name': lh_name,
                                'lineh': line_h,
                                'pn': pn,
                                'a': a, 'b': b,
                                'top_row': tr_name,
                                'prefix_cols': [p1_col, p2_col],
                                'digit_map': dm_name,
                                'pt': pt[:80],
                                **scores,
                            }
                            all_results.append(result)
                            print(f"  HIT: {lh_name} pn={pn} {tr_name} ({p1_col},{p2_col}) {dm_name} "
                                  f"fixed={scores['fixed_score']} free={scores['free_score']} "
                                  f"ene_partial={scores['ene_partial']} bc_partial={scores['bc_partial']}")

                        entry = (total, scores['qg_per_char'], {
                            'phase': 'full_vic',
                            'lineh_name': lh_name,
                            'pn': pn, 'a': a, 'b': b,
                            'top_row': tr_name,
                            'prefix_cols': [p1_col, p2_col],
                            'digit_map': dm_name,
                            'pt': pt[:60],
                            **scores,
                        })
                        if len(top_results) < 20 or total > top_results[-1][0] or \
                           (total == top_results[-1][0] and scores['qg_per_char'] > top_results[-1][1]):
                            top_results.append(entry)
                            top_results.sort(key=lambda x: (x[0], x[1]), reverse=True)
                            top_results = top_results[:20]

            if p1_configs % 10000 == 0 and p1_configs > 0:
                elapsed = time.time() - p1_start
                print(f"  Phase 1: {p1_configs:,} configs, {p1_keys} keys, "
                      f"{len(all_results)} hits, {elapsed:.0f}s", flush=True)

    phase1_time = time.time() - p1_start
    print(f"\nPhase 1 complete: {p1_configs:,} configs, {p1_keys} keys, "
          f"{keys_failed} failed, {len(all_results)} hits, {phase1_time:.0f}s")

    # ─── Phase 2: Single transposition variants ──────────────────
    print()
    print("=" * 72)
    print("PHASE 2: Single transposition (columnar only, then disrupted only)")
    print("=" * 72)

    p2_start = time.time()
    p2_configs = 0

    for lh_name, line_h in UNIQUE_CANDIDATES:
        for pn in PERSONAL_NUMBERS:
            keys = vic_keys_from_lineh(line_h, pn)
            if keys is None:
                continue

            a = keys['a']
            b = keys['b']
            cb_key = keys['checkerboard_key']

            for trans_label, trans_key, use_disrupted in [
                (f"col_a{a}", keys['trans1_key'], False),
                (f"col_b{b}", keys['trans2_key'], False),
                (f"disr_a{a}", keys['trans1_key'], True),
                (f"disr_b{b}", keys['trans2_key'], True),
            ]:
                if len(trans_key) < 3 or len(trans_key) > 25:
                    continue
                if len(set(trans_key)) != len(trans_key):
                    continue

                for tr_name, top_row in TOP_ROW_CONFIGS:
                    for p1_col, p2_col in PREFIX_PAIRS:
                        enc_table, dec_table, prefix_d = build_checkerboard_with_prefixes(
                            cb_key, top_row, (p1_col, p2_col)
                        )
                        if enc_table is None or dec_table is None:
                            continue

                        for dm_name, dm_fn in DIGIT_MAPPINGS:
                            ct_digits = dm_fn(CT)
                            ct_digit_str = ''.join(str(d) for d in ct_digits)

                            configs_tested += 1
                            p2_configs += 1

                            try:
                                pt = vic_decrypt_single_trans(
                                    ct_digit_str, trans_key, dec_table,
                                    prefix_d, use_disrupted
                                )
                            except Exception:
                                continue

                            scores = score_result(pt)
                            total = scores['fixed_score'] + scores['free_score']

                            if scores['fixed_score'] >= 8 or scores['free_score'] >= 10 or \
                               scores['ene_partial'] >= 8 or scores['bc_partial'] >= 7:
                                result = {
                                    'phase': 'single_trans',
                                    'trans': trans_label,
                                    'lineh_name': lh_name,
                                    'pn': pn,
                                    'top_row': tr_name,
                                    'prefix_cols': [p1_col, p2_col],
                                    'digit_map': dm_name,
                                    'pt': pt[:80],
                                    **scores,
                                }
                                all_results.append(result)
                                print(f"  HIT: {lh_name} pn={pn} {trans_label} {tr_name} "
                                      f"fixed={scores['fixed_score']} free={scores['free_score']}")

                            entry = (total, scores['qg_per_char'], {
                                'phase': 'single_trans',
                                'trans': trans_label,
                                'lineh_name': lh_name,
                                'pn': pn,
                                'top_row': tr_name,
                                'digit_map': dm_name,
                                'pt': pt[:60],
                                **scores,
                            })
                            if len(top_results) < 20 or total > top_results[-1][0]:
                                top_results.append(entry)
                                top_results.sort(key=lambda x: (x[0], x[1]), reverse=True)
                                top_results = top_results[:20]

        if p2_configs % 20000 == 0 and p2_configs > 0:
            elapsed = time.time() - p2_start
            print(f"  Phase 2: {p2_configs:,} configs, {elapsed:.0f}s", flush=True)

    phase2_time = time.time() - p2_start
    print(f"\nPhase 2 complete: {p2_configs:,} configs, {phase2_time:.0f}s")

    # ─── Phase 3: Checkerboard only (no transposition) ────────────
    print()
    print("=" * 72)
    print("PHASE 3: Checkerboard decode only (no transposition)")
    print("=" * 72)

    p3_start = time.time()
    p3_configs = 0

    for lh_name, line_h in UNIQUE_CANDIDATES:
        for pn in PERSONAL_NUMBERS:
            keys = vic_keys_from_lineh(line_h, pn)
            if keys is None:
                continue

            cb_key = keys['checkerboard_key']

            for tr_name, top_row in TOP_ROW_CONFIGS:
                for p1_col, p2_col in PREFIX_PAIRS:
                    enc_table, dec_table, prefix_d = build_checkerboard_with_prefixes(
                        cb_key, top_row, (p1_col, p2_col)
                    )
                    if enc_table is None or dec_table is None:
                        continue

                    for dm_name, dm_fn in DIGIT_MAPPINGS:
                        ct_digits = dm_fn(CT)
                        ct_digit_str = ''.join(str(d) for d in ct_digits)

                        configs_tested += 1
                        p3_configs += 1

                        try:
                            pt = vic_decrypt_cb_only(ct_digit_str, dec_table, prefix_d)
                        except Exception:
                            continue

                        scores = score_result(pt)
                        total = scores['fixed_score'] + scores['free_score']

                        if scores['fixed_score'] >= 8 or scores['free_score'] >= 10 or \
                           scores['ene_partial'] >= 8 or scores['bc_partial'] >= 7:
                            result = {
                                'phase': 'cb_only',
                                'lineh_name': lh_name,
                                'pn': pn,
                                'top_row': tr_name,
                                'prefix_cols': [p1_col, p2_col],
                                'digit_map': dm_name,
                                'pt': pt[:80],
                                **scores,
                            }
                            all_results.append(result)
                            print(f"  HIT: {lh_name} {tr_name} {dm_name} "
                                  f"fixed={scores['fixed_score']} free={scores['free_score']}")

                        entry = (total, scores['qg_per_char'], {
                            'phase': 'cb_only',
                            'lineh_name': lh_name,
                            'pn': pn,
                            'top_row': tr_name,
                            'digit_map': dm_name,
                            'pt': pt[:60],
                            **scores,
                        })
                        if len(top_results) < 20 or total > top_results[-1][0]:
                            top_results.append(entry)
                            top_results.sort(key=lambda x: (x[0], x[1]), reverse=True)
                            top_results = top_results[:20]

    phase3_time = time.time() - p3_start
    print(f"\nPhase 3 complete: {p3_configs:,} configs, {phase3_time:.0f}s")

    # ─── Phase 4: Direct CB parsing (CT letters as digit codes) ───
    print()
    print("=" * 72)
    print("PHASE 4: Direct checkerboard parsing (CT97 as digit stream via encode table)")
    print("=" * 72)

    p4_start = time.time()
    p4_configs = 0

    for lh_name, line_h in UNIQUE_CANDIDATES:
        for pn in PERSONAL_NUMBERS:
            keys = vic_keys_from_lineh(line_h, pn)
            if keys is None:
                continue

            cb_key = keys['checkerboard_key']
            trans1_key = keys['trans1_key']
            trans2_key = keys['trans2_key']

            t1_ok = len(trans1_key) >= 3 and len(trans1_key) <= 25 and len(set(trans1_key)) == len(trans1_key)
            t2_ok = len(trans2_key) >= 3 and len(trans2_key) <= 25 and len(set(trans2_key)) == len(trans2_key)

            for tr_name, top_row in TOP_ROW_CONFIGS:
                for p1_col, p2_col in PREFIX_PAIRS[:5]:
                    enc_table, dec_table, prefix_d = build_checkerboard_with_prefixes(
                        cb_key, top_row, (p1_col, p2_col)
                    )
                    if enc_table is None or dec_table is None:
                        continue

                    # Convert CT97 letters to digits using the encode table
                    ct_as_encoded = checkerboard_encode(CT, enc_table)

                    configs_tested += 1
                    p4_configs += 1

                    if t1_ok and t2_ok:
                        try:
                            pt_full = vic_decrypt_full(
                                ct_as_encoded, trans1_key, trans2_key,
                                dec_table, prefix_d
                            )
                            scores = score_result(pt_full)
                            total = scores['fixed_score'] + scores['free_score']

                            if scores['fixed_score'] >= 8 or scores['free_score'] >= 10:
                                result = {
                                    'phase': 'direct_cb_parse',
                                    'lineh_name': lh_name,
                                    'pn': pn,
                                    'top_row': tr_name,
                                    'prefix_cols': [p1_col, p2_col],
                                    'pt': pt_full[:80],
                                    **scores,
                                }
                                all_results.append(result)
                                print(f"  HIT: direct_cb {lh_name} pn={pn} {tr_name} "
                                      f"fixed={scores['fixed_score']} free={scores['free_score']}")

                            entry = (total, scores['qg_per_char'], {
                                'phase': 'direct_cb_parse',
                                'lineh_name': lh_name,
                                'pn': pn,
                                'top_row': tr_name,
                                'pt': pt_full[:60],
                                **scores,
                            })
                            if len(top_results) < 20 or total > top_results[-1][0]:
                                top_results.append(entry)
                                top_results.sort(key=lambda x: (x[0], x[1]), reverse=True)
                                top_results = top_results[:20]
                        except Exception:
                            pass

    phase4_time = time.time() - p4_start
    print(f"\nPhase 4 complete: {p4_configs:,} configs, {phase4_time:.0f}s")

    # ═════════════════════════════════════════════════════════════════
    # KEY DUMP
    # ═════════════════════════════════════════════════════════════════
    print()
    print("=" * 72)
    print("KEY GENERATION DUMP: All Line-H candidates (pn=5)")
    print("=" * 72)

    key_dump = []
    for lh_name, line_h in UNIQUE_CANDIDATES:
        keys = vic_keys_from_lineh(line_h, 5)
        if keys is None:
            key_dump.append({'lineh_name': lh_name, 'lineh': line_h, 'status': 'FAILED'})
            continue
        key_dump.append({
            'lineh_name': lh_name,
            'lineh': line_h,
            'line_j': keys['line_j'],
            'line_p': keys['line_p'],
            'line_s': keys['line_s'],
            'a': keys['a'],
            'b': keys['b'],
            'trans1_key': keys['trans1_key'],
            'trans2_key': keys['trans2_key'],
        })
        print(f"  {lh_name}: H={line_h} -> J={keys['line_j']} P={keys['line_p']} "
              f"S={keys['line_s']} a={keys['a']} b={keys['b']}")

    # ═════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═════════════════════════════════════════════════════════════════
    total_elapsed = time.time() - t0

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configs tested: {configs_tested:,}")
    print(f"  Phase 1 (full VIC double trans): {p1_configs:,} ({phase1_time:.0f}s)")
    print(f"  Phase 2 (single trans): {p2_configs:,} ({phase2_time:.0f}s)")
    print(f"  Phase 3 (CB only): {p3_configs:,} ({phase3_time:.0f}s)")
    print(f"  Phase 4 (direct CB parse): {p4_configs:,} ({phase4_time:.0f}s)")
    print(f"Keys generated: {keys_generated:,}")
    print(f"Keys failed (a/b out of range): {keys_failed:,}")
    print(f"Total elapsed: {total_elapsed:.1f}s")
    print(f"Threshold hits: {len(all_results)}")
    print()

    max_fixed = 0
    max_free = 0
    max_total = 0
    if top_results:
        print("TOP 20 RESULTS (by total score, then quadgram):")
        print("-" * 72)
        for i, (total, qg, info) in enumerate(top_results):
            print(f"  #{i+1}: total={total} qg={qg:.3f} | {info.get('phase','')} "
                  f"lineh={info.get('lineh_name','')} pn={info.get('pn','')} "
                  f"fixed={info.get('fixed_score',0)} free={info.get('free_score',0)} "
                  f"| {info.get('pt','')[:50]}")
            if info.get('fixed_score', 0) > max_fixed:
                max_fixed = info['fixed_score']
            if info.get('free_score', 0) > max_free:
                max_free = info['free_score']
            if total > max_total:
                max_total = total

    if max_total >= 18:
        verdict = "SIGNAL"
    elif max_total >= 10 or max_fixed >= 8 or max_free >= 10:
        verdict = "INTERESTING"
    elif max_total >= 6:
        verdict = "WEAK INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\nMax fixed score: {max_fixed}/24")
    print(f"Max free score: {max_free}/24")
    print(f"Max total score: {max_total}")
    print(f"VERDICT: {verdict}")

    # Save results
    output = {
        'experiment': 'e_vic_lineh_k2_direct',
        'description': 'VIC cipher with K2 coordinate digits as direct Line-H',
        'hypothesis': 'K2 digits 3,8,5,7,6,5,7,7,8,4,4 ARE VIC Line-H directly',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'k2_digits': K2_ALL_DIGITS,
        'lineh_candidates_tested': len(UNIQUE_CANDIDATES),
        'personal_numbers_tested': PERSONAL_NUMBERS,
        'total_configs': configs_tested,
        'keys_generated': keys_generated,
        'keys_failed': keys_failed,
        'elapsed_seconds': total_elapsed,
        'phases': {
            'phase1_full_vic': {'configs': p1_configs, 'time': phase1_time},
            'phase2_single_trans': {'configs': p2_configs, 'time': phase2_time},
            'phase3_cb_only': {'configs': p3_configs, 'time': phase3_time},
            'phase4_direct_cb': {'configs': p4_configs, 'time': phase4_time},
        },
        'max_fixed_score': max_fixed,
        'max_free_score': max_free,
        'max_total_score': max_total,
        'verdict': verdict,
        'key_dump': key_dump,
        'top_20': [info for _, _, info in top_results],
        'threshold_hits': all_results,
    }

    results_dir = Path(__file__).resolve().parents[2] / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / "vic_lineh_k2_direct.json"
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    run()
