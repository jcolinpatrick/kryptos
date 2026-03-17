#!/usr/bin/env python3
"""
Full VIC Cipher Decryption Pipeline for K4.

Cipher:  VIC cipher (full key generation + straddling checkerboard + double transposition)
Family:  analysis
Status:  active
Keyspace: ~10 phrases x ~13 dates x ~9 personal_numbers x ~6 top-row configs = ~7,020 base + variants
Last run: never
Best score: N/A

WHAT IS NEW vs prior VIC work:
- e_vic_model.py tested LETTER-level prefix-set parsing + single columnar trans (130.7M configs).
  It did NOT implement VIC key generation or disrupted diagonal transposition.
- e_straddling_checkerboard_k4.py tested digit-level decode + digit permutations (36.5M configs).
  It did NOT implement the full VIC key generation or double transposition.
- e_vic_01_chain_addition.py tested chain addition from grille extract. Not the full VIC pipeline.

THIS SCRIPT implements:
1. COMPLETE VIC key generation (phrase + date + personal number -> all keys)
2. Straddling checkerboard encode/decode
3. Standard columnar transposition and its inverse
4. Disrupted diagonal transposition and its inverse
5. Keygroup insertion/extraction
6. Multiple CT-to-digit mappings for the letter->digit conversion problem
7. Forward direction tests (what if K4 IS the digit stream?)
8. Single-transposition variant (simplified VIC with only one transposition)
"""

import sys
import os
import json
import time
import math
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ========================================================================
# VIC KEY GENERATION — RANKING FUNCTIONS
# ========================================================================

def rank10(items, is_letters=False):
    """Rank 10 items VIC-style: returns list of digits 1-9 and 0 (where 0=10th rank).
    For letters: alphabetical order, ties left-to-right.
    For digits: numerical order (0 treated as 10), ties left-to-right.
    """
    assert len(items) == 10, f"rank10 requires exactly 10 items, got {len(items)}"
    if is_letters:
        indexed = [(items[i], i) for i in range(10)]
    else:
        # Digits: treat 0 as 10 for ordering
        indexed = [(items[i] if items[i] != 0 else 10, i) for i in range(10)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * 10
    for rank_idx, (_, orig_pos) in enumerate(ranked):
        result[orig_pos] = (rank_idx + 1) % 10  # rank 10 -> 0
    return result


def rank_n(items):
    """Rank N items for transposition key: returns list of integers 0..N-1.
    Items are digits; 0 treated as 10. Ties broken left-to-right.
    Result is 0-indexed (column 0 is read first, etc.)."""
    indexed = [(items[i] if items[i] != 0 else 10, i) for i in range(len(items))]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * len(items)
    for new_rank, (_, orig_pos) in enumerate(ranked):
        result[orig_pos] = new_rank
    return result


def mod10_subtract(a, b):
    """Digit-by-digit subtraction mod 10, no borrow."""
    return [(a[i] - b[i]) % 10 for i in range(len(a))]


def mod10_add(a, b):
    """Digit-by-digit addition mod 10, no carry."""
    return [(a[i] + b[i]) % 10 for i in range(min(len(a), len(b)))]


def chain_add(digits, target_len):
    """Chain addition: repeatedly false-add consecutive pairs until target length."""
    result = list(digits)
    while len(result) < target_len:
        new_digit = (result[-2] + result[-1]) % 10
        result.append(new_digit)
    return result[:target_len]


def generate_vic_keys(phrase, date_digits, personal_number):
    """Full VIC key generation. Returns base_keys dict or None."""
    if len(phrase) < 20:
        return None
    phrase = phrase.upper()[:20]

    line_d = phrase[:20]
    line_e1 = rank10(list(line_d[:10]), is_letters=True)
    line_e2 = rank10(list(line_d[10:20]), is_letters=True)
    line_b = list(date_digits[:5])

    return {
        'phrase': phrase,
        'date': date_digits,
        'personal_number': personal_number,
        'line_d': line_d,
        'line_e1': line_e1,
        'line_e2': line_e2,
        'line_b': line_b,
    }


def complete_vic_keys(base_keys, keygroup):
    """Complete VIC key generation with a specific keygroup. Returns dict or None."""
    line_a = list(keygroup)
    line_b = base_keys['line_b']
    line_e1 = base_keys['line_e1']
    line_e2 = base_keys['line_e2']
    pn = base_keys['personal_number']

    # Line-C = (Line-A - Line-B) mod 10
    line_c = mod10_subtract(line_a, line_b)

    # Line-F.1 = chain-add Line-C from 5 to 10 digits
    line_f1 = chain_add(line_c, 10)

    # Line-G = (Line-E.1 + Line-F.1) mod 10
    line_g = mod10_add(line_e1, line_f1)

    # Line-H: encode Line-G through Line-E.2
    # For each digit d in Line-G, replace with Line-E.2 at position (d-1) (0-indexed),
    # where d=0 means position 9.
    line_h = []
    for d in line_g:
        idx = (d - 1) % 10
        line_h.append(line_e2[idx])

    # Line-J = rank10 of Line-H
    line_j = rank10(line_h, is_letters=False)

    # Lines K-P: chain addition from Line-H for 50 more digits
    chain_60 = chain_add(line_h, 60)
    line_k = chain_60[10:20]
    line_l = chain_60[20:30]
    line_m = chain_60[30:40]
    line_n = chain_60[40:50]
    line_p = chain_60[50:60]

    # Determine a and b from Line-P's last two unequal digits + personal number
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
    a = raw_a + pn
    b = raw_b + pn

    if a < 3 or a > 25 or b < 3 or b > 25:
        return None

    # Transpose the 5x10 K-P block by Line-J column ordering
    kp_block = [line_k, line_l, line_m, line_n, line_p]

    # Read columns in Line-J rank order (1 first, then 2, ..., 0=10 last)
    col_order = []
    for rank in range(1, 11):
        target = rank % 10  # 10->0
        for ci in range(10):
            if line_j[ci] == target:
                col_order.append(ci)
                break

    transposed = []
    for ci in col_order:
        for row in range(5):
            transposed.append(kp_block[row][ci])

    if a + b > len(transposed):
        return None

    line_q_raw = transposed[:a]
    line_r_raw = transposed[a:a + b]

    # Trans keys: rank_n for arbitrary-length permutations (0-indexed)
    trans1_key = rank_n(line_q_raw)
    trans2_key = rank_n(line_r_raw)

    # Line-S = rank10 of Line-P (checkerboard column labels)
    line_s = rank10(line_p, is_letters=False)

    return {
        'a': a, 'b': b,
        'trans1_key': trans1_key,
        'trans2_key': trans2_key,
        'line_q_raw': line_q_raw,
        'line_r_raw': line_r_raw,
        'line_s': line_s,
        'line_h': line_h,
        'line_k': line_k,
        'line_p': line_p,
        'keygroup': keygroup,
    }


# ========================================================================
# STRADDLING CHECKERBOARD
# ========================================================================

def build_checkerboard(line_s, top_row_letters, prefix_cols):
    """Build straddling checkerboard.

    Args:
        line_s: list of 10 digits (VIC column labels from rank10)
        top_row_letters: 8 high-frequency letters
        prefix_cols: (p1, p2) column indices that are blank in top row

    Returns (encode_table, decode_table, prefix_digit_set) or (None, None, None)
    """
    top = top_row_letters.upper()
    remaining = [c for c in ALPH if c not in top]
    if len(remaining) != 18:
        return None, None, None

    row2 = remaining[:10]
    row3 = remaining[10:18]
    p1, p2 = prefix_cols

    encode = {}
    decode = {}

    # Top row: 8 letters in non-prefix columns
    letter_idx = 0
    for col in range(10):
        if col in (p1, p2):
            continue
        label = str(line_s[col] % 10)
        encode[top[letter_idx]] = label
        decode[label] = top[letter_idx]
        letter_idx += 1

    # Row 2 (prefix1): 10 letters
    pf1 = str(line_s[p1] % 10)
    for col in range(10):
        label = pf1 + str(line_s[col] % 10)
        encode[row2[col]] = label
        decode[label] = row2[col]

    # Row 3 (prefix2): 8 letters (+ 2 slots for digit/special, unused here)
    pf2 = str(line_s[p2] % 10)
    for idx, col in enumerate(range(10)):
        if idx >= len(row3):
            break
        label = pf2 + str(line_s[col] % 10)
        encode[row3[idx]] = label
        decode[label] = row3[idx]

    prefix_set = {pf1, pf2}
    return encode, decode, prefix_set


def cb_encode(plaintext, encode_table):
    """Encode plaintext to digit string via checkerboard."""
    return ''.join(encode_table.get(c, '') for c in plaintext.upper())


def cb_decode(digit_string, decode_table, prefix_set):
    """Decode digit string to plaintext via checkerboard."""
    result = []
    i = 0
    n = len(digit_string)
    while i < n:
        if digit_string[i] in prefix_set and i + 1 < n:
            code = digit_string[i:i + 2]
            result.append(decode_table.get(code, '?'))
            i += 2
        else:
            result.append(decode_table.get(digit_string[i], '?'))
            i += 1
    return ''.join(result)


# ========================================================================
# TRANSPOSITION (0-indexed keys: key[i]=rank means column i has that rank)
# ========================================================================

def col_order_from_key(key):
    """Convert key (where key[col]=rank) to reading order: which col to read first."""
    # Sort columns by their rank value
    return sorted(range(len(key)), key=lambda c: key[c])


def columnar_encrypt(text, key):
    """Standard columnar transposition. key is 0-indexed rank list."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)

    # Fill grid row by row
    grid = [[None] * width for _ in range(nrows)]
    idx = 0
    for r in range(nrows):
        for c in range(width):
            if idx < n:
                grid[r][c] = text[idx]
                idx += 1

    # Read columns in rank order
    order = col_order_from_key(key)
    result = []
    for c in order:
        for r in range(nrows):
            if grid[r][c] is not None:
                result.append(grid[r][c])

    return ''.join(result) if isinstance(text, str) else result


def columnar_decrypt(text, key):
    """Inverse columnar transposition."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)
    short_cols_count = nrows * width - n

    # Column lengths: last short_cols_count columns (by grid position) have nrows-1
    col_len = {}
    for c in range(width):
        if c < width - short_cols_count:
            col_len[c] = nrows
        else:
            col_len[c] = nrows - 1 if short_cols_count > 0 else nrows

    # Distribute text into columns in rank order
    order = col_order_from_key(key)
    cols = {}
    idx = 0
    for c in order:
        cl = col_len[c]
        cols[c] = list(text[idx:idx + cl])
        idx += cl

    # Read row by row
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(cols.get(c, [])):
                result.append(cols[c][r])

    return ''.join(result) if isinstance(text, str) else result


def disrupted_encrypt(text, key):
    """VIC disrupted diagonal transposition."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)
    grid = [[None] * width for _ in range(nrows)]

    # Disruption column = column with highest rank value
    disrupt_col = max(range(width), key=lambda c: key[c])

    # Phase 1: fill triangle
    idx = 0
    for row in range(nrows):
        end_col = min(disrupt_col + row + 1, width)
        for col in range(end_col):
            if idx < n:
                grid[row][col] = text[idx]
                idx += 1
        if end_col >= width:
            break

    # Phase 2: fill remaining left-to-right, top-to-bottom
    for row in range(nrows):
        for col in range(width):
            if grid[row][col] is None and idx < n:
                grid[row][col] = text[idx]
                idx += 1

    # Read columns in rank order
    order = col_order_from_key(key)
    result = []
    for c in order:
        for r in range(nrows):
            if grid[r][c] is not None:
                result.append(grid[r][c])

    return ''.join(result) if isinstance(text, str) else result


def disrupted_decrypt(text, key):
    """Inverse VIC disrupted diagonal transposition."""
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)

    disrupt_col = max(range(width), key=lambda c: key[c])

    # Reconstruct fill pattern to know which cells are filled
    filled = [[False] * width for _ in range(nrows)]
    fill_order = []
    count = 0

    # Triangle phase
    for row in range(nrows):
        end_col = min(disrupt_col + row + 1, width)
        for col in range(end_col):
            if count < n:
                filled[row][col] = True
                fill_order.append((row, col))
                count += 1
        if end_col >= width:
            break

    # Remaining phase
    for row in range(nrows):
        for col in range(width):
            if not filled[row][col] and count < n:
                filled[row][col] = True
                fill_order.append((row, col))
                count += 1

    # Count cells per column
    col_counts = [sum(1 for r in range(nrows) if filled[r][c]) for c in range(width)]

    # Distribute ciphertext into columns in rank order
    order = col_order_from_key(key)
    cols = {}
    idx = 0
    for c in order:
        cl = col_counts[c]
        cols[c] = list(text[idx:idx + cl])
        idx += cl

    # Reconstruct grid
    grid = [[None] * width for _ in range(nrows)]
    col_read = [0] * width
    for r in range(nrows):
        for c in range(width):
            if filled[r][c] and col_read[c] < len(cols.get(c, [])):
                grid[r][c] = cols[c][col_read[c]]
                col_read[c] += 1

    # Read in original fill order
    result = []
    for r, c in fill_order:
        if grid[r][c] is not None:
            result.append(grid[r][c])

    return ''.join(result) if isinstance(text, str) else result


# ========================================================================
# CT -> DIGIT MAPPINGS
# ========================================================================

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}


def ct_to_digits_az(ct):
    return ''.join(str(ALPH_IDX[c] % 10) for c in ct)


def ct_to_digits_ka(ct):
    return ''.join(str(KA_IDX[c] % 10) for c in ct)


def ct_to_digits_az1(ct):
    return ''.join(str((ALPH_IDX[c] + 1) % 10) for c in ct)


DIGIT_MAPS = [("AZ", ct_to_digits_az), ("KA", ct_to_digits_ka), ("AZ1", ct_to_digits_az1)]


# ========================================================================
# SCORING
# ========================================================================

QUADGRAMS = {}
QG_FLOOR = -10.0


def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qp = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
    if qp.exists():
        with open(qp) as f:
            QUADGRAMS = json.load(f)
        QG_FLOOR = min(QUADGRAMS.values()) - 1.0


def qg_score(text):
    if len(text) < 4:
        return QG_FLOOR
    return sum(QUADGRAMS.get(text[i:i + 4], QG_FLOOR) for i in range(len(text) - 3)) / (len(text) - 3)


def score_pt(pt):
    """Score plaintext against cribs (fixed + free) and quadgrams."""
    pt = pt.replace('?', '')
    # Fixed-position cribs
    fixed = 0
    if len(pt) >= 34:
        for i, ch in enumerate("EASTNORTHEAST"):
            if 21 + i < len(pt) and pt[21 + i] == ch:
                fixed += 1
    if len(pt) >= 74:
        for i, ch in enumerate("BERLINCLOCK"):
            if 63 + i < len(pt) and pt[63 + i] == ch:
                fixed += 1

    # Free crib search
    free = 0
    ene_pos = pt.find("EASTNORTHEAST")
    bc_pos = pt.find("BERLINCLOCK")
    if ene_pos >= 0:
        free += 13
    if bc_pos >= 0:
        free += 11

    qg = qg_score(pt) if QUADGRAMS else -99.0
    return fixed, free, ene_pos, bc_pos, qg, len(pt)


# ========================================================================
# FULL VIC DECRYPT
# ========================================================================

def vic_decrypt(digit_str, trans1_key, trans2_key, decode_table, prefix_set):
    """Full VIC decrypt: undo trans2 (disrupted) -> undo trans1 (columnar) -> CB decode."""
    step1 = disrupted_decrypt(digit_str, trans2_key)
    step2 = columnar_decrypt(step1, trans1_key)
    return cb_decode(step2, decode_table, prefix_set)


def vic_decrypt_single(digit_str, trans_key, decode_table, prefix_set, disrupted=False):
    """Single-transposition VIC variant."""
    if disrupted:
        step = disrupted_decrypt(digit_str, trans_key)
    else:
        step = columnar_decrypt(digit_str, trans_key)
    return cb_decode(step, decode_table, prefix_set)


# ========================================================================
# TEST PARAMETERS
# ========================================================================

PHRASES = [
    ("KA_20", "KRYPTOSABCDEFGHIJLMN"),
    ("K1_20", "BETWEENSUBTLESHADING"),
    ("K2_20", "ITWASTOTALLYINVISIBL"),
    ("K3_20", "SLOWLYDESPARATLYSLOW"),
    ("PAK", "PALIMPSESTABSCISSAKR"),
    ("KPA", "KRYPTOSPALIMPSESTAB"),
    ("DAP", "DEFECTORABSCISSAPALI"),
    ("AKP", "ABSCISSAKRYPTOSPALIN"),
    ("CRIBS", "EASTNORTHEASTBERLINC"),
    ("META", "THEANSWERISTWOSYSTEM"),
]

DATES = [
    ("BerlinDDMMYY", [0, 9, 1, 1, 8, 9]),
    ("BerlinMMDDYY", [1, 1, 0, 9, 8, 9]),
    ("DedicDDMMYY", [0, 3, 1, 1, 9, 0]),
    ("DedicMMDDYY", [1, 1, 0, 3, 9, 0]),
    ("AbelDDMMYY", [1, 0, 0, 2, 6, 2]),
    ("AbelMMDDYY", [0, 2, 1, 0, 6, 2]),
    ("NickelDDMMYY", [2, 2, 0, 6, 5, 3]),
    ("NickelMMDDYY", [0, 6, 2, 2, 5, 3]),
    ("HayDDMMYY", [0, 4, 0, 5, 5, 7]),
    ("HayMMDDYY", [0, 5, 0, 4, 5, 7]),
    ("K2_385765", [3, 8, 5, 7, 6, 5]),
    ("K2_770844", [7, 7, 0, 8, 4, 4]),
    ("VIC_ex", [1, 3, 9, 1, 9, 5]),
]

PNS = [0, 1, 2, 3, 4, 5, 6, 7, 8]

TOP_ROWS = [
    ("ASINTOER", "ASINTOER"),
    ("ATONESIR", "ATONESIR"),
    ("ETAOINSH", "ETAOINSH"),
    ("KRYPTOSA", "KRYPTOSA"),
    ("SENORITA", "SENORITA"),
    ("ETAOIRNS", "ETAOIRNS"),
]

KEYGROUPS_FIXED = [
    [0, 0, 0, 0, 0],
    [1, 2, 3, 4, 5],
    [3, 8, 5, 7, 6],
    [7, 3, 2, 4, 1],
]

PREFIX_PAIRS = [(0, 1), (0, 5), (1, 2), (2, 7), (3, 7)]


# ========================================================================
# VERIFICATION
# ========================================================================

def verify_pipeline():
    """Round-trip verification of all components."""
    print("Pipeline Verification:")

    # Test rank functions
    r = rank10([3, 1, 4, 1, 5, 9, 2, 6, 5, 3], is_letters=False)
    assert len(set(r)) == 10, f"rank10 not unique: {r}"
    print(f"  rank10 OK: {r}")

    rn = rank_n([3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 8, 7, 6])
    assert len(set(rn)) == 13, f"rank_n not unique: {rn}"
    assert sorted(rn) == list(range(13)), f"rank_n not 0..N-1: {sorted(rn)}"
    print(f"  rank_n OK: {rn}")

    # Test checkerboard round-trip
    line_s = rank10([3, 7, 1, 9, 5, 2, 8, 4, 6, 0])
    enc, dec, pf = build_checkerboard(line_s, "ETAOINSH", (0, 5))
    assert enc is not None, "CB build failed"
    assert len(enc) == 26, f"CB encode table has {len(enc)} entries"
    test_pt = "THISISATESTMESSAGE"
    encoded = cb_encode(test_pt, enc)
    decoded = cb_decode(encoded, dec, pf)
    assert decoded == test_pt, f"CB roundtrip: {test_pt} -> {encoded} -> {decoded}"
    print(f"  CB round-trip OK: {test_pt} -> {encoded} -> {decoded}")

    # Test columnar round-trip
    key = rank_n([3, 1, 4, 1, 5, 9, 2, 6])
    ct_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    ct_enc = columnar_encrypt(ct_text, key)
    ct_dec = columnar_decrypt(ct_enc, key)
    assert ct_dec == ct_text, f"Columnar roundtrip: {ct_text} -> {ct_enc} -> {ct_dec}"
    print(f"  Columnar round-trip OK")

    # Test disrupted round-trip
    key2 = rank_n([2, 7, 1, 8, 2, 8, 1, 8, 2, 8])
    d_enc = disrupted_encrypt(ct_text, key2)
    d_dec = disrupted_decrypt(d_enc, key2)
    assert d_dec == ct_text, f"Disrupted roundtrip: {ct_text} -> {d_enc} -> {d_dec}"
    print(f"  Disrupted round-trip OK")

    # Full pipeline round-trip
    step1 = cb_encode(test_pt, enc)
    step2 = columnar_encrypt(step1, key)
    step3 = disrupted_encrypt(step2, key2)
    # Decrypt
    step4 = disrupted_decrypt(step3, key2)
    step5 = columnar_decrypt(step4, key)
    step6 = cb_decode(step5, dec, pf)
    assert step6 == test_pt, f"Full pipeline: {test_pt} -> ... -> {step6}"
    print(f"  Full pipeline round-trip OK")
    print()


# ========================================================================
# MAIN
# ========================================================================

def run():
    t0 = time.time()
    print("=" * 72)
    print("FULL VIC CIPHER DECRYPTION PIPELINE FOR K4")
    print("=" * 72)
    print(f"CT: {CT} ({CT_LEN} chars)")
    print(f"Params: {len(PHRASES)} phrases, {len(DATES)} dates, {len(PNS)} PNs,")
    print(f"  {len(TOP_ROWS)} top-rows, {len(DIGIT_MAPS)} digit-maps,")
    print(f"  {len(PREFIX_PAIRS)} prefix-pairs, {len(KEYGROUPS_FIXED)} fixed keygroups")
    print()

    load_quadgrams()
    print(f"Quadgrams: {len(QUADGRAMS)}")

    verify_pipeline()

    top20 = []  # (total_score, qg, config_dict)
    all_interesting = []
    configs = 0
    keys_ok = 0
    keys_fail = 0

    def record(phase, config_info, pt):
        nonlocal configs
        configs += 1
        fixed, free, ene_p, bc_p, qg, pt_len = score_pt(pt)
        total = fixed + free

        if total > 0 or fixed >= 6:
            config_info.update({
                'fixed': fixed, 'free': free, 'ene_pos': ene_p,
                'bc_pos': bc_p, 'qg': round(qg, 3), 'pt_len': pt_len,
                'pt': pt[:80], 'phase': phase,
            })
            all_interesting.append(config_info)

        entry = (total, qg, {
            'phase': phase, 'fixed': fixed, 'free': free,
            'qg': round(qg, 3), 'pt': pt[:60], 'pt_len': pt_len,
            **{k: v for k, v in config_info.items() if k not in ('pt',)}
        })
        if len(top20) < 20 or total > top20[-1][0] or (total == top20[-1][0] and qg > top20[-1][1]):
            top20.append(entry)
            top20.sort(key=lambda x: (x[0], x[1]), reverse=True)
            while len(top20) > 20:
                top20.pop()

    # ── Phase 1: Full VIC double transposition ────────────────────────────
    print("PHASE 1: Full VIC (checkerboard + columnar + disrupted)")
    p1_t = time.time()
    p1_n = 0

    for phrase_name, phrase in PHRASES:
        for date_name, date_digits in DATES:
            for pn in PNS:
                base = generate_vic_keys(phrase, date_digits, pn)
                if base is None:
                    continue

                # Build keygroups to try
                kgs = list(KEYGROUPS_FIXED)
                for _, dm_fn in DIGIT_MAPS:
                    d = dm_fn(CT)
                    kgs.append([int(d[i]) for i in range(5)])
                    kgs.append([int(d[i]) for i in range(len(d) - 5, len(d))])

                for kg in kgs:
                    keys = complete_vic_keys(base, kg)
                    if keys is None:
                        keys_fail += 1
                        continue
                    keys_ok += 1

                    for tr_name, top_row in TOP_ROWS:
                        for pp in PREFIX_PAIRS:
                            enc, dec, pf = build_checkerboard(keys['line_s'], top_row, pp)
                            if enc is None:
                                continue

                            for dm_name, dm_fn in DIGIT_MAPS:
                                ct_d = dm_fn(CT)
                                try:
                                    pt = vic_decrypt(ct_d, keys['trans1_key'],
                                                    keys['trans2_key'], dec, pf)
                                except Exception:
                                    p1_n += 1
                                    continue

                                record('full_vic', {
                                    'phrase': phrase_name, 'date': date_name,
                                    'pn': pn, 'top_row': tr_name,
                                    'prefix': pp, 'dm': dm_name,
                                    'a': keys['a'], 'b': keys['b'],
                                }, pt)
                                p1_n += 1

                if p1_n % 50000 == 0 and p1_n > 0:
                    print(f"  {p1_n:,} configs, {keys_ok:,} keys, "
                          f"{len(all_interesting)} hits, {time.time()-p1_t:.0f}s", flush=True)

    p1_time = time.time() - p1_t
    print(f"  Phase 1 done: {p1_n:,} configs, {keys_ok} keys, {p1_time:.0f}s")

    # ── Phase 2: Single transposition variants ────────────────────────────
    print("\nPHASE 2: Single transposition (columnar OR disrupted only)")
    p2_t = time.time()
    p2_n = 0

    for phrase_name, phrase in PHRASES:
        for date_name, date_digits in DATES:
            for pn in PNS:
                base = generate_vic_keys(phrase, date_digits, pn)
                if base is None:
                    continue

                for kg in KEYGROUPS_FIXED[:2]:  # Reduced set for speed
                    keys = complete_vic_keys(base, kg)
                    if keys is None:
                        continue

                    for tr_name, top_row in TOP_ROWS[:3]:
                        for pp in PREFIX_PAIRS[:3]:
                            enc, dec, pf = build_checkerboard(keys['line_s'], top_row, pp)
                            if enc is None:
                                continue

                            for dm_name, dm_fn in DIGIT_MAPS:
                                ct_d = dm_fn(CT)

                                # Try each transposition key alone
                                for tk_label, tk, use_disr in [
                                    ("col_t1", keys['trans1_key'], False),
                                    ("col_t2", keys['trans2_key'], False),
                                    ("dis_t1", keys['trans1_key'], True),
                                    ("dis_t2", keys['trans2_key'], True),
                                ]:
                                    try:
                                        pt = vic_decrypt_single(ct_d, tk, dec, pf, use_disr)
                                    except Exception:
                                        p2_n += 1
                                        continue

                                    record('single_trans', {
                                        'phrase': phrase_name, 'date': date_name,
                                        'pn': pn, 'trans': tk_label,
                                        'top_row': tr_name, 'dm': dm_name,
                                    }, pt)
                                    p2_n += 1

    p2_time = time.time() - p2_t
    print(f"  Phase 2 done: {p2_n:,} configs, {p2_time:.0f}s")

    # ── Phase 3: CB decode only (no transposition) ────────────────────────
    print("\nPHASE 3: Checkerboard decode only (direct, no transposition)")
    p3_t = time.time()
    p3_n = 0

    for tr_name, top_row in TOP_ROWS:
        for ls_opt in [
            rank10([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
            rank10([3, 7, 1, 9, 5, 2, 8, 4, 6, 0]),
            rank10([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
        ]:
            for pp in PREFIX_PAIRS:
                enc, dec, pf = build_checkerboard(ls_opt, top_row, pp)
                if enc is None:
                    continue
                for dm_name, dm_fn in DIGIT_MAPS:
                    ct_d = dm_fn(CT)
                    pt = cb_decode(ct_d, dec, pf)
                    record('cb_only', {
                        'top_row': tr_name, 'dm': dm_name, 'prefix': pp,
                    }, pt)
                    p3_n += 1

    p3_time = time.time() - p3_t
    print(f"  Phase 3 done: {p3_n:,} configs, {p3_time:.0f}s")

    # ── Phase 4: VIC keys driving col-7 transposition ─────────────────────
    print("\nPHASE 4: VIC-derived col-7 key + checkerboard")
    p4_t = time.time()
    p4_n = 0

    for phrase_name, phrase in PHRASES:
        for date_name, date_digits in DATES:
            for pn in PNS:
                base = generate_vic_keys(phrase, date_digits, pn)
                if base is None:
                    continue
                for kg in KEYGROUPS_FIXED[:2]:
                    keys = complete_vic_keys(base, kg)
                    if keys is None:
                        continue

                    # Extract 7-digit segments from various key lines
                    key_srcs = {
                        'h7': keys['line_h'][:7],
                        'k7': keys['line_k'][:7],
                        'p7': keys['line_p'][:7],
                    }
                    if len(keys['line_q_raw']) >= 7:
                        key_srcs['q7'] = keys['line_q_raw'][:7]

                    for src_name, src in key_srcs.items():
                        col7 = rank_n(src)

                        for tr_name, top_row in TOP_ROWS[:3]:
                            for pp in PREFIX_PAIRS[:3]:
                                enc, dec, pf = build_checkerboard(keys['line_s'], top_row, pp)
                                if enc is None:
                                    continue
                                for dm_name, dm_fn in DIGIT_MAPS:
                                    ct_d = dm_fn(CT)
                                    try:
                                        pt = vic_decrypt_single(ct_d, col7, dec, pf, False)
                                    except Exception:
                                        p4_n += 1
                                        continue
                                    record('col7_vic', {
                                        'phrase': phrase_name, 'date': date_name,
                                        'pn': pn, 'key_src': src_name,
                                        'top_row': tr_name, 'dm': dm_name,
                                    }, pt)
                                    p4_n += 1

    p4_time = time.time() - p4_t
    print(f"  Phase 4 done: {p4_n:,} configs, {p4_time:.0f}s")

    # ═══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    total_time = time.time() - t0
    total_configs = p1_n + p2_n + p3_n + p4_n

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configs: {total_configs:,}")
    print(f"  Phase 1 (full VIC): {p1_n:,} ({p1_time:.0f}s)")
    print(f"  Phase 2 (single trans): {p2_n:,} ({p2_time:.0f}s)")
    print(f"  Phase 3 (CB only): {p3_n:,} ({p3_time:.0f}s)")
    print(f"  Phase 4 (col7 VIC): {p4_n:,} ({p4_time:.0f}s)")
    print(f"Keys: {keys_ok:,} valid, {keys_fail:,} failed")
    print(f"Elapsed: {total_time:.1f}s")
    print(f"Interesting results: {len(all_interesting)}")

    max_fixed = max((r['fixed'] for r in all_interesting), default=0) if all_interesting else 0
    max_free = max((r['free'] for r in all_interesting), default=0) if all_interesting else 0
    max_total = max((r['fixed'] + r['free'] for r in all_interesting), default=0) if all_interesting else 0

    print(f"\nMax fixed: {max_fixed}/24, Max free: {max_free}/24, Max total: {max_total}")

    print(f"\nTop 20 results:")
    for i, (total, qg, info) in enumerate(top20):
        print(f"  {i+1:2d}. total={total:2d} qg={qg:.3f} | {info.get('phase','')} | "
              f"f={info.get('fixed',0)} fr={info.get('free',0)} | "
              f"PT({info.get('pt_len','?')}): {info.get('pt','')[:50]}")

    if max_free >= 13:
        verdict = "SIGNAL"
    elif max_total >= 10:
        verdict = "INTERESTING"
    elif max_fixed >= 6:
        verdict = "WEAK"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")

    # Save results
    out_path = Path(__file__).resolve().parents[2] / "results" / "full_vic_pipeline_k4.json"
    output = {
        'experiment': 'e_full_vic_pipeline_k4',
        'description': 'Full VIC cipher pipeline (key generation + CB + double transposition)',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'keys_valid': keys_ok,
        'keys_failed': keys_fail,
        'elapsed_seconds': round(total_time, 1),
        'phases': {
            'phase1_full_vic': {'configs': p1_n, 'time': round(p1_time, 1)},
            'phase2_single_trans': {'configs': p2_n, 'time': round(p2_time, 1)},
            'phase3_cb_only': {'configs': p3_n, 'time': round(p3_time, 1)},
            'phase4_col7_vic': {'configs': p4_n, 'time': round(p4_time, 1)},
        },
        'max_fixed': max_fixed,
        'max_free': max_free,
        'max_total': max_total,
        'verdict': verdict,
        'top_20': [{'total': t, 'qg': q, **d} for t, q, d in top20],
        'interesting': all_interesting[:50],
        'elimination': (
            f"Full VIC pipeline ({total_configs:,} configs): "
            f"{len(PHRASES)} phrases x {len(DATES)} dates x {len(PNS)} PNs. "
            f"Max fixed={max_fixed}/24, free={max_free}/24. "
            f"VERDICT: {verdict}."
        ),
    }
    os.makedirs(out_path.parent, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    run()
