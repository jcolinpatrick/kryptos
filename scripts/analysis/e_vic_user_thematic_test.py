#!/usr/bin/env python3
"""
VIC Cipher Thematic Parameter Test for K4.

Cipher:  VIC cipher (full key generation + straddling checkerboard + double transposition)
Family:  analysis
Status:  active
Keyspace: ~4 top-rows x 2 dates x 9 PNs x 45 prefix-pairs x 2 transposition-orders = ~6,480 core
Last run: never
Best score: N/A

KEY DIFFERENCE FROM PRIOR WORK:
Prior VIC scripts (e_full_vic_pipeline_k4.py, f_vic_narrative_sweep_v1.py) converted
K4 letters to digits using A=0..Z=25 (or A=1..Z=0) BEFORE running the VIC decrypt.

In the REAL VIC cipher, the final ciphertext is TEXT because after encryption,
the digit stream is converted to letters via the checkerboard (or a codebook).
To DECRYPT, the correct flow is:
  1. Use the checkerboard to ENCODE K4 letters -> digit stream
  2. Undo transposition(s) on the digit stream
  3. Use the checkerboard to DECODE digits -> plaintext letters

This script implements that correct pipeline with user-specified thematic parameters:
- Phrase: SLOWLYDESPARATLYSLOWLY (K3 plaintext with misspelling)
- Date: 091189 (Berlin Wall fall, Nov 9 1989)
- Personal number: 5
- Keygroup: 10110
- Top row: ENDYAHRO (from raised/NDYAHR chars)

Variants tested:
- Top row orderings: ENDYAHRO, NDYAHROE, AHEROYDN
- Date formats: 091189, 110989
- Personal numbers: 1-9
- All C(10,2)=45 prefix column pairs
- Both transposition orders (Model A: undo disrupted then columnar; Model B: reversed)
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys
import os
import json
import time
import math
import itertools
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ========================================================================
# VIC KEY GENERATION (copied from e_full_vic_pipeline_k4.py)
# ========================================================================

def rank10(items, is_letters=False):
    """Rank 10 items VIC-style: returns list of digits 1-9 and 0 (where 0=10th rank)."""
    assert len(items) == 10, f"rank10 requires exactly 10 items, got {len(items)}"
    if is_letters:
        indexed = [(items[i], i) for i in range(10)]
    else:
        indexed = [(items[i] if items[i] != 0 else 10, i) for i in range(10)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * 10
    for rank_idx, (_, orig_pos) in enumerate(ranked):
        result[orig_pos] = (rank_idx + 1) % 10
    return result


def rank_n(items):
    """Rank N items: returns list of integers 0..N-1. 0 treated as 10 for ordering."""
    indexed = [(items[i] if items[i] != 0 else 10, i) for i in range(len(items))]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * len(items)
    for new_rank, (_, orig_pos) in enumerate(ranked):
        result[orig_pos] = new_rank
    return result


def mod10_subtract(a, b):
    return [(a[i] - b[i]) % 10 for i in range(len(a))]


def mod10_add(a, b):
    return [(a[i] + b[i]) % 10 for i in range(min(len(a), len(b)))]


def chain_add(digits, target_len):
    result = list(digits)
    while len(result) < target_len:
        new_digit = (result[-2] + result[-1]) % 10
        result.append(new_digit)
    return result[:target_len]


def generate_vic_keys(phrase, date_digits, personal_number):
    """Full VIC key generation from phrase + date + PN. Returns base_keys dict or None."""
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
    """Complete VIC key generation with a specific keygroup."""
    line_a = list(keygroup)
    line_b = base_keys['line_b']
    line_e1 = base_keys['line_e1']
    line_e2 = base_keys['line_e2']
    pn = base_keys['personal_number']

    line_c = mod10_subtract(line_a, line_b)
    line_f1 = chain_add(line_c, 10)
    line_g = mod10_add(line_e1, line_f1)

    line_h = []
    for d in line_g:
        idx = (d - 1) % 10
        line_h.append(line_e2[idx])

    line_j = rank10(line_h, is_letters=False)

    chain_60 = chain_add(line_h, 60)
    line_k = chain_60[10:20]
    line_l = chain_60[20:30]
    line_m = chain_60[30:40]
    line_n = chain_60[40:50]
    line_p = chain_60[50:60]

    # Determine a and b
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

    kp_block = [line_k, line_l, line_m, line_n, line_p]
    col_order = []
    for rank in range(1, 11):
        target = rank % 10
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
    trans1_key = rank_n(line_q_raw)
    trans2_key = rank_n(line_r_raw)
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

    line_s: list of 10 digits (column labels from rank10 of line_p)
    top_row_letters: 8 high-frequency letters
    prefix_cols: (p1, p2) column indices that are blank in top row

    Returns (encode_table, decode_table, prefix_digit_set) or (None, None, None)
    """
    top = top_row_letters.upper()
    if len(top) != 8:
        return None, None, None
    remaining = [c for c in ALPH if c not in top]
    if len(remaining) != 18:
        return None, None, None

    row2 = remaining[:10]
    row3 = remaining[10:18]
    p1, p2 = prefix_cols

    encode = {}
    decode = {}

    # Top row: 8 letters mapped to single-digit codes
    letter_idx = 0
    for col in range(10):
        if col in (p1, p2):
            continue
        label = str(line_s[col] % 10)
        encode[top[letter_idx]] = label
        decode[label] = top[letter_idx]
        letter_idx += 1

    # Row 2: 10 letters with prefix1
    pf1 = str(line_s[p1] % 10)
    for col in range(10):
        label = pf1 + str(line_s[col] % 10)
        encode[row2[col]] = label
        decode[label] = row2[col]

    # Row 3: 8 letters with prefix2 (+ 2 slots for digit/special if needed)
    pf2 = str(line_s[p2] % 10)
    for idx in range(min(len(row3), 10)):
        col = idx
        label = pf2 + str(line_s[col] % 10)
        encode[row3[idx]] = label
        decode[label] = row3[idx]

    prefix_set = {pf1, pf2}
    return encode, decode, prefix_set


def cb_encode(text, encode_table):
    """Encode text to digit string via checkerboard."""
    return ''.join(encode_table.get(c, '') for c in text.upper())


def cb_decode(digit_string, decode_table, prefix_set):
    """Decode digit string to text via checkerboard."""
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
# TRANSPOSITION
# ========================================================================

def col_order_from_key(key):
    return sorted(range(len(key)), key=lambda c: key[c])


def columnar_encrypt(text, key):
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)
    grid = [[None] * width for _ in range(nrows)]
    idx = 0
    for r in range(nrows):
        for c in range(width):
            if idx < n:
                grid[r][c] = text[idx]
                idx += 1
    order = col_order_from_key(key)
    result = []
    for c in order:
        for r in range(nrows):
            if grid[r][c] is not None:
                result.append(grid[r][c])
    return ''.join(result) if isinstance(text, str) else result


def columnar_decrypt(text, key):
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)
    short_cols_count = nrows * width - n
    col_len = {}
    for c in range(width):
        if c < width - short_cols_count:
            col_len[c] = nrows
        else:
            col_len[c] = nrows - 1 if short_cols_count > 0 else nrows
    order = col_order_from_key(key)
    cols = {}
    idx = 0
    for c in order:
        cl = col_len[c]
        cols[c] = list(text[idx:idx + cl])
        idx += cl
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(cols.get(c, [])):
                result.append(cols[c][r])
    return ''.join(result) if isinstance(text, str) else result


def disrupted_encrypt(text, key):
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)
    grid = [[None] * width for _ in range(nrows)]
    disrupt_col = max(range(width), key=lambda c: key[c])
    idx = 0
    for row in range(nrows):
        end_col = min(disrupt_col + row + 1, width)
        for col in range(end_col):
            if idx < n:
                grid[row][col] = text[idx]
                idx += 1
        if end_col >= width:
            break
    for row in range(nrows):
        for col in range(width):
            if grid[row][col] is None and idx < n:
                grid[row][col] = text[idx]
                idx += 1
    order = col_order_from_key(key)
    result = []
    for c in order:
        for r in range(nrows):
            if grid[r][c] is not None:
                result.append(grid[r][c])
    return ''.join(result) if isinstance(text, str) else result


def disrupted_decrypt(text, key):
    width = len(key)
    n = len(text)
    nrows = math.ceil(n / width)
    disrupt_col = max(range(width), key=lambda c: key[c])
    filled = [[False] * width for _ in range(nrows)]
    fill_order = []
    count = 0
    for row in range(nrows):
        end_col = min(disrupt_col + row + 1, width)
        for col in range(end_col):
            if count < n:
                filled[row][col] = True
                fill_order.append((row, col))
                count += 1
        if end_col >= width:
            break
    for row in range(nrows):
        for col in range(width):
            if not filled[row][col] and count < n:
                filled[row][col] = True
                fill_order.append((row, col))
                count += 1
    col_counts = [sum(1 for r in range(nrows) if filled[r][c]) for c in range(width)]
    order = col_order_from_key(key)
    cols = {}
    idx = 0
    for c in order:
        cl = col_counts[c]
        cols[c] = list(text[idx:idx + cl])
        idx += cl
    grid = [[None] * width for _ in range(nrows)]
    col_read = [0] * width
    for r in range(nrows):
        for c in range(width):
            if filled[r][c] and col_read[c] < len(cols.get(c, [])):
                grid[r][c] = cols[c][col_read[c]]
                col_read[c] += 1
    result = []
    for r, c in fill_order:
        if grid[r][c] is not None:
            result.append(grid[r][c])
    return ''.join(result) if isinstance(text, str) else result


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
    """Score plaintext: fixed crib positions + free search + substring check."""
    pt = pt.replace('?', '')
    # Fixed-position crib check
    fixed = 0
    if len(pt) >= 34:
        for i, ch in enumerate("EASTNORTHEAST"):
            if 21 + i < len(pt) and pt[21 + i] == ch:
                fixed += 1
    if len(pt) >= 74:
        for i, ch in enumerate("BERLINCLOCK"):
            if 63 + i < len(pt) and pt[63 + i] == ch:
                fixed += 1

    # Free crib search (full strings)
    free = 0
    ene_pos = pt.find("EASTNORTHEAST")
    bc_pos = pt.find("BERLINCLOCK")
    if ene_pos >= 0:
        free += 13
    if bc_pos >= 0:
        free += 11

    # Substring matches of length >= 3
    submatches = []
    for crib_name, crib in [("ENE", "EASTNORTHEAST"), ("BC", "BERLINCLOCK")]:
        for l in range(len(crib), 2, -1):
            for start in range(len(crib) - l + 1):
                sub = crib[start:start + l]
                pos = pt.find(sub)
                if pos >= 0:
                    submatches.append((crib_name, sub, pos, l))
                    break  # Longest match per starting position
            if submatches and submatches[-1][3] >= l:
                break  # Found longest substring

    qg = qg_score(pt) if QUADGRAMS else -99.0
    return fixed, free, ene_pos, bc_pos, qg, len(pt), submatches


# ========================================================================
# DECRYPT PIPELINES
# ========================================================================

def vic_decrypt_model_a(digit_str, trans1_key, trans2_key, decode_table, prefix_set):
    """Model A: undo disrupted (trans2) -> undo columnar (trans1) -> CB decode.
    Standard VIC decrypt order: last transposition undone first."""
    step1 = disrupted_decrypt(digit_str, trans2_key)
    step2 = columnar_decrypt(step1, trans1_key)
    return cb_decode(step2, decode_table, prefix_set)


def vic_decrypt_model_b(digit_str, trans1_key, trans2_key, decode_table, prefix_set):
    """Model B: undo columnar (trans1) -> undo disrupted (trans2) -> CB decode.
    Reversed transposition order."""
    step1 = columnar_decrypt(digit_str, trans1_key)
    step2 = disrupted_decrypt(step1, trans2_key)
    return cb_decode(step2, decode_table, prefix_set)


def vic_decrypt_single_col(digit_str, key, decode_table, prefix_set):
    """Single columnar transposition only."""
    step = columnar_decrypt(digit_str, key)
    return cb_decode(step, decode_table, prefix_set)


def vic_decrypt_single_disr(digit_str, key, decode_table, prefix_set):
    """Single disrupted transposition only."""
    step = disrupted_decrypt(digit_str, key)
    return cb_decode(step, decode_table, prefix_set)


def cb_only_decode(digit_str, decode_table, prefix_set):
    """No transposition, just checkerboard decode."""
    return cb_decode(digit_str, decode_table, prefix_set)


# ========================================================================
# TEST PARAMETERS
# ========================================================================

# User's phrase: K3 plaintext with misspelling (21 chars, use first 20)
PHRASE = "SLOWLYDESPARATLYSLOWLY"

# Date formats
DATES = [
    ("091189", [0, 9, 1, 1, 8, 9]),    # Nov 9, 1989 - DDMMYY
    ("110989", [1, 1, 0, 9, 8, 9]),    # Nov 9, 1989 - MMDDYY
]

# Personal numbers
PNS = list(range(1, 10))  # 1-9

# User's keygroup
PRIMARY_KEYGROUP = [1, 0, 1, 1, 0]

# Top row orderings from NDYAHR raised chars
TOP_ROWS = [
    ("ENDYAHRO", "ENDYAHRO"),   # User's primary
    ("NDYAHROE", "NDYAHROE"),   # Shifted
    ("AHEROYDN", "AHEROYDN"),   # Reversed alpha-ish
    ("ADEHONRY", "ADEHONRY"),   # Alphabetical
]

# All C(10,2) = 45 prefix column pairs
ALL_PREFIX_PAIRS = list(itertools.combinations(range(10), 2))


# ========================================================================
# MAIN
# ========================================================================

def run():
    t0 = time.time()
    print("=" * 78)
    print("VIC CIPHER THEMATIC PARAMETER TEST (CORRECT CHECKERBOARD PIPELINE)")
    print("=" * 78)
    print(f"CT: {CT} ({CT_LEN} chars)")
    print(f"Phrase: {PHRASE}")
    print(f"Dates: {[d[0] for d in DATES]}")
    print(f"Personal numbers: {PNS}")
    print(f"Primary keygroup: {PRIMARY_KEYGROUP}")
    print(f"Top rows: {[t[0] for t in TOP_ROWS]}")
    print(f"Prefix pairs: all {len(ALL_PREFIX_PAIRS)} C(10,2) combinations")
    print()

    load_quadgrams()
    print(f"Quadgrams loaded: {len(QUADGRAMS)}")

    # ── Verify round-trip first ──────────────────────────────────────────
    print("\n--- Round-trip verification ---")
    test_s = rank10([3, 7, 1, 9, 5, 2, 8, 4, 6, 0])
    test_enc, test_dec, test_pf = build_checkerboard(test_s, "ETAOINSH", (0, 5))
    if test_enc:
        test_pt = "HELLOWORLD"
        encoded = cb_encode(test_pt, test_enc)
        decoded = cb_decode(encoded, test_dec, test_pf)
        assert decoded == test_pt, f"CB round-trip FAILED: {test_pt} -> {encoded} -> {decoded}"
        print(f"  CB round-trip OK: {test_pt} -> {encoded} -> {decoded}")

        # Full pipeline round-trip
        test_key1 = rank_n([3, 1, 4, 1, 5, 9, 2, 6])
        test_key2 = rank_n([2, 7, 1, 8, 2, 8, 1, 8, 2, 8])
        step1 = cb_encode(test_pt, test_enc)
        step2 = columnar_encrypt(step1, test_key1)
        step3 = disrupted_encrypt(step2, test_key2)
        # Now decrypt Model A
        pt_a = vic_decrypt_model_a(step3, test_key1, test_key2, test_dec, test_pf)
        assert pt_a == test_pt, f"Model A round-trip FAILED: {test_pt} -> ... -> {pt_a}"
        print(f"  Model A round-trip OK")
        # Model B should NOT round-trip (different order)
        pt_b = vic_decrypt_model_b(step3, test_key1, test_key2, test_dec, test_pf)
        if pt_b == test_pt:
            print(f"  Model B also round-trips (keys commute for this case)")
        else:
            print(f"  Model B produces different output (expected)")

        # Verify CB-based encode: K4 letters -> digits -> back via CB
        k4_encoded = cb_encode(CT, test_enc)
        k4_rt = cb_decode(k4_encoded, test_dec, test_pf)
        assert k4_rt == CT, f"K4 CB round-trip FAILED"
        print(f"  K4 CB encode round-trip OK (CT -> {len(k4_encoded)} digits -> CT)")
        print(f"  K4 digit stream length: {len(k4_encoded)} digits from 97 letters")
    print()

    # ── Collect all results ──────────────────────────────────────────────
    all_results = []
    configs = 0
    keys_ok = 0
    keys_fail = 0

    def try_decrypt(config_label, pt, config_info):
        nonlocal configs
        configs += 1
        fixed, free, ene_p, bc_p, qg, pt_len, submatches = score_pt(pt)
        total = fixed + free

        result = {
            'config': config_label,
            'fixed': fixed,
            'free': free,
            'total': total,
            'ene_pos': ene_p,
            'bc_pos': bc_p,
            'qg': round(qg, 3),
            'pt_len': pt_len,
            'pt': pt[:100],
            'submatches': submatches,
            **config_info,
        }

        # Report any result with substring match >= 3 chars
        if submatches:
            max_submatch = max(s[3] for s in submatches)
        else:
            max_submatch = 0

        if total > 0 or max_submatch >= 3 or fixed >= 3:
            all_results.append(result)

        return result

    # =====================================================================
    # PHASE 1: CORRECT VIC PIPELINE (CB-encode K4 -> undo trans -> CB-decode)
    # =====================================================================
    print("=" * 78)
    print("PHASE 1: CORRECT VIC PIPELINE (checkerboard encode/decode)")
    print("  K4 letters -> CB encode -> digit stream -> undo transpositions -> CB decode")
    print("=" * 78)

    phase1_configs = 0
    phase1_t = time.time()

    for date_name, date_digits in DATES:
        for pn in PNS:
            base = generate_vic_keys(PHRASE, date_digits, pn)
            if base is None:
                continue

            # Try primary keygroup and a few random-ish ones
            keygroups = [
                ("10110", PRIMARY_KEYGROUP),
                ("00000", [0, 0, 0, 0, 0]),
                ("12345", [1, 2, 3, 4, 5]),
                ("38576", [3, 8, 5, 7, 6]),  # K2 numbers
                ("73241", [7, 3, 2, 4, 1]),
            ]

            for kg_name, kg in keygroups:
                keys = complete_vic_keys(base, kg)
                if keys is None:
                    keys_fail += 1
                    continue
                keys_ok += 1

                for tr_name, top_row in TOP_ROWS:
                    for pp in ALL_PREFIX_PAIRS:
                        enc, dec, pf = build_checkerboard(keys['line_s'], top_row, pp)
                        if enc is None:
                            continue

                        # CORRECT APPROACH: use CB to encode K4 letters to digits
                        ct_digits = cb_encode(CT, enc)
                        if not ct_digits or '?' in ct_digits:
                            continue  # Some letters not in checkerboard

                        config_base = {
                            'date': date_name, 'pn': pn, 'kg': kg_name,
                            'top_row': tr_name, 'prefix': pp,
                            'a': keys['a'], 'b': keys['b'],
                            'digit_len': len(ct_digits),
                        }

                        # Model A: undo disrupted then columnar
                        try:
                            pt = vic_decrypt_model_a(ct_digits, keys['trans1_key'],
                                                     keys['trans2_key'], dec, pf)
                            try_decrypt('model_a_full', pt, {**config_base, 'mode': 'model_a_full'})
                            phase1_configs += 1
                        except Exception:
                            phase1_configs += 1

                        # Model B: undo columnar then disrupted
                        try:
                            pt = vic_decrypt_model_b(ct_digits, keys['trans1_key'],
                                                     keys['trans2_key'], dec, pf)
                            try_decrypt('model_b_full', pt, {**config_base, 'mode': 'model_b_full'})
                            phase1_configs += 1
                        except Exception:
                            phase1_configs += 1

                        # Single transposition variants
                        for tk_label, tk in [
                            ("col_t1", keys['trans1_key']),
                            ("col_t2", keys['trans2_key']),
                        ]:
                            try:
                                pt = vic_decrypt_single_col(ct_digits, tk, dec, pf)
                                try_decrypt(f'single_{tk_label}', pt,
                                           {**config_base, 'mode': f'single_col_{tk_label}'})
                                phase1_configs += 1
                            except Exception:
                                phase1_configs += 1

                            try:
                                pt = vic_decrypt_single_disr(ct_digits, tk, dec, pf)
                                try_decrypt(f'single_disr_{tk_label}', pt,
                                           {**config_base, 'mode': f'single_disr_{tk_label}'})
                                phase1_configs += 1
                            except Exception:
                                phase1_configs += 1

                        # CB-only (no transposition)
                        pt = cb_only_decode(ct_digits, dec, pf)
                        try_decrypt('cb_only', pt, {**config_base, 'mode': 'cb_only'})
                        phase1_configs += 1

                if phase1_configs % 10000 == 0 and phase1_configs > 0:
                    print(f"  {phase1_configs:,} configs, {len(all_results)} hits, "
                          f"{time.time()-phase1_t:.0f}s", flush=True)

    phase1_time = time.time() - phase1_t
    print(f"\n  Phase 1 done: {phase1_configs:,} configs, "
          f"{len(all_results)} hits, {phase1_time:.1f}s")

    # =====================================================================
    # PHASE 2: DIAGNOSTIC — Show exact keys + checkerboard for primary params
    # =====================================================================
    print("\n" + "=" * 78)
    print("PHASE 2: DIAGNOSTIC — Primary parameter set details")
    print("=" * 78)

    base = generate_vic_keys(PHRASE, DATES[0][1], 5)
    if base:
        print(f"  Phrase: {base['phrase']}")
        print(f"  Line D (first 10): {base['line_d'][:10]}")
        print(f"  Line D (last 10):  {base['line_d'][10:]}")
        print(f"  Line E.1 (rank of D[:10]): {base['line_e1']}")
        print(f"  Line E.2 (rank of D[10:]): {base['line_e2']}")
        print(f"  Line B (date[:5]):  {base['line_b']}")
        print()

        keys = complete_vic_keys(base, PRIMARY_KEYGROUP)
        if keys:
            print(f"  Keygroup: {PRIMARY_KEYGROUP}")
            print(f"  a={keys['a']}, b={keys['b']}")
            print(f"  Trans1 key (len {len(keys['trans1_key'])}): {keys['trans1_key']}")
            print(f"  Trans2 key (len {len(keys['trans2_key'])}): {keys['trans2_key']}")
            print(f"  Line S (CB col labels): {keys['line_s']}")
            print(f"  Line H: {keys['line_h']}")
            print(f"  Line K: {keys['line_k']}")
            print(f"  Line P: {keys['line_p']}")
            print()

            # Show full checkerboard for the primary top-row
            enc, dec, pf = build_checkerboard(keys['line_s'], "ENDYAHRO", (0, 1))
            if enc:
                print(f"  Checkerboard (top=ENDYAHRO, prefix cols=0,1):")
                print(f"  Column labels (line_s): {keys['line_s']}")
                print(f"  Prefix digits: {pf}")
                print()
                # Display the checkerboard grid
                col_labels = [str(keys['line_s'][c] % 10) for c in range(10)]
                print(f"    Col:  {'  '.join(col_labels)}")
                # Top row
                top_display = []
                letter_idx = 0
                for col in range(10):
                    if col in (0, 1):
                        top_display.append('-')
                    else:
                        top_display.append("ENDYAHRO"[letter_idx])
                        letter_idx += 1
                print(f"    Top:  {'  '.join(top_display)}")
                remaining = [c for c in ALPH if c not in "ENDYAHRO"]
                row2 = remaining[:10]
                row3 = remaining[10:18]
                pf1 = str(keys['line_s'][0] % 10)
                pf2 = str(keys['line_s'][1] % 10)
                print(f"    {pf1}xx:  {'  '.join(row2)}")
                print(f"    {pf2}xx:  {'  '.join(row3)}")
                print()
                print(f"  Encode table:")
                for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                    print(f"    {ch} -> {enc.get(ch, '??')}")
                print()
                ct_digits = cb_encode(CT, enc)
                print(f"  K4 encoded to digits: {ct_digits}")
                print(f"  Digit stream length: {len(ct_digits)}")
                print()
                # Decode directly (no transposition)
                pt_direct = cb_decode(ct_digits, dec, pf)
                print(f"  Direct CB decode (no trans): {pt_direct}")

                # Full VIC decrypt Model A
                try:
                    pt_a = vic_decrypt_model_a(ct_digits, keys['trans1_key'],
                                               keys['trans2_key'], dec, pf)
                    print(f"  Model A decrypt: {pt_a}")
                except Exception as e:
                    print(f"  Model A decrypt error: {e}")

                # Full VIC decrypt Model B
                try:
                    pt_b = vic_decrypt_model_b(ct_digits, keys['trans1_key'],
                                               keys['trans2_key'], dec, pf)
                    print(f"  Model B decrypt: {pt_b}")
                except Exception as e:
                    print(f"  Model B decrypt error: {e}")
        else:
            print(f"  Key generation FAILED with primary keygroup")
    else:
        print(f"  Base key generation FAILED")

    # =====================================================================
    # PHASE 3: EXTENDED KEYGROUP SEARCH
    # =====================================================================
    print("\n" + "=" * 78)
    print("PHASE 3: Extended keygroup search (100K random keygroups)")
    print("=" * 78)

    phase3_t = time.time()
    phase3_configs = 0
    import random
    rng = random.Random(42)

    # Generate 100K random keygroups
    random_keygroups = set()
    while len(random_keygroups) < 100000:
        kg = tuple(rng.randint(0, 9) for _ in range(5))
        random_keygroups.add(kg)

    # Test with best top-row and a few prefix pairs
    BEST_PREFIX_PAIRS = [(0, 1), (0, 5), (1, 5), (2, 7), (3, 6), (4, 8), (8, 9)]

    for date_name, date_digits in DATES:
        for pn in [5]:  # Primary PN
            base = generate_vic_keys(PHRASE, date_digits, pn)
            if base is None:
                continue

            for kg_tuple in random_keygroups:
                kg = list(kg_tuple)
                keys = complete_vic_keys(base, kg)
                if keys is None:
                    continue

                for tr_name, top_row in TOP_ROWS[:2]:  # Primary + shifted
                    for pp in BEST_PREFIX_PAIRS:
                        enc, dec, pf = build_checkerboard(keys['line_s'], top_row, pp)
                        if enc is None:
                            continue

                        ct_digits = cb_encode(CT, enc)
                        if not ct_digits:
                            continue

                        config_base = {
                            'date': date_name, 'pn': pn,
                            'kg': ''.join(str(d) for d in kg),
                            'top_row': tr_name, 'prefix': pp,
                        }

                        # Model A only (for speed)
                        try:
                            pt = vic_decrypt_model_a(ct_digits, keys['trans1_key'],
                                                     keys['trans2_key'], dec, pf)
                            try_decrypt('phase3_model_a', pt,
                                       {**config_base, 'mode': 'model_a_full'})
                            phase3_configs += 1
                        except Exception:
                            phase3_configs += 1

                        # Also Model B
                        try:
                            pt = vic_decrypt_model_b(ct_digits, keys['trans1_key'],
                                                     keys['trans2_key'], dec, pf)
                            try_decrypt('phase3_model_b', pt,
                                       {**config_base, 'mode': 'model_b_full'})
                            phase3_configs += 1
                        except Exception:
                            phase3_configs += 1

                if phase3_configs % 100000 == 0 and phase3_configs > 0:
                    elapsed = time.time() - phase3_t
                    print(f"  {phase3_configs:,} configs, {len(all_results)} hits, "
                          f"{elapsed:.0f}s", flush=True)

    phase3_time = time.time() - phase3_t
    print(f"  Phase 3 done: {phase3_configs:,} configs, "
          f"{len(all_results)} hits, {phase3_time:.1f}s")

    # =====================================================================
    # SUMMARY
    # =====================================================================
    total_time = time.time() - t0
    total_configs = phase1_configs + phase3_configs

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"Total configs: {total_configs:,}")
    print(f"  Phase 1 (core params): {phase1_configs:,} ({phase1_time:.1f}s)")
    print(f"  Phase 3 (100K keygroups): {phase3_configs:,} ({phase3_time:.1f}s)")
    print(f"Keys: {keys_ok:,} valid, {keys_fail:,} failed")
    print(f"Elapsed: {total_time:.1f}s")
    print(f"Results with crib matches: {len(all_results)}")

    if all_results:
        # Sort by total score descending, then qg descending
        all_results.sort(key=lambda r: (r['total'], r['qg']), reverse=True)

        max_fixed = max(r['fixed'] for r in all_results)
        max_free = max(r['free'] for r in all_results)
        max_total = max(r['total'] for r in all_results)
        best_qg = max(r['qg'] for r in all_results)
        max_submatch = max(
            (max(s[3] for s in r['submatches']) if r['submatches'] else 0)
            for r in all_results
        )

        print(f"\nMax fixed: {max_fixed}/24, Max free: {max_free}/24")
        print(f"Max total: {max_total}, Best qg: {best_qg:.3f}")
        print(f"Longest substring match: {max_submatch}")

        # Print ALL results with substring matches >= 3
        sub3_results = [r for r in all_results if r['submatches'] and max(s[3] for s in r['submatches']) >= 3]
        if sub3_results:
            print(f"\n--- Results with substring match >= 3 chars ({len(sub3_results)}) ---")
            for r in sub3_results[:50]:
                print(f"\n  Config: {r['config']} | date={r.get('date','')} pn={r.get('pn','')} "
                      f"kg={r.get('kg','')} top={r.get('top_row','')} pfx={r.get('prefix','')}")
                print(f"  Fixed: {r['fixed']}/24, Free: {r['free']}/24, QG: {r['qg']:.3f}")
                print(f"  PT({r['pt_len']}): {r['pt']}")
                for sm in r['submatches']:
                    print(f"    Substring: {sm[0]}:'{sm[1]}' at pos {sm[2]} (len {sm[3]})")

        print(f"\n--- Top 30 by total score ---")
        for i, r in enumerate(all_results[:30]):
            subs = '; '.join(f"{s[0]}:'{s[1]}'@{s[2]}" for s in r['submatches']) if r['submatches'] else '-'
            print(f"  {i+1:3d}. total={r['total']:2d} fixed={r['fixed']:2d} free={r['free']:2d} "
                  f"qg={r['qg']:.3f} | {r['config']} | subs=[{subs}]")
            print(f"       PT({r['pt_len']}): {r['pt'][:70]}")
    else:
        print("\nNo results with any crib matches found.")
        max_fixed = 0
        max_free = 0
        max_total = 0

    if max_free >= 13:
        verdict = "SIGNAL"
    elif max_total >= 10:
        verdict = "INTERESTING"
    elif max_total >= 6:
        verdict = "WEAK"
    else:
        verdict = "NOISE"

    print(f"\nVERDICT: {verdict}")

    # Save results
    out_path = Path(__file__).resolve().parents[2] / "results" / "vic_user_thematic_test.json"
    os.makedirs(out_path.parent, exist_ok=True)
    output = {
        'experiment': 'e_vic_user_thematic_test',
        'description': 'VIC cipher with CORRECT checkerboard pipeline + user thematic params',
        'key_difference': 'Uses CB-encode(K4 letters) -> digits, NOT A=0..Z=25 mapping',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'parameters': {
            'phrase': PHRASE,
            'dates': [d[0] for d in DATES],
            'personal_numbers': PNS,
            'primary_keygroup': PRIMARY_KEYGROUP,
            'top_rows': [t[0] for t in TOP_ROWS],
            'prefix_pairs_phase1': 'all_45',
            'prefix_pairs_phase3': [list(p) for p in BEST_PREFIX_PAIRS],
            'keygroups_phase3': '100K random',
        },
        'total_configs': total_configs,
        'keys_valid': keys_ok,
        'keys_failed': keys_fail,
        'elapsed_seconds': round(total_time, 1),
        'max_fixed': max_fixed,
        'max_free': max_free,
        'max_total': max_total,
        'verdict': verdict,
        'top_results': all_results[:50],
    }
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    run()
