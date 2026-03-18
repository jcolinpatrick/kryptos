#!/usr/bin/env python3
"""
VIC cipher with NON-STANDARD key schedule variant for K4.

Cipher:  VIC variant (personal_no as offset, CB alphabet from chain-add sort)
Family:  campaigns
Status:  active
Keyspace: ~120M configs (100K keygroups x phrases x dates x top-rows x variants)
Last run: never
Best score: N/A

WHAT IS NOVEL vs prior VIC sweeps:
- personal_no used as OFFSET into chain-added sequence (not additive to a,b)
- Checkerboard alphabet derived by sorting A-Z by chain-addition driver digits
- Fixed 10-digit transposition keys (vs standard VIC variable-length a,b)
- K2 coordinate concatenations as keygroup candidates
- Disrupted diagonal variant: fill down-right from (start_row, 0)

Based on user-provided VIC implementation with bugs fixed:
- Fixed: diagonal decryption now uses proper inverse (not columnar_untranspose)
- Fixed: keygroup iterator reset per phrase
- Fixed: both standard and offset key schedules tested
"""

import sys
import os
import json
import time
import math
from pathlib import Path
from multiprocessing import Pool, cpu_count

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ========================================================================
# VIC PRIMITIVES
# ========================================================================

def phrase_to_digits(phrase):
    """Sequence first 10 chars of phrase alphabetically. Returns 10 digits (0-9)."""
    p = phrase.upper().replace(" ", "")[:10]
    while len(p) < 10:
        p += 'A'
    indexed = sorted(range(len(p)), key=lambda i: (p[i], i))
    digits = [0] * len(p)
    for rank, idx in enumerate(indexed):
        digits[idx] = rank % 10
    return digits


def chain_add(seed, target_len):
    """Non-carrying mod-10 chain addition (lagged Fibonacci)."""
    result = list(seed)
    while len(result) < target_len:
        result.append((result[-1] + result[-2]) % 10)
    return result[:target_len]


def derive_column_order(key_digits):
    """Key digits -> column reading order (lowest digit read first, ties left-to-right)."""
    return sorted(range(len(key_digits)), key=lambda i: (key_digits[i], i))


# ========================================================================
# CHECKERBOARD (alphabet sorted by chain-add driver)
# ========================================================================

def build_checkerboard_sorted(driver_digits, top_row_letters):
    """Build checkerboard with alphabet sorted by driver digits.

    top_row_letters: 10-char string, '_' marks 2 blank positions.
    driver_digits: 26+ digits used to sort the alphabet.
    """
    top = top_row_letters.upper()
    if len(top) != 10:
        return None, None, None

    blank_cols = [i for i, c in enumerate(top) if c in ('_', ' ', '.')]
    if len(blank_cols) != 2:
        return None, None, None

    # Sort alphabet by driver digits
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if len(driver_digits) >= 26:
        sorted_alpha = ''.join(c for _, c in sorted(zip(driver_digits[:26], alpha)))
    else:
        sorted_alpha = alpha

    encode = {}
    decode = {}
    alpha_iter = iter(sorted_alpha)

    # Row 0: single-digit codes at non-blank columns
    for col in range(10):
        if col not in blank_cols:
            try:
                letter = next(alpha_iter)
                code = str(col)
                encode[letter] = code
                decode[code] = letter
            except StopIteration:
                break

    # Rows 1-2: two-digit codes using blank cols as prefixes
    for prefix_col in blank_cols:
        for col in range(10):
            try:
                letter = next(alpha_iter)
                code = f"{prefix_col}{col}"
                encode[letter] = code
                decode[code] = letter
            except StopIteration:
                break

    prefix_set = {str(blank_cols[0]), str(blank_cols[1])}
    return encode, decode, prefix_set


def build_checkerboard_standard(top_row_letters):
    """Build checkerboard with remaining alphabet in standard order (no driver sort)."""
    top = top_row_letters.upper()
    if len(top) != 10:
        return None, None, None

    blank_cols = [i for i, c in enumerate(top) if c in ('_', ' ', '.')]
    if len(blank_cols) != 2:
        return None, None, None

    # Non-blank letters in top row
    top_letters = set()
    for i, c in enumerate(top):
        if c not in ('_', ' ', '.'):
            top_letters.add(c)

    # Remaining alphabet
    remaining = [c for c in ALPH if c not in top_letters]

    encode = {}
    decode = {}

    # Row 0
    letter_idx = 0
    for col in range(10):
        if col not in blank_cols:
            letter = top[col]
            if letter not in ('_', ' ', '.'):
                code = str(col)
                encode[letter] = code
                decode[code] = letter

    # Rows 1-2
    rem_iter = iter(remaining)
    for prefix_col in blank_cols:
        for col in range(10):
            try:
                letter = next(rem_iter)
                code = f"{prefix_col}{col}"
                encode[letter] = code
                decode[code] = letter
            except StopIteration:
                break

    prefix_set = {str(blank_cols[0]), str(blank_cols[1])}
    return encode, decode, prefix_set


def cb_decode(digit_str, decode_table, prefix_set):
    """Decode digit string through checkerboard."""
    result = []
    i = 0
    while i < len(digit_str):
        if digit_str[i] in prefix_set and i + 1 < len(digit_str):
            code = digit_str[i:i+2]
            result.append(decode_table.get(code, '?'))
            i += 2
        else:
            result.append(decode_table.get(digit_str[i], '?'))
            i += 1
    return ''.join(result)


def cb_encode(text, encode_table):
    """Encode text to digit string through checkerboard."""
    return ''.join(encode_table.get(c, '') for c in text.upper())


# ========================================================================
# TRANSPOSITIONS
# ========================================================================

def columnar_decrypt(text, key_digits):
    """Inverse columnar transposition."""
    n_cols = len(key_digits)
    n = len(text)
    n_rows = math.ceil(n / n_cols)
    short_cols = n_rows * n_cols - n
    col_order = derive_column_order(key_digits)

    # Column lengths
    col_len = {}
    for c in range(n_cols):
        col_len[c] = n_rows - (1 if c >= n_cols - short_cols and short_cols > 0 else 0)

    # Fill columns in key order
    cols = {}
    pos = 0
    for c in col_order:
        cl = col_len[c]
        cols[c] = list(text[pos:pos + cl])
        pos += cl

    # Read row by row
    result = []
    for r in range(n_rows):
        for c in range(n_cols):
            if r < len(cols.get(c, [])):
                result.append(cols[c][r])
    return ''.join(result)


def disrupted_diagonal_decrypt(text, key_digits):
    """Inverse of diagonal-fill disrupted transposition.

    Fill pattern: for each start_row, fill diagonally down-right from (start_row, 0).
    Then fill remaining cells row-by-row.
    """
    n_cols = len(key_digits)
    n = len(text)
    n_rows = math.ceil(n / n_cols)

    # Reconstruct fill order
    filled = [[False] * n_cols for _ in range(n_rows)]
    fill_order = []
    count = 0

    # Diagonal fill phase
    for start_row in range(n_rows):
        row, col = start_row, 0
        while col < n_cols and count < n:
            if not filled[row][col]:
                filled[row][col] = True
                fill_order.append((row, col))
                count += 1
            row += 1
            col += 1
            if row >= n_rows:
                break

    # Row-by-row fill phase for remaining cells
    for r in range(n_rows):
        for c in range(n_cols):
            if not filled[r][c] and count < n:
                filled[r][c] = True
                fill_order.append((r, c))
                count += 1

    # Count cells per column
    col_counts = [0] * n_cols
    for r, c in fill_order:
        col_counts[c] += 1

    # Distribute ciphertext into columns in key order
    col_order = derive_column_order(key_digits)
    cols = {}
    pos = 0
    for c in col_order:
        cl = col_counts[c]
        cols[c] = list(text[pos:pos + cl])
        pos += cl

    # Reconstruct grid
    grid = [[None] * n_cols for _ in range(n_rows)]
    col_read = [0] * n_cols
    for r, c in fill_order:
        if col_read[c] < len(cols.get(c, [])):
            grid[r][c] = cols[c][col_read[c]]
            col_read[c] += 1

    # Read in fill order
    result = []
    for r, c in fill_order:
        if grid[r][c] is not None:
            result.append(grid[r][c])
    return ''.join(result)


# ========================================================================
# KEY SCHEDULES
# ========================================================================

def keyschedule_offset(phrase, date_str, personal_no, keygroup_str):
    """Non-standard key schedule: personal_no as offset into chain-added sequence.

    1. Phrase -> 10 digits (sequencing)
    2. Chain-add to 50
    3. Extract 10 digits at personal_no offset, subtract date
    4. Add keygroup to first 5
    5. Chain-add to 60
    6. Split: columnar_key[0:10], diagonal_key[10:20], cb_driver[20:46]
    """
    seed = phrase_to_digits(phrase)
    expanded = chain_add(seed, 50)
    offset = personal_no % len(expanded)
    window = expanded[offset:offset + 10]
    if len(window) < 10:
        window = window + expanded[:10 - len(window)]

    # Subtract date (cyclic over 6 digits)
    date_digits = [int(c) for c in date_str[:6]]
    after_date = [(window[i] - date_digits[i % 6]) % 10 for i in range(10)]

    # Add keygroup
    kg = [int(c) for c in keygroup_str[:5]]
    after_kg = list(after_date)
    for i in range(5):
        after_kg[i] = (after_kg[i] + kg[i]) % 10

    # Second chain add
    final = chain_add(after_kg, 60)
    return final[0:10], final[10:20], final[20:46]


def keyschedule_standard_fixed10(phrase, date_str, personal_no, keygroup_str):
    """Standard-ish VIC key schedule but with fixed 10-digit keys.

    Uses the standard VIC Line-A through Line-H derivation,
    then chain-adds to 60 and splits into fixed 10-digit keys.
    """
    seed = phrase_to_digits(phrase)
    kg = [int(c) for c in keygroup_str[:5]]
    date5 = [int(c) for c in date_str[:5]]

    # Line-C = (keygroup - date[:5]) mod 10
    line_c = [(kg[i] - date5[i]) % 10 for i in range(5)]

    # Chain add Line-C to 10
    line_f = chain_add(line_c, 10)

    # Line-G = (seed + line_f) mod 10
    line_g = [(seed[i] + line_f[i]) % 10 for i in range(10)]

    # Sequence second half of phrase
    phrase_upper = phrase.upper().replace(" ", "")
    if len(phrase_upper) >= 20:
        e2 = phrase_to_digits(phrase_upper[10:20])
    else:
        e2 = list(range(10))

    # Line-H = encode G through E.2
    line_h = [e2[(line_g[i] - 1) % 10] for i in range(10)]

    # Chain add to 60
    final = chain_add(line_h, 60)

    # Add personal_no offset
    pn_offset = personal_no % 40
    col_key = final[pn_offset:pn_offset + 10]
    if len(col_key) < 10:
        col_key = col_key + final[:10 - len(col_key)]
    diag_key = final[pn_offset + 10:pn_offset + 20]
    if len(diag_key) < 10:
        diag_key = diag_key + final[:10 - len(diag_key)]
    cb_driver = final[20:46]

    return col_key, diag_key, cb_driver


# ========================================================================
# CT -> DIGIT MAPPINGS
# ========================================================================

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

DIGIT_MAPS = {
    "AZ0": lambda ct: ''.join(str(ALPH_IDX[c] % 10) for c in ct),
    "AZ1": lambda ct: ''.join(str((ALPH_IDX[c] + 1) % 10) for c in ct),
    "KA0": lambda ct: ''.join(str(KA_IDX[c] % 10) for c in ct),
    "KA1": lambda ct: ''.join(str((KA_IDX[c] + 1) % 10) for c in ct),
}

CT_DIGITS = {name: fn(CT) for name, fn in DIGIT_MAPS.items()}

# ========================================================================
# SCORING
# ========================================================================

ENE = "EASTNORTHEAST"
BC = "BERLINCLOCK"

def score_free(pt):
    s = 0
    if ENE in pt:
        s += 13
    if BC in pt:
        s += 11
    return s

def score_anchored(pt):
    total = 0
    if len(pt) >= 34:
        for i, ch in enumerate(ENE):
            if 21 + i < len(pt) and pt[21 + i] == ch:
                total += 1
    if len(pt) >= 74:
        for i, ch in enumerate(BC):
            if 63 + i < len(pt) and pt[63 + i] == ch:
                total += 1
    return total

# ========================================================================
# PARAMETERS
# ========================================================================

PHRASES = [
    "PALIMPSEST", "ABSCISSA", "KRYPTOS", "DEFECTOR",
    "VIRTUALLYINVISIBLE", "LUCIDMEMORY", "SHADOWFORCES",
    "BETWEENSUBTLESHADING", "ITWASTOTALLYINVISIBL",
    "SLOWLYDESPARATLYSLOW", "KRYPTOSABCDEFGHIJLMN",
    "EASTNORTHEASTBERLINC", "THEANSWERISTWOSYSTEM",
    "BERLINCLOCKWALLNORTH", "SANBORNSCULPTUREKRYP",
    "PALIMPSESTABSCISSAKR", "TWOSYSTEMSOFENCIPHER",
]

DATES = ["091189", "110989"]

PERSONAL_NOS = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

# Top rows: 8 letters + 2 blanks ('_')
TOP_ROWS = [
    "ENDRYAHR_.",    # NDYAHR front + 2 blanks
    "RHAYDNE._",    # NDYAHR reversed + 2 blanks
    "ADEHONRY_.",   # Alphabetical + 2 blanks
    "ETAOINSR_.",   # English freq + 2 blanks
    "ASINTOER_.",   # Classic VIC top row + 2 blanks
    "EORNDYAH._",  # By K4 frequency + 2 blanks
]

# K2 coordinate keygroups + thematic
KEYGROUPS_THEMATIC = [
    "38574", "38576", "57644", "38564", "06544",
    "11001", "10000", "00007", "01008", "10100",
    "90271", "02741", "73241", "00000", "12345",
]

KEY_SCHEDULES = [
    ("offset", keyschedule_offset),
    ("standard_fixed10", keyschedule_standard_fixed10),
]

# ========================================================================
# WORKER
# ========================================================================

def worker(args):
    """Process a batch of keygroups for one (phrase, date, pn, keysched) combo."""
    phrase, date_str, pn, ks_name, ks_fn, kg_start, kg_end, top_rows = args

    results = []
    configs = 0

    for kg_int in range(kg_start, kg_end):
        kg_str = f"{kg_int:05d}"

        try:
            col_key, diag_key, cb_driver = ks_fn(phrase, date_str, pn, kg_str)
        except Exception:
            continue

        for top_row in top_rows:
            # Two checkerboard modes: sorted by driver, and standard
            for cb_mode in ["sorted", "standard"]:
                if cb_mode == "sorted":
                    enc, dec, pf = build_checkerboard_sorted(cb_driver, top_row)
                else:
                    enc, dec, pf = build_checkerboard_standard(top_row)

                if enc is None:
                    continue

                for dm_name, ct_digits in CT_DIGITS.items():
                    configs += 1

                    # Full pipeline: undo diagonal, undo columnar, CB decode
                    try:
                        step1 = disrupted_diagonal_decrypt(ct_digits, diag_key)
                        step2 = columnar_decrypt(step1, col_key)
                        pt = cb_decode(step2, dec, pf)
                    except Exception:
                        continue

                    fs = score_free(pt)
                    anch = score_anchored(pt)
                    if fs >= 11 or anch >= 8:
                        results.append({
                            'score_free': fs, 'score_anchored': anch,
                            'phrase': phrase[:20], 'date': date_str,
                            'pn': pn, 'kg': kg_str, 'ks': ks_name,
                            'top_row': top_row, 'cb': cb_mode, 'dm': dm_name,
                            'pt': pt[:80], 'pt_len': len(pt),
                        })

                    # Also try: columnar only (skip diagonal)
                    configs += 1
                    try:
                        step_col = columnar_decrypt(ct_digits, col_key)
                        pt_col = cb_decode(step_col, dec, pf)
                    except Exception:
                        continue

                    fs2 = score_free(pt_col)
                    anch2 = score_anchored(pt_col)
                    if fs2 >= 11 or anch2 >= 8:
                        results.append({
                            'score_free': fs2, 'score_anchored': anch2,
                            'phrase': phrase[:20], 'date': date_str,
                            'pn': pn, 'kg': kg_str, 'ks': ks_name,
                            'top_row': top_row, 'cb': cb_mode, 'dm': dm_name,
                            'pt': pt_col[:80], 'pt_len': len(pt_col),
                            'mode': 'columnar_only',
                        })

    return results, configs


# ========================================================================
# MAIN
# ========================================================================

def run():
    t0 = time.time()
    ncores = min(cpu_count(), 28)

    print("=" * 72)
    print("VIC NON-STANDARD KEY SCHEDULE SWEEP")
    print("=" * 72)
    print(f"CT: {CT[:40]}... ({CT_LEN} chars)")
    print(f"Cores: {ncores}")
    print(f"Phrases: {len(PHRASES)}")
    print(f"Dates: {len(DATES)}")
    print(f"Personal numbers: {len(PERSONAL_NOS)}")
    print(f"Top rows: {len(TOP_ROWS)}")
    print(f"Key schedules: {len(KEY_SCHEDULES)}")
    print(f"Digit mappings: {len(CT_DIGITS)}")
    print(f"CB modes: 2 (sorted + standard)")

    # Phase 1: Thematic keygroups (fast)
    print(f"\n--- PHASE 1: Thematic keygroups ({len(KEYGROUPS_THEMATIC)}) ---")
    p1_work = []
    for phrase in PHRASES:
        for date_str in DATES:
            for pn in PERSONAL_NOS:
                for ks_name, ks_fn in KEY_SCHEDULES:
                    # Pack thematic keygroups as individual integers
                    for kg_str in KEYGROUPS_THEMATIC:
                        kg_int = int(kg_str)
                        p1_work.append((phrase, date_str, pn, ks_name, ks_fn,
                                       kg_int, kg_int + 1, TOP_ROWS))

    print(f"Work items: {len(p1_work)}")
    all_results = []
    total_configs = 0

    with Pool(ncores) as pool:
        for batch_results, batch_configs in pool.imap_unordered(worker, p1_work, chunksize=32):
            all_results.extend(batch_results)
            total_configs += batch_configs

    p1_time = time.time() - t0
    best_p1 = max((max(r['score_free'], r['score_anchored']) for r in all_results), default=0)
    print(f"Phase 1: {total_configs:,} configs, {len(all_results)} hits, "
          f"best={best_p1}/24, {p1_time:.1f}s")

    # Phase 2: Brute-force all 100K keygroups (top phrases + dates only)
    print(f"\n--- PHASE 2: Brute-force 100K keygroups ---")
    TOP_PHRASES = PHRASES[:8]  # Most promising phrases
    BATCH_SIZE = 500

    p2_work = []
    for phrase in TOP_PHRASES:
        for date_str in DATES:
            for pn in [5]:  # Focus on PN=5 (FIVE)
                for ks_name, ks_fn in KEY_SCHEDULES:
                    for kg_start in range(0, 100_000, BATCH_SIZE):
                        p2_work.append((phrase, date_str, pn, ks_name, ks_fn,
                                       kg_start, min(kg_start + BATCH_SIZE, 100_000),
                                       TOP_ROWS))

    print(f"Work items: {len(p2_work)}")
    p2_t0 = time.time()
    p2_configs = 0
    batches_done = 0

    with Pool(ncores) as pool:
        for batch_results, batch_configs in pool.imap_unordered(worker, p2_work, chunksize=4):
            all_results.extend(batch_results)
            p2_configs += batch_configs
            total_configs += batch_configs
            batches_done += 1

            if batches_done % 500 == 0:
                elapsed = time.time() - p2_t0
                pct = 100 * batches_done / len(p2_work)
                best = max((max(r['score_free'], r['score_anchored']) for r in all_results), default=0)
                print(f"  [{pct:5.1f}%] {batches_done}/{len(p2_work)} | "
                      f"{p2_configs:,} configs | {len(all_results)} hits | "
                      f"best={best}/24 | {elapsed:.0f}s", flush=True)

    p2_time = time.time() - p2_t0
    total_time = time.time() - t0

    # Sort results
    all_results.sort(key=lambda r: max(r['score_free'], r['score_anchored']), reverse=True)

    # Summary
    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print(f"Total configs: {total_configs:,}")
    print(f"Phase 1 (thematic): {p1_time:.1f}s")
    print(f"Phase 2 (brute-force): {p2_configs:,} configs, {p2_time:.1f}s")
    print(f"Total time: {total_time:.1f}s ({total_time/60:.1f}m)")
    print(f"Results: {len(all_results)} hits")

    best_score = max((max(r['score_free'], r['score_anchored']) for r in all_results), default=0)
    print(f"Best score: {best_score}/24")

    if all_results:
        print(f"\nTop 30:")
        for i, r in enumerate(all_results[:30]):
            sc = max(r['score_free'], r['score_anchored'])
            print(f"  {i+1:3d}. {sc:2d}/24 (free={r['score_free']}, anch={r['score_anchored']}) | "
                  f"{r['ks']} {r['phrase']} {r['date']} pn={r['pn']} kg={r['kg']} "
                  f"{r['cb']} {r['dm']} | PT: {r['pt'][:45]}")

    verdict = "SIGNAL" if best_score >= 18 else ("INTERESTING" if best_score >= 10 else "NOISE")
    print(f"\nVERDICT: {verdict}")

    # Save
    out_path = Path(__file__).resolve().parents[2] / "results" / "f_vic_nonstandard_keyschedule_v1.json"
    os.makedirs(out_path.parent, exist_ok=True)
    output = {
        'experiment': 'f_vic_nonstandard_keyschedule_v1',
        'description': 'VIC non-standard key schedule (personal_no as offset, CB alphabet from chain-add sort)',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'elapsed_seconds': round(total_time, 1),
        'best_score': best_score,
        'verdict': verdict,
        'top_50': all_results[:50],
    }
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    run()
