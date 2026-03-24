#!/usr/bin/env python3 -u
"""
Cipher: ITA-2/Baudot mod-31 reflective encoding
Family: novel
Status: active
Keyspace: ~9 keywords x 6 models x 3 widths = ~162 base configs + grid permutations
Last run:
Best score:
"""
"""
e_baudot_mod31_01.py -- ITA-2/Baudot mod-31 reflective encoding for K4.

HYPOTHESIS (Edward Hannon, kryptos mailing list 2011):
- The Kryptos sculpture has 31 characters per line width
- ITA-2 (Baudot) uses 5-bit codes (values 0-31)
- Mod-31 arithmetic maps naturally to the sculpture's physical layout
- Letters are encoded as their ITA-2 values, then processed mod 31
- The reflective property: encoding and decoding use the same operation (like Beaufort)

MODELS TESTED:
1. ITA-2 encoding + mod-31 Vigenere: (CT_ita2 - KEY_ita2) mod 31, map back
2. ITA-2 encoding + mod-31 Beaufort: (KEY_ita2 - CT_ita2) mod 31
3. Standard A=0 encoding + mod-31: standard 0-25 but arithmetic mod 31
4. Line-width transposition: CT into 31-wide grid, column permutations
5. Mod-31 position-dependent key: key[i] = (keyword_val * i) mod 31
6. Mixed: ITA-2 encode, keyword Beaufort mod 31, decode via ITA-2

Keywords: KRYPTOS, PALIMPSEST, ABSCISSA, DEFECTOR, SHADOW, BERLIN, SCHEIDT, SANBORN, SCHEIDTQ
Grid widths: 30, 31, 32

All positions 0-indexed. Results: results/baudot_mod31_YYYYMMDD.json
"""

import sys
import os
import json
import datetime
import itertools

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, MOD, ALPH, ALPH_IDX
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# ============================================================================
# ENCODINGS
# ============================================================================

# Standard A=0..Z=25
AZ_ENCODE = {c: i for i, c in enumerate(ALPH)}
AZ_DECODE = {i: c for i, c in enumerate(ALPH)}

# ITA-2 / Baudot Telegraph Code (letters only, 5-bit: values 0-30)
ITA2_ENCODE = {
    'A': 3,  'B': 25, 'C': 14, 'D': 9,
    'E': 1,  'F': 13, 'G': 26, 'H': 20,
    'I': 6,  'J': 11, 'K': 15, 'L': 18,
    'M': 28, 'N': 12, 'O': 24, 'P': 22,
    'Q': 23, 'R': 10, 'S': 5,  'T': 16,
    'U': 7,  'V': 30, 'W': 19, 'X': 29,
    'Y': 21, 'Z': 17,
}
# Reverse: value -> letter (only for values that map to a letter)
ITA2_DECODE = {v: k for k, v in ITA2_ENCODE.items()}

# ============================================================================
# KEYWORDS
# ============================================================================

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SHADOW",
    "BERLIN", "SCHEIDT", "SANBORN", "SCHEIDTQ",
]

# ============================================================================
# SCORING
# ============================================================================

REPORT_THRESHOLD = 10


def evaluate(pt_str, method_desc):
    """Score a plaintext candidate. Returns dict or None."""
    if not pt_str or len(pt_str) < 10:
        return None
    # Filter out strings that are mostly non-alpha (from bad mapping)
    alpha_count = sum(1 for c in pt_str if c in ALPH_IDX)
    if alpha_count < len(pt_str) * 0.5:
        return None
    try:
        anchored = score_candidate(pt_str)
        free = score_candidate_free(pt_str)
    except Exception:
        return None
    return {
        'plaintext': pt_str,
        'pt_len': len(pt_str),
        'method': method_desc,
        'crib_score_anchored': anchored.crib_score,
        'crib_score_free': free.crib_score,
        'crib_classification': anchored.crib_classification,
    }


# ============================================================================
# MODEL 1: ITA-2 encoding + mod-31 Vigenere
# ============================================================================

def model_ita2_vig31(ct, keyword):
    """(CT_ita2 - KEY_ita2) mod 31, map back via ITA2_DECODE."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = ITA2_ENCODE.get(c)
        key_val = ITA2_ENCODE.get(keyword[i % key_len])
        if ct_val is None or key_val is None:
            pt_chars.append('?')
            continue
        pt_val = (ct_val - key_val) % 31
        pt_ch = ITA2_DECODE.get(pt_val)
        if pt_ch is None:
            pt_chars.append('?')
        else:
            pt_chars.append(pt_ch)
    return ''.join(pt_chars)


# ============================================================================
# MODEL 2: ITA-2 encoding + mod-31 Beaufort
# ============================================================================

def model_ita2_beau31(ct, keyword):
    """(KEY_ita2 - CT_ita2) mod 31, map back via ITA2_DECODE."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = ITA2_ENCODE.get(c)
        key_val = ITA2_ENCODE.get(keyword[i % key_len])
        if ct_val is None or key_val is None:
            pt_chars.append('?')
            continue
        pt_val = (key_val - ct_val) % 31
        pt_ch = ITA2_DECODE.get(pt_val)
        if pt_ch is None:
            pt_chars.append('?')
        else:
            pt_chars.append(pt_ch)
    return ''.join(pt_chars)


# ============================================================================
# MODEL 3: Standard A=0 encoding + mod-31 arithmetic
# ============================================================================

def model_az_vig31(ct, keyword):
    """Standard encoding, (CT_az - KEY_az) mod 31, map back mod 26."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = AZ_ENCODE.get(c)
        key_val = AZ_ENCODE.get(keyword[i % key_len])
        if ct_val is None or key_val is None:
            pt_chars.append('?')
            continue
        pt_val = (ct_val - key_val) % 31
        # Map back: if >= 26, it wraps around
        pt_chars.append(ALPH[pt_val % 26])
    return ''.join(pt_chars)


def model_az_beau31(ct, keyword):
    """Standard encoding, (KEY_az - CT_az) mod 31, map back mod 26."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = AZ_ENCODE.get(c)
        key_val = AZ_ENCODE.get(keyword[i % key_len])
        if ct_val is None or key_val is None:
            pt_chars.append('?')
            continue
        pt_val = (key_val - ct_val) % 31
        pt_chars.append(ALPH[pt_val % 26])
    return ''.join(pt_chars)


def model_az_add31(ct, keyword):
    """Standard encoding, (CT_az + KEY_az) mod 31, map back mod 26."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = AZ_ENCODE.get(c)
        key_val = AZ_ENCODE.get(keyword[i % key_len])
        if ct_val is None or key_val is None:
            pt_chars.append('?')
            continue
        pt_val = (ct_val + key_val) % 31
        pt_chars.append(ALPH[pt_val % 26])
    return ''.join(pt_chars)


# ============================================================================
# MODEL 4: Line-width transposition (grid read-off)
# ============================================================================

def model_grid_transpose(ct, width, col_order=None):
    """
    Write CT into grid of given width, read off columns in col_order.
    If col_order is None, read columns left-to-right (identity).
    Returns reordered CT string.
    """
    nrows = (len(ct) + width - 1) // width
    # Pad with X
    padded = ct + 'X' * (nrows * width - len(ct))
    grid = [padded[r * width:(r + 1) * width] for r in range(nrows)]

    if col_order is None:
        col_order = list(range(width))

    result = []
    for col in col_order:
        for row in range(nrows):
            if col < len(grid[row]):
                result.append(grid[row][col])
    return ''.join(result)[:len(ct)]


def model_grid_row_read(ct, width):
    """
    Write CT into grid by columns, read off by rows.
    This is the inverse of columnar transposition.
    """
    nrows = (len(ct) + width - 1) // width
    ncols = width
    # Number of long columns (nrows chars) vs short columns (nrows-1 chars)
    n_long = len(ct) - (nrows - 1) * ncols
    if n_long < 0:
        n_long = ncols

    # Fill columns
    grid = [[''] * ncols for _ in range(nrows)]
    idx = 0
    for col in range(ncols):
        col_len = nrows if col < n_long else nrows - 1
        for row in range(col_len):
            if idx < len(ct):
                grid[row][col] = ct[idx]
                idx += 1

    # Read rows
    result = []
    for row in range(nrows):
        for col in range(ncols):
            if grid[row][col]:
                result.append(grid[row][col])
    return ''.join(result)[:len(ct)]


def keyword_col_order(keyword, width):
    """Generate column order from keyword for grid of given width.
    Keyword is repeated/truncated to width, then columns sorted alphabetically.
    Returns permutation: col_order[i] = which column to read i-th."""
    kw = (keyword * ((width // len(keyword)) + 1))[:width]
    # Sort columns by keyword character (stable sort preserves order for ties)
    indexed = list(enumerate(kw))
    indexed.sort(key=lambda x: x[1])
    col_order = [idx for idx, _ in indexed]
    return col_order


# ============================================================================
# MODEL 5: Mod-31 position-dependent key
# ============================================================================

def model_pos_dep_31(ct, keyword):
    """key[i] = (keyword_val[i%len(kw)] * i) mod 31, then Vigenere decrypt mod 26."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = AZ_ENCODE.get(c)
        kw_val = AZ_ENCODE.get(keyword[i % key_len])
        if ct_val is None or kw_val is None:
            pt_chars.append('?')
            continue
        key_i = (kw_val * i) % 31
        pt_val = (ct_val - key_i) % 26
        pt_chars.append(ALPH[pt_val])
    return ''.join(pt_chars)


def model_pos_dep_31_beau(ct, keyword):
    """key[i] = (keyword_val[i%len(kw)] * i) mod 31, then Beaufort decrypt mod 26."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = AZ_ENCODE.get(c)
        kw_val = AZ_ENCODE.get(keyword[i % key_len])
        if ct_val is None or kw_val is None:
            pt_chars.append('?')
            continue
        key_i = (kw_val * i) % 31
        pt_val = (key_i - ct_val) % 26
        pt_chars.append(ALPH[pt_val])
    return ''.join(pt_chars)


# ============================================================================
# MODEL 6: Mixed ITA-2 encode, Beaufort mod-31, ITA-2 decode
# ============================================================================

def model_mixed_ita2_beau31(ct, keyword):
    """ITA-2 encode CT and KEY, (KEY - CT) mod 31, ITA-2 decode result."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = ITA2_ENCODE.get(c)
        key_val = ITA2_ENCODE.get(keyword[i % key_len])
        if ct_val is None or key_val is None:
            pt_chars.append('?')
            continue
        result = (key_val - ct_val) % 31
        pt_ch = ITA2_DECODE.get(result)
        if pt_ch is None:
            pt_chars.append('?')
        else:
            pt_chars.append(pt_ch)
    return ''.join(pt_chars)


def model_mixed_ita2_vig31(ct, keyword):
    """ITA-2 encode CT and KEY, (CT - KEY) mod 31, ITA-2 decode result."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = ITA2_ENCODE.get(c)
        key_val = ITA2_ENCODE.get(keyword[i % key_len])
        if ct_val is None or key_val is None:
            pt_chars.append('?')
            continue
        result = (ct_val - key_val) % 31
        pt_ch = ITA2_DECODE.get(result)
        if pt_ch is None:
            pt_chars.append('?')
        else:
            pt_chars.append(pt_ch)
    return ''.join(pt_chars)


def model_mixed_ita2_add31(ct, keyword):
    """ITA-2 encode CT and KEY, (CT + KEY) mod 31, ITA-2 decode result."""
    key_len = len(keyword)
    pt_chars = []
    for i, c in enumerate(ct):
        ct_val = ITA2_ENCODE.get(c)
        key_val = ITA2_ENCODE.get(keyword[i % key_len])
        if ct_val is None or key_val is None:
            pt_chars.append('?')
            continue
        result = (ct_val + key_val) % 31
        pt_ch = ITA2_DECODE.get(result)
        if pt_ch is None:
            pt_chars.append('?')
        else:
            pt_chars.append(pt_ch)
    return ''.join(pt_chars)


# ============================================================================
# MAIN SWEEP
# ============================================================================

def run_sweep():
    print(f"K4 CT ({CT_LEN} chars): {CT}")
    print(f"Keywords: {KEYWORDS}")
    print(f"ITA-2 encoding covers values 1-30 (26 letters mapped to 5-bit codes)")
    print(f"ITA-2 unmapped mod-31 values: {sorted(set(range(31)) - set(ITA2_ENCODE.values()))}")
    print()

    best_anchored = {'crib_score_anchored': -1}
    best_free = {'crib_score_free': -1}
    results_above_threshold = []
    total_tested = 0

    # ========================================================================
    # MODELS 1-2: ITA-2 + mod-31 Vigenere/Beaufort
    # ========================================================================
    print("=" * 72)
    print("MODELS 1-2: ITA-2 encoding + mod-31 Vigenere/Beaufort")
    print("=" * 72)

    for kw in KEYWORDS:
        for model_name, model_fn in [
            ("ITA2_vig31", model_ita2_vig31),
            ("ITA2_beau31", model_ita2_beau31),
        ]:
            total_tested += 1
            pt = model_fn(CT, kw)
            method = f"{model_name}|key={kw}"

            # Filter out mostly-? results
            q_count = pt.count('?')
            if q_count > len(pt) * 0.5:
                continue

            # Replace ? with X for scoring
            pt_clean = pt.replace('?', 'X')
            result = evaluate(pt_clean, method)
            if result:
                result['unmapped_count'] = q_count
                max_s = max(result['crib_score_anchored'], result['crib_score_free'])
                if max_s >= REPORT_THRESHOLD:
                    results_above_threshold.append(result)
                    print(f"  ** SCORE {max_s}/24: {method} | PT={pt_clean[:60]}")
                if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                    best_anchored = result
                if result['crib_score_free'] > best_free['crib_score_free']:
                    best_free = result

    print(f"  Models 1-2: {total_tested} tested, best anchored={best_anchored.get('crib_score_anchored', 0)}")

    # ========================================================================
    # MODEL 3: Standard A=0 + mod-31
    # ========================================================================
    print("\n" + "=" * 72)
    print("MODEL 3: Standard A=0 encoding + mod-31 arithmetic")
    print("=" * 72)

    count_3 = 0
    for kw in KEYWORDS:
        for model_name, model_fn in [
            ("AZ_vig31", model_az_vig31),
            ("AZ_beau31", model_az_beau31),
            ("AZ_add31", model_az_add31),
        ]:
            total_tested += 1
            count_3 += 1
            pt = model_fn(CT, kw)
            method = f"{model_name}|key={kw}"
            result = evaluate(pt, method)
            if result:
                max_s = max(result['crib_score_anchored'], result['crib_score_free'])
                if max_s >= REPORT_THRESHOLD:
                    results_above_threshold.append(result)
                    print(f"  ** SCORE {max_s}/24: {method} | PT={pt[:60]}")
                if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                    best_anchored = result
                if result['crib_score_free'] > best_free['crib_score_free']:
                    best_free = result

    print(f"  Model 3: {count_3} tested")

    # ========================================================================
    # MODEL 4: Line-width transposition
    # ========================================================================
    print("\n" + "=" * 72)
    print("MODEL 4: Line-width grid transposition")
    print("=" * 72)

    WIDTHS = [30, 31, 32]
    count_4 = 0

    for width in WIDTHS:
        # 4a: Simple column read-off (identity permutation)
        total_tested += 1
        count_4 += 1
        pt = model_grid_transpose(CT, width)
        method = f"grid_col_read|width={width}"
        result = evaluate(pt, method)
        if result:
            max_s = max(result['crib_score_anchored'], result['crib_score_free'])
            if max_s >= REPORT_THRESHOLD:
                results_above_threshold.append(result)
                print(f"  ** SCORE {max_s}/24: {method} | PT={pt[:60]}")
            if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                best_anchored = result
            if result['crib_score_free'] > best_free['crib_score_free']:
                best_free = result

        # 4b: Reverse column read
        total_tested += 1
        count_4 += 1
        col_order = list(range(width - 1, -1, -1))
        pt = model_grid_transpose(CT, width, col_order)
        method = f"grid_col_rev|width={width}"
        result = evaluate(pt, method)
        if result:
            max_s = max(result['crib_score_anchored'], result['crib_score_free'])
            if max_s >= REPORT_THRESHOLD:
                results_above_threshold.append(result)
                print(f"  ** SCORE {max_s}/24: {method} | PT={pt[:60]}")
            if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                best_anchored = result
            if result['crib_score_free'] > best_free['crib_score_free']:
                best_free = result

        # 4c: Write by columns, read by rows (inverse columnar)
        total_tested += 1
        count_4 += 1
        pt = model_grid_row_read(CT, width)
        method = f"grid_row_read|width={width}"
        result = evaluate(pt, method)
        if result:
            max_s = max(result['crib_score_anchored'], result['crib_score_free'])
            if max_s >= REPORT_THRESHOLD:
                results_above_threshold.append(result)
                print(f"  ** SCORE {max_s}/24: {method} | PT={pt[:60]}")
            if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                best_anchored = result
            if result['crib_score_free'] > best_free['crib_score_free']:
                best_free = result

        # 4d: Keyword-keyed column permutations
        for kw in KEYWORDS:
            total_tested += 1
            count_4 += 1
            col_order = keyword_col_order(kw, width)
            pt = model_grid_transpose(CT, width, col_order)
            method = f"grid_kw_col|width={width}|key={kw}"
            result = evaluate(pt, method)
            if result:
                max_s = max(result['crib_score_anchored'], result['crib_score_free'])
                if max_s >= REPORT_THRESHOLD:
                    results_above_threshold.append(result)
                    print(f"  ** SCORE {max_s}/24: {method} | PT={pt[:60]}")
                if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                    best_anchored = result
                if result['crib_score_free'] > best_free['crib_score_free']:
                    best_free = result

            # Also try inverse: write by keyword-order columns, read rows
            total_tested += 1
            count_4 += 1
            inv_order = [0] * width
            for new_pos, old_pos in enumerate(col_order):
                inv_order[old_pos] = new_pos
            pt = model_grid_transpose(CT, width, inv_order)
            method = f"grid_kw_inv|width={width}|key={kw}"
            result = evaluate(pt, method)
            if result:
                max_s = max(result['crib_score_anchored'], result['crib_score_free'])
                if max_s >= REPORT_THRESHOLD:
                    results_above_threshold.append(result)
                    print(f"  ** SCORE {max_s}/24: {method} | PT={pt[:60]}")
                if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                    best_anchored = result
                if result['crib_score_free'] > best_free['crib_score_free']:
                    best_free = result

    print(f"  Model 4: {count_4} tested")

    # ========================================================================
    # MODEL 5: Mod-31 position-dependent key
    # ========================================================================
    print("\n" + "=" * 72)
    print("MODEL 5: Mod-31 position-dependent key")
    print("=" * 72)

    count_5 = 0
    for kw in KEYWORDS:
        for model_name, model_fn in [
            ("pos_dep_31_vig", model_pos_dep_31),
            ("pos_dep_31_beau", model_pos_dep_31_beau),
        ]:
            total_tested += 1
            count_5 += 1
            pt = model_fn(CT, kw)
            method = f"{model_name}|key={kw}"
            result = evaluate(pt, method)
            if result:
                max_s = max(result['crib_score_anchored'], result['crib_score_free'])
                if max_s >= REPORT_THRESHOLD:
                    results_above_threshold.append(result)
                    print(f"  ** SCORE {max_s}/24: {method} | PT={pt[:60]}")
                if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                    best_anchored = result
                if result['crib_score_free'] > best_free['crib_score_free']:
                    best_free = result

    print(f"  Model 5: {count_5} tested")

    # ========================================================================
    # MODEL 6: Mixed ITA-2/Beaufort/Vigenere mod-31
    # ========================================================================
    print("\n" + "=" * 72)
    print("MODEL 6: Mixed ITA-2 encode + mod-31 arithmetic + ITA-2 decode")
    print("=" * 72)

    count_6 = 0
    for kw in KEYWORDS:
        for model_name, model_fn in [
            ("mixed_ITA2_beau31", model_mixed_ita2_beau31),
            ("mixed_ITA2_vig31", model_mixed_ita2_vig31),
            ("mixed_ITA2_add31", model_mixed_ita2_add31),
        ]:
            total_tested += 1
            count_6 += 1
            pt = model_fn(CT, kw)
            method = f"{model_name}|key={kw}"

            q_count = pt.count('?')
            if q_count > len(pt) * 0.5:
                continue

            pt_clean = pt.replace('?', 'X')
            result = evaluate(pt_clean, method)
            if result:
                result['unmapped_count'] = q_count
                max_s = max(result['crib_score_anchored'], result['crib_score_free'])
                if max_s >= REPORT_THRESHOLD:
                    results_above_threshold.append(result)
                    print(f"  ** SCORE {max_s}/24: {method} | PT={pt_clean[:60]}")
                if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                    best_anchored = result
                if result['crib_score_free'] > best_free['crib_score_free']:
                    best_free = result

    print(f"  Model 6: {count_6} tested")

    # ========================================================================
    # BONUS: Grid transposition + substitution combos
    # ========================================================================
    print("\n" + "=" * 72)
    print("BONUS: Grid transposition (width 31) + mod-31 substitution")
    print("=" * 72)

    count_bonus = 0
    # First transpose with width 31, then apply mod-31 substitution
    for trans_kw in KEYWORDS[:5]:  # limit combos
        col_order = keyword_col_order(trans_kw, 31)
        transposed = model_grid_transpose(CT, 31, col_order)

        for sub_kw in KEYWORDS:
            for model_name, model_fn in [
                ("AZ_vig31", model_az_vig31),
                ("AZ_beau31", model_az_beau31),
                ("ITA2_beau31", model_ita2_beau31),
            ]:
                total_tested += 1
                count_bonus += 1
                pt = model_fn(transposed, sub_kw)
                method = f"grid31({trans_kw})+{model_name}|key={sub_kw}"

                q_count = pt.count('?')
                pt_clean = pt.replace('?', 'X')
                result = evaluate(pt_clean, method)
                if result:
                    max_s = max(result['crib_score_anchored'], result['crib_score_free'])
                    if max_s >= REPORT_THRESHOLD:
                        results_above_threshold.append(result)
                        print(f"  ** SCORE {max_s}/24: {method} | PT={pt_clean[:60]}")
                    if result['crib_score_anchored'] > best_anchored['crib_score_anchored']:
                        best_anchored = result
                    if result['crib_score_free'] > best_free['crib_score_free']:
                        best_free = result

    print(f"  Bonus: {count_bonus} tested")

    # ========================================================================
    # SUMMARY
    # ========================================================================

    print("\n" + "=" * 72)
    print("SWEEP COMPLETE")
    print(f"Total configs tested: {total_tested}")
    print(f"Results >= {REPORT_THRESHOLD}/24: {len(results_above_threshold)}")
    print()

    print("BEST ANCHORED SCORE:")
    if best_anchored.get('crib_score_anchored', -1) >= 0:
        print(f"  Score: {best_anchored['crib_score_anchored']}/24")
        print(f"  Method: {best_anchored.get('method', 'N/A')}")
        print(f"  PT: {best_anchored.get('plaintext', 'N/A')[:80]}")
    else:
        print("  No valid results")

    print("\nBEST FREE SCORE:")
    if best_free.get('crib_score_free', -1) >= 0:
        print(f"  Score: {best_free['crib_score_free']}/24")
        print(f"  Method: {best_free.get('method', 'N/A')}")
        print(f"  PT: {best_free.get('plaintext', 'N/A')[:80]}")
    else:
        print("  No valid results")

    # ========================================================================
    # SAVE
    # ========================================================================

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(_ROOT, "results", f"baudot_mod31_{timestamp}.json")

    output = {
        'timestamp': datetime.datetime.now().isoformat(),
        'hypothesis': 'ITA-2/Baudot mod-31 reflective encoding',
        'source': 'Edward Hannon, kryptos mailing list 2011',
        'ciphertext': CT,
        'total_tested': total_tested,
        'report_threshold': REPORT_THRESHOLD,
        'keywords_tested': KEYWORDS,
        'models_tested': [
            'ITA2_vig31', 'ITA2_beau31',
            'AZ_vig31', 'AZ_beau31', 'AZ_add31',
            'grid_transpose (widths 30,31,32)',
            'pos_dep_31_vig', 'pos_dep_31_beau',
            'mixed_ITA2_beau31', 'mixed_ITA2_vig31', 'mixed_ITA2_add31',
            'grid31+substitution combos',
        ],
        'widths_tested': [30, 31, 32],
        'best_anchored': best_anchored if best_anchored.get('crib_score_anchored', -1) >= 0 else None,
        'best_free': best_free if best_free.get('crib_score_free', -1) >= 0 else None,
        'results_above_threshold': sorted(
            results_above_threshold,
            key=lambda x: max(x.get('crib_score_anchored', 0),
                              x.get('crib_score_free', 0)),
            reverse=True
        )[:100],
        'conclusion': None,
    }

    max_anchored = best_anchored.get('crib_score_anchored', 0)
    max_free = best_free.get('crib_score_free', 0)
    best_overall = max(max_anchored, max_free)

    if best_overall >= 18:
        output['conclusion'] = 'SIGNAL -- investigate further'
    elif best_overall >= 10:
        output['conclusion'] = 'INTERESTING -- log for review'
    elif best_overall >= 6:
        output['conclusion'] = 'MARGINAL -- likely noise'
    else:
        output['conclusion'] = 'NOISE -- no crib matches above random expectation'

    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {out_path}")
    print(f"Conclusion: {output['conclusion']}")

    return output


if __name__ == '__main__':
    run_sweep()
