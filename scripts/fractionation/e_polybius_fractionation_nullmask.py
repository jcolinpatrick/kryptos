#!/usr/bin/env python3
"""
Cipher: Polybius fractionation
Family: fractionation
Status: active
Keyspace: ~500K+ configs
Last run: never
Best score: TBD
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""E-POLYBIUS-FRAC-NULLMASK: Polybius fractionation + null mask (two-system model)

HYPOTHESIS:
  36-37 PT letters -> Polybius fractionation (x2) -> 72-74 CT chars -> insert 23-25 nulls -> 97 carved chars

This is DISTINCT from prior fractionation eliminations which all assumed:
  - ADFGVX: eliminated by parity (97 is odd) -- BUT 72 is EVEN, so null-extracted works
  - Bifid 5x5: eliminated by 26-letter CT -- BUT 5x6 KA grid handles all 26
  - Bifid 6x6: eliminated by IC mismatch on raw 97 -- BUT null-extracted 72 untested

The fractionation-with-null-mask model has NEVER been tested.

TESTS:
  1. Direct Polybius decode on 72/73-char null-extracted text
  2. Bifid (period 5,7,8,13) on null-extracted text with KA and keyword-keyed grids
  3. ADFGVX-style (Polybius + undo columnar trans col5/col7) on null-extracted text
  4. Keyword-keyed Polybius squares (DEFECTOR, KRYPTOS, SEVEN, etc.)
  5. Half-length crib checking (if 2 CT chars = 1 PT char, cribs halved)
  6. Coordinate digit analysis (rows/cols as digit stream)

Run: PYTHONPATH=src python3 -u scripts/fractionation/e_polybius_fractionation_nullmask.py
"""

import sys
import os
import json
import time
import math
from collections import Counter
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, KRYPTOS_ALPHABET, ALPH, ALPH_IDX
from kryptos.kernel.scoring.ngram import NgramScorer

CT97 = CT
N = 97
KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ

# Load quadgram scorer
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
scorer = NgramScorer.from_file(QG_PATH)

# ─── Null mask definitions ───────────────────────────────────────────────
# 24-null consensus mask from MEMORY.md
MASK_24 = sorted([0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59,
                  74, 75, 78, 84, 85, 88, 94, 96])

# For 25-null: extend from 24-null by adding one more position
# Candidates: non-crib, non-consensus positions
CRIB_POS = set(CRIB_DICT.keys())
EXTRA_NULL_CANDIDATES = [i for i in range(97) if i not in MASK_24 and i not in CRIB_POS]

# ─── Polybius grid builders ─────────────────────────────────────────────

def build_5x6_grid(alphabet):
    """Build a 5-wide, 6-row grid (26 letters, last row has 1)."""
    grid = {}
    reverse = {}
    for i, ch in enumerate(alphabet):
        r, c = divmod(i, 5)
        grid[ch] = (r, c)
        reverse[(r, c)] = ch
    return grid, reverse

def build_5x5_grid(alphabet, merge='Z'):
    """Build a 5x5 grid by merging one letter. Returns grid + reverse."""
    # Remove the merge letter, mapping it to another
    reduced = []
    merge_target = None
    for ch in alphabet:
        if ch == merge:
            continue
        reduced.append(ch)
    if len(reduced) > 25:
        reduced = reduced[:25]
    grid = {}
    reverse = {}
    for i, ch in enumerate(reduced):
        r, c = divmod(i, 5)
        grid[ch] = (r, c)
        reverse[(r, c)] = ch
    # Map merged letter to same cell as its neighbor
    if merge not in grid:
        # Find closest letter in alphabet
        if merge == 'Z':
            grid['Z'] = grid.get('Y', (4, 4))
        elif merge == 'J':
            grid['J'] = grid.get('I', (1, 3))
        else:
            grid[merge] = (4, 4)
    return grid, reverse

def build_keyword_5x6(keyword):
    """Build 5x6 Polybius grid with keyword-mixed alphabet."""
    seen = set()
    alpha = []
    for ch in keyword.upper():
        if ch not in seen and ch.isalpha():
            seen.add(ch)
            alpha.append(ch)
    for ch in ALPH:
        if ch not in seen:
            seen.add(ch)
            alpha.append(ch)
    return build_5x6_grid(''.join(alpha))

def build_keyword_5x5(keyword, merge='Z'):
    """Build 5x5 Polybius grid with keyword-mixed alphabet, merging one letter."""
    seen = set()
    alpha = []
    for ch in keyword.upper():
        if ch not in seen and ch.isalpha() and ch != merge:
            seen.add(ch)
            alpha.append(ch)
    for ch in ALPH:
        if ch not in seen and ch != merge:
            seen.add(ch)
            alpha.append(ch)
    return build_5x5_grid(''.join(alpha), merge=merge)

# ─── Extract functions ───────────────────────────────────────────────────

def extract_with_mask(ct, null_positions):
    """Remove null positions from ciphertext."""
    return ''.join(ct[i] for i in range(len(ct)) if i not in set(null_positions))

def undo_columnar(text, width):
    """Undo columnar transposition: given text was read off columns, reconstruct rows."""
    n = len(text)
    nrows = math.ceil(n / width)
    full_cols = n % width if n % width != 0 else width
    if full_cols == 0:
        full_cols = width

    # Build columns
    cols = []
    idx = 0
    for c in range(width):
        col_len = nrows if c < full_cols else nrows - 1
        cols.append(text[idx:idx + col_len])
        idx += col_len

    # Read rows
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return ''.join(result)

def undo_columnar_keyed(text, key_order):
    """Undo keyed columnar transposition."""
    width = len(key_order)
    n = len(text)
    nrows = math.ceil(n / width)
    full_cols = n % width if n % width != 0 else width

    # Determine which columns are full vs short
    # key_order[i] = original column position for the i-th sorted column
    # Columns 0..full_cols-1 (in original order) are full
    sorted_cols = sorted(range(width), key=lambda x: key_order[x])

    cols = [''] * width
    idx = 0
    for rank in range(width):
        orig_col = sorted_cols[rank]
        col_len = nrows if orig_col < full_cols else nrows - 1
        cols[orig_col] = text[idx:idx + col_len]
        idx += col_len

    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return ''.join(result)

# ─── Polybius decoding functions ─────────────────────────────────────────

def polybius_decode_pairs(text, grid, reverse, pair_mode='sequential'):
    """Decode text by reading pairs of characters as Polybius coordinates.

    pair_mode:
      'sequential': (char0,char1), (char2,char3), ...
      'halves': first half = rows, second half = cols
    """
    if len(text) % 2 != 0:
        return None  # Odd length, can't pair

    result = []
    if pair_mode == 'sequential':
        for i in range(0, len(text), 2):
            ch1, ch2 = text[i], text[i + 1]
            if ch1 not in grid or ch2 not in grid:
                return None
            r1, c1 = grid[ch1]
            r2, c2 = grid[ch2]
            # Try: first char's row as row, second char's col as col
            coord = (r1, c2)
            if coord in reverse:
                result.append(reverse[coord])
            else:
                result.append('?')
    elif pair_mode == 'halves':
        half = len(text) // 2
        rows_text = text[:half]
        cols_text = text[half:]
        for i in range(half):
            ch_r, ch_c = rows_text[i], cols_text[i]
            if ch_r not in grid or ch_c not in grid:
                return None
            r, _ = grid[ch_r]
            _, c = grid[ch_c]
            coord = (r, c)
            if coord in reverse:
                result.append(reverse[coord])
            else:
                result.append('?')

    return ''.join(result) if result else None

def polybius_decode_direct(text, grid, reverse):
    """Decode pairs where first char gives row coordinate, second gives col coordinate."""
    if len(text) % 2 != 0:
        return None
    result = []
    for i in range(0, len(text), 2):
        ch1, ch2 = text[i], text[i + 1]
        if ch1 not in grid or ch2 not in grid:
            return None
        r, _ = grid[ch1]  # row from first char
        _, c = grid[ch2]  # col from second char
        coord = (r, c)
        if coord in reverse:
            result.append(reverse[coord])
        else:
            result.append('?')
    return ''.join(result)

def polybius_decode_reverse(text, grid, reverse):
    """Decode pairs where first char gives col, second gives row."""
    if len(text) % 2 != 0:
        return None
    result = []
    for i in range(0, len(text), 2):
        ch1, ch2 = text[i], text[i + 1]
        if ch1 not in grid or ch2 not in grid:
            return None
        _, c = grid[ch1]
        r, _ = grid[ch2]
        coord = (r, c)
        if coord in reverse:
            result.append(reverse[coord])
        else:
            result.append('?')
    return ''.join(result)

def bifid_decode(text, grid, reverse, period=None):
    """Decode using Bifid cipher (standard: rows then cols per group)."""
    n = len(text)
    if period is None:
        period = n  # Full-length bifid

    result = []
    for start in range(0, n, period):
        block = text[start:start + period]
        blen = len(block)

        # Get (row, col) for each CT character
        coords = []
        for ch in block:
            if ch not in grid:
                return None
            coords.append(grid[ch])

        # Extract row digits and col digits
        rows = [r for r, c in coords]
        cols = [c for r, c in coords]

        # Combined stream: all rows then all cols
        combined = rows + cols

        # Re-pair: take consecutive pairs
        for i in range(0, len(combined), 2):
            if i + 1 < len(combined):
                r, c = combined[i], combined[i + 1]
                coord = (r, c)
                if coord in reverse:
                    result.append(reverse[coord])
                else:
                    result.append('?')

    return ''.join(result) if result else None

def bifid_decode_reverse(text, grid, reverse, period=None):
    """Decode using reverse Bifid (cols then rows)."""
    n = len(text)
    if period is None:
        period = n

    result = []
    for start in range(0, n, period):
        block = text[start:start + period]
        blen = len(block)

        coords = []
        for ch in block:
            if ch not in grid:
                return None
            coords.append(grid[ch])

        rows = [r for r, c in coords]
        cols = [c for r, c in coords]

        # Combined: cols then rows
        combined = cols + rows

        for i in range(0, len(combined), 2):
            if i + 1 < len(combined):
                r, c = combined[i], combined[i + 1]
                coord = (r, c)
                if coord in reverse:
                    result.append(reverse[coord])
                else:
                    result.append('?')

    return ''.join(result) if result else None

# ─── Scoring and crib checking ───────────────────────────────────────────

def check_cribs_halflen(pt, ct_positions_kept):
    """Check if half-length cribs appear.

    Under Polybius fractionation, each PT char = 2 CT chars.
    So EASTNORTHEAST (13 PT chars) = 26 CT chars.
    BERLINCLOCK (11 PT chars) = 22 CT chars.

    The known crib positions in CT (21-33, 63-73) would encode only
    the first 6-7 PT chars of each crib under this model.
    """
    hits = []

    # Check if decoded PT contains fragments of cribs
    for crib_name, crib in [("ENE", "EASTNORTHEAST"), ("BCL", "BERLINCLOCK")]:
        for fraglen in range(3, len(crib) + 1):
            frag = crib[:fraglen]
            pos = pt.find(frag)
            if pos >= 0:
                hits.append((crib_name, frag, pos))
            # Also check for the crib anywhere
            if fraglen == len(crib):
                for p in range(len(pt) - len(crib) + 1):
                    if pt[p:p + len(crib)] == crib:
                        hits.append((crib_name + "_FULL", crib, p))

    return hits

def score_result(pt, method):
    """Score a plaintext candidate."""
    if pt is None or '?' in pt or len(pt) < 4:
        return -999, ""
    qg = scorer.score_per_char(pt)
    crib_hits = check_cribs_halflen(pt, None)
    return qg, crib_hits

# ─── Main tests ──────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 70)
    print("E-POLYBIUS-FRAC-NULLMASK: Polybius Fractionation + Null Mask")
    print("=" * 70)
    print(f"CT97: {CT97}")
    print(f"KA:   {KA}")
    print()

    results = {
        'experiment': 'E-POLYBIUS-FRAC-NULLMASK',
        'hypothesis': 'Polybius fractionation as inner cipher + null mask as outer layer',
        'model': '36-37 PT -> Polybius (x2) -> 72-74 CT -> insert 23-25 nulls -> 97 chars',
        'tests': {},
        'best_scores': [],
    }

    all_scores = []

    # ─── Build grids ─────────────────────────────────────────────────────

    keywords = {
        'KA': KA,
        'KRYPTOS': 'KRYPTOS',
        'DEFECTOR': 'DEFECTOR',
        'SEVEN': 'SEVEN',
        'PALIMPSEST': 'PALIMPSEST',
        'ABSCISSA': 'ABSCISSA',
        'KOMPASS': 'KOMPASS',
    }

    grids_5x6 = {}
    grids_5x5 = {}
    for name, kw in keywords.items():
        if name == 'KA':
            grids_5x6[name] = build_5x6_grid(KA)
        else:
            grids_5x6[name] = build_keyword_5x6(kw)
        grids_5x5[name] = build_keyword_5x5(kw, merge='Z')

    # ─── TEST 1: Direct Polybius decode on 73-char extract ───────────────

    print("\n" + "=" * 70)
    print("TEST 1: Direct Polybius decode on null-extracted text")
    print("=" * 70)

    extract73 = extract_with_mask(CT97, MASK_24)
    print(f"73-char extract: {extract73}")

    test1_results = []

    for grid_name, (grid, reverse) in grids_5x6.items():
        # 73 chars is odd, try dropping first or last
        for drop in ['first', 'last']:
            if drop == 'first':
                text72 = extract73[1:]
            else:
                text72 = extract73[:-1]

            for decode_name, decode_fn in [
                ('direct_pairs', polybius_decode_direct),
                ('reverse_pairs', polybius_decode_reverse),
                ('halves', lambda t, g, r: polybius_decode_pairs(t, g, r, 'halves')),
            ]:
                pt = decode_fn(text72, grid, reverse)
                if pt:
                    qg, hits = score_result(pt, f"{grid_name}_{decode_name}_drop{drop}")
                    entry = {
                        'grid': grid_name, 'decode': decode_name, 'drop': drop,
                        'pt': pt, 'qg_per_char': round(qg, 3),
                        'crib_hits': str(hits) if hits else 'none',
                        'pt_len': len(pt),
                    }
                    test1_results.append(entry)
                    all_scores.append((qg, f"T1:{grid_name}:{decode_name}:drop{drop}", pt))

    # Sort by quadgram
    test1_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTop 10 results (of {len(test1_results)}):")
    for r in test1_results[:10]:
        print(f"  qg={r['qg_per_char']:.3f} grid={r['grid']} decode={r['decode']} drop={r['drop']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test1_direct_decode'] = {
        'description': 'Direct Polybius decode on 73-char extract (drop first/last for 72)',
        'n_configs': len(test1_results),
        'top5': test1_results[:5],
    }

    # ─── TEST 2: 72-char models with various 25-null masks ───────────────

    print("\n" + "=" * 70)
    print("TEST 2: 72-char models (25 nulls = 36 Polybius pairs)")
    print("=" * 70)

    test2_results = []
    n_masks_tested = 0

    # Try extending the 24-null mask by adding one more null
    for extra_null in EXTRA_NULL_CANDIDATES[:40]:  # Test 40 candidates
        mask25 = sorted(MASK_24 + [extra_null])
        extract72 = extract_with_mask(CT97, mask25)

        if len(extract72) != 72:
            continue

        n_masks_tested += 1

        for grid_name in ['KA', 'KRYPTOS', 'DEFECTOR']:
            grid, reverse = grids_5x6[grid_name]

            for decode_name, decode_fn in [
                ('direct', polybius_decode_direct),
                ('reverse', polybius_decode_reverse),
                ('halves', lambda t, g, r: polybius_decode_pairs(t, g, r, 'halves')),
            ]:
                pt = decode_fn(extract72, grid, reverse)
                if pt:
                    qg, hits = score_result(pt, f"m25_{grid_name}_{decode_name}")
                    entry = {
                        'extra_null': extra_null,
                        'grid': grid_name, 'decode': decode_name,
                        'pt': pt, 'qg_per_char': round(qg, 3),
                        'crib_hits': str(hits) if hits else 'none',
                        'pt_len': len(pt),
                    }
                    test2_results.append(entry)
                    all_scores.append((qg, f"T2:m25+{extra_null}:{grid_name}:{decode_name}", pt))

    test2_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTested {n_masks_tested} masks x 3 grids x 3 decode modes = {len(test2_results)} configs")
    print(f"Top 10:")
    for r in test2_results[:10]:
        print(f"  qg={r['qg_per_char']:.3f} extra_null={r['extra_null']} grid={r['grid']} decode={r['decode']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test2_72char_masks'] = {
        'description': '72-char models (25 nulls, extending consensus 24)',
        'n_masks': n_masks_tested,
        'n_configs': len(test2_results),
        'top5': test2_results[:5],
    }

    # ─── TEST 3: Bifid decode on null-extracted text ─────────────────────

    print("\n" + "=" * 70)
    print("TEST 3: Bifid cipher on null-extracted text")
    print("=" * 70)

    test3_results = []

    periods = [5, 6, 7, 8, 9, 10, 12, 13, 14, 18, 24, 36]

    for grid_name in ['KA', 'KRYPTOS', 'DEFECTOR', 'SEVEN', 'PALIMPSEST', 'ABSCISSA', 'KOMPASS']:
        grid56, rev56 = grids_5x6[grid_name]
        grid55, rev55 = grids_5x5[grid_name]

        for grid_type, grid, reverse in [('5x6', grid56, rev56), ('5x5', grid55, rev55)]:
            # On 72-char (drop last from 73)
            text72 = extract73[:-1]
            # On raw 73
            text73 = extract73

            for text, tname in [(text72, '72'), (text73, '73')]:
                for period in periods:
                    if period > len(text):
                        continue

                    for bifid_fn, bname in [(bifid_decode, 'bifid'), (bifid_decode_reverse, 'rbifid')]:
                        pt = bifid_fn(text, grid, reverse, period=period)
                        if pt and '?' not in pt:
                            qg, hits = score_result(pt, f"T3_{grid_name}_{grid_type}_{bname}_p{period}")
                            entry = {
                                'grid': grid_name, 'grid_type': grid_type,
                                'bifid': bname, 'period': period,
                                'text_len': tname,
                                'pt': pt, 'qg_per_char': round(qg, 3),
                                'crib_hits': str(hits) if hits else 'none',
                                'pt_len': len(pt),
                            }
                            test3_results.append(entry)
                            all_scores.append((qg, f"T3:{grid_name}:{grid_type}:{bname}:p{period}:{tname}", pt))

    test3_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTested {len(test3_results)} bifid configs")
    print(f"Top 10:")
    for r in test3_results[:10]:
        print(f"  qg={r['qg_per_char']:.3f} grid={r['grid']}:{r['grid_type']} {r['bifid']} p={r['period']} len={r['text_len']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test3_bifid'] = {
        'description': 'Bifid cipher (standard + reverse) on null-extracted text',
        'periods': periods,
        'n_configs': len(test3_results),
        'top5': test3_results[:5],
    }

    # ─── TEST 4: ADFGVX-style (undo columnar then decode) ───────────────

    print("\n" + "=" * 70)
    print("TEST 4: ADFGVX-style (undo columnar transposition + Polybius decode)")
    print("=" * 70)

    test4_results = []
    col_widths = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]

    text72 = extract73[:-1]  # Drop last for even length

    for width in col_widths:
        # Undo columnar, then decode pairs
        untransposed = undo_columnar(text72, width)

        for grid_name in ['KA', 'KRYPTOS', 'DEFECTOR', 'SEVEN']:
            grid, reverse = grids_5x6[grid_name]

            for decode_name, decode_fn in [
                ('direct', polybius_decode_direct),
                ('reverse', polybius_decode_reverse),
                ('halves', lambda t, g, r: polybius_decode_pairs(t, g, r, 'halves')),
            ]:
                pt = decode_fn(untransposed, grid, reverse)
                if pt:
                    qg, hits = score_result(pt, f"T4_w{width}_{grid_name}_{decode_name}")
                    entry = {
                        'width': width, 'grid': grid_name, 'decode': decode_name,
                        'pt': pt, 'qg_per_char': round(qg, 3),
                        'crib_hits': str(hits) if hits else 'none',
                        'pt_len': len(pt),
                    }
                    test4_results.append(entry)
                    all_scores.append((qg, f"T4:w{width}:{grid_name}:{decode_name}", pt))

    # Also try: decode pairs FIRST, then undo columnar on the decoded PT
    for width in col_widths:
        for grid_name in ['KA', 'KRYPTOS', 'DEFECTOR']:
            grid, reverse = grids_5x6[grid_name]

            pt_pre = polybius_decode_direct(text72, grid, reverse)
            if pt_pre:
                pt = undo_columnar(pt_pre, width)
                qg, hits = score_result(pt, f"T4b_decode_then_untrans_w{width}_{grid_name}")
                entry = {
                    'width': width, 'grid': grid_name, 'decode': 'decode_then_untrans',
                    'pt': pt, 'qg_per_char': round(qg, 3),
                    'crib_hits': str(hits) if hits else 'none',
                    'pt_len': len(pt),
                }
                test4_results.append(entry)
                all_scores.append((qg, f"T4b:w{width}:{grid_name}:decode_then_untrans", pt))

    test4_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTested {len(test4_results)} ADFGVX-style configs")
    print(f"Top 10:")
    for r in test4_results[:10]:
        print(f"  qg={r['qg_per_char']:.3f} w={r['width']} grid={r['grid']} decode={r['decode']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test4_adfgvx_style'] = {
        'description': 'ADFGVX-style: undo columnar then Polybius decode (and vice versa)',
        'widths': col_widths,
        'n_configs': len(test4_results),
        'top5': test4_results[:5],
    }

    # ─── TEST 5: Coordinate digit analysis ───────────────────────────────

    print("\n" + "=" * 70)
    print("TEST 5: Coordinate digit stream analysis")
    print("=" * 70)

    test5_results = []

    grid_ka, rev_ka = grids_5x6['KA']

    for text, tname in [(extract73, '73'), (text72, '72')]:
        # Get coordinates for each character
        coords = []
        for ch in text:
            if ch in grid_ka:
                coords.append(grid_ka[ch])

        rows = [r for r, c in coords]
        cols = [c for r, c in coords]

        # Interleaved: r0,c0,r1,c1,...
        interleaved = []
        for r, c in coords:
            interleaved.extend([r, c])

        # Concatenated: all rows then all cols
        concat_rc = rows + cols
        concat_cr = cols + rows

        # Try interpreting digit streams as base-5 or base-6
        for stream_name, stream in [
            ('interleaved', interleaved),
            ('rows_then_cols', concat_rc),
            ('cols_then_rows', concat_cr),
        ]:
            # Convert pairs of digits to letters (base 5)
            pt_chars = []
            for i in range(0, len(stream) - 1, 2):
                idx = stream[i] * 5 + stream[i + 1]
                if idx < 26:
                    pt_chars.append(chr(65 + idx))
                else:
                    pt_chars.append('?')
            pt = ''.join(pt_chars)

            if '?' not in pt and len(pt) >= 4:
                qg, hits = score_result(pt, f"T5_{tname}_{stream_name}")
                entry = {
                    'text_len': tname, 'stream': stream_name,
                    'pt': pt, 'qg_per_char': round(qg, 3),
                    'crib_hits': str(hits) if hits else 'none',
                    'pt_len': len(pt),
                }
                test5_results.append(entry)
                all_scores.append((qg, f"T5:{tname}:{stream_name}", pt))

        # Also: rows only or cols only as ordinal values
        for coord_name, stream in [('rows', rows), ('cols', cols)]:
            # Frequency analysis
            freq = Counter(stream)
            print(f"  {tname}-char {coord_name} digit frequencies: {dict(sorted(freq.items()))}")

    test5_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTested {len(test5_results)} digit-stream configs")
    for r in test5_results[:5]:
        print(f"  qg={r['qg_per_char']:.3f} len={r['text_len']} stream={r['stream']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test5_coordinates'] = {
        'description': 'Coordinate digit stream decoding',
        'n_configs': len(test5_results),
        'top5': test5_results[:5],
    }

    # ─── TEST 6: Half-length crib positional check ───────────────────────

    print("\n" + "=" * 70)
    print("TEST 6: Half-length crib analysis")
    print("=" * 70)

    # Under Polybius fractionation, each PT char = 2 CT chars.
    # Crib EASTNORTHEAST at CT positions 21-33 (13 chars) = 6.5 PT chars
    # This means the crib starts at PT position 21//2=10 (if no nulls)
    # or at a variable position depending on null mask

    # More precisely: if we have 72 CT chars (after removing 25 nulls),
    # positions 21-33 in CT97 map to certain positions in CT72.
    # Those CT72 positions, read as pairs, give PT characters.

    test6_results = {}

    for extra_null in EXTRA_NULL_CANDIDATES[:20]:
        mask25 = sorted(MASK_24 + [extra_null])
        extract72 = extract_with_mask(CT97, mask25)

        if len(extract72) != 72:
            continue

        # Map CT97 positions to CT72 positions
        kept = [i for i in range(97) if i not in set(mask25)]
        pos_map = {orig: new for new, orig in enumerate(kept)}

        # Check where crib positions land in CT72
        ene_positions_in_72 = []
        for p in range(21, 34):
            if p in pos_map:
                ene_positions_in_72.append(pos_map[p])

        bcl_positions_in_72 = []
        for p in range(63, 74):
            if p in pos_map:
                bcl_positions_in_72.append(pos_map[p])

        # Under Polybius, PT position = CT72 position // 2
        # So crib positions become PT positions
        ene_pt_start = ene_positions_in_72[0] // 2 if ene_positions_in_72 else None
        bcl_pt_start = bcl_positions_in_72[0] // 2 if bcl_positions_in_72 else None

        # Decode the extract72 with each grid
        for grid_name in ['KA', 'DEFECTOR', 'KRYPTOS']:
            grid, reverse = grids_5x6[grid_name]
            pt = polybius_decode_direct(extract72, grid, reverse)

            if pt and ene_pt_start is not None and bcl_pt_start is not None:
                # Check what PT chars are at crib-derived positions
                ene_frag = pt[ene_pt_start:ene_pt_start + 7]  # ~half of 13
                bcl_frag = pt[bcl_pt_start:bcl_pt_start + 6]  # ~half of 11

                # Check for any crib prefix match
                ene_match = 0
                for i, ch in enumerate(ene_frag):
                    if i < len("EASTNOR") and ch == "EASTNOR"[i]:
                        ene_match += 1
                    else:
                        break

                bcl_match = 0
                for i, ch in enumerate(bcl_frag):
                    if i < len("BERLIN") and ch == "BERLIN"[i]:
                        bcl_match += 1
                    else:
                        break

                if ene_match + bcl_match > 0:
                    key = f"null+{extra_null}:{grid_name}"
                    test6_results[key] = {
                        'extra_null': extra_null, 'grid': grid_name,
                        'ene_pt_start': ene_pt_start, 'bcl_pt_start': bcl_pt_start,
                        'ene_frag': ene_frag, 'bcl_frag': bcl_frag,
                        'ene_match': ene_match, 'bcl_match': bcl_match,
                        'total_match': ene_match + bcl_match,
                    }

    print(f"\nHalf-length crib analysis: {len(test6_results)} configs with any match")
    for key, r in sorted(test6_results.items(), key=lambda x: x[1]['total_match'], reverse=True)[:10]:
        print(f"  {key}: ENE@{r['ene_pt_start']}='{r['ene_frag']}' ({r['ene_match']} match), "
              f"BCL@{r['bcl_pt_start']}='{r['bcl_frag']}' ({r['bcl_match']} match)")

    results['tests']['test6_halflen_cribs'] = {
        'description': 'Half-length crib positional analysis under Polybius model',
        'n_matches': len(test6_results),
        'top_matches': dict(list(sorted(test6_results.items(),
                                         key=lambda x: x[1]['total_match'], reverse=True))[:5]),
    }

    # ─── TEST 7: Row/column separation via col7 ─────────────────────────

    print("\n" + "=" * 70)
    print("TEST 7: Col7 separates rows from columns (ADFGVX interleaving)")
    print("=" * 70)

    test7_results = []

    for text, tname in [(text72, '72'), (extract73, '73')]:
        for width in [5, 7, 8, 9, 10, 11, 12, 13, 14]:
            untransposed = undo_columnar(text, width)

            # In ADFGVX, after undoing columnar trans, the digits alternate row/col
            # Try: odd positions = rows, even positions = cols (and vice versa)

            for grid_name in ['KA', 'KRYPTOS', 'DEFECTOR']:
                grid, reverse = grids_5x6[grid_name]

                # Interpretation 1: positions 0,2,4,... are row-chars, 1,3,5,... are col-chars
                pt_chars_a = []
                for i in range(0, len(untransposed) - 1, 2):
                    ch_r, ch_c = untransposed[i], untransposed[i + 1]
                    if ch_r in grid and ch_c in grid:
                        r, _ = grid[ch_r]
                        _, c = grid[ch_c]
                        if (r, c) in reverse:
                            pt_chars_a.append(reverse[(r, c)])
                        else:
                            pt_chars_a.append('?')
                pt_a = ''.join(pt_chars_a)

                # Interpretation 2: first half = rows, second half = cols
                half = len(untransposed) // 2
                pt_chars_b = []
                for i in range(half):
                    ch_r = untransposed[i]
                    ch_c = untransposed[half + i] if half + i < len(untransposed) else None
                    if ch_r and ch_c and ch_r in grid and ch_c in grid:
                        r, _ = grid[ch_r]
                        _, c = grid[ch_c]
                        if (r, c) in reverse:
                            pt_chars_b.append(reverse[(r, c)])
                        else:
                            pt_chars_b.append('?')
                pt_b = ''.join(pt_chars_b)

                for pt, iname in [(pt_a, 'interleaved'), (pt_b, 'halved')]:
                    if pt and '?' not in pt and len(pt) >= 4:
                        qg, hits = score_result(pt, f"T7_{tname}_w{width}_{grid_name}_{iname}")
                        entry = {
                            'text_len': tname, 'width': width,
                            'grid': grid_name, 'interp': iname,
                            'pt': pt, 'qg_per_char': round(qg, 3),
                            'pt_len': len(pt),
                        }
                        test7_results.append(entry)
                        all_scores.append((qg, f"T7:{tname}:w{width}:{grid_name}:{iname}", pt))

    test7_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTested {len(test7_results)} configs")
    print(f"Top 10:")
    for r in test7_results[:10]:
        print(f"  qg={r['qg_per_char']:.3f} len={r['text_len']} w={r['width']} grid={r['grid']} interp={r['interp']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test7_col_separation'] = {
        'description': 'Col7 as ADFGVX-style row/column separator',
        'n_configs': len(test7_results),
        'top5': test7_results[:5],
    }

    # ─── TEST 8: DEFECTOR-keyed Polybius square ──────────────────────────

    print("\n" + "=" * 70)
    print("TEST 8: DEFECTOR as Polybius square keyword (not Beaufort key)")
    print("=" * 70)

    test8_results = []

    # DEFECTOR-keyed 5x5 and 5x6 squares already built
    # Comprehensive sweep: all decode methods on all text variants

    grid_d56, rev_d56 = grids_5x6['DEFECTOR']
    grid_d55, rev_d55 = grids_5x5['DEFECTOR']

    print(f"DEFECTOR 5x6 grid:")
    defector_alpha = []
    seen = set()
    for ch in 'DEFECTOR':
        if ch not in seen:
            defector_alpha.append(ch)
            seen.add(ch)
    for ch in ALPH:
        if ch not in seen:
            defector_alpha.append(ch)
            seen.add(ch)
    for i in range(0, len(defector_alpha), 5):
        row = defector_alpha[i:i+5]
        print(f"  Row {i//5}: {' '.join(row)}")

    # Try on raw 97 (even though odd - test with drop first/last/middle)
    # Try on 73-char extract (drop first/last)
    # Try on various 72-char extracts

    texts = {
        '73_dropfirst': extract73[1:],
        '73_droplast': extract73[:-1],
        '97_dropfirst': CT97[1:],
        '97_droplast': CT97[:-1],
    }

    # Add 72-char extracts from mask25 variants
    for extra in EXTRA_NULL_CANDIDATES[:10]:
        mask25 = sorted(MASK_24 + [extra])
        e72 = extract_with_mask(CT97, mask25)
        if len(e72) == 72:
            texts[f'm25+{extra}'] = e72

    for tname, text in texts.items():
        if len(text) % 2 != 0:
            continue

        for gtype, grid, reverse in [('5x6', grid_d56, rev_d56), ('5x5', grid_d55, rev_d55)]:
            for decode_name, decode_fn in [
                ('direct', polybius_decode_direct),
                ('reverse', polybius_decode_reverse),
            ]:
                pt = decode_fn(text, grid, reverse)
                if pt and '?' not in pt:
                    qg, hits = score_result(pt, f"T8_{tname}_{gtype}_{decode_name}")
                    entry = {
                        'text': tname, 'grid_type': gtype, 'decode': decode_name,
                        'pt': pt, 'qg_per_char': round(qg, 3),
                        'pt_len': len(pt),
                    }
                    test8_results.append(entry)
                    all_scores.append((qg, f"T8:{tname}:{gtype}:{decode_name}", pt))

            # Bifid with DEFECTOR square
            for period in [5, 6, 7, 8, 9, 12, 13, 18, 24, 36]:
                if period > len(text):
                    continue
                pt = bifid_decode(text, grid, reverse, period=period)
                if pt and '?' not in pt:
                    qg, hits = score_result(pt, f"T8_bifid_{tname}_{gtype}_p{period}")
                    entry = {
                        'text': tname, 'grid_type': gtype, 'decode': f'bifid_p{period}',
                        'pt': pt, 'qg_per_char': round(qg, 3),
                        'pt_len': len(pt),
                    }
                    test8_results.append(entry)
                    all_scores.append((qg, f"T8:bifid:{tname}:{gtype}:p{period}", pt))

    test8_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTested {len(test8_results)} DEFECTOR Polybius configs")
    print(f"Top 10:")
    for r in test8_results[:10]:
        print(f"  qg={r['qg_per_char']:.3f} text={r['text']} {r['grid_type']} {r['decode']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test8_defector_polybius'] = {
        'description': 'DEFECTOR as Polybius square keyword',
        'n_configs': len(test8_results),
        'top5': test8_results[:5],
    }

    # ─── TEST 9: Comprehensive keyword x method sweep ────────────────────

    print("\n" + "=" * 70)
    print("TEST 9: Comprehensive keyword x method sweep")
    print("=" * 70)

    test9_results = []

    # Already covered in tests 1-8, but add the remaining combinations
    # Focus on ADFGVX-style with keyed columnar using keyword order

    keyword_orders = {
        'KRYPTOS': [0, 4, 6, 3, 5, 2, 1],  # K=0,R=4,Y=6,P=3,T=5,O=2,S=1 (alphabetical rank)
        'DEFECTOR': [1, 2, 3, 0, 1, 6, 4, 5],  # We need unique ranks; skip
    }

    # Simpler: use alphabetical order of keyword letters
    def keyword_to_order(kw):
        """Convert keyword to column order (alphabetical rank of each letter)."""
        indexed = [(ch, i) for i, ch in enumerate(kw)]
        ranked = sorted(indexed, key=lambda x: x[0])
        order = [0] * len(kw)
        for rank, (ch, orig_idx) in enumerate(ranked):
            order[orig_idx] = rank
        return order

    for kw_name, kw in [('KRYPTOS', 'KRYPTOS'), ('DEFECTOR', 'DEFECTOR'), ('SEVEN', 'SEVEN')]:
        order = keyword_to_order(kw)
        width = len(kw)

        # Try keyed columnar undo on text72
        if len(text72) > 0:
            try:
                untransposed = undo_columnar_keyed(text72, order)
            except Exception:
                continue

            for grid_name in ['KA', kw_name]:
                if grid_name not in grids_5x6:
                    continue
                grid, reverse = grids_5x6[grid_name]

                pt = polybius_decode_direct(untransposed, grid, reverse)
                if pt and '?' not in pt:
                    qg, hits = score_result(pt, f"T9_keyed_{kw_name}_{grid_name}")
                    entry = {
                        'keyed_trans': kw_name, 'grid': grid_name,
                        'pt': pt, 'qg_per_char': round(qg, 3),
                        'pt_len': len(pt),
                    }
                    test9_results.append(entry)
                    all_scores.append((qg, f"T9:keyed_{kw_name}:{grid_name}", pt))

    test9_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTested {len(test9_results)} keyed columnar + Polybius configs")
    for r in test9_results[:5]:
        print(f"  qg={r['qg_per_char']:.3f} trans={r['keyed_trans']} grid={r['grid']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test9_keyword_sweep'] = {
        'description': 'Keyed columnar transposition + Polybius decode',
        'n_configs': len(test9_results),
        'top5': test9_results[:5],
    }

    # ─── TEST 10: On raw 97 chars (96 pairs after drop) ─────────────────

    print("\n" + "=" * 70)
    print("TEST 10: Direct Polybius on raw 97-char CT (drop one for 96 = 48 pairs)")
    print("=" * 70)

    test10_results = []

    for drop_pos in [0, 96]:  # Drop first or last
        if drop_pos == 0:
            text96 = CT97[1:]
        else:
            text96 = CT97[:-1]

        for grid_name in ['KA', 'KRYPTOS', 'DEFECTOR']:
            grid, reverse = grids_5x6[grid_name]

            for decode_name, decode_fn in [
                ('direct', polybius_decode_direct),
                ('reverse', polybius_decode_reverse),
                ('halves', lambda t, g, r: polybius_decode_pairs(t, g, r, 'halves')),
            ]:
                pt = decode_fn(text96, grid, reverse)
                if pt and '?' not in pt:
                    qg, hits = score_result(pt, f"T10_drop{drop_pos}_{grid_name}_{decode_name}")
                    entry = {
                        'drop': drop_pos, 'grid': grid_name, 'decode': decode_name,
                        'pt': pt, 'qg_per_char': round(qg, 3),
                        'pt_len': len(pt),
                    }
                    test10_results.append(entry)
                    all_scores.append((qg, f"T10:drop{drop_pos}:{grid_name}:{decode_name}", pt))

            # Also with columnar undo first
            for width in [5, 6, 7, 8, 12]:
                untransposed = undo_columnar(text96, width)
                pt = polybius_decode_direct(untransposed, grid, reverse)
                if pt and '?' not in pt:
                    qg, hits = score_result(pt, f"T10_w{width}_{grid_name}")
                    entry = {
                        'drop': drop_pos, 'width': width, 'grid': grid_name,
                        'decode': f'untrans_w{width}_direct',
                        'pt': pt, 'qg_per_char': round(qg, 3),
                        'pt_len': len(pt),
                    }
                    test10_results.append(entry)
                    all_scores.append((qg, f"T10:drop{drop_pos}:w{width}:{grid_name}", pt))

    test10_results.sort(key=lambda x: x['qg_per_char'], reverse=True)
    print(f"\nTested {len(test10_results)} raw-97 Polybius configs")
    print(f"Top 5:")
    for r in test10_results[:5]:
        print(f"  qg={r['qg_per_char']:.3f} drop={r['drop']} grid={r['grid']} {r['decode']}")
        print(f"    PT({r['pt_len']}): {r['pt'][:60]}...")

    results['tests']['test10_raw97'] = {
        'description': 'Direct Polybius on raw 97-char CT (96 pairs)',
        'n_configs': len(test10_results),
        'top5': test10_results[:5],
    }

    # ─── GLOBAL SUMMARY ─────────────────────────────────────────────────

    elapsed = time.time() - t0

    all_scores.sort(key=lambda x: x[0], reverse=True)

    print("\n" + "=" * 70)
    print("GLOBAL SUMMARY")
    print("=" * 70)

    total_configs = sum(
        results['tests'][t].get('n_configs', 0) for t in results['tests']
    )

    print(f"Total configs tested: {total_configs}")
    print(f"Elapsed: {elapsed:.1f}s")
    print()

    # English quadgram reference: random ~ -10.5, English ~ -4.0 to -3.5
    print("Quadgram reference: random ~ -10.5/char, English ~ -4.0/char")
    print()

    print("GLOBAL TOP 20:")
    for i, (qg, method, pt) in enumerate(all_scores[:20]):
        print(f"  {i+1:2d}. qg={qg:.3f}  {method}")
        print(f"      PT: {pt[:70]}{'...' if len(pt) > 70 else ''}")

    # Check if any score is above English-like threshold
    best_qg = all_scores[0][0] if all_scores else -999

    if best_qg > -5.0:
        verdict = "PROMISING"
    elif best_qg > -7.0:
        verdict = "MARGINAL"
    else:
        verdict = "NOISE"

    print(f"\nBest quadgram: {best_qg:.3f}/char")
    print(f"VERDICT: {verdict}")

    # Check for any crib fragments in top results
    print("\nCrib fragment search in top 50 results:")
    crib_found = False
    for qg, method, pt in all_scores[:50]:
        for crib_name, crib in [("ENE", "EASTNORTHEAST"), ("BCL", "BERLINCLOCK")]:
            for fraglen in range(4, len(crib) + 1):
                frag = crib[:fraglen]
                if frag in pt:
                    print(f"  FOUND '{frag}' in {method} (qg={qg:.3f})")
                    crib_found = True
            # Also check any 4+ char substring
            for start in range(len(crib) - 3):
                frag = crib[start:start + 4]
                if frag in pt:
                    print(f"  FOUND '{frag}' (from {crib_name}[{start}:]) in {method}")
                    crib_found = True

    if not crib_found:
        print("  No crib fragments found in top 50 results")

    results['global_summary'] = {
        'total_configs': total_configs,
        'elapsed_seconds': round(elapsed, 1),
        'best_qg_per_char': round(best_qg, 3),
        'verdict': verdict,
        'top10': [(round(qg, 3), method, pt[:80]) for qg, method, pt in all_scores[:10]],
    }

    # Save results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_polybius_frac_nullmask.json"
    with open(outpath, "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\nArtifact: {outpath}")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/fractionation/e_polybius_fractionation_nullmask.py")


if __name__ == "__main__":
    main()
