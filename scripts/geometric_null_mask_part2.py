#!/usr/bin/env python3
"""
Geometric Null-Mask Exploration Part 2 — Deep Analysis
=======================================================
Follows up on findings from Part 1:

KEY FINDING from Part 1: K4's crib positions span 22 of 31 columns.
Only columns 8-16 (9 columns) are crib-free in all three full rows (25-27).
Choosing ANY 8 of these 9 columns as null-columns gives exactly 24 nulls.
That's 9 valid column-based masks — all preserving cribs and contiguity.

This script:
1. Exhaustively tests all 9 column-based masks with ALL cipher variants
2. Tests the 24° angle relationship to column selection
3. Tests if the 9 available columns map to the 24° geometry
4. Tests composite masks (row-24 + columns + W-positions)
5. Deep decrypt analysis of most promising masks
6. Explores whether column indices have geometric meaning
"""

import sys, math, os
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, CRIB_DICT, ALPH_IDX, ALPH, MOD,
    KRYPTOS_ALPHABET, SELF_ENCRYPTING, BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC, BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC
)

# ── Grid Parameters ─────────────────────────────────────────────────────
GRID_ROWS = 28
GRID_COLS = 31

K4_START_ROW = 24
K4_START_COL = 27
K4_START_POS = K4_START_ROW * GRID_COLS + K4_START_COL  # 771

def k4_grid_positions():
    positions = []
    grid_pos = K4_START_POS
    for i in range(CT_LEN):
        row = grid_pos // GRID_COLS
        col = grid_pos % GRID_COLS
        positions.append((row, col))
        grid_pos += 1
    return positions

K4_GRID = k4_grid_positions()
W_POSITIONS = [20, 36, 48, 58, 74]

# ── Cipher functions ────────────────────────────────────────────────────
def vig_dec(ct, key, alph=ALPH):
    idx = {c: i for i, c in enumerate(alph)}
    return ''.join(alph[(idx[c] - idx[key[i % len(key)]]) % 26] for i, c in enumerate(ct))

def beau_dec(ct, key, alph=ALPH):
    idx = {c: i for i, c in enumerate(alph)}
    return ''.join(alph[(idx[key[i % len(key)]] - idx[c]) % 26] for i, c in enumerate(ct))

def vbeau_dec(ct, key, alph=ALPH):
    idx = {c: i for i, c in enumerate(alph)}
    return ''.join(alph[(idx[c] + idx[key[i % len(key)]]) % 26] for i, c in enumerate(ct))

def ic(text):
    freqs = [0]*26
    for c in text:
        freqs[ALPH_IDX[c]] += 1
    n = len(text)
    return sum(f*(f-1) for f in freqs) / (n*(n-1)) if n > 1 else 0

def crib_score_free(pt, cribs=("EASTNORTHEAST", "BERLINCLOCK")):
    """Search for cribs anywhere in plaintext. Return (score, positions)."""
    total = 0
    found = []
    for crib in cribs:
        for i in range(len(pt) - len(crib) + 1):
            if pt[i:i+len(crib)] == crib:
                total += len(crib)
                found.append((crib, i))
    return total, found

def extract_73(null_positions):
    null_set = set(null_positions)
    return ''.join(CT[i] for i in range(CT_LEN) if i not in null_set)

def new_crib_positions(null_positions):
    """Map original crib positions to positions in 73-char extract."""
    null_set = set(null_positions)
    pos_map = {}
    new_idx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            pos_map[i] = new_idx
            new_idx += 1
    result = {}
    for pos in sorted(CRIB_POSITIONS):
        if pos in pos_map:
            result[pos] = pos_map[pos]
    return result

# ══════════════════════════════════════════════════════════════════════════
# PART 1: ALL 9 COLUMN-BASED MASKS — EXHAUSTIVE CIPHER TESTING
# ══════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("PART 1: COLUMN-BASED NULL MASKS (8 of 9 Available Columns)")
print("=" * 80)

# Crib columns (22 of 31): [0,1,2,3,4,5,6,7, 17,18,19,20,21,22,23,24,25,26,27,28,29,30]
# Available (9): [8,9,10,11,12,13,14,15,16]
AVAILABLE_COLS = [8, 9, 10, 11, 12, 13, 14, 15, 16]

print(f"\nCrib-free columns: {AVAILABLE_COLS}")
print(f"Choose 8 of 9 → C(9,8) = 9 masks, each leaving one column as 'real'")
print(f"Equivalently: which 1 of 9 columns is NOT null?\n")

# Extended keyword list including thematic words
KEYWORDS = [
    "KRYPTOS", "KOMPASS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "COLOPHON", "SHADOW", "ENIGMA", "CIPHER", "BERLIN",
    "COMPASS", "HIDDEN", "SECRET", "BURIED", "MARKER",
    "LOOMIS", "TRANSIT", "SURVEY",
]

all_masks = []
for combo in combinations(AVAILABLE_COLS, 8):
    null_cols = set(combo)
    kept_col = (set(AVAILABLE_COLS) - null_cols).pop()
    nulls = []
    for i, (r, c) in enumerate(K4_GRID):
        if r >= 25 and c in null_cols:
            nulls.append(i)
    if len(nulls) != 24:
        continue

    text_73 = extract_73(nulls)
    crib_map = new_crib_positions(nulls)

    # Check crib contiguity
    ene_new = [crib_map[p] for p in range(21, 34)]
    bc_new = [crib_map[p] for p in range(63, 74)]
    ene_contig = all(ene_new[i+1] == ene_new[i]+1 for i in range(len(ene_new)-1))
    bc_contig = all(bc_new[i+1] == bc_new[i]+1 for i in range(len(bc_new)-1))

    all_masks.append({
        'null_cols': sorted(null_cols),
        'kept_col': kept_col,
        'nulls': nulls,
        'text_73': text_73,
        'ene_new_start': ene_new[0],
        'bc_new_start': bc_new[0],
        'ene_contig': ene_contig,
        'bc_contig': bc_contig,
    })

    print(f"\n--- Kept column: {kept_col} | Null columns: {sorted(null_cols)} ---")
    print(f"  73-char: {text_73}")
    print(f"  ENE at new pos {ene_new[0]}-{ene_new[-1]} ({'contig' if ene_contig else 'BROKEN'})")
    print(f"  BC  at new pos {bc_new[0]}-{bc_new[-1]} ({'contig' if bc_contig else 'BROKEN'})")

    # Which W's are nulled?
    w_nulled = [p for p in W_POSITIONS if p in set(nulls)]
    print(f"  W's nulled: {w_nulled}")

    # Test all cipher variants
    best_score = 0
    best_result = None
    for kw in KEYWORDS:
        for cipher_name, cipher_fn in [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", vbeau_dec)]:
            for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                pt = cipher_fn(text_73, kw, alph)
                score, found = crib_score_free(pt)
                pt_ic = ic(pt)
                if score > best_score or (score == best_score and pt_ic > 0.055):
                    best_score = score
                    best_result = (score, pt_ic, kw, cipher_name, alph_name, pt, found)

    if best_result:
        s, i, kw, cn, an, pt, found = best_result
        print(f"  Best: [{s}] IC={i:.4f} {cn}/{an}/{kw}: {pt[:60]}...")
        if found:
            print(f"    Found cribs: {found}")
    else:
        print(f"  Best: [0] no crib matches")


# ══════════════════════════════════════════════════════════════════════════
# PART 2: GEOMETRIC MEANING OF COLUMNS 8-16
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PART 2: GEOMETRIC ANALYSIS OF THE NULL COLUMN BAND (8-16)")
print("=" * 80)

print(f"\nThe 9 available null columns: {AVAILABLE_COLS}")
print(f"These form a CONTIGUOUS BAND from col 8 to col 16 (inclusive)")
print(f"Band width: 9 columns in a 31-column grid")
print(f"Band center: column {(8+16)/2:.1f} = 12")
print(f"Grid center: column {(GRID_COLS-1)/2:.1f} = 15")
print(f"K4 start column: {K4_START_COL}")

# What fraction of the grid width?
print(f"\n9/31 = {9/31:.6f}")
print(f"8/31 = {8/31:.6f} (null fraction per mask)")
print(f"24/97 = {24/97:.6f} (overall null fraction)")
print(f"  Note: 8/31 = {8/31:.6f} ≈ 24/97 = {24/97:.6f} — very close!")
print(f"  (8/31 = 0.2581, 24/97 = 0.2474, ratio = {(8/31)/(24/97):.4f})")

# Angular relationship
print(f"\n24° analysis:")
print(f"  tan(24°) = {math.tan(math.radians(24)):.6f}")
print(f"  Cols 8-16 span 9 cols out of 31")
print(f"  atan(9/31) = {math.degrees(math.atan(9/31)):.2f}°")
print(f"  atan(8/31) = {math.degrees(math.atan(8/31)):.2f}°")
print(f"  atan(3/4) = {math.degrees(math.atan(3/4)):.2f}° (related to 4 rows of K4)")
print(f"  atan(4/9) = {math.degrees(math.atan(4/9)):.2f}° ← close to 24°!")
print(f"  4 rows / 9 columns → angle = {math.degrees(math.atan(4/9)):.2f}° ≈ 24° !!!")

# The 4/9 relationship: K4 spans 4 rows, null band is 9 cols wide
# tan(24°) ≈ 0.4452 ≈ 4/9 = 0.4444
# This means a 24° line through K4's 4-row extent sweeps across ~9 columns!

print(f"\n*** KEY GEOMETRIC RELATIONSHIP ***")
print(f"  K4 height = 4 rows")
print(f"  Null band width = 9 columns")
print(f"  4/9 = {4/9:.6f}")
print(f"  tan(24°) = {math.tan(math.radians(24)):.6f}")
print(f"  MATCH within {abs(4/9 - math.tan(math.radians(24)))/math.tan(math.radians(24))*100:.2f}%")

# ══════════════════════════════════════════════════════════════════════════
# PART 3: THE "MIDDLE BAND" INTERPRETATION
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PART 3: MIDDLE BAND INTERPRETATION")
print("=" * 80)

print("""
K4 in the 31-column grid:
  Cols 0-7:   CRIB ZONE (right end of ENE crib in row 25, all BC crib in rows 26-27)
  Cols 8-16:  NULL BAND (no crib characters) ← these are the null columns
  Cols 17-30: CRIB ZONE (ENE crib in row 25, start of BC crib in row 26)

This creates a natural three-zone structure:
  LEFT: 8 cols × 3 full rows = 24 chars (+ 0 from row 24) = 24 real chars
  MIDDLE: 9 cols × 3 full rows = 27 chars (8 of 9 cols are null = 24 nulls)
  RIGHT: 14 cols × 3 full rows = 42 chars (+ 4 from row 24) = 46 real chars

With 8 null columns: 24 + 3 (1 kept middle col) + 42 + 4 = 73 ✓
""")

# Show the three-zone layout
for row in [24, 25, 26, 27]:
    chars = [(i, CT[i], c) for i, (r, c) in enumerate(K4_GRID) if r == row]
    line = ""
    for i, ch, col in chars:
        if col == 8:
            line += " |"
        if col == 17:
            line += "| "
        # Mark crib positions
        if i in CRIB_POSITIONS:
            line += ch.lower()  # lowercase = crib
        elif i in set(W_POSITIONS):
            line += '*'  # star = W position
        else:
            line += ch
    print(f"  Row {row}: {line}")

print("\n  (lowercase = crib position, * = W position)")

# ══════════════════════════════════════════════════════════════════════════
# PART 4: WHICH SINGLE COLUMN TO KEEP? — DEEPER ANALYSIS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PART 4: WHICH COLUMN TO KEEP FROM THE NULL BAND?")
print("=" * 80)

print("""
With 9 available columns (8-16) and 8 chosen as nulls, ONE column survives.
Which column should be kept? Geometric criteria:
""")

angle_24 = math.radians(24)
for kept in AVAILABLE_COLS:
    null_cols = set(AVAILABLE_COLS) - {kept}
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols]
    text_73 = extract_73(nulls)

    # Characters at the kept column
    kept_chars = [(i, CT[i], r) for i, (r, c) in enumerate(K4_GRID) if c == kept and r >= 25]

    # Geometric significance of this column
    col_angle_from_start = math.degrees(math.atan2(1, kept - K4_START_COL)) if kept != K4_START_COL else 90
    col_center_offset = kept - 15  # offset from grid center column

    print(f"\n  Keep col {kept}: chars = {''.join(ch for _, ch, _ in kept_chars)}")
    print(f"    Angle from K4 start col {K4_START_COL}: {col_angle_from_start:.1f}°")
    print(f"    Offset from grid center (col 15): {col_center_offset:+d}")
    print(f"    Column {kept} mod various: mod 3={kept%3}, mod 4={kept%4}, mod 6={kept%6}, mod 8={kept%8}")

    # Special relationships
    if kept == 12:
        print(f"    ★ Column 12 = center of band, 12 = half of 24")
    if kept == 13:
        print(f"    ★ Column 13 = len(EASTNORTHEAST)")
    if kept == 8:
        print(f"    ★ Column 8 = '8 lines' from legal pad")
    if kept == 11:
        print(f"    ★ Column 11 = len(BERLINCLOCK)")
    if kept == 14:
        print(f"    ★ Column 14 = 14 lines (legal pad '14 Lines')")
    if kept == 16:
        print(f"    ★ Column 16 = K4 start in Vigenere grid?")
    if kept == 15:
        print(f"    ★ Column 15 = center of 31-col grid")
    if kept == 9:
        print(f"    ★ Column 9 = denominator in 4/9 ≈ tan(24°)")
    if kept == 10:
        print(f"    ★ Column 10 = decimal base")

# ══════════════════════════════════════════════════════════════════════════
# PART 5: COMPREHENSIVE KEYWORD SWEEP ON ALL 9 MASKS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PART 5: EXTENDED KEYWORD SWEEP — ALL MASKS × ALL KEYWORDS × ALL CIPHERS")
print("=" * 80)

# Load thematic keywords if available
try:
    with open(os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'thematic_keywords.txt')) as f:
        extra_kw = [line.strip().upper() for line in f if line.strip() and line.strip().isalpha()]
    KEYWORDS.extend([kw for kw in extra_kw if kw not in KEYWORDS and 3 <= len(kw) <= 15])
    print(f"  Loaded {len(KEYWORDS)} total keywords")
except FileNotFoundError:
    print(f"  Using {len(KEYWORDS)} built-in keywords")

global_best = []

for mask_info in all_masks:
    kept = mask_info['kept_col']
    text_73 = mask_info['text_73']
    nulls = mask_info['nulls']

    for kw in KEYWORDS:
        for cipher_name, cipher_fn in [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", vbeau_dec)]:
            for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                pt = cipher_fn(text_73, kw, alph)
                score, found = crib_score_free(pt)
                pt_ic = ic(pt)

                if score > 0 or pt_ic > 0.060:
                    global_best.append({
                        'score': score,
                        'ic': pt_ic,
                        'kept_col': kept,
                        'keyword': kw,
                        'cipher': cipher_name,
                        'alphabet': alph_name,
                        'plaintext': pt,
                        'cribs_found': found,
                    })

global_best.sort(key=lambda x: (-x['score'], -x['ic']))
print(f"\n  Results with crib hits or IC > 0.060: {len(global_best)}")

if global_best:
    print(f"\n  Top 20 results:")
    for i, r in enumerate(global_best[:20]):
        print(f"  {i+1:2d}. [{r['score']:2d}] IC={r['ic']:.4f} col={r['kept_col']:2d} "
              f"{r['cipher']}/{r['alphabet']}/{r['keyword']:12s}: {r['plaintext'][:50]}...")
        if r['cribs_found']:
            print(f"       Cribs: {r['cribs_found']}")
else:
    print("  No results with crib hits or IC > 0.060")

# ══════════════════════════════════════════════════════════════════════════
# PART 6: NON-PERIODIC CIPHERS (AUTOKEY) ON COLUMN MASKS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PART 6: AUTOKEY CIPHER ON COLUMN-BASED NULL MASKS")
print("=" * 80)

def autokey_vig_decrypt(ct, primer, alph=ALPH):
    """Vigenère autokey: key = primer + plaintext"""
    idx = {c: i for i, c in enumerate(alph)}
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        ki = idx[key[i]]
        pi = (idx[c] - ki) % 26
        pt_char = alph[pi]
        pt.append(pt_char)
        key.append(pt_char)
    return ''.join(pt)

def autokey_beau_decrypt(ct, primer, alph=ALPH):
    """Beaufort autokey: key = primer + plaintext"""
    idx = {c: i for i, c in enumerate(alph)}
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        ki = idx[key[i]]
        pi = (ki - idx[c]) % 26
        pt_char = alph[pi]
        pt.append(pt_char)
        key.append(pt_char)
    return ''.join(pt)

AUTOKEY_PRIMERS = [
    "K", "KRYPTOS", "KOMPASS", "PALIMPSEST", "ABSCISSA",
    "DEFECTOR", "COLOPHON", "BERLIN", "CLOCK", "EAST",
    "NORTH", "SHADOW", "HIDDEN", "SECRET",
]

for mask_info in all_masks[:3]:  # Test first 3 masks
    kept = mask_info['kept_col']
    text_73 = mask_info['text_73']
    print(f"\n  --- Kept col {kept} ---")

    for primer in AUTOKEY_PRIMERS:
        for ak_name, ak_fn in [("AK-Vig", autokey_vig_decrypt), ("AK-Beau", autokey_beau_decrypt)]:
            for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                pt = ak_fn(text_73, primer, alph)
                score, found = crib_score_free(pt)
                pt_ic = ic(pt)
                if score > 0 or pt_ic > 0.055:
                    print(f"    [{score}] IC={pt_ic:.4f} {ak_name}/{alph_name}/{primer}: {pt[:50]}...")
                    if found:
                        print(f"      Cribs: {found}")

# ══════════════════════════════════════════════════════════════════════════
# PART 7: ROW-24 AS NULLS — DIFFERENT TOTAL
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PART 7: ROW-24 (4 chars) + COLUMN NULLS — MODIFIED COUNTS")
print("=" * 80)

print("""
If K4 really starts at row 25 (not row 24), the 4 chars 'OBKR' in row 24
could be padding/header. Then we need 20 nulls from 93 chars = 73.
That requires ~6.67 null columns — not an integer. Let's check nearby.
""")

row24_nulls = [0, 1, 2, 3]  # Row 24 positions in K4

for n_null_cols in [6, 7]:
    total_null = 4 + 3 * n_null_cols
    remaining = 93 - 3 * n_null_cols + 4  # total - nulled + row24 still there
    print(f"\n  Row 24 (4) + {n_null_cols} col nulls ({3*n_null_cols}) = {total_null} total nulls → {97 - total_null} chars")

    if total_null == 24:  # Need this for our hypothesis
        for combo in combinations(AVAILABLE_COLS, n_null_cols):
            null_cols = set(combo)
            nulls = list(row24_nulls)
            for i, (r, c) in enumerate(K4_GRID):
                if r >= 25 and c in null_cols and i not in nulls:
                    nulls.append(i)

            valid = len(set(nulls)) == 24 and not (set(nulls) & CRIB_POSITIONS)
            if len(set(nulls)) == 24 and valid:
                text_73 = extract_73(nulls)
                print(f"    VALID: Row24 + cols {sorted(combo)} → {text_73[:40]}...")

                # Quick cipher test
                for kw in ["KRYPTOS", "KOMPASS"]:
                    for cn, cf in [("Vig", vig_dec), ("Beau", beau_dec)]:
                        pt = cf(text_73, kw)
                        s, f = crib_score_free(pt)
                        if s > 0:
                            print(f"      [{s}] {cn}/{kw}: {pt[:50]}... Cribs: {f}")

# 4 + 3*7 = 25 → one too many. But what if one column only has 2 chars nulled (row 24 only has col 27-30)?
# Actually row 24 has cols 27-30 which are in the crib zone, so can't null them
# Let's try: 3*8=24 is the only clean solution (no row-24 involvement)

# ══════════════════════════════════════════════════════════════════════════
# PART 8: STAGGERED DIAGONAL NULL SELECTION
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PART 8: STAGGERED DIAGONAL — 24° ACROSS 3 ROWS")
print("=" * 80)

print("""
Instead of SAME 8 columns nulled in each row, what if the null band
SHIFTS by tan(24°) ≈ 4/9 cols per row, matching the 24° angle?

K4 rows 25-27 span 3 rows. A 24° diagonal across 3 rows shifts:
  Row 25: base column range
  Row 26: shift +4/9 ≈ +0.44 cols → shift 0 or 1
  Row 27: shift +8/9 ≈ +0.89 cols → shift 1

With integer approximation (shift 0, 0, 1) or (0, 1, 1):
""")

for shift_pattern in [(0, 0, 0), (0, 0, 1), (0, 1, 1), (0, 1, 2), (0, 0, -1), (0, -1, -1), (0, -1, -2)]:
    for base_start in range(0, 24):
        null_cols_per_row = {}
        valid = True
        total_nulls = []

        for row_idx, (row, shift) in enumerate(zip([25, 26, 27], shift_pattern)):
            cols = [(base_start + shift + j) % GRID_COLS for j in range(8)]
            null_cols_per_row[row] = set(cols)

            for i, (r, c) in enumerate(K4_GRID):
                if r == row and c in null_cols_per_row[row]:
                    total_nulls.append(i)

        if len(total_nulls) == 24:
            null_set = set(total_nulls)
            crib_conflict = null_set & CRIB_POSITIONS
            if not crib_conflict:
                text_73 = extract_73(total_nulls)
                print(f"  VALID: base={base_start}, shifts={shift_pattern}")
                print(f"    Row 25 null cols: {sorted(null_cols_per_row[25])}")
                print(f"    Row 26 null cols: {sorted(null_cols_per_row[26])}")
                print(f"    Row 27 null cols: {sorted(null_cols_per_row[27])}")
                print(f"    73-char: {text_73}")

                # Quick test
                for kw in ["KRYPTOS", "KOMPASS", "PALIMPSEST"]:
                    for cn, cf in [("Vig", vig_dec), ("Beau", beau_dec)]:
                        pt = cf(text_73, kw)
                        s, f = crib_score_free(pt)
                        if s > 0:
                            print(f"    [{s}] {cn}/{kw}: {pt[:50]}... Cribs: {f}")

# ══════════════════════════════════════════════════════════════════════════
# PART 9: 24° LINE THROUGH TABLEAU → NULL MASK
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PART 9: 24° LINE THROUGH FULL 28×31 TABLEAU")
print("=" * 80)

print("""
The full tableau is 28×31 = 868 cells. K1-K3 occupy the first 771 cells.
K4 is the last 97. A line at 24° through the FULL tableau might intersect
specific K4 positions.

Drawing lines at 24° from every point on the top edge (row 0):
""")

for start_col in range(GRID_COLS):
    # Line: row = slope * (col - start_col) + 0
    # At 24° from horizontal: slope = tan(24°) ≈ 0.4452
    # For each (row, col) pair this line passes through:
    k4_hits = set()
    for col in range(GRID_COLS):
        row_exact = math.tan(angle_24) * (col - start_col)
        for r_try in [math.floor(row_exact), math.ceil(row_exact)]:
            grid_pos = r_try * GRID_COLS + col
            k4_idx = grid_pos - K4_START_POS
            if 0 <= k4_idx < CT_LEN:
                # Verify position
                if K4_GRID[k4_idx] == (r_try, col):
                    k4_hits.add(k4_idx)

    if len(k4_hits) > 0:
        # Also try from bottom edge going up
        pass

    # Try multiple parallel lines (stacked at regular intervals)
    for spacing in range(1, 10):
        all_hits = set()
        for line_num in range(50):
            base_row = line_num * spacing
            for col in range(GRID_COLS):
                row_exact = base_row + math.tan(angle_24) * (col - start_col)
                r = round(row_exact)
                grid_pos = r * GRID_COLS + col
                k4_idx = grid_pos - K4_START_POS
                if 0 <= k4_idx < CT_LEN:
                    if K4_GRID[k4_idx] == (r, col):
                        all_hits.add(k4_idx)

        nulls = [i for i in range(CT_LEN) if i not in all_hits]
        if len(nulls) == 24:
            crib_conflict = set(nulls) & CRIB_POSITIONS
            if not crib_conflict:
                print(f"  VALID: start_col={start_col}, spacing={spacing}")
                text_73 = extract_73(nulls)
                print(f"    73-char: {text_73[:50]}...")

# ══════════════════════════════════════════════════════════════════════════
# PART 10: SUMMARY AND KEY FINDINGS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("SUMMARY OF KEY FINDINGS")
print("=" * 80)

print("""
1. K4 GRID STRUCTURE:
   - K4 occupies rows 24-27 of the 28×31 grid
   - Row 24: 4 chars (OBKR) at cols 27-30
   - Rows 25-27: 31 chars each (cols 0-30)

2. CRIB COLUMN DISTRIBUTION:
   - Cribs span 22 of 31 columns (0-7 and 17-30)
   - Only columns 8-16 (9 columns) are crib-free
   - This creates a natural 3-zone structure: LEFT | MIDDLE | RIGHT

3. COLUMN-BASED NULL MASKS:
   - Choosing any 8 of the 9 crib-free columns as nulls gives exactly 24 nulls
   - All 9 such masks preserve all crib positions and maintain contiguity
   - This is the ONLY column-based approach that works

4. GEOMETRIC CONNECTION TO 24°:
   - K4 spans 4 rows, null band spans 9 columns
   - 4/9 = 0.4444 ≈ tan(24°) = 0.4452 (0.17% error)
   - This is the slope of a 24° line through K4's extent!
   - COINCIDENCE? The 24° angle from the installation triangle
     matches the aspect ratio of K4's row height to null band width

5. NULL BAND INTERPRETATION:
   - Cols 8-16 form a "null band" in the middle of K4
   - The band separates the two crib zones
   - 8 of 9 columns are nulls = 24 characters removed
   - 1 column from this band survives → determines the exact mask

6. UNRESOLVED: Which 1 of 9 columns survives?
   - No simple cipher (periodic Vig/Beau/VBeau with tested keywords)
     produces crib hits in the 73-char extracts
   - The surviving column may be determined by the 24° geometry:
     the exact intersection of the diagonal line with the K4 rows
""")

print("\nDone.")
