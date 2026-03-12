#!/usr/bin/env python3
"""
Part 5: Verification and Extended Analysis
===========================================
Verify the key claims and explore whether the column-based masks
actually match what we'd expect from a Cardan grille.

Also test: what if the 24° angle determines a READING ORDER
(not null selection)?
"""

import sys, os, math
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, CRIB_DICT, ALPH_IDX, ALPH, MOD,
    KRYPTOS_ALPHABET
)

GRID_COLS = 31
K4_START_POS = 24 * 31 + 27

def k4_grid_positions():
    positions = []
    grid_pos = K4_START_POS
    for i in range(CT_LEN):
        positions.append((grid_pos // GRID_COLS, grid_pos % GRID_COLS))
        grid_pos += 1
    return positions

K4_GRID = k4_grid_positions()
AVAILABLE_COLS = [8, 9, 10, 11, 12, 13, 14, 15, 16]

# ══════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("VERIFICATION: IS THE COLUMN GAP GENUINELY STRUCTURAL?")
print("=" * 80)

print("""
QUESTION: Is it COINCIDENTAL that cribs avoid columns 8-16?

The ENE crib (13 chars) starts at K4[21], which is row 25, col 17.
The BC crib (11 chars) starts at K4[63], which is row 26, col 28.

Row 25 has 31 columns (0-30). ENE occupies cols 17-29 (13 cols).
Row 26 has 31 columns (0-30). BC in row 26 occupies cols 28-30 (3 cols, 'NYP').
Row 27 has 31 columns (0-30). BC in row 27 occupies cols 0-7 (8 cols, 'VTTMZFPK').

The gap between ENE's end (col 29, row 25) and the NEXT crib (col 28, row 26)
wraps around through cols 30, 0-27 in row 26. That's 29 non-crib columns in row 26.
But wait — BC starts at position 63 (col 28, row 26), so row 26 cols 0-27 are non-crib.

Actually, let me recount carefully:
""")

# Precise crib-column mapping
for row in [24, 25, 26, 27]:
    crib_in_row = {}
    for pos in sorted(CRIB_POSITIONS):
        r, c = K4_GRID[pos]
        if r == row:
            crib_in_row[c] = (pos, CRIB_DICT[pos])

    non_crib_cols = sorted(set(range(31)) - set(crib_in_row.keys()))
    # But only count cols that K4 actually occupies in this row
    k4_cols_in_row = set(c for i, (r, c) in enumerate(K4_GRID) if r == row)

    print(f"  Row {row}: K4 cols = {sorted(k4_cols_in_row)}")
    print(f"    Crib cols: {sorted(crib_in_row.keys())}")
    # Show which cribs
    for c in sorted(crib_in_row.keys()):
        pos, ch = crib_in_row[c]
        print(f"      col {c:2d} = K4[{pos}] = '{ch}' (crib)")
    avail = sorted(k4_cols_in_row - set(crib_in_row.keys()))
    print(f"    Non-crib cols in K4: {avail}")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("CROSS-ROW INTERSECTION OF NON-CRIB COLUMNS")
print("=" * 80)

# For each row, find non-crib columns
non_crib_by_row = {}
for row in [25, 26, 27]:
    crib_cols = set()
    for pos in CRIB_POSITIONS:
        r, c = K4_GRID[pos]
        if r == row:
            crib_cols.add(c)
    non_crib_by_row[row] = set(range(31)) - crib_cols

# Intersection across all 3 rows
common_non_crib = non_crib_by_row[25] & non_crib_by_row[26] & non_crib_by_row[27]
print(f"\nNon-crib cols in row 25: {sorted(non_crib_by_row[25])}")
print(f"Non-crib cols in row 26: {sorted(non_crib_by_row[26])}")
print(f"Non-crib cols in row 27: {sorted(non_crib_by_row[27])}")
print(f"\n*** Columns that are non-crib in ALL three rows: {sorted(common_non_crib)} ***")
print(f"Count: {len(common_non_crib)}")

# This should be exactly {8,9,10,11,12,13,14,15,16}
if sorted(common_non_crib) == AVAILABLE_COLS:
    print("CONFIRMED: These are exactly the 9 columns in the null band (8-16)")
else:
    print(f"MISMATCH: Expected {AVAILABLE_COLS}, got {sorted(common_non_crib)}")
    # Show the difference
    extra = common_non_crib - set(AVAILABLE_COLS)
    missing = set(AVAILABLE_COLS) - common_non_crib
    if extra:
        print(f"  Extra columns: {sorted(extra)}")
    if missing:
        print(f"  Missing columns: {sorted(missing)}")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("HOW CRIBS CREATE THE GAP — GEOMETRIC VIEW")
print("=" * 80)

print("""
Visualization of K4 in the 31-column grid:
(. = non-crib, E = ENE crib, B = BC crib, blank = not K4)
""")

for row in [24, 25, 26, 27]:
    line = f"  Row {row}: "
    for col in range(31):
        # Find if this (row, col) is in K4
        found = False
        for i, (r, c) in enumerate(K4_GRID):
            if r == row and c == col:
                if i in CRIB_POSITIONS:
                    word = "E" if 21 <= i <= 33 else "B"
                    line += word
                else:
                    line += "."
                found = True
                break
        if not found:
            line += " "
    # Add column numbers underneath
    print(line)

col_header = "         " + "".join(f"{i%10}" for i in range(31))
print(col_header)
col_tens = "         " + "".join(f"{i//10}" for i in range(31))
print(col_tens)

print(f"""
The gap is visible: columns 8-16 have NO crib letters in any row.
Row 25: ENE starts at col 17 → cols 0-16 are non-crib
         But cols 0-7 become crib columns via row 27 (BC continuation)
         So only cols 8-16 are free in ALL rows.

Row 27: BC occupies cols 0-7 → cols 8-30 are non-crib
         But cols 17-29 are crib columns via row 25 (ENE)
         And col 30 is crib via row 25 (not part of ENE though—let me check)
""")

# Verify col 30 in row 25
for pos in CRIB_POSITIONS:
    r, c = K4_GRID[pos]
    if r == 25 and c == 30:
        print(f"  K4[{pos}] at row 25, col 30 = '{CRIB_DICT[pos]}' — IS a crib!")
    if r == 25 and c == 17:
        print(f"  K4[{pos}] at row 25, col 17 = '{CRIB_DICT[pos]}' — IS a crib!")

# Show ENE more precisely
print("\nENE crib precise mapping:")
for i in range(21, 34):
    r, c = K4_GRID[i]
    print(f"  K4[{i}] = '{CRIB_DICT[i]}' at row {r}, col {c}")

print("\nBC crib precise mapping:")
for i in range(63, 74):
    r, c = K4_GRID[i]
    print(f"  K4[{i}] = '{CRIB_DICT[i]}' at row {r}, col {c}")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("WIDER CONTEXT: WHAT IF NULLS COME FROM OUTSIDE THE BAND?")
print("=" * 80)

print("""
We've been focused on band-based masks (8 cols from 8-16).
But row 26 has 28 non-crib columns and row 27 has 23.
The total non-crib positions across all 4 rows:
""")

non_crib_all = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)
print(f"Total non-crib positions: {len(non_crib_all)} out of 97")
print(f"Need to choose 24 as nulls from these {len(non_crib_all)} positions")
print(f"That's C({len(non_crib_all)}, 24) = ~10^17 — too many to enumerate")

# But the constraint that the mask is COLUMN-BASED (same cols for all rows)
# dramatically reduces the space
print(f"\nColumn-based constraint (same 8 cols in all 3 full rows):")
print(f"  Only 9 available columns → C(9,8) = 9 masks")
print(f"  Reduction factor: ~10^17 / 9 ≈ 10^16")

# What about the 24° angle further constraining?
print(f"\n24° angle constraint (staggered band, shift 0-1 per row):")
print(f"  ~15 valid staggered masks (from Part 2)")
print(f"  Each gives 24 nulls, all cribs preserved")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("TESTING MONOALPHABETIC SUBSTITUTION ON BEST MASKS")
print("=" * 80)

# For each column mask, try frequency analysis on the 73-char extract
print("If the cipher is monoalphabetic, frequency analysis should work on 73 chars.\n")

for kept in [8, 12, 16]:  # Representative masks
    null_cols = set(AVAILABLE_COLS) - {kept}
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols]
    null_set = set(nulls)
    text_73 = ''.join(CT[i] for i in range(CT_LEN) if i not in null_set)

    print(f"  Kept col {kept}: '{text_73}'")
    freq = Counter(text_73)
    total = len(text_73)
    print(f"  Letter frequencies (sorted):")
    for ch, count in freq.most_common():
        pct = count / total * 100
        bar = "#" * int(pct)
        print(f"    {ch}: {count:2d} ({pct:5.1f}%) {bar}")

    # IC of the extract
    freqs = [0]*26
    for c in text_73:
        freqs[ALPH_IDX[c]] += 1
    n = len(text_73)
    ic_val = sum(f*(f-1) for f in freqs) / (n*(n-1))
    print(f"  IC = {ic_val:.4f} (English=0.0667, random=0.0385)")

    # Compare with English frequency expectations
    eng_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    ct_order = ''.join(ch for ch, _ in freq.most_common())
    print(f"  CT frequency order:      {ct_order}")
    print(f"  English frequency order:  {eng_order}")
    print()

# ══════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("IC COMPARISON: RAW 97 vs EACH 73-CHAR EXTRACT")
print("=" * 80)

# IC of raw 97
freqs_97 = [0]*26
for c in CT:
    freqs_97[ALPH_IDX[c]] += 1
ic_97 = sum(f*(f-1) for f in freqs_97) / (97*96)
print(f"  IC of raw 97-char CT: {ic_97:.4f}")

for kept in AVAILABLE_COLS:
    null_cols = set(AVAILABLE_COLS) - {kept}
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols]
    null_set = set(nulls)
    text_73 = ''.join(CT[i] for i in range(CT_LEN) if i not in null_set)

    freqs = [0]*26
    for c in text_73:
        freqs[ALPH_IDX[c]] += 1
    ic_val = sum(f*(f-1) for f in freqs) / (73*72)

    # IC of the 24 removed chars
    removed = ''.join(CT[i] for i in range(CT_LEN) if i in null_set)
    freqs_r = [0]*26
    for c in removed:
        freqs_r[ALPH_IDX[c]] += 1
    ic_removed = sum(f*(f-1) for f in freqs_r) / (24*23)

    print(f"  Col {kept:2d}: IC(73)={ic_val:.4f}  IC(24 removed)={ic_removed:.4f}  "
          f"removed='{removed}'")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("THE REMOVED CHARACTERS — WHAT DO THEY SPELL?")
print("=" * 80)

print("If the null band hides a secondary message, the 24 removed chars might be meaningful.\n")

for kept in AVAILABLE_COLS:
    null_cols = set(AVAILABLE_COLS) - {kept}
    nulls = sorted(i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols)
    removed = ''.join(CT[i] for i in nulls)
    print(f"  Col {kept:2d} kept → removed 24: '{removed}'")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("K4 POSITION MAP — COMPLETE")
print("=" * 80)

print("\nK4 positions in the 28×31 grid (K4 index, character, row, col):\n")
print(f"{'K4':>3s} {'CH':>2s} {'ROW':>3s} {'COL':>3s}  {'CRIB?':>5s} {'ZONE':>6s}")
for i, (r, c) in enumerate(K4_GRID):
    is_crib = 'CRIB' if i in CRIB_POSITIONS else ''
    if c <= 7:
        zone = "A(0-7)"
    elif c <= 16:
        zone = "B(8-16)"
    else:
        zone = "C(17-30)"
    if r == 24:
        zone = "ROW24"
    print(f"{i:3d}  {CT[i]}  {r:3d} {c:3d}  {is_crib:5s} {zone}")

print("\nDone.")
