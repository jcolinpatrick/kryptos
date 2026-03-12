#!/usr/bin/env python3
"""
Geometric Null-Mask Part 4 — Key Invariance Proof & Implications
================================================================
CRITICAL FINDING from Part 3: The keystream at crib positions is IDENTICAL
across all 9 column-based masks! This is because the null columns (8-16)
are BETWEEN the two crib zones — removing them doesn't change which
ciphertext characters align with which plaintext characters at crib positions.

The cribs map to the SAME CT characters regardless of mask choice.
Only the NON-CRIB positions between the zones are affected.

This means: the choice of which column to keep affects ONLY positions 26-46
in the 73-char extract (the gap between the two crib blocks).

Implications:
1. Bean constraint is mask-invariant (always passes)
2. Periodic consistency is mask-invariant at crib positions
3. The mask determines only 3 characters (one per full row) in the middle zone
4. Cipher testing should focus on the NON-CRIB gap, not the crib positions
"""

import sys, os, math
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_POSITIONS, CRIB_DICT, ALPH_IDX, ALPH, MOD,
    KRYPTOS_ALPHABET, BEAN_EQ, BEAN_INEQ
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

def extract_and_map(null_positions):
    null_set = set(null_positions)
    text_73 = []
    pos_map = {}
    new_idx = 0
    for i in range(CT_LEN):
        if i not in null_set:
            text_73.append(CT[i])
            pos_map[i] = new_idx
            new_idx += 1
    return ''.join(text_73), pos_map

# ══════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("PROOF: CRIB CHARACTERS ARE MASK-INVARIANT")
print("=" * 80)

print("""
The null columns (8-16) are in the MIDDLE of K4's column range.
Crib positions span:
  ENE (21-33): columns 17-29 in row 25 → Zone C (RIGHT of null band)
  BC  (63-73): columns 28-30 in row 26 + columns 0-7 in row 27 → Zones A/C

None of the crib characters are in columns 8-16.
Therefore, removing ANY subset of columns 8-16 leaves ALL crib characters
in the extract, with the SAME ciphertext-to-plaintext pairing.

The only difference between masks is which 1-3 non-crib characters from
columns 8-16 appear in the 73-char extract and WHERE in the sequence.
""")

# Verify: show which characters change between masks
for kept in AVAILABLE_COLS:
    null_cols = set(AVAILABLE_COLS) - {kept}
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols]
    text_73, pos_map = extract_and_map(nulls)

    # Find the variable characters (from the kept column)
    var_chars = []
    for i, (r, c) in enumerate(K4_GRID):
        if c == kept and r >= 25:
            new_pos = pos_map[i]
            var_chars.append((i, CT[i], new_pos, r))

    print(f"  Keep col {kept}: variable chars = ", end="")
    for orig, ch, new, row in var_chars:
        print(f"K4[{orig}]='{ch}'→pos{new} ", end="")
    print()

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("THE GAP STRUCTURE: What the Mask Determines")
print("=" * 80)

# Show the structure of the 73-char extract for one mask
kept = 12  # Center of band
null_cols = set(AVAILABLE_COLS) - {kept}
nulls = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols]
text_73, pos_map = extract_and_map(nulls)

print(f"\n73-char extract (keeping col {kept}):")
print(f"  {text_73}")
print(f"  {''.join(str(i%10) for i in range(73))}")

# Mark zones
zone_markers = ['.' for _ in range(73)]
for orig_pos in range(21, 34):  # ENE
    new = pos_map[orig_pos]
    zone_markers[new] = 'E'
for orig_pos in range(63, 74):  # BC
    new = pos_map[orig_pos]
    zone_markers[new] = 'B'
# Mark variable positions
for i, (r, c) in enumerate(K4_GRID):
    if c == kept and r >= 25:
        new = pos_map[i]
        zone_markers[new] = 'V'
print(f"  {''.join(zone_markers)}")
print(f"  (E=ENE crib, B=BC crib, V=variable, .=fixed non-crib)")

# Show segments
fixed_before_ene = text_73[:pos_map[21]]
ene_text = text_73[pos_map[21]:pos_map[33]+1]
gap = text_73[pos_map[33]+1:pos_map[63]]
bc_text = text_73[pos_map[63]:pos_map[73]+1]
fixed_after_bc = text_73[pos_map[73]+1:]

print(f"\nSegment analysis:")
print(f"  Before ENE: [{pos_map[0]}..{pos_map[21]-1}] = '{fixed_before_ene}' ({len(fixed_before_ene)} chars)")
print(f"  ENE crib:   [{pos_map[21]}..{pos_map[33]}] = '{ene_text}' ({len(ene_text)} chars)")
print(f"  GAP:        [{pos_map[33]+1}..{pos_map[63]-1}] = '{gap}' ({len(gap)} chars)")
print(f"  BC crib:    [{pos_map[63]}..{pos_map[73]}] = '{bc_text}' ({len(bc_text)} chars)")
print(f"  After BC:   [{pos_map[73]+1}..72] = '{fixed_after_bc}' ({len(fixed_after_bc)} chars)")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("WHAT CHANGES BETWEEN MASKS — DETAILED VIEW")
print("=" * 80)

# Show the gap region for all 9 masks
print(f"\nThe GAP between ENE and BC cribs for each mask:")
print(f"  (chars 26-46 in the 73-char extract vary by mask)\n")

for kept in AVAILABLE_COLS:
    null_cols = set(AVAILABLE_COLS) - {kept}
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols]
    text_73, pos_map = extract_and_map(nulls)

    gap_start = pos_map[33] + 1
    gap_end = pos_map[63] - 1
    gap = text_73[gap_start:gap_end + 1]

    print(f"  Col {kept:2d}: gap[{gap_start}..{gap_end}] = '{gap}' ({len(gap)} chars)")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("COMBINED-COLUMN MASKS: KEEP 0, 2, OR 3+ COLUMNS")
print("=" * 80)

print("""
What if ALL 9 middle columns are null? (0 kept → 24+3 = 27 nulls → 70 chars)
What if 2 columns kept? (7 nulled → 21 nulls → 76 chars)
""")

# All 9 nulled (0 kept)
nulls_all = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in set(AVAILABLE_COLS)]
print(f"All 9 null → {len(nulls_all)} nulls (need 24, got {len(nulls_all)}) — TOO MANY")

# 7 nulled (2 kept) → 21 nulls
for combo2 in combinations(AVAILABLE_COLS, 2):
    null_cols = set(AVAILABLE_COLS) - set(combo2)
    nulls = [i for i, (r, c) in enumerate(K4_GRID) if r >= 25 and c in null_cols]
    if len(nulls) == 21:
        break
print(f"7 null → {21} nulls (need 24, got 21) — TOO FEW")

# What about 8 from cols 8-16 + row 24?
# Row 24 has 4 chars at cols 27-30 — these are NOT in null band
# So: 8 col × 3 rows = 24 from band, but row 24's chars at cols 27-30 are crib-adjacent
# (col 27 is K4[31]=K at ENE position)
# Let's verify row 24 is NOT in cribs
print(f"\nRow 24 K4 positions: K4[0..3] = '{CT[0:4]}' at cols 27-30")
print(f"Position 0 in cribs? {0 in CRIB_POSITIONS}")
print(f"Position 1 in cribs? {1 in CRIB_POSITIONS}")
print(f"Position 2 in cribs? {2 in CRIB_POSITIONS}")
print(f"Position 3 in cribs? {3 in CRIB_POSITIONS}")

# So we could null row 24 (4 chars) + 7 cols from band (21) = 25 → one too many
# Or: 4 row24 + fewer cols from band to make 24 total
# 4 + 3*N = 24 → N = 6.67 not integer
# But: if we keep some cells in the band non-null selectively...
# 4 (row24) + 24 (8 cols × 3 rows) = 28 nulls → too many
# Need row24 nulls + band nulls = 24
# row24 = 4, so band = 20. But 20/3 = 6.67 → can't be uniform columns

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("ASYMMETRIC BAND MASKS: DIFFERENT # OF NULLS PER ROW")
print("=" * 80)

print("""
What if the null count per row is NOT uniform?
Total must be 24. Possible splits across rows 25-27:
8+8+8=24 ✓ (uniform — our current model)
9+8+7=24 ✓ (one more from row 25, one fewer from row 27)
9+9+6=24 ✓ (etc.)
7+8+9=24 ✓ (reverse)
...

For each split, which columns can be nulled while preserving cribs?
""")

from itertools import product

crib_cols_per_row = {}
for pos in CRIB_POSITIONS:
    r, c = K4_GRID[pos]
    crib_cols_per_row.setdefault(r, set()).add(c)

print("Crib columns by row:")
for row in [25, 26, 27]:
    cols = crib_cols_per_row.get(row, set())
    avail = set(range(31)) - cols
    print(f"  Row {row}: {len(cols)} crib cols, {len(avail)} available → {sorted(avail)}")

# For each row, the max number of null columns = number of available columns
max_per_row = {
    25: len(set(range(31)) - crib_cols_per_row.get(25, set())),
    26: len(set(range(31)) - crib_cols_per_row.get(26, set())),
    27: len(set(range(31)) - crib_cols_per_row.get(27, set())),
}
print(f"\nMax nulls per row: {max_per_row}")

# Find all splits that sum to 24 and respect maxima
valid_splits = []
for n25 in range(max_per_row[25] + 1):
    for n26 in range(max_per_row[26] + 1):
        n27 = 24 - n25 - n26
        if 0 <= n27 <= max_per_row[27]:
            valid_splits.append((n25, n26, n27))

print(f"Valid (n25, n26, n27) splits summing to 24: {len(valid_splits)}")
for split in valid_splits[:10]:
    print(f"  {split}")
if len(valid_splits) > 10:
    print(f"  ... and {len(valid_splits) - 10} more")

# Focus on splits that can use ONLY columns 8-16 (our crib-free band)
# Row 25: available non-crib in band = cols 8-16 (9 cols, 0 crib)
# Row 26: available non-crib = many more (crib only at cols 28-30 + wrapping)
# Row 27: available non-crib = many more (crib only at cols 0-7)

# Actually, let me check what's available per row more carefully
for row in [25, 26, 27]:
    avail = sorted(set(range(31)) - crib_cols_per_row.get(row, set()))
    band_avail = sorted(set(AVAILABLE_COLS) & set(avail))
    non_band_avail = sorted(set(avail) - set(AVAILABLE_COLS))
    print(f"\n  Row {row}:")
    print(f"    All available ({len(avail)}): {avail}")
    print(f"    Band cols 8-16 available ({len(band_avail)}): {band_avail}")
    print(f"    Non-band available ({len(non_band_avail)}): {non_band_avail}")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("ROW 26 AND ROW 27 NON-BAND NULL OPTIONS")
print("=" * 80)

print("""
Row 26 has cribs at cols 28-30 (positions 63-65: NYP from BERLINCLOCK).
Other positions in row 26 NOT in cribs:
""")

for row in [25, 26, 27]:
    non_crib = []
    for i, (r, c) in enumerate(K4_GRID):
        if r == row and i not in CRIB_POSITIONS:
            non_crib.append((i, c, CT[i]))
    print(f"  Row {row}: non-crib positions:")
    for idx, col, ch in non_crib:
        in_band = "BAND" if col in AVAILABLE_COLS else "    "
        is_w = " W!" if idx in [20, 36, 48, 58, 74] else "   "
        print(f"    K4[{idx:2d}] col {col:2d} = '{ch}' {in_band}{is_w}")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("THE 24° DIAGONAL AS A GRILLE: PRECISE INTERSECTION")
print("=" * 80)

print("""
A line at 24° from horizontal through the K4 grid region.
Let's trace it precisely: starting from the top-left of the K4 bounding box
(row 24, col 0 of the full grid), going at angle 24° down-right.

The line equation: y = x * tan(24°) + y0
In grid coordinates: row = row0 + (col - col0) * tan(24°)

For K4's bounding box (rows 24-27, cols 0-30):
""")

angle_24 = math.radians(24)
slope = math.tan(angle_24)

# Multiple starting points along top edge and left edge of K4 bounding box
print("Lines from top edge (row 24) at 24°:")
for start_col in range(31):
    # Line: row = 24 + (col - start_col) * slope
    intersections = []
    for col in range(31):
        row_exact = 24 + (col - start_col) * slope
        row = round(row_exact)
        if 24 <= row <= 27:
            # Find K4 index at this (row, col)
            for ki, (kr, kc) in enumerate(K4_GRID):
                if kr == row and kc == col:
                    intersections.append((ki, kr, kc, CT[ki], row_exact))

    if intersections:
        is_crib = any(ki in CRIB_POSITIONS for ki, _, _, _, _ in intersections)
        chars = ''.join(ch for _, _, _, ch, _ in intersections)
        if len(intersections) >= 3:  # Only show substantial lines
            print(f"  Start col {start_col:2d}: {len(intersections)} hits → '{chars}'"
                  f" {'(hits crib!)' if is_crib else ''}")

# Lines from left edge (col 0)
print("\nLines from left edge (col 0) at 24°:")
for start_row_tenths in range(240, 280, 1):  # Row 24.0 to 27.9
    start_row = start_row_tenths / 10
    intersections = []
    for col in range(31):
        row_exact = start_row + col * slope
        row = round(row_exact)
        if 24 <= row <= 27:
            for ki, (kr, kc) in enumerate(K4_GRID):
                if kr == row and kc == col:
                    intersections.append((ki, kr, kc, CT[ki]))

    if len(intersections) >= 4:  # Show longer intersections
        is_crib = any(ki in CRIB_POSITIONS for ki, _, _, _ in intersections)
        chars = ''.join(ch for _, _, _, ch in intersections)
        indices = [ki for ki, _, _, _ in intersections]
        print(f"  Start row {start_row:.1f}: {len(intersections)} hits → '{chars}'"
              f" K4{indices}"
              f" {'(hits crib!)' if is_crib else ''}")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PARALLEL LINES AT 24° — COVERAGE ANALYSIS")
print("=" * 80)

print("""
How many parallel lines at 24° are needed to cover all 97 K4 positions?
(Like a Cardan grille rotated to 24°)

Line family: row = k + col * tan(24°), for different intercepts k.
Two positions are on the same line iff row1 - col1*tan(24°) ≈ row2 - col2*tan(24°)
""")

# Compute the "24° intercept" for each K4 position
intercepts = []
for i, (r, c) in enumerate(K4_GRID):
    intercept = r - c * slope
    intercepts.append((i, intercept, r, c, CT[i]))

# Sort by intercept
intercepts.sort(key=lambda x: x[1])

# Group into lines (positions with intercepts within 0.3 of each other)
lines = []
current_line = [intercepts[0]]
for item in intercepts[1:]:
    if abs(item[1] - current_line[-1][1]) < 0.3:
        current_line.append(item)
    else:
        lines.append(current_line)
        current_line = [item]
lines.append(current_line)

print(f"Number of distinct 24° lines through K4: {len(lines)}")
total_covered = 0
null_candidates = []

for line in lines:
    indices = [item[0] for item in line]
    chars = ''.join(item[4] for item in line)
    avg_intercept = sum(item[1] for item in line) / len(line)
    has_crib = any(idx in CRIB_POSITIONS for idx in indices)
    total_covered += len(indices)

    marker = ""
    if len(line) == 1 and not has_crib:
        null_candidates.append(indices[0])
        marker = " ← NULL CANDIDATE"
    if len(line) <= 2 or has_crib:
        pass  # Only print interesting lines
    print(f"  intercept={avg_intercept:6.2f}: {len(line)} pos → K4{indices} = '{chars}'"
          f" {'*CRIB*' if has_crib else ''}{marker}")

print(f"\nTotal positions covered: {total_covered}")
print(f"Single-position lines (no crib): {len(null_candidates)} → potential nulls")
print(f"  Positions: {null_candidates}")

# What if we null the positions on lines with only 1 position?
if len(null_candidates) == 24:
    print(f"\n*** EXACTLY 24 single-position lines! Testing as null mask... ***")
    text_73, pos_map = extract_and_map(null_candidates)
    crib_conflict = set(null_candidates) & CRIB_POSITIONS
    print(f"  Crib conflicts: {crib_conflict}")
    if not crib_conflict:
        print(f"  73-char extract: {text_73}")
elif len(null_candidates) < 24:
    print(f"\n  Need {24 - len(null_candidates)} more nulls")
    # Add from 2-position non-crib lines?
    two_pos_non_crib = []
    for line in lines:
        if len(line) == 2 and not any(item[0] in CRIB_POSITIONS for item in line):
            two_pos_non_crib.extend([item[0] for item in line])
    print(f"  2-position non-crib line positions: {len(two_pos_non_crib)}: {two_pos_non_crib}")
else:
    print(f"\n  Too many ({len(null_candidates)}) — need exactly 24")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("FINAL SUMMARY: GEOMETRIC NULL MASK FINDINGS")
print("=" * 80)

print("""
KEY FINDINGS:

1. STRUCTURAL RESULT: K4's crib positions occupy 22 of 31 grid columns.
   Only columns 8-16 (9 columns) are entirely crib-free across all 3 full rows.

2. COLUMN-BASED NULL MASK: Nulling 8 of these 9 columns (24 positions)
   creates exactly a 73-char extract. All 9 possible masks are valid
   (preserve all cribs, maintain contiguity). C(9,8) = 9 masks.

3. MASK INVARIANCE: The keystream at crib positions is IDENTICAL for all
   9 masks — the null columns sit between the two crib zones, so removing
   them doesn't affect CT↔PT alignment at crib positions.

4. 24° GEOMETRIC CONNECTION:
   - K4 height = 4 rows, null band width = 9 columns
   - 4/9 = 0.4444 ≈ tan(24°) = 0.4452 (0.18% error)
   - A 24° line through K4's extent sweeps across exactly the null band width

5. THREE-ZONE STRUCTURE:
   - Zone A (cols 0-7): 8 cols × 3 rows = 24 real chars
   - Zone B (cols 8-16): 9 cols × 3 rows = 24 nulls + 3 variable chars
   - Zone C (cols 17-30): 14 cols × 3 rows + 4 (row 24) = 46 real chars
   - Total: 24 + 3 + 46 = 73 real chars ✓

6. CIPHER BARRIER: No periodic cipher (Vig/Beau/VBeau, periods 1-20,
   AZ or KA alphabet, 303 keywords) produces ANY crib hits in any of
   the 729 possible band-based masks. No autokey produces hits either.
   The cipher layer is likely NON-STANDARD.

7. BEAN CONSTRAINT: All masks pass Bean equality (k[27]==k[65]).
   This is structural — positions 27 and 65 are both in crib zones.

8. STAGGERED DIAGONALS: Shifting the null band by 0-1 column per row
   (matching 24° slope) produces additional valid masks, but with
   identical crib-position keystreams and no cipher hits.

OPEN QUESTIONS:
- Which 1 of 9 columns is kept? (Geometric determination needed)
- What cipher operates on the 73-char extract? (Non-periodic, non-autokey)
- Does the 24° angle determine both the mask AND the cipher parameters?
- Is there a transposition layer WITHIN the null band selection?
""")
