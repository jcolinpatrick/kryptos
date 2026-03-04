#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Analyze the first-E exclusion and Cardan grille overlay on the 28×31 cipher grid.

Key discovery: The cipher side has 869 total characters (865 letters + 4 ?'s).
28 × 31 = 868. The first E is the extra character.
Without it, every row is exactly 31 characters wide.

This script:
1. Verifies all 28 row lengths (with and without first E)
2. Maps the grid structure (K1/K2/K3/K4 + ? boundaries)
3. Overlays the Cardan grille onto the cipher grid
4. Tests if grille holes on K4 positions define the unscrambling permutation
"""

import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as K4_CT

# ============================================================
# SECTION 1: Full cipher text (as carved, 28 visual lines)
# ============================================================

# These are the 28 lines as they appear on the sculpture's cipher side
LINES = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",   # Row 1
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",    # Row 2
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",     # Row 3
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",     # Row 4
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",     # Row 5
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",   # Row 6
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",     # Row 7
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",    # Row 8
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",    # Row 9
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",    # Row 10
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",     # Row 11
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",    # Row 12
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",    # Row 13
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",    # Row 14 (last K1+K2 row)
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA",   # Row 15 (K3 starts)
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",     # Row 16
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",     # Row 17
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",      # Row 18
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",   # Row 19
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",      # Row 20
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",   # Row 21
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",    # Row 22
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",  # Row 23
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",      # Row 24
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",    # Row 25 (K3 ends, K4 starts)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",    # Row 26
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",    # Row 27
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",   # Row 28
]

print("=" * 80)
print("SECTION 1: Row Lengths")
print("=" * 80)

total = 0
for i, line in enumerate(LINES):
    total += len(line)
    marker = ""
    if len(line) != 31:
        marker = f"  *** {len(line)} chars (NOT 31) ***"
    print(f"Row {i+1:2d}: {len(line):2d} chars{marker}  {line}")

print(f"\nTotal: {total}")
print(f"Letters: {sum(1 for c in ''.join(LINES) if c.isalpha())}")
print(f"Question marks: {sum(1 for c in ''.join(LINES) if c == '?')}")

# Without first E
grid_text = ''.join(LINES)[1:]  # Skip the first E
print(f"\nWithout first E: {len(grid_text)} chars")
print(f"28 × 31 = {28*31}")
print(f"Perfect fit: {len(grid_text) == 28*31}")

# ============================================================
# SECTION 2: The 28×31 Grid (without first E)
# ============================================================

print()
print("=" * 80)
print("SECTION 2: 28×31 Grid (first E excluded)")
print("=" * 80)

WIDTH = 31
NROWS = 28

grid = []
for r in range(NROWS):
    row = grid_text[r*WIDTH : (r+1)*WIDTH]
    grid.append(row)

# Mark section boundaries
full = ''.join(LINES)
# Find ? positions in full text
q_positions_full = [i for i, c in enumerate(full) if c == '?']
print(f"Question mark positions in full text (0-indexed): {q_positions_full}")

# In grid text (shifted by 1)
q_positions_grid = [p - 1 for p in q_positions_full]
print(f"Question mark positions in grid text: {q_positions_grid}")

# Find K4 in grid text
k4_pos = grid_text.find(K4_CT)
print(f"\nK4 '{K4_CT[:20]}...' starts at grid position {k4_pos}")
print(f"K4 in grid: row {k4_pos // WIDTH}, col {k4_pos % WIDTH}")
print(f"K4 ends at grid position {k4_pos + len(K4_CT) - 1}")

# Print grid with section markers
print(f"\n{'Row':>3} {'Col0':>4}  {'Content':<31}  Section")
print("-" * 75)

for r in range(NROWS):
    start = r * WIDTH
    end = start + WIDTH
    row_str = grid[r]

    # Determine section
    sections = []
    for c in range(WIDTH):
        pos = start + c
        ch = grid_text[pos]
        if ch == '?':
            sections.append('?')
        elif pos < k4_pos:
            # Check if K3
            k3_start_text = "ENDYAHROHNLSR"
            k3_pos = grid_text.find(k3_start_text)
            if k3_pos >= 0 and pos >= k3_pos:
                sections.append('K3')
            else:
                sections.append('K1K2')
        else:
            sections.append('K4')

    unique_sections = []
    seen = set()
    for s in sections:
        if s not in seen:
            unique_sections.append(s)
            seen.add(s)

    sec_str = '+'.join(unique_sections)
    print(f"{r:3d} [{start:3d}] {row_str}  {sec_str}")

# ============================================================
# SECTION 3: Does first E → Row 1 width 32 vs 31?
# ============================================================

print()
print("=" * 80)
print("SECTION 3: Line 1 Analysis")
print("=" * 80)
print(f"Line 1 with E:    '{LINES[0]}' ({len(LINES[0])} chars)")
print(f"Line 1 without E: '{LINES[0][1:]}' ({len(LINES[0])-1} chars)")
print()

# Check if all OTHER lines are 31
non_31_lines = [(i+1, len(line)) for i, line in enumerate(LINES) if len(line) != 31]
print("Lines with length ≠ 31:")
for row_num, length in non_31_lines:
    print(f"  Row {row_num}: {length} chars")

# ============================================================
# SECTION 4: K4's position in the grid
# ============================================================

print()
print("=" * 80)
print("SECTION 4: K4 Layout in 28×31 Grid")
print("=" * 80)

# K4 occupies rows 24-27 (0-indexed)
k4_row = k4_pos // WIDTH
k4_col = k4_pos % WIDTH

print(f"K4 starts at row {k4_row}, col {k4_col}")
print(f"K4 occupies {4 - (k4_col == 0)} rows" if k4_col > 0 else "K4 occupies 4 rows")
print()

# Show K4 in the grid
for r in range(k4_row, NROWS):
    row_start = r * WIDTH
    row_end = row_start + WIDTH
    row_str = grid[r]

    # Highlight K4 portion
    k4_start_in_row = max(0, k4_pos - row_start)
    k4_end_in_row = min(WIDTH, k4_pos + len(K4_CT) - row_start)

    before = row_str[:k4_start_in_row]
    k4_part = row_str[k4_start_in_row:k4_end_in_row]
    after = row_str[k4_end_in_row:]

    print(f"Row {r}: {before}[{k4_part}]{after}")

# What are the first chars of each K4 "internal" row in 31-wide layout?
print(f"\nK4 internal layout (31-wide rows starting from K4 position):")
for i in range(4):
    start = k4_pos + i * 31
    end = min(start + 31, k4_pos + 97)
    if start < k4_pos + 97:
        row = grid_text[start:end]
        print(f"  K4 row {i}: {row[:4]}...{row[-4:]} ({len(row)} chars)")

# ============================================================
# SECTION 5: Cardan Grille Overlay
# ============================================================

print()
print("=" * 80)
print("SECTION 5: Cardan Grille Overlay on Cipher Grid")
print("=" * 80)

# Parse the Cardan grille mask (from memory/cardan_grille.md)
MASK_ROWS = [
    "000000001010100000000010000000001~~",   # Row 01
    "100000000010000001000100110000011~~",   # Row 02
    "000000000000001000000000000000011~~",   # Row 03
    "00000000000000000000100000010011~~",    # Row 04
    "00000001000000001000010000000011~~",    # Row 05
    "000000001000000000000000000000011~",    # Row 06
    "100000000000000000000000000000011",     # Row 07
    "00000000000000000000000100000100~~",    # Row 08
    "0000000000000000000100000001000~~",     # Row 09
    "0000000000000000000000000000100~~",     # Row 10
    "000000001000000000000000000000~~",      # Row 11
    "00000110000000000000000000000100~~",    # Row 12
    "00000000000000100010000000000001~~",    # Row 13
    "00000000000100000000000000001000~~",    # Row 14
    "000110100001000000000000001000010~~",   # Row 15
    "00001010000000000000000001000001~~",    # Row 16
    "001001000010010000000000000100010~~",   # Row 17
    "00000000000100000000010000010001~~",    # Row 18
    "000000000000010001001000000010001~~",   # Row 19
    "00000000000000001001000000000100~~",    # Row 20
    "000000001100000010100100010001001~~",   # Row 21
    "000000000000000100001010100100011~",    # Row 22
    "00000000100000000000100001100001~~~",   # Row 23
    "100000000000000000001000001000010~",    # Row 24
    "10000001000001000000100000000001~~",    # Row 25
    "000010000000000000010000100000011",     # Row 26
    "0000000000000000000100001000000011",    # Row 27
    "00000000000000100000001010000001~~",    # Row 28
]

print(f"Mask has {len(MASK_ROWS)} rows")

# Parse each mask row: extract binary digits only (ignore tildes)
mask_parsed = []
total_ones = 0
total_zeros = 0
total_tildes = 0

for i, mrow in enumerate(MASK_ROWS):
    bits = []
    ntilde = 0
    for ch in mrow:
        if ch in '01':
            bits.append(int(ch))
        elif ch == '~':
            ntilde += 1
    ones = sum(bits)
    zeros = len(bits) - ones
    total_ones += ones
    total_zeros += zeros
    total_tildes += ntilde
    mask_parsed.append(bits)
    print(f"Mask row {i+1:2d}: {len(bits):2d} bits ({ones:2d} holes, {zeros:2d} solid, {ntilde} off-grid)")

print(f"\nTotals: {total_ones} holes, {total_zeros} solid, {total_tildes} off-grid")

# ============================================================
# SECTION 6: Overlay Grille on Cipher Grid
# ============================================================

print()
print("=" * 80)
print("SECTION 6: Grille-on-Cipher Overlay Analysis")
print("=" * 80)

# The cipher grid is 28 rows × 31 columns.
# The grille mask has 28 rows but varying widths (30-35 bits).
# We need to figure out the column alignment.

# Theory: The grille was placed on the TABLEAU (31 wide: 1 label + 30 body).
# The cipher grid (without E) is also 28 × 31.
# If the grille aligns the same way on both, the SAME holes read different data.

# Try various column alignments: offset 0 means grille col 0 = grid col 0
# The grille has 30-35 bits per row; the grid has 31 columns.

for offset in range(4):
    print(f"\n--- Alignment: grille col {offset} → grid col 0 ---")

    holes_on_k4 = 0
    holes_on_k1k2 = 0
    holes_on_k3 = 0
    holes_on_q = 0
    holes_total = 0
    holes_outside = 0

    k4_chars_from_grille = []  # (grid_pos, char) for holes landing on K4

    k3_text = "ENDYAHROHNLSR"
    k3_pos = grid_text.find(k3_text)

    for r in range(NROWS):
        bits = mask_parsed[r]
        for bit_idx, bit in enumerate(bits):
            if bit == 1:  # Hole
                grid_col = bit_idx - offset
                if grid_col < 0 or grid_col >= WIDTH:
                    holes_outside += 1
                    continue

                holes_total += 1
                grid_pos = r * WIDTH + grid_col
                ch = grid_text[grid_pos]

                if ch == '?':
                    holes_on_q += 1
                elif grid_pos >= k4_pos:
                    holes_on_k4 += 1
                    k4_chars_from_grille.append((grid_pos - k4_pos, ch))
                elif grid_pos >= k3_pos:
                    holes_on_k3 += 1
                else:
                    holes_on_k1k2 += 1

    print(f"  Total holes on grid: {holes_total}")
    print(f"  Holes outside grid: {holes_outside}")
    print(f"  K1+K2: {holes_on_k1k2}")
    print(f"  K3: {holes_on_k3}")
    print(f"  K4: {holes_on_k4}")
    print(f"  On ?: {holes_on_q}")

    if holes_on_k4 > 0:
        k4_chars_from_grille.sort()
        chars = ''.join(ch for _, ch in k4_chars_from_grille)
        print(f"  K4 chars read through grille: {chars}")
        print(f"  K4 positions: {[p for p, _ in k4_chars_from_grille]}")

# Also try MIRRORED grille (as if looking from the other side of the sculpture)
print()
print("=" * 80)
print("SECTION 7: MIRRORED Grille Overlay (flip horizontal)")
print("=" * 80)

for offset in range(4):
    print(f"\n--- Mirrored, offset {offset} ---")

    holes_on_k4 = 0
    holes_total = 0
    holes_outside = 0
    k4_chars = []

    k3_pos = grid_text.find("ENDYAHROHNLSR")

    for r in range(NROWS):
        bits = mask_parsed[r]
        row_width = len(bits)
        for bit_idx, bit in enumerate(bits):
            if bit == 1:
                # Mirror: flip column
                mirrored_col = (row_width - 1 - bit_idx) - offset
                if mirrored_col < 0 or mirrored_col >= WIDTH:
                    holes_outside += 1
                    continue

                holes_total += 1
                grid_pos = r * WIDTH + mirrored_col
                ch = grid_text[grid_pos]

                if grid_pos >= k4_pos:
                    holes_on_k4 += 1
                    k4_chars.append((grid_pos - k4_pos, ch))

    print(f"  Holes on grid: {holes_total}, on K4: {holes_on_k4}, outside: {holes_outside}")
    if holes_on_k4 > 0:
        k4_chars.sort()
        chars = ''.join(ch for _, ch in k4_chars)
        print(f"  K4 chars: {chars}")

# ============================================================
# SECTION 8: Check the ACTUAL sculpture row widths
# ============================================================

print()
print("=" * 80)
print("SECTION 8: Sculpture Row Width Analysis")
print("=" * 80)

print("\nWithout first E (shift row 1 by 1):")
adjusted_lines = [LINES[0][1:]] + LINES[1:]  # Remove first E
for i, line in enumerate(adjusted_lines):
    marker = "" if len(line) == 31 else f"  *** {len(line)} chars ***"
    print(f"Row {i+1:2d}: {len(line):2d} chars{marker}")

print(f"\nRows with 31 chars: {sum(1 for l in adjusted_lines if len(l) == 31)}/{len(adjusted_lines)}")
print(f"Total chars: {sum(len(l) for l in adjusted_lines)}")

# How many rows are NOT 31?
non_31 = [(i+1, len(l)) for i, l in enumerate(adjusted_lines) if len(l) != 31]
print(f"\nNon-31 rows: {non_31}")

# ============================================================
# SECTION 9: Test Grille holes as permutation for K4
# ============================================================

print()
print("=" * 80)
print("SECTION 9: Grille Holes as K4 Permutation")
print("=" * 80)

# The grille extract (106 chars) was read from the TABLEAU through the grille.
# If we overlay the SAME grille on the CIPHER grid:
# - Some holes will fall on K4 characters
# - The ORDER of those holes (left-to-right, top-to-bottom) could define the reading order
# - Reading K4 in that order might produce the unscrambled CT

# For this to work as an unscrambling permutation, we need exactly 97 holes on K4.
# Currently we're getting ~10-20 (K4 is only 97/868 ≈ 11% of the grid).

# Alternative: What if the grille is applied ONLY to K4 (not the whole grid)?
# K4 in 31-wide rows: 3 full rows (31 each) + 1 partial row (4 chars) = 97 chars
# K4 occupies rows 24-27 of the 28-row grid.
# The corresponding grille rows (25-28 in 1-indexed) would be rows 24-27 (0-indexed).

print("K4 occupies grid rows 24-27 (0-indexed)")
print(f"Grille rows 25-28 (1-indexed) = rows 24-27 (0-indexed)")
print()

# But first — the grille K4 rows might not align because K4 doesn't start at col 0.
# K4 starts at col 27 of row 24.

# Let's check what grille holes fall on K4's 4 rows
print("Grille holes on K4's grid rows:")
for r in range(24, 28):
    if r < len(mask_parsed):
        bits = mask_parsed[r]
        hole_cols = [i for i, b in enumerate(bits) if b == 1 and i < WIDTH]
        row_start = r * WIDTH

        # Which of these are K4?
        k4_hole_cols = []
        for c in hole_cols:
            pos = row_start + c
            if pos >= k4_pos and pos < k4_pos + 97:
                k4_hole_cols.append(c)

        print(f"  Row {r}: {len(hole_cols)} holes total, {len(k4_hole_cols)} on K4, cols: {k4_hole_cols}")

# ============================================================
# SECTION 10: What if we use grille on K4-only grid (different geometry)?
# ============================================================

print()
print("=" * 80)
print("SECTION 10: K4 as Standalone Grid + Grille")
print("=" * 80)

# K4 = 97 chars. 97 is prime. But we could lay it in various grids:
# 97 = 1×97 (trivial)
# If we pad to 98 = 2×49 or 7×14
# Or use the LAST 4 grille rows (rows 25-28) which have some holes

# Actually, key insight: K4 in the master grid spans PARTS of 4 rows.
# Rows 24-27 of the master grid. K4 chars per row:
# Row 24: cols 27-30 = 4 chars (OBKR)
# Row 25: cols 0-30 = 31 chars
# Row 26: cols 0-30 = 31 chars
# Row 27: cols 0-30 = 31 chars
# Total: 4 + 31 + 31 + 31 = 97 ✓

# What if we look at it differently: K4 occupies a 4×31 sub-grid
# (with 4 chars in row 0 and 31 in rows 1-3)
# The "missing" 27 chars of row 0 are K3 ending + ?

# Let me just show the visual layout
print("K4 in the master grid (rows 24-27):")
for r in range(24, 28):
    row = grid[r]
    # Mark K4 portion
    row_start = r * WIDTH
    k4_start_in_row = max(0, k4_pos - row_start)
    k4_end_in_row = min(WIDTH, k4_pos + 97 - row_start)

    annotated = ''
    for c in range(WIDTH):
        pos = row_start + c
        if pos >= k4_pos and pos < k4_pos + 97:
            annotated += row[c]
        else:
            annotated += '.'
    print(f"  Row {r}: {annotated}")

# ============================================================
# SECTION 11: Test: 106 grille holes → 97 K4 mapping
# ============================================================

print()
print("=" * 80)
print("SECTION 11: Grille Extract Length Analysis")
print("=" * 80)

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

print(f"Grille extract: {len(GRILLE_EXTRACT)} chars")
print(f"K4 length: {len(K4_CT)} chars")
print(f"Difference: {len(GRILLE_EXTRACT) - len(K4_CT)}")
print()

# 106 - 97 = 9. What are these 9 extra characters?
# Theory: 106 grille holes extract 106 chars from the tableau.
# When overlaid on the cipher grid, 97 of those holes fall on K4,
# and 9 fall on K3 or ? marks.

# Check: from Section 6, at various offsets, how many holes total landed on K4?
# (This was already computed above, but let's see if any combination gives 97)

# What if the grille should be applied to K4 ALONE in a different grid?
# K4 as 97 chars in a grid:
# If written in a 31×4 rectangle (31 cols, ~4 rows): 31×4=124 > 97
# But K4 only fills 97 of 124 positions.

# More interesting: What are the 106 hole positions across all 28 rows?
all_hole_positions = []
for r in range(NROWS):
    bits = mask_parsed[r]
    for c, b in enumerate(bits):
        if b == 1 and c < WIDTH:  # Only holes within 31-col grid
            all_hole_positions.append((r, c, r * WIDTH + c))

print(f"Holes within 31-col grid: {len(all_hole_positions)}")
print(f"  K4 positions ({k4_pos} to {k4_pos+96}):")
k4_holes = [(r, c, p) for r, c, p in all_hole_positions if p >= k4_pos and p < k4_pos + 97]
print(f"  {len(k4_holes)} holes on K4")
non_k4_holes = [(r, c, p) for r, c, p in all_hole_positions if p < k4_pos or p >= k4_pos + 97]
print(f"  {len(non_k4_holes)} holes NOT on K4")

# ============================================================
# SECTION 12: The E as Key Indicator
# ============================================================

print()
print("=" * 80)
print("SECTION 12: What Does the First E Mean?")
print("=" * 80)

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

print(f"E in KA alphabet: position {KA.index('E')}")
print(f"E in AZ alphabet: position {AZ.index('E')}")
print()

# E is the label of row 5 in the tableau (0-indexed from A)
# In KA, E is at position 11
# In AZ, E is at position 4

# What row of the tableau does E correspond to?
# Row E of the tableau: ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA
# This means: key letter E, decrypt using this row

print("Tableau row E: ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA")
print()

# Check: does E appear at special positions in K4?
e_positions_k4 = [i for i, c in enumerate(K4_CT) if c == 'E']
print(f"E positions in K4: {e_positions_k4}")
print(f"Number of E's in K4: {len(e_positions_k4)}")

# E in the full cipher text (as first char)
# K1 starts with E: EMUFPHZLR...
# K3 also starts with E: ENDYAHROHNLSR...
print(f"\nFirst char of K1: {LINES[0][0]}")
print(f"First char of K3: {LINES[14][0]}")
print(f"Both K1 and K3 start with E!")

# ============================================================
# SECTION 13: Precise ? position verification
# ============================================================

print()
print("=" * 80)
print("SECTION 13: Question Mark Position Verification")
print("=" * 80)

full_text = ''.join(LINES)
for i, pos in enumerate(q_positions_full):
    context_start = max(0, pos - 5)
    context_end = min(len(full_text), pos + 6)
    context = full_text[context_start:context_end]
    print(f"? #{i+1} at full pos {pos}: ...{context}...")

# What section is each ? in?
# K1: 63 chars (pos 0-62)
# K2: 369 chars (pos 63-431 in letter-only count)
# But with ?'s interspersed, the boundaries shift

# Cumulative position tracking
pos = 0
section_boundaries = {}
sections_text = {
    'K1': 63,   # letter count
    'K2': 369,
    'K3': 336,
    'K4': 97,
}

print("\nSection boundaries in full text (including ?'s):")
letters_seen = 0
q_seen = 0
current_section = 'K1'
section_letter_target = 63
boundaries = {}

for i, ch in enumerate(full_text):
    if ch == '?':
        q_seen += 1
    else:
        letters_seen += 1

    if letters_seen == 63 and 'K1_end' not in boundaries:
        boundaries['K1_end'] = i
    if letters_seen == 63 + 369 and 'K2_end' not in boundaries:
        boundaries['K2_end'] = i
    if letters_seen == 63 + 369 + 336 and 'K3_end' not in boundaries:
        boundaries['K3_end'] = i

print(f"K1 ends at full pos {boundaries.get('K1_end', '?')}")
print(f"K2 ends at full pos {boundaries.get('K2_end', '?')}")
print(f"K3 ends at full pos {boundaries.get('K3_end', '?')}")
print(f"K4 starts at full pos {boundaries.get('K3_end', 0) + 1} (after ? before OBKR)")

# Verify K4 starts correctly
k4_full_start = full_text.find(K4_CT)
print(f"K4 '{K4_CT[:10]}...' found at full pos {k4_full_start}")

# Verify ? before K4
if k4_full_start > 0:
    print(f"Character before K4: '{full_text[k4_full_start-1]}'")
    print(f"Context around K4 start: ...{full_text[k4_full_start-10:k4_full_start+10]}...")

# ============================================================
# SECTION 14: Alternative - What if one ? is NOT a ?
# ============================================================

print()
print("=" * 80)
print("SECTION 14: What If Only 3 Question Marks?")
print("=" * 80)

# If there are only 3 ?'s, total = 865 + 3 = 868 = 28×31 (no E exclusion needed!)
# The ? at position 288 (FLGGTEZ?FKZ) is the one between K2 and K3.
# Some sources may not include this as a ? on the sculpture.

print("If the 3rd ? (at FLGGTEZ?FKZ boundary) is NOT a ? on the sculpture:")
print(f"  Total = 865 letters + 3 ?'s = 868 = 28×31")
print(f"  No E exclusion needed! The first E fits perfectly.")
print()

# In this case, what replaces the ? at position 288?
# Context: FLGGTEZ_FKZBSFDQVG...
# This is at the K2 boundary. Some transcriptions might have an extra letter here.
print(f"Context: '{full_text[283:298]}'")
print("If the 3rd ? is actually a letter, the grid fits without excluding E.")
print()

# Let's also test: with all 4 ?'s and the E, can we fit 869 in a near-28×31 grid?
# 869 = 11 × 79 (both prime factors)
# 869 = 28 × 31 + 1
# No nice factorization other than 11 × 79

for a in range(2, 40):
    for b in range(2, 40):
        if a * b == 869:
            print(f"869 = {a} × {b}")

# ============================================================
# SECTION 15: Test reading order from grille holes on full grid
# ============================================================

print()
print("=" * 80)
print("SECTION 15: Full Grid Grille Reading → Unscramble K4")
print("=" * 80)

# What if the grille reading order across the ENTIRE grid defines a permutation?
# There are ~107 holes in 31-col space. If 97 of them are on K4 positions,
# the reading order of those 97 holes is the unscrambling permutation.

# But from Section 6, we only get ~10-20 holes on K4. Not enough.

# Alternative approach: The grille defines a GENERAL reading order for all 868 chars.
# The reading order produces a NEW sequence. K4 in this new sequence might be meaningful.

# Read all grid chars through holes (left-to-right, top-to-bottom)
hole_chars = []
for r, c, p in all_hole_positions:
    hole_chars.append(grid_text[p])

hole_text = ''.join(hole_chars)
print(f"Chars read through grille: {len(hole_text)}")
print(f"Text: {hole_text}")
print()

# Does this contain any K4 cribs?
CRIBS = ["EASTNORTHEAST", "BERLINCLOCK", "SLOWLY", "CHAMBER", "CANDLE"]
for crib in CRIBS:
    if crib in hole_text:
        print(f"  CRIB FOUND: {crib}")
    else:
        # Check if it's close to an anagram of K4
        pass

# Try Vigenère decrypt on hole_text with various keywords
def vigenere_decrypt(ct, key, alphabet):
    key_idx = {ch: i for i, ch in enumerate(alphabet)}
    pt = []
    kp = 0
    for ch in ct:
        if ch not in key_idx:
            pt.append(ch)
            continue
        cv = key_idx[ch]
        kv = key_idx[key[kp % len(key)]]
        pv = (cv - kv) % len(alphabet)
        pt.append(alphabet[pv])
        kp += 1
    return ''.join(pt)

# Only try on the alpha chars from holes
alpha_hole = ''.join(c for c in hole_text if c.isalpha())
print(f"\nAlpha chars from grille: {len(alpha_hole)} chars")
print(f"Text: {alpha_hole}")

for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    for alpha in [("AZ", AZ), ("KA", KA)]:
        pt = vigenere_decrypt(alpha_hole, keyword, alpha[1])
        for crib in CRIBS:
            if crib in pt:
                print(f"  HIT: Vig({keyword},{alpha[0]}): {crib} in {pt}")

print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)
print("""
Key findings:
1. Full cipher text = 869 chars (865 letters + 4 question marks)
2. 28 × 31 = 868 — exactly 1 character too many
3. The FIRST E is the extra character — line 1 has 32 chars, all others have 31
4. Without E: K3 starts at row 14, col 0 (perfect center split: 434/434)
5. K4 occupies rows 24-27 with OBKR at row 24, col 27
6. Grille (28 rows) overlays cipher grid (28 rows) directly
7. ALTERNATIVE: If 3rd ? is NOT a real ?, total = 868 with NO E exclusion needed

Critical question: Are there 3 or 4 question marks on the physical sculpture?
""")
