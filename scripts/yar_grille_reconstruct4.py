#!/usr/bin/env python3
"""
YAR Cardan grille reconstruction - version 4.

New approach: Use the physical sculpture layout data.

The sculpture has two sides - cipher and tableau. The cipher side is the
S-curved copper screen with the ciphertext. The tableau side has the
Vigenère tableau.

From the fold_theory memory and other analysis, we know the exact row
layout of the ciphertext on the sculpture. Let me use the actual
sculpture row structure.

The key reference is the Kryptos sculpture layout:
- 28 rows of cipher text on one side
- 28 rows of tableau on the other side (header + 26 body + footer)

The ciphertext rows ARE the lines from full_ciphertext.md.
The tableau rows are: header (A-Z + ABCD), 26 KA-shifted rows, footer.

The CRITICAL question: column alignment between cipher and tableau.

On the physical sculpture, the cipher and tableau are on opposite sides
of the same copper sheet. When you look through a hole, you see the
corresponding position on the other side. The question is: does cipher
column N align with tableau column N?

From the v2 test, rows 1-4 had many correct matches, suggesting the
basic column alignment is correct. But there are systematic errors.

Let me try a different tableau construction. Maybe the KA alphabet
wraps differently than I think. Let me use the actual tableau data
from the memory file directly instead of computing it.
"""

# KA alphabet
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Build tableau directly from the memory file data
# From memory/kryptos_tableau.md:
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",       # Header (row 1)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",       # A (row 2)
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",       # B (row 3)
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",       # C (row 4)
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",       # D (row 5)
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",       # E (row 6)
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",       # F (row 7)
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",       # G (row 8)
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",       # H (row 9)
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",       # I (row 10)
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",       # J (row 11)
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",       # K (row 12)
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",       # L (row 13)
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",       # M (row 14)
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",      # N (row 15) - 32 chars! extra L
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # O (row 16)
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",       # P (row 17)
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",       # Q (row 18)
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",       # R (row 19)
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",       # S (row 20)
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",      # T (row 21) - wait this is wrong
]

# Wait, I'm mixing up cipher and tableau! The tableau rows from the memory file
# are the TABLEAU side. Let me re-read the file carefully.

# Actually looking at the memory file more carefully:
# Row O: "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL"
# This has 31 chars. But the standard should be 31 (1 label + 30 body).
# Let me verify: O-H-I-J-L-M-N-Q-U-V-W-X-Z-K-R-Y-P-T-O-S-A-B-C-D-E-F-G-H-I-J-L
# That's 31. But wait, row O starts at KA offset 14 (O is 15th letter A-O = 14th index).
# KA[(14+0)%26] = H, KA[(14+1)%26] = I, KA[(14+2)%26] = J, ...
# Actually, O is index 14 in A-Z (A=0, B=1, ..., O=14).
# KA[14] = H. So Row O body starts with H. ✓

# The memory file tableau rows include the label as first char.
# Let me use these directly.

TABLEAU_DATA = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # row 1 (header)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",        # row 2  (A)
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",        # row 3  (B)
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",        # row 4  (C)
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",        # row 5  (D)
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",        # row 6  (E)
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",        # row 7  (F)
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",        # row 8  (G)
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",        # row 9  (H)
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",        # row 10 (I)
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",        # row 11 (J)
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",        # row 12 (K)
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",        # row 13 (L)
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",        # row 14 (M)
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # row 15 (N) - 32 chars
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",        # row 16 (O)
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",        # row 17 (P)
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",        # row 18 (Q)
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",        # row 19 (R)
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",        # row 20 (S)
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",        # row 21 (T)
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",        # row 22 (U)
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",        # row 23 (V)
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",        # row 24 (W)
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",        # row 25 (X)
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",        # row 26 (Y)
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",        # row 27 (Z)
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # row 28 (footer)
]

# Verify row lengths
print("Tableau row data:")
for i, row in enumerate(TABLEAU_DATA):
    img_row = i + 1
    print(f"  Row {img_row:2d}: len={len(row):2d} '{row}'")

# Build tableau dict: (row, col) -> letter
# The first character of each row is at col 1
tableau = {}
for i, row_data in enumerate(TABLEAU_DATA):
    img_row = i + 1
    for j, ch in enumerate(row_data):
        img_col = j + 1  # 1-indexed
        tableau[(img_row, img_col)] = ch

# Now verify against the image cells I read
image_cells = [
    (1, 9, 'H'), (1, 11, 'J'), (1, 13, 'L'), (1, 23, 'V'),
    (2, 1, 'A'), (2, 11, 'C'), (2, 17, 'I'), (2, 21, 'N'), (2, 25, 'X'), (2, 26, 'Z'),
    (3, 14, 'H'),
    (4, 21, 'U'), (4, 27, 'Y'), (4, 31, 'O'),
    (5, 7, 'C'), (5, 17, 'M'), (5, 22, 'W'), (5, 30, 'S'),
    (6, 9, 'E'), (6, 30, 'A'),
    (7, 1, 'F'),
    (8, 24, 'Y'), (8, 31, 'B'),
    (9, 20, 'Z'), (9, 28, 'A'),
    (10, 29, 'C'),
    (11, 9, 'J'),
    (12, 5, 'H'), (12, 6, 'I'), (12, 31, 'F'),
    (13, 15, 'X'), (13, 19, 'R'), (13, 20, 'Y'),
    (14, 12, 'V'), (14, 27, 'F'),
    (15, 3, 'I'), (15, 4, 'J'), (15, 7, 'M'), (15, 13, 'X'), (15, 24, 'E'),
    (15, 30, 'I'), (15, 33, 'L'),
    (16, 5, 'L'), (16, 7, 'N'), (16, 24, 'E'), (16, 31, 'L'),
    (17, 1, 'J'), (17, 5, 'N'), (17, 12, 'X'), (17, 13, 'Z'), (17, 14, 'K'),
    (17, 28, 'I'), (17, 30, 'L'),
    (18, 12, 'K'), (18, 13, 'R'), (18, 22, 'D'), (18, 27, 'I'), (18, 30, 'N'),
    (19, 14, 'P'), (19, 18, 'A'), (19, 21, 'D'), (19, 28, 'M'), (19, 29, 'N'),
    (20, 5, 'V'), (20, 8, 'Z'), (20, 17, 'A'), (20, 18, 'C'), (20, 21, 'E'),
    (20, 24, 'I'), (20, 27, 'M'), (20, 31, 'U'),
    (21, 5, 'W'), (21, 14, 'A'), (21, 20, 'F'), (21, 21, 'G'), (21, 24, 'I'),
    (21, 27, 'M'), (21, 31, 'U'),
    (22, 8, 'K'), (22, 9, 'R'), (22, 19, 'G'), (22, 22, 'I'), (22, 25, 'L'),
    (22, 26, 'N'), (22, 27, 'Q'),
    (23, 1, 'V'), (23, 19, 'H'), (23, 31, 'X'),
    (24, 1, 'W'), (24, 8, 'Y'), (24, 12, 'A'), (24, 13, 'B'), (24, 30, 'X'),
    (24, 31, 'Z'),
    (25, 4, 'K'), (25, 17, 'I'), (25, 30, 'K'),
    (26, 17, 'J'), (26, 25, 'U'),
    (27, 13, 'F'), (27, 22, 'Q'), (27, 30, 'R'),
    (28, 24, 'X'), (28, 30, 'C'), (28, 31, 'D'),
]

print("\n" + "=" * 70)
print("VERIFY IMAGE CELLS vs TABLEAU DATA")
print("=" * 70)
mismatches = 0
for row, col, img_letter in image_cells:
    tab_letter = tableau.get((row, col), '?')
    if tab_letter != img_letter:
        mismatches += 1
        # Find where in the row this letter actually appears
        row_data = TABLEAU_DATA[row - 1]
        actual_positions = [i+1 for i, ch in enumerate(row_data) if ch == img_letter]
        print(f"  Row {row:2d} Col {col:2d}: image='{img_letter}' tableau='{tab_letter}'"
              f" ('{img_letter}' appears at cols {actual_positions} in this row)")

print(f"\nTotal mismatches: {mismatches}/{len(image_cells)}")

# Now let me try: what if the cipher side has each row's first character at col 1,
# but the TABLEAU side has the first character shifted?
# On the physical sculpture, the cipher text is on one side and the tableau on the other.
# Due to the S-curve shape, when you fold/overlay them, there might be an offset.

# Actually, the simpler hypothesis: what if the column numbering in the image
# uses col 1 for the HEADER A position (not blank), and the label column doesn't
# exist?

# In the memory file, the header row starts with a SPACE, suggesting col 1 is empty.
# If the image numbers cols starting from the first actual content character...

# Actually I realize the issue might be that the image was generated by the user
# and the column numbers might count differently. Let me instead try to match
# the image data against different column offsets for each row.

print("\n" + "=" * 70)
print("BRUTE FORCE: Find best column offset per row")
print("=" * 70)

from collections import defaultdict
row_cells = defaultdict(list)
for row, col, letter in image_cells:
    row_cells[row].append((col, letter))

for img_row in sorted(row_cells.keys()):
    cells = row_cells[img_row]
    row_data = TABLEAU_DATA[img_row - 1]

    best_offset = None
    best_matches = -1

    for offset in range(-5, 6):
        matches = 0
        for col, letter in cells:
            adj_col = col + offset
            if 1 <= adj_col <= len(row_data):
                if row_data[adj_col - 1] == letter:
                    matches += 1
        if matches > best_matches:
            best_matches = matches
            best_offset = offset

    total = len(cells)
    print(f"  Row {img_row:2d}: best_offset={best_offset:+d}, "
          f"matches={best_matches}/{total}", end="")

    if best_matches < total:
        # Show which cells still don't match
        bad = []
        for col, letter in cells:
            adj_col = col + best_offset
            if 1 <= adj_col <= len(row_data):
                if row_data[adj_col - 1] != letter:
                    bad.append(f"c{col}={letter}(got {row_data[adj_col-1]})")
            else:
                bad.append(f"c{col}={letter}(out of range)")
        print(f"  BAD: {', '.join(bad)}", end="")
    print()
