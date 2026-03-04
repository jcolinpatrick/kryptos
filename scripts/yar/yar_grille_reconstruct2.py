#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
YAR Cardan grille reconstruction - version 2.

Key insight from v1: rows 1-4 (header + body rows A-C) match perfectly.
Starting from row 5 (body row D), all positions are shifted.

The issue is likely the column alignment between cipher and tableau.
The tableau has a LABEL column that shifts things.

Let me carefully model the tableau from the image and then figure out
the correct mapping.

From the image:
- Column 1 has the row labels for body rows (A through Z)
- The header row has NO label in column 1
- Columns 2-31 contain the body of the tableau (30 chars)
- Some rows extend to col 32 or 33

But the CIPHERTEXT side doesn't have labels. So how do the cipher characters
map to columns?

Hypothesis: The cipher text occupies columns 1 through N (where N = line length).
When overlaid, cipher col 1 aligns with tableau col 1 (which is the label column
for body rows, or blank for header/footer).

For the HEADER row (tableau row 1), there's no label at col 1, and the header
starts at col 2. So cipher col 1 on the header row maps to tableau col 1 (blank),
cipher col 2 maps to header col 2 = 'A', etc.

For BODY rows (tableau rows 2-27), col 1 has the label letter. The body text
is in cols 2-31. So cipher col 1 maps to the label letter, cipher col 2 maps
to the first body character, etc.

Wait, but in v1, the first 13 chars all matched correctly! Let me check:
- Row 1 (header): cipher 'R' at col 9 -> tableau col 9 = 'H'.
  Header: cols 2-27 = A-Z. Col 9 = H (the 8th letter of A-Z). Correct!
- Row 2 (body A): cipher 'Y' at col 1 -> tableau col 1 = label 'A'. Correct!
- Row 2: cipher 'Y' at col 11 -> tableau col 11.
  Body row A, col 11 = KA[9] = C. (offset = col-2 = 9, KA[0+9] = C). Correct!

So for rows 1-4, my mapping works. But starting at row 5 (body row D), it breaks.

Let me check row 5 specifically. The image shows:
- Row 5, col 7: 'C'
- Row 5, col 17: 'M'
- Row 5, col 22: 'W'

My tableau for row 5 (body row D, row_idx=3):
- Col 7: offset = 7-2 = 5, KA[(3+5)%26] = KA[8] = C. That IS 'C'.

Wait, that matches 'C'. But the user's CT at this position has 'O', not 'C'.
And the IMAGE shows 'C' at row 5 col 7.

Hmm, so the IMAGE shows 'C' but the user's CT has 'O'? Let me recheck.

Actually wait - positions 0-12 are:
0: H, 1: J, 2: L, 3: V, 4: A, 5: C, 6: I, 7: N, 8: X, 9: Z, 10: H, 11: U, 12: Y

The user's CT: H J L V A C I N X Z H U Y O C M W S E A F Y B Z A C J F H I F X R Y V F I J M X E I L L N E L J N X Z K I L K R D I N P A D M N V Z A C E I M U W A F G I M U K R G I L V H N Q X W Y A B X Z K I K J U F Q R X C D

So position 13 in user's CT is 'O'. My extraction at position 13 gives 'C'.

My position 13 is at row 5, col 8 (CT='A'). The ciphertext line 5 is:
TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA

Position 0123456789...
T=1, I=2, M=3, V=4, M=5, Z=6, J=7, A=8, N=9, Q=10, L=11, V=12, K=13, Q=14,
E=15, D=16, A=17, G=18, D=19, V=20, F=21, R=22, P=23, J=24, U=25, N=26, G=27,
E=28, U=29, N=30, A=31
That's 31 chars. The A's are at positions 7, 16, 30 (cols 8, 17, 31).
The R is at position 21 (col 22).

The IMAGE shows for row 5: 'C' at col 7, 'M' at col 17, 'W' at col 22.

But wait - col 7 in the image has the value shown at that specific column number.
And the CT has 'J' at col 7 (position 6, 0-indexed). 'J' is NOT Y/A/R, so col 7
should NOT be a grille hole.

The CT has 'A' at col 8 (position 7). So the grille hole should be at col 8.
But the IMAGE shows the letter at col 7, not col 8!

This suggests the cipher text is SHIFTED by 1 column relative to the tableau
for certain rows. OR, more likely, the cipher text row widths don't match what
I have, causing cumulative misalignment.

Actually, let me reconsider. Maybe the ciphertext is NOT laid out starting at col 1
for all rows. Maybe it starts at col 2 for body rows (to account for the label column).

Let me test: if the cipher text for body rows starts at col 2 instead of col 1:
- Row 5 (body D): cipher char at position 0 = 'T' goes to col 2,
  position 7 = 'A' goes to col 9, not col 8.
- Row 5 col 9: Body D, offset=7, KA[(3+7)%26] = KA[10] = E. That gives 'E', not 'O'.

That doesn't help either. Let me try a different approach: reverse-engineer the
mapping from the image.
"""

# KA alphabet
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Build the full tableau as (image_row, image_col) -> letter
# This time, let me be very explicit and print it out for verification.

tableau = {}

# Header (row 1): cols 2-31 = ABCDEFGHIJKLMNOPQRSTUVWXYZ + ABCD
header = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "ABCD"
for i, ch in enumerate(header):
    tableau[(1, i + 2)] = ch

# Body rows (rows 2-27 = labels A-Z)
ROW_LABELS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
for row_idx, label in enumerate(ROW_LABELS):
    img_row = row_idx + 2
    tableau[(img_row, 1)] = label
    # Standard 30 body chars in cols 2-31
    for col_offset in range(30):
        ka_idx = (row_idx + col_offset) % 26
        tableau[(img_row, col_offset + 2)] = KA[ka_idx]
    # Row N (img_row 15) has extra chars
    if label == 'N':
        for extra in range(30, 32):
            ka_idx = (row_idx + extra) % 26
            tableau[(img_row, extra + 2)] = KA[ka_idx]

# Footer (row 28): same as header
for i, ch in enumerate(header):
    tableau[(28, i + 2)] = ch

# Now print rows around where mismatches happen to verify tableau construction
print("TABLEAU VERIFICATION (selected rows):")
for img_row in [1, 2, 5, 6, 7, 8, 9, 15, 17, 20, 23, 28]:
    row_str = ""
    for col in range(1, 34):
        ch = tableau.get((img_row, col), '.')
        row_str += ch
    print(f"  Row {img_row:2d}: {row_str}")

# Now let me check: what does the IMAGE show at specific positions?
# From careful reading of the image:
print("\n" + "=" * 70)
print("IMAGE VERIFICATION: Reading white cells from image")
print("=" * 70)

# These are the (row, col, letter) triples I read from the image
image_cells = [
    # Row 1
    (1, 9, 'H'), (1, 11, 'J'), (1, 13, 'L'), (1, 23, 'V'),
    # Row 2
    (2, 1, 'A'), (2, 11, 'C'), (2, 17, 'I'), (2, 21, 'N'), (2, 25, 'X'), (2, 26, 'Z'),
    # Row 3
    (3, 14, 'H'),
    # Row 4
    (4, 21, 'U'), (4, 27, 'Y'), (4, 31, 'O'),
    # Row 5
    (5, 7, 'C'), (5, 17, 'M'), (5, 22, 'W'), (5, 30, 'S'),
    # Row 6
    (6, 9, 'E'), (6, 30, 'A'),
    # Row 7
    (7, 1, 'F'),
    # Row 8
    (8, 24, 'Y'), (8, 31, 'B'),
    # Row 9
    (9, 20, 'Z'), (9, 28, 'A'),
    # Row 10
    (10, 29, 'C'),
    # Row 11
    (11, 9, 'J'),
    # Row 12
    (12, 5, 'H'), (12, 6, 'I'), (12, 31, 'F'),
    # Row 13
    (13, 15, 'X'), (13, 19, 'R'), (13, 20, 'Y'),
    # Row 14
    (14, 12, 'V'), (14, 27, 'F'),
    # Row 15
    (15, 3, 'I'), (15, 4, 'J'), (15, 7, 'M'), (15, 13, 'X'), (15, 24, 'E'),
    (15, 30, 'I'), (15, 33, 'L'),
    # Row 16
    (16, 5, 'L'), (16, 7, 'N'), (16, 24, 'E'), (16, 31, 'L'),
    # Row 17
    (17, 1, 'J'), (17, 5, 'N'), (17, 12, 'X'), (17, 13, 'Z'), (17, 14, 'K'),
    (17, 28, 'I'), (17, 30, 'L'),
    # Row 18
    (18, 12, 'K'), (18, 13, 'R'), (18, 22, 'D'), (18, 27, 'I'), (18, 30, 'N'),
    # Row 19
    (19, 14, 'P'), (19, 18, 'A'), (19, 21, 'D'), (19, 28, 'M'), (19, 29, 'N'),
    # Row 20
    (20, 5, 'V'), (20, 8, 'Z'), (20, 17, 'A'), (20, 18, 'C'), (20, 21, 'E'),
    (20, 24, 'I'), (20, 27, 'M'), (20, 31, 'U'),
    # Row 21
    (21, 5, 'W'), (21, 14, 'A'), (21, 20, 'F'), (21, 21, 'G'), (21, 24, 'I'),
    (21, 27, 'M'), (21, 31, 'U'),
    # Row 22
    (22, 8, 'K'), (22, 9, 'R'), (22, 19, 'G'), (22, 22, 'I'), (22, 25, 'L'),
    (22, 26, 'N'), (22, 27, 'Q'),
    # Row 23
    (23, 1, 'V'), (23, 19, 'H'), (23, 31, 'X'),
    # Row 24
    (24, 1, 'W'), (24, 8, 'Y'), (24, 12, 'A'), (24, 13, 'B'), (24, 30, 'X'),
    (24, 31, 'Z'),
    # Row 25
    (25, 4, 'K'), (25, 17, 'I'), (25, 30, 'K'),
    # Row 26
    (26, 17, 'J'), (26, 25, 'U'),
    # Row 27
    (27, 13, 'F'), (27, 22, 'Q'), (27, 30, 'R'),
    # Row 28
    (28, 24, 'X'), (28, 30, 'C'), (28, 31, 'D'),
]

print(f"\nTotal white cells read from image: {len(image_cells)}")
reading_order = ''.join(ch for _, _, ch in image_cells)
print(f"Reading order: {reading_order}")
print(f"Length: {len(reading_order)}")

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
print(f"\nUser CT: {USER_CT}")
print(f"Length: {len(USER_CT)}")

# Check if my image reading matches user CT
print(f"\nDirect image reading matches user CT: {reading_order == USER_CT}")

if reading_order != USER_CT:
    min_len = min(len(reading_order), len(USER_CT))
    for i in range(min_len):
        if reading_order[i] != USER_CT[i]:
            print(f"  First mismatch at pos {i}: read='{reading_order[i]}', user='{USER_CT[i]}'")
            break
    if len(reading_order) != len(USER_CT):
        print(f"  Length diff: read={len(reading_order)}, user={len(USER_CT)}")

# Now verify each image cell against my tableau
print("\n" + "=" * 70)
print("VERIFY IMAGE CELLS vs COMPUTED TABLEAU")
print("=" * 70)
mismatches = 0
for row, col, img_letter in image_cells:
    tab_letter = tableau.get((row, col), '?')
    match = "OK" if tab_letter == img_letter else "MISMATCH"
    if tab_letter != img_letter:
        mismatches += 1
        print(f"  Row {row:2d} Col {col:2d}: image='{img_letter}' tableau='{tab_letter}' {match}")

print(f"\nTotal mismatches: {mismatches}/{len(image_cells)}")
if mismatches == 0:
    print("ALL IMAGE CELLS MATCH COMPUTED TABLEAU - tableau construction is correct!")
