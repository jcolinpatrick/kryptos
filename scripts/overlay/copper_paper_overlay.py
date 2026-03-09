#!/usr/bin/env python3
"""
Copper-as-Paper Overlay Analysis

Theory: All copper in the Kryptos installation represents "paper" (Sanborn's own word).
The cipher side and tableau side are two "pages" of the same sheet.
The tableau is "intentionally flipped" (CIA official page) — readable from behind.

When light shines through from the tableau side:
- Front position (row, col) maps to back position (row, 30-col) due to horizontal flip
- We check what tableau character sits "behind" each K4 cipher character

This script maps every K4 position to its flipped tableau counterpart.
"""

import sys
sys.path.insert(0, "src")
from kryptos.kernel.constants import CT

# === CIPHER GRID (28x31) ===
# Full cipher side content (all 4 messages)
# We only need K4's position: starts at row 24, col 27

K4 = CT  # 97 chars
assert len(K4) == 97

# K4 grid positions (0-indexed rows 0-27 of full 28x31 grid)
# Row 24, cols 27-30: K4[0:4]
# Row 25, cols 0-30:  K4[4:35]
# Row 26, cols 0-30:  K4[35:66]
# Row 27, cols 0-30:  K4[66:97]

k4_positions = []  # list of (k4_index, grid_row, grid_col)
idx = 0
for c in range(27, 31):
    k4_positions.append((idx, 24, c))
    idx += 1
for r in range(25, 28):
    for c in range(31):
        k4_positions.append((idx, r, c))
        idx += 1
assert idx == 97

# === TABLEAU GRID (28x31) ===
# KA alphabet
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
assert len(KA) == 26
assert len(AZ) == 26

# Build full 28x31 tableau
tableau = []

# Row 0 (header): space + ABCDEFGHIJKLMNOPQRSTUVWXYZABCD
header = [' '] + list("ABCDEFGHIJKLMNOPQRSTUVWXYZABCD")
assert len(header) == 31
tableau.append(header)

# Rows 1-26 (body): key letter + 30-char KA cyclic shift
for key_idx in range(26):
    key_letter = AZ[key_idx]
    # Body = KA shifted by key_idx (first 30 chars)
    body = [(KA[(key_idx + j) % 26]) for j in range(30)]
    row = [key_letter] + body
    assert len(row) == 31, f"Row {key_idx+1} has {len(row)} chars"
    tableau.append(row)

# Row 27 (footer): same as header
tableau.append(header[:])

assert len(tableau) == 28

# Verify a few known values from memory/kryptos_tableau.md
# Row 2 (key=A, index 1): AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP
row1 = ''.join(tableau[1])
assert row1 == "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP", f"Row 1 mismatch: {row1}"

# Row 25 (key=X, index 24): XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK
row24 = ''.join(tableau[24])
assert row24 == "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK", f"Row 24 mismatch: {row24}"

# Row 27 (key=Z, index 26): ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY
row26 = ''.join(tableau[26])
assert row26 == "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY", f"Row 26 mismatch: {row26}"

print("=" * 80)
print("COPPER-AS-PAPER OVERLAY: K4 Cipher Side vs Flipped Tableau")
print("=" * 80)
print()
print("Physical model: light shines from behind (tableau side).")
print("Horizontal flip: front (row, col) → back (row, 30-col)")
print()

# === MAP EACH K4 POSITION ===
print(f"{'K4#':>4} {'CT':>3} {'Grid':>8} {'Flip':>8} {'Tab':>4} {'Match':>6} {'TabType':>10}")
print("-" * 55)

matches = []
mismatches = []
spaces = []
key_col_hits = []
header_footer_hits = []

# Track tableau chars behind K4
tableau_behind = []

for k4_idx, grow, gcol in k4_positions:
    ct_char = K4[k4_idx]

    # Flipped column
    flip_col = 30 - gcol

    # Tableau char at flipped position
    tab_char = tableau[grow][flip_col]
    tableau_behind.append(tab_char)

    # Classify the tableau position
    if grow == 0 or grow == 27:
        tab_type = "header/ftr"
        if flip_col == 0:
            tab_type = "hdr-space"
    elif flip_col == 0:
        tab_type = "key-col"
    else:
        tab_type = "body"

    is_match = ct_char == tab_char
    match_str = "MATCH" if is_match else ""

    if tab_char == ' ':
        spaces.append(k4_idx)
    if is_match:
        matches.append(k4_idx)
    if flip_col == 0 and grow not in (0, 27):
        key_col_hits.append(k4_idx)
    if grow == 0 or grow == 27:
        header_footer_hits.append(k4_idx)

    # Crib annotation
    crib = ""
    if 21 <= k4_idx <= 33:
        crib = f" ← ENE[{k4_idx-21}]={'EASTNORTHEAST'[k4_idx-21]}"
    elif 63 <= k4_idx <= 73:
        crib = f" ← BC[{k4_idx-63}]={'BERLINCLOCK'[k4_idx-63]}"

    print(f"{k4_idx:>4} {ct_char:>3} ({grow:>2},{gcol:>2}) ({grow:>2},{flip_col:>2}) {tab_char:>4} {match_str:>6} {tab_type:>10}{crib}")

print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"\nExact matches (CT char == Tableau char behind): {len(matches)}")
for i in matches:
    ct = K4[i]
    print(f"  K4[{i}] = '{ct}' (both sides)")

print(f"\nSpaces (tableau has blank behind K4 position): {len(spaces)}")
for i in spaces:
    print(f"  K4[{i}] = '{K4[i]}'")

print(f"\nKey column hits (flipped to col 0 = key letter column): {len(key_col_hits)}")
for i in key_col_hits:
    grow = [g for idx, g, c in k4_positions if idx == i][0]
    tab = tableau[grow][0]
    print(f"  K4[{i}] = '{K4[i]}' → key letter '{tab}' (row key={AZ[grow-1]})")

print(f"\nHeader/footer row hits: {len(header_footer_hits)}")

# The flipped tableau string behind K4
tab_str = ''.join(tableau_behind)
print(f"\nTableau string behind K4 (flipped): {tab_str}")
print(f"Length: {len(tab_str)}")

# Check for interesting properties
from collections import Counter
tab_freq = Counter(tab_str)
print(f"\nTableau-behind letter frequencies:")
for ch in sorted(tab_freq.keys()):
    print(f"  {ch}: {tab_freq[ch]}", end="")
print()

# IC of tableau string (excluding spaces)
tab_letters = [c for c in tab_str if c != ' ']
n = len(tab_letters)
if n > 1:
    freq = Counter(tab_letters)
    ic = sum(f * (f-1) for f in freq.values()) / (n * (n-1))
    print(f"\nIC of tableau-behind string: {ic:.4f} (n={n})")

# What if the "real" K4 chars are where CT char DIFFERS from tableau char?
# (light blocked = null; light through = real)
# Or opposite: matching = light passes through same shape?
print()
print("=" * 80)
print("INTERPRETATIONS")
print("=" * 80)

print(f"\n1. If MATCHES = real (same cutout shape → light passes):")
print(f"   Real positions ({len(matches)}): {matches}")
print(f"   Null positions ({97 - len(matches)}): not enough/too many for 73-char hypothesis")

print(f"\n2. If NON-KEY-COL and NON-SPACE = real (body tableau letters behind = real):")
body_positions = [i for i, (idx, gr, gc) in zip(range(97), k4_positions)
                  if tableau_behind[i] != ' ' and (30 - gc) != 0]
# Wait, need to fix this
body_real = []
non_body = []
for k4_idx, grow, gcol in k4_positions:
    flip_col = 30 - gcol
    tab_char = tableau[grow][flip_col]
    if tab_char == ' ':
        non_body.append(k4_idx)
    elif flip_col == 0 and grow not in (0, 27):
        non_body.append(k4_idx)  # key column
    else:
        body_real.append(k4_idx)

print(f"   Body tableau behind: {len(body_real)} positions")
print(f"   Non-body (space/key-col): {len(non_body)} positions → {non_body}")

# The W-separator positions
w_positions = [i for i in range(97) if K4[i] == 'W']
print(f"\n3. W positions in K4: {w_positions}")
print(f"   Tableau behind W positions: ", end="")
for i in w_positions:
    print(f"K4[{i}]→'{tableau_behind[i]}' ", end="")
print()

# Check: does the tableau-behind string XOR with CT give anything?
print(f"\n4. Vigenère decrypt K4 using tableau-behind as key:")
result = []
for i in range(97):
    ct_val = ord(K4[i]) - ord('A')
    tab_char = tableau_behind[i]
    if tab_char == ' ':
        result.append('?')
    else:
        tab_val = ord(tab_char) - ord('A')
        # Vigenère: PT = (CT - Key) mod 26
        pt_val = (ct_val - tab_val) % 26
        result.append(chr(pt_val + ord('A')))
pt_vig = ''.join(result)
print(f"   Vig:  {pt_vig}")

result2 = []
for i in range(97):
    ct_val = ord(K4[i]) - ord('A')
    tab_char = tableau_behind[i]
    if tab_char == ' ':
        result2.append('?')
    else:
        tab_val = ord(tab_char) - ord('A')
        # Beaufort: PT = (Key - CT) mod 26
        pt_val = (tab_val - ct_val) % 26
        result2.append(chr(pt_val + ord('A')))
pt_beau = ''.join(result2)
print(f"   Beau: {pt_beau}")

# Check IC of results
for label, pt in [("Vig", pt_vig), ("Beau", pt_beau)]:
    letters = [c for c in pt if c != '?']
    n = len(letters)
    freq = Counter(letters)
    ic = sum(f * (f-1) for f in freq.values()) / (n * (n-1))
    print(f"   IC({label}): {ic:.4f}")

# Check for cribs in results
for label, pt in [("Vig", pt_vig), ("Beau", pt_beau)]:
    for crib_name, crib in [("EASTNORTHEAST", "EASTNORTHEAST"), ("BERLINCLOCK", "BERLINCLOCK")]:
        if crib in pt:
            pos = pt.index(crib)
            print(f"   *** {label} contains {crib_name} at position {pos}! ***")

print()
print("=" * 80)
print("GRID VISUALIZATION: K4 cipher vs flipped tableau")
print("=" * 80)

# Show row-by-row
rows_data = [
    ("Row 24 (key=X)", 24, 27, 31),
    ("Row 25 (key=Y)", 25, 0, 31),
    ("Row 26 (key=Z)", 26, 0, 31),
    ("Row 27 (footer)", 27, 0, 31),
]

k4_idx = 0
for label, row, start_col, end_col in rows_data:
    print(f"\n{label}:")
    cipher_chars = []
    tableau_chars = []
    for c in range(start_col, end_col):
        cipher_chars.append(K4[k4_idx])
        flip_c = 30 - c
        tableau_chars.append(tableau[row][flip_c])
        k4_idx += 1

    print(f"  Cipher (front):   {' '.join(cipher_chars)}")
    print(f"  Tableau (behind): {' '.join(tableau_chars)}")
    match_line = []
    for ci, ti in zip(cipher_chars, tableau_chars):
        if ci == ti:
            match_line.append('*')
        elif ti == ' ':
            match_line.append('_')
        else:
            match_line.append('.')
    print(f"  Matches:          {' '.join(match_line)}")
    print(f"  (* = same letter, _ = space, . = different)")
