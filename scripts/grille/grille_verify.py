#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Deterministic Cardan grille verification.

Applies the user's explicit visible-cell mask to the Kryptos Vigenère tableau.
No cyclic extension — out-of-bounds cells are flagged and skipped.
Reading order: left-to-right, top-to-bottom.
"""

# ── KA Vigenère Tableau (exact sculpture data from e_grille_08) ──────────
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",                # Row 1: header (31)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",                # Row 2: A (31)
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",                # Row 3: B (31)
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",                # Row 4: C (31)
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",                # Row 5: D (31)
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",                # Row 6: E (31)
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",                # Row 7: F (31)
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",                # Row 8: G (31)
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",                # Row 9: H (31)
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",                # Row 10: I (31)
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",                # Row 11: J (31)
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",                # Row 12: K (31)
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",                # Row 13: L (31)
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",                # Row 14: M (31)
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",               # Row 15: N (32) extra L
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",                # Row 16: O (31)
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",                # Row 17: P (31)
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",                # Row 18: Q (31)
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",                # Row 19: R (31)
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",                # Row 20: S (31)
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",                # Row 21: T (31)
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",                # Row 22: U (31)
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWXT",               # Row 23: V (32) extra T
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",                # Row 24: W (31)
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",                # Row 25: X (31)
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",                # Row 26: Y (31)
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",                # Row 27: Z (31)
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",                # Row 28: footer (31)
]

# ── Visible cells (col, row) — 1-based ──────────────────────────────────
VISIBLE_CELLS = [
    (9,1), (11,1), (13,1), (23,1), (33,1),
    (1,2), (11,2), (17,2), (21,2), (26,2), (27,2), (32,2), (33,2),
    (15,3), (32,3), (33,3),
    (21,4), (28,4), (31,4), (32,4), (33,4),
    (8,5), (17,5), (22,5), (31,5), (32,5), (33,5),
    (9,6), (31,6), (32,6), (33,6),
    (1,7), (32,7), (33,7),
    (24,8), (30,8), (32,8), (33,8),
    (20,9), (28,9), (33,9),
    (29,10), (32,10), (33,10),
    (9,11), (31,11), (32,11), (33,11),
    (6,12), (7,12), (30,12), (32,12), (33,12),
    (15,13), (18,13), (19,13), (32,13), (33,13),
    (12,14), (28,14), (33,14),
    (4,15), (5,15), (7,15), (13,15), (26,15), (30,15), (32,15), (33,15),
    (5,16), (7,16), (25,16), (31,16), (32,16), (33,16),
    (3,17), (6,17), (11,17), (12,17), (13,17), (28,17), (30,17), (32,17), (33,17),
    (12,18), (13,18), (22,18), (27,18), (31,18), (32,18), (33,18),
    (14,19), (18,19), (21,19), (29,19), (30,19), (31,19), (32,19), (33,19),
    (17,20), (20,20), (29,20), (30,20), (32,20), (33,20),
    (9,21), (10,21), (17,21), (19,21), (21,21), (25,21), (28,21), (31,21), (32,21), (33,21),
    (16,22), (21,22), (23,22), (25,22), (27,22), (32,22), (33,22),
    (8,23), (9,23), (21,23), (26,23), (27,23), (32,23), (33,23),
    (1,24), (21,24), (26,24), (27,24), (31,24), (33,24),
    (1,25), (8,25), (13,25), (14,25), (20,25), (30,25), (31,25), (32,25), (33,25),
    (5,26), (20,26), (25,26), (32,26), (33,26),
    (20,27), (25,27), (32,27), (33,27),
    (15,28), (23,28), (25,28), (29,28), (30,28), (31,28), (32,28), (33,28),
]

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

print("=" * 80)
print("CARDAN GRILLE VERIFICATION — DETERMINISTIC COORDINATE EXTRACTION")
print("=" * 80)

# ── 1. GRID NORMALIZATION ────────────────────────────────────────────────
print("\n--- 1. GRID NORMALIZATION ---")
print(f"Grid rows: {len(TABLEAU_ROWS)}")
row_lengths = [len(r) for r in TABLEAU_ROWS]
print(f"Row lengths: {row_lengths}")
print(f"Min width: {min(row_lengths)}, Max width: {max(row_lengths)}")
print(f"Declared grid: 33 cols × 28 rows")
print(f"Total visible cells declared: {len(VISIBLE_CELLS)}")

# Validate row count
assert len(TABLEAU_ROWS) == 28, f"Expected 28 rows, got {len(TABLEAU_ROWS)}"

# ── 2. MASK EVALUATION — classify each cell ─────────────────────────────
print("\n--- 2. MASK EVALUATION ---")

# Sort visible cells in reading order: by row, then by column
sorted_cells = sorted(VISIBLE_CELLS, key=lambda c: (c[1], c[0]))

in_bounds = []
out_of_bounds = []

for col, row in sorted_cells:
    row_len = len(TABLEAU_ROWS[row - 1])
    if col <= row_len:
        letter = TABLEAU_ROWS[row - 1][col - 1]  # 1-based to 0-based
        in_bounds.append((col, row, letter))
    else:
        out_of_bounds.append((col, row, row_len))

print(f"IN_BOUNDS cells:     {len(in_bounds)}")
print(f"OUT_OF_BOUNDS cells: {len(out_of_bounds)}")
print(f"Total:               {len(in_bounds) + len(out_of_bounds)}")

print(f"\nOUT_OF_BOUNDS cells (col > row_length):")
for col, row, row_len in out_of_bounds:
    print(f"  ({col:2d},{row:2d}) — row {row} has {row_len} cols, col {col} is {col - row_len} beyond")

# ── 3. EXTRACTION (in-bounds only, reading order) ───────────────────────
print(f"\n--- 3. EXTRACTION TRACE ---")
print(f"{'Pos':>4} {'Coord':>10} {'Letter':>7} {'Row_Len':>8}")
extracted = []
for i, (col, row, letter) in enumerate(in_bounds):
    row_len = len(TABLEAU_ROWS[row - 1])
    extracted.append(letter)
    print(f"{i:4d}  ({col:2d},{row:2d})    {letter:>4}     {row_len:>4}")

extracted_str = ''.join(extracted)

# ── 4. COMPARISON WITH USER STRING ──────────────────────────────────────
print(f"\n--- 4. COMPARISON ---")
print(f"Extracted length: {len(extracted_str)}")
print(f"User CT length:   {len(USER_CT)}")
print(f"\nExtracted: {extracted_str}")
print(f"User CT:   {USER_CT}")

min_len = min(len(extracted_str), len(USER_CT))
matches = 0
mismatches = []
for i in range(min_len):
    if extracted_str[i] == USER_CT[i]:
        matches += 1
    else:
        mismatches.append((i, extracted_str[i], USER_CT[i], in_bounds[i]))

print(f"\nCharacter matches: {matches}/{min_len}")
if mismatches:
    print(f"\nMISMATCHES ({len(mismatches)}):")
    for pos, got, expected, (col, row, _) in mismatches:
        print(f"  pos {pos:3d}: extracted '{got}' vs user '{expected}' at ({col},{row})")

if len(extracted_str) != len(USER_CT):
    print(f"\nLENGTH MISMATCH: {len(extracted_str)} extracted vs {len(USER_CT)} user")

# ── 5. OCCUPANCY MAP ────────────────────────────────────────────────────
print(f"\n--- 5. BINARY OCCUPANCY MAP (1=VISIBLE in-bounds, x=VISIBLE out-of-bounds, 0=MASKED) ---")
visible_set = set((c, r) for c, r in VISIBLE_CELLS)
oob_set = set((c, r) for c, r, _ in out_of_bounds)

# Find max row length for display
max_len = max(row_lengths)
print(f"     {''.join(str(c % 10) for c in range(1, max_len + 1))}")
for row_idx in range(1, 29):
    row_len = len(TABLEAU_ROWS[row_idx - 1])
    line = []
    for col_idx in range(1, max_len + 1):
        if col_idx > row_len:
            if (col_idx, row_idx) in oob_set:
                line.append('x')
            else:
                line.append('·')
        elif (col_idx, row_idx) in visible_set:
            line.append('1')
        else:
            line.append('0')
    print(f"R{row_idx:02d}: {''.join(line)}")

# ── 6. PER-ROW EXTRACTION SUMMARY ──────────────────────────────────────
print(f"\n--- 6. PER-ROW EXTRACTION ---")
row_groups = {}
for col, row, letter in in_bounds:
    row_groups.setdefault(row, []).append((col, letter))

for row_num in sorted(row_groups.keys()):
    cells = row_groups[row_num]
    letters = ''.join(l for _, l in cells)
    coords = [(c, row_num) for c, _ in cells]
    row_label = TABLEAU_ROWS[row_num - 1][0] if TABLEAU_ROWS[row_num - 1][0] != ' ' else '·'
    print(f"  Row {row_num:2d} ({row_label}): {letters:20s} from {coords}")

# ── 7. FINAL SUMMARY ───────────────────────────────────────────────────
print(f"\n{'=' * 80}")
print("FINAL RESULT")
print(f"{'=' * 80}")
print(f"Total visible cells declared: {len(VISIBLE_CELLS)}")
print(f"In-bounds (extractable):      {len(in_bounds)}")
print(f"Out-of-bounds (skipped):      {len(out_of_bounds)}")
print(f"Extracted sequence ({len(extracted_str)} chars): {extracted_str}")
print(f"User CT            ({len(USER_CT)} chars): {USER_CT}")
if extracted_str == USER_CT:
    print("\n*** PERFECT MATCH ***")
elif matches == min_len and len(extracted_str) != len(USER_CT):
    print(f"\n*** PREFIX MATCH — length differs by {abs(len(extracted_str) - len(USER_CT))} chars ***")
else:
    print(f"\n*** {len(mismatches)} MISMATCHES at positions: {[m[0] for m in mismatches]} ***")
print(f"Conflicts: {len(mismatches)}")
print(f"Assumptions: out-of-bounds cells skipped (no cyclic extension)")
