#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: yar
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
YAR Cardan grille reconstruction - version 5.

New strategy: Instead of reading column numbers from the image, use
the known tableau and ciphertext data, and find the alignment that
reproduces the user's 106-char CT.

Key insight: The image column numbers might be slightly off in my reading.
Instead, I'll try different alignment strategies between cipher rows and
tableau rows.

The fundamental alignment options:
A) Cipher starts at col 1, tableau label at col 1, body at col 2+
   (cipher col 1 overlaps tableau label)
B) Cipher starts at col 2, aligning with tableau body
   (cipher col 1 aligns with tableau col 2)
C) Cipher starts at col 1, but tableau has no label offset
   (header mode: content starts at col 1)
D) Variable: different rows have different alignments due to the
   physical S-curve of the sculpture

Since v1 showed rows 1-4 matched perfectly with option A (cipher col 1 = tableau col 1),
let me stick with that base and figure out where it diverges.

Actually, wait. Let me re-examine v1 results more carefully. In v1:
- Positions 0-12 (rows 1-4) matched perfectly
- Position 13 (row 5, col 8, CT='A') gave 'C' but expected 'O'

The user's CT at position 13 is 'O'. If the tableau at this position should
give 'O', where in row D (row 5) does 'O' appear?

Row D = "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS"
         1234567890123456789012345678901
O appears at position 4 (col 4) and at position 28 (col 28).
Wait: D-P-T-O-S-A-B-C-D-E-F-G-H-I-J-L-M-N-Q-U-V-W-X-Z-K-R-Y-P-T-O-S
O is at index 3 (col 4) and index 29 (col 30).

But the cipher has 'A' (=Y/A/R target) at col 8 in row 5.
For the tableau to give 'O' at this position, we need tableau[row5][col] = 'O'.
'O' is at col 4 and col 30 in row 5.
Neither is col 8.

Unless the alignment between cipher and tableau is not 1-to-1 column mapping
for row 5. Hmm.

Let me try a completely different approach: exhaustive search for the
correct cipher-to-tableau column mapping that produces the user's CT.
"""

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Tableau data from memory file
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

# Ciphertext lines
CT_LINES = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",  # row 1: 32
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",   # row 2: 31
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",   # row 3: 31
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # row 4: 30
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 5: 31
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",  # row 6: 32
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",   # row 7: 31
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",   # row 8: 31
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",  # row 9: 32
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",  # row 10: 31
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 11: 30
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",  # row 12: 31
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",  # row 13: 31
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",  # row 14: 31
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA", # row 15: 32
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 16: 30
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # row 17: 31
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",    # row 18: 30
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR", # row 19: 32
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",    # row 20: 30
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI", # row 21: 32
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",  # row 22: 31
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",# row 23: 33
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",    # row 24: 29
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # row 25: 31
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",  # row 26: 31
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",  # row 27: 31
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR", # row 28: 31
]

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

print("User's CT:", USER_CT)
print("Length:", len(USER_CT))

# Try alignment: cipher char at position i in line maps to tableau position i+offset
# For each row, try offsets from -5 to +5
# For the header/footer rows, the tableau starts with a space at position 0

def try_extraction(ct_lines, tableau_data, offsets):
    """Extract grille characters using per-row offsets.
    offset = how many positions to shift cipher relative to tableau.
    cipher_pos + offset = tableau_pos (0-indexed within the row string)
    """
    result = []
    for row_idx in range(28):
        ct_line = ct_lines[row_idx]
        tab_row = tableau_data[row_idx]
        offset = offsets[row_idx] if isinstance(offsets, list) else offsets

        for ci, ch in enumerate(ct_line):
            if ch in ('Y', 'A', 'R'):
                ti = ci + offset
                if 0 <= ti < len(tab_row):
                    result.append(tab_row[ti])
                else:
                    result.append('?')
    return ''.join(result)

# First, try a single global offset
print("\n" + "=" * 70)
print("GLOBAL OFFSET SEARCH")
print("=" * 70)
for offset in range(-5, 6):
    extracted = try_extraction(CT_LINES, TABLEAU_DATA, offset)
    # Count matches with user CT
    min_len = min(len(extracted), len(USER_CT))
    matches = sum(1 for i in range(min_len) if extracted[i] == USER_CT[i])
    print(f"  Offset {offset:+d}: len={len(extracted):3d}, "
          f"matches={matches}/{len(USER_CT)} "
          f"{'<-- BEST' if matches > 80 else ''}")
    if offset == 0:
        print(f"    First 30: {extracted[:30]}")
        print(f"    User  30: {USER_CT[:30]}")

# Now try per-row optimization
print("\n" + "=" * 70)
print("PER-ROW OFFSET OPTIMIZATION")
print("=" * 70)

# For each row, determine which Y/A/R positions exist and what user CT chars they should produce
user_pos = 0
row_yar_data = []  # list of (row_idx, [(cipher_pos, target_char), ...])
for row_idx in range(28):
    ct_line = CT_LINES[row_idx]
    yar_positions = []
    for ci, ch in enumerate(ct_line):
        if ch in ('Y', 'A', 'R'):
            if user_pos < len(USER_CT):
                yar_positions.append((ci, USER_CT[user_pos]))
                user_pos += 1
    row_yar_data.append((row_idx, yar_positions))

print(f"Total Y/A/R positions found: {user_pos}")
print(f"User CT length: {len(USER_CT)}")
if user_pos != len(USER_CT):
    print(f"MISMATCH: {user_pos} Y/A/R positions vs {len(USER_CT)} user CT chars")
    print("This might mean UNDERGRUUND correction changes the count, or my CT lines are wrong")

# Find best offset for each row
best_offsets = []
for row_idx, yar_positions in row_yar_data:
    tab_row = TABLEAU_DATA[row_idx]

    best_off = 0
    best_matches = -1
    for offset in range(-5, 6):
        matches = 0
        for ci, target in yar_positions:
            ti = ci + offset
            if 0 <= ti < len(tab_row) and tab_row[ti] == target:
                matches += 1
        if matches > best_matches:
            best_matches = matches
            best_off = offset

    best_offsets.append(best_off)
    total = len(yar_positions)
    if total > 0:
        detail = ""
        # Show which ones don't match even with best offset
        bad = []
        for ci, target in yar_positions:
            ti = ci + best_off
            if 0 <= ti < len(tab_row):
                got = tab_row[ti]
                if got != target:
                    bad.append(f"ci={ci}:want={target},got={got}")
            else:
                bad.append(f"ci={ci}:want={target},OOB")
        if bad:
            detail = f"  BAD: {', '.join(bad)}"
        print(f"  Row {row_idx+1:2d} (tab '{TABLEAU_DATA[row_idx][0]}'): "
              f"offset={best_off:+d}, matches={best_matches}/{total}"
              f"{detail}")

# Extract with best per-row offsets
print("\n" + "=" * 70)
print("EXTRACTION WITH OPTIMAL PER-ROW OFFSETS")
print("=" * 70)
extracted = try_extraction(CT_LINES, TABLEAU_DATA, best_offsets)
min_len = min(len(extracted), len(USER_CT))
matches = sum(1 for i in range(min_len) if extracted[i] == USER_CT[i])
print(f"Extracted: {extracted}")
print(f"User CT:   {USER_CT}")
print(f"Matches: {matches}/{len(USER_CT)}")

# Show mismatches
if extracted != USER_CT:
    for i in range(min_len):
        if extracted[i] != USER_CT[i]:
            print(f"  Pos {i}: got '{extracted[i]}', want '{USER_CT[i]}'")

# Now let me also check: maybe the issue is with the CT lines themselves.
# Let me verify the CT by concatenating and checking the total.
full_ct = ''.join(CT_LINES)
print(f"\nFull CT total: {len(full_ct)} chars")
print(f"Contains Y: {full_ct.count('Y')}, A: {full_ct.count('A')}, R: {full_ct.count('R')}")
print(f"Total Y+A+R: {full_ct.count('Y') + full_ct.count('A') + full_ct.count('R')}")

# Also count Y/A/R per row
print("\nY/A/R count per row:")
cumulative = 0
for row_idx, line in enumerate(CT_LINES):
    yar = sum(1 for ch in line if ch in 'YAR')
    cumulative += yar
    print(f"  Row {row_idx+1:2d}: {yar:2d} Y/A/R (cumulative: {cumulative})")
