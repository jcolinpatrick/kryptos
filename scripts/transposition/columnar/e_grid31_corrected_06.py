#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Corrected 28×31 grid with the 3rd K2 ? squeezed (doesn't occupy a grid position).

KEY INSIGHT (Colin, 2026-03-03):
- On Antipodes Row 22, the ? near S.F./W.W. is visibly squeezed — no character space
- Therefore on Kryptos, the same ? doesn't count as a position
- Total = 865 letters + 3 positional ?'s = 868 = 28 × 31
- The first E IS part of the grid
- This changes the grid content and all prior grille analysis

The squeezed ? is at full-text position 288: FLGGTEZ[?]FKZBSFD...
"""

import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as K4_CT

# Full cipher text as carved (869 chars = 865 letters + 4 ?'s)
FULL_CT = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF"   # ← the ? here is SQUEEZED
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR"
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO"
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP"
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
)

print(f"Full text: {len(FULL_CT)} chars")
assert len(FULL_CT) == 869

# Find the squeezed ? — it's at GGTEZ?FKZ (the 3rd K2 ?)
# Find all ? positions
q_positions = [i for i, c in enumerate(FULL_CT) if c == '?']
print(f"All ? positions: {q_positions}")

# The squeezed one is position 288 (GGTEZ?FKZ)
SQUEEZED_POS = 288
context = FULL_CT[SQUEEZED_POS-5:SQUEEZED_POS+6]
print(f"Squeezed ? at pos {SQUEEZED_POS}: ...{context}...")
assert FULL_CT[SQUEEZED_POS] == '?'

# Build grid text by removing the squeezed ?
grid_text = FULL_CT[:SQUEEZED_POS] + FULL_CT[SQUEEZED_POS+1:]
print(f"\nGrid text: {len(grid_text)} chars")
assert len(grid_text) == 868
print(f"28 × 31 = {28*31}")
assert len(grid_text) == 28 * 31

# Remaining ? positions in grid text
grid_q = [i for i, c in enumerate(grid_text) if c == '?']
print(f"Remaining ? positions in grid: {grid_q}")
print(f"  ?#1: ...{grid_text[grid_q[0]-3:grid_q[0]+4]}...")
print(f"  ?#2: ...{grid_text[grid_q[1]-3:grid_q[1]+4]}...")
print(f"  ?#3: ...{grid_text[grid_q[2]-3:grid_q[2]+4]}...")

# ============================================================
# SECTION 1: Build the 28×31 grid
# ============================================================

WIDTH = 31
NROWS = 28

print()
print("=" * 80)
print("CORRECTED 28×31 GRID (E included, 3rd K2 ? squeezed)")
print("=" * 80)

grid = []
for r in range(NROWS):
    row = grid_text[r*WIDTH : (r+1)*WIDTH]
    grid.append(row)

# Find section starts
k4_pos = grid_text.find(K4_CT)
k3_text_start = "ENDYAHROHNLSR"
k3_pos = grid_text.find(k3_text_start)

# The ? before K4 (K3/K4 boundary)
# In grid_text, this ? is at position grid_q[2] (DOHW?OBKR)
k4_boundary_q = grid_q[2]

print(f"\nK1 starts at: row 0, col 0 (first char = '{grid_text[0]}')")
print(f"K3 starts at position {k3_pos}: row {k3_pos//WIDTH}, col {k3_pos%WIDTH}")
print(f"K4 starts at position {k4_pos}: row {k4_pos//WIDTH}, col {k4_pos%WIDTH}")
print(f"K3/K4 boundary ? at position {k4_boundary_q}: row {k4_boundary_q//WIDTH}, col {k4_boundary_q%WIDTH}")
print()

# Compare with old analysis (E excluded)
print("COMPARISON:")
print(f"  Old (E excluded):     K3 at row 14, col 0 → 434/434 split")
print(f"  New (? squeezed):     K3 at row {k3_pos//WIDTH}, col {k3_pos%WIDTH}")
print(f"  K3 at row 14 boundary? {k3_pos == 14*31}")

# Print the grid with annotations
print()
for r in range(NROWS):
    start = r * WIDTH
    row_str = grid[r]

    # Determine what's in this row
    sections = set()
    for c in range(WIDTH):
        pos = start + c
        ch = grid_text[pos]
        if ch == '?':
            sections.add('?')
        elif pos >= k4_pos:
            sections.add('K4')
        elif pos >= k3_pos:
            sections.add('K3')
        else:
            sections.add('K1/K2')

    sec = '+'.join(sorted(sections))
    half = "TOP" if r < 14 else "BOT"
    print(f"Row {r:2d} [{start:3d}]: {row_str}  {half}  {sec}")

# ============================================================
# SECTION 2: K4 in the grid
# ============================================================

print()
print("=" * 80)
print("SECTION 2: K4 Position in Corrected Grid")
print("=" * 80)

k4_row = k4_pos // WIDTH
k4_col = k4_pos % WIDTH
print(f"K4 starts at row {k4_row}, col {k4_col}")
print(f"K4 = {len(K4_CT)} chars, occupies rows {k4_row}-{NROWS-1}")
print()

# Show K4 in context
for r in range(max(0, k4_row-1), NROWS):
    start = r * WIDTH
    row_str = grid[r]

    # Mark K4 portion
    k4_start_in_row = max(0, k4_pos - start)
    k4_end_in_row = min(WIDTH, k4_pos + 97 - start)

    if k4_end_in_row <= 0 or k4_start_in_row >= WIDTH:
        print(f"Row {r}: {row_str}")
    else:
        before = row_str[:k4_start_in_row]
        k4_part = row_str[k4_start_in_row:k4_end_in_row]
        after = row_str[k4_end_in_row:]
        print(f"Row {r}: {before}[{k4_part}]{after}")

# ============================================================
# SECTION 3: Verify K4 internal layout at width 31
# ============================================================

print()
print("=" * 80)
print("SECTION 3: K4 Internal Layout (width 31)")
print("=" * 80)

# K4 internally at width 31
for i in range(4):
    start = i * 31
    end = min(start + 31, 97)
    row = K4_CT[start:end]
    print(f"K4 row {i}: {row[:4]}...{row[-4:]} ({len(row)} chars)")

# ============================================================
# SECTION 4: Grille Overlay on CORRECTED Grid
# ============================================================

print()
print("=" * 80)
print("SECTION 4: Cardan Grille Overlay (Corrected Grid)")
print("=" * 80)

# Parse grille mask
MASK_ROWS = [
    "000000001010100000000010000000001~~",
    "100000000010000001000100110000011~~",
    "000000000000001000000000000000011~~",
    "00000000000000000000100000010011~~",
    "00000001000000001000010000000011~~",
    "000000001000000000000000000000011~",
    "100000000000000000000000000000011",
    "00000000000000000000000100000100~~",
    "0000000000000000000100000001000~~",
    "0000000000000000000000000000100~~",
    "000000001000000000000000000000~~",
    "00000110000000000000000000000100~~",
    "00000000000000100010000000000001~~",
    "00000000000100000000000000001000~~",
    "000110100001000000000000001000010~~",
    "00001010000000000000000001000001~~",
    "001001000010010000000000000100010~~",
    "00000000000100000000010000010001~~",
    "000000000000010001001000000010001~~",
    "00000000000000001001000000000100~~",
    "000000001100000010100100010001001~~",
    "000000000000000100001010100100011~",
    "00000000100000000000100001100001~~~",
    "100000000000000000001000001000010~",
    "10000001000001000000100000000001~~",
    "000010000000000000010000100000011",
    "0000000000000000000100001000000011",
    "00000000000000100000001010000001~~",
]

mask_parsed = []
for mrow in MASK_ROWS:
    bits = [int(ch) for ch in mrow if ch in '01']
    mask_parsed.append(bits)

# The KEY question: what column offset aligns the grille with the 31-col cipher grid?
# The tableau has: 1 label col + 30 body cols = 31 total
# Header: space + ABCDEFGHIJKLMNOPQRSTUVWXYZABCD = 1 + 30 = 31
# The grille mask has varying widths (30-35 bits)
# The grille was placed on the tableau, which is 31 wide

# If the cipher grid is also 31 wide, and the grille aligns the same way,
# then grille col 0 = grid col 0 (the label/first-char column)
# OR grille col 0 = the left edge of the physical grille

# Let's try all offsets 0-4 and see which gives the most interesting results
for offset in range(5):
    print(f"\n--- Offset {offset}: grille col {offset} → grid col 0 ---")

    on_k4 = []
    on_k3 = []
    on_k1k2 = []
    on_q = []
    outside = 0

    for r in range(NROWS):
        bits = mask_parsed[r]
        for bit_idx, bit in enumerate(bits):
            if bit == 1:
                grid_col = bit_idx - offset
                if grid_col < 0 or grid_col >= WIDTH:
                    outside += 1
                    continue

                grid_pos = r * WIDTH + grid_col
                if grid_pos >= len(grid_text):
                    outside += 1
                    continue

                ch = grid_text[grid_pos]
                if ch == '?':
                    on_q.append((r, grid_col, grid_pos))
                elif grid_pos >= k4_pos:
                    on_k4.append((r, grid_col, grid_pos, ch))
                elif grid_pos >= k3_pos:
                    on_k3.append((r, grid_col, grid_pos, ch))
                else:
                    on_k1k2.append((r, grid_col, grid_pos, ch))

    total = len(on_k1k2) + len(on_k3) + len(on_k4) + len(on_q)
    print(f"  On grid: {total} holes  (K1K2:{len(on_k1k2)} K3:{len(on_k3)} K4:{len(on_k4)} ?:{len(on_q)})")
    print(f"  Outside grid: {outside}")

    if on_k4:
        k4_chars = ''.join(ch for _, _, _, ch in on_k4)
        k4_positions = [p - k4_pos for _, _, p, _ in on_k4]
        print(f"  K4 chars: {k4_chars}")
        print(f"  K4 internal positions: {k4_positions}")

# ============================================================
# SECTION 5: What Changed? (Old vs New Grid)
# ============================================================

print()
print("=" * 80)
print("SECTION 5: Old Grid vs New Grid Comparison")
print("=" * 80)

old_grid = FULL_CT[1:]  # Old: E excluded
new_grid = grid_text     # New: 3rd K2 ? squeezed

print(f"Old grid (E excluded): starts with '{old_grid[:10]}...'")
print(f"New grid (? squeezed): starts with '{new_grid[:10]}...'")
print()

# They're identical except:
# Old: missing position 0 (E)
# New: missing position 288 (?)
# So positions 0-286 are shifted by 1, position 287 is the divergence

# Find where they first differ
for i in range(min(len(old_grid), len(new_grid))):
    if old_grid[i] != new_grid[i]:
        print(f"First difference at position {i}:")
        print(f"  Old[{i}] = '{old_grid[i]}' (full text [{i+1}])")
        print(f"  New[{i}] = '{new_grid[i]}' (full text [{i}])")
        print(f"  Context old: ...{old_grid[max(0,i-5):i+6]}...")
        print(f"  Context new: ...{new_grid[max(0,i-5):i+6]}...")
        break

# The grids are offset by 1 for positions 0-287,
# then differ at position 288 (? removed vs E removed)
print()
print("Grid shift analysis:")
print("  Positions 0-287: new grid = old grid shifted RIGHT by 1")
print(f"  Position 0: new='{new_grid[0]}' (E), old='{old_grid[0]}' (M)")
print(f"  Position 287: new='{new_grid[287]}' old='{old_grid[287]}'")
print(f"  Position 288: new='{new_grid[288]}' old='{old_grid[288]}'")
print(f"  Position 289: new='{new_grid[289]}' old='{old_grid[289]}'")
print(f"  Position 290: new='{new_grid[290]}' old='{old_grid[290]}'")
print()

# After the squeezed ? (position 288 in full text), both grids have the same content
# Old grid: starts at full[1], so position i = full[i+1]
# New grid: starts at full[0] minus full[288], so:
#   pos 0-287: full[0]-full[287] (288 chars)
#   pos 288-867: full[289]-full[868] (580 chars)
# Old grid:
#   pos 0-867: full[1]-full[868] (868 chars)

# After position 288:
# New[288] = full[289], Old[288] = full[289]. SAME!
# New[289] = full[290], Old[289] = full[290]. SAME!
# So after position 288, both grids are IDENTICAL.

same_after = all(new_grid[i] == old_grid[i] for i in range(288, 868))
print(f"Grids identical after position 288: {same_after}")
print("→ K3 and K4 positions are IDENTICAL in both grids!")
print("→ The ONLY difference is in the first 288 characters (K1+K2)")

# ============================================================
# SECTION 6: Implications for the Cardan Grille
# ============================================================

print()
print("=" * 80)
print("SECTION 6: Implications for Cardan Grille")
print("=" * 80)

print("""
KEY FINDINGS:

1. The 3rd K2 ? (GGTEZ?FKZ, Antipodes Row 22) doesn't count as a space.
   → Total positional chars = 868 = 28 × 31
   → The first E IS part of the cipher grid

2. This ONLY affects the first 288 positions (K1+K2 region).
   K3 and K4 positions are IDENTICAL in both the old and new grids.
   → K4 analysis is NOT affected by this correction!

3. K3 starts at exactly row 14, col 0 in BOTH grids (434 chars before K3).

4. K4 starts at row 24, col 27 in BOTH grids.

5. The grille overlay on K4 gives the same results regardless of which
   grid model we use, because K4's grid region is identical.

So what does "the cardan grille is all wrong" mean?
""")

# ============================================================
# SECTION 7: Re-examine grille dimensions
# ============================================================

print("=" * 80)
print("SECTION 7: Grille Dimensions vs Grid Dimensions")
print("=" * 80)

print(f"\nCipher grid: {NROWS} rows × {WIDTH} cols = {NROWS * WIDTH}")
print(f"Tableau: 28 rows × 31 cols (1 label + 30 body)")
print(f"Grille mask rows: {len(mask_parsed)}")
print()

# Count bits per row (actual data, not tildes)
for i, bits in enumerate(mask_parsed):
    ones = sum(bits)
    total_bits = len(bits)
    print(f"  Row {i+1:2d}: {total_bits:2d} bits ({ones:2d} holes) | extra cols: {total_bits - 31}")

# The grille has VARIABLE width (30-35 bits per row)
# Most rows have 31-33 bits
# A clean 28×31 grille would have exactly 31 bits per row
# The extra bits could be:
# - Physical edge effects (grille extends slightly beyond grid)
# - Off-grid position markers
# - Errors in our mask transcription

# What if we TRIM each row to exactly 31 bits?
print()
print("Trimming grille to 31 cols (left-aligned):")
trimmed_holes = 0
trimmed_k4 = []

for r in range(NROWS):
    bits = mask_parsed[r][:31]  # Take only first 31 bits
    ones = sum(bits)
    trimmed_holes += ones

    for c in range(len(bits)):
        if bits[c] == 1:
            grid_pos = r * WIDTH + c
            if grid_pos >= k4_pos and grid_pos < k4_pos + 97:
                ch = grid_text[grid_pos]
                trimmed_k4.append((grid_pos - k4_pos, ch))

print(f"  Total holes (first 31 cols only): {trimmed_holes}")
print(f"  K4 holes: {len(trimmed_k4)}")
if trimmed_k4:
    trimmed_k4.sort()
    print(f"  K4 chars: {''.join(ch for _, ch in trimmed_k4)}")
    print(f"  K4 positions: {[p for p, _ in trimmed_k4]}")

# What if we RIGHT-align (take last 31 bits)?
print()
print("Trimming grille to 31 cols (right-aligned):")
right_holes = 0
right_k4 = []

for r in range(NROWS):
    bits = mask_parsed[r]
    if len(bits) > 31:
        bits = bits[len(bits)-31:]  # Take last 31 bits
    elif len(bits) < 31:
        bits = [0] * (31 - len(bits)) + bits  # Pad left with zeros

    ones = sum(bits)
    right_holes += ones

    for c in range(len(bits)):
        if bits[c] == 1:
            grid_pos = r * WIDTH + c
            if grid_pos >= k4_pos and grid_pos < k4_pos + 97:
                ch = grid_text[grid_pos]
                right_k4.append((grid_pos - k4_pos, ch))

print(f"  Total holes (last 31 cols only): {right_holes}")
print(f"  K4 holes: {len(right_k4)}")
if right_k4:
    right_k4.sort()
    print(f"  K4 chars: {''.join(ch for _, ch in right_k4)}")
    print(f"  K4 positions: {[p for p, _ in right_k4]}")

# ============================================================
# SECTION 8: The REAL question — grille on tableau vs cipher
# ============================================================

print()
print("=" * 80)
print("SECTION 8: Fundamental Question")
print("=" * 80)

print("""
The grille extracts 106 characters from the TABLEAU side.
The cipher grid has 868 characters on the CIPHER side.

Both are 28 × 31. The grille has 28 rows matching both.

TWO POSSIBLE USES:
A) Grille on TABLEAU → extract 106 chars → use as key/permutation for K4
B) Grille on CIPHER GRID → extract ~87-110 chars from the cipher text

For (B), the grille gives only 8-14 chars from K4 (depending on alignment).
That's not enough for a 97-char unscrambling permutation.

For (A), we've tested many ways to convert the 106-char extract into a
permutation. All scored 0/24 on cribs.

OPEN QUESTION: Is the grille mask correct? If 28×31, we expect exactly
31 bits per row, but our mask has 30-35 bits per row. This suggests
either:
- The mask transcription has column alignment errors
- The physical grille extends beyond the 31-col grid
- The grille is designed for a different grid than 28×31
""")

# ============================================================
# SECTION 9: Character frequency at grille holes
# ============================================================

print("=" * 80)
print("SECTION 9: What Does the Grille Read from the Cipher Grid?")
print("=" * 80)

# At offset 0 (best guess for alignment), read all grid chars through holes
for offset in [0, 1, 2]:
    chars_read = []
    for r in range(NROWS):
        bits = mask_parsed[r]
        for bit_idx, bit in enumerate(bits):
            if bit == 1:
                grid_col = bit_idx - offset
                if 0 <= grid_col < WIDTH:
                    grid_pos = r * WIDTH + grid_col
                    if grid_pos < len(grid_text):
                        chars_read.append(grid_text[grid_pos])

    text = ''.join(chars_read)
    alpha_only = ''.join(c for c in text if c.isalpha())
    print(f"\nOffset {offset}: {len(chars_read)} chars read, {len(alpha_only)} alpha")
    print(f"  Text: {text}")

    # Check if it contains any meaningful patterns
    for crib in ["EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "BERLIN",
                  "CLOCK", "SLOWLY", "CHAMBER", "CANDLE", "KRYPTOS"]:
        if crib in alpha_only:
            pos = alpha_only.index(crib)
            print(f"  *** CRIB: {crib} at position {pos} ***")

    # Check for T
    if 'T' not in alpha_only:
        print(f"  *** T IS ABSENT from cipher-grid grille reading! ***")
    else:
        t_count = alpha_only.count('T')
        print(f"  T count: {t_count}")

    # Letter frequency
    from collections import Counter
    freq = Counter(alpha_only)
    missing = [c for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if c not in freq]
    if missing:
        print(f"  Missing letters: {missing}")

print()
print("=" * 80)
print("DONE")
print("=" * 80)
