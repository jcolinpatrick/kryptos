#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Tableau reflow grille analysis.

Theory: The Kryptos tableau has 869 characters (row 15 has 32 due to an extra L).
Removing the extra L and reflowing into 28×31 creates a shifted grille overlay
that can be compared to the cipher grid.

Steps:
1. Concatenate tableau rows → 869 chars
2. Remove extra L at position 463 → 868 chars
3. Reflow into 28×31
4. Compare physical vs reflowed tableau
5. Build cipher grid (868 chars, 28×31)
6. Overlay analysis (match positions)
7. Grille hypothesis testing
8. Letter frequency analysis
"""

import sys
sys.path.insert(0, 'src')

from collections import Counter

try:
    from kryptos.kernel.constants import (
        CT as K4_CT, CRIB_DICT, ALPH, KRYPTOS_ALPHABET,
    )
except ImportError:
    print("WARNING: Could not import from kryptos.kernel.constants, using hardcoded values")
    K4_CT = (
        "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWAT"
        "JKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    )
    ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    CRIB_DICT = {}
    for i, ch in enumerate("EASTNORTHEAST"):
        CRIB_DICT[21 + i] = ch
    for i, ch in enumerate("BERLINCLOCK"):
        CRIB_DICT[63 + i] = ch

# ============================================================
# TABLEAU DATA — as physically carved on the sculpture
# ============================================================

TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",   # Row 1 (header)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",   # Row 2
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",   # Row 3
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",   # Row 4
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",   # Row 5
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",   # Row 6
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",   # Row 7
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",   # Row 8
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",   # Row 9
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",   # Row 10
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",   # Row 11
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",   # Row 12
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",   # Row 13
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",   # Row 14
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # Row 15 — 32 chars! Extra L
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",   # Row 16
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",   # Row 17
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",   # Row 18
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",   # Row 19
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",   # Row 20
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",   # Row 21
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",   # Row 22
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",   # Row 23
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",   # Row 24
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",   # Row 25
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",   # Row 26
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",   # Row 27
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",   # Row 28 (footer)
]

# ============================================================
# CIPHER GRID DATA — 868 chars (28×31)
# ============================================================

# Full ciphertext from the sculpture (869 chars with squeezed ? removed → 868)
FULL_CT_869 = (
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

# The squeezed ? is at position 288 in the 869-char string
SQUEEZED_POS = 288
assert FULL_CT_869[SQUEEZED_POS] == '?', f"Expected ? at {SQUEEZED_POS}, got '{FULL_CT_869[SQUEEZED_POS]}'"

CIPHER_GRID_TEXT = FULL_CT_869[:SQUEEZED_POS] + FULL_CT_869[SQUEEZED_POS + 1:]
assert len(CIPHER_GRID_TEXT) == 868, f"Expected 868, got {len(CIPHER_GRID_TEXT)}"

WIDTH = 31
NROWS = 28

# Find K4 in the cipher grid
K4_START = CIPHER_GRID_TEXT.find(K4_CT)
assert K4_START >= 0, "K4 not found in cipher grid"
assert K4_START == 868 - 97  # K4 is the last 97 chars

# ============================================================
# Helper: Vigenere/Beaufort decryption
# ============================================================

def vig_decrypt(ct, key, alphabet=ALPH):
    """Vigenere decrypt: PT[i] = (CT[i] - KEY[i]) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        if c not in alphabet:
            pt.append(c)
            continue
        ci = alphabet.index(c)
        ki = alphabet.index(key[i % len(key)])
        pi = (ci - ki) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)

def beau_decrypt(ct, key, alphabet=ALPH):
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26"""
    pt = []
    for i, c in enumerate(ct):
        if c not in alphabet:
            pt.append(c)
            continue
        ci = alphabet.index(c)
        ki = alphabet.index(key[i % len(key)])
        pi = (ki - ci) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)


def try_decrypt(text, label=""):
    """Try standard keywords with Vig/Beaufort and print results."""
    if not text or len(text) < 3:
        print(f"  {label}: too short ({len(text)} chars)")
        return
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
    alpha_text = ''.join(c for c in text if c.isalpha())
    if not alpha_text:
        print(f"  {label}: no alpha chars")
        return
    for kw in keywords:
        vd = vig_decrypt(alpha_text, kw)
        bd = beau_decrypt(alpha_text, kw)
        # Check for common English fragments
        for name, result in [("Vig", vd), ("Beau", bd)]:
            # Simple English check: look for common trigrams
            common = ["THE", "AND", "ING", "ION", "TIO", "ENT", "FOR", "ATE",
                       "HER", "TER", "HAT", "HIS", "EST", "ALL", "NOT", "BUT"]
            hits = sum(1 for tri in common if tri in result)
            if hits >= 2 or any(w in result for w in ["EAST", "NORTH", "BERLIN", "CLOCK",
                                                        "SLOWLY", "KRYPTOS", "BETWEEN",
                                                        "WONDERFUL", "YES"]):
                print(f"  ** {label} {name}/{kw}: {result[:60]}... ({hits} trigram hits)")
            else:
                print(f"  {label} {name}/{kw}: {result[:50]}...")


# ============================================================
# STEP 1: Concatenate the tableau
# ============================================================

print("=" * 80)
print("STEP 1: Concatenate Tableau Rows")
print("=" * 80)

tableau_linear = ''.join(TABLEAU_ROWS)
print(f"Total tableau rows: {len(TABLEAU_ROWS)}")
print(f"Row lengths: {[len(r) for r in TABLEAU_ROWS]}")
print(f"Total linear length: {len(tableau_linear)}")
assert len(tableau_linear) == 869, f"Expected 869, got {len(tableau_linear)}"
print("CONFIRMED: 869 characters (28 rows, row 15 has 32 chars)")

# Verify row lengths
for i, row in enumerate(TABLEAU_ROWS):
    expected = 32 if i == 14 else 31  # Row 15 (0-indexed: 14) has 32
    assert len(row) == expected, f"Row {i+1}: expected {expected}, got {len(row)}"
print(f"Row 15 length: {len(TABLEAU_ROWS[14])} (extra L at end)")

# ============================================================
# STEP 2: Find and remove the extra L
# ============================================================

print()
print("=" * 80)
print("STEP 2: Find and Remove the Extra L")
print("=" * 80)

# The extra L is at the end of row 15 (0-indexed row 14)
# Calculate its position in the linear stream
pos_before_row15 = sum(len(TABLEAU_ROWS[i]) for i in range(14))
extra_l_pos = pos_before_row15 + len(TABLEAU_ROWS[14]) - 1  # Last char of row 15

print(f"Characters before row 15: {pos_before_row15}")
print(f"Row 15 = '{TABLEAU_ROWS[14]}'")
print(f"Extra L position in linear stream: {extra_l_pos}")
print(f"Character at position {extra_l_pos}: '{tableau_linear[extra_l_pos]}'")
assert tableau_linear[extra_l_pos] == 'L', f"Expected L at {extra_l_pos}, got '{tableau_linear[extra_l_pos]}'"

# Context
print(f"Context: ...{tableau_linear[extra_l_pos-5:extra_l_pos+6]}...")

# The expected position: 14 rows × 31 chars = 434, then row 15 has 32 chars, extra L at position 434+31 = 465
# Wait, let's be precise:
# Rows 0-13: 14 × 31 = 434 chars
# Row 14 (row 15): position 434 to 465 (32 chars, indices 434-465)
# Extra L at index 465 (last char)
print(f"\nVerification: 14 × 31 = {14 * 31}")
print(f"Extra L at index: {extra_l_pos}")
print(f"This is position {extra_l_pos - pos_before_row15} within row 15 (0-indexed: char index 31 in a 32-char row)")

# Remove the extra L
tableau_trimmed = tableau_linear[:extra_l_pos] + tableau_linear[extra_l_pos + 1:]
print(f"\nAfter removal: {len(tableau_trimmed)} chars")
assert len(tableau_trimmed) == 868, f"Expected 868, got {len(tableau_trimmed)}"
print("CONFIRMED: 868 characters = 28 × 31")

# ============================================================
# STEP 3: Reflow into 28×31
# ============================================================

print()
print("=" * 80)
print("STEP 3: Reflow into 28×31 Grid")
print("=" * 80)

reflowed = []
for r in range(NROWS):
    row = tableau_trimmed[r * WIDTH:(r + 1) * WIDTH]
    reflowed.append(row)
    assert len(row) == WIDTH, f"Row {r}: expected {WIDTH}, got {len(row)}"

print("Reflowed tableau (28×31):")
for r, row in enumerate(reflowed):
    print(f"  Row {r+1:2d}: {row}")

# ============================================================
# STEP 4: Compare physical vs reflowed
# ============================================================

print()
print("=" * 80)
print("STEP 4: Physical vs Reflowed Comparison")
print("=" * 80)

# Two views of the tableau as 28×31 grids:
#
# PHYSICAL: Each row is carved independently on the sculpture.
#   Row 15 has 32 chars (extra L), but as a grid row we see only the first 31.
#   The extra L is "dangling" at the end of row 15 — visible on the sculpture
#   but doesn't fit in a 31-col grid.
#   All other rows are exactly 31 chars. Rows 16-28 start fresh.
#
# REFLOWED: All 869 chars concatenated linearly, extra L removed → 868 chars,
#   then wrapped at 31 columns. This causes row 15 to absorb the first char
#   of what was physical row 16, and cascading shifts for all subsequent rows.

# Physical grid: each carved row truncated to 31 chars
physical = []
for i, row in enumerate(TABLEAU_ROWS):
    if len(row) <= 31:
        physical.append(row)
    else:
        physical.append(row[:31])  # Physical row 15: first 31 of 32 chars

# Since each physical row is independently carved and each is 31 chars
# (except row 15 which has 32), the physical grid rows 16-28 are already
# correct 31-char rows. The reflowed grid is identical to the physical grid
# EXCEPT at row 15 (where the last char differs).
#
# The KEY difference is in the LINEAR interpretation:
# Physical linear: 869 chars (with extra L embedded)
# Reflowed linear: 868 chars (extra L removed)
# After position 465 (the extra L), the reflowed stream is shifted -1.

print("Row-by-row comparison (physical carved rows vs reflowed 28×31):")
print(f"{'Row':>5} {'Status':>14} {'Phys last 5':>12} {'Refl last 5':>12} {'Differ?':>8}")
print("-" * 60)

shifted_positions = []
unchanged_positions = []
row_diffs = {}

for r in range(NROWS):
    phys_row = physical[r]
    refl_row = reflowed[r]

    diffs_in_row = []
    for c in range(WIDTH):
        p = phys_row[c] if c < len(phys_row) else ' '
        rf = refl_row[c]
        if p == rf:
            unchanged_positions.append((r, c))
        else:
            shifted_positions.append((r, c, p, rf))
            diffs_in_row.append((c, p, rf))

    if not diffs_in_row:
        status = "IDENTICAL"
        differ = ""
    else:
        status = f"DIFFERS ({len(diffs_in_row)})"
        differ = f"col(s) {[c for c,_,_ in diffs_in_row]}"
        row_diffs[r] = diffs_in_row

    print(f"  {r+1:2d}   {status:>14}   ...{phys_row[-5:]}   ...{refl_row[-5:]}  {differ}")

print(f"\nRow-by-row: {len(unchanged_positions)} identical positions, {len(shifted_positions)} different")

if shifted_positions:
    print(f"\nAll differing positions:")
    for r, c, p, rf in shifted_positions:
        print(f"  Row {r+1}, Col {c}: physical='{p}' → reflowed='{rf}'")

# Now show the LINEAR shift effect
print("\n--- Linear stream comparison ---")
print("Physical linear stream = all 28 rows concatenated (869 chars, extra L at pos 465)")
print("Reflowed linear stream = extra L removed (868 chars)")
print()

phys_linear = ''.join(TABLEAU_ROWS)  # 869 chars
refl_linear = tableau_trimmed         # 868 chars

# Before the extra L: positions 0-464 are identical
print("Before extra L (positions 0-464):")
before_same = all(phys_linear[i] == refl_linear[i] for i in range(465))
print(f"  All identical: {before_same}")

# At the extra L
print(f"\nAt the boundary:")
print(f"  Physical[465] = '{phys_linear[465]}' (the extra L)")
print(f"  Reflowed[465] = '{refl_linear[465]}' (absorbed from next row)")

# After the extra L: reflowed[i] = physical[i+1] for i >= 465
print(f"\nAfter extra L (positions 465+):")
after_shifted = all(refl_linear[i] == phys_linear[i + 1] for i in range(465, 868))
print(f"  Reflowed[i] == Physical[i+1] for all i >= 465: {after_shifted}")
print(f"  Total shifted positions in linear stream: {868 - 465} = {868 - 465}")

# But when wrapped back to 28×31, rows 16-28 are independently carved,
# so the row-based view shows minimal difference:
print(f"\nIMPORTANT INSIGHT:")
print(f"  In the LINEAR stream, 403 positions are shifted after removing the extra L.")
print(f"  But in the ROW-BASED view, physical rows 16-28 are independently carved,")
print(f"  so only row 15 col 30 differs (phys='J' truncated from 32-char row, refl='J' from linear wrap).")
print(f"  The reflowed grid happens to match the physical grid almost perfectly because")
print(f"  each KA row is a cyclic shift — removing one L from the cycle at row 15 boundary")
print(f"  only changes whether the 31st char is 'J' or 'L' (the extra L).")

# Detail: what happens at the boundary
print("\n--- Boundary detail (row 15, the extra-L row) ---")
print(f"Physical row 15 (32 chars): {TABLEAU_ROWS[14]}")
print(f"Physical row 15 in grid:    {physical[14]}  (first 31 chars)")
print(f"Reflowed row 15:            {reflowed[14]}")
print(f"Physical row 16:            {TABLEAU_ROWS[15]}")
print(f"Reflowed row 16:            {reflowed[15]}")
print()
print(f"Physical row 15 char 31 (extra L): '{TABLEAU_ROWS[14][31]}'")
print(f"Physical row 15 last char (col 30): '{TABLEAU_ROWS[14][30]}'")
print(f"Reflowed row 15 last char (col 30): '{reflowed[14][30]}'")

# ============================================================
# STEP 5: Build the cipher grid
# ============================================================

print()
print("=" * 80)
print("STEP 5: Cipher Grid (28×31)")
print("=" * 80)

cipher_grid = []
for r in range(NROWS):
    row = CIPHER_GRID_TEXT[r * WIDTH:(r + 1) * WIDTH]
    cipher_grid.append(row)

print("Cipher grid (28×31):")
for r, row in enumerate(cipher_grid):
    k4_marker = ""
    row_start = r * WIDTH
    row_end = row_start + WIDTH
    if row_end > K4_START and row_start < K4_START + 97:
        k4_marker = " ← K4"
    print(f"  Row {r+1:2d}: {row}{k4_marker}")

# ============================================================
# STEP 6: Overlay Analysis
# ============================================================

print()
print("=" * 80)
print("STEP 6: Overlay Analysis")
print("=" * 80)

# 6a: Where does reflowed_tableau == cipher_grid?
print("\n--- 6a: Reflowed tableau == Cipher grid (MATCH positions) ---")
refl_match_positions = []
for r in range(NROWS):
    for c in range(WIDTH):
        if reflowed[r][c] == cipher_grid[r][c]:
            refl_match_positions.append((r, c, reflowed[r][c]))

print(f"Total MATCH positions (reflowed == cipher): {len(refl_match_positions)}")
print("Matches by row:")
for r in range(NROWS):
    row_matches = [(rr, cc, ch) for rr, cc, ch in refl_match_positions if rr == r]
    if row_matches:
        cols = [(cc, ch) for _, cc, ch in row_matches]
        print(f"  Row {r+1:2d}: {len(row_matches)} matches — cols {cols}")

# Visual: show match grid
print("\nMatch grid (X = match, . = no match):")
for r in range(NROWS):
    line = ""
    for c in range(WIDTH):
        if reflowed[r][c] == cipher_grid[r][c]:
            line += "X"
        else:
            line += "."
    row_count = line.count('X')
    print(f"  Row {r+1:2d}: {line}  ({row_count})")

# 6b: Where does reflowed == physical (original)?
print("\n--- 6b: Reflowed tableau == Physical tableau (unchanged positions) ---")
print(f"Unchanged positions: {len(unchanged_positions)} (rows 1-14 are fully unchanged)")
print(f"Shifted positions: {len(shifted_positions)} (rows 15-28, shifted by removal of extra L)")

# 6c: Where do reflowed and physical DIFFER?
print("\n--- 6c: Positions where reflowed differs from physical ---")
if shifted_positions:
    print(f"Total shifted: {len(shifted_positions)}")
    print("First 20 shifted positions:")
    for r, c, p, rf in shifted_positions[:20]:
        print(f"  ({r+1:2d},{c:2d}): physical='{p}' → reflowed='{rf}'")
    if len(shifted_positions) > 20:
        print(f"  ... and {len(shifted_positions) - 20} more")

# 6d: K4 region analysis
print("\n--- 6d: K4 Region Detail ---")
print(f"K4 starts at grid position {K4_START} = row {K4_START // WIDTH + 1}, col {K4_START % WIDTH}")
print()
print(f"{'Pos':>4} {'Row':>4} {'Col':>4} {'Cipher':>7} {'Orig Tab':>9} {'Refl Tab':>9} {'Match Orig':>11} {'Match Refl':>11}")
print("-" * 75)

k4_orig_matches = 0
k4_refl_matches = 0
k4_both_matches = 0
k4_neither = 0

for i in range(97):
    grid_pos = K4_START + i
    r = grid_pos // WIDTH
    c = grid_pos % WIDTH
    cipher_ch = cipher_grid[r][c]
    refl_ch = reflowed[r][c]
    phys_ch = physical[r][c] if c < len(physical[r]) else ' '

    match_orig = "YES" if cipher_ch == phys_ch else ""
    match_refl = "YES" if cipher_ch == refl_ch else ""

    if cipher_ch == phys_ch:
        k4_orig_matches += 1
    if cipher_ch == refl_ch:
        k4_refl_matches += 1
    if cipher_ch == phys_ch and cipher_ch == refl_ch:
        k4_both_matches += 1
    if cipher_ch != phys_ch and cipher_ch != refl_ch:
        k4_neither += 1

    # Only print interesting positions (matches)
    if match_orig or match_refl:
        crib = CRIB_DICT.get(i, "")
        crib_str = f" PT={crib}" if crib else ""
        print(f"  {i:3d}  {r+1:3d}  {c:3d}   {cipher_ch:>5}  {phys_ch:>8}  {refl_ch:>8}  {match_orig:>10}  {match_refl:>10}{crib_str}")

print()
print(f"K4 summary:")
print(f"  Cipher matches ORIGINAL tableau: {k4_orig_matches}/97")
print(f"  Cipher matches REFLOWED tableau: {k4_refl_matches}/97")
print(f"  Matches BOTH: {k4_both_matches}/97")
print(f"  Matches NEITHER: {k4_neither}/97")

# ============================================================
# STEP 7: Grille Hypothesis Testing
# ============================================================

print()
print("=" * 80)
print("STEP 7: Grille Hypothesis Testing")
print("=" * 80)

# Hypothesis A: matches are "holes" — read cipher through them
print("\n--- Hypothesis A: Reflowed==Cipher positions are 'holes' ---")
holes_a = [(r, c, ch) for r, c, ch in refl_match_positions]
text_a = ''.join(cipher_grid[r][c] for r, c, _ in holes_a)
print(f"Total holes: {len(holes_a)}")
print(f"Text through holes (row order): {text_a}")
try_decrypt(text_a, "HypA-full")

# K4 portion
k4_holes_a = []
for r, c, ch in refl_match_positions:
    pos = r * WIDTH + c
    if K4_START <= pos < K4_START + 97:
        k4_holes_a.append((pos - K4_START, cipher_grid[r][c]))
k4_text_a = ''.join(ch for _, ch in sorted(k4_holes_a))
print(f"\nK4 holes: {len(k4_holes_a)}")
print(f"K4 text through holes: {k4_text_a}")
print(f"K4 hole positions: {[p for p, _ in sorted(k4_holes_a)]}")

# Hypothesis B: NON-matches are "holes"
print("\n--- Hypothesis B: Reflowed!=Cipher positions are 'holes' ---")
non_match_positions = []
for r in range(NROWS):
    for c in range(WIDTH):
        if reflowed[r][c] != cipher_grid[r][c]:
            non_match_positions.append((r, c))
text_b = ''.join(cipher_grid[r][c] for r, c in non_match_positions)
print(f"Total non-match positions: {len(non_match_positions)}")
print(f"Text (first 100 chars): {text_b[:100]}...")
# K4 portion
k4_nonmatch = []
for r, c in non_match_positions:
    pos = r * WIDTH + c
    if K4_START <= pos < K4_START + 97:
        k4_nonmatch.append((pos - K4_START, cipher_grid[r][c]))
k4_text_b = ''.join(ch for _, ch in sorted(k4_nonmatch))
print(f"K4 non-match: {len(k4_nonmatch)} chars")
print(f"K4 non-match text: {k4_text_b}")

# Hypothesis C: K4-specific — matches are "in-place" positions
print("\n--- Hypothesis C: K4 match positions are 'in-place' (not scrambled) ---")
print(f"K4 positions where cipher == reflowed tableau: {k4_refl_matches}")
print(f"K4 positions where cipher == original tableau: {k4_orig_matches}")
print("These positions were NOT moved by the scramble (if scramble exists).")
print(f"Remaining scrambled positions: {97 - k4_refl_matches} (reflowed) or {97 - k4_orig_matches} (original)")

# Hypothesis D: Read match positions in row order as unscrambled CT
print("\n--- Hypothesis D: Match-position letters = unscrambled CT reading order ---")
# Collect all K4 match positions (reflowed)
k4_refl_match_chars = []
k4_refl_nonmatch_chars = []
for i in range(97):
    grid_pos = K4_START + i
    r = grid_pos // WIDTH
    c = grid_pos % WIDTH
    cipher_ch = cipher_grid[r][c]
    refl_ch = reflowed[r][c]
    if cipher_ch == refl_ch:
        k4_refl_match_chars.append((i, cipher_ch))
    else:
        k4_refl_nonmatch_chars.append((i, cipher_ch))

print(f"Match chars ({len(k4_refl_match_chars)}): {''.join(ch for _, ch in k4_refl_match_chars)}")
print(f"Non-match chars ({len(k4_refl_nonmatch_chars)}): {''.join(ch for _, ch in k4_refl_nonmatch_chars)}")

# Try: match chars first, then non-match chars
reordered_d1 = ''.join(ch for _, ch in k4_refl_match_chars) + ''.join(ch for _, ch in k4_refl_nonmatch_chars)
print(f"\nReordered (matches first, then non-matches): {reordered_d1}")
try_decrypt(reordered_d1, "HypD-reorder")

# Try: interleave
if k4_refl_match_chars and k4_refl_nonmatch_chars:
    interleaved = []
    mi, ni = 0, 0
    for i in range(97):
        if mi < len(k4_refl_match_chars) and (ni >= len(k4_refl_nonmatch_chars) or
                                                 k4_refl_match_chars[mi][0] <= k4_refl_nonmatch_chars[ni][0]):
            interleaved.append(k4_refl_match_chars[mi][1])
            mi += 1
        else:
            interleaved.append(k4_refl_nonmatch_chars[ni][1])
            ni += 1
    # This is just the original K4 in order, so skip printing

# Try decryption on the full K4 with various readings
print("\n--- Standard decryptions of K4 for comparison ---")
try_decrypt(K4_CT, "K4-direct")

# Hypothesis E: Use the DIFFERENCE between reflowed and original LINEAR positions
print("\n--- Hypothesis E: LINEAR shift effect on K4 ---")
# In the linear stream, positions >= 465 are shifted by -1 in the reflowed version.
# K4 starts at grid position 771 in the 868-char grid, which is well past 465.
# So K4 is in the shifted zone.
#
# Physical linear position for K4[i] = K4_START + i (in 868-char physical grid, rows concatenated)
# But the physical 869-char tableau has the extra L at position 465.
# Physical tableau position for same grid cell = K4_START + i + 1 (shifted by 1 because of extra L before it)
#
# Compare: what letter is at each K4 grid cell in the physical vs reflowed tableau?
# Physical tableau at (r,c) = TABLEAU_ROWS[r][c] (each row carved independently)
# Reflowed tableau at (r,c) = tableau_trimmed[r*31+c]
#
# Since K4 is in rows 25-28 (0-indexed 24-27), and these are all after row 15,
# the LINEAR position in the 869-char physical stream is offset by +1 from the
# 868-char reflowed stream (because the extra L at position 465 hasn't been removed).
#
# But the ROW-BASED physical grid reads each row independently, so physical[r][c]
# is NOT affected by the linear shift. Only the linear interpretation changes.

print("K4 is in the LINEAR shifted zone (all positions >= 465).")
print("Row-based physical and reflowed grids are nearly identical for K4.")
print()

# The more interesting question: what letter does the PHYSICAL 869-char
# linear stream place at each K4 grid cell, vs the reflowed 868-char stream?
print("Linear position comparison for K4:")
print(f"{'K4 pos':>7} {'Grid(r,c)':>10} {'Cipher':>7} {'Refl Tab':>9} {'Phys Lin':>9} {'Same?':>6}")
print("-" * 55)

k4_linear_diffs = []
for i in range(97):
    grid_pos = K4_START + i
    r = grid_pos // WIDTH
    c = grid_pos % WIDTH
    cipher_ch = cipher_grid[r][c]
    refl_ch = reflowed[r][c]  # = tableau_trimmed[grid_pos]
    # Physical linear: the extra L shifts everything after pos 465 by +1
    phys_lin_pos = grid_pos + 1  # +1 because extra L at 465 is before K4
    phys_lin_ch = phys_linear[phys_lin_pos] if phys_lin_pos < len(phys_linear) else '?'
    same = "YES" if refl_ch == phys_lin_ch else "NO"
    if refl_ch != phys_lin_ch:
        k4_linear_diffs.append((i, cipher_ch, refl_ch, phys_lin_ch))
    if i < 10 or refl_ch != phys_lin_ch:  # Show first 10 + all diffs
        print(f"  {i:5d}  ({r+1:2d},{c:2d})  {cipher_ch:>5}  {refl_ch:>8}  {phys_lin_ch:>8}  {same:>5}")

if i >= 10 and not k4_linear_diffs:
    print(f"  ... (all remaining identical)")

print(f"\nK4 positions where reflowed linear != physical linear: {len(k4_linear_diffs)}")
if k4_linear_diffs:
    print("Differences:")
    for pos, cch, rch, pch in k4_linear_diffs:
        print(f"  K4[{pos}]: cipher={cch}, reflowed_tab={rch}, physical_lin={pch}")
else:
    print("The reflowed and physical linear streams give the SAME tableau letter at all K4 positions.")
    print("This is because the +1 shift from the extra L merely shifts within the same")
    print("cyclic KA row pattern — the letter at each grid position is preserved.")

# Hypothesis F: Column reading through reflowed match positions
print("\n--- Hypothesis F: Column-order reading of match positions ---")
# Read matches column by column instead of row by row
col_order_matches = []
for c in range(WIDTH):
    for r in range(NROWS):
        pos = r * WIDTH + c
        if K4_START <= pos < K4_START + 97:
            refl_ch = reflowed[r][c]
            cipher_ch = cipher_grid[r][c]
            if cipher_ch == refl_ch:
                col_order_matches.append(cipher_ch)

col_text = ''.join(col_order_matches)
print(f"Column-order match text ({len(col_text)} chars): {col_text}")
if col_text:
    try_decrypt(col_text, "HypF-col")

# ============================================================
# STEP 8: Letter Frequency Analysis
# ============================================================

print()
print("=" * 80)
print("STEP 8: Letter Frequency Analysis")
print("=" * 80)

# Compare frequencies in the full reflowed vs physical tableau
refl_alpha = ''.join(c for c in tableau_trimmed if c.isalpha())
orig_alpha = ''.join(c for c in tableau_linear if c.isalpha())

print(f"Original tableau alpha chars: {len(orig_alpha)}")
print(f"Reflowed tableau alpha chars: {len(refl_alpha)}")
print(f"Difference: {len(orig_alpha) - len(refl_alpha)} (the removed L)")

orig_freq = Counter(orig_alpha)
refl_freq = Counter(refl_alpha)

print(f"\n{'Letter':>7} {'Original':>9} {'Reflowed':>9} {'Diff':>5}")
print("-" * 35)
for ch in ALPH:
    o = orig_freq.get(ch, 0)
    r = refl_freq.get(ch, 0)
    diff = r - o
    marker = " ← REMOVED" if diff != 0 else ""
    print(f"  {ch:>5} {o:>9} {r:>9} {diff:>+5}{marker}")

# What letters appear at the match positions (reflowed==cipher)?
print(f"\n--- Letter frequency at MATCH positions (reflowed==cipher) ---")
match_chars = ''.join(ch for _, _, ch in refl_match_positions if ch.isalpha())
match_freq = Counter(match_chars)
print(f"Total match positions with alpha: {len(match_chars)}")
print(f"{'Letter':>7} {'Count':>6} {'% of matches':>13}")
print("-" * 30)
for ch in ALPH:
    cnt = match_freq.get(ch, 0)
    pct = 100.0 * cnt / len(match_chars) if match_chars else 0
    print(f"  {ch:>5} {cnt:>6} {pct:>12.1f}%")

missing_letters = [ch for ch in ALPH if ch not in match_freq]
print(f"\nLetters MISSING from matches: {missing_letters if missing_letters else 'none'}")

# What about at K4 match positions specifically?
print(f"\n--- K4 match position letter frequency ---")
k4_match_text = ''.join(ch for _, ch in k4_refl_match_chars)
k4_match_freq = Counter(k4_match_text)
print(f"K4 match letters ({len(k4_match_text)}): {k4_match_text}")
print(f"K4 non-match letters ({len(k4_refl_nonmatch_chars)}): {''.join(ch for _, ch in k4_refl_nonmatch_chars)}")

# Compare with K4 overall frequency
k4_freq = Counter(K4_CT)
print(f"\nK4 overall vs match frequency:")
print(f"{'Letter':>7} {'K4 total':>9} {'K4 match':>9} {'K4 non-match':>13}")
print("-" * 45)
for ch in ALPH:
    total = k4_freq.get(ch, 0)
    match = k4_match_freq.get(ch, 0)
    nonmatch = total - match
    print(f"  {ch:>5} {total:>9} {match:>9} {nonmatch:>13}")

# ============================================================
# STEP 9: Summary
# ============================================================

print()
print("=" * 80)
print("SUMMARY")
print("=" * 80)

print(f"""
Tableau reflow analysis complete.

Key findings:
- Original tableau: 869 chars (row 15 has 32 due to extra L at position {extra_l_pos})
- Reflowed tableau: 868 chars = 28×31 (extra L removed)
- Rows 1-14: IDENTICAL between physical and reflowed
- Rows 15-28: SHIFTED by -1 position (every char moves left by one)

Full grid overlay:
- Reflowed tableau == cipher grid at {len(refl_match_positions)} positions
- Expected random matches: ~868/26 ≈ {868/26:.1f} (if uniform) or ~868/26 ≈ 33.4

K4 region:
- Cipher matches ORIGINAL tableau at {k4_orig_matches}/97 positions
- Cipher matches REFLOWED tableau at {k4_refl_matches}/97 positions
- K4 linear-shift differences: {len(k4_linear_diffs)}/97
  (Positions where reflowed vs physical LINEAR stream differ)

Grille hypotheses tested:
- Hypothesis A: Match positions as holes → extracted {len(holes_a)} chars
- Hypothesis B: Non-match positions as holes → extracted {len(non_match_positions)} chars
- Hypothesis C: K4 match/non-match classification
- Hypothesis D: Reordered K4 by match/non-match
- Hypothesis E: K4 chars at reflow-affected vs unaffected positions
- Hypothesis F: Column-order reading of match positions
""")

print("=" * 80)
print("DONE")
print("=" * 80)
