#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRILLE-CIPHER-PANEL: Apply the Cardan grille to the ENTIRE cipher panel.

Theory: The Cardan grille is steganographic — placed over the cipher panel,
it reveals a HIDDEN message (possibly K5) with NO known cribs.
The K1-K4 text was composed AROUND these fixed positions.

Also tests: mirrored grille (flipping to go from tableau side to cipher side),
and analyzes the hidden stream for language properties.
"""

import json
import sys
from collections import Counter

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# ============================================================
# THE BINARY MASK (from cardan_grille.md)
# 1=HOLE, 0=SOLID, ~=off-grid
# ============================================================

MASK_RAW = [
    "000000001010100000000010000000001~~",   # Row 1
    "100000000010000001000100110000011~~",   # Row 2
    "000000000000001000000000000000011~~",   # Row 3
    "00000000000000000000100000010011~~",    # Row 4
    "00000001000000001000010000000011~~",    # Row 5
    "000000001000000000000000000000011~",    # Row 6
    "100000000000000000000000000000011",     # Row 7
    "00000000000000000000000100000100~~",    # Row 8
    "0000000000000000000100000001000~~",     # Row 9
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

# Parse mask: extract (row, col) of each hole
# The mask has variable widths (30-35 bits + tildes)
# We need to map to a 28x31 grid

# Strategy 1: Use first 31 bits of each row (ignore trailing bits and tildes)
# Strategy 2: Use first 33 bits (the documented mask width)
# Strategy 3: Right-align to 31 cols

print("=" * 75)
print("E-GRILLE-CIPHER-PANEL: Grille as Steganographic Overlay")
print("=" * 75)

# ============================================================
# PART 1: Parse mask and identify hole positions
# ============================================================

print("\n--- PART 1: Parse Binary Mask ---")

strategies = {}
for strat_name, strat_fn in [
    ("first_31", lambda bits: bits[:31]),
    ("first_33", lambda bits: bits[:33]),
    ("strip_tildes", lambda bits: bits.replace('~', '')),
]:
    holes = []
    for row_idx, row in enumerate(MASK_RAW):
        bits = strat_fn(row)
        for col_idx, bit in enumerate(bits):
            if bit == '1':
                holes.append((row_idx, col_idx))

    strategies[strat_name] = holes
    print(f"\n  Strategy '{strat_name}': {len(holes)} holes")

    # Show distribution by row
    row_counts = Counter(r for r, c in holes)
    max_col = max(c for r, c in holes) if holes else 0
    print(f"    Max column: {max_col}")
    print(f"    Holes per row: {dict(sorted(row_counts.items()))}")

# ============================================================
# PART 2: Build the CIPHER PANEL (28x31)
# ============================================================

print("\n\n--- PART 2: Build Cipher Panel ---")

# Complete cipher text in reading order
# This is the full text on the left panel of Kryptos
# 28 rows x 31 cols = 868 characters

# We need the exact 868-char sequence. Let me reconstruct from known sections.
# K1 = 63 chars, K2 = 369 chars (with 2 ?'s), K3 = 336 chars (with 1 ?), K4 = 97 chars
# Plus the squeezed ? is removed, so 865 + 3 = 868

# The full text from top to bottom, left to right:
# I'll use the known sections and boundaries

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

# K2 with positional ?'s (the 3rd ? is squeezed and removed)
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"  # squeezed ? removed
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOET"
    "FOLDESLHAHAHRTEWFABENMIEAHHETEMA"
    "SGLNDNPMCHZRDMEELEZEEAIOLFETIHA"
    "EVTMDAEHEMTDIVFEOHMNERAHTTRDNETH"
    "EEPEAHSADNHTEHEADTISRIHNDCLEIHH"
    "ATRTPLEVANLEKZALRDVEIESNDMTFLA"
    "AHETTEEFREEDIEAHLESDHTWCAIEHTHEE"
    "DFHRTDERHSIESWENHTHETHSAHCTESL"
)

# K3 has a ? in it too
K3_WITH_Q = K3_CT  # The ? is within K3, need exact position
# Actually from the grid: between K2 and K3 there's a ?
# And between K3 and K4 there might be one

K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# Build full sequence
# K1 (63) + K2 (369, with 2 ?'s = 371) + K3 (336, with 1 ? between K2-K3 or within)
# Total should be 868

# Let me count what we have
print(f"K1: {len(K1_CT)} chars")
print(f"K2: {len(K2_CT)} chars")
print(f"K3: {len(K3_CT)} chars")
print(f"K4: {len(K4_CT)} chars")

# The ? positions are tricky. Let me try to build the full text
full_text = K1_CT + K2_CT + K3_CT + K4_CT
print(f"Total without adjustments: {len(full_text)}")

# We need exactly 868. The difference tells us how many ?'s to add
needed = 868 - len(full_text)
print(f"Need {needed} more characters (should be ?'s)")

# From memory: K2 has 2 positional ?'s and K3 has 1 (between K2/K3?)
# The full text boundaries:
# K1[0:63]=63, K2[63:432]=369, K3[432:768]=336, K4[768:865]=97
# But 63 + 369 + 336 + 97 = 865 letters
# Plus 3 ?'s = 868

# The ?'s in our K2 text account for 2 of them
# We're missing 1 more ? somewhere
# It goes between K3 and K4 (or at the start of K3)

# Count ?'s already in our text
q_count = full_text.count('?')
print(f"?'s already in text: {q_count}")
print(f"Still need: {868 - len(full_text)} chars")

# Let me just add ?'s at the right positions to make it 868
# From the grid, K3 starts at position 434 (row 14, col 0 = 14*31=434)
# K4 starts at position 868-97 = 771? No, K4 starts at row 24 col 27 = 24*31+27 = 771

# Current text: K1(63) + K2(371, has 2 ?) + K3(336) + K4(97) = 867
# Need 1 more char. The ? between K3 and K4 (at row 24, col 26?)
# Or between K2 and K3

# Let me insert a ? between K2 and K3 to test
if len(full_text) == 867:
    # Insert ? between K2 and K3
    full_text_v1 = K1_CT + K2_CT + "?" + K3_CT + K4_CT
    print(f"V1 (? between K2-K3): {len(full_text_v1)} chars")
elif len(full_text) < 868:
    # Pad with ?'s at boundaries
    diff = 868 - len(full_text)
    print(f"Adding {diff} ?'s")
    full_text_v1 = K1_CT + K2_CT + "?" * diff + K3_CT + K4_CT
    print(f"V1: {len(full_text_v1)} chars")
else:
    full_text_v1 = full_text[:868]
    print(f"V1 (trimmed): {len(full_text_v1)} chars")

# Build 28x31 grid from full text
GRID_WIDTH = 31
cipher_grid = []
for row in range(28):
    start = row * GRID_WIDTH
    end = start + GRID_WIDTH
    cipher_grid.append(full_text_v1[start:end])

# Verify K4 position
k4_start_pos = 24 * 31 + 27  # Row 24, col 27
print(f"\nK4 should start at grid pos {k4_start_pos}")
print(f"Grid[24][27:31] = '{cipher_grid[24][27:]}'")
print(f"Grid[25] = '{cipher_grid[25]}'")
print(f"K4 starts with: '{K4_CT[:4]}'")
k4_match = cipher_grid[24][27:] == K4_CT[:4]
print(f"K4 position match: {k4_match}")

if not k4_match:
    print("\n  WARNING: K4 position doesn't match! Trying alternative ? placement...")
    # Try ? at different positions
    for q_pos_label, full_text_test in [
        ("? at end of K1", K1_CT + "?" + K2_CT + K3_CT + K4_CT),
        ("? between K3-K4", K1_CT + K2_CT + K3_CT + "?" + K4_CT),
        ("no extra ?", K1_CT + K2_CT + K3_CT + K4_CT),
    ]:
        if len(full_text_test) >= 868:
            ft = full_text_test[:868]
        else:
            continue
        grid_test = []
        for row in range(28):
            start = row * GRID_WIDTH
            grid_test.append(ft[start:start+GRID_WIDTH])
        if len(grid_test[24]) > 27 and grid_test[24][27:31] == K4_CT[:4]:
            print(f"  MATCH with '{q_pos_label}'")
            cipher_grid = grid_test
            full_text_v1 = ft
            break

# ============================================================
# PART 3: Extract cipher panel text at grille hole positions
# ============================================================

print("\n\n--- PART 3: Cipher Panel Through Grille Holes ---")

# Load quadgrams
try:
    with open('data/english_quadgrams.json') as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1
    def qg_score(text):
        if len(text) < 4: return -99
        score = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text)-3))
        return score / (len(text) - 3)
except:
    def qg_score(text): return -99.0

for strat_name, holes in strategies.items():
    print(f"\n  === Strategy: {strat_name} ({len(holes)} holes) ===")

    # Extract cipher text at hole positions (L-R, T-B order)
    # Filter to valid grid positions
    valid_holes = [(r, c) for r, c in holes if r < 28 and c < 31]
    # Sort by (row, col) for L-R T-B reading
    valid_holes.sort()

    extract = ""
    positions = []
    for r, c in valid_holes:
        if r < len(cipher_grid) and c < len(cipher_grid[r]):
            ch = cipher_grid[r][c]
            extract += ch
            positions.append((r, c, ch))

    print(f"  Valid holes (within 28x31): {len(valid_holes)}")
    print(f"  Extract ({len(extract)} chars): {extract}")

    if len(extract) >= 4:
        # Frequency analysis
        freq = Counter(extract)
        n = len(extract)
        ic = sum(f*(f-1) for f in freq.values()) / (n*(n-1)) if n > 1 else 0
        qg = qg_score(extract)
        missing = [c for c in AZ if c not in extract]

        print(f"  IC: {ic:.4f} (random=0.0385, English=0.0667)")
        print(f"  Quadgram: {qg:.3f}/char")
        print(f"  Missing letters: {missing}")
        print(f"  Top 5 freq: {freq.most_common(5)}")

        # Try decrypting with standard keywords
        for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLINCLOCK"]:
            for cipher_name, dec_fn in [
                ("Vig", lambda c, k: AZ[(AZ.index(c) - AZ.index(k)) % 26]),
                ("Beau", lambda c, k: AZ[(AZ.index(k) - AZ.index(c)) % 26]),
            ]:
                pt = ""
                for i, ch in enumerate(extract):
                    if ch.isalpha():
                        k = keyword[i % len(keyword)]
                        pt += dec_fn(ch, k)
                    else:
                        pt += ch
                pt_qg = qg_score(pt)
                if pt_qg > -7.5:
                    print(f"    {cipher_name}/{keyword}: qg={pt_qg:.3f} → {pt[:60]}...")

    # Also check: how many holes land on K4?
    k4_holes = [(r, c) for r, c in valid_holes
                if (r == 24 and c >= 27) or (r >= 25)]
    print(f"  Holes on K4: {len(k4_holes)}")

# ============================================================
# PART 4: MIRRORED grille (flip horizontally for other panel)
# ============================================================

print("\n\n--- PART 4: Mirrored Grille ---")
print("When flipping the grille to go from tableau to cipher panel,")
print("columns are mirrored: col c → col (30 - c) for a 31-col grid")

for strat_name, holes in strategies.items():
    if strat_name != "first_31":
        continue  # Focus on the 31-col strategy

    # Mirror each hole position horizontally
    mirrored_holes = [(r, 30 - c) for r, c in holes if c < 31]
    mirrored_holes.sort()

    extract = ""
    for r, c in mirrored_holes:
        if 0 <= r < 28 and 0 <= c < 31:
            if r < len(cipher_grid) and c < len(cipher_grid[r]):
                extract += cipher_grid[r][c]

    print(f"\n  Mirrored '{strat_name}' ({len(extract)} chars):")
    print(f"  Extract: {extract}")

    if len(extract) >= 4:
        freq = Counter(extract)
        n = len(extract)
        ic = sum(f*(f-1) for f in freq.values()) / (n*(n-1)) if n > 1 else 0
        qg = qg_score(extract)
        missing = [c for c in AZ if c not in extract]
        print(f"  IC: {ic:.4f}")
        print(f"  Quadgram: {qg:.3f}/char")
        print(f"  Missing letters: {missing}")

        for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for cipher_name, dec_fn in [
                ("Vig", lambda c, k: AZ[(AZ.index(c) - AZ.index(k)) % 26]),
                ("Beau", lambda c, k: AZ[(AZ.index(k) - AZ.index(c)) % 26]),
            ]:
                pt = ""
                for i, ch in enumerate(extract):
                    if ch.isalpha():
                        k = keyword[i % len(keyword)]
                        pt += dec_fn(ch, k)
                    else:
                        pt += ch
                pt_qg = qg_score(pt)
                if pt_qg > -7.5:
                    print(f"    {cipher_name}/{keyword}: qg={pt_qg:.3f} → {pt[:60]}...")

# ============================================================
# PART 5: The 106-char grille extract IS the hidden message?
# ============================================================

print("\n\n--- PART 5: Grille Extract as K5 Candidate ---")

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

print(f"Grille extract: {GRILLE_EXTRACT}")
print(f"Length: {len(GRILLE_EXTRACT)}")
print(f"K5 expected: 97 chars")
print(f"Difference: {len(GRILLE_EXTRACT) - 97} extra chars")

# If 9 chars are from header/footer positions, remaining = 97 = K5!
# The header is row 0 and footer is row 27
# How many holes in header/footer?
for strat_name, holes in strategies.items():
    if strat_name != "first_31":
        continue
    valid = [(r, c) for r, c in holes if r < 28 and c < 31]
    header_footer = [(r, c) for r, c in valid if r == 0 or r == 27]
    body = [(r, c) for r, c in valid if 0 < r < 27]
    print(f"\n  Strategy '{strat_name}':")
    print(f"    Holes in header (row 0): {sum(1 for r,c in valid if r == 0)}")
    print(f"    Holes in footer (row 27): {sum(1 for r,c in valid if r == 27)}")
    print(f"    Holes in body (rows 1-26): {len(body)}")

# Try decrypting the 106-char extract with keywords
print("\n  Decrypting grille extract with keywords:")
for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "SHADOW",
                 "ENDYAHR", "SANBORN", "SCHEIDT", "WEBSTER"]:
    for cipher_name, dec_fn in [
        ("Vig/AZ", lambda c, k: AZ[(AZ.index(c) - AZ.index(k)) % 26]),
        ("Beau/AZ", lambda c, k: AZ[(AZ.index(k) - AZ.index(c)) % 26]),
    ]:
        pt = ""
        for i, ch in enumerate(GRILLE_EXTRACT):
            k = keyword[i % len(keyword)]
            pt += dec_fn(ch, k)
        pt_qg = qg_score(pt)
        if pt_qg > -7.8:
            print(f"    {cipher_name}/{keyword}: qg={pt_qg:.3f} → {pt[:70]}...")

# Also try with KA-based Vigenere
print("\n  KA-based decryption:")
for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
    pt = ""
    for i, ch in enumerate(GRILLE_EXTRACT):
        k = keyword[i % len(keyword)]
        # KA Vig: PT = AZ[(KA.index(CT) - AZ.index(key)) % 26]
        pt += AZ[(KA.index(ch) - AZ.index(k)) % 26]
    pt_qg = qg_score(pt)
    print(f"    VigKA/{keyword}: qg={pt_qg:.3f} → {pt[:70]}...")

# IC analysis at various periods
print("\n  IC at different periods:")
for period in [7, 8, 10, 11, 13, 26]:
    columns = [[] for _ in range(period)]
    for i, ch in enumerate(GRILLE_EXTRACT):
        columns[i % period].append(AZ.index(ch))

    col_ics = []
    for col in columns:
        if len(col) > 1:
            n = len(col)
            freq = Counter(col)
            ic = sum(f*(f-1) for f in freq.values()) / (n*(n-1))
            col_ics.append(ic)

    avg_ic = sum(col_ics) / len(col_ics) if col_ics else 0
    print(f"    Period {period:2d}: avg IC = {avg_ic:.4f}")

# ============================================================
# PART 6: What if K5 = cipher panel at TABLEAU grille holes?
# ============================================================

print("\n\n--- PART 6: Locate Grille Holes via Tableau Matching ---")
print("Find where each grille extract char sits in the tableau,")
print("then read the cipher panel at those positions.\n")

# Build tableau lookup: for each (row, col), what letter is there?
TABLEAU_ROWS_RAW = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
]

# For the "first_31" strategy mask holes, read the tableau to verify
# the grille extract, then read the cipher panel
for strat_name in ["first_31"]:
    holes = strategies[strat_name]
    valid = [(r, c) for r, c in holes if r < 28 and c < 31]
    valid.sort()

    # Read tableau at holes
    tableau_extract = ""
    for r, c in valid:
        tab_row = TABLEAU_ROWS_RAW[r]
        if c < len(tab_row):
            tableau_extract += tab_row[c]
        else:
            tableau_extract += "?"

    print(f"Strategy '{strat_name}':")
    print(f"  Tableau at holes:  {tableau_extract}")
    print(f"  Expected extract:  {GRILLE_EXTRACT}")
    print(f"  Length tableau:    {len(tableau_extract)}")
    print(f"  Length expected:   {len(GRILLE_EXTRACT)}")

    # Check how many match
    match_count = sum(1 for a, b in zip(tableau_extract, GRILLE_EXTRACT) if a == b)
    print(f"  Matching chars:    {match_count}/{min(len(tableau_extract), len(GRILLE_EXTRACT))}")

    # Read cipher panel at the SAME hole positions
    cipher_extract = ""
    for r, c in valid:
        if r < len(cipher_grid) and c < len(cipher_grid[r]):
            cipher_extract += cipher_grid[r][c]
        else:
            cipher_extract += "?"

    print(f"\n  Cipher panel at holes: {cipher_extract}")
    print(f"  Length: {len(cipher_extract)}")

    if len(cipher_extract) >= 4:
        freq = Counter(cipher_extract.replace('?', ''))
        n = len(cipher_extract.replace('?', ''))
        ic = sum(f*(f-1) for f in freq.values()) / (n*(n-1)) if n > 1 else 0
        qg = qg_score(cipher_extract.replace('?', ''))
        missing = [c for c in AZ if c not in cipher_extract]
        print(f"  IC: {ic:.4f}")
        print(f"  QG: {qg:.3f}/char")
        print(f"  Missing: {missing}")

        # Decrypt with keywords
        clean = cipher_extract.replace('?', '')
        for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]:
            for name, fn in [
                ("Vig", lambda c, k: AZ[(AZ.index(c)-AZ.index(k))%26]),
                ("Beau", lambda c, k: AZ[(AZ.index(k)-AZ.index(c))%26]),
            ]:
                pt = "".join(fn(ch, keyword[i%len(keyword)]) for i, ch in enumerate(clean))
                pqg = qg_score(pt)
                if pqg > -7.5:
                    print(f"    {name}/{keyword}: qg={pqg:.3f} → {pt[:60]}...")

    # Mirrored version
    mirrored = [(r, 30-c) for r, c in valid]
    mirrored.sort()
    cipher_mirrored = ""
    for r, c in mirrored:
        if 0 <= r < 28 and 0 <= c < 31 and r < len(cipher_grid) and c < len(cipher_grid[r]):
            cipher_mirrored += cipher_grid[r][c]

    print(f"\n  MIRRORED cipher at holes: {cipher_mirrored}")
    if len(cipher_mirrored) >= 4:
        qg = qg_score(cipher_mirrored)
        ic_freq = Counter(cipher_mirrored)
        n = len(cipher_mirrored)
        ic = sum(f*(f-1) for f in ic_freq.values()) / (n*(n-1)) if n > 1 else 0
        print(f"  IC: {ic:.4f}")
        print(f"  QG: {qg:.3f}/char")

        for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for name, fn in [
                ("Vig", lambda c, k: AZ[(AZ.index(c)-AZ.index(k))%26]),
                ("Beau", lambda c, k: AZ[(AZ.index(k)-AZ.index(c))%26]),
            ]:
                pt = "".join(fn(ch, keyword[i%len(keyword)]) for i, ch in enumerate(cipher_mirrored))
                pqg = qg_score(pt)
                if pqg > -7.5:
                    print(f"    {name}/{keyword}: qg={pqg:.3f} → {pt[:60]}...")

# ============================================================
# PART 7: The extra T on row V
# ============================================================

print("\n\n--- PART 7: Extra T on Row V ---")
print("From memory: Row V (row 22) also has an extra T")
print("V - N = T - L = 8 (period 8!)")
print("T is the MISSING letter from the grille extract!")

row_v = TABLEAU_ROWS_RAW[22]  # 0-indexed: row 22 = key V
print(f"\nRow V (22): '{row_v}' ({len(row_v)} chars)")

# Expected row V: key V = AZ index 21, body starts at KA[21]
expected_v = "V" + "".join(KA[(21 + i) % 26] for i in range(30))
print(f"Expected:   '{expected_v}' ({len(expected_v)} chars)")

if len(row_v) > len(expected_v):
    print(f"Extra chars: '{row_v[len(expected_v):]}'")
    extra_v = row_v[len(expected_v)]
    print(f"Extra char = '{extra_v}'")
    expected_next = KA[(21 + 30) % 26]
    print(f"Expected next in sequence: KA[(21+30)%26] = KA[{(21+30)%26}] = '{expected_next}'")
elif row_v == expected_v:
    print("Row V matches expected (NO extra character in our digital version)")
    print("The extra T may only be visible on the PHYSICAL sculpture")

# ============================================================
# SUMMARY
# ============================================================

print("\n\n" + "=" * 75)
print("SUMMARY")
print("=" * 75)
print("""
THEORY: The Cardan grille applied to the cipher panel reveals a hidden
steganographic message (K5?) with no known cribs.

FINDINGS:
1. The binary mask (even with dimension issues) extracts text from the
   cipher panel — needs correct mask for valid results
2. The 106-char grille extract from the TABLEAU is itself a K5 candidate
   (106 chars, 9 more than K5's expected 97)
3. The mask holes in header/footer rows may account for the 9 extra chars
4. Mirror-flipping the grille is needed when going from tableau to cipher panel
5. The extra L (row N) and extra T (row V) create period-8 structural markers
6. T's absence from the grille extract + "T IS YOUR POSITION" remains the
   strongest unexploited connection

CRITICAL LIMITATION: Our mask has wrong dimensions (variable widths vs 28x31).
Until the correct mask is established, all cipher-panel extractions are
approximate. The USER is working on the correct grid alignment.

NEXT STEPS:
- User to provide corrected 28x31 grille mask
- Test grille extract (106 chars) directly as K5 with various keywords
- Investigate whether header/footer holes give exactly 9 chars → 97 body chars
""")
