#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: tableau
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-TABLEAU-OVERLAY: Investigate the tableau-as-grille theory.

Theory: Place the tableau (right panel) on top of the cipher panel (left panel).
Remove certain letters from the tableau → read cipher text underneath at those
positions. The tableau IS the Cardan grille.

Also investigates:
- The extra L on row N (extends to col 32, outside 31-col grid)
- What adjustments to row N would mean for the overlay
- Strip cipher / scytale interpretation
- Which tableau letter removals create meaningful cipher extracts
"""

import json
import sys
from collections import Counter
from itertools import combinations

# Constants
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Full cipher text (868 chars with positional ?'s)
# K1 + K2 + ? + K3 + ? + K4 = 63 + 369 + ? + 336 + ? + 97
# With squeezed 3rd K2 ? removed: 865 letters + 3 positional ?'s = 868

# Build the complete cipher panel (left side of sculpture), 28 rows x 31 cols
# From memory/full_ciphertext.md and constants
FULL_CT_LETTERS = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV"  # row 0
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"  # row 1 — wait, need exact
)

# Actually let me build this properly from the known sections
# K1 CT (63 chars)
K1 = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
# K2 CT (369 chars)
K2 = ("VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
      "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG"
      "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
      "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
      "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
      "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE"
      "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
      "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF"
      "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
      "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
      "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
      "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG")
# K3 CT (336 chars)
K3 = ("ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
      "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
      "TPRNGATIHNRARPESLNNELEBLPIIACAE"
      "WMTWNDITEENRAHCTENEUDRETNHAEOET"
      "FOLDESLHAHAHRTEWFABENMIEAHHETEMA"
      "SGLNDNPMCHZRDMEELEZEEAIOLFETIHA"
      "EVTMDAEHEMTDIVFEOHMNERAHTTRDNETH"
      "EEPEAHSADNHTEHEADTISRIHNDCLEIHH"
      "ATRTPLEVANLEKZALRDVEIESNDMTFLA"
      "AHETTEEFREEDIEAHLESDHTWCAIEHTHEE"
      "DFHRTDERHSIESWENHTHETHSAHCTESL")
# K4 CT (97 chars)
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# OK this is getting messy with the ?'s. Let me build from the actual grid.
# The key insight: we need the 28x31 cipher panel as it appears on the sculpture.

# From memory and previous work, the full cipher panel at width 31:
# Let me reconstruct row by row from known data

# Actually, let me read from the master build script or constants
sys.path.insert(0, 'src')
try:
    from kryptos.kernel.constants import CT as K4_CT
except:
    K4_CT = K4

print("=" * 75)
print("E-TABLEAU-OVERLAY: Tableau as Cardan Grille")
print("=" * 75)

# ============================================================
# PART 1: Build the tableau (right panel), 28 rows x 31+ cols
# ============================================================

print("\n--- PART 1: Build the Tableau ---")

# The physical tableau from kryptos_tableau.md (verified)
TABLEAU_ROWS_RAW = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",   # Row 0: header (space + 30)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",   # Row 1: key=A
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",   # Row 2: key=B
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",   # Row 3: key=C
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",   # Row 4: key=D
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",   # Row 5: key=E
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",   # Row 6: key=F
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",   # Row 7: key=G
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",   # Row 8: key=H
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",   # Row 9: key=I
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",   # Row 10: key=J
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",   # Row 11: key=K
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",   # Row 12: key=L
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",   # Row 13: key=M
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # Row 14: key=N *** EXTRA L ***
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",   # Row 15: key=O
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",   # Row 16: key=P
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",   # Row 17: key=Q
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",   # Row 18: key=R
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",   # Row 19: key=S
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",   # Row 20: key=T
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",   # Row 21: key=U
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",   # Row 22: key=V
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",   # Row 23: key=W
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",   # Row 24: key=X
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",   # Row 25: key=Y
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",   # Row 26: key=Z
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",   # Row 27: footer
]

# Verify row lengths
print("\nTableau row lengths:")
for i, row in enumerate(TABLEAU_ROWS_RAW):
    flag = " *** EXTRA L ***" if len(row) != 31 else ""
    if flag or i <= 2 or i >= 26:
        print(f"  Row {i:2d}: {len(row)} chars{flag}")

# For the 31-column overlay, we need to decide how to handle:
# 1. The header/footer space (column 0 = space)
# 2. Row N's extra L (column 31 = 32nd char)

# Option A: Trim all rows to 31 columns (drop extra L)
# Option B: Keep row N at 32, shift everything after it
# Option C: The extra L REPLACES something — tableau is adjusted

print(f"\nRow N (raw): {TABLEAU_ROWS_RAW[14]}")
print(f"Row N length: {len(TABLEAU_ROWS_RAW[14])}")
print(f"Row N last 5 chars: ...{TABLEAU_ROWS_RAW[14][-5:]}")
print(f"Row O (next): {TABLEAU_ROWS_RAW[15]}")
print(f"Row O length: {len(TABLEAU_ROWS_RAW[15])}")

# Row N expected (without extra L):
# Key N = AZ index 13, so body starts at KA[13] = H
# Body: HIJLMNQUVWXZKRYPTOSABCDEFGHIJLM (first 30 of KA shifted by 13)
# Full: NHIJLMNQUVWXZKRYPTOSABCDEFGHIJLM  (key + 30 body = 31)
expected_n = "N" + "".join(KA[(13 + i) % 26] for i in range(30))
print(f"\nExpected Row N: {expected_n}")
print(f"Actual Row N:   {TABLEAU_ROWS_RAW[14]}")
# Find the difference
for i in range(min(len(expected_n), len(TABLEAU_ROWS_RAW[14]))):
    if i < len(expected_n) and i < len(TABLEAU_ROWS_RAW[14]):
        if expected_n[i] != TABLEAU_ROWS_RAW[14][i]:
            print(f"  DIFF at col {i}: expected '{expected_n[i]}', actual '{TABLEAU_ROWS_RAW[14][i]}'")
if len(TABLEAU_ROWS_RAW[14]) > len(expected_n):
    print(f"  EXTRA chars at end: '{TABLEAU_ROWS_RAW[14][len(expected_n):]}'")

# ============================================================
# PART 2: Build the cipher panel (left side), 28 rows x 31 cols
# ============================================================

print("\n\n--- PART 2: Cipher Panel (28x31) ---")

# We need the actual 868 characters as they appear on the sculpture
# From the master grid build and memory
# Row 0: EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV (31 chars, K1 starts)
# ...
# Row 24: starts with end of K3 + K4 start (OBKR at end)
# etc.

# Build from the known full ciphertext
# Total: 865 letters + 3 positional ?'s = 868 = 28 x 31

# The full text in reading order (row by row, left to right)
# This needs to be exact. Let me use what we know:

# From memory: the full ciphertext boundaries are:
# K1[0:63]=63 chars
# K2[63:432]=369 chars (including 2 positional ?'s)
# K3[432:768]=336 chars (including 1 positional ?)
# K4[768:865]=97 chars
# But with the ?'s counted differently...

# Actually the simplest approach: read from the master build script
# or reconstruct from known row data

# K4 layout in 28x31 grid (from memory):
# Row 24, cols 27-30: OBKR (4 chars)
# Row 25, cols 0-30: UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO (31 chars)
# Row 26, cols 0-30: TWTQSJQSSEKZZWATJKLUDIAWINFBNYP (31 chars)
# Row 27, cols 0-30: VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR (31 chars)
# Total: 4 + 31 + 31 + 31 = 97 ✓

# For the full cipher panel, let me try to load or reconstruct
# First try loading from master build
try:
    with open('results/grid31_master.json') as f:
        grid_data = json.load(f)
        CIPHER_ROWS = grid_data.get('cipher_rows', [])
except:
    CIPHER_ROWS = []

if not CIPHER_ROWS:
    # Reconstruct from known data
    # We know K4's position precisely. For the overlay analysis,
    # we mainly need the K4 rows (24-27) and their alignment with tableau rows (24-27)
    # But let's try to get the full grid

    # From e_grid31_master_build.py output or constants
    # Let me just hardcode what we need for the K4 region
    # and use placeholder for the rest

    # The K3 ciphertext
    K3_CT = ("ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
             "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
             "TPRNGATIHNRARPESLNNELEBLPIIACAE"
             "WMTWNDITEENRAHCTENEUDRETNHAEOET"
             "FOLDESLHAHAHRTEWFABENMIEAHHETEMA"
             "SGLNDNPMCHZRDMEELEZEEAIOLFETIHA"
             "EVTMDAEHEMTDIVFEOHMNERAHTTRDNETH"
             "EEPEAHSADNHTEHEADTISRIHNDCLEIHH"
             "ATRTPLEVANLEKZALRDVEIESNDMTFLA"
             "AHETTEEFREEDIEAHLESDHTWCAIEHTHEE"
             "DFHRTDERHSIESWENHTHETHSAHCTESL")

    # For now, focus on what we can verify: K4 rows
    # K4 occupies: row 24 cols 27-30, rows 25-27 full

    # Row 24 ends with OBKR (cols 27-30)
    # Row 24 starts with the end of K3...
    # K3 is 336 chars, starts at row 14 col 0 (position 434)
    # K3 rows: 14-24 (but row 24 only partial)
    # Actually K3 is rows 14 through part of row 24
    # Row 14-23 = 10 full rows = 310 chars
    # Row 24, cols 0-26 = 27 chars more = 337 chars total
    # But K3 is 336 chars + 1 ? = 337 positions?
    # Or K3 is 336 chars occupying rows 14-24 (col 0-26 of row 24 = 310+27=337 positions)
    # The ? is one of those 337 positions, so 336 letters + 1 ? = 337

    # This is getting complicated. Let me focus on what matters:
    # The TABLEAU ROWS that overlay K4 positions

    print("  Using known K4 grid positions for analysis")
    print("  K4 in grid: row 24 cols 27-30, rows 25-27 cols 0-30")

# ============================================================
# PART 3: Tableau overlay on K4 positions
# ============================================================

print("\n\n--- PART 3: Tableau Letters at K4 Grid Positions ---")

# K4 grid positions and their tableau overlay
# K4[0] = OBKR... at row 24, cols 27-30
# K4[4-34] = row 25, cols 0-30
# K4[35-65] = row 26, cols 0-30
# K4[66-96] = row 27, cols 0-30

k4_grid_positions = []
# Row 24, cols 27-30 (4 chars)
for c in range(27, 31):
    k4_grid_positions.append((24, c))
# Rows 25-27, cols 0-30 (31 chars each)
for r in range(25, 28):
    for c in range(31):
        k4_grid_positions.append((r, c))

assert len(k4_grid_positions) == 97, f"Expected 97, got {len(k4_grid_positions)}"

# Get tableau letter at each position
# Tableau rows (trimmed to 31 cols for standard alignment)
tableau_31 = []
for row in TABLEAU_ROWS_RAW:
    tableau_31.append(row[:31])  # Trim to 31 cols

print(f"\nK4 positions with tableau overlay:")
print(f"{'Pos':>4} {'Row':>3} {'Col':>3} {'K4':>3} {'Tab':>3} {'Match':>5}")
matches = []
for i, (r, c) in enumerate(k4_grid_positions):
    k4_char = K4_CT[i]
    tab_char = tableau_31[r][c] if c < len(tableau_31[r]) else '?'
    match = k4_char == tab_char
    if match:
        matches.append(i)
    if match or i < 10 or i > 90:
        print(f"  {i:3d}  {r:3d}  {c:3d}   {k4_char}    {tab_char}   {'YES' if match else ''}")

print(f"\nTotal matches (cipher == tableau): {len(matches)}")
print(f"Match positions: {matches}")
print(f"Match K4 chars: {''.join(K4_CT[i] for i in matches)}")

# ============================================================
# PART 4: For each letter A-Z, find where it appears in the
# tableau at K4 positions → extract cipher text at those spots
# ============================================================

print("\n\n--- PART 4: Letter Removal Analysis ---")
print("For each letter: where does it appear in tableau at K4 positions?")
print("If removed, what cipher text is revealed underneath?\n")

# Load quadgrams
try:
    with open('data/english_quadgrams.json') as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1
    def qg_score(text):
        if len(text) < 4:
            return -99
        score = 0
        for i in range(len(text) - 3):
            qg = text[i:i+4]
            score += QUADGRAMS.get(qg, QG_FLOOR)
        return score / (len(text) - 3)
except:
    def qg_score(text):
        return -99.0

# For each letter, find positions and extract cipher
for letter in AZ:
    positions = []
    for i, (r, c) in enumerate(k4_grid_positions):
        tab_char = tableau_31[r][c] if c < len(tableau_31[r]) else '?'
        if tab_char == letter:
            positions.append(i)

    if positions:
        extracted = "".join(K4_CT[p] for p in positions)
        qg = qg_score(extracted) if len(extracted) >= 4 else -99
        # Also extract what's NOT at those positions (complement)
        complement = "".join(K4_CT[p] for p in range(97) if p not in positions)
        qg_comp = qg_score(complement) if len(complement) >= 4 else -99
        print(f"  Remove {letter}: {len(positions):2d} positions → CT='{extracted}' (qg={qg:.2f})")
        if len(positions) >= 3 and len(positions) <= 10:
            print(f"           positions: {positions}")

# ============================================================
# PART 5: The Extra L — Row N Analysis
# ============================================================

print("\n\n--- PART 5: Extra L on Row N (Row 14) ---")

row_n_actual = TABLEAU_ROWS_RAW[14]  # 32 chars
row_n_expected = expected_n  # 31 chars

print(f"Row N actual:   '{row_n_actual}' ({len(row_n_actual)} chars)")
print(f"Row N expected: '{row_n_expected}' ({len(row_n_expected)} chars)")
print(f"Extra char: '{row_n_actual[-1]}' at position {len(row_n_actual)-1}")

# What's at row 14 in the cipher panel? K3 starts here.
# Row 14 = positions 434-464 of the full grid (14*31=434 to 14*31+30=464)
# K3 starts at position 434 (row 14, col 0)
# First 31 chars of K3 CT: ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA
k3_first_row = K3_CT[:31]
print(f"\nCipher at row 14: {k3_first_row}")
print(f"Tableau row N:    {row_n_actual[:31]}  (+{row_n_actual[31:]})")

# Overlay comparison
print(f"\nRow 14 overlay (tableau vs cipher):")
print(f"  Tab: {row_n_actual[:31]}")
print(f"  Cip: {k3_first_row}")
match_str = ""
for i in range(31):
    if i < len(row_n_actual) and i < len(k3_first_row):
        if row_n_actual[i] == k3_first_row[i]:
            match_str += "^"
        else:
            match_str += " "
    else:
        match_str += " "
print(f"       {match_str}")

overlay_matches = sum(1 for i in range(31) if row_n_actual[i] == k3_first_row[i])
print(f"  Matches: {overlay_matches}/31")

# What if the extra L shifts row N?
# Theory: Remove the L at position 31 and row N becomes 31 chars (normal)
# Theory: The L was supposed to be at the BEGINNING, shifting everything right
# Theory: Remove one L from the body to make it 31 chars

# Find all L's in row N
l_positions = [i for i, ch in enumerate(row_n_actual) if ch == 'L']
print(f"\nL positions in row N: {l_positions}")
print(f"If we remove each L, what row N variants do we get?")
for lp in l_positions:
    variant = row_n_actual[:lp] + row_n_actual[lp+1:]
    assert len(variant) == 31
    # Compare with cipher at row 14
    matches_v = sum(1 for i in range(31) if variant[i] == k3_first_row[i])
    print(f"  Remove L at col {lp:2d}: '{variant}' → {matches_v}/31 cipher matches")

# ============================================================
# PART 6: Tableau overlay on FULL K4 — different row N treatments
# ============================================================

print("\n\n--- PART 6: Row N Treatments and K4 Overlay ---")

# Row N (row 14) doesn't directly overlay K4 (rows 24-27).
# But the extra L could affect how we CONSTRUCT the overlay.
# The tableau rows that overlay K4 are rows 24-27:
# Row 24 (key=X): XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK (31 chars)
# Row 25 (key=Y): YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR (31 chars)
# Row 26 (key=Z): ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY (31 chars)
# Row 27 (footer): _ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (31 chars)

print("Tableau rows overlaying K4:")
for r in range(24, 28):
    print(f"  Row {r}: {TABLEAU_ROWS_RAW[r]}")

# K4 at these rows:
# Row 24, cols 27-30: OBKR (tableau: WXZK)
# Row 25, cols 0-30: UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO (tableau: YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR)
# Row 26, cols 0-30: TWTQSJQSSEKZZWATJKLUDIAWINFBNYP (tableau: ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY)
# Row 27, cols 0-30: VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR (tableau: _ABCDEFGHIJKLMNOPQRSTUVWXYZABCD)

print("\nDetailed K4 overlay with tableau (rows 24-27):")
print(f"{'Pos':>4} {'Row':>3} {'Col':>3} {'CT':>3} {'Tab':>3} {'Diff':>5} {'VigK':>5} {'BeauK':>6}")
vig_keys = []
beau_keys = []
for i, (r, c) in enumerate(k4_grid_positions):
    ct = K4_CT[i]
    tab = tableau_31[r][c] if c < len(tableau_31[r]) else ' '

    if tab.isalpha() and ct.isalpha():
        vig_k = (AZ.index(ct) - AZ.index(tab)) % 26
        beau_k = (AZ.index(ct) + AZ.index(tab)) % 26
    else:
        vig_k = -1
        beau_k = -1

    vig_keys.append(vig_k)
    beau_keys.append(beau_k)

    if i < 8 or i in matches or (21 <= i <= 33) or (63 <= i <= 73) or i > 92:
        match = "YES" if ct == tab else ""
        vk = AZ[vig_k] if vig_k >= 0 else "?"
        bk = AZ[beau_k] if beau_k >= 0 else "?"
        print(f"  {i:3d}  {r:3d}  {c:3d}   {ct}    {tab}   {match:5s}  {vk}({vig_k:2d})  {bk}({beau_k:2d})")

# ============================================================
# PART 7: Key derived from tableau position
# If CT = Vig(PT, Tab) then PT = CT - Tab (mod 26)
# This treats the tableau letter as the KEY
# ============================================================

print("\n\n--- PART 7: Tableau as Running Key ---")
print("If tableau provides the key letter at each position:")

# For Vigenère: PT = (CT - TabKey) mod 26
# For Beaufort: PT = (TabKey - CT) mod 26
# For Variant Beaufort: PT = (CT + TabKey) mod 26

for cipher_name, formula in [
    ("Vig (PT=CT-Tab)", lambda c, t: (AZ.index(c) - AZ.index(t)) % 26),
    ("Beau (PT=Tab-CT)", lambda c, t: (AZ.index(t) - AZ.index(c)) % 26),
    ("VarBeau (PT=CT+Tab)", lambda c, t: (AZ.index(c) + AZ.index(t)) % 26),
]:
    pt = ""
    for i, (r, c_col) in enumerate(k4_grid_positions):
        ct = K4_CT[i]
        tab = tableau_31[r][c_col] if c_col < len(tableau_31[r]) else 'A'
        if tab.isalpha():
            pt += AZ[formula(ct, tab)]
        else:
            pt += ct  # space in header/footer

    qg = qg_score(pt)
    # Check cribs
    ene_match = sum(1 for j, ch in enumerate("EASTNORTHEAST") if pt[21+j] == ch)
    bc_match = sum(1 for j, ch in enumerate("BERLINCLOCK") if pt[63+j] == ch)
    print(f"\n  {cipher_name}:")
    print(f"    PT: {pt}")
    print(f"    QG: {qg:.3f}/char")
    print(f"    ENE crib: {ene_match}/13, BC crib: {bc_match}/11")

# Also try with KA alphabet
print("\n  --- Using KA alphabet ---")
for cipher_name, formula in [
    ("VigKA (PT=KA.inv(CT)-Tab)", lambda c, t: (KA.index(c) - AZ.index(t)) % 26),
    ("BeauKA (PT=Tab-KA.inv(CT))", lambda c, t: (AZ.index(t) - KA.index(c)) % 26),
]:
    pt = ""
    for i, (r, c_col) in enumerate(k4_grid_positions):
        ct = K4_CT[i]
        tab = tableau_31[r][c_col] if c_col < len(tableau_31[r]) else 'A'
        if tab.isalpha():
            pt += AZ[formula(ct, tab)]
        else:
            pt += ct

    qg = qg_score(pt)
    ene_match = sum(1 for j, ch in enumerate("EASTNORTHEAST") if pt[21+j] == ch)
    bc_match = sum(1 for j, ch in enumerate("BERLINCLOCK") if pt[63+j] == ch)
    print(f"\n  {cipher_name}:")
    print(f"    PT: {pt}")
    print(f"    QG: {qg:.3f}/char")
    print(f"    ENE crib: {ene_match}/13, BC crib: {bc_match}/11")

# ============================================================
# PART 8: Remove specific letters from tableau → read cipher
# Which removal patterns create best quadgram scores?
# ============================================================

print("\n\n--- PART 8: Multi-Letter Removal Patterns ---")
print("Remove combinations of letters from tableau, read cipher underneath\n")

# For each pair of letters removed
best_pairs = []
for l1, l2 in combinations(AZ, 2):
    positions = []
    for i, (r, c) in enumerate(k4_grid_positions):
        tab = tableau_31[r][c] if c < len(tableau_31[r]) else '?'
        if tab in (l1, l2):
            positions.append(i)

    if len(positions) >= 4:
        extracted = "".join(K4_CT[p] for p in positions)
        qg = qg_score(extracted)
        best_pairs.append((qg, l1, l2, len(positions), extracted, positions))

best_pairs.sort(reverse=True)
print("Top 10 two-letter removal patterns (by quadgram score):")
for qg, l1, l2, n, text, positions in best_pairs[:10]:
    print(f"  Remove {l1}{l2}: {n:2d} positions → '{text}' (qg={qg:.2f})")

# For each single letter removed, also check if the COMPLEMENT
# (everything except those positions) has better properties
print("\n\nSingle letter removal — COMPLEMENT analysis:")
print("(Keep everything EXCEPT where this letter appears in tableau)\n")
for letter in AZ:
    positions = []
    for i, (r, c) in enumerate(k4_grid_positions):
        tab = tableau_31[r][c] if c < len(tableau_31[r]) else '?'
        if tab == letter:
            positions.append(i)

    if positions:
        complement_pos = [p for p in range(97) if p not in positions]
        complement = "".join(K4_CT[p] for p in complement_pos)
        qg = qg_score(complement)
        # IC of complement
        freq = Counter(complement)
        n = len(complement)
        ic = sum(f * (f-1) for f in freq.values()) / (n * (n-1)) if n > 1 else 0
        print(f"  Remove {letter}: keep {len(complement_pos)}/97 chars, IC={ic:.4f}, qg={qg:.2f}")

# ============================================================
# PART 9: Strip cipher interpretation
# Each tableau row is a shifted KA alphabet strip
# The cipher text is read through "windows" in the strips
# ============================================================

print("\n\n--- PART 9: Strip Cipher / Scytale Interpretation ---")

# In a strip cipher, you align strips (shifted alphabets) and read at a row
# The Kryptos tableau is literally strips of shifted KA alphabet
# If we "look through" the tableau at specific positions, we get cipher text

# What if the "windows" are positions where a specific relationship holds
# between the tableau letter and the cipher letter?

# Check: at how many positions does cipher = tableau + N (mod 26)?
for shift in range(26):
    count = 0
    positions = []
    for i, (r, c) in enumerate(k4_grid_positions):
        ct = K4_CT[i]
        tab = tableau_31[r][c] if c < len(tableau_31[r]) else '?'
        if tab.isalpha():
            if (AZ.index(ct) - AZ.index(tab)) % 26 == shift:
                count += 1
                positions.append(i)
    if count >= 5:
        extracted = "".join(K4_CT[p] for p in positions)
        print(f"  CT = Tab + {shift:2d} ({AZ[shift]}): {count:2d} positions → {extracted[:40]}...")

# ============================================================
# PART 10: What if the extra L means row N should be SPLIT?
# ============================================================

print("\n\n--- PART 10: Row N Split Theory ---")
print("The extra L at col 31 could mean row N wraps or splits.")
print("What if row N's extra character means the tableau shifts by 1 from row N onward?\n")

# Theory: From row N (14) onward, the tableau is shifted right by 1 column
# This would change the overlay for rows 14-27

# Build shifted tableau for rows 14+
tableau_shifted = list(tableau_31)  # copy
for r in range(14, 28):
    original = TABLEAU_ROWS_RAW[r]
    # Shift right by 1: prepend the last char of the EXPECTED row
    if r == 14:
        # Use the full 32-char row N, columns 1-31 (shift everything right by 1)
        shifted = original[0] + original[0] + original[1:31]  # key + key + body[0:30]
        # Actually, shift right = insert space/char at beginning
        # Let's try: take the 32-char row, use cols 1-31 (skip key, take body including extra L)
        shifted = original[:32]  # all 32 chars, trim to first 31
        shifted = original[:31]  # same as before...
    # Actually let me think about this differently
    # If the extra L pushes everything right by 1 from row N onward:
    # Row N body should start one position later
    pass

# Simpler approach: test if removing each L from row N and recomputing
# the K4 overlay changes anything meaningful

# But row N is row 14, and K4 is at rows 24-27
# The extra L in row N doesn't directly affect K4's overlay
# UNLESS the extra L is a signal about ALL rows

print("Note: Row N (14) doesn't directly overlay K4 (rows 24-27).")
print("But the extra L could be a GLOBAL signal about tableau construction.")
print()

# What if the extra L means: at the ROW where L falls in KA,
# something special happens?
# L is at KA index 12 (KA = KRYPTOSABCDEFGHIJLMNQUVWXZ, L is position 17)
# Wait: K(0)R(1)Y(2)P(3)T(4)O(5)S(6)A(7)B(8)C(9)D(10)E(11)F(12)G(13)H(14)I(15)J(16)L(17)
# L is KA index 17
# In AZ: L = index 11

# The extra L is at the END of row N (the 32nd character)
# Row N key letter is N (AZ index 13)
# In the KA-shifted row for N, the sequence is HIJLMNQUVWXZKRYPTOSABCDEFG...
# The extra L would be the 31st body character
# Normal body is 30 chars (KA shifted, first 30)
# The 31st would be KA[(13+30) % 26] = KA[43 % 26] = KA[17] = L
# So the extra L is simply the NEXT character in the sequence!
# It's as if row N has 31 body chars instead of 30

print("The extra L = KA[(13+30) % 26] = KA[17] = L")
print("It's the NEXT character in the shifted KA sequence.")
print("Row N has 31 body chars instead of 30 — one full extra KA wrap position.")
print()
print("31 body chars = full column coverage at width 31!")
print("Normal rows have 30 body = miss one column. Row N covers ALL 31 columns.")
print("This means: for key letter N, the tableau provides a value for EVERY column,")
print("whereas other key letters leave one column unmapped.")

# ============================================================
# PART 11: Full 31-column coverage — what column does each row miss?
# ============================================================

print("\n\n--- PART 11: Which Column Does Each Row Miss? ---")
print("Normal rows have key + 30 body = 31 chars = cols 0-30")
print("But col 0 is the key letter, cols 1-30 are body")
print("The HEADER maps col 0 to space, cols 1-26 to A-Z, cols 27-30 to ABCD")
print()

# Actually, the header/footer have: space + ABCDEFGHIJKLMNOPQRSTUVWXYZ + ABCD
# = space + 30 = 31 characters
# Each body row has: key_letter + 30 body = 31 characters
# So each row is exactly 31 chars (fills cols 0-30) — EXCEPT row N which is 32

# The question is: what does the 32nd character (col 31) mean?
# In a 31-column grid (cols 0-30), col 31 doesn't exist.
# So the extra L is OUTSIDE the grid.

# But what if the grid is actually 32 cols at row N?
# Or what if the key letter doesn't count as a column?

# Physical layout question: does the key letter occupy a column?
# On the physical sculpture, the key letters are at the left margin,
# and the body text starts at the same column as the header's A

# So the physical layout might be:
# Header: [space] A B C D E F G H I J K L M N O P Q R S T U V W X Y Z A B C D
# Row A:  [A]     K R Y P T O S A B C D E F G H I J L M N Q U V W X Z K R Y P
# ...
# Row N:  [N]     G H I J L M N Q U V W X Z K R Y P T O S A B C D E F G H I J [L]

# If the key letters are in a separate column (col -1 or left margin),
# then the body has 30 chars in cols 0-29 for normal rows
# and 31 chars in cols 0-30 for row N
# And the header has: A-Z + ABCD = 30 chars in cols 0-29

# This changes everything about column alignment!
# Let me check: the header has "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" = 30 chars
# If these map to cols 0-29, then the cipher panel also has cols 0-29 = 30 columns?
# But we said the grid is 31 columns wide...

# Actually the full header is " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" = space + 30 = 31
# If space is col 0: header cols 0-30 = 31
# If key letters are in col 0: body cols 0-30 = 31 (key + 30 body)
# Row N: key + 31 body = 32, with the extra L at col 31

print("CRITICAL QUESTION: Does the key letter share column 0 with the space?")
print("If yes: body starts at col 1, normal rows go to col 30, row N goes to col 31")
print("If no: key is outside the grid, body cols 0-29, row N body cols 0-30")
print()
print("The extra L extends row N by one character beyond all other rows.")
print("This is the ONLY row with a character in that position.")

# ============================================================
# PART 12: T-absence in grille + "T IS YOUR POSITION" + Morse
# ============================================================

print("\n\n--- PART 12: T Analysis in Tableau Overlay ---")

# Where does T appear in the tableau at K4 positions?
t_positions = []
for i, (r, c) in enumerate(k4_grid_positions):
    tab = tableau_31[r][c] if c < len(tableau_31[r]) else '?'
    if tab == 'T':
        t_positions.append(i)

print(f"T appears in tableau at {len(t_positions)} K4 positions: {t_positions}")
print(f"K4 chars at T-positions: {''.join(K4_CT[p] for p in t_positions)}")

# Where does T appear in K4 CT?
t_in_k4 = [i for i, ch in enumerate(K4_CT) if ch == 'T']
print(f"\nT appears in K4 CT at {len(t_in_k4)} positions: {t_in_k4}")

# Positions where T is in tableau but NOT in CT
t_tab_not_ct = [p for p in t_positions if K4_CT[p] != 'T']
print(f"T in tableau, not in CT: {len(t_tab_not_ct)} positions")

# Positions where T is in CT but NOT in tableau
t_ct_not_tab = [p for p in t_in_k4 if p not in t_positions]
print(f"T in CT, not in tableau: {len(t_ct_not_tab)} positions")

# Positions where T is in BOTH
t_both = [p for p in t_positions if K4_CT[p] == 'T']
print(f"T in both: {len(t_both)} positions: {t_both}")

# The grille extract has NO T's — what if "remove T from tableau"
# IS the grille operation?
print(f"\n'Remove T' = keep {97 - len(t_positions)}/{97} K4 positions")
non_t_cipher = "".join(K4_CT[p] for p in range(97) if p not in t_positions)
print(f"Cipher without T-positions: {non_t_cipher} ({len(non_t_cipher)} chars)")
t_cipher = "".join(K4_CT[p] for p in t_positions)
print(f"Cipher at T-positions only: {t_cipher} ({len(t_cipher)} chars)")

print("\n" + "=" * 75)
print("SUMMARY")
print("=" * 75)
print("""
Key findings:
1. Tableau rows 24-27 (X,Y,Z,footer) overlay K4 positions
2. The extra L on row N is the natural NEXT char in the KA sequence
   - Row N uniquely has 31 body chars instead of 30
   - This gives row N full coverage of all 31 columns
3. The tableau-as-running-key produces garbage for all cipher variants
4. T positions in the tableau at K4 locations need investigation
   in connection with the grille T-absence
""")
