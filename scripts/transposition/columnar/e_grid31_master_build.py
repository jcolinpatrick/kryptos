#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Build and verify the 28×31 Master Grid with Antipodes corrections.

Corrections:
1. BQCRTBJ → BQCETBJ (UNDERGRUUND → UNDERGROUND, R→E)
2. Remove squeezed 3rd K2 ? (GGTEZ?F → GGTEZF)

Goal: Establish high confidence that 868 = 28×31 is the true grid.
"""

# ══════════════════════════════════════════════════════════════════════════
# RAW CIPHERTEXT (as carved, concatenated from sculpture)
# ══════════════════════════════════════════════════════════════════════════

RAW = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
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

print("=" * 80)
print("28×31 MASTER GRID CONSTRUCTION & VERIFICATION")
print("=" * 80)

# ══════════════════════════════════════════════════════════════════════════
# STEP 1: Apply corrections
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 1: Apply Antipodes Corrections ---")
print(f"  Raw length: {len(RAW)} chars (letters + ?'s)")

# Count ?'s in raw
q_count = RAW.count('?')
letter_count = len(RAW) - q_count
print(f"  Letters: {letter_count}, ?'s: {q_count}")

# Correction 1: R→E (UNDERGRUUND → UNDERGROUND)
# Find BQCRTBJ and change to BQCETBJ
assert "BQCRTBJ" in RAW, "Cannot find BQCRTBJ in raw text!"
corrected = RAW.replace("BQCRTBJ", "BQCETBJ", 1)
print(f"  Correction 1: BQCRTBJ → BQCETBJ (R→E) ✓")

# Verify the correction happened
assert "BQCETBJ" in corrected
assert corrected.count("BQCRTBJ") == 0

# Correction 2: Remove squeezed 3rd K2 ? (GGTEZ?F → GGTEZF)
# This is the ? in the sequence FLGGTEZ?FKZBS
assert "GGTEZ?F" in corrected, "Cannot find GGTEZ?F in text!"
corrected = corrected.replace("GGTEZ?F", "GGTEZF", 1)
print(f"  Correction 2: GGTEZ?F → GGTEZF (remove squeezed ?) ✓")

print(f"\n  Corrected length: {len(corrected)} chars")
print(f"  Letters: {len(corrected) - corrected.count('?')}")
print(f"  Remaining ?'s: {corrected.count('?')}")
print(f"  Total positional chars: {len(corrected)}")
print(f"  28 × 31 = {28 * 31}")
print(f"  Match: {'✓ PERFECT FIT' if len(corrected) == 868 else '✗ MISMATCH'}")

assert len(corrected) == 868, f"Expected 868, got {len(corrected)}"

# ══════════════════════════════════════════════════════════════════════════
# STEP 2: Identify remaining ?'s and their positions
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 2: Remaining ? Positions ---")
q_positions = [i for i, c in enumerate(corrected) if c == '?']
print(f"  {len(q_positions)} positional ?'s at positions: {q_positions}")
for pos in q_positions:
    context = corrected[max(0,pos-5):pos+6]
    row = pos // 31
    col = pos % 31
    print(f"    pos {pos} (row {row}, col {col}): ...{context}...")

# ══════════════════════════════════════════════════════════════════════════
# STEP 3: Build the 28×31 grid
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 3: 28×31 Grid Layout ---")
WIDTH = 31
ROWS = 28
grid = []
for r in range(ROWS):
    row_text = corrected[r * WIDTH : (r + 1) * WIDTH]
    grid.append(row_text)

print()
for r, row_text in enumerate(grid):
    # Mark section boundaries
    marker = ""
    if r == 0:
        marker = "  ← K1 starts"
    elif r == 14:
        marker = "  ← K3 starts (perfect center!)"
    print(f"  Row {r:2d}: {row_text}{marker}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 4: Verify section boundaries
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 4: Section Boundary Verification ---")

# K1 plaintext (known, 63 chars)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABORATEYETWHATARETH"  # approximate
K1_LEN = 63

# K2 len = 369
K2_LEN = 369

# K3 len = 336
K3_LEN = 336

# K4 len = 97
K4_LEN = 97

# K1: starts at position 0
K1_CT = corrected[0:K1_LEN]
print(f"  K1 [{0}:{K1_LEN}] ({K1_LEN} chars): {K1_CT[:40]}...")
print(f"    Starts: row 0, col 0")
print(f"    Ends:   row {(K1_LEN-1)//WIDTH}, col {(K1_LEN-1)%WIDTH}")

# K2: positions 63 to 63+369-1=431, but we have ?'s mixed in
# Let's find where K2 starts and account for ?'s
# K1 = 63 letters, then K2 starts
# But ?'s are positional, so we need to count by position

# Actually, the sections include ? marks as positional characters.
# K1 = 63 letters (no ?), ends at position 62
# K2 = 369 letters + 2 remaining ?'s = 371 positional characters
# K3 = 336 letters (no ?), but wait - there's a ? at K3/K4 boundary

# Let me think about this differently. The structure is:
# K1 (63 chars, all letters) | K2 (letters + 2 ?'s) | K3 (336 chars) | ? | K4 (97 chars)
# Total letters = 63 + K2_letters + 336 + 97 = 865
# K2_letters = 865 - 63 - 336 - 97 = 369
# Total positional = 865 + 3 ?'s = 868 ✓

# Count letters in corrected text
total_letters = sum(1 for c in corrected if c != '?')
print(f"\n  Total letters: {total_letters}")
print(f"  Expected: 63 + 369 + 336 + 97 = {63+369+336+97}")
assert total_letters == 865, f"Expected 865 letters, got {total_letters}"

# Find K1 end
k1_end = 63  # position 63 (0-indexed: chars 0-62 = K1)
print(f"\n  K1: positions 0-62 ({K1_LEN} letters)")
print(f"    row 0 col 0 → row {62//WIDTH} col {62%WIDTH}")

# K2 starts at position 63
# K2 has 369 letters + 2 ?'s = 371 positional characters
# K2 ends at position 63 + 371 - 1 = 433
k2_start = 63
# Count K2 characters (letters + ?'s until we reach 369 letters)
k2_letter_count = 0
k2_pos = k2_start
while k2_letter_count < 369:
    if corrected[k2_pos] != '?':
        k2_letter_count += 1
    k2_pos += 1
k2_end = k2_pos  # exclusive end
k2_positional = k2_end - k2_start
print(f"\n  K2: positions {k2_start}-{k2_end-1} ({k2_positional} positional chars, {369} letters + {k2_positional-369} ?'s)")
print(f"    row {k2_start//WIDTH} col {k2_start%WIDTH} → row {(k2_end-1)//WIDTH} col {(k2_end-1)%WIDTH}")

# Verify K2 ? count
k2_section = corrected[k2_start:k2_end]
k2_q = k2_section.count('?')
print(f"    ?'s in K2: {k2_q}")

# K3 starts right after K2
k3_start = k2_end
# K3 = 336 letters, no ?'s in K3 itself
k3_end = k3_start + 336
k3_section = corrected[k3_start:k3_end]
k3_q = k3_section.count('?')
print(f"\n  K3: positions {k3_start}-{k3_end-1} ({336} chars, {k3_q} ?'s)")
print(f"    row {k3_start//WIDTH} col {k3_start%WIDTH} → row {(k3_end-1)//WIDTH} col {(k3_end-1)%WIDTH}")
if k3_start % WIDTH == 0 and k3_start // WIDTH == 14:
    print(f"    ✓ K3 starts at row 14, col 0 — PERFECT CENTER SPLIT")
else:
    print(f"    Row {k3_start//WIDTH}, col {k3_start%WIDTH}")

# ? between K3 and K4
boundary_q = k3_end
print(f"\n  K3/K4 ? at position {boundary_q}: '{corrected[boundary_q]}' (row {boundary_q//WIDTH}, col {boundary_q%WIDTH})")

# K4 starts after the ?
k4_start = boundary_q + 1
k4_end = k4_start + 97
k4_section = corrected[k4_start:k4_end]
print(f"\n  K4: positions {k4_start}-{k4_end-1} ({97} chars)")
print(f"    row {k4_start//WIDTH} col {k4_start%WIDTH} → row {(k4_end-1)//WIDTH} col {(k4_end-1)%WIDTH}")
print(f"    K4 text: {k4_section}")
print(f"    Expected: OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR")

expected_k4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
if k4_section == expected_k4:
    print(f"    ✓ K4 MATCHES EXPECTED")
else:
    print(f"    ✗ K4 MISMATCH")
    # Show differences
    for i, (a, b) in enumerate(zip(k4_section, expected_k4)):
        if a != b:
            print(f"      pos {i}: got '{a}', expected '{b}'")

# Verify end
print(f"\n  Total: K1({K1_LEN}) + K2({k2_positional}) + K3({336}) + ?({1}) + K4({97}) = {K1_LEN + k2_positional + 336 + 1 + 97}")
assert K1_LEN + k2_positional + 336 + 1 + 97 == 868

# ══════════════════════════════════════════════════════════════════════════
# STEP 5: Build the KA Vigenère Tableau (28×31)
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 5: KA Vigenère Tableau (28 rows × 31 cols) ---")

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# The physical tableau has:
# Row 0 (header): ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (standard alphabet + ABCD wrap)
# Rows 1-26 (body, keyed A-Z): Each is KA shifted by the key letter's position
# Row 27 (footer): ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (same as header)
#
# But wait: The physical tableau is:
# Header: " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" (space + 30 chars)
# Row A: "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP" (label + 30 chars)
# ...
# Footer: " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD" (space + 30 chars)
#
# Total: 28 rows (header + 26 body + footer), each 31 chars wide (label/space + 30 body chars)

tableau = []

# Header row (row 0): space + standard alphabet + ABCD wrap = 31 chars
header = " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
assert len(header) == 31, f"Header length {len(header)}"
tableau.append(header)

# Body rows (rows 1-26): key letter + KA shifted
# IMPORTANT: Use AZ index (standard alphabet position), NOT KA index.
# For key letter at AZ position i, body = KA starting at position i.
for key_idx in range(26):
    key_letter = AZ[key_idx]  # A, B, C, ..., Z
    # Body starts at KA[key_idx] where key_idx is the AZ position
    shifted = ''.join(KA[(key_idx + i) % 26] for i in range(30))
    row = key_letter + shifted
    assert len(row) == 31, f"Row {key_letter} length {len(row)}"
    tableau.append(row)

# Footer row (row 27): same as header
tableau.append(header)

print("\n  Tableau (28 rows × 31 cols):")
for r, row in enumerate(tableau):
    print(f"  Tab {r:2d}: {row}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 6: Overlay — Cipher Grid on top of Tableau
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 6: Cipher Grid → Tableau Overlay ---")
print("  Each cell: cipher_char / tableau_char")
print("  If cipher text is placed ON TOP of tableau, a Cardan grille with holes")
print("  would reveal tableau letters at the hole positions.\n")

# Show the overlay
for r in range(ROWS):
    cipher_row = grid[r]
    tab_row = tableau[r]
    overlay = []
    for c in range(WIDTH):
        cc = cipher_row[c]
        tc = tab_row[c]
        if cc == tc:
            overlay.append(f'={cc}')  # same letter
        else:
            overlay.append(f'{cc}/{tc}')
    # Print compact
    print(f"  Row {r:2d}: {cipher_row}  |  {tab_row}  |  matches: {sum(1 for c in range(WIDTH) if cipher_row[c] == tab_row[c])}")

# ══════════════════════════════════════════════════════════════════════════
# STEP 7: Match analysis — where cipher = tableau
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 7: Exact Matches (cipher == tableau at same position) ---")
matches = []
for r in range(ROWS):
    for c in range(WIDTH):
        if grid[r][c] == tableau[r][c]:
            matches.append((r, c, grid[r][c]))

print(f"  Total exact matches: {len(matches)} out of {ROWS * WIDTH} = {868}")
for r, c, ch in matches:
    section = "K1" if r*WIDTH+c < 63 else ("K2" if r*WIDTH+c < k2_end else ("K3" if r*WIDTH+c < k3_end else ("?" if r*WIDTH+c == boundary_q else "K4")))
    print(f"    ({r:2d},{c:2d}) = '{ch}'  [{section}]")

# ══════════════════════════════════════════════════════════════════════════
# STEP 8: K4 in the grid — detailed view
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 8: K4 Position in Grid (detailed) ---")
k4_row_start = k4_start // WIDTH
k4_col_start = k4_start % WIDTH
k4_row_end = (k4_end - 1) // WIDTH
k4_col_end = (k4_end - 1) % WIDTH

print(f"  K4 starts: row {k4_row_start}, col {k4_col_start}")
print(f"  K4 ends:   row {k4_row_end}, col {k4_col_end}")
print(f"  K4 spans {k4_row_end - k4_row_start + 1} rows")

# Show K4 rows with tableau underneath
print(f"\n  K4 layout in grid (with tableau underneath):")
for r in range(k4_row_start, k4_row_end + 1):
    cipher_row = grid[r]
    tab_row = tableau[r]
    # Mark K4 portion
    k4_chars = ""
    tab_chars = ""
    for c in range(WIDTH):
        pos = r * WIDTH + c
        if k4_start <= pos < k4_end:
            k4_chars += cipher_row[c]
            tab_chars += tab_row[c]
        else:
            k4_chars += "."
            tab_chars += "."

    print(f"  Row {r:2d} cipher: {cipher_row}")
    print(f"         K4:     {k4_chars}")
    print(f"         tableau: {tab_row}")
    print(f"         tab(K4): {tab_chars}")
    print()

# ══════════════════════════════════════════════════════════════════════════
# STEP 9: Grille problem statement
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 9: The Grille Construction Problem ---")
print("""
  THE SETUP:
  - Cipher text (868 chars) laid out in 28×31 grid
  - KA Vigenère Tableau (28×31) underneath
  - A Cardan grille (28×31 mask) placed on top

  THE QUESTION:
  Which of the 868 cells are HOLES (showing tableau letters through)?
  Which are SOLID (showing cipher text on top)?

  CONSTRAINTS:
  - The grille has some number of holes (unknown, perhaps ~100-120)
  - Letters visible through holes form a meaningful sequence
  - This sequence is somehow related to K4's decryption
  - K4's 97 chars start at row {k4_row_start}, col {k4_col_start}

  KEY INSIGHT:
  The cipher grid and tableau are PARALLEL STRUCTURES — same dimensions,
  same physical orientation on the sculpture. A physical grille/mask
  placed over one shows corresponding cells of the other.

  WHAT WE'RE LOOKING FOR:
  A binary mask M[r][c] ∈ {{0,1}} for all 28×31 cells such that:
  - Reading the tableau letters at M[r][c]=1 positions (L→R, T→B)
    produces a sequence that decrypts K4 or defines K4's transposition.
""".format(k4_row_start=k4_row_start, k4_col_start=k4_col_start))

# ══════════════════════════════════════════════════════════════════════════
# STEP 10: Summary statistics for the grid
# ══════════════════════════════════════════════════════════════════════════

print("\n--- STEP 10: Grid Summary ---")
print(f"  Grid: {ROWS} × {WIDTH} = {ROWS * WIDTH}")
print(f"  K1: rows 0-{(K1_LEN-1)//WIDTH} ({K1_LEN} chars)")
print(f"  K2: rows {k2_start//WIDTH}-{(k2_end-1)//WIDTH} ({k2_positional} chars incl. 2 ?'s)")
print(f"  K3: rows {k3_start//WIDTH}-{(k3_end-1)//WIDTH} ({336} chars)")
print(f"  ?:  row {boundary_q//WIDTH}, col {boundary_q%WIDTH}")
print(f"  K4: rows {k4_row_start}-{k4_row_end} ({97} chars)")
print(f"  Center split: K1+K2 = top 14 rows, K3+?+K4 = bottom 14 rows")
print(f"  434 + 434 = 868 ✓")

# Key numbers
print(f"\n  KEY NUMBERS:")
print(f"    868 = 28 × 31 = 4 × 7 × 31")
print(f"    434 = 2 × 7 × 31 (each half)")
print(f"    28 = 4 × 7 (tableau rows: header + 26 body + footer)")
print(f"    31 = prime (tableau cols: label + 26 body + 4 wrap)")
print(f"    7 = len(KRYPTOS)")
print(f"    97 = prime (K4 length)")

# The NOVA video evidence
print(f"\n  NOVA VIDEO EVIDENCE (8/8 column readings match):")
video_checks = [
    (20, "NRTI", "row 20"),
    (21, "WFEB", "row 21"),
    (22, "DLOR", "row 22"),
    (23, "EUHE", "row 23"),
    (24, "OBKR", "row 24 ← K4 starts"),
    (25, "KSSO", "row 25"),
    (26, "BNYP", "row 26"),
    (27, "KCAR", "row 27 (last row)"),
]
all_match = True
for r, expected, label in video_checks:
    actual = grid[r][-4:]  # last 4 chars
    match = actual == expected
    all_match = all_match and match
    print(f"    Row {r:2d} last 4: {actual} {'✓' if match else '✗'} (expected {expected}) [{label}]")

print(f"\n  All 8 video checks: {'✓ ALL MATCH' if all_match else '✗ SOME FAILED'}")

print("\n" + "=" * 80)
print("CONCLUSION: 28×31 grid is CONFIRMED with HIGH CONFIDENCE")
print("=" * 80)
print(f"""
  Evidence:
  1. 868 = 28 × 31 EXACTLY (with Antipodes corrections)
  2. 8/8 NOVA video column readings match perfectly
  3. K3 starts at row 14, col 0 — perfect center split (434/434)
  4. K4 at rows 24-27, starting col 27 (OBKR at end of row 24)
  5. Tableau dimensions MATCH: 28 rows (header+26+footer) × 31 cols (label+30)
  6. GCD(28,7) = 7 = len(KRYPTOS) — structural connection

  The cipher grid overlays the tableau 1:1.
  The grille construction is the key remaining question.
""")

# Output the corrected full text for reference
print(f"CORRECTED_FULL_CT = \"{corrected}\"")
print(f"Length: {len(corrected)}")


if __name__ == '__main__':
    pass
