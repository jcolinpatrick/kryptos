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
Reconstruct the YAR Cardan grille extraction from the Kryptos sculpture.

Method:
1. Build the KA Vigenere tableau (28 rows x 33 cols)
2. Overlay the Kryptos ciphertext (K1-K4, 865 chars) on the same grid
3. Where the ciphertext letter is Y, A, or R, read the tableau letter at that position
4. The UNDERGRUUND correction changes one R->E in K3, removing an R hole and adding an E hole
"""

# =====================================================================
# STEP 1: Build the KA Vigenere Tableau
# =====================================================================

# KA alphabet (keyword KRYPTOS followed by remaining letters in order)
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
assert len(KA) == 26

# The tableau as shown on the sculpture:
# Row 0 = header:  space + ABCDEFGHIJKLMNOPQRSTUVWXYZ + ABCD  (col 0 blank, cols 1-26 = A-Z, cols 27-30 = ABCD)
# Rows 1-26 = body: col 0 = row label (A-Z), cols 1-30 = KA alphabet shifted, wrapping cyclically
# Row 27 = footer: same as header
#
# But the IMAGE uses 1-indexed columns (1-33) and rows (1-28):
#   Image row 1 = header
#   Image rows 2-27 = body (labeled A through Z)
#   Image row 28 = footer
#
# The header has: cols 2-27 = A-Z standard (26 letters), cols 28-31 = A,B,C,D
# Body rows: col 1 = label, cols 2-31 = 30 chars of KA cyclically shifted
# Row N (image row 15): has an extra L at col 33 (31 body chars instead of 30)
# Row V (image row 23) appears to extend to col 33 as well

# Build tableau as a dict: (image_row, image_col) -> letter
tableau = {}

# Header row (image row 1, cols 2-27 = A-Z, cols 28-31 = ABCD)
header = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "ABCD"  # 30 chars at cols 2-31
for i, ch in enumerate(header):
    tableau[(1, i + 2)] = ch

# Footer row (image row 28, same as header)
for i, ch in enumerate(header):
    tableau[(28, i + 2)] = ch

# Body rows (image rows 2-27, labeled A-Z)
# Row label at col 1, body at cols 2-31 (30 chars)
# Row A (image row 2): starts with KA[0] = K
# Row B (image row 3): starts with KA[1] = R
# etc.
ROW_LABELS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
for row_idx, label in enumerate(ROW_LABELS):
    img_row = row_idx + 2  # image row 2 = A, row 3 = B, ...
    tableau[(img_row, 1)] = label  # label column

    # The body: 30 chars of KA shifted cyclically
    # Row A starts at KA offset 0, Row B at offset 1, etc.
    for col_offset in range(30):
        ka_idx = (row_idx + col_offset) % 26
        tableau[(img_row, col_offset + 2)] = KA[ka_idx]

    # Special case: Row N (image row 15) has an extra L at col 33
    # Row N is row_idx=13, img_row=15
    # After 30 body chars (cols 2-31), the next KA char would be at offset 30
    if label == 'N':
        ka_idx = (13 + 30) % 26
        tableau[(15, 32)] = KA[ka_idx]
        ka_idx = (13 + 31) % 26
        tableau[(15, 33)] = KA[ka_idx]

# =====================================================================
# STEP 2: Build the ciphertext grid
# =====================================================================

# Full Kryptos ciphertext (K1-K4) as continuous text
# From memory/full_ciphertext.md, removing line breaks and ? marks
FULL_CT_LINES = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA",
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
]

# The ciphertext is laid out on the sculpture as rows of text.
# The sculpture's cipher side has the same physical dimensions as the tableau side.
# Looking at the image: 28 rows, and the body text occupies rows 1-28 mapped to the
# ciphertext lines. The '?' characters are literal question marks on the sculpture.
#
# The key question: how does the ciphertext map to the 28x33 grid?
#
# The tableau has:
#   Row 1 (header): cols 2-31 = 30 chars
#   Rows 2-27 (body): col 1 = label, cols 2-31 = 30 body chars
#   Row 28 (footer): cols 2-31 = 30 chars
#
# The cipher side does NOT have the label column or header/footer rows.
# Instead, the ciphertext occupies the positions corresponding to the tableau body.
#
# Wait - the image shows 28 rows. Looking at the ciphertext lines, there are 28 lines.
# Each line has varying length (29-33 chars). The image grid is 28 rows x ~33 cols.
#
# The cipher text lines map directly to image rows 1-28, and each character maps
# to columns starting from col 1. Let me verify by counting chars per line:

print("Ciphertext line lengths:")
total = 0
for i, line in enumerate(FULL_CT_LINES):
    clean = line.replace('?', '?')  # keep ? as-is for now
    print(f"  Line {i+1:2d} (img row {i+1:2d}): {len(clean):2d} chars  {clean}")
    total += len(clean)
print(f"  Total chars: {total}")

# Now let me check: does the ciphertext occupy cols 1-N where N = line length?
# Or does it start at col 2 (like the tableau body)?
#
# The image grid has the tableau underneath. The ciphertext grid must align with
# the tableau grid for the Cardan grille to work. So:
# - Cipher row i maps to image row i
# - Each cipher character at position j in the line maps to image column j+1 (1-indexed)
#
# But wait - the tableau body rows have a LABEL in col 1 and body chars in cols 2-31.
# The cipher side does NOT have labels. So cipher chars likely start at col 1.
#
# Let me verify against the image. The image shows white cells where Y/A/R appear
# in the ciphertext, revealing the tableau character underneath.
#
# Let me check row 2 (image row 2). The ciphertext line 2 is:
# YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD (32 chars)
# Y is at position 0 (col 1), positions 10 (col 11), 20 (col 21), etc.
# A is at... no A in this line.
# R is at position 27 (col 28).
#
# The image shows white cells in row 2 at: col 1 (A), col 11 (C), col 17 (I),
# col 21 (N), col 25 (X), col 26 (Z)
#
# Line 2: Y Q T Q U X Q B Q V Y U V L L T R E V J Y Q T M K Y R D M F D
#          1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
# Y at col 1: tableau row 2 (A), col 1 = label 'A'. Image shows 'A'. MATCH!
# Y at col 11: tableau row 2 (A), col 11. Tableau body col 11 means offset 9 from KA.
#   Row A (row_idx=0), offset=9: KA[(0+9)%26] = KA[9] = 'C'. Image shows 'C'. MATCH!
# Y at col 21: Row A, offset 19: KA[19] = 'N'. Image shows 'N'. MATCH!
# R at col 17: Row A, offset 15: KA[15] = 'I'. Image shows 'I'. MATCH!
# Y at col 26: Row A, offset 24: KA[24] = 'X'. Wait, image shows X at col 25 and Z at col 26.
# Let me recount: K at col 25 means offset 23: KA[23] = 'W'. That doesn't work.
#
# Actually wait, let me recount the ciphertext line 2 positions more carefully.
# YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD
# pos: 0123456789...
# Y=0, Q=1, T=2, Q=3, U=4, X=5, Q=6, B=7, Q=8, V=9, Y=10, U=11, V=12, L=13, L=14,
# T=15, R=16, E=17, V=18, J=19, Y=20, Q=21, T=22, M=23, K=24, Y=25, R=26, D=27, M=28, F=29, D=30
# That's 31 chars (indices 0-30), mapping to cols 1-31.
# Wait, the line has 32 chars. Let me recount:
line2 = "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
print(f"\nLine 2 length: {len(line2)}")
print(f"Line 2: {line2}")
for i, ch in enumerate(line2):
    col = i + 1
    if ch in 'YAR':
        print(f"  '{ch}' at col {col}")

# Hmm, that line is only 31 chars. But the file shows 32.
# Let me recheck.

# Actually the issue might be in how I'm reading the ciphertext file. Let me
# be very precise about the line lengths.
print("\nPrecise line analysis:")
for i, line in enumerate(FULL_CT_LINES):
    print(f"  Row {i+1:2d}: len={len(line):2d} | {line}")

print()
# Now let me map each Y, A, R position and look up the tableau character.
# The cipher text at (row, col) where row=line_number (1-indexed), col=position_in_line+1 (1-indexed)
# maps to tableau at the SAME (row, col).

# For the ? chars: they are physical question marks, not alphabetic. They are NOT Y, A, or R.
# So they just mask whatever is underneath.

# UNDERGRUUND correction: In K3, the word UNDERGRUUND appears. The correct spelling
# is UNDERGROUND. Looking at K3 plaintext, the misspelling is in the ciphertext mapping.
# Actually wait - the ciphertext itself doesn't spell UNDERGRUUND; the PLAINTEXT does.
# The ciphertext characters that decrypt to UNDERGRUUND are on the cipher panel.
# The correction mentioned is about the CIPHERTEXT side: one R in the CT is changed to E.
# This would remove one R hole and add one E hole (E is not Y/A/R, so it adds a mask).
#
# Actually, re-reading the task: "corrected the known UNDERGRUUND misspelling (R→E),
# which changes one grille hole."
#
# This likely means: in the ciphertext, at the position where UNDERGRUUND's misspelled
# letter maps, there's an R that should be an E if the word were spelled correctly.
# Actually, more likely: somewhere in the K3 CIPHERTEXT, an R appears at a position
# where the decrypted text gives the wrong U instead of O in UNDERGROUND. If you
# correct the plaintext, the ciphertext letter at that position would change.
#
# But actually the simplest interpretation: the full Kryptos ciphertext has the text
# "UNDERGRUUND" embedded in K3 plaintext. Looking at the actual K3 plaintext:
# "SLOWLY DESPARATELY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER
# PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE
# UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE
# AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT
# PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN YOU SEE ANYTHING Q"
#
# UNDERGRUUND is not in K3. Let me check K2. K2 decrypts to text that includes
# "IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE ? THEY USED THE EARTHS MAGNETIC FIELD X
# THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X"
#
# So UNDERGRUUND is in K2's plaintext. The ciphertext for this section is somewhere
# in the K2 area. But for the Cardan grille, we're looking at the CIPHERTEXT characters.
# One of the CT characters that encrypts to give U (instead of O for UNDERGROUND) is
# presumably an R (or involves an R). If corrected, that R becomes something else,
# changing it from a grille hole to a non-hole.
#
# For now, let me first try WITHOUT the correction and see how close we get.
# Then we can apply the correction.

print("=" * 70)
print("RECONSTRUCTION: YAR Cardan Grille Extraction")
print("=" * 70)

# Build the ciphertext grid: (row, col) -> letter
ct_grid = {}
for row_idx, line in enumerate(FULL_CT_LINES):
    img_row = row_idx + 1  # 1-indexed
    for col_idx, ch in enumerate(line):
        img_col = col_idx + 1  # 1-indexed
        ct_grid[(img_row, img_col)] = ch

# Extract: for each position where CT is Y, A, or R, read the tableau
extraction = []
extraction_details = []
grille_letters = set(['Y', 'A', 'R'])

for row_idx, line in enumerate(FULL_CT_LINES):
    img_row = row_idx + 1
    for col_idx, ch in enumerate(line):
        img_col = col_idx + 1
        if ch in grille_letters:
            tab_ch = tableau.get((img_row, img_col), '?')
            extraction.append(tab_ch)
            extraction_details.append((img_row, img_col, ch, tab_ch))

extracted_ct = ''.join(extraction)
print(f"\nExtracted CT ({len(extracted_ct)} chars):")
print(f"  {extracted_ct}")

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
print(f"\nUser's CT ({len(USER_CT)} chars):")
print(f"  {USER_CT}")

print(f"\nMatch: {extracted_ct == USER_CT}")

# Show detailed comparison
if extracted_ct != USER_CT:
    print(f"\nLength difference: extracted={len(extracted_ct)}, user={len(USER_CT)}")
    min_len = min(len(extracted_ct), len(USER_CT))
    mismatches = []
    for i in range(min_len):
        if extracted_ct[i] != USER_CT[i]:
            mismatches.append((i, extracted_ct[i], USER_CT[i]))
    if mismatches:
        print(f"\nMismatches ({len(mismatches)}):")
        for pos, got, expected in mismatches:
            row, col, ct_ch, tab_ch = extraction_details[pos]
            print(f"  Pos {pos}: got '{got}' expected '{expected}' "
                  f"(row {row}, col {col}, CT='{ct_ch}', tableau='{tab_ch}')")

    # Show extra/missing chars
    if len(extracted_ct) > len(USER_CT):
        print(f"\nExtra chars in extraction: '{extracted_ct[min_len:]}'")
        for i in range(min_len, len(extracted_ct)):
            row, col, ct_ch, tab_ch = extraction_details[i]
            print(f"  Pos {i}: '{tab_ch}' (row {row}, col {col}, CT='{ct_ch}')")
    elif len(USER_CT) > len(extracted_ct):
        print(f"\nMissing chars: user has '{USER_CT[min_len:]}'")

print("\n" + "=" * 70)
print("DETAILED EXTRACTION (all Y/A/R positions)")
print("=" * 70)
for i, (row, col, ct_ch, tab_ch) in enumerate(extraction_details):
    user_ch = USER_CT[i] if i < len(USER_CT) else '?'
    match = "OK" if tab_ch == user_ch else "MISMATCH"
    print(f"  {i:3d}: row={row:2d} col={col:2d} CT='{ct_ch}' -> tableau='{tab_ch}' "
          f"(user='{user_ch}') {match}")
