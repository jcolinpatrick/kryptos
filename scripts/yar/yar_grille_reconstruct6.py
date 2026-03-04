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
YAR Cardan grille reconstruction - version 6.

KEY ISSUE: 102 Y/A/R in ciphertext, but user CT has 106 chars.
4 extra characters need to come from somewhere.

Possible explanations:
1. The ciphertext layout I'm using is wrong (different line breaks)
2. The ? characters in K2 might be replaced with actual letters (Y, A, or R)
3. The UNDERGRUUND correction adds holes rather than removing
4. The user's ciphertext includes additional characters beyond K1-K4
5. Some rows on the sculpture include more characters than what I have

Let me check: the ? marks in K2 appear at 3 positions. If those are replaced
with letters that happen to be Y, A, or R, that could add up to 3 holes.
With one more correction, that gets us to 106.

From the ciphertext:
Row 4:  GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG  (? at position 6)
Row 8:  HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE  (? at position 8)
Row 10: FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF  (? at position 7)

If ? is replaced with:
- Row 4 col 7: if ? = Y or A or R → adds 1 hole
- Row 8 col 9: if ? = Y or A or R → adds 1 hole
- Row 10 col 8: if ? = Y or A or R → adds 1 hole

That gives 102 + 3 = 105. Still 1 short of 106.

Plus the UNDERGRUUND correction: "one R panel was changed to E"
This REMOVES one R hole, giving 104. Even worse.

Unless the correction goes the other way: "one R was changed to E" means
a non-R letter was changed TO R or FROM R. Or perhaps there's another
interpretation.

Actually wait - "corrected the known UNDERGRUUND misspelling (R→E), which
changes one grille hole." R→E could mean an R was changed to E (removes a hole)
or an E was changed to R (adds a hole). The notation "R→E" most naturally means
R becomes E. But in context of correcting UNDERGRUUND:

UNDERGRUUND → UNDERGROUND: the 8th letter changes from U to O.
But that's in the PLAINTEXT. On the cipher side, the relevant ciphertext
character would be different. The correction might involve changing a ciphertext
character. Let me check.

K2 ciphertext for the UNDERGRUUND section... K2 uses Vigenere with keyword ABSCISSA
on the KA alphabet. The misspelling is in the plaintext.

Actually, I think the user's approach is: they are treating the CIPHERTEXT as
a grid. For the UNDERGRUUND misspelling, Sanborn has acknowledged the spelling
error. If you imagine correcting the plaintext from UNDERGRUUND to UNDERGROUND,
the corresponding ciphertext character would change. Perhaps an existing R in
the CT at that position becomes something else, or something else becomes R.

But actually, the simplest interpretation: on the physical cipher panel, there
is literally an extra R somewhere that should be a different letter (or vice versa).
The sculpture has known misspellings. Perhaps changing one character in the CT
from R to E removes an R hole but... we're still short.

Let me try a different approach: what if the actual sculpture ciphertext has
slightly different letters than what's in the standard transcriptions?
Or what if the ? marks are actually replaced by specific letters?

Let me first see: what letters at the ? positions would make the extraction
match the user's CT better?

Also, let me check if there's a different transcription of the K1-K4 ciphertext
that might have 4 more Y/A/R characters.
"""

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Let me look up the commonly used Kryptos ciphertext transcription
# and compare with what I have.

# From kryptos.kernel.constants, K4 CT is:
# OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR

# My lines 25-28 should contain K4. Let me verify:
CT_LINES = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",  # row 1
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",   # row 2
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",   # row 3
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # row 4
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 5
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",  # row 6
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",   # row 7
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",   # row 8
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",  # row 9
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",  # row 10
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 11
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",  # row 12
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",  # row 13
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",  # row 14
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA", # row 15
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 16
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # row 17
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",    # row 18
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR", # row 19
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",    # row 20
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI", # row 21
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",  # row 22
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",# row 23
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",    # row 24
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # row 25
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",  # row 26
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",  # row 27
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR", # row 28
]

# Extract K4 from the lines: the last 97 chars
all_ct = ''.join(CT_LINES)
# K4 starts with OBKR... let me find it
k4_start = all_ct.find("OBKR")
print(f"K4 starts at position {k4_start} in full CT (total {len(all_ct)})")
print(f"K4 from position: {all_ct[k4_start:k4_start+97]}")

# Now let me consider: maybe the ? characters should be replaced with
# specific letters. Let me look at references for what the ? chars actually are.
# The Kryptos sculpture has literal question marks engraved as ? symbols.
# But in some transcriptions, people use different characters.
# For the Cardan grille, the user might have used a specific character for ?.

# Let me check: if we replace ? with different letters, how many Y/A/R do we get?
# There are 3 ? marks. If all 3 become Y/A/R, we get 102 + 3 = 105. Still need 1 more.

# The UNDERGRUUND correction: maybe it ADDS an R instead of removing one.
# "corrected the known UNDERGRUUND misspelling (R→E), which changes one grille hole"
# This says "changes" not "removes". Maybe an existing non-hole becomes a hole.
# If a non-Y/A/R letter is changed to Y/A/R, that adds a hole: 105 + 1 = 106. YES!

# Wait, "R→E" means R changes to E. R IS a grille letter. So changing R to E
# REMOVES a hole. That gives 105 - 1 = 104. Still wrong.

# Unless "changes one grille hole" means the position of one hole changes,
# not the total count. E.g., an R is removed and a different letter becomes
# Y/A/R at a different position.

# Or maybe my ciphertext transcription is wrong and has 4 fewer Y/A/R than the
# actual sculpture.

# Let me look at this from the other direction. The user's CT has 106 chars.
# Reading the image, I counted 105 white cells. But I might have missed one.
# The image reading gave 105 chars vs user's 106 - off by 1.
# My direct reading from the image: "HJLVACINXZHUYOCMWSEAFYBZACJHIFXRYV..."
# vs user: "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYV..."
# At position 27, I read 'H' but user has 'F', then 'H'.
# It looks like I missed one cell in the image. Let me recheck.

# Let me count positions more carefully. The user's CT at positions 25-32:
# ...A C J F H I F X R Y V F I J M X E I L L N E L J N X Z K I L K R D I N P A D M N...
# My reading: ...A C J H I F X R Y V F I J M X E I L L N E L J N X Z K I L K R D I N P A D M N...
# I'm missing the 'F' before the 'H' at position 27.

# This means I missed reading one white cell from the image. Let me figure out where.
# Between 'J' (position 26) and 'H' (position 28), there should be 'F' at position 27.
# Position 26 = 'J': from row 11, col 9 (0-indexed: ct pos 8 in row 11)
# Position 27 = 'F': should be somewhere after row 11 and before row 12
# Position 28 = 'H': from row 12, col 5

# So the 'F' at position 27 must be in row 11 or early row 12.
# Row 11 CT: FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ
# A at position 8 (col 9) → already found (gives 'J')
# No more Y/A/R in row 11.

# Row 12 CT: ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE
# R at position 5 (col 6), R at position 6 (col 7)
# Wait, position 5 is R and position 6 is also R? Let me recount:
# E-L-Z-Z-V-R-R-G-K-F-F-V-O-E-E-X-B-D-M-V-P-N-F-Q-X-E-Z-L-G-R-E
# 0 1 2 3 4 5 6 7 8 9 ...
# R at pos 5 (col 6), R at pos 6 (col 7)
# So row 12 has R at col 6 and R at col 7, plus any others.
# More R: pos 29 (col 30)

# In my image reading, I had row 12: (12, 5, 'H'), (12, 6, 'I'), (12, 31, 'F')
# If the CT has R at col 6, the tableau letter at (12, 6) would be the extracted letter.
# But wait - my CT for row 12 starts at col 1, so col 6 = CT position 5 = 'R'. Yes!
# And CT col 7 = position 6 = 'R'. Both are R holes.

# But I read from the image that (12, 5, 'H') and (12, 6, 'I').
# CT col 5 = position 4 = 'V' (not Y/A/R). So col 5 should NOT be a hole.
# CT col 6 = position 5 = 'R'. This IS a hole.
# CT col 7 = position 6 = 'R'. This IS a hole.

# So image should show holes at cols 6 and 7 in row 12, not cols 5 and 6!
# I was reading the image column numbers slightly off.

# This confirms: my image column readings are systematically off by 1 in some places.

# Let me try a completely different approach: instead of reading the image,
# compute the extraction programmatically and try different configurations
# for the ? characters and the UNDERGRUUND correction.

# First, let me find the UNDERGRUUND correction position.
# K2 plaintext contains "UNDERGRUUND". Let me find it.
# K2 section in the ciphertext includes lines 4-10 approximately.

# Actually, let me focus on finding the right number of Y/A/R.
# Current count: 102. Need: 106.
# Difference: 4.
# 3 ? marks could each become Y, A, or R → +3 max → 105.
# Need 1 more.

# Maybe one of my CT lines is wrong. Let me check against the commonly
# known Kryptos transcription.

# Patrick Kellogg's transcription (from external/):
import os
ext_path = "/home/cpatrick/kryptos/external"
if os.path.exists(ext_path):
    print(f"\nChecking external reference at {ext_path}")
    # Look for any transcription files
    for root, dirs, files in os.walk(ext_path):
        for f in files:
            if any(keyword in f.lower() for keyword in ['kryptos', 'cipher', 'text']):
                print(f"  Found: {os.path.join(root, f)}")

# Let me also check the reference directory
ref_path = "/home/cpatrick/kryptos/reference"
for root, dirs, files in os.walk(ref_path):
    for f in files:
        if any(keyword in f.lower() for keyword in ['transcript', 'cipher', 'text', 'fulltext']):
            print(f"  Found: {os.path.join(root, f)}")

# Let me try a completely different approach: use the known data from the
# patrickkellogg project or other reference to get the exact CT layout.

# Actually, let me check if the data/ct.txt file contains the full Kryptos CT
ct_data = "/home/cpatrick/kryptos/data/ct.txt"
if os.path.exists(ct_data):
    with open(ct_data) as f:
        ct_content = f.read().strip()
    print(f"\ndata/ct.txt: '{ct_content[:50]}...' (length: {len(ct_content)})")

# The key insight: let me look at the actual Kryptos sculpture photo transcriptions.
# The standard transcription by Elonka Dunin et al. uses specific line breaks.
# These line breaks correspond to the physical rows on the sculpture.

# Let me look at this from the Sanborn/sculpture perspective:
# The cipher panel has text in rows. The standard Elonka transcription:
# https://elonka.com/kryptos/

# Let me check what transcription the external reference uses.
ext_kryptos_dir = "/home/cpatrick/kryptos/external/patrickkellogg-Kryptos"
if os.path.exists(ext_kryptos_dir):
    for root, dirs, files in os.walk(ext_kryptos_dir):
        for f in files:
            if f.endswith(('.txt', '.py', '.md')):
                print(f"  External file: {os.path.join(root, f)}")

# The fundamental issue is that I need 106 Y/A/R holes, but I only have 102.
# Let me check: are there any known alternative transcriptions where Y/A/R count
# differs? Some transcriptions have 97 vs 98 chars for K4 ("try both").

# Actually, maybe the user's method works with a DIFFERENT ciphertext layout.
# The user said they overlaid K1-K4 ciphertext as a 28x33 grid on the 28x33 tableau.
# What if the ciphertext grid is NOT simply the 28 physical rows, but rather
# the text is reflowed to exactly fit a 28x33 grid (with padding)?

# 28 * 33 = 924. But total CT = 869. That's 55 short.
# 28 * 31 = 868. Close to 869!
# The CT has 869 chars (including 3 ?'s).

# What if the grid is 28 rows x 31 cols = 868, and the extra char goes somewhere?
# Or 28 rows with varying widths (29-33 chars per row)?

# Let me try a fixed-width layout: all rows have exactly 31 characters.
# 28 * 31 = 868. Need 869 chars. Could add 1 char to one row.

full_ct_no_breaks = ''.join(CT_LINES)
print(f"\nTotal CT chars: {len(full_ct_no_breaks)}")
print(f"28 * 31 = {28 * 31}")
print(f"28 * 32 = {28 * 32}")

# Try reflowing at width 31:
print("\n" + "=" * 70)
print("TRYING: Reflow CT at width 31")
print("=" * 70)
ct_str = full_ct_no_breaks
for width in [29, 30, 31, 32, 33]:
    rows = []
    for i in range(0, len(ct_str), width):
        rows.append(ct_str[i:i+width])
    num_rows = len(rows)
    yar_count = sum(1 for ch in ct_str if ch in 'YAR')
    print(f"Width {width}: {num_rows} rows, {yar_count} Y/A/R")
    # Show how many Y/A/R per row for this layout
    total_yar = 0
    for j, row in enumerate(rows):
        row_yar = sum(1 for ch in row if ch in 'YAR')
        total_yar += row_yar
    print(f"  Total Y/A/R: {total_yar}")

# The count doesn't change with reflowing - it's the same characters!
# The Y/A/R count is a property of the ciphertext itself: 102.

# So to get 106, we MUST have 4 more Y/A/R characters.
# Options:
# 1. ? marks are Y/A/R (3 marks → +3 to -0, net depends on what they become)
# 2. The CT I have is wrong (some letters should be different)
# 3. Additional characters exist (more than 869)

# Let me check option 1: if all 3 ? become Y or A or R:
# 102 + 3 = 105. Still need 1 more.

# Option 2: what if one letter in the CT should be R/A/Y but isn't?
# The UNDERGRUUND correction could go the other way: maybe a non-R
# character should be R, adding a hole.
# "corrected the known UNDERGRUUND misspelling (R→E)"
# This means one R in the CT was changed to E. This REMOVES a grille hole.
# So with correction: 102 - 1 = 101. With 3 ? as Y/A/R: 101 + 3 = 104.
# Still 2 short!

# Unless "R→E" means R was CORRECTED to become E, i.e., the ORIGINAL has
# the wrong letter and it should be E, but wait...

# Let me reconsider. Maybe (R→E) refers to the correction of the
# UNDERGRUUND misspelling IN THE CIPHERTEXT. On the physical sculpture,
# what appears might differ from published transcriptions.

# Actually, let me just try: what if the ? characters ARE treated as Y/A/R
# AND the UNDERGRUUND correction is NOT applied (or it adds rather than removes)?

# 102 + 3 ? = 105. One short.
# But wait - I should double-check my CT line counts very carefully.
# Let me compare my transcription with a known authoritative source.

print("\n" + "=" * 70)
print("CHECKING Y/A/R COUNT BY LETTER")
print("=" * 70)
for letter in 'YAR':
    count = sum(1 for ch in full_ct_no_breaks if ch == letter)
    print(f"  {letter}: {count} occurrences")
    # Show which rows
    for row_idx, line in enumerate(CT_LINES):
        lcount = sum(1 for ch in line if ch == letter)
        if lcount > 0:
            positions = [i+1 for i, ch in enumerate(line) if ch == letter]
            print(f"    Row {row_idx+1:2d}: {lcount} at cols {positions}")

# Let me also check: what if the user used a slightly different transcription?
# E.g., one where a specific letter is different?
# The "try both" for 97/98 chars of K4 might be relevant.

# Another thought: what if the last row extends beyond what I have?
# Row 28: VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR (31 chars)
# If it's actually 32 chars, with an extra letter that happens to be Y/A/R...

# Or what if some rows should be parsed differently from the full_ciphertext.md?
# Let me check the external Kryptos transcription for comparison.

try:
    with open("/home/cpatrick/kryptos/data/ct.txt") as f:
        k4_ct = f.read().strip()
    print(f"\nK4 from data/ct.txt: {k4_ct}")
    print(f"K4 length: {len(k4_ct)}")
except:
    pass

# Let me also check: maybe I need to include additional text that I'm missing.
# Like the footer row text or some other element.

# Actually, I just realized: the image has 28 rows and 33 columns.
# The TABLEAU has 28 rows (header + 26 body + footer).
# And the tableau header is "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "ABCD" = 30 chars,
# starting at col 2, going to col 31.
# Some body rows extend to col 32 or 33 (row N has an extra L).

# But what about the CIPHERTEXT side? Does it also extend to 33 columns?
# The cipher side might have ADDITIONAL characters in the margins that
# aren't in the standard transcription but ARE on the physical sculpture.

# For example, maybe some rows have characters in cols 32-33 that aren't
# in the published transcription. If those extra chars are Y/A/R, that
# would add holes.

# This is getting complex. Let me try a more practical approach:
# Since I can read the image directly, let me very carefully re-read it
# and trust the image data, even if it doesn't perfectly match my
# column computations.

# The image reading gave 105 characters. The user has 106. I'm off by 1.
# Let me see if there's a white cell I might have missed.

# From my earlier reading, the mismatch was at position 27:
# My reading:   ...ACJHIFXRYV...
# User's CT:    ...ACJFHIFXRYV...
# I'm missing an 'F' between J and H.

# This 'F' should be between row 11 (which gave 'J') and row 12 (which gave 'H').
# In row 12, the CT is: ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE
# R at col 6 (position 5), R at col 7 (position 6), R at col 30 (position 29)
# R at col 6 in row 12: tableau row K, col 6.
# Row K = "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG"
# Col 6 = 'G'... but user expects 'F'.
# Hmm, unless it's at col 5: Row K col 5 = 'F'.

# Wait, maybe the 'F' comes from row 11, col 31 or row 12, col 4 or somewhere
# else I didn't read from the image.

# Actually, you know what, I think the issue might be simpler. Let me check
# if the full Kryptos transcription I have includes ALL characters. Some
# transcriptions include Morse code characters (K0) or other elements.

# Let me try: treat ? as 'A' (since A is Y/A/R) and see if that helps.
print("\n" + "=" * 70)
print("TRYING: Replace ? with A, Y, or R")
print("=" * 70)

for replacement in ['A', 'Y', 'R']:
    modified_lines = [line.replace('?', replacement) for line in CT_LINES]
    total_yar = sum(1 for line in modified_lines for ch in line if ch in 'YAR')
    print(f"  Replace ? with '{replacement}': {total_yar} Y/A/R")

# The answer is always the same: 102 + 3 = 105 when ? becomes Y/A/R.
# But we need 106. So there must be an additional Y/A/R character somewhere.

# Let me check: maybe the "E" in the UNDERGRUUND correction adds a hole somehow.
# "Corrected UNDERGRUUND misspelling (R→E), which changes one grille hole"
# What if this means: a non-grille-letter was changed TO R (not from R)?
# I.e., the correction changes some letter TO a grille letter?

# If UNDERGRUUND has a typo where the CT letter should be R but is actually E:
# Then changing E→R (correcting it) ADDS a hole: 105 + 1 = 106. YES!

# "R→E" could be read as: "the correction is R replacing E" (i.e., E→R in the CT),
# meaning the plaintext had E where it should have had R (UNDERGRUUND vs UNDERGROUND),
# and the CT character that decrypts to give U (wrong) should have been the CT char
# that gives O (correct). This CT character change might not be E→R.

# Actually, the simplest reading: "one R panel was changed to E" in the context
# of correcting UNDERGRUUND. UNDERGRUUND has an extra U where O should be.
# In the plaintext: UNDERG-R-U-U-ND → UNDERG-R-O-U-ND (position 8 changes from U to O).
# But in the CIPHERTEXT, the corresponding character would change.
# With Vigenere ABSCISSA on KA alphabet, different key letters would produce
# different CT characters. The CT char at this position might change from one
# letter to another. If the wrong CT char happens to NOT be Y/A/R, and the
# corrected CT char IS Y/A/R (or vice versa), the grille changes.

# I think the right interpretation is:
# On the physical sculpture, there's an R at a certain position. When you
# correct the UNDERGRUUND misspelling, that R should actually be something
# else (like E). So you REMOVE that R from the grille set. But the user
# wrote "changes one grille hole" - the hole moves from R to E (E is not
# a grille letter, so it's removed). 102 - 1 = 101 with correction,
# + 3 from ? = 104. Still short.

# OK, I'm going in circles. Let me try the most productive approach:
# reflow the ciphertext into the 28-row grid in different ways and
# find which arrangement gives exactly 106 Y/A/R.

# What if row 23 has 33 chars but I've been reading it as fewer?
# Row 23: AECTDDHILCEIHSITEGOEAOSDDRYDLORIT (33 chars) - actually it IS 33!
# Let me recount Y/A/R: A-E-C-T-D-D-H-I-L-C-E-I-H-S-I-T-E-G-O-E-A-O-S-D-D-R-Y-D-L-O-R-I-T
# A at pos 0, A at pos 20, R at pos 25, Y at pos 26, R at pos 30 = 5 Y/A/R. Already counted.

# What if I'm missing a character in one of the rows?
print("\nChecking row 16 (known variable-width):")
print(f"  Row 16: '{CT_LINES[15]}' (len={len(CT_LINES[15])})")
# Row 16 (O) in tableau has 31 chars. But CT row 16 has 30 chars.
# Might there be a 31st character?

# Let me check the Elonka Dunin transcription row by row:
# Row 16 on the cipher side corresponds to K3 text. Looking at the sculpture,
# K3 lines have varying lengths.

# You know what, let me just look at the external reference for exact CT layout.
import glob
external_files = glob.glob("/home/cpatrick/kryptos/external/**/*.py", recursive=True)
for f in external_files[:10]:
    print(f"  External: {f}")
