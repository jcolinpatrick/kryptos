#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
YAR Cardan grille reconstruction - version 3.

V2 showed 51/105 mismatches between computed tableau and image.
The mismatches suggest my KA alphabet or the shifting pattern is wrong.

Let me re-examine the actual KA alphabet from the Kryptos tableau.

From memory/kryptos_tableau.md:
Row A: KRYPTOSABCDEFGHIJLMNQUVWXZ (starting at col 2)
Row B: RYPTOSABCDEFGHIJLMNQUVWXZK (shifted by 1)

But wait - the standard alphabet has 26 letters: A-Z.
The KA alphabet also has 26 letters: KRYPTOSABCDEFGHIJLMNQUVWXZ

Wait... does the KA alphabet have all 26 letters? Let me check:
K-R-Y-P-T-O-S-A-B-C-D-E-F-G-H-I-J-L-M-N-Q-U-V-W-X-Z
That's: K,R,Y,P,T,O,S,A,B,C,D,E,F,G,H,I,J,L,M,N,Q,U,V,W,X,Z = 26 letters

But standard has: A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z = 26 letters.

The KA alphabet skips... let me compare:
Standard: A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
KA:       K R Y P T O S A B C D E F G H I J L M N Q U V W X Z

In KA, after J comes L (no K). After the keyword KRYPTOS, the remaining letters
are: A,B,C,D,E,F,G,H,I,J,L,M,N,Q,U,V,W,X,Z
Wait, that's missing some letters. Let me enumerate what's NOT in "KRYPTOS":
A,B,C,D,E,F,G,H,I,J,L,M,N,Q,U,V,W,X,Z = 19 letters.
K,R,Y,P,T,O,S = 7 letters.
7 + 19 = 26. Good.

So KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

Now, the 30-column body. Each body row is the KA alphabet, cyclically shifted,
repeated to fill 30 columns. But wait - the memory file says cols 2-31 = 30 columns.
But the header row shows ABCDEFGHIJKLMNOPQRSTUVWXYZ + ABCD = 30 chars in cols 2-31.

The body rows have 30 chars in cols 2-31. Since KA has 26 chars, it wraps around
for 4 more chars.

But the CLAUDE.md says the header has:
"cols 2-27 = standard alphabet A-Z, cols 28-31 = A,B,C,D"

That means: col 2=A, col 3=B, ..., col 27=Z, col 28=A, col 29=B, col 30=C, col 31=D.

And body rows: col 2 through col 31 = 30 chars of KA cyclically shifted.

For row A (first body row), the KA starts with K:
col 2=K, col 3=R, col 4=Y, col 5=P, col 6=T, col 7=O, col 8=S, col 9=A,
col 10=B, col 11=C, col 12=D, col 13=E, col 14=F, col 15=G, col 16=H,
col 17=I, col 18=J, col 19=L, col 20=M, col 21=N, col 22=Q, col 23=U,
col 24=V, col 25=W, col 26=X, col 27=Z, col 28=K, col 29=R, col 30=Y, col 31=P

That's 30 chars: KRYPTOSABCDEFGHIJLMNQUVWXZKRYP

Let me verify against the image row 2 (body row A):
The image shows at row 2:
- col 1: 'A' (label)
- col 11: 'C'
- col 17: 'I'
- col 21: 'N'
- col 25: 'X'
- col 26: 'Z'

My computation:
- col 11: KA[9] = 'C' ✓ (offset = 11-2 = 9)
  Wait, KA[9] = C. Let me verify: K(0) R(1) Y(2) P(3) T(4) O(5) S(6) A(7) B(8) C(9). Yes, C. ✓
- col 17: KA[15] = 'I'. K(0)R(1)Y(2)P(3)T(4)O(5)S(6)A(7)B(8)C(9)D(10)E(11)F(12)G(13)H(14)I(15). Yes, I. ✓
- col 21: KA[19] = 'N'. ...J(16)L(17)M(18)N(19). Yes, N. ✓
- col 25: KA[23] = 'W'. ...Q(20)U(21)V(22)W(23). Yes, W.
  But image shows 'X' at col 25! MISMATCH.

So the issue is at col 25. My KA[23] = W, but image shows X.

KA: K R Y P T O S A B C D E F G H I J L M N Q U V W X Z
     0 1 2 3 4 5 6 7 8 9 ...                   21 22 23 24 25

So KA[24] = X, KA[25] = Z.

For col 25: offset = 25 - 2 = 23. KA[(0 + 23) % 26] = KA[23] = W.

But the image shows X at col 25. X = KA[24]. So the expected offset is 24, not 23.

That means col 25 should give offset 24, i.e., offset = col - 1, not col - 2.

Or maybe: the body starts at col 1 (with the label), and col 2 is the first
KA character with offset = row_shift. So:
col 1 = label
col 2 = KA[(row_shift + 0)]
col 3 = KA[(row_shift + 1)]
...
col N = KA[(row_shift + N - 2)]

For row A, row_shift = 0:
col 25 = KA[(0 + 25 - 2)] = KA[23] = W. Still W.

Hmm, but the image clearly shows X. Let me check col 26 as well:
Image shows Z at col 26.
My: KA[(0 + 26 - 2)] = KA[24] = X.
But image shows Z. Z = KA[25].

So image has KA[24] at col 25 and KA[25] at col 26.
My formula gives KA[23] at col 25 and KA[24] at col 26.
The image is offset by +1 from my computation.

But col 11 was correct: KA[9] = C. Let me check again...
My: KA[(0 + 11 - 2)] = KA[9] = C. Image confirms C at col 11. ✓

So KA[9] at col 11 is correct, but KA[23] at col 25 is wrong (should be KA[24]).

This means my KA alphabet is wrong! Some letter is missing or extra before position 23.

Wait - let me recount the KA alphabet very carefully:
K-R-Y-P-T-O-S-A-B-C-D-E-F-G-H-I-J-L-M-N-Q-U-V-W-X-Z

After KRYPTOS (7 letters), the remaining letters in standard order should be:
A, B, C, D, E, F, G, H, I, J, (skip K), L, M, N, (skip O, P), Q, (skip R, S),
(skip T), U, V, W, X, (skip Y), Z

Wait, that gives: A,B,C,D,E,F,G,H,I,J,L,M,N,Q,U,V,W,X,Z = 19 letters.
But wait: after KRYPTOS, the remaining letters in alphabetical order should be ALL
letters not in "KRYPTOS":
Letters in KRYPTOS: K, R, Y, P, T, O, S
Remaining: A, B, C, D, E, F, G, H, I, J, L, M, N, Q, U, V, W, X, Z = 19 letters

So KA = KRYPTOS + ABCDEFGHIJLMNQUVWXZ

Let me count: KRYPTOS = 7, ABCDEFGHIJLMNQUVWXZ = 19. Total = 26. ✓

KA indexed:
0:K 1:R 2:Y 3:P 4:T 5:O 6:S 7:A 8:B 9:C 10:D 11:E 12:F 13:G 14:H 15:I 16:J
17:L 18:M 19:N 20:Q 21:U 22:V 23:W 24:X 25:Z

Row A, col 25, offset=23: KA[23] = W. Image shows X = KA[24].

Hmm. But what if the actual KA alphabet on the sculpture is slightly different?
Let me check the memory/kryptos_tableau.md more carefully.

From the tableau file:
Row A: KRYPTOSABCDEFGHIJLMNQUVWXZKRYP

K-R-Y-P-T-O-S-A-B-C-D-E-F-G-H-I-J-L-M-N-Q-U-V-W-X-Z-K-R-Y-P
That's 30 chars for cols 2-31.

Col 25 = position 23 (0-indexed from col 2) = W. Col 26 = position 24 = X.

But the image shows X at col 25 and Z at col 26.

WAIT. What if the column numbering in the image is different from what I think?
What if the header row ABCDEFGHIJKLMNOPQRSTUVWXYZABCD starts at col 1, not col 2?

Let me reconsider: The header row in the image is at row 1. The column numbers
at the top go 1, 2, 3, ..., 33. Let me see what column the letter 'A' in the
header is at.

The header says ABCDEFGHIJKLMNOPQRSTUVWXYZABCD = 30 chars.
If A is at col 1, then: A=1, B=2, ..., Z=26, A=27, B=28, C=29, D=30.
If A is at col 2, then: A=2, B=3, ..., Z=27, A=28, B=29, C=30, D=31.

The label column is col 1 for body rows. For the header row, col 1 is blank
(the image shows no letter at row 1, col 1). So the header starts at col 2.

Row A body starts at col 2 with K. The label 'A' is at col 1.

So:
Header: col 2=A, col 3=B, ..., col 27=Z, col 28=A, col 29=B, col 30=C, col 31=D
Row A:  col 1=A(label), col 2=K, col 3=R, ..., col 27=Z, col 28=K, col 29=R, col 30=Y, col 31=P

col 25 in Row A: position from col 2 = 25-2 = 23, KA[23] = W
col 26 in Row A: position from col 2 = 26-2 = 24, KA[24] = X

But image shows X at col 25, Z at col 26. That's +1 offset.

Unless... the image column numbering doesn't match what I think. Maybe the columns
in the image are labeled differently. Let me examine what the header row tells us.

The header row should be: ABCDEFGHIJKLMNOPQRSTUVWXYZABCD at specific columns.
If I see 'H' at image col 9 (from row 1 of the image), then the header says
col 9 = H. In the standard alphabet, H is the 8th letter (A=1, B=2, ..., H=8).
If A is at col 2, then H is at col 9 (2+7=9). ✓

So H at col 9 confirms A is at col 2 in the header.

Now for the body row A: the first KA char K should be at col 2.
If K is at col 2, then:
col 25 = KA[25-2] = KA[23] = W.

But image shows X at col 25. X = KA[24].

This is a systematic +1 error. Unless...

Actually, wait. Let me look at this from the other side. Let me check what the
image shows at known positions and reverse-engineer the actual tableau.

Row 2 (body A), col 1: label 'A' ✓
Row 2 (body A), col 11: 'C'  -> C = KA[9]. If col 11 = offset 9, then offset = col - 2. ✓
Row 2 (body A), col 17: 'I'  -> I = KA[15]. Offset = 17-2 = 15. ✓
Row 2 (body A), col 21: 'N'  -> N = KA[19]. Offset = 21-2 = 19. ✓
Row 2 (body A), col 25: 'X'  -> X = KA[24]. Offset = 25-2 = 23. But KA[23] = W ≠ X.

Something is wrong with the KA alphabet itself, or my reading of the image.

Hmm, maybe I'm reading the column numbers wrong from the image. Let me check
by counting the image column numbers precisely. The numbers at the top of the
image go: 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33

Let me verify with another row. Row 1 (header):
Image shows letters at: col 9=H, col 11=J, col 13=L, col 23=V

Header should be: col 2=A, col 3=B, ..., col 8=G, col 9=H ✓, col 10=I, col 11=J ✓,
col 12=K, col 13=L ✓, ..., col 24=W, col 23=V ✓.

Wait: col 23=V means V is the 22nd letter of the header (offset 21 from A),
and V IS the 22nd letter of the alphabet. A(0), B(1), ..., V(21).
col 23 = offset 21 from col 2. So col = 2 + 21 = 23. ✓

OK so the header checks out perfectly. The issue must be with the KA alphabet
construction for body rows. Let me very carefully check if there's a discrepancy.

Actually, wait. Let me re-read the image much more carefully for row 2.
The white cell I labeled as col 25 might actually be col 26, or I might have
miscounted. Let me be more systematic.
"""

# Let me take a completely different approach: just trust the image data and verify.
# I'll manually catalog EVERY white cell position and letter from the image,
# then build the extraction from that.

# But first, let me check the ACTUAL Kryptos tableau more carefully.
# The CLAUDE.md says:
# KA alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
print("KA alphabet:")
for i, ch in enumerate(KA):
    print(f"  {i:2d}: {ch}")
print(f"  Length: {len(KA)}")

# Double-check from the tableau file: Row A = KRYPTOSABCDEFGHIJLMNQUVWXZKRYP
ROW_A = "KRYPTOSABCDEFGHIJLMNQUVWXZKRYP"
print(f"\nRow A from tableau file: {ROW_A}")
print(f"  Length: {len(ROW_A)}")

# Check: does ROW_A match KA repeated?
expected_row_a = (KA * 2)[:30]
print(f"  Expected (KA*2)[:30]: {expected_row_a}")
print(f"  Match: {ROW_A == expected_row_a}")

# Now let me check what letter is at each column for Row A:
print("\nRow A column mapping:")
for i, ch in enumerate(ROW_A):
    col = i + 2  # starts at col 2
    print(f"  col {col:2d}: {ch}", end="")
    ka_idx = i % 26
    ka_ch = KA[ka_idx]
    if ch != ka_ch:
        print(f"  MISMATCH (KA[{ka_idx}]={ka_ch})", end="")
    print()

# Now for the image, col 25 should be ROW_A[23] = W or X?
print(f"\nROW_A[23] = {ROW_A[23]}")  # col 25 = index 23
print(f"ROW_A[24] = {ROW_A[24]}")  # col 26 = index 24

# So Row A col 25 should be 'W' and col 26 should be 'X'.
# But the image showed X at what I thought was col 25 and Z at col 26.
# If actually X is at col 26 and Z at col 27, that would match!
# ROW_A[24] = X (col 26), ROW_A[25] = Z (col 27). Yes!

# So I was reading the column numbers wrong from the image!
# Let me shift my image readings by 1 column to the right and see if that fixes things.

print("\n" + "=" * 70)
print("TESTING: Shift image column readings by +1")
print("=" * 70)

image_cells_original = [
    (1, 9, 'H'), (1, 11, 'J'), (1, 13, 'L'), (1, 23, 'V'),
    (2, 1, 'A'), (2, 11, 'C'), (2, 17, 'I'), (2, 21, 'N'), (2, 25, 'X'), (2, 26, 'Z'),
    (3, 14, 'H'),
    (4, 21, 'U'), (4, 27, 'Y'), (4, 31, 'O'),
    (5, 7, 'C'), (5, 17, 'M'), (5, 22, 'W'), (5, 30, 'S'),
    (6, 9, 'E'), (6, 30, 'A'),
    (7, 1, 'F'),
    (8, 24, 'Y'), (8, 31, 'B'),
    (9, 20, 'Z'), (9, 28, 'A'),
    (10, 29, 'C'),
    (11, 9, 'J'),
    (12, 5, 'H'), (12, 6, 'I'), (12, 31, 'F'),
    (13, 15, 'X'), (13, 19, 'R'), (13, 20, 'Y'),
    (14, 12, 'V'), (14, 27, 'F'),
    (15, 3, 'I'), (15, 4, 'J'), (15, 7, 'M'), (15, 13, 'X'), (15, 24, 'E'),
    (15, 30, 'I'), (15, 33, 'L'),
    (16, 5, 'L'), (16, 7, 'N'), (16, 24, 'E'), (16, 31, 'L'),
    (17, 1, 'J'), (17, 5, 'N'), (17, 12, 'X'), (17, 13, 'Z'), (17, 14, 'K'),
    (17, 28, 'I'), (17, 30, 'L'),
    (18, 12, 'K'), (18, 13, 'R'), (18, 22, 'D'), (18, 27, 'I'), (18, 30, 'N'),
    (19, 14, 'P'), (19, 18, 'A'), (19, 21, 'D'), (19, 28, 'M'), (19, 29, 'N'),
    (20, 5, 'V'), (20, 8, 'Z'), (20, 17, 'A'), (20, 18, 'C'), (20, 21, 'E'),
    (20, 24, 'I'), (20, 27, 'M'), (20, 31, 'U'),
    (21, 5, 'W'), (21, 14, 'A'), (21, 20, 'F'), (21, 21, 'G'), (21, 24, 'I'),
    (21, 27, 'M'), (21, 31, 'U'),
    (22, 8, 'K'), (22, 9, 'R'), (22, 19, 'G'), (22, 22, 'I'), (22, 25, 'L'),
    (22, 26, 'N'), (22, 27, 'Q'),
    (23, 1, 'V'), (23, 19, 'H'), (23, 31, 'X'),
    (24, 1, 'W'), (24, 8, 'Y'), (24, 12, 'A'), (24, 13, 'B'), (24, 30, 'X'),
    (24, 31, 'Z'),
    (25, 4, 'K'), (25, 17, 'I'), (25, 30, 'K'),
    (26, 17, 'J'), (26, 25, 'U'),
    (27, 13, 'F'), (27, 22, 'Q'), (27, 30, 'R'),
    (28, 24, 'X'), (28, 30, 'C'), (28, 31, 'D'),
]

# Build tableau
tableau = {}
header = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
for i, ch in enumerate(header):
    tableau[(1, i + 2)] = ch
for i, ch in enumerate(header):
    tableau[(28, i + 2)] = ch

ROW_LABELS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
for row_idx, label in enumerate(ROW_LABELS):
    img_row = row_idx + 2
    tableau[(img_row, 1)] = label
    for col_offset in range(30):
        ka_idx = (row_idx + col_offset) % 26
        tableau[(img_row, col_offset + 2)] = KA[ka_idx]
    if label == 'N':
        for extra in range(30, 32):
            ka_idx = (row_idx + extra) % 26
            tableau[(img_row, extra + 2)] = KA[ka_idx]

# Check with +1 shift
mismatches_shifted = 0
for row, col, img_letter in image_cells_original:
    shifted_col = col + 1
    tab_letter = tableau.get((row, shifted_col), '?')
    if tab_letter != img_letter:
        mismatches_shifted += 1

print(f"With +1 column shift: {mismatches_shifted} mismatches")

# Check with -1 shift
mismatches_neg = 0
for row, col, img_letter in image_cells_original:
    shifted_col = col - 1
    tab_letter = tableau.get((row, shifted_col), '?')
    if tab_letter != img_letter:
        mismatches_neg += 1

print(f"With -1 column shift: {mismatches_neg} mismatches")

# Check without shift (original)
mismatches_orig = 0
for row, col, img_letter in image_cells_original:
    tab_letter = tableau.get((row, col), '?')
    if tab_letter != img_letter:
        mismatches_orig += 1

print(f"With no shift: {mismatches_orig} mismatches")

# Let me also check if the issue is per-row. Some rows might have different offsets.
print("\nPer-row mismatch analysis (no shift):")
from collections import defaultdict
row_offsets = defaultdict(list)
for row, col, img_letter in image_cells_original:
    # Find what offset in KA this image letter corresponds to
    if img_letter in KA:
        img_ka_idx = KA.index(img_letter)
    else:
        img_ka_idx = -1

    if row == 1 or row == 28:
        # Header/footer - standard alphabet
        std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "ABCD"
        if img_letter in std:
            expected_col = std.index(img_letter) + 2
            delta = col - expected_col
        else:
            delta = None
    else:
        # Body row
        row_idx = row - 2  # 0-based
        if col == 1:
            # Label column
            expected_letter = ROW_LABELS[row_idx]
            delta = 0 if img_letter == expected_letter else None
        else:
            # Body column: expected KA index = (row_idx + col - 2) % 26
            expected_ka_idx = (row_idx + col - 2) % 26
            tab_letter = KA[expected_ka_idx]
            if tab_letter == img_letter:
                delta = 0
            else:
                # What col would give the correct ka_idx?
                # We need: (row_idx + col_correct - 2) % 26 = img_ka_idx
                # col_correct = (img_ka_idx - row_idx) % 26 + 2
                if img_ka_idx >= 0:
                    needed_offset = (img_ka_idx - row_idx) % 26
                    expected_col_for_this_letter = needed_offset + 2
                    delta = col - expected_col_for_this_letter
                else:
                    delta = None

    row_offsets[row].append((col, img_letter, delta))

for row in sorted(row_offsets.keys()):
    items = row_offsets[row]
    deltas = [d for _, _, d in items if d is not None]
    details = ", ".join(f"c{c}={l}(d={d})" for c, l, d in items)
    print(f"  Row {row:2d}: {details}")
