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
Direct image reading of the Cardan grille.

Rather than trying to compute the tableau and match it, let me just
carefully read the image and list every white cell, then compare with
the user's CT.

The user's CT is 106 chars: HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD

Let me catalog every white cell reading from the image, row by row,
being very careful about column positions. I'll use the header row
to calibrate.
"""

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

# Reading the image very carefully, row by row.
# For each white cell: (row_number, approximate_column, letter)
# I'll be especially careful about columns 4-6 in row 12.

# Calibration from header (row 1):
# H at approximately col 9 -> header H = 8th letter. If A=col2, H=col9.
# But if A=col1, H=col8. Let me check by counting cell widths from the image.
# The column headers show: 1 2 3 4 5 6 7 8 9 10 11 12 13 ...
# The cells appear evenly spaced. H in row 1 is clearly in the col 9 area.
# So header: A=col2, B=col3, ..., H=col9, I=col10, J=col11, K=col12, L=col13

# Image reading (being very careful):
image_reading = [
    # Row 1: I see H, J (wait - actually looking carefully, there are TWO letters
    # between H and L. Could be J and another? Or just J?)
    # Actually in the image: H at ~col9, then at ~col10-11 area there seem to be
    # TWO characters in separate cells. One is 'J' and one is 'C' (from the user's
    # row 2 data? No, those are in row 2.)
    # Wait - row 1 and row 2 are separate. Let me be more careful.

    # Row 1 (top row):
    # I see white cells at approximately: col 9 (H), col 11 (J/something), col 13 (L), col 23 (V)
    # But wait - is that actually a 'J' at col 11? Let me check.
    # In the image, row 1 has white cells around cols 9, 10-11, 13, and 23.
    # The cell at col 10-11 shows 'J'. The 'L' is at col 13.

    # Row 2: starts with a large white cell at col 1 showing 'A'.
    # Then I see 'C' around col 10-11.
    # Wait - actually there seem to be two cells stacked: row 1 at col 10-11 shows 'J'
    # and row 2 at col 10-11 shows 'C'. Let me look again...

    # Actually, I think what I see is:
    # Row 1, col 10: J  (and row 2, col 10: nothing, black)
    # Row 1, col 11: nothing / row 2, col 11: C
    # But actually the letter in row 1 between H and L looks more like it's
    # at col 10 or 11 and shows 'J'.

    # For now, let me just list what I'm fairly confident about and compare
    # letter by letter with the user's CT.

    # From USER_CT position mapping:
    # H(0) J(1) L(2) V(3) - these 4 come from row 1
    # A(4) C(5) I(6) N(7) X(8) Z(9) - these 6 from row 2
    # H(10) - row 3
    # U(11) Y(12) O(13) - 3 from row 4 (includes the ?)
    # C(14) M(15) W(16) S(17) - 4 from row 5
    # E(18) A(19) F(20) - 3 from row 6 (includes one that extends to col 32?)
    # Y(21) - row 6 continued or row 7
    # B(22) Z(23) - row 7 continued or row 8 (includes ?)
    # A(24) C(25) - row 8 continued or row 9
    # J(26) - row 9 continued or row 10 or row 11
    # F(27) H(28) I(29) F(30) - row 11/12
    # X(31) R(32) Y(33) - row 13
    # V(34) F(35) - row 14
    # etc.

    # Actually, the simplest check: count Y/A/R/? per row and see if it matches
    # the number of characters the user assigns to each row.
]

# Let me figure out how many user CT chars come from each row by counting
# Y/A/R/? in each cipher row.

CT_LINES = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",  # 1
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",   # 2
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",   # 3
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # 4
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # 5
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",  # 6
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",   # 7
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",   # 8
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",  # 9
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",  # 10
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # 11
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",  # 12
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",  # 13
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",  # 14
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA", # 15
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # 16
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # 17
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",    # 18
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR", # 19
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",    # 20
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI", # 21
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",  # 22
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",# 23
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",    # 24
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # 25
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",  # 26
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",  # 27
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR", # 28
]

GRILLE_CHARS = set('YAR?')

print("Grille holes per row:")
cumulative = 0
for i, line in enumerate(CT_LINES):
    row = i + 1
    count = sum(1 for ch in line if ch in GRILLE_CHARS)
    positions = [(j, line[j]) for j in range(len(line)) if line[j] in GRILLE_CHARS]
    user_slice = USER_CT[cumulative:cumulative+count]
    print(f"  Row {row:2d}: {count:2d} holes | user chars: {user_slice}"
          f" | CT positions(0-idx): {[(p,c) for p,c in positions]}")
    cumulative += count

print(f"\nTotal: {cumulative}")

# Now I have a clear mapping:
# Row 1: 4 holes → user chars H,J,L,V
# Row 2: 6 holes → user chars A,C,I,N,X,Z
# Row 3: 1 hole → user chars H
# Row 4: 3 holes (including ?) → user chars U,Y,O
# Row 5: 4 holes → user chars C,M,W,S
# etc.

# For each row, the holes are at specific cipher positions.
# The user's letters at those positions tell us what the tableau has.
# Let me check if there's a consistent offset PER ROW.

print("\n" + "=" * 70)
print("PER-ROW OFFSET ANALYSIS")
print("=" * 70)

# I'll use the tableau from my memory file and check what offset makes each row work.
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # row 1
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",        # row 2
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",        # row 3
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",        # row 4
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",        # row 5
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",        # row 6
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",        # row 7
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",        # row 8
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",        # row 9
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",        # row 10
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",        # row 11
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",        # row 12
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",        # row 13
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",        # row 14
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # row 15
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",        # row 16
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",        # row 17
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",        # row 18
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",        # row 19
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",        # row 20
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",        # row 21
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",        # row 22
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",        # row 23
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",        # row 24
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",        # row 25
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",        # row 26
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",        # row 27
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # row 28
]

cumulative = 0
for row_idx, ct_line in enumerate(CT_LINES):
    tab_row = TABLEAU_ROWS[row_idx]
    holes = [(j, ct_line[j]) for j in range(len(ct_line)) if ct_line[j] in GRILLE_CHARS]
    num_holes = len(holes)
    user_chars = USER_CT[cumulative:cumulative+num_holes]

    if num_holes == 0:
        cumulative += num_holes
        continue

    # For each possible offset, check how many holes match
    best_offset = 0
    best_match = 0
    for offset in range(-33, 34):
        matches = 0
        for hi, (ci, ct_ch) in enumerate(holes):
            ti = ci + offset
            if 0 <= ti < len(tab_row) and hi < len(user_chars):
                if tab_row[ti] == user_chars[hi]:
                    matches += 1
        if matches > best_match:
            best_match = matches
            best_offset = offset

    # Check if ALL holes match at the best offset
    detail_parts = []
    for hi, (ci, ct_ch) in enumerate(holes):
        ti = ci + best_offset
        if 0 <= ti < len(tab_row) and hi < len(user_chars):
            tab_ch = tab_row[ti]
            user_ch = user_chars[hi]
            ok = "OK" if tab_ch == user_ch else f"MISS(got={tab_ch})"
            detail_parts.append(f"ci={ci}→ti={ti}:{ok}")
        else:
            detail_parts.append(f"ci={ci}→OOB")

    print(f"Row {row_idx+1:2d}: offset={best_offset:+3d}, match={best_match}/{num_holes} | "
          + ", ".join(detail_parts))

    cumulative += num_holes
