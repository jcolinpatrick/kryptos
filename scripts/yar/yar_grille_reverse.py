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
YAR Cardan grille - reverse engineering approach.

For each user CT character, I know:
1. The row it comes from (sequential assignment based on Y/A/R/? count per row)
2. It comes from a Y, A, R, or ? position in the cipher text
3. At that position, the tableau character = user's CT character

If the tableau at offset 0 is correct (as confirmed by rows 1-3, 5, 26-28),
then for each user CT character, I can find which tableau position(s) in that
row contain that letter, and thus determine which cipher column it must be at.

If the cipher character at that column is Y, A, R, or ?, the system is consistent.
If not, either:
a) The cipher text is different from what I have, or
b) The tableau is different, or
c) The alignment is different.
"""

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # 1
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",        # 2
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",        # 3
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",        # 4
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",        # 5
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",        # 6
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",        # 7
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",        # 8
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",        # 9
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",        # 10
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",        # 11
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",        # 12
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",        # 13
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",        # 14
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # 15
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",        # 16
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",        # 17
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",        # 18
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",        # 19
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",        # 20
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",        # 21
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",        # 22
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",        # 23
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",        # 24
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",        # 25
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",        # 26
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",        # 27
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # 28
]

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

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
GRILLE_CHARS = set('YAR?')

# Step 1: For each user CT character (in order), determine which row it's in
# and which column(s) in the tableau contain that letter
user_pos = 0
print("=" * 70)
print("REVERSE ENGINEERING: Required cipher positions")
print("=" * 70)

for row_idx in range(28):
    ct_line = CT_LINES[row_idx]
    tab_row = TABLEAU_ROWS[row_idx]
    img_row = row_idx + 1

    # Count Y/A/R/? in this cipher row
    holes = [(ci, ct_line[ci]) for ci in range(len(ct_line)) if ct_line[ci] in GRILLE_CHARS]
    num_holes = len(holes)

    if num_holes == 0:
        continue

    user_chars = USER_CT[user_pos:user_pos+num_holes]

    print(f"\nRow {img_row:2d} ({num_holes} holes):")
    print(f"  CT:  {ct_line}")
    print(f"  Tab: {tab_row}")
    print(f"  User chars needed: {user_chars}")

    # For each user char, find where it appears in the tableau row
    for hi, user_ch in enumerate(user_chars):
        hole_ci, hole_ct = holes[hi]

        # Find all positions in tab_row with this letter
        tab_positions = [i for i, c in enumerate(tab_row) if c == user_ch]

        # Check if the current hole position gives the right letter
        if hole_ci < len(tab_row) and tab_row[hole_ci] == user_ch:
            status = "CORRECT"
        else:
            # What CT char is at each possible tableau position?
            possible = []
            for tp in tab_positions:
                if tp < len(ct_line):
                    ct_ch = ct_line[tp]
                    is_grille = ct_ch in GRILLE_CHARS
                    possible.append(f"col{tp}=CT'{ct_ch}'({'hole' if is_grille else 'mask'})")
                else:
                    possible.append(f"col{tp}=OOB")
            status = f"NEED tab[{','.join(str(p) for p in tab_positions)}], " + \
                     f"current hole at col{hole_ci} gives '{tab_row[hole_ci] if hole_ci < len(tab_row) else 'OOB'}'. " + \
                     f"Possible: {'; '.join(possible)}"

        if status != "CORRECT":
            print(f"  [{user_pos+hi:3d}] '{user_ch}': {status}")

    user_pos += num_holes

# Summary: for each failing row, show which tableau positions would need
# Y/A/R to give the user's expected output
print("\n" + "=" * 70)
print("SUMMARY: Which columns MUST have Y/A/R/? for user's CT to work?")
print("=" * 70)

user_pos = 0
total_correct = 0
total_wrong = 0

for row_idx in range(28):
    ct_line = CT_LINES[row_idx]
    tab_row = TABLEAU_ROWS[row_idx]
    img_row = row_idx + 1

    holes = [(ci, ct_line[ci]) for ci in range(len(ct_line)) if ct_line[ci] in GRILLE_CHARS]
    num_holes = len(holes)
    if num_holes == 0:
        continue

    user_chars = USER_CT[user_pos:user_pos+num_holes]
    needed_cols = []  # columns where a Y/A/R would need to be

    for hi, user_ch in enumerate(user_chars):
        hole_ci = holes[hi][0]
        if hole_ci < len(tab_row) and tab_row[hole_ci] == user_ch:
            needed_cols.append((hole_ci, True))  # current position works
            total_correct += 1
        else:
            # Find where user_ch is in tableau row
            tab_pos = [i for i, c in enumerate(tab_row) if c == user_ch]
            needed_cols.append((tab_pos, False))
            total_wrong += 1

    # Show results for this row
    if any(not ok for _, ok in needed_cols):
        correct = sum(1 for _, ok in needed_cols if ok)
        wrong = sum(1 for _, ok in needed_cols if not ok)
        print(f"\nRow {img_row:2d}: {correct}/{num_holes} correct, {wrong} need different columns")
        for hi, (info, ok) in enumerate(needed_cols):
            if not ok:
                user_ch = user_chars[hi]
                hole_ci = holes[hi][0]
                ct_ch = holes[hi][1]
                # info is list of possible positions
                possible_str = []
                for tp in info:
                    if tp < len(ct_line):
                        possible_str.append(f"col{tp}=CT'{ct_line[tp]}'")
                    else:
                        possible_str.append(f"col{tp}=OOB")
                print(f"  [{user_pos+hi:3d}] need '{user_ch}' at "
                      f"{'/'.join(possible_str)}, "
                      f"but hole at col{hole_ci}=CT'{ct_ch}'")

    user_pos += num_holes

print(f"\nTotal: {total_correct} correct, {total_wrong} wrong out of {total_correct+total_wrong}")
