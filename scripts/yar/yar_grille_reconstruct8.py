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
YAR Cardan grille reconstruction - version 8.

REVERSE ENGINEERING approach:
Since the user's CT is the ground truth, and I know the grille letters
(Y, A, R, ?) and their positions in the ciphertext, I can reverse-engineer
what tableau letter MUST be at each grille position.

For each Y/A/R/? in the ciphertext grid, the user's CT tells me what
tableau character is at that position. From this, I can determine the
actual tableau row content (or at least verify my tableau).

This will show me exactly where my tableau construction diverges from
the user's actual tableau.
"""

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

CT_LINES = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",  # row 1: 32
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",   # row 2: 31
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",   # row 3: 31
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # row 4: 30
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 5: 31
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",  # row 6: 32
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",   # row 7: 31
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",   # row 8: 31
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",  # row 9: 32
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",  # row 10: 31
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 11: 30
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",  # row 12: 31
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",  # row 13: 31
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",  # row 14: 31
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA", # row 15: 32
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 16: 30
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # row 17: 31
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",    # row 18: 30
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR", # row 19: 32
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",    # row 20: 30
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI", # row 21: 32
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",  # row 22: 31
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",# row 23: 33
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",    # row 24: 29
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # row 25: 31
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",  # row 26: 31
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",  # row 27: 31
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR", # row 28: 31
]

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
GRILLE_CHARS = set('YAR?')

# Tableau from memory file (with label in first position)
TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # row 1 (header)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",        # row 2  (A)
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",        # row 3  (B)
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",        # row 4  (C)
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",        # row 5  (D)
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",        # row 6  (E)
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",        # row 7  (F)
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",        # row 8  (G)
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",        # row 9  (H)
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",        # row 10 (I)
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",        # row 11 (J)
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",        # row 12 (K)
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",        # row 13 (L)
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",        # row 14 (M)
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # row 15 (N)
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",        # row 16 (O)
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",        # row 17 (P)
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",        # row 18 (Q)
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",        # row 19 (R)
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",        # row 20 (S)
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",        # row 21 (T)
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",        # row 22 (U)
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",        # row 23 (V)
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",        # row 24 (W)
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",        # row 25 (X)
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",        # row 26 (Y)
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",        # row 27 (Z)
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # row 28 (footer)
]

# For each grille hole, determine what the user's CT says the tableau letter should be
# Then compare with our tableau to find the pattern
user_pos = 0
print("=" * 70)
print("REVERSE ENGINEERING: Required tableau values at grille positions")
print("=" * 70)
print(f"{'Pos':>3} {'Row':>3} {'Col':>3} {'CT':>3} {'UserCh':>6} {'MyTab':>5} {'Match':>5} {'KA_idx_needed':>13}")
print("-" * 70)

for row_idx, ct_line in enumerate(CT_LINES):
    img_row = row_idx + 1
    tab_row = TABLEAU_ROWS[row_idx]

    for ci, ch in enumerate(ct_line):
        if ch in GRILLE_CHARS:
            user_ch = USER_CT[user_pos] if user_pos < len(USER_CT) else '?'
            my_tab_ch = tab_row[ci] if ci < len(tab_row) else '?'
            match = "OK" if my_tab_ch == user_ch else "MISS"

            # What KA index does the user_ch correspond to?
            if user_ch in KA:
                ka_idx = KA.index(user_ch)
                # What KA offset is needed relative to this row?
                row_letter_idx = row_idx  # for body rows (0-indexed = A-Z)
                if img_row == 1 or img_row == 28:
                    ka_offset_str = "header"
                else:
                    needed_offset = (ka_idx - (img_row - 2)) % 26
                    ka_offset_str = str(needed_offset)
            else:
                ka_offset_str = "N/A"

            if match == "MISS":
                print(f"{user_pos:3d} {img_row:3d} {ci:3d} {ch:>3} {user_ch:>6} {my_tab_ch:>5} {match:>5} {ka_offset_str:>13}")

            user_pos += 1

print(f"\nTotal positions: {user_pos}")

# Now let me check: for the MATCHING positions, what column index do they have?
# And for the MISMATCHING ones, what column offset would make them work?
print("\n" + "=" * 70)
print("OFFSET ANALYSIS FOR MISMATCHES")
print("=" * 70)

user_pos = 0
for row_idx, ct_line in enumerate(CT_LINES):
    img_row = row_idx + 1
    tab_row = TABLEAU_ROWS[row_idx]
    row_mismatches = []

    for ci, ch in enumerate(ct_line):
        if ch in GRILLE_CHARS:
            user_ch = USER_CT[user_pos] if user_pos < len(USER_CT) else '?'
            my_tab_ch = tab_row[ci] if ci < len(tab_row) else '?'

            if my_tab_ch != user_ch:
                # Find what position in this tab_row gives user_ch
                positions = [i for i, c in enumerate(tab_row) if c == user_ch]
                offsets_needed = [p - ci for p in positions]
                row_mismatches.append((ci, ch, user_ch, my_tab_ch, offsets_needed))

            user_pos += 1

    if row_mismatches:
        print(f"\nRow {img_row:2d} ({len(row_mismatches)} mismatches):")
        for ci, ch, user_ch, my_ch, offsets in row_mismatches:
            print(f"  ci={ci:2d} CT='{ch}' user='{user_ch}' mine='{my_ch}' "
                  f"needed_offsets={offsets}")
