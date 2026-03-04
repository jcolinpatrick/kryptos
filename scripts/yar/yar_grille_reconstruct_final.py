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
YAR Cardan grille reconstruction - FINAL version.

KEY FINDING: There are 4 question marks (?) in the Kryptos ciphertext.
102 Y/A/R + 4 ? = 106, matching the user's CT length exactly.
The user treats ? as grille holes (same as Y, A, R).

The grille letters are: Y, A, R, and ?

Now I need to get the column alignment right between cipher and tableau.
V1 showed rows 1-4 matched perfectly with direct alignment (cipher col N =
tableau col N). So the alignment IS direct. The mismatches in v1 starting
at row 5 were because I was NOT including ? as grille holes, which threw
off the position mapping between extracted chars and user CT chars.

Let me redo the extraction with ? included as grille holes.
"""

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Tableau data from memory file (each row's first char at col 1)
TABLEAU_DATA = [
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
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # row 15 (N) - 32 chars
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

# Ciphertext lines (28 rows matching the 28 tableau rows)
CT_LINES = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",  # row 1: 32
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",   # row 2: 31
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",   # row 3: 31
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # row 4: 30  (? at col 7)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 5: 31
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",  # row 6: 32
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",   # row 7: 31
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",   # row 8: 31  (? at col 9)
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",  # row 9: 32
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",  # row 10: 31  (? at col 8)
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
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # row 25: 31  (? at col 27)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",  # row 26: 31
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",  # row 27: 31
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR", # row 28: 31
]

GRILLE_CHARS = set('YAR?')
USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

print("=" * 70)
print("FINAL RECONSTRUCTION: YAR+? Cardan Grille")
print("=" * 70)

# Direct alignment: cipher char at position i in row maps to tableau position i
# (0-indexed within each row string)
extraction = []
extraction_details = []

for row_idx in range(28):
    ct_line = CT_LINES[row_idx]
    tab_row = TABLEAU_DATA[row_idx]

    for ci, ch in enumerate(ct_line):
        if ch in GRILLE_CHARS:
            # Direct alignment: cipher position ci = tableau position ci
            if ci < len(tab_row):
                tab_ch = tab_row[ci]
            else:
                tab_ch = '?'
            extraction.append(tab_ch)
            extraction_details.append({
                'row': row_idx + 1,
                'col': ci + 1,
                'ct_char': ch,
                'tab_char': tab_ch,
            })

extracted_ct = ''.join(extraction)

print(f"\nExtracted: {extracted_ct}")
print(f"User CT:   {USER_CT}")
print(f"Length: extracted={len(extracted_ct)}, user={len(USER_CT)}")
print(f"Match: {extracted_ct == USER_CT}")

if extracted_ct != USER_CT:
    min_len = min(len(extracted_ct), len(USER_CT))
    matches = sum(1 for i in range(min_len) if extracted_ct[i] == USER_CT[i])
    print(f"Matches: {matches}/{len(USER_CT)}")

    print("\nMismatches:")
    for i in range(min_len):
        if extracted_ct[i] != USER_CT[i]:
            d = extraction_details[i]
            print(f"  Pos {i:3d}: got '{extracted_ct[i]}' want '{USER_CT[i]}' "
                  f"| row {d['row']:2d} col {d['col']:2d} CT='{d['ct_char']}' "
                  f"tab='{d['tab_char']}'")

# Now let me also try with cipher offset +1 (cipher starts at col 2 of tableau)
print("\n" + "=" * 70)
print("TRYING: Cipher offset +1 (cipher[0] = tableau[1])")
print("=" * 70)

extraction2 = []
for row_idx in range(28):
    ct_line = CT_LINES[row_idx]
    tab_row = TABLEAU_DATA[row_idx]

    for ci, ch in enumerate(ct_line):
        if ch in GRILLE_CHARS:
            ti = ci + 1
            if ti < len(tab_row):
                tab_ch = tab_row[ti]
            else:
                tab_ch = '?'
            extraction2.append(tab_ch)

ext2 = ''.join(extraction2)
matches2 = sum(1 for i in range(min(len(ext2), len(USER_CT))) if ext2[i] == USER_CT[i])
print(f"Matches: {matches2}/{len(USER_CT)}")

# Try -1
extraction3 = []
for row_idx in range(28):
    ct_line = CT_LINES[row_idx]
    tab_row = TABLEAU_DATA[row_idx]

    for ci, ch in enumerate(ct_line):
        if ch in GRILLE_CHARS:
            ti = ci - 1
            if 0 <= ti < len(tab_row):
                tab_ch = tab_row[ti]
            else:
                tab_ch = '?'
            extraction3.append(tab_ch)

ext3 = ''.join(extraction3)
matches3 = sum(1 for i in range(min(len(ext3), len(USER_CT))) if ext3[i] == USER_CT[i])
print(f"\nCipher offset -1: Matches: {matches3}/{len(USER_CT)}")

# Let me check the ? positions specifically
print("\n" + "=" * 70)
print("? POSITIONS (grille holes from question marks)")
print("=" * 70)
for d in extraction_details:
    if d['ct_char'] == '?':
        print(f"  Row {d['row']:2d} col {d['col']:2d}: tableau='{d['tab_char']}'")

# Show what the user's CT has at corresponding positions
q_pos = [i for i, d in enumerate(extraction_details) if d['ct_char'] == '?']
print(f"\n? extraction positions in output: {q_pos}")
for pos in q_pos:
    user_ch = USER_CT[pos] if pos < len(USER_CT) else '?'
    ext_ch = extracted_ct[pos] if pos < len(extracted_ct) else '?'
    d = extraction_details[pos]
    print(f"  Pos {pos}: extracted='{ext_ch}', user='{user_ch}', "
          f"row={d['row']}, col={d['col']}")
