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
YAR Cardan grille reconstruction - version 9.

KEY HYPOTHESIS: The user removed ? characters from each CT line before
overlaying on the tableau. This shifts subsequent characters LEFT within
each row.

Rows without ? (1, 2, 3, 5, etc.) are unaffected.
Rows with ? (4, 8, 10, 25) have chars after ? shifted left by 1.

This explains why rows 1-3 and 5 match perfectly at offset 0, but
row 4 (which has ? at position 6) fails.

But wait - this only affects rows that CONTAIN ?. Most failing rows
(6, 7, 9, 11-24) don't contain ?. So this hypothesis alone can't
explain all failures.

ALTERNATIVE HYPOTHESIS: The user removed ? from the ENTIRE ciphertext
and then reflowed it into rows of a fixed width. This would shift
ALL subsequent positions.

Let me test: remove all ? marks, then pack the CT into rows matching
the tableau row widths.
"""

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # row 1: 31
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",        # row 2: 31
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",        # row 3: 31
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",        # row 4: 31
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",        # row 5: 31
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",        # row 6: 31
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",        # row 7: 31
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",        # row 8: 31
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",        # row 9: 31
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",        # row 10: 31
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",        # row 11: 31
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",        # row 12: 31
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",        # row 13: 31
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",        # row 14: 31
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",       # row 15: 32
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",        # row 16: 31
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",        # row 17: 31
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",        # row 18: 31
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",        # row 19: 31
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",        # row 20: 31
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",        # row 21: 31
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",        # row 22: 31
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",        # row 23: 31
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",        # row 24: 31
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",        # row 25: 31
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",        # row 26: 31
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",        # row 27: 31
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",        # row 28: 31
]

CT_LINES_WITH_Q = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",  # 1: 32
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",   # 2: 31
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",   # 3: 31
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # 4: 30 (with ?)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # 5: 31
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",  # 6: 32
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",   # 7: 31
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",   # 8: 31 (with ?)
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",  # 9: 32
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",  # 10: 31 (with ?)
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # 11: 30
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",  # 12: 31
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",  # 13: 31
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",  # 14: 31
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA", # 15: 32
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # 16: 30
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # 17: 31
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",    # 18: 30
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR", # 19: 32
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",    # 20: 30
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI", # 21: 32
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",  # 22: 31
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",# 23: 33
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",    # 24: 29
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # 25: 31 (with ?)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",  # 26: 31
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",  # 27: 31
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR", # 28: 31
]

USER_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
GRILLE_CHARS = set('YAR')  # NOT including ? this time

# Test 1: Remove ? from each line, keep same row structure
print("=" * 70)
print("TEST 1: Remove ? from each line, keep row structure, offset=0")
print("=" * 70)
ct_lines_no_q = [line.replace('?', '') for line in CT_LINES_WITH_Q]
extraction = []
for row_idx, ct_line in enumerate(ct_lines_no_q):
    tab_row = TABLEAU_ROWS[row_idx]
    for ci, ch in enumerate(ct_line):
        if ch in GRILLE_CHARS:
            if ci < len(tab_row):
                extraction.append(tab_row[ci])
            else:
                extraction.append('?')
ext = ''.join(extraction)
min_len = min(len(ext), len(USER_CT))
matches = sum(1 for i in range(min_len) if ext[i] == USER_CT[i])
print(f"Extracted ({len(ext)}): {ext}")
print(f"User CT  ({len(USER_CT)}): {USER_CT}")
print(f"Matches: {matches}/{len(USER_CT)}")

# Show match/mismatch detail for first 30 positions
print("\nDetail (first divergence):")
for i in range(min_len):
    if ext[i] != USER_CT[i]:
        print(f"  First mismatch at pos {i}: got='{ext[i]}' want='{USER_CT[i]}'")
        break

# Test 2: Remove ?, reflow entire CT at width 31
print("\n" + "=" * 70)
print("TEST 2: Remove ?, reflow at various widths")
print("=" * 70)
full_ct_no_q = ''.join(CT_LINES_WITH_Q).replace('?', '')
print(f"CT without ?: {len(full_ct_no_q)} chars")

for width in range(28, 35):
    rows = []
    for i in range(0, len(full_ct_no_q), width):
        rows.append(full_ct_no_q[i:i+width])
    extraction = []
    for row_idx, ct_line in enumerate(rows):
        if row_idx >= len(TABLEAU_ROWS):
            break
        tab_row = TABLEAU_ROWS[row_idx]
        for ci, ch in enumerate(ct_line):
            if ch in GRILLE_CHARS:
                if ci < len(tab_row):
                    extraction.append(tab_row[ci])
                else:
                    extraction.append('?')
    ext = ''.join(extraction)
    matches = sum(1 for i in range(min(len(ext), len(USER_CT)))
                  if ext[i] == USER_CT[i])
    marker = " <-- NOTABLE" if matches > 40 else ""
    print(f"  Width {width}: {len(rows)} rows, extracted {len(ext)} chars, "
          f"matches={matches}/{len(USER_CT)}{marker}")

# Test 3: Keep original row structure (with ?), but use ? positions as grille
# holes, and ADJUST the cipher position by -1 for each preceding ? in the row
print("\n" + "=" * 70)
print("TEST 3: Keep row structure, ? as hole, shift positions after ?")
print("=" * 70)
extraction3 = []
for row_idx, ct_line in enumerate(CT_LINES_WITH_Q):
    tab_row = TABLEAU_ROWS[row_idx]
    q_count = 0  # running count of ? seen so far in this row
    for ci, ch in enumerate(ct_line):
        if ch == '?':
            # This is a hole, but we shift the tableau position
            tab_ci = ci - q_count
            if 0 <= tab_ci < len(tab_row):
                extraction3.append(tab_row[tab_ci])
            else:
                extraction3.append('?')
            q_count += 1
        elif ch in GRILLE_CHARS:
            tab_ci = ci - q_count
            if 0 <= tab_ci < len(tab_row):
                extraction3.append(tab_row[tab_ci])
            else:
                extraction3.append('?')

ext3 = ''.join(extraction3)
matches3 = sum(1 for i in range(min(len(ext3), len(USER_CT)))
               if ext3[i] == USER_CT[i])
print(f"Extracted ({len(ext3)}): {ext3}")
print(f"Matches: {matches3}/{len(USER_CT)}")

# Test 4: Remove ?, reflow at row widths matching TABLEAU row widths
# Each tableau row has 31 chars (except row 15 which has 32)
print("\n" + "=" * 70)
print("TEST 4: Remove ?, reflow to match tableau row widths")
print("=" * 70)
tab_widths = [len(row) for row in TABLEAU_ROWS]
ct_stream = full_ct_no_q
pos = 0
extraction4 = []
for row_idx in range(28):
    width = tab_widths[row_idx]
    ct_row = ct_stream[pos:pos+width]
    tab_row = TABLEAU_ROWS[row_idx]
    for ci, ch in enumerate(ct_row):
        if ch in GRILLE_CHARS:
            if ci < len(tab_row):
                extraction4.append(tab_row[ci])
            else:
                extraction4.append('?')
    pos += width

ext4 = ''.join(extraction4)
matches4 = sum(1 for i in range(min(len(ext4), len(USER_CT)))
               if ext4[i] == USER_CT[i])
print(f"Extracted ({len(ext4)}): {ext4}")
print(f"Matches: {matches4}/{len(USER_CT)}")
print(f"CT chars used: {pos}/{len(ct_stream)}")

# Test 5: The user might have reflowed with the original line widths but
# WITHOUT the ? chars. So row 4 goes from 30 to 29 chars, row 8 from 31
# to 30, etc. The subsequent text spills into the next rows.
# But that changes all subsequent row contents!
# Actually, this is equivalent to: remove ? from the stream, then pack
# into rows at the ORIGINAL line widths.
print("\n" + "=" * 70)
print("TEST 5: Remove ?, but keep ORIGINAL row widths (? gaps filled from next row)")
print("=" * 70)

orig_widths = [len(line) for line in CT_LINES_WITH_Q]
ct_stream = full_ct_no_q  # 865 chars
pos = 0
extraction5 = []
for row_idx in range(28):
    width = orig_widths[row_idx]
    ct_row = ct_stream[pos:pos+width]
    tab_row = TABLEAU_ROWS[row_idx]
    for ci, ch in enumerate(ct_row):
        if ch in GRILLE_CHARS:
            if ci < len(tab_row):
                extraction5.append(tab_row[ci])
            else:
                extraction5.append('?')
    pos += width

ext5 = ''.join(extraction5)
matches5 = sum(1 for i in range(min(len(ext5), len(USER_CT)))
               if ext5[i] == USER_CT[i])
print(f"Extracted ({len(ext5)}): {ext5[:80]}...")
print(f"User CT  ({len(USER_CT)}): {USER_CT[:80]}...")
print(f"Matches: {matches5}/{len(USER_CT)}")

# Test 6: What if the user treated the ciphertext as a CONTINUOUS stream
# and the tableau as a CONTINUOUS stream, both wrapping at the same width?
# Tableau body: 26 rows x 30 chars each = 780 body chars.
# With header+footer: 28 * 31 = 868 chars (approx).
# CT: 865 chars (no ?).
# What if both are laid out as 31 chars per row?
print("\n" + "=" * 70)
print("TEST 6: Both CT and tableau as continuous streams, width 31")
print("=" * 70)
# Build continuous tableau stream
tab_stream = ''.join(TABLEAU_ROWS)
print(f"Tableau stream: {len(tab_stream)} chars")
print(f"CT stream: {len(full_ct_no_q)} chars")

# Align by position: ct[i] maps to tab[i]
extraction6 = []
for i, ch in enumerate(full_ct_no_q):
    if ch in GRILLE_CHARS and i < len(tab_stream):
        extraction6.append(tab_stream[i])

ext6 = ''.join(extraction6)
matches6 = sum(1 for i in range(min(len(ext6), len(USER_CT)))
               if ext6[i] == USER_CT[i])
print(f"Extracted ({len(ext6)}): {ext6[:60]}...")
print(f"Matches: {matches6}/{len(USER_CT)}")
