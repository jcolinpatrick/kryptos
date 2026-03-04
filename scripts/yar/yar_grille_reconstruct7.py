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
YAR Cardan grille reconstruction - version 7.

NEW HYPOTHESIS: The tableau occupies columns 1-30 for the header/body,
NOT columns 2-31 as I previously assumed.

Evidence: Looking at the image more carefully:
- Row 1 header: 'H' appears to be at col 8, not col 9
- Row 1 header: 'J' appears to be at col 10, not col 11
- Row 1 header: 'L' appears to be at col 12, not col 13
- Row 1 header: 'V' appears to be at col 22, not col 23

If the header is A=col1, B=col2, ..., Z=col26, A=col27, B=col28, C=col29, D=col30:
H would be at col 8, J at col 10, L at col 12, V at col 22.

For body rows:
- Label at col 0 (or no label column, just the body content starts at col 1)
- Body: 30 chars at cols 1-30

If cipher col N maps to tableau col N, and tableau body starts at col 1:
- Row 2 (body A): col 1 = K (first char of KA), col 2 = R, ..., col 26 = Z, col 27 = K(wrap), etc.

Let me test this. It would mean the tableau in the memory file should be read
differently. The first character of each body row IS the label, but the label
is NOT at a separate column - it's part of the content.

Wait, actually that doesn't make sense either. The label IS a separate column
physically.

Let me try yet another interpretation: maybe the IMAGE column numbers are
off by 1 from what I think. What if the image col 1 actually corresponds
to tableau/cipher position 0 (0-indexed), and the column numbers in the
image are truly 1-indexed cell indices.

Let me just directly test the hypothesis: header content at cols 1-30.
"""

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Standard alphabet for header/footer
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "ABCD"  # 30 chars

# Build tableau with header starting at col 1
# Body rows: label is NOT in the grid, just body content at cols 1-30
# Actually, let me build multiple hypotheses and test each one.

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

# Hypothesis A: Tableau col 1 = label, cols 2-31 = body. Cipher col 1 maps to tableau col 1.
# This is what I've been doing.

# Hypothesis B: Tableau has NO label column in the grid.
# The 30 header chars go at cols 1-30. Body rows: 30 KA chars at cols 1-30.
# Row N has 31 chars at cols 1-31.

# Hypothesis C: Tableau col 1 = label. But cipher text is shifted by 1.
# Cipher col 1 maps to tableau col 2.

# For each hypothesis, build the tableau and extract.

def build_tableau_A():
    """Label at col 1, body at cols 2-31."""
    t = {}
    # Header (row 1): blank col 1, A-Z at cols 2-27, ABCD at cols 28-31
    for i, ch in enumerate(STD):
        t[(1, i + 2)] = ch
    # Footer (row 28): same
    for i, ch in enumerate(STD):
        t[(28, i + 2)] = ch
    # Body rows
    for ri, label in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        r = ri + 2  # image row
        t[(r, 1)] = label
        for ci in range(30):
            t[(r, ci + 2)] = KA[(ri + ci) % 26]
        if label == 'N':
            t[(r, 32)] = KA[(ri + 30) % 26]
            t[(r, 33)] = KA[(ri + 31) % 26]
    return t

def build_tableau_B():
    """No label column. Header at cols 1-30. Body at cols 1-30."""
    t = {}
    # Header (row 1): A=1, B=2, ..., Z=26, A=27, B=28, C=29, D=30
    for i, ch in enumerate(STD):
        t[(1, i + 1)] = ch
    # Footer (row 28): same
    for i, ch in enumerate(STD):
        t[(28, i + 1)] = ch
    # Body rows: no label, body starts at col 1
    for ri, label in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        r = ri + 2
        for ci in range(30):
            t[(r, ci + 1)] = KA[(ri + ci) % 26]
        if label == 'N':
            t[(r, 31)] = KA[(ri + 30) % 26]
            t[(r, 32)] = KA[(ri + 31) % 26]
    return t

def extract(tableau, cipher_lines, offset=0):
    """Extract grille chars. cipher_pos + offset = tableau position (1-indexed col)."""
    result = []
    for row_idx, ct_line in enumerate(cipher_lines):
        img_row = row_idx + 1
        for ci, ch in enumerate(ct_line):
            if ch in GRILLE_CHARS:
                tab_col = ci + 1 + offset  # ci is 0-indexed, col is 1-indexed
                tab_ch = tableau.get((img_row, tab_col), '?')
                result.append(tab_ch)
    return ''.join(result)

def count_matches(extracted, user_ct):
    return sum(1 for i in range(min(len(extracted), len(user_ct)))
               if extracted[i] == user_ct[i])

# Test all hypotheses
print("=" * 70)
print("HYPOTHESIS TESTING")
print("=" * 70)

tab_A = build_tableau_A()
tab_B = build_tableau_B()

for name, tab in [("A (label at col 1, body at col 2)", tab_A),
                   ("B (no label, body at col 1)", tab_B)]:
    print(f"\nTableau {name}:")
    for offset in range(-3, 4):
        ext = extract(tab, CT_LINES, offset)
        m = count_matches(ext, USER_CT)
        marker = " <-- BEST" if m > 50 else ""
        print(f"  Offset {offset:+d}: len={len(ext)}, matches={m}/{len(USER_CT)}{marker}")
        if m > 50:
            print(f"    Extracted: {ext[:50]}...")
            print(f"    User CT:   {USER_CT[:50]}...")

# Also try: cipher line PADDED to 33 chars each (right-padded with a non-grille char)
# Then the cipher fills the full 33-column grid.
print("\n\nTrying with cipher lines padded to 33 chars:")
padded_lines = [line.ljust(33, '.') for line in CT_LINES]
for name, tab in [("A", tab_A), ("B", tab_B)]:
    for offset in range(-3, 4):
        ext = extract(tab, padded_lines, offset)
        m = count_matches(ext, USER_CT)
        if m > 50:
            print(f"  Tableau {name} Offset {offset:+d}: matches={m}/{len(USER_CT)} <-- NOTABLE")

# Another idea: what if the cipher text is right-justified within the grid?
# E.g., row 1 has 32 chars, but the grid has 33 columns, so the text
# starts at col 2 (right-shifted by 1)?
print("\n\nTrying with RIGHT-justified cipher (different rows shift differently):")
for tab_name, tab in [("A", tab_A), ("B", tab_B)]:
    max_width = max(len(line) for line in CT_LINES)
    for grid_width in [30, 31, 32, 33]:
        result = []
        for row_idx, ct_line in enumerate(CT_LINES):
            img_row = row_idx + 1
            # Right-justify: first char at col (grid_width - len(ct_line) + 1)
            start_col = grid_width - len(ct_line) + 1
            for ci, ch in enumerate(ct_line):
                if ch in GRILLE_CHARS:
                    tab_col = start_col + ci
                    tab_ch = tab.get((img_row, tab_col), '?')
                    result.append(tab_ch)
        ext = ''.join(result)
        m = count_matches(ext, USER_CT)
        if m > 30:
            print(f"  Tableau {tab_name} GridWidth {grid_width} RIGHT-justified: "
                  f"matches={m}/{len(USER_CT)}")

# One more idea: what if every row in the cipher grid has EXACTLY 31 chars,
# and some rows have been split or joined differently than I think?
# The total CT is 869 chars. 869 / 28 = 31.04. Almost exactly 31!
# 28 * 31 = 868. We'd need to drop 1 char or have one row with 32 chars.
# What if the grid is 28 rows x 31 cols (plus possibly row 23 at 33)?

# Actually, let me try the simplest thing: reflow the entire CT at width 31,
# use tableau_B (no label, 30 body cols), and see what happens.
print("\n\nTrying with CT reflowed at various widths (tableau B, offset 0):")
full_ct = ''.join(CT_LINES)
for width in range(28, 34):
    rows = []
    for i in range(0, len(full_ct), width):
        rows.append(full_ct[i:i+width])
    result = []
    for row_idx, ct_line in enumerate(rows):
        img_row = row_idx + 1
        for ci, ch in enumerate(ct_line):
            if ch in GRILLE_CHARS:
                tab_col = ci + 1
                tab_ch = tab_B.get((img_row, tab_col), '?')
                result.append(tab_ch)
    ext = ''.join(result)
    m = count_matches(ext, USER_CT)
    if m > 20:
        print(f"  Width {width}: {len(rows)} rows, matches={m}/{len(USER_CT)}")
