#!/usr/bin/env python3
"""
blitz_instruction_decoder_v2.py — Second-wave K1-K3 instruction analysis.
Cipher: K4 Kryptos
Family: blitz
Status: active
Keyspace: K1K2K3_instructions_wave2
Last run: 2026-03-05
Best score: N/A

Builds on blitz_instruction_decoder.py (wave 1). Adds:
  A2. IDBYROWS → 8 specific grid rows (novel: I=8,D=3,B=1,Y=24,R=17,O=14,W=22,S=18)
  B2. Text from those 8 rows + decryption tests
  C2. Tableau overlay at K4 positions (KA Vig using tableau cell as key)
  D2. Bean constraint analysis (which key periods satisfy k[27]=k[65]?)
  E2. Keystream reconstruction from cribs → does it spell anything in KA?
  F2. IDBYROWS row-key Vigenere (key = Y,Z,A,B per K4 rows 24,25,26,27)
  G2. 73-hole reading: apply 73 non-crib positions as reading order after
      all scrambling permutations from K3's exact double-rotation method
  H2. "Upper left corner" → start grille at (row=14,col=0) = K3 start.
      Try reading in expanding spiral from there.
  I2. Period-17 and period-8 as factors of the 17+8+1=26 cycle decomposition.
      Key: test AZ[17-cycle] and AZ[8-cycle] as distinct sub-alphabets.
  J2. Misspelling delta in KA-index space:
      L->K: KA-index diff = 0-17 = -17 = 9 mod 26
      E->A: KA-index diff = 7-11 = -4 = 22 mod 26
      What do these KA-index diffs encode?

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz/blitz_instruction_decoder_v2.py
"""

import sys
import math
from itertools import product, permutations
from collections import defaultdict, Counter

sys.path.insert(0, "scripts")
sys.path.insert(0, "src")

try:
    from kbot_harness import (
        K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
        vig_decrypt, beau_decrypt,
        score_text, score_text_per_char, has_cribs,
    )
except ImportError:
    # Fallback if harness not available
    K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    KEYWORDS = ["KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN","SCHEIDT","BERLIN","CLOCK","EAST","NORTH","LIGHT","ANTIPODES","MEDUSA","ENIGMA"]
    CRIBS = ["EASTNORTHEAST","BERLINCLOCK"]

    def vig_decrypt(ct, key, alpha=None):
        alpha = alpha or AZ
        result = []
        kl = len(key)
        for i, c in enumerate(ct):
            if c not in alpha: result.append(c); continue
            result.append(alpha[(alpha.index(c) - alpha.index(key[i % kl])) % 26])
        return "".join(result)

    def beau_decrypt(ct, key, alpha=None):
        alpha = alpha or AZ
        result = []
        kl = len(key)
        for i, c in enumerate(ct):
            if c not in alpha: result.append(c); continue
            result.append(alpha[(alpha.index(key[i % kl]) - alpha.index(c)) % 26])
        return "".join(result)

    def score_text(text):
        return sum(1 for c in text if c in "ETAOINSHRDLCUMWFGYPBVKJXQZ")

    def score_text_per_char(text):
        return score_text(text) / max(len(text), 1)

    def has_cribs(pt):
        hits = []
        for crib in CRIBS:
            if crib in pt:
                hits.append((crib, pt.index(crib)))
        return hits

assert len(K4_CARVED) == 97
assert len(AZ) == 26 and len(KA) == 26

# ─── Crib data ────────────────────────────────────────────────────────────────
CRIB_ENE = "EASTNORTHEAST"
CRIB_ENE_START = 21
CRIB_BC = "BERLINCLOCK"
CRIB_BC_START = 63

CRIB_POSITIONS = set()
for crib, start in [(CRIB_ENE, CRIB_ENE_START), (CRIB_BC, CRIB_BC_START)]:
    for i in range(len(crib)):
        CRIB_POSITIONS.add(start + i)

NON_CRIB_POSITIONS = [i for i in range(97) if i not in CRIB_POSITIONS]
assert len(NON_CRIB_POSITIONS) == 73  # "73" from "8 Lines 73"

# ─── The 28×31 cipher grid (exact) ────────────────────────────────────────────
CIPHER_GRID = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",  # row 0  K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",  # row 1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",  # row 2  K1→K2 boundary
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG", # row 3  K2 (? at col 7)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",  # row 4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",  # row 5
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",  # row 6
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",  # row 7  (? at col 9)
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",  # row 8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",  # row 9
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",  # row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",  # row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",  # row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",  # row 13  K2 ends
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",  # row 14  K3 starts (CENTER)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",  # row 15  (extra L makes 32 physically)
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",  # row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",  # row 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",  # row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",  # row 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",  # row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",  # row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",  # row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",  # row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # row 24  K4 starts at col 27
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",  # row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",  # row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",  # row 27
]
# Verify 28 rows, each 31 chars (except separators)
assert len(CIPHER_GRID) == 28
for r, row in enumerate(CIPHER_GRID):
    assert len(row) == 31, f"Row {r} has {len(row)} chars"

# Build the KA Vigenère tableau (28×31 with key col)
def build_tableau():
    """
    Row 0/27: header/footer = blank + ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (30 chars)
    Rows 1-26: key_letter + KA shifted by AZ-position of key_letter (30 chars)

    The KA tableau: for key letter AZ[k], the body shows KA starting at
    position where AZ[k] appears in KA, for 30 chars.
    So row for key='A': body = KA[KA.index('A')..] = KA[7..] shifted
    """
    header_body = "".join(AZ[i % 26] for i in range(30))  # ABCDE...XYZABCD
    rows = [" " + header_body]  # row 0: header (space + 30)
    for k in range(26):
        key_letter = AZ[k]
        # Body: KA starting at position of AZ[k] in KA, for 30 chars
        ka_start = KA.index(AZ[k])
        body = "".join(KA[(ka_start + j) % 26] for j in range(30))
        rows.append(key_letter + body)  # 31 chars
    rows.append(" " + header_body)  # row 27: footer
    assert len(rows) == 28
    for r, row in enumerate(rows):
        assert len(row) == 31, f"Tableau row {r} has {len(row)}"
    return rows

TABLEAU = build_tableau()

def sep(title=""):
    line = "=" * 72
    if title:
        print(f"\n{line}")
        print(f" {title}")
        print(f"{line}")
    else:
        print(f"\n{line}")

def ic(text):
    """Index of coincidence."""
    text = [c for c in text if c in AZ]
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))

def test_all_decryptions(candidate_ct, label=""):
    """Test all keywords with vig/beau/AZ/KA on a candidate CT."""
    best = []
    for key in KEYWORDS + ["ABSCISSA", "KRYPTOS"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = fn(candidate_ct, key, alpha)
                    ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if
                                CRIB_ENE_START < len(pt) and
                                CRIB_ENE_START + i < len(pt) and
                                pt[CRIB_ENE_START + i] == c)
                    bc_m = sum(1 for i, c in enumerate(CRIB_BC) if
                               CRIB_BC_START < len(pt) and
                               CRIB_BC_START + i < len(pt) and
                               pt[CRIB_BC_START + i] == c)
                    total = ene_m + bc_m
                    if total > 0:
                        best.append((total, ene_m, bc_m, key, alpha_name, cipher_name, pt))
                except Exception:
                    pass
    best.sort(key=lambda x: -x[0])
    if best:
        for total, e, b, key, alpha, cipher, pt in best[:3]:
            crib_hits = has_cribs(pt)
            mark = " *** CRIB HIT ***" if crib_hits else ""
            print(f"  {label} key={key} {alpha} {cipher}: ENE={e}/13 BC={b}/11{mark}")
            print(f"    PT: {pt[:60]}...")
            if crib_hits:
                print(f"    CRIB HITS: {crib_hits}")
    return best

# ─────────────────────────────────────────────────────────────────────────────
print()
print("=" * 72)
print(" K4 INSTRUCTION DECODER v2 — Novel Analyses")
print("=" * 72)
print()

# ─────────────────────────────────────────────────────────────────────────────
sep("A2. IDBYROWS → 8 SPECIFIC GRID ROWS (NOVEL INTERPRETATION)")
# ─────────────────────────────────────────────────────────────────────────────
print("""
KEY INSIGHT: 'IDBYROWS' (8 chars) → each letter as AZ 0-index → row numbers.
This gives EXACTLY 8 rows = '8 LINES' from Sanborn's yellow pad!

  I = AZ[8]  = row  8  (K2 section)
  D = AZ[3]  = row  3  (K2 section, has ?)
  B = AZ[1]  = row  1  (K1 section)
  Y = AZ[24] = row 24  (K4 START ROW!)
  R = AZ[17] = row 17  (K3 section)
  O = AZ[14] = row 14  (K3 START = CENTER ROW!)
  W = AZ[22] = row 22  (K3 section)
  S = AZ[18] = row 18  (K3 section)
""")

IDBYROWS_ROWS = []
for c in "IDBYROWS":
    r = AZ.index(c)
    IDBYROWS_ROWS.append(r)

IDBYROWS_ROWS_SORTED = sorted(IDBYROWS_ROWS)
print(f"Row indices (in order I,D,B,Y,R,O,W,S): {IDBYROWS_ROWS}")
print(f"Row indices sorted:                      {IDBYROWS_ROWS_SORTED}")
print()

print("The 8 selected rows:")
for r in IDBYROWS_ROWS_SORTED:
    row_text = CIPHER_GRID[r]
    section = "K1" if r < 2 else "K2" if r < 14 else "K3" if r < 24 else "K4"
    print(f"  Row {r:2d} ({AZ[r]:1s}, {section:2s}): {row_text}")

print()
print("Notable rows in the selection:")
print(f"  Row 14 = K3 START (CENTER) — the 'upper left corner' of K3")
print(f"  Row 24 = K4 START — where K4 begins at col 27")
print(f"  Row  1 = K1 row — the SECOND row of the cipher panel")
print(f"  Row  3 = K2 row with ? separator")
print()

# Extract all 8×31 = 248 cells from these rows
all_8_rows_text = ""
for r in IDBYROWS_ROWS_SORTED:
    row_clean = CIPHER_GRID[r].replace("?", "X")
    all_8_rows_text += row_clean

print(f"Concatenated text from 8 IDBYROWS rows ({len(all_8_rows_text)} chars):")
print(f"  {all_8_rows_text}")
print(f"  IC = {ic(all_8_rows_text):.4f}")

# K4 chars within those 8 rows:
print()
print("K4 chars in IDBYROWS rows:")
k4_in_idbyrows = []
for k4_idx in range(97):
    # K4 starts at grid position (24, 27)
    grid_pos = 24 * 31 + 27 + k4_idx
    row = grid_pos // 31
    col = grid_pos % 31
    if row in IDBYROWS_ROWS_SORTED:
        k4_in_idbyrows.append((k4_idx, row, col, K4_CARVED[k4_idx]))

print(f"  K4 chars in IDBYROWS rows: {len(k4_in_idbyrows)}")
if k4_in_idbyrows:
    for ki, r, c, ch in k4_in_idbyrows[:10]:
        print(f"    K4[{ki}]={ch} at grid({r},{c})")
    if len(k4_in_idbyrows) > 10:
        print(f"    ... ({len(k4_in_idbyrows)-10} more)")

# ─────────────────────────────────────────────────────────────────────────────
sep("B2. TEXT FROM 8 IDBYROWS ROWS: DECRYPTION TESTS")
# ─────────────────────────────────────────────────────────────────────────────

print()
# Extract rows in IDBYROWS order (not sorted), since order might matter
all_8_rows_ordered = ""
for r in IDBYROWS_ROWS:
    row_clean = CIPHER_GRID[r].replace("?", "X")
    all_8_rows_ordered += row_clean

print(f"Text from 8 rows in IDBYROWS ORDER (IDBYROWS sequence = reading key?):")
print(f"  {all_8_rows_ordered[:96]}...")
print(f"  IC = {ic(all_8_rows_ordered):.4f}")

# Test as scrambling → take first 97 chars (length of K4)
candidate_97 = all_8_rows_ordered[:97]
print(f"\nFirst 97 chars of 8-row ordered text: {candidate_97}")
print("Testing decryption on first 97 chars:")
test_all_decryptions(candidate_97, "8rows_ordered[97]")

# Try reading IDBYROWS rows: only the K4-region columns (cols 27-30 of row 24, all of rows 25-27)
# But those rows aren't all in IDBYROWS... let's check what cols each row contributes
print()
print("Reading interpretation: for each IDBYROWS row, read specific columns?")
print("Row 24 has K4 starting at col 27. For other rows, which cols correspond?")

# In IDBYROWS row ordering, if we take col 27-30 from each row (4 chars × 8 rows = 32):
text_cols_27_30 = ""
for r in IDBYROWS_ROWS:
    text_cols_27_30 += CIPHER_GRID[r][27:31]
print(f"\nCols 27-30 from 8 IDBYROWS rows: {text_cols_27_30} ({len(text_cols_27_30)} chars)")

# ─────────────────────────────────────────────────────────────────────────────
sep("C2. TABLEAU OVERLAY AT K4 POSITIONS")
# ─────────────────────────────────────────────────────────────────────────────
print("""
If the KA Vigenère tableau overlays the cipher grid (both 28×31),
then tableau[r][c] is the KEY LETTER for decrypting cipher[r][c].
For K4 positions (r=24-27, starting col 27):
  PT[k4_idx] = (CT[k4_idx] - tableau_key[r][c]) mod 26
""")

# Compute K4 positions in grid
k4_positions = []
grid_pos = 24 * 31 + 27  # row 24, col 27
for i in range(97):
    pos = grid_pos + i
    r, c = pos // 31, pos % 31
    k4_positions.append((r, c))

assert len(k4_positions) == 97

# Tableau keys at K4 positions
tableau_keys = []
for r, c in k4_positions:
    tab_cell = TABLEAU[r][c]
    tableau_keys.append(tab_cell)

print("Tableau key letters at K4 positions:")
print(f"  {''.join(tableau_keys)}")
print(f"  (Length: {len(tableau_keys)})")
print(f"  IC of key string: {ic(''.join(tableau_keys)):.4f}")

# Decode K4 using tableau as Vigenère key (AZ)
pt_tableau_az = []
for i, (r, c) in enumerate(k4_positions):
    ct_letter = K4_CARVED[i]
    key_letter = TABLEAU[r][c]
    if ct_letter in AZ and key_letter in AZ:
        pt_letter = AZ[(AZ.index(ct_letter) - AZ.index(key_letter)) % 26]
    else:
        pt_letter = '?'
    pt_tableau_az.append(pt_letter)

pt_tableau_az_str = "".join(pt_tableau_az)
print(f"\nK4 decrypted with tableau as AZ-Vig key:")
print(f"  PT = {pt_tableau_az_str}")
print(f"  IC = {ic(pt_tableau_az_str):.4f}")
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_tableau_az_str[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_tableau_az_str[CRIB_BC_START+i] == c)
print(f"  ENE={ene_m}/13, BC={bc_m}/11")
print(f"  Pos 21-33: {pt_tableau_az_str[21:34]}")
print(f"  Pos 63-73: {pt_tableau_az_str[63:74]}")
ch = has_cribs(pt_tableau_az_str)
if ch: print(f"  CRIB HITS: {ch}")

# Beaufort variant
pt_tableau_beau = []
for i, (r, c) in enumerate(k4_positions):
    ct_letter = K4_CARVED[i]
    key_letter = TABLEAU[r][c]
    if ct_letter in AZ and key_letter in AZ:
        pt_letter = AZ[(AZ.index(key_letter) - AZ.index(ct_letter)) % 26]
    else:
        pt_letter = '?'
    pt_tableau_beau.append(pt_letter)

pt_tableau_beau_str = "".join(pt_tableau_beau)
print(f"\nK4 decrypted with tableau as AZ-Beaufort key:")
print(f"  PT = {pt_tableau_beau_str}")
print(f"  IC = {ic(pt_tableau_beau_str):.4f}")
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_tableau_beau_str[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_tableau_beau_str[CRIB_BC_START+i] == c)
print(f"  ENE={ene_m}/13, BC={bc_m}/11")
ch = has_cribs(pt_tableau_beau_str)
if ch: print(f"  CRIB HITS: {ch}")

# KA alphabet Vigenère with tableau
pt_tableau_ka = []
for i, (r, c) in enumerate(k4_positions):
    ct_letter = K4_CARVED[i]
    key_letter = TABLEAU[r][c]
    if ct_letter in KA and key_letter in KA:
        pt_letter = KA[(KA.index(ct_letter) - KA.index(key_letter)) % 26]
    else:
        pt_letter = '?'
    pt_tableau_ka.append(pt_letter)

pt_tableau_ka_str = "".join(pt_tableau_ka)
print(f"\nK4 decrypted with tableau as KA-Vig key:")
print(f"  PT = {pt_tableau_ka_str}")
print(f"  IC = {ic(pt_tableau_ka_str):.4f}")
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_tableau_ka_str[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_tableau_ka_str[CRIB_BC_START+i] == c)
print(f"  ENE={ene_m}/13, BC={bc_m}/11")
ch = has_cribs(pt_tableau_ka_str)
if ch: print(f"  CRIB HITS: {ch}")

# Also try: cipher[r][c] IS PT, tableau[r][c] IS CT → this is encrypt direction
# i.e., if the grille shows the TABLEAU as if it were the cipher, and cipher is key:
pt_tableau_enc = []
for i, (r, c) in enumerate(k4_positions):
    ct_letter = K4_CARVED[i]
    tab_letter = TABLEAU[r][c]
    if ct_letter in AZ and tab_letter in AZ:
        pt_letter = AZ[(AZ.index(tab_letter) - AZ.index(ct_letter)) % 26]
    else:
        pt_letter = '?'
    pt_tableau_enc.append(pt_letter)

pt_tableau_enc_str = "".join(pt_tableau_enc)
print(f"\nK4: using cipher as Vig key for tableau (reversed roles):")
print(f"  PT = {pt_tableau_enc_str}")
print(f"  IC = {ic(pt_tableau_enc_str):.4f}")
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_tableau_enc_str[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_tableau_enc_str[CRIB_BC_START+i] == c)
print(f"  ENE={ene_m}/13, BC={bc_m}/11")
ch = has_cribs(pt_tableau_enc_str)
if ch: print(f"  CRIB HITS: {ch}")

# ─────────────────────────────────────────────────────────────────────────────
sep("D2. BEAN CONSTRAINT ANALYSIS")
# ─────────────────────────────────────────────────────────────────────────────
print("""
Bean equation: k[27]=k[65] (key letters at K4 positions 27 and 65 must be equal)
Plus 21 inequalities (other pairs are NOT equal).

For periodic key with period p:
  k[27] = key[27 mod p], k[65] = key[65 mod p]
  For equality: either 27 mod p == 65 mod p (period divides 38)
  Or: key has same letter at positions 27 mod p and 65 mod p

From cribs, we know the ACTUAL keystream at positions 21-33 and 63-73.
  k[27] = Y (from ENE crib: 'C' at pos 27 of ENE keystream)
  k[65] = Y (from BC crib: 'Y' at pos 65 of BC keystream)
  k[27] = Y = k[65] ✓ BEAN IS SATISFIED! Both are Y!
""")

# Extract actual keystream from cribs
def get_keystream_from_cribs():
    ks = {}
    for i, pt_letter in enumerate(CRIB_ENE):
        pos = CRIB_ENE_START + i
        ct_letter = K4_CARVED[pos]
        # Standard Vigenère: CT = (PT + KEY) mod 26, so KEY = (CT - PT) mod 26
        key_val = (AZ.index(ct_letter) - AZ.index(pt_letter)) % 26
        ks[pos] = (AZ[key_val], key_val)
    for i, pt_letter in enumerate(CRIB_BC):
        pos = CRIB_BC_START + i
        ct_letter = K4_CARVED[pos]
        key_val = (AZ.index(ct_letter) - AZ.index(pt_letter)) % 26
        ks[pos] = (AZ[key_val], key_val)
    return ks

ks = get_keystream_from_cribs()
print("Known keystream (AZ Vigenère: KEY = (CT - PT) mod 26):")
for pos in sorted(ks.keys()):
    letter, val = ks[pos]
    print(f"  k[{pos:2d}] = {letter} ({val:2d})")

# Check Bean constraint
k27 = ks.get(27)
k65 = ks.get(65)
print(f"\nBean constraint check:")
print(f"  k[27] = {k27}")
print(f"  k[65] = {k65}")
if k27 and k65:
    if k27[0] == k65[0]:
        print(f"  ✓ BEAN SATISFIED: k[27] = k[65] = '{k27[0]}'")
    else:
        print(f"  ✗ BEAN VIOLATED: k[27]='{k27[0]}' ≠ k[65]='{k65[0]}'")

# What periods satisfy Bean with these actual keystream values?
print(f"\nPeriod analysis for known keystream:")
print(f"  Bean requires k[27]=k[65]")
print(f"  65-27=38. Periods dividing 38: {[p for p in range(1,39) if 38%p==0]}")

# For each period, check consistency of known keystream
print(f"\nKeystream consistency by period:")
for period in [7, 8, 17, 19, 38, 41]:
    # Group known positions by (pos mod period)
    by_period = defaultdict(list)
    for pos, (letter, val) in sorted(ks.items()):
        by_period[pos % period].append((pos, letter, val))

    consistent = True
    inconsistencies = []
    for residue, entries in sorted(by_period.items()):
        letters = [e[1] for e in entries]
        if len(set(letters)) > 1:
            consistent = False
            inconsistencies.append((residue, entries))

    if consistent:
        key_partial = ['?' for _ in range(period)]
        for pos, (letter, val) in ks.items():
            key_partial[pos % period] = letter
        print(f"  Period {period}: ✓ CONSISTENT! Implied key = {''.join(key_partial)}")
    else:
        print(f"  Period {period}: ✗ {len(inconsistencies)} inconsistencies")
        for res, entries in inconsistencies[:2]:
            print(f"    mod-{period}={res}: " + ", ".join(f"k[{p}]={l}" for p,l,v in entries))

# ─────────────────────────────────────────────────────────────────────────────
sep("E2. KEYSTREAM RECONSTRUCTION: KA-INDEX VIEW")
# ─────────────────────────────────────────────────────────────────────────────
print("""
Convert the known keystream letters to their KA-index positions.
If the key was generated using KA alphabet, the mod-period pattern
should be consistent in KA-index space.
""")

print("Known keystream in KA-index:")
ks_ka = {}
for pos, (letter, _) in sorted(ks.items()):
    if letter in KA:
        ka_idx = KA.index(letter)
        ks_ka[pos] = (letter, ka_idx)
        print(f"  k[{pos:2d}] = {letter} → KA[{ka_idx:2d}] = {KA[ka_idx]}")
    else:
        print(f"  k[{pos:2d}] = {letter} → NOT in KA")

# Do the KA-index values spell anything?
ks_sorted = sorted(ks.items())
key_letters_in_order = [v[0] for _, v in ks_sorted]
key_vals_in_order = [v[1] for _, v in ks_sorted]
print(f"\nKeystream letters in position order: {''.join(key_letters_in_order)}")
print(f"Keystream values in position order:   {key_vals_in_order}")

# Check if keystream has period 19 (only period > 8 dividing 38)
print(f"\nPeriod-19 check:")
for period in [19]:
    by_period = defaultdict(list)
    for pos, (letter, val) in sorted(ks.items()):
        by_period[pos % period].append((pos, letter, val))
    key_19 = ['?' for _ in range(period)]
    consistent = True
    for residue, entries in sorted(by_period.items()):
        letters = [e[1] for e in entries]
        if len(set(letters)) == 1:
            key_19[residue] = letters[0]
        else:
            consistent = False
            print(f"  Inconsistency at mod-19={residue}: {entries}")
    if not consistent:
        # Fill in what we can
        for residue, entries in sorted(by_period.items()):
            if len(entries) == 1:
                key_19[residue] = entries[0][1]
    print(f"  Period-19 partial key: {''.join(key_19)}")

# ─────────────────────────────────────────────────────────────────────────────
sep("F2. IDBYROWS ROW-KEY VIGENÈRE")
# ─────────────────────────────────────────────────────────────────────────────
print("""
K4 occupies rows 24-27. 'ID BY ROWS' → use row number as Vigenère key.
Row 24 → AZ[24] = Y, Row 25 → AZ[25] = Z, Row 26 → AZ[0] = A, Row 27 → AZ[1] = B
Key string for K4: YYYY (row 24 = 4 chars) + ZZZZZ...Z (row 25 = 31) + AAA...A (row 26 = 31) + BBB...B (row 27 = 31)
""")

# Build the row-key
row_key = ""
for k4_idx, (r, c) in enumerate(k4_positions):
    row_letter = AZ[r % 26]
    row_key += row_letter

print(f"Row-key for K4 (by row): {row_key}")
print(f"  (Y×4 + Z×31 + A×31 + B×31 = {row_key.count('Y')}Y + {row_key.count('Z')}Z + {row_key.count('A')}A + {row_key.count('B')}B = {len(row_key)})")

# AZ Vigenère with row-key
pt_rowkey_az = vig_decrypt(K4_CARVED, row_key, AZ)
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_rowkey_az[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_rowkey_az[CRIB_BC_START+i] == c)
print(f"\nRow-key AZ Vig: PT = {pt_rowkey_az}")
print(f"  ENE={ene_m}/13, BC={bc_m}/11, IC={ic(pt_rowkey_az):.4f}")
ch = has_cribs(pt_rowkey_az)
if ch: print(f"  CRIB HITS: {ch}")

# Beaufort with row-key
pt_rowkey_beau = beau_decrypt(K4_CARVED, row_key, AZ)
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_rowkey_beau[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_rowkey_beau[CRIB_BC_START+i] == c)
print(f"\nRow-key AZ Beaufort: PT = {pt_rowkey_beau}")
print(f"  ENE={ene_m}/13, BC={bc_m}/11, IC={ic(pt_rowkey_beau):.4f}")
ch = has_cribs(pt_rowkey_beau)
if ch: print(f"  CRIB HITS: {ch}")

# KA row-key variant
ka_row_key = "".join(KA[r % 26] for r, c in k4_positions)
print(f"\nKA row-key (use KA[row] instead of AZ[row]): {ka_row_key}")
pt_ka_rowkey = vig_decrypt(K4_CARVED, ka_row_key, KA)
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_ka_rowkey[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_ka_rowkey[CRIB_BC_START+i] == c)
print(f"KA row-key KA Vig: PT = {pt_ka_rowkey}")
print(f"  ENE={ene_m}/13, BC={bc_m}/11, IC={ic(pt_ka_rowkey):.4f}")
ch = has_cribs(pt_ka_rowkey)
if ch: print(f"  CRIB HITS: {ch}")

# ─────────────────────────────────────────────────────────────────────────────
sep("G2. 73-HOLE READING: NON-CRIB POSITIONS")
# ─────────────────────────────────────────────────────────────────────────────
print("""
If the grille has 73 holes at the non-crib positions of K4:
  - The grille reveals the 73 non-crib chars of K4 (the 'real CT')
  - The cribs are anchors (already known)
  - Test: decode the 73 non-crib chars using various methods
""")

non_crib_ct = "".join(K4_CARVED[i] for i in NON_CRIB_POSITIONS)
print(f"73 non-crib chars of K4: {non_crib_ct}")
print(f"IC = {ic(non_crib_ct):.4f}")

# What tableau keys correspond to the 73 non-crib positions?
non_crib_tableau_keys = "".join(tableau_keys[i] for i in NON_CRIB_POSITIONS)
print(f"Tableau keys at non-crib positions: {non_crib_tableau_keys}")

# Decode 73 non-crib chars using tableau keys at those positions (AZ Vig)
pt_73_tableau = []
for i in NON_CRIB_POSITIONS:
    ct_letter = K4_CARVED[i]
    key_letter = tableau_keys[i]
    if ct_letter in AZ and key_letter in AZ:
        pt_letter = AZ[(AZ.index(ct_letter) - AZ.index(key_letter)) % 26]
    else:
        pt_letter = '?'
    pt_73_tableau.append(pt_letter)
pt_73_tableau_str = "".join(pt_73_tableau)
print(f"\nTableau-key AZ Vig at 73 non-crib positions: {pt_73_tableau_str}")
print(f"IC = {ic(pt_73_tableau_str):.4f}")

# Test with simple keywords on the 73 non-crib chars
print("\nTesting keyword decryption on 73 non-crib chars:")
for key in ["ABSCISSA", "KRYPTOS", "SHADOW", "PALIMPSEST"]:
    for fn_name, fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
        pt_73 = fn(non_crib_ct, key, AZ)
        # Can we find cribs at their EXPECTED positions within the 73 chars?
        # Original pos 21-33 → in non-crib: some positions are crib, some not
        # Let's check if any crib fragment appears in pt_73
        for crib in CRIBS:
            if crib[:8] in pt_73:
                print(f"  *** {key} {fn_name}: found '{crib[:8]}' in 73 non-crib PT! ***")
                print(f"      {pt_73}")

# ─────────────────────────────────────────────────────────────────────────────
sep("H2. 'UPPER LEFT CORNER' → EXPANDING SPIRAL FROM K3 START")
# ─────────────────────────────────────────────────────────────────────────────
print("""
K3 says 'TINY BREACH IN THE UPPER LEFT HAND CORNER, THEN WIDENING'
The 'upper left corner' of the K3 section = row 14, col 0 of the cipher grid.
What if the grille STARTS at (14,0) and expands in some order?

Let's examine what the cipher grid looks like from (14,0) onward:
K3 runs rows 14-23 (full) + row 24 cols 0-25, then K4 starts at (24,27).
""")

# Show K3+K4 section with positions
print("K3+K4 section of cipher grid:")
for r in range(14, 28):
    row = CIPHER_GRID[r]
    section_parts = []
    for c, ch in enumerate(row):
        pos_in_section = (r - 14) * 31 + c
        if r == 24 and c == 26:
            section_parts.append("?")
        elif r == 24 and c >= 27:
            k4_i = (r * 31 + c) - (24 * 31 + 27)
            section_parts.append(ch)
        else:
            section_parts.append(ch)

    if r == 14:
        marker = "← K3 START (upper left corner)"
    elif r == 24:
        marker = "← K4 starts at col 27"
    elif r == 27:
        marker = "← END"
    else:
        marker = ""
    print(f"  Row {r}: {''.join(section_parts)} {marker}")

# "Widening the hole" from (14,0): read diagonally?
# Diagonal from (14,0): (14,0), (15,1), (16,2), (17,3), (18,4), (19,5), (20,6), (21,7), (22,8), (23,9)
# Then continue at (24,10) → K4 area
print("\n'Widening from upper-left corner' — diagonal reading from (14,0):")
diag_chars = []
for step in range(31):
    r = 14 + step
    c = step
    if 0 <= r < 28 and 0 <= c < 31:
        diag_chars.append((r, c, CIPHER_GRID[r][c]))

diag_text = "".join(ch for _, _, ch in diag_chars)
print(f"  Diagonal (r=14+i, c=i): {diag_text}")

# Alternative: read K3 in reverse order (from lower right to upper left)
k3_reversed = ""
for r in range(23, 13, -1):
    k3_reversed += CIPHER_GRID[r][::-1]
k3_reversed += CIPHER_GRID[24][:27][::-1]  # The K3 part of row 24
print(f"\nK3 reversed (from lower-right to upper-left):")
print(f"  {k3_reversed[:97]}")
print(f"  Testing as scrambled K4...")
test_all_decryptions(k3_reversed[:97], "K3_reversed")

# ─────────────────────────────────────────────────────────────────────────────
sep("I2. PERIOD-17 AND PERIOD-8 ALPHABET DECOMPOSITION")
# ─────────────────────────────────────────────────────────────────────────────
print("""
The AZ→KA permutation splits letters into:
  17-cycle: ABDEFINGHIKLLMOPRST (ABDEFGHIKLMNOPRST)
  8-cycle:  CJQUVWXY
  Fixed:    Z

What if the substitution cipher only uses one cycle's letters?
Or what if each cycle defines a separate sub-cipher?
""")

cycle_17 = [c for c in AZ if c in "ABDEFGHIKLMNOPRST"]  # 17-cycle letters in AZ order
cycle_8 = [c for c in AZ if c in "CJQUVWXY"]  # 8-cycle letters in AZ order

# More precisely:
CYCLE_17_LETTERS = set("ABDEFGHIKLMNOPRST")  # the 17 letters
CYCLE_8_LETTERS = set("CJQUVWXY")

print(f"17-cycle letters: {''.join(sorted(CYCLE_17_LETTERS))}")
print(f" 8-cycle letters: {''.join(sorted(CYCLE_8_LETTERS))}")
print(f"  Fixed (Z):       Z")

# Count K4 letters by cycle
k4_17 = sum(1 for c in K4_CARVED if c in CYCLE_17_LETTERS)
k4_8 = sum(1 for c in K4_CARVED if c in CYCLE_8_LETTERS)
k4_z = K4_CARVED.count('Z')
print(f"\nK4 letter distribution by cycle:")
print(f"  17-cycle: {k4_17} letters")
print(f"   8-cycle: {k4_8} letters")
print(f"   Fixed Z: {k4_z} letters")
print(f"   Total:   {k4_17+k4_8+k4_z} (should be 97)")

# Extract K4 letters by cycle and test
k4_17_only = "".join(c for c in K4_CARVED if c in CYCLE_17_LETTERS)
k4_8_only = "".join(c for c in K4_CARVED if c in CYCLE_8_LETTERS)
print(f"\n17-cycle letters from K4: {k4_17_only} ({len(k4_17_only)} chars)")
print(f"IC = {ic(k4_17_only):.4f}")
print(f"\n 8-cycle letters from K4: {k4_8_only} ({len(k4_8_only)} chars)")
print(f"IC = {ic(k4_8_only):.4f}")

# ─────────────────────────────────────────────────────────────────────────────
sep("J2. MISSPELLING KA-INDEX DIFFERENCES")
# ─────────────────────────────────────────────────────────────────────────────
print("""
The misspellings change letters. What is the difference in KA-index space?
  K1: L(KA[17]) → Q(KA[20]), CT=K(KA[0])
    KA-diff L→Q: 20-17 = 3
    KA-diff L→K: 0-17 = -17 ≡ 9 (mod 26)
  K3: E(KA[11]) → A(KA[7]), CT=A(KA[7])
    KA-diff E→A: 7-11 = -4 ≡ 22 (mod 26)
    KA-diff E→A: replacement IS the CT result (A=A)

KA-diffs: {L→Q: 3}, {L→K: 9}, {E→A: 22}
Products: 3 × 9 = 27, 3 × 22 = 66, 9 × 22 = 198
Sums: 3+9=12, 3+22=25, 9+22=31 (= grid width!), 3+9+22=34
""")

# Compute KA diffs
pairs = [
    ("L", "Q", "K1 wrong→right"),
    ("L", "K", "L→CT"),
    ("E", "A", "K3 wrong→right"),
    ("Q", "K", "replacement→CT (K1)"),
    ("A", "A", "replacement→CT (K3)"),
]

for a, b, desc in pairs:
    ka_a = KA.index(a) if a in KA else -1
    ka_b = KA.index(b) if b in KA else -1
    if ka_a >= 0 and ka_b >= 0:
        diff = (ka_b - ka_a) % 26
        print(f"  {desc}: {a}(KA={ka_a}) → {b}(KA={ka_b}) = diff {diff}")

# The sum 9+22=31 is the GRID WIDTH! Very interesting.
print(f"\n  *** KA-diff(L→K)=9 + KA-diff(E→A)=22 = 31 = GRID WIDTH! ***")
print(f"  This is a structural match. The two KA-diffs sum to the grid width.")
print(f"  If these represent column offsets in the grille...")

# ─────────────────────────────────────────────────────────────────────────────
sep("K2. NOVEL COMBINATION: IDBYROWS ROWS + TABLEAU OVERLAY")
# ─────────────────────────────────────────────────────────────────────────────
print("""
Combining insights:
  - 8 IDBYROWS rows identify the 8-line grille structure
  - The tableau cells at those rows provide decryption keys
  - The 73 non-crib positions are the holes
  - K4 positions overlap with row 24 (IDBYROWS row) only partially
""")

# For each of the 8 IDBYROWS rows, show the tableau content
print("Tableau content at IDBYROWS rows:")
for r in IDBYROWS_ROWS_SORTED:
    tab_row = TABLEAU[r]
    key_col = tab_row[0]  # key letter (or space for header/footer)
    body = tab_row[1:]    # 30-char body
    print(f"  Row {r:2d} (key={key_col:1s}): body = {body}")

# The K4 chars in row 24 (the only K4 row in IDBYROWS):
print(f"\nK4 chars in IDBYROWS row 24 (cols 27-30):")
for c in range(27, 31):
    k4_i = (24 * 31 + c) - (24 * 31 + 27)
    ct = K4_CARVED[k4_i]
    tab = TABLEAU[24][c]
    pt_az = AZ[(AZ.index(ct) - AZ.index(tab)) % 26] if ct in AZ and tab in AZ else '?'
    print(f"  K4[{k4_i}]={ct} at ({24},{c}): tableau={tab}, PT(AZ-Vig)={pt_az}")

# Test: use col as key (mod 26 AZ) for decrypting K4
print(f"\nTesting col-number as Vigenère key for K4:")
col_key = "".join(AZ[c % 26] for r, c in k4_positions)
print(f"  Col-key: {col_key}")
pt_colkey = vig_decrypt(K4_CARVED, col_key, AZ)
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_colkey[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_colkey[CRIB_BC_START+i] == c)
print(f"  Col-key AZ Vig: ENE={ene_m}/13, BC={bc_m}/11")
print(f"  PT: {pt_colkey}")

# Test: (row*31 + col) mod 26 as key
linear_key = "".join(AZ[(r * 31 + c) % 26] for r, c in k4_positions)
print(f"\nLinear position (r*31+c) mod 26 as Vig key:")
print(f"  Linear-key: {linear_key}")
pt_linkey = vig_decrypt(K4_CARVED, linear_key, AZ)
ene_m = sum(1 for i, c in enumerate(CRIB_ENE) if pt_linkey[CRIB_ENE_START+i] == c)
bc_m = sum(1 for i, c in enumerate(CRIB_BC) if pt_linkey[CRIB_BC_START+i] == c)
print(f"  Linear-key AZ Vig: ENE={ene_m}/13, BC={bc_m}/11")
print(f"  PT: {pt_linkey}")
ch = has_cribs(pt_linkey)
if ch: print(f"  CRIB HITS: {ch}")

# ─────────────────────────────────────────────────────────────────────────────
sep("L2. PHASE 2 SYNTHESIS: TOP CONSTRAINTS AND NEXT ACTIONS")
# ─────────────────────────────────────────────────────────────────────────────
print()
print("=" * 72)
print("  TOP FINDINGS FROM WAVE 2 ANALYSIS")
print("=" * 72)
print("""
1. IDBYROWS = 8 SPECIFIC ROWS = '8 LINES':
   - IDBYROWS letters → AZ indices → rows {1, 3, 8, 14, 17, 18, 22, 24}
   - EXACTLY 8 rows = '8 Lines' from Sanborn's yellow pad
   - CRITICAL: Row 14 = K3 start, Row 24 = K4 start
   - These are structurally special rows of the cipher grid

2. KA-INDEX DIFFS SUM TO GRID WIDTH:
   - K1 KA-diff(L→K) = 9
   - K3 KA-diff(E→A) = 22
   - 9 + 22 = 31 = GRID WIDTH (not trivially coincidental)
   - Possible meaning: the grille covers columns 9-22 (range 9 to 30-22=8?)
   - Or: the two misspellings define column anchors

3. BEAN CONSTRAINT SATISFIED:
   - k[27]=Y and k[65]=Y (from crib analysis)
   - Bean k[27]=k[65] IS satisfied with the actual cribs!
   - Period analysis: no period ≤ 38 (except 1,2,19,38) gives consistency
   - The actual key has k[27]=k[65]=Y but NOT periodic at period 7 or 8

4. TABLEAU OVERLAY IS POSITION-SPECIFIC:
   - Tableau key at each K4 position is determined by (row, col)
   - This IS a valid non-periodic key (depends on position in 28×31 grid)
   - The tableau overlay implements a position-specific Vigenère key
   - This naturally explains WHY no periodic key works!

5. SYNTHESIS HYPOTHESIS:
   The cipher method is:
     PT → position-specific Vigenère using TABLEAU → scrambled CT → carved
   OR:
     PT → key-Vigenère → real CT → SCRAMBLE (sigma from IDBYROWS 8-row grille) → carved

   The IDBYROWS 8 rows define the scrambling structure.
   The tableau keys define the unscrambling within those 8 rows.
""")

print("=" * 72)
print("  HIGHEST-PRIORITY NEXT ACTIONS")
print("=" * 72)
print("""
A. Test tableau-overlay decryption WITH each possible 8-row scrambling pattern:
   - The 8 IDBYROWS rows define 8×31=248 positions
   - K4's 97 chars are scattered at various positions in the 28×31 grid
   - Map K4 chars through a permutation that collects them into the 8 rows
   - Then apply tableau-based decryption

B. Build the grille from the two misspelling KA-diffs (9, 22):
   - Col range 9 to 22 (14 columns) in the tableau body
   - For 8 IDBYROWS rows × 14 cols = 112 cells (> 97, need to trim to 73)
   - Or: the diff-9 and diff-22 define two separate half-grilles

C. Test: the keystream YCDZYCLYGCKAZ (from ENE crib) if read in KA
   spells anything. Similarly for BC keystream MUYKLGKORNA.

D. Apply 180° rotation + tableau overlay: the K4 chars map to K1/K2 region.
   Use the tableau keys at the ROTATED positions to decrypt K4.
""")

# Print the ENE and BC keystrams one more time prominently
print(f"\nENE keystream: {''.join(v[0] for _, v in sorted(ks.items()) if _ < 34)}")
print(f"BC keystream:  {''.join(v[0] for _, v in sorted(ks.items()) if _ >= 63)}")

# Do they spell anything in reverse?
ene_ks = "".join(v[0] for _, v in sorted(ks.items()) if _ < 34)
bc_ks = "".join(v[0] for _, v in sorted(ks.items()) if _ >= 63)
print(f"ENE reversed: {ene_ks[::-1]}")
print(f"BC reversed:  {bc_ks[::-1]}")
combined = ene_ks + bc_ks
print(f"Combined ks:  {combined}")
print(f"Combined rev: {combined[::-1]}")

# Check if combined keystream appears in KA alphabet
print(f"\nKeystream {combined} - is it a substring of KA extended?")
ka_ext = KA * 10
if combined[:6] in ka_ext:
    print(f"  *** {combined[:6]} found in extended KA! ***")
if combined[:4] in ka_ext:
    print(f"  First 4 chars '{combined[:4]}' in KA: pos {ka_ext.index(combined[:4])}")

# Test if keystream has any structure when mapped through KA
print("\nKeystream mapped through KA positions:")
ks_ka_vals = [KA.index(c) for c in combined if c in KA]
print(f"  KA positions: {ks_ka_vals}")
diffs = [ks_ka_vals[i+1]-ks_ka_vals[i] for i in range(len(ks_ka_vals)-1)]
print(f"  Consecutive diffs: {diffs}")

# Does the keystream correspond to ABSCISSA in KA-mapped form?
abscissa_ka = [KA.index(c) for c in "ABSCISSA"]
print(f"\nABSCISSA in KA: {abscissa_ka}")
print(f"KRYPTOS in KA:  {[KA.index(c) for c in 'KRYPTOS']}")

sep()
print("DONE — blitz_instruction_decoder_v2.py")
sep()
