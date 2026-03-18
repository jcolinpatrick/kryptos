#!/usr/bin/env python3
"""
Cipher: analysis
Family: campaigns
Status: active
Keyspace: analytical + exhaustive small searches
Last run: never
Best score: TBD
"""
"""E-PALETTE-DEEP-INVESTIGATION: Comprehensive analysis of the 7-letter null palette {B,G,I,K,O,W,Z}.

The 17 consensus null characters use ONLY these 7 letters (p=0.000024).
This script exhaustively tests every proposed generating rule.

Run: PYTHONPATH=src python3 -u scripts/campaigns/e_palette_deep_investigation.py
"""

import sys, os, json, time, math
from collections import Counter, defaultdict
from itertools import product as iter_product, combinations, permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CRIB_POSITIONS, KRYPTOS_ALPHABET, ALPH, ALPH_IDX

CT97 = CT
N = 97
KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ = ALPH
AZ_IDX = ALPH_IDX

PALETTE = frozenset('BGIKOWZ')
PALETTE_LETTERS = sorted(PALETTE)
PAL_AZ = sorted(AZ_IDX[c] for c in PALETTE_LETTERS)   # [1,6,8,10,14,22,25]
PAL_KA = sorted(KA_IDX[c] for c in PALETTE_LETTERS)   # [0,5,8,13,15,23,25]

CONSENSUS_NULLS = sorted([0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85])
CONSENSUS_CHARS = [CT97[p] for p in CONSENSUS_NULLS]
CONSENSUS_AZ = [AZ_IDX[c] for c in CONSENSUS_CHARS]

# All 35 positions where CT has a palette letter
ALL_PALETTE_POS = [i for i in range(97) if CT97[i] in PALETTE]
# The 18 non-null palette positions
NONNULL_PALETTE_POS = [p for p in ALL_PALETTE_POS if p not in set(CONSENSUS_NULLS)]

CRIB_POS_SET = set(CRIB_POSITIONS)
ENE_START, BCL_START = 21, 63
ENE_WORD, BCL_WORD = "EASTNORTHEAST", "BERLINCLOCK"

KEYWORDS = [
    "KRYPTOS", "DEFECTOR", "ABSCISSA", "KOMPASS", "PALIMPSEST",
    "COLOPHON", "PARALLAX", "SHADOW", "SANBORN", "BERLIN",
    "CLOCK", "FIVE", "SEVEN", "ENIGMA", "MEDUSA"
]

# Known 15/24 masks (6 distinct)
MASKS_15 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],
    [0,1,2,5,8,12,14,20,36,38,39,45,52,55,58,59,74,75,78,84,85,87,93,96],
    [0,1,2,5,8,12,14,20,36,39,40,44,52,56,58,59,74,75,78,84,85,87,95,96],
    [0,1,2,5,8,12,14,20,36,38,44,45,52,55,58,59,74,75,78,84,85,88,93,96],
]

K4_START_ROW = 24
K4_START_COL = 27
GRID_WIDTH = 31

results = {}
findings = []

def note(msg):
    findings.append(msg)
    print(msg)

t0 = time.time()

# ══════════════════════════════════════════════════════════════════════
# TEST 1: TABLEAU-DERIVED RELATIONSHIPS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 1: TABLEAU-DERIVED RELATIONSHIPS")
print("=" * 72)
print()

# Build the KA tableau: tableau[key_row][col] = letter
# Row 'A' (key=0) -> KA shifted by 0 = KRYPTOSABCDEFGHIJLMNQUVWXZ
# Row 'B' (key=1) -> KA shifted by 1 = RYPTOSABCDEFGHIJLMNQUVWXZK
# etc.
def build_ka_tableau():
    """Build tableau[key_idx][col_idx] = letter (AZ index)"""
    tab = []
    for key_shift in range(26):
        row = []
        for col in range(26):
            ka_idx = (col + key_shift) % 26
            letter = KA_STR[ka_idx]
            row.append(AZ_IDX[letter])
        tab.append(row)
    return tab

KA_TAB = build_ka_tableau()

# 1a) For each key letter (row), which columns contain palette letters?
print("--- 1a: Palette letter column positions in each tableau row ---")
pal_az_set = set(PAL_AZ)
tab_results_1a = {}
for key_row in range(26):
    key_letter = AZ[key_row]
    cols_with_palette = [col for col in range(26) if KA_TAB[key_row][col] in pal_az_set]
    tab_results_1a[key_letter] = cols_with_palette
    if len(set(c % 7 for c in cols_with_palette)) <= 2 or len(cols_with_palette) < 5:
        print(f"  Key={key_letter}: columns {cols_with_palette} (mod7 = {sorted(set(c%7 for c in cols_with_palette))})")

# Check: is there a fixed column pattern?
print("\n  Column positions where palette appears, for each key row:")
col_pattern_counts = Counter()
for key_row in range(26):
    key_letter = AZ[key_row]
    cols = tuple(sorted(col for col in range(26) if KA_TAB[key_row][col] in pal_az_set))
    col_pattern_counts[cols] += 1
    # Report the KA-indexed version too
    ka_cols = tuple(sorted((col + key_row) % 26 for col in range(26) if KA_TAB[key_row][col] in pal_az_set))
    if key_row < 5:
        print(f"  Key={AZ[key_row]}: AZ-cols={cols}, KA-cols-shifted={ka_cols}")

# The KA-cols-shifted should be CONSTANT (the KA positions of palette letters)
# because shifting the row = shifting where each letter appears
ka_pal_indices = tuple(sorted(KA_IDX[c] for c in PALETTE_LETTERS))
print(f"\n  KA indices of palette: {ka_pal_indices}")
print(f"  All rows have palette at same KA indices? YES (by construction)")

# 1b) What plaintext letters produce ONLY palette letters under encryption with a given key?
print("\n--- 1b: Key letters where encrypting fixed PT produces only palette CT ---")
for variant_name, variant_fn in [
    ("Vigenere", lambda pt, key: (pt + key) % 26),
    ("Beaufort", lambda pt, key: (key - pt) % 26),
]:
    for key_val in range(26):
        key_letter = AZ[key_val]
        # Which PT values produce palette CT?
        pt_producing_pal = []
        for pt_val in range(26):
            # Use KA for encryption
            pt_ka = KA_IDX[AZ[pt_val]]
            key_ka = KA_IDX[key_letter]
            ct_ka = variant_fn(pt_ka, key_ka)
            ct_letter = KA_STR[ct_ka]
            if ct_letter in PALETTE:
                pt_producing_pal.append(AZ[pt_val])
        if len(pt_producing_pal) == 7:
            # Check if PT values form a meaningful set
            pt_set = frozenset(pt_producing_pal)
            kws_match = [kw for kw in KEYWORDS if frozenset(kw).issubset(pt_set)]
            if kws_match or pt_set == PALETTE:
                print(f"  {variant_name} key={key_letter}: PT={sorted(pt_producing_pal)} -> palette CT. Keywords: {kws_match}")

# 1c) For each row of tableau, extract columns at palette positions
print("\n--- 1c: Tableau row slicing at palette KA positions ---")
# Palette KA indices: {0,5,8,13,15,23,25}
# For each key row, read the letters at these KA column positions
# These ARE the palette letters (by construction), mapped back through key
# More interesting: what key-column letters correspond?
print("  For each KA column in palette position, what KEY ROW has that column = a specific letter?")
# Inverted question: given target CT letters at specific columns, what key row?
# This is just Vigenere decryption.

# 1d) Palette positions in KA as a function of KRYPTOS letters
print("\n--- 1d: KRYPTOS -> Palette mapping ---")
KRYPTOS_LETTERS = list("KRYPTOS")
for i, (kl, pl) in enumerate(zip(KRYPTOS_LETTERS, PALETTE_LETTERS)):
    k_az = AZ_IDX[kl]
    p_az = AZ_IDX[pl]
    k_ka = KA_IDX[kl]
    p_ka = KA_IDX[pl]
    vig = (p_az - k_az) % 26
    beau = (p_az + k_az) % 26
    vig_ka = (p_ka - k_ka) % 26
    beau_ka = (p_ka + k_ka) % 26
    print(f"  {kl}(AZ={k_az},KA={k_ka}) -> {pl}(AZ={p_az},KA={p_ka}): "
          f"vig_AZ={vig}({AZ[vig]}), beau_AZ={beau}({AZ[beau%26]}), "
          f"vig_KA={vig_ka}({KA_STR[vig_ka]}), beau_KA={beau_ka%26}({KA_STR[beau_ka%26]})")

# Are the Vig/Beau differences meaningful?
vig_diffs_az = [(AZ_IDX[pl] - AZ_IDX[kl]) % 26 for kl, pl in zip(KRYPTOS_LETTERS, PALETTE_LETTERS)]
beau_diffs_az = [(AZ_IDX[pl] + AZ_IDX[kl]) % 26 for kl, pl in zip(KRYPTOS_LETTERS, PALETTE_LETTERS)]
vig_diffs_ka = [(KA_IDX[pl] - KA_IDX[kl]) % 26 for kl, pl in zip(KRYPTOS_LETTERS, PALETTE_LETTERS)]
beau_diffs_ka = [(KA_IDX[pl] + KA_IDX[kl]) % 26 for kl, pl in zip(KRYPTOS_LETTERS, PALETTE_LETTERS)]

vig_text_az = ''.join(AZ[d] for d in vig_diffs_az)
beau_text_az = ''.join(AZ[d] for d in beau_diffs_az)
vig_text_ka = ''.join(KA_STR[d] for d in vig_diffs_ka)
beau_text_ka = ''.join(KA_STR[d] for d in beau_diffs_ka)

print(f"\n  KRYPTOS->Palette Vig AZ keys: {vig_diffs_az} = '{vig_text_az}'")
print(f"  KRYPTOS->Palette Beau AZ keys: {beau_diffs_az} = '{beau_text_az}'")
print(f"  KRYPTOS->Palette Vig KA keys: {vig_diffs_ka} = '{vig_text_ka}'")
print(f"  KRYPTOS->Palette Beau KA keys: {beau_diffs_ka} = '{beau_text_ka}'")

results["test1"] = {
    "vig_diffs_az": vig_diffs_az, "beau_diffs_az": beau_diffs_az,
    "vig_text_az": vig_text_az, "beau_text_az": beau_text_az,
    "vig_diffs_ka": vig_diffs_ka, "beau_diffs_ka": beau_diffs_ka,
    "vig_text_ka": vig_text_ka, "beau_text_ka": beau_text_ka,
}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 2: PALETTE AS CIPHER OUTPUT
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 2: PALETTE AS CIPHER OUTPUT")
print("=" * 72)
print()

test2_hits = []

for kw in KEYWORDS + ["BGIKOW", "BGIKWZ", "BGIKOWZ", "FIVE", "SEVEN", "SHADOW", "YAR", "NDYAHR"]:
    if len(kw) > 7:
        continue  # Palette has 7 letters, skip longer keywords
    kw_upper = kw.upper()
    kw_set = frozenset(kw_upper)

    for variant_name, enc_fn in [
        ("vig_AZ", lambda p, k: (p + k) % 26),
        ("beau_AZ", lambda p, k: (k - p) % 26),
        ("vbeau_AZ", lambda p, k: (p - k) % 26),
    ]:
        # Encrypt kw with key KRYPTOS
        key = "KRYPTOS"
        key_ext = (key * ((len(kw_upper)//len(key)) + 1))[:len(kw_upper)]
        enc = []
        for p_c, k_c in zip(kw_upper, key_ext):
            enc.append(enc_fn(AZ_IDX[p_c], AZ_IDX[k_c]))
        enc_str = ''.join(AZ[v] for v in enc)
        enc_set = frozenset(enc_str)
        if enc_set.issubset(PALETTE):
            hit = f"Enc({kw},{key},{variant_name})={enc_str} SUBSET of palette"
            print(f"  {hit}")
            test2_hits.append(hit)

        # Encrypt KRYPTOS with kw as key (if kw length == 7)
        if len(kw_upper) == 7:
            key_ext2 = kw_upper
            enc2 = []
            for p_c, k_c in zip("KRYPTOS", key_ext2):
                enc2.append(enc_fn(AZ_IDX[p_c], AZ_IDX[k_c]))
            enc2_str = ''.join(AZ[v] for v in enc2)
            enc2_set = frozenset(enc2_str)
            if enc2_set.issubset(PALETTE) or enc2_set == PALETTE:
                hit = f"Enc(KRYPTOS,{kw},{variant_name})={enc2_str} {'EXACT' if enc2_set==PALETTE else 'SUBSET'}"
                print(f"  {hit}")
                test2_hits.append(hit)

    # All 26 Caesar shifts of kw
    for shift in range(26):
        shifted = ''.join(AZ[(AZ_IDX[c] + shift) % 26] for c in kw_upper)
        if frozenset(shifted).issubset(PALETTE):
            hit = f"Caesar({kw},+{shift})={shifted} SUBSET"
            if frozenset(shifted) == PALETTE:
                hit = f"Caesar({kw},+{shift})={shifted} EXACT MATCH"
            print(f"  {hit}")
            test2_hits.append(hit)

# Decrypt palette as plaintext with various keys
print("\n  Decrypting 'BGIKOWZ' with various keys:")
pal_str = "BGIKOWZ"
for key_str in ["KRYPTOS", "DEFECTOR", "ABSCISSA", "KOMPASS"]:
    key_ext = (key_str * 2)[:7]
    for variant_name, dec_fn in [
        ("vig_AZ", lambda c, k: (c - k) % 26),
        ("beau_AZ", lambda c, k: (k - c) % 26),
    ]:
        dec = ''.join(AZ[dec_fn(AZ_IDX[c], AZ_IDX[k])] for c, k in zip(pal_str, key_ext))
        # Check if result is meaningful
        print(f"    Dec({pal_str},{key_str[:7]},{variant_name}) = {dec}")

results["test2"] = {"hits": test2_hits}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 3: MODULAR PATTERNS — SYSTEMATIC
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 3: MODULAR PATTERNS — SYSTEMATIC")
print("=" * 72)
print()

test3_findings = []

for label, vals in [("AZ", PAL_AZ), ("KA", PAL_KA)]:
    print(f"\n--- {label} values: {vals} ---")
    val_set = set(vals)

    for mod_n in range(2, 27):
        residues = [v % mod_n for v in vals]
        residue_set = set(residues)
        n_residues = len(residue_set)
        coverage_pct = n_residues / mod_n * 100

        if n_residues <= 3:
            finding = f"  {label} mod {mod_n}: ONLY {n_residues} residues {sorted(residue_set)} from {residues}"
            print(finding)
            test3_findings.append(finding)
        elif n_residues == mod_n and mod_n <= 7:
            print(f"  {label} mod {mod_n}: ALL residues covered ({mod_n}/{mod_n})")

    # Check pairwise differences mod various N
    diffs = sorted(set((vals[j] - vals[i]) % 26 for i in range(7) for j in range(7) if i != j))
    print(f"\n  {label} pairwise diffs mod 26: {diffs}")

    # Check if vals form an arithmetic progression mod any N
    for mod_n in range(7, 27):
        for step in range(1, mod_n):
            for start in range(mod_n):
                ap = set((start + i * step) % mod_n for i in range(7))
                if ap == val_set or (mod_n == 26 and ap == {v % 26 for v in vals}):
                    if mod_n > 7:  # Non-trivial
                        finding = f"  {label} mod {mod_n}: AP start={start} step={step}"
                        print(finding)
                        test3_findings.append(finding)

    # Specific check: mod 5 for AZ values
    if label == "AZ":
        r5 = [v % 5 for v in vals]
        print(f"\n  AZ mod 5: {r5} -> only {len(set(r5))} distinct: {sorted(set(r5))}")
        # {0,0,3,3,0,3,0} -> 4 zeros, 3 threes
        if set(r5) == {0, 3}:
            note("  *** AZ mod 5 uses ONLY residues {0, 3}! ***")
            # Which letters are mod 5 == 0? B(1)->1%5=1 NO. Recalculate.
            for c in PALETTE_LETTERS:
                v = AZ_IDX[c]
                print(f"    {c}={v}: {v} mod 5 = {v%5}")

    # Specific check for KA
    if label == "KA":
        print(f"\n  KA consecutive diffs: {[vals[i+1]-vals[i] for i in range(6)]}")
        print(f"  KA sorted: {vals}")

# Check: palette values as a coset of a subgroup of Z_26
print("\n--- Subgroup/coset analysis ---")
for d in [2, 13]:  # Subgroups of Z_26 have orders dividing 26: 1,2,13,26
    subgroup = set(range(0, 26, d))  # Not quite right, let me use actual subgroups
    # Z_26 subgroups: {0}, {0,13}, Z_26 itself (and no others, since 26=2*13)
    pass

# {0,13} is the only nontrivial subgroup of Z_26
subgroup = {0, 13}
for coset_shift in range(13):
    coset = {(v + coset_shift) % 26 for v in subgroup}
    hits = coset & set(PAL_AZ)
    if len(hits) >= 2:
        print(f"  Z_26 subgroup {{0,13}} + {coset_shift}: coset={sorted(coset)}, palette hits={sorted(hits)}")

results["test3"] = test3_findings
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 4: BINARY/SET-THEORETIC PROPERTIES
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 4: BINARY/SET-THEORETIC PROPERTIES")
print("=" * 72)
print()

# 4a) Palette vs crib letters
ene_letters = frozenset(ENE_WORD)
bcl_letters = frozenset(BCL_WORD)
crib_letters = ene_letters | bcl_letters
print(f"ENE letters: {sorted(ene_letters)} ({len(ene_letters)})")
print(f"BCL letters: {sorted(bcl_letters)} ({len(bcl_letters)})")
print(f"All crib letters: {sorted(crib_letters)} ({len(crib_letters)})")
print(f"Palette: {sorted(PALETTE)} ({len(PALETTE)})")
print()
print(f"Palette & ENE: {sorted(PALETTE & ene_letters)}")
print(f"Palette & BCL: {sorted(PALETTE & bcl_letters)}")
print(f"Palette & cribs: {sorted(PALETTE & crib_letters)}")
print(f"Palette - cribs: {sorted(PALETTE - crib_letters)}")
print(f"Cribs - palette: {sorted(crib_letters - PALETTE)}")
print()

# 4b) Complement analysis
complement = frozenset(AZ) - PALETTE
comp_letters = sorted(complement)
print(f"Complement (19 letters): {''.join(comp_letters)}")
print(f"Complement & ENE: {sorted(complement & ene_letters)} ({len(complement & ene_letters)}/{len(ene_letters)})")
print(f"Complement & BCL: {sorted(complement & bcl_letters)} ({len(complement & bcl_letters)}/{len(bcl_letters)})")
print(f"Complement contains ALL ENE letters? {ene_letters.issubset(complement)}")
print(f"Complement contains ALL BCL letters? {bcl_letters.issubset(complement)}")
print()

# 4c) Odd/even appearance counts in various texts
print("--- 4c: Odd/even count analysis ---")
for text_name, text in [("CT97", CT97), ("ENE", ENE_WORD), ("BCL", BCL_WORD),
                         ("ENE+BCL", ENE_WORD+BCL_WORD), ("KA", KA_STR), ("KRYPTOS", "KRYPTOS")]:
    cnt = Counter(text)
    odd_letters = frozenset(c for c in cnt if cnt[c] % 2 == 1)
    even_letters = frozenset(c for c in cnt if cnt[c] % 2 == 0 and c in set(AZ))
    if odd_letters == PALETTE:
        note(f"  *** {text_name}: ODD-count letters = PALETTE! ***")
    elif even_letters == PALETTE:
        note(f"  *** {text_name}: EVEN-count letters = PALETTE! ***")
    else:
        print(f"  {text_name}: odd-count={sorted(odd_letters)}, even-count={sorted(even_letters)}")

# 4d) Letters NOT in EASTNORTHEAST
ene_missing = frozenset(AZ) - ene_letters
print(f"\nLetters NOT in EASTNORTHEAST: {sorted(ene_missing)} ({len(ene_missing)})")
print(f"Palette subset of ENE-missing? {PALETTE.issubset(ene_missing)}")  # O is in both

# 4e) Letters NOT in BERLINCLOCK
bcl_missing = frozenset(AZ) - bcl_letters
print(f"Letters NOT in BERLINCLOCK: {sorted(bcl_missing)} ({len(bcl_missing)})")
print(f"Palette subset of BCL-missing? {PALETTE.issubset(bcl_missing)}")  # B,I,K,O are in both

# 4f) XOR of palette AZ values
xor_val = 0
for v in PAL_AZ:
    xor_val ^= v
print(f"\nXOR of palette AZ values: {xor_val} = {AZ[xor_val]} ({xor_val:05b})")

# 4g) Product mod 26
prod = 1
for v in PAL_AZ:
    prod = (prod * v) % 26
print(f"Product of palette AZ values mod 26: {prod}")
prod_ka = 1
for v in PAL_KA:
    if v > 0:
        prod_ka = (prod_ka * v) % 26
print(f"Product of non-zero palette KA values mod 26: {prod_ka}")

print()

# ══════════════════════════════════════════════════════════════════════
# TEST 5: POLYBIUS/GRID RELATIONSHIPS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 5: POLYBIUS/GRID RELATIONSHIPS")
print("=" * 72)
print()

# 5a) 5x5 Polybius (KRYPTOS-keyed, I/J merged)
# Even though K4 uses all 26 letters, the palette itself uses only 7
ka_no_j = KA_STR.replace('J', '')  # Remove J for 5x5
print("5x5 Polybius (KRYPTOS-keyed, J removed):")
for row in range(5):
    row_letters = [ka_no_j[row*5+col] for col in range(5)]
    palette_marks = ['*' if c in PALETTE else '.' for c in row_letters]
    print(f"  Row {row}: {' '.join(row_letters)}  {' '.join(palette_marks)}")
# Report positions
for c in PALETTE_LETTERS:
    if c in ka_no_j:
        idx = ka_no_j.index(c)
        r, co = idx // 5, idx % 5
        print(f"  {c} at ({r},{co})")
    elif c == 'J':
        print(f"  J merged with I")

# 5b) Full 26-letter grid layouts
print(f"\n5x6 grid (5 rows, 6 cols, leftover in last row):")
for n_cols in [5, 6, 7, 8, 9, 13]:
    n_rows_grid = (26 + n_cols - 1) // n_cols
    print(f"\n  {n_rows_grid}x{n_cols} grid of KA:")
    for row in range(n_rows_grid):
        row_letters = [KA_STR[row*n_cols+col] if row*n_cols+col < 26 else ' ' for col in range(n_cols)]
        palette_marks = ['*' if c in PALETTE else '.' for c in row_letters]
        row_str = ' '.join(f"{c}{m}" for c, m in zip(row_letters, palette_marks))
        print(f"    Row {row}: {row_str}")

    # Check if palette occupies specific rows or columns
    pal_rows = set()
    pal_cols = set()
    for c in PALETTE_LETTERS:
        if c in KA_STR:
            idx = KA_IDX[c]
            pal_rows.add(idx // n_cols)
            pal_cols.add(idx % n_cols)
    print(f"    Palette rows: {sorted(pal_rows)}, Palette cols: {sorted(pal_cols)}")
    if len(pal_rows) == 1:
        note(f"    *** All palette letters in row {list(pal_rows)[0]} of {n_rows_grid}x{n_cols} KA grid! ***")
    if len(pal_cols) == 1:
        note(f"    *** All palette letters in col {list(pal_cols)[0]} of {n_rows_grid}x{n_cols} KA grid! ***")
    # Check diagonal
    pal_diags = set()
    for c in PALETTE_LETTERS:
        idx = KA_IDX[c]
        r, co = idx // n_cols, idx % n_cols
        pal_diags.add(r - co)  # main diagonal
    if len(pal_diags) == 1:
        note(f"    *** All palette on single diagonal of {n_rows_grid}x{n_cols} KA grid! ***")

# 5c) AZ grid
print(f"\nAZ grids:")
for n_cols in [5, 6, 7, 13]:
    n_rows_grid = (26 + n_cols - 1) // n_cols
    pal_rows = set()
    pal_cols = set()
    for c in PALETTE_LETTERS:
        idx = AZ_IDX[c]
        pal_rows.add(idx // n_cols)
        pal_cols.add(idx % n_cols)
    print(f"  {n_rows_grid}x{n_cols} AZ: pal_rows={sorted(pal_rows)}, pal_cols={sorted(pal_cols)}")

print()

# ══════════════════════════════════════════════════════════════════════
# TEST 6: DEFECTOR CONNECTION
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 6: DEFECTOR CONNECTION")
print("=" * 72)
print()

DEFECTOR = "DEFECTOR"
def_az = [AZ_IDX[c] for c in DEFECTOR]
def_ka = [KA_IDX[c] for c in DEFECTOR]
print(f"DEFECTOR AZ: {def_az}")
print(f"DEFECTOR KA: {def_ka}")
print(f"Palette AZ: {PAL_AZ}")
print(f"Palette KA: {PAL_KA}")
print()

# 6a) Differences palette - DEFECTOR (cycling)
print("--- 6a: Palette[i] - DEFECTOR[i mod 8] ---")
for label, p_vals, d_vals in [("AZ", PAL_AZ, def_az), ("KA", PAL_KA, def_ka)]:
    diffs = [(p_vals[i] - d_vals[i % len(d_vals)]) % 26 for i in range(7)]
    print(f"  {label}: diffs = {diffs}")
    if len(set(diffs)) == 1:
        note(f"  *** {label}: CONSTANT difference {diffs[0]}! ***")

# 6b) Autokey encrypt DEFECTOR with itself
print("\n--- 6b: Autokey encrypt ---")
for variant_name, enc_fn in [("vig", lambda p,k: (p+k)%26), ("beau", lambda p,k: (k-p)%26)]:
    pt = def_az
    key = list(def_az)
    ct = []
    for i in range(len(pt)):
        c = enc_fn(pt[i], key[i % len(key)])
        ct.append(c)
    ct_str = ''.join(AZ[v] for v in ct)
    ct_set = frozenset(ct_str)
    print(f"  Autokey({DEFECTOR},{DEFECTOR},{variant_name}) = {ct_str}")
    if ct_set.issubset(PALETTE):
        note(f"  *** DEFECTOR autokey output is palette subset! ***")

# 6c) Every 7-letter subset of DEFECTOR(8) -> any match palette?
print("\n--- 6c: 7/8 DEFECTOR subsets ---")
for skip in range(8):
    subset = [def_az[i] for i in range(8) if i != skip]
    subset_letters = [DEFECTOR[i] for i in range(8) if i != skip]
    # Check if sorted subset values == PAL_AZ
    if sorted(subset) == PAL_AZ:
        note(f"  *** DEFECTOR minus position {skip} ({DEFECTOR[skip]}) has same AZ values as palette! ***")
    # Check affine transform
    for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
        for b in range(26):
            transformed = sorted((a * v + b) % 26 for v in subset)
            if transformed == PAL_AZ:
                note(f"  DEFECTOR\\{skip} * {a} + {b} mod 26 = palette AZ!")

# 6d) Map DEFECTOR through KA permutation
print("\n--- 6d: DEFECTOR through AZ->KA permutation ---")
def_ka_mapped = [KA_IDX[c] for c in DEFECTOR]
print(f"  DEFECTOR -> KA indices: {def_ka_mapped}")
# Reverse: palette letters -> KA^-1 = AZ positions
pal_ka_inv = [KA_STR[v] for v in PAL_AZ]
print(f"  Palette AZ values as KA indices -> letters: {pal_ka_inv}")
pal_az_from_ka = [AZ_IDX[KA_STR[v]] for v in PAL_KA]
print(f"  Palette KA values -> KA letters -> AZ values: {pal_az_from_ka}")

results["test6"] = {"defector_az": def_az, "defector_ka": def_ka}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 7: KRYPTOS -> PALETTE MAPPING
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 7: KRYPTOS -> PALETTE MAPPING (7 letters each)")
print("=" * 72)
print()

# 7a) All 7! = 5040 permuted mappings KRYPTOS -> BGIKOWZ
print("--- 7a: Searching for affine/simple mappings KRYPTOS -> PALETTE ---")
kryptos_az = [AZ_IDX[c] for c in "KRYPTOS"]
kryptos_ka = [KA_IDX[c] for c in "KRYPTOS"]

# For each permutation of palette, check if there's an affine map
found_affine = False
for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
    for b in range(26):
        mapped = [(a * v + b) % 26 for v in kryptos_az]
        if set(mapped) == set(PAL_AZ):
            print(f"  AZ affine: {a}*KRYPTOS+{b} mod 26 -> {[AZ[m] for m in mapped]} ({''.join(AZ[m] for m in mapped)})")
            note(f"  AZ affine a={a} b={b} maps KRYPTOS to palette letters!")
            found_affine = True

# Same in KA
for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
    for b in range(26):
        mapped = [(a * v + b) % 26 for v in kryptos_ka]
        if set(mapped) == set(PAL_KA):
            print(f"  KA affine: {a}*KRYPTOS+{b} mod 26 -> {[KA_STR[m] for m in mapped]} ({''.join(KA_STR[m] for m in mapped)})")
            note(f"  KA affine a={a} b={b} maps KRYPTOS to palette letters!")
            found_affine = True

if not found_affine:
    print("  No affine mapping found (neither AZ nor KA)")

# 7b) Check multiplicative relationships
print("\n--- 7b: Element-wise relationships ---")
print("  KA indices: KRYPTOS = [0,1,2,3,4,5,6] (identity!)")
print("  KA palette = [0,5,8,13,15,23,25]")
print()
# KRYPTOS letters have KA indices 0-6 (they ARE the first 7 letters of KA!)
# So the question reduces to: what maps {0,1,2,3,4,5,6} -> {0,5,8,13,15,23,25}?
for a in range(1, 26):
    for b in range(26):
        mapped = [(a * i + b) % 26 for i in range(7)]
        if set(mapped) == set(PAL_KA):
            note(f"  *** KA: {a}*i + {b} mod 26 for i=0..6 -> palette KA positions! ***")
            print(f"    Mapping: {[(i, (a*i+b)%26) for i in range(7)]}")

# Quadratic?
print("\n  Trying quadratic: a*i^2 + b*i + c mod 26 for i=0..6:")
quad_hits = 0
for a in range(26):
    for b in range(26):
        for c in range(26):
            mapped = [(a * i * i + b * i + c) % 26 for i in range(7)]
            if set(mapped) == set(PAL_KA) and len(set(mapped)) == 7:
                if quad_hits < 10:
                    print(f"    {a}*i^2 + {b}*i + {c} mod 26: {mapped}")
                quad_hits += 1
if quad_hits == 0:
    print("    No quadratic mapping found")
else:
    print(f"    Total quadratic hits: {quad_hits}")

# Check specific polynomial: palette_KA[i] = 0,5,8,13,15,23,25 for i=0..6
# Differences: 5,3,5,2,8,2
# Second differences: -2,2,-3,6,-6
# Not constant -> not quadratic
pal_ka_diffs = [PAL_KA[i+1] - PAL_KA[i] for i in range(6)]
pal_ka_diffs2 = [pal_ka_diffs[i+1] - pal_ka_diffs[i] for i in range(5)]
print(f"\n  Palette KA first diffs: {pal_ka_diffs}")
print(f"  Palette KA second diffs: {pal_ka_diffs2}")

results["test7"] = {"quad_hits": quad_hits}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 8: POSITION-DEPENDENT GENERATION (f(position) -> char)
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 8: POSITION-DEPENDENT GENERATION")
print("=" * 72)
print()

pos = CONSENSUS_NULLS
chars_az = CONSENSUS_AZ

# 8a) Linear: char = (a * pos + b) mod 26
print("--- 8a: Linear formula char = (a*pos + b) mod 26 ---")
best_linear = (0, 0, 0)  # (a, b, matches)
for a in range(26):
    for b in range(26):
        matches = sum(1 for p, c in zip(pos, chars_az) if (a * p + b) % 26 == c)
        if matches > best_linear[2]:
            best_linear = (a, b, matches)
            if matches >= 8:
                predicted = [(a * p + b) % 26 for p in pos]
                print(f"  a={a}, b={b}: {matches}/17 matches")
                # Show which match
                for p, c, pred in zip(pos, chars_az, predicted):
                    mark = "OK" if c == pred else "MISS"
                    print(f"    pos={p:2d}: actual={AZ[c]}({c}), pred={AZ[pred]}({pred}) {mark}")
print(f"  Best linear: a={best_linear[0]}, b={best_linear[1]}, {best_linear[2]}/17 matches")

# 8b) char = CT[(pos + offset) mod 97]
print("\n--- 8b: char = CT[(pos + offset) mod 97] ---")
best_ct_offset = (0, 0)
for offset in range(97):
    matches = sum(1 for p, c in zip(pos, chars_az) if AZ_IDX[CT97[(p + offset) % 97]] == c)
    if matches > best_ct_offset[1]:
        best_ct_offset = (offset, matches)
        if matches >= 6:
            print(f"  offset={offset}: {matches}/17 matches")
print(f"  Best CT offset: offset={best_ct_offset[0]}, {best_ct_offset[1]}/17 matches")

# 8c) char = KEYWORD[pos mod len(keyword)]
print("\n--- 8c: char = KEYWORD[pos mod len(kw)] ---")
for kw in KEYWORDS + ["BGIKOWZ", "KRYPTOS"]:
    kw_upper = kw.upper()
    kw_az = [AZ_IDX[c] for c in kw_upper]
    L = len(kw_az)
    matches = sum(1 for p, c in zip(pos, chars_az) if kw_az[p % L] == c)
    if matches >= 5:
        predicted = [kw_az[p % L] for p in pos]
        print(f"  {kw} (L={L}): {matches}/17 matches")
        for p, c, pred in zip(pos, chars_az, predicted):
            mark = "OK" if c == pred else "miss"
            print(f"    pos={p:2d} mod {L} = {p%L}: actual={AZ[c]}, pred={AZ[pred]} {mark}")

# 8d) char = KEYWORD[pos mod len(keyword)] through KA
print("\n--- 8d: char = KA_KEYWORD[pos mod len(kw)] ---")
for kw in KEYWORDS + ["BGIKOWZ", "KRYPTOS"]:
    kw_upper = kw.upper()
    kw_ka = [KA_IDX[c] for c in kw_upper]
    L = len(kw_ka)
    # Map consensus chars to KA
    chars_ka = [KA_IDX[c] for c in CONSENSUS_CHARS]
    matches = sum(1 for p, c in zip(pos, chars_ka) if kw_ka[p % L] == c)
    if matches >= 5:
        print(f"  {kw} (L={L}) via KA: {matches}/17 matches")

# 8e) char = position-dependent function involving neighbors
print("\n--- 8e: Neighbor-based formulas ---")
for p, c in zip(pos, chars_az):
    left = AZ_IDX[CT97[p-1]] if p > 0 else None
    right = AZ_IDX[CT97[p+1]] if p < 96 else None
    neighbors = []
    if left is not None and right is not None:
        mean = (left + right) / 2
        xor = left ^ right
        add = (left + right) % 26
        sub = (left - right) % 26
        neighbors.append((mean, xor, add, sub))
        if abs(mean - c) < 0.01:
            print(f"  pos={p}: char={AZ[c]}={c}, left={AZ[left]}={left}, right={AZ[right]}={right}, MEAN MATCH!")
        if xor == c:
            print(f"  pos={p}: char={AZ[c]}={c}, left={AZ[left]}={left}, right={AZ[right]}={right}, XOR MATCH!")
        if add == c:
            print(f"  pos={p}: char={AZ[c]}={c}, left={AZ[left]}={left}, right={AZ[right]}={right}, SUM MATCH!")

# 8f) Beaufort/Vigenere with position-cycling key
print("\n--- 8f: char = Enc(CT_neighbor, position-derived key) ---")
# What if null char = (CT[pos-1] + CT[pos+1]) mod 26? (average of neighbors)
# Or char = Beaufort_key(position) applied to some constant?
for key_source in ["KRYPTOS", "DEFECTOR"]:
    key_az = [AZ_IDX[c] for c in key_source]
    L = len(key_az)
    # char = Vig(constant, key[pos mod L]) -> char = (constant + key[pos mod L]) mod 26
    for constant in range(26):
        matches = sum(1 for p, c in zip(pos, chars_az) if (constant + key_az[p % L]) % 26 == c)
        if matches >= 8:
            print(f"  Vig({AZ[constant]}, {key_source}[pos mod {L}]): {matches}/17")
    # char = Beau(constant, key[pos mod L]) -> char = (key[pos mod L] - constant) mod 26
    for constant in range(26):
        matches = sum(1 for p, c in zip(pos, chars_az) if (key_az[p % L] - constant) % 26 == c)
        if matches >= 8:
            print(f"  Beau({AZ[constant]}, {key_source}[pos mod {L}]): {matches}/17")

results["test8"] = {"best_linear": best_linear, "best_ct_offset": best_ct_offset}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 9: PALETTE AS BEAUFORT/VIGENERE OF NULL POSITIONS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 9: PALETTE CHARS AS CIPHER OF POSITIONS")
print("=" * 72)
print()

# 9a) For each (pos, char) pair, compute "implied key" under various ciphers
print("--- 9a: Implied keys ---")
for cipher_name, key_fn in [
    ("Vig: key = char - pos", lambda c, p: (c - p) % 26),
    ("Beau: key = char + pos", lambda c, p: (c + p) % 26),
    ("VBeau: key = pos - char", lambda c, p: (p - c) % 26),
]:
    keys = [key_fn(c, p) for p, c in zip(pos, chars_az)]
    key_str = ''.join(AZ[k] for k in keys)
    print(f"  {cipher_name}: keys = {keys}")
    print(f"    = '{key_str}'")
    # Check if keys cycle with period P
    for period in range(1, 10):
        if all(keys[i] == keys[i % period] for i in range(len(keys))):
            note(f"    *** Period-{period} key! ***")
    # Check if keys match a keyword
    for kw in KEYWORDS:
        kw_az = [AZ_IDX[c] for c in kw]
        kw_L = len(kw_az)
        matches = sum(1 for i, (p, k) in enumerate(zip(pos, keys)) if kw_az[p % kw_L] == k)
        if matches >= 8:
            print(f"    Matches {kw}[pos mod {kw_L}] at {matches}/17 positions")

# 9b) char = (a * pos) mod 26 for all a coprime to 26
print("\n--- 9b: char = (a * pos) mod 26, a coprime to 26 ---")
for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
    matches = sum(1 for p, c in zip(pos, chars_az) if (a * p) % 26 == c)
    if matches >= 4:
        predicted = [(a * p) % 26 for p in pos]
        actual_vs_pred = [(p, AZ[c], AZ[predicted[i]]) for i, (p, c) in enumerate(zip(pos, chars_az))]
        print(f"  a={a}: {matches}/17 matches")

# 9c) char = (a * pos + b) mod 26, position is grid coordinate
print("\n--- 9c: Grid-coordinate-based formulas ---")
for p_idx, (p, c) in enumerate(zip(pos, chars_az)):
    linear = K4_START_COL + K4_START_ROW * GRID_WIDTH + p
    row = linear // GRID_WIDTH
    col = linear % GRID_WIDTH
    k4_row = p // GRID_WIDTH  # row within K4 (0-based)
    k4_col = p % GRID_WIDTH if p < GRID_WIDTH * 3 else p - GRID_WIDTH * 3  # simplified

# Try: char = f(col) or char = f(row) or char = f(row+col) etc.
best_grid = (0, "", "")
for func_name, func in [
    ("col%26", lambda r,c: c % 26),
    ("row%26", lambda r,c: r % 26),
    ("(r+c)%26", lambda r,c: (r+c) % 26),
    ("(r-c)%26", lambda r,c: (r-c) % 26),
    ("(r*c)%26", lambda r,c: (r*c) % 26),
    ("(r^c)%26", lambda r,c: (r^c) % 26),
    ("(r*7+c)%26", lambda r,c: (r*7+c) % 26),
    ("(c*4+r)%26", lambda r,c: (c*4+r) % 26),
]:
    matches = 0
    for p, c in zip(pos, chars_az):
        linear = K4_START_COL + K4_START_ROW * GRID_WIDTH + p
        row = linear // GRID_WIDTH
        col = linear % GRID_WIDTH
        pred = func(row, col)
        if pred == c:
            matches += 1
    if matches > best_grid[0]:
        best_grid = (matches, func_name, "")
    if matches >= 5:
        print(f"  {func_name}: {matches}/17 matches")

print(f"  Best grid formula: {best_grid[1]} with {best_grid[0]}/17")

results["test9"] = {}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 10: BOTH A=0 AND A=1 COMPREHENSIVE
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 10: COMPREHENSIVE A=0 vs A=1 MODULAR ANALYSIS")
print("=" * 72)
print()

for base_name, offset in [("A=0", 0), ("A=1", 1)]:
    vals = [AZ_IDX[c] + offset for c in PALETTE_LETTERS]
    val_set = set(v % 26 for v in vals)  # Keep mod 26 for A=1 where Z=26
    print(f"\n{base_name} values: {vals}")

    # Find ALL moduli where residue count <= 3
    low_residue = []
    for mod_n in range(2, 30):
        residues = set(v % mod_n for v in vals)
        if len(residues) <= 3:
            low_residue.append((mod_n, sorted(residues), len(residues)))

    if low_residue:
        print(f"  Moduli with <= 3 residues:")
        for mod_n, res, count in low_residue:
            print(f"    mod {mod_n}: {count} residues: {res}")
    else:
        print(f"  No moduli with <= 3 residues found (range 2-29)")

# Special investigation: AZ mod 5
print("\n--- Special: AZ values mod 5 ---")
print(f"  B(1)%5={1%5}, G(6)%5={6%5}, I(8)%5={8%5}, K(10)%5={10%5}, O(14)%5={14%5}, W(22)%5={22%5}, Z(25)%5={25%5}")
# 1,1,3,0,4,2,0 -> residues {0,1,2,3,4} = all 5! Correction: let me recompute
az_mod5 = {c: AZ_IDX[c] % 5 for c in PALETTE_LETTERS}
print(f"  Actual: {az_mod5}")
print(f"  Distinct: {sorted(set(az_mod5.values()))}")

# A=1 mod 5
a1_mod5 = {c: (AZ_IDX[c]+1) % 5 for c in PALETTE_LETTERS}
print(f"  A=1 mod 5: {a1_mod5}")
print(f"  Distinct: {sorted(set(a1_mod5.values()))}")

results["test10"] = {}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 11: AFFINE INVERSE SEARCH
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 11: AFFINE INVERSE SEARCH")
print("=" * 72)
print()

# For each affine transform (a,b) with gcd(a,26)=1:
# Compute source = {(a_inv * (p - b)) mod 26 : p in palette_AZ}
# Check if source matches any known set

known_sets = {}
# Build known sets
for kw in KEYWORDS + ["KRYPTOS", "DEFECTOR", "ABSCISSA", "NDYAHR", "ENDYAHR"]:
    kw_upper = kw.upper()
    known_sets[kw] = frozenset(AZ_IDX[c] for c in kw_upper)

# Also some structural sets
known_sets["first7_AZ"] = frozenset(range(7))
known_sets["last7_AZ"] = frozenset(range(19, 26))
known_sets["evens_0to12"] = frozenset(range(0, 13, 2))
known_sets["odds_1to13"] = frozenset(range(1, 14, 2))
known_sets["consecutive_0to6"] = frozenset(range(7))
known_sets["consecutive_10to16"] = frozenset(range(10, 17))

# Compute modular inverse
def modinv(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

pal_az_set = frozenset(PAL_AZ)
affine_hits = []

print("Searching for source sets that map to palette under affine transform...")
for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
    a_inv = modinv(a)
    for b in range(26):
        source = frozenset((a_inv * (p - b)) % 26 for p in PAL_AZ)
        for name, known in known_sets.items():
            if source == known:
                affine_hits.append((a, b, name, sorted(source)))
                print(f"  Affine ({a}*x + {b}) mod 26: source = {name} {sorted(source)} -> palette")

if not affine_hits:
    print("  No affine mapping from any known set to palette found.")

# Also check: palette -> known set
print("\nChecking palette -> known set:")
for a in [1,3,5,7,9,11,15,17,19,21,23,25]:
    for b in range(26):
        dest = frozenset((a * p + b) % 26 for p in PAL_AZ)
        for name, known in known_sets.items():
            if dest == known:
                print(f"  Affine ({a}*palette + {b}) mod 26 = {name}")

results["test11"] = {"affine_hits": [(a,b,n) for a,b,n,_ in affine_hits]}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 12: 35 PALETTE POSITIONS — 17 NULL vs 18 NON-NULL
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 12: WHAT DISTINGUISHES 17 NULL FROM 18 NON-NULL PALETTE POSITIONS?")
print("=" * 72)
print()

null_set = set(CONSENSUS_NULLS)
print(f"All 35 palette-character positions in CT97:")
print(f"  17 NULL positions: {CONSENSUS_NULLS}")
print(f"  18 NON-NULL positions: {NONNULL_PALETTE_POS}")
print()

# 12a) Grid coordinates
print("--- 12a: Grid coordinates (28x31) ---")
print(f"  {'Pos':>3} {'Char':>4} {'Null?':>5} {'Row':>3} {'Col':>3} {'K4row':>5} {'K4col':>5}")
k4_null_rows = []
k4_null_cols = []
k4_nonnull_rows = []
k4_nonnull_cols = []

for p in ALL_PALETTE_POS:
    char = CT97[p]
    is_null = p in null_set
    linear = K4_START_COL + K4_START_ROW * GRID_WIDTH + p
    row = linear // GRID_WIDTH
    col = linear % GRID_WIDTH
    k4_row = (K4_START_COL + p) // GRID_WIDTH  # row offset within K4
    k4_col = (K4_START_COL + p) % GRID_WIDTH

    print(f"  {p:3d} {char:>4} {'NULL' if is_null else '    ':>5} {row:3d} {col:3d} {k4_row:5d} {k4_col:5d}")

    if is_null:
        k4_null_rows.append(row)
        k4_null_cols.append(col)
    else:
        k4_nonnull_rows.append(row)
        k4_nonnull_cols.append(col)

print(f"\n  Null grid rows: {k4_null_rows}")
print(f"  Null grid cols: {k4_null_cols}")
print(f"  Non-null grid rows: {k4_nonnull_rows}")
print(f"  Non-null grid cols: {k4_nonnull_cols}")

# Row distribution
null_row_counter = Counter(k4_null_rows)
nonnull_row_counter = Counter(k4_nonnull_rows)
print(f"\n  Null by row: {dict(null_row_counter)}")
print(f"  Non-null by row: {dict(nonnull_row_counter)}")

# Column distribution
null_col_counter = Counter(k4_null_cols)
nonnull_col_counter = Counter(k4_nonnull_cols)
print(f"  Null by col: {dict(sorted(null_col_counter.items()))}")
print(f"  Non-null by col: {dict(sorted(nonnull_col_counter.items()))}")

# 12b) Position mod various N
print("\n--- 12b: Position modular analysis ---")
for mod_n in [2, 3, 5, 7, 8, 13, 14, 24, 31]:
    null_residues = Counter(p % mod_n for p in CONSENSUS_NULLS if CT97[p] in PALETTE)
    nonnull_residues = Counter(p % mod_n for p in NONNULL_PALETTE_POS)
    # Check if nulls concentrate in specific residues
    null_res_set = set(null_residues.keys())
    nonnull_res_set = set(nonnull_residues.keys())
    null_only = null_res_set - nonnull_res_set
    nonnull_only = nonnull_res_set - null_res_set
    if null_only or nonnull_only:
        print(f"  mod {mod_n}: null-only residues={sorted(null_only)}, nonnull-only={sorted(nonnull_only)}")

# 12c) Col7 column assignment
print("\n--- 12c: Col7 column assignment ---")
# In col7 transposition of 73 chars: which column does each palette position land in?
# But first, we need to map 97-pos to 73-pos (after null removal)
# Use mask 0 for this analysis
mask0 = set(MASKS_15[0])
pos_97_to_73 = {}
j = 0
for i in range(97):
    if i not in mask0:
        pos_97_to_73[i] = j
        j += 1

print(f"  Non-null palette positions -> 73-char indices -> col7 columns:")
for p in NONNULL_PALETTE_POS:
    if p in pos_97_to_73:
        idx73 = pos_97_to_73[p]
        col7_col = idx73 % 7
        col7_row = idx73 // 7
        print(f"    pos97={p:2d} ({CT97[p]}) -> idx73={idx73:2d} -> col7=({col7_row},{col7_col})")

# 12d) Do null palette positions form a pattern that non-null don't?
print("\n--- 12d: Pattern discrimination ---")
# Check: are null palette positions all EVEN or ODD?
null_parity = [p % 2 for p in CONSENSUS_NULLS]
nonnull_parity = [p % 2 for p in NONNULL_PALETTE_POS]
print(f"  Null parity: {Counter(null_parity)} (even={null_parity.count(0)}, odd={null_parity.count(1)})")
print(f"  Non-null parity: {Counter(nonnull_parity)} (even={nonnull_parity.count(0)}, odd={nonnull_parity.count(1)})")

# Check: are null palette positions in the first/second half?
midpoint = 48
null_half = Counter('first' if p < midpoint else 'second' for p in CONSENSUS_NULLS)
nonnull_half = Counter('first' if p < midpoint else 'second' for p in NONNULL_PALETTE_POS)
print(f"  Null halves: {dict(null_half)}")
print(f"  Non-null halves: {dict(nonnull_half)}")

# Check: relationship to crib positions
print(f"\n  Null palette positions relative to cribs:")
for p in CONSENSUS_NULLS:
    crib_status = ""
    if p in CRIB_POS_SET:
        crib_status = "IN CRIB"
    elif p < ENE_START:
        crib_status = f"before ENE (dist={ENE_START-p})"
    elif p < BCL_START:
        if p > 33:
            crib_status = f"between cribs"
        else:
            crib_status = f"after ENE (dist={p-33})"
    elif p > 73:
        crib_status = f"after BCL (dist={p-73})"
    else:
        crib_status = f"in BCL region"
    print(f"    pos={p:2d} ({CT97[p]}): {crib_status}")

# 12e) Adjacent positions
print(f"\n--- 12e: Adjacent positions (are nulls clustered?) ---")
null_gaps = [CONSENSUS_NULLS[i+1] - CONSENSUS_NULLS[i] for i in range(16)]
nonnull_gaps = [NONNULL_PALETTE_POS[i+1] - NONNULL_PALETTE_POS[i] for i in range(17)]
print(f"  Null gaps: {null_gaps}")
print(f"  Non-null gaps: {nonnull_gaps}")
print(f"  Null consecutive pairs (gap=1): {sum(1 for g in null_gaps if g == 1)}")
print(f"  Non-null consecutive pairs: {sum(1 for g in nonnull_gaps if g == 1)}")

# 12f) The 18 non-null palette positions — what are they in the decrypted text?
print(f"\n--- 12f: Non-null palette chars in context ---")
for p in NONNULL_PALETTE_POS:
    context_start = max(0, p-2)
    context_end = min(97, p+3)
    context = CT97[context_start:context_end]
    local_pos = p - context_start
    context_marked = context[:local_pos] + '[' + context[local_pos] + ']' + context[local_pos+1:]
    in_crib = p in CRIB_POS_SET
    print(f"    pos={p:2d} ({CT97[p]}): ...{context_marked}... {'<- CRIB' if in_crib else ''}")

results["test12"] = {
    "null_positions": CONSENSUS_NULLS,
    "nonnull_positions": NONNULL_PALETTE_POS,
}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 13: ADDITIONAL STRUCTURAL TESTS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 13: ADDITIONAL STRUCTURAL TESTS")
print("=" * 72)
print()

# 13a) Is palette = the 7 LEAST frequent letters in CT97?
print("--- 13a: Frequency ranking ---")
ct_freq = Counter(CT97)
freq_ranked = sorted(ct_freq.items(), key=lambda x: x[1])
print(f"  CT97 letter frequencies (ascending):")
for i, (letter, count) in enumerate(freq_ranked):
    in_pal = letter in PALETTE
    print(f"    {i+1:2d}. {letter}: {count} {'<-- PALETTE' if in_pal else ''}")

# Check: are palette letters the bottom N by frequency?
bottom7 = frozenset(c for c, _ in freq_ranked[:7])
print(f"\n  Bottom 7 by frequency: {sorted(bottom7)}")
print(f"  Palette: {sorted(PALETTE)}")
print(f"  Match? {bottom7 == PALETTE}")

# 13b) Palette letters in KA: consecutive positions?
print("\n--- 13b: Palette in KA ---")
pal_ka_sorted = PAL_KA  # [0,5,8,13,15,23,25]
print(f"  KA positions: {pal_ka_sorted}")
print(f"  These spell: {''.join(KA_STR[i] for i in range(26) if i in set(pal_ka_sorted))}")
# Complement in KA
comp_ka = sorted(set(range(26)) - set(pal_ka_sorted))
print(f"  KA complement positions: {comp_ka}")
print(f"  KA complement letters: {''.join(KA_STR[i] for i in comp_ka)}")

# 13c) DEFECTOR:AZ_beau keystream at crib positions — palette enrichment details
print("\n--- 13c: Keystream palette enrichment ---")
from kryptos.kernel.constants import VIGENERE_KEY_ENE, VIGENERE_KEY_BC, BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC

for name, ks in [("Vig ENE", VIGENERE_KEY_ENE), ("Vig BC", VIGENERE_KEY_BC),
                  ("Beau ENE", BEAUFORT_KEY_ENE), ("Beau BC", BEAUFORT_KEY_BC)]:
    ks_letters = [AZ[k] for k in ks]
    ks_in_pal = sum(1 for k in ks_letters if k in PALETTE)
    print(f"  {name}: {ks_letters} -> {ks_in_pal}/{len(ks)} in palette ({ks_in_pal/len(ks)*100:.0f}%)")

# 13d) Palette = letters at K4 row boundaries in the grid?
print("\n--- 13d: K4 row boundary letters ---")
# K4 occupies roughly positions 0-96 in a 4-row section
# With width 31: row 0 = pos 0-30, row 1 = 31-61, row 2 = 62-92, row 3 = 93-96
row_starts = [0, 31, 62, 93]
row_ends = [30, 61, 92, 96]
boundary_chars = set()
for s in row_starts:
    if s < 97:
        boundary_chars.add(CT97[s])
for e in row_ends:
    if e < 97:
        boundary_chars.add(CT97[e])
print(f"  Row boundary chars: {sorted(boundary_chars)}")
print(f"  Overlap with palette: {sorted(boundary_chars & PALETTE)}")

# 13e) The 17 consensus null chars form the string OBKOGBOWWKWIWGZIG
null_string = ''.join(CONSENSUS_CHARS)
print(f"\n--- 13e: Null string analysis ---")
print(f"  Null string: {null_string}")
print(f"  Length: {len(null_string)}")
print(f"  Reversed: {null_string[::-1]}")
print(f"  Frequencies: {dict(Counter(null_string))}")

# Check if it's a simple substitution of some known text
# The null string has 17 chars using 7 letters.
# If we assign numbers to letters (by first appearance): O=0, B=1, K=2, G=3, W=4, I=5, Z=6
first_appear = {}
null_encoded = []
counter = 0
for c in null_string:
    if c not in first_appear:
        first_appear[c] = counter
        counter += 1
    null_encoded.append(first_appear[c])
print(f"  First-appearance encoding: {null_encoded}")
# Check: does this match any known sequence?
# 0,1,2,0,3,1,0,4,4,2,4,5,4,3,6,5,3

# 13f) W positions analysis
print(f"\n--- 13f: W positions deep analysis ---")
w_positions = [i for i in range(97) if CT97[i] == 'W']
print(f"  All W positions: {w_positions}")
print(f"  W positions that are nulls: {[p for p in w_positions if p in null_set]}")
print(f"  W positions that are NOT nulls: {[p for p in w_positions if p not in null_set]}")
w48_significance = "(33+63)/2 = 48.0 = MIDPOINT of crib start positions"
print(f"  W@48 significance: {w48_significance}")

# Check: in each 15/24 mask, how many W's are nulls?
print(f"\n  W null status across all 6 known 15/24 masks:")
for mask_idx, mask in enumerate(MASKS_15):
    mask_set = set(mask)
    w_null = [p for p in w_positions if p in mask_set]
    w_nonnull = [p for p in w_positions if p not in mask_set]
    print(f"    Mask {mask_idx}: W null at {w_null}, W non-null at {w_nonnull}")

results["test13"] = {
    "null_string": null_string,
    "first_appearance_encoding": null_encoded,
}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 14: EXHAUSTIVE SMALL-SET SEARCH
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 14: EXHAUSTIVE SEARCH — What 7-element subsets of Z_26 have same properties?")
print("=" * 72)
print()

# Properties of the palette:
# P1: range (max-min) = 24
# P2: size = 7
# P3: sum mod 26 = 86 mod 26 = 8
# How many 7-element subsets of {0..25} share these properties?

target_sum_mod26 = sum(PAL_AZ) % 26
target_range = max(PAL_AZ) - min(PAL_AZ)
print(f"Palette properties: sum mod 26 = {target_sum_mod26}, range = {target_range}")

count_same_sum = 0
count_same_range = 0
count_both = 0
total = 0

for combo in combinations(range(26), 7):
    total += 1
    s = sum(combo) % 26
    r = combo[-1] - combo[0]
    if s == target_sum_mod26:
        count_same_sum += 1
    if r == target_range:
        count_same_range += 1
    if s == target_sum_mod26 and r == target_range:
        count_both += 1

print(f"Total C(26,7) = {total}")
print(f"Same sum mod 26 = {target_sum_mod26}: {count_same_sum} ({count_same_sum/total*100:.1f}%)")
print(f"Same range = {target_range}: {count_same_range} ({count_same_range/total*100:.1f}%)")
print(f"Both: {count_both} ({count_both/total*100:.1f}%)")
print(f"Expected if independent: {count_same_sum * count_same_range / total:.0f}")

# Additional property: all 7 values mod 5 span ALL 5 residues... let me check
pal_mod5_residues = set(v % 5 for v in PAL_AZ)
print(f"\nPalette mod 5 residues: {sorted(pal_mod5_residues)}")
if len(pal_mod5_residues) == 5:
    # Count 7-element subsets with all 5 mod-5 residues
    count_all5 = 0
    for combo in combinations(range(26), 7):
        if len(set(v % 5 for v in combo)) == 5:
            count_all5 += 1
    print(f"7-element subsets covering all 5 mod-5 residues: {count_all5}/{total} ({count_all5/total*100:.1f}%)")

results["test14"] = {
    "total_C26_7": total,
    "same_sum_mod26": count_same_sum,
    "same_range": count_same_range,
    "both": count_both,
}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 15: PALETTE AND THE AZ->KA PERMUTATION CYCLES
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 15: PALETTE AND AZ->KA PERMUTATION CYCLE STRUCTURE")
print("=" * 72)
print()

# AZ->KA permutation: AZ[i] -> position of AZ[i] in KA
az_to_ka_perm = [KA_IDX[AZ[i]] for i in range(26)]
print(f"AZ->KA permutation: {az_to_ka_perm}")

# Find cycles
visited = [False] * 26
cycles = []
for start in range(26):
    if visited[start]:
        continue
    cycle = []
    current = start
    while not visited[current]:
        visited[current] = True
        cycle.append(current)
        current = az_to_ka_perm[current]
    if len(cycle) > 1:
        cycles.append(cycle)
    elif len(cycle) == 1:
        if az_to_ka_perm[cycle[0]] == cycle[0]:
            cycles.append(cycle)  # fixed point

print(f"\nCycle structure:")
for cyc in cycles:
    letters = [AZ[i] for i in cyc]
    in_palette = [AZ[i] in PALETTE for i in cyc]
    pal_count = sum(in_palette)
    print(f"  Cycle (len={len(cyc)}): {'->'.join(letters)} ({pal_count}/{len(cyc)} palette)")
    if pal_count > 0:
        pal_positions_in_cycle = [i for i, ip in enumerate(in_palette) if ip]
        print(f"    Palette members at cycle positions: {pal_positions_in_cycle}")
        # Check if palette members are evenly spaced in cycle
        if len(pal_positions_in_cycle) > 1:
            cycle_gaps = [pal_positions_in_cycle[i+1] - pal_positions_in_cycle[i]
                         for i in range(len(pal_positions_in_cycle)-1)]
            print(f"    Gaps in cycle: {cycle_gaps}")

# 17-cycle letters vs palette
cycle17 = None
cycle8 = None
for cyc in cycles:
    if len(cyc) == 17:
        cycle17 = cyc
    elif len(cyc) == 8:
        cycle8 = cyc

if cycle17:
    c17_letters = frozenset(AZ[i] for i in cycle17)
    c17_pal = PALETTE & c17_letters
    print(f"\n17-cycle palette members: {sorted(c17_pal)} ({len(c17_pal)}/7)")
if cycle8:
    c8_letters = frozenset(AZ[i] for i in cycle8)
    c8_pal = PALETTE & c8_letters
    print(f"8-cycle palette members: {sorted(c8_pal)} ({len(c8_pal)}/7)")

# Fixed point
fixed = [i for i in range(26) if az_to_ka_perm[i] == i]
fixed_letters = [AZ[i] for i in fixed]
print(f"Fixed points: {fixed_letters}")
print(f"Z in palette? {('Z' in PALETTE)}, Z is fixed point? {('Z' in fixed_letters)}")

results["test15"] = {
    "cycle17_palette": sorted(c17_pal) if cycle17 else [],
    "cycle8_palette": sorted(c8_pal) if cycle8 else [],
    "Z_fixed": 'Z' in fixed_letters and 'Z' in PALETTE,
}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 16: PALETTE AND COL7 STRUCTURE
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 16: PALETTE AND COL7 STRUCTURE")
print("=" * 72)
print()

# With 73 chars in col7: 10 full rows + 3 extra (11 rows, cols 0-2 have 11 entries, cols 3-6 have 10)
# After col7 trans, positions 0-10 are col 0 (11 entries), 11-21 are col 1 (11 entries), 22-32 are col 2 (11 entries)
# 33-42 are col 3 (10 entries), 43-52 col 4 (10 entries), 53-62 col 5 (10 entries), 63-72 col 6 (10 entries)

# Using mask 0, map to 73-char text
mask0 = set(MASKS_15[0])
ct73_text = ''.join(CT97[i] for i in range(97) if i not in mask0)
print(f"73-char text (mask 0): {ct73_text}")
print(f"Length: {len(ct73_text)}")

# Col7 column contents
col_ranges = [(0,11), (11,22), (22,33), (33,43), (43,53), (53,63), (63,73)]
print(f"\nCol7 columns:")
for col_idx, (start, end) in enumerate(col_ranges):
    col_text = ct73_text[start:end]
    pal_count = sum(1 for c in col_text if c in PALETTE)
    print(f"  Col {col_idx} [{start}:{end}]: {col_text} ({pal_count}/{len(col_text)} palette)")

# After col7 transposition (read by columns)
# Original positions (row-major) -> column-major reading
# Build col7 perm on 73 chars
width = 7
n = 73
n_full_rows = n // width  # 10
n_extra = n % width        # 3
n_rows = n_full_rows + 1   # 11

perm = []
for col in range(width):
    col_len = n_rows if col < n_extra else n_full_rows
    for row in range(col_len):
        perm.append(row * width + col)

inv_perm = [0] * n
for i, p in enumerate(perm):
    inv_perm[p] = i

ct73_transposed = ''.join(ct73_text[inv_perm[i]] for i in range(n))
print(f"\nAfter col7 transposition: {ct73_transposed}")

# Where do palette letters appear in the transposed text?
pal_in_trans = [i for i in range(73) if ct73_transposed[i] in PALETTE]
print(f"Palette positions in transposed text: {pal_in_trans}")
print(f"Count: {len(pal_in_trans)}/73")

# Which col7 columns do they fall in AFTER transposition?
print(f"\nPalette in transposed text by column:")
for col_idx, (start, end) in enumerate(col_ranges):
    col_pal = [i for i in range(start, end) if ct73_transposed[i] in PALETTE]
    print(f"  Col {col_idx}: {len(col_pal)}/{end-start} palette")

results["test16"] = {}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 17: PALETTE GENERATING RULE — DEEP COMBINATORIAL
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 17: DEEP COMBINATORIAL — Palette from known structures")
print("=" * 72)
print()

# 17a) Vigenere tableau: for each pair of letters, the "key" is fixed.
# Which pairs (PT, key) produce output EXACTLY = palette when applied letter-by-letter?
print("--- 17a: 7-letter PT encrypted with 7-letter key -> palette ---")
# We need PT and KEY both 7 letters such that Enc(PT[i], KEY[i]) produces PALETTE_LETTERS
# Under Vig AZ: palette[i] = (PT[i] + KEY[i]) mod 26
# Try KEY = KRYPTOS (7 letters)
for key_word in ["KRYPTOS", "DEFECTO", "KOMPASS", "ABSCISS", "PALIMPS", "COLOPHO"]:
    key_az = [AZ_IDX[c] for c in key_word]
    if len(key_az) != 7:
        continue
    for var_name, dec_fn in [("vig", lambda c,k: (c-k)%26), ("beau", lambda c,k: (k-c)%26), ("vbeau", lambda c,k: (c+k)%26)]:
        # "Decrypt" palette to get PT
        pt = [dec_fn(AZ_IDX[p], k) for p, k in zip(PALETTE_LETTERS, key_az)]
        pt_str = ''.join(AZ[v] for v in pt)
        # Check if pt_str is meaningful
        # Simple check: is it a word or close to one?
        print(f"  Key={key_word} {var_name}: palette decrypts to '{pt_str}'")

# 17b) Is palette the set of letters that appear at EVERY grid width as boundary?
print("\n--- 17b: Letters appearing at specific structural positions ---")
# For width W, first column = positions 0, W, 2W, ...
for w in [7, 13, 14, 31]:
    first_col_chars = set(CT97[i] for i in range(0, 97, w))
    last_col_chars = set(CT97[i] for i in range(w-1, 97, w))
    if first_col_chars == PALETTE or last_col_chars == PALETTE:
        note(f"  Width {w}: first col = {sorted(first_col_chars)}, last col = {sorted(last_col_chars)}")
    else:
        # Check intersection
        fc_pal = first_col_chars & PALETTE
        lc_pal = last_col_chars & PALETTE
        if len(fc_pal) >= 5 or len(lc_pal) >= 5:
            print(f"  Width {w}: first_col & palette = {sorted(fc_pal)} ({len(fc_pal)}/7)")

# 17c) Palette = every Nth letter of CT97?
print("\n--- 17c: Palette from CT97 sampling ---")
for step in range(2, 20):
    for offset in range(step):
        sampled = set(CT97[i] for i in range(offset, 97, step))
        if sampled == PALETTE:
            note(f"  CT97[{offset}::step={step}] = palette EXACTLY!")
        elif sampled.issubset(PALETTE) and len(sampled) >= 5:
            print(f"  CT97[{offset}::step={step}] subset of palette: {sorted(sampled)}")

# 17d) Palette = Vigenere/Beaufort encryption of a single letter repeated 7 times
print("\n--- 17d: Single char encrypted with cycling key -> palette ---")
for plaintext_val in range(26):
    for key_word in ["KRYPTOS", "DEFECTO"]:
        key_az = [AZ_IDX[c] for c in key_word]
        enc = [(plaintext_val + k) % 26 for k in key_az]
        if frozenset(enc) == frozenset(PAL_AZ):
            note(f"  Vig('{AZ[plaintext_val]}'*7, {key_word}) = palette!")
        enc_b = [(k - plaintext_val) % 26 for k in key_az]
        if frozenset(enc_b) == frozenset(PAL_AZ):
            note(f"  Beau('{AZ[plaintext_val]}'*7, {key_word}) = palette!")

results["test17"] = {}
print()

# ══════════════════════════════════════════════════════════════════════
# TEST 18: KNOWN 15/24 MASKS — VARYING POSITIONS ANALYSIS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("TEST 18: VARYING POSITIONS IN 15/24 MASKS — PALETTE vs NON-PALETTE")
print("=" * 72)
print()

# The 17 consensus nulls are at fixed positions. The remaining 7 vary.
# In each mask, what characters are at the 7 varying positions?
print("Varying positions across 6 known 15/24 masks:")
consensus_set = set(CONSENSUS_NULLS)
for mask_idx, mask in enumerate(MASKS_15):
    varying = [p for p in mask if p not in consensus_set]
    varying_chars = [CT97[p] for p in varying]
    varying_in_palette = sum(1 for c in varying_chars if c in PALETTE)
    print(f"  Mask {mask_idx}: varying={varying}, chars={''.join(varying_chars)}, "
          f"palette={varying_in_palette}/7")

# Statistics
all_varying_chars = []
for mask in MASKS_15:
    for p in mask:
        if p not in consensus_set:
            all_varying_chars.append(CT97[p])
var_in_pal = sum(1 for c in all_varying_chars if c in PALETTE)
print(f"\nAll varying chars ({len(all_varying_chars)} total): {var_in_pal} in palette ({var_in_pal/len(all_varying_chars)*100:.1f}%)")
print(f"Expected if random from CT97: {35/97*100:.1f}%")

# Which varying positions have palette chars vs non-palette?
print(f"\nAll unique varying positions and their chars:")
all_varying_positions = set()
for mask in MASKS_15:
    for p in mask:
        if p not in consensus_set:
            all_varying_positions.add(p)
for p in sorted(all_varying_positions):
    in_how_many = sum(1 for mask in MASKS_15 if p in mask)
    print(f"  pos={p:2d} ({CT97[p]}): in {in_how_many}/6 masks, palette={'YES' if CT97[p] in PALETTE else 'NO'}")

results["test18"] = {}
print()

# ══════════════════════════════════════════════════════════════════════
# SUMMARY OF ALL FINDINGS
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("SUMMARY OF ALL FINDINGS")
print("=" * 72)
print()

if findings:
    print("NOTABLE FINDINGS (marked with ***):")
    for f in findings:
        print(f"  {f}")
else:
    print("No notable findings (all marked with ***)")

print(f"\n--- Key numbers ---")
print(f"Palette AZ values: {PAL_AZ}")
print(f"Palette KA values: {PAL_KA}")
print(f"Sum AZ: {sum(PAL_AZ)} (mod 26 = {sum(PAL_AZ)%26})")
print(f"Sum KA: {sum(PAL_KA)} (mod 26 = {sum(PAL_KA)%26})")
print(f"Range AZ: {max(PAL_AZ)-min(PAL_AZ)} = 24")
print(f"Range KA: {max(PAL_KA)-min(PAL_KA)} = 25")
print(f"XOR AZ: {0}")
xor_az = 0
for v in PAL_AZ:
    xor_az ^= v
print(f"XOR AZ: {xor_az}")

# Timing
elapsed = time.time() - t0
print(f"\nTotal runtime: {elapsed:.1f}s")

# Save results
out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'palette_deep_investigation.json')
out_path = os.path.abspath(out_path)
results["findings"] = findings
results["elapsed_seconds"] = elapsed
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nResults saved to: {out_path}")
