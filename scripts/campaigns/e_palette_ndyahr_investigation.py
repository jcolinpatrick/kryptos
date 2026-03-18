#!/usr/bin/env python3
"""
Cipher: analysis + autokey
Family: campaigns
Status: active
Keyspace: Investigation 1 = analytical; Investigation 2 = 1,536 configs
Last run: never
Best score: TBD
"""
"""E-PALETTE-NDYAHR-INVESTIGATION: Two parallel investigations.

Investigation 1: What mathematical rule generates the 7-letter null palette {B,G,I,K,O,W,Z}?
  Tests: modular residues, keyword relationships, complement set, cipher outputs,
  binary patterns, NDYAHR relationship, position-derived rules.

Investigation 2: NDYAHR displacement vectors as col7 reading-order modifier.
  The 6 displacement directions (N=left, D=right, Y=up, A=up, H=right, R=up-left)
  modify whether each column in col7 transposition is read top-to-bottom or bottom-to-top.
  Tests all 2^6=64 direction interpretations x 6 masks x 4 cipher variants = 1,536 configs.

Run: PYTHONPATH=src python3 -u scripts/campaigns/e_palette_ndyahr_investigation.py
"""

import sys, os, json, time, math
from collections import Counter
from itertools import product as iter_product, combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_POSITIONS, KRYPTOS_ALPHABET

CT97 = CT
N = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[chr(i+65)] for i in range(26)]

# ── Constants ─────────────────────────────────────────────────────────
PALETTE = frozenset('BGIKOWZ')
PALETTE_LETTERS = sorted(PALETTE)
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})

# Known 15/24 masks
MASKS_24 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],
]

# NDYAHR displacement directions
# N: LEFT (West), D: RIGHT (East), Y: UP (North), A: UP (North), H: RIGHT (East), R: UP-LEFT (NW)
NDYAHR_LETTERS = 'NDYAHR'
NDYAHR_DIRECTIONS = ['LEFT', 'RIGHT', 'UP', 'UP', 'RIGHT', 'UP-LEFT']

results = {}

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 1: Palette Analysis
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 1: What generates the 7-letter null palette {B,G,I,K,O,W,Z}?")
print("=" * 72)
print()

# 1a) Modular patterns
print("--- (a) MODULAR PATTERNS ---")
inv1a = {}
for base_label, offset in [("A=0", 0), ("A=1", 1)]:
    vals = [ord(c) - 65 + offset for c in PALETTE_LETTERS]
    print(f"\n{base_label} values: {dict(zip(PALETTE_LETTERS, vals))}")
    for mod_n in [2, 3, 4, 5, 6, 7, 8, 9, 10, 13]:
        residues = [v % mod_n for v in vals]
        residue_set = set(residues)
        all_same = len(residue_set) == 1
        pairs = [(PALETTE_LETTERS[i], residues[i]) for i in range(len(vals))]
        if all_same:
            print(f"  mod {mod_n}: ALL congruent to {residues[0]}! {pairs}")
        else:
            # Check if they form a contiguous range or arithmetic progression
            residue_list = sorted(residue_set)
            diffs = [residue_list[i+1] - residue_list[i] for i in range(len(residue_list)-1)]
            ap = len(set(diffs)) == 1 if len(diffs) > 0 else False
            coverage = f"{len(residue_set)}/{mod_n} residues"
            detail = f"residues={residue_list}"
            if ap and len(residue_list) > 2:
                print(f"  mod {mod_n}: AP with step {diffs[0]}! {detail} {coverage}")
            else:
                print(f"  mod {mod_n}: {detail} {coverage}")
        inv1a[f"{base_label}_mod{mod_n}"] = {
            "residues": dict(zip(PALETTE_LETTERS, residues)),
            "distinct_residues": sorted(residue_set),
            "all_same": all_same,
        }

    # Check pairwise differences
    print(f"\n  {base_label} pairwise differences:")
    for i in range(len(vals)):
        for j in range(i+1, len(vals)):
            d = abs(vals[j] - vals[i])
            dm26 = min(d, 26-d) if offset == 0 else min(d, 27-d)  # circular distance
            # Only report small ones
    diffs = sorted(set(abs(vals[j] - vals[i]) for i in range(len(vals)) for j in range(i+1, len(vals))))
    print(f"  All pairwise diffs: {diffs}")
    gcd_all = vals[0]
    for v in vals[1:]:
        gcd_all = math.gcd(gcd_all, v)
    print(f"  GCD of all values: {gcd_all}")

results["1a_modular"] = inv1a
print()

# 1b) Keyword relationships
print("--- (b) KEYWORD RELATIONSHIPS ---")

# Anagram check
palette_str = ''.join(PALETTE_LETTERS)
complement_str = ''.join(c for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if c not in PALETTE)
print(f"Palette: {palette_str} (sorted)")
print(f"Complement: {complement_str}")

# Check if palette letters are in or relate to keywords
KEYWORDS = [
    "KRYPTOS", "DEFECTOR", "ABSCISSA", "KOMPASS", "PALIMPSEST",
    "COLOPHON", "PARALLAX", "SHADOW", "SANBORN", "BERLIN",
    "CLOCK", "EAST", "NORTH", "ENIGMA", "MEDUSA",
    "HOROLOGE", "BERLINCLOCK", "EASTNORTHEAST", "FIVE", "SEVEN",
    "UNDERGRUUND", "IQLUSION", "VERDIGRIS"
]
print(f"\nPalette letters in keywords:")
inv1b_kw = {}
for kw in KEYWORDS:
    kw_set = frozenset(kw)
    palette_in_kw = PALETTE & kw_set
    kw_in_palette = kw_set & PALETTE
    palette_not_in_kw = PALETTE - kw_set
    kw_not_in_palette = kw_set - PALETTE
    overlap = len(palette_in_kw)
    inv1b_kw[kw] = {"overlap": overlap, "palette_in_kw": sorted(palette_in_kw),
                     "missing_from_kw": sorted(palette_not_in_kw)}
    if overlap >= 3:
        print(f"  {kw}: {overlap}/7 palette letters present: {sorted(palette_in_kw)}, "
              f"missing: {sorted(palette_not_in_kw)}")

# KA indices of palette letters
print(f"\nKA indices of palette letters:")
ka_indices = {c: KA_IDX[c] for c in PALETTE_LETTERS}
print(f"  {ka_indices}")
ka_vals = sorted(ka_indices.values())
print(f"  Sorted KA values: {ka_vals}")
ka_diffs = [ka_vals[i+1] - ka_vals[i] for i in range(len(ka_vals)-1)]
print(f"  KA consecutive diffs: {ka_diffs}")

# Check if first/last N letters of keywords
print(f"\nPalette as prefix/suffix of keyword alphabets:")
for kw in ["KRYPTOS", "DEFECTOR", "ABSCISSA", "KOMPASS", "PALIMPSEST"]:
    # Build keyword-mixed alphabet
    seen = set(); mixed = []
    for c in kw + "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        if c not in seen:
            seen.add(c); mixed.append(c)
    first7 = set(mixed[:7])
    last7 = set(mixed[-7:])
    first7_match = first7 == PALETTE
    last7_match = last7 == PALETTE
    if first7_match or last7_match:
        print(f"  {kw}: {'FIRST' if first7_match else ''} {'LAST' if last7_match else ''} 7 = palette!")
    # Check every 7-position window
    for start in range(20):
        window = set(mixed[start:start+7])
        if window == PALETTE:
            print(f"  {kw} mixed alphabet positions [{start}:{start+7}] = palette!")

results["1b_keyword"] = inv1b_kw
results["1b_ka_indices"] = ka_indices
print()

# 1c) Complement set analysis
print("--- (c) COMPLEMENT SET ---")
complement = sorted(set('ABCDEFGHIJKLMNOPQRSTUVWXYZ') - PALETTE)
comp_str = ''.join(complement)
print(f"Complement (19 letters): {comp_str}")
print(f"  Contains all of KRYPTOS? {set('KRYPTOS').issubset(set(complement))}")
print(f"  Contains all of DEFECTOR? {set('DEFECTOR').issubset(set(complement))}")
print(f"  Contains all of ABSCISSA? {set('ABSCISSA').issubset(set(complement))}")
print(f"  Contains all of EASTNORTHEAST? {set('EASTNORTHEAST').issubset(set(complement))}")
print(f"  Contains all of BERLINCLOCK? {set('BERLINCLOCK').issubset(set(complement))}")
print(f"  Contains PALINDROME? {set('PALINDROME').issubset(set(complement))}")
print(f"  Contains DECIPHER? {set('DECIPHER').issubset(set(complement))}")
print(f"  Contains ENCRYPT? {set('ENCRYPT').issubset(set(complement))}")
print(f"  Contains PALIMPSEST? {set('PALIMPSEST').issubset(set(complement))}")
print(f"  Contains SHADOW? {set('SHADOW').issubset(set(complement))}")
print(f"  Contains LANGUAGE? {set('LANGUAGE').issubset(set(complement))}")

# A=0 and A=1 values for complement
comp_a0 = {c: ord(c)-65 for c in complement}
comp_a1 = {c: ord(c)-64 for c in complement}
print(f"\n  Complement A=0 values: {sorted(comp_a0.values())}")
print(f"  Complement A=1 values: {sorted(comp_a1.values())}")
comp_a0_set = set(comp_a0.values())
pal_a0_set = set(ord(c)-65 for c in PALETTE_LETTERS)
print(f"  Palette A=0: {sorted(pal_a0_set)}")
print(f"  Union: {sorted(comp_a0_set | pal_a0_set)} (should be 0-25)")
print(f"  Intersection: {sorted(comp_a0_set & pal_a0_set)} (should be empty)")

# Check: are complement values = non-palette? (tautologically yes, but check modular structure)
for mod_n in [2, 3, 5, 7, 13]:
    pal_res = set((ord(c)-65) % mod_n for c in PALETTE_LETTERS)
    comp_res = set((ord(c)-65) % mod_n for c in complement)
    disjoint = len(pal_res & comp_res) == 0
    if disjoint:
        print(f"  mod {mod_n}: palette and complement have DISJOINT residues! Palette={sorted(pal_res)}, Comp={sorted(comp_res)}")
    else:
        overlap = pal_res & comp_res
        print(f"  mod {mod_n}: residue overlap={sorted(overlap)}, palette={sorted(pal_res)}, comp={sorted(comp_res)}")

results["1c_complement"] = comp_str
print()

# 1d) Cipher output
print("--- (d) CIPHER OUTPUT ---")
inv1d = {}
src_keywords = ["KRYPTOS", "DEFECTOR", "ABSCISSA", "KOMPASS", "FIVE", "SEVEN", "SHADOW", "YAR", "NDYAHR"]
print("Can palette letters be obtained by encrypting a keyword?")
for kw in src_keywords:
    for shift in range(26):
        enc = ''.join(chr((ord(c)-65+shift) % 26 + 65) for c in kw)
        if set(enc) == PALETTE or set(enc).issubset(PALETTE):
            print(f"  Caesar({kw}, shift={shift}) = {enc} -> {'EXACT' if set(enc)==PALETTE else 'SUBSET'}")
            inv1d[f"caesar_{kw}_{shift}"] = enc

    # Beaufort with KRYPTOS key
    for key_kw in ["KRYPTOS", "DEFECTOR"]:
        key_ext = (key_kw * ((len(kw)//len(key_kw))+1))[:len(kw)]
        enc = ''.join(chr((ord(k)-65 - (ord(p)-65)) % 26 + 65) for p, k in zip(kw, key_ext))
        if set(enc).issubset(PALETTE):
            print(f"  Beaufort({kw}, key={key_kw}) = {enc} -> SUBSET of palette")

# Check if palette = some cipher applied to a short keyword
for length in range(3, 8):
    # Brute force for very short ones
    if length > 5:
        break  # too many combos
    for combo in combinations(range(26), length):
        enc_set = set()
        for shift in range(26):
            enc_set.update((v + shift) % 26 for v in combo)
            if enc_set.issuperset(pal_a0_set):
                break
        # This is getting too large, skip brute

results["1d_cipher_output"] = inv1d
print()

# 1e) Binary / bit pattern
print("--- (e) BINARY / BIT PATTERNS ---")
for base_label, offset in [("A=0", 0), ("A=1", 1)]:
    vals = [ord(c) - 65 + offset for c in PALETTE_LETTERS]
    print(f"\n{base_label} binary representations:")
    for c, v in zip(PALETTE_LETTERS, vals):
        print(f"  {c}={v:2d} = {v:05b}")

    # Bit-column analysis
    print(f"  Bit columns (MSB to LSB):")
    for bit in range(4, -1, -1):
        bits = [(v >> bit) & 1 for v in vals]
        print(f"    bit{bit}: {bits} (sum={sum(bits)})")

    # Check XOR patterns
    xor_all = vals[0]
    for v in vals[1:]:
        xor_all ^= v
    print(f"  XOR of all values: {xor_all} = {xor_all:05b}")
    print(f"  Sum of all values: {sum(vals)}")
    print(f"  Sum mod 26: {sum(vals) % 26}")

    # Popcount (number of 1-bits)
    popcounts = [bin(v).count('1') for v in vals]
    print(f"  Popcount: {dict(zip(PALETTE_LETTERS, popcounts))}")

results["1e_binary"] = {
    "a0": {c: ord(c)-65 for c in PALETTE_LETTERS},
    "a1": {c: ord(c)-64 for c in PALETTE_LETTERS},
}
print()

# 1f) NDYAHR relationship
print("--- (f) NDYAHR RELATIONSHIP ---")
ndyahr_a0 = [ord(c)-65 for c in NDYAHR_LETTERS]  # N=13, D=3, Y=24, A=0, H=7, R=17
pal_a0 = sorted(ord(c)-65 for c in PALETTE_LETTERS)  # B=1, G=6, I=8, K=10, O=14, W=22, Z=25
print(f"NDYAHR (A=0): {dict(zip(NDYAHR_LETTERS, ndyahr_a0))}")
print(f"Palette (A=0): {dict(zip(PALETTE_LETTERS, pal_a0))}")

# Check palette = NDYAHR + constant mod 26
print(f"\nPalette = NDYAHR + c (mod 26)?")
inv1f = {}
for c_val in range(26):
    shifted = sorted((v + c_val) % 26 for v in ndyahr_a0)
    if set(shifted).issubset(set(pal_a0)):
        print(f"  +{c_val}: {shifted} -> SUBSET")
    if set(shifted) == set(pal_a0[:6]):  # NDYAHR has 6 values, palette has 7
        print(f"  +{c_val}: {shifted} -> matches 6 of 7 palette values!")

# Union, intersection, complement
ndyahr_set = set(ndyahr_a0)
pal_set = set(pal_a0)
print(f"\nUnion (A=0): {sorted(ndyahr_set | pal_set)} ({len(ndyahr_set | pal_set)} values)")
print(f"Intersection (A=0): {sorted(ndyahr_set & pal_set)}")
print(f"NDYAHR - Palette: {sorted(ndyahr_set - pal_set)}")
print(f"Palette - NDYAHR: {sorted(pal_set - ndyahr_set)}")

# Check: NDYAHR values as indices into some alphabet -> palette?
print(f"\nNDYAHR as indices into AZ: {[chr(v+65) for v in ndyahr_a0]}")
print(f"NDYAHR as indices into KA: {[KA_STR[v] for v in ndyahr_a0]}")
# Reverse: palette as indices into AZ/KA
print(f"Palette as indices into KA: {[KA_STR[v] for v in pal_a0]}")

# Check simple transforms: palette = f(NDYAHR)?
print(f"\nSimple transforms NDYAHR -> Palette:")
# Try: palette values = NDYAHR values * k mod 26
for k in range(1, 26):
    transformed = sorted((v * k) % 26 for v in ndyahr_a0)
    if set(transformed).issubset(pal_set):
        print(f"  NDYAHR * {k} mod 26 = {transformed} -> {'EXACT 6/7' if len(set(transformed)&pal_set)==6 else 'SUBSET'}")

# E (anchor) + NDYAHR
e_val = ord('E') - 65  # = 4
print(f"\nENDYAHR (with E=anchor) A=0: E={e_val}, {dict(zip(NDYAHR_LETTERS, ndyahr_a0))}")
endyahr_a0 = [e_val] + ndyahr_a0
endyahr_set = set(endyahr_a0)
print(f"ENDYAHR values: {sorted(endyahr_set)} (7 values: {len(endyahr_set)})")
print(f"Palette values:  {sorted(pal_set)} (7 values)")
# Are they the same set?
if endyahr_set == pal_set:
    print(f"  *** ENDYAHR VALUES = PALETTE VALUES! ***")
# Transform?
for c_val in range(26):
    shifted = set((v + c_val) % 26 for v in endyahr_a0)
    if shifted == pal_set:
        print(f"  ENDYAHR + {c_val} mod 26 = PALETTE! (shift by {c_val} = {chr(c_val+65)})")
        inv1f[f"endyahr_shift_{c_val}"] = True

# Negation?
for c_val in range(26):
    negated = set((c_val - v) % 26 for v in endyahr_a0)
    if negated == pal_set:
        print(f"  ({c_val} - ENDYAHR) mod 26 = PALETTE! (Beaufort with constant {c_val} = {chr(c_val+65)})")
        inv1f[f"endyahr_beau_{c_val}"] = True

# Affine?
for a in range(1, 26):
    if math.gcd(a, 26) != 1:
        continue
    for b in range(26):
        transformed = set((a * v + b) % 26 for v in endyahr_a0)
        if transformed == pal_set:
            print(f"  ({a} * ENDYAHR + {b}) mod 26 = PALETTE! (affine a={a}, b={b})")
            inv1f[f"endyahr_affine_{a}_{b}"] = True

# Same for just NDYAHR (6 values -> need to find which 6 of 7 palette they map to)
for a in range(1, 26):
    if math.gcd(a, 26) != 1:
        continue
    for b in range(26):
        transformed = set((a * v + b) % 26 for v in ndyahr_a0)
        if transformed.issubset(pal_set) and len(transformed) == 6:
            missing = pal_set - transformed
            print(f"  ({a} * NDYAHR + {b}) mod 26 maps to 6/7 palette, missing {missing}")

results["1f_ndyahr"] = inv1f
print()

# 1g) Position-derived
print("--- (g) POSITION-DERIVED ---")
cons_positions = sorted(CONSENSUS_NULLS)
cons_chars_az = [ord(CT97[p]) - 65 for p in cons_positions]
print(f"Consensus positions: {cons_positions}")
print(f"Consensus chars (A=0): {cons_chars_az}")
print(f"Consensus chars: {''.join(CT97[p] for p in cons_positions)}")

# Check: char = f(position)?
print(f"\nChar vs position relationships:")
for p, c in zip(cons_positions, cons_chars_az):
    p_mod7 = p % 7
    p_mod13 = p % 13
    p_mod26 = p % 26
    c_eq_pmod26 = (c == p_mod26)
    c_eq_neg_pmod26 = (c == (26 - p_mod26) % 26)
    print(f"  pos={p:2d}, char={CT97[p]}({c:2d}), p%7={p_mod7}, p%13={p_mod13}, p%26={p_mod26}, "
          f"c==p%26?{c_eq_pmod26}, c==(26-p)%26?{c_eq_neg_pmod26}, (p+c)%26={(p+c)%26}, (p-c)%26={(p-c)%26}")

# Check if (position + char_value) mod N is constant
sums_mod26 = [(p + c) % 26 for p, c in zip(cons_positions, cons_chars_az)]
diffs_mod26 = [(p - c) % 26 for p, c in zip(cons_positions, cons_chars_az)]
sums_mod97 = [(p + c) % 97 for p, c in zip(cons_positions, cons_chars_az)]
print(f"\n  (pos + char) mod 26: {sums_mod26}")
print(f"  (pos - char) mod 26: {diffs_mod26}")
print(f"  (pos + char) mod 97: {sums_mod97}")
if len(set(sums_mod26)) == 1:
    print(f"  *** (pos + char) mod 26 is CONSTANT = {sums_mod26[0]}! ***")
if len(set(diffs_mod26)) == 1:
    print(f"  *** (pos - char) mod 26 is CONSTANT = {diffs_mod26[0]}! ***")

# Check if char depends on position mod K for various K
for mod_k in range(2, 15):
    pos_mod = [p % mod_k for p in cons_positions]
    # Group by position mod K, check if char is deterministic
    groups = {}
    for pm, c in zip(pos_mod, cons_chars_az):
        groups.setdefault(pm, set()).add(c)
    deterministic = all(len(v) == 1 for v in groups.values())
    if deterministic and len(groups) > 1:
        print(f"  mod {mod_k}: char is DETERMINISTIC from pos mod {mod_k}! {groups}")

# Check: are the 7 palette values related to row/col in the 28x31 grid?
# K4 starts at row 24, col 27 in the 28x31 grid
K4_START_ROW = 24
K4_START_COL = 27
print(f"\nGrid positions (28x31, K4 starts at row {K4_START_ROW}, col {K4_START_COL}):")
for i, p in enumerate(cons_positions):
    # K4 position p maps to grid position
    linear = K4_START_COL + K4_START_ROW * 31 + p
    row = linear // 31
    col = linear % 31
    print(f"  p={p:2d} -> grid[{row},{col}], char={CT97[p]}({cons_chars_az[i]}), "
          f"row%7={row%7}, col%7={col%7}")

results["1g_position"] = {
    "sums_mod26": sums_mod26,
    "diffs_mod26": diffs_mod26,
}
print()

# Additional: statistics on palette in full CT
print("--- (ADDITIONAL) Palette frequency analysis ---")
ct_counter = Counter(CT97)
print(f"Palette letter frequencies in CT97:")
total_palette = 0
for c in PALETTE_LETTERS:
    freq = ct_counter.get(c, 0)
    total_palette += freq
    # How many are in null positions vs non-null?
    null_count = sum(1 for p in cons_positions if CT97[p] == c)
    nonnull_count = freq - null_count
    print(f"  {c}: {freq} total ({null_count} null, {nonnull_count} non-null)")
print(f"  Total palette chars: {total_palette}/97")
print(f"  Non-palette chars: {97 - total_palette}/97")

# Check: palette = characters that appear at BOTH null and non-null positions?
print(f"\nLetters at BOTH null and non-null positions:")
both_set = set()
for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
    at_null = any(CT97[p] == c for p in cons_positions)
    at_nonnull = any(CT97[p] == c for p in range(97) if p not in CONSENSUS_NULLS)
    if at_null and at_nonnull:
        both_set.add(c)
    elif at_null and not at_nonnull:
        print(f"  {c}: ONLY at null positions (never non-null)")
print(f"  Letters at both: {sorted(both_set)} ({len(both_set)} letters)")
print(f"  Letters only at null: {sorted(PALETTE - both_set)}")

print()

# ══════════════════════════════════════════════════════════════════════
# INVESTIGATION 2: NDYAHR-modified col7 reading order
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("INVESTIGATION 2: NDYAHR as col7 reading-order modifier")
print("=" * 72)
print()

# ── Transposition helpers ─────────────────────────────────────────────
def build_modified_col7(reverse_flags):
    """Build a col7 transposition permutation with per-column direction.

    reverse_flags: list of 7 bools. True = read column bottom-to-top.
    Standard col7: all False.

    Col7 on 73 chars: 11 rows x 7 cols, last row has 3 entries (cols 0-2).
    Write in row order, read by columns with specified directions.

    Returns perm where transposed[i] = original[perm[i]].
    """
    n = N_PT  # 73
    width = 7
    n_full_rows = n // width  # 10 full rows
    n_extra = n % width       # 3 extra in last row
    n_rows = n_full_rows + (1 if n_extra > 0 else 0)  # 11

    # Build grid: grid[row][col] = original index
    grid = []
    idx = 0
    for row in range(n_rows):
        row_data = []
        for col in range(width):
            if idx < n:
                row_data.append(idx)
                idx += 1
            # else: no entry for this (row, col)
        grid.append(row_data)

    # Read columns with direction flags
    perm = []
    for col in range(width):
        # Collect indices in this column
        col_indices = []
        for row in range(n_rows):
            if col < len(grid[row]):
                col_indices.append(grid[row][col])

        if reverse_flags[col]:
            col_indices = col_indices[::-1]

        perm.extend(col_indices)

    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

# ── Autokey decryption ─────────────────────────────────────────────
def autokey_decrypt_az(ct73_az, kw_str, beau=False):
    kw_az = [ord(c) - 65 for c in kw_str.upper()]
    L = len(kw_az)
    pt = []
    for i, c in enumerate(ct73_az):
        k = kw_az[i] if i < L else pt[i - L]
        p = (k - c) % 26 if beau else (c - k) % 26
        pt.append(p)
    return pt

def autokey_decrypt_ka(ct73_az, kw_str, beau=False):
    ct73_ka = [AZ_TO_KA[c] for c in ct73_az]
    kw_ka = [KA_IDX[c] for c in kw_str.upper()]
    L = len(kw_ka)
    pt_ka = []
    for i, c in enumerate(ct73_ka):
        k = kw_ka[i] if i < L else pt_ka[i - L]
        p = (k - c) % 26 if beau else (c - k) % 26
        pt_ka.append(p)
    return pt_ka

# ── Crib scoring ───────────────────────────────────────────────────
def count_crib_hits_az(pt_indices, ene_s, bcl_s):
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < N_PT and pt_indices[ene_s + j] == ord(c) - 65)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < N_PT and pt_indices[bcl_s + j] == ord(c) - 65)
    return e + b, e, b

def count_crib_hits_ka(pt_ka_indices, ene_s, bcl_s):
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if ene_s + j < N_PT and pt_ka_indices[ene_s + j] == KA_IDX[c])
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if bcl_s + j < N_PT and pt_ka_indices[bcl_s + j] == KA_IDX[c])
    return e + b, e, b

# ── Verify standard col7 baseline ─────────────────────────────────
std_col7 = build_modified_col7([False]*7)
std_col7_inv = reverse_perm(std_col7)

# Verify against known result with mask 0
test_mask = frozenset(MASKS_24[0])
ct73_raw = [CT97[i] for i in range(N) if i not in test_mask]
ct73_az = [ord(c) - 65 for c in ct73_raw]
n1 = sum(1 for p in test_mask if p < ENE_START)
n2 = sum(1 for p in test_mask if p < BCL_START)
ene_s = ENE_START - n1
bcl_s = BCL_START - n2

ct73_trans = [ct73_az[std_col7_inv[i]] for i in range(N_PT)]
pt = autokey_decrypt_az(ct73_trans, 'DEFECTOR', beau=True)
total, e, b = count_crib_hits_az(pt, ene_s, bcl_s)
print(f"Baseline verification: DEFECTOR:AZ_beau + standard col7 + mask0 = {total}/24 (ene={e}/13, bcl={b}/11)")
if total != 15:
    print(f"  WARNING: Expected 15/24, got {total}/24. Check implementation!")
else:
    print(f"  Confirmed 15/24 -- implementation correct.")
print()

# ── Cipher configs ─────────────────────────────────────────────────
CIPHER_CONFIGS = [
    ("DEFECTOR:AZ_beau", "DEFECTOR", True, False),
    ("DEFECTOR:AZ_vig",  "DEFECTOR", False, False),
    ("KRYPTOS:KA_vig",   "KRYPTOS",  False, True),
    ("KRYPTOS:KA_beau",  "KRYPTOS",  True, True),
]

# ── Main sweep ─────────────────────────────────────────────────────
print(f"Testing 64 NDYAHR reading orders x {len(MASKS_24)} masks x {len(CIPHER_CONFIGS)} ciphers")
print(f"= {64 * len(MASKS_24) * len(CIPHER_CONFIGS)} configs")
print()

# Direction interpretation key:
# For each of 6 columns (1-6), the direction determines read direction.
# Column 0 (E=anchor) is always standard (top-to-bottom).
# We test all 2^6 = 64 combinations.

best_overall = 0
best_results = []
all_scores = []
t0 = time.time()

for mask_idx, mask_list in enumerate(MASKS_24):
    mask_set = frozenset(mask_list)
    ct73_raw = [CT97[i] for i in range(N) if i not in mask_set]
    ct73_az_base = [ord(c) - 65 for c in ct73_raw]

    n1 = sum(1 for p in mask_set if p < ENE_START)
    n2 = sum(1 for p in mask_set if p < BCL_START)
    ene_s_mask = ENE_START - n1
    bcl_s_mask = BCL_START - n2

    for direction_bits in range(64):
        # Column 0 = always standard (False)
        # Columns 1-6 = determined by bits 0-5
        reverse_flags = [False]  # col 0
        for bit in range(6):
            reverse_flags.append(bool(direction_bits & (1 << bit)))

        perm = build_modified_col7(reverse_flags)
        inv_perm = reverse_perm(perm)
        ct73_trans = [ct73_az_base[inv_perm[i]] for i in range(N_PT)]

        for cipher_name, kw, beau, ka in CIPHER_CONFIGS:
            if ka:
                pt = autokey_decrypt_ka(ct73_trans, kw, beau)
                total, e, b = count_crib_hits_ka(pt, ene_s_mask, bcl_s_mask)
            else:
                pt = autokey_decrypt_az(ct73_trans, kw, beau)
                total, e, b = count_crib_hits_az(pt, ene_s_mask, bcl_s_mask)

            all_scores.append(total)

            if total >= 15:
                flag_desc = ''.join('R' if f else 'S' for f in reverse_flags)
                dir_map = {
                    'LEFT': None, 'RIGHT': None, 'UP': None, 'UP-LEFT': None
                }
                entry = {
                    "score": total,
                    "ene": e,
                    "bcl": b,
                    "mask_idx": mask_idx,
                    "cipher": cipher_name,
                    "direction_bits": direction_bits,
                    "flags": flag_desc,
                    "reverse_cols": [i for i in range(7) if reverse_flags[i]],
                }
                best_results.append(entry)
                if total > best_overall:
                    best_overall = total
                    if ka:
                        pt_text = ''.join(KA_STR[p] for p in pt)
                    else:
                        pt_text = ''.join(chr(p+65) for p in pt)
                    print(f"  NEW BEST: {total}/24 (e={e},b={b}) mask={mask_idx} {cipher_name} "
                          f"flags={flag_desc} PT={pt_text[:40]}...")

# Also test reversed view (RHAYDN with flipped directions)
# R: UP-LEFT -> DOWN-RIGHT = standard; H: RIGHT -> LEFT = reverse;
# A: UP -> DOWN = standard; Y: UP -> DOWN = standard; D: RIGHT -> LEFT = reverse; N: LEFT -> RIGHT = standard
# So RHAYDN gives [False, True, False, False, True, False] for cols 1-6
# But we already tested this in the 64 combinations.

t1 = time.time()
print(f"\nCompleted in {t1-t0:.1f}s")

# ── Score distribution ─────────────────────────────────────────────
score_counter = Counter(all_scores)
print(f"\nScore distribution (all {len(all_scores)} configs):")
for s in sorted(score_counter.keys(), reverse=True):
    count = score_counter[s]
    pct = 100*count/len(all_scores)
    bar = '#' * min(int(pct), 60)
    print(f"  {s:2d}/24: {count:5d} ({pct:5.1f}%) {bar}")

print(f"\nBest score: {best_overall}/24")
if best_results:
    print(f"\nAll results >= 15/24:")
    for r in sorted(best_results, key=lambda x: -x['score']):
        print(f"  {r['score']}/24 (e={r['ene']},b={r['bcl']}) mask={r['mask_idx']} "
              f"{r['cipher']} flags={r['flags']} rev_cols={r['reverse_cols']}")

# Check: does the standard col7 (all standard) appear?
std_count = sum(1 for r in best_results if r['direction_bits'] == 0)
print(f"\nStandard col7 (all-standard) results >= 15/24: {std_count}")

# ── Hypothesis-specific direction interpretations ──────────────────
print("\n--- Specific NDYAHR direction interpretations ---")
# The user hypothesized: LEFT=reverse, RIGHT=standard, UP=reverse, UP-LEFT=reverse
# Cols: 0=E(standard), 1=N(LEFT=rev), 2=D(RIGHT=std), 3=Y(UP=rev), 4=A(UP=rev), 5=H(RIGHT=std), 6=R(UPLEFT=rev)
hypotheses = {
    "H1: LEFT=rev, RIGHT=std, UP=rev, UPLEFT=rev":
        {"LEFT": True, "RIGHT": False, "UP": True, "UP-LEFT": True},
    "H2: LEFT=rev, RIGHT=std, UP=std, UPLEFT=rev":
        {"LEFT": True, "RIGHT": False, "UP": False, "UP-LEFT": True},
    "H3: horiz=std, vert=rev (horizontal=std, vertical=rev)":
        {"LEFT": False, "RIGHT": False, "UP": True, "UP-LEFT": True},  # UP-LEFT has vertical component
    "H4: LEFT=std, RIGHT=rev, UP=rev, UPLEFT=std":
        {"LEFT": False, "RIGHT": True, "UP": True, "UP-LEFT": False},
    "H5: all reversed":
        {"LEFT": True, "RIGHT": True, "UP": True, "UP-LEFT": True},
}

for hyp_name, dir_map in hypotheses.items():
    # Map NDYAHR directions to reverse flags
    reverse_flags = [False]  # col 0 = E anchor
    for d in NDYAHR_DIRECTIONS:
        reverse_flags.append(dir_map[d])

    # Find this in our results
    direction_bits = 0
    for bit in range(6):
        if reverse_flags[bit + 1]:
            direction_bits |= (1 << bit)

    flag_desc = ''.join('R' if f else 'S' for f in reverse_flags)
    matching = [r for r in best_results if r['direction_bits'] == direction_bits]
    print(f"\n{hyp_name}")
    print(f"  Flags: {flag_desc} (bits={direction_bits})")
    if matching:
        for r in matching:
            print(f"  HIT: {r['score']}/24 mask={r['mask_idx']} {r['cipher']}")
    else:
        # Get scores for this direction from all configs
        print(f"  No results >= 15/24 for this direction interpretation")

print()

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════
print("=" * 72)
print("SUMMARY")
print("=" * 72)

print("\n--- Investigation 1: Palette {B,G,I,K,O,W,Z} ---")
print("Key findings:")
# Check if any affine/shift of ENDYAHR = palette
if results.get("1f_ndyahr"):
    for key, val in results["1f_ndyahr"].items():
        print(f"  CRITICAL: {key}")
else:
    print("  No simple transform maps ENDYAHR -> palette")

# Summarize modular results
print(f"\n  A=0 palette values: {sorted(ord(c)-65 for c in PALETTE_LETTERS)}")
print(f"  Sum = {sum(ord(c)-65 for c in PALETTE_LETTERS)}, Sum mod 26 = {sum(ord(c)-65 for c in PALETTE_LETTERS) % 26}")
print(f"  KA indices: {sorted(KA_IDX[c] for c in PALETTE_LETTERS)}")
print(f"  KA sum = {sum(KA_IDX[c] for c in PALETTE_LETTERS)}, KA sum mod 26 = {sum(KA_IDX[c] for c in PALETTE_LETTERS) % 26}")

print(f"\n--- Investigation 2: NDYAHR-modified col7 ---")
print(f"  Best score: {best_overall}/24")
print(f"  Results >= 15/24: {len(best_results)}")
if best_overall > 15:
    print(f"  *** IMPROVEMENT OVER BASELINE 15/24! ***")
elif best_overall == 15:
    print(f"  Matches baseline. Modified reading does NOT improve score.")
else:
    print(f"  BELOW baseline. Modified reading DEGRADES score.")

# ── Save results ─────────────────────────────────────────────────────
output = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "investigation_1": {
        "palette": sorted(PALETTE),
        "a0_values": sorted(ord(c)-65 for c in PALETTE_LETTERS),
        "a1_values": sorted(ord(c)-64 for c in PALETTE_LETTERS),
        "ka_values": sorted(KA_IDX[c] for c in PALETTE_LETTERS),
        "sum_a0": sum(ord(c)-65 for c in PALETTE_LETTERS),
        "sum_a1": sum(ord(c)-64 for c in PALETTE_LETTERS),
        "sum_ka": sum(KA_IDX[c] for c in PALETTE_LETTERS),
        "ndyahr_transforms_found": results.get("1f_ndyahr", {}),
        "complement": comp_str,
        "complement_contains_kryptos": set('KRYPTOS').issubset(set(complement)),
        "complement_contains_defector": set('DEFECTOR').issubset(set(complement)),
    },
    "investigation_2": {
        "configs_tested": len(all_scores),
        "best_score": best_overall,
        "results_ge_15": best_results,
        "score_distribution": {str(k): v for k, v in sorted(score_counter.items())},
        "standard_col7_ge15": std_count,
    }
}

out_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'palette_ndyahr_investigation.json')
out_path = os.path.abspath(out_path)
with open(out_path, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults saved to: {out_path}")
print(f"Total runtime: {time.time() - t0:.1f}s")
