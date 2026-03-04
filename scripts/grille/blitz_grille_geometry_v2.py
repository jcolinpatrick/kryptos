#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Grille Geometry v2 — targeted follow-up with new approaches.

Key insights from v1:
1. 94 holes (after off-grid exclusion), 115 holes (raw) — neither gives clean 97-position overlay
2. No overlay approach worked (K4 doesn't fit neatly under the grille)
3. All geometric permutations: scores -7.6 to -8.7 (noise level)
4. The grille must define the permutation INDIRECTLY, not by direct overlay on K4

New approaches to try:
A. Grille extract as CUSTOM ALPHABET for Vigenère
B. KA tableau structure of hole positions as key
C. T-avoidance: anti-diagonal positions as constraint on permutation
D. Two-step: grille as transposition, then KA Vigenère with KRYPTOS
E. Grille extract letter positions → index into K4 (multiple interpretations)
F. "8 Lines 73" physical layout variants
G. Grille extract pairs/triples as base-25/26 numbers → K4 indices
H. Apply grille extract as KEYWORD for the columnar transposition of K4
I. Test ALL permutations definable by row-count sequences
J. Grille as strip cipher with various widths
"""

import json, sys, os, math, itertools
from collections import Counter

sys.path.insert(0, 'src')

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GE) == 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
            'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']

QG = json.load(open('data/english_quadgrams.json'))

def score_per_char(text):
    t = text.upper(); n = len(t)-3
    return sum(QG.get(t[i:i+4],-10.) for i in range(n))/n if n>0 else -10.

def vig_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(ct[i])-alpha.index(key[i%len(key)]))%26] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    return ''.join(alpha[(alpha.index(key[i%len(key)])-alpha.index(ct[i]))%26] for i in range(len(ct)))

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

def col_read_perm(width, n=97):
    nr = math.ceil(n/width)
    return [r*width+c for c in range(width) for r in range(nr) if r*width+c < n]

def columnar_perm(key, n=97):
    nc = len(key); nr = math.ceil(n/nc)
    cols = sorted(range(nc), key=lambda i: (key[i],i))
    return [r*nc+c for c in cols for r in range(nr) if r*nc+c < n]

RESULTS_DIR = "blitz_results/grille_geometry"
os.makedirs(RESULTS_DIR, exist_ok=True)
all_results = []; crib_hits = []; tested = set()

def test_all(candidate_ct, label_prefix):
    """Test a candidate CT against all keywords/ciphers/alphabets."""
    found_any = False
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(candidate_ct, kw, alpha)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    r = {"label": f"{label_prefix}_{name}_{alpha_name}_{kw}",
                         "pt": pt, "score": score_per_char(pt),
                         "ene_pos": ene, "bc_pos": bc}
                    print(f"\n{'!'*60}")
                    print(f"*** CRIB HIT: {r['label']}")
                    print(f"    ENE@{ene}  BC@{bc}")
                    print(f"    PT: {pt}")
                    print('!'*60)
                    crib_hits.append(r); all_results.append(r)
                    found_any = True
    return found_any

def test_perm(perm, label):
    perm = list(perm)
    if label in tested: return None
    tested.add(label)
    if len(perm)!=97 or len(set(perm))!=97 or min(perm)!=0 or max(perm)!=96: return None
    ct2 = apply_perm(K4, perm)
    test_all(ct2, label)
    best = None; best_sc = -1e9
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(ct2, kw, alpha)
                sc = score_per_char(pt)
                if sc > best_sc:
                    best_sc = sc
                    best = {"label": label, "pt": pt, "score": sc, "key": kw,
                            "cipher": name, "alpha": alpha_name}
    if best: all_results.append(best)
    return best

def report(label, perm):
    perm = list(perm)
    if len(perm)!=97 or len(set(perm))!=97: return None
    r = test_perm(perm, label)
    if r: print(f"  [{label[:55]}] sc={r['score']:.4f} {r['key'][:12]} {r['cipher']}/{r['alpha']}")
    return r

# ═══════════════════════════════════════════════════════════════
# APPROACH A: Custom alphabet from grille extract
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH A: Custom alphabet from grille extract ===")

# Build custom alphabet from grille extract (first occurrence of each letter)
# GE has 25 distinct letters (no T). We need 26 for a full alphabet.
ge_unique_order = []
ge_seen = set()
for ch in GE:
    if ch not in ge_seen:
        ge_seen.add(ch); ge_unique_order.append(ch)
print(f"Unique letters in GE (first occurrence order): {''.join(ge_unique_order)}")
print(f"Missing from GE: {''.join(c for c in AZ if c not in ge_seen)}")

# Insert T at various positions to make 26-letter alphabet
for t_pos in range(26):
    custom_alpha = ge_unique_order[:t_pos] + ['T'] + ge_unique_order[t_pos:]
    if len(custom_alpha) == 26:
        custom_str = ''.join(custom_alpha)
        for kw in KEYWORDS:
            for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(K4, kw, custom_str)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                label = f"A_custom_T{t_pos}_{name}_{kw}"
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")
                    print(f"    Custom alpha: {custom_str}")
                if label not in tested:
                    tested.add(label)
                    sc = score_per_char(pt)
                    all_results.append({"label": label, "pt": pt, "score": sc,
                                        "key": kw, "cipher": name, "alpha": custom_str,
                                        "ene_pos": ene, "bc_pos": bc})

# Also: T at KA position 4 = HJLV[T]ACINXZUYOMWSEFBRDPKGQ
# That means: position 4 in the first-occurrence list... let me check ge_unique_order[4]:
print(f"ge_unique_order[4] = {ge_unique_order[4]} (will be replaced by T when t_pos=4)")
# The above loop already handles t_pos=4.

# Variant: custom alphabet sorted by second occurrence
ge_val = {ch: GE.index(ch) for ch in ge_unique_order}
# Sort AZ letters by their position in GE (T=last since absent from GE)
sorted_by_ge = sorted(AZ, key=lambda c: ge_val.get(c, len(GE)))
custom_by_firstocc = ''.join(sorted_by_ge)
print(f"AZ sorted by first occurrence in GE: {custom_by_firstocc}")

for kw in KEYWORDS:
    for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        pt = fn(K4, kw, custom_by_firstocc)
        ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
        label = f"A2_ge_sorted_alpha_{name}_{kw}"
        if ene >= 0 or bc >= 0:
            print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
            print(f"    PT: {pt}")
        if label not in tested:
            tested.add(label)
            sc = score_per_char(pt)
            all_results.append({"label": label, "pt": pt, "score": sc,
                                 "key": kw, "cipher": name, "alpha": custom_by_firstocc,
                                 "ene_pos": ene, "bc_pos": bc})

# ═══════════════════════════════════════════════════════════════
# APPROACH B: KA tableau structure — hole row+col defines key
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH B: KA tableau hole values as key ===")

# Each grille hole at (r,c) (0-indexed within the KA tableau area)
# has value KA[(r + c) % 26] in a standard Vigenère tableau.
# But the exact tableau layout depends on where the 26×26 area starts in the 28×33 grid.

# Try various offsets for the tableau within the 28×33 grid
HOLES_ALL = []  # Use the 115-hole version (no off-grid exclusion)
MASK_DATA_RAW = [
    "000000001010100000000010000000001",
    "100000000010000001000100110000011",
    "000000000000001000000000000000011",
    "00000000000000000000100000010011",
    "00000001000000001000010000000011",
    "000000001000000000000000000000011",
    "100000000000000000000000000000011",
    "00000000000000000000000100000100",
    "0000000000000000000100000001000",
    "0000000000000000000000000000100",
    "000000001000000000000000000000",
    "00000110000000000000000000000100",
    "00000000000000100010000000000001",
    "00000000000100000000000000001000",
    "000110100001000000000000001000010",
    "00001010000000000000000001000001",
    "001001000010010000000000000100010",
    "00000000000100000000010000010001",
    "000000000000010001001000000010001",
    "00000000000000001001000000000100",
    "000000001100000010100100010001001",
    "000000000000000100001010100100011",
    "00000000100000000000100001100001",
    "100000000000000000001000001000010",
    "10000001000001000000100000000001",
    "000010000000000000010000100000011",
    "000000000000000000010000100000011",  # fixed 34→33 chars
    "00000000000000100000001010000001",
]
for r, row_str in enumerate(MASK_DATA_RAW):
    for c, ch in enumerate(row_str):
        if ch == '1':
            HOLES_ALL.append((r, c))
print(f"Raw holes (all): {len(HOLES_ALL)}")

# For various tableau offsets (dr, dc), compute KA value at each hole
# KA tableau: row r → starting letter KA[r], col c → plain letter AZ[c]
# Cell (r,c) in TABLEAU contains KA[(r + KA.index(AZ[c])) % 26]
# Simplified: KA[(r + c) % 26] where r,c are 0-indexed tableau coordinates
# Hole at grid (gr, gc) → tableau (tr, tc) = (gr - dr, gc - dc)

for dr in range(3):
    for dc in range(5):
        hole_values = []
        for gr, gc in HOLES_ALL:
            tr = gr - dr; tc = gc - dc
            if 0 <= tr < 26 and 0 <= tc < 26:
                val = (tr + tc) % 26  # KA-index of the letter at this tableau cell
                hole_values.append((gr, gc, tr, tc, val))

        if len(hole_values) < 97:
            continue

        # Use hole values (KA indices) as a sequence of shifts for K4
        key_vals = [v for _,_,_,_,v in sorted(hole_values, key=lambda x: (x[0],x[1]))][:97]
        key_str_az = ''.join(AZ[v % 26] for v in key_vals)
        key_str_ka = ''.join(KA[v % 26] for v in key_vals)

        for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            for key_s, alpha_name in [(key_str_az, "AZ"), (key_str_ka, "KA")]:
                pt = fn(K4, key_s, AZ)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                label = f"B_dr{dr}_dc{dc}_{name}_{alpha_name}"
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")
                if label not in tested:
                    tested.add(label)
                    sc = score_per_char(pt)
                    all_results.append({"label": label, "pt": pt, "score": sc,
                                        "key": "tableau_hole_vals", "cipher": name,
                                        "alpha": alpha_name, "ene_pos": ene, "bc_pos": bc})

# ═══════════════════════════════════════════════════════════════
# APPROACH C: Grille extract pairs as base-25 indices
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH C: Grille extract consecutive pairs as indices ===")

# Grille extract has 25 distinct letters. Map each to 0-24.
ge_rank = {ch: i for i, ch in enumerate(ge_unique_order)}
print(f"GE unique order (rank mapping): {ge_rank}")

# Pairs of GE letters → base-25 number → mod 97
ge_vals = [ge_rank.get(c, 24) for c in GE]

# Consecutive pairs
pair_vals = [ge_vals[i]*25 + ge_vals[i+1] for i in range(len(ge_vals)-1)]
print(f"Pairs (first 20): {pair_vals[:20]}")
print(f"Max pair value: {max(pair_vals)}, (97 range: 0-96)")

from collections import OrderedDict
def dedup(seq, n=97):
    seen = set(); out = []
    for v in seq:
        v = v % 97
        if v not in seen:
            seen.add(v); out.append(v)
        if len(out) == n: break
    return out if len(out) == n else None

p = dedup(pair_vals)
if p: report("C_ge_pairs_base25_dedup", p)

# Triple values
triple_vals = [ge_vals[i]*625 + ge_vals[i+1]*25 + ge_vals[i+2] for i in range(len(ge_vals)-2)]
p = dedup(triple_vals)
if p: report("C_ge_triples_base25_dedup", p)

# GE values directly (each char as 0-24)
p = dedup(ge_vals)
if p: report("C_ge_vals_base25_dedup", p)

# GE AZ indices
ge_az = [AZ.index(c) for c in GE]
p = dedup(ge_az)
if p: report("C_ge_az_indices_dedup", p)

# GE KA indices
ge_ka = [KA.index(c) if c in KA else 25 for c in GE]
p = dedup(ge_ka)
if p: report("C_ge_ka_indices_dedup", p)

# Sum of consecutive pairs
for chunk in [2, 3, 4]:
    sums = [sum(ge_az[i:i+chunk]) for i in range(0, len(ge_az)-chunk+1)]
    p = dedup(sums)
    if p: report(f"C_ge_az_sum{chunk}_dedup", p)

# ═══════════════════════════════════════════════════════════════
# APPROACH D: "8 Lines 73" — K4 in 8 rows, grille overlay
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH D: '8 Lines 73' layout variants ===")

# Sanborn's yellow pad says "8 Lines 73" for K4
# Interpretation 1: K4 in 8 lines, with special position at 73
# Interpretation 2: K4 written in a grid where line 8 starts at position 73

# Test various 8-line layouts
for line_len in range(10, 16):  # try 10-15 chars per line
    p = col_read_perm(line_len)
    report(f"D_8lines_linelen{line_len}_col", p)

# "73" interpretation: K4[0:72] in one arrangement, K4[72:97] in another
# Try: K4[0:72] in 8 lines of 9, K4[72:97] in one more block
# This would mean 9 lines total, so "8 Lines" refers to the first 8

# Test: reverse only last 25 chars (after position 72)
p_partial = list(range(72)) + list(range(96, 71, -1))
report("D_first72_normal_last25_rev", p_partial)

# Test: K4 written in a 8×13 grid (104 cells, 97 used)
for nr in range(6, 14):
    nc = math.ceil(97/nr)
    for start_right in [True, False]:
        if start_right:
            perm = [r*nc + (nc-1-c if r%2==1 else c)
                    for c in range(nc) for r in range(nr)
                    if r*nc + (nc-1-c if r%2==1 else c) < 97]
        else:
            perm = [r*nc+c for c in range(nc) for r in range(nr) if r*nc+c < 97]
        if len(perm) == 97 and len(set(perm)) == 97:
            report(f"D_grid_{nr}x{nc}_{'bous' if start_right else 'col'}", perm)

# ═══════════════════════════════════════════════════════════════
# APPROACH E: Strip cipher with grille-determined strip widths
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH E: Strip cipher with hole-count widths ===")

# Strip cipher: write K4 in strips of various widths, then read by rearranging strips
# The widths are determined by the hole count per row

HOLES_CORRECTED = []
for r, row_str in enumerate(MASK_DATA_RAW):
    valid_len = min(len(row_str), 33)  # max 33 cols
    for c in range(valid_len):
        if row_str[c] == '1':
            HOLES_CORRECTED.append((r, c))
print(f"Corrected holes (max 33 cols): {len(HOLES_CORRECTED)}")

row_counts_corrected = Counter(r for r,c in HOLES_CORRECTED)
print(f"Row hole counts: {[row_counts_corrected.get(r,0) for r in range(28)]}")

# Non-zero row hole counts as strip lengths
strip_widths = [row_counts_corrected.get(r,0) for r in range(28) if row_counts_corrected.get(r,0) > 0]
print(f"Strip widths (non-zero): {strip_widths}")
print(f"Sum of strip widths: {sum(strip_widths)}")

# E1: Use strip widths to write K4 into groups, read by some ordering
# This is complex; simplified: use strip widths as columnar key
p = columnar_perm(strip_widths)
if len(p)==97 and len(set(p))==97: report("E1_strip_widths_columnar", p)

# E2: Fixed strip width = (total holes) / 97 ≈ some number
for strip_w in [1, 2, 3, 4, 5, 6, 7, 8]:
    n_strips = 97 // strip_w
    if n_strips * strip_w != 97:
        continue
    # Each strip is strip_w consecutive K4 chars
    # Reorder strips using hole data
    strip_order = list(range(n_strips))
    # Sort strips by cumulative hole count... try reversed
    perm = list(range(n_strips-1, -1, -1))  # reversed strip order
    full_perm = [strip_w * s + j for s in perm for j in range(strip_w)]
    if len(full_perm)==97: report(f"E2_strip{strip_w}_rev", full_perm)

# ═══════════════════════════════════════════════════════════════
# APPROACH F: Grille extract as keyword for double-transposition
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH F: Grille extract as double-transposition keyword ===")

def apply_kw_col(text, keyword):
    """Apply keyword columnar transposition to text."""
    nc = len(keyword); nr = math.ceil(len(text)/nc)
    padded = text + 'X'*(nr*nc - len(text))
    # Sort columns by keyword
    col_order = sorted(range(nc), key=lambda i: (keyword[i], i))
    result = ''.join(padded[r*nc+c] for c in col_order for r in range(nr))
    return result[:len(text)]

for klen in [5, 6, 7, 8, 9, 10, 11, 12, 13, 97]:
    kw1 = GE[:klen]
    ct2 = apply_kw_col(K4, kw1)
    # Then test with short keyword Vigenère
    found = test_all(ct2, f"F_ge{klen}_col_then")

# Double: columnar once with GE prefix, then again with GE continuation
for k1 in [7, 9, 11]:
    for k2 in [7, 9, 11]:
        if k1 == k2: continue
        ct2 = apply_kw_col(apply_kw_col(K4, GE[:k1]), GE[k1:k1+k2])
        found = test_all(ct2, f"F_double_ge{k1}_ge{k2}")

# ═══════════════════════════════════════════════════════════════
# APPROACH G: Grille extract positions of each K4 letter
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH G: K4 letter → position in GE ===")

# G1: For K4[i], find where K4[i] FIRST appears in GE
# Use first-occurrence position in GE as a "rank" for reordering K4
ge_first_pos = {ch: GE.index(ch) if ch in GE else len(GE) for ch in AZ}
print(f"GE first occurrence positions: {ge_first_pos}")
print(f"T not in GE → position {ge_first_pos['T']}")

# Sort K4 positions by the GE first-occurrence position of that K4 letter
sorted_by_ge_firstpos = sorted(range(97), key=lambda i: (ge_first_pos.get(K4[i], len(GE)), i))
report("G1_k4_sorted_by_ge_firstpos", sorted_by_ge_firstpos)

inv_g1 = [0]*97
for r,i in enumerate(sorted_by_ge_firstpos): inv_g1[i] = r
report("G1_inv_k4_sorted_by_ge_firstpos", inv_g1)

# G2: For each K4 position i, find the i-th occurrence of K4[i] in GE
# Build occurrence index for each letter in GE
ge_occurrences = {}
for pos, ch in enumerate(GE):
    ge_occurrences.setdefault(ch, []).append(pos)

occurrence_seq = []
occurrence_count = Counter()
for i, ch in enumerate(K4):
    idx = occurrence_count[ch]
    if ch in ge_occurrences and idx < len(ge_occurrences[ch]):
        occurrence_seq.append(ge_occurrences[ch][idx] % 97)
    else:
        occurrence_seq.append(i)  # fallback
    occurrence_count[ch] += 1

print(f"G2: occurrence-based seq (first 20): {occurrence_seq[:20]}")
if len(set(occurrence_seq)) == 97:
    report("G2_ge_occurrence_seq", occurrence_seq)

# G3: Rank of each letter in GE (position in GE string) → reorder K4
# For K4[i] = letter L at GE position p → output position = p % 97
# Build from each K4 letter's occurrence in GE
k4_ge_ranks = []
for i, ch in enumerate(K4):
    # Find which occurrence of K4[i] in GE corresponds to position i
    # Use all occurrences of ch in GE, cycle through them
    occs = ge_occurrences.get(ch, [])
    if occs:
        idx = i % len(occs)  # use modular cycling
        k4_ge_ranks.append(occs[idx])
    else:
        k4_ge_ranks.append(i * 5)  # T not in GE, use fallback

print(f"G3 GE ranks (first 20): {k4_ge_ranks[:20]}")
p = sorted(range(97), key=lambda i: k4_ge_ranks[i])
report("G3_k4_ge_rank_sort", p)

# ═══════════════════════════════════════════════════════════════
# APPROACH H: Row/column hole position as AMSCO transposition
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH H: AMSCO-style transpositions ===")

# AMSCO: fill text into table with alternating 1 and 2 char groups per column
# Then read columns in keyword order

def amsco_write_perm(n_cols, groups_per_col, n=97):
    """
    AMSCO transposition: write n chars into n_cols columns.
    groups_per_col[c] determines the group sizes for column c (alternating 1,2 or fixed).
    Returns permutation.
    """
    # Assign positions to (col, row, start, length)
    assignments = []  # (pos_in_text, col, sort_key)
    col_pos = [0] * n_cols
    group_flip = [0] * n_cols  # which size to use next
    sizes = [[1,2], [2,1]]
    text_pos = 0
    row = 0
    while text_pos < n:
        for col in range(n_cols):
            if text_pos >= n: break
            grp_size = sizes[group_flip[col]][row % 2]
            for k in range(grp_size):
                if text_pos + k < n:
                    assignments.append((text_pos + k, col))
            text_pos += grp_size
            group_flip[col] = 1 - group_flip[col]
        row += 1

    # Read columns in order 0..n_cols-1 (or sorted)
    # Output: read column by column, top to bottom
    from collections import defaultdict
    col_chars = defaultdict(list)
    for text_idx, col in assignments:
        if text_idx < n:
            col_chars[col].append(text_idx)

    perm = []
    for col in range(n_cols):
        perm.extend(col_chars[col])
    return perm if len(perm) == n and len(set(perm)) == n else None

for nc in range(5, 20):
    p = amsco_write_perm(nc, [], 97)
    if p: report(f"H_amsco_nc{nc}", p)

# ═══════════════════════════════════════════════════════════════
# APPROACH I: Grille extract defines a route cipher path
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH I: Route cipher permutations ===")

# Various route cipher reading patterns for a grid layout of K4

def route_perm(nr, nc, route, n=97):
    """Apply a route reading to an nr×nc grid holding n chars."""
    # route: list of (row, col) pairs in the order to read them
    perm = [r*nc+c for r,c in route if r*nc+c < n]
    return perm if len(perm)==n and len(set(perm))==n else None

# I1: Horizontal serpentine (boustrophedon)
for nc in range(10, 17):
    nr = math.ceil(97/nc)
    route = []
    for r in range(nr):
        cols = range(nc) if r%2==0 else range(nc-1, -1, -1)
        for c in cols:
            if r*nc+c < 97: route.append((r, c))
    p = route_perm(nr, nc, route)
    if p: report(f"I1_bous_nc{nc}", p)

# I2: Vertical serpentine (column-wise boustrophedon)
for nc in range(10, 17):
    nr = math.ceil(97/nc)
    route = []
    for c in range(nc):
        rows = range(nr) if c%2==0 else range(nr-1, -1, -1)
        for r in rows:
            if r*nc+c < 97: route.append((r, c))
    p = route_perm(nr, nc, route)
    if p: report(f"I2_vert_bous_nc{nc}", p)

# I3: Spiral inward
def spiral_route(nr, nc):
    route = []
    top, bot, left, right = 0, nr-1, 0, nc-1
    while top <= bot and left <= right:
        for c in range(left, right+1): route.append((top, c))
        top += 1
        for r in range(top, bot+1): route.append((r, right))
        right -= 1
        if top <= bot:
            for c in range(right, left-1, -1): route.append((bot, c))
            bot -= 1
        if left <= right:
            for r in range(bot, top-1, -1): route.append((r, left))
            left += 1
    return route

for nc in range(10, 17):
    nr = math.ceil(97/nc)
    rt = spiral_route(nr, nc)
    p = route_perm(nr, nc, rt)
    if p: report(f"I3_spiral_nc{nc}", p)

# ═══════════════════════════════════════════════════════════════
# APPROACH J: Permutation defined by GE letter positions in K4
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH J: GE positions in K4 ===")

# J1: The grille extract defines which K4 chars to read FIRST
# "HJLVACINXZ..." → at K4 find positions of H, J, L, V, A, C, I, N, X, Z, ...

# Build a sequence: for each GE letter, take the NEXT unused K4 position of that letter
k4_queues = {}
for i, ch in enumerate(K4):
    k4_queues.setdefault(ch, []).append(i)

seq_j1 = []
used_j1 = set()
q = {ch: list(pos) for ch, pos in k4_queues.items()}
for ch in GE:
    if ch in q:
        while q[ch] and q[ch][0] in used_j1:
            q[ch].pop(0)
        if q[ch]:
            pos = q[ch].pop(0)
            used_j1.add(pos)
            seq_j1.append(pos)

print(f"J1: Sequence length from GE→K4 mapping: {len(seq_j1)}")
if len(seq_j1) >= 97:
    report("J1_ge_to_k4_seq", seq_j1[:97])

# Pad with remaining positions
remaining = [i for i in range(97) if i not in used_j1]
seq_j1_padded = seq_j1 + remaining
if len(seq_j1_padded) >= 97:
    report("J1_ge_k4_seq_padded", seq_j1_padded[:97])

# J2: Reverse: GE letter positions, then read K4 in that order
# GE letter → find ALL positions of that letter in K4, take in GE-read order
seq_j2 = []
used_j2 = set()
for ch in GE:
    for pos in sorted(k4_queues.get(ch, [])):
        if pos not in used_j2:
            used_j2.add(pos); seq_j2.append(pos)
            break

remaining2 = [i for i in range(97) if i not in used_j2]
seq_j2_full = seq_j2 + remaining2
print(f"J2: Unique positions from GE letter mapping: {len(seq_j2)}")
if len(seq_j2_full) >= 97:
    report("J2_ge_k4_first_occurrence", seq_j2_full[:97])

# J3: GE defines reading order by letter type
# All K4 positions where K4[i] = 'H' (first GE letter), then 'J', etc.
seq_j3 = []
for ch in ge_unique_order:  # 25 distinct letters in GE order
    for i in range(97):
        if K4[i] == ch:
            seq_j3.append(i)
remaining3 = [i for i in range(97) if K4[i] == 'T']  # T positions (not in GE)
seq_j3 += remaining3
if len(seq_j3) == 97: report("J3_ge_letter_type_grouping", seq_j3)

# ═══════════════════════════════════════════════════════════════
# APPROACH K: Systematic 2-step approaches
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH K: Two-step cipher combinations ===")

# K1: Beaufort with GE as key, then Vigenère with KRYPTOS
for ge_start in range(10):
    ge_key = GE[ge_start:ge_start+97]
    if len(ge_key) < 97: continue
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        # Step 1: Beaufort K4 with GE
        ct1 = beau_dec(K4, ge_key, alpha)
        # Step 2: Test result with all keywords
        for kw in KEYWORDS:
            for name2, fn2 in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn2(ct1, kw, alpha)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                label = f"K1_beau_ge{ge_start}_{alpha_name}_{name2}_{kw}"
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")

# K2: Columnar with KRYPTOS keyword, then Beaufort with GE
ct_kryptos = ''.join(K4[i] for i in columnar_perm("KRYPTOS"))
for ge_start in range(10):
    ge_key = GE[ge_start:ge_start+97]
    if len(ge_key) < 97: continue
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(ct_kryptos, ge_key, alpha)
            ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
            label = f"K2_KRYPTOS_col_then_ge{ge_start}_{name}_{alpha_name}"
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                print(f"    PT: {pt}")

# ═══════════════════════════════════════════════════════════════
# APPROACH L: GE reversed and reflected
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH L: GE reversed / reflected ===")

GE_REV = GE[::-1]
GE_REV97 = GE_REV[:97]

# L1: Reverse GE as running key
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        pt = fn(K4, GE_REV97, alpha)
        ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
        label = f"L1_ge_rev_{name}_{alpha_name}"
        if ene >= 0 or bc >= 0:
            print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
            print(f"    PT: {pt}")
        if label not in tested:
            tested.add(label)
            sc = score_per_char(pt)
            all_results.append({"label": label, "pt": pt, "score": sc,
                                 "key": "GE_reversed", "cipher": name, "alpha": alpha_name,
                                 "ene_pos": ene, "bc_pos": bc})

# L2: Argsort of reversed GE
ge_rev97 = GE_REV[:97]
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    vals = [alpha.index(c) if c in alpha else 25 for c in ge_rev97]
    argsort = sorted(range(97), key=lambda i: (vals[i], i))
    report(f"L2_ge_rev_argsort_{alpha_name}", argsort)

# L3: GE interleaved with itself (odd/even positions)
ge_interleaved = ''.join(GE[i] for i in range(0, len(GE), 2)) + ''.join(GE[i] for i in range(1, len(GE), 2))
ge_inter97 = ge_interleaved[:97]
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        pt = fn(K4, ge_inter97, alpha)
        ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
        label = f"L3_ge_interleaved_{name}_{alpha_name}"
        if ene >= 0 or bc >= 0:
            print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
            print(f"    PT: {pt}")
        if label not in tested:
            tested.add(label)
            sc = score_per_char(pt)
            all_results.append({"label": label, "pt": pt, "score": sc,
                                 "key": "GE_interleaved", "cipher": name, "alpha": alpha_name,
                                 "ene_pos": ene, "bc_pos": bc})

# ═══════════════════════════════════════════════════════════════
# APPROACH M: Grille extract as substitution-then-permute
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH M: GE-derived substitution ciphers ===")

# M1: Atbash variant using GE ordering
# Encrypt: K4[i] → ge_unique_order[24 - ge_rank.get(K4[i], 24)]
ge_atbash = {ch: ge_unique_order[24-i] for i, ch in enumerate(ge_unique_order)}
ge_atbash['T'] = 'T'  # T maps to itself
ct_atbash = ''.join(ge_atbash.get(c, c) for c in K4)
test_all(ct_atbash, "M1_ge_atbash")

# M2: Simple substitution where AZ→GE_unique_order (with T inserted)
for t_pos in [4, 12, 0, 25]:
    custom = ge_unique_order[:t_pos] + ['T'] + ge_unique_order[t_pos:]
    if len(custom) != 26: continue
    custom_str = ''.join(custom)
    # This IS a 26-letter alphabet. Use as the substitution alphabet.
    # Decrypt: K4[i] is in AZ, map through custom alphabet
    try:
        ct2 = ''.join(AZ[custom_str.index(c)] if c in custom_str else c for c in K4)
        test_all(ct2, f"M2_ge_subst_T{t_pos}")
    except ValueError:
        pass

# ═══════════════════════════════════════════════════════════════
# APPROACH N: Mixed-alphabet Vigenère with GE-derived key alphabet
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH N: All known keywords in AZ/KA + GE custom alphabets ===")

# Build a few GE-derived alphabets
ge_alphabets = {}
for t_pos in [0, 4, 12, 24]:
    custom = ge_unique_order[:t_pos] + ['T'] + ge_unique_order[t_pos:]
    if len(custom) == 26:
        ge_alphabets[f"GE_T{t_pos}"] = ''.join(custom)

# Try each GE alphabet with each keyword and cipher
for alpha_name, alpha in ge_alphabets.items():
    for kw in KEYWORDS:
        # Index keyword in this alphabet
        try:
            kw_in_alpha = [alpha.index(c) for c in kw if c in alpha]
        except ValueError:
            continue
        for name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn(K4, kw, alpha)
            ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
            label = f"N_{alpha_name}_{name}_{kw}"
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT {label}: ENE@{ene} BC@{bc}")
                print(f"    PT: {pt}")
                print(f"    Alphabet: {alpha}")
            if label not in tested:
                tested.add(label)
                sc = score_per_char(pt)
                all_results.append({"label": label, "pt": pt, "score": sc,
                                     "key": kw, "cipher": name, "alpha": alpha_name,
                                     "ene_pos": ene, "bc_pos": bc})

# ═══════════════════════════════════════════════════════════════
# APPROACH O: Test if any short Beaufort/Vigenère gives >-6.0 score
# ═══════════════════════════════════════════════════════════════
print("\n=== APPROACH O: Exhaustive short-key scan with best perm candidates ===")

# From v1, best permutation was F1_col_w61 with score -7.64
# Let's test the top 5 permutation candidates with ALL 2-3 letter keywords in AZ
p_col61 = col_read_perm(61)
p_col82 = col_read_perm(82)
p_stride94 = [(i * 94) % 97 for i in range(97)]
p_stride12 = [(i * 12) % 97 for i in range(97)]

top_perms = [
    ("col61", p_col61),
    ("col82", p_col82),
    ("stride94", p_stride94),
    ("stride12", p_stride12),
]

best_overall = -1e9
best_result = None

for pname, perm in top_perms:
    ct2 = apply_perm(K4, perm)
    # Try all 2-letter keywords (676 combos) and all 3-letter keywords in AZ
    for klen in [2, 3]:
        if klen == 2:
            keys = [a+b for a in AZ for b in AZ]
        else:
            keys = [a+b+c for a in AZ for b in AZ for c in AZ[:5]]  # limit

        for kw in keys:
            for alpha in [AZ, KA]:
                pt = vig_dec(ct2, kw, alpha)
                ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT O_{pname}_{kw}: ENE@{ene} BC@{bc}")
                    print(f"    PT: {pt}")
                sc = score_per_char(pt)
                if sc > best_overall:
                    best_overall = sc
                    best_result = (pname, kw, pt, sc)
                if sc > -7.0:
                    print(f"  HIGH SCORE O_{pname}_vig_{kw}: {sc:.4f}")
                    print(f"    PT: {pt}")

if best_result:
    pname, kw, pt, sc = best_result
    print(f"\nBest from approach O: [{pname}+{kw}] sc={sc:.4f}")
    print(f"  PT: {pt}")

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("SUMMARY")
print("="*60)
print(f"Tests run: {len(tested)}, Results: {len(all_results)}")

if crib_hits:
    print(f"\n{'!'*60}\nCRIB HITS: {len(crib_hits)}")
    for h in crib_hits:
        print(f"  [{h['label']}]  ENE@{h['ene_pos']}  BC@{h['bc_pos']}")
        print(f"  PT: {h['pt']}\n  Score: {h['score']:.4f}")
else:
    print("\nNo crib hits found.")

if all_results:
    top = sorted(all_results, key=lambda r: r['score'], reverse=True)[:15]
    print("\nTop 15 results by quadgram score:")
    for r in top:
        print(f"  [{r['label'][:50]:50s}] sc={r['score']:.4f} {r['key'][:12]} {r['cipher']}/{r['alpha']}")
        print(f"    PT: {r['pt'][:70]}")

with open(f"{RESULTS_DIR}/results_v2.json", 'w') as f:
    json.dump({"crib_hits": crib_hits,
               "top_results": sorted(all_results, key=lambda r: r['score'], reverse=True)[:30],
               "total_tested": len(tested)}, f, indent=2, default=str)
print(f"\nSaved to {RESULTS_DIR}/results_v2.json\nDone.")
