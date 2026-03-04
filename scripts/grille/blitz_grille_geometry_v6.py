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
Blitz Grille Geometry v6 — Genuinely new approaches NOT covered in v1-v5.

CRITICAL FIX vs previous scripts: 1=HOLE, 0=SOLID (verified).
This gives 114 in-grid holes (106 with tableau letters = GE).

v5 covered: GE[:97] rank, column-of-holes key, physical overlay (offsets ≈18-27),
hole coords (r*C+c) mod 97 for C=26-39, Manhattan/Euclidean/diagonal sort,
columnar transpositions widths 7/8/9/12/13/14, period-8 layouts, SA.

NEW in v6:
  A. GE substrings at offsets 1-9 as rank-permutations (v5 did only offset 0)
  B. GE reversed substrings as rank-permutations
  C. Mirrored/rotated grille masks (H-flip, V-flip, 180° rotation) — CORRECT HOLES
  D. Row-based hole count transposition key (v5 did column-based)
  E. GE as running key at offsets 0-9 (direct Vig/Beau decryption)
  F. New hole-coordinate formulas: r*c, r^2, c^2, XOR, cumulative sum
  G. Physical overlay ALL row offsets 0-27 (v5 did only ~18-27)
  H. Mod-97 collision analysis for actual 114 holes
  I. Grille row strips → various ordering of non-empty rows
  J. Column-index sequence of holes as permutation keys
  K. Interleaved/alternating readings (first/second half, odd/even rows)
  L. K4 char first-GE-occurrence position as permutation key
  M. Keyword-labeled columnar (keyword for each key×alphabet combination)
  N. Period-7/8/10 group permutations (group-by-key-char)
  O. Distance sort from specific grille feature points
  P. Hole pair analysis: holes at same column, row-distance as key
"""

import json, sys, os, math, itertools
from collections import defaultdict, Counter

sys.path.insert(0, 'scripts')
sys.path.insert(0, 'src')

# ── Constants ─────────────────────────────────────────────────────────────────

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GE) == 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
            'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']

QG = json.load(open('data/english_quadgrams.json'))

RESULTS_DIR = "blitz_results/grille_geometry"
os.makedirs(RESULTS_DIR, exist_ok=True)

hits = []
all_results = []
tested_count = 0

# ── Helpers ───────────────────────────────────────────────────────────────────

def score_pc(text):
    t = text.upper(); n = len(t) - 3
    return sum(QG.get(t[i:i+4], -10.) for i in range(n)) / n if n > 0 else -10.

def vig_dec(ct, key, alpha=AZ):
    ai = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(ai[ct[i]] - ai[key[i % len(key)]]) % 26] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    ai = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(ai[key[i % len(key)]] - ai[ct[i]]) % 26] for i in range(len(ct)))

def is_valid(sigma, n=97):
    return len(sigma) == n and len(set(sigma)) == n and all(0 <= x < n for x in sigma)

def report_hit(label, pt, sigma=None):
    ene = pt.find("EASTNORTHEAST")
    bc  = pt.find("BERLINCLOCK")
    sc  = score_pc(pt)
    print(f"\n{'!'*72}")
    print(f"*** CRIB HIT: {label}")
    print(f"    ENE@{ene}  BC@{bc}  score/char={sc:.4f}")
    print(f"    PT: {pt}")
    if sigma: print(f"    sigma[:20]={list(sigma)[:20]}...")
    print('!'*72)
    hits.append({"label": label, "pt": pt, "ene": ene, "bc": bc, "score": sc})

def test_sigma(sigma, label_base=""):
    """Test sigma (real_CT[j] = K4[sigma[j]]) under all ciphers/keys."""
    global tested_count
    if not is_valid(sigma):
        return -1e9
    tested_count += 1
    real_ct = ''.join(K4[sigma[j]] for j in range(97))
    best_sc = -1e9
    best_r = {}
    for alpha_nm, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for cn, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                try:
                    pt = fn(real_ct, kw, alpha)
                except Exception:
                    continue
                sc = score_pc(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    report_hit(f"{label_base}_{cn}_{alpha_nm}_{kw}", pt, list(sigma))
                    return sc
                if sc > best_sc:
                    best_sc = sc
                    best_r = {"label": f"{label_base}_{cn}_{alpha_nm}_{kw}", "pt": pt, "score": sc}
    if best_r:
        all_results.append(best_r)
    return best_sc

def test_ct_direct(ct97, label):
    """Directly test a 97-char candidate real_CT."""
    global tested_count
    tested_count += 1
    for alpha_nm, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for cn, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                try:
                    pt = fn(ct97, kw, alpha)
                except Exception:
                    continue
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    report_hit(f"{label}_{cn}_{alpha_nm}_{kw}", pt)
                    return True
    return False

def rank_perm(chars, alpha):
    """Rank-sort n chars by alpha order → valid permutation of 0..n-1."""
    n = len(chars)
    return sorted(range(n), key=lambda i: (alpha.index(chars[i]), i))

# ── Build grille hole list — 1=HOLE, 0=SOLID ─────────────────────────────────

MASK_ROWS_RAW = [
    "000000001010100000000010000000001",   # row 0
    "100000000010000001000100110000011",   # row 1
    "000000000000001000000000000000011",   # row 2
    "00000000000000000000100000010011",    # row 3
    "00000001000000001000010000000011",    # row 4
    "000000001000000000000000000000011",   # row 5
    "100000000000000000000000000000011",   # row 6
    "00000000000000000000000100000100",    # row 7
    "0000000000000000000100000001000",     # row 8
    "0000000000000000000000000000100",     # row 9
    "000000001000000000000000000000",      # row 10
    "00000110000000000000000000000100",    # row 11
    "00000000000000100010000000000001",    # row 12
    "00000000000100000000000000001000",    # row 13
    "000110100001000000000000001000010",   # row 14
    "00001010000000000000000001000001",    # row 15
    "001001000010010000000000000100010",   # row 16
    "00000000000100000000010000010001",    # row 17
    "000000000000010001001000000010001",   # row 18
    "00000000000000001001000000000100",    # row 19
    "000000001100000010100100010001001",   # row 20
    "000000000000000100001010100100011",   # row 21
    "00000000100000000000100001100001",    # row 22
    "100000000000000000001000001000010",   # row 23
    "10000001000001000000100000000001",    # row 24
    "000010000000000000010000100000011",   # row 25
    "0000000000000000000100001000000011",  # row 26
    "00000000000000100000001010000001",    # row 27
]

# CORRECT CONVENTION: 1=HOLE, 0=SOLID
holes_all = [(r, c) for r, row in enumerate(MASK_ROWS_RAW)
             for c, ch in enumerate(row) if ch == '1' and c < 33]

N_HOLES = len(holes_all)
print(f"Total 1-holes (c<33): {N_HOLES}")

# Row distribution
row_holes = Counter(r for r, c in holes_all)
for r in range(28):
    if row_holes[r]:
        cols = [c for rr, c in holes_all if rr == r]
        print(f"  Row {r:2d}: {row_holes[r]} holes at {cols}")

# GE-letter mapping: GE[k] = letter at the k-th hole that has a tableau letter
# For now we assume ALL holes map to GE chars (might have slight off-by-one at boundaries)
# Use first min(N_HOLES, 106) holes for GE correspondence
def hole_ge_letter(i):
    return GE[i] if i < len(GE) else None

# ── APPROACH A: GE SUBSTRINGS AT OFFSETS 0-9 (rank-permutations) ─────────────

print("\n" + "="*72)
print("APPROACH A: GE SUBSTRINGS AT ALL OFFSETS (v5 did only offset 0)")
print("="*72)

count_a = 0
for offset in range(10):
    if offset + 97 > len(GE):
        break
    substr = GE[offset:offset+97]
    for alpha_nm, alpha in [("AZ", AZ), ("KA", KA)]:
        # Forward rank
        sigma = rank_perm(substr, alpha)
        test_sigma(sigma, f"A_ge_off{offset}_rank_{alpha_nm}")
        # Inverse rank
        inv = [0]*97
        for j, v in enumerate(sigma): inv[v] = j
        test_sigma(inv, f"A_ge_off{offset}_invrank_{alpha_nm}")
        count_a += 2

# B: Reversed GE at all offsets
GE_REV = GE[::-1]
for offset in range(10):
    if offset + 97 > len(GE_REV):
        break
    substr = GE_REV[offset:offset+97]
    for alpha_nm, alpha in [("AZ", AZ), ("KA", KA)]:
        sigma = rank_perm(substr, alpha)
        test_sigma(sigma, f"A_ge_rev_off{offset}_rank_{alpha_nm}")
        count_a += 1

print(f"Approach A: {count_a} tested")

# ── APPROACH B: MIRRORED/ROTATED GRILLE (correct holes) ──────────────────────

print("\n" + "="*72)
print("APPROACH B: MIRRORED/ROTATED GRILLE MASKS")
print("="*72)

NROWS, NCOLS = 28, 33

def transform_holes(holes, mode):
    if mode == "hflip":
        th = [(r, NCOLS-1-c) for r, c in holes]
    elif mode == "vflip":
        th = [(NROWS-1-r, c) for r, c in holes]
    elif mode == "rot180":
        th = [(NROWS-1-r, NCOLS-1-c) for r, c in holes]
    elif mode == "colmaj":
        th = sorted(holes, key=lambda x: (x[1], x[0]))
        return th
    elif mode == "colmaj_hflip":
        th = sorted([(r, NCOLS-1-c) for r, c in holes], key=lambda x: (x[1], x[0]))
        return th
    elif mode == "colmaj_vflip":
        th = sorted([(NROWS-1-r, c) for r, c in holes], key=lambda x: (x[1], x[0]))
        return th
    elif mode == "antidiag":
        th = sorted(holes, key=lambda x: (x[0]+x[1], x[0]))
        return th
    elif mode == "zigzag":
        th = sorted(holes, key=lambda x: (x[0], x[1] if x[0]%2==0 else -x[1]))
        return th
    else:
        return holes[:]
    return sorted(th, key=lambda x: (x[0], x[1]))

# Map from original hole position to GE letter
orig_pos_to_ge = {(r,c): GE[i] for i, (r,c) in enumerate(holes_all) if i < len(GE)}

count_b = 0
for mode in ["hflip", "vflip", "rot180", "colmaj", "colmaj_hflip", "colmaj_vflip",
             "antidiag", "zigzag"]:
    th = transform_holes(holes_all, mode)
    th97 = th[:97]

    # Method 1: rank by linear position r*33+c
    lp_rank = sorted(range(len(th97)), key=lambda i: th97[i][0]*33 + th97[i][1])
    if is_valid(lp_rank):
        test_sigma(lp_rank, f"B_{mode}_linrank")
        count_b += 1

    # Method 2: rank by GE letter at original position
    letters = [orig_pos_to_ge.get(rc, 'A') for rc in th97]
    for alpha_nm, alpha in [("AZ", AZ), ("KA", KA)]:
        sigma = rank_perm(letters, alpha)
        test_sigma(sigma, f"B_{mode}_letrank_{alpha_nm}")
        count_b += 1

print(f"Approach B: {count_b} tested")

# ── APPROACH C: ROW-BASED HOLE COUNT TRANSPOSITION ────────────────────────────

print("\n" + "="*72)
print("APPROACH C: ROW-BASED HOLE COUNT TRANSPOSITION KEY")
print("="*72)

def columnar_perm_by_key(text, col_key, width):
    n = len(text)
    n_rows = (n + width - 1) // width
    col_order = sorted(range(width), key=lambda c: col_key[c])
    sigma = []
    for col in col_order:
        for row in range(n_rows):
            in_idx = row * width + col
            if in_idx < n:
                sigma.append(in_idx)
    return sigma

row_hole_counts = [row_holes.get(r, 0) for r in range(28)]
print(f"Row hole counts (rows 0-27): {row_hole_counts}")

count_c = 0
for width in [4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 28]:
    key = row_hole_counts[:width]
    sigma = columnar_perm_by_key(K4, key, width)
    if is_valid(sigma):
        test_sigma(sigma, f"C_rowkey_w{width}_holecount")
        count_c += 1
    key_inv = [-x for x in key]
    sigma_inv = columnar_perm_by_key(K4, key_inv, width)
    if is_valid(sigma_inv):
        test_sigma(sigma_inv, f"C_rowkey_w{width}_holecount_inv")
        count_c += 1

# Also: use first-hole-column in each row as key
row_first_col = {}
for r in range(28):
    cols_in_r = sorted(c for rr, c in holes_all if rr == r)
    row_first_col[r] = cols_in_r[0] if cols_in_r else 99

row_first_key = [row_first_col[r] for r in range(28)]
for width in [7, 8, 9, 10, 12, 13, 14, 28]:
    key = row_first_key[:width]
    sigma = columnar_perm_by_key(K4, key, width)
    if is_valid(sigma):
        test_sigma(sigma, f"C_rowkey_w{width}_firstcol")
        count_c += 1

# Column hole count (for completeness, even though v5 did this)
col_holes = Counter(c for r, c in holes_all)
col_key_counts = [col_holes.get(c, 0) for c in range(33)]
print(f"Column hole counts: {col_key_counts}")
for width in [7, 8, 13, 33]:
    key = col_key_counts[:width]
    sigma = columnar_perm_by_key(K4, key, width)
    if is_valid(sigma):
        test_sigma(sigma, f"C_colkey_w{width}_holecount_1hole")
        count_c += 1
    key_inv = [-x for x in key]
    sigma_inv = columnar_perm_by_key(K4, key_inv, width)
    if is_valid(sigma_inv):
        test_sigma(sigma_inv, f"C_colkey_w{width}_holecount_inv_1hole")
        count_c += 1

print(f"Approach C: {count_c} tested")

# ── APPROACH D: GE AS RUNNING KEY (all offsets × all cipher × alphabet) ──────

print("\n" + "="*72)
print("APPROACH D: GE AS RUNNING KEY — ALL OFFSETS AND DIRECTIONS")
print("="*72)

count_d = 0
for ge_src, src_name in [(GE, "fwd"), (GE[::-1], "rev")]:
    for offset in range(10):
        if offset + 97 > len(ge_src):
            break
        running_key = ge_src[offset:offset+97]
        for cn, fn in [("vig", vig_dec), ("beau", beau_dec)]:
            for anm, alpha in [("AZ", AZ), ("KA", KA)]:
                try:
                    pt = fn(K4, running_key, alpha)
                    ene = pt.find("EASTNORTHEAST"); bc = pt.find("BERLINCLOCK")
                    if ene >= 0 or bc >= 0:
                        report_hit(f"D_ge_{src_name}_off{offset}_{cn}_{anm}", pt)
                except Exception:
                    pass
                count_d += 1

print(f"Approach D: {count_d} running-key tests done")

# ── APPROACH E: NEW HOLE-COORDINATE FORMULAS ──────────────────────────────────

print("\n" + "="*72)
print("APPROACH E: NEW HOLE-COORDINATE FORMULAS (with correct 1-holes)")
print("="*72)

count_e = 0

def try_vals(vals, label):
    """Try vals as direct permutation or as rank-based permutation."""
    global count_e
    n = len(vals)
    if n != 97:
        return
    if is_valid(vals):
        test_sigma(list(vals), label + "_direct")
        count_e += 1
    # Always try rank
    ranked = sorted(range(n), key=lambda i: (vals[i], i))
    if is_valid(ranked):
        test_sigma(ranked, label + "_rank")
        count_e += 1
    inv = [0]*n
    for j, v in enumerate(ranked): inv[v] = j
    if is_valid(inv):
        test_sigma(inv, label + "_invrank")
        count_e += 1

h97 = holes_all[:97]

# r*c mod 97
try_vals([(r*c) % 97 for r,c in h97], "E_rc_mod97")
# r^2 mod 97
try_vals([(r*r) % 97 for r,c in h97], "E_r2_mod97")
# c^2 mod 97
try_vals([(c*c) % 97 for r,c in h97], "E_c2_mod97")
# (r+c)^2 mod 97
try_vals([((r+c)**2) % 97 for r,c in h97], "E_rcsum2_mod97")
# (r-c)^2 mod 97
try_vals([((r-c)**2) % 97 for r,c in h97], "E_rcdiff2_mod97")
# r XOR c
try_vals([r ^ c for r,c in h97], "E_rxorc")
# r*r + c*c mod 97
try_vals([(r*r + c*c) % 97 for r,c in h97], "E_r2c2_mod97")
# r*r*c mod 97
try_vals([(r*r*c) % 97 for r,c in h97], "E_r2c_mod97")
# r*c*c mod 97
try_vals([(r*c*c) % 97 for r,c in h97], "E_rc2_mod97")
# (r*c + r + c) mod 97
try_vals([(r*c + r + c) % 97 for r,c in h97], "E_rcplusmix_mod97")
# (2r + 3c) mod 97, (3r + 2c) mod 97
try_vals([(2*r + 3*c) % 97 for r,c in h97], "E_2r3c_mod97")
try_vals([(3*r + 2*c) % 97 for r,c in h97], "E_3r2c_mod97")
# (r + c*33) mod 97 (reversed linear)
try_vals([(r + c*33) % 97 for r,c in h97], "E_rcrev33_mod97")
# cumulative sum of r+c mod 97
cs = 0; cumv = []
for r,c in h97:
    cs = (cs + r + c) % 97
    cumv.append(cs)
try_vals(cumv, "E_cumsum_rc")

# Try all first 97 holes that give unique values mod 97 for (r*C+c)
for C in [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
          21, 22, 23, 24, 25, 33, 34, 97]:
    vals = [(r*C + c) % 97 for r,c in h97]
    if is_valid(vals):
        test_sigma(vals, f"E_rCc_mod97_C{C}")
        count_e += 1
    # Also with all N_HOLES
    if N_HOLES >= 97:
        vals_all = [(r*C + c) % 97 for r,c in holes_all]
        # Take first 97 that are unique
        seen = set(); sel = []
        for i, v in enumerate(vals_all):
            if v not in seen:
                seen.add(v)
                sel.append(v)
            if len(sel) == 97:
                break
        if len(sel) == 97 and is_valid(sel):
            test_sigma(sel, f"E_rCc_mod97_C{C}_unique")
            count_e += 1

print(f"Approach E: {count_e} tested")

# ── APPROACH F: LINEAR POSITION SELECT (r*33+c < 97) ─────────────────────────

print("\n" + "="*72)
print("APPROACH F: LINEAR POSITION SELECT — K4 AT START OF 28×33 GRID")
print("="*72)

lpos_valid = [(lp := r*33+c, lp) for r,c in holes_all if r*33+c < 97]
sigma_f = [lp for _, lp in lpos_valid]
print(f"Holes with linear pos < 97: {len(sigma_f)}")
if sigma_f:
    print(f"  -> {sigma_f}")
    if is_valid(sigma_f):
        test_sigma(sigma_f, "F_linpos_lt97")
    ranked_f = sorted(range(len(sigma_f)), key=lambda i: sigma_f[i])
    if is_valid(ranked_f):
        test_sigma(ranked_f, "F_linpos_lt97_ranked")

# Try: first 97 holes that DON'T fall on header rows/cols of KA tableau
# The KA tableau body is rows 1-26, cols 1-26 (approximately)
# Filter: 0 < r <= 26 AND 0 < c <= 26
tableau_holes = [(r,c) for r,c in holes_all if 0 < r <= 26 and 0 < c <= 26]
print(f"Holes in tableau body (rows 1-26, cols 1-26): {len(tableau_holes)}")
if len(tableau_holes) >= 97:
    sigma_tab = [r*27+c-28 for r,c in tableau_holes[:97]]  # map to 0-96
    # Actually just rank by linear position in body
    lps_tab = [r*26+(c-1) for r,c in tableau_holes[:97]]
    if len(set(lps_tab)) == 97 and all(0 <= v < 97 for v in lps_tab):
        test_sigma(lps_tab, "F_tableau_body_linpos")
    ranked_tab = sorted(range(len(tableau_holes[:97])),
                        key=lambda i: tableau_holes[i][0]*33+tableau_holes[i][1])
    if is_valid(ranked_tab):
        test_sigma(ranked_tab, "F_tableau_body_rank")

# ── APPROACH G: MOD-97 COLLISION ANALYSIS ────────────────────────────────────

print("\n" + "="*72)
print("APPROACH G: MOD-97 COLLISION ANALYSIS")
print("="*72)

for C in [33, 28, 29, 30, 31, 32, 34, 1]:
    vals97 = [(r*C + c) % 97 for r,c in holes_all]
    groups = defaultdict(list)
    for i, v in enumerate(vals97):
        groups[v].append(i)
    doubles = [(v, g) for v, g in groups.items() if len(g) == 2]
    singletons = [v for v, g in groups.items() if len(g) == 1]
    triples = [(v, g) for v, g in groups.items() if len(g) >= 3]
    uncovered = 97 - len(groups)  # values 0-96 not represented
    print(f"  C={C}: singletons={len(singletons)}, doubles={len(doubles)}, "
          f"triples+={len(triples)}, uncovered={uncovered}")

    if len(doubles) <= 12 and len(triples) == 0 and uncovered == 0:
        print(f"    -> Resolving {len(doubles)} pairs...")
        count_g = 0
        double_groups = [g for v, g in doubles]
        sing_dict = {v: g[0] for v, g in groups.items() if len(g) == 1}
        for choices in itertools.product(*[[0,1] for _ in double_groups]):
            selected = {v: sing_dict[v] for v in singletons}
            for ci, (choice, dg) in enumerate(zip(choices, double_groups)):
                v = [k for k, gg in groups.items() if gg == dg][0]
                selected[v] = dg[choice]
            # Build sigma: sigma[j] = which hole index in reading order
            # corresponds to mod-97 value j?
            # sigma[v] = selected[v] means: real_CT[v] = K4[sigma[v]]
            # But sigma[v] should be a K4 position (0-96), not a hole index
            sigma_g = [selected[v] % 97 for v in range(97)]
            if is_valid(sigma_g):
                test_sigma(sigma_g, f"G_C{C}_resolve")
                count_g += 1
        print(f"    -> Tested {count_g}")

# ── APPROACH H: GRILLE ROW STRIPS ────────────────────────────────────────────

print("\n" + "="*72)
print("APPROACH H: GRILLE ROW STRIPS — READING K4 BY ROW GROUPS")
print("="*72)

# Each grille row defines which K4 positions are in that row's "strip".
# In the standard Cardan grille usage: write real_CT through holes row-by-row.
# Holes in row r get chars r*n_cols_per_row + col_rank_in_row.
# When reading the carved text (K4), the holes in reading order = real_CT order.

# Build per-row hole lists in column order
row_hole_cols = defaultdict(list)
for r, c in holes_all:
    row_hole_cols[r].append(c)
for r in row_hole_cols:
    row_hole_cols[r].sort()

# The reading order of all holes is already holes_all (row-major, col-major within row).
# Strip permutations: reorder the rows.

# Assign sequential positions to holes in reading order
hole_reading_pos = {(r,c): i for i, (r,c) in enumerate(holes_all)}

active_rows = sorted(r for r in range(28) if row_holes[r] > 0)
print(f"Active rows ({len(active_rows)}): {active_rows}")

def strip_perm_from_row_order(row_order):
    """Given row reading order, return sigma for first 97 holes."""
    positions = []
    for r in row_order:
        for c in row_hole_cols[r]:
            positions.append(hole_reading_pos[(r,c)])
    # sigma[j] = positions[j] for j=0..96 (if valid)
    if len(positions) >= 97:
        s97 = positions[:97]
        if is_valid(s97):
            return s97
    return None

count_h = 0
half = len(active_rows) // 2
for variant_name, row_order in [
    ("identity",   active_rows),
    ("reversed",   list(reversed(active_rows))),
    ("first_rev",  list(reversed(active_rows[:half])) + active_rows[half:]),
    ("second_rev", active_rows[:half] + list(reversed(active_rows[half:]))),
    ("odd_even",   active_rows[::2] + active_rows[1::2]),
    ("even_odd",   active_rows[1::2] + active_rows[::2]),
    ("top_half_only", active_rows[:half]),
    ("bot_half_only", active_rows[half:]),
]:
    sigma = strip_perm_from_row_order(row_order)
    if sigma:
        test_sigma(sigma, f"H_rowstrip_{variant_name}")
        count_h += 1

# Sort rows by hole count (ascending, descending)
row_by_count_asc = sorted(active_rows, key=lambda r: row_holes[r])
row_by_count_desc = sorted(active_rows, key=lambda r: -row_holes[r])
for rname, rorder in [("bycount_asc", row_by_count_asc),
                       ("bycount_desc", row_by_count_desc)]:
    sigma = strip_perm_from_row_order(rorder)
    if sigma:
        test_sigma(sigma, f"H_rowstrip_{rname}")
        count_h += 1

# Sort rows by first-hole column
row_by_firstcol = sorted(active_rows, key=lambda r: min(row_hole_cols[r]))
sigma = strip_perm_from_row_order(row_by_firstcol)
if sigma:
    test_sigma(sigma, "H_rowstrip_byfirstcol")
    count_h += 1

print(f"Approach H: {count_h} tested")

# ── APPROACH I: PHYSICAL OVERLAY — ALL ROW OFFSETS ───────────────────────────

print("\n" + "="*72)
print("APPROACH I: PHYSICAL OVERLAY — ALL ROW OFFSETS 0-27")
print("="*72)

FULL_K4_START = 768
count_i = 0

for row_width in [29, 30, 31, 32, 33]:
    for grille_offset in range(28):
        sigma_i = []
        for r, c in holes_all:
            sculpt_pos = (r + grille_offset) * row_width + c - FULL_K4_START
            if 0 <= sculpt_pos < 97:
                sigma_i.append(sculpt_pos)
        if len(sigma_i) == 97 and is_valid(sigma_i):
            test_sigma(sigma_i, f"I_w{row_width}_off{grille_offset}")
            count_i += 1
            print(f"  VALID: width={row_width}, offset={grille_offset}")

print(f"Approach I: {count_i} valid overlay permutations")

# ── APPROACH J: COLUMN SEQUENCE OF HOLES AS PERMUTATION ──────────────────────

print("\n" + "="*72)
print("APPROACH J: COLUMN INDEX SEQUENCE OF HOLES")
print("="*72)

col_seq = [c for r, c in holes_all]
row_seq = [r for r, c in holes_all]

print(f"Col sequence (first 30): {col_seq[:30]}")
print(f"Row sequence (first 30): {row_seq[:30]}")
print(f"Unique cols: {sorted(set(col_seq))}")
print(f"Unique rows: {sorted(set(row_seq))}")

count_j = 0

# Method J1: col indices mod 97 (each col 0-32 → map to 0-96)
# scale factor: 97//33 = 2, 33*3=99≈97
for scale in [1, 2, 3, 97]:
    vals = [(c * scale) % 97 for c in col_seq[:97]]
    if is_valid(vals):
        test_sigma(vals, f"J_colseq_s{scale}_mod97")
        count_j += 1
    ranked = sorted(range(97), key=lambda i: (col_seq[i], row_seq[i]))
    if is_valid(ranked):
        test_sigma(ranked, f"J_colseq_rank_s{scale}")
        count_j += 1

# Rank by col-then-row (already done in E but for first 97 holes)
ranked_cr = sorted(range(N_HOLES), key=lambda i: (col_seq[i], row_seq[i]))[:97]
if is_valid(ranked_cr):
    test_sigma(ranked_cr, "J_colrow_rank")
    count_j += 1

# Rank by row-then-col (standard, already in hole reading order essentially)
# But try reversed
ranked_rc_rev = sorted(range(N_HOLES), key=lambda i: (-row_seq[i], -col_seq[i]))[:97]
if is_valid(ranked_rc_rev):
    test_sigma(ranked_rc_rev, "J_rowcol_revrank")
    count_j += 1

print(f"Approach J: {count_j} tested")

# ── APPROACH K: INTERLEAVED READINGS ─────────────────────────────────────────

print("\n" + "="*72)
print("APPROACH K: INTERLEAVED/ALTERNATING HOLE READINGS")
print("="*72)

count_k = 0

def holes_to_sigma(hole_list):
    """Convert ordered hole list to permutation via linear-position rank."""
    h97 = hole_list[:97]
    lps = [r*33+c for r,c in h97]
    ranked = sorted(range(len(h97)), key=lambda i: lps[i])
    return ranked if is_valid(ranked) else None

# Odd/even indexed holes
odd_h  = holes_all[::2]
even_h = holes_all[1::2]

for combo_name, combo in [
    ("odd_even",     odd_h + even_h),
    ("even_odd",     even_h + odd_h),
    ("odd_fwd_even_rev", odd_h + list(reversed(even_h))),
    ("even_fwd_odd_rev", even_h + list(reversed(odd_h))),
]:
    if len(combo) >= 97:
        s = holes_to_sigma(combo)
        if s: test_sigma(s, f"K_{combo_name}"); count_k += 1

# Top half / bottom half rows
top_h = [(r,c) for r,c in holes_all if r < 14]
bot_h = [(r,c) for r,c in holes_all if r >= 14]
for combo_name, combo in [
    ("top_bot",     top_h + bot_h),
    ("bot_top",     bot_h + top_h),
    ("top_fwd_bot_rev", top_h + list(reversed(bot_h))),
    ("bot_fwd_top_rev", bot_h + list(reversed(top_h))),
    ("top_rev_bot_fwd", list(reversed(top_h)) + bot_h),
]:
    if len(combo) >= 97:
        s = holes_to_sigma(combo)
        if s: test_sigma(s, f"K_{combo_name}"); count_k += 1

# Left/right column halves
left_h  = [(r,c) for r,c in holes_all if c < 17]
right_h = [(r,c) for r,c in holes_all if c >= 17]
for combo_name, combo in [
    ("left_right",  left_h + right_h),
    ("right_left",  right_h + left_h),
    ("left_rrev",   left_h + list(reversed(right_h))),
    ("right_lrev",  right_h + list(reversed(left_h))),
]:
    if len(combo) >= 97:
        s = holes_to_sigma(combo)
        if s: test_sigma(s, f"K_{combo_name}"); count_k += 1

print(f"Approach K: {count_k} tested")

# ── APPROACH L: K4 CHAR → GE FIRST-OCCURRENCE ────────────────────────────────

print("\n" + "="*72)
print("APPROACH L: K4 CHAR → GE FIRST-OCCURRENCE POSITION")
print("="*72)

count_l = 0
ge_first = {}
for i, letter in enumerate(GE):
    if letter not in ge_first:
        ge_first[letter] = i
for letter in AZ:
    if letter not in ge_first:
        ge_first[letter] = 200  # T maps to 200 (absent from GE)

# For each K4 position j, get first occurrence of K4[j] in GE
fo_vals = [ge_first[K4[j]] for j in range(97)]
ranked = sorted(range(97), key=lambda j: (fo_vals[j], j))
if is_valid(ranked):
    test_sigma(ranked, "L_k4_ge_firstocc_rank")
    count_l += 1
inv = [0]*97
for j, v in enumerate(ranked): inv[v] = j
if is_valid(inv):
    test_sigma(inv, "L_k4_ge_firstocc_invrank")
    count_l += 1

# K4 position → GE last occurrence
ge_last = {}
for i, letter in enumerate(GE):
    ge_last[letter] = i
for letter in AZ:
    if letter not in ge_last:
        ge_last[letter] = -1

lo_vals = [ge_last[K4[j]] for j in range(97)]
ranked2 = sorted(range(97), key=lambda j: (lo_vals[j], j))
if is_valid(ranked2):
    test_sigma(ranked2, "L_k4_ge_lastocc_rank")
    count_l += 1

print(f"Approach L: {count_l} tested")

# ── APPROACH M: KEYWORD COLUMNAR (proper keyword × alphabet pairs) ────────────

print("\n" + "="*72)
print("APPROACH M: KEYWORD COLUMNAR (all keywords × both alphabets)")
print("="*72)

count_m = 0

def keyword_col_perm(kw, alpha, width=None):
    """Columnar transposition using keyword to define column reading order."""
    if width is None:
        width = len(kw)
    # Rank-order columns by keyword letter in alpha
    col_order = sorted(range(width), key=lambda i: (alpha.index(kw[i % len(kw)]), i))
    n = 97
    n_rows = (n + width - 1) // width
    sigma = []
    for col in col_order:
        for row in range(n_rows):
            pos = row * width + col
            if pos < n:
                sigma.append(pos)
    return sigma if is_valid(sigma) else None

for kw in KEYWORDS:
    for alpha_nm, alpha in [("AZ", AZ), ("KA", KA)]:
        width = len(kw)
        sigma = keyword_col_perm(kw, alpha, width)
        if sigma:
            test_sigma(sigma, f"M_kw{kw}_{alpha_nm}_w{width}")
            count_m += 1
        # Read bottom-to-top
        col_order = sorted(range(width), key=lambda i: (alpha.index(kw[i % len(kw)]), i))
        n_rows = (97 + width - 1) // width
        sigma_btt = []
        for col in col_order:
            for row in range(n_rows-1, -1, -1):
                pos = row * width + col
                if pos < 97:
                    sigma_btt.append(pos)
        if is_valid(sigma_btt):
            test_sigma(sigma_btt, f"M_kw{kw}_{alpha_nm}_w{width}_btt")
            count_m += 1
        # Reverse column order
        sigma_rev = []
        for col in reversed(col_order):
            for row in range(n_rows):
                pos = row * width + col
                if pos < 97:
                    sigma_rev.append(pos)
        if is_valid(sigma_rev):
            test_sigma(sigma_rev, f"M_kw{kw}_{alpha_nm}_w{width}_revcol")
            count_m += 1

print(f"Approach M: {count_m} tested")

# ── APPROACH N: PERIOD-BASED GROUP PERMUTATIONS ───────────────────────────────

print("\n" + "="*72)
print("APPROACH N: PERIOD-BASED GROUP PERMUTATIONS")
print("="*72)

count_n = 0
for period in [5, 6, 7, 8, 9, 10, 11, 12, 13]:
    # Forward group: read all positions ≡ 0 (mod period), then ≡ 1, then ≡ 2, ...
    sigma_fwd = [k for g in range(period) for k in range(g, 97, period)]
    if is_valid(sigma_fwd):
        test_sigma(sigma_fwd, f"N_period{period}_group_fwd")
        count_n += 1
    # Reverse group order
    sigma_rev = [k for g in range(period-1, -1, -1) for k in range(g, 97, period)]
    if is_valid(sigma_rev):
        test_sigma(sigma_rev, f"N_period{period}_group_rev")
        count_n += 1
    # Boustrophedon by group
    sigma_bous = []
    for g in range(period):
        grp = list(range(g, 97, period))
        if g % 2 == 1:
            grp = list(reversed(grp))
        sigma_bous.extend(grp)
    if is_valid(sigma_bous):
        test_sigma(sigma_bous, f"N_period{period}_boustrophedon")
        count_n += 1

print(f"Approach N: {count_n} tested")

# ── APPROACH O: DISTANCE FROM GRILLE FEATURE POINTS ──────────────────────────

print("\n" + "="*72)
print("APPROACH O: DISTANCE SORT FROM GRILLE FEATURE POINTS")
print("="*72)

count_o = 0
# The tableau anomalies: extra L at row N (row 14 in 0-indexed), extra T at row V (row 22)
# These are at specific column positions in the KA tableau
# Use these as focal points for distance-based sorting

feature_points = [
    (14, 0), (14, 16), (14, 26),   # Row 14 (extra L row) at various cols
    (22, 0), (22, 16), (22, 26),   # Row 22 (extra T row) at various cols
    (14, 14), (22, 22), (0, 0),    # Diagonal points
    (7, 16), (21, 16),             # Middle rows
]

for fp in feature_points:
    fr, fc = fp
    # Manhattan distance from feature point
    dists = [abs(r-fr) + abs(c-fc) for r,c in holes_all[:97]]
    ranked = sorted(range(97), key=lambda i: (dists[i], holes_all[i][0], holes_all[i][1]))
    if is_valid(ranked):
        test_sigma(ranked, f"O_manhattan_{fr}_{fc}")
        count_o += 1
    # Euclidean distance
    dists_e = [(r-fr)**2 + (c-fc)**2 for r,c in holes_all[:97]]
    ranked_e = sorted(range(97), key=lambda i: (dists_e[i], holes_all[i][0], holes_all[i][1]))
    if is_valid(ranked_e):
        test_sigma(ranked_e, f"O_eucl_{fr}_{fc}")
        count_o += 1

print(f"Approach O: {count_o} tested")

# ── APPROACH P: GRILLE EXTRACT UNIQUE-LETTER PERMUTATION ─────────────────────

print("\n" + "="*72)
print("APPROACH P: GE UNIQUE-LETTER ORDER AND FREQUENCY SORTING")
print("="*72)

count_p = 0

# K4 sorted by frequency of that letter in GE
ge_freq = Counter(GE)
k4_by_ge_freq = sorted(range(97), key=lambda j: (ge_freq.get(K4[j], 0), j))
if is_valid(k4_by_ge_freq):
    test_sigma(k4_by_ge_freq, "P_k4_sort_by_ge_freq")
    count_p += 1
# Inverse
inv_p = [0]*97
for j, v in enumerate(k4_by_ge_freq): inv_p[v] = j
if is_valid(inv_p):
    test_sigma(inv_p, "P_k4_sort_by_ge_freq_inv")
    count_p += 1

# K4 sorted by KA-index, then by GE-frequency
for alpha_nm, alpha in [("AZ", AZ), ("KA", KA)]:
    ranked = sorted(range(97), key=lambda j: (alpha.index(K4[j]), ge_freq.get(K4[j], 0), j))
    if is_valid(ranked):
        test_sigma(ranked, f"P_k4_sort_alpha_{alpha_nm}_gfreq")
        count_p += 1

# GE sorted by KA-index, K4 matching
for alpha_nm, alpha in [("AZ", AZ), ("KA", KA)]:
    # Sort all 106 GE positions by alpha-index of GE[i], take first 97
    sorted_ge = sorted(range(106), key=lambda i: (alpha.index(GE[i]), i))
    first97 = sorted_ge[:97]
    if is_valid(first97):
        test_sigma(first97, f"P_ge106_sort_{alpha_nm}_first97")
        count_p += 1
    last97 = sorted_ge[9:]
    if is_valid(last97):
        test_sigma(last97, f"P_ge106_sort_{alpha_nm}_last97")
        count_p += 1

print(f"Approach P: {count_p} tested")

# ── APPROACH Q: CROSS-REFERENCE KNOWN K4 FACTS ───────────────────────────────

print("\n" + "="*72)
print("APPROACH Q: KNOWN CONSTRAINT — SELF-ENCRYPTING POSITIONS")
print("="*72)

# CT[32]=PT[32]=S, CT[73]=PT[73]=K
# Under Vigenère: PT[i] = CT[i] means key[i]=A (identity shift)
# So keyword[32 mod len(kw)] = A and keyword[73 mod len(kw)] = A
# For KRYPTOS (len=7): 32 mod 7 = 4 → KRYPTOS[4] = T ≠ A (contradiction unless T→A in KA)
# In AZ alphabet: T is at index 19. CT[32]=S is at index 18. PT[32]=S is at index 18.
# Vig decryption: PT = CT - key → 18 = 18 - key[4 mod 7] → key[4 mod 7] = 0 → key char = A
# But KRYPTOS[4] = T ≠ A in AZ. However in KA alphabet, T is at index 4!
# So if using KA alphabet: KRYPTOS[4 in KA] = T, which is at KA-index 4.
# We need KA-index(T) = 0 for self-encryption. But KA[0]=K ≠ T.
# This means Vigenère with KRYPTOS in AZ doesn't satisfy the self-encryption unless
# the scramble has placed S at position 32 of real_CT too (not just carved text).
# Under Model 2: PT[32]=S and real_CT[32]=... depends on key at pos 32.
# CT[32] in carved text = S. For self-encryption: PT[32]=CT[32]=S.
# real_CT[32] = carved[sigma(32)] for some sigma.
# This is a constraint on sigma: sigma(32) must be the position in carved where the
# letter that makes PT[32]=S is found.

# For KRYPTOS Vigenère: PT[32] = AZ[(real_CT[32]_AZ_idx - KRYPTOS[32%7]_AZ_idx) % 26]
# For PT[32]=S: AZ_idx(S)=18, AZ_idx(KRYPTOS[32%7=4]=T)=19
# 18 = (real_CT_32_idx - 19) % 26 → real_CT_32_idx = 37 % 26 = 11 → L
# So sigma(32) must be a position in K4 where the letter is L.
# K4 positions with L: [index for i,c in enumerate(K4) if c=='L']

k4_l_positions = [i for i, c in enumerate(K4) if c == 'L']
print(f"Positions of L in K4 (carved): {k4_l_positions}")
# sigma(32) must be one of these.

# For CT[73]=PT[73]=K, under Vig/KRYPTOS/AZ:
# AZ_idx(K)=10, KRYPTOS[73%7=3]=P, AZ_idx(P)=15
# 10 = (real_CT_73_idx - 15) % 26 → real_CT_73_idx = 25 → Z? Z=25
# Wait: 10 = (real_CT - 15) mod 26 → real_CT = 10+15 = 25 → Z
# So sigma(73) must be a position where K4[sigma(73)] = Z.
k4_z_positions = [i for i, c in enumerate(K4) if c == 'Z']
print(f"Positions of Z in K4 (carved): {k4_z_positions}")

# This gives us TWO anchor constraints:
# sigma(32) in {k4_l_positions}
# sigma(73) in {k4_z_positions}
# Combined with crib constraints, this significantly restricts valid permutations.

# For exhaustive search we'd need more infrastructure, but we can print this info.
print(f"Constraint: sigma(32) ∈ {k4_l_positions} (for Vig/KRYPTOS/AZ, PT[32]=S)")
print(f"Constraint: sigma(73) ∈ {k4_z_positions} (for Vig/KRYPTOS/AZ, PT[73]=K)")

count_q = 0
print(f"Approach Q: {count_q} additional tests (analysis only)")

# ── APPROACH R: GRILLE HOLES AS SPARSE INDEX INTO K4 ─────────────────────────

print("\n" + "="*72)
print("APPROACH R: SPARSE SELECTION — FIRST 97 UNIQUE K4 POSITIONS FROM HOLES")
print("="*72)

count_r = 0

# Map each hole's linear position to K4 position in various ways
for mod_val in [97, 96, 98, 99, 100]:
    vals = [(r*33+c) % mod_val for r,c in holes_all]
    # Find first 97 that give unique values 0..96
    if mod_val != 97:
        # Need to map mod_val → 97 range
        vals97 = [v % 97 for v in vals]
    else:
        vals97 = vals
    seen = set(); sel = []
    for v in vals97:
        if v not in seen and v < 97:
            seen.add(v)
            sel.append(v)
        if len(sel) == 97:
            break
    if len(sel) == 97 and is_valid(sel):
        test_sigma(sel, f"R_linpos_mod{mod_val}_first97unique")
        count_r += 1

print(f"Approach R: {count_r} tested")

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────────

print("\n" + "="*72)
print(f"DONE. Total tested: {tested_count}")
print(f"CRIB HITS: {len(hits)}")
print("="*72)

if hits:
    print("\n🎉 CRIB HITS FOUND:")
    for h in hits:
        print(f"  {h['label']}")
        print(f"    ENE@{h['ene']} BC@{h['bc']} score={h['score']:.4f}")
        print(f"    PT: {h['pt']}")
else:
    print("No crib hits. Top 5 by score:")
    if all_results:
        best5 = sorted(all_results, key=lambda x: -x['score'])[:5]
        for r in best5:
            print(f"  score={r['score']:.4f}  {r['label'][:50]}")
            print(f"  PT: {r['pt'][:70]}")

out = {
    "hits": hits,
    "top_results": sorted(all_results, key=lambda x: -x['score'])[:20],
    "total_tested": tested_count,
}
with open(f"{RESULTS_DIR}/results_v6.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\nSaved to {RESULTS_DIR}/results_v6.json")
