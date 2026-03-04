#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_t_position_extended.py — Deep dive on T-diagonal paradox + extended approaches.

KEY FINDING from blitz_t_position.py:
  3 holes are ON the T-diagonal at indices 21, 33, 90 — BUT T is absent from extract!
  This is paradoxical. Explanations:
  1. Physical column offset k≠0 (alphabet doesn't start at column 0 of mask)
  2. Those holes produce T but T is deliberately excluded from extract
  3. My t_col formula is wrong for the actual physical layout

This script:
  - Finds column offset k that places T outside all 107 holes
  - Uses corrected T-columns for ALL approaches
  - Treats the 3 T-diagonal holes as special "pivot" positions
  - Tries full enumeration of plausible T-column structures
  - Adds more novel permutation approaches
"""

import sys, json, os, math, itertools
from collections import defaultdict, Counter

sys.path.insert(0, 'src')

K4  = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA  = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
CRIB1 = "EASTNORTHEAST"
CRIB2 = "BERLINCLOCK"
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA',
            'LAYER','ILLUSION','IQLUSION','SHADOW','EAST','NORTH','BERLIN']

OUT_DIR = 'blitz_results/t_position'
os.makedirs(OUT_DIR, exist_ok=True)

qg = json.load(open('data/english_quadgrams.json'))
def qgscore(text):
    return sum(qg.get(text[i:i+4].upper(), -10.0) for i in range(len(text)-3))

# Expected good-English score: ~94 quadgrams × ~-4 = -376
# Noise score: ~94 × -10 = -940
# Threshold for "interesting": total > -600 (roughly -6.4/quadgram)
SCORE_THRESHOLD = -600  # raw total quadgram score

MASK_TEXT = """1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    ~
0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    1    1    0    1    1    1    1    0    0    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    1    0    ~    ~
1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    0    0    1    0    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    0    ~
1    1    1    1    0    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    ~    ~
1    1    0    1    1    0    1    1    1    1    0    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    0    1    ~    ~
1    1    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    0    1    1    0    1    1    0    ~    ~
1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    0    1    1    0    1    1    0    1    1    ~
1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    0    1    1
0    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    0    ~    ~
1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    ~    ~"""

HOLES = []
for r, line in enumerate(MASK_TEXT.strip().split('\n')):
    vals = line.split()
    for c, v in enumerate(vals):
        if v == '0':
            HOLES.append((r, c))

assert len(HOLES) == 107

# ── Utilities ─────────────────────────────────────────────────────────────────
def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

def invert_perm(perm):
    inv = [0]*len(perm)
    for i,p in enumerate(perm): inv[p] = i
    return inv

def is_valid_perm(perm, n=97):
    return len(perm) == n and set(perm) == set(range(n))

def vig_dec(ct, key, alpha=AZ):
    out = []
    for i,c in enumerate(ct):
        ci = alpha.find(c); ki = alpha.find(key[i % len(key)])
        if ci < 0 or ki < 0: return None
        out.append(alpha[(ci - ki) % 26])
    return ''.join(out)

def beau_dec(ct, key, alpha=AZ):
    out = []
    for i,c in enumerate(ct):
        ci = alpha.find(c); ki = alpha.find(key[i % len(key)])
        if ci < 0 or ki < 0: return None
        out.append(alpha[(ki - ci) % 26])
    return ''.join(out)

def stable_rank(vals):
    return sorted(range(len(vals)), key=lambda i: (vals[i], i))

RESULTS = []

def test_perm(perm, name="unnamed", verbose=False):
    if not is_valid_perm(perm): return None
    candidate_ct = apply_perm(K4, perm)
    best = None
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(candidate_ct, kw, alpha)
                if pt is None: continue
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n{'='*70}")
                    print(f"*** CRIB HIT [{name}]: ENE@{ene} BC@{bc}")
                    print(f"    key={kw} cipher={cipher_name}/{alpha_name}")
                    print(f"    CT: {candidate_ct}")
                    print(f"    PT: {pt}")
                    print(f"    Score: {sc:.2f}")
                    print(f"{'='*70}\n")
                    RESULTS.append((sc, name, list(perm), pt, kw, cipher_name, alpha_name))
                if best is None or sc > best[0]:
                    best = (sc, name, list(perm), pt, kw, cipher_name, alpha_name)
    if best and best[0] > SCORE_THRESHOLD:
        RESULTS.append(best)
        if verbose:
            print(f"  {name}: score={best[0]:.2f} [{best[4]}/{best[5]}/{best[6]}]")
    return best

# ── Section 1: Column Offset Analysis ─────────────────────────────────────────
print("═══ SECTION 1: Column Offset Analysis ═══")
print(f"Finding column offset k such that T lands OUTSIDE all 107 holes\n")

# t_col_k(r, k) = column where T appears in row r when alphabet starts at column k
# Formula: In row r, letter at col c is KA[(c - k + r) % 26] (for col c in [k, k+25])
# T is at col c where KA[(c - k + r) % 26] = T = KA[4]
# → (c - k + r) % 26 = 4 → c = (4 + k - r) % 26 + k (if that's in [k, k+25])
# Simplified: T is at physical col = k + (4 - r) % 26

def t_col_with_offset(r, k):
    """Physical column of T in row r when alphabet starts at column k."""
    return k + (4 - r) % 26  # physical column (may exceed 25)

# For each offset k, count how many holes fall on T-diagonal
print("Offset k | Holes on T-diagonal | Hole positions")
print("-" * 70)
best_offset_k = None
best_offset_count = 999
for k in range(-5, 10):  # try negative offsets too in case alphabet starts before col 0
    t_diag_hits = []
    for hole_idx, (r, c) in enumerate(HOLES):
        tc = t_col_with_offset(r, k)
        if c == tc and 0 <= tc <= 32:  # within physical bounds
            t_diag_hits.append((hole_idx, r, c))
    print(f"  k={k:2d}: {len(t_diag_hits)} hits → {[(h[1],h[2]) for h in t_diag_hits]}")
    if len(t_diag_hits) < best_offset_count:
        best_offset_count = len(t_diag_hits)
        best_offset_k = k

print(f"\nBest offset: k={best_offset_k} with {best_offset_count} T-diagonal hits")

# Also: for k=0, check which holes produce T (for reconstruction)
t_holes_k0 = [(i, r, c) for i,(r,c) in enumerate(HOLES) if c == (4-r)%26]
print(f"\nk=0: T-diagonal holes at indices {[h[0] for h in t_holes_k0]}")
print(f"  These are at reading positions: {[(h[1],h[2]) for h in t_holes_k0]}")

# Reconstruct full 107-char sequence WITH T inserted at those positions
# (assuming these 3 positions give T)
full_seq_107 = []
extract_iter = iter(GRILLE_EXTRACT)
t_hole_indices = set(h[0] for h in t_holes_k0)
for i in range(107):
    if i in t_hole_indices:
        full_seq_107.append('T')
    else:
        full_seq_107.append(next(extract_iter))
print(f"\nFull 107-char sequence (with T reinserted at positions {sorted(t_hole_indices)}):")
print(''.join(full_seq_107))
print(f"T positions in full seq: {[i for i,c in enumerate(full_seq_107) if c=='T']}")

# ── Section 2: Full sequence approaches (using 107-char with T) ───────────────
print("\n═══ SECTION 2: Using Full 107-char Sequence (T reinserted) ═══")

# The full 107 chars include T. This gives us the COMPLETE reading order.
# If we select 97 chars from these 107 (dropping the 10 extras), we get the permutation.

full107 = full_seq_107  # list of chars

# S2-A: Use KA-index of full107 chars as permutation
ka_indices_107 = [KA.index(c) if c in KA else -1 for c in full107]
print(f"KA-indices (with T=4): {ka_indices_107[:20]}... (T=4 at positions {[i for i,v in enumerate(ka_indices_107) if v==4]})")

# Select first 97, use rank as permutation
ka97 = ka_indices_107[:97]
perm_ka_rank = stable_rank(ka97)
if is_valid_perm(perm_ka_rank):
    res = test_perm(perm_ka_rank, 'S2A_ka97_rank', verbose=True)

perm_ka_rank_inv = invert_perm(perm_ka_rank) if is_valid_perm(perm_ka_rank) else None
if perm_ka_rank_inv and is_valid_perm(perm_ka_rank_inv):
    test_perm(perm_ka_rank_inv, 'S2A_ka97_rank_inv', verbose=True)

# S2-B: T at hole_idx=21 divides sequence into two parts: [0:21] + [22:]
# Use T-position as SPLIT POINT and interleave
for t_pos in [21, 33, 90]:  # T-diagonal hole indices
    before = list(range(t_pos))
    after  = list(range(t_pos+1, 107))

    # Method: before-part goes to positions 0..t_pos-1, after-part goes to t_pos..106
    combined = before + after  # 106 elements (one T excluded)
    # Select 97 from 106
    for sel_method in ['first97', 'last97', 'evenly_spaced']:
        if sel_method == 'first97':
            sel = combined[:97]
        elif sel_method == 'last97':
            sel = combined[9:]
        else:
            step = 106 / 97
            sel = [combined[int(i*step)] for i in range(97)]

        if len(set(sel)) == 97 and all(0 <= s < 97 for s in sel):
            res = test_perm(sel, f'S2B_tpos{t_pos}_{sel_method}', verbose=True)

# S2-C: Full 107 KA-indices. The 3 T's (value=4) are "anchors".
# Position the 97 non-anchor K4 chars relative to these anchors.
anchor_positions = sorted(t_hole_indices)  # [21, 33, 90]
non_anchor = [i for i in range(107) if i not in t_hole_indices]  # 104 non-anchor holes

# Use anchors to split non-anchors into 4 regions
regions = []
prev = 0
for ap in anchor_positions + [107]:
    region = [i for i in non_anchor if prev <= i < ap]
    regions.append(region)
    prev = ap + 1

print(f"\nRegions (split by T-anchors at {anchor_positions}):")
for i, reg in enumerate(regions):
    print(f"  Region {i}: {len(reg)} holes")

# Try all 4! = 24 region orderings
for perm_regions in itertools.permutations(range(4)):
    ordered = []
    for ri in perm_regions:
        ordered.extend(regions[ri])
    # Take first 97
    sel = [p for p in ordered[:97] if p < 97]
    if len(sel) == 97 and len(set(sel)) == 97:
        name = f'S2C_regions_{"".join(str(r) for r in perm_regions)}'
        res = test_perm(sel, name)
        if res and res[0] > SCORE_THRESHOLD:
            print(f"  {name}: score={res[0]:.2f}")

# ── Section 3: T-Offset Columnar with all widths 2-30 ────────────────────────
print("\n═══ SECTION 3: Exhaustive T-offset columnar (all widths) ═══")

t_offsets_107 = [(c - (4-r)%26) % 26 for (r,c) in HOLES]
b_dists_107   = [abs(c - (4-r)%26) for (r,c) in HOLES]

best_sc = -9999
best_name = None
for W in range(2, 31):
    # Use T-offsets of first W holes as columnar key
    if W > 107: break
    col_key = t_offsets_107[:W]

    for key_variant in ['offset', 'dist', 'offset_plus_dist', 'row']:
        if key_variant == 'offset':
            key = col_key
        elif key_variant == 'dist':
            key = b_dists_107[:W]
        elif key_variant == 'offset_plus_dist':
            key = [(t_offsets_107[i] + b_dists_107[i]) % 26 for i in range(W)]
        else:
            key = [HOLES[i][0] for i in range(W)]

        col_order = sorted(range(W), key=lambda c: (key[c], c))
        n_rows_grid = math.ceil(97 / W)
        perm = []
        for c in col_order:
            for r_idx in range(n_rows_grid):
                idx = r_idx * W + c
                if idx < 97: perm.append(idx)

        if not is_valid_perm(perm): continue

        # Test forward and inverse
        for variant, p in [('fwd', perm), ('inv', invert_perm(perm))]:
            candidate_ct = apply_perm(K4, p)
            best_here = None
            for kw in KEYWORDS:
                for afn, fn in [('vig', vig_dec), ('beau', beau_dec)]:
                    pt = fn(candidate_ct, kw, AZ)
                    if not pt: continue
                    sc = qgscore(pt)
                    ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                    if ene >= 0 or bc >= 0:
                        print(f"\n*** CRIB HIT [W{W}_{key_variant}_{variant}/{kw}/{afn}]: ENE@{ene} BC@{bc}")
                        print(f"    CT: {candidate_ct}")
                        print(f"    PT: {pt}")
                    if best_here is None or sc > best_here:
                        best_here = sc
            name = f'col_W{W}_{key_variant}_{variant}'
            if best_here and best_here > best_sc:
                best_sc = best_here
                best_name = name

print(f"  Best columnar score: {best_sc:.2f} [{best_name}]")

# ── Section 4: T-column with non-zero offsets ─────────────────────────────────
print("\n═══ SECTION 4: T-column with non-zero physical offsets ═══")

for k in range(0, 26):  # Try all 26 possible alphabet-start columns
    t_cols_k = [(k + (4-r)%26) for r in range(28)]  # physical col of T for each row

    # Check if ANY of these fall in valid range [0, 25] and match a hole
    hits = [(i, r, c) for i,(r,c) in enumerate(HOLES) if c in t_cols_k[:28]
            and t_cols_k[r] == c and 0 <= c <= 25]

    if len(hits) == 0:
        print(f"  k={k}: ZERO T-diagonal hits! (T-cols: {t_cols_k[:5]}...)")

        # This offset gives T nowhere in the holes. Use these T-columns for permutation.
        def b_dist_k(r, c):
            return abs(c - t_cols_k[r]) if t_cols_k[r] <= 25 else abs(c - (t_cols_k[r] % 26))

        dists_k = [b_dist_k(r, c) for (r,c) in HOLES[:97]]

        # Rank-based permutation
        perm_dist_k = stable_rank(dists_k)
        if is_valid_perm(perm_dist_k):
            res = test_perm(perm_dist_k, f'k{k}_dist_rank', verbose=True)

        # Columnar with width 26
        offsets_k = [(c - t_cols_k[r]) % 26 for (r,c) in HOLES[:26]]
        col_order_k = sorted(range(26), key=lambda c: (offsets_k[c], c))
        perm_col_k = []
        for c in col_order_k:
            for r_idx in range(math.ceil(97/26)):
                idx = r_idx * 26 + c
                if idx < 97: perm_col_k.append(idx)
        if is_valid_perm(perm_col_k):
            test_perm(perm_col_k, f'k{k}_offset_col26', verbose=True)

# ── Section 5: The 3 T-holes as permutation pivots ───────────────────────────
print("\n═══ SECTION 5: The 3 T-diagonal holes as pivots ═══")

# Holes 21, 33, 90 are ON the T-diagonal.
# These divide the 107-hole sequence into 4 segments:
# Seg 0: holes 0-20 (21 holes)
# Seg 1: holes 22-32 (11 holes)
# Seg 2: holes 34-89 (56 holes)
# Seg 3: holes 91-106 (16 holes)

t_pivot_indices = [21, 33, 90]
seg0 = list(range(0, 21))
seg1 = list(range(22, 33))
seg2 = list(range(34, 90))
seg3 = list(range(91, 107))

print(f"Segments: {len(seg0)}, {len(seg1)}, {len(seg2)}, {len(seg3)} holes")
print(f"Total: {len(seg0)+len(seg1)+len(seg2)+len(seg3)} (+ 3 T-pivots = 107)")

# P5-A: Interleave segments differently
# The 97-char K4 needs to be read in the right order.
# If T-pivots mark "phase transitions", maybe K4 chars map to segments
for seg_order in itertools.permutations([0, 1, 2, 3]):
    segs = [seg0, seg1, seg2, seg3]
    ordered = []
    for si in seg_order:
        ordered.extend(segs[si])

    sel = [p for p in ordered if p < 97][:97]
    if len(sel) == 97 and len(set(sel)) == 97:
        name = f'P5A_segs{"".join(str(s) for s in seg_order)}'
        res = test_perm(sel, name)
        if res and res[0] > SCORE_THRESHOLD:
            print(f"  {name}: score={res[0]:.2f}")

# P5-B: T-pivot positions (21, 33, 90) AS K4 INDICES
# What if these tell us "K4[21], K4[33], K4[90] are anchors"?
# K4[21] = Q, K4[33] = O, K4[90] = E (in 0-indexed)
print(f"\nK4 chars at T-pivot positions: K4[21]={K4[21]}, K4[33]={K4[33]}, K4[90]={K4[90]}")

# P5-C: T-pivot indices define a 3-element permutation key
# Use [21, 33, 90] as pivot for a 3-column split of K4
for W_base in [21, 12, 9, 7]:  # widths derived from segment sizes
    if W_base == 0: continue
    col_key_3 = [21 % W_base, 33 % W_base, 90 % W_base]  # pivot positions mod W

    # Build a W-column permutation using pivot-derived key
    n_cols = W_base
    col_order_p = sorted(range(n_cols), key=lambda c: (col_key_3[c % 3], c))
    n_rows_p = math.ceil(97 / n_cols)
    perm_p = []
    for c in col_order_p:
        for r_idx in range(n_rows_p):
            idx = r_idx * n_cols + c
            if idx < 97: perm_p.append(idx)
    if is_valid_perm(perm_p):
        res = test_perm(perm_p, f'P5C_W{W_base}_pivot_col', verbose=True)

# ── Section 6: T-column diagonal as explicit permutation ─────────────────────
print("\n═══ SECTION 6: T-diagonal path as explicit permutation ═══")

# The T-diagonal visits (row, t_col(row)) for row=0..27.
# If we read these 28 positions in the K4 grid, we get a specific pattern.
# But K4 is 97 chars in a 1D array. We can "lay it in" a 2D grid.

for W in [13, 14, 26, 28, 29, 33]:
    if W == 0: continue
    n_rows_grid = math.ceil(97 / W)

    # Visit T-diagonal cells first, then remaining cells
    visited = set()
    diag_positions = []
    other_positions = []
    for r in range(n_rows_grid):
        tc = (4 - r) % 26  # T-column within 26-wide alphabet
        tc_wrapped = tc % W  # wrap to grid width
        for c in range(W):
            pos = r * W + c
            if pos >= 97: continue
            if c == tc_wrapped:
                diag_positions.append(pos)
                visited.add(pos)
            else:
                other_positions.append(pos)

    # P: diagonal first, then others
    perm_diag = diag_positions + other_positions
    if is_valid_perm(perm_diag, 97):
        res = test_perm(perm_diag, f'S6_diag_first_W{W}')
        if res and res[0] > SCORE_THRESHOLD:
            print(f"  S6_diag_first_W{W}: score={res[0]:.2f}")

    # P inverse
    perm_other = other_positions + diag_positions
    if is_valid_perm(perm_other, 97):
        test_perm(perm_other, f'S6_diag_last_W{W}')

# ── Section 7: T as "missing letter" substitution ─────────────────────────────
print("\n═══ SECTION 7: T substitution approaches ═══")

# What letter substitutes for T in the extract?
# If we replace some extract letter with T systematically, does K4 decrypt?
# Under "one-letter substitution" paradigm:
# The real grille extract has T at positions 21, 33, 90.
# The OTHER 104 non-T chars are the remaining letters.

# If we drop positions 21, 33, 90 from the 107 sequence and take the 104 remaining:
# These 104 chars (in reading order) should give us info about the permutation.
# To get 97 from 104, take first 97 or last 97.
remaining_104 = [i for i in range(107) if i not in set(t_pivot_indices)]  # 104 indices
remaining104_k4 = [p for p in remaining_104 if p < 97]  # those that are K4 positions

print(f"104 non-T holes: {len(remaining_104)}, of which < 97: {len(remaining104_k4)}")

if len(remaining104_k4) >= 97:
    perm_104_f97 = remaining104_k4[:97]
    if is_valid_perm(perm_104_f97):
        res = test_perm(perm_104_f97, 'S7_remaining104_first97', verbose=True)

# ── Section 8: Mutual information — T-column as key position ─────────────────
print("\n═══ SECTION 8: T-column as direct cipher key positions ═══")

# Each K4 position i corresponds to hole HOLES[i] at (r, c).
# The KA letter at that hole position in the TABLEAU is the "key letter" for pos i.
# The tableau letter at (r, c) is KA[(c + r) % 26].
# So key[i] = KA[(HOLES[i][1] + HOLES[i][0]) % 26] for i=0..96

tableau_key_97 = ''.join(KA[(c + r) % 26] for (r, c) in HOLES[:97])
print(f"Tableau key (97 chars): {tableau_key_97}")
print(f"T appears in tableau key at: {[i for i,c in enumerate(tableau_key_97) if c=='T']}")

# Decrypt K4 with this key
for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        pt = fn(K4, tableau_key_97, alpha)
        if pt:
            sc = qgscore(pt)
            ene = pt.find(CRIB1); bc = pt.find(CRIB2)
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT [S8/{cipher_name}/{alpha_name}]: ENE@{ene} BC@{bc}")
                print(f"    PT: {pt}")
            if sc > SCORE_THRESHOLD:
                print(f"  S8_{cipher_name}_{alpha_name}: score={sc:.2f}")

# Also: tableau key for all 107 holes (selecting 97)
for start in range(11):
    tableau_key_sel = ''.join(KA[(HOLES[i][1] + HOLES[i][0]) % 26] for i in range(start, start+97))
    for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
        pt = fn(K4, tableau_key_sel, AZ)
        if pt:
            sc = qgscore(pt)
            ene = pt.find(CRIB1); bc = pt.find(CRIB2)
            if ene >= 0 or bc >= 0:
                print(f"\n*** CRIB HIT [S8_sel{start}/{cipher_name}]: ENE@{ene} BC@{bc}")
                print(f"    PT: {pt}")
            if sc > SCORE_THRESHOLD:
                print(f"  S8_sel{start}_{cipher_name}: score={sc:.2f}")

# ── Section 9: Rank-based permutations with tableau letter values ─────────────
print("\n═══ SECTION 9: Tableau letter ranks as permutation ═══")

# For each of 97 holes: tableau_letter = KA[(c+r)%26]
# KA-index of this letter is the "rank key"
# Different selections of 97 from 107 holes give different rank keys

for start in [0, 5, 10]:
    holes97 = HOLES[start:start+97]
    if len(holes97) < 97: continue

    # Method 1: sort by KA-index of tableau letter
    tableau_ranks = [KA.index(KA[(c+r)%26]) for (r,c) in holes97]  # = (c+r)%26
    perm_trank = stable_rank(tableau_ranks)
    if is_valid_perm(perm_trank):
        res = test_perm(perm_trank, f'S9_tableau_rank_s{start}', verbose=True)
        if res and res[0] > SCORE_THRESHOLD:
            print(f"  S9_tableau_rank_s{start}: score={res[0]:.2f}")

    # Method 2: sort by (row, KA-index)
    perm_trank2 = sorted(range(97), key=lambda i: (holes97[i][0], tableau_ranks[i]))
    if is_valid_perm(perm_trank2):
        res = test_perm(perm_trank2, f'S9_row_then_tableau_s{start}')
        if res and res[0] > SCORE_THRESHOLD:
            print(f"  S9_row_then_tableau_s{start}: score={res[0]:.2f}")

# ── Section 10: "T is your position" — extended interpretations ───────────────
print("\n═══ SECTION 10: Extended T-position interpretations ═══")

T_AZ = AZ.index('T')  # 19
T_KA = KA.index('T')  # 4

# Extended G: "T is your position" applied iteratively
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    T_idx = alpha.index('T')
    # First iteration: find key that would make CT → T
    key1_vig = ''.join(alpha[(alpha.index(c) - T_idx) % 26] for c in K4)
    key1_beau = ''.join(alpha[(T_idx + alpha.index(c)) % 26] for c in K4)

    # Second iteration: find key that would make CT → key1 → T
    # i.e., apply same transform to key1
    key2_vig = ''.join(alpha[(alpha.index(c) - T_idx) % 26] for c in key1_vig)
    key2_beau = ''.join(alpha[(T_idx + alpha.index(c)) % 26] for c in key1_beau)

    for iter_name, key in [
        ('key1_vig', key1_vig), ('key1_beau', key1_beau),
        ('key2_vig', key2_vig), ('key2_beau', key2_beau)
    ]:
        # Use first N chars as periodic key for N in [4,5,6,7,8,10,13]
        for klen in [4, 5, 6, 7, 8, 10, 13, 14, 19, 26]:
            key_short = key[:klen]
            for cipher_name, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(K4, key_short, AZ)
                if pt:
                    sc = qgscore(pt)
                    ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                    if ene >= 0 or bc >= 0:
                        print(f"\n*** CRIB HIT [S10/{alpha_name}/{iter_name}/klen{klen}/{cipher_name}]: ENE@{ene} BC@{bc}")
                        print(f"    key: {key_short}")
                        print(f"    PT: {pt}")
                    if sc > SCORE_THRESHOLD:
                        print(f"  S10_{alpha_name}_{iter_name}_k{klen}_{cipher_name}: score={sc:.2f}")

# ── Section 11: Grille extract reverse-engineered as permutation ───────────────
print("\n═══ SECTION 11: Extract-derived unique permutations ═══")

# The 106-char extract has MANY repeated letters. But in KA, each letter maps to
# a unique position 0-25 (plus T=4). The key insight: no letter in KA is at two
# positions, so the extract values ARE from 0-25 (minus 4=T).

# Q: What if the extract is NOT a sequence of permutation indices but a
# POLYBIUS-style encoding where PAIRS of letters encode a single value 0-96?
# 106 chars / 2 = 53 pairs → not 97. Skip.

# What if the 106 chars encode 97 values via some arithmetic over sliding window?
# Approach: sum of consecutive pairs mod 97
sums_consec = [(KA.index(GRILLE_EXTRACT[i]) + KA.index(GRILLE_EXTRACT[i+1])) % 97
               for i in range(97)]
if len(set(sums_consec)) == 97:
    res = test_perm(sums_consec, 'S11_consec_sum97', verbose=True)
elif len(set(sums_consec)) > 90:
    print(f"  S11_consec_sum97: {len(set(sums_consec))} unique values (not 97)")
    # Try as rank-based perm
    perm_s11 = stable_rank(sums_consec)
    test_perm(perm_s11, 'S11_consec_sum_rank', verbose=True)

# Product mod 97
prods_consec = [(KA.index(GRILLE_EXTRACT[i]) * KA.index(GRILLE_EXTRACT[i+1])) % 97
                for i in range(97)]
if len(set(prods_consec)) == 97:
    test_perm(prods_consec, 'S11_consec_prod97', verbose=True)

# XOR pairs
xors_consec = [KA.index(GRILLE_EXTRACT[i]) ^ KA.index(GRILLE_EXTRACT[i+1])
               for i in range(97)]
perm_xor = stable_rank(xors_consec)
test_perm(perm_xor, 'S11_consec_xor_rank', verbose=True)

# ── Section 12: T-avoidance score per row as key ──────────────────────────────
print("\n═══ SECTION 12: Per-row T-avoidance as structured key ═══")

# For each row, compute the average T-distance of holes in that row
row_avg_dist = {}
for r, c in HOLES:
    d = abs(c - (4-r)%26)
    if r not in row_avg_dist:
        row_avg_dist[r] = []
    row_avg_dist[r].append(d)

row_avg = {r: sum(v)/len(v) for r, v in row_avg_dist.items()}
print(f"Rows with holes: {sorted(row_avg.keys())}")
print(f"Avg T-dist per row: {[(r, f'{v:.1f}') for r,v in sorted(row_avg.items())]}")

# Use row ordering by avg T-dist as a key
rows_by_avg_dist = sorted(row_avg.keys(), key=lambda r: row_avg[r])
print(f"Rows ordered by avg T-dist: {rows_by_avg_dist}")

# Build permutation by reading K4 row by row in this order
row_to_k4_positions = defaultdict(list)
for i, (r, c) in enumerate(HOLES[:97]):
    row_to_k4_positions[r].append(i)

perm_row_avgdist = []
for r in rows_by_avg_dist:
    perm_row_avgdist.extend(sorted(row_to_k4_positions.get(r, [])))

if is_valid_perm(perm_row_avgdist):
    res = test_perm(perm_row_avgdist, 'S12_row_avgdist', verbose=True)

# Reverse
perm_row_avgdist_rev = []
for r in reversed(rows_by_avg_dist):
    perm_row_avgdist_rev.extend(sorted(row_to_k4_positions.get(r, [])))
if is_valid_perm(perm_row_avgdist_rev):
    test_perm(perm_row_avgdist_rev, 'S12_row_avgdist_rev', verbose=True)

# ── Section 13: Cribs as decryption oracle ────────────────────────────────────
print("\n═══ SECTION 13: Crib oracle — K4 chars that MUST be in crib positions ═══")

# Under the scrambling paradigm, crib positions (21-33=ENE, 63-73=BC) are for
# the CARVED K4, not the real CT. So K4[21:34] = QPRNGKSSOTWTQ (carved chars at ENE positions)
# and K4[63:74] = NYPVTTMZFPK (carved chars at BC positions).

k4_ene_region = K4[21:34]  # 13 chars, should be REAL CT chars for EASTNORTHEAST
k4_bc_region  = K4[63:74]  # 11 chars

print(f"K4 chars at carved ENE positions (21-33): {k4_ene_region}")
print(f"K4 chars at carved BC positions (63-73): {k4_bc_region}")

# Under simple Vig, EASTNORTHEAST ←→ (K4[21:34]) using some key kw
# PT[i] = (CT[i] - key[i]) % 26 → key[i] = (CT[i] - PT[i]) % 26
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    # Derive key from ENE crib
    for cipher_name, mode in [("vig", "vig"), ("beau", "beau")]:
        try:
            if mode == "vig":
                # key[i] = (CT[i] - PT[i]) % 26
                key_from_ene = [( alpha.index(k4_ene_region[i]) - alpha.index(CRIB1[i]) ) % 26
                                for i in range(13)]
            else:
                # key[i] = (PT[i] + CT[i]) % 26
                key_from_ene = [( alpha.index(CRIB1[i]) + alpha.index(k4_ene_region[i]) ) % 26
                                for i in range(13)]
        except ValueError:
            continue

        key_ene_letters = ''.join(alpha[k] for k in key_from_ene)
        print(f"  Key derived from ENE crib ({cipher_name}/{alpha_name}): {key_ene_letters}")

        # Try this as periodic key on K4
        for cipher2, fn2 in [("vig", vig_dec), ("beau", beau_dec)]:
            pt = fn2(K4, key_ene_letters, AZ)
            if pt:
                sc = qgscore(pt)
                ene = pt.find(CRIB1); bc = pt.find(CRIB2)
                if ene >= 0 or bc >= 0:
                    print(f"\n*** CRIB HIT [S13/{alpha_name}/{cipher_name}/{cipher2}]: ENE@{ene} BC@{bc}")
                    print(f"    key: {key_ene_letters}")
                    print(f"    PT: {pt}")
                if sc > SCORE_THRESHOLD:
                    print(f"  S13_{alpha_name}_{cipher_name}_{cipher2}: score={sc:.2f}")

# ── Section 14: Holes-per-row density as transposition key ───────────────────
print("\n═══ SECTION 14: Holes-per-row density analysis ═══")

holes_per_row = Counter(r for r,c in HOLES)
print(f"Holes per row: {sorted(holes_per_row.items())}")

# Rows ordered by hole count → key for columnar transposition
rows_by_count = sorted(range(28), key=lambda r: (-holes_per_row.get(r, 0), r))
print(f"Rows by hole count (desc): {rows_by_count[:10]}...")

# Build permutation: read K4 assigned to rows in hole-count order
perm_density = []
for r in rows_by_count:
    perm_density.extend(sorted(row_to_k4_positions.get(r, [])))

if is_valid_perm(perm_density):
    res = test_perm(perm_density, 'S14_density_order', verbose=True)

# Also: hole-count as columnar transposition key (first 7 or 8 rows)
for W in [7, 8, 9, 10, 14]:
    row_counts = [holes_per_row.get(r, 0) for r in range(W)]
    col_order = sorted(range(W), key=lambda c: (row_counts[c], c))
    n_rows_g = math.ceil(97/W)
    perm_dens_col = []
    for c in col_order:
        for r_idx in range(n_rows_g):
            idx = r_idx * W + c
            if idx < 97: perm_dens_col.append(idx)
    if is_valid_perm(perm_dens_col):
        res = test_perm(perm_dens_col, f'S14_density_col_W{W}')
        if res and res[0] > SCORE_THRESHOLD:
            print(f"  S14_density_col_W{W}: score={res[0]:.2f}")

# ── Final Summary ─────────────────────────────────────────────────────────────
print("\n═══ FINAL SUMMARY ═══")
if RESULTS:
    RESULTS.sort(key=lambda x: -x[0])
    print(f"\nTop results (score > {SCORE_THRESHOLD}):")
    seen = set()
    for r in RESULTS[:20]:
        sc, name, perm, pt, kw, cipher, alpha = r
        key = f"{name}_{kw}_{cipher}_{alpha}"
        if key in seen: continue
        seen.add(key)
        ene = pt.find(CRIB1); bc = pt.find(CRIB2)
        crib_str = f"ENE@{ene}" if ene>=0 else ""
        crib_str += f" BC@{bc}" if bc>=0 else ""
        print(f"  {sc:.2f} [{name}] key={kw} {cipher}/{alpha} {crib_str}")
        print(f"       PT: {pt[:70]}...")

    with open(f'{OUT_DIR}/extended_results.json', 'w') as f:
        json.dump([{"score": r[0], "name": r[1], "perm": r[2], "pt": r[3],
                    "key": r[4], "cipher": r[5], "alpha": r[6]} for r in RESULTS[:20]], f, indent=2)
    print(f"\nSaved to {OUT_DIR}/extended_results.json")
else:
    print("No results above threshold.")

print("\nDone!")
