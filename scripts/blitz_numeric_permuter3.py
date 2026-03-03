#!/usr/bin/env python3
"""
BLITZ Wave 3: Geometric Rectangle Analysis + Targeted Permutations

KEY INSIGHT: If K4's 97 chars are written in a grid and the grille is
overlaid, we need exactly 97 holes to fall on valid K4 positions.

This script:
1. Finds ALL rectangular sub-regions of the 28×33 grille with exactly 97 holes
2. Tries ALL valid permutations derived from these regions
3. Tests with every cipher/key combination
4. Also tries: extended affine perms, cyclic group perms, self-encoding
"""
import json, sys, os, math, itertools
from collections import defaultdict, Counter

K4     = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GRILLE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA     = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS','PALIMPSEST','ABSCISSA','SHADOW','SANBORN','SCHEIDT',
            'BERLIN','CLOCK','EAST','NORTH','LIGHT','ANTIPODES','MEDUSA','ENIGMA']
N = 97
assert len(K4) == N

AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}
GRILLE_AZ = [AZ_IDX[c] for c in GRILLE]
GRILLE_KA = [KA_IDX[c] for c in GRILLE]
K4_AZ = [AZ_IDX[c] for c in K4]
K4_KA = [KA_IDX[c] for c in K4]

QG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    qg = json.load(f)

def qgscore(text):
    return sum(qg.get(text[i:i+4], -10.0) for i in range(len(text)-3))

def vig_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[ct[i]] - idx[key[i % len(key)]]) % n] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[key[i % len(key)]] - idx[ct[i]]) % n] for i in range(len(ct)))

def is_valid_perm(p, n=N):
    return len(p) == n and sorted(p) == list(range(n))

def apply_perm(text, perm):
    return ''.join(text[p] for p in perm)

def values_to_perm(vals):
    indexed = sorted(range(len(vals)), key=lambda i: vals[i])
    perm = [0]*len(vals)
    for rank, idx in enumerate(indexed): perm[idx] = rank
    return perm

RESULTS = []
BEST_SCORE = -9999
TRIED = set()
COUNT = 0

def try_perm(perm, label):
    global BEST_SCORE, COUNT
    key = tuple(perm)
    if key in TRIED: return
    TRIED.add(key)
    COUNT += 1
    candidate_ct = apply_perm(K4, perm)
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(candidate_ct, kw, alpha)
                sc = qgscore(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    print(f"\n{'='*70}")
                    print(f"*** CRIB HIT *** label={label}")
                    print(f"  ENE@{ene}  BC@{bc}  key={kw}  {cname}/{alpha_name}")
                    print(f"  PT : {pt}")
                    print(f"  CT': {candidate_ct}")
                    print(f"  Score: {sc:.2f}")
                    print(f"  perm: {list(perm)}")
                    print(f"{'='*70}\n")
                    RESULTS.append({'label':label,'ene':ene,'bc':bc,'kw':kw,
                                    'cipher':cname,'alpha':alpha_name,
                                    'pt':pt,'score':sc,'perm':list(perm)})
                    return
                if sc > BEST_SCORE:
                    BEST_SCORE = sc
                    print(f"  [best] {sc:.2f}  {label}  {kw}/{cname}/{alpha_name}  {pt[:40]}…")

# ─────────────────────────────────────────────────────────────────────────────
# PARSE GRILLE MASK
# ─────────────────────────────────────────────────────────────────────────────
GRILLE_MASK_ROWS = [
    "000000001010100000000010000000001~~",
    "100000000010000001000100110000011~~",
    "000000000000001000000000000000011~~",
    "00000000000000000000100000010011~~",
    "00000001000000001000010000000011~~",
    "000000001000000000000000000000011~",
    "100000000000000000000000000000011",
    "00000000000000000000000100000100~~",
    "0000000000000000000100000001000~~",
    "0000000000000000000000000000100~~",
    "000000001000000000000000000000~~",
    "00000110000000000000000000000100~~",
    "00000000000000100010000000000001~~",
    "00000000000100000000000000001000~~",
    "000110100001000000000000001000010~~",
    "00001010000000000000000001000001~~",
    "001001000010010000000000000100010~~",
    "00000000000100000000010000010001~~",
    "000000000000010001001000000010001~~",
    "00000000000000001001000000000100~~",
    "000000001100000010100100010001001~~",
    "000000000000000100001010100100011~",
    "00000000100000000000100001100001~~~",
    "100000000000000000001000001000010~",
    "10000001000001000000100000000001~~",
    "000010000000000000010000100000011",
    "0000000000000000000100001000000011",
    "00000000000000100000001010000001~~",
]
GRILLE_ROWS = len(GRILLE_MASK_ROWS)  # 28
GRILLE_COLS = 33

# Build hole grid: hole_grid[r][c] = True if hole
hole_grid = [[False]*GRILLE_COLS for _ in range(GRILLE_ROWS)]
all_holes = []
for r, row_str in enumerate(GRILLE_MASK_ROWS):
    for c, ch in enumerate(row_str):
        if c < GRILLE_COLS and ch == '0':
            hole_grid[r][c] = True
            all_holes.append((r, c))

print(f"Total holes: {len(all_holes)}")

# ─────────────────────────────────────────────────────────────────────────────
# SEARCH FOR RECTANGLES WITH EXACTLY 97 HOLES
# ─────────────────────────────────────────────────────────────────────────────
def find_97_hole_rectangles():
    """
    Find all (r0, r1, c0, c1) such that the subgrid [r0..r1) × [c0..c1)
    contains exactly 97 holes.
    """
    # Precompute prefix sums for fast rectangle queries
    # prefix[r][c] = number of holes in [0..r) × [0..c)
    prefix = [[0]*(GRILLE_COLS+1) for _ in range(GRILLE_ROWS+1)]
    for r in range(GRILLE_ROWS):
        for c in range(GRILLE_COLS):
            prefix[r+1][c+1] = (prefix[r][c+1] + prefix[r+1][c]
                                 - prefix[r][c] + (1 if hole_grid[r][c] else 0))

    def rect_count(r0, r1, c0, c1):
        return (prefix[r1][c1] - prefix[r0][c1] - prefix[r1][c0] + prefix[r0][c0])

    rects = []
    for r0 in range(GRILLE_ROWS):
        for r1 in range(r0+1, GRILLE_ROWS+1):
            for c0 in range(GRILLE_COLS):
                for c1 in range(c0+1, GRILLE_COLS+1):
                    if rect_count(r0, r1, c0, c1) == N:
                        rects.append((r0, r1, c0, c1))
    return rects

print("\nSearching for rectangles with exactly 97 holes...")
rects_97 = find_97_hole_rectangles()
print(f"Found {len(rects_97)} rectangles with exactly 97 holes:")
for r0, r1, c0, c1 in rects_97[:50]:  # print first 50
    nrows = r1 - r0
    ncols = c1 - c0
    print(f"  rows [{r0},{r1}) × cols [{c0},{c1}) = {nrows}×{ncols} grid")

# ─────────────────────────────────────────────────────────────────────────────
# FOR EACH 97-HOLE RECTANGLE: Build permutation and test
# ─────────────────────────────────────────────────────────────────────────────
def rectangle_to_perms(r0, r1, c0, c1):
    """
    Given a rectangle with exactly 97 holes:
    The holes define a READING ORDER for K4 positions.

    Two interpretations:
    A) K4 chars are at HOLE positions (in K4's own layout), grille reads them.
       The i-th hole (row-major) corresponds to K4[i] → perm[i] = position of
       i-th hole in K4's layout.

    B) K4 is laid out in the rectangle's grid. Each hole (r,c) maps to
       K4 position = (r-r0)*ncols + (c-c0). The reading order of holes
       gives which K4 positions are "revealed" first.

    Try both forward and inverse.
    """
    nrows = r1 - r0
    ncols = c1 - c0

    # Get holes in this rectangle, row-major order
    rect_holes_rowmaj = [(r, c) for r in range(r0, r1) for c in range(c0, c1)
                          if hole_grid[r][c]]
    # col-major order
    rect_holes_colmaj = sorted(rect_holes_rowmaj, key=lambda x: (x[1]-c0, x[0]-r0))
    # diagonal order
    rect_holes_diag = sorted(rect_holes_rowmaj, key=lambda x: (x[0]+x[1]-r0-c0, x[0]-r0))

    assert len(rect_holes_rowmaj) == N, f"Expected {N} holes, got {len(rect_holes_rowmaj)}"

    perms = []

    for order_name, holes_ordered in [("rowmaj", rect_holes_rowmaj),
                                       ("colmaj", rect_holes_colmaj),
                                       ("diag", rect_holes_diag)]:
        # Interpretation A: holes define which K4 positions to read
        # K4 is written left-to-right top-to-bottom in the rectangle
        # Hole (r,c) → K4 position (r-r0)*ncols + (c-c0), clamped to N
        perm_A = []
        valid = True
        for r, c in holes_ordered:
            k4_pos = (r - r0) * ncols + (c - c0)
            if k4_pos >= N:
                valid = False
                break
            perm_A.append(k4_pos)

        if valid and len(perm_A) == N:
            if is_valid_perm(perm_A):
                perms.append((perm_A, f"rect_{r0}_{r1}_{c0}_{c1}_{order_name}_A"))
            else:
                # Use rank
                perms.append((values_to_perm(perm_A),
                               f"rect_{r0}_{r1}_{c0}_{c1}_{order_name}_A_rank"))

        # Interpretation B: the i-th hole reads K4[i]
        # So perm[output_i] = i, where output_i is the hole's position in the rectangle
        # i.e., reading K4 in hole order: CT'[i] = K4[holes_ordered[i] maps to K4 index]
        # Actually: perm[i] = global index of i-th hole in reading order
        # This is just the list of K4 positions in hole order = perm_A
        # But if perm_A is not a valid perm, we can't use it directly

        # Interpretation C: the grille is a MASK that reorders
        # perm[pos_in_K4] = which position it goes to in real CT
        # i-th hole reads: K4[i] → real_CT[position_of_hole_in_grid]
        # So: real_CT[(r-r0)*ncols + (c-c0)] = K4[i]
        # → perm: K4 position i → real_CT position (r-r0)*ncols+(c-c0)
        perm_C_forward = [None]*N  # perm_C_forward[k4_pos] = ct_pos
        perm_C_inverse = [None]*N  # perm_C_inverse[ct_pos] = k4_pos
        valid_C = True
        for i, (r, c) in enumerate(holes_ordered):
            ct_pos = (r - r0) * ncols + (c - c0)
            if ct_pos >= N or i >= N:
                valid_C = False
                break
            if perm_C_forward[i] is not None:
                valid_C = False; break
            perm_C_forward[i] = ct_pos  # hole i reads K4[ct_pos]...

        # More precisely:
        # The grille is placed over K4. Hole #i (in reading order) is at
        # K4 grid position grid_pos[i]. We read K4[grid_pos[i]] as CT'[i].
        # So: CT'[i] = K4[grid_pos[i]] → apply_perm(K4, grid_pos_list)
        # This means perm = grid_pos_list (if it's a valid perm).
        # This is identical to perm_A above.

    return perms

print(f"\nBuilding permutations from {len(rects_97)} rectangles...")
tested_rects = 0
for r0, r1, c0, c1 in rects_97:
    nrows = r1 - r0
    ncols = c1 - c0
    perm_tuples = rectangle_to_perms(r0, r1, c0, c1)
    for perm, label in perm_tuples:
        try_perm(perm, label)
        # Also inverse
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, label+"_inv")
    tested_rects += 1
    if tested_rects % 50 == 0:
        print(f"  Tested {tested_rects}/{len(rects_97)} rectangles, tried {COUNT}")

print(f"\n✓ Rectangle analysis done. Tried {COUNT} permutations total.")

# ─────────────────────────────────────────────────────────────────────────────
# SPECIAL: K4 as 8×13 grid (rows 20-27, cols 0-12 of grille)
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- Special: K4 as 8×13 grid analysis ---")

# The grille rows 20-27, cols 0-12 have exactly 97 holes.
# K4 chars in the 8×13 grid: positions 0..103, but only 0..96 are valid.
# Holes that fall on positions 97-103 (row 7, cols 6-12) must map to padding.

# But wait: maybe the K4 layout has the LAST chars in a different arrangement.
# Try: K4 is written from BOTTOM to TOP, or reversed column order, etc.

# Or maybe: the rectangle is NOT rows 20-27, cols 0-12.
# Let me find the EXACT rectangle that has 97 holes AND all holes fall
# within an 8×13 (or similar) usable grid.

for r0, r1, c0, c1 in rects_97:
    nrows = r1 - r0
    ncols = c1 - c0
    # Check if all holes are within an N-cell grid (nrows × ncols with N valid cells)
    # Valid K4 positions: row*ncols + col < N
    rect_holes = [(r, c) for r in range(r0, r1) for c in range(c0, c1) if hole_grid[r][c]]
    all_valid = all((r-r0)*ncols + (c-c0) < N for r, c in rect_holes)
    if all_valid:
        print(f"  PERFECT FIT: rows [{r0},{r1}) × cols [{c0},{c1}) = {nrows}×{ncols}")
        print(f"    All {len(rect_holes)} holes within 0..{N-1}")
        # Generate permutation
        perm = [(r-r0)*ncols + (c-c0) for r in range(r0, r1) for c in range(c0, c1)
                if hole_grid[r][c]]
        if is_valid_perm(perm):
            print(f"    → Valid permutation!")
            try_perm(perm, f"PERFECT_{r0}_{r1}_{c0}_{c1}")
            inv = [0]*N
            for i, v in enumerate(perm): inv[v] = i
            try_perm(inv, f"PERFECT_{r0}_{r1}_{c0}_{c1}_inv")

# ─────────────────────────────────────────────────────────────────────────────
# K4 HOLE COORDINATES AS PERMUTATION SEEDS
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- Hole coordinate chains ---")

# For the interesting rectangle (rows 20-27, cols 0-12): 97 holes
# Map each hole to a K4 position (even if some are padding)
# Then adjust: holes that land on padding → map to leftover positions
main_rect = (20, 28, 0, 13)  # rows 20-28? But only 28 rows → rows 20-27
# Actually there are only 28 rows (0-27), so r1=28 means row 27 inclusive
main_rect = (20, 28, 0, 13)
r0, r1, c0, c1 = 20, 28, 0, 13
nrows = 8
ncols = 13

rect_holes_rowmaj = [(r, c) for r in range(r0, min(r1, GRILLE_ROWS))
                     for c in range(c0, c1) if hole_grid[r][c]]
print(f"Holes in rows 20-27, cols 0-12: {len(rect_holes_rowmaj)}")

if len(rect_holes_rowmaj) == 97:
    # Grid positions (relative to rect)
    grid_positions = [(r-r0)*ncols + (c-c0) for r, c in rect_holes_rowmaj]
    print(f"Grid positions (first 20): {grid_positions[:20]}")
    print(f"Max position: {max(grid_positions)}")

    # Some may be >= 97 (padding). Count how many:
    valid_pos = [p for p in grid_positions if p < N]
    pad_pos = [p for p in grid_positions if p >= N]
    print(f"Valid positions (< 97): {len(valid_pos)}, Padding positions (>= 97): {len(pad_pos)}")

    # Remap padding to unused positions
    used = set(valid_pos)
    unused = [p for p in range(N) if p not in used]
    print(f"Unused K4 positions: {unused}")

    # Build permutation: replace padding with unused slots
    perm = []
    unused_iter = iter(unused)
    for p in grid_positions:
        if p < N:
            perm.append(p)
        else:
            perm.append(next(unused_iter))

    if is_valid_perm(perm):
        print(f"Remapped permutation is valid!")
        try_perm(perm, "REMAP_8x13_rowmaj")
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, "REMAP_8x13_rowmaj_inv")

    # Try with unused appended at end (instead of remapping in-place)
    perm_valid_first = valid_pos + unused
    if len(perm_valid_first) == N and is_valid_perm(perm_valid_first):
        try_perm(perm_valid_first, "REMAP_8x13_validfirst")

    # Try column-major
    rect_holes_colmaj = sorted(rect_holes_rowmaj, key=lambda x: (x[1]-c0, x[0]-r0))
    grid_positions_col = [(r-r0)*ncols + (c-c0) for r, c in rect_holes_colmaj]
    valid_col = [p for p in grid_positions_col if p < N]
    unused_col_set = set(grid_positions_col) - set(range(N))
    unused_col = [p for p in range(N) if p not in set(valid_col)]
    perm_col = []
    unused_col_iter = iter(unused_col)
    for p in grid_positions_col:
        if p < N: perm_col.append(p)
        else: perm_col.append(next(unused_col_iter))
    if is_valid_perm(perm_col):
        try_perm(perm_col, "REMAP_8x13_colmaj")
        inv = [0]*N
        for i, v in enumerate(perm_col): inv[v] = i
        try_perm(inv, "REMAP_8x13_colmaj_inv")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH W: Extended affine + cyclic group permutations for N=97
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH W: All affine permutations mod 97 ---")
# N=97 is prime. Affine perm: p(i) = (a*i + b) mod 97 for a=1..96, b=0..96
# = 96 × 97 = 9312 permutations. Test them all.
for a in range(1, N):
    for b in range(N):
        perm = [(a*i + b) % N for i in range(N)]
        # This IS always a valid perm (a != 0, N prime)
        try_perm(perm, f"W_aff_a{a}_b{b}")
    if a % 10 == 0:
        print(f"  a={a} done, tried={COUNT}")

print(f"Affine perms done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH X: All power permutations in GF(97)
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH X: Power permutations in GF(97) ---")
# p(i) = (base^i) mod 97 for base in 2..96
# This generates cyclic groups and may give "structured" permutations
for base in range(2, N):
    perm = [pow(base, i, N) for i in range(N)]
    # This cycles through at most (ord of base) elements, may repeat → check
    if is_valid_perm(perm):
        try_perm(perm, f"X_pow_base{base}")
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, f"X_pow_base{base}_inv")

# Also: p(i) = (i^exp) mod 97 for exp in 2..96
for exp in range(2, N):
    perm = [(i**exp) % N for i in range(N)]
    if is_valid_perm(perm):
        try_perm(perm, f"X_iexp{exp}")
        inv = [0]*N
        for i, v in enumerate(perm): inv[v] = i
        try_perm(inv, f"X_iexp{exp}_inv")

print(f"Power perms done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH Y: Grille extract → seed for structured math permutation
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH Y: Math perms seeded by grille ---")

g_ka = GRILLE_KA[:N]
g_az = GRILLE_AZ[:N]

# Y1. Grille KA values as (a,b) for affine perm of K4
# Use first two grille values: a = GRILLE_KA[0], b = GRILLE_KA[1]
for i in range(0, min(50, 106-1)):
    for vals, sfx in [(GRILLE_KA, "ka"), (GRILLE_AZ, "az")]:
        a = max(1, vals[i])  # must be nonzero mod 97
        b = vals[i+1]
        perm = [(a*j + b) % N for j in range(N)]
        try_perm(perm, f"Y1_aff_g{i}_{sfx}")

# Y2. Running grille-keyed affine: a_i = g[i], b_i = g[i+1]
# But this generates N different affines - pick one that's "canonical"
# Use cumulative XOR of grille values as (a,b)
for start in range(50):
    xor_a = 0
    xor_b = 0
    for i in range(start, min(start+13, 106)):
        xor_a ^= GRILLE_KA[i]
        xor_b ^= GRILLE_AZ[i]
    a = max(1, xor_a % N)
    b = xor_b % N
    perm = [(a*j + b) % N for j in range(N)]
    try_perm(perm, f"Y2_xor_aff_start{start}")

# Y3. Grille as a sequence of steps for group action
# g[0], g[1], ... as successive values of (a1*a2*...*ak) and (b sums) mod 97
a_running = 1
b_running = 0
for i, v in enumerate(GRILLE_KA[:50]):
    a_running = (a_running * max(1, v)) % N
    if a_running == 0: a_running = 1
    b_running = (b_running + v) % N
    perm = [(a_running * j + b_running) % N for j in range(N)]
    try_perm(perm, f"Y3_runningaff_ka_i{i}")

print(f"Approach Y done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH Z: Grille-KA indexed substitution applied as permutation
# ─────────────────────────────────────────────────────────────────────────────
print("\n--- APPROACH Z: Mixed-alphabet permutation ---")

# The KA alphabet is a permuted AZ.
# KA_IDX maps AZ letter → KA position.
# Use GRILLE extract to define a substitution of K4 INDICES:
# For position i in K4: new_position = f(K4[i], GRILLE[i])

# Z1. Apply KA-to-AZ substitution to K4 indices, rank
ka_to_az = [AZ_IDX[KA[i]] for i in range(26)]  # KA[i] in AZ → its AZ position
az_to_ka = [KA_IDX[AZ[i]] for i in range(26)]  # AZ[i] in KA → its KA position

for vals, sfx in [(g_ka[:N], "ka"), (g_az[:N], "az")]:
    # Z1: K4_AZ[i] + grille[i] mod 26, then rank
    combined = [(K4_AZ[i] + vals[i]) % 26 for i in range(N)]
    from collections import defaultdict as dd
    try_perm(values_to_perm(combined), f"Z1_sum26_{sfx}")

    # Z2: K4_AZ[i] - grille[i] mod 26
    combined2 = [(K4_AZ[i] - vals[i]) % 26 for i in range(N)]
    try_perm(values_to_perm(combined2), f"Z2_diff26_{sfx}")

    # Z3: K4_KA[i] * grille_KA[i] mod 97
    combined3 = [(K4_KA[i] * max(vals[i],1)) % N for i in range(N)]
    try_perm(values_to_perm(combined3), f"Z3_mul97_{sfx}")

    # Z4: (K4_AZ[i] * 26 + vals[i]) % 97
    combined4 = [(K4_AZ[i] * 26 + vals[i]) % N for i in range(N)]
    try_perm(values_to_perm(combined4), f"Z4_k4_g_pair97_{sfx}")
    if is_valid_perm(combined4): try_perm(combined4, f"Z4_k4_g_pair97_{sfx}_direct")

# Z5. Grille as tableau row selection for K4
# For each K4 position i, the real CT position is KA_IDX[GRILLE[i]] mapped to N
for i, c in enumerate(GRILLE[:N]):
    pass
vals_grille_ka_n = [KA_IDX[c] * N // 26 for c in GRILLE[:N]]
try_perm(values_to_perm(vals_grille_ka_n), "Z5_ka_scaled_N")

print(f"Approach Z done. Tried={COUNT}")

# ─────────────────────────────────────────────────────────────────────────────
# SAVE
# ─────────────────────────────────────────────────────────────────────────────
def save():
    out_dir = "/home/cpatrick/kryptos/blitz_results/numeric_permuter"
    os.makedirs(out_dir, exist_ok=True)
    summary = {"wave": 3, "total_tried": COUNT, "crib_hits": len(RESULTS),
                "best_score": BEST_SCORE, "hits": RESULTS,
                "rectangles_found": len(rects_97)}
    with open(f"{out_dir}/results_wave3.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n✓ Wave 3 saved. Tried={COUNT}, Hits={len(RESULTS)}, Best={BEST_SCORE:.2f}")
    print(f"  Rectangles with exactly 97 holes: {len(rects_97)}")

save()

if RESULTS:
    print("\n" + "="*70)
    print("CRIB HITS:")
    for r in RESULTS:
        print(f"  {r['label']}  ENE@{r['ene']} BC@{r['bc']}")
        print(f"  PT: {r['pt']}")
else:
    print(f"\nNo crib hits. Best score: {BEST_SCORE:.2f}")
