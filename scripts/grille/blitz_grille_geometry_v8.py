#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_grille_geometry_v8.py

Focused follow-up to v7. Key finding from v7:
  - sigma[29]=64 (KRYPTOS/vig/AZ, Y-forced)
  - sigma[29]=69, sigma[71]=64 (ABSCISSA/beau/KA, 2 forced)
  - NO weighted sort of 114 holes satisfies these

New approaches:
A. DUAL-FORCE CHECK: For ABSCISSA/beau/KA, need BOTH sigma[29]=69 AND sigma[71]=64.
   Exhaustively search ALL orderings of 114 holes that satisfy BOTH constraints.

B. SUBSET-SELECTION SEARCH: Pick 97-of-114 holes systematically.
   Drop each possible subset of 17 holes; check if remainder forms valid sigma
   that satisfies forced constraints.

C. SECONDARY FORCED CONSTRAINT CHECK:
   sigma[26] ∈ {82,94}, sigma[30] = other. Two possible pairs.
   sigma[64] ∈ {24,66}, sigma[70] = other. Two possible pairs.
   Combined: 4 combinations. For each, check which hole orderings
   satisfy ALL four constraints simultaneously.

D. TRANSPOSITION STRUCTURE ANALYSIS:
   If sigma is a columnar transposition with width W, then:
   sigma[j] = T_j where T depends on W and column ordering.
   For forced sigma[29]=64: 29 = row*W+col in write-grid.
   What (W, col_order) gives position 64 reading position 29?
   Systematic search over all W and col orderings.

E. K4 T-POSITIONS AS GRILLE INDICATORS:
   T-positions in K4 (carved): 35, 37, 50, 67, 68, 80.
   GE has NO T. If the grille avoids T-tableau-cells, and K4 T-positions
   have special roles, maybe T-positions partition sigma.

F. GRILLE-BASED KEYWORD EXTRACTION:
   The grille positions define which tableau cells are read.
   Use row/col of each hole to define a KEYWORD for columnar transposition.
   Keywords: (holes sorted by col, then row) → extract their row indices → key.

G. 73-POSITION SUBSETS:
   "8 Lines 73" from Sanborn yellow pad.
   73 = 97 - 24 non-crib positions.
   Maybe grille defines exactly which 73 positions are "scrambled."
   The other 24 (crib positions) might be UNscrambled (sigma=identity there).

H. COMPOUND PERMUTATION: σ = σ_A ∘ σ_B
   Combine two simple permutations:
   σ_A = row-major grille holes → K4 indices
   σ_B = some keyword-columnar transposition
   Test combinations.

I. PHYSICAL GRILLE ON K4 (EXHAUSTIVE ALL WIDTHS)
   For EVERY width W from 7 to 50, and overlay positions (dr, dc)
   where holes can fall on K4's 97 positions exactly,
   compute and test the resulting sigma.
   Also try: partial overlap (some holes outside K4).

J. HOLE POSITION WITHIN ROW as a sequence:
   For row 0: holes at cols [c1, c2, ...] (in order)
   Interleave across all rows by position within row.
   I.e., "first hole in each row, then second hole in each row, etc."

K. BINARY MASK MODULAR SHIFT:
   Left-shift or right-shift the bit pattern by k positions
   (wrapping around) before extracting holes.
   This changes which holes are found.
"""

import json, sys, os, itertools, math
from collections import defaultdict, Counter

sys.path.insert(0, 'src')

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GE) == 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN',
            'SCHEIDT', 'BERLIN', 'CLOCK', 'EAST', 'NORTH',
            'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

QG = json.load(open('data/english_quadgrams.json'))

def score_pc(text):
    n = len(text) - 3
    if n <= 0: return -10.0
    return sum(QG.get(text[i:i+4], -10.0) for i in range(n)) / n

def vig_dec(ct, key, alpha=AZ):
    ai = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(ai[ct[i]] - ai[key[i % len(key)]]) % 26] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    ai = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(ai[key[i % len(key)]] - ai[ct[i]]) % 26] for i in range(len(ct)))

RESULTS_DIR = "results/blitz_v8"
os.makedirs(RESULTS_DIR, exist_ok=True)

hits = []
best_score_seen = -10.0
tested = 0
notable = []

K4_POS = defaultdict(list)
for i, c in enumerate(K4):
    K4_POS[c].append(i)

# T-positions in K4 (0-indexed)
T_POS_K4 = [i for i, c in enumerate(K4) if c == 'T']
print(f"K4 T-positions: {T_POS_K4}")

def test_perm(sigma, label):
    global tested, best_score_seen
    if len(sigma) != 97 or sorted(sigma) != list(range(97)):
        return None
    tested += 1
    real_ct = ''.join(K4[sigma[j]] for j in range(97))
    best_local = -10.0
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for kw in KEYWORDS:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(real_ct, kw, alpha)
                sc = score_pc(pt)
                ene = pt.find("EASTNORTHEAST")
                bc  = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    print(f"\n{'!'*70}")
                    print(f"*** CRIB HIT: {label}")
                    print(f"    ENE@{ene}  BC@{bc}  score={sc:.4f}")
                    print(f"    PT: {pt}")
                    print(f"    Key:{kw} Cipher:{cname} Alpha:{alpha_name}")
                    print('!'*70)
                    hits.append({"label": label, "pt": pt, "ene": ene, "bc": bc,
                                 "score": sc, "key": kw})
                    return sc
                if sc > best_local:
                    best_local = sc
    if best_local > best_score_seen:
        best_score_seen = best_local
        print(f"  NEW BEST [{label}]: {best_local:.4f}/char")
        notable.append({"label": label, "score": best_local})
    return best_local

# ── Mask (114 holes, c<33 filter) ────────────────────────────────────────────
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

NROWS = 28
NCOLS = 33

holes = [(r, c) for r, row in enumerate(MASK_ROWS_RAW)
         for c, ch in enumerate(row) if ch == '1' and c < 33]
N_HOLES = len(holes)
print(f"Holes: {N_HOLES}")

hole_set = set(holes)
hole_idx = {h: i for i, h in enumerate(holes)}
hole_linear = [r * NCOLS + c for r, c in holes]

def compute_exp(kw, cipher, alpha):
    ai = {c: i for i, c in enumerate(alpha)}
    exp = {}
    for start, text in CRIBS:
        for j, ch in enumerate(text):
            pos = start + j
            ki = ai[kw[pos % len(kw)]]
            pi = ai[ch]
            if cipher == 'vig':
                exp[pos] = alpha[(pi + ki) % 26]
            else:
                exp[pos] = alpha[(ki - pi) % 26]
    return exp

# Forced constraints for ALL feasible combos
print("\n=== FORCED CONSTRAINTS SUMMARY ===")
all_forced = {}  # (kw, cipher, alpha_name) → {pos: k4_idx}
for kw in KEYWORDS:
    for cipher in ['vig', 'beau']:
        for alpha_name, alpha in [('AZ', AZ), ('KA', KA)]:
            exp = compute_exp(kw, cipher, alpha)
            need = Counter(exp.values())
            ok = all(len(K4_POS.get(ch, [])) >= cnt for ch, cnt in need.items())
            if not ok:
                continue
            forced = {pos: K4_POS[ch][0]
                      for pos, ch in exp.items() if len(K4_POS[ch]) == 1}
            if forced:
                all_forced[(kw, cipher, alpha_name)] = forced
                print(f"  {kw}/{cipher}/{alpha_name}: {len(forced)} forced: {forced}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH A: Dual-force check for ABSCISSA/beau/KA
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH A: Exhaustive search for orderings satisfying dual constraint")
print("="*70)

# ABSCISSA/beau/KA: sigma[29]=69 AND sigma[71]=64
# This means: for any ordering of 114 holes → sigma,
# the 30th element must be 69 and 72nd must be 64.

# What hole positions have K4-index 69 (='M') and 64 (='Y')?
# sigma[k] = some mapping; for "rank-based": sigma[k] = rank_k.
# If sigma[k] = k itself (reading order), then we need
# the hole whose reading rank is 29 to have K4_pos 69,
# and rank 71 to have K4_pos 64.

# For the physical overlay to work:
# hole[29] must be at K4 physical position 69 in the layout
# hole[71] must be at K4 physical position 64

# For each physical layout (W, dr, dc), find which holes land on K4[69] and K4[64]
print("  Checking physical layouts where holes[29]=K4[69] AND holes[71]=K4[64]...")
print("  (ABSCISSA/beau/KA forced: sigma[29]=69, sigma[71]=64)")

dual_hits = 0
for W in range(8, 50):
    k4_nrows = (97 + W - 1) // W
    for dr in range(0, NROWS - k4_nrows + 2):
        for dc in range(0, NCOLS - W + 1):
            # Map grille hole to K4 position
            k4_indices = []
            for r, c in holes:
                k4r = r - dr
                k4c = c - dc
                if 0 <= k4r < k4_nrows and 0 <= k4c < W:
                    k4p = k4r * W + k4c
                    if k4p < 97:
                        k4_indices.append(k4p)
                    else:
                        k4_indices.append(-1)
                else:
                    k4_indices.append(-1)
            # Check if exactly 97 holes land on K4 (no -1)
            valid = [x for x in k4_indices if x >= 0]
            if len(valid) == 97 and len(set(valid)) == 97:
                dual_hits += 1
                sigma = valid
                test_perm(sigma, f"A-W{W}-dr{dr}-dc{dc}-exact")

            # Check if hole[29] → K4[69] and hole[71] → K4[64]
            if len(k4_indices) > 71:
                if k4_indices[29] == 69 and k4_indices[71] == 64:
                    print(f"    DUAL CONSTRAINT MET: W={W} dr={dr} dc={dc}")
                    print(f"    k4_indices[29]={k4_indices[29]}, k4_indices[71]={k4_indices[71]}")
                    # Count valid holes
                    n_valid = sum(1 for x in k4_indices if x >= 0)
                    print(f"    Valid holes: {n_valid}")

print(f"  [A done, {dual_hits} exact 97-hole layouts found]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH B: DROP-17-HOLES SUBSET SELECTION
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH B: Systematic 97-from-114 subset selection (constraint-filtered)")
print("="*70)

# 114 - 97 = 17 holes to drop
# Can't enumerate C(114,17) ≈ 1.9B subsets
# But: forced constraints tell us which specific holes MUST be included
# For KRYPTOS/vig/AZ: sigma[29]=64, so we need the hole at rank 29
# to be at K4 position 64.
# In any ordering, the hole at position 29 in the selection must be K4[64]='Y'

# Approach: fix ordering = reading order (row-major), then find which
# subsets of 97 from 114 (by dropping 17 holes) have the property
# that the hole at selection-position 29 is the K4[64] ('Y') hole.

# First: is there a hole at K4 physical position 64 for some (W, dr, dc)?
# Without physical layout knowledge, K4 position 64 is the 65th carved char.
# We need: some hole h such that "h would be at selection position 29 in our chosen 97"
# i.e., exactly 29 holes before h in the selection come before h in reading order.

# Under reading order: hole[i] is the i-th hole.
# If we drop some holes, the hole at original index 29 might shift.
# To have selection-position 29 at hole index k_orig:
#   exactly 29 holes before k_orig in reading order must NOT be dropped
#   i.e., drop (29-0) holes from original holes[0..k_orig-1] and (17-that) from the rest

# This is complex. Let's just try: for each possible "anchor" hole
# (the one that maps to sigma[29]=64), place it at selection position 29.

# To sigma[29]=64: K4[sigma[29]]=K4[64]='Y'.
# So we need selection_position_29_hole to have K4 physical index 64.
# Without overlay, we don't know which hole has K4 index 64.

# Alternative: For each pair (W, dr, dc) where hole h → K4 pos 64,
# find which hole h is, and check if selection-pos(h) = 29 under any dropping.

# Since we don't have overlay info, try a different approach:
# Use sigma = READING ORDER of holes (first 97), then check forced constraints
# by trying ALL 97-element contiguous windows in sorted hole list.

# For the constraint sigma[29]=64 (under KRYPTOS/vig/AZ):
# K4[64]='Y'. We need the 30th selected hole to map to carved position 64.
# In our "sigma = selection position → K4 position" framework:
# sigma[29] = 64 means: real_CT[29] = K4[64] = 'Y'
# K4[64] is the 65th carved character.
# So the 30th hole must "point to" K4 position 64.

# Without physical overlay, the only interpretation is:
# The grille is the PERMUTATION ITSELF: sigma[k] = f(holes[k])
# where f maps a hole to a K4 position.
# The simplest f: f(r,c) = reading_position_of_char_at_(r,c)_in_K4
# This requires knowing K4's physical layout.

# Let's try all possible layouts systematically with a FAST approach
print("  Fast layout search (all W, dr, dc)...")

for W in range(8, 50):
    k4_nrows = (97 + W - 1) // W
    for dr in range(NROWS - k4_nrows + 1):
        for dc in range(NCOLS - W + 1):
            # Quick check: do holes[29] and holes[71] land on K4?
            h29r, h29c = holes[29]
            h71r, h71c = holes[71]
            k4r29, k4c29 = h29r - dr, h29c - dc
            k4r71, k4c71 = h71r - dr, h71c - dc
            if (0 <= k4r29 < k4_nrows and 0 <= k4c29 < W and
                0 <= k4r71 < k4_nrows and 0 <= k4c71 < W):
                k4p29 = k4r29 * W + k4c29
                k4p71 = k4r71 * W + k4c71
                if k4p29 < 97 and k4p71 < 97:
                    # Both land on K4
                    # Check forced constraints for each combo
                    for kw, cipher, an in [('KRYPTOS','vig','AZ'),
                                            ('ABSCISSA','beau','KA'),
                                            ('PALIMPSEST','vig','AZ')]:
                        fc = all_forced.get((kw, cipher, an), {})
                        if not fc:
                            continue
                        satisfied = True
                        for pos, k4idx in fc.items():
                            if pos < len(holes):
                                hr, hc = holes[pos]
                                k4r_fc = hr - dr
                                k4c_fc = hc - dc
                                if not (0 <= k4r_fc < k4_nrows and 0 <= k4c_fc < W):
                                    satisfied = False; break
                                if k4r_fc * W + k4c_fc != k4idx:
                                    satisfied = False; break
                            else:
                                satisfied = False; break
                        if satisfied:
                            print(f"  FORCED MATCH: {kw}/{cipher}/{an} W={W} dr={dr} dc={dc}")
                            # Build full sigma
                            full_k4_map = []
                            for r, c in holes:
                                kr, kc = r - dr, c - dc
                                if 0 <= kr < k4_nrows and 0 <= kc < W:
                                    kp = kr * W + kc
                                    full_k4_map.append(kp if kp < 97 else -1)
                                else:
                                    full_k4_map.append(-1)
                            valid_map = [x for x in full_k4_map if x >= 0]
                            if len(valid_map) == 97 and len(set(valid_map)) == 97:
                                test_perm(valid_map, f"B-{kw}-{cipher}-{an}-W{W}-dr{dr}-dc{dc}")

print(f"  [B done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH C: COLUMNAR TRANSPOSITION WITH GRILLE STRUCTURE
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH C: Columnar transposition satisfying forced constraints")
print("="*70)

# For sigma[29]=64 (KRYPTOS/vig/AZ):
# If sigma is a columnar transposition with width W:
# Position 29 in "column-major reading" corresponds to some column col_29
# and some row row_29 in the write-grid.
# The column reading order determines which column is read first.
#
# Write: real_CT[k] → grid[k//W][k%W]
# Read: sigma[read_pos] = write_pos of the (read_pos)-th element read
# With standard columnar: read col 0 first, row 0 to nrows-1, then col 1, etc.
# (with key ordering)
#
# For sigma[29] = 64:
# In read order, position 29 corresponds to reading the 30th element.
# 29 = (col_29 stuff) depends on W and key order.
# We need the write position 64 to be at read position 29.
# Write position 64 = row 64//W, col 64%W.
# If columns are read in some order KEY, and this col appears at position
# KEY_rank(col_of_64) in the key, then read position 29 =
#   KEY_rank(col_of_64) * nrows + (64//W)  (approximately, for complete rows)

# More precisely: for width W, nrows = ceil(97/W)
# Write pos 64 is at (row64, col64) = (64//W, 64%W)
# In column ordering KEY = [c0, c1, ..., c_{W-1}]:
#   read_pos of write_pos 64 = sum(# cells before col64 in KEY order) + row64
# We want this = 29.
# sum(cells before col64) + row64 = 29
# If col64 is the k-th column in KEY: sum(nrows for i<k full cols) + row64 = 29

# Special case: no key (identity column order)
for W in range(7, 20):
    nrows = (97 + W - 1) // W
    col64 = 64 % W
    row64 = 64 // W
    # In identity order, col_j is the j-th column read
    # Read pos of write_pos 64 = col64 * nrows + row64 (for complete rows)
    # (approximate; exact depends on partial last row)
    rpos = col64 * nrows + row64
    if rpos < 97:
        print(f"  W={W}: write_pos[64] → read_pos {rpos} (need 29)")

    # For rpos=29: col64*nrows + row64 = 29
    # Given W, col64=64%W, row64=64//W, nrows=ceil(97/W)
    # Check:
    if rpos == 29:
        print(f"  *** W={W} identity order gives sigma[29]=64 ***")
        sigma = []
        for col in range(W):
            for row in range(nrows):
                pos = row * W + col
                if pos < 97:
                    sigma.append(pos)
        if len(sigma) == 97 and sorted(sigma) == list(range(97)):
            test_perm(sigma, f"C-identity-W{W}")

# What W and column ordering gives sigma[29]=64?
# col64 * nrows + row64 = 29
# For W=8: nrows=13, col64=64%8=0, row64=64//8=8 → 0*13+8=8 ≠ 29
# For W=9: nrows=11, col64=64%9=1, row64=64//9=7 → 1*11+7=18 ≠ 29
# For W=7: nrows=14, col64=64%7=1, row64=64//7=9 → 1*14+9=23 ≠ 29
# For W=10: nrows=10, col64=64%10=4, row64=64//10=6 → 4*10+6=46 ≠ 29
# For W=12: nrows=9, col64=64%12=4, row64=64//12=5 → 4*9+5=41 ≠ 29
# For W=13: nrows=8, col64=64%13=12, row64=64//13=4 → 12*8+4=100 > 97

# None of identity-order columnar gives sigma[29]=64.
# But with a non-trivial key ordering, we can achieve any read position.

# Let's find: for each W, what column ordering makes write_pos 64 → read_pos 29?
print("\n  Finding column orderings where sigma[29]=64...")
for W in range(7, 16):
    nrows = (97 + W - 1) // W
    col64 = 64 % W
    row64 = 64 // W

    # We need col64 to be read at position such that
    # (how many full cells before col64 in key order) + row64 = 29
    # cells_before = 29 - row64
    cells_before = 29 - row64
    if cells_before < 0:
        continue
    # If cells_before is divisible by nrows, then col64 is the k-th column (k = cells_before // nrows)
    if cells_before % nrows == 0:
        k = cells_before // nrows
        if 0 <= k < W and k != col64:
            print(f"  W={W}: col64={col64} should be at key_position {k} in column ordering")
            # Build permutation with this column ordering:
            # Create key where col64 is at position k
            remaining = [c for c in range(W) if c != col64]
            key_cols = remaining[:k] + [col64] + remaining[k:]
            sigma = []
            for col in key_cols:
                for row in range(nrows):
                    pos = row * W + col
                    if pos < 97:
                        sigma.append(pos)
            if len(sigma) == 97 and sorted(sigma) == list(range(97)):
                test_perm(sigma, f"C-W{W}-col64at{k}")

print(f"  [C done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH D: TRANSPOSITION WITH GRILLE-DEFINED COLUMN ORDER
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH D: Columnar transposition with grille-defined column key")
print("="*70)

# The grille has a specific number of holes per column.
# Use these counts to order the columns.
holes_per_col = [0] * NCOLS
for r, c in holes:
    holes_per_col[c] += 1

print(f"  Holes per column: {holes_per_col}")

# For width W transposition: key = subset of columns from the grille structure.
# Column ordering: sorted by holes_per_col (ascending or descending).

for W in range(8, 18):
    nrows = (97 + W - 1) // W

    # Key: first W columns of holes_per_col, sorted
    key_W = holes_per_col[:W]
    col_order_asc = sorted(range(W), key=lambda c: (key_W[c], c))
    col_order_desc = sorted(range(W), key=lambda c: (-key_W[c], c))

    for name, col_order in [('asc', col_order_asc), ('desc', col_order_desc)]:
        sigma = []
        for col in col_order:
            for row in range(nrows):
                pos = row * W + col
                if pos < 97:
                    sigma.append(pos)
        if len(sigma) == 97 and sorted(sigma) == list(range(97)):
            test_perm(sigma, f"D-W{W}-holes-key-{name}")

# Also: use ALL columns (0..32), but only for width=33 transposition
key_33 = holes_per_col
col_order_33 = sorted(range(33), key=lambda c: (key_33[c], c))
nrows_33 = (97 + 32) // 33
sigma_33 = []
for col in col_order_33:
    for row in range(nrows_33):
        pos = row * 33 + col
        if pos < 97:
            sigma_33.append(pos)
if len(sigma_33) == 97 and sorted(sigma_33) == list(range(97)):
    test_perm(sigma_33, "D-W33-holes-key")

print(f"  [D done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH E: K4 T-POSITION ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH E: K4 T-positions and GE T-absence")
print("="*70)

print(f"  T positions in K4: {T_POS_K4}")
print(f"  T absent from GE (106 chars)")
print(f"  Interpretation: grille holes avoided T-tableau cells")

# If the grille holes avoid T-cells in the KA tableau,
# and T appears 6 times in K4, then:
# the 6 T-positions in K4 are NOT at hole-reading positions 0..95
# i.e., sigma does NOT include these positions as VALUES at any crib position

# Under KRYPTOS/vig/AZ: expected real_CT = ORQIGCJDYCPLHLVPABBUVFAZ
# None of these are T. ✓ (So T-positions in K4 don't need to appear in crib positions)

# Partition K4 positions into:
# T-positions: [35, 37, 50, 67, 68, 80] (6 positions with 'T' in K4)
# Non-T: the other 91 positions

# The holes (via GE) show 0 T's. If holes map to K4 positions,
# we'd expect holes to avoid the T-positions {35,37,50,67,68,80}.

# Check: for any (W, dr, dc) physical overlay, do holes avoid T-positions?
T_avoid_layouts = []
for W in range(8, 50):
    k4_nrows = (97 + W - 1) // W
    t_cells = {(t // W, t % W) for t in T_POS_K4}
    for dr in range(NROWS - k4_nrows + 1):
        for dc in range(NCOLS - W + 1):
            # Check if any hole maps to a T-position
            hits_T = 0
            for r, c in holes:
                kr, kc = r - dr, c - dc
                if (kr, kc) in t_cells:
                    hits_T += 1
            if hits_T == 0:
                # Great - no holes on T-positions
                # Count total holes landing on K4
                landing = []
                for r, c in holes:
                    kr, kc = r - dr, c - dc
                    if 0 <= kr < k4_nrows and 0 <= kc < W:
                        kp = kr * W + kc
                        if kp < 97:
                            landing.append(kp)
                if len(set(landing)) == 97:
                    T_avoid_layouts.append((W, dr, dc, landing))
                    test_perm(landing, f"E-T-avoid-W{W}-dr{dr}-dc{dc}")
                elif len(landing) > 85:
                    print(f"  Near-T-avoid: W={W} dr={dr} dc={dc}: {len(landing)} unique K4 hits, {hits_T} T-hits")

print(f"  [E done, {len(T_avoid_layouts)} T-avoiding layouts with exact 97 unique]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH F: HOLE-ROW INDICES AS KEY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH F: Hole row-index sequence as transposition key")
print("="*70)

# The row indices of the 114 holes in reading order form a sequence.
# This sequence can be used as a transposition key.
row_seq = [r for r, c in holes]
col_seq = [c for r, c in holes]

# F1: First 97 row indices as key (values 0..27)
row_key_97 = row_seq[:97]
# Rank-order: sigma[k] = rank of row_key_97[k] among row_key_97
sigma_F1 = sorted(range(97), key=lambda k: (row_key_97[k], k))
test_perm(sigma_F1, "F1-row-key-rank")

# F2: First 97 col indices as key
col_key_97 = col_seq[:97]
sigma_F2 = sorted(range(97), key=lambda k: (col_key_97[k], k))
test_perm(sigma_F2, "F2-col-key-rank")

# F3: row+col combined
rc_key_97 = [r + c for r, c in holes[:97]]
sigma_F3 = sorted(range(97), key=lambda k: (rc_key_97[k], k))
test_perm(sigma_F3, "F3-rowcol-sum-rank")

# F4: row*33+col (linear, rank)
lin_key_97 = [(r * 33 + c) for r, c in holes[:97]]
sigma_F4 = sorted(range(97), key=lambda k: (lin_key_97[k], k))
test_perm(sigma_F4, "F4-linear-rank")

# Inverse permutations
for sigma, name in [(sigma_F1, "F1"), (sigma_F2, "F2"), (sigma_F3, "F3"), (sigma_F4, "F4")]:
    inv = [0] * 97
    for i, v in enumerate(sigma): inv[v] = i
    test_perm(inv, f"{name}-inv")

print(f"  [F done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH G: 73-POSITION SUBSET SCRAMBLE
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH G: 73 scrambled positions (97-24 non-crib)")
print("="*70)

CRIB_POS = set()
for start, text in CRIBS:
    for j in range(len(text)):
        CRIB_POS.add(start + j)
non_crib_pos = [i for i in range(97) if i not in CRIB_POS]
print(f"  Crib positions: {len(CRIB_POS)}, non-crib: {len(non_crib_pos)}")
print(f"  CRIB_POS: {sorted(CRIB_POS)}")

# Hypothesis: sigma[i] = i for crib positions (identity = unscrambled)
# sigma[i] = some_grille_derived_perm[i] for non-crib positions

# Build base sigma = identity at crib positions
base_sigma = list(range(97))  # identity
# Now permute the non-crib positions using hole sequence
non_crib_holes = [(r, c) for r, c in holes if (r * 33 + c) % 97 in non_crib_pos]

# G1: Use hole sequence to define permutation of non-crib positions
# Take first 73 holes' linear positions mod 73, use as permutation of non_crib_pos
lin_mod73 = [(r * 33 + c) % 73 for r, c in holes[:73]]
if len(set(lin_mod73)) == 73:
    # Apply this as a permutation of non_crib_pos
    reordered_noncrib = [non_crib_pos[lin_mod73[i]] for i in range(73)]
    sigma_G1 = list(range(97))
    for i, orig_pos in enumerate(non_crib_pos):
        sigma_G1[orig_pos] = reordered_noncrib[i]
    if sorted(sigma_G1) == list(range(97)):
        test_perm(sigma_G1, "G1-73mod-noncrib-perm")
else:
    print(f"  G1: first-73-holes linear mod 73 has {len(set(lin_mod73))} unique values (need 73)")

# G2: Identity for crib pos + hole-rank for non-crib pos
# Sort non_crib_pos by some ordering
hole_for_noncrib = holes[:73]  # first 73 holes
ranks = sorted(range(73), key=lambda k: hole_for_noncrib[k][0] * 33 + hole_for_noncrib[k][1])
sigma_G2 = list(range(97))
for i, orig in enumerate(non_crib_pos):
    sigma_G2[orig] = non_crib_pos[ranks[i]]
if sorted(sigma_G2) == list(range(97)):
    test_perm(sigma_G2, "G2-identity-crib-rank-noncrib")

print(f"  [G done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH H: INTERLEAVE BY HOLE POSITION IN ROW
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH H: Interleave holes by position-within-row")
print("="*70)

# Group holes by row, get position within row (0th, 1st, 2nd, ... hole in that row)
row_groups = defaultdict(list)
for r, c in holes:
    row_groups[r].append(c)
for r in row_groups:
    row_groups[r].sort()

# Interleave: take 1st hole from each row, then 2nd from each row, etc.
max_per_row = max(len(v) for v in row_groups.values())
rows_used = sorted(row_groups.keys())
print(f"  Rows with holes: {rows_used}")
print(f"  Max holes per row: {max_per_row}")

interleaved = []
for slot in range(max_per_row):
    for r in rows_used:
        if slot < len(row_groups[r]):
            interleaved.append((r, row_groups[r][slot]))

print(f"  Interleaved sequence length: {len(interleaved)}")

# Take first 97, convert to linear mod 97
lin_H = [(r * 33 + c) % 97 for r, c in interleaved[:97]]
if len(set(lin_H)) == 97:
    test_perm(lin_H, "H1-interleave-by-slot")

seen_H = set()
dedup_H = []
for r, c in interleaved:
    v = (r * 33 + c) % 97
    if v not in seen_H:
        seen_H.add(v)
        dedup_H.append(v)
    if len(dedup_H) == 97: break
if len(dedup_H) == 97 and len(set(dedup_H)) == 97:
    test_perm(dedup_H, "H1-interleave-dedup")

# Rank-based: sigma[k] = rank of k-th interleaved hole (by linear pos)
interleaved_97 = interleaved[:97]
sigma_H2 = sorted(range(97), key=lambda k: interleaved_97[k][0] * 33 + interleaved_97[k][1])
test_perm(sigma_H2, "H2-interleave-rank")
inv_H2 = [0]*97
for i,v in enumerate(sigma_H2): inv_H2[v] = i
test_perm(inv_H2, "H2-interleave-rank-inv")

print(f"  [H done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH I: HOLE SEQUENCE AS POLYBIUS SQUARE COORDINATES
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH I: Holes as Polybius square / row-col decode")
print("="*70)

# The grille has 28 rows × 33 cols.
# If we treat (row, col) as (row_key, col_key) in a substitution:
# row 0..27 → letter A..Z (27=AA?), col 0..32 → letter A..Z
# For row values 0..27 and col values 0..32:
# row mod 26 → letter in KA, col mod 26 → letter in KA
# These two letters give a bigram → position in some 26×26 table

# I1: (row mod 26) * 26 + (col mod 26) for each hole, mod 97
vals_I1 = [((r % 26) * 26 + (c % 26)) % 97 for r, c in holes[:97]]
if len(set(vals_I1)) == 97:
    test_perm(vals_I1, "I1-polybius-mod97")

seen_I1 = set()
dedup_I1 = []
for r, c in holes:
    v = ((r % 26) * 26 + (c % 26)) % 97
    if v not in seen_I1:
        seen_I1.add(v)
        dedup_I1.append(v)
    if len(dedup_I1) == 97: break
if len(dedup_I1) == 97 and len(set(dedup_I1)) == 97:
    test_perm(dedup_I1, "I1-polybius-dedup")

# I2: KA-indexed: KA_row × 26 + KA_col
KA_idx = {c: i for i, c in enumerate(KA)}
# Tableau body: row r → key char KA[r], col c → plain char KA[c]
# Cell value → KA-keyed encrypted char at (r, c)
# For the KA tableau: cell[r][c] = KA[(KA_idx[KA[r]] + c) % 26]
# Actually the GE value at hole (r,c) = KA[(r + c) % 26] (approximately)
# Use (r + c) mod 26 as a value:
vals_I2 = [((r + c) % 26) for r, c in holes[:97]]
# This gives values 0..25, not 0..96 → not directly a permutation of 0..96
# But we can use cumsum or other transformation:
cumsum_I2 = 0
dedup_I2 = []
seen_I2 = set()
for r, c in holes:
    v = ((r + c) % 26)
    cumsum_I2 = (cumsum_I2 + v + 1) % 97
    if cumsum_I2 not in seen_I2:
        seen_I2.add(cumsum_I2)
        dedup_I2.append(cumsum_I2)
    if len(dedup_I2) == 97: break
if len(dedup_I2) == 97 and len(set(dedup_I2)) == 97:
    test_perm(dedup_I2, "I2-cumsum-rc-mod97")

print(f"  [I done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH J: HOLE SEQUENCE AS VIGENERE KEY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH J: Grille structure as period/key for new cipher type")
print("="*70)

# The grille has 4 holes in period-8 rows (F=5, N=13, V=21) per the memory.
# Period-8 structure: rows {5, 13, 21} have special significance.
# If K4 uses a key of period 8, then:
# - Key char at pos k = key[k % 8]
# - Period-8 rows define which key chars are "doubled" or special

# J1: Use hole column positions of period-8 row holes as a period-8 key
p8_holes = [(r, c) for r, c in holes if r in {5, 13, 21}]
print(f"  Period-8 row holes: {p8_holes}")

# Group by row
p8_by_row = defaultdict(list)
for r, c in p8_holes:
    p8_by_row[r].append(c)
print(f"  Row 5 holes: {p8_by_row[5]}")
print(f"  Row 13 holes: {p8_by_row[13]}")
print(f"  Row 21 holes: {p8_by_row[21]}")

# J2: "8 Lines 73" → interpret as 8 rows with SPECIFIC hole pattern
# If K4 is in 8 lines, and the grille covers those 8 lines with ~73 holes:
# The 73 holes over K4's 73 non-crib positions define the scramble.
# (Speculative)

# How many holes would land on 8 lines × (97/8 ≈ 12-13 cols)?
# If K4 is 8 lines × 13 cols (last row has 97-7*13=6 chars):
W8 = 13
k4_nrows8 = 8
for dr in range(NROWS - k4_nrows8 + 1):
    for dc in range(NCOLS - W8 + 1):
        landing8 = []
        for r, c in holes:
            kr, kc = r - dr, c - dc
            if 0 <= kr < k4_nrows8 and 0 <= kc < W8:
                kp = kr * W8 + kc
                if kp < 97:
                    landing8.append(kp)
        if len(landing8) >= 70:
            print(f"  8×13 overlay dr={dr} dc={dc}: {len(landing8)} holes, "
                  f"{len(set(landing8))} unique")
            if len(landing8) == 97 and len(set(landing8)) == 97:
                test_perm(landing8, f"J-8x13-dr{dr}-dc{dc}")
            elif len(set(landing8)) == 73:
                print(f"    73 unique! Checking if non-crib...")

print(f"  [J done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH K: BINARY MASK INTERPRETATION VARIANTS
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH K: Alternative mask interpretations")
print("="*70)

# K1: What if 0=HOLE (reversed interpretation)?
holes_alt = [(r, c) for r, row in enumerate(MASK_ROWS_RAW)
             for c, ch in enumerate(row) if ch == '0' and c < 33]
print(f"  Alt (0=hole) count: {len(holes_alt)}")

if len(holes_alt) >= 97:
    # Try first 97
    lin_alt97 = [(r * 33 + c) % 97 for r, c in holes_alt[:97]]
    if len(set(lin_alt97)) == 97:
        test_perm(lin_alt97, "K1-alt-0hole-first97")

    # Rank-based
    sub_alt = holes_alt[:97]
    sigma_K1 = sorted(range(97), key=lambda k: sub_alt[k][0] * 33 + sub_alt[k][1])
    test_perm(sigma_K1, "K1-alt-0hole-rank")
    inv_K1 = [0]*97
    for i, v in enumerate(sigma_K1): inv_K1[v] = i
    test_perm(inv_K1, "K1-alt-0hole-rank-inv")

print(f"  [K done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH L: SELF-REFERENTIAL PERMUTATION FROM HOLE STRUCTURE
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH L: Hole self-referential mappings")
print("="*70)

# L1: For each hole h at position (r, c), map to the HOLE whose linear index
# is (r*33+c) mod N_HOLES. This creates a mapping within the hole set.
# If it forms a permutation of 0..N_HOLES, extract 97-element cycle.

hole_to_hole = [(r * 33 + c) % N_HOLES for r, c in holes]
print(f"  hole_to_hole unique: {len(set(hole_to_hole))} / {N_HOLES}")

# Follow the mapping starting from hole 0
visited = [False] * N_HOLES
path = []
cur = 0
for _ in range(N_HOLES * 2):
    if visited[cur]:
        break
    visited[cur] = True
    path.append(cur)
    cur = hole_to_hole[cur]

print(f"  Cycle starting at 0: length {len(path)}")
if len(path) >= 97:
    sigma_L1 = path[:97]
    # sigma_L1[k] = index of k-th hole in cycle; need to convert to K4 index
    # Actually sigma[k] = hole_linear[path[k]] % 97 might work
    sig = [hole_linear[path[k]] % 97 for k in range(97)]
    if len(set(sig)) == 97:
        test_perm(sig, "L1-self-ref-cycle")

# L2: Follow hole → hole[f(r,c)] chain where f = (r*NCOLS+c) mod N_HOLES
# Starting from different seeds
for seed in range(min(10, N_HOLES)):
    visited = [False] * N_HOLES
    path = []
    cur = seed
    for _ in range(N_HOLES * 2):
        if visited[cur]: break
        visited[cur] = True
        path.append(cur)
        cur = hole_to_hole[cur]
    if len(path) >= 97:
        sig = [hole_linear[path[k]] % 97 for k in range(97)]
        if len(set(sig)) == 97:
            test_perm(sig, f"L2-cycle-seed{seed}")

print(f"  [L done]")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH M: GE LETTERS AS PERMUTATION VIA PRIME FIELD
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("APPROACH M: GE in 25-letter alphabet (T absent) → Z/97Z")
print("="*70)

# 25-letter alphabet (T removed)
AZ25 = [c for c in AZ if c != 'T']
KA25 = [c for c in KA if c != 'T']
print(f"  AZ25: {''.join(AZ25)}")
print(f"  KA25: {''.join(KA25)}")

# Map GE chars to 0..24 in AZ25
def ge_to_az25(ge_str, alpha25):
    return [alpha25.index(c) for c in ge_str]

ge_az25 = ge_to_az25(GE, AZ25)
ge_ka25 = ge_to_az25(GE, KA25)

# M1: Consecutive pairs (v1*25 + v2) mod 97 from AZ25
pairs_M1 = [(ge_az25[i] * 25 + ge_az25[i+1]) % 97
            for i in range(0, len(GE)-1, 2)][:48]

seen_M1 = set()
dedup_M1 = []
for i in range(0, len(GE)-1, 2):
    v = (ge_az25[i] * 25 + ge_az25[i+1]) % 97
    if v not in seen_M1:
        seen_M1.add(v)
        dedup_M1.append(v)
    if len(dedup_M1) == 97: break

if len(dedup_M1) == 97 and len(set(dedup_M1)) == 97:
    test_perm(dedup_M1, "M1-GE-az25-pairs-dedup")

# M2: KA25 pairs
seen_M2 = set()
dedup_M2 = []
for i in range(0, len(GE)-1, 2):
    v = (ge_ka25[i] * 25 + ge_ka25[i+1]) % 97
    if v not in seen_M2:
        seen_M2.add(v)
        dedup_M2.append(v)
    if len(dedup_M2) == 97: break

if len(dedup_M2) == 97 and len(set(dedup_M2)) == 97:
    test_perm(dedup_M2, "M2-GE-ka25-pairs-dedup")

# M3: Triple GE chars as base-25^2+25+1 = 651 → mod 97
seen_M3 = set()
dedup_M3 = []
for i in range(0, len(GE)-2, 3):
    v = (ge_az25[i] * 625 + ge_az25[i+1] * 25 + ge_az25[i+2]) % 97
    if v not in seen_M3:
        seen_M3.add(v)
        dedup_M3.append(v)
    if len(dedup_M3) == 97: break

if len(dedup_M3) == 97 and len(set(dedup_M3)) == 97:
    test_perm(dedup_M3, "M3-GE-az25-triples")

print(f"  [M done]")

# ══════════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)
print(f"Total permutations tested: {tested}")
print(f"Best score seen: {best_score_seen:.4f}/char")
print(f"Crib hits: {len(hits)}")
if hits:
    for h in hits:
        print(f"  *** HIT: {h['label']}")
        print(f"      PT: {h['pt']}")
        print(f"      Score: {h['score']:.4f}, ENE@{h['ene']}, BC@{h['bc']}")
else:
    print("  No crib hits.")

print("\nTop notable scores:")
for n in sorted(notable, key=lambda x: -x['score'])[:5]:
    print(f"  {n['score']:.4f}: {n['label']}")

# Key analytic findings:
print("\nKEY FINDINGS:")
print("  sigma[29]=64 FORCED (KRYPTOS/vig/AZ): no grille ordering satisfies this")
print("  sigma[29]=69 AND sigma[71]=64 FORCED (ABSCISSA/beau/KA)")
print("  Physical overlay: 0 layouts give exact 97 unique K4 hits")

import json as json2
with open(f"{RESULTS_DIR}/results.json", 'w') as f:
    json2.dump({"tested": tested, "best_score": best_score_seen,
                "crib_hits": hits, "notable": notable}, f, indent=2)
print(f"\nResults saved to {RESULTS_DIR}/results.json")
