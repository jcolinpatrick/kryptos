#!/usr/bin/env python3
"""Cylindrical Projection — Column Coincidence Deep Dive + Geometric Summary.

# Cipher: null_mask
# Family: geometry
# Status: active
# Keyspace: ~10K configurations
# Last run: never
# Best score: n/a

Investigates the strong correlation between consensus null positions and
LOW same-column letter coincidence across the 28×31 grid.

Also provides a definitive geometric analysis of whether the consensus
null positions have ANY interpretable pattern on the cylinder.
"""

import sys, os, math
from collections import Counter
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS

CT97 = CT; N = 97; N_NULLS = 24; N_PT = 73
ENE_START = 21; BCL_START = 63; GRID_COLS = 31
K4_START_ROW = 24; K4_START_COL = 27
CONSENSUS_17 = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}
KNOWN_15_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
W_POSITIONS = {20, 36, 48, 58, 74}

def k4_grid_positions():
    positions = []
    gp = K4_START_ROW * GRID_COLS + K4_START_COL
    for i in range(CT_LEN):
        positions.append((gp // GRID_COLS, gp % GRID_COLS))
        gp += 1
    return positions

K4_GRID = k4_grid_positions()

# Cipher evaluation
def columnar_perm(n, w):
    nr=(n+w-1)//w
    g=[list(range(r*w,min((r+1)*w,n))) for r in range(nr)]
    p=[]
    for c in range(w):
        for r in range(nr):
            if c<len(g[r]):p.append(g[r][c])
    return p
def rev(p):
    inv=[0]*len(p)
    for i,v in enumerate(p):inv[v]=i
    return inv
PC7=rev(columnar_perm(N_PT,7))

def eval_mask(ns,kw='DEFECTOR',perm=None):
    if perm is None:perm=PC7
    ns=frozenset(ns)
    ct73=''.join(CT97[i] for i in range(N) if i not in ns)
    az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in ns if p<ENE_START);n2=sum(1 for p in ns if p<BCL_START)
    es=ENE_START-n1;bs=BCL_START-n2
    t=[az[perm[i]] for i in range(N_PT)]
    pt=[];kn=[ord(c)-65 for c in kw];L=len(kn)
    for i,ci in enumerate(t):
        ki=kn[i] if i<L else ord(pt[i-L])-65
        pt.append(chr((ki-ci)%26+65))
    pt=''.join(pt)
    e=sum(1 for j,c in enumerate("EASTNORTHEAST") if es+j<len(pt) and pt[es+j]==c)
    b=sum(1 for j,c in enumerate("BERLINCLOCK") if bs+j<len(pt) and pt[bs+j]==c)
    return e+b,e,b,pt

def valid(ns):return len(ns)==N_NULLS and frozenset(ns).isdisjoint(CRIB_POSITIONS)

# Full grid
GRID = [
    'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV',
    'JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF',
    'DVFPJUDEEHZWETZYVGWHKKQETGFQJNC',
    'EGGWHKKXDQMCPFQZDQMMIAGPFXHQRLG',
    'TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA',
    'QZGZLECGYUXUEENJTBJLBQCETBJDFHR',
    'RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT',
    'IHHDDDUVHXDWKBFUFPWNTDFIYCUQZER',
    'EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI',
    'DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK',
    'FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ',
    'ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE',
    'DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP',
    'DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG',
    'ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI',
    'ACHTNREYULDSLLSLLNOHSNOSMRWXMNE',
    'TPRNGATIHNRARPESLNNELEBLPIIACAEX',
    'WMTWNDITEENRAHCTENEUDRETNHAEOETX',
    'FOLSEDTIWENHAEIOYTEYQHEENCTAYCR',
    'EIFTBRSPAMHHEWENATAMATEGYEERLBT',
    'EEFOASFIOTUETUAEOTOARMAEERTNRTI',
    'BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB',
    'AECTDDHILCEIHSITEGOEAOSDDRYDLOR',
    'ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE',
    'ECDMRIPFEIMEHNLSSTTRTVDOHWXOBKR',
    'UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO',
    'TWTQSJQSSEKZZWATJKLUDIAWINFBNYP',
    'VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR',
]

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 1: Column coincidence scoring for ALL K4 positions
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("COLUMN COINCIDENCE ANALYSIS")
print("="*80)
print()

# For each K4 position, count how many times the same letter appears
# in the same column across all other rows
coincidence_scores = {}
for i in range(N):
    r, c = K4_GRID[i]
    k4_char = CT97[i]
    matches = 0
    for row_idx, row_text in enumerate(GRID):
        if row_idx == r:
            continue
        if c < len(row_text) and row_text[c] == k4_char:
            matches += 1
    coincidence_scores[i] = matches

print(f"{'K4idx':>6} {'Char':>4} {'Row':>4} {'Col':>4} {'Coincidence':>12} {'Status':>10}")
print("-"*50)
for i in sorted(range(N), key=lambda x: coincidence_scores[x]):
    status = "NULL*" if i in CONSENSUS_17 else ("CRIB" if i in CRIB_POSITIONS else "real")
    print(f"{i:6d} {CT97[i]:>4} {K4_GRID[i][0]:4d} {K4_GRID[i][1]:4d} {coincidence_scores[i]:12d} {status:>10}")

print()

# Statistics
null_coinc = [coincidence_scores[i] for i in CONSENSUS_17]
real_coinc = [coincidence_scores[i] for i in range(N) if i not in CONSENSUS_17]
crib_coinc = [coincidence_scores[i] for i in CRIB_POSITIONS]

print(f"Consensus null coincidence: mean={sum(null_coinc)/len(null_coinc):.2f}, "
      f"median={sorted(null_coinc)[len(null_coinc)//2]}, "
      f"range={min(null_coinc)}-{max(null_coinc)}")
print(f"Real position coincidence:  mean={sum(real_coinc)/len(real_coinc):.2f}, "
      f"median={sorted(real_coinc)[len(real_coinc)//2]}, "
      f"range={min(real_coinc)}-{max(real_coinc)}")
print(f"Crib position coincidence:  mean={sum(crib_coinc)/len(crib_coinc):.2f}, "
      f"median={sorted(crib_coinc)[len(crib_coinc)//2]}, "
      f"range={min(crib_coinc)}-{max(crib_coinc)}")

print()

# Distribution histogram
print("Coincidence distribution:")
for c_val in range(max(coincidence_scores.values()) + 1):
    n_null = sum(1 for i in CONSENSUS_17 if coincidence_scores[i] == c_val)
    n_real = sum(1 for i in range(N) if i not in CONSENSUS_17 and coincidence_scores[i] == c_val)
    print(f"  {c_val}: null={n_null:2d}, real={n_real:2d}  "
          f"{'N'*n_null}{'.'*n_real}")

print()

# Test: use coincidence score as the null selection rule
# Rank all positions by coincidence, take bottom 24 as nulls
ranked = sorted(range(N), key=lambda x: coincidence_scores[x])
for cutoff in range(20, 35):
    null_set = set(ranked[:cutoff])
    # If more than 24, need to trim; if less, need to add
    # Just test exact 24
    pass

# More precise: take the 24 positions with lowest coincidence that don't hit cribs
ranked_nocrib = [i for i in ranked if i not in CRIB_POSITIONS]
null_set_by_coinc = set(ranked_nocrib[:24])
print(f"Bottom 24 by coincidence (avoiding cribs): {sorted(null_set_by_coinc)}")
print(f"  Overlap with consensus: {len(null_set_by_coinc & CONSENSUS_17)}/17")
if valid(null_set_by_coinc):
    sc, e, b, pt = eval_mask(null_set_by_coinc)
    print(f"  Score: {sc}/24 (e={e}, b={b})")

print()

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 2: Is the coincidence-null correlation SIGNIFICANT?
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("SIGNIFICANCE TEST: COINCIDENCE-NULL CORRELATION")
print("="*80)
print()

# Monte Carlo: pick 17 random non-crib positions, measure mean coincidence
import random
random.seed(42)

non_crib = [i for i in range(N) if i not in CRIB_POSITIONS]
observed_mean = sum(null_coinc) / len(null_coinc)
n_trials = 100000
count_leq = 0
for _ in range(n_trials):
    sample = random.sample(non_crib, 17)
    sample_mean = sum(coincidence_scores[i] for i in sample) / 17
    if sample_mean <= observed_mean:
        count_leq += 1

p_value = count_leq / n_trials
print(f"Observed mean coincidence of 17 consensus nulls: {observed_mean:.3f}")
print(f"P-value (Monte Carlo, {n_trials} trials): {p_value:.6f}")
print(f"  This means: probability of randomly selecting 17 non-crib positions")
print(f"  with mean coincidence ≤ {observed_mean:.3f} is {p_value:.4%}")
print()

if p_value < 0.05:
    print("STATISTICALLY SIGNIFICANT (p < 0.05)")
    print("The consensus null positions have unusually LOW same-column coincidence.")
    print("This is consistent with the nulls being positions where the letter")
    print("does NOT appear elsewhere in the same column — i.e., UNIQUE letters")
    print("in their column, which would NOT project light through aligned cutouts.")
else:
    print("NOT STATISTICALLY SIGNIFICANT (p >= 0.05)")
    print("The coincidence-null correlation could be explained by chance.")

print()

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 3: UNWRAPPED CYLINDER VISUALIZATION
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("UNWRAPPED CYLINDER VISUALIZATION")
print("="*80)
print()

# Show the 4 K4 rows on the unwrapped cylinder
# with null positions marked
print("K4 on the unwrapped 31-column cylinder:")
print("(X=consensus null, C=crib, W=W-position, o=other real, .=not K4)")
print()

# Column header
print("     ", end="")
for c in range(31):
    print(f"{c%10}", end="")
print()
print("     ", end="")
for c in range(31):
    print(f"{c//10}", end="")
print()

for row in range(24, 28):
    print(f"R{row}: ", end="")
    for col in range(31):
        # Find K4 index for this (row, col)
        found = False
        for i, (r, c) in enumerate(K4_GRID):
            if r == row and c == col:
                if i in CONSENSUS_17:
                    print("X", end="")
                elif i in CRIB_POSITIONS:
                    print("C", end="")
                elif i in W_POSITIONS:
                    print("W", end="")
                else:
                    print("o", end="")
                found = True
                break
        if not found:
            print(".", end="")
    print()

print()

# Show the KNOWN 15/24 mask
print("KNOWN 15/24 mask on unwrapped cylinder:")
print("(N=null, C=crib, o=real, .=not K4)")
print()
print("     ", end="")
for c in range(31):
    print(f"{c%10}", end="")
print()

for row in range(24, 28):
    print(f"R{row}: ", end="")
    for col in range(31):
        found = False
        for i, (r, c) in enumerate(K4_GRID):
            if r == row and c == col:
                if i in KNOWN_15_MASK:
                    print("N", end="")
                elif i in CRIB_POSITIONS:
                    print("C", end="")
                else:
                    print("o", end="")
                found = True
                break
        if not found:
            print(".", end="")
    print()

print()

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 4: CYLINDER ANGULAR DISTANCE BETWEEN CONSECUTIVE NULLS
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("ANGULAR PATTERN IN CONSECUTIVE CONSENSUS NULLS")
print("="*80)
print()

sorted_consensus = sorted(CONSENSUS_17)
print("Consecutive consensus null positions:")
for k, pos in enumerate(sorted_consensus):
    r, c = K4_GRID[pos]
    angle = c * 360.0 / 31.0
    if k > 0:
        prev_pos = sorted_consensus[k-1]
        gap = pos - prev_pos
        prev_c = K4_GRID[prev_pos][1]
        angle_diff = ((c - prev_c) * 360.0 / 31.0 + 180) % 360 - 180
        print(f"  K4[{pos:2d}] (row {r}, col {c:2d}, {angle:5.1f}°) — gap={gap:2d}, angle_diff={angle_diff:+6.1f}°")
    else:
        print(f"  K4[{pos:2d}] (row {r}, col {c:2d}, {angle:5.1f}°)")

print()

# Check if gaps follow a pattern
gaps = [sorted_consensus[i+1] - sorted_consensus[i] for i in range(len(sorted_consensus)-1)]
print(f"Gaps between consecutive consensus nulls: {gaps}")
print(f"Gap set: {sorted(set(gaps))}")
print(f"Mean gap: {sum(gaps)/len(gaps):.2f}")

# Check modular pattern
for mod in range(2, 31):
    residues = [pos % mod for pos in sorted_consensus]
    if len(set(residues)) <= mod // 2:
        print(f"  Mod {mod}: residues = {sorted(set(residues))} ({len(set(residues))} distinct)")

print()

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 5: COLUMN COINCIDENCE AS NULL MASK GENERATOR
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("COLUMN COINCIDENCE AS NULL MASK GENERATOR")
print("="*80)
print()

# Since the coincidence-null correlation is strong, try using column
# coincidence score as a ranking function to generate null masks.
# For each K4 position, the "null score" = (27 - coincidence_count)
# High null_score = more likely null.

# But we need exactly 24 nulls. Try different ways to break ties.

# Method 1: strict ranking, break ties by position
ranked_by_coinc = sorted(range(N), key=lambda x: (coincidence_scores[x], x))
for n_nulls_to_try in [24]:
    candidates = [i for i in ranked_by_coinc if i not in CRIB_POSITIONS]
    null_set = set(candidates[:n_nulls_to_try])
    if valid(null_set):
        sc, e, b, pt = eval_mask(null_set)
        overlap = len(null_set & CONSENSUS_17)
        overlap_15 = len(null_set & KNOWN_15_MASK)
        print(f"Top-{n_nulls_to_try} lowest coincidence: {sc}/24 (e={e},b={b})")
        print(f"  Overlap with consensus-17: {overlap}/17")
        print(f"  Overlap with known-15/24: {overlap_15}/24")
        print(f"  Nulls: {sorted(null_set)}")
        print()

# Method 2: all positions with coinc=0 + fill from coinc=1
coinc_0 = set(i for i in range(N) if coincidence_scores[i] == 0 and i not in CRIB_POSITIONS)
print(f"Positions with coincidence=0 (not crib): {len(coinc_0)}")
print(f"  Indices: {sorted(coinc_0)}")
print(f"  Overlap with consensus: {len(coinc_0 & CONSENSUS_17)}/17")

if len(coinc_0) < N_NULLS:
    remaining = N_NULLS - len(coinc_0)
    coinc_1 = set(i for i in range(N) if coincidence_scores[i] == 1 and i not in CRIB_POSITIONS and i not in coinc_0)
    print(f"Positions with coincidence=1 (not crib, not in coinc_0): {len(coinc_1)}")
    print(f"  Need {remaining} more from {len(coinc_1)} candidates")
    print(f"  Indices: {sorted(coinc_1)}")

    # Try all combinations of 'remaining' from coinc_1
    if len(coinc_1) >= remaining:
        n_combos = math.comb(len(coinc_1), remaining)
        print(f"  Testing {n_combos} combinations...")
        best_coinc = 0
        for extra in combinations(sorted(coinc_1), remaining):
            null_set = coinc_0 | set(extra)
            if valid(null_set):
                sc, e, b, pt = eval_mask(null_set)
                if sc > best_coinc:
                    best_coinc = sc
                    overlap = len(null_set & CONSENSUS_17)
                    overlap_15 = len(null_set & KNOWN_15_MASK)
                    print(f"  NEW BEST: {sc}/24 (e={e},b={b}) overlap_17={overlap} overlap_24={overlap_15}")
                    print(f"    Nulls: {sorted(null_set)}")
                if sc >= 7:
                    pass  # Already printed if new best

        print(f"  Best from coinc-0+1 combination: {best_coinc}/24")

print()

# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS 6: DEFINITIVE GEOMETRIC SUMMARY
# ══════════════════════════════════════════════════════════════════════════

print("="*80)
print("DEFINITIVE GEOMETRIC ANALYSIS SUMMARY")
print("="*80)
print()

# Key physical dimensions
circumference = GRID_COLS  # 31 columns = circumference
R_cyl = circumference / (2 * math.pi)
print(f"Cylinder circumference: {circumference} columns")
print(f"Cylinder radius: {R_cyl:.2f} column-widths")
print(f"K4 rows: {sorted(set(r for r,c in K4_GRID))}")
print(f"K4 row composition:")
print(f"  Row 24: 4 positions (cols 27-30)")
print(f"  Row 25: 31 positions (cols 0-30)")
print(f"  Row 26: 31 positions (cols 0-30)")
print(f"  Row 27: 31 positions (cols 0-30)")
print(f"Total: {4+31+31+31} = 97 positions")
print()

# The fundamental problem with column-based geometric models:
print("FUNDAMENTAL CONSTRAINT ON COLUMN-BASED MODELS:")
print("  Rows 25-27 each have ALL 31 columns. Any rule based purely on")
print("  column position (angle, sector, arc, front/back) will select")
print("  the SAME columns as null in all 3 full rows. This means:")
print(f"  - If X columns are null, you get 3X nulls from rows 25-27")
print(f"  - Plus 0-4 from row 24 (max 4)")
print(f"  - Need 24 total → 3X + y = 24, X = (24-y)/3")
print(f"  - For y=0: X=8 (8 null columns)")
print(f"  - For y=3: X=7 (7 null columns + 3 from row 24)")
print(f"  - For y=4: X=6.67 — NOT INTEGER, impossible!")
print(f"  - So: either 7 null columns + 3 from row24, or 8 null columns + 0 from row24")
print()

# Check consensus: how many distinct null columns?
consensus_cols = [K4_GRID[p][1] for p in CONSENSUS_17]
distinct_consensus_cols = sorted(set(consensus_cols))
print(f"Consensus null distinct columns: {distinct_consensus_cols}")
print(f"Number of distinct columns: {len(distinct_consensus_cols)}")

# Count nulls per column
col_null_counts = Counter(consensus_cols)
print("Nulls per column:")
for c in distinct_consensus_cols:
    print(f"  Col {c}: {col_null_counts[c]} consensus nulls")

# If column-based: need 3 nulls in each null column (from rows 25-27)
# Plus possibly some from row 24
fully_null_cols = [c for c, count in col_null_counts.items() if count >= 3]
partially_null_cols = [c for c, count in col_null_counts.items() if count < 3]
print(f"\nColumns with 3+ consensus nulls (could be fully null): {fully_null_cols}")
print(f"Columns with <3 consensus nulls: {partially_null_cols}")

# This is the KEY test: if consensus follows column-based geometry,
# then cols with 3 consensus nulls should be the "null columns"
# and the total from these alone should be close to 24

total_from_full = sum(col_null_counts[c] for c in fully_null_cols)
print(f"\nTotal consensus nulls from 'full' columns: {total_from_full}")
print(f"Total consensus nulls from 'partial' columns: {17 - total_from_full}")
print()

if partially_null_cols:
    print("CONCLUSION: Consensus nulls are NOT purely column-based.")
    print("Some columns have nulls in some rows but not others.")
    print("A row-dependent model (helix, per-row arc, S-curve, etc.) is needed.")
else:
    print("CONCLUSION: Consensus nulls ARE column-based! Specific columns are")
    print("consistently null across all K4 rows.")

print()

# Check if the known 15/24 mask is column-based
mask_cols = [K4_GRID[p][1] for p in KNOWN_15_MASK]
mask_col_counts = Counter(mask_cols)
print("Known 15/24 mask column analysis:")
for c in sorted(set(mask_cols)):
    k4_in_col = sum(1 for _, cc in K4_GRID if cc == c)
    print(f"  Col {c:2d}: {mask_col_counts[c]}/{k4_in_col} null in mask")

fully_null_mask_cols = [c for c, count in mask_col_counts.items()
                        if count == sum(1 for _, cc in K4_GRID if cc == c)]
print(f"\nFully null columns in 15/24 mask: {fully_null_mask_cols}")
print(f"Partially null columns: {[c for c in sorted(set(mask_cols)) if c not in fully_null_mask_cols]}")
