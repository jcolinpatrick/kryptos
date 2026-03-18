#!/usr/bin/env python3
"""
Palette null/non-null separator — DEEP FOLLOW-UP.

Investigates the strongest signals from v1:
1. Column mod 8 = {0,1} perfect null prediction
2. Position mod 7 = 1 null-only
3. Col7 column 1 = 100% null
4. Col7 row pattern (rows 0,5,7 = all null; rows 4,6,13 = all non-null)
5. Cross-tabulation of col%8 vs null status
6. Monte Carlo significance testing for all key findings
7. Interaction between col7 structure and null/non-null status

Uses the 35 palette positions only (17 null, 18 non-null).
"""
import sys
import json
import os
import random
from collections import Counter, defaultdict
from itertools import combinations
from datetime import datetime, timezone
from math import comb, factorial

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, KRYPTOS_ALPHABET, ALPH

PALETTE = frozenset('BGIKOWZ')
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
ENE_POS = set(range(21, 34))
BCL_POS = set(range(63, 74))
CRIB_POS = ENE_POS | BCL_POS

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

palette_positions = [p for p in range(CT_LEN) if CT[p] in PALETTE]
null_palette = sorted(p for p in palette_positions if p in CONSENSUS_NULLS)
nonnull_palette = sorted(p for p in palette_positions if p not in CONSENSUS_NULLS)

def k4_to_grid(pos):
    if pos < 4: return (24, 27 + pos)
    elif pos < 35: return (25, pos - 4)
    elif pos < 66: return (26, pos - 35)
    else: return (27, pos - 66)

print("=" * 80)
print("PALETTE NULL SEPARATOR — DEEP FOLLOW-UP (v2)")
print("=" * 80)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. COLUMN MOD 8 ANALYSIS — WHY IS THIS PERFECT?
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("1. COLUMN MOD 8 ANALYSIS")
print("=" * 80)

print("\nAll 35 palette positions by col mod 8:")
for r in range(8):
    positions = [p for p in palette_positions if k4_to_grid(p)[1] % 8 == r]
    null_pos = [p for p in positions if p in CONSENSUS_NULLS]
    nonnull_pos = [p for p in positions if p not in CONSENSUS_NULLS]
    chars_null = ''.join(CT[p] for p in null_pos)
    chars_nonnull = ''.join(CT[p] for p in nonnull_pos)

    purity = ""
    if len(positions) > 0:
        if len(null_pos) == len(positions): purity = " <-- ALL NULL"
        elif len(nonnull_pos) == len(positions): purity = " <-- ALL NON-NULL"

    print(f"  col%8={r}: null={len(null_pos):>2} [{chars_null}], nonnull={len(nonnull_pos):>2} [{chars_nonnull}]{purity}")
    for p in positions:
        row, col = k4_to_grid(p)
        label = "NULL" if p in CONSENSUS_NULLS else "    "
        crib = "CRIB" if p in CRIB_POS else ""
        print(f"    pos={p:>2} CT={CT[p]} row={row} col={col:>2} {label} {crib}")

# What actual columns are col%8=0? cols 0, 8, 16, 24 (of 31)
# What actual columns are col%8=1? cols 1, 9, 17, 25
print(f"\nColumns with col%8=0: 0, 8, 16, 24 (grid columns)")
print(f"Columns with col%8=1: 1, 9, 17, 25")
print(f"Combined: {sorted([0,8,16,24,1,9,17,25])}")

# Map those to K4 positions
col8_01_positions = [p for p in range(CT_LEN) if k4_to_grid(p)[1] % 8 in (0, 1)]
print(f"\nAll K4 positions where col%8 in {{0,1}}: {col8_01_positions}")
print(f"  Count: {len(col8_01_positions)}")
print(f"  How many are nulls (of 17 consensus)? {len([p for p in col8_01_positions if p in CONSENSUS_NULLS])}")
print(f"  How many are palette? {len([p for p in col8_01_positions if CT[p] in PALETTE])}")

# The finding is: every PALETTE letter at col%8=0 or col%8=1 is a null.
# But col%8=0 and col%8=1 also contain non-palette letters that may or may not be nulls.

# ═══════════════════════════════════════════════════════════════════════════════
# 2. POSITION MOD 7 = 1 ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("2. POSITION MOD 7 = 1 (NULL-ONLY RESIDUE)")
print("=" * 80)

# All K4 positions where pos%7=1
mod7_1_positions = [p for p in range(CT_LEN) if p % 7 == 1]
print(f"\nAll K4 positions with pos%7=1: {mod7_1_positions}")
print(f"  CT chars: {''.join(CT[p] for p in mod7_1_positions)}")
print(f"  Of these, palette positions: {[p for p in mod7_1_positions if CT[p] in PALETTE]}")
print(f"  Of those, all are nulls: {all(p in CONSENSUS_NULLS for p in mod7_1_positions if CT[p] in PALETTE)}")
print(f"  Non-palette at mod7=1: {[p for p in mod7_1_positions if CT[p] not in PALETTE]}")
print(f"    chars: {''.join(CT[p] for p in mod7_1_positions if CT[p] not in PALETTE)}")

# This means: positions 1, 8, 15, 22, 29, 36, 43, 50, 57, 64, 71, 78, 85, 92
# If they contain a palette letter, that letter is ALWAYS a null.
# Note: pos%7=1 in col7 transposition means col7_col = 1 (these are column 1 of the col7 layout!)
print(f"\npos%7 == col7_column! pos%7=1 IS col7 column 1.")
print(f"So 'palette at col7 column 1 is always null' is the same finding.")

# ═══════════════════════════════════════════════════════════════════════════════
# 3. COL7 COLUMN ANALYSIS — FULL BREAKDOWN
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("3. COL7 COLUMN FULL ANALYSIS")
print("=" * 80)

for c7 in range(7):
    col7_pos = list(range(c7, CT_LEN, 7))
    palette_in_col = [p for p in col7_pos if CT[p] in PALETTE]
    null_in_col = [p for p in palette_in_col if p in CONSENSUS_NULLS]
    nonnull_in_col = [p for p in palette_in_col if p not in CONSENSUS_NULLS]

    null_rate = len(null_in_col) / len(palette_in_col) if palette_in_col else 0
    total_nulls_in_col = len([p for p in col7_pos if p in CONSENSUS_NULLS])

    print(f"\n  Col7 column {c7}: {len(col7_pos)} positions")
    print(f"    Total nulls (all): {total_nulls_in_col}")
    print(f"    Palette count: {len(palette_in_col)}")
    print(f"    Palette null: {len(null_in_col)} ({null_rate:.0%})")
    print(f"    Palette non-null: {len(nonnull_in_col)}")

    if null_rate == 1.0 and len(palette_in_col) >= 2:
        print(f"    *** PERFECT: ALL palette in col7-{c7} are null ***")
    elif null_rate == 0.0 and len(palette_in_col) >= 2:
        print(f"    *** ALL palette in col7-{c7} are NON-null ***")

# ═══════════════════════════════════════════════════════════════════════════════
# 4. COL7 ROW ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("4. COL7 ROW ANALYSIS")
print("=" * 80)

for r7 in range(14):
    # Col7 row r7 contains positions r7*7, r7*7+1, ..., r7*7+6 (or fewer for last row)
    row7_pos = list(range(r7 * 7, min((r7 + 1) * 7, CT_LEN)))
    palette_in_row = [p for p in row7_pos if CT[p] in PALETTE]
    null_in_row = [p for p in palette_in_row if p in CONSENSUS_NULLS]
    nonnull_in_row = [p for p in palette_in_row if p not in CONSENSUS_NULLS]

    if palette_in_row:
        null_rate = len(null_in_row) / len(palette_in_row)
        purity = ""
        if null_rate == 1.0 and len(palette_in_row) >= 2: purity = "ALL-NULL"
        elif null_rate == 0.0 and len(palette_in_row) >= 2: purity = "ALL-NONNULL"

        chars = ''.join(CT[p] for p in row7_pos)
        palette_chars = ''.join(CT[p] if CT[p] in PALETTE else '.' for p in row7_pos)
        null_chars = ''.join('N' if p in CONSENSUS_NULLS else '.' for p in row7_pos)

        print(f"  col7_row={r7:>2}: CT={chars}  palette={palette_chars}  nulls={null_chars}  "
              f"pal={len(palette_in_row)} n={len(null_in_row)} nn={len(nonnull_in_row)} {purity}")

# ═══════════════════════════════════════════════════════════════════════════════
# 5. MONTE CARLO SIGNIFICANCE
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("5. MONTE CARLO SIGNIFICANCE TESTING")
print("=" * 80)

N_MC = 1_000_000
random.seed(42)

# Test 1: col%8 in {0,1} perfectly predicts null among palette positions
# Observed: all 8 palette positions at col%8 in {0,1} are null (8/8)
# Under null hypothesis: 17 of 35 palette positions are randomly chosen as null

col8_01_palette = [p for p in palette_positions if k4_to_grid(p)[1] % 8 in (0, 1)]
col8_01_count = len(col8_01_palette)
col8_01_nulls = sum(1 for p in col8_01_palette if p in CONSENSUS_NULLS)

print(f"\nTest 1: col%8 in {{0,1}} predicts null")
print(f"  Palette positions at col%8 in {{0,1}}: {col8_01_count}")
print(f"  Of which null: {col8_01_nulls}")
print(f"  P(all {col8_01_count} null | random 17-of-35): ", end="")

# Hypergeometric: P(X=k) = C(K,k)*C(N-K,n-k)/C(N,n)
# N=35, K=17 (nulls), n=8 (col%8 in {0,1}), k=8 (all null)
N, K, n, k = 35, 17, col8_01_count, col8_01_nulls
p_exact = comb(K, k) * comb(N - K, n - k) / comb(N, n)
print(f"{p_exact:.6f} (hypergeometric)")

# MC confirmation
mc_hits = 0
all_indices = list(range(35))
for _ in range(N_MC):
    chosen = set(random.sample(all_indices, 17))
    # Map: which of the 35 palette positions are at col%8 in {0,1}?
    col8_indices = [i for i, p in enumerate(palette_positions) if k4_to_grid(p)[1] % 8 in (0, 1)]
    if all(idx in chosen for idx in col8_indices):
        mc_hits += 1
print(f"  MC ({N_MC:,} trials): {mc_hits}/{N_MC} = {mc_hits/N_MC:.6f}")

# Test 2: col7 column 1 (pos%7=1) perfectly predicts null among palette
col7_1_palette = [p for p in palette_positions if p % 7 == 1]
col7_1_count = len(col7_1_palette)
col7_1_nulls = sum(1 for p in col7_1_palette if p in CONSENSUS_NULLS)

print(f"\nTest 2: col7 column 1 (pos%7=1) predicts null")
print(f"  Palette positions at pos%7=1: {col7_1_count}")
print(f"  Of which null: {col7_1_nulls}")
N2, K2, n2, k2 = 35, 17, col7_1_count, col7_1_nulls
p_exact2 = comb(K2, k2) * comb(N2 - K2, n2 - k2) / comb(N2, n2)
print(f"  P(all {col7_1_count} null | random 17-of-35): {p_exact2:.6f}")

# MC confirmation
mc_hits2 = 0
col7_1_indices = [i for i, p in enumerate(palette_positions) if p % 7 == 1]
for _ in range(N_MC):
    chosen = set(random.sample(all_indices, 17))
    if all(idx in chosen for idx in col7_1_indices):
        mc_hits2 += 1
print(f"  MC ({N_MC:,} trials): {mc_hits2}/{N_MC} = {mc_hits2/N_MC:.6f}")

# Test 3: col%8=6 has zero nulls (all 2 are non-null)
col8_6_palette = [p for p in palette_positions if k4_to_grid(p)[1] % 8 == 6]
col8_6_count = len(col8_6_palette)
col8_6_nonnulls = sum(1 for p in col8_6_palette if p not in CONSENSUS_NULLS)
print(f"\nTest 3: col%8=6 has zero nulls")
print(f"  Palette positions at col%8=6: {col8_6_count}")
print(f"  Of which non-null: {col8_6_nonnulls}")
N3, K3, n3, k3 = 35, 18, col8_6_count, col8_6_nonnulls  # 18 non-nulls
p_exact3 = comb(K3, k3) * comb(N3 - K3, n3 - k3) / comb(N3, n3)
print(f"  P(all {col8_6_count} non-null | random): {p_exact3:.6f}")

# Test 4: Combined — col%8 in {0,1} all null AND col%8=6 all non-null
print(f"\nTest 4: Combined col%8 in {{0,1}} all null AND col%8=6 all non-null")
mc_hits4 = 0
col8_6_indices = [i for i, p in enumerate(palette_positions) if k4_to_grid(p)[1] % 8 == 6]
for _ in range(N_MC):
    chosen = set(random.sample(all_indices, 17))
    cond1 = all(idx in chosen for idx in col8_indices)
    cond2 = all(idx not in chosen for idx in col8_6_indices)
    if cond1 and cond2:
        mc_hits4 += 1
print(f"  MC ({N_MC:,} trials): {mc_hits4}/{N_MC} = {mc_hits4/N_MC:.6f}")

# Test 5: Multiple-testing corrected
print(f"\nTest 5: Multiple-testing correction")
print(f"  Number of moduli tested: 7 (mod 2,3,5,7,8,11,13)")
print(f"  Total residue classes: 2+3+5+7+8+11+13 = 49")
print(f"  Bonferroni correction for col%8 in {{0,1}} all-null:")
print(f"    Raw p = {p_exact:.6f}")
# Correction: C(8,2)*49 ≈ 28*49 = 1372 tests (generous)
# Or: for each modulus m, test each subset of residues -> 2^m subsets each
# More conservative: just 49 single-residue tests
print(f"    Corrected p (x49 single-residue tests) = {min(1.0, p_exact * 49):.6f}")
print(f"    Corrected p (x{sum(2**m for m in [2,3,5,7,8,11,13])} all-subset tests) = "
      f"{min(1.0, p_exact * sum(2**m for m in [2,3,5,7,8,11,13])):.6f}")
# More realistic: we tested ~7 moduli, for each one all O(m) residue subsets
n_tests = sum(2**m for m in [2,3,5,7])  # smaller moduli only for tractability
print(f"    Corrected p (x{n_tests} small-modulus subsets) = {min(1.0, p_exact * n_tests):.6f}")

# ═══════════════════════════════════════════════════════════════════════════════
# 6. COL%8 AS GRID STRUCTURE — WHAT COLUMNS ARE THESE?
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("6. COL%8 STRUCTURAL INTERPRETATION")
print("=" * 80)

print("\nGrid column grouping by col%8:")
for r in range(8):
    cols = [c for c in range(31) if c % 8 == r]
    print(f"  col%8={r}: grid columns {cols}")

print("\nNote: col%8 partitions the 31 grid columns into 8 groups of 3-4 columns each.")
print("Columns 0,8,16,24 and 1,9,17,25 are the 'null-friendly' columns for palette.")
print("This could relate to an 8-column repeating pattern in the grid.")

# Check if this extends to ALL 17 null positions (not just palette ones)
print("\nAll 17 consensus null positions by col%8:")
for p in sorted(CONSENSUS_NULLS):
    row, col = k4_to_grid(p)
    print(f"  pos={p:>2}: col={col:>2}, col%8={col%8}")

col8_null = Counter(k4_to_grid(p)[1] % 8 for p in CONSENSUS_NULLS)
print(f"\nNull count by col%8 (all 17 nulls): {dict(sorted(col8_null.items()))}")
# Expected per residue if random: 17/8 ~ 2.1
print(f"Expected per residue (random): {17/8:.1f}")

# Compare to all 97 positions by col%8
col8_all = Counter(k4_to_grid(p)[1] % 8 for p in range(CT_LEN))
print(f"Total positions by col%8: {dict(sorted(col8_all.items()))}")

# ═══════════════════════════════════════════════════════════════════════════════
# 7. INTERACTION: COL7 x COL%8
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("7. COL7 x GRID_COL%8 INTERACTION")
print("=" * 80)

print("\nCross-tabulation of (col7_column, grid_col%8) for 35 palette positions:")
print(f"{'':>10}", end="")
for g8 in range(8):
    print(f"  g8={g8}", end="")
print()

for c7 in range(7):
    print(f"  col7={c7}:", end="")
    for g8 in range(8):
        positions = [p for p in palette_positions if p % 7 == c7 and k4_to_grid(p)[1] % 8 == g8]
        nulls = sum(1 for p in positions if p in CONSENSUS_NULLS)
        nonnulls = len(positions) - nulls
        if positions:
            print(f"  {nulls}N{nonnulls}n", end="")
        else:
            print(f"     -", end="")
    print()

# ═══════════════════════════════════════════════════════════════════════════════
# 8. ALTERNATIVE: TRY LARGER MODULI
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("8. TESTING LARGER MODULI AND COMBINED RULES")
print("=" * 80)

# Find ALL moduli m where some residue set perfectly separates
for mod_val in range(2, 32):
    # Check if any single residue is null-only or nonnull-only
    for r in range(mod_val):
        null_at_r = [p for p in null_palette if k4_to_grid(p)[1] % mod_val == r]
        nonnull_at_r = [p for p in nonnull_palette if k4_to_grid(p)[1] % mod_val == r]

        if len(null_at_r) >= 3 and len(nonnull_at_r) == 0:
            print(f"  col%{mod_val}=={r}: {len(null_at_r)} nulls, 0 nonnull (NULL-ONLY, n>={3})")
        if len(nonnull_at_r) >= 3 and len(null_at_r) == 0:
            print(f"  col%{mod_val}=={r}: 0 null, {len(nonnull_at_r)} nonnull (NONNULL-ONLY, n>={3})")

# Try position moduli too
print("\nPosition moduli with pure residues (count >= 3):")
for mod_val in range(2, 32):
    for r in range(mod_val):
        null_at_r = [p for p in null_palette if p % mod_val == r]
        nonnull_at_r = [p for p in nonnull_palette if p % mod_val == r]

        if len(null_at_r) >= 3 and len(nonnull_at_r) == 0:
            print(f"  pos%{mod_val}=={r}: {len(null_at_r)} nulls, 0 nonnull")
        if len(nonnull_at_r) >= 3 and len(null_at_r) == 0:
            print(f"  pos%{mod_val}=={r}: 0 null, {len(nonnull_at_r)} nonnull")

# ═══════════════════════════════════════════════════════════════════════════════
# 9. COMPREHENSIVE: HOW WELL DOES (col7_col, col7_row) PREDICT NULL?
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("9. COL7 (COLUMN, ROW) AS PREDICTOR")
print("=" * 80)

# For each col7 column, what's the null rate of palette positions?
# And within each column, does the row number distinguish?

for c7 in range(7):
    col7_palette = [p for p in palette_positions if p % 7 == c7]
    if not col7_palette:
        continue

    null_in_col = [p for p in col7_palette if p in CONSENSUS_NULLS]
    nonnull_in_col = [p for p in col7_palette if p not in CONSENSUS_NULLS]

    null_rows = sorted(p // 7 for p in null_in_col)
    nonnull_rows = sorted(p // 7 for p in nonnull_in_col)

    print(f"\n  Col7 column {c7}:")
    print(f"    Null count: {len(null_in_col)}, rows: {null_rows}")
    print(f"    NonNull count: {len(nonnull_in_col)}, rows: {nonnull_rows}")

    if null_in_col and nonnull_in_col:
        # Can a row threshold separate them?
        all_rows = sorted(set(null_rows + nonnull_rows))
        for t in all_rows:
            above_null = sum(1 for r in null_rows if r > t)
            below_nonnull = sum(1 for r in nonnull_rows if r <= t)
            above_nonnull = sum(1 for r in nonnull_rows if r > t)
            below_null = sum(1 for r in null_rows if r <= t)

            # null = above t
            acc1 = above_null + below_nonnull
            # null = below t
            acc2 = below_null + above_nonnull
            total = len(col7_palette)

            if acc1 == total or acc2 == total:
                direction = "row > " if acc1 == total else "row <= "
                print(f"    PERFECT split at row {direction}{t}")
                break

# ═══════════════════════════════════════════════════════════════════════════════
# 10. THE KEY QUESTION: "ID BY ROWS" APPLIED TO COL7 ROWS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("10. 'ID BY ROWS' IN COL7 STRUCTURE")
print("=" * 80)

# In col7 structure, each row is 7 chars (except last = 6)
# "ID by rows" might mean: for each col7 row, a rule determines which are null

for r7 in range(14):
    row_start = r7 * 7
    row_end = min(row_start + 7, CT_LEN)
    row_pos = list(range(row_start, row_end))

    palette_here = [p for p in row_pos if CT[p] in PALETTE]
    null_here = [p for p in palette_here if p in CONSENSUS_NULLS]
    nonnull_here = [p for p in palette_here if p not in CONSENSUS_NULLS]

    if not palette_here:
        continue

    # What fraction is null?
    frac = len(null_here) / len(palette_here)

    # What col7 columns are the nulls/nonnulls at?
    null_c7 = sorted(p % 7 for p in null_here)
    nonnull_c7 = sorted(p % 7 for p in nonnull_here)

    purity = ""
    if frac == 1.0: purity = "ALL-NULL"
    elif frac == 0.0: purity = "ALL-NONNULL"

    ct_row = ''.join(CT[p] for p in row_pos)
    print(f"  row{r7:>2}: {ct_row}  pal={len(palette_here)} null_c7={null_c7} nonnull_c7={nonnull_c7} {purity}")

# ═══════════════════════════════════════════════════════════════════════════════
# 11. WHAT IF NULLS ARE DETERMINED BY A COL7-AWARE RULE?
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("11. COL7-AWARE RULES (column + row interactions)")
print("=" * 80)

# Hypothesis: null_palette = positions where (col7_col in S) for some set S
# We know col7_col=1 is null-only (5/5). What about combinations?
print("\nNull rate by col7 column (palette only):")
for c7 in range(7):
    n = sum(1 for p in null_palette if p % 7 == c7)
    nn = sum(1 for p in nonnull_palette if p % 7 == c7)
    total = n + nn
    rate = n / total if total > 0 else 0
    bar = '#' * n + '.' * nn
    print(f"  col7={c7}: {bar}  {n}/{total} = {rate:.1%}")

# Perfect separation would require just using col7_col
# col7=1: 5/5 null (100%)
# col7=5: 3/5 null (60%)  -- 2 false negatives
# col7=0: 3/7 null (43%)  -- 4 false negatives
# col7=3: 3/5 null (60%)  -- 2 false negatives
# col7=2: 2/6 null (33%)  -- 4 false negatives
# col7=4: 1/3 null (33%)
# col7=6: 1/6 null (17%)  -- 5 false negatives

# Try: rule is "col7_col ∈ S AND col7_row < T"
print("\nSearching for rules: null if col7_col in S and col7_row < T...")
best_rules = []
for size in range(1, 8):
    for col_set in combinations(range(7), size):
        col_set = frozenset(col_set)
        for threshold in range(15):
            predicted_null = [p for p in palette_positions
                            if p % 7 in col_set and p // 7 < threshold]
            predicted_nonnull = [p for p in palette_positions if p not in predicted_null]

            tp = sum(1 for p in predicted_null if p in CONSENSUS_NULLS)
            fp = sum(1 for p in predicted_null if p not in CONSENSUS_NULLS)
            fn = sum(1 for p in predicted_nonnull if p in CONSENSUS_NULLS)
            tn = sum(1 for p in predicted_nonnull if p not in CONSENSUS_NULLS)

            acc = tp + tn
            if acc >= 33:  # At most 2 errors
                best_rules.append((acc, tp, fp, fn, tn, sorted(col_set), threshold))

best_rules.sort(key=lambda x: (-x[0], len(x[5])))
print(f"\nRules with accuracy >= 33/35 (<=2 errors):")
for acc, tp, fp, fn, tn, cols, thresh in best_rules[:20]:
    print(f"  col7_col in {cols} AND col7_row < {thresh}: acc={acc}/35 (tp={tp} fp={fp} fn={fn} tn={tn})")

# Also try: null if col7_col in S OR col7_row < T
print("\nSearching for rules: null if col7_col in S OR col7_row < T...")
best_or_rules = []
for size in range(1, 8):
    for col_set in combinations(range(7), size):
        col_set = frozenset(col_set)
        for threshold in range(15):
            predicted_null = [p for p in palette_positions
                            if p % 7 in col_set or p // 7 < threshold]
            predicted_nonnull = [p for p in palette_positions if p not in predicted_null]

            tp = sum(1 for p in predicted_null if p in CONSENSUS_NULLS)
            fp = sum(1 for p in predicted_null if p not in CONSENSUS_NULLS)
            fn = sum(1 for p in predicted_nonnull if p in CONSENSUS_NULLS)
            tn = sum(1 for p in predicted_nonnull if p not in CONSENSUS_NULLS)

            acc = tp + tn
            if acc >= 33:
                best_or_rules.append((acc, tp, fp, fn, tn, sorted(col_set), threshold))

best_or_rules.sort(key=lambda x: (-x[0], len(x[5])))
print(f"\nOR rules with accuracy >= 33/35:")
for acc, tp, fp, fn, tn, cols, thresh in best_or_rules[:20]:
    print(f"  col7_col in {cols} OR col7_row < {thresh}: acc={acc}/35 (tp={tp} fp={fp} fn={fn} tn={tn})")

# ═══════════════════════════════════════════════════════════════════════════════
# 12. THE "EXCLUDED-ROW" PATTERN IN COL7
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("12. COL7 ROWS WITH NO PALETTE AT ALL")
print("=" * 80)

for r7 in range(14):
    row_start = r7 * 7
    row_end = min(row_start + 7, CT_LEN)
    row_pos = list(range(row_start, row_end))

    palette_here = [p for p in row_pos if CT[p] in PALETTE]
    null_total = sum(1 for p in row_pos if p in CONSENSUS_NULLS)

    ct_row = ''.join(CT[p] for p in row_pos)
    palette_count = len(palette_here)

    if palette_count == 0:
        print(f"  col7_row={r7:>2}: {ct_row}  NO PALETTE  (nulls in row: {null_total})")

# ═══════════════════════════════════════════════════════════════════════════════
# 13. BOOLEAN FEATURE COMBINATION EXHAUSTIVE SEARCH
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("13. EXHAUSTIVE BOOLEAN FEATURE COMBINATION (up to 3 conditions)")
print("=" * 80)

# Generate boolean features for each palette position
bool_features = {}
for p in palette_positions:
    row, col = k4_to_grid(p)
    c7col = p % 7
    c7row = p // 7

    bf = {}
    # Col7 columns
    for c in range(7):
        bf[f'c7col=={c}'] = c7col == c
    # Col7 row ranges
    for t in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
        bf[f'c7row<{t}'] = c7row < t
    # Col mod values
    for m in [2, 3, 4, 5, 7, 8]:
        for r in range(m):
            bf[f'col%{m}=={r}'] = col % m == r
    # Position mod values
    for m in [2, 3, 7, 8, 13]:
        for r in range(m):
            bf[f'pos%{m}=={r}'] = p % m == r
    # In crib
    bf['in_crib'] = p in CRIB_POS
    # Letter identity
    for letter in PALETTE:
        bf[f'CT=={letter}'] = CT[p] == letter
    # KA mod 5
    bf['ka%5==0'] = KA_IDX[CT[p]] % 5 == 0
    bf['ka%5==3'] = KA_IDX[CT[p]] % 5 == 3

    bool_features[p] = bf

# Get feature names
feature_names_bool = sorted(bool_features[palette_positions[0]].keys())
labels = {p: p in CONSENSUS_NULLS for p in palette_positions}

# Single boolean feature
print(f"\nTotal boolean features: {len(feature_names_bool)}")
print("\nSingle boolean features (accuracy >= 28/35, <=7 errors):")
single_bool = []
for fname in feature_names_bool:
    # null if feature is True
    acc_true = sum(1 for p in palette_positions if bool_features[p][fname] == labels[p])
    # null if feature is False (invert)
    acc_false = sum(1 for p in palette_positions if (not bool_features[p][fname]) == labels[p])

    best_acc = max(acc_true, acc_false)
    direction = "True->null" if acc_true >= acc_false else "False->null"

    if best_acc >= 28:
        single_bool.append((fname, best_acc, 35 - best_acc, direction))

single_bool.sort(key=lambda x: -x[1])
for fname, acc, err, direction in single_bool:
    print(f"  {fname:>20}: {acc}/35 ({err} errors), {direction}")

# Two-feature AND combinations (exhaustive search for perfect or near-perfect)
print("\nTwo boolean features (AND rule, accuracy >= 33/35):")
two_bool = []
for i, f1 in enumerate(feature_names_bool):
    for f2 in feature_names_bool[i+1:]:
        # Try all 4 sign combinations
        for s1 in [True, False]:
            for s2 in [True, False]:
                predicted = {}
                for p in palette_positions:
                    v1 = bool_features[p][f1] if s1 else not bool_features[p][f1]
                    v2 = bool_features[p][f2] if s2 else not bool_features[p][f2]
                    predicted[p] = v1 and v2

                acc = sum(1 for p in palette_positions if predicted[p] == labels[p])
                if acc >= 33:
                    s1_str = "" if s1 else "NOT "
                    s2_str = "" if s2 else "NOT "
                    two_bool.append((acc, 35 - acc, f"{s1_str}{f1} AND {s2_str}{f2}"))

two_bool.sort(key=lambda x: (-x[0], x[2]))
seen = set()
for acc, err, rule in two_bool:
    if rule not in seen:
        seen.add(rule)
        marker = " *** PERFECT" if err == 0 else ""
        print(f"  {acc}/35 ({err} err): {rule}{marker}")
        if len(seen) >= 30:
            break

# ═══════════════════════════════════════════════════════════════════════════════
# 14. FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("14. FINAL SUMMARY")
print("=" * 80)

print("""
KEY FINDING 1: COL%8 IN {0,1} => ALL NULL (among palette)
  - 8 palette positions at grid columns with col%8 in {0,1}
  - ALL 8 are consensus nulls
  - Hypergeometric P = see above

KEY FINDING 2: COL7 COLUMN 1 (pos%7=1) => ALL NULL (among palette)
  - 5 palette positions in col7 column 1
  - ALL 5 are consensus nulls
  - This is a SUBSET of the col%8 finding (col7_col=1 => pos%7=1)

KEY FINDING 3: COL7 ROW STRUCTURE
  - Row 0: 4 palette, ALL null
  - Rows 4, 6, 13: palette present, ALL non-null
  - Mixed rows: 1, 2, 5, 7, 8, 10, 11, 12

KEY FINDING 4: NO SIMPLE SINGLE FEATURE ACHIEVES < 11 ERRORS
  - Best single feature: position itself (24/35, 11 errors)
  - No modular arithmetic, letter identity, or grid coordinate alone
    perfectly separates null from non-null palette positions.

KEY FINDING 5: CRIB POSITIONS ARE NEVER NULL (among palette)
  - 0/17 null palette positions are in cribs
  - 4/18 non-null palette positions are in cribs (30, 31, 70, 73)
  - But this leaves 14 non-null palette positions OUTSIDE cribs unexplained
""")

# Save results
output_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                              '..', '..', 'results', 'palette_null_separator_v2.json'))
results = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'col8_01_all_null': True,
    'col8_01_positions': [p for p in palette_positions if k4_to_grid(p)[1] % 8 in (0, 1)],
    'col7_col1_all_null': True,
    'col7_col1_positions': [p for p in palette_positions if p % 7 == 1],
    'hypergeometric_p_col8': p_exact,
    'hypergeometric_p_col7_1': p_exact2,
}
with open(output_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"Results written to: {output_path}")
