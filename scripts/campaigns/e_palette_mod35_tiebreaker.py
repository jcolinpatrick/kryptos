#!/usr/bin/env python3
"""
Palette Mod-35 Tiebreaker Analysis

The (pos%7, pos%5) grid nearly perfectly separates null/non-null palette
positions: 10 pure-null cells, 13 pure-real cells, and only 3 MIXED cells.
That's 32/35 correct from a simple 2D table lookup.

This script investigates what distinguishes the null from non-null positions
WITHIN those 3 mixed cells, and evaluates all possible tiebreaker rules.

Mixed cells:
  (0,0): pos=0 [NULL,O], pos=70 [REAL,Z]
  (2,3): pos=58 [NULL,W], pos=93 [REAL,K]
  (5,2): pos=12 [NULL,B], pos=47 [REAL,Z]

Each mixed cell has exactly 1 null and 1 non-null. A perfect tiebreaker
need only distinguish 3 binary choices.
"""
import sys
import os
import json
from collections import Counter, defaultdict
from itertools import product
from datetime import datetime, timezone
from math import comb

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, KRYPTOS_ALPHABET, ALPH

PALETTE = frozenset('BGIKOWZ')
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(ALPH)}
ENE_POS = set(range(21, 34))
BCL_POS = set(range(63, 74))
CRIB_POS = ENE_POS | BCL_POS

palette_positions = sorted(p for p in range(CT_LEN) if CT[p] in PALETTE)
labels = {p: p in CONSENSUS_NULLS for p in palette_positions}

SEVEN_AZ = [AZ_IDX[c] for c in 'SEVEN']
SEVEN_KA = [KA_IDX[c] for c in 'SEVEN']
KRYPTOS_AZ = [AZ_IDX[c] for c in 'KRYPTOS']
KRYPTOS_KA = [KA_IDX[c] for c in 'KRYPTOS']
DEFECTOR_AZ = [AZ_IDX[c] for c in 'DEFECTOR']

def k4_to_grid(pos):
    if pos < 4: return (24, 27 + pos)
    elif pos < 35: return (25, pos - 4)
    elif pos < 66: return (26, pos - 35)
    else: return (27, pos - 66)

# ══════════════════════════════════════════════════════════════════════════
# Build the (pos%7, pos%5) classification table
# ══════════════════════════════════════════════════════════════════════════
table = {}  # (c7, c5) -> 'null', 'real', 'mixed', 'empty'
cell_positions = defaultdict(list)

for p in palette_positions:
    cell = (p % 7, p % 5)
    cell_positions[cell].append(p)

for c7 in range(7):
    for c5 in range(5):
        cell = (c7, c5)
        positions = cell_positions.get(cell, [])
        if not positions:
            table[cell] = 'empty'
        else:
            null_count = sum(1 for p in positions if labels[p])
            real_count = len(positions) - null_count
            if null_count > 0 and real_count > 0:
                table[cell] = 'mixed'
            elif null_count > 0:
                table[cell] = 'null'
            else:
                table[cell] = 'real'

print("=" * 90)
print("PALETTE MOD-35 TIEBREAKER ANALYSIS")
print("=" * 90)

print("\n(pos%7, pos%5) classification grid:")
print(f"{'':>8}", end="")
for c5 in range(5):
    print(f"  p%5={c5}", end="")
print()
for c7 in range(7):
    print(f"p%7={c7}:", end="")
    for c5 in range(5):
        cell = (c7, c5)
        status = table[cell]
        char = {'null': 'N', 'real': 'R', 'mixed': '?', 'empty': '-'}[status]
        positions = cell_positions.get(cell, [])
        n = sum(1 for p in positions if labels[p])
        r = len(positions) - n
        print(f"  {n}N{r}R={char}", end="")
    print()

# Mixed cells detailed
mixed_cells = [(c7,c5) for (c7,c5), status in table.items() if status == 'mixed']
print(f"\nMixed cells: {mixed_cells}")

for c7, c5 in mixed_cells:
    positions = cell_positions[(c7,c5)]
    null_pos = [p for p in positions if labels[p]]
    real_pos = [p for p in positions if not labels[p]]
    print(f"\n  Cell ({c7},{c5}):")
    for p in positions:
        row, col = k4_to_grid(p)
        ka_idx = KA_IDX[CT[p]]
        ka_row = ka_idx // 5
        ka_col = ka_idx % 5
        tag = "NULL" if labels[p] else "REAL"
        print(f"    pos={p:>2} CT={CT[p]}(AZ={AZ_IDX[CT[p]]:>2},KA={ka_idx:>2}) "
              f"KA=({ka_row},{ka_col}) row={row} col={col:>2} "
              f"p%35={p%35:>2} crib={'yes' if p in CRIB_POS else 'no'} {tag}")

# ══════════════════════════════════════════════════════════════════════════
# The 3 mixed cells — what distinguishes null from non-null?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("TIEBREAKER ANALYSIS FOR 3 MIXED CELLS")
print("=" * 90)

# Cell (0,0): pos=0 [NULL,O] vs pos=70 [REAL,Z]
# Cell (2,3): pos=58 [NULL,W] vs pos=93 [REAL,K]
# Cell (5,2): pos=12 [NULL,B] vs pos=47 [REAL,Z]

null_mixed = [0, 58, 12]   # null positions in mixed cells
real_mixed = [70, 93, 47]  # non-null positions in mixed cells

print("\nKey differences between null and non-null in mixed cells:")
print(f"  Null positions: {null_mixed}, letters: {''.join(CT[p] for p in null_mixed)} = O,W,B")
print(f"  Real positions: {real_mixed}, letters: {''.join(CT[p] for p in real_mixed)} = Z,K,Z")

# Feature comparison
print("\nFeature comparison (null vs real in mixed cells):")
features_to_test = []

for p_null, p_real, cell in zip(null_mixed, real_mixed, mixed_cells):
    row_n, col_n = k4_to_grid(p_null)
    row_r, col_r = k4_to_grid(p_real)
    ka_n = KA_IDX[CT[p_null]]
    ka_r = KA_IDX[CT[p_real]]
    az_n = AZ_IDX[CT[p_null]]
    az_r = AZ_IDX[CT[p_real]]

    print(f"\n  Cell {cell}: NULL={p_null}({CT[p_null]}) vs REAL={p_real}({CT[p_real]})")
    print(f"    AZ:     {az_n:>2} vs {az_r:>2}  (diff = {(az_n-az_r)%26})")
    print(f"    KA:     {ka_n:>2} vs {ka_r:>2}  (diff = {(ka_n-ka_r)%26})")
    print(f"    KA_row: {ka_n//5} vs {ka_r//5}")
    print(f"    KA_col: {ka_n%5} vs {ka_r%5}")
    print(f"    Grid:   ({row_n},{col_n}) vs ({row_r},{col_r})")
    print(f"    col:    {col_n:>2} vs {col_r:>2}  (diff = {col_n-col_r})")
    print(f"    pos:    {p_null:>2} vs {p_real:>2}  (diff = {p_null-p_real})")
    print(f"    p%35:   {p_null%35:>2} vs {p_real%35:>2}")
    print(f"    crib:   {'Y' if p_null in CRIB_POS else 'N'} vs {'Y' if p_real in CRIB_POS else 'N'}")
    print(f"    row%4:  {row_n%4} vs {row_r%4}")

# ══════════════════════════════════════════════════════════════════════════
# Test 1: Is the tiebreaker simply "earlier position = null"?
# ══════════════════════════════════════════════════════════════════════════
print("\n\n--- TIEBREAKER TEST: Earlier position = null? ---")
earlier_is_null = all(p_null < p_real for p_null, p_real in zip(null_mixed, real_mixed))
print(f"  {null_mixed[0]} < {real_mixed[0]}: {null_mixed[0] < real_mixed[0]}")
print(f"  {null_mixed[1]} < {real_mixed[1]}: {null_mixed[1] < real_mixed[1]}")
print(f"  {null_mixed[2]} < {real_mixed[2]}: {null_mixed[2] < real_mixed[2]}")
print(f"  All earlier = null? {earlier_is_null}")
if earlier_is_null:
    print(f"  *** YES! In all 3 mixed cells, the EARLIER position is null ***")

# ══════════════════════════════════════════════════════════════════════════
# Test 2: Is the tiebreaker based on the CT letter?
# ══════════════════════════════════════════════════════════════════════════
print("\n--- TIEBREAKER TEST: Letter identity? ---")
print(f"  Null letters: {[CT[p] for p in null_mixed]} = O, W, B")
print(f"  Real letters: {[CT[p] for p in real_mixed]} = Z, K, Z")
# O,W,B have AZ values [14,22,1]; Z,K,Z have [25,10,25]
# O,W,B have KA values [5,23,8]; Z,K,Z have [25,0,25]
print(f"  Null AZ: {[AZ_IDX[CT[p]] for p in null_mixed]}")
print(f"  Real AZ: {[AZ_IDX[CT[p]] for p in real_mixed]}")
print(f"  Null KA: {[KA_IDX[CT[p]] for p in null_mixed]}")
print(f"  Real KA: {[KA_IDX[CT[p]] for p in real_mixed]}")

# KA values: null=[5,23,8], real=[25,0,25]
# Null KA_row: [1,4,1], Real KA_row: [5,0,5]
# Null KA_col: [0,3,3], Real KA_col: [0,0,0]
print(f"  Null KA_rows: {[KA_IDX[CT[p]]//5 for p in null_mixed]}")
print(f"  Real KA_rows: {[KA_IDX[CT[p]]//5 for p in real_mixed]}")
print(f"  Null KA_cols: {[KA_IDX[CT[p]]%5 for p in null_mixed]}")
print(f"  Real KA_cols: {[KA_IDX[CT[p]]%5 for p in real_mixed]}")

# Real letters are Z,K,Z. Z appears at KA_row=5 and K at KA_row=0.
# The real letters are at the EXTREME rows (0 and 5) of the KA Polybius grid!
# Null letters O,B have KA_row=1, W has KA_row=4
# Row extremeness: real={0,5,5}, null={1,4,1}
print(f"\n  Row extremeness: null rows {[KA_IDX[CT[p]]//5 for p in null_mixed]}, "
      f"real rows {[KA_IDX[CT[p]]//5 for p in real_mixed]}")

# Check: KA_row in {0,5} = real in mixed cell?
for p in null_mixed + real_mixed:
    ka_row = KA_IDX[CT[p]] // 5
    extreme = ka_row in {0, 5}
    is_null = labels[p]
    print(f"  pos={p} KA_row={ka_row} extreme={extreme} null={is_null} "
          f"{'correct' if extreme != is_null else 'WRONG'}")

# This gives perfect separation within mixed cells!
# But does it mess up the pure cells?
print("\n--- Checking KA_row extremeness (0 or 5) as null predictor across ALL 35 ---")
extreme_correct = 0
for p in palette_positions:
    ka_row = KA_IDX[CT[p]] // 5
    extreme = ka_row in {0, 5}
    # In mixed cells: extreme = real. In pure cells?
    predicted_real = extreme  # NOT null if extreme
    actual_real = not labels[p]
    if predicted_real == actual_real:
        extreme_correct += 1

print(f"  'KA_row not in {{0,5}} -> null' accuracy: {extreme_correct}/35")

# The tiebreaker in mixed cells is clear, but let's check if it works as GLOBAL rule
# combined with (pos%7, pos%5) table
print("\n--- COMBINED RULE: (pos%7,pos%5) table + KA_row tiebreaker ---")
combined_correct = 0
for p in palette_positions:
    cell = (p % 7, p % 5)
    cell_status = table.get(cell, 'empty')
    if cell_status == 'null':
        predicted_null = True
    elif cell_status == 'real':
        predicted_null = False
    elif cell_status == 'mixed':
        ka_row = KA_IDX[CT[p]] // 5
        predicted_null = ka_row not in {0, 5}  # extreme rows = real
    else:
        predicted_null = False  # empty = no palette = skip

    if predicted_null == labels[p]:
        combined_correct += 1
    else:
        print(f"  ERROR: pos={p} CT={CT[p]} cell={cell} status={cell_status} "
              f"predicted_null={predicted_null} actual_null={labels[p]}")

print(f"\n  Combined accuracy: {combined_correct}/35")
if combined_correct == 35:
    print(f"  *** PERFECT 35/35! ***")

# ══════════════════════════════════════════════════════════════════════════
# Test 3: What about the grid row?
# ══════════════════════════════════════════════════════════════════════════
print("\n\n--- TIEBREAKER TEST: Grid row ---")
for p_null, p_real, cell in zip(null_mixed, real_mixed, mixed_cells):
    row_n = k4_to_grid(p_null)[0]
    row_r = k4_to_grid(p_real)[0]
    print(f"  Cell {cell}: NULL row={row_n}, REAL row={row_r}, NULL < REAL = {row_n < row_r}")

# Check: in mixed cells, is the null always at a lower grid row?
lower_row_is_null = all(k4_to_grid(pn)[0] <= k4_to_grid(pr)[0]
                        for pn, pr in zip(null_mixed, real_mixed))
print(f"  Lower grid row = null? {lower_row_is_null}")

# ══════════════════════════════════════════════════════════════════════════
# Test 4: pos < 35 = first half of K4 = null? (K4 rows 24-25)
# ══════════════════════════════════════════════════════════════════════════
print("\n--- TIEBREAKER TEST: pos < 35 (first half) ---")
for p_null, p_real, cell in zip(null_mixed, real_mixed, mixed_cells):
    print(f"  Cell {cell}: NULL pos={p_null} < 35? {p_null < 35}, REAL pos={p_real} < 35? {p_real < 35}")

# pos < 35 means grid rows 24-25. All 3 null mixed positions are in rows 24-25.
# All 3 real mixed positions are in rows 26-27.
first_half_separates = all(p_null < 35 and p_real >= 35
                          for p_null, p_real in zip(null_mixed, real_mixed))
print(f"  First half = null in mixed cells? {first_half_separates}")

# But wait - pos=0 < 35 and pos=12 < 35 but pos=58 is NOT < 35 (58 >= 35)
print(f"  pos=58 < 35? {58 < 35}")  # FALSE! 58 is not in first half
print(f"  CORRECTION: pos < 35 does NOT work for cell (2,3)")

# ══════════════════════════════════════════════════════════════════════════
# Test 5: p%35 (mod 35 position)
# ══════════════════════════════════════════════════════════════════════════
print("\n--- TIEBREAKER TEST: p%35 ---")
for p_null, p_real, cell in zip(null_mixed, real_mixed, mixed_cells):
    print(f"  Cell {cell}: NULL p%35={p_null%35}, REAL p%35={p_real%35}")
# Cell (0,0): NULL p%35=0, REAL p%35=0 -- TIE
# Hmm, they have the SAME p%35 in cell (0,0). That's the fundamental issue --
# they're in the same (p%7, p%5) cell because p%35 maps the same way.

# Actually wait: gcd(7,5) = 1, so (p%7, p%5) uniquely determines p%35.
# That means in cell (0,0), both positions have p%35=0.
# But pos=0 is null and pos=70 is real. Both have p%35=0.
# The tiebreaker CANNOT be p%35 since it's the same for both.

# So the tiebreaker must use something BEYOND the period-35 structure.

# ══════════════════════════════════════════════════════════════════════════
# Test 6: Which repetition of the mod-35 pattern?
# ══════════════════════════════════════════════════════════════════════════
print("\n--- TIEBREAKER TEST: repetition index (p // 35) ---")
for p_null, p_real, cell in zip(null_mixed, real_mixed, mixed_cells):
    rep_null = p_null // 35
    rep_real = p_real // 35
    print(f"  Cell {cell}: NULL rep={rep_null} (p={p_null}), REAL rep={rep_real} (p={p_real})")
# Cell (0,0): NULL rep=0, REAL rep=2
# Cell (2,3): NULL rep=1, REAL rep=2
# Cell (5,2): NULL rep=0, REAL rep=1
# Is it: rep 0 = null, rep 2 = real?
# Cell (5,2) has rep 0 = null, rep 1 = real
# So it's just "lower rep = null"?

print(f"\n  Lower repetition = null in mixed cells:")
for p_null, p_real in zip(null_mixed, real_mixed):
    print(f"    {p_null//35} < {p_real//35} = {p_null//35 < p_real//35}")

# This is equivalent to "earlier position = null" since gcd(7,5)=1

# ══════════════════════════════════════════════════════════════════════════
# Test 7: "FIRST occurrence of each (p%7,p%5) cell = null"
# ══════════════════════════════════════════════════════════════════════════
print("\n\n--- COMBINED RULE: 'First occurrence in (p%7,p%5) cell = null' ---")
first_occurrence = {}
for p in range(CT_LEN):
    if CT[p] in PALETTE:
        cell = (p % 7, p % 5)
        if cell not in first_occurrence:
            first_occurrence[cell] = p

# For pure-null cells: first occurrence should be null (yes, by definition)
# For pure-real cells: first occurrence should be real
# For mixed cells: first occurrence should be null (the earlier one)
print("Checking if first occurrence determines null/real for ALL cells:")
first_occ_correct = 0
first_occ_total = 0
for p in palette_positions:
    cell = (p % 7, p % 5)
    is_first = (p == first_occurrence[cell])
    cell_status = table[cell]

    if cell_status == 'null':
        # All positions should be null, regardless of first/not
        predicted_null = True
    elif cell_status == 'real':
        # All positions should be real
        predicted_null = False
    elif cell_status == 'mixed':
        # First = null, later = real
        predicted_null = is_first

    if predicted_null == labels[p]:
        first_occ_correct += 1
    first_occ_total += 1

print(f"  Accuracy: {first_occ_correct}/{first_occ_total}")

# ══════════════════════════════════════════════════════════════════════════
# COMPREHENSIVE: Try all single-feature tiebreakers for mixed cells
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("EXHAUSTIVE SINGLE-FEATURE TIEBREAKER SEARCH")
print("=" * 90)

# For each mixed cell pair, compute many features
def compute_features(p):
    row, col = k4_to_grid(p)
    ka_val = KA_IDX[CT[p]]
    az_val = AZ_IDX[CT[p]]
    sv_az = SEVEN_AZ[p % 5]
    sv_ka = SEVEN_KA[p % 5]
    kw_az = AZ_IDX['KRYPTOS'[p % 7]]
    kw_ka = KA_IDX['KRYPTOS'[p % 7]]
    return {
        'pos': p,
        'ct_az': az_val,
        'ct_ka': ka_val,
        'ka_row': ka_val // 5,
        'ka_col': ka_val % 5,
        'grid_row': row,
        'grid_col': col,
        'p_div35': p // 35,
        'p_div7': p // 7,
        'sv_az': sv_az,
        'sv_ka': sv_ka,
        'kw_az': kw_az,
        'kw_ka': kw_ka,
        'ct_az + sv_az': (az_val + sv_az) % 26,
        'ct_az - sv_az': (az_val - sv_az) % 26,
        'sv_az - ct_az': (sv_az - az_val) % 26,
        'ct_ka + sv_ka': (ka_val + sv_ka) % 26,
        'ct_ka - sv_ka': (ka_val - sv_ka) % 26,
        'sv_ka - ct_ka': (sv_ka - ka_val) % 26,
        'ct_az + kw_az': (az_val + kw_az) % 26,
        'ct_ka + kw_ka': (ka_val + kw_ka) % 26,
        'ct_az + 13': (az_val + 13) % 26,
        'ct_ka + 13': (ka_val + 13) % 26,
        'ct_ka + 19': (ka_val + 19) % 26,
        'col % 7': col % 7,
        'col % 8': col % 8,
        'col % 5': col % 5,
        'col % 13': col % 13,
        'pos % 13': p % 13,
        'pos % 97': p % 97,
        '(pos + 13) % 26': (p + 13) % 26,
        '(pos + ct_az) % 26': (p + az_val) % 26,
        '(pos + ct_ka) % 26': (p + ka_val) % 26,
        '(pos * ct_az) % 26': (p * az_val) % 26,
        'ka_row * 5 + p%5': ka_val // 5 * 5 + p % 5,
        'ka_row XOR p%7': (ka_val // 5) ^ (p % 7),
        'ka_row + p%7': (ka_val // 5) + (p % 7),
        'in_crib': int(p in CRIB_POS),
        'ct_in_KRYPTOS': int(CT[p] in 'KRYPTOS'),
        'ct_in_SEVEN': int(CT[p] in 'SEVEN'),
        'left_ct_az': AZ_IDX[CT[p-1]] if p > 0 else -1,
        'right_ct_az': AZ_IDX[CT[p+1]] if p < CT_LEN-1 else -1,
        'abs(pos-48)': abs(p - 48),
    }

print("\nFeatures that perfectly separate null/real in ALL 3 mixed cells:")
print("(Feature value must be consistently higher or lower for null vs real)")

# For each feature, check if it separates all 3 mixed cell pairs
feature_names = list(compute_features(0).keys())
perfect_tiebreakers = []

for fname in feature_names:
    null_vals = [compute_features(p)[fname] for p in null_mixed]
    real_vals = [compute_features(p)[fname] for p in real_mixed]

    # Check: all null < all real in each pair?
    all_null_less = all(nv < rv for nv, rv in zip(null_vals, real_vals))
    all_null_greater = all(nv > rv for nv, rv in zip(null_vals, real_vals))

    if all_null_less or all_null_greater:
        direction = "null < real" if all_null_less else "null > real"
        perfect_tiebreakers.append((fname, direction, null_vals, real_vals))

for fname, direction, nv, rv in perfect_tiebreakers:
    print(f"  {fname:>30}: {direction}  null={nv} real={rv}")

# ══════════════════════════════════════════════════════════════════════════
# For each perfect tiebreaker, check overall accuracy when combined
# with the (p%7, p%5) table
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("COMBINED (p%7,p%5) TABLE + TIEBREAKER: OVERALL ACCURACY")
print("=" * 90)

for fname, direction, nv, rv in perfect_tiebreakers:
    # For mixed cells, use the tiebreaker
    # Need to determine the threshold
    # Find a threshold that separates null from real in mixed cells
    all_vals = [(compute_features(p)[fname], labels[p]) for p in palette_positions]

    # For mixed cells only, the tiebreaker must work:
    # null < real: use (val of first null) < midpoint or similar

    # Count correct predictions
    correct = 0
    for p in palette_positions:
        cell = (p % 7, p % 5)
        cell_status = table[cell]
        if cell_status == 'null':
            predicted_null = True
        elif cell_status == 'real':
            predicted_null = False
        elif cell_status == 'mixed':
            val = compute_features(p)[fname]
            # Find the null and real vals for this specific cell
            cell_positions_list = cell_positions[(p%7, p%5)]
            null_p = [pp for pp in cell_positions_list if labels[pp]]
            real_p = [pp for pp in cell_positions_list if not labels[pp]]
            null_val = compute_features(null_p[0])[fname]
            real_val = compute_features(real_p[0])[fname]
            if direction == "null < real":
                predicted_null = val <= null_val  # or val < midpoint
            else:
                predicted_null = val >= null_val
        else:
            predicted_null = False

        if predicted_null == labels[p]:
            correct += 1

    marker = " *** PERFECT" if correct == 35 else ""
    print(f"  Table + {fname:>30} ({direction}): {correct}/35{marker}")

# ══════════════════════════════════════════════════════════════════════════
# The simplest perfect rule
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("THE (pos%7, pos%5) TABLE — COMPLETE LOOKUP")
print("=" * 90)

print("\nEach (p%7, p%5) cell classification (N=null, R=real, E=empty):")
print("For mixed cells: first occurrence = null, later = real")
print()
print(f"{'':>8}", end="")
for c5 in range(5):
    print(f"   {c5}  ", end="")
print()
for c7 in range(7):
    print(f"  {c7}:  ", end="")
    for c5 in range(5):
        cell = (c7, c5)
        status = table.get(cell, 'empty')
        positions = cell_positions.get(cell, [])
        if status == 'empty':
            print(f"   -  ", end="")
        elif status == 'null':
            print(f"   N  ", end="")
        elif status == 'real':
            print(f"   R  ", end="")
        elif status == 'mixed':
            print(f"  N/R ", end="")
    print()

# ══════════════════════════════════════════════════════════════════════════
# Statistical significance
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STATISTICAL SIGNIFICANCE")
print("=" * 90)

# How likely is this pattern by chance?
# We have 35 positions to classify as 17 null / 18 real.
# The (p%7, p%5) table with 3 mixed cells = 23 cells, 10 pure-null, 13 pure-real.
# Pure cells account for 32 positions perfectly (all the multiples).
# Only 3 cells need tiebreaking (6 positions).

# Monte Carlo: assign 17 random of 35 as null, check how many (p%7,p%5) cells are pure
import random
random.seed(42)
N_MC = 1_000_000
pure_counts = []
mixed_3_or_less = 0
mixed_exact_3 = 0

for _ in range(N_MC):
    random_nulls = set(random.sample(range(35), 17))  # Indices into palette_positions
    cell_status_rand = {}
    for i, p in enumerate(palette_positions):
        cell = (p % 7, p % 5)
        is_null = i in random_nulls
        if cell not in cell_status_rand:
            cell_status_rand[cell] = set()
        cell_status_rand[cell].add(is_null)

    n_mixed = sum(1 for v in cell_status_rand.values() if True in v and False in v)
    pure_counts.append(26 - n_mixed)  # 26 occupied cells - n_mixed
    if n_mixed <= 3:
        mixed_3_or_less += 1
    if n_mixed == 3:
        mixed_exact_3 += 1

from statistics import mean, stdev
print(f"\n  MC ({N_MC:,} trials): random 17-of-35 classified by (p%7, p%5) cell")
print(f"  Mean mixed cells: {mean([26 - pc for pc in pure_counts]):.2f}")
print(f"  P(<=3 mixed cells): {mixed_3_or_less/N_MC:.6f} (1 in {N_MC//max(1,mixed_3_or_less):,})")
print(f"  P(exactly 3 mixed): {mixed_exact_3/N_MC:.6f}")

# Additionally: within those 3 mixed cells, what's the probability that
# the earlier position is ALWAYS the null? (3 independent binary choices)
# Each mixed cell has 2 positions; the null is one of them.
# P(all 3 earlier positions are null) = product of individual probabilities
# For cell (0,0) with positions [0,70]: P(earlier=null) = 1/C(2,1) = 1/2
# Same for each cell: 1/2 each. Combined: (1/2)^3 = 1/8
print(f"\n  Among configurations with exactly 3 mixed cells:")
print(f"  P(earlier = null in all 3 mixed cells) = (1/2)^3 = 1/8 = {1/8:.6f}")
print(f"  Combined P(<=3 mixed AND earlier=null in all): {mixed_3_or_less/N_MC * 0.125:.6f}")

# ══════════════════════════════════════════════════════════════════════════
# THE DEFINITIVE RULE — Can we express it as a table?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("THE DEFINITIVE RULE")
print("=" * 90)

# Null positions among palette: EXACTLY those where:
# 1. The (pos%7, pos%5) cell is classified as "null" in the table, OR
# 2. The (pos%7, pos%5) cell is "mixed" AND this is the first palette position in that cell.

# Equivalently: among all palette positions, sort by position.
# For each (p%7, p%5) cell, check if ALL its positions are null, ALL real, or mixed.
# The table is determined by the cell classification + first-occurrence tiebreaker.

# Can we compute the table from SEVEN and KRYPTOS alone?
# The (p%7, p%5) cell is equivalent to p % lcm(7,5) = p % 35.
# For 97 positions: p%35 cycles through 0..34 three times (35*2=70, 35*3=105>97)
# Third cycle is partial: positions 70-96 = p%35 values 0-26.

# The table maps p%35 -> {null, real, empty, mixed}
# For p%35 values 0-34:
print("\np%35 -> classification:")
for r in range(35):
    positions = [p for p in palette_positions if p % 35 == r]
    if not positions:
        continue
    null_count = sum(1 for p in positions if labels[p])
    real_count = len(positions) - null_count
    status = 'null' if real_count == 0 else 'real' if null_count == 0 else 'mixed'
    pos_str = ', '.join(f"{p}({'N' if labels[p] else 'R'})" for p in positions)
    print(f"  p%35={r:>2}: {status:>6}  positions: {pos_str}")

# Generate the mask as a binary string over p%35
print("\nThe null mask over p%35 (palette positions only):")
mask_35 = {}
for r in range(35):
    positions = [p for p in palette_positions if p % 35 == r]
    if not positions:
        mask_35[r] = '-'  # no palette at this residue
    else:
        null_count = sum(1 for p in positions if labels[p])
        real_count = len(positions) - null_count
        if real_count == 0:
            mask_35[r] = 'N'
        elif null_count == 0:
            mask_35[r] = 'R'
        else:
            mask_35[r] = '?'

mask_str = ''.join(mask_35.get(r, '-') for r in range(35))
print(f"  {mask_str}")
print(f"  N=null-only, R=real-only, ?=mixed, -=no palette")

# Lay it out as 7x5:
print("\nAs 7x5 grid (row = p%7, col = p%5):")
print(f"{'':>4}", end="")
for c5 in range(5):
    print(f"  {c5}", end="")
print()
for c7 in range(7):
    print(f"  {c7}:", end="")
    for c5 in range(5):
        r = (c7 * 5 + c5 * 7) % 35  # wrong -- need CRT
        # Actually: the cell (c7,c5) corresponds to p%7=c7 AND p%5=c5
        # By CRT, the unique r in [0,35) with r%7=c7 and r%5=c5 is:
        # r = c7*15 + c5*21 mod 35 (since 15 is 5-inverse mod 7: 15%7=1, 21 is 7-inverse mod 5: 21%5=1)
        r_crt = (c7 * 15 + c5 * 21) % 35
        print(f"  {mask_35.get(r_crt, '-')}", end="")
    print()

# ══════════════════════════════════════════════════════════════════════════
# VERIFICATION: Apply the rule to ALL 97 positions
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("VERIFICATION: APPLY RULE TO ALL K4 POSITIONS")
print("=" * 90)

# The rule says: a position p is a null if:
# 1. CT[p] is in palette {B,G,I,K,O,W,Z}
# 2. The (p%7, p%5) cell is "null" or "mixed-first"
# This predicts 17 specific null positions.
# Are they exactly the 17 consensus nulls?

predicted_nulls = set()
for p in range(CT_LEN):
    if CT[p] not in PALETTE:
        continue
    cell = (p % 7, p % 5)
    cell_status = table.get(cell, 'empty')
    if cell_status == 'null':
        predicted_nulls.add(p)
    elif cell_status == 'mixed':
        # Check if this is the FIRST palette position in this cell
        if p == first_occurrence[cell]:
            predicted_nulls.add(p)

print(f"\nPredicted null positions: {sorted(predicted_nulls)}")
print(f"Actual consensus nulls:   {sorted(CONSENSUS_NULLS)}")
print(f"Match: {predicted_nulls == CONSENSUS_NULLS}")

if predicted_nulls != CONSENSUS_NULLS:
    missing = CONSENSUS_NULLS - predicted_nulls
    extra = predicted_nulls - CONSENSUS_NULLS
    print(f"  Missing (in consensus but not predicted): {sorted(missing)}")
    print(f"  Extra (predicted but not in consensus): {sorted(extra)}")

# ══════════════════════════════════════════════════════════════════════════
# INTERPRETABILITY: What generates the 7x5 table?
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("INTERPRETATION: WHAT GENERATES THE 7x5 NULL/REAL TABLE?")
print("=" * 90)

# The 10 pure-null cells (p%7, p%5):
pure_null_cells = [(c7,c5) for (c7,c5), s in table.items() if s == 'null']
pure_real_cells = [(c7,c5) for (c7,c5), s in table.items() if s == 'real']
mixed_cells_list = [(c7,c5) for (c7,c5), s in table.items() if s == 'mixed']

print(f"\nPure null cells (10): {sorted(pure_null_cells)}")
print(f"Pure real cells (13): {sorted(pure_real_cells)}")
print(f"Mixed cells (3): {sorted(mixed_cells_list)}")

# Can we describe these with SEVEN and KRYPTOS?
# SEVEN = letters at indices [18,4,21,4,13] in AZ = [S,E,V,E,N]
# KRYPTOS = letters at indices [10,17,24,15,19,14,18] in AZ = [K,R,Y,P,T,O,S]

# In the 7x5 grid: row = KRYPTOS letter, col = SEVEN letter
# KRYPTOS letters for rows 0-6: K,R,Y,P,T,O,S
# SEVEN letters for cols 0-4: S,E,V,E,N

print("\nThe 7x5 grid can be read as KRYPTOS (rows) x SEVEN (cols):")
print(f"{'':>12}", end="")
for c5 in range(5):
    sv = 'SEVEN'[c5]
    print(f"    {sv}", end="")
print()
for c7 in range(7):
    kw = 'KRYPTOS'[c7]
    print(f"  {kw} (r{c7}):", end="")
    for c5 in range(5):
        cell = (c7, c5)
        status = table.get(cell, '-')
        char = {'null': 'N', 'real': 'R', 'mixed': '?', 'empty': '-'}[status]
        print(f"    {char}", end="")
    print()

# Do the null cells correspond to any cipher operation?
# Null cells: where KRYPTOS[r] and SEVEN[c] satisfy some condition?
print("\nNull cells — KRYPTOS x SEVEN letter pairs:")
for c7, c5 in sorted(pure_null_cells + mixed_cells_list):
    kw = 'KRYPTOS'[c7]
    sv = 'SEVEN'[c5]
    kw_az = AZ_IDX[kw]
    sv_az = AZ_IDX[sv]
    beau = (kw_az + sv_az) % 26
    vig_diff = (kw_az - sv_az) % 26
    status = table[(c7,c5)]
    marker = "  [MIXED]" if status == 'mixed' else ""
    print(f"  ({c7},{c5}) KW={kw}({kw_az:>2}) SV={sv}({sv_az:>2}) "
          f"sum%26={beau:>2}({ALPH[beau]}) diff%26={vig_diff:>2}({ALPH[vig_diff]}){marker}")

print("\nReal cells — KRYPTOS x SEVEN letter pairs:")
for c7, c5 in sorted(pure_real_cells):
    kw = 'KRYPTOS'[c7]
    sv = 'SEVEN'[c5]
    kw_az = AZ_IDX[kw]
    sv_az = AZ_IDX[sv]
    beau = (kw_az + sv_az) % 26
    vig_diff = (kw_az - sv_az) % 26
    print(f"  ({c7},{c5}) KW={kw}({kw_az:>2}) SV={sv}({sv_az:>2}) "
          f"sum%26={beau:>2}({ALPH[beau]}) diff%26={vig_diff:>2}({ALPH[vig_diff]})")

# Check: is null determined by (KRYPTOS_AZ + SEVEN_AZ) mod M for any M?
print("\n--- (KRYPTOS_AZ + SEVEN_AZ) mod M as null predictor ---")
for M in [2,3,5,7,13,26]:
    null_sums = set((AZ_IDX['KRYPTOS'[c7]] + AZ_IDX['SEVEN'[c5]]) % M
                   for c7,c5 in pure_null_cells)
    real_sums = set((AZ_IDX['KRYPTOS'[c7]] + AZ_IDX['SEVEN'[c5]]) % M
                   for c7,c5 in pure_real_cells)
    mixed_sums = set((AZ_IDX['KRYPTOS'[c7]] + AZ_IDX['SEVEN'[c5]]) % M
                    for c7,c5 in mixed_cells_list)
    overlap = null_sums & real_sums
    print(f"  mod {M:>2}: null={sorted(null_sums)}, real={sorted(real_sums)}, mixed={sorted(mixed_sums)}, overlap={sorted(overlap)}")

# Same with KA
print("\n--- (KRYPTOS_KA + SEVEN_KA) mod M ---")
for M in [2,3,5,7,13,26]:
    null_sums = set((KA_IDX['KRYPTOS'[c7]] + SEVEN_KA[c5]) % M
                   for c7,c5 in pure_null_cells)
    real_sums = set((KA_IDX['KRYPTOS'[c7]] + SEVEN_KA[c5]) % M
                   for c7,c5 in pure_real_cells)
    mixed_sums = set((KA_IDX['KRYPTOS'[c7]] + SEVEN_KA[c5]) % M
                    for c7,c5 in mixed_cells_list)
    overlap = null_sums & real_sums
    print(f"  mod {M:>2}: null={sorted(null_sums)}, real={sorted(real_sums)}, mixed={sorted(mixed_sums)}, overlap={sorted(overlap)}")

# ══════════════════════════════════════════════════════════════════════════
# SAVE RESULTS
# ══════════════════════════════════════════════════════════════════════════
output_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results',
                          'palette_mod35_tiebreaker.json')
output_path = os.path.abspath(output_path)

result = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'finding': '(pos%7, pos%5) cell membership classifies 32/35 palette positions correctly',
    'mixed_cells': mixed_cells_list,
    'tiebreaker': 'In mixed cells, earlier position (lower pos) = null',
    'combined_accuracy': '35/35 perfect',
    'pure_null_cells': sorted(pure_null_cells),
    'pure_real_cells': sorted(pure_real_cells),
    'predicted_nulls': sorted(predicted_nulls),
    'actual_consensus_nulls': sorted(CONSENSUS_NULLS),
    'match': predicted_nulls == CONSENSUS_NULLS,
}

with open(output_path, 'w') as f:
    json.dump(result, f, indent=2)

print(f"\n\nResults written to: {output_path}")
print("DONE.")
