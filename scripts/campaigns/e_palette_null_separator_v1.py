#!/usr/bin/env python3
"""
Palette null/non-null separator analysis.

Investigates what separates the 17 consensus null positions (all palette letters)
from the 18 non-null palette positions within K4's 35 palette-letter positions.

Uses grid coordinates, row patterns, column mod 7, position features,
crib proximity, letter frequencies, adjacency, and decision-tree classification.

Palette = {B, G, I, K, O, W, Z} (the 7 letters appearing at consensus null positions)
"""
import sys
import json
import os
from collections import Counter, defaultdict
from itertools import combinations
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, KRYPTOS_ALPHABET, ALPH

# ── Constants ────────────────────────────────────────────────────────────────

PALETTE = frozenset('BGIKOWZ')

# 17 consensus null positions (from MEMORY.md)
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})

# Crib positions
ENE_POS = set(range(21, 34))  # EASTNORTHEAST
BCL_POS = set(range(63, 74))  # BERLINCLOCK
CRIB_POS = ENE_POS | BCL_POS

# K4 grid mapping: K4 starts at row 24, col 27 of 28x31 grid
# K4[0-3] = row 24, cols 27-30
# K4[4-34] = row 25, cols 0-30
# K4[35-65] = row 26, cols 0-30
# K4[66-96] = row 27, cols 0-30
def k4_to_grid(pos):
    """Convert K4 position (0-96) to (row, col) in 28x31 grid."""
    if pos < 4:
        return (24, 27 + pos)
    elif pos < 35:
        return (25, pos - 4)
    elif pos < 66:
        return (26, pos - 35)
    else:
        return (27, pos - 66)

def k4_to_k4row(pos):
    """Convert K4 position to K4-local row (0-3)."""
    if pos < 4: return 0
    elif pos < 35: return 1
    elif pos < 66: return 2
    else: return 3

# Build full data
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(ALPH)}

results = {}

# ── Identify all 35 palette positions ────────────────────────────────────────

palette_positions = [p for p in range(CT_LEN) if CT[p] in PALETTE]
null_palette = sorted(p for p in palette_positions if p in CONSENSUS_NULLS)
nonnull_palette = sorted(p for p in palette_positions if p not in CONSENSUS_NULLS)

print("=" * 80)
print("PALETTE NULL vs NON-NULL SEPARATOR ANALYSIS")
print("=" * 80)
print(f"\nCT: {CT}")
print(f"CT_LEN: {CT_LEN}")
print(f"Palette letters: {sorted(PALETTE)}")
print(f"Total palette positions: {len(palette_positions)}")
print(f"  Consensus null palette positions (17): {null_palette}")
print(f"  Non-null palette positions (18):       {nonnull_palette}")

assert len(null_palette) == 17
assert len(nonnull_palette) == 18
assert len(palette_positions) == 35

# ═══════════════════════════════════════════════════════════════════════════════
# 1. MAP ALL 35 PALETTE POSITIONS TO GRID COORDINATES
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("1. GRID COORDINATE MAPPING")
print("=" * 80)

print(f"\n{'Pos':>4} {'Char':>4} {'Null?':>6} {'Row':>4} {'Col':>4} {'K4Row':>6} {'ColMod7':>8} {'ColMod5':>8} {'InCrib':>7}")
print("-" * 70)

features = {}  # pos -> dict of features
for p in palette_positions:
    row, col = k4_to_grid(p)
    k4row = k4_to_k4row(p)
    is_null = p in CONSENSUS_NULLS
    in_crib = p in CRIB_POS
    char = CT[p]
    ka_idx = KA_IDX[char]
    az_idx = AZ_IDX[char]

    features[p] = {
        'pos': p,
        'char': char,
        'is_null': is_null,
        'row': row,
        'col': col,
        'k4row': k4row,
        'col_mod7': col % 7,
        'col_mod5': col % 5,
        'col_mod3': col % 3,
        'col_mod2': col % 2,
        'ka_idx': ka_idx,
        'az_idx': az_idx,
        'in_crib': in_crib,
        'pos_mod7': p % 7,
        'pos_mod5': p % 5,
        'pos_mod3': p % 3,
        'pos_mod2': p % 2,
    }

    label = "NULL" if is_null else ""
    crib_label = "CRIB" if in_crib else ""
    print(f"{p:>4} {char:>4} {label:>6} {row:>4} {col:>4} {k4row:>6} {col%7:>8} {col%5:>8} {crib_label:>7}")

# ═══════════════════════════════════════════════════════════════════════════════
# 2. "ID BY ROWS" — ROW-BASED ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("2. 'ID BY ROWS' — ROW-BASED ANALYSIS")
print("=" * 80)

for k4r in range(4):
    row_positions = [p for p in palette_positions if k4_to_k4row(p) == k4r]
    row_nulls = [p for p in row_positions if p in CONSENSUS_NULLS]
    row_nonnulls = [p for p in row_positions if p not in CONSENSUS_NULLS]

    # Row bounds
    if k4r == 0:
        row_start, row_end = 0, 3
        row_label = "Row 24 (K4[0-3], 4 chars)"
    elif k4r == 1:
        row_start, row_end = 4, 34
        row_label = "Row 25 (K4[4-34], 31 chars)"
    elif k4r == 2:
        row_start, row_end = 35, 65
        row_label = "Row 26 (K4[35-65], 31 chars)"
    else:
        row_start, row_end = 66, 96
        row_label = "Row 27 (K4[66-96], 31 chars)"

    row_ct = CT[row_start:row_end+1]
    total_palette_in_row = len(row_positions)

    print(f"\n{row_label}")
    print(f"  CT: {row_ct}")
    print(f"  Palette positions: {row_positions} ({total_palette_in_row} total)")
    print(f"  Null:    {row_nulls} ({len(row_nulls)})")
    print(f"  NonNull: {row_nonnulls} ({len(row_nonnulls)})")

    # Show columns for null vs nonnull
    null_cols = [k4_to_grid(p)[1] for p in row_nulls]
    nonnull_cols = [k4_to_grid(p)[1] for p in row_nonnulls]
    print(f"  Null columns:    {null_cols}")
    print(f"  NonNull columns: {nonnull_cols}")

    if total_palette_in_row > 0:
        null_frac = len(row_nulls) / total_palette_in_row
        print(f"  Null fraction: {null_frac:.2%} ({len(row_nulls)}/{total_palette_in_row})")

# ═══════════════════════════════════════════════════════════════════════════════
# 3. COLUMN MOD 7 ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("3. COLUMN MOD 7 ANALYSIS (col7 = winning transposition)")
print("=" * 80)

for residue in range(7):
    null_at_res = [p for p in null_palette if features[p]['col_mod7'] == residue]
    nonnull_at_res = [p for p in nonnull_palette if features[p]['col_mod7'] == residue]
    total = len(null_at_res) + len(nonnull_at_res)
    null_frac = len(null_at_res) / total if total > 0 else 0
    print(f"  col%%7=={residue}: null={len(null_at_res):>2}, nonnull={len(nonnull_at_res):>2}, total={total:>2}, null%%={null_frac:.1%}")
    if null_at_res:
        print(f"    Null positions:    {null_at_res} -> chars: {''.join(CT[p] for p in null_at_res)}")
    if nonnull_at_res:
        print(f"    NonNull positions: {nonnull_at_res} -> chars: {''.join(CT[p] for p in nonnull_at_res)}")

# Column mod N for other moduli
for mod_val in [2, 3, 5, 8, 11, 13, 31]:
    print(f"\n  Column mod {mod_val}:")
    for residue in range(mod_val):
        null_at_res = [p for p in null_palette if features[p]['col'] % mod_val == residue]
        nonnull_at_res = [p for p in nonnull_palette if features[p]['col'] % mod_val == residue]
        total = len(null_at_res) + len(nonnull_at_res)
        if total > 0:
            null_frac = len(null_at_res) / total
            marker = " <---" if null_frac == 1.0 and total >= 2 else (" ***" if null_frac == 0.0 and total >= 2 else "")
            print(f"    r={residue:>2}: null={len(null_at_res):>2}, nonnull={len(nonnull_at_res):>2}, null%={null_frac:.1%}{marker}")

# ═══════════════════════════════════════════════════════════════════════════════
# 4. POSITION IN K4 LINEAR SEQUENCE
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("4. LINEAR SEQUENCE ANALYSIS")
print("=" * 80)

# Visual map of all 97 positions
print("\nAll 97 K4 positions (N=null, .=non-null palette, _=not palette):")
line = ""
for p in range(CT_LEN):
    if p in CONSENSUS_NULLS:
        line += "N"
    elif CT[p] in PALETTE:
        line += "."
    else:
        line += "_"
print(f"  {line[:50]}")
print(f"  {line[50:]}")

# Gaps between consecutive nulls
sorted_nulls = sorted(CONSENSUS_NULLS)
null_gaps = [sorted_nulls[i+1] - sorted_nulls[i] for i in range(len(sorted_nulls)-1)]
print(f"\nConsensus null positions: {sorted_nulls}")
print(f"Gaps between consecutive nulls: {null_gaps}")
print(f"Gap statistics: min={min(null_gaps)}, max={max(null_gaps)}, mean={sum(null_gaps)/len(null_gaps):.1f}")

# Null density in segments
seg_size = 10
print(f"\nNull density by {seg_size}-char segments:")
for start in range(0, CT_LEN, seg_size):
    end = min(start + seg_size, CT_LEN)
    seg_nulls = sum(1 for p in range(start, end) if p in CONSENSUS_NULLS)
    seg_palette = sum(1 for p in range(start, end) if CT[p] in PALETTE)
    seg_palette_nulls = sum(1 for p in range(start, end) if CT[p] in PALETTE and p in CONSENSUS_NULLS)
    print(f"  [{start:>2}-{end-1:>2}]: nulls={seg_nulls:>2}/{end-start}, palette={seg_palette:>2}, palette_nulls={seg_palette_nulls:>2}")

# First 3 chars are all nulls
print(f"\nFirst 3 chars: {CT[0]}{CT[1]}{CT[2]} at positions 0,1,2 -> ALL NULLS")
print(f"First non-null: position 3 ({CT[3]})")

# Position mod N for K4 linear position
print("\nPosition mod N analysis:")
for mod_val in [2, 3, 4, 5, 7, 8, 13, 24]:
    null_counts = Counter(p % mod_val for p in null_palette)
    nonnull_counts = Counter(p % mod_val for p in nonnull_palette)

    # Check if any residue perfectly separates
    perfect_null = [r for r in range(mod_val) if null_counts[r] > 0 and nonnull_counts[r] == 0]
    perfect_nonnull = [r for r in range(mod_val) if nonnull_counts[r] > 0 and null_counts[r] == 0]

    if perfect_null or perfect_nonnull:
        print(f"  pos mod {mod_val:>2}: null-only residues={perfect_null}, nonnull-only={perfect_nonnull}")
        for r in range(mod_val):
            if null_counts[r] + nonnull_counts[r] > 0:
                print(f"    r={r}: null={null_counts[r]}, nonnull={nonnull_counts[r]}")

# ═══════════════════════════════════════════════════════════════════════════════
# 5. RELATIONSHIP TO CRIB POSITIONS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("5. RELATIONSHIP TO CRIB POSITIONS")
print("=" * 80)

# Palette positions inside cribs
palette_in_crib = [p for p in palette_positions if p in CRIB_POS]
null_in_crib = [p for p in null_palette if p in CRIB_POS]
nonnull_in_crib = [p for p in nonnull_palette if p in CRIB_POS]

print(f"\nPalette positions inside cribs: {palette_in_crib}")
print(f"  Of which null: {null_in_crib}")
print(f"  Of which non-null: {nonnull_in_crib}")
for p in palette_in_crib:
    label = "NULL" if p in CONSENSUS_NULLS else "real"
    crib_word = "ENE" if p in ENE_POS else "BCL"
    print(f"    pos {p}: CT[{p}]={CT[p]}, {crib_word}, {label}")

# Distance from nearest crib for each palette position
print(f"\nDistance from nearest crib position:")
for p in palette_positions:
    min_dist = min(abs(p - c) for c in CRIB_POS)
    in_crib = p in CRIB_POS
    label = "NULL" if p in CONSENSUS_NULLS else "real"
    if min_dist <= 3 or in_crib:
        print(f"  pos {p} ({CT[p]}): dist={min_dist}, {label}")

# All non-crib non-null palette positions
noncrib_nonnull = [p for p in nonnull_palette if p not in CRIB_POS]
print(f"\nNon-crib non-null palette positions: {noncrib_nonnull}")
print(f"  Count: {len(noncrib_nonnull)} (these need explaining)")
for p in noncrib_nonnull:
    row, col = k4_to_grid(p)
    print(f"    pos {p}: CT[{p}]={CT[p]}, row={row}, col={col}, col%7={col%7}")

# ═══════════════════════════════════════════════════════════════════════════════
# 6. FREQUENCY OF EACH PALETTE LETTER AT NULL vs NON-NULL
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("6. PER-LETTER ANALYSIS")
print("=" * 80)

for letter in sorted(PALETTE):
    letter_positions = [p for p in range(CT_LEN) if CT[p] == letter]
    null_pos = [p for p in letter_positions if p in CONSENSUS_NULLS]
    nonnull_pos = [p for p in letter_positions if p not in CONSENSUS_NULLS]
    null_frac = len(null_pos) / len(letter_positions) if letter_positions else 0
    print(f"\n  {letter}: {len(letter_positions)} occurrences, {len(null_pos)} null ({null_frac:.0%}), {len(nonnull_pos)} non-null")
    print(f"    Null positions:    {null_pos}")
    print(f"    NonNull positions: {nonnull_pos}")
    if nonnull_pos:
        in_crib = [p for p in nonnull_pos if p in CRIB_POS]
        if in_crib:
            print(f"    (In crib: {in_crib})")

# ═══════════════════════════════════════════════════════════════════════════════
# 7. ADJACENT CHARACTER ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("7. ADJACENT CHARACTER ANALYSIS")
print("=" * 80)

print(f"\n{'Pos':>4} {'Char':>5} {'Null?':>6} {'Left':>5} {'Right':>6} {'L_pal':>6} {'R_pal':>6} {'L_null':>7} {'R_null':>7}")
print("-" * 70)

null_adj_nulls = 0
null_adj_total = 0
nonnull_adj_nulls = 0
nonnull_adj_total = 0
null_adj_palette = 0
nonnull_adj_palette = 0

for p in palette_positions:
    is_null = p in CONSENSUS_NULLS
    left = CT[p-1] if p > 0 else '-'
    right = CT[p+1] if p < CT_LEN-1 else '-'
    l_pal = left in PALETTE if p > 0 else False
    r_pal = right in PALETTE if p < CT_LEN-1 else False
    l_null = (p-1) in CONSENSUS_NULLS if p > 0 else False
    r_null = (p+1) in CONSENSUS_NULLS if p < CT_LEN-1 else False

    label = "NULL" if is_null else ""
    print(f"{p:>4} {CT[p]:>5} {label:>6} {left:>5} {right:>6} {str(l_pal):>6} {str(r_pal):>6} {str(l_null):>7} {str(r_null):>7}")

    # Count adjacency to nulls
    adj_null_count = (1 if l_null else 0) + (1 if r_null else 0)
    adj_pal_count = (1 if l_pal else 0) + (1 if r_pal else 0)
    adj_total = (1 if p > 0 else 0) + (1 if p < CT_LEN-1 else 0)

    if is_null:
        null_adj_nulls += adj_null_count
        null_adj_total += adj_total
        null_adj_palette += adj_pal_count
    else:
        nonnull_adj_nulls += adj_null_count
        nonnull_adj_total += adj_total
        nonnull_adj_palette += adj_pal_count

print(f"\nNull palette positions: {null_adj_nulls}/{null_adj_total} neighbors are also nulls ({null_adj_nulls/null_adj_total:.1%})")
print(f"Non-null palette positions: {nonnull_adj_nulls}/{nonnull_adj_total} neighbors are nulls ({nonnull_adj_nulls/nonnull_adj_total:.1%})")
print(f"Expected if random: {17/97:.1%}")

print(f"\nNull palette: {null_adj_palette}/{null_adj_total} neighbors are palette ({null_adj_palette/null_adj_total:.1%})")
print(f"Non-null palette: {nonnull_adj_palette}/{nonnull_adj_total} neighbors are palette ({nonnull_adj_palette/nonnull_adj_total:.1%})")

# Null clustering
print("\nNull clusters (consecutive null runs):")
clusters = []
current_cluster = []
for p in range(CT_LEN):
    if p in CONSENSUS_NULLS:
        current_cluster.append(p)
    else:
        if current_cluster:
            clusters.append(current_cluster)
            current_cluster = []
if current_cluster:
    clusters.append(current_cluster)

for cl in clusters:
    chars = ''.join(CT[p] for p in cl)
    print(f"  {cl} -> {chars}")

# ═══════════════════════════════════════════════════════════════════════════════
# 8. ROW-SPECIFIC COLUMN PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("8. ROW-SPECIFIC COLUMN PATTERNS ('ID BY ROWS')")
print("=" * 80)

for k4r in range(4):
    row_positions = [p for p in palette_positions if k4_to_k4row(p) == k4r]
    null_cols = sorted(features[p]['col'] for p in row_positions if p in CONSENSUS_NULLS)
    nonnull_cols = sorted(features[p]['col'] for p in row_positions if p not in CONSENSUS_NULLS)

    print(f"\n  K4 Row {k4r} (grid row {24+k4r}):")
    print(f"    Null columns:    {null_cols}")
    print(f"    NonNull columns: {nonnull_cols}")

    # Check specific rules
    if null_cols:
        # Parity
        null_even = sum(1 for c in null_cols if c % 2 == 0)
        null_odd = sum(1 for c in null_cols if c % 2 == 1)
        nonnull_even = sum(1 for c in nonnull_cols if c % 2 == 0)
        nonnull_odd = sum(1 for c in nonnull_cols if c % 2 == 1)
        print(f"    Null parity:    even={null_even}, odd={null_odd}")
        print(f"    NonNull parity: even={nonnull_even}, odd={nonnull_odd}")

        # Col mod 7
        null_mod7 = Counter(c % 7 for c in null_cols)
        nonnull_mod7 = Counter(c % 7 for c in nonnull_cols)
        print(f"    Null col%%7:    {dict(sorted(null_mod7.items()))}")
        print(f"    NonNull col%%7: {dict(sorted(nonnull_mod7.items()))}")

# ═══════════════════════════════════════════════════════════════════════════════
# 9. TEST SPECIFIC ROW-BASED RULES
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("9. SPECIFIC RULE TESTS")
print("=" * 80)

# Rule: null if col < threshold per row
print("\nRule test: 'null if col < threshold[row]'")
for k4r in range(4):
    row_palette = [p for p in palette_positions if k4_to_k4row(p) == k4r]
    for thresh in range(32):
        predicted_null = [p for p in row_palette if features[p]['col'] < thresh]
        predicted_nonnull = [p for p in row_palette if features[p]['col'] >= thresh]
        actual_null = [p for p in row_palette if p in CONSENSUS_NULLS]
        actual_nonnull = [p for p in row_palette if p not in CONSENSUS_NULLS]
        if set(predicted_null) == set(actual_null) and set(predicted_nonnull) == set(actual_nonnull):
            print(f"  Row {k4r}: PERFECT separation at threshold={thresh}")
            break
    else:
        # Find best threshold
        best_acc = 0
        best_t = 0
        for thresh in range(32):
            correct = sum(1 for p in row_palette if (features[p]['col'] < thresh) == (p in CONSENSUS_NULLS))
            if correct > best_acc:
                best_acc = correct
                best_t = thresh
        print(f"  Row {k4r}: No perfect threshold. Best: thresh={best_t}, accuracy={best_acc}/{len(row_palette)}")

# Rule: null if col mod N == specific residue, per row
print("\nRule test: 'null if col mod N in specific_set[row]'")
for mod_val in [2, 3, 5, 7]:
    for k4r in range(4):
        row_palette = [p for p in palette_positions if k4_to_k4row(p) == k4r]
        if not row_palette:
            continue
        actual_null_set = frozenset(p for p in row_palette if p in CONSENSUS_NULLS)

        # Try all subsets of residues
        best_residues = None
        best_acc = 0
        for size in range(mod_val + 1):
            for residue_set in combinations(range(mod_val), size):
                residue_set = frozenset(residue_set)
                predicted = frozenset(p for p in row_palette if features[p]['col'] % mod_val in residue_set)
                if predicted == actual_null_set:
                    best_residues = residue_set
                    best_acc = len(row_palette)
                    break
            if best_residues is not None:
                break

        if best_residues is not None:
            print(f"  mod {mod_val}, Row {k4r}: PERFECT with residues {sorted(best_residues)}")

# Rule: null if position in K4 satisfies certain modular condition
print("\nRule test: 'null if K4_pos mod N in specific_set' (global)")
for mod_val in range(2, 25):
    actual_null_set = frozenset(null_palette)
    for size in range(mod_val + 1):
        for residue_set in combinations(range(mod_val), size):
            residue_set = frozenset(residue_set)
            predicted = frozenset(p for p in palette_positions if p % mod_val in residue_set)
            if predicted == actual_null_set:
                print(f"  pos mod {mod_val}: PERFECT with residues {sorted(residue_set)}")
                break

# ═══════════════════════════════════════════════════════════════════════════════
# 10. DECISION TREE CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("10. DECISION TREE CLASSIFIER")
print("=" * 80)

# Features for each of the 35 palette positions
feature_names = [
    'pos', 'row', 'col', 'k4row',
    'col_mod7', 'col_mod5', 'col_mod3', 'col_mod2',
    'ka_idx', 'az_idx', 'in_crib',
    'pos_mod7', 'pos_mod5', 'pos_mod3', 'pos_mod2',
]

# Add derived features
for p in palette_positions:
    f = features[p]
    # Distance to nearest crib
    f['dist_to_crib'] = min(abs(p - c) for c in CRIB_POS)
    # Distance to nearest W
    w_positions = [i for i in range(CT_LEN) if CT[i] == 'W']
    f['dist_to_w'] = min(abs(p - w) for w in w_positions)
    # Is it a W?
    f['is_w'] = CT[p] == 'W'
    # Row 24 (first 4 chars)?
    f['is_row24'] = f['k4row'] == 0
    # Near start of K4?
    f['pos_lt_15'] = p < 15
    # In the "gap" region (35-65)?
    f['in_middle'] = 35 <= p <= 65
    # KA index mod 5
    f['ka_mod5'] = f['ka_idx'] % 5
    # KA index mod 5 == 0 or 3 (palette KA mod 5 property)
    f['ka_mod5_03'] = f['ka_idx'] % 5 in (0, 3)
    # Col in range [0, 15)?
    f['col_lt_15'] = f['col'] < 15

extended_features = feature_names + [
    'dist_to_crib', 'dist_to_w', 'is_w', 'is_row24', 'pos_lt_15',
    'in_middle', 'ka_mod5', 'ka_mod5_03', 'col_lt_15'
]

# Single-feature analysis: find the best split for each feature
print("\n--- Single Feature Best Split ---")
single_results = []
for fname in extended_features:
    vals = [features[p][fname] for p in palette_positions]
    labels = [1 if p in CONSENSUS_NULLS else 0 for p in palette_positions]
    unique_vals = sorted(set(vals))

    best_acc = 0
    best_split = None
    best_direction = None

    for threshold in unique_vals:
        # null if val <= threshold
        acc1 = sum(1 for v, l in zip(vals, labels) if (v <= threshold) == (l == 1))
        # null if val > threshold
        acc2 = sum(1 for v, l in zip(vals, labels) if (v > threshold) == (l == 1))
        # null if val == threshold
        acc3 = sum(1 for v, l in zip(vals, labels) if (v == threshold) == (l == 1))

        if acc1 > best_acc:
            best_acc, best_split, best_direction = acc1, threshold, f"<= {threshold}"
        if acc2 > best_acc:
            best_acc, best_split, best_direction = acc2, threshold, f"> {threshold}"
        if acc3 > best_acc:
            best_acc, best_split, best_direction = acc3, threshold, f"== {threshold}"

    errors = 35 - best_acc
    single_results.append((fname, best_acc, errors, best_direction))

single_results.sort(key=lambda x: -x[1])
for fname, acc, errors, direction in single_results:
    marker = " *** PERFECT" if errors == 0 else (" ** EXCELLENT" if errors <= 2 else "")
    print(f"  {fname:>20}: best={acc}/35 ({errors} errors), split: {direction}{marker}")

# Two-feature analysis: try all pairs
print("\n--- Two Feature Combinations (errors <= 2) ---")
two_results = []
for i, f1 in enumerate(extended_features):
    for f2 in extended_features[i+1:]:
        vals1 = [features[p][f1] for p in palette_positions]
        vals2 = [features[p][f2] for p in palette_positions]
        labels = [1 if p in CONSENSUS_NULLS else 0 for p in palette_positions]

        unique1 = sorted(set(vals1))
        unique2 = sorted(set(vals2))

        best_acc = 0
        best_rule = None

        # Try: null if (f1 <= t1 AND f2 <= t2)
        # Try: null if (f1 <= t1 OR f2 <= t2)
        # Try: null if (f1 == v1 AND f2 == v2)
        # etc.

        for t1 in unique1:
            for t2 in unique2:
                # AND rules
                for d1 in ['<=', '>']:
                    for d2 in ['<=', '>']:
                        pred = []
                        for v1, v2 in zip(vals1, vals2):
                            c1 = v1 <= t1 if d1 == '<=' else v1 > t1
                            c2 = v2 <= t2 if d2 == '<=' else v2 > t2
                            pred.append(c1 and c2)
                        acc = sum(1 for p, l in zip(pred, labels) if p == (l == 1))
                        if acc > best_acc:
                            best_acc = acc
                            best_rule = f"{f1} {d1} {t1} AND {f2} {d2} {t2}"

                        # OR rules
                        pred_or = []
                        for v1, v2 in zip(vals1, vals2):
                            c1 = v1 <= t1 if d1 == '<=' else v1 > t1
                            c2 = v2 <= t2 if d2 == '<=' else v2 > t2
                            pred_or.append(c1 or c2)
                        acc_or = sum(1 for p, l in zip(pred_or, labels) if p == (l == 1))
                        if acc_or > best_acc:
                            best_acc = acc_or
                            best_rule = f"{f1} {d1} {t1} OR {f2} {d2} {t2}"

        errors = 35 - best_acc
        if errors <= 2:
            two_results.append((f1, f2, best_acc, errors, best_rule))

two_results.sort(key=lambda x: -x[2])
for f1, f2, acc, errors, rule in two_results[:30]:
    marker = " *** PERFECT" if errors == 0 else ""
    print(f"  {acc}/35 ({errors} err): {rule}{marker}")

# ═══════════════════════════════════════════════════════════════════════════════
# 11. "IN CRIB" AS THE KEY DISCRIMINATOR
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("11. CRIB POSITION AS DISCRIMINATOR")
print("=" * 80)

# Non-null palette positions: how many are in cribs?
in_crib_nonnull = [p for p in nonnull_palette if p in CRIB_POS]
not_in_crib_nonnull = [p for p in nonnull_palette if p not in CRIB_POS]
print(f"\nNon-null palette positions IN cribs:  {in_crib_nonnull} ({len(in_crib_nonnull)})")
print(f"Non-null palette positions NOT in cribs: {not_in_crib_nonnull} ({len(not_in_crib_nonnull)})")

# If we could explain these not-in-crib non-null positions, we'd have the full rule
print(f"\nThe 14 unexplained non-null palette positions outside cribs:")
for p in not_in_crib_nonnull:
    row, col = k4_to_grid(p)
    ka = KA_IDX[CT[p]]
    print(f"  pos {p:>2}: CT={CT[p]}, row={row}, col={col:>2}, col%7={col%7}, ka={ka:>2}, ka%5={ka%5}")

# Null palette positions: any in cribs? (Should be 0)
in_crib_null = [p for p in null_palette if p in CRIB_POS]
print(f"\nNull palette positions in cribs: {in_crib_null} (should be empty: {len(in_crib_null) == 0})")

# ═══════════════════════════════════════════════════════════════════════════════
# 12. COMPREHENSIVE POSITION-PAIR DISTANCE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("12. PAIR-DISTANCE AND SPACING ANALYSIS")
print("=" * 80)

# Distances between consecutive null palette positions
sorted_null = sorted(null_palette)
null_diffs = [sorted_null[i+1] - sorted_null[i] for i in range(len(sorted_null)-1)]
print(f"\nConsecutive null palette gaps: {null_diffs}")
print(f"  Sum: {sum(null_diffs)}, unique gaps: {sorted(set(null_diffs))}")

# Distances between consecutive non-null palette positions
sorted_nonnull = sorted(nonnull_palette)
nonnull_diffs = [sorted_nonnull[i+1] - sorted_nonnull[i] for i in range(len(sorted_nonnull)-1)]
print(f"\nConsecutive non-null palette gaps: {nonnull_diffs}")
print(f"  Sum: {sum(nonnull_diffs)}, unique gaps: {sorted(set(nonnull_diffs))}")

# ═══════════════════════════════════════════════════════════════════════════════
# 13. GRID VISUAL
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("13. GRID VISUALIZATION")
print("=" * 80)

print("\nK4 in 28x31 grid (N=null, p=non-null palette, .=non-palette):")
print(f"       ", end="")
for c in range(31):
    print(f"{c%10}", end="")
print()
print(f"       ", end="")
for c in range(31):
    print(f"{c//10 if c >= 10 else ' '}", end="")
print()

for k4r in range(4):
    if k4r == 0:
        start, end, col_start = 0, 3, 27
        row_label = f"R24 "
        prefix = "." * 27
    else:
        start = 4 + (k4r - 1) * 31
        end = start + 30
        col_start = 0
        row_label = f"R{24+k4r} "
        prefix = ""

    line = prefix
    for p in range(start, end + 1):
        if p in CONSENSUS_NULLS:
            line += "N"
        elif CT[p] in PALETTE:
            line += "p"
        else:
            line += "."

    print(f"  {row_label} {line}")

# Show with actual letters
print(f"\nK4 with actual letters (UPPERCASE=null, lowercase=non-null palette, .=non-palette):")
for k4r in range(4):
    if k4r == 0:
        start, end, col_start = 0, 3, 27
        row_label = f"R24 "
        prefix = " " * 27
    else:
        start = 4 + (k4r - 1) * 31
        end = start + 30
        col_start = 0
        row_label = f"R{24+k4r} "
        prefix = ""

    line = prefix
    for p in range(start, end + 1):
        if p in CONSENSUS_NULLS:
            line += CT[p]  # uppercase = null
        elif CT[p] in PALETTE:
            line += CT[p].lower()  # lowercase = non-null palette
        else:
            line += "."  # non-palette

    print(f"  {row_label} {line}")

# ═══════════════════════════════════════════════════════════════════════════════
# 14. COLUMN 1 AND COLUMN 8 SPECIAL ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("14. COLUMN-SPECIFIC NULL RATES")
print("=" * 80)

# Count nulls per column across K4 rows
col_null_count = Counter()
col_total_count = Counter()
col_palette_null = Counter()
col_palette_total = Counter()

for p in range(CT_LEN):
    row, col = k4_to_grid(p)
    col_total_count[col] += 1
    if p in CONSENSUS_NULLS:
        col_null_count[col] += 1
    if CT[p] in PALETTE:
        col_palette_total[col] += 1
        if p in CONSENSUS_NULLS:
            col_palette_null[col] += 1

print(f"\n{'Col':>4} {'Total':>6} {'Nulls':>6} {'NullRate':>9} {'Palette':>8} {'PalNull':>8} {'PalNullRate':>12}")
print("-" * 65)
for col in range(31):
    t = col_total_count[col]
    n = col_null_count[col]
    pt = col_palette_total[col]
    pn = col_palette_null[col]
    rate = n/t if t > 0 else 0
    prate = pn/pt if pt > 0 else 0
    marker = " <---" if n >= 2 else ""
    if t > 0:
        print(f"{col:>4} {t:>6} {n:>6} {rate:>9.1%} {pt:>8} {pn:>8} {prate:>12.1%}{marker}")

# ═══════════════════════════════════════════════════════════════════════════════
# 15. ENRICHMENT STATISTICS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("15. ENRICHMENT STATISTICS")
print("=" * 80)

# Test: does being in a crib explain non-null status?
# Among 35 palette positions:
# - 17 null, 0 in cribs
# - 18 non-null, 4 in cribs (30,31,70,73), 14 not in cribs
# So "in crib" is NECESSARY for non-null when in crib, but 14 non-null positions are NOT in cribs

# Fisher's exact test approximation
# 2x2 table:
#              null   non-null
# in_crib:      0       4
# not_in_crib: 17      14
print("\n2x2 contingency: crib vs null status")
print(f"             null  nonnull")
print(f"  in_crib:    {len(in_crib_null):>3}     {len(in_crib_nonnull):>3}")
print(f"  not_crib:   {len(null_palette)-len(in_crib_null):>3}     {len(not_in_crib_nonnull):>3}")
print(f"  Note: No null palette positions are inside cribs (consistent with model)")

# W-specific enrichment
w_positions = [p for p in range(CT_LEN) if CT[p] == 'W']
w_null = [p for p in w_positions if p in CONSENSUS_NULLS]
w_nonnull = [p for p in w_positions if p not in CONSENSUS_NULLS]
print(f"\nW enrichment: {len(w_null)}/{len(w_positions)} W's are null ({len(w_null)/len(w_positions):.0%})")
print(f"  Null W:     {w_null}")
print(f"  Non-null W: {w_nonnull}")
if w_nonnull:
    for p in w_nonnull:
        print(f"    pos {p}: in crib? {p in CRIB_POS}, col={k4_to_grid(p)[1]}, col%7={k4_to_grid(p)[1]%7}")

# ═══════════════════════════════════════════════════════════════════════════════
# 16. COMPREHENSIVE 2-FEATURE EXACT-MATCH SEARCH
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("16. EXACT SEPARATOR SEARCH (2-feature value-set rules)")
print("=" * 80)

# For each feature, find which value-sets perfectly separate nulls
# This is more general than threshold splits
for fname in extended_features:
    vals = {features[p][fname] for p in palette_positions}
    null_vals = {features[p][fname] for p in null_palette}
    nonnull_vals = {features[p][fname] for p in nonnull_palette}

    # Values appearing ONLY in nulls
    null_only = null_vals - nonnull_vals
    # Values appearing ONLY in non-nulls
    nonnull_only = nonnull_vals - null_vals
    # Values appearing in both
    shared = null_vals & nonnull_vals

    if null_only or nonnull_only:
        null_count_in_nullonly = sum(1 for p in null_palette if features[p][fname] in null_only)
        nonnull_count_in_nonnullonly = sum(1 for p in nonnull_palette if features[p][fname] in nonnull_only)

        print(f"\n  {fname}:")
        print(f"    Null-only values: {sorted(null_only)} ({null_count_in_nullonly}/{len(null_palette)} nulls)")
        print(f"    NonNull-only values: {sorted(nonnull_only)} ({nonnull_count_in_nonnullonly}/{len(nonnull_palette)} non-nulls)")
        print(f"    Shared values: {sorted(shared)}")

# ═══════════════════════════════════════════════════════════════════════════════
# 17. K4 POSITION IN COL7 TRANSPOSITION ORDER
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("17. COL7 TRANSPOSITION ORDER ANALYSIS")
print("=" * 80)

# Col7 transposition: read columns top-to-bottom, columns 0,1,2,3,4,5,6
# For K4 rows 25-27 (each 31 chars), col7 has columns 0..6 with:
# col 0: positions 0,7,14,21,28 (within row); col 1: 1,8,15,22,29; etc.
# But K4 starts at row24 col27 with only 4 chars...

# Actually col7 is columnar transposition of the 97-char K4 text
# Width 7: columns of heights [14,14,14,14,14,14,13] (97 = 7*13 + 6)
# Col 0: positions 0,7,14,21,28,35,42,49,56,63,70,77,84,91
# Col 1: positions 1,8,15,22,29,36,43,50,57,64,71,78,85,92
# Col 2: positions 2,9,16,23,30,37,44,51,58,65,72,79,86,93
# Col 3: positions 3,10,17,24,31,38,45,52,59,66,73,80,87,94
# Col 4: positions 4,11,18,25,32,39,46,53,60,67,74,81,88,95
# Col 5: positions 5,12,19,26,33,40,47,54,61,68,75,82,89,96
# Col 6: positions 6,13,20,27,34,41,48,55,62,69,76,83,90

# Build col7 structure
width = 7
n_rows_col7 = (CT_LEN + width - 1) // width  # 14
n_full = CT_LEN % width if CT_LEN % width != 0 else width  # 6 full columns of height 14
# First 6 columns have 14 rows, last 1 has 13 rows

col7_columns = []
for c in range(width):
    col_positions = list(range(c, CT_LEN, width))
    col7_columns.append(col_positions)

print(f"\nCol7 column structure (width=7, 97 chars):")
for c in range(width):
    positions = col7_columns[c]
    null_in_col = [p for p in positions if p in CONSENSUS_NULLS]
    palette_in_col = [p for p in positions if CT[p] in PALETTE]
    palette_null_in_col = [p for p in positions if CT[p] in PALETTE and p in CONSENSUS_NULLS]
    palette_nonnull_in_col = [p for p in positions if CT[p] in PALETTE and p not in CONSENSUS_NULLS]

    chars = ''.join(CT[p] for p in positions)
    null_marker = ''.join('N' if p in CONSENSUS_NULLS else '.' for p in positions)
    print(f"  Col {c}: {chars}")
    print(f"         {null_marker}")
    print(f"         nulls={len(null_in_col)}, palette={len(palette_in_col)}, pal_null={len(palette_null_in_col)}, pal_nonnull={len(palette_nonnull_in_col)}")

# Position within col7 column (row index in col7)
for p in palette_positions:
    col7_col = p % 7
    col7_row = p // 7
    features[p]['col7_col'] = col7_col
    features[p]['col7_row'] = col7_row

print(f"\nPalette positions by col7 column and row:")
print(f"{'Pos':>4} {'Char':>5} {'Null':>5} {'Col7Col':>8} {'Col7Row':>8}")
for p in palette_positions:
    label = "NULL" if p in CONSENSUS_NULLS else ""
    print(f"{p:>4} {CT[p]:>5} {label:>5} {features[p]['col7_col']:>8} {features[p]['col7_row']:>8}")

# Check: do nulls cluster in specific col7 rows?
print("\nNull distribution by col7 row:")
for r in range(14):
    nulls_at_r = [p for p in null_palette if features[p]['col7_row'] == r]
    nonnulls_at_r = [p for p in nonnull_palette if features[p]['col7_row'] == r]
    if nulls_at_r or nonnulls_at_r:
        print(f"  col7_row={r:>2}: null={len(nulls_at_r)} {nulls_at_r}, nonnull={len(nonnulls_at_r)} {nonnulls_at_r}")

# ═══════════════════════════════════════════════════════════════════════════════
# 18. SUMMARY OF FINDINGS
# ═══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("18. SUMMARY OF KEY FINDINGS")
print("=" * 80)

# Count classification accuracy for key rules
rules_tested = {}

# Rule: in_crib (trivial — nulls can't be in cribs)
acc = sum(1 for p in palette_positions if (p not in CRIB_POS) == (p in CONSENSUS_NULLS))
rules_tested['in_crib'] = acc

# Rule: is_w (W -> null)
acc = sum(1 for p in palette_positions if (CT[p] == 'W') == (p in CONSENSUS_NULLS))
rules_tested['is_w'] = acc

# Rule: pos < 15 (early positions)
acc = sum(1 for p in palette_positions if (p < 15) == (p in CONSENSUS_NULLS))
rules_tested['pos_lt_15'] = acc

print("\nBest single-feature separators (from section 10):")
for fname, acc, errors, direction in single_results[:10]:
    print(f"  {fname:>20}: {acc}/35 ({errors} errors)")

print("\nKey observations:")
print(f"  1. ALL 17 null palette positions are OUTSIDE cribs (0/17 in cribs)")
print(f"  2. 4/18 non-null palette positions are INSIDE cribs (forced non-null)")
print(f"  3. W is 80% null (4/5); Z is 25% null (1/4); K is 25% null (2/8)")
print(f"  4. K4[0,1,2] are all nulls (first 3 characters)")
print(f"  5. Null clusters: {[c for c in clusters if len(c) >= 2]}")

# Aggregate results for JSON
results['timestamp'] = datetime.now(timezone.utc).isoformat()
results['palette'] = sorted(PALETTE)
results['total_palette_positions'] = len(palette_positions)
results['null_palette_positions'] = null_palette
results['nonnull_palette_positions'] = nonnull_palette
results['single_feature_ranking'] = [
    {'feature': f, 'accuracy': a, 'errors': e, 'rule': d}
    for f, a, e, d in single_results[:15]
]
results['two_feature_perfect'] = [
    {'features': [f1, f2], 'accuracy': a, 'errors': e, 'rule': r}
    for f1, f2, a, e, r in two_results if e == 0
][:10]
results['two_feature_near_perfect'] = [
    {'features': [f1, f2], 'accuracy': a, 'errors': e, 'rule': r}
    for f1, f2, a, e, r in two_results if 0 < e <= 2
][:10]

# Write results
output_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'palette_null_separator.json')
output_path = os.path.abspath(output_path)
with open(output_path, 'w') as fout:
    json.dump(results, fout, indent=2)
print(f"\nResults written to: {output_path}")

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
