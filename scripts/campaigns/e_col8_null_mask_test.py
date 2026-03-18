#!/usr/bin/env python3
"""
Test: Are the 24 positions where grid col%8 in {0,1} the null positions?

Key observation from separator analysis:
- K4 has EXACTLY 24 positions where the grid column mod 8 is 0 or 1
- Among the 35 palette positions, ALL 8 at col%8 in {0,1} are consensus nulls
- 24 is the exact number of nulls needed in the 73-char hypothesis

This script tests whether col%8 in {0,1} defines the full 24-null mask,
and evaluates it against all known cipher configurations.
"""
import sys
import os
import json
from datetime import datetime, timezone
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import (CT, CT_LEN, KRYPTOS_ALPHABET, ALPH,
                                       CRIB_DICT, ALPH_IDX)

PALETTE = frozenset('BGIKOWZ')
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})

def k4_to_grid(pos):
    if pos < 4: return (24, 27 + pos)
    elif pos < 35: return (25, pos - 4)
    elif pos < 66: return (26, pos - 35)
    else: return (27, pos - 66)

# ── Derive the col%8 in {0,1} mask ──────────────────────────────────────────

col8_null_positions = sorted(p for p in range(CT_LEN) if k4_to_grid(p)[1] % 8 in (0, 1))
col8_null_set = frozenset(col8_null_positions)

print("=" * 80)
print("COL%8 IN {0,1} AS NULL MASK TEST")
print("=" * 80)

print(f"\nK4 positions with col%8 in {{0,1}}: {col8_null_positions}")
print(f"Count: {len(col8_null_positions)}")
print(f"Expected: 24 (matches 73-char hypothesis)")

# Check overlap with consensus nulls
overlap = CONSENSUS_NULLS & col8_null_set
consensus_only = CONSENSUS_NULLS - col8_null_set
col8_only = col8_null_set - CONSENSUS_NULLS

print(f"\nOverlap with 17 consensus nulls: {len(overlap)} of 17")
print(f"  Shared: {sorted(overlap)}")
print(f"  Consensus but NOT col8: {sorted(consensus_only)}")
print(f"  Col8 but NOT consensus: {sorted(col8_only)}")

# Show what letters are at the col8 positions
print(f"\nLetters at col%8 in {{0,1}} positions:")
for p in col8_null_positions:
    row, col = k4_to_grid(p)
    in_consensus = p in CONSENSUS_NULLS
    in_crib = p in CRIB_DICT
    pal = CT[p] in PALETTE
    status = []
    if in_consensus: status.append("CONSENSUS_NULL")
    if in_crib: status.append(f"CRIB({CRIB_DICT[p]})")
    if pal: status.append("PALETTE")
    print(f"  pos={p:>2}: CT={CT[p]}, row={row}, col={col:>2}, col%8={col%8}, {' '.join(status)}")

# CRITICAL: Check if any crib positions are in this mask (would invalidate it)
crib_in_mask = [p for p in col8_null_positions if p in CRIB_DICT]
print(f"\n*** CRIB POSITIONS IN MASK: {crib_in_mask} ***")
if crib_in_mask:
    print("  WARNING: Crib positions would be removed as nulls!")
    for p in crib_in_mask:
        print(f"    pos={p}: CT={CT[p]}, crib={CRIB_DICT[p]}")
else:
    print("  OK: No crib positions in mask (mask is crib-consistent)")

# ── Extract 73-char CT ──────────────────────────────────────────────────────

non_null_positions = sorted(p for p in range(CT_LEN) if p not in col8_null_set)
ct73 = ''.join(CT[p] for p in non_null_positions)
print(f"\n73-char CT (after removing col%8 in {{0,1}}): {ct73}")
print(f"Length: {len(ct73)}")

# Where do crib positions fall in the 73-char text?
crib_positions_73 = {}
for old_pos, new_idx in zip(non_null_positions, range(len(non_null_positions))):
    if old_pos in CRIB_DICT:
        crib_positions_73[new_idx] = (old_pos, CRIB_DICT[old_pos])

print(f"\nCrib positions in 73-char text:")
for new_pos, (old_pos, crib_char) in sorted(crib_positions_73.items()):
    print(f"  73-text pos {new_pos}: CT={ct73[new_pos]}, was K4 pos {old_pos}, crib={crib_char}")

# ── Test cipher configurations ──────────────────────────────────────────────

print("\n" + "=" * 80)
print("CIPHER TESTING ON 73-CHAR CT")
print("=" * 80)

# Build mapping from 73-char positions to crib chars
crib_map_73 = {new_pos: crib_char for new_pos, (_, crib_char) in crib_positions_73.items()}

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ = ALPH
AZ_IDX = ALPH_IDX

def derive_keystream(ct_text, pt_positions, alphabet_idx, variant):
    """Derive keystream values at known positions."""
    keys = {}
    for ct_pos, pt_char in pt_positions.items():
        if ct_pos >= len(ct_text):
            continue
        ct_char = ct_text[ct_pos]
        c = alphabet_idx[ct_char]
        p = alphabet_idx[pt_char]
        if variant == 'vig':
            k = (c - p) % 26
        elif variant == 'beau':
            k = (c + p) % 26
        elif variant == 'vbeau':
            k = (p - c) % 26
        keys[ct_pos] = k
    return keys

def check_periodic_consistency(keystream, max_period=26):
    """Check if keystream is consistent with any period."""
    results = {}
    for period in range(1, max_period + 1):
        consistent = True
        residue_vals = {}
        for pos, val in keystream.items():
            r = pos % period
            if r in residue_vals:
                if residue_vals[r] != val:
                    consistent = False
                    break
            else:
                residue_vals[r] = val
        if consistent:
            n_constrained = len(residue_vals)
            n_values = len(set(residue_vals.values()))
            results[period] = (n_constrained, n_values)
    return results

# Test all combos
keywords = ['KRYPTOS', 'DEFECTOR', 'PALIMPSEST', 'ABSCISSA', 'KOMPASS',
            'PARALLAX', 'COLOPHON', 'SHADOW', 'MEDUSA']
alphabets = [('AZ', AZ_IDX), ('KA', KA_IDX)]
variants = ['vig', 'beau', 'vbeau']

print(f"\nTesting periodic consistency of keystream on 73-char CT:")
print(f"{'Keyword':>15} {'Alpha':>4} {'Var':>5} {'Crib#':>6} {'BestPeriod':>11} {'Constrained':>12}")
print("-" * 65)

best_results = []

for keyword in keywords:
    for alpha_name, alpha_idx in alphabets:
        for variant in variants:
            keystream = derive_keystream(ct73, crib_map_73, alpha_idx, variant)

            # Count how many cribs produce valid keys
            n_cribs = len(keystream)

            # Check periodicity
            periodic = check_periodic_consistency(keystream, max_period=26)

            if periodic:
                # Find lowest period with most constraints
                best_period = None
                best_constrained = 0
                for p, (nc, nv) in periodic.items():
                    if nc > best_constrained:
                        best_constrained = nc
                        best_period = p

                best_results.append((keyword, alpha_name, variant, n_cribs,
                                   best_period, best_constrained))

                if best_period and best_period <= 13:
                    print(f"{keyword:>15} {alpha_name:>4} {variant:>5} {n_cribs:>6} {best_period:>11} {best_constrained:>12} ***")
                elif best_period and best_period <= 20:
                    print(f"{keyword:>15} {alpha_name:>4} {variant:>5} {n_cribs:>6} {best_period:>11} {best_constrained:>12}")

# ── Check crib consistency (how many crib positions match) ───────────────────

print(f"\n\nCrib consistency scoring (like score_candidate):")
print(f"{'Keyword':>15} {'Alpha':>4} {'Var':>5} {'Score':>6} {'Details':>40}")
print("-" * 80)

for keyword in keywords:
    for alpha_name, alpha_idx in alphabets:
        for variant in variants:
            keystream = derive_keystream(ct73, crib_map_73, alpha_idx, variant)

            # Score: for each period 1-26, count consistent positions
            best_score = 0
            best_period = 0
            for period in range(1, 27):
                residues = {}
                consistent = 0
                conflict = 0
                for pos, val in keystream.items():
                    r = pos % period
                    if r in residues:
                        if residues[r] == val:
                            consistent += 1
                        else:
                            conflict += 1
                    else:
                        residues[r] = val
                        consistent += 1
                score = consistent
                if score > best_score:
                    best_score = score
                    best_period = period

            if best_score >= 12:
                key_vals = list(keystream.values())
                key_chars = ''.join(chr(v + 65) for v in key_vals[:10])
                print(f"{keyword:>15} {alpha_name:>4} {variant:>5} {best_score:>5}/24 p={best_period:>2} key={key_chars}...")

# ── Also check WITHOUT col7 transposition ────────────────────────────────────

print(f"\n" + "=" * 80)
print("ALSO TESTING: col%8 mask + col7 transposition")
print("=" * 80)

# Col7 transposition on 73-char text
def col7_transpose(text, width=7):
    """Read text into rows of width, then read by columns."""
    n = len(text)
    n_rows = (n + width - 1) // width
    result = []
    for col in range(width):
        for row in range(n_rows):
            idx = row * width + col
            if idx < n:
                result.append(text[idx])
    return ''.join(result)

def col7_untranspose(text, width=7):
    """Inverse of col7_transpose: given column-read text, produce row-read."""
    n = len(text)
    n_rows = (n + width - 1) // width
    n_full_cols = n - (n_rows - 1) * width if n % width != 0 else width
    # n_full_cols columns have n_rows entries, rest have n_rows-1
    # Actually: first (n % width) columns have ceil(n/width) rows, rest have floor
    if n % width == 0:
        col_lengths = [n_rows] * width
    else:
        col_lengths = [n_rows] * (n % width) + [n_rows - 1] * (width - n % width)

    # Read text into columns
    grid = []
    idx = 0
    for c in range(width):
        col_data = text[idx:idx + col_lengths[c]]
        grid.append(col_data)
        idx += col_lengths[c]

    # Read by rows
    result = []
    for r in range(n_rows):
        for c in range(width):
            if r < len(grid[c]):
                result.append(grid[c][r])
    return ''.join(result)

# Apply col7 transpose to 73-char CT, then test
ct73_transposed = col7_transpose(ct73, 7)
ct73_untransposed = col7_untranspose(ct73, 7)

print(f"\n73-char CT: {ct73}")
print(f"After col7 transpose:   {ct73_transposed}")
print(f"After col7 untranspose: {ct73_untransposed}")

# Need to remap crib positions through the transposition
# After col7_untranspose, position mapping:
# Row-read pos -> col-read pos
def col7_mapping(n, width=7):
    """Return mapping: row_pos -> col_pos for col7 transpose."""
    n_rows = (n + width - 1) // width
    if n % width == 0:
        col_lengths = [n_rows] * width
    else:
        col_lengths = [n_rows] * (n % width) + [n_rows - 1] * (width - n % width)

    # col_pos = position in column-read order
    row_to_col = {}
    col_idx = 0
    for c in range(width):
        for r in range(col_lengths[c]):
            row_pos = r * width + c
            row_to_col[row_pos] = col_idx
            col_idx += 1
    return row_to_col

row_to_col = col7_mapping(73, 7)
col_to_row = {v: k for k, v in row_to_col.items()}

# After untranspose, crib positions in row-read:
# If cribs are at positions X in ct73 (row-read), after col7_untranspose they move to col_to_row[X]
# Actually let's think clearly:
# ct73 = row-read extracted text
# col7_transpose(ct73) reads by columns = rearranges
# If the CIPHER operates on the column-read version, then we untranspose:
# col7_untranspose(ct73) = pretend ct73 was written by columns, read by rows

# Test both directions
for label, text in [("73-char direct", ct73),
                    ("73-char col7-transposed", ct73_transposed),
                    ("73-char col7-untransposed", ct73_untransposed)]:
    print(f"\n  {label}:")
    # Use original crib positions for direct, need to remap for transposed
    if "direct" in label:
        crib_test = crib_map_73
    else:
        # For transposed/untransposed, we need to figure out where cribs land
        # This is complex - let's just score all positions for free crib search
        # Check if EASTNORTHEAST or BERLINCLOCK appear as substrings
        ene = "EASTNORTHEAST"
        bcl = "BERLINCLOCK"
        ene_pos = text.find(ene)
        bcl_pos = text.find(bcl)
        print(f"    ENE found at: {ene_pos}")
        print(f"    BCL found at: {bcl_pos}")
        continue

    # Score with cribs
    for keyword in ['KRYPTOS', 'DEFECTOR']:
        for alpha_name, alpha_idx in alphabets:
            for variant in ['vig', 'beau', 'vbeau']:
                keystream = derive_keystream(text, crib_test, alpha_idx, variant)
                for period in range(1, 27):
                    residues = {}
                    score = 0
                    for pos, val in keystream.items():
                        r = pos % period
                        if r in residues:
                            if residues[r] == val:
                                score += 1
                        else:
                            residues[r] = val
                            score += 1
                    if score >= 12:
                        print(f"    {keyword}:{alpha_name}_{variant} p={period}: {score}/24")

# ── Visual comparison: col8 mask vs consensus mask ──────────────────────────

print(f"\n" + "=" * 80)
print("VISUAL: COL%8 MASK vs CONSENSUS MASK")
print("=" * 80)

print("\nK4 positions:")
print("CT:     ", CT)
line1 = ""
line2 = ""
line3 = ""
for p in range(CT_LEN):
    if p in col8_null_set:
        line1 += "N"
    else:
        line1 += "."
    if p in CONSENSUS_NULLS:
        line2 += "N"
    else:
        line2 += "."
    if p in col8_null_set and p in CONSENSUS_NULLS:
        line3 += "="  # both
    elif p in col8_null_set and p not in CONSENSUS_NULLS:
        line3 += "8"  # col8 only
    elif p not in col8_null_set and p in CONSENSUS_NULLS:
        line3 += "C"  # consensus only
    else:
        line3 += "."

print("col8:   ", line1)
print("consens:", line2)
print("overlap:", line3)
print("Legend: = both, 8 = col8 only, C = consensus only, . = neither")

# Count agreement
both = len(col8_null_set & CONSENSUS_NULLS)
col8_extra = len(col8_null_set - CONSENSUS_NULLS)
consensus_extra = len(CONSENSUS_NULLS - col8_null_set)
neither = CT_LEN - len(col8_null_set | CONSENSUS_NULLS)
print(f"\nAgreement: both_null={both}, col8_only={col8_extra}, consensus_only={consensus_extra}, both_non_null={neither}")
print(f"Total agreement (both_null + both_non_null): {both + neither}/97 = {(both+neither)/97:.1%}")

# ── Save results ────────────────────────────────────────────────────────────

output = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'col8_null_positions': col8_null_positions,
    'col8_count': len(col8_null_positions),
    'overlap_with_consensus': sorted(overlap),
    'consensus_only': sorted(consensus_only),
    'col8_only': sorted(col8_only),
    'ct73': ct73,
    'crib_in_mask': crib_in_mask,
    'agreement_rate': (both + neither) / 97,
}

output_path = os.path.abspath(os.path.join(os.path.dirname(__file__),
                              '..', '..', 'results', 'col8_null_mask_test.json'))
with open(output_path, 'w') as f:
    json.dump(output, f, indent=2)
print(f"\nResults written to: {output_path}")
