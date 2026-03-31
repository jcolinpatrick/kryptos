#!/usr/bin/env python3
"""
e_dmpq_exclusion_rule.py — Investigate the {D,M,P,Q} exclusion rule in
the KA 5-wide grid palette generation mechanism.

The null palette {B,G,I,K,O,W,Z} consists of 7 letters drawn from columns
0 and 3 of the 5-wide KA grid (11 letters total: {K,P,O,B,D,G,I,M,Q,W,Z}).
The 4 EXCLUDED letters are {D,M,P,Q}. This script characterizes the
exclusion pattern through 6 independent tests.

Conventions:
  Positions:    0-indexed
  Alphabet:     A=0, B=1, ..., Z=25 (AZ); KA = KRYPTOSABCDEFGHIJLMNQUVWXZ
  Grid width:   5
  Grid alpha:   KA
  Scope:        CT97

Usage: PYTHONPATH=src python3 -u scripts/analysis/e_dmpq_exclusion_rule.py
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys
import os
import json
import itertools
from datetime import datetime, timezone
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, NULL_PALETTE,
    BEAUFORT_KEYSTREAM_AT_CRIBS, CRIB_POSITIONS, MOD,
)


# ── Build KA grid (5-wide) ──────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
GRID_WIDTH = 5

def ka_grid_pos(letter):
    """Return (row, col) of letter in 5-wide KA grid."""
    idx = KA_IDX[letter]
    return divmod(idx, GRID_WIDTH)


# ── Superset: columns 0 and 3 ───────────────────────────────────────────

SUPERSET = []
SUPERSET_INFO = []
for i, ch in enumerate(KA):
    row, col = divmod(i, GRID_WIDTH)
    if col in (0, 3):
        SUPERSET.append(ch)
        SUPERSET_INFO.append({
            "letter": ch, "ka_idx": i, "row": row, "col": col,
            "col_index": 0 if col == 0 else 1  # index within {col0, col3}
        })

PALETTE = set(NULL_PALETTE)
EXCLUDED = set(SUPERSET) - PALETTE

print("=" * 70)
print("DMPQ EXCLUSION RULE INVESTIGATION")
print("=" * 70)
print(f"\nKA alphabet:  {KA}")
print(f"Grid width:   {GRID_WIDTH}")
print(f"Superset (cols 0,3): {sorted(SUPERSET)} ({len(SUPERSET)} letters)")
print(f"Palette:      {sorted(PALETTE)} ({len(PALETTE)} letters)")
print(f"Excluded:     {sorted(EXCLUDED)} ({len(EXCLUDED)} letters)")
print()

# Print grid
print("5-wide KA grid:")
for row_num in range((len(KA) + GRID_WIDTH - 1) // GRID_WIDTH):
    start = row_num * GRID_WIDTH
    end = min(start + GRID_WIDTH, len(KA))
    cells = []
    for c in range(GRID_WIDTH):
        idx = start + c
        if idx < len(KA):
            ch = KA[idx]
            marker = "*" if ch in PALETTE else ("x" if ch in EXCLUDED else " ")
            cells.append(f"{ch}{marker}")
        else:
            cells.append("  ")
    print(f"  row{row_num}: " + "  ".join(cells))
print("  (* = palette, x = excluded)")
print()


# ══════════════════════════════════════════════════════════════════════════
# TEST 1: Alternation Enumeration
# ══════════════════════════════════════════════════════════════════════════

print("=" * 70)
print("TEST 1: ALTERNATION ENUMERATION")
print("=" * 70)

# Build row membership of superset
rows_with_both = {}  # row -> (col0_letter, col3_letter)
rows_with_one = {}   # row -> (letter, which_col)

for info in SUPERSET_INFO:
    r = info["row"]
    if r not in rows_with_both:
        rows_with_both[r] = [None, None]
    rows_with_both[r][info["col_index"]] = info["letter"]

# Row 5 has only col0 (Z), no col3
row_info = {}
for r in sorted(rows_with_both.keys()):
    pair = rows_with_both[r]
    row_info[r] = {"col0": pair[0], "col3": pair[1]}

print("\nRow membership in superset:")
for r in sorted(row_info.keys()):
    info = row_info[r]
    c0 = info["col0"] or "-"
    c3 = info["col3"] or "-"
    c0_sel = "SEL" if info["col0"] and info["col0"] in PALETTE else ("EXC" if info["col0"] and info["col0"] in EXCLUDED else "---")
    c3_sel = "SEL" if info["col3"] and info["col3"] in PALETTE else ("EXC" if info["col3"] and info["col3"] in EXCLUDED else "---")
    print(f"  Row {r}: col0={c0}({c0_sel})  col3={c3}({c3_sel})")

# Classify the actual pattern
actual_pattern = []
for r in sorted(row_info.keys()):
    info = row_info[r]
    c0_in = info["col0"] in PALETTE if info["col0"] else None
    c3_in = info["col3"] in PALETTE if info["col3"] else None
    if c0_in and c3_in:
        actual_pattern.append("BOTH")
    elif c0_in and not c3_in:
        actual_pattern.append("COL0")
    elif not c0_in and c3_in:
        actual_pattern.append("COL3")
    elif c0_in is None and c3_in:
        actual_pattern.append("COL3_ONLY")
    elif c3_in is None and c0_in:
        actual_pattern.append("COL0_ONLY")
    elif c0_in is None and not c3_in:
        actual_pattern.append("NEITHER_PARTIAL")
    elif not c0_in and c3_in is None:
        actual_pattern.append("NEITHER_PARTIAL")
    else:
        actual_pattern.append("NEITHER")

print(f"\nActual pattern: {actual_pattern}")
print(f"  Row 0: COL0 (K sel, P exc)")
print(f"  Row 1: BOTH (O sel, B sel)")
print(f"  Row 2: COL3 (D exc, G sel)")
print(f"  Row 3: COL0 (I sel, M exc)")
print(f"  Row 4: COL3 (Q exc, W sel)")
print(f"  Row 5: COL0_ONLY (Z sel, no col3)")

# Enumerate all C(11,7) = 330 subsets
all_subsets = list(itertools.combinations(SUPERSET, 7))
print(f"\nTotal C(11,7) = {len(all_subsets)} subsets")

# Classify each subset
def classify_subset(subset):
    """Classify a 7-letter subset's selection pattern."""
    subset_set = set(subset)
    pattern = []
    for r in sorted(row_info.keys()):
        info = row_info[r]
        c0_in = info["col0"] in subset_set if info["col0"] else None
        c3_in = info["col3"] in subset_set if info["col3"] else None
        if c0_in and c3_in:
            pattern.append("BOTH")
        elif c0_in and (c3_in is False):
            pattern.append("COL0")
        elif (c0_in is False) and c3_in:
            pattern.append("COL3")
        elif c0_in and c3_in is None:
            pattern.append("COL0_ONLY")
        elif c3_in and c0_in is None:
            pattern.append("COL3_ONLY")
        elif (c0_in is False) and (c3_in is False):
            pattern.append("NEITHER")
        elif c0_in is None and (c3_in is False):
            pattern.append("NONE_PARTIAL")
        else:
            pattern.append("OTHER")
    return tuple(pattern)

def is_alternating(pattern):
    """Check if a pattern shows alternation between COL0 and COL3.

    Allow at most 1 BOTH row. For non-BOTH rows with both columns,
    check if selection alternates between COL0 and COL3.
    """
    both_count = pattern.count("BOTH")
    if both_count > 1:
        return False

    # Extract the column choices for rows 0-4 (which have both columns)
    choices = []
    for r in range(5):
        p = pattern[r]
        if p == "COL0":
            choices.append(0)
        elif p == "COL3":
            choices.append(1)
        elif p == "BOTH":
            choices.append("B")
        elif p == "NEITHER":
            choices.append("N")
        else:
            choices.append("?")

    # Check alternation: non-BOTH, non-NEITHER entries should alternate
    col_seq = [c for c in choices if c in (0, 1)]
    if len(col_seq) < 2:
        return True  # trivially alternating

    for i in range(1, len(col_seq)):
        if col_seq[i] == col_seq[i-1]:
            return False
    return True

alternating_count = 0
pattern_counts = Counter()
alternating_subsets = []

for subset in all_subsets:
    pat = classify_subset(subset)
    pattern_counts[pat] += 1
    if is_alternating(pat):
        alternating_count += 1
        alternating_subsets.append({"subset": sorted(subset), "pattern": list(pat)})

print(f"\n  Subsets with alternating pattern (<=1 BOTH, col0/col3 alternate): {alternating_count}")
print(f"  Proportion: {alternating_count}/{len(all_subsets)} = {alternating_count/len(all_subsets):.4f}")

# Show the most common patterns
print(f"\n  Top 10 pattern types:")
for pat, count in pattern_counts.most_common(10):
    is_alt = "ALT" if is_alternating(pat) else "   "
    print(f"    {is_alt} {list(pat)}: {count}")

# Check if actual palette's pattern is unique
actual_pat = classify_subset(sorted(PALETTE))
match_count = pattern_counts.get(actual_pat, 0)
print(f"\n  Actual palette pattern: {list(actual_pat)}")
print(f"  Subsets sharing this exact pattern: {match_count}")


# ══════════════════════════════════════════════════════════════════════════
# TEST 2: Parity Model
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("TEST 2: PARITY MODEL")
print("=" * 70)

# For each superset letter, compute various parity features
print("\nSuperset letter features:")
print(f"  {'Letter':>6} {'row':>3} {'col':>3} {'col_idx':>7} {'r+ci':>4} {'r*ci':>4} {'r%2':>3} {'ci%2':>4} {'r+c':>3} {'IN_PAL':>6}")

parity_rules = {
    "(row+col_idx)%2": lambda r, ci, c: (r + ci) % 2,
    "(row*col_idx)%2": lambda r, ci, c: (r * ci) % 2,
    "row%2":           lambda r, ci, c: r % 2,
    "col_idx%2":       lambda r, ci, c: ci % 2,
    "(row+col)%2":     lambda r, ci, c: (r + c) % 2,
    "(row*col)%2":     lambda r, ci, c: (r * c) % 2,
    "row%3":           lambda r, ci, c: r % 3,
    "(row+col_idx)%3": lambda r, ci, c: (r + ci) % 3,
}

for info in SUPERSET_INFO:
    ch = info["letter"]
    r, c, ci = info["row"], info["col"], info["col_index"]
    in_pal = "YES" if ch in PALETTE else "NO"
    print(f"  {ch:>6} {r:>3} {c:>3} {ci:>7} {(r+ci):>4} {(r*ci):>4} {r%2:>3} {ci%2:>4} {(r+c):>3} {in_pal:>6}")

print("\nParity rule accuracy (predicting IN_PALETTE):")
best_rule = None
best_acc = 0
rule_results = {}

for rule_name, rule_fn in parity_rules.items():
    # Try each possible target value
    values = {}
    for info in SUPERSET_INFO:
        ch = info["letter"]
        val = rule_fn(info["row"], info["col_index"], info["col"])
        if val not in values:
            values[val] = {"pal": 0, "exc": 0}
        if ch in PALETTE:
            values[val]["pal"] += 1
        else:
            values[val]["exc"] += 1

    # Best accuracy: for each value, assign to majority class
    correct = sum(max(v["pal"], v["exc"]) for v in values.values())
    total = len(SUPERSET_INFO)
    acc = correct / total

    # Also check: is there a single value that captures all 7 palette letters?
    pal_values = set()
    for info in SUPERSET_INFO:
        ch = info["letter"]
        if ch in PALETTE:
            pal_values.add(rule_fn(info["row"], info["col_index"], info["col"]))

    exc_values = set()
    for info in SUPERSET_INFO:
        ch = info["letter"]
        if ch not in PALETTE:
            exc_values.add(rule_fn(info["row"], info["col_index"], info["col"]))

    overlap = pal_values & exc_values

    rule_results[rule_name] = {
        "accuracy": acc,
        "correct": correct,
        "total": total,
        "value_dist": {str(k): v for k, v in sorted(values.items())},
        "palette_values": sorted(pal_values),
        "excluded_values": sorted(exc_values),
        "overlap": sorted(overlap),
    }

    print(f"  {rule_name:>25}: {correct}/{total} = {acc:.3f}  "
          f"pal_vals={sorted(pal_values)} exc_vals={sorted(exc_values)} overlap={sorted(overlap)}")

    if acc > best_acc:
        best_acc = acc
        best_rule = rule_name

print(f"\n  Best simple parity rule: {best_rule} ({best_acc:.3f})")
print(f"  Note: no single parity/modular rule cleanly separates palette from excluded")


# ══════════════════════════════════════════════════════════════════════════
# TEST 3: Checkerboard and 2D Pattern Selection
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("TEST 3: CHECKERBOARD / 2D PATTERN SELECTION")
print("=" * 70)

# Model as 6x2 grid (rows 0-5, columns = {col0_present, col3_present})
print("\n6x2 grid view (rows 0-5, cols = {col0, col3}):")
grid_6x2 = {}
for info in SUPERSET_INFO:
    r = info["row"]
    ci = info["col_index"]
    grid_6x2[(r, ci)] = info["letter"]

for r in range(6):
    cells = []
    for ci in range(2):
        if (r, ci) in grid_6x2:
            ch = grid_6x2[(r, ci)]
            marker = "#" if ch in PALETTE else "."
            cells.append(f"{ch}{marker}")
        else:
            cells.append("--")
    print(f"  row{r}: {cells[0]}  {cells[1]}")

# Checkerboard: (r+ci)%2 == 0 or 1
print("\nCheckerboard coloring ((r+ci)%2):")
for target in (0, 1):
    selected = []
    for info in SUPERSET_INFO:
        if (info["row"] + info["col_index"]) % 2 == target:
            selected.append(info["letter"])
    pal_match = sum(1 for s in selected if s in PALETTE)
    print(f"  (r+ci)%2 == {target}: {sorted(selected)} -> {pal_match}/{len(selected)} palette match, "
          f"misses {sorted(PALETTE - set(selected))}")

# Diagonal selection: ci == r%2 or ci == (r+1)%2
print("\nDiagonal selection (ci == r%2):")
for offset in range(2):
    selected = []
    for info in SUPERSET_INFO:
        if info["col_index"] == (info["row"] + offset) % 2:
            selected.append(info["letter"])
    pal_match = sum(1 for s in selected if s in PALETTE)
    print(f"  ci == (r+{offset})%2: {sorted(selected)} -> {pal_match}/{len(selected)} palette match")

# Spiral: read the 6x2 grid in spiral order and take first 7
print("\nSpiral order (6x2 grid):")
# For a 6x2 grid, spiral is: top row L->R, right col top->bottom, bottom row R->L, left col bottom->top
spiral_order = []
# Top row
for ci in range(2):
    if (0, ci) in grid_6x2:
        spiral_order.append(grid_6x2[(0, ci)])
# Right column (rows 1-5)
for r in range(1, 6):
    if (r, 1) in grid_6x2:
        spiral_order.append(grid_6x2[(r, 1)])
# Bottom row R->L (already covered by right column since width=2)
# Left column bottom->top (rows 4-1)
for r in range(5, 0, -1):
    if (r, 0) in grid_6x2:
        spiral_order.append(grid_6x2[(r, 0)])
spiral_first_7 = spiral_order[:7]
pal_match = sum(1 for s in spiral_first_7 if s in PALETTE)
print(f"  Spiral order: {spiral_order}")
print(f"  First 7: {spiral_first_7} -> {pal_match}/7 palette match")

# Column-major selection: all of col0 then col3
print("\nColumn-major patterns:")
col0_letters = [info["letter"] for info in SUPERSET_INFO if info["col_index"] == 0]
col3_letters = [info["letter"] for info in SUPERSET_INFO if info["col_index"] == 1]
print(f"  Col0 (6 letters): {col0_letters}")
print(f"  Col3 (5 letters): {col3_letters}")
print(f"  Palette from col0: {[c for c in col0_letters if c in PALETTE]} ({sum(1 for c in col0_letters if c in PALETTE)}/6)")
print(f"  Palette from col3: {[c for c in col3_letters if c in PALETTE]} ({sum(1 for c in col3_letters if c in PALETTE)}/5)")

# Best 2D pattern: brute-force all 2^11 selection masks and find one matching palette
print("\nBrute-force: patterns with exact 7/4 split matching palette:")
patterns_matching = 0
for mask in range(2**11):
    if bin(mask).count("1") != 7:
        continue
    selected = set()
    for i, info in enumerate(SUPERSET_INFO):
        if mask & (1 << i):
            selected.add(info["letter"])
    if selected == PALETTE:
        patterns_matching += 1
print(f"  Exactly 1 mask of C(11,7)=330 produces the palette: {patterns_matching} (sanity check)")


# ══════════════════════════════════════════════════════════════════════════
# TEST 4: Excluded Letters as Meaningful Set
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("TEST 4: EXCLUDED LETTERS {D,M,P,Q} AS MEANINGFUL SET")
print("=" * 70)

excluded_list = sorted(EXCLUDED)
print(f"\nExcluded set: {excluded_list}")

# AZ positions
az_pos = [ALPH_IDX[c] for c in excluded_list]
print(f"AZ indices: {dict(zip(excluded_list, az_pos))}")
print(f"AZ diffs:   {[az_pos[i+1]-az_pos[i] for i in range(len(az_pos)-1)]}")
print(f"AZ sum:     {sum(az_pos)}")

# KA positions
ka_pos = [KA_IDX[c] for c in excluded_list]
print(f"KA indices: {dict(zip(excluded_list, ka_pos))}")
print(f"KA diffs:   {[ka_pos[i+1]-ka_pos[i] for i in range(len(ka_pos)-1)]}")
print(f"KA sum:     {sum(ka_pos)}")

# Sorted by KA index
ka_sorted = sorted(zip(ka_pos, excluded_list))
print(f"KA sorted:  {[(ch, ki) for ki, ch in ka_sorted]}")

# Check if consecutive in any ordering
print(f"\nConsecutive in AZ?  {az_pos == list(range(az_pos[0], az_pos[0]+len(az_pos)))}")
print(f"Consecutive in KA?  {ka_pos == list(range(ka_pos[0], ka_pos[0]+len(ka_pos)))}")

# Check if they form a word or acronym
from itertools import permutations
excluded_perms = [''.join(p) for p in permutations(excluded_list)]
# Check against some common patterns
known_words = {"DMPQ", "QMPD", "PDMQ", "QPDM", "PQDM"}  # unlikely
print(f"\nAll 4! = {len(excluded_perms)} permutations of DMPQ:")
# Check if any permutation is a recognizable English word or abbreviation
# Just list them all since there are only 24
for perm in sorted(excluded_perms):
    print(f"  {perm}", end="")
print()

# Check what they spell in KA order
ka_order = ''.join(ch for _, ch in ka_sorted)
print(f"\nIn KA order: {ka_order}")
az_order = ''.join(ch for ch in sorted(excluded_list))
print(f"In AZ order: {az_order}")

# Check complement properties
palette_az = sorted([ALPH_IDX[c] for c in PALETTE])
excluded_az = sorted(az_pos)
print(f"\nPalette AZ indices: {palette_az}")
print(f"Excluded AZ indices: {excluded_az}")
print(f"Union: {sorted(palette_az + excluded_az)}")
print(f"Superset AZ indices: {sorted([ALPH_IDX[c] for c in SUPERSET])}")

# Check if {D,M,P,Q} has special properties in mod arithmetic
print(f"\nMod properties of excluded AZ indices {excluded_az}:")
for m in range(2, 8):
    residues = [x % m for x in excluded_az]
    print(f"  mod {m}: {residues}  unique: {sorted(set(residues))}")

# Check KA mod properties
ka_excluded = sorted([KA_IDX[c] for c in EXCLUDED])
print(f"\nMod properties of excluded KA indices {ka_excluded}:")
for m in range(2, 8):
    residues = [x % m for x in ka_excluded]
    print(f"  mod {m}: {residues}  unique: {sorted(set(residues))}")

# Row indices of excluded letters
excluded_rows = sorted(set(info["row"] for info in SUPERSET_INFO if info["letter"] in EXCLUDED))
print(f"\nRows containing excluded letters: {excluded_rows}")
print(f"Rows NOT containing excluded letters: {sorted(set(range(6)) - set(excluded_rows))}")


# ══════════════════════════════════════════════════════════════════════════
# TEST 5: Monte Carlo Baseline
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("TEST 5: MONTE CARLO BASELINE")
print("=" * 70)

import random
random.seed(42)

N_MC = 100_000

# Property A: alternating pattern with at most 1 BOTH row
# (already counted: alternating_count out of 330)
alt_pct = alternating_count / len(all_subsets) * 100

# Property B: selected letters include at least one from each row with superset members
rows_with_members = set(info["row"] for info in SUPERSET_INFO)
n_rows = len(rows_with_members)

coverage_count = 0
both_count = 0
for subset in all_subsets:
    subset_set = set(subset)
    covered = set()
    for info in SUPERSET_INFO:
        if info["letter"] in subset_set:
            covered.add(info["row"])
    if covered == rows_with_members:
        coverage_count += 1

    # Check both A and B
    pat = classify_subset(subset)
    if is_alternating(pat) and covered == rows_with_members:
        both_count += 1

print(f"\nAmong C(11,7) = {len(all_subsets)} subsets:")
print(f"  Alternating pattern (<=1 BOTH):    {alternating_count} ({alt_pct:.1f}%)")
print(f"  Full row coverage:                  {coverage_count} ({coverage_count/len(all_subsets)*100:.1f}%)")
print(f"  BOTH properties simultaneously:     {both_count} ({both_count/len(all_subsets)*100:.1f}%)")

# Compare to random 7-letter draws from full 26
mc_alt_count = 0
mc_both_count = 0
mc_all_cols03 = 0

col03_set = set(SUPERSET)

for _ in range(N_MC):
    draw = set(random.sample(ALPH, 7))

    # Check if all 7 are in cols 0,3
    if draw <= col03_set:
        mc_all_cols03 += 1

        # Check alternation and coverage
        pat = classify_subset(sorted(draw))
        if is_alternating(pat):
            mc_alt_count += 1

            # Coverage
            covered = set()
            for info in SUPERSET_INFO:
                if info["letter"] in draw:
                    covered.add(info["row"])
            if covered == rows_with_members:
                mc_both_count += 1

print(f"\nMonte Carlo ({N_MC:,} random 7-from-26 draws):")
print(f"  All 7 in cols 0,3:                  {mc_all_cols03} ({mc_all_cols03/N_MC*100:.4f}%)")
print(f"  + alternating:                      {mc_alt_count} ({mc_alt_count/N_MC*100:.4f}%)")
print(f"  + alternating + full row coverage:  {mc_both_count} ({mc_both_count/N_MC*100:.4f}%)")
print(f"  Expected all_cols03: C(11,7)/C(26,7) = {len(all_subsets)}/{26*25*24*23*22*21*20//(7*6*5*4*3*2*1)} = {len(all_subsets)/657800:.6f}")

# Exact probability
from math import comb
p_in_cols03 = comb(11, 7) / comb(26, 7)
p_alt_given_cols03 = alternating_count / len(all_subsets)
p_both_given_cols03 = both_count / len(all_subsets)
p_joint_alt = p_in_cols03 * p_alt_given_cols03
p_joint_both = p_in_cols03 * p_both_given_cols03

print(f"\n  Exact probabilities:")
print(f"    P(all in cols 0,3) = {p_in_cols03:.6e}")
print(f"    P(alternating | in cols 0,3) = {p_alt_given_cols03:.4f}")
print(f"    P(alt + coverage | in cols 0,3) = {p_both_given_cols03:.4f}")
print(f"    P(in cols 0,3 AND alternating) = {p_joint_alt:.6e}")
print(f"    P(in cols 0,3 AND alt AND coverage) = {p_joint_both:.6e}")


# ══════════════════════════════════════════════════════════════════════════
# TEST 6: Beaufort Key=N Preimage Connection
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("TEST 6: BEAUFORT KEY=N PREIMAGE CONNECTION")
print("=" * 70)

# Under Beaufort KA: C = (K - P) mod 26 in KA indexing
# With key=N (KA index 19): source_letter -> palette_letter
# Verify: for each source letter S, Beaufort_KA(S, key=N) should give palette letter

key_letter = "N"
key_ka_idx = KA_IDX[key_letter]
print(f"\nKey letter: {key_letter} (KA index {key_ka_idx})")

# Beaufort: C_ka = (K_ka - P_ka) mod 26
source_set = set()
mapping = {}
for p_idx in range(26):
    c_idx = (key_ka_idx - p_idx) % 26
    c_letter = KA[c_idx]
    p_letter = KA[p_idx]
    if c_letter in PALETTE:
        source_set.add(p_letter)
        mapping[p_letter] = c_letter

print(f"Source letters that map to palette: {sorted(source_set)}")
print(f"Mapping (source -> palette via Beaufort KA key=N):")
for s in sorted(mapping.keys()):
    print(f"  {s} (KA idx {KA_IDX[s]}) -> {mapping[s]} (KA idx {KA_IDX[mapping[s]]})")

# Check if source contains "SEVEN"
source_str = ''.join(sorted(source_set))
print(f"\nSource set letters: {source_str}")
seven_letters = set("SEVEN")
print(f"Contains SEVEN letters? {seven_letters <= source_set}")
print(f"SEVEN letters: {sorted(seven_letters)}")
print(f"Intersection with source: {sorted(seven_letters & source_set)}")
print(f"Missing from source: {sorted(seven_letters - source_set)}")
print(f"Extra in source: {sorted(source_set - seven_letters)}")

# Grid positions of source letters
print(f"\nSource letter grid positions:")
source_cols = Counter()
for s in sorted(source_set):
    r, c = ka_grid_pos(s)
    source_cols[c] += 1
    print(f"  {s}: row={r}, col={c}, KA_idx={KA_IDX[s]}")

print(f"\nSource column distribution: {dict(source_cols)}")

# Do source letters also show column concentration?
print(f"\nColumn concentration test for source letters:")
for target_col_set in [(0, 3), (1, 4), (0, 2), (1, 3), (2, 4)]:
    in_cols = sum(1 for s in source_set if ka_grid_pos(s)[1] in target_col_set)
    print(f"  Cols {target_col_set}: {in_cols}/{len(source_set)} source letters")

# Does Beaufort mapping preserve grid structure?
print(f"\nGrid structure transformation under Beaufort KA key=N:")
print(f"  {'Source':>8} {'(row,col)':>10} -> {'Palette':>8} {'(row,col)':>10} {'row_diff':>8} {'col_diff':>8}")
for s in sorted(mapping.keys()):
    sr, sc = ka_grid_pos(s)
    pr, pc = ka_grid_pos(mapping[s])
    print(f"  {s:>8} ({sr},{sc}):>10 -> {mapping[s]:>8} ({pr},{pc}):>10 {pr-sr:>8} {pc-sc:>8}")

# Also check: what key letters map {D,M,P,Q} excluded letters to something?
print(f"\nWhat maps EXCLUDED letters {sorted(EXCLUDED)} under Beaufort KA?")
for excl in sorted(EXCLUDED):
    excl_ka = KA_IDX[excl]
    # C = (K - P) mod 26, so P = (K - C) mod 26
    p_idx = (key_ka_idx - excl_ka) % 26
    p_letter = KA[p_idx]
    print(f"  Key=N encrypting ? to {excl}: source = {p_letter} (KA idx {p_idx})")

# What are the source letters for the excluded set?
excl_sources = set()
for excl in EXCLUDED:
    excl_ka = KA_IDX[excl]
    p_idx = (key_ka_idx - excl_ka) % 26
    excl_sources.add(KA[p_idx])
print(f"\nSource letters for EXCLUDED set: {sorted(excl_sources)}")
print(f"Source letters for PALETTE set:  {sorted(source_set)}")
print(f"Union of all sources: {sorted(source_set | excl_sources)}")
print(f"These are all 11 superset preimages: {sorted(source_set | excl_sources) == sorted(ALPH)[:11]}")


# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

summary = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "conventions": {
        "positions": "0-indexed",
        "alphabet_map": "A=0...Z=25",
        "grid_alphabet": "KA = KRYPTOSABCDEFGHIJLMNQUVWXZ",
        "grid_width": 5,
        "scope": "CT97",
    },
    "superset": {
        "letters": sorted(SUPERSET),
        "count": len(SUPERSET),
        "columns": [0, 3],
    },
    "palette": sorted(PALETTE),
    "excluded": sorted(EXCLUDED),
    "test_1_alternation": {
        "total_subsets": len(all_subsets),
        "alternating_subsets": alternating_count,
        "proportion": alternating_count / len(all_subsets),
        "actual_pattern_matches": match_count,
    },
    "test_2_parity": {
        "best_rule": best_rule,
        "best_accuracy": best_acc,
        "verdict": "No simple parity/modular rule cleanly separates palette from excluded",
        "rule_details": rule_results,
    },
    "test_3_checkerboard": {
        "verdict": "No clean 2D pattern (checkerboard, diagonal, spiral) separates palette from excluded",
    },
    "test_4_excluded_meaning": {
        "az_indices": dict(zip(excluded_list, az_pos)),
        "ka_indices": dict(zip(excluded_list, [KA_IDX[c] for c in excluded_list])),
        "az_diffs": [az_pos[i+1]-az_pos[i] for i in range(len(az_pos)-1)],
        "consecutive_az": False,
        "consecutive_ka": False,
    },
    "test_5_monte_carlo": {
        "p_in_cols03": p_in_cols03,
        "p_alternating_given_cols03": p_alt_given_cols03,
        "p_both_given_cols03": p_both_given_cols03,
        "p_joint_alternating": p_joint_alt,
        "p_joint_both": p_joint_both,
    },
    "test_6_beaufort_preimage": {
        "key_letter": key_letter,
        "key_ka_index": key_ka_idx,
        "source_set": sorted(source_set),
        "source_contains_SEVEN": seven_letters <= source_set,
        "source_column_distribution": dict(source_cols),
        "excluded_sources": sorted(excl_sources),
    },
}

print(f"""
Test 1 (Alternation):
  {alternating_count}/{len(all_subsets)} subsets show alternating pattern
  Actual palette pattern has {match_count} matches among all 330 subsets
  VERDICT: The alternation is NOT uniquely constraining within the superset

Test 2 (Parity):
  Best rule: {best_rule} with accuracy {best_acc:.3f}
  VERDICT: No simple parity/modular rule cleanly separates 7 from 4

Test 3 (Checkerboard):
  VERDICT: No clean 2D pattern separates palette from excluded in the 6x2 grid

Test 4 (Excluded as meaningful set):
  {{D,M,P,Q}} AZ indices: {dict(zip(excluded_list, az_pos))}
  AZ diffs: {[az_pos[i+1]-az_pos[i] for i in range(len(az_pos)-1)]}
  Not consecutive in AZ or KA, no obvious word or keyword
  VERDICT: No clear semantic or structural meaning for the excluded set

Test 5 (Monte Carlo):
  P(7 from 26 all in cols 0,3) = {p_in_cols03:.6e}
  P(+ alternating) = {p_joint_alt:.6e}
  P(+ alternating + full row coverage) = {p_joint_both:.6e}
  VERDICT: Column restriction is the dominant signal; alternation adds modest constraint

Test 6 (Beaufort preimage):
  Beaufort KA key=N: {{E,H,N,Q,S,T,V}} -> palette
  Source contains SEVEN: {seven_letters <= source_set}
  Source column distribution: {dict(source_cols)}
  VERDICT: Source letters do NOT show column concentration; grid structure is NOT preserved
""")

# Save results
results_path = os.path.join(_ROOT, "results", "dmpq_exclusion_rule.json")
with open(results_path, "w") as f:
    json.dump(summary, f, indent=2)
print(f"Results saved to: {results_path}")
