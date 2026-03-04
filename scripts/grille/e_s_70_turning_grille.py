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
E-S-70: Constraint-Based Turning Grille Attack

A turning grille (Cardan grille) is a physical device: a square grid with holes.
Place the grille on the grid, write PT through the holes, rotate 90°, repeat
4 times. This fills all grid cells with PT characters in a scrambled order.

Then optionally apply a substitution layer (Vigenère/Beaufort).

For K4 (97 chars), possible grids:
- 10×10 = 100 cells (3 unused)
- 7×14 = 98 cells (1 unused) — but not square, can't rotate 90°

So 10×10 is the natural turning grille size.

The grille divides the 100 cells into 25 "orbits" of 4 cells each (the 4
rotational images of each cell). For each orbit, exactly one cell is open
in each rotation. The assignment of which cell opens in which rotation
determines the reading order.

Search space: 4^25 ≈ 10^15 — too large for exhaustive search.

KEY INNOVATION: Use crib constraints to prune. Each known PT position maps
to a specific orbit and rotation. The 24 crib characters constrain which
orbits must be open in which rotation, massively reducing the search space.

Also test: Model B (turning grille as transposition) + Vigenère substitution.
"""

import json
import math
import os
import sys
import time
import random

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)  # 97
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
CRIB_IDX = {p: IDX[c] for p, c in CRIB_DICT.items()}

print("=" * 70)
print("E-S-70: Constraint-Based Turning Grille Attack")
print("=" * 70)

# ── Build 10×10 turning grille orbits ──────────────────────────────────────
GRID_SIZE = 10
TOTAL_CELLS = GRID_SIZE * GRID_SIZE  # 100
UNUSED = TOTAL_CELLS - N  # 3 unused cells

def rotate_90(r, c, size):
    """Rotate position (r,c) by 90° clockwise in a size×size grid."""
    return (c, size - 1 - r)

# Compute orbits: groups of 4 positions related by 90° rotation
orbits = []
visited = set()
for r in range(GRID_SIZE):
    for c in range(GRID_SIZE):
        if (r, c) not in visited:
            orbit = [(r, c)]
            cr, cc = r, c
            for _ in range(3):
                cr, cc = rotate_90(cr, cc, GRID_SIZE)
                orbit.append((cr, cc))
            # Check for self-rotation (center cells in odd-sized grids)
            orbit_set = set(orbit)
            if len(orbit_set) == 4:
                orbits.append(orbit)
                visited.update(orbit_set)
            elif len(orbit_set) == 2:
                # 180° self-rotation: orbit has 2 unique positions
                orbits.append(list(orbit_set) + list(orbit_set))
                visited.update(orbit_set)
            elif len(orbit_set) == 1:
                # Center cell (only for odd grids): self-rotation
                orbits.append([orbit[0]] * 4)
                visited.update(orbit_set)

print(f"Grid: {GRID_SIZE}×{GRID_SIZE} = {TOTAL_CELLS} cells")
print(f"Orbits: {len(orbits)} (each with 4 rotational positions)")
print(f"Unused cells: {UNUSED}")

# ── Map PT positions to grid cells ────────────────────────────────────────
# The PT is written into the grid through the grille, one rotation at a time.
# In rotation r (0-3), the open cells reveal positions for PT characters.
# The order of writing within each rotation is typically row-major (left-to-right,
# top-to-bottom) through the holes.

# For the grille, we assign each orbit i a rotation value rot[i] ∈ {0,1,2,3}.
# In rotation r, orbit i is "open" if rot[i] == r.
# The open cell in rotation r for orbit i is orbits[i][r].
# Characters are written in the order of the open cells within that rotation
# (sorted by row-major position).

# So the PT reading order is determined by rot[0..24]:
# For rotation 0: all orbits i with rot[i]==0, sorted by row-major position of orbits[i][0]
# For rotation 1: all orbits i with rot[i]==1, sorted by row-major position of orbits[i][1]
# etc.

# The first N (97) characters fill the grid; 3 cells are unused (or filled with nulls).

# After the grille transposition, an optional substitution layer is applied.

def grille_perm(hole_choices):
    """
    Given hole choices for 25 orbits, compute the full 100-cell permutation.
    hole_choices[i] = which of the 4 orbit cells (0-3) has the hole cut.

    In rotation k (0-3), orbit i exposes cell orbits[i][(hole_choices[i]+k) % 4].
    Within each rotation, characters are written in row-major order of exposed cells.

    Returns cells[0..99] where cells[pt_pos] = grid cell index (row-major).
    """
    all_cells = []
    for k in range(4):  # rotation 0,1,2,3
        rotation_cells = []
        for i in range(len(hole_choices)):  # each orbit
            cell = orbits[i][(hole_choices[i] + k) % 4]
            cell_idx = cell[0] * GRID_SIZE + cell[1]
            rotation_cells.append(cell_idx)
        rotation_cells.sort()  # row-major order within this rotation
        all_cells.extend(rotation_cells)

    # all_cells has 100 entries (25 per rotation × 4 rotations)
    return all_cells


def grille_to_ct_perm(rot_assignment):
    """
    Given rotation assignments, return the transposition permutation.
    perm[ct_pos] = pt_pos (gather convention).
    CT is read row-major from the filled grid.
    """
    # Place PT characters into grid cells
    cells = grille_perm(rot_assignment)

    # Grid is read row-major to produce CT (or intermediate before sub)
    # grid[cells[pt_pos]] = PT[pt_pos]
    # CT is read as grid[0], grid[1], ..., grid[99]
    # So CT[cell] = PT[pt_pos] where cells[pt_pos] = cell
    # Or equivalently: perm[cell] = pt_pos (scatter: grid cell → PT position)

    # Build scatter: for each grid cell, which PT position fills it?
    grid_to_pt = [None] * TOTAL_CELLS
    for pt_pos, cell in enumerate(cells):
        if pt_pos < N:
            grid_to_pt[cell] = pt_pos

    # Build gather permutation for CT: CT[j] = PT[perm[j]]
    # where j indexes the used grid cells in row-major order
    perm = []
    for cell in range(TOTAL_CELLS):
        if grid_to_pt[cell] is not None:
            perm.append(grid_to_pt[cell])

    # Handle unused cells: they don't appear in CT
    # But we need exactly N entries. The 3 unused cells are skipped.
    if len(perm) != N:
        return None  # Invalid: wrong number of cells used

    return perm


# ── Phase 1: Monte Carlo with crib checking ──────────────────────────────
print("\n" + "-" * 50)
print("Phase 1: Monte Carlo turning grille (10M random grilles)")
print("-" * 50)

random.seed(42)
best_mc = {'cribs': 0}
configs_mc = 0
t0 = time.time()

for _ in range(10_000_000):
    # Random rotation assignment
    rot = [random.randint(0, 3) for _ in range(25)]

    # Check if we get exactly N used cells
    # (All 25 orbits contribute 1 cell per rotation, 4 rotations → 100 cells total)
    # But we only use 97 → 3 unused. The "unused" cells are the last 3 positions.
    # Actually: the grille fills all 100 cells, but CT only uses 97.
    # The last 3 characters in the reading order are nulls/unused.

    cells = grille_perm(rot)
    # cells has 100 entries (25 per rotation × 4 rotations)
    # PT positions 0-96 map to cells[0]-cells[96]
    # cells[97]-cells[99] are unused

    # Build inverse: grid_cell → PT_position (for cells used by PT)
    cell_to_pt = {}
    for pt_pos in range(N):
        cell = cells[pt_pos]
        if cell in cell_to_pt:
            continue  # Duplicate cell — invalid grille
        cell_to_pt[cell] = pt_pos

    if len(cell_to_pt) < N:
        continue  # Invalid grille (duplicate cells)

    # For the "direct" model: CT is just the grid read row-major
    # grid[cell] = PT[pt_pos] where cell_to_pt[cell] = pt_pos
    # CT reading: for cell 0,1,...,99 (row-major), output PT value at that cell
    # CT[j] = PT[cell_to_pt[j]] where j is the j-th used cell in row-major order

    # Build CT-order permutation
    ct_perm = []
    for cell in range(TOTAL_CELLS):
        if cell in cell_to_pt:
            ct_perm.append(cell_to_pt[cell])
    if len(ct_perm) != N:
        continue

    # Check cribs: PT[ct_perm[j]] should give us PT at position ct_perm[j]
    # Under pure transposition: CT[j] = PT[ct_perm[j]]
    # So for crib at PT position p: we need j such that ct_perm[j] = p
    # Then CT[j] should equal CRIB_DICT[p]

    # Build inv: pt_pos → ct_pos
    inv_ct = [0] * N
    for j, pt_pos in enumerate(ct_perm):
        inv_ct[pt_pos] = j

    # Check cribs (pure transposition, no substitution)
    cribs_pure = 0
    for p, expected in CRIB_DICT.items():
        j = inv_ct[p]
        if CT[j] == expected:
            cribs_pure += 1

    # Check cribs with Vigenère substitution (key unknown — just count fixed points)
    # Under Model B: CT[j] = (PT[ct_perm[j]] + key[j]) % 26
    # For crib: PT[p] at ct_pos j = inv_ct[p]
    # key[j] = (CT_IDX[j] - CRIB_IDX[p]) % 26
    # This is always satisfiable (just defines key). So Model B always gives 24/24.
    # We need additional constraints on the key to filter.

    configs_mc += 1
    if cribs_pure > best_mc['cribs']:
        best_mc = {'cribs': cribs_pure, 'rot': list(rot)}
        if cribs_pure >= 3:
            pass  # Don't print for small values

    if configs_mc % 2_000_000 == 0:
        elapsed = time.time() - t0
        print(f"  {configs_mc/1e6:.0f}M configs, {elapsed:.0f}s, best_pure={best_mc['cribs']}/24")

t1 = time.time()
print(f"  {configs_mc:,} configs, {t1-t0:.1f}s")
print(f"  Best pure transposition: {best_mc['cribs']}/24")

# ── Phase 2: Constraint-based search ──────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 2: Constraint-based turning grille search")
print("-" * 50)
print("  Using crib positions to constrain grille assignments")

# For each crib position p (0-indexed PT position):
# Under the turning grille, PT[p] is placed at grid cell cells[p].
# cells[p] is determined by the rotation assignment.
# PT[p] is the p-th character written, which is in rotation r = p // 25
# (since each rotation has 25 cells, and the first 25 go in rotation 0, etc.)
# Wait, that's not quite right. Each rotation has exactly (number of orbits with that rotation) cells.

# Let me reconsider. The grille has 25 orbits. Each orbit is assigned a rotation (0-3).
# In rotation r, the orbits assigned to r expose their cells. The characters are written
# in row-major order through the exposed cells.

# So the number of characters per rotation varies: if k orbits have rot=r, then rotation r
# handles k characters.

# PT positions 0..k0-1 are in rotation 0
# PT positions k0..k0+k1-1 are in rotation 1
# etc.
# where k0 = #{orbits with rot=0}, k1 = #{orbits with rot=1}, etc.

# Crib position p is in rotation r if sum(k0..k_{r-1}) <= p < sum(k0..k_r)
# Within rotation r, p is the (p - sum(k0..k_{r-1}))-th character,
# placed at the (p - sum(k0..k_{r-1}))-th open cell (sorted row-major).

# To constrain: crib position p requires that the open cell at rank (p - offset_r)
# within rotation r maps to grid cell X. This means specific orbits must be assigned
# to specific rotations.

# This is complex but doable. Let me set up the constraint propagation.

# For now, let me try a focused search: test grilles where the crib positions
# map to reasonable grid cells. The ENE crib at PT positions 21-33 (13 chars)
# and BC crib at 63-73 (11 chars).

# If rotation sizes are 25-25-25-25 (all even), then:
# ENE (pos 21-33) is in rotation 0 (pos 0-24), specifically at ranks 21-24 of rot 0
# and ranks 0-8 of rotation 1.
# BC (pos 63-73) is in rotation 2 (pos 50-74), at ranks 13-23 of rot 2 and rank 0 of rot 3.

# But rotation sizes depend on the assignment. This is circular.

# ALTERNATIVE APPROACH: For pure transposition (Model B with identity substitution),
# CT[j] = PT[perm[j]], so we need CT[j] to match the crib values.
# This means: for each crib position p, grid cell grid_cell[p] must be at CT position j
# where CT[j] = CRIB_DICT[p].

# Under the turning grille, grid_cell[p] is determined by the rotation assignment.
# And j is determined by the row-major reading of the grid (skipping unused cells).

# So the constraint is: the grid cell where PT[p] is placed must be at a row-major
# position j where CT[j] matches the expected crib letter.

# For each crib position p and expected letter, find all CT positions j where CT[j] = expected.
# Then grid_cell[p] must be one of these CT positions.

# This is a CONSTRAINT SATISFACTION PROBLEM.

# For pure transposition, find valid grille assignments.
# Build: for each crib letter, which CT positions have that letter?
ct_positions_for_letter = {}
for j, c in enumerate(CT):
    if c not in ct_positions_for_letter:
        ct_positions_for_letter[c] = []
    ct_positions_for_letter[c].append(j)

print(f"\n  CT letter distribution for crib letters:")
for p in sorted(CRIB_DICT.keys()):
    letter = CRIB_DICT[p]
    positions = ct_positions_for_letter.get(letter, [])
    print(f"    PT[{p}]={letter}: {len(positions)} occurrences in CT at {positions}")

# For pure transposition: the grille must map each crib PT position to a CT position
# with the matching letter. The number of valid mappings for each crib position
# is the number of occurrences of that letter in CT.

# Total constraint power: product of choices
total_choices = 1
for p in sorted(CRIB_DICT.keys()):
    letter = CRIB_DICT[p]
    total_choices *= len(ct_positions_for_letter.get(letter, []))
print(f"\n  Total unconstrained choices: {total_choices:.2e}")
print(f"  (But many are mutually exclusive — real space much smaller)")

# The real question: among 4^25 ≈ 10^15 grilles, how many satisfy ALL 24 crib constraints?
# Expected: (product of letter frequencies)^24 × 10^15 ≈ very small if constraints are tight.

# Let's estimate: each crib position has freq(letter)/97 chance of landing on a matching
# CT position. The geometric mean frequency is about 4/97 ≈ 0.04.
# P(all 24 match) ≈ (0.04)^24 ≈ 10^{-33.5}. With 10^15 grilles: 10^{-18.5}.
# So essentially ZERO valid pure-transposition turning grilles!

# But with a substitution layer (Model B), the constraint is removed — any grille works
# with the right key. We need key-quality constraints.

# Let me estimate for the Vigenère layer:
# Under Model B: key[j] = (CT_IDX[j] - PT_IDX[perm[j]]) % 26
# For each grille, the 24 crib positions determine 24 key values.
# If the key is periodic with small period, many key values at different positions
# must be equal. This filters grilles.

# For period 7: 97/7 ≈ 14 values per residue class. 24 cribs give ~3-4 constraints
# per residue class. Most random grilles will fail.

# But we already proved the key is non-periodic! So periodic key filtering won't work.

# What CAN we use to filter?
# 1. Key quadgram quality (if key is English text)
# 2. Key character frequency (should match English if running key)
# 3. PT quality at non-crib positions

# For the MC approach: generate random grilles, derive key at 24 positions,
# score key for English-ness. But we showed in E-S-65 that bigram z=2.80 is not
# significant for width-7 columnar. The same would apply here.

# Let me instead try the pure-transposition MC to see if we can find any grille
# where ALL crib letters match (score 24/24 without substitution).

print("\n" + "-" * 50)
print("Phase 3: Pure transposition MC (looking for 24/24 without sub)")
print("-" * 50)

# This should find ~0 grilles (estimated 10^{-18.5} expected).
# But let's confirm.

random.seed(123)
best_pure = {'cribs': 0}
configs_pure = 0
t2 = time.time()

for _ in range(20_000_000):
    rot = [random.randint(0, 3) for _ in range(25)]
    cells = grille_perm(rot)

    # Check for valid (no duplicate cells in first 97)
    used = set()
    valid = True
    for i in range(N):
        if cells[i] in used:
            valid = False
            break
        used.add(cells[i])
    if not valid:
        continue

    # Build inv: pt_pos → grid_cell
    # CT reading: row-major, skipping unused cells
    # grid_cell_to_ct_pos: which ct position does each grid cell get?
    grid_cells_used = set(cells[:N])
    cell_to_ct_pos = {}
    ct_pos = 0
    for gc in range(TOTAL_CELLS):
        if gc in grid_cells_used:
            cell_to_ct_pos[gc] = ct_pos
            ct_pos += 1

    # For each crib position p: grid cell = cells[p], ct_pos = cell_to_ct_pos[cells[p]]
    cribs = 0
    for p, expected in CRIB_DICT.items():
        gc = cells[p]
        j = cell_to_ct_pos[gc]
        if CT[j] == expected:
            cribs += 1

    configs_pure += 1
    if cribs > best_pure['cribs']:
        best_pure = {'cribs': cribs, 'rot': list(rot)}

    if configs_pure % 5_000_000 == 0:
        elapsed = time.time() - t2
        print(f"  {configs_pure/1e6:.0f}M configs, {elapsed:.0f}s, best={best_pure['cribs']}/24")

t3 = time.time()
print(f"  {configs_pure:,} configs, {t3-t2:.1f}s")
print(f"  Best pure transposition: {best_pure['cribs']}/24")
expected_random = sum(len(ct_positions_for_letter.get(CRIB_DICT[p], [])) / N
                      for p in CRIB_DICT) / len(CRIB_DICT) * 24
print(f"  Expected random: ~{expected_random:.1f}/24")

# ── Phase 4: Model B (grille + Vigenère) with key quality scoring ─────────
print("\n" + "-" * 50)
print("Phase 4: Model B (grille + Vig/Beau) with key bigram scoring")
print("-" * 50)

# Load bigram scores
with open("data/english_quadgrams.json") as f:
    qg_data = json.load(f)
if isinstance(qg_data, dict) and "logp" in qg_data:
    qg_data = qg_data["logp"]

# Derive bigrams from quadgrams
bigram_logp = {}
for qg, logp in qg_data.items():
    if len(qg) == 4:
        bg = qg[:2]
        if bg not in bigram_logp:
            bigram_logp[bg] = []
        bigram_logp[bg].append(logp)

bg_scores = {}
for bg, logps in bigram_logp.items():
    max_lp = max(logps)
    lse = max_lp + math.log(sum(math.exp(lp - max_lp) for lp in logps))
    bg_scores[bg] = lse
bg_floor = min(bg_scores.values()) - 2.0

random.seed(456)
best_model_b = {'score': -999}
configs_mb = 0
t4 = time.time()

for _ in range(5_000_000):
    rot = [random.randint(0, 3) for _ in range(25)]
    cells = grille_perm(rot)

    used = set()
    valid = True
    for i in range(N):
        if cells[i] in used:
            valid = False
            break
        used.add(cells[i])
    if not valid:
        continue

    grid_cells_used = set(cells[:N])
    cell_to_ct_pos = {}
    ct_pos = 0
    for gc in range(TOTAL_CELLS):
        if gc in grid_cells_used:
            cell_to_ct_pos[gc] = ct_pos
            ct_pos += 1

    # For each variant, compute key at crib positions and score bigrams
    for var_sign in (1, -1):
        # Derive key at crib positions
        key_vals = {}  # ct_pos → key_value
        for p, expected in CRIB_DICT.items():
            gc = cells[p]
            j = cell_to_ct_pos[gc]
            pt_v = IDX[expected]
            ct_v = CT_IDX[j]
            kv = (ct_v - var_sign * pt_v) % 26
            key_vals[j] = kv

        # Score consecutive key positions (bigrams in key)
        sorted_ct_positions = sorted(key_vals.keys())
        bg_score = 0.0
        bg_count = 0
        for idx in range(len(sorted_ct_positions) - 1):
            j1, j2 = sorted_ct_positions[idx], sorted_ct_positions[idx + 1]
            if j2 == j1 + 1:  # Consecutive CT positions
                bg = AZ[key_vals[j1]] + AZ[key_vals[j2]]
                bg_score += bg_scores.get(bg, bg_floor)
                bg_count += 1

        configs_mb += 1
        if bg_count > 0 and bg_score / bg_count > best_model_b.get('avg_score', -999):
            vname = 'vig' if var_sign == 1 else 'beau'
            best_model_b = {
                'score': bg_score,
                'avg_score': bg_score / bg_count if bg_count > 0 else -999,
                'bg_count': bg_count,
                'variant': vname,
                'rot': list(rot),
            }

    if configs_mb % 2_000_000 == 0:
        elapsed = time.time() - t4
        print(f"  {configs_mb/1e6:.0f}M configs, {elapsed:.0f}s, best avg_bg={best_model_b.get('avg_score', -999):.3f}")

t5 = time.time()
print(f"  {configs_mb:,} configs, {t5-t4:.1f}s")
print(f"  Best Model B: {best_model_b}")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1+3 (pure transposition MC): best {best_pure['cribs']}/24")
print(f"  Phase 4 (Model B + key bigram): best avg_bg={best_model_b.get('avg_score', -999):.3f}")

max_pure = best_pure['cribs']
if max_pure >= 18:
    verdict = f"SIGNAL — {max_pure}/24 pure transposition"
elif max_pure >= 10:
    verdict = f"WEAK SIGNAL — {max_pure}/24"
else:
    verdict = f"NO SIGNAL — best {max_pure}/24 (random level)"

print(f"\n  Verdict: {verdict}")
print(f"  10×10 turning grille space: 4^25 ≈ 10^15")
print(f"  MC coverage: {configs_pure + configs_mc:.0e} / 10^15 ≈ {(configs_pure + configs_mc)/1e15:.1e}")

output = {
    'experiment': 'E-S-70',
    'description': 'Constraint-based turning grille attack',
    'best_pure': {'cribs': best_pure['cribs'], 'rot': best_pure.get('rot', [])},
    'best_model_b': best_model_b,
    'mc_coverage': (configs_pure + configs_mc) / 1e15,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_70_turning_grille.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_70_turning_grille.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_70_turning_grille.py")
