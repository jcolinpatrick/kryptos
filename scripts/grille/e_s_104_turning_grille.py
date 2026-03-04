#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-104: Turning Grille with Constraint Propagation

A turning grille (Cardan grille) is a physical mask with holes placed over
a grid. The sender writes plaintext through the holes, rotates the mask 90
degrees, writes more, rotates again, etc. After 4 rotations, all cells are
filled with either PT characters or nulls.

For K4 (97 chars), we need a grid with at least 97 cells. A 10×10 grid has
100 cells. Each quarter of the grid has 25 cells (5×5 quarter). Each
quarter-cell can have its hole in one of 4 rotations (or no hole, but
exactly one hole per group of 4 rotationally-related cells).

Search space: 4^25 ≈ 10^15 for a 10×10 grille.

Key insight for constraint propagation:
- We know PT at 24 positions. For each grille, the mapping from writing
  order to grid position is determined. The crib constrains which cells
  must be which writing-order positions.
- This lets us fix many quarter-cell orientations, massively pruning space.

Approach:
  P1: Direct grille (no substitution layer) — PT written through holes
  P2: Grille + Vigenère (grille provides transposition, then Vig sub)
  P3: SA search over grille orientations
  P4: Constraint propagation from cribs

Note: Reading order of grid is row-by-row (standard for Cardan grilles).
"""

import json, os, time, random, math
from collections import Counter

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_FULL = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())

GRID_SIZE = 10
HALF = GRID_SIZE // 2  # 5
N_QUARTER_CELLS = HALF * HALF  # 25
N_CELLS = GRID_SIZE * GRID_SIZE  # 100
N_EXTRA = N_CELLS - N  # 3 cells unused (100 - 97)


def rotate_90(row, col, size=GRID_SIZE):
    """Rotate (row, col) 90 degrees clockwise in a size×size grid."""
    return col, size - 1 - row


def get_rotation_group(row, col, size=GRID_SIZE):
    """Get the 4 positions that are rotationally related."""
    positions = [(row, col)]
    r, c = row, col
    for _ in range(3):
        r, c = rotate_90(r, c, size)
        positions.append((r, c))
    return positions


def build_quarter_cells(size=GRID_SIZE):
    """Build the 25 quarter-cell groups.
    Each group has 4 cells that map to each other under 90° rotation.
    Returns: list of 25 groups, each group = [(r0,c0), (r1,c1), (r2,c2), (r3,c3)]
    """
    half = size // 2
    used = set()
    groups = []
    for r in range(half):
        for c in range(half):
            if (r, c) in used:
                continue
            group = get_rotation_group(r, c, size)
            # Remove duplicates (e.g., center cell in odd-sized grids)
            unique_group = []
            seen = set()
            for pos in group:
                if pos not in seen:
                    unique_group.append(pos)
                    seen.add(pos)
            for pos in unique_group:
                used.add(pos)
            groups.append(unique_group)
    return groups


QUARTER_CELLS = build_quarter_cells()
print(f"Quarter cells: {len(QUARTER_CELLS)} groups")
for i, g in enumerate(QUARTER_CELLS[:3]):
    print(f"  Group {i}: {g}")


def grille_to_perm(orientations):
    """Convert grille orientations to a transposition permutation.

    orientations: list of 25 values (0-3), one per quarter-cell.
    Orientation k means the hole is in rotation k of that cell.

    Returns: permutation list where perm[writing_order] = grid_position (linear index)

    Writing order:
      Rotation 0: write through holes (up to 25 chars)
      Rotation 1: rotate grille 90° CW, write through holes
      Rotation 2: rotate 180°, write through holes
      Rotation 3: rotate 270°, write through holes
    """
    # For each quarter cell i with orientation k:
    #   The hole is at position QUARTER_CELLS[i][k] during rotation 0
    #   During rotation r, the hole is at QUARTER_CELLS[i][(k+r) % 4]
    #   Wait — the grille rotates, so the holes move.
    #   At rotation 0: hole is at QUARTER_CELLS[i][k]
    #   At rotation 1: grille rotated 90° CW → hole moves to QUARTER_CELLS[i][(k+1)%4]
    #   At rotation 2: → QUARTER_CELLS[i][(k+2)%4]
    #   At rotation 3: → QUARTER_CELLS[i][(k+3)%4]

    # So the cell filled at rotation r for quarter cell i is QUARTER_CELLS[i][(orientations[i]+r)%4]
    # This means: writing order = rotation * 25 + quarter_cell_index
    #   → grid position = QUARTER_CELLS[i][(orientations[i]+rotation)%4]
    #   → linear index = row * GRID_SIZE + col

    perm = []  # perm[writing_order] = grid linear index
    for rotation in range(4):
        for i in range(N_QUARTER_CELLS):
            if len(QUARTER_CELLS[i]) < 4:
                continue  # Skip degenerate groups
            pos = QUARTER_CELLS[i][(orientations[i] + rotation) % 4]
            linear_idx = pos[0] * GRID_SIZE + pos[1]
            perm.append(linear_idx)

    # perm should have 100 entries. We only use first 97.
    return perm[:N]


def grid_pos_to_linear(row, col):
    return row * GRID_SIZE + col


def check_grille_cribs(perm):
    """Check how many cribs match under a pure transposition grille.
    Under pure grille: CT is read from grid row-by-row.
    Grid[perm[writing_order]] = PT[writing_order]
    So: CT is the grid read row-by-row. Grid[grid_pos] = CT[grid_pos] (identity reading).

    Actually, let me think about this more carefully.

    Encryption with turning grille:
    1. Place grille on empty 10×10 grid
    2. Write first 25 PT chars through holes (filling those grid cells)
    3. Rotate grille 90° CW, write next 25 PT chars
    4. Repeat for 3rd and 4th rotations
    5. Read grid row-by-row → CT

    So: grid[perm[w]] = PT[w] for writing order w = 0..96
    And: CT[linear_pos] = grid[linear_pos]

    But grid positions are linear indices. So CT[linear_pos] = PT[w] where perm[w] = linear_pos.
    Or equivalently: PT[w] = CT[perm[w]].

    This means: PT = CT composed with perm (reading CT in the writing order).

    For cribs: PT[p] is known at positions p in CPOS.
    So: CT[perm[p]] must equal PT_FULL[p] (as a letter).
    """
    matches = 0
    for p in CPOS:
        if p < len(perm) and perm[p] < N_CELLS:
            grid_idx = perm[p]
            # CT is the grid read row-by-row. CT[grid_idx] = the letter at grid_idx.
            # But CT is only 97 chars — grid has 100 cells. 3 cells are empty.
            if grid_idx < N:
                # Assuming CT fills first 97 cells of the grid (rows 0-9, last row has 7)
                # This mapping might not be exact; depends on how CT maps to grid.
                if CT_N[grid_idx] == PT_FULL[p]:
                    matches += 1
    return matches


def check_grille_with_sub(perm, period=7):
    """Check grille + periodic Vigenère.
    PT[w] = (CT[perm[w]] - key[w % period]) mod 26
    At crib position p: PT_FULL[p] = (CT[perm[p]] - key[p % period]) mod 26
    So: key[p % period] = (CT[perm[p]] - PT_FULL[p]) mod 26
    Check consistency of residue classes.
    """
    residue_vals = {}  # residue → set of required key values
    for p in CPOS:
        if p >= len(perm):
            return 0
        grid_idx = perm[p]
        if grid_idx >= N:
            ct_val = 0  # placeholder for empty cells
        else:
            ct_val = CT_N[grid_idx]
        key_val = (ct_val - PT_FULL[p]) % 26
        r = p % period
        if r in residue_vals:
            if residue_vals[r] != key_val:
                return 0  # Inconsistent
        else:
            residue_vals[r] = key_val
    return len(residue_vals)  # Number of residues determined (max 7)


print("=" * 70)
print("E-S-104: Turning Grille with Constraint Propagation")
print(f"  Grid: {GRID_SIZE}×{GRID_SIZE}, quarter cells: {N_QUARTER_CELLS}")
print(f"  Search space: 4^{N_QUARTER_CELLS} = {4**N_QUARTER_CELLS:.2e}")
print("=" * 70)

t0 = time.time()
results = {}
random.seed(42)


# ── Phase 1: Random sampling (baseline) ──────────────────────────────
print("\n--- P1: Random grille sampling (5M samples) ---")

N_SAMPLES = 5_000_000
p1_best = 0
p1_best_orient = None
p1_hist = Counter()

for trial in range(N_SAMPLES):
    orientations = [random.randint(0, 3) for _ in range(N_QUARTER_CELLS)]
    perm = grille_to_perm(orientations)
    score = check_grille_cribs(perm)
    p1_hist[score] += 1

    if score > p1_best:
        p1_best = score
        p1_best_orient = orientations[:]
        print(f"  Trial {trial}: score={score}/24")

    if trial % 1_000_000 == 0 and trial > 0:
        print(f"    {trial:,} trials, best={p1_best}, {time.time()-t0:.1f}s")

print(f"  P1: best={p1_best}/24 from {N_SAMPLES:,} random samples")
print(f"  Distribution: {dict(sorted(p1_hist.items()))}")
results['P1_random'] = {'best': p1_best, 'n_samples': N_SAMPLES}


# ── Phase 2: SA over grille orientations (pure transposition) ────────
print("\n--- P2: SA over grille orientations ---")

N_SA_RUNS = 20
N_SA_STEPS = 500_000
p2_best = 0
p2_best_orient = None

for run in range(N_SA_RUNS):
    # Initialize
    orientations = [random.randint(0, 3) for _ in range(N_QUARTER_CELLS)]
    perm = grille_to_perm(orientations)
    current_score = check_grille_cribs(perm)

    best_this_run = current_score
    T = 2.0

    for step in range(N_SA_STEPS):
        # Mutate: change one quarter cell's orientation
        idx = random.randint(0, N_QUARTER_CELLS - 1)
        old_orient = orientations[idx]
        new_orient = (old_orient + random.randint(1, 3)) % 4
        orientations[idx] = new_orient

        new_perm = grille_to_perm(orientations)
        new_score = check_grille_cribs(new_perm)

        delta = new_score - current_score
        if delta > 0 or random.random() < math.exp(delta / max(T, 0.01)):
            current_score = new_score
            perm = new_perm
            if current_score > best_this_run:
                best_this_run = current_score
        else:
            orientations[idx] = old_orient

        # Cool
        T *= 0.999995

    if best_this_run > p2_best:
        p2_best = best_this_run
        p2_best_orient = orientations[:]

    print(f"  SA run {run}: best={best_this_run}/24")

print(f"  P2: SA best={p2_best}/24 from {N_SA_RUNS} runs")
results['P2_sa_pure'] = {'best': p2_best}


# ── Phase 3: SA with grille + periodic Vig (p=7) ─────────────────────
print("\n--- P3: SA grille + periodic Vig (p=7) ---")

p3_best = 0
for run in range(N_SA_RUNS):
    orientations = [random.randint(0, 3) for _ in range(N_QUARTER_CELLS)]
    perm = grille_to_perm(orientations)
    current_score = check_grille_with_sub(perm, 7)

    best_this_run = current_score
    T = 2.0

    for step in range(N_SA_STEPS):
        idx = random.randint(0, N_QUARTER_CELLS - 1)
        old_orient = orientations[idx]
        new_orient = (old_orient + random.randint(1, 3)) % 4
        orientations[idx] = new_orient

        new_perm = grille_to_perm(orientations)
        new_score = check_grille_with_sub(new_perm, 7)

        delta = new_score - current_score
        if delta > 0 or random.random() < math.exp(delta / max(T, 0.01)):
            current_score = new_score
            perm = new_perm
            if current_score > best_this_run:
                best_this_run = current_score
        else:
            orientations[idx] = old_orient

        T *= 0.999995

    if best_this_run > p3_best:
        p3_best = best_this_run

    if run % 5 == 0:
        print(f"  SA+Vig run {run}: best_this_run={best_this_run}")

print(f"  P3: SA+Vig best={p3_best}/7 residues consistent")
results['P3_sa_vig'] = {'best': p3_best}


# ── Phase 4: Constraint propagation from cribs ────────────────────────
print("\n--- P4: Constraint propagation ---")

# For each crib position p, PT[p] is known.
# Under grille: PT[p] = CT[perm[p]].
# So perm[p] must be the index where CT has the letter PT_FULL[p].

# Find all grid positions where CT has each required letter:
ct_positions = {}  # letter_num → list of grid linear indices
for idx in range(N):
    letter = CT_N[idx]
    if letter not in ct_positions:
        ct_positions[letter] = []
    ct_positions[letter].append(idx)

# For each crib, the grille must map writing position p to a grid cell
# containing the crib letter.
# writing_pos p → grid_cell perm[p] where CT[perm[p]] == PT_FULL[p]
print(f"  Crib constraints:")
for p in CPOS:
    letter = PT_FULL[p]
    n_candidates = len(ct_positions.get(letter, []))
    print(f"    pos {p} needs '{AZ[letter]}': {n_candidates} candidate grid cells")

# The grille maps writing position p to grid cell determined by:
#   rotation = p // 25
#   quarter_cell = p % 25
#   grid_cell = QUARTER_CELLS[quarter_cell][(orientations[quarter_cell] + rotation) % 4]
# So for writing position p:
#   i = p % 25 (quarter cell index)
#   r = p // 25 (rotation number)
#   grid_cell = QUARTER_CELLS[i][(orientations[i] + r) % 4]
# We need grid_cell (as linear index) to be in ct_positions[PT_FULL[p]]

# This means: for crib position p, quarter cell i = p%25, rotation r = p//25:
#   QUARTER_CELLS[i][(orientations[i] + r) % 4] must be at a grid position
#   whose linear index corresponds to a CT letter == PT_FULL[p]

# This constrains orientations[i].
# For each i, collect constraints from ALL cribs that map to this quarter cell.
# Constraint: (orientations[i] + r) % 4 must be the rotation index k such that
#   QUARTER_CELLS[i][k] has linear index in ct_positions[PT_FULL[p]]

print(f"\n  Propagating constraints...")
constraints_per_qc = {i: set(range(4)) for i in range(N_QUARTER_CELLS)}

n_constrained = 0
for p in CPOS:
    i = p % N_QUARTER_CELLS
    r = p // N_QUARTER_CELLS

    if r >= 4:
        continue  # p >= 100, shouldn't happen for N=97

    required_letter = PT_FULL[p]
    valid_positions = set(ct_positions.get(required_letter, []))

    valid_orientations = set()
    for orient in range(4):
        k = (orient + r) % 4
        if k < len(QUARTER_CELLS[i]):
            pos = QUARTER_CELLS[i][k]
            linear_idx = pos[0] * GRID_SIZE + pos[1]
            if linear_idx in valid_positions:
                valid_orientations.add(orient)

    old_size = len(constraints_per_qc[i])
    constraints_per_qc[i] &= valid_orientations
    new_size = len(constraints_per_qc[i])

    if new_size < old_size:
        n_constrained += 1

    if new_size == 0:
        print(f"    IMPOSSIBLE: quarter cell {i} has no valid orientation for crib pos {p}")

n_impossible = sum(1 for i in range(N_QUARTER_CELLS) if len(constraints_per_qc[i]) == 0)
product = 1
for i in range(N_QUARTER_CELLS):
    product *= len(constraints_per_qc[i])

print(f"  Constrained {n_constrained}/{N_QUARTER_CELLS} quarter cells")
print(f"  Impossible cells: {n_impossible}")
print(f"  Remaining orientations per cell: {[len(constraints_per_qc[i]) for i in range(N_QUARTER_CELLS)]}")
print(f"  Remaining search space: {product:.2e} (was {4**25:.2e})")

results['P4_constraint'] = {
    'impossible': n_impossible,
    'remaining_space': float(product),
    'constrained_cells': n_constrained,
}

# If search space is small enough, enumerate
if product > 0 and product < 10_000_000:
    print(f"\n  Enumerating {product:.0f} candidates...")

    from itertools import product as iproduct

    valid_per_cell = [sorted(constraints_per_qc[i]) for i in range(N_QUARTER_CELLS)]
    p4_best = 0

    for combo in iproduct(*valid_per_cell):
        orientations = list(combo)
        perm = grille_to_perm(orientations)
        score = check_grille_cribs(perm)
        if score > p4_best:
            p4_best = score
            print(f"    score={score}/24")
        if score >= 24:
            pt = [CT_N[perm[w]] if perm[w] < N else 0 for w in range(N)]
            pt_text = ''.join(AZ[x] for x in pt)
            print(f"    BREAKTHROUGH! PT: {pt_text}")

    print(f"  P4 enumeration: best={p4_best}/24")
    results['P4_enumeration'] = {'best': p4_best}
elif product > 0:
    # Sample from constrained space
    print(f"\n  Space too large for enumeration. Sampling 5M from constrained space...")
    valid_per_cell = [sorted(constraints_per_qc[i]) for i in range(N_QUARTER_CELLS)]
    p4_best = 0

    for trial in range(5_000_000):
        orientations = [random.choice(valid_per_cell[i]) if valid_per_cell[i] else 0
                       for i in range(N_QUARTER_CELLS)]
        perm = grille_to_perm(orientations)
        score = check_grille_cribs(perm)
        if score > p4_best:
            p4_best = score
            print(f"    Trial {trial}: score={score}/24")

    print(f"  P4 sampling: best={p4_best}/24 from 5M constrained samples")
    results['P4_constrained_sample'] = {'best': p4_best}


# ── Phase 5: Different grid sizes ────────────────────────────────────
print("\n--- P5: Alternative grid sizes ---")

# Try non-square grids: 7×14 = 98 cells (1 extra)
for grid_rows, grid_cols in [(7, 14), (14, 7)]:
    n_cells = grid_rows * grid_cols
    if n_cells < N:
        print(f"  {grid_rows}×{grid_cols}: too small ({n_cells} < {N})")
        continue

    # For rectangular grilles, rotation doesn't work the same way.
    # Instead, try reading orders: row-by-row, col-by-col, zigzag
    print(f"  {grid_rows}×{grid_cols} ({n_cells} cells):")

    # Row-by-row reading → identity permutation (already tested)
    # Col-by-col reading
    perm_col = []
    for c in range(grid_cols):
        for r in range(grid_rows):
            idx = r * grid_cols + c
            if idx < N:
                perm_col.append(idx)
    if len(perm_col) == N:
        pt = [CT_N[perm_col[w]] for w in range(N)]
        from collections import Counter
        freq = Counter(pt)
        ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))
        crib_matches = sum(1 for p in CPOS if pt[p] == PT_FULL[p])
        print(f"    Col-by-col: IC={ic:.4f}, cribs={crib_matches}/24")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for phase, data in sorted(results.items()):
    print(f"  {phase}: {data}")
print(f"  Total: {total_elapsed:.1f}s")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-104',
    'description': 'Turning grille with constraint propagation',
    'results': {k: str(v) for k, v in results.items()},
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_104_turning_grille.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_104_turning_grille.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_104_turning_grille.py")
