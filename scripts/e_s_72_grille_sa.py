#!/usr/bin/env python3
"""
E-S-72: Turning Grille SA Attack

E-S-70 found 9/24 pure transposition matches in 30M random grilles
(vs ~1/24 expected). This experiment uses Simulated Annealing to
systematically explore the 4^25 turning grille space.

Under pure transposition: CT[j] = PT[perm[j]], where perm is determined
by the grille. For this to work, CT[j] must equal the crib character
at PT position perm[j] — which is a VERY strong constraint since
most CT characters don't match most crib characters.

SA neighborhood: flip one orbit's rotation assignment.
Score: number of crib positions that match under pure transposition.

Also tests Model B (grille + periodic Vigenère) by checking if the
derived key at crib positions is consistent with a periodic key.
"""

import json
import math
import os
import random
import sys
import time

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
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
CRIB_POS = sorted(CRIB_DICT.keys())

GRID_SIZE = 10
TOTAL_CELLS = 100

print("=" * 70)
print("E-S-72: Turning Grille SA Attack (10×10)")
print("=" * 70)

# Build orbits
def rotate_90(r, c, size=10):
    return (c, size - 1 - r)

orbits = []
visited = set()
for r in range(GRID_SIZE):
    for c in range(GRID_SIZE):
        if (r, c) not in visited:
            orbit = [(r, c)]
            cr, cc = r, c
            for _ in range(3):
                cr, cc = rotate_90(cr, cc)
                orbit.append((cr, cc))
            orbit_set = set(orbit)
            if len(orbit_set) == 4:
                orbits.append(orbit)
                visited.update(orbit_set)

N_ORBITS = len(orbits)
print(f"Orbits: {N_ORBITS}")

# Convert orbits to cell indices for speed
orbit_cells = []  # orbit_cells[i][j] = cell_idx for orbit i, rotation j
for orbit in orbits:
    orbit_cells.append([r * GRID_SIZE + c for r, c in orbit])

def build_perm(holes):
    """Build the reading order permutation from hole choices.
    Returns (cells, inv): cells[pt_pos] = cell_idx, inv[cell_idx] = pt_pos"""
    all_cells = []
    for k in range(4):
        rotation_cells = []
        for i in range(N_ORBITS):
            cell = orbit_cells[i][(holes[i] + k) % 4]
            rotation_cells.append(cell)
        rotation_cells.sort()
        all_cells.extend(rotation_cells)

    # Build inverse: cell_idx → position in all_cells
    inv = {}
    for pos, cell in enumerate(all_cells):
        inv[cell] = pos
    return all_cells, inv

def score_pure_transposition(holes):
    """Score: number of crib matches under pure transposition."""
    cells, inv = build_perm(holes)

    # For pure transposition: CT is read from grid row-major
    # grid[cells[pt_pos]] = PT[pt_pos]
    # CT[j] = grid[j] where j = cell index in row-major order
    # But CT has only 97 chars while grid has 100 cells
    # We skip 3 cells (the unused ones) when reading CT

    # Build the row-major reading: for each cell 0..99 in order,
    # if that cell is in the used set (first 97 positions), it's part of CT
    used_cells = set(cells[:N])
    ct_pos = 0
    cell_to_ct = {}
    for cell in range(TOTAL_CELLS):
        if cell in used_cells:
            cell_to_ct[cell] = ct_pos
            ct_pos += 1

    # For each crib position p:
    # PT[p] is written at grid cell cells[p]
    # When reading row-major, cells[p] becomes CT position cell_to_ct[cells[p]]
    # So CT[cell_to_ct[cells[p]]] should equal CRIB_DICT[p]
    score = 0
    for p in CRIB_POS:
        grid_cell = cells[p]
        j = cell_to_ct.get(grid_cell, -1)
        if j >= 0 and j < N and CT[j] == CRIB_DICT[p]:
            score += 1
    return score

# ── SA for pure transposition ─────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 1: SA for pure transposition (24 targets)")
print("-" * 50)

best_overall = {'score': 0}
NUM_RESTARTS = 200
SA_ITERS = 100000

t0 = time.time()
for restart in range(NUM_RESTARTS):
    # Random initial state
    holes = [random.randint(0, 3) for _ in range(N_ORBITS)]
    current_score = score_pure_transposition(holes)

    best_local = current_score
    best_holes_local = list(holes)

    T = 5.0
    T_min = 0.01
    alpha = (T_min / T) ** (1.0 / SA_ITERS)

    for step in range(SA_ITERS):
        # Flip one orbit's rotation
        orbit = random.randint(0, N_ORBITS - 1)
        old_rot = holes[orbit]
        new_rot = (old_rot + random.randint(1, 3)) % 4
        holes[orbit] = new_rot

        new_score = score_pure_transposition(holes)
        delta = new_score - current_score

        if delta > 0 or random.random() < math.exp(delta / T):
            current_score = new_score
            if current_score > best_local:
                best_local = current_score
                best_holes_local = list(holes)
        else:
            holes[orbit] = old_rot

        T *= alpha

    if best_local > best_overall['score']:
        best_overall = {'score': best_local, 'holes': best_holes_local}
        print(f"  Restart {restart}: new best = {best_local}/24")

    if restart % 50 == 49:
        elapsed = time.time() - t0
        print(f"  Restart {restart+1}/{NUM_RESTARTS}, {elapsed:.0f}s, best={best_overall['score']}/24")

t1 = time.time()
print(f"\n  {NUM_RESTARTS} restarts × {SA_ITERS} steps, {t1-t0:.1f}s")
print(f"  Best pure transposition: {best_overall['score']}/24")

if best_overall['score'] >= 10:
    # Print the plaintext
    cells, inv = build_perm(best_overall['holes'])
    used_cells = set(cells[:N])
    ct_pos = 0
    cell_to_ct = {}
    for cell in range(TOTAL_CELLS):
        if cell in used_cells:
            cell_to_ct[cell] = ct_pos
            ct_pos += 1

    # Reverse: for each CT position j, find which PT position maps there
    ct_to_pt = {}
    for p in range(N):
        gc = cells[p]
        j = cell_to_ct.get(gc, -1)
        if j >= 0:
            ct_to_pt[j] = p

    # Build PT
    pt = ['?'] * N
    for j in range(N):
        if j in ct_to_pt:
            pt_pos = ct_to_pt[j]
            pt[pt_pos] = CT[j]
    print(f"  PT: {''.join(pt)}")

# ── Phase 2: SA for Model B (grille + Vig) scoring quadgrams ──────────────
print("\n" + "-" * 50)
print("Phase 2: SA for Model B (grille + Vig/Beau) scoring PT quadgrams")
print("-" * 50)

# Load quadgrams
with open("data/english_quadgrams.json") as f:
    qg_data = json.load(f)
if isinstance(qg_data, dict) and "logp" in qg_data:
    qg_data = qg_data["logp"]

QG_TABLE = [0.0] * (26**4)
QG_FLOOR = -15.0
for qg, logp in qg_data.items():
    if len(qg) == 4:
        a, b, c, d = [IDX[ch] for ch in qg]
        QG_TABLE[a*17576 + b*676 + c*26 + d] = logp
# Set floor for unseen quadgrams
for i in range(len(QG_TABLE)):
    if QG_TABLE[i] == 0.0:
        QG_TABLE[i] = QG_FLOOR

def score_model_b(holes, variant_sign=1):
    """Score Model B: grille transposition + Vigenère/Beaufort.
    Derive key from crib constraints, decrypt non-crib positions assuming
    periodic key, score PT quadgrams.
    Returns (qg_score, cribs_at_period_7)
    """
    cells, _ = build_perm(holes)
    used_cells = set(cells[:N])

    # Map grid cells to CT positions
    ct_pos = 0
    cell_to_ct = {}
    for cell in range(TOTAL_CELLS):
        if cell in used_cells:
            cell_to_ct[cell] = ct_pos
            ct_pos += 1

    # For each crib position p, derive key at CT position j = cell_to_ct[cells[p]]
    key_at_ct = {}
    for p in CRIB_POS:
        gc = cells[p]
        j = cell_to_ct.get(gc, -1)
        if j < 0 or j >= N:
            continue
        pt_v = CRIB_IDX[p]
        ct_v = CT_IDX[j]
        kv = (ct_v - variant_sign * pt_v) % 26
        key_at_ct[j] = kv

    # Try period 7: check consistency of key values at same residue
    period = 7
    residue_vals = {}
    cribs_p7 = 0
    consistent_p7 = True
    for j, kv in key_at_ct.items():
        r = j % period
        if r in residue_vals:
            if residue_vals[r] == kv:
                cribs_p7 += 1
            else:
                consistent_p7 = False
        else:
            residue_vals[r] = kv
            cribs_p7 += 1

    if not consistent_p7:
        return QG_FLOOR * 24, 0  # Bad period-7 consistency

    # Decrypt all PT using period-7 key
    pt_vals = [0] * N
    for j in range(N):
        r = j % period
        if r in residue_vals:
            kv = residue_vals[r]
        else:
            kv = 0  # Unknown key for this residue
        ct_v = CT_IDX[j]
        pt_val = (ct_v - variant_sign * kv) % 26
        # Map back through transposition
        # Under Model B: intermediate[j] = PT[perm[j]]
        # intermediate[j] = (CT[j] - key[j]) % 26
        # We want PT, which requires un-transposing
        pass

    # Actually, just score the intermediate (pre-transposition) text
    # which should also be somewhat English-like
    intermediate = [0] * N
    for j in range(N):
        r = j % period
        kv = residue_vals.get(r, 0)
        intermediate[j] = (CT_IDX[j] - variant_sign * kv) % 26

    qg_score = 0.0
    for i in range(N - 3):
        qg_score += QG_TABLE[intermediate[i]*17576 + intermediate[i+1]*676 + intermediate[i+2]*26 + intermediate[i+3]]

    return qg_score / (N-3), cribs_p7


best_mb = {'score': -999, 'cribs_p7': 0}
NUM_RESTARTS_MB = 100
SA_ITERS_MB = 50000

t2 = time.time()
for restart in range(NUM_RESTARTS_MB):
    holes = [random.randint(0, 3) for _ in range(N_ORBITS)]
    variant_sign = 1 if restart % 2 == 0 else -1
    current_score, current_cribs = score_model_b(holes, variant_sign)

    best_local_score = current_score
    best_local_holes = list(holes)
    best_local_cribs = current_cribs

    T = 2.0
    T_min = 0.01
    alpha = (T_min / T) ** (1.0 / SA_ITERS_MB)

    for step in range(SA_ITERS_MB):
        orbit = random.randint(0, N_ORBITS - 1)
        old_rot = holes[orbit]
        new_rot = (old_rot + random.randint(1, 3)) % 4
        holes[orbit] = new_rot

        new_score, new_cribs = score_model_b(holes, variant_sign)
        delta = new_score - current_score

        if delta > 0 or random.random() < math.exp(delta / T):
            current_score = new_score
            current_cribs = new_cribs
            if current_score > best_local_score:
                best_local_score = current_score
                best_local_holes = list(holes)
                best_local_cribs = current_cribs
        else:
            holes[orbit] = old_rot

        T *= alpha

    if best_local_score > best_mb['score']:
        vname = 'vig' if variant_sign == 1 else 'beau'
        best_mb = {'score': best_local_score, 'cribs_p7': best_local_cribs,
                   'holes': best_local_holes, 'variant': vname}
        print(f"  Restart {restart}: score={best_local_score:.4f} cribs_p7={best_local_cribs} {vname}")

    if restart % 25 == 24:
        elapsed = time.time() - t2
        print(f"  Restart {restart+1}/{NUM_RESTARTS_MB}, {elapsed:.0f}s, best_qg={best_mb['score']:.4f}")

t3 = time.time()
print(f"\n  {NUM_RESTARTS_MB} restarts × {SA_ITERS_MB} steps, {t3-t2:.1f}s")
print(f"  Best Model B: qg/c={best_mb['score']:.4f}, cribs_p7={best_mb['cribs_p7']}")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (pure transposition SA): best {best_overall['score']}/24")
print(f"  Phase 2 (Model B + p7 key SA): best qg/c={best_mb['score']:.4f}, cribs_p7={best_mb['cribs_p7']}")

if best_overall['score'] >= 18:
    verdict = f"SIGNAL — {best_overall['score']}/24"
elif best_overall['score'] >= 10:
    verdict = f"WEAK SIGNAL — investigate"
else:
    verdict = f"NO SIGNAL — best {best_overall['score']}/24"

print(f"\n  Verdict: {verdict}")

output = {
    'experiment': 'E-S-72',
    'description': 'Turning grille SA attack',
    'pure_trans_best': best_overall['score'],
    'model_b_best_qg': best_mb['score'],
    'model_b_cribs_p7': best_mb['cribs_p7'],
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_72_grille_sa.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_72_grille_sa.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_72_grille_sa.py")
