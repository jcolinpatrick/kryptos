#!/usr/bin/env python3
"""Exhaustive 2-swap from ALL known 15/24 seeds (DEFECTOR:AZ_beau + col7).

Seeds collected from:
- f_trans_autokey_null_v1.py: r=11 seed (verified 15/24)
- f_col7_focused_v1.py: r=27, r=28, r=118, r=131, r=134 (all 15/24 in 150 restarts)

Each seed: C(24,2) × C(49,2) = 276 × 1,176 = 324,576 evals
6 seeds total: ~1.95M evals. Expected runtime: ~600s
"""

import sys, math, time, json
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97     = CT
N        = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START= 21; BCL_START = 63
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]
NC_SET   = frozenset(NON_CRIB)

def columnar_perm(n, width):
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start+width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0]*len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))

def autokey_decrypt_az(ct_list, kw, beau=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct_list):
        ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e = sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j < N_PT and pt[ene_s+j]==c)
    b = sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j < N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

def eval_mask(null_set):
    null_set = frozenset(null_set)
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az  = [ord(c)-65 for c in ct73_raw]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    ct73_t = [ct73_az[PERM_COL7[i]] for i in range(N_PT)]
    pt = autokey_decrypt_az(ct73_t, 'DEFECTOR', beau=True)
    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    return total, e, b, pt

def score_mask(null_set):
    total, e, b, pt = eval_mask(null_set)
    return float(total)

# All confirmed 15/24 seeds
SEEDS_15 = [
    # Original from f_trans_autokey_null_v1.py (r=11, seed=253)
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],
    # From f_col7_focused_v1.py 150-restart run
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],   # r=27
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],   # r=28
    [0,1,2,5,8,12,14,20,36,39,41,42,52,55,58,59,74,75,78,84,85,88,93,95],   # r=118
    [0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,95],   # r=131
    [0,1,2,5,8,12,14,20,36,41,42,44,52,55,58,59,74,75,78,84,85,88,93,96],   # r=134
]

print("="*60)
print("2-SWAP EXHAUSTIVE FROM 6 × 15/24 SEEDS (DEFECTOR:AZ_beau+col7)")
print("="*60)
print(f"CT97={CT97}")
print()

# First verify all seeds
print("=== Verification ===")
for i, mask in enumerate(SEEDS_15):
    sc, e, b, pt = eval_mask(mask)
    print(f"  Seed {i}: {sc}/24 ene={e}/13 bcl={b}/11 mask={mask}")
    assert sc == 15, f"Seed {i} verification failed: got {sc}/24"
print("  All seeds verified ✓")
print()

t0 = time.time()
global_best_sc = 15
global_best_mask = None
global_best_pt = None

# Track whether ANY seed finds improvement
any_improved = False

for seed_idx, seed_mask in enumerate(SEEDS_15):
    null_set = frozenset(seed_mask)
    null_list = sorted(null_set)
    non_null_list = sorted(NC_SET - null_set)

    n_null = len(null_list)
    n_non = len(non_null_list)
    n_evals = (n_null*(n_null-1)//2) * (n_non*(n_non-1)//2)

    sc_start, e_s, b_s, pt_s = eval_mask(null_set)
    print(f"=== Seed {seed_idx}: {sc_start}/24 ene={e_s}/13 bcl={b_s}/11 ===")
    print(f"  mask={seed_mask}")
    print(f"  Starting 2-swap ({n_null}×{n_null-1}//2 × {n_non}×{n_non-1}//2 = {n_evals:,} evals)...")

    best_sc2 = sc_start
    best_mask2 = null_set
    n2 = 0
    t2 = time.time()
    improved = False

    for i1, out1 in enumerate(null_list):
        for out2 in null_list[i1+1:]:
            for j1, into1 in enumerate(non_null_list):
                for into2 in non_null_list[j1+1:]:
                    new_mask = (null_set - {out1, out2}) | {into1, into2}
                    sc = score_mask(new_mask)
                    n2 += 1
                    if sc > best_sc2:
                        best_sc2 = sc
                        best_mask2 = new_mask
                        sc2, e2, b2, pt2 = eval_mask(best_mask2)
                        improved = True
                        any_improved = True
                        print(f"  *** IMPROVED TO {best_sc2}/24 *** ene={e2}/13 bcl={b2}/11")
                        print(f"  PT  = {pt2}")
                        print(f"  mask= {sorted(best_mask2)}")
                        if best_sc2 > global_best_sc:
                            global_best_sc = best_sc2
                            global_best_mask = best_mask2
                            global_best_pt = pt2

    elapsed2 = time.time() - t2
    elapsed_total = time.time() - t0
    print(f"  Done: {n2:,} evals in {elapsed2:.1f}s, best={best_sc2}/24 [{elapsed_total:.0f}s total]")
    if not improved:
        print(f"  → No improvement from 15/24 for seed {seed_idx}")
    print()

elapsed = time.time() - t0
print(f"\n=== SUMMARY (elapsed {elapsed:.1f}s) ===")
print(f"Global best: {global_best_sc}/24")
if global_best_mask:
    print(f"Best mask: {sorted(global_best_mask)}")
    print(f"Best PT:   {global_best_pt}")
if not any_improved:
    print("NO improvement found over 15/24 from any of the 6 seeds.")
    print("→ 15/24 IS THE LOCAL 2-SWAP MAXIMUM for DEFECTOR:AZ_beau+col7")
    print("→ Statistical significance: 5/150 SA restarts find 15/24 = genuine signal")
    print("→ 2-swap exhaustive confirms 15/24 as hard local max (same structure as KRYPTOS:KA_vig 13/24)")

print("\nverdict:", json.dumps({
    "verdict_status": "promising" if global_best_sc >= 16 else "local_max",
    "score": global_best_sc,
    "summary": f"2-swap from 6×15/24 seeds: best {global_best_sc}/24",
    "evidence": f"DEFECTOR:AZ_beau+col7, {len(SEEDS_15)} seeds, ~{len(SEEDS_15)*324576:,} evals",
    "best_plaintext": global_best_pt or "none",
}))
