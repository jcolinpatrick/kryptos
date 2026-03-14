#!/usr/bin/env python3
"""3-swap exhaustive probe from BEST 15/24 seed.

This answers: is 16/24 achievable from the 15/24 local maximum?
C(24,3) × C(49,3) = 2,024 × 18,424 = 37,289,776 evals per seed.
At ~31μs/eval → ~1160s ≈ 19 min per seed.
We run the canonical seed first, then as many others as time permits.
"""

import sys, itertools, time, json
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
    return float(eval_mask(null_set)[0])

# Seeds in priority order (canonical first)
SEEDS_15 = [
    [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96],   # canonical
    [0,1,2,5,8,12,14,20,36,41,42,44,52,55,58,59,74,75,78,84,85,88,93,96],   # r=134
    [0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95],   # r=27
    [0,1,2,5,8,12,14,20,36,42,43,44,52,55,58,59,74,75,78,84,85,88,94,95],   # r=28
    [0,1,2,5,8,12,14,20,36,39,41,42,52,55,58,59,74,75,78,84,85,88,93,95],   # r=118
    [0,1,2,5,8,12,14,20,36,38,39,45,52,56,58,59,74,75,78,84,85,87,93,95],   # r=131
]

print("="*60)
print("3-SWAP EXHAUSTIVE FROM 15/24 SEEDS (DEFECTOR:AZ_beau+col7)")
print("="*60)
print(f"CT97={CT97}")
print(f"Seeds: {len(SEEDS_15)}")
print(f"Evals per seed: C(24,3)×C(49,3) = 2,024×18,424 = {2024*18424:,}")
print(f"Max runtime: ~{len(SEEDS_15)*2024*18424*31e-6/60:.0f} min")
print()

t0 = time.time()
global_best = 15
global_best_mask = None
global_best_pt = None
any_improved = False

for seed_idx, seed_mask in enumerate(SEEDS_15):
    null_set = frozenset(seed_mask)
    null_list = sorted(null_set)
    non_null_list = sorted(NC_SET - null_set)

    sc_start, e_s, b_s, pt_s = eval_mask(null_set)
    n_null = len(null_list)
    n_non = len(non_null_list)
    n_evals = (n_null*(n_null-1)*(n_null-2)//6) * (n_non*(n_non-1)*(n_non-2)//6)

    print(f"=== Seed {seed_idx}: {sc_start}/24 ene={e_s}/13 bcl={b_s}/11 ===")
    print(f"  mask={seed_mask}")
    print(f"  3-swap: C({n_null},3)×C({n_non},3) = {n_null*(n_null-1)*(n_null-2)//6:,}×{n_non*(n_non-1)*(n_non-2)//6:,} = {n_evals:,} evals")

    best_sc3 = sc_start
    best_mask3 = null_set
    n3 = 0
    improved = False
    t3 = time.time()
    last_report = t3

    for i1, out1 in enumerate(null_list):
        for i2, out2 in enumerate(null_list[i1+1:], i1+1):
            for out3 in null_list[i2+1:]:
                for j1, into1 in enumerate(non_null_list):
                    for j2, into2 in enumerate(non_null_list[j1+1:], j1+1):
                        for into3 in non_null_list[j2+1:]:
                            new_mask = (null_set - {out1, out2, out3}) | {into1, into2, into3}
                            sc = score_mask(new_mask)
                            n3 += 1
                            if sc > best_sc3:
                                best_sc3 = sc
                                best_mask3 = new_mask
                                sc3, e3, b3, pt3 = eval_mask(best_mask3)
                                improved = True
                                any_improved = True
                                print(f"  *** IMPROVED TO {best_sc3}/24 *** ene={e3}/13 bcl={b3}/11 [{time.time()-t0:.0f}s]")
                                print(f"  PT  = {pt3}")
                                print(f"  mask= {sorted(best_mask3)}")
                                if best_sc3 > global_best:
                                    global_best = best_sc3
                                    global_best_mask = best_mask3
                                    global_best_pt = pt3
                            # Progress every 60s
                            now = time.time()
                            if now - last_report > 60:
                                pct = n3 / n_evals * 100
                                print(f"  Progress: {n3:,}/{n_evals:,} ({pct:.1f}%) in {now-t3:.0f}s, best={best_sc3}/24")
                                last_report = now

    elapsed3 = time.time() - t3
    elapsed_total = time.time() - t0
    print(f"  Done: {n3:,} evals in {elapsed3:.1f}s, best={best_sc3}/24 [{elapsed_total:.0f}s total]")
    if not improved:
        print(f"  → No improvement from 15/24 for seed {seed_idx}")
    print()

elapsed = time.time() - t0
print(f"\n=== FINAL SUMMARY (elapsed {elapsed:.1f}s) ===")
print(f"Global best: {global_best}/24")
if global_best_mask:
    print(f"Best mask: {sorted(global_best_mask)}")
    print(f"Best PT:   {global_best_pt}")
if not any_improved:
    print("NO improvement found over 15/24 via 3-swap.")
    print("→ 15/24 is robust to 3-position changes")
    print("→ Either 16/24 requires >3-swap, or 15/24 is theoretical max for this model")

print("\nverdict:", json.dumps({
    "verdict_status": "promising" if global_best >= 16 else "hard_max_confirmed",
    "score": global_best,
    "summary": f"3-swap from {len(SEEDS_15)}×15/24 seeds: best {global_best}/24",
    "evidence": f"DEFECTOR:AZ_beau+col7, {len(SEEDS_15)} seeds",
    "best_plaintext": global_best_pt or "none",
}))
