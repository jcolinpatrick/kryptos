#!/usr/bin/env python3
"""2-swap exhaustive search from best known 12/24 masks.

SA is stuck at 12/24 for multiple cipher variants. If 24/24 exists,
there must be a path from 12/24 to 24/24. But a series of single swaps
might pass through a crib-hit "valley" that SA won't cross.

2-swap search: from a seed mask, try ALL pairs of (remove a, add b, remove c, add d)
This explores a broader neighbourhood without requiring monotonic improvement.

For each seed mask, the 2-swap space has size:
  C(24,2) × C(49,2) ≈ 276 × 1176 = 324,576 evaluations per seed

That's fast enough to be exhaustive.

Tests both KRYPTOS:KA_vig (corrected) and DEFECTOR:beau (AZ) simultaneously.
"""

import sys, random, math, time, json, itertools
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97     = CT
N        = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START= 21; BCL_START = 63
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]
NC_SET   = frozenset(NON_CRIB)
NON_CRIB_LIST = sorted(NON_CRIB)

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[c] for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']

def autokey_decrypt_ka(ct73_az, kw, beau=False):
    ct73_ka = [AZ_TO_KA[ci] for ci in ct73_az]
    kw_ka   = [KA_IDX[c] for c in kw.upper() if c in KA_IDX]
    L        = len(kw_ka)
    pt_ka_indices = []; pt_output = []
    for i, cki in enumerate(ct73_ka):
        ki = kw_ka[i] if i < L else pt_ka_indices[i - L]
        pt_ki = ((ki - cki) if beau else (cki - ki)) % 26
        pt_ka_indices.append(pt_ki)
        pt_output.append(KA_STR[pt_ki])
    return ''.join(pt_output)

def autokey_decrypt_az(ct73_az, kw, beau=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct73_az):
        ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

CIPHERS = [
    ('KRYPTOS', False, True,  'KRYPTOS:KA_vig'),
    ('KRYPTOS', True,  True,  'KRYPTOS:KA_beau'),
    ('DEFECTOR',True,  False, 'DEFECTOR:AZ_beau'),
    ('KOMPASS', False, False, 'KOMPASS:AZ_vig'),
    ('ABSCISSA',False, True,  'ABSCISSA:KA_vig'),
]

def eval_all(null_set):
    """Evaluate all ciphers on a null mask; return best crib hits."""
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    best=0; best_kw=''; best_pt=''
    for kw,beau,is_ka,label in CIPHERS:
        if is_ka: pt=autokey_decrypt_ka(ct73_az,kw,beau)
        else:     pt=autokey_decrypt_az(ct73_az,kw,beau)
        total,e,b=count_crib_hits(pt,ene_s,bcl_s)
        if total>best:
            best=total; best_kw=f"{label} ene={e}/13 bcl={b}/11"; best_pt=pt
    return best,best_kw,best_pt,ct73

# ── Seed masks from previous SA results ───────────────────────────────────────
# Best masks from prior campaigns (12/24 DEFECTOR:beau)
SEED_MASKS = [
    # From f_sa_continuation_v1.py
    [2, 4, 8, 10, 17, 37, 40, 42, 43, 44, 45, 47, 49, 51, 53, 54, 55, 75, 76, 81, 83, 84, 85, 92],
    [5, 6, 8, 10, 14, 34, 36, 37, 38, 43, 44, 47, 48, 49, 51, 54, 55, 74, 75, 79, 84, 86, 92, 93],
    [6, 7, 8, 10, 14, 34, 35, 36, 38, 42, 45, 46, 49, 50, 51, 54, 55, 75, 76, 77, 78, 79, 85, 96],
    # From f_sa_null_qg_v2.py
    [0, 2, 8, 10, 17, 36, 38, 39, 42, 43, 44, 45, 49, 51, 55, 57, 59, 75, 76, 84, 85, 86, 88, 92],
]

print("="*60)
print("2-SWAP EXHAUSTIVE SEARCH FROM 12/24 SEED MASKS")
print("="*60)
print(f"Seed masks: {len(SEED_MASKS)}")
print(f"Ciphers: {[c[3] for c in CIPHERS]}")
print()

# Verify seeds
for i,mask in enumerate(SEED_MASKS):
    crib,kw,pt,ct73=eval_all(frozenset(mask))
    print(f"Seed {i}: {crib}/24 {kw}")
    print(f"  PT={pt}")

print()
t0=time.time()
all_results=[]

for seed_i, seed_mask in enumerate(SEED_MASKS):
    seed_set = frozenset(seed_mask)
    non_null_list = sorted(NC_SET - seed_set)
    null_list = sorted(seed_set)
    print(f"--- Seed {seed_i}: {len(null_list)} nulls, {len(non_null_list)} candidates ---")

    best_so_far=12; best_mask=seed_set; best_info=''

    # 1-swap first (fast)
    for out_pos in null_list:
        for into_pos in non_null_list:
            new_mask = (seed_set - {out_pos}) | {into_pos}
            crib,kw,pt,ct73=eval_all(new_mask)
            if crib>best_so_far:
                best_so_far=crib; best_mask=new_mask; best_info=kw
                print(f"  1-swap NEW BEST: {crib}/24 {kw}")
                print(f"  PT={pt}")
                if crib>=16:
                    print(f"  *** STRONG HIT {crib}/24 ***")
                    print(f"  mask={sorted(new_mask)}")

    print(f"  After 1-swap: best={best_so_far}/24")

    # 2-swap search from seed (full exhaustive)
    print(f"  Starting 2-swap ({len(null_list)}×{len(null_list)-1}/2 × {len(non_null_list)}×{len(non_null_list)-1}/2 = "
          f"{len(null_list)*(len(null_list)-1)//2 * len(non_null_list)*(len(non_null_list)-1)//2} evals)...")

    n_evals=0
    out_pairs  = list(itertools.combinations(null_list, 2))
    into_pairs = list(itertools.combinations(non_null_list, 2))

    for out1,out2 in out_pairs:
        for into1,into2 in into_pairs:
            new_mask = (seed_set - {out1,out2}) | {into1,into2}
            crib,kw,pt,ct73=eval_all(new_mask)
            n_evals+=1
            if crib>best_so_far:
                best_so_far=crib; best_mask=new_mask; best_info=kw
                print(f"  2-swap NEW BEST: {crib}/24 {kw} (eval #{n_evals})")
                print(f"  PT={pt}")
                if crib>=16:
                    print(f"  *** STRONG HIT {crib}/24 ***")
                    print(f"  mask={sorted(new_mask)}")
                    all_results.append({'crib':crib,'kw':kw,'pt':pt,'ct73':ct73,
                                       'mask':sorted(new_mask),'seed':seed_i})

    elapsed_seed = time.time()-t0
    print(f"  Seed {seed_i} done: {n_evals} evals, best={best_so_far}/24 ({elapsed_seed:.1f}s)")
    if best_so_far>12:
        crib,kw,pt,ct73=eval_all(best_mask)
        all_results.append({'crib':crib,'kw':kw,'pt':pt,'ct73':ct73,
                            'mask':sorted(best_mask),'seed':seed_i})

elapsed=time.time()-t0
print(f"\n=== RESULTS (elapsed {elapsed:.1f}s) ===")
all_results.sort(key=lambda x:-x['crib'])
if all_results:
    for r in all_results[:5]:
        print(f"  {r['crib']}/24 {r['kw']}")
        print(f"  PT  = {r['pt']}")
        print(f"  CT73= {r['ct73']}")
        print(f"  mask= {r['mask']}")
        print()
else:
    print("  No improvement over 12/24 found via 2-swap.")

best_crib=max(r['crib'] for r in all_results) if all_results else 12
print("verdict:",json.dumps({
    "verdict_status":"promising" if best_crib>=16 else "inconclusive",
    "score":best_crib,
    "summary":f"2-swap exhaustive from 12/24 seeds: best {best_crib}/24",
    "evidence":"no improvement" if best_crib<=12 else f"kw={all_results[0]['kw'][:40]}",
    "best_plaintext":all_results[0]['pt'] if all_results else "",
}))
