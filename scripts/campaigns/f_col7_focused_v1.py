#!/usr/bin/env python3
"""Focused col7/stride7 deep dive: confirm 15/24 and probe for 16+.

KEY FINDING: DEFECTOR:AZ_beau + col7 transposition + null mask → 15/24 (r=11, seed=253)
             = theoretical maximum for KRYPTOS:KA_vig (7/13 ENE + 8/11 BCL)
             Note: col7=stride7 (mathematically identical for 73 chars)

This script:
1. Verifies the 15/24 seed
2. Runs 150 restarts × 120K steps for top keyword variants with col7
3. Priority order: DEFECTOR:AZ_beau first (the 15/24 result), then KRYPTOS variants
4. 2-swap exhaustive from ALL 15+/24 seeds found
5. Reports frequency of 15/24 hits to assess statistical significance
"""

import sys, random, math, time, json
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97     = CT
N        = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START= 21; BCL_START = 63
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]
NC_SET   = frozenset(NON_CRIB)
NC_LIST  = sorted(NON_CRIB)

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[c] for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']

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

# Pre-compute col7 permutation (same logic as f_trans_autokey_null_v1.py)
PERM_COL7 = reverse_perm(columnar_perm(N_PT, 7))
PERM_COL3 = reverse_perm(columnar_perm(N_PT, 3))

def autokey_decrypt_az(ct_list, kw, beau=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct_list):
        ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def autokey_decrypt_ka(ct73_az, kw, beau=False):
    ct73_ka = [AZ_TO_KA[ci] for ci in ct73_az]
    kw_ka   = [KA_IDX[c] for c in kw.upper() if c in KA_IDX]
    L = len(kw_ka)
    pt_ka_indices = []; pt_output = []
    for i, cki in enumerate(ct73_ka):
        ki = kw_ka[i] if i < L else pt_ka_indices[i - L]
        pt_ki = ((ki - cki) if beau else (cki - ki)) % 26
        pt_ka_indices.append(pt_ki)
        pt_output.append(KA_STR[pt_ki])
    return ''.join(pt_output)

def count_crib_hits(pt, ene_s, bcl_s):
    e = sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j < N_PT and pt[ene_s+j]==c)
    b = sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j < N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

def eval_mask(null_set, kw, beau, ka, perm):
    null_set = frozenset(null_set)
    ct73_raw = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az  = [ord(c)-65 for c in ct73_raw]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    ct73_t = [ct73_az[perm[i]] for i in range(N_PT)]
    if ka:
        pt = autokey_decrypt_ka(ct73_t, kw, beau)
    else:
        pt = autokey_decrypt_az(ct73_t, kw, beau)
    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    return total, e, b, pt

def score_mask(null_set, kw, beau, ka, perm):
    total, e, b, pt = eval_mask(null_set, kw, beau, ka, perm)
    return float(total)

print("="*60)
print("COL7 FOCUSED DEEP DIVE — 15/24 VERIFICATION & PROBE")
print("="*60)
print(f"CT97={CT97}")
print()

# Verify the known 15/24 seed
SEED_15_MASK = frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
v_sc, v_e, v_b, v_pt = eval_mask(SEED_15_MASK, 'DEFECTOR', True, False, PERM_COL7)
print(f"Verify 15/24 (DEFECTOR:AZ_beau+col7): {v_sc}/24 ene={v_e}/13 bcl={v_b}/11")
print(f"  PT={v_pt}")
print(f"  mask={sorted(SEED_15_MASK)}")
assert v_sc == 15, f"Verification failed! got {v_sc}"
print("  ✓ VERIFIED")
print()

# Keywords prioritized: DEFECTOR:AZ_beau first, then KRYPTOS/KOMPASS variants
KEYWORDS = [
    ('DEFECTOR', True,  False, 'AZ_beau',  PERM_COL7, 'col7'),   # THE 15/24 cipher
    ('DEFECTOR', True,  False, 'AZ_beau',  PERM_COL3, 'col3'),   # 14/24 cipher
    ('KRYPTOS',  True,  False, 'AZ_beau',  PERM_COL7, 'col7'),
    ('KRYPTOS',  False, False, 'AZ_vig',   PERM_COL7, 'col7'),
    ('KRYPTOS',  True,  True,  'KA_beau',  PERM_COL7, 'col7'),
    ('KRYPTOS',  False, True,  'KA_vig',   PERM_COL7, 'col7'),
    ('KOMPASS',  True,  False, 'AZ_beau',  PERM_COL7, 'col7'),
    ('KOMPASS',  False, False, 'AZ_vig',   PERM_COL7, 'col7'),
    ('DEFECTOR', False, False, 'AZ_vig',   PERM_COL7, 'col7'),
    ('DEFECTOR', True,  True,  'KA_beau',  PERM_COL7, 'col7'),
    ('DEFECTOR', False, True,  'KA_vig',   PERM_COL7, 'col7'),
    ('COLOPHON', True,  True,  'KA_beau',  PERM_COL7, 'col7'),
    ('COLOPHON', False, True,  'KA_vig',   PERM_COL7, 'col7'),
    ('ABSCISSA', True,  True,  'KA_beau',  PERM_COL7, 'col7'),
    ('ABSCISSA', False, True,  'KA_vig',   PERM_COL7, 'col7'),
    ('PARALLAX', True,  True,  'KA_beau',  PERM_COL7, 'col7'),
    ('PARALLAX', False, True,  'KA_vig',   PERM_COL7, 'col7'),
    ('SHADOW',   True,  True,  'KA_beau',  PERM_COL7, 'col7'),
    ('SHADOW',   True,  False, 'AZ_beau',  PERM_COL7, 'col7'),
]

t0 = time.time()
all_results = []
score_dist = {}  # label → {score → count}

N_RESTARTS = 150  # 150 restarts × 120K steps ≈ 30s per keyword → 10 min total

for kw, beau, ka, var, perm, trans_name in KEYWORDS:
    label = f"{kw}:{var}:{trans_name}"
    score_dist[label] = {}
    results_this = []

    for restart in range(N_RESTARTS):
        # Use same seed scheme as original script: restart*23 + fix_w_bool
        rng = random.Random(restart * 23 + (0 if restart % 2 == 0 else 1))
        null_set = set(rng.sample(NC_LIST, N_NULLS))
        non_null = NC_SET - null_set

        sc = score_mask(frozenset(null_set), kw, beau, ka, perm)
        best_sc = sc; best_null = frozenset(null_set)

        T0 = 0.3; Tf = 0.01
        steps = 120_000
        for step in range(steps):
            T = T0 * (Tf/T0) ** (step/steps)
            out  = rng.choice(list(null_set))
            into = rng.choice(list(non_null))
            null_set = (null_set - {out}) | {into}
            non_null = (non_null - {into}) | {out}
            new_sc = score_mask(frozenset(null_set), kw, beau, ka, perm)
            delta = new_sc - sc
            if delta > 0 or rng.random() < math.exp(delta/T):
                sc = new_sc
                if sc > best_sc: best_sc = sc; best_null = frozenset(null_set)
            else:
                null_set = (null_set - {into}) | {out}
                non_null = (non_null - {out}) | {into}

        total, e, b, pt = eval_mask(best_null, kw, beau, ka, perm)
        results_this.append({'score': total, 'e': e, 'b': b, 'pt': pt,
                              'mask': sorted(best_null), 'label': label})
        all_results.append({'score': total, 'e': e, 'b': b, 'pt': pt,
                              'mask': sorted(best_null), 'label': label})
        score_dist[label][total] = score_dist[label].get(total, 0) + 1

        if total >= 14 or restart % 50 == 0:
            elapsed = time.time() - t0
            print(f"  {label} r={restart:3d}: {total}/24 ene={e}/13 bcl={b}/11  [{elapsed:.0f}s]")
            if total >= 14:
                print(f"  *** HIGH SCORE {total}/24 ***")
                print(f"  PT  = {pt}")
                print(f"  mask= {sorted(best_null)}")

    best_r = max(results_this, key=lambda x: x['score'])
    n15 = score_dist[label].get(15, 0)
    n14 = score_dist[label].get(14, 0)
    elapsed = time.time() - t0
    print(f"  → {label} BEST: {best_r['score']}/24 (ene={best_r['e']}/13 bcl={best_r['b']}/11) "
          f"[15+:{n15}/{N_RESTARTS} 14+:{n14}/{N_RESTARTS}] [{elapsed:.0f}s]")
    print(f"  PT={best_r['pt']}")
    print()

# Phase 2: 2-swap from ALL 15+/24 seeds
seeds_15 = [r for r in all_results if r['score'] >= 15]
print(f"\nFound {len(seeds_15)} seeds with 15+/24")
if seeds_15:
    print("="*60)
    print("PHASE 2: 2-SWAP FROM 15+/24 SEEDS")
    print("="*60)
    seen_masks = set()
    for seed_r in seeds_15:
        mask_key = tuple(sorted(seed_r['mask']))
        if mask_key in seen_masks:
            continue
        seen_masks.add(mask_key)
        null_set = frozenset(seed_r['mask'])
        null_list = sorted(null_set)
        non_null_list = sorted(NC_SET - null_set)
        parts = seed_r['label'].split(':')
        kw = parts[0]
        var = parts[1]
        trans_n = parts[2]
        beau = 'beau' in var
        ka = 'KA' in var
        perm = PERM_COL7 if trans_n == 'col7' else PERM_COL3

        print(f"\nSeed: {seed_r['label']} {seed_r['score']}/24")
        print(f"  mask={sorted(null_set)}")
        print(f"  Starting 2-swap ({len(null_list)}×{len(null_list)-1}//2 × {len(non_null_list)}×{len(non_null_list)-1}//2 evals)...")
        best_sc2 = seed_r['score']
        best_null2 = null_set
        n2swap = 0
        t2 = time.time()
        for i, out1 in enumerate(null_list):
            for out2 in null_list[i+1:]:
                for j, into1 in enumerate(non_null_list):
                    for into2 in non_null_list[j+1:]:
                        new_mask = (null_set - {out1, out2}) | {into1, into2}
                        sc = score_mask(new_mask, kw, beau, ka, perm)
                        n2swap += 1
                        if sc > best_sc2:
                            best_sc2 = sc
                            best_null2 = new_mask
                            total2, e2, b2, pt2 = eval_mask(best_null2, kw, beau, ka, perm)
                            print(f"  *** IMPROVED TO {best_sc2}/24 *** ene={e2}/13 bcl={b2}/11")
                            print(f"  PT  = {pt2}")
                            print(f"  mask= {sorted(best_null2)}")
        elapsed2 = time.time() - t2
        print(f"  2-swap done: {n2swap:,} evals in {elapsed2:.0f}s, best={best_sc2}/24")

# Final summary
elapsed = time.time() - t0
all_results.sort(key=lambda x: -x['score'])

print(f"\n=== TOP 15 RESULTS (elapsed {elapsed:.1f}s) ===")
for r in all_results[:15]:
    print(f"  {r['score']}/24 ene={r['e']}/13 bcl={r['b']}/11  {r['label']}")
    print(f"  PT={r['pt']}")
    print(f"  mask={r['mask']}")
    print()

print("\n=== SCORE DISTRIBUTIONS ===")
for label, dist in score_dist.items():
    total_r = sum(dist.values())
    best = max(dist.keys())
    n15 = dist.get(15, 0)
    n14 = dist.get(14, 0)
    n13 = dist.get(13, 0)
    n12 = dist.get(12, 0)
    print(f"  {label}: best={best} 15+:{n15} 14+:{n14} 13:{n13} 12:{n12} (total {total_r})")

best = all_results[0] if all_results else {'score':0,'pt':'','label':'none','e':0,'b':0}
print("verdict:", json.dumps({
    "verdict_status": "promising" if best['score'] >= 15 else "inconclusive",
    "score": best['score'],
    "summary": f"col7 focused: best {best['score']}/24 (ene={best['e']}/13 bcl={best['b']}/11)",
    "evidence": f"label={best['label']}, 15+/150 frequency shown above",
    "best_plaintext": best['pt'],
}))
