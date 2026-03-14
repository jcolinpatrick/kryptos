#!/usr/bin/env python3
"""Deep-dive: col7 transposition + autokey null-mask model.

KEY FINDING (f_trans_autokey_null_v1.py):
- Trans=col7 + DEFECTOR:beau → 15/24 (ene=7/13, bcl=8/11) — NEW HIGH
- Trans=col3 + DEFECTOR:beau → 14/24 (ene=7/13, bcl=7/11)
- Direct KRYPTOS:KA_vig (no trans) → 13/24 hard local max (2-swap exhaustive)

HYPOTHESIS: col7 = 7-column transposition = KRYPTOS keyword length.
Maybe KRYPTOS is the autokey keyword AND the column count.

This script:
1. Runs 200 SA restarts for col7 specifically, testing ALL keyword variants
2. Also tests: col7 with KRYPTOS:KA_vig (not just KRYPTOS:beau)
3. 2-swap from any 15+/24 seeds found
4. Reports best PT, mask, scores

Key model:
  CT97 → remove 24 nulls → CT73 → col7-transpose → CT73' → autokey-decrypt → PT73
  Crib positions in PT73 computed from null mask (n1, n2).
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

# ── Exact transposition logic from f_trans_autokey_null_v1.py ────────────────
def columnar_perm(n, width):
    """Columnar transposition perm: write row-by-row width-wide, read col-by-col.
    Returns p where transposed[i] = original[p[i]]."""
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
    """Given p where transposed[i]=original[p[i]], return inverse inv where inv[p[i]]=i."""
    inv = [0]*len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

# Pre-compute permutations for col3 and col7 (same logic as original script)
_PERMS = {}
for _w in [3, 4, 5, 6, 7, 8, 9, 10]:
    _p = columnar_perm(N_PT, _w)
    _PERMS[f'col{_w}'] = reverse_perm(_p)
# Rail fence
def rail_fence_perm(n, depth):
    rails = [[] for _ in range(depth)]
    rail = 0; direction = 1
    for i in range(n):
        rails[rail].append(i)
        if rail == 0: direction = 1
        elif rail == depth-1: direction = -1
        rail += direction
    perm = []
    for r in rails: perm.extend(r)
    return perm
for _d in [2,3,4,5]:
    _p = rail_fence_perm(N_PT, _d)
    _PERMS[f'rail{_d}'] = reverse_perm(_p)

def apply_trans(ct73_list, trans_name):
    """Apply transposition permutation to ct73_list. Returns new list."""
    perm = _PERMS.get(trans_name)
    if perm is None or trans_name == 'id':
        return list(ct73_list)
    return [ct73_list[perm[i]] for i in range(len(ct73_list))]

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

def autokey_decrypt_az(ct73_az, kw, beau=False):
    kw_az = [ord(c)-65 for c in kw.upper() if 'A' <= c <= 'Z']
    L = len(kw_az)
    pt_indices = []; pt_output = []
    for i, cki in enumerate(ct73_az):
        ki = kw_az[i] if i < L else pt_indices[i - L]
        pt_ki = ((ki - cki) if beau else (cki - ki)) % 26
        pt_indices.append(pt_ki)
        pt_output.append(chr(pt_ki + 65))
    return ''.join(pt_output)

def count_crib_hits(pt, ene_s, bcl_s):
    e = sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j < N_PT and pt[ene_s+j]==c)
    b = sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j < N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

def eval_col7(null_set, kw, beau, ka, trans_name='col7'):
    null_set = frozenset(null_set)
    ct73_raw = [CT97[i] for i in range(N) if i not in null_set]
    ct73_az  = [ord(c)-65 for c in ct73_raw]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    # Apply transposition using exact same logic as f_trans_autokey_null_v1.py
    ct73_t = apply_trans(ct73_az, trans_name)
    if ka:
        pt = autokey_decrypt_ka(ct73_t, kw, beau)
    else:
        pt = autokey_decrypt_az(ct73_t, kw, beau)
    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    return total, e, b, pt

def score_col7(null_set, kw, beau, ka, trans_name='col7'):
    total, e, b, pt = eval_col7(null_set, kw, beau, ka, trans_name)
    return float(total)

print("="*60)
print("COL7 TRANSPOSITION + AUTOKEY NULL-MASK DEEP DIVE")
print("="*60)
print(f"CT97={CT97}")
print()

# Verified 15/24: DEFECTOR:beau(AZ), col7, mask=[0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
SEED_MASK_15 = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
verify_sc, verify_e, verify_b, verify_pt = eval_col7(
    frozenset(SEED_MASK_15), 'DEFECTOR', True, False, 'col7')
print(f"Verify 15/24 seed: {verify_sc}/24 ene={verify_e}/13 bcl={verify_b}/11")
print(f"  PT={verify_pt}")
print(f"  mask={SEED_MASK_15}")
print()

# Keywords to test: canonical Kryptos + cipher keywords
KEYWORDS = [
    ('KRYPTOS',  True,  True),   # KA_beau  (known 13/24 direct)
    ('KRYPTOS',  False, True),   # KA_vig   (known 13/24 direct)
    ('KRYPTOS',  True,  False),  # AZ_beau
    ('KRYPTOS',  False, False),  # AZ_vig
    ('DEFECTOR', True,  False),  # AZ_beau  (15/24 result)
    ('DEFECTOR', False, False),  # AZ_vig
    ('DEFECTOR', True,  True),   # KA_beau
    ('DEFECTOR', False, True),   # KA_vig
    ('KOMPASS',  True,  False),  # AZ_beau
    ('KOMPASS',  False, False),  # AZ_vig
    ('KOMPASS',  True,  True),   # KA_beau
    ('KOMPASS',  False, True),   # KA_vig
    ('ABSCISSA', True,  True),   # KA_beau
    ('ABSCISSA', False, True),   # KA_vig
    ('COLOPHON', True,  True),   # KA_beau
    ('COLOPHON', False, True),   # KA_vig
    ('PARALLAX', True,  True),   # KA_beau
    ('PARALLAX', False, True),   # KA_vig
]

t0 = time.time()
all_results = []

# Test multiple transpositions: focused on col7 (15/24 record) and col3 (14/24 record)
for trans_name in ['col7', 'col3']:
    print(f"\n{'='*60}")
    print(f"TRANS={trans_name}")
    print(f"{'='*60}")

    for kw, beau, ka in KEYWORDS:
        variant = f"{'KA' if ka else 'AZ'}_{'beau' if beau else 'vig'}"
        label = f"{kw}:{variant}:{trans_name}"

        results_this = []
        n_restarts = 200 if trans_name == 'col7' else 60

        for restart in range(n_restarts):
            rng = random.Random(restart * 137 + hash(kw + variant + trans_name) % 10000)
            null_set = set(rng.sample(NC_LIST, N_NULLS))
            non_null = NC_SET - null_set

            score = score_col7(frozenset(null_set), kw, beau, ka, trans_name)
            best_sc = score; best_null = frozenset(null_set)

            Tf = 0.005; T0 = 0.6
            steps = 500_000
            for step in range(steps):
                T = T0 * (Tf/T0) ** (step/steps)
                out  = rng.choice(list(null_set))
                into = rng.choice(list(non_null))
                null_set = (null_set - {out}) | {into}
                non_null = (non_null - {into}) | {out}
                new_sc = score_col7(frozenset(null_set), kw, beau, ka, trans_name)
                delta = new_sc - score
                if delta > 0 or rng.random() < math.exp(delta/T):
                    score = new_sc
                    if score > best_sc: best_sc = score; best_null = frozenset(null_set)
                else:
                    null_set = (null_set - {into}) | {out}
                    non_null = (non_null - {out}) | {into}

            total, e, b, pt = eval_col7(best_null, kw, beau, ka, trans_name)
            results_this.append({'score': total, 'e': e, 'b': b, 'pt': pt,
                                  'mask': sorted(best_null), 'label': label})
            all_results.append({'score': total, 'e': e, 'b': b, 'pt': pt,
                                  'mask': sorted(best_null), 'label': label})

            if total >= 14 or restart % 50 == 0:
                elapsed = time.time() - t0
                print(f"  {label} r={restart:3d}: {total}/24 ene={e}/13 bcl={b}/11  [{elapsed:.0f}s]")
                if total >= 14:
                    print(f"  *** HIGH SCORE {total}/24 ***")
                    print(f"  PT  = {pt}")
                    print(f"  mask= {sorted(best_null)}")

        best_r = max(results_this, key=lambda x: x['score'])
        print(f"  → {label} BEST: {best_r['score']}/24 (ene={best_r['e']}/13 bcl={best_r['b']}/11)")
        print(f"  PT={best_r['pt']}")
        print()

# Phase 2: 2-swap from any 15+/24 seeds
seeds_15 = [r for r in all_results if r['score'] >= 15]
if seeds_15:
    print("\n" + "="*60)
    print("PHASE 2: 2-SWAP FROM 15+/24 SEEDS")
    print("="*60)
    for seed_r in seeds_15:
        null_set = frozenset(seed_r['mask'])
        null_list = sorted(null_set)
        non_null_list = sorted(NC_SET - null_set)
        kw_full = seed_r['label']
        # Parse label: KW:variant:transName
        parts = kw_full.split(':')
        kw = parts[0]; var = parts[1]; t_name = parts[2]
        beau = 'beau' in var; ka = 'KA' in var

        print(f"\nSeed: {kw_full} {seed_r['score']}/24 → 2-swap exhaustive...")
        best_sc2 = seed_r['score']
        best_null2 = null_set
        n2swap = 0
        for i, out1 in enumerate(null_list):
            for out2 in null_list[i+1:]:
                for j, into1 in enumerate(non_null_list):
                    for into2 in non_null_list[j+1:]:
                        new_mask = (null_set - {out1, out2}) | {into1, into2}
                        sc = score_col7(new_mask, kw, beau, ka, t_name)
                        n2swap += 1
                        if sc > best_sc2:
                            best_sc2 = sc
                            best_null2 = new_mask
                            total2, e2, b2, pt2 = eval_col7(best_null2, kw, beau, ka, t_name)
                            print(f"  IMPROVED! {best_sc2}/24 ene={e2}/13 bcl={b2}/11")
                            print(f"  PT  = {pt2}")
                            print(f"  mask= {sorted(best_null2)}")
        print(f"  2-swap done ({n2swap} evals), best={best_sc2}/24")

# Summary
elapsed = time.time() - t0
all_results.sort(key=lambda x: -x['score'])
print(f"\n=== TOP 10 RESULTS (elapsed {elapsed:.1f}s) ===")
for r in all_results[:10]:
    print(f"  {r['score']}/24 ene={r['e']}/13 bcl={r['b']}/11 {r['label']}")
    print(f"  PT  = {r['pt']}")
    print(f"  mask= {r['mask']}")
    print()

best = all_results[0] if all_results else {'score':0,'pt':'','label':'none','e':0,'b':0}
print("verdict:", json.dumps({
    "verdict_status": "promising" if best['score'] >= 15 else "inconclusive",
    "score": best['score'],
    "summary": f"col7/col3 deep dive: best {best['score']}/24 (ene={best['e']}/13 bcl={best['b']}/11)",
    "evidence": f"label={best['label']}",
    "best_plaintext": best['pt'],
}))
