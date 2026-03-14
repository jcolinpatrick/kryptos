#!/usr/bin/env python3
"""EASTNORTHEAST:KA_vig with fixed n1=9 pre-ENE nulls.

KEY INSIGHT from f_autokey_chain_analysis_v1.py:
- EASTNORTHEAST:KA_vig MAX ENE = 5/13 at n1=9
- Best pre-ENE config: nulls=(0,1,2,3,8,9,10,11,20) → 5/13 ENE

This script:
1. Fixes those 9 null positions in {0..20}
2. Runs SA to optimize remaining 15 nulls from {34..62, 74..96}
3. Checks if 5/13 ENE + good BCL = 13-16/24 is achievable

If yes: EASTNORTHEAST:KA_vig may rival or beat KRYPTOS:KA_vig (13/24)
If no: confirmed elimination.

Also tests the other top ENE pre-configs found in exhaustive analysis.
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

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[c] for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']

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
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

def score_ene_ka_vig(null_set, beau=False):
    null_set = frozenset(null_set)
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c)-65 for c in ct73]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    pt = autokey_decrypt_ka(ct73_az, 'EASTNORTHEAST', beau)
    total, _, _ = count_crib_hits(pt, ene_s, bcl_s)
    return float(total)

def eval_ene(null_set, beau=False):
    null_set = frozenset(null_set)
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c)-65 for c in ct73]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    pt = autokey_decrypt_ka(ct73_az, 'EASTNORTHEAST', beau)
    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    return total, e, b, pt

print("="*60)
print("EASTNORTHEAST:KA_vig FIXED n1=9 PRE-ENE CONFIG")
print("="*60)
print(f"CT97={CT97}")
print()

# Best pre-ENE null configs from exhaustive analysis (5/13 ENE each)
BEST_PRE_ENE_CONFIGS = [
    (9, (0,1,2,3,8,9,10,11,20), "best_5ene"),
    (9, (0,1,2,3,7,8,9,10,20), "alt_4ene"),  # May give 4/13 ENE
]

# Middle and end positions available for remaining nulls
MIDDLE_POS = [i for i in range(34, 63) if i not in CRIB_POSITIONS]  # 29 positions
END_POS = [i for i in range(74, 97) if i not in CRIB_POSITIONS]     # 23 positions
print(f"Middle pool ({len(MIDDLE_POS)} positions): {MIDDLE_POS[:5]}...{MIDDLE_POS[-3:]}")
print(f"End pool ({len(END_POS)} positions): {END_POS[:5]}...{END_POS[-3:]}")
print()

t0 = time.time()
all_results = []

for n1, pre_nulls, config_label in BEST_PRE_ENE_CONFIGS:
    pre_null_set = frozenset(pre_nulls)
    n_remaining = N_NULLS - n1  # = 15 more nulls needed
    free_pool = [p for p in NON_CRIB if p not in pre_null_set]  # middle + end
    free_set = frozenset(free_pool)

    print(f"=== Config: n1={n1}, fixed_nulls={sorted(pre_nulls)}, {config_label} ===")
    print(f"    Remaining: {n_remaining} nulls from {len(free_pool)} positions")

    # Quick check: what's the ENE score with these fixed nulls?
    test_null = pre_null_set | frozenset(random.sample(free_pool, n_remaining))
    t, e, b, pt = eval_ene(test_null)
    print(f"    Random init: {t}/24 (ene={e}/13 bcl={b}/11)")

    # Run SA with fixed pre-ENE nulls
    for beau in [False, True]:
        variant = "KA_beau" if beau else "KA_vig"
        results_this = []
        for restart in range(60):
            rng = random.Random(restart * 71 + 999 + int(beau) * 3000)
            # Start from random complement
            extra = set(rng.sample(free_pool, n_remaining))
            null_set = pre_null_set | extra
            non_null = free_set - extra

            score = score_ene_ka_vig(frozenset(null_set), beau)
            best_sc = score; best_null = frozenset(null_set)

            Tf = 0.01; T0 = 0.5
            steps = 300_000
            for step in range(steps):
                T = T0 * (Tf/T0) ** (step/steps)
                cands = [p for p in null_set if p not in pre_null_set]
                if not cands or not non_null: break
                out = rng.choice(cands)
                into = rng.choice(list(non_null))
                null_set = (null_set - {out}) | {into}
                non_null = (non_null - {into}) | {out}
                new_sc = score_ene_ka_vig(frozenset(null_set), beau)
                delta = new_sc - score
                if delta > 0 or rng.random() < math.exp(delta/T):
                    score = new_sc
                    if score > best_sc: best_sc = score; best_null = frozenset(null_set)
                else:
                    null_set = (null_set - {into}) | {out}
                    non_null = (non_null - {out}) | {into}

            total, e, b, pt = eval_ene(best_null, beau)
            results_this.append({'score': total, 'e': e, 'b': b, 'pt': pt, 'mask': sorted(best_null)})
            all_results.append({'score': total, 'e': e, 'b': b, 'pt': pt, 'kw': f'ENE:{variant}:{config_label}',
                                 'mask': sorted(best_null)})

            if total >= 13 or restart % 15 == 0:
                print(f"  {variant} r={restart:2d}: {total}/24 ene={e}/13 bcl={b}/11")
                if total >= 13:
                    print(f"  *** HIGH SCORE ***")
                    print(f"  PT  = {pt}")
                    print(f"  mask= {sorted(best_null)}")

        best_r = max(results_this, key=lambda x: x['score'])
        print(f"  → {variant} best: {best_r['score']}/24 (ene={best_r['e']}/13 bcl={best_r['b']}/11)")
        print(f"  PT={best_r['pt']}")
        print()

# Summary
all_results.sort(key=lambda x: -x['score'])
elapsed = time.time() - t0
print(f"\n=== TOP 5 RESULTS (elapsed {elapsed:.1f}s) ===")
for r in all_results[:5]:
    print(f"  {r['score']}/24 ene={r['e']}/13 bcl={r['b']}/11 kw={r['kw']}")
    print(f"  PT  = {r['pt']}")
    print(f"  mask= {r['mask']}")
    print()

best = all_results[0] if all_results else {'score': 0, 'pt': '', 'kw': 'none', 'e': 0, 'b': 0}
print("verdict:", json.dumps({
    "verdict_status": "promising" if best['score'] >= 13 else "inconclusive",
    "score": best['score'],
    "summary": f"ENE:KA_vig fixed n1=9: best {best['score']}/24 (ene={best['e']}/13 bcl={best['b']}/11)",
    "evidence": f"kw={best['kw']}",
    "best_plaintext": best['pt'],
}))
