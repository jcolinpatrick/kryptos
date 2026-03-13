#!/usr/bin/env python3
"""Consensus null position analysis for KRYPTOS:KA_vig.

INSIGHT: Multiple SA runs converge to 13/24 with KRYPTOS:KA_vig.
If positions appearing in MOST of these 13/24 masks are "correct",
we can identify a consensus core and then only search the remaining positions.

APPROACH:
1. Run 200 SA restarts for KRYPTOS:KA_vig, collect all masks scoring >=12
2. Build a frequency histogram: how often each position appears in 12+ masks
3. Positions with high frequency = likely correct null positions
4. Fix the top K consensus positions and run intensive SA for the rest
5. Report any mask achieving >=14/24

Also: if two different 13/24 masks share K positions, those K are highly likely correct.
"""

import sys, random, math, time, json, collections
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

def score_kaka(null_set, kw='KRYPTOS', beau=False):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    pt=autokey_decrypt_ka(ct73_az,kw,beau)
    total,_,_=count_crib_hits(pt,ene_s,bcl_s)
    return float(total)

def sa_run(seed, fixed_set=None, steps=300_000, T0=0.5):
    rng=random.Random(seed)
    if fixed_set is None: fixed_set=frozenset()
    fixed=fixed_set&NC_SET
    pool=[p for p in NON_CRIB if p not in fixed]
    n_extra=N_NULLS-len(fixed)
    if n_extra<0 or n_extra>len(pool): return None
    extra=set(rng.sample(pool,n_extra)); null_set=fixed|extra
    non_null=NC_SET-null_set

    score=score_kaka(frozenset(null_set))
    best_sc=score; best_null=frozenset(null_set)

    Tf=0.01
    for step in range(steps):
        T=T0*(Tf/T0)**(step/steps)
        cands=[p for p in null_set if p not in fixed]
        if not cands or not non_null: break
        out=rng.choice(cands); into=rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}; non_null=(non_null-{into})|{out}
        new_sc=score_kaka(frozenset(null_set))
        delta=new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc: best_sc=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}

    ct73=''.join(CT97[i] for i in range(N) if i not in best_null)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in best_null if p<ENE_START)
    n2=sum(1 for p in best_null if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    pt=autokey_decrypt_ka(ct73_az,'KRYPTOS',False)
    total,e,b=count_crib_hits(pt,ene_s,bcl_s)
    return {'crib':total,'e':e,'b':b,'pt':pt,'ct73':ct73,
            'mask':sorted(best_null),'seed':seed,'fixed_count':len(fixed)}

print("="*60)
print("CONSENSUS NULL ANALYSIS — KRYPTOS:KA_vig")
print("="*60)
print(f"CT97={CT97}")
print()

# ── Phase 1: Collect many 12+/24 masks ────────────────────────────────────────
t0=time.time()
print("Phase 1: Collecting 200 random SA runs to build consensus...")
print()

all_masks_12plus = []
all_masks_13plus = []
position_freq = collections.Counter()  # freq of each position in 12+ masks

for restart in range(200):
    r=sa_run(seed=restart*53, steps=300_000, T0=0.5)
    if r and r['crib']>=12:
        all_masks_12plus.append(r)
        for p in r['mask']: position_freq[p]+=1
    if r and r['crib']>=13:
        all_masks_13plus.append(r)
        if restart%10==0 or r['crib']>=14:
            print(f"  r={restart:3d}: {r['crib']}/24 ene={r['e']}/13 bcl={r['b']}/11")
            print(f"    PT={r['pt']}")
            if r['crib']>=14:
                print(f"  *** HIGH HIT {r['crib']}/24 ***")
                print(f"  mask={r['mask']}")

print(f"\nPhase 1: {len(all_masks_12plus)} masks with 12+/24, {len(all_masks_13plus)} with 13+/24 "
      f"(elapsed {time.time()-t0:.1f}s)")
print()

# ── Frequency analysis ─────────────────────────────────────────────────────────
print("Top 30 most frequent null positions in 12+/24 masks:")
print(f"  (out of {len(all_masks_12plus)} masks)")
for pos,freq in position_freq.most_common(30):
    bar='#'*(freq*20//max(1,max(position_freq.values())))
    pct=freq*100//max(1,len(all_masks_12plus))
    print(f"  pos={pos:2d} (CT={CT97[pos]}): {freq:3d}/{len(all_masks_12plus)} ({pct:2d}%) {bar}")
print()

# Positions appearing in >50% of 12+ masks — likely correct
consensus_50 = frozenset(p for p,f in position_freq.items() if f > len(all_masks_12plus)*0.5)
consensus_30 = frozenset(p for p,f in position_freq.items() if f > len(all_masks_12plus)*0.3)
print(f"Consensus (>50%): {len(consensus_50)} positions: {sorted(consensus_50)}")
print(f"Consensus (>30%): {len(consensus_30)} positions: {sorted(consensus_30)}")
print()

# ── Phase 2: SA with consensus positions fixed ────────────────────────────────
print("Phase 2: SA with consensus positions fixed...")

for threshold, fixed in [(0.5, consensus_50), (0.3, consensus_30)]:
    if len(fixed) > N_NULLS: continue
    print(f"  Fixing {len(fixed)} positions (>{threshold*100:.0f}%): {sorted(fixed)}")
    phase2_results=[]
    for restart in range(50):
        r=sa_run(seed=restart*71+100, fixed_set=fixed, steps=300_000, T0=0.5)
        if r: phase2_results.append(r)
        if r and (r['crib']>=13 or restart%10==0):
            print(f"    r={restart:2d}: {r['crib']}/24 ene={r['e']}/13 bcl={r['b']}/11")
            if r['crib']>=14:
                print(f"    *** HIGH HIT {r['crib']}/24 ***")
                print(f"    PT={r['pt']}")
                print(f"    mask={r['mask']}")
    if phase2_results:
        best2=max(phase2_results,key=lambda x:x['crib'])
        print(f"  → Phase 2 best with {threshold*100:.0f}% consensus: {best2['crib']}/24")
        print(f"    PT={best2['pt']}")
    print()

# ── Phase 3: For best 13/24 masks, print full details ─────────────────────────
print("Phase 3: Best masks found:")
if all_masks_13plus:
    all_masks_13plus.sort(key=lambda x:-x['crib'])
    for r in all_masks_13plus[:10]:
        print(f"  {r['crib']}/24 ene={r['e']}/13 bcl={r['b']}/11")
        print(f"  PT  = {r['pt']}")
        print(f"  CT73= {r['ct73']}")
        print(f"  mask= {r['mask']}")
        print()
elif all_masks_12plus:
    best=max(all_masks_12plus,key=lambda x:x['crib'])
    print(f"  Best: {best['crib']}/24")
    print(f"  PT  = {best['pt']}")
    print(f"  mask= {best['mask']}")

elapsed=time.time()-t0
best_crib=max((r['crib'] for r in all_masks_12plus),default=0)
print(f"\nTotal elapsed: {elapsed:.1f}s")
print("verdict:",json.dumps({
    "verdict_status":"promising" if best_crib>=14 else "inconclusive",
    "score":best_crib,
    "summary":f"Consensus null analysis KRYPTOS:KA_vig: best {best_crib}/24",
    "evidence":f"consensus positions: {sorted(consensus_50)[:8]}..." if consensus_50 else "insufficient data",
    "best_plaintext":all_masks_12plus[0]['pt'] if all_masks_12plus else "",
}))
