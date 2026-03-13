#!/usr/bin/env python3
"""Intensive SA for KRYPTOS/ABSCISSA:KA_vig (corrected) on null-extracted 73-char.

HYPOTHESIS: K4 uses the SAME cipher as K1 and K2, just with autokey instead of periodic:
  K1: KA Vigenère (periodic), keyword = PALIMPSEST
  K2: KA Vigenère (periodic), keyword = ABSCISSA
  K4: KA Vigenère (AUTOKEY), keyword = KRYPTOS (or ABSCISSA, PARALLAX, COLOPHON...)

Why this makes sense:
  - K1-K3 all used the KA tableau (KRYPTOSABCDEFGHIJLMNQUVWXZ)
  - Bean proof eliminates periodic sub → autokey is the natural non-periodic extension
  - KRYPTOS is both the sculpture name AND the base of the KA alphabet
  - KRYPTOS:KA_vig (corrected) already shows 12/24 in early SA runs

Corrected KA autokey:
  ct73_ka = AZ→KA map of CT73
  key_ka: kw[i] in KA for i<L, else pt_ka_indices[i-L] for i>=L
  pt_ka = (ct73_ka - key_ka) mod 26  [Vigenère]
  pt_ka = (key_ka - ct73_ka) mod 26  [Beaufort]
  output letter = KA_STR[pt_ka]

Tests:
  1. KRYPTOS:KA_vig — most likely if K4 follows K1/K2 pattern
  2. KRYPTOS:KA_beau — Beaufort variant
  3. ABSCISSA:KA_vig — ABSCISSA was K2 keyword
  4. PARALLAX:KA_vig — prominent candidate
  5. COLOPHON:KA_vig — another candidate
  6. All above with fix_w=True and fix_w=False

For each candidate, run 80 SA restarts × 400K steps to search null mask space.
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
    """Corrected KA autokey: pt_ka_indices feed back directly."""
    ct73_ka = [AZ_TO_KA[ci] for ci in ct73_az]
    kw_ka   = [KA_IDX[c] for c in kw.upper() if c in KA_IDX]
    L        = len(kw_ka)
    pt_ka_indices = []
    pt_output     = []
    for i, cki in enumerate(ct73_ka):
        ki = kw_ka[i] if i < L else pt_ka_indices[i - L]
        pt_ki = ((ki - cki) if beau else (cki - ki)) % 26
        pt_ka_indices.append(pt_ki)
        pt_output.append(KA_STR[pt_ki])
    return ''.join(pt_output)

def autokey_decrypt_az(ct73_az, kw, beau=False):
    """Standard AZ autokey for comparison."""
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct73_az):
        ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

# ── Candidates: (keyword, beau, description) ──────────────────────────────────
CANDIDATES = [
    # Primary hypothesis
    ('KRYPTOS',   False, 'KA_vig'),
    ('KRYPTOS',   True,  'KA_beau'),
    # K2 keyword
    ('ABSCISSA',  False, 'KA_vig'),
    ('ABSCISSA',  True,  'KA_beau'),
    # Other prominent keywords
    ('PARALLAX',  False, 'KA_vig'),
    ('COLOPHON',  False, 'KA_vig'),
    ('KOMPASS',   False, 'KA_vig'),
    ('KOMPASS',   True,  'KA_beau'),
    ('DEFECTOR',  False, 'KA_vig'),
    ('DEFECTOR',  True,  'KA_beau'),
    # AZ variants for comparison
    ('KRYPTOS',   False, 'AZ_vig'),
    ('KRYPTOS',   True,  'AZ_beau'),
    ('DEFECTOR',  True,  'AZ_beau'),  # Previously best
]

def score_fast(null_set, kw, beau, is_ka):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    if is_ka:
        pt=autokey_decrypt_ka(ct73_az,kw,beau)
    else:
        pt=autokey_decrypt_az(ct73_az,kw,beau)
    total,_,_=count_crib_hits(pt,ene_s,bcl_s)
    return float(total)

def eval_mask(null_set, kw, beau, is_ka):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    if is_ka:
        pt=autokey_decrypt_ka(ct73_az,kw,beau)
    else:
        pt=autokey_decrypt_az(ct73_az,kw,beau)
    total,e,b=count_crib_hits(pt,ene_s,bcl_s)
    label=f"{'KA' if is_ka else 'AZ'}:{'beau' if beau else 'vig'}"
    return total,e,b,pt,ct73,f"{kw}:{label} ene={e}/13 bcl={b}/11"

def sa_run(seed, kw, beau, is_ka, fix_w=False, steps=400_000, T0=0.5):
    rng=random.Random(seed)
    W=frozenset([20,36,48,58,74])
    if fix_w:
        fixed=W&NC_SET
        pool=[p for p in NON_CRIB if p not in fixed]
        extra=set(rng.sample(pool,N_NULLS-len(fixed)))
        null_set=fixed|extra
    else:
        null_set=set(rng.sample(NON_CRIB,N_NULLS))
    non_null=NC_SET-null_set

    score=score_fast(frozenset(null_set),kw,beau,is_ka)
    best_sc=score; best_null=frozenset(null_set)

    Tf=0.01
    for step in range(steps):
        T=T0*(Tf/T0)**(step/steps)
        cands=[p for p in null_set if not(fix_w and p in W)]
        if not cands or not non_null: break
        out=rng.choice(cands); into=rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}; non_null=(non_null-{into})|{out}
        new_sc=score_fast(frozenset(null_set),kw,beau,is_ka)
        delta=new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc: best_sc=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}

    total,e,b,pt,ct73,kw_label=eval_mask(best_null,kw,beau,is_ka)
    return {'crib':total,'e':e,'b':b,'pt':pt,'ct73':ct73,'kw':kw_label,
            'mask':sorted(best_null),'seed':seed,'fix_w':fix_w}

print("="*60)
print("INTENSIVE KA/AZ AUTOKEY SA — KRYPTOS/ABSCISSA/PARALLAX")
print("="*60)
print(f"CT97={CT97}")
print(f"Candidates: {len(CANDIDATES)}")
print()

t0=time.time(); all_results=[]

for kw, beau, label in CANDIDATES:
    is_ka = label.startswith('KA')
    print(f"=== {kw}:{label} ===")
    cand_results=[]
    for restart in range(50):
        for fix_w in (True,False):
            r=sa_run(seed=restart*41+int(fix_w)+hash(kw)%1000,
                     kw=kw,beau=beau,is_ka=is_ka,fix_w=fix_w,steps=400_000)
            cand_results.append(r); all_results.append(r)
            if r['crib']>=12:
                print(f"  r={restart:2d} w={fix_w} {r['crib']:2d}/24 {r['kw']}")
                if r['crib']>=15:
                    print(f"  *** HIGH {r['crib']}/24 ***")
                    print(f"  PT  = {r['pt']}")
                    print(f"  CT73= {r['ct73']}")
                    print(f"  mask= {r['mask']}")
    best_c=max(cand_results,key=lambda x:x['crib'])
    print(f"  → Best for {kw}:{label}: {best_c['crib']}/24 ene={best_c['e']}/13 bcl={best_c['b']}/11")
    print(f"  PT={best_c['pt']}")
    print()

all_results.sort(key=lambda x:-x['crib'])
elapsed=time.time()-t0
print(f"\n=== TOP 10 RESULTS (elapsed {elapsed:.1f}s) ===")
for r in all_results[:10]:
    print(f"  {r['crib']:2d}/24  {r['kw']}")
    print(f"  PT  = {r['pt']}")
    print(f"  CT73= {r['ct73']}")
    print(f"  mask= {r['mask']}")
    print()

best=all_results[0]
print("verdict:",json.dumps({
    "verdict_status":"promising" if best['crib']>=16 else "inconclusive",
    "score":best['crib'],
    "summary":f"Intensive KA vig SA: best {best['crib']}/24",
    "evidence":f"kw={best['kw'][:50]}",
    "best_plaintext":best['pt'],
}))
