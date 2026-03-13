#!/usr/bin/env python3
"""Long-keyword autokey — theoretical max 24/24 when L >= 13.

KEY MATHEMATICAL INSIGHT:
For an autokey cipher with keyword length L, within a crib of length C:
  - Pairs (j, j+L) within the crib create cross-constraints
  - If BCL_WORD_KA[j1] != (BCL_CT_KA[j2] - BCL_WORD_KA[j2]) mod 26 for pair (j1, j1+L),
    then BCL hits at positions j1 and j1+L are MUTUALLY EXCLUSIVE
  - For most keyword lengths, multiple such incompatible pairs exist

RESULTS:
  - KRYPTOS (L=7):   6 ENE incompatible pairs + 3 BCL = max 15/24
  - DEFECTOR (L=8):  5 ENE incompatible pairs + 3 BCL = max 16/24
  - BERLINCLOCK (L=11): 2 ENE incompatible pairs + 0 BCL = max 22/24
  - EASTNORTHEAST (L=13): 0 ENE pairs + 0 BCL pairs = max 24/24 !!!

PROOF for EASTNORTHEAST (L=13):
  ENE has 13 positions (ene_s to ene_s+12). Cross-pairs (j, j+13): none since j+13 > 12.
  BCL has 11 positions (bcl_s to bcl_s+10). Cross-pairs (j, j+13): none since j+13 > 10.
  Therefore: THEORETICAL MAXIMUM = 24/24.

SCRIPTS tests L=13..26 autokey keywords including:
  - EASTNORTHEAST (13) — most promising
  - BERLINCLOCK (11) — high max (22/24)
  - KRYPTOSABCDE (13, first 13 of KA alphabet)
  - NORTHBYNORTHWEST (16)
  - ABSCISSACOMPASS (15)
  - PALIMPSESTDEFEC (15)
  - Various KA-alphabet versions
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

def autokey_decrypt_az(ct73_az, kw, beau=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct73_az):
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
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

def compute_theoretical_max(kw, beau, is_ka):
    """Compute theoretical max crib hits for this cipher via cross-constraint analysis."""
    kw_n = [ord(c)-65 for c in kw.upper()] if not is_ka else [KA_IDX[c] for c in kw.upper() if c in KA_IDX]
    L = len(kw_n)

    # ENE cross-constraints (positions j and j+L within ENE of length 13)
    ene_incompatible = 0
    for j1 in range(13):
        j2 = j1 + L
        if j2 >= 13: continue  # no constraint
        # Check if compatible
        if is_ka:
            ene_ct_ka = [AZ_TO_KA[ord(c)-65] for c in CT97[ENE_START:ENE_START+13]]
            ene_pt_ka = [KA_IDX[c] for c in ENE_WORD]
            req_j1 = (ene_ct_ka[j2] - ene_pt_ka[j2]) % 26 if not beau else (ene_pt_ka[j2] + ene_ct_ka[j2]) % 26
            if req_j1 != ene_pt_ka[j1]:
                ene_incompatible += 1
        else:
            ene_ct_az = [ord(c)-65 for c in CT97[ENE_START:ENE_START+13]]
            ene_pt_az = [ord(c)-65 for c in ENE_WORD]
            req_j1 = (ene_ct_az[j2] - ene_pt_az[j2]) % 26 if beau else (ene_pt_az[j2] + ene_ct_az[j2]) % 26
            if req_j1 != ene_pt_az[j1]:
                ene_incompatible += 1

    # BCL cross-constraints (positions j and j+L within BCL of length 11)
    bcl_incompatible = 0
    for j1 in range(11):
        j2 = j1 + L
        if j2 >= 11: continue
        if is_ka:
            bcl_ct_ka = [AZ_TO_KA[ord(c)-65] for c in CT97[BCL_START:BCL_START+11]]
            bcl_pt_ka = [KA_IDX[c] for c in BCL_WORD]
            req_j1 = (bcl_ct_ka[j2] - bcl_pt_ka[j2]) % 26 if not beau else (bcl_pt_ka[j2] + bcl_ct_ka[j2]) % 26
            if req_j1 != bcl_pt_ka[j1]:
                bcl_incompatible += 1
        else:
            bcl_ct_az = [ord(c)-65 for c in CT97[BCL_START:BCL_START+11]]
            bcl_pt_az = [ord(c)-65 for c in BCL_WORD]
            req_j1 = (bcl_ct_az[j2] - bcl_pt_az[j2]) % 26 if beau else (bcl_pt_az[j2] + bcl_ct_az[j2]) % 26
            if req_j1 != bcl_pt_az[j1]:
                bcl_incompatible += 1

    # Theoretical max (upper bound): each incompatible pair costs 1 hit
    max_ene = 13 - ene_incompatible
    max_bcl = 11 - bcl_incompatible
    return max_ene, max_bcl, max_ene + max_bcl

# ── Keywords to test (length >= 11) ───────────────────────────────────────────
LONG_KEYWORDS = [
    # Length 13 — CRITICAL: cross-constraints disappear at L=13 for ENE
    ("EASTNORTHEAST",  False, False, "AZ_vig"),   # THE ENE crib itself
    ("EASTNORTHEAST",  True,  False, "AZ_beau"),
    ("EASTNORTHEAST",  False, True,  "KA_vig"),
    ("EASTNORTHEAST",  True,  True,  "KA_beau"),
    # Length 11 — max 22/24 for BCL (no BCL cross-constraints)
    ("BERLINCLOCK",    False, False, "AZ_vig"),
    ("BERLINCLOCK",    True,  False, "AZ_beau"),
    ("BERLINCLOCK",    False, True,  "KA_vig"),
    ("BERLINCLOCK",    True,  True,  "KA_beau"),
    # Length 13 — first 13 of KA alphabet
    ("KRYPTOSABCDEF",  False, True,  "KA_vig"),
    ("KRYPTOSABCDEF",  True,  True,  "KA_beau"),
    # Length 16
    ("NORTHBYNORTHWEST", False, False, "AZ_vig"),
    ("NORTHBYNORTHWEST", True,  False, "AZ_beau"),
    # Length 15
    ("ABSCISSACOMPASS",  False, True, "KA_vig"),
    ("ABSCISSACOMPASS",  True,  True, "KA_beau"),
    # Other long
    ("KRYPTEIAKRYPTOS", False, True,  "KA_vig"),
    ("PALIMPSESTABSCISSA", False, True, "KA_vig"),
    # Combined cribs
    ("EASTNORTHEASTBERLINCLOCK", False, False, "AZ_vig"),
    ("EASTNORTHEASTBERLINCLOCK", True,  False, "AZ_beau"),
    ("EASTNORTHEASTBERLINCLOCK", False, True,  "KA_vig"),
]

print("="*60)
print("LONG-KEYWORD AUTOKEY — THEORETICAL MAX ANALYSIS")
print("="*60)
print(f"CT97={CT97}")
print()

# Print theoretical maximums
print("Theoretical maximum crib hits by keyword length:")
for kw, beau, is_ka, label in LONG_KEYWORDS:
    max_ene, max_bcl, total = compute_theoretical_max(kw, beau, is_ka)
    print(f"  {kw[:20]:20s} (L={len(kw):2d}) {label:8s}: max ENE={max_ene}/13 BCL={max_bcl}/11 TOTAL={total}/24")
print()

def score_fast(null_set, kw, beau, is_ka):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    if is_ka: pt=autokey_decrypt_ka(ct73_az,kw,beau)
    else:     pt=autokey_decrypt_az(ct73_az,kw,beau)
    total,_,_=count_crib_hits(pt,ene_s,bcl_s)
    return float(total)

def eval_mask(null_set, kw, beau, is_ka, label):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    if is_ka: pt=autokey_decrypt_ka(ct73_az,kw,beau)
    else:     pt=autokey_decrypt_az(ct73_az,kw,beau)
    total,e,b=count_crib_hits(pt,ene_s,bcl_s)
    return total,e,b,pt,ct73,f"{kw[:15]}:{label} ene={e}/13 bcl={b}/11"

def sa_run(seed, kw, beau, is_ka, fix_w=False, steps=300_000, T0=0.5):
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

    total,e,b,pt,ct73,kw_label=eval_mask(best_null,kw,beau,is_ka,'')
    return {'crib':total,'e':e,'b':b,'pt':pt,'ct73':ct73,
            'kw':kw_label,'mask':sorted(best_null),'seed':seed}

t0=time.time(); all_results=[]

for kw, beau, is_ka, label in LONG_KEYWORDS:
    max_ene, max_bcl, theory_max = compute_theoretical_max(kw, beau, is_ka)
    print(f"=== {kw[:20]}:{label} (theoretical_max={theory_max}/24) ===")
    kw_results=[]
    n_restarts = 60 if theory_max == 24 else 30  # More for 24/24-capable ciphers
    for restart in range(n_restarts):
        for fix_w in (True,False):
            r=sa_run(seed=restart*47+int(fix_w)+hash(kw)%500,
                     kw=kw,beau=beau,is_ka=is_ka,fix_w=fix_w,steps=300_000)
            kw_results.append(r); all_results.append(r)
            if r['crib'] >= theory_max - 1:
                print(f"  r={restart:2d} w={fix_w} {r['crib']:2d}/24 {r['kw']}")
                if r['crib'] >= 18:
                    print(f"  *** HIGH HIT {r['crib']}/24 ***")
                    print(f"  PT  = {r['pt']}")
                    print(f"  CT73= {r['ct73']}")
                    print(f"  mask= {r['mask']}")
            elif r['crib'] >= 14 or restart%10==0:
                print(f"  r={restart:2d} w={fix_w} {r['crib']:2d}/24 {r['kw']}")
    best_k=max(kw_results,key=lambda x:x['crib'])
    print(f"  → Best: {best_k['crib']}/24 (theory max={theory_max}/24)")
    print(f"  PT={best_k['pt']}")
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
    "verdict_status":"promising" if best['crib']>=18 else "inconclusive",
    "score":best['crib'],
    "summary":f"Long-kw autokey: best {best['crib']}/24",
    "evidence":f"kw={best['kw'][:50]}",
    "best_plaintext":best['pt'],
}))
