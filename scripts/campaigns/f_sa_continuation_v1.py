#!/usr/bin/env python3
"""SA continuation from best 10/24 mask — DEFECTOR:beau focus.

Starts from the best known 10/24 mask and runs intensive SA to push higher.
Also: local neighborhood exhaustive search around best mask (±1, ±2 swaps).
Tests all keywords, both variants, for the best nearby masks.
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

import json as _json, pathlib as _pl
QG = None
for _p in ['data/english_quadgrams.json', '../data/english_quadgrams.json']:
    try: QG = _json.loads(_pl.Path(_p).read_text()); break
    except FileNotFoundError: pass
if QG is None: raise FileNotFoundError("quadgrams not found")
QG_FLOOR = -10.0

KEYWORDS = ['KRYPTOS','KOMPASS','DEFECTOR','PARALLAX','ABSCISSA','COLOPHON',
            'BERLIN','CLOCK','SHADOW','K','KR','KRY','KRYPTOS','SANBORN',
            'KRYPTEIA','KLEPSYDRA']

def qg_score(t):
    return sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t)-3))

def autokey_decrypt(ct73, kw, beau=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,c in enumerate(ct73):
        ci=ord(c)-65; ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

def eval_mask(null_set):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    best_crib=0; best_sc=-1e9; best_pt=''; best_kw=''
    for kw in KEYWORDS:
        for beau in (False,True):
            pt=autokey_decrypt(ct73,kw,beau)
            total,e,b=count_crib_hits(pt,ene_s,bcl_s)
            sc=total*200+qg_score(pt)
            if sc>best_sc:
                best_sc=sc; best_crib=total; best_pt=pt
                best_kw=f"{kw}:{'beau' if beau else 'vig'}  ene={e}/13 bcl={b}/11"
    return best_crib,best_sc,best_pt,best_kw,ct73

def score_fast(null_set):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    best=-1e9
    for kw in ['KRYPTOS','KOMPASS','DEFECTOR']:
        for beau in (False,True):
            pt=autokey_decrypt(ct73,kw,beau)
            total,e,b=count_crib_hits(pt,ene_s,bcl_s)
            sc=total*200+qg_score(pt)
            if sc>best: best=sc
    return best

# ── Seed mask from best 10/24 result ─────────────────────────────────────────
SEED_MASK = frozenset([9,10,11,12,14,38,41,43,44,46,49,56,58,62,74,75,76,77,81,83,88,89,92,94])
print("="*60)
print("CONTINUATION SA from best 10/24 mask (DEFECTOR:beau)")
print("="*60)
crib,sc,pt,kw,ct73=eval_mask(SEED_MASK)
print(f"Seed: crib={crib}/24 kw={kw}")
print(f"PT  = {pt}")
print(f"CT73= {ct73}")
print()

# ── Neighborhood exhaustive search: swap 1 null ──────────────────────────────
print("--- NEIGHBORHOOD: 1-swap exhaustive ---")
t0=time.time()
best_neighbor = (crib, sc, pt, kw, ct73, SEED_MASK)
nulls_list=sorted(SEED_MASK)
non_null_list=sorted(NC_SET-SEED_MASK)

for out in nulls_list:
    for into in non_null_list:
        new_null=(SEED_MASK-{out})|{into}
        c,s,p,k,c73=eval_mask(new_null)
        if c>best_neighbor[0] or (c==best_neighbor[0] and s>best_neighbor[1]):
            best_neighbor=(c,s,p,k,c73,new_null)
            print(f"  NEW BEST: crib={c}/24 out={out}→{into} kw={k}")
            print(f"  PT={p}")

print(f"1-swap best: crib={best_neighbor[0]}/24 ({time.time()-t0:.1f}s)")
print(f"PT  = {best_neighbor[2]}")
print(f"mask= {sorted(best_neighbor[5])}")
print()

# ── Intensive SA from seed mask ───────────────────────────────────────────────
print("--- INTENSIVE SA from seed mask (200K steps × 10 restarts) ---")
t0=time.time()
results=[]
for restart in range(10):
    rng=random.Random(restart*97)
    null_set=set(SEED_MASK)
    non_null=set(NON_CRIB)-null_set
    score=score_fast(frozenset(null_set))
    best_sc_sa=score; best_null=frozenset(null_set)
    T0,Tf=300.0,1.0
    for step in range(200_000):
        T=T0*(Tf/T0)**(step/200_000)
        out=rng.choice(list(null_set)); into=rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}; non_null=(non_null-{into})|{out}
        new_sc=score_fast(frozenset(null_set))
        delta=new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc_sa: best_sc_sa=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}
    c,s,p,k,c73=eval_mask(best_null)
    results.append((c,s,p,k,c73,sorted(best_null),restart))
    print(f"  restart={restart}: crib={c}/24 kw={k}")
    print(f"    PT={p[:65]}...")
    if c>=12:
        print(f"    *** STRONG HIT {c}/24 ***  FULL: {p}")
        print(f"    MASK: {sorted(best_null)}")

results.sort(key=lambda x:(-x[0],-x[1]))
elapsed=time.time()-t0
print(f"\n=== TOP 3 continuation SA ({elapsed:.1f}s) ===")
for c,s,p,k,c73,mask,seed in results[:3]:
    print(f"  crib={c}/24  kw={k}  seed={seed}")
    print(f"  PT  = {p}")
    print(f"  CT73= {c73}")
    print(f"  mask= {mask}")
    print()

# Also try 2-swap from seed mask best
best_now=results[0]
print("--- 1-swap from SA best ---")
new_seed=frozenset(best_now[5])
if best_now[0]>crib:
    for out in best_now[5]:
        for into in sorted(NC_SET-new_seed)[:20]:  # only top 20 for speed
            new_null=(new_seed-{out})|{into}
            c2,s2,p2,k2,c73_2=eval_mask(new_null)
            if c2>best_now[0]:
                print(f"  *** IMPROVEMENT {c2}/24: out={out}→{into} kw={k2} ***")
                print(f"  PT={p2}")

best=results[0]
print("\nverdict:",json.dumps({
    "verdict_status":"promising" if best[0]>=12 else "inconclusive",
    "score":best[0],
    "summary":f"Continuation SA best {best[0]}/24 crib hits (DEFECTOR:beau)",
    "evidence":f"kw={best[3]} mask={best[5][:6]}...",
    "best_plaintext":best[2],
}))
