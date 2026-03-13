#!/usr/bin/env python3
"""SA null mask + autokey — quadgram objective (v2).

v1 used IC as SA objective but IC rewards letter-concentration artifacts.
v2 uses quadgram score directly (slower per step but better gradient).
Fewer restarts, more focused on top keywords (KRYPTOS, KOMPASS, DEFECTOR).

Also adds: Quagmire I (monoalphabetic keyword sub) after null removal —
distinct from periodic sub and not yet tested in null-extraction model.
"""

import sys, random, math, time, json
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97     = CT
N        = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START= 21; BCL_START = 63
W_POS    = frozenset([20, 36, 48, 58, 74])
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]

import json as _json, pathlib as _pl
QG = None
for _p in ['data/english_quadgrams.json', '../data/english_quadgrams.json']:
    try: QG = _json.loads(_pl.Path(_p).read_text()); break
    except FileNotFoundError: pass
if QG is None: raise FileNotFoundError("quadgrams not found")
QG_FLOOR = -10.0

KEYWORDS = ['KRYPTOS', 'KOMPASS', 'DEFECTOR', 'PARALLAX', 'ABSCISSA',
            'BERLIN', 'CLOCK', 'SHADOW', 'K', 'KR', 'KRY']

def qg_score(t):
    return sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t) - 3))

def ic(t):
    c = [0]*26
    for ch in t: c[ord(ch)-65] += 1
    n = len(t)
    return sum(x*(x-1) for x in c) / (n*(n-1)) if n > 1 else 0.0

def autokey_decrypt(ct73, kw, beaufort=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,c in enumerate(ct73):
        ci=ord(c)-65; ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beaufort else (ci-ki))%26+65))
    return ''.join(pt)

def keyed_mono_decrypt(ct73, kw):
    """Keyed monoalphabetic substitution (Quagmire I).
    Keyword fills the sub alphabet, remainder follows."""
    seen={}; sub=[]
    for c in kw.upper():
        if c not in seen: seen[c]=True; sub.append(c)
    for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if c not in seen: sub.append(c)
    # sub[i] = what AZ-index i decrypts to
    az_to_pt = {i: sub[i] for i in range(26)}
    return ''.join(az_to_pt[ord(c)-65] for c in ct73)

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b

def score_mask_qg(null_set):
    """Main scoring: quadgram over top 3 keywords."""
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    best=-1e9
    for kw in ['KRYPTOS','KOMPASS','DEFECTOR']:
        for beau in (False,True):
            pt=autokey_decrypt(ct73,kw,beau)
            ch=count_crib_hits(pt,ene_s,bcl_s)
            sc=ch*200 + qg_score(pt)
            if sc>best: best=sc
    return best

def eval_mask_full(null_set):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    best_crib=0; best_sc=-1e9; best_pt=''; best_kw=''
    for kw in KEYWORDS:
        for beau in (False,True):
            pt=autokey_decrypt(ct73,kw,beau)
            ch=count_crib_hits(pt,ene_s,bcl_s)
            sc=ch*200+qg_score(pt)
            if sc>best_sc:
                best_sc=sc; best_crib=ch; best_pt=pt
                best_kw=f"{kw}:{'beau' if beau else 'vig'}"
        # Also try keyed mono sub
        pt=keyed_mono_decrypt(ct73,kw)
        ch=count_crib_hits(pt,ene_s,bcl_s)
        sc=ch*200+qg_score(pt)
        if sc>best_sc:
            best_sc=sc; best_crib=ch; best_pt=pt; best_kw=f"{kw}:mono"
    return best_crib,best_sc,best_pt,best_kw,ct73

def sa_run(seed, fix_w=True, steps=80_000):
    rng=random.Random(seed)
    if fix_w:
        fixed=W_POS&frozenset(NON_CRIB)
        pool=[p for p in NON_CRIB if p not in fixed]
        extra=set(rng.sample(pool,N_NULLS-len(fixed)))
        null_set=fixed|extra
    else:
        null_set=set(rng.sample(NON_CRIB,N_NULLS))
    non_null=set(NON_CRIB)-null_set

    score=score_mask_qg(frozenset(null_set))
    best_sc=score; best_null=frozenset(null_set)
    T0,Tf=200.0,2.0

    for step in range(steps):
        T=T0*(Tf/T0)**(step/steps)
        swap_out=[p for p in null_set if not(fix_w and p in W_POS)]
        if not swap_out or not non_null: break
        out=rng.choice(swap_out); into=rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}
        non_null=(non_null-{into})|{out}
        new_sc=score_mask_qg(frozenset(null_set))
        delta=new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc: best_sc=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}

    crib,sc,pt,kw,ct73=eval_mask_full(best_null)
    return {'crib':crib,'sc':sc,'pt':pt,'kw':kw,
            'mask':sorted(best_null),'ct73':ct73,'fix_w':fix_w,'seed':seed}

if __name__=='__main__':
    print("="*60)
    print("SA NULL MASK + AUTOKEY (v2: quadgram objective)")
    print("="*60)
    print(f"CT97={CT97}")
    t0=time.time(); results=[]

    for restart in range(15):
        for fix_w in (True,False):
            r=sa_run(seed=restart*11+int(fix_w),fix_w=fix_w,steps=80_000)
            results.append(r)
            if r['crib']>=6 or restart%3==0:
                print(f"  r={restart:2d} w={fix_w} crib={r['crib']:2d}/24 kw={r['kw']}")
                print(f"    PT={r['pt'][:65]}...")
                if r['crib']>=10:
                    print(f"    *** HIGH HIT {r['crib']}/24 ***  FULL: {r['pt']}")
                    print(f"    MASK: {r['mask']}")

    results.sort(key=lambda x:(-x['crib'],-x['sc']))
    elapsed=time.time()-t0
    print(f"\n=== TOP 5 (elapsed {elapsed:.1f}s) ===")
    for r in results[:5]:
        print(f"  crib={r['crib']:2d}/24  kw={r['kw']}  fix_w={r['fix_w']}")
        print(f"  PT  = {r['pt']}")
        print(f"  mask= {r['mask']}")
        print(f"  ct73= {r['ct73']}")
        print()

    best=results[0]
    print("verdict:",json.dumps({
        "verdict_status":"inconclusive","score":best['crib'],
        "summary":f"SA null+autokey v2 best {best['crib']}/24 crib hits",
        "evidence":f"kw={best['kw']}",
        "best_plaintext":best['pt'],
    }))
