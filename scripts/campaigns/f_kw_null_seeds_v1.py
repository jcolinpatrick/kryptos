#!/usr/bin/env python3
"""K+W null seed model + intensive SA.

HYPOTHESIS: K and W are the null markers in K4.
- K appears 7 times in non-crib positions (2,31,45,52,77,86,93) — K=KRYPTOS, marks nulls?
- W appears 5 times in non-crib positions (20,36,48,58,74) — W=delimiter
- Together 12 seed nulls; SA fills 12 more

Also: pure K-null model (7 K + 17 more)
Also: tries KOMPASS more intensively (d=7 anomaly suggests period-7 / KOMPASS=7 chars)

The KOMPASS:vig result was 10/24 in v1 (competitive with DEFECTOR:beau at 12/24).
KOMPASS = German for COMPASS = lodestone reference.
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

import json as _json, pathlib as _pl
QG = None
for _p in ['data/english_quadgrams.json', '../data/english_quadgrams.json']:
    try: QG = _json.loads(_pl.Path(_p).read_text()); break
    except FileNotFoundError: pass
QG_FLOOR = -10.0
KEYWORDS = ['KRYPTOS','KOMPASS','DEFECTOR','PARALLAX','ABSCISSA','COLOPHON',
            'BERLIN','CLOCK','SHADOW','SANBORN','K','KR','KRY','KRYPTEIA']
def qg_score(t): return sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t)-3))

def autokey_decrypt(ct73, kw, beau=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,c in enumerate(ct73):
        ci=ord(c)-65; ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b,e,b

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
                best_kw=f"{kw}:{'beau' if beau else 'vig'} ene={e}/13 bcl={b}/11"
    return best_crib,best_sc,best_pt,best_kw,ct73

def score_fast(null_set, kws=('KRYPTOS','KOMPASS','DEFECTOR')):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    best=-1e9
    for kw in kws:
        for beau in (False,True):
            pt=autokey_decrypt(ct73,kw,beau)
            total,e,b=count_crib_hits(pt,ene_s,bcl_s)
            sc=total*200+qg_score(pt)
            if sc>best: best=sc
    return best

def sa_run(seed, fixed_nulls=None, steps=150_000, kws=('KRYPTOS','KOMPASS','DEFECTOR')):
    rng=random.Random(seed)
    if fixed_nulls is None: fixed_nulls=set()
    fixed=frozenset(p for p in fixed_nulls if p in NC_SET)
    pool=[p for p in NON_CRIB if p not in fixed]
    n_extra=N_NULLS-len(fixed)
    if n_extra<0 or n_extra>len(pool): return None
    extra=set(rng.sample(pool,n_extra)); null_set=fixed|extra
    non_null=NC_SET-null_set
    score=score_fast(frozenset(null_set),kws)
    best_sc=score; best_null=frozenset(null_set)
    T0,Tf=300.0,1.0
    for step in range(steps):
        T=T0*(Tf/T0)**(step/steps)
        cands=[p for p in null_set if p not in fixed]
        if not cands or not non_null: break
        out=rng.choice(cands); into=rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}; non_null=(non_null-{into})|{out}
        new_sc=score_fast(frozenset(null_set),kws)
        delta=new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc: best_sc=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}
    crib,sc,pt,kw,ct73=eval_mask(best_null)
    return {'crib':crib,'sc':sc,'pt':pt,'kw':kw,'ct73':ct73,
            'mask':sorted(best_null),'fixed':sorted(fixed),'seed':seed}

# ── Null seeds ────────────────────────────────────────────────────────────────
# Non-crib K positions (K appears at: 2,31,45,52,77,86,93)
K_NULLS = frozenset(i for i in range(N) if CT97[i]=='K' and i not in CRIB_POSITIONS)
# Non-crib W positions
W_NULLS = frozenset([20,36,48,58,74])
# Combined
KW_NULLS = K_NULLS | W_NULLS
# Also try Z (another rare-ish letter at 4 positions: 46,47,70,78 — none crib)
Z_NULLS = frozenset(i for i in range(N) if CT97[i]=='Z' and i not in CRIB_POSITIONS)

print("="*60)
print("K+W NULL SEED HYPOTHESIS + INTENSIVE SA")
print("="*60)
print(f"K positions (non-crib): {sorted(K_NULLS)}")
print(f"W positions (non-crib): {sorted(W_NULLS)}")
print(f"Z positions (non-crib): {sorted(Z_NULLS)}")
print(f"K+W combined ({len(KW_NULLS)} seeds): {sorted(KW_NULLS)}")
print()

t0=time.time(); all_results=[]

# Test 1: K+W seeds
print("--- TEST 1: K+W nulls (12 fixed) ---")
for restart in range(15):
    r=sa_run(seed=restart*7, fixed_nulls=KW_NULLS, steps=150_000)
    if r: all_results.append(r)
    if r and (r['crib']>=10 or restart%4==0):
        print(f"  r={restart:2d}: crib={r['crib']:2d}/24 kw={r['kw']}")
        if r['crib']>=12: print(f"    PT={r['pt']}")

# Test 2: W seeds only (5 fixed) — intensive focus on KOMPASS
print("\n--- TEST 2: W-only seeds (5 fixed) × KOMPASS focus ---")
for restart in range(15):
    r=sa_run(seed=restart*11+1, fixed_nulls=W_NULLS, steps=150_000, kws=('KOMPASS','KRYPTOS','K','KR'))
    if r: all_results.append(r)
    if r and (r['crib']>=10 or restart%4==0):
        print(f"  r={restart:2d}: crib={r['crib']:2d}/24 kw={r['kw']}")
        if r['crib']>=12: print(f"    PT={r['pt']}")

# Test 3: K-only seeds (7 fixed) + d=7 autokey focus
print("\n--- TEST 3: K-only seeds (7 fixed) ---")
for restart in range(10):
    r=sa_run(seed=restart*13+2, fixed_nulls=K_NULLS, steps=120_000)
    if r: all_results.append(r)
    if r and (r['crib']>=10 or restart%3==0):
        print(f"  r={restart:2d}: crib={r['crib']:2d}/24 kw={r['kw']}")
        if r['crib']>=12: print(f"    PT={r['pt']}")

# Test 4: K+W+Z seeds (16 fixed)
print("\n--- TEST 4: K+W+Z seeds (16 fixed), needs only 8 more ---")
KWZ_NULLS = KW_NULLS | Z_NULLS
print(f"K+W+Z={sorted(KWZ_NULLS)} ({len(KWZ_NULLS)} seeds)")
for restart in range(10):
    r=sa_run(seed=restart*17+3, fixed_nulls=KWZ_NULLS, steps=120_000)
    if r: all_results.append(r)
    if r and (r['crib']>=10 or restart%3==0):
        print(f"  r={restart:2d}: crib={r['crib']:2d}/24 kw={r['kw']}")
        if r['crib']>=12: print(f"    PT={r['pt']}")

all_results.sort(key=lambda x:(-x['crib'],-x['sc']))
elapsed=time.time()-t0
print(f"\n=== TOP 5 RESULTS (elapsed {elapsed:.1f}s) ===")
for r in all_results[:5]:
    print(f"  crib={r['crib']:2d}/24  kw={r['kw']}")
    print(f"  PT  = {r['pt']}")
    print(f"  CT73= {r['ct73']}")
    print(f"  mask= {r['mask']}")
    print(f"  fixed={r['fixed']}")
    print()

best=all_results[0] if all_results else None
print("verdict:",json.dumps({
    "verdict_status":"promising" if (best and best['crib']>=14) else "inconclusive",
    "score":best['crib'] if best else 0,
    "summary":f"K+W null seeds: best {best['crib'] if best else 0}/24 crib hits",
    "evidence":f"kw={best['kw'][:40] if best else 'none'} fixed={best['fixed'][:4] if best else []}",
    "best_plaintext":best['pt'] if best else "",
}))
