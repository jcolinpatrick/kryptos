#!/usr/bin/env python3
"""K2 coordinate numbers as null position hints + SA fill.

From memory: K2 encodes K4 structural constants.
Numbers from "38°57'6.5"N 77°8'44"W":
  38, 57, 6, 5, 77, 8, 44  (all non-crib!)

These 7 positions may be structural nulls. SA fills remaining 17.
Also tests: expanded K2-derived sets (mod-97 arithmetic, digit splits, etc.)

Script 2 of 2: focused on K2-coordinate null-position hypothesis.
"""

import sys, random, math, time, json, itertools
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

# ── Shared constants ──────────────────────────────────────────────────────────
CT97      = CT
N         = 97; N_NULLS = 24; N_PT = 73
ENE_WORD  = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63
NON_CRIB  = [i for i in range(N) if i not in CRIB_POSITIONS]
W_POS     = frozenset([20, 36, 48, 58, 74])

import json as _json, pathlib as _pl
QG = None
for _p in ['data/english_quadgrams.json', '../data/english_quadgrams.json']:
    try: QG = _json.loads(_pl.Path(_p).read_text()); break
    except FileNotFoundError: pass
if QG is None: raise FileNotFoundError("quadgrams not found")
QG_FLOOR = -10.0

KEYWORDS = ['KRYPTOS','KOMPASS','DEFECTOR','PARALLAX','COLOPHON',
            'ABSCISSA','BERLIN','CLOCK','SHADOW','SANBORN','K','KR','KRY']

def qg_score(t): return sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t)-3))
def ic(t):
    c = [0]*26
    for ch in t: c[ord(ch)-65] += 1
    n = len(t)
    return sum(x*(x-1) for x in c) / (n*(n-1)) if n>1 else 0.0

def autokey_decrypt(ct73, kw, beaufort=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,c in enumerate(ct73):
        ci=ord(c)-65; ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beaufort else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e = sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b = sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b

def eval_mask(null_set):
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    n1   = sum(1 for p in null_set if p<ENE_START)
    n2   = sum(1 for p in null_set if p<BCL_START)
    ene_s = ENE_START-n1; bcl_s = BCL_START-n2
    best_crib=0; best_sc=-1e9; best_pt=''; best_kw=''
    for kw in KEYWORDS:
        for beau in (False,True):
            pt  = autokey_decrypt(ct73, kw, beau)
            ch  = count_crib_hits(pt, ene_s, bcl_s)
            sc  = ch*100 + qg_score(pt)/N_PT
            if sc>best_sc: best_sc=sc; best_crib=ch; best_pt=pt; best_kw=f"{kw}:{'beau' if beau else 'vig'}"
    return best_crib, best_sc, best_pt, best_kw, ct73

def fast_ic(null_set):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    return ic(autokey_decrypt(ct73,'KRYPTOS',False))

def sa_fill(seed, fixed_nulls, steps=100_000):
    """SA to fill remaining nulls given a fixed seed set."""
    rng = random.Random(seed)
    fixed = frozenset(p for p in fixed_nulls if p in set(NON_CRIB))
    n_extra = N_NULLS - len(fixed)
    if n_extra < 0:
        return None
    pool_list = [p for p in NON_CRIB if p not in fixed]
    if n_extra > len(pool_list):
        return None
    extra     = set(rng.sample(pool_list, n_extra))
    null_set  = fixed | extra
    non_null  = set(NON_CRIB) - null_set
    score     = fast_ic(null_set)
    best_ic   = score; best_null = frozenset(null_set)
    T0,Tf = 0.005,0.00008
    for step in range(steps):
        T = T0*(Tf/T0)**(step/steps)
        swap_out = [p for p in null_set if p not in fixed]
        if not swap_out or not non_null: break
        out  = rng.choice(swap_out)
        into = rng.choice(list(non_null))
        null_set    = (null_set  -{out}) |{into}
        non_null    = (non_null  -{into})|{out}
        new_sc = fast_ic(null_set)
        delta = new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_ic: best_ic=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}
    crib,sc,pt,kw,ct73=eval_mask(best_null)
    return {'ic':best_ic,'crib':crib,'sc':sc,'pt':pt,'kw':kw,
            'mask':sorted(best_null),'ct73':ct73,'fixed':sorted(fixed)}

# ── K2-derived null candidate sets ───────────────────────────────────────────
K2_NUMS = [38, 57, 6, 5, 77, 8, 44]   # raw coordinate digits/values

# Expanded: digit splits, mod arithmetic, sums/products
K2_EXPANDED = set(K2_NUMS)
K2_EXPANDED.update([3, 7, 74, 44, 8, 57-38, 38+57-97])  # differences
K2_EXPANDED.update([(38+57)%97, (6+5)%97, (77+8)%97, (8+44)%97])
K2_EXPANDED.update([38*57%97, 6*5%97, 77*8%97, 8*44%97])  # products mod 97
K2_EXPANDED.update([38**2%97, 57**2%97])   # squares mod 97 (mod-73 chain)
# Remove crib positions
K2_VALID = sorted(p for p in K2_EXPANDED if p in set(NON_CRIB))

print("=" * 60)
print("K2 COORDINATE NULL POSITION HYPOTHESIS")
print("=" * 60)
print(f"CT97 = {CT97}")
print(f"\nRaw K2 numbers:        {K2_NUMS}")
print(f"All non-crib K2 valid: {K2_VALID}")
print(f"  ({len(K2_VALID)} candidates; need {N_NULLS} total)")
print()

# ── Test 1: K2-seed subsets of size 7 (all raw K2 positions) ─────────────────
print("--- TEST 1: Fix raw K2={} as nulls, SA fills 17 more ---".format(K2_NUMS[:7]))
t0 = time.time()
results = []
for restart in range(12):
    r = sa_fill(seed=restart*17, fixed_nulls=set(K2_NUMS), steps=120_000)
    if r: results.append(r)
results.sort(key=lambda x:(-x['crib'],-x['ic']))
print(f"  Best: crib={results[0]['crib']}/24 ic={results[0]['ic']:.5f} kw={results[0]['kw']}")
print(f"  PT  = {results[0]['pt']}")
print(f"  mask= {results[0]['mask']}")

# ── Test 2: K2 + W positions (12 fixed), SA fills 12 more ────────────────────
k2_w = set(K2_NUMS) | (W_POS & set(NON_CRIB))
print(f"\n--- TEST 2: Fix K2+W={sorted(k2_w)} ({len(k2_w)} fixed), SA fills rest ---")
results2 = []
for restart in range(12):
    r = sa_fill(seed=restart*19+5, fixed_nulls=k2_w, steps=120_000)
    if r: results2.append(r)
results2.sort(key=lambda x:(-x['crib'],-x['ic']))
print(f"  Best: crib={results2[0]['crib']}/24 ic={results2[0]['ic']:.5f} kw={results2[0]['kw']}")
print(f"  PT  = {results2[0]['pt']}")
print(f"  mask= {results2[0]['mask']}")

# ── Test 3: Expanded K2 set (all valid non-crib), SA fills rest ───────────────
print(f"\n--- TEST 3: Fix expanded K2={K2_VALID} ({len(K2_VALID)} fixed), SA fills rest ---")
results3 = []
for restart in range(10):
    r = sa_fill(seed=restart*23+3, fixed_nulls=set(K2_VALID), steps=120_000)
    if r: results3.append(r)
results3.sort(key=lambda x:(-x['crib'],-x['ic']))
if results3:
    print(f"  Best: crib={results3[0]['crib']}/24 ic={results3[0]['ic']:.5f} kw={results3[0]['kw']}")
    print(f"  PT  = {results3[0]['pt']}")
    print(f"  mask= {results3[0]['mask']}")

# ── Test 4: Mod-73 squaring chain positions (38²≡57, 57²≡38, mod 97) ─────────
# mod-73: 38²=1444=73*19+57 → 57; 57²=3249=73*44+37 → 37 mod 73 = position 37
# These are the specific arithmetic chain from K2 analysis
mod73_chain = set()
v = 38
for _ in range(10):
    mod73_chain.add(v)
    v = (v*v) % 73
print(f"\n--- TEST 4: Mod-73 squaring chain positions={sorted(mod73_chain)} ---")
chain_valid = [p for p in mod73_chain if p in set(NON_CRIB)]
print(f"  Non-crib valid: {chain_valid}")
results4 = []
for restart in range(10):
    r = sa_fill(seed=restart*31+7, fixed_nulls=set(chain_valid), steps=120_000)
    if r: results4.append(r)
results4.sort(key=lambda x:(-x['crib'],-x['ic']))
if results4:
    print(f"  Best: crib={results4[0]['crib']}/24 ic={results4[0]['ic']:.5f} kw={results4[0]['kw']}")
    print(f"  PT  = {results4[0]['pt']}")

# ── Summary ───────────────────────────────────────────────────────────────────
all_results = results + results2 + results3 + results4
all_results.sort(key=lambda x:(-x['crib'],-x['ic']))
elapsed = time.time()-t0
print(f"\n=== TOP 3 OVERALL (elapsed {elapsed:.1f}s) ===")
for r in all_results[:3]:
    print(f"  crib={r['crib']:2d}/24  ic={r['ic']:.5f}  kw={r['kw']}")
    print(f"  PT  = {r['pt']}")
    print(f"  mask= {r['mask']}")
    print(f"  fixed={r['fixed']}")
    print()

best = all_results[0]
print("verdict:", json.dumps({
    "verdict_status": "inconclusive",
    "score": best['crib'],
    "summary": f"K2-guided null+autokey: best {best['crib']}/24 crib hits",
    "evidence": f"ic={best['ic']:.5f} kw={best['kw']} fixed={best['fixed'][:5]}",
    "best_plaintext": best['pt'],
}))
