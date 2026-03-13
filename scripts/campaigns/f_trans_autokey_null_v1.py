#!/usr/bin/env python3
"""Transposition of null-extracted CT73 then autokey decrypt.

KEY INSIGHT:
- MITM proof eliminated: transposition + PERIODIC sub (p=2-20) on raw 97 chars
- BUT autokey is non-periodic — the MITM proof does NOT eliminate
  transposition + autokey on null-extracted 73-char text
- This is a completely new search space

Model: CT97 → remove 24 nulls → CT73 → transpose → CT73' → autokey → PT73

SA optimises:
  (a) null_mask (24 positions from NON_CRIB)
  (b) transposition configuration (rail fence depth, columnar width, stride)

Transposition families tested:
  1. Rail fence (depth 2-5) — simple
  2. Columnar transposition (width 2-8, fixed reading order: cols left→right)
  3. Stride cipher (stride k reading, k from 2-10)
  4. Reversal (read CT73 backwards)
  5. Block reversal (reverse within blocks of size b=2-8)
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

KEYWORDS = ['KRYPTOS','KOMPASS','DEFECTOR','PARALLAX','ABSCISSA',
            'BERLIN','CLOCK','SHADOW','K','KR','KRY','KRYPTEIA']

# ── Transpositions ─────────────────────────────────────────────────────────────
def rail_fence_perm(n, depth):
    """Rail fence permutation of length n with given depth.
    Returns permutation p such that transposed[i] = original[p[i]].
    """
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

def columnar_perm(n, width, col_order=None):
    """Columnar transposition: write row-by-row width-wide, read col-by-col.
    col_order: list of column indices to read (default: 0,1,...,width-1)
    """
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start+width, n))))
    if col_order is None: col_order = list(range(width))
    perm = []
    for col in col_order:
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def stride_perm(n, stride):
    """Read every stride-th element, starting from each offset."""
    perm = []
    for start in range(stride):
        for i in range(start, n, stride):
            perm.append(i)
    return perm

def apply_perm(text_list, perm):
    """Reorder text_list by perm: output[i] = input[perm[i]]."""
    return [text_list[p] for p in perm]

def reverse_perm(perm):
    """Given perm where transposed[i]=original[perm[i]], return inverse."""
    inv = [0]*len(perm)
    for i,p in enumerate(perm): inv[p]=i
    return inv

# Pre-compute a variety of transpositions
TRANS_PERMS = {}
n = N_PT  # 73 chars in decrypted plaintext

for d in range(2, 6):
    p = rail_fence_perm(n, d)
    # For decryption: we apply inverse perm to transposed CT to get original CT order
    TRANS_PERMS[f'rail{d}'] = reverse_perm(p)

for w in range(2, 9):
    p = columnar_perm(n, w)
    TRANS_PERMS[f'col{w}'] = reverse_perm(p)

for s in range(2, 10):
    p = stride_perm(n, s)
    TRANS_PERMS[f'stride{s}'] = reverse_perm(p)

# Identity (no transposition)
TRANS_PERMS['id'] = list(range(n))

# Reversal
TRANS_PERMS['rev'] = list(range(n-1,-1,-1))

TRANS_NAMES = list(TRANS_PERMS.keys())
print("="*60)
print("TRANSPOSITION + AUTOKEY ON NULL-EXTRACTED CT73")
print("="*60)
print(f"Transposition families: {len(TRANS_PERMS)}")
print(f"Trans names: {TRANS_NAMES}")
print()

# ── Core cipher ────────────────────────────────────────────────────────────────
def autokey_decrypt_az(ct_list, kw, beau=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct_list):
        ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

def score_null_trans(null_set, trans_perm, kws=('KRYPTOS','KOMPASS','DEFECTOR')):
    """Extract CT73, apply transposition, try all autokey variants, return best crib hits."""
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2

    # Apply transposition: reorder CT73 chars
    ct73_list=[ord(c)-65 for c in ct73]
    if trans_perm is not None:
        ct73_t=[ct73_list[trans_perm[i]] for i in range(N_PT)]
    else:
        ct73_t=ct73_list

    best=0
    for kw in kws:
        for beau in (False,True):
            pt=autokey_decrypt_az(ct73_t,kw,beau)
            total,_,_=count_crib_hits(pt,ene_s,bcl_s)
            if total>best: best=total
    return float(best)

def eval_null_trans(null_set, trans_perm, trans_name):
    """Full evaluation with all keywords."""
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2

    ct73_list=[ord(c)-65 for c in ct73]
    if trans_perm is not None:
        ct73_t=[ct73_list[trans_perm[i]] for i in range(N_PT)]
    else:
        ct73_t=ct73_list

    best_crib=0; best_kw=''; best_pt=''
    for kw in KEYWORDS:
        for beau in (False,True):
            pt=autokey_decrypt_az(ct73_t,kw,beau)
            total,e,b=count_crib_hits(pt,ene_s,bcl_s)
            if total>best_crib:
                best_crib=total; best_pt=pt
                best_kw=f"{kw}:{'beau' if beau else 'vig'} trans={trans_name} ene={e}/13 bcl={b}/11"
    return best_crib,best_kw,best_pt,ct73

# ── SA: jointly optimise null_mask + transposition ─────────────────────────────
def sa_run(seed, fix_w=True, trans_name='id', steps=150_000):
    """SA over null mask with a fixed transposition."""
    rng=random.Random(seed)
    W=frozenset([20,36,48,58,74])
    trans_perm=TRANS_PERMS.get(trans_name)

    if fix_w:
        fixed=W&NC_SET
        pool=[p for p in NON_CRIB if p not in fixed]
        extra=set(rng.sample(pool,N_NULLS-len(fixed)))
        null_set=fixed|extra
    else:
        null_set=set(rng.sample(NON_CRIB,N_NULLS))
    non_null=NC_SET-null_set

    score=score_null_trans(frozenset(null_set),trans_perm)
    best_sc=score; best_null=frozenset(null_set)

    T0=0.3; Tf=0.01
    for step in range(steps):
        T=T0*(Tf/T0)**(step/steps)
        cands=[p for p in null_set if not(fix_w and p in W)]
        if not cands or not non_null: break
        out=rng.choice(cands); into=rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}; non_null=(non_null-{into})|{out}
        new_sc=score_null_trans(frozenset(null_set),trans_perm)
        delta=new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc: best_sc=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}

    crib,kw,pt,ct73=eval_null_trans(best_null,trans_perm,trans_name)
    return {'crib':crib,'kw':kw,'pt':pt,'ct73':ct73,
            'mask':sorted(best_null),'seed':seed,'trans':trans_name,'fix_w':fix_w}

# ── Run: for each transposition type, multiple SA restarts ─────────────────────
t0=time.time(); results=[]

# Priority order: rail fence then columnar then stride then special
PRIORITY_TRANS = (
    ['id']  # baseline
    + [f'rail{d}' for d in range(2,6)]
    + [f'col{w}' for w in range(2,9)]
    + [f'stride{s}' for s in range(2,9)]
    + ['rev']
)

for trans_name in PRIORITY_TRANS:
    print(f"--- Trans={trans_name} ---")
    trans_results=[]
    for restart in range(12):
        for fix_w in (True,False):
            r=sa_run(seed=restart*23+int(fix_w),fix_w=fix_w,
                     trans_name=trans_name,steps=120_000)
            trans_results.append(r); results.append(r)
            if r['crib']>=12:
                print(f"  r={restart:2d} w={fix_w} crib={r['crib']}/24 kw={r['kw']}")
                if r['crib']>=14:
                    print(f"  *** HIGH HIT {r['crib']}/24 ***")
                    print(f"  PT = {r['pt']}")
                    print(f"  mask= {r['mask']}")
    best_t=max(trans_results,key=lambda x:x['crib'])
    if best_t['crib']>=12:
        print(f"  Trans={trans_name} best: {best_t['crib']}/24 kw={best_t['kw']}")
        print(f"  PT={best_t['pt']}")

results.sort(key=lambda x:-x['crib'])
elapsed=time.time()-t0
print(f"\n=== TOP 5 RESULTS (elapsed {elapsed:.1f}s) ===")
for r in results[:5]:
    print(f"  crib={r['crib']:2d}/24  kw={r['kw']}")
    print(f"  PT  = {r['pt']}")
    print(f"  CT73= {r['ct73']}")
    print(f"  mask= {r['mask']}")
    print()

best=results[0]
print("verdict:",json.dumps({
    "verdict_status":"promising" if best['crib']>=16 else "inconclusive",
    "score":best['crib'],
    "summary":f"Trans+autokey on null-extracted: best {best['crib']}/24 trans={best['trans']}",
    "evidence":f"kw={best['kw'][:50]}",
    "best_plaintext":best['pt'],
}))
