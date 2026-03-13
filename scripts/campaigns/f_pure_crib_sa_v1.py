#!/usr/bin/env python3
"""Pure crib-hit maximisation SA for null mask + autokey.

KEY INSIGHT: K4 PT 'is not standard English' — quadgram scoring REJECTS
correct answers. This script optimises for pure crib hits ONLY.

If any null mask achieves 24/24 crib hits with any autokey keyword, that
is almost certainly the true null mask. The PT around the cribs would then
tell us the true message.

Also: tries KA-alphabet autokey variants (haven't been tested before).
KA = KRYPTOSABCDEFGHIJLMNQUVWXZ

The KA Beaufort: PT_ka = (KEY_ka - CT_ka) % 26 where subscript _ka
means index in the KA alphabet (not standard AZ).
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

# KA alphabet (Kryptos keyed)
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}   # letter → KA index
KA_INV = {i: c for i, c in enumerate(KA_STR)}    # KA index → letter
AZ_TO_KA = [KA_IDX[c] for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']  # AZ→KA index
KA_TO_AZ = [KA_STR.index(chr(i+65)) if chr(i+65) in KA_STR else i
             for i in range(26)]

# Pre-built: for each CT97 letter (AZ index), its KA index
CT97_KA = [KA_IDX[c] for c in CT97]

KEYWORDS = ['KRYPTOS','KOMPASS','DEFECTOR','PARALLAX','ABSCISSA',
            'BERLIN','CLOCK','SHADOW','K','KR','KRY','KRYPTEIA',
            'SANBORN','SCHEIDT','ENIGMA','COLOPHON']

def autokey_decrypt_az(ct73_az, kw, beau=False):
    """Standard AZ autokey Beaufort or Vigenère."""
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct73_az):
        ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def autokey_decrypt_ka(ct73_az, kw, beau=False):
    """KA-alphabet autokey: indices in KA alphabet."""
    # Map ct73 AZ indices to KA indices
    ct73_ka = [AZ_TO_KA[ci] for ci in ct73_az]
    kw_ka   = [KA_IDX[c] for c in kw.upper() if c in KA_IDX]
    L        = len(kw_ka)
    pt_ka    = []
    for i, cki in enumerate(ct73_ka):
        ki = kw_ka[i] if i < L else AZ_TO_KA[ord(pt_ka[i-L])-65]
        pt_ka.append(chr(((ki-cki) if beau else (cki-ki)) % 26 + 65))
        # Note: result is in AZ letters (0-25), to be re-encoded if needed
    return ''.join(pt_ka)

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

def eval_mask(null_set):
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    best_crib=0; best_sc=-1e9; best_pt=''; best_kw=''
    for kw in KEYWORDS:
        for beau in (False,True):
            # AZ autokey
            pt=autokey_decrypt_az(ct73_az,kw,beau)
            total,e,b=count_crib_hits(pt,ene_s,bcl_s)
            if total>best_crib or (total==best_crib and total>0):
                if total>best_crib:
                    best_sc=total; best_crib=total; best_pt=pt
                    best_kw=f"{kw}:{'beau' if beau else 'vig'} ene={e}/13 bcl={b}/11"
            # KA autokey
            pt_ka=autokey_decrypt_ka(ct73_az,kw,beau)
            total_ka,eka,bka=count_crib_hits(pt_ka,ene_s,bcl_s)
            if total_ka>best_crib:
                best_sc=total_ka; best_crib=total_ka; best_pt=pt_ka
                best_kw=f"{kw}:KA_{'beau' if beau else 'vig'} ene={eka}/13 bcl={bka}/11"
    return best_crib,best_sc,best_pt,best_kw,ct73

def score_fast(null_set):
    """Pure crib hits (no quadgram)."""
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    best=0
    for kw in ['KRYPTOS','KOMPASS','DEFECTOR']:
        for beau in (False,True):
            pt=autokey_decrypt_az(ct73_az,kw,beau)
            total,_,_=count_crib_hits(pt,ene_s,bcl_s)
            if total>best: best=total
            pt_ka=autokey_decrypt_ka(ct73_az,kw,beau)
            total_ka,_,_=count_crib_hits(pt_ka,ene_s,bcl_s)
            if total_ka>best: best=total_ka
    return float(best)

def sa_run(seed, fix_w=False, steps=150_000, noise_T=0.3):
    """SA with pure crib hit objective (no quadgram)."""
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

    score=score_fast(frozenset(null_set))
    best_sc=score; best_null=frozenset(null_set)

    # High temperature to escape basins, low to find cribs
    T0=noise_T; Tf=0.01
    for step in range(steps):
        T=T0*(Tf/T0)**(step/steps)
        cands=[p for p in null_set if not(fix_w and p in W)]
        if not cands or not non_null: break
        out=rng.choice(cands); into=rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}; non_null=(non_null-{into})|{out}
        new_sc=score_fast(frozenset(null_set))
        delta=new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc: best_sc=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}
    crib,sc,pt,kw,ct73=eval_mask(best_null)
    return {'crib':crib,'sc':sc,'pt':pt,'kw':kw,'ct73':ct73,
            'mask':sorted(best_null),'seed':seed,'fix_w':fix_w}

if __name__=='__main__':
    print("="*60)
    print("PURE CRIB-HIT SA + KA ALPHABET AUTOKEY VARIANTS")
    print("="*60)
    print(f"CT97={CT97}")
    print(f"Keywords: {KEYWORDS}")
    print(f"Variants: AZ/KA alphabet × Beaufort/Vigenère = 4 combos per keyword")
    print()

    t0=time.time(); results=[]
    for restart in range(25):
        for fix_w in (True,False):
            r=sa_run(seed=restart*17+int(fix_w),fix_w=fix_w,steps=150_000)
            results.append(r)
            if r['crib']>=12 or restart%4==0:
                print(f"  r={restart:2d} w={fix_w} crib={r['crib']:2d}/24 kw={r['kw']}")
                if r['crib']>=14:
                    print(f"  *** HIGH HIT {r['crib']}/24 ***")
                    print(f"  PT = {r['pt']}")
                    print(f"  CT73= {r['ct73']}")
                    print(f"  mask= {r['mask']}")

    results.sort(key=lambda x:(-x['crib'],-x['sc']))
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
        "summary":f"Pure crib SA: best {best['crib']}/24",
        "evidence":f"kw={best['kw'][:40]}",
        "best_plaintext":best['pt'],
    }))
