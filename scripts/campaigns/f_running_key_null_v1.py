#!/usr/bin/env python3
"""Running-key cipher on null-extracted 73-char text.

KEY INSIGHT:
- Running key eliminated on raw 97-char text (max 7/24 direct, 9/24 with trans)
- BUT: on the null-extracted 73-char text, a different substring of the running
  key would be used (shifted by any offset 0..len(key)-73).
- This creates a new search space: (null_mask × key_source × key_offset × variant)
- Running key sources: K1 PT, K2 PT, K3 PT, K1+K2 PT, K2+K3 PT, K1+K2+K3 PT

Running key cipher: CT[i] = (PT[i] + KEY[i]) mod 26  (Vigenère)
                   CT[i] = (KEY[i] - PT[i]) mod 26  (Beaufort)
where KEY[i] is the i-th letter of the running text.

SA strategy: optimise (null_mask) with fixed (source, offset, variant).
Then: for each (source, offset, variant), inner SA over null_masks.
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

# ── Running key sources ────────────────────────────────────────────────────────
K1_PT = ("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUAN"
         "CEOFIQLUSION")
K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYHUSEDTHEE"
         "ARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANS"
         "MITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLEYKNOW"
         "ABOUTTHISXTHEYSHOULDITSBUIREDOUTTHERESOMEWHEREXWHOKN"
         "OWSTHEEXACTLOCATIONXONLYWWX")
K3_PT = ("SLOWLYDESPARATLYSLOWTHEREMAINSOFPASSAGEDEBRISTHAEN"
         "CUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMB"
         "LINGHANDSIHADEINATINBREACHINTHEX")  # truncated for brevity

# Combined sources (strip spaces, uppercase only alpha)
def clean(s):
    return ''.join(c for c in s.upper() if c.isalpha())

SOURCES = {
    'K1':     clean(K1_PT),
    'K2':     clean(K2_PT),
    'K3':     clean(K3_PT),
    'K1K2':   clean(K1_PT + K2_PT),
    'K2K3':   clean(K2_PT + K3_PT),
    'K1K2K3': clean(K1_PT + K2_PT + K3_PT),
}

# Also include K1-K3 PT derived from their actual full texts
# K1 full PT (62 chars): BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUA NCEOFIQLUSION
K1_FULL = clean("BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION")
# K2 full PT (249 chars): ...
K2_FULL = clean("IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT LOCATION ONLY WW X")
# K3 full PT (336 chars):
K3_FULL = clean("SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS")

SOURCES.update({
    'K1f':      K1_FULL,
    'K2f':      K2_FULL,
    'K3f':      K3_FULL,
    'K1fK2f':   K1_FULL + K2_FULL,
    'K2fK3f':   K2_FULL + K3_FULL,
    'K1fK2fK3f':K1_FULL + K2_FULL + K3_FULL,
})

print("="*60)
print("RUNNING KEY ON NULL-EXTRACTED 73-CHAR TEXT")
print("="*60)
for k,v in SOURCES.items():
    print(f"  {k:12s}: {len(v):3d} chars")
print()

def running_key_decrypt(ct73_az, key_az, beau=False):
    """Decrypt 73-char CT using running key (same length slice)."""
    pt=[]
    for ci,ki in zip(ct73_az, key_az):
        if beau:
            pt.append((ki-ci)%26)
        else:
            pt.append((ci-ki)%26)
    return pt

def count_crib_hits(pt_nums, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD)
          if ene_s+j<N_PT and pt_nums[ene_s+j]==ord(c)-65)
    b=sum(1 for j,c in enumerate(BCL_WORD)
          if bcl_s+j<N_PT and pt_nums[bcl_s+j]==ord(c)-65)
    return e+b, e, b

def score_null_key(null_set, key_nums, beau):
    """Score a null mask with a given running key slice."""
    ct73=''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az=[ord(c)-65 for c in ct73]
    n1=sum(1 for p in null_set if p<ENE_START)
    n2=sum(1 for p in null_set if p<BCL_START)
    ene_s=ENE_START-n1; bcl_s=BCL_START-n2
    pt_nums=running_key_decrypt(ct73_az, key_nums[:len(ct73_az)], beau)
    total,e,b=count_crib_hits(pt_nums,ene_s,bcl_s)
    return total,e,b,''.join(chr(x+65) for x in pt_nums)

# ── Exhaustive scan: for each (source, offset, variant), random sample null masks ──
t0=time.time()
top_results=[]
THRESHOLD=10  # Report results >= this

print("--- Phase 1: Scan (source × offset × variant × random null masks) ---")
total_evals=0
for src_name, src_text in list(SOURCES.items())[:4]:  # First 4 sources for speed
    src_nums=[ord(c)-65 for c in src_text]
    max_offset=max(0, len(src_nums)-N_PT)
    offsets=list(range(0,min(max_offset+1,50),1)) if max_offset<50 else list(range(0,max_offset+1,max(1,max_offset//50)))
    for offset in offsets:
        if offset+N_PT > len(src_nums): continue
        key_nums=src_nums[offset:offset+N_PT]
        for beau in (False,True):
            # Random sample 30 null masks per (source,offset,variant)
            rng=random.Random(offset*37+int(beau)*1000)
            for _ in range(30):
                null_set=frozenset(rng.sample(NON_CRIB,N_NULLS))
                total,e,b,pt=score_null_key(null_set,key_nums,beau)
                total_evals+=1
                if total>=THRESHOLD:
                    top_results.append({
                        'src':src_name,'offset':offset,'beau':beau,
                        'total':total,'e':e,'b':b,'pt':pt,
                        'mask':sorted(null_set)
                    })
                    print(f"  HIT {total}/24 src={src_name} off={offset} {'beau' if beau else 'vig'} ene={e}/13 bcl={b}/11")
                    print(f"  PT={pt}")

print(f"Phase 1: {total_evals} evals in {time.time()-t0:.1f}s. Hits>=10: {len(top_results)}")
print()

# ── SA Phase: for high-scoring (source,offset,variant) configs, run SA on null mask ──
print("--- Phase 2: SA over null mask for best (source,offset,variant) configs ---")

# Enumerate best configs by exhaustive crib scan
def find_best_configs():
    """For each (src, offset, beau), compute max crib hits over W-seeded null mask."""
    W=frozenset([20,36,48,58,74])
    configs=[]
    for src_name, src_text in SOURCES.items():
        src_nums=[ord(c)-65 for c in src_text]
        max_offset=max(0,len(src_nums)-N_PT)
        step=max(1,max_offset//30) if max_offset>30 else 1
        for offset in range(0,max_offset+1,step):
            if offset+N_PT>len(src_nums): continue
            key_nums=src_nums[offset:offset+N_PT]
            for beau in (False,True):
                # Quick test with W-seeded nulls + 19 random
                rng2=random.Random(offset*13+int(beau))
                pool=[p for p in NON_CRIB if p not in W]
                extra=set(rng2.sample(pool,N_NULLS-len(W)))
                ns=W|extra
                total,_,_,_=score_null_key(frozenset(ns),key_nums,beau)
                configs.append((total, src_name, offset, beau, key_nums))
    configs.sort(key=lambda x:-x[0])
    return configs[:20]

best_configs=find_best_configs()
print(f"Top 20 configs by quick scan:")
for total,src,offset,beau,_ in best_configs[:10]:
    print(f"  {total}/24 src={src} off={offset} {'beau' if beau else 'vig'}")

def sa_run_rk(src_name, key_nums, beau, seed, steps=120_000, fix_w=True):
    """SA over null mask with fixed running key."""
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

    score=score_null_key(frozenset(null_set),key_nums,beau)[0]
    best_sc=score; best_null=frozenset(null_set)

    T0=0.5; Tf=0.01
    for step in range(steps):
        T=T0*(Tf/T0)**(step/steps)
        cands=[p for p in null_set if not(fix_w and p in W)]
        if not cands or not non_null: break
        out=rng.choice(cands); into=rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}; non_null=(non_null-{into})|{out}
        new_sc=score_null_key(frozenset(null_set),key_nums,beau)[0]
        delta=new_sc-score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc: best_sc=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}

    total,e,b,pt=score_null_key(best_null,key_nums,beau)
    ct73=''.join(CT97[i] for i in range(N) if i not in best_null)
    return {'src':src_name,'beau':beau,'total':total,'e':e,'b':b,
            'pt':pt,'ct73':ct73,'mask':sorted(best_null),'seed':seed}

print()
print("Running SA for each top config...")
sa_results=[]
for total,src,offset,beau,key_nums in best_configs[:20]:
    for restart in range(5):
        for fix_w in (True,False):
            r=sa_run_rk(f"{src}@{offset}",key_nums,beau,
                        seed=restart*31+offset+int(fix_w)*1000,
                        fix_w=fix_w)
            sa_results.append(r)
            if r['total']>=10:
                vt='beau' if r['beau'] else 'vig'
                print(f"  HIT {r['total']}/24 src={r['src']}:{vt} ene={r['e']}/13 bcl={r['b']}/11")
                print(f"  PT={r['pt']}")
                if r['total']>=14:
                    print(f"  *** STRONG HIT ***")
                    print(f"  mask={r['mask']}")

sa_results.sort(key=lambda x:-x['total'])
elapsed=time.time()-t0
print(f"\n=== TOP 5 SA RESULTS (elapsed {elapsed:.1f}s) ===")
for r in sa_results[:5]:
    vt='beau' if r['beau'] else 'vig'
    print(f"  {r['total']}/24 src={r['src']}:{vt} ene={r['e']}/13 bcl={r['b']}/11")
    print(f"  PT  = {r['pt']}")
    print(f"  CT73= {r['ct73']}")
    print(f"  mask= {r['mask']}")
    print()

best=sa_results[0] if sa_results else None
print("verdict:",json.dumps({
    "verdict_status":"promising" if (best and best['total']>=14) else "inconclusive",
    "score":best['total'] if best else 0,
    "summary":f"Running key on null-extracted 73: best {best['total'] if best else 0}/24",
    "evidence":f"src={best['src']} {'beau' if best['beau'] else 'vig'}" if best else "none",
    "best_plaintext":best['pt'] if best else "",
}))
