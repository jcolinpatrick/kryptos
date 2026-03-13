#!/usr/bin/env python3
"""Period-24 Vigenère/Beaufort on null-extracted 73-char text.

KEY INSIGHT:
- Bean proof eliminates periodic sub (p=1-23) on ANY 73-char null extraction
- Period 24 = len(EASTNORTHEAST) + len(BERLINCLOCK) = 13+11 = 24 SURVIVES the proof
- For n1-n2 ≡ 13 (mod 24) [i.e. n1-n2=19 or n1-n2=-5]: all 24 crib positions
  fall in DISTINCT mod-24 slots → key is UNIQUELY DETERMINED by cribs!
- If determined key → English plaintext: SOLVED

Two approaches:
(A) For special (n1,n2) with distinct mod-24 crib positions: compute key directly
(B) SA over all null masks: for each mask, find the best period-24 key via crib
    constraints (may be consistent or contradictory), score resulting PT.
"""

import sys, random, math, time, json, itertools
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97     = CT
N        = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START= 21; BCL_START = 63; PERIOD = 24
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]

import json as _json, pathlib as _pl
QG = None
for _p in ['data/english_quadgrams.json', '../data/english_quadgrams.json']:
    try: QG = _json.loads(_pl.Path(_p).read_text()); break
    except FileNotFoundError: pass
QG_FLOOR = -10.0
def qg_score(t): return sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t)-3))

# ── Core functions ─────────────────────────────────────────────────────────────
def get_crib_constraints(null_set):
    """Return list of (ct73_pos, ct97_val, pt_val) for each crib position."""
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    constraints = []
    for j, ch in enumerate(ENE_WORD):
        pos73 = ENE_START - n1 + j
        constraints.append((pos73, ord(CT97[ENE_START+j])-65, ord(ch)-65))
    for j, ch in enumerate(BCL_WORD):
        pos73 = BCL_START - n2 + j
        constraints.append((pos73, ord(CT97[BCL_START+j])-65, ord(ch)-65))
    return constraints

def derive_period24_key(null_set, variant='beau'):
    """Derive period-24 key from crib constraints. Returns (key_list, consistent, n_conflicts)."""
    constr = get_crib_constraints(null_set)
    key = [None] * PERIOD
    n_conflicts = 0
    for pos73, ct_val, pt_val in constr:
        slot = pos73 % PERIOD
        if variant == 'beau':
            k = (pt_val + ct_val) % 26  # Beaufort: PT = KEY - CT, so KEY = PT+CT
        else:
            k = (ct_val - pt_val) % 26  # Vig: PT = CT - KEY, so KEY = CT-PT
        if key[slot] is None:
            key[slot] = k
        elif key[slot] != k:
            n_conflicts += 1
    # Fill unset slots with 0 (unknown)
    for i in range(PERIOD):
        if key[i] is None:
            key[i] = 0  # unknown slot
    return key, n_conflicts == 0, n_conflicts

def apply_period_cipher(ct73, key, variant='beau'):
    """Apply periodic Vigenère/Beaufort with given key."""
    pt = []
    for i, c in enumerate(ct73):
        ci = ord(c)-65; k = key[i % PERIOD]
        if variant == 'beau':
            pt.append(chr((k - ci) % 26 + 65))
        else:
            pt.append(chr((ci - k) % 26 + 65))
    return ''.join(pt)

def eval_mask_p24(null_set):
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    n1   = sum(1 for p in null_set if p < ENE_START)
    n2   = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2

    best_crib = 0; best_sc = -1e9; best_pt = ''; best_kw = ''
    for variant in ('beau', 'vig'):
        key, consistent, n_conf = derive_period24_key(null_set, variant)
        if n_conf > 6: continue  # Too many conflicts — skip
        pt  = apply_period_cipher(ct73, key, variant)
        # Crib hits
        e = sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
        b = sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
        ch  = e + b
        sc  = ch*200 + qg_score(pt) - n_conf*100  # penalise conflicts
        if sc > best_sc:
            best_sc = sc; best_crib = ch; best_pt = pt
            key_str = ''.join(chr(k+65) for k in key)
            best_kw = f"p24:{variant} key={key_str} conf={n_conf}"
    return best_crib, best_sc, best_pt, best_kw, ct73

def score_fast_p24(null_set):
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    best = -1e9
    for variant in ('beau', 'vig'):
        key, _, n_conf = derive_period24_key(null_set, variant)
        if n_conf > 4: continue
        pt  = apply_period_cipher(ct73, key, variant)
        sc  = qg_score(pt) - n_conf*100
        if sc > best: best = sc
    return best

# ── Part A: Special (n1-n2 ≡ -5 mod 24) analysis ────────────────────────────
print("="*60)
print("PERIOD-24 NULL MASK ATTACK")
print("="*60)
print("Part A: Cases where bcl_s - ene_s ≡ 13 (mod 24)")
print("       → all 24 crib positions in DISTINCT mod-24 slots")
print("       → key UNIQUELY determined by cribs")
print()

# Check which (n1,n2) give distinct mod-24 slots
# bcl_s - ene_s = (63-n2) - (21-n1) = 42 + n1 - n2 ≡ 13 (mod 24) → n1-n2 ≡ -29 ≡ 19 (mod 24)
# → n1-n2 ∈ {19, -5} in feasible range
distinct_combos = []
for n1 in range(0, 22):   # seg1 has 21 positions max
    for n2 in range(0, 30):  # n2 total before BCL
        extra = n2 - n1  # nulls in seg2 (positions 34-62)
        if extra < 0 or extra > 29: continue
        n3 = N_NULLS - n2  # nulls in seg3
        if n3 < 0 or n3 > 23: continue
        ene_s = ENE_START - n1; bcl_s = BCL_START - n2
        if ene_s < 0 or bcl_s < 0 or ene_s+13 > N_PT or bcl_s+11 > N_PT: continue
        gap = (bcl_s - ene_s) % PERIOD
        if gap == 13:
            distinct_combos.append((n1, n2, n3, ene_s, bcl_s))

print(f"Valid (n1,n2,n3) triples with gap≡13: {len(distinct_combos)}")
print()

# For each, sample null masks and compute key
t0 = time.time(); a_results = []
for n1, n2, n3, ene_s, bcl_s in distinct_combos[:50]:
    seg1_all = list(range(0, 21))
    seg2_all = list(range(34, 63))
    seg3_all = list(range(74, 97))
    extra = n2 - n1

    # Try 5 random masks for each (n1,n2,n3)
    rng = random.Random(n1*100+n2)
    for trial in range(5):
        try:
            null1 = set(rng.sample(seg1_all, n1))
            null2 = set(rng.sample(seg2_all, extra))
            null3 = set(rng.sample(seg3_all, n3))
            null_set = null1 | null2 | null3
        except ValueError: continue
        if len(null_set) != N_NULLS: continue

        ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
        for variant in ('beau', 'vig'):
            key, consistent, n_conf = derive_period24_key(null_set, variant)
            if not consistent: continue  # Must be perfectly consistent
            pt  = apply_period_cipher(ct73, key, variant)
            e = sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
            b = sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
            ch  = e + b
            sc  = qg_score(pt)
            key_str = ''.join(chr(k+65) for k in key)
            a_results.append((ch, sc, pt, variant, key_str, n1, n2, n3, sorted(null_set)))
            if ch == 24:
                print(f"*** PERFECT 24/24 SOLUTION! ***")
                print(f"kw={key_str} variant={variant} n1={n1} n2={n2} n3={n3}")
                print(f"PT={pt}")
                print(f"mask={sorted(null_set)}")

a_results.sort(key=lambda x:(-x[0],-x[1]))
print(f"Part A results (distinct mod-24, {time.time()-t0:.1f}s):")
for ch,sc,pt,var,key_str,n1,n2,n3,mask in a_results[:5]:
    print(f"  crib={ch}/24 p24:{var} key={key_str} n1={n1} n2={n2} n3={n3}")
    print(f"  PT={pt[:65]}...")

# ── Part B: SA over all null masks ────────────────────────────────────────────
print()
print("Part B: SA over all null masks with p24 objective")
NC_SET = frozenset(NON_CRIB)
W_POS  = frozenset([20, 36, 48, 58, 74])

def sa_p24(seed, fix_w=True, steps=100_000):
    rng = random.Random(seed)
    if fix_w:
        fixed = W_POS & NC_SET
        pool  = [p for p in NON_CRIB if p not in fixed]
        extra = set(rng.sample(pool, N_NULLS-len(fixed)))
        null_set = fixed | extra
    else:
        null_set = set(rng.sample(NON_CRIB, N_NULLS))
    non_null = NC_SET - null_set

    score = score_fast_p24(frozenset(null_set))
    best_sc = score; best_null = frozenset(null_set)
    T0, Tf = 200.0, 1.0
    for step in range(steps):
        T  = T0*(Tf/T0)**(step/steps)
        cands = [p for p in null_set if not(fix_w and p in W_POS)]
        if not cands or not non_null: break
        out  = rng.choice(cands); into = rng.choice(list(non_null))
        null_set=(null_set-{out})|{into}; non_null=(non_null-{into})|{out}
        new_sc = score_fast_p24(frozenset(null_set))
        delta  = new_sc - score
        if delta>0 or rng.random()<math.exp(delta/T):
            score=new_sc
            if score>best_sc: best_sc=score; best_null=frozenset(null_set)
        else:
            null_set=(null_set-{into})|{out}; non_null=(non_null-{out})|{into}
    crib,sc,pt,kw,ct73 = eval_mask_p24(best_null)
    return {'crib':crib,'sc':sc,'pt':pt,'kw':kw,'ct73':ct73,
            'mask':sorted(best_null),'seed':seed,'fix_w':fix_w}

t0 = time.time(); b_results = []
for restart in range(20):
    for fix_w in (True, False):
        r = sa_p24(seed=restart*13+int(fix_w), fix_w=fix_w, steps=100_000)
        b_results.append(r)
        if r['crib'] >= 8 or restart % 4 == 0:
            print(f"  r={restart:2d} w={fix_w} crib={r['crib']:2d}/24 kw={r['kw']}")
            print(f"    PT={r['pt'][:65]}...")
            if r['crib'] >= 18:
                print(f"    *** HIGH HIT {r['crib']}/24 ***")
                print(f"    FULL PT={r['pt']}")
                print(f"    MASK={r['mask']}")

b_results.sort(key=lambda x:(-x['crib'],-x['sc']))
elapsed = time.time()-t0
print(f"\n=== TOP 5 SA RESULTS (elapsed {elapsed:.1f}s) ===")
for r in b_results[:5]:
    print(f"  crib={r['crib']}/24  kw={r['kw']}")
    print(f"  PT  = {r['pt']}")
    print(f"  mask= {r['mask']}")
    print()

best = b_results[0] if b_results else None
print("verdict:", json.dumps({
    "verdict_status": "promising" if (best and best['crib']>=14) else "inconclusive",
    "score": best['crib'] if best else 0,
    "summary": f"Period-24 null mask: Part A {len(a_results)} trials, best SA {best['crib'] if best else 0}/24",
    "evidence": f"kw={best['kw'][:40] if best else 'none'}",
    "best_plaintext": best['pt'] if best else "",
}))
