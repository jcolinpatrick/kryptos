#!/usr/bin/env python3
"""2-swap exhaustive search from KRYPTOS:KA_vig 13/24 seed masks.

MOTIVATION:
- KRYPTOS:KA_vig consistently achieves 13/24 (best among all tested ciphers)
- Theoretical max cross-constraint analysis = 14/24 (KA cross-pairs)
- EASTNORTHEAST L>=13 keywords: ELIMINATED (9/24 practical ceiling,
  fixed CT97 crib values create autokey chain constraint impossible to overcome)
- 2-swap exhaustive from KRYPTOS:KA_vig 13/24 masks: can we reach 14/24?

APPROACH:
1. Run SA (40 restarts x 600K steps) to collect 13/24 masks for KRYPTOS:KA_vig
2. From each 13/24 mask: exhaustive 1-swap then 2-swap
3. Also evaluate KOMPASS:KA_vig and DEFECTOR:KA_vig on each swap candidate
4. Report any improvement to 14+/24

CROSS-CONSTRAINT THEORETICAL MAX FOR KRYPTOS:KA_vig (L=7):
- ENE: 6 cross-pairs all incompatible → max ENE ≤ 7/13
- BCL: 4 cross-pairs all incompatible → max BCL ≤ 7/11
- Total theoretical max = 14/24 (tight bound)
- SA achieves 13/24 reliably → 2-swap may find the last point
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

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_TO_KA = [KA_IDX[c] for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']

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

def autokey_decrypt_az(ct73_az, kw, beau=False):
    pt=[]; kw_n=[ord(c)-65 for c in kw.upper()]; L=len(kw_n)
    for i,ci in enumerate(ct73_az):
        ki=kw_n[i] if i<L else ord(pt[i-L])-65
        pt.append(chr(((ki-ci) if beau else (ci-ki))%26+65))
    return ''.join(pt)

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_WORD) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_WORD) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

# ── Core cipher configurations to evaluate ──────────────────────────────────
CIPHERS = [
    ('KRYPTOS', False, True,  'KRYPTOS:KA_vig'),
    ('KRYPTOS', True,  True,  'KRYPTOS:KA_beau'),
    ('KOMPASS', False, True,  'KOMPASS:KA_vig'),
    ('KOMPASS', True,  True,  'KOMPASS:KA_beau'),
    ('KRYPTOS', False, False, 'KRYPTOS:AZ_vig'),
    ('DEFECTOR',False, False, 'DEFECTOR:AZ_beau'),   # Beaufort = beau=True
    ('DEFECTOR',True,  False, 'DEFECTOR:AZ_vig'),
]
# Fix: DEFECTOR:AZ_beau = beau=True in AZ; swap:
CIPHERS = [
    ('KRYPTOS', False, True,  'KRYPTOS:KA_vig'),
    ('KRYPTOS', True,  True,  'KRYPTOS:KA_beau'),
    ('KOMPASS', False, True,  'KOMPASS:KA_vig'),
    ('KOMPASS', True,  True,  'KOMPASS:KA_beau'),
    ('DEFECTOR',True,  False, 'DEFECTOR:AZ_beau'),
    ('DEFECTOR',False, False, 'DEFECTOR:AZ_vig'),
    ('KRYPTOS', False, False, 'KRYPTOS:AZ_vig'),
    ('KRYPTOS', True,  False, 'KRYPTOS:AZ_beau'),
]

def eval_all(null_set):
    """Evaluate all cipher configs on a given null mask, return best."""
    null_set = frozenset(null_set)
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c)-65 for c in ct73]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    best = None
    for kw, beau, is_ka, label in CIPHERS:
        if is_ka:
            pt = autokey_decrypt_ka(ct73_az, kw, beau)
        else:
            pt = autokey_decrypt_az(ct73_az, kw, beau)
        total, e, b = count_crib_hits(pt, ene_s, bcl_s)
        if best is None or total > best[0]:
            best = (total, e, b, pt, ct73, label)
    return best

def score_ka_vig(null_set):
    """Score KRYPTOS:KA_vig only (fast)."""
    null_set = frozenset(null_set)
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_az = [ord(c)-65 for c in ct73]
    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1; bcl_s = BCL_START - n2
    pt = autokey_decrypt_ka(ct73_az, 'KRYPTOS', False)
    total, _, _ = count_crib_hits(pt, ene_s, bcl_s)
    return float(total)

def sa_run_ka_vig(seed, steps=600_000, T0=0.5):
    """SA run for KRYPTOS:KA_vig, returns mask with score."""
    rng = random.Random(seed)
    null_set = set(rng.sample(NON_CRIB, N_NULLS))
    non_null = NC_SET - null_set
    score = score_ka_vig(frozenset(null_set))
    best_sc = score; best_null = frozenset(null_set)
    Tf = 0.01
    for step in range(steps):
        T = T0 * (Tf/T0) ** (step/steps)
        out = rng.choice(list(null_set))
        into = rng.choice(list(non_null))
        null_set = (null_set - {out}) | {into}
        non_null = (non_null - {into}) | {out}
        new_sc = score_ka_vig(frozenset(null_set))
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta/T):
            score = new_sc
            if score > best_sc: best_sc = score; best_null = frozenset(null_set)
        else:
            null_set = (null_set - {into}) | {out}
            non_null = (non_null - {out}) | {into}
    return best_null, best_sc

print("="*60)
print("2-SWAP EXHAUSTIVE FROM KRYPTOS:KA_vig 13/24 SEEDS")
print("="*60)
print(f"CT97={CT97}")
print()

t0 = time.time()

# ── Phase 1: Collect 13/24 seed masks ───────────────────────────────────────
print("Phase 1: Collecting 13/24 KRYPTOS:KA_vig seed masks (40 restarts x 600K steps)...")
seeds_13 = []
seeds_12 = []
for restart in range(40):
    mask, sc = sa_run_ka_vig(seed=restart*83+7, steps=600_000)
    if sc >= 13:
        seeds_13.append(mask)
        print(f"  r={restart:2d}: {sc:.0f}/24 *** 13+ SEED ***")
    elif sc >= 12:
        seeds_12.append(mask)
    if (restart+1) % 10 == 0:
        print(f"  r={restart:2d}: {sc:.0f}/24  (13+: {len(seeds_13)}, 12+: {len(seeds_12)}, elapsed {time.time()-t0:.0f}s)")

# Use 13/24 seeds if available, else best 12/24
if seeds_13:
    seed_masks = seeds_13[:8]  # use up to 8 seeds
    seed_label = "13/24"
elif seeds_12:
    seed_masks = seeds_12[:8]
    seed_label = "12/24"
else:
    print("  No 12+ seeds found!")
    sys.exit(1)

print(f"\nPhase 1 done: {len(seed_masks)} {seed_label} seeds for 2-swap (elapsed {time.time()-t0:.0f}s)")
print()

# ── Phase 2: 1-swap from each seed ──────────────────────────────────────────
print("Phase 2: Exhaustive 1-swap from each seed...")
improved_seeds = []
for si, null_set in enumerate(seed_masks):
    null_list = sorted(null_set)
    non_null_list = sorted(NC_SET - null_set)
    base_sc = score_ka_vig(null_set)
    best_mask_1 = null_set; best_sc_1 = base_sc
    for out in null_list:
        for into in non_null_list:
            new_mask = (null_set - {out}) | {into}
            sc = score_ka_vig(new_mask)
            if sc > best_sc_1:
                best_sc_1 = sc; best_mask_1 = frozenset(new_mask)
    print(f"  Seed {si}: {base_sc:.0f}→{best_sc_1:.0f}/24 after 1-swap ({len(null_list)*len(non_null_list)} evals)")
    if best_sc_1 >= 14:
        print(f"  *** 14+ IMPROVEMENT! ***")
        r = eval_all(best_mask_1)
        print(f"  Best cipher: {r[5]} score={r[0]}/24 ene={r[1]}/13 bcl={r[2]}/11")
        print(f"  PT  = {r[3]}")
        print(f"  CT73= {r[4]}")
        print(f"  mask= {sorted(best_mask_1)}")
    improved_seeds.append((best_mask_1, best_sc_1))
print()

# Use best 1-swap results as seeds for 2-swap
swap2_seeds = [(m, s) for m, s in improved_seeds if s >= 13]
if not swap2_seeds:
    swap2_seeds = sorted(improved_seeds, key=lambda x: -x[1])[:4]
print(f"Phase 2 done: {len(swap2_seeds)} seeds for 2-swap. Elapsed {time.time()-t0:.0f}s")
print()

# ── Phase 3: 2-swap from best seeds ─────────────────────────────────────────
print("Phase 3: Exhaustive 2-swap...")
all_results = []
for si, (null_set, seed_sc) in enumerate(swap2_seeds[:4]):
    null_list = sorted(null_set)
    non_null_list = sorted(NC_SET - null_set)
    n_null = len(null_list); n_pool = len(non_null_list)
    n_evals = (n_null*(n_null-1)//2) * (n_pool*(n_pool-1)//2)
    print(f"--- Seed {si}: {seed_sc:.0f}/24, {n_null} nulls, {n_pool} candidates ---")
    print(f"  Starting 2-swap ({n_null}×{n_null-1}/2 × {n_pool}×{n_pool-1}/2 = {n_evals} evals)...")
    best_mask = null_set; best_sc = seed_sc
    count = 0
    for i, out1 in enumerate(null_list):
        for out2 in null_list[i+1:]:
            for j, into1 in enumerate(non_null_list):
                for into2 in non_null_list[j+1:]:
                    new_mask = (null_set - {out1, out2}) | {into1, into2}
                    sc = score_ka_vig(new_mask)
                    count += 1
                    if sc > best_sc:
                        best_sc = sc; best_mask = frozenset(new_mask)
                        print(f"  *** IMPROVEMENT: {sc}/24 after {count} evals ***")
                        if sc >= 14:
                            r = eval_all(best_mask)
                            print(f"  Best cipher: {r[5]} score={r[0]}/24 ene={r[1]}/13 bcl={r[2]}/11")
                            print(f"  PT  = {r[3]}")
                            print(f"  CT73= {r[4]}")
                            print(f"  mask= {sorted(best_mask)}")
    elapsed = time.time() - t0
    print(f"  Seed {si} done: {count} evals, best={best_sc:.0f}/24 ({elapsed:.1f}s)")
    all_results.append((best_sc, best_mask))
    if best_sc >= 14:
        print(f"  *** 14+ FOUND! ***")
        r = eval_all(best_mask)
        print(f"  PT  = {r[3]}")
        print(f"  mask= {sorted(best_mask)}")

# ── Results ──────────────────────────────────────────────────────────────────
elapsed = time.time() - t0
all_results.sort(key=lambda x: -x[0])
best_sc, best_mask = all_results[0] if all_results else (0, frozenset())

print(f"\n=== RESULTS (elapsed {elapsed:.1f}s) ===")
if best_sc >= 14:
    print(f"  *** IMPROVEMENT FOUND: {best_sc:.0f}/24 ***")
    r = eval_all(best_mask)
    print(f"  {r[5]} score={r[0]}/24 ene={r[1]}/13 bcl={r[2]}/11")
    print(f"  PT  = {r[3]}")
    print(f"  CT73= {r[4]}")
    print(f"  mask= {sorted(best_mask)}")
else:
    print(f"  No improvement over {best_sc:.0f}/24 found via 2-swap.")

print("verdict:", json.dumps({
    "verdict_status": "promising" if best_sc >= 14 else "inconclusive",
    "score": int(best_sc),
    "summary": f"2-swap from KRYPTOS:KA_vig 13/24 seeds: best {best_sc:.0f}/24",
    "evidence": f"2-swap exhaustive from {len(swap2_seeds)} 13/24 seeds",
    "best_plaintext": eval_all(best_mask)[3] if best_sc >= 14 else "",
}))
