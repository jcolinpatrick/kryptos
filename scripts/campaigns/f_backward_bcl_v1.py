#!/usr/bin/env python3
"""Backward constraint propagation from BCL.

KEY INSIGHT:
- BCL CT chars are FIXED (CT97[63..73] = N,Y,P,V,T,T,M,Z,F,P,K)
- For perfect BCL decrypt, the autokey KEY at BCL positions must be specific values
- KEY[bcl_s+j] = PT[bcl_s+j-L] (autokey)
- So PT[bcl_s-L..bcl_s-L+10] must equal required KEY values
- These PT values come from the middle segment CT73 chars
- By propagating backward, we can determine what CT73 must look like

Strategy: for each possible bcl_s (= 63-n2 for n2 in 0..30), propagate
backward to get required PT[bcl_s-8..bcl_s+2], then further backward to
get required CT73, then find null masks that produce that CT73.

Does the same for ENE. Then intersect constraints.

Focuses on DEFECTOR:beau (L=8) which was consistently best in SA runs.
Also tests KRYPTOS:beau (L=7) and KOMPASS:beau (L=7).
"""

import sys, itertools, json, time
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS

CT97     = CT
N        = 97; N_NULLS = 24; N_PT = 73
ENE_WORD = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START= 21; BCL_START = 63
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]
NC_SET   = frozenset(NON_CRIB)

# CT97 values at crib positions (never change)
ENE_CT = [ord(CT97[ENE_START+j])-65 for j in range(13)]  # always F,L,R,V,Q,Q,P,R,N,G,K,S,S
BCL_CT = [ord(CT97[BCL_START+j])-65 for j in range(11)]  # always N,Y,P,V,T,T,M,Z,F,P,K
ENE_PT = [ord(c)-65 for c in ENE_WORD]   # E,A,S,T,N,O,R,T,H,E,A,S,T
BCL_PT = [ord(c)-65 for c in BCL_WORD]   # B,E,R,L,I,N,C,L,O,C,K

print("="*60)
print("BACKWARD CONSTRAINT PROPAGATION FROM CRIB POSITIONS")
print("="*60)
print(f"BCL CT (fixed): {[chr(x+65) for x in BCL_CT]}")
print(f"BCL PT target:  {[chr(x+65) for x in BCL_PT]}")
print()

def beaufort_decrypt_forward(ct73_nums: list, kw: str) -> list:
    """Autokey Beaufort forward decryption."""
    kw_n = [ord(c)-65 for c in kw.upper()]
    L    = len(kw_n)
    pt   = []
    for i, ci in enumerate(ct73_nums):
        ki = kw_n[i] if i < L else pt[i-L]
        pt.append((ki - ci) % 26)
    return pt

def vigenere_decrypt_forward(ct73_nums: list, kw: str) -> list:
    kw_n = [ord(c)-65 for c in kw.upper()]
    L    = len(kw_n)
    pt   = []
    for i, ci in enumerate(ct73_nums):
        ki = kw_n[i] if i < L else pt[i-L]
        pt.append((ci - ki) % 26)
    return pt

# ── Compute required KEY at BCL/ENE for each cipher variant ──────────────────
def compute_required_keys(ct_vals, pt_vals, variant='beau'):
    """Required KEY[i] = PT[i] + CT[i] (Beaufort) or PT[i] - CT[i] (Vig), mod 26."""
    if variant == 'beau':
        return [(p + c) % 26 for p, c in zip(pt_vals, ct_vals)]
    else:
        return [(p - c) % 26 for p, c in zip(pt_vals, ct_vals)]

BCL_KEY_BEAU = compute_required_keys(BCL_CT, BCL_PT, 'beau')
ENE_KEY_BEAU = compute_required_keys(ENE_CT, ENE_PT, 'beau')
BCL_KEY_VIG  = compute_required_keys(BCL_CT, BCL_PT, 'vig')
ENE_KEY_VIG  = compute_required_keys(ENE_CT, ENE_PT, 'vig')

print(f"BCL required KEY (Beau): {[chr(x+65) for x in BCL_KEY_BEAU]}")
print(f"ENE required KEY (Beau): {[chr(x+65) for x in ENE_KEY_BEAU]}")
print(f"BCL required KEY (Vig):  {[chr(x+65) for x in BCL_KEY_VIG]}")
print(f"ENE required KEY (Vig):  {[chr(x+65) for x in ENE_KEY_VIG]}")
print()

# ── For each (n1,n2), derive what PT values are needed BEFORE the cribs ───────
print("="*60)
print("CONSTRAINT ANALYSIS: n1,n2 → required PT before cribs")
print("="*60)

import json as _json, pathlib as _pl
QG = None
for _p in ['data/english_quadgrams.json', '../data/english_quadgrams.json']:
    try: QG = _json.loads(_pl.Path(_p).read_text()); break
    except FileNotFoundError: pass
QG_FLOOR = -10.0
def qg_score(t): return sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t)-3))

def count_crib_hits(pt, ene_s, bcl_s):
    e=sum(1 for j,c in enumerate(ENE_PT) if ene_s+j<N_PT and pt[ene_s+j]==c)
    b=sum(1 for j,c in enumerate(BCL_PT) if bcl_s+j<N_PT and pt[bcl_s+j]==c)
    return e+b, e, b

# For autokey with keyword KW of length L:
# KEY[bcl_s+j] = PT[bcl_s+j-L]  (for bcl_s+j >= L, which is always true here)
# Required PT[bcl_s-L..bcl_s-L+10] = BCL_KEY (for Beaufort/Vig)

def analyze_constraint(kw: str, variant: str, n1: int, n2: int):
    L     = len(kw)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2
    if ene_s < 0 or bcl_s < 0 or ene_s+13 > N_PT or bcl_s+11 > N_PT:
        return None

    bcl_key = BCL_KEY_BEAU if variant=='beau' else BCL_KEY_VIG
    ene_key = ENE_KEY_BEAU if variant=='beau' else ENE_KEY_VIG

    # Required PT at positions feeding into BCL key (bcl_s-L .. bcl_s-L+10)
    bcl_feed_start = bcl_s - L
    # Required PT at positions feeding into ENE key (ene_s-L .. ene_s-L+12)
    ene_feed_start = ene_s - L

    # Check if ene_feed_start overlaps with ENE crib itself (creates circular dep)
    # If ene_feed_start < ene_s (usually, since ene_s-L < ene_s), no circular dep for ENE
    # If bcl_feed_start < bcl_s, no circular dep for BCL

    return {
        'kw': kw, 'variant': variant, 'n1': n1, 'n2': n2,
        'ene_s': ene_s, 'bcl_s': bcl_s,
        'ene_feed_start': ene_feed_start,
        'bcl_feed_start': bcl_feed_start,
        'required_pt_ene_feed': ene_key,  # at positions ene_feed_start..ene_feed_start+12
        'required_pt_bcl_feed': bcl_key,  # at positions bcl_feed_start..bcl_feed_start+10
    }

# Check for keyword/n1/n2 combos where the feed positions are in CT97 range
# that we can control (non-crib positions)
print("Testing DEFECTOR:beau across all feasible (n1,n2) values...")
t0 = time.time()
best_results = []

for kw in ['DEFECTOR', 'KRYPTOS', 'KOMPASS']:
    L = len(kw)
    for variant in ['beau', 'vig']:
        for n1 in range(0, 22):   # nulls before position 21
            for n2 in range(n1, n1+31):  # total nulls before 63
                extra_n2 = n2 - n1  # nulls in positions 21..62 (non-crib only: 34-62)
                # Must have enough non-crib positions in each segment
                seg1_size = 21          # positions 0-20 (all non-crib)
                seg2_size = 29          # positions 34-62 (all non-crib)
                if n1 > seg1_size or extra_n2 > seg2_size: continue
                if n1 + extra_n2 + (N_NULLS - n1 - extra_n2) != N_NULLS: pass
                remaining = N_NULLS - n1 - extra_n2
                seg3_size = 23  # positions 74-96 (all non-crib)
                if remaining < 0 or remaining > seg3_size: continue

                ene_s = ENE_START - n1
                bcl_s = BCL_START - n2
                if ene_s < 0 or bcl_s < 0: continue
                if ene_s + 13 > N_PT or bcl_s + 11 > N_PT: continue

                # For autokey: KEY at ENE[j] = PT[ene_s+j-L]
                # For j=0: ene_feed = ene_s - L. Must be >= 0.
                # If keyword is long enough, early positions use keyword directly
                ene_feed_start = ene_s - L
                bcl_feed_start = bcl_s - L

                if ene_feed_start < 0:
                    # Some ENE key positions come from the keyword itself
                    # That's fine — we just can't control those key values
                    pass

                if bcl_feed_start < 0:
                    continue  # BCL feed positions require keyword to be very long

                # BCL feed positions in CT73: bcl_feed_start .. bcl_feed_start+10
                # These are "free" positions (not in crib range) that we can influence
                # by choosing the null mask in CT97 accordingly

                # Quick check: do the BCL feed positions fall in controllable CT73 range?
                # bcl_feed_start must be in non-crib CT73 range (not ENE or BCL itself)
                if bcl_feed_start >= ene_s and bcl_feed_start < ene_s+13:
                    continue  # Overlaps with ENE — circular dependency
                if bcl_feed_start >= bcl_s:
                    continue  # This can't happen as feed_start < bcl_s

                best_results.append((kw, variant, n1, n2, ene_s, bcl_s,
                                     bcl_feed_start, ene_feed_start))

print(f"Feasible (kw,variant,n1,n2) combos: {len(best_results)}")
print()

# For each feasible combo, build a null mask by selecting which CT97 chars
# appear at each CT73 position (segment by segment), then evaluate
print("--- Generating optimal null masks for each combo ---")
all_masks = []
for combo in best_results[:200]:  # Limit to first 200 for speed
    kw, variant, n1, n2, ene_s, bcl_s, bcl_feed_s, ene_feed_s = combo

    # Segment null counts
    n3 = N_NULLS - n1 - (n2 - n1)

    # Build null mask: take first n1 from seg1, next (n2-n1) from seg2, last n3 from seg3
    seg1 = list(range(0, 21))
    seg2 = list(range(34, 63))
    seg3 = list(range(74, 97))

    # Simple greedy: take last positions as nulls (arbitrary, just to test the (n1,n2,n3) combo)
    nulls1 = set(seg1[:n1])
    nulls2 = set(seg2[:n2-n1])
    nulls3 = set(seg3[:n3])
    null_set = nulls1 | nulls2 | nulls3

    if len(null_set) != N_NULLS: continue

    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
    ct73_nums = [ord(c)-65 for c in ct73]

    if variant == 'beau':
        pt_nums = beaufort_decrypt_forward(ct73_nums, kw)
    else:
        pt_nums = vigenere_decrypt_forward(ct73_nums, kw)

    total, e, b = count_crib_hits(pt_nums, ene_s, bcl_s)
    pt = ''.join(chr(x+65) for x in pt_nums)
    sc = total*200 + qg_score(pt)
    all_masks.append((total, sc, e, b, kw, variant, n1, n2, pt, sorted(null_set)))

all_masks.sort(key=lambda x: (-x[0], -x[1]))
elapsed = time.time()-t0
print(f"({elapsed:.1f}s) Top results from greedy null masks:")
for total,sc,e,b,kw,variant,n1,n2,pt,mask in all_masks[:10]:
    print(f"  crib={total}/24 ene={e}/13 bcl={b}/11 kw={kw}:{variant} n1={n1} n2={n2}")
    print(f"  PT={pt[:65]}...")

best = all_masks[0] if all_masks else None
if best:
    total,sc,e,b,kw,variant,n1,n2,pt,mask = best
    print(f"\nBest greedy: crib={total}/24 kw={kw}:{variant} n1={n1} n2={n2}")
    print(f"PT = {pt}")
    print(f"mask={mask}")

print("\nverdict:", json.dumps({
    "verdict_status": "inconclusive",
    "score": best[0] if best else 0,
    "summary": f"Backward BCL constraint analysis: {len(best_results)} combos, best {best[0] if best else 0}/24",
    "evidence": f"kw={best[4]}:{best[5]} n1={best[6]} n2={best[7]}" if best else "no result",
    "best_plaintext": best[8] if best else "",
}))
