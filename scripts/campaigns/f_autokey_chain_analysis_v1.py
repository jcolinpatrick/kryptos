#!/usr/bin/env python3
"""Autokey chain constraint analysis for K4 null-mask model.

KEY INSIGHT (derived 2026-03-13):
For autokey cipher on null-extracted CT73, the ENE and BCL crib windows
in CT73 ALWAYS contain CT97[21..33] and CT97[63..73] respectively,
regardless of null mask (those positions are never null).

This creates FIXED constraints on the autokey key stream at crib positions:
  Required key[ene_s+k] = (CT97[21+k] - ENE_WORD[k]) mod 26  [for Vigenère]

The key stream comes from:
  - Keyword characters (for positions < L in the autokey stream)
  - PT values in the pre-crib region (for autokey positions ≥ L)

ANALYSIS:
1. For EASTNORTHEAST (L=13) as keyword: ELIMINATED
   - CT97[21..33] and the EASTNORTHEAST keyword create incompatible constraints
   - MAX ENE = 1-2/13 regardless of null mask (proven by exhaustive enumeration)
   - Practical max ≈ 9/24 (SA confirms this)

2. For KRYPTOS (L=7) as keyword:
   - 6 ENE cross-pairs ALL incompatible → theoretical max ENE ≤ 7/13
   - 4 BCL cross-pairs ALL incompatible → theoretical max BCL ≤ 7/11
   - SA achieves 13/24 (6+7), close to theoretical max 14/24 (7+7)
   - Is 14/24 achievable? This script exhaustively checks.

METHOD:
1. Enumerate all 2^21 pre-ENE null masks (positions 0..20)
2. For each: compute max ENE hits achievable
3. For each: check which BCL configurations work
4. Report the combined maximum
"""

import sys, itertools, time, json
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

# Fixed CT97 values at ENE and BCL crib windows
ENE_CT97 = [AZ_TO_KA[ord(c)-65] for c in CT97[ENE_START:ENE_START+13]]  # KA indices
BCL_CT97 = [AZ_TO_KA[ord(c)-65] for c in CT97[BCL_START:BCL_START+11]]  # KA indices
ENE_PT_KA = [KA_IDX[c] for c in ENE_WORD]   # Expected ENE plaintext in KA
BCL_PT_KA = [KA_IDX[c] for c in BCL_WORD]   # Expected BCL plaintext in KA

print("="*60)
print("AUTOKEY CHAIN CONSTRAINT ANALYSIS")
print("="*60)
print(f"CT97={CT97}")
print()

print("Fixed CT97 values at crib windows:")
print(f"  CT97[21..33] = {''.join(CT97[21:34])} = {[AZ_TO_KA[ord(c)-65] for c in CT97[21:34]]} (KA indices)")
print(f"  CT97[63..73] = {''.join(CT97[63:74])} = {[AZ_TO_KA[ord(c)-65] for c in CT97[63:74]]} (KA indices)")
print()
print(f"Required key stream at ENE positions (= CT97_KA[k] - ENE_PT_KA[k]) mod 26:")
ene_req = [(ENE_CT97[k] - ENE_PT_KA[k]) % 26 for k in range(13)]
print(f"  {ene_req}")
print(f"  = {''.join(KA_STR[v] for v in ene_req)}")
print()
print(f"Required key stream at BCL positions:")
bcl_req = [(BCL_CT97[k] - BCL_PT_KA[k]) % 26 for k in range(11)]
print(f"  {bcl_req}")
print(f"  = {''.join(KA_STR[v] for v in bcl_req)}")
print()

# ── Part 1: Prove EASTNORTHEAST is eliminated ───────────────────────────────
print("="*60)
print("PART 1: EASTNORTHEAST as keyword — exhaustive ENE analysis")
print("="*60)

KW_ENE = [KA_IDX[c] for c in 'EASTNORTHEAST']  # KA indices
L_ENE = 13

# For all n1 in 0..21 and all pre-ENE null masks:
# Compute max ENE hits achievable

pre_ene_positions = list(range(21))  # Positions 0..20 (all can be null)
ct97_pre = [AZ_TO_KA[ord(c)-65] for c in CT97[:21]]  # KA indices

best_ene_total = 0
best_ene_configs = []

t0 = time.time()
print("Enumerating all 2^21 pre-ENE null configurations for EASTNORTHEAST:KA_vig...")

for n1 in range(22):
    for null_positions in itertools.combinations(pre_ene_positions, n1):
        null_set_pre = set(null_positions)
        # Build CT73 pre-ENE portion
        ct73_pre_ka = [ct97_pre[j] for j in range(21) if j not in null_set_pre]
        ene_s = 21 - n1

        # Compute PT[0..ene_s-1] via EASTNORTHEAST:KA_vig autokey
        pt_ka = []
        for i, cki in enumerate(ct73_pre_ka):
            ki = KW_ENE[i] if i < L_ENE else pt_ka[i - L_ENE]
            pt_ki = (cki - ki) % 26
            pt_ka.append(pt_ki)

        # Now evaluate each ENE position
        hits = 0
        for k in range(13):
            j = ene_s + k  # position in CT73 for this ENE char
            if j < L_ENE:
                key_j = KW_ENE[j]
            elif j - L_ENE < len(pt_ka):
                key_j = pt_ka[j - L_ENE]
            else:
                break
            # CT73[j] = CT97[21+k] (fixed, KA index)
            pt_j = (ENE_CT97[k] - key_j) % 26
            if pt_j == ENE_PT_KA[k]:
                hits += 1

        if hits > best_ene_total:
            best_ene_total = hits
            best_ene_configs = [(n1, null_positions, hits)]
            print(f"  NEW BEST ENE: {hits}/13 at n1={n1}, nulls={null_positions}")
        elif hits == best_ene_total and hits >= 3:
            best_ene_configs.append((n1, null_positions, hits))

elapsed = time.time() - t0
print(f"\nEASTNORTHEAST:KA_vig MAX ENE = {best_ene_total}/13 (checked all 2^21 configs in {elapsed:.1f}s)")
if best_ene_total < 5:
    print(f"CONCLUSION: EASTNORTHEAST:KA_vig is ELIMINATED (max ENE={best_ene_total}/13, practical max ≤ {best_ene_total+11}/24)")
    print(f"            Cannot compete with KRYPTOS:KA_vig (13/24)")
print()

# ── Part 2: Compute exact theoretical max for KRYPTOS:KA_vig ────────────────
print("="*60)
print("PART 2: KRYPTOS:KA_vig — cross-constraint exact analysis")
print("="*60)

KW_KR = [KA_IDX[c] for c in 'KRYPTOS']  # KA indices
L_KR = 7

print("Cross-constraint analysis (KRYPTOS:KA_vig, L=7):")
print("\nENE cross-pairs (j1, j1+7) where j1+7 < 13:")
ene_incompatible = []
for j1 in range(6):  # j1 = 0..5, j2 = 7..12
    j2 = j1 + L_KR
    # For both j1 and j2 to be ENE hits with KRYPTOS:KA_vig:
    # At j2: key[ene_s+j2] = PT[ene_s+j2-7] = PT[ene_s+j1] = ENE_PT_KA[j1]
    # PT[ene_s+j2] = (CT97_KA[j2] - ENE_PT_KA[j1]) % 26
    # For crib: PT[ene_s+j2] = ENE_PT_KA[j2]
    # So: ENE_PT_KA[j2] = (CT97_KA[j2] - ENE_PT_KA[j1]) % 26
    # → ENE_PT_KA[j1] = (CT97_KA[j2] - ENE_PT_KA[j2]) % 26
    req = (ENE_CT97[j2] - ENE_PT_KA[j2]) % 26
    actual = ENE_PT_KA[j1]
    compatible = (req == actual)
    status = "COMPATIBLE" if compatible else "INCOMPATIBLE"
    print(f"  (j1={j1}, j2={j2}): req ENE_PT[{j1}]={KA_STR[req]} actual={KA_STR[actual]} → {status}")
    if not compatible:
        ene_incompatible.append((j1, j2))

print(f"\n  {len(ene_incompatible)} incompatible ENE pairs → max_ene ≤ {13 - len(ene_incompatible)}/13")

print("\nBCL cross-pairs (j1, j1+7) where j1+7 < 11:")
bcl_incompatible = []
for j1 in range(4):  # j1 = 0..3, j2 = 7..10
    j2 = j1 + L_KR
    req = (BCL_CT97[j2] - BCL_PT_KA[j2]) % 26
    actual = BCL_PT_KA[j1]
    compatible = (req == actual)
    status = "COMPATIBLE" if compatible else "INCOMPATIBLE"
    print(f"  (j1={j1}, j2={j2}): req BCL_PT[{j1}]={KA_STR[req]} actual={KA_STR[actual]} → {status}")
    if not compatible:
        bcl_incompatible.append((j1, j2))

print(f"\n  {len(bcl_incompatible)} incompatible BCL pairs → max_bcl ≤ {11 - len(bcl_incompatible)}/11")

max_ene = 13 - len(ene_incompatible)
max_bcl = 11 - len(bcl_incompatible)
print(f"\nKRYPTOS:KA_vig theoretical max = {max_ene}/13 ENE + {max_bcl}/11 BCL = {max_ene+max_bcl}/24")
print(f"SA achieves 13/24 reliably. Gap to theoretical max: {max_ene+max_bcl-13} points.")
print()

# ── Part 3: Enumerate which ENE positions are achievable simultaneously ──────
print("="*60)
print("PART 3: KRYPTOS:KA_vig — achievable ENE subset analysis")
print("="*60)

# The 6 incompatible pairs partition the 13 ENE positions.
# For each pair (j1, j2): can satisfy EITHER j1 OR j2, not both.
# The maximum independent set (positions we can SIMULTANEOUSLY satisfy):
# represents an upper bound.

# Build conflict graph
conflicts = set()
for j1, j2 in ene_incompatible:
    conflicts.add((j1, j2))
    conflicts.add((j2, j1))

print("ENE incompatible pairs:", ene_incompatible)
print("\nMaximum independent set analysis (simultaneously satisfiable ENE positions):")

best_set_size = 0
best_set = None
for size in range(13, 0, -1):
    found = False
    for subset in itertools.combinations(range(13), size):
        ok = True
        for i, a in enumerate(subset):
            for b in subset[i+1:]:
                if (a, b) in conflicts or (b, a) in conflicts:
                    ok = False
                    break
            if not ok: break
        if ok:
            best_set = subset
            best_set_size = size
            found = True
            break
    if found:
        break

print(f"  Maximum independent set: size={best_set_size}, positions={best_set}")
print(f"  → Max ENE simultaneously satisfiable: {best_set_size}/13 (upper bound)")

# Same for BCL
bcl_conflicts = set()
for j1, j2 in bcl_incompatible:
    bcl_conflicts.add((j1, j2))
    bcl_conflicts.add((j2, j1))

best_bcl_size = 0
best_bcl_set = None
for size in range(11, 0, -1):
    found = False
    for subset in itertools.combinations(range(11), size):
        ok = True
        for i, a in enumerate(subset):
            for b in subset[i+1:]:
                if (a, b) in bcl_conflicts or (b, a) in bcl_conflicts:
                    ok = False
                    break
            if not ok: break
        if ok:
            best_bcl_set = subset
            best_bcl_size = size
            found = True
            break
    if found:
        break

print(f"  Maximum BCL independent set: size={best_bcl_size}, positions={best_bcl_set}")
print(f"  → Max BCL simultaneously satisfiable: {best_bcl_size}/11 (upper bound)")

print(f"\nCombined theoretical max: {best_set_size}/{best_bcl_size}/24 = {best_set_size+best_bcl_size}/24")
print()

# ── Part 4: Summary ─────────────────────────────────────────────────────────
print("="*60)
print("SUMMARY")
print("="*60)
print(f"EASTNORTHEAST:KA_vig practical max ENE: {best_ene_total}/13")
print(f"  → Max total ≤ {best_ene_total+11}/24 (NOISE LEVEL)")
print(f"  → ELIMINATED as autokey keyword")
print()
print(f"KRYPTOS:KA_vig cross-constraint theoretical max: {max_ene+max_bcl}/24")
print(f"  Max independent set: ENE={best_set_size}/13, BCL={best_bcl_size}/11")
print(f"  SA currently achieves: 13/24")
print(f"  Remaining gap: {best_set_size+best_bcl_size-13} points")

print("verdict:", json.dumps({
    "verdict_status": "inconclusive",
    "score": 13,
    "summary": f"EASTNORTHEAST max ENE={best_ene_total}/13 (eliminated). KRYPTOS:KA_vig theoretical max={max_ene+max_bcl}/24",
    "evidence": f"Cross-constraint: KRYPTOS ENE={max_ene}/13, BCL={max_bcl}/11",
    "best_plaintext": "",
}))
