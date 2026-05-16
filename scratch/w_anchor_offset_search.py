#!/usr/bin/env python3
"""
Refined W-anchor hypothesis: cribs preserve their LETTER content + ORDER
(via even-parity reversals around W anchors), but their ABSOLUTE POSITIONS
in the manipulated CT can be anything. Test: is there any relative offset
d at any period p that makes EAST and BERLIN jointly consistent under a
periodic Vig/Beau/VarBeau cipher?

If yes -> live hypothesis, follow up by checking reversal-achievability.
If no  -> hypothesis falsified across all reversal mechanisms.
"""
import os, sys
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    parent = os.path.dirname(_ROOT)
    if parent == _ROOT: sys.exit("repo root not found")
    _ROOT = parent
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

EAST_POSITIONS = sorted(p for p in CRIB_DICT if p < 35)   # 21..33
BERLIN_POSITIONS = sorted(p for p in CRIB_DICT if p >= 35) # 63..73

def derive_k(c_char, p_char, variant):
    c, p = ord(c_char)-65, ord(p_char)-65
    if variant == 'vig':     return (c - p) % 26
    if variant == 'beau':    return (c + p) % 26
    if variant == 'varbeau': return (p - c) % 26

def crib_k_vector(positions, variant):
    return [derive_k(CT[p], CRIB_DICT[p], variant) for p in positions]

print("="*72)
print(" REFINED W-ANCHOR: crib-block preserved, free relative offset")
print("="*72)

# Show k-vectors per variant
for variant in ['vig','beau','varbeau']:
    eK = crib_k_vector(EAST_POSITIONS, variant)
    bK = crib_k_vector(BERLIN_POSITIONS, variant)
    print(f"\n {variant} k-vectors:")
    print(f"   EAST   (len={len(eK)}): {eK}")
    print(f"   BERLIN (len={len(bK)}): {bK}")

# === The search ===
print(f"\n{'='*72}")
print(" Sweep: p in 13..30, d in 0..p-1, all three variants")
print("="*72)

# Track all consistent configs
all_results = []  # (variant, p, d, n_real_overlap, n_constrained, overlap_residues)

for variant in ['vig','beau','varbeau']:
    eK = crib_k_vector(EAST_POSITIONS, variant)
    bK = crib_k_vector(BERLIN_POSITIONS, variant)

    for p in range(13, 31):
        # Verify EAST internally consistent at p (at p>=13 it always is for K4)
        east_residues = {}
        ok = True
        for i, k in enumerate(eK):
            r = i % p
            if r in east_residues and east_residues[r] != k:
                ok = False
                break
            east_residues[r] = k
        if not ok:
            continue

        # Sweep BERLIN starting offset d
        for d in range(p):
            constraints = dict(east_residues)
            overlap_residues = []
            consistent = True
            for j, k in enumerate(bK):
                r = (d + j) % p
                if r in east_residues:
                    overlap_residues.append(r)
                    if east_residues[r] != k:
                        consistent = False
                        break
                if r in constraints and constraints[r] != k:
                    consistent = False
                    break
                constraints[r] = k
            if consistent:
                all_results.append((variant, p, d, len(overlap_residues), len(constraints), overlap_residues))

# Sort by overlap descending: most-constrained survivors first
all_results.sort(key=lambda x: (-x[3], x[1]))

print(f"\n Total (variant, p, d) configs with NO conflict: {len(all_results)}")
print()
print(f" Top 30 configs ranked by real-overlap (forced equalities that all matched):")
print(f" {'variant':10} {'p':4} {'d':4} {'overlap':8} {'constrained':12} {'overlap residues'}")
for r in all_results[:30]:
    print(f" {r[0]:10} {r[1]:<4} {r[2]:<4} {r[3]:<8} {r[4]:<12} {r[5]}")

# Distribution of overlap counts
from collections import Counter
overlap_counts = Counter(r[3] for r in all_results)
print(f"\n Overlap distribution (how many residues forced into agreement):")
for ov in sorted(overlap_counts.keys(), reverse=True):
    print(f"   overlap={ov:2d}: {overlap_counts[ov]:4d} configs")

# Substantive: overlap >= 3 is non-vacuous
substantive = [r for r in all_results if r[3] >= 3]
print(f"\n Substantive consistency (overlap >= 3): {len(substantive)} configs")
if substantive:
    print(f" Top by overlap:")
    for r in substantive[:10]:
        # Decode the actual matching k values to show what's happening
        var, p, d, ov, nc, ovr = r
        eK = crib_k_vector(EAST_POSITIONS, var)
        bK = crib_k_vector(BERLIN_POSITIONS, var)
        # For each overlap residue, show east_idx -> berlin_idx and the k value
        triples = []
        for r_val in ovr:
            east_idx = r_val  # since EAST starts at offset 0 mod p
            berlin_idx = (r_val - d) % p
            if 0 <= east_idx < len(eK) and 0 <= berlin_idx < len(bK):
                triples.append((east_idx, berlin_idx, eK[east_idx]))
        print(f"   {var} p={p} d={d}: triples (east_i, berlin_j, k) = {triples}")

# === Compare to baseline: original K4 positions ===
print(f"\n{'='*72}")
print(" Baseline check: ORIGINAL K4 positions (e_0=21, b_0=63, d=42 mod p)")
print("="*72)
for variant in ['vig','beau','varbeau']:
    eK = crib_k_vector(EAST_POSITIONS, variant)
    bK = crib_k_vector(BERLIN_POSITIONS, variant)
    print(f"\n {variant}:")
    for p in range(13, 27):
        # Original positions: EAST at 21, BERLIN at 63
        d_baseline = (63 - 21) % p
        constraints = {}
        consistent = True
        overlap = 0
        for i, k in enumerate(eK):
            r = (21 + i) % p
            if r in constraints and constraints[r] != k:
                consistent = False
                break
            constraints[r] = k
        if not consistent:
            print(f"   p={p:2d}: EAST internally inconsistent (raw)")
            continue
        for j, k in enumerate(bK):
            r = (63 + j) % p
            if r in constraints:
                overlap += 1
                if constraints[r] != k:
                    consistent = False
                    break
            constraints[r] = k
        status = "OK" if consistent else "FAIL"
        print(f"   p={p:2d}: {status}  d={d_baseline:2d}  real-overlap={overlap}")
