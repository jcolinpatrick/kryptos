#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-02b: Monte Carlo baseline for column-progressive model.

Quick test: what score does a RANDOM permutation achieve under the
column-progressive model? If the noise floor is ~18-20, then the
20/24 results from E-FRAC-02 are artifacts of underdetermination.
"""
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

WIDTH = 9


def test_column_progressive_random(perm):
    """Column-progressive test on an arbitrary permutation."""
    # Derive keys at crib positions (Vigenère, Model B)
    keys = {}
    for i, src in enumerate(perm):
        if src in CRIB_SET:
            keys[i] = (CT_NUM[i] - CRIB_PT_NUM[src]) % MOD

    # Group by PT column
    col_groups = defaultdict(list)
    for ct_pos, kval in keys.items():
        pt_pos = perm[ct_pos]
        pt_col = pt_pos % WIDTH
        pt_row = pt_pos // WIDTH
        col_groups[pt_col].append((ct_pos, kval, pt_row))

    total_matches = 0
    for col in range(WIDTH):
        entries = col_groups[col]
        if len(entries) <= 1:
            total_matches += len(entries)
            continue
        best_col = 0
        for base in range(MOD):
            for step in range(MOD):
                matches = sum(1 for _, kval, row in entries
                              if (base + step * row) % MOD == kval)
                if matches > best_col:
                    best_col = matches
        total_matches += best_col

    return total_matches


random.seed(42)
N_RANDOM = 10000
t0 = time.time()

print("Monte Carlo: column-progressive model on random permutations")
print(f"N={N_RANDOM}, width={WIDTH}")

scores = []
for trial in range(N_RANDOM):
    perm = list(range(CT_LEN))
    random.shuffle(perm)
    sc = test_column_progressive_random(perm)
    scores.append(sc)
    if (trial + 1) % 2000 == 0:
        print(f"  {trial+1}/{N_RANDOM}... current max={max(scores)}")

elapsed = time.time() - t0
dist = Counter(scores)
mean_sc = sum(scores) / len(scores)
max_sc = max(scores)
min_sc = min(scores)

print(f"\nResults ({elapsed:.1f}s):")
print(f"  Mean: {mean_sc:.2f}")
print(f"  Max:  {max_sc}")
print(f"  Min:  {min_sc}")
print(f"  Distribution:")
for sc in sorted(dist.keys(), reverse=True)[:10]:
    print(f"    {sc:2d}/24: {dist[sc]:,} ({100*dist[sc]/N_RANDOM:.2f}%)")

# Conclusion
print(f"\n{'='*60}")
if max_sc >= 18:
    print(f"CONFIRMED: Random perms achieve {max_sc}/24 under col-progressive.")
    print(f"Noise floor: ~{mean_sc:.1f}/24, max observed: {max_sc}/24")
    print(f"The 20/24 from E-FRAC-02 is an UNDERDETERMINATION ARTIFACT.")
else:
    print(f"Random perms peak at {max_sc}/24. If E-FRAC-02 got significantly higher,")
    print(f"the result may be genuine.")
print(f"{'='*60}")
