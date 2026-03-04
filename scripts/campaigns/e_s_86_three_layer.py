#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-86: Three-Layer Cipher (Trans1 + Period-7 Vig + Trans2)

Tests the model: CT = Trans2(Vig(Trans1(PT), period-7 key))

Where:
  Trans1 = width-7 columnar (5040 orderings)
  Trans2 = simple post-substitution transposition

Key insight: Many simple Trans2 options PRESERVE the lag-7 autocorrelation
signal observed in K4's CT. Specifically, any T2 that preserves residues
mod 7 (circular shifts, reversal, etc.) maintains period-7 structure.

This three-layer model hasn't been tested before. Standard Model B tests
only cover T2 = identity.

Trans2 options tested:
  1. Circular shifts (s=1..96): t2_inv[j] = (j-s) % 97
  2. Reversal: t2_inv[j] = 96-j
  3. Boustrophedon on 7×14 grid (alternating row direction)
  4. Column-direction variants (128 patterns)
  5. Interleave patterns (odd/even, thirds)

Score: period-7 key consistency from crib-derived values.
For each (T2, σ1, variant): group key values by intermediate position mod 7,
check that each group is consistent (all same value).
"""

import json
import os
import sys
import time
from itertools import permutations
from collections import Counter

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
CT_NUM = [AZ_IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
PT_NUM = {pos: AZ_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POS = sorted(CRIB_DICT.keys())

WIDTH = 7
NROWS_FULL = N // WIDTH  # 13
NROWS_EXTRA = N % WIDTH  # 6
COL_LENGTHS = [NROWS_FULL + 1 if c < NROWS_EXTRA else NROWS_FULL
               for c in range(WIDTH)]

print("=" * 70)
print("E-S-86: Three-Layer Cipher (Trans1 + Period-7 Vig + Trans2)")
print("=" * 70)


def build_columnar_perm(order):
    """perm[k] = PT position for intermediate position k (gather)."""
    perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        col = order[rank]
        clen = COL_LENGTHS[col]
        for row in range(clen):
            pt_pos = row * WIDTH + col
            perm[j] = pt_pos
            j += 1
    return perm


def score_three_layer(perm1, t2_inv, variant):
    """Score period-7 key consistency for three-layer model.

    Model: CT[j] = (PT[perm1[t2_inv[j]]] + key[t2_inv[j] % 7]) % 26

    For each CT position j where perm1[t2_inv[j]] is a crib position:
      derive key_val, group by t2_inv[j] % 7.
    """
    residue_keys = {}
    for j in range(N):
        k = t2_inv[j]          # intermediate position
        i = perm1[k]            # PT position
        if i in PT_NUM:
            if variant == 'vig':
                kv = (CT_NUM[j] - PT_NUM[i]) % 26
            elif variant == 'beau':
                kv = (CT_NUM[j] + PT_NUM[i]) % 26
            else:
                kv = (PT_NUM[i] - CT_NUM[j]) % 26
            r = k % 7
            if r not in residue_keys:
                residue_keys[r] = []
            residue_keys[r].append(kv)

    # Count matches: for each residue, mode count
    matches = 0
    total = 0
    for r, vals in residue_keys.items():
        counts = Counter(vals)
        matches += counts.most_common(1)[0][1]
        total += len(vals)

    return matches, total


# ── Build T2 transforms ──────────────────────────────────────────────────

T2_transforms = {}

# 1. Identity (baseline)
T2_transforms['identity'] = list(range(N))

# 2. Reversal
T2_transforms['reversal'] = [N - 1 - j for j in range(N)]

# 3. Circular shifts (s=1..96)
for s in range(1, N):
    T2_transforms[f'shift_{s}'] = [(j - s) % N for j in range(N)]

# 4. Boustrophedon on 7×14 grid
# Write row-by-row but alternate row direction
boustro = []
for row in range(14):
    cols = range(7) if row % 2 == 0 else range(6, -1, -1)
    for col in cols:
        pos = row * 7 + col
        if pos < N:
            boustro.append(pos)
if len(boustro) == N:
    # t2_inv: CT position j → intermediate position boustro[j]
    # Need inverse: given CT position j, what intermediate position?
    # If boustro[k] = j, then t2_inv[j] = k
    t2_inv_boustro = [0] * N
    for k, pos in enumerate(boustro):
        t2_inv_boustro[pos] = k
    T2_transforms['boustrophedon'] = t2_inv_boustro

# 5. Column-direction variants (sample of 128 patterns)
# For a 7×14 grid, each column can be read top-down or bottom-up
# Encode as 7-bit mask: bit i=1 means column i is read bottom-up
for mask in range(1, 128):  # skip 0 (= identity columnar)
    label = f'coldir_{mask:07b}'
    t2_inv = [0] * N
    idx = 0
    for col in range(WIDTH):
        clen = COL_LENGTHS[col]
        if mask & (1 << col):
            # Bottom-up
            for row in range(clen - 1, -1, -1):
                pos = row * WIDTH + col
                t2_inv[pos] = idx
                idx += 1
        else:
            # Top-down
            for row in range(clen):
                pos = row * WIDTH + col
                t2_inv[pos] = idx
                idx += 1
    T2_transforms[label] = t2_inv

# 6. Interleave: odd positions first, then even
interleave_oe = []
for j in range(0, N, 2):
    interleave_oe.append(j)
for j in range(1, N, 2):
    interleave_oe.append(j)
# t2_inv: need inverse
if len(interleave_oe) == N and sorted(interleave_oe) == list(range(N)):
    t2_inv_oe = [0] * N
    for k, pos in enumerate(interleave_oe):
        t2_inv_oe[pos] = k
    T2_transforms['interleave_oe'] = t2_inv_oe

# Even positions first, then odd
interleave_eo = []
for j in range(1, N, 2):
    interleave_eo.append(j)
for j in range(0, N, 2):
    interleave_eo.append(j)
if len(interleave_eo) == N and sorted(interleave_eo) == list(range(N)):
    t2_inv_eo = [0] * N
    for k, pos in enumerate(interleave_eo):
        t2_inv_eo[pos] = k
    T2_transforms['interleave_eo'] = t2_inv_eo

print(f"  T2 transforms: {len(T2_transforms)}")
print(f"  Breakdown: 1 identity + 1 reversal + 96 shifts + "
      f"1 boustrophedon + 127 coldir + 2 interleave = "
      f"{1 + 1 + 96 + 1 + 127 + 2}")


# ── Main sweep ────────────────────────────────────────────────────────────

all_orders = list(permutations(range(WIDTH)))
VARIANTS = ['vig', 'beau', 'var_beau']

# Phase 1: Test all T2 × all orderings × 3 variants
# But 228 T2 × 5040 orderings × 3 = 3.4M configs... let's focus.
# First: test all T2 with KRYPTOS ordering only
# Then: test top T2 with all orderings

print("\n" + "-" * 50)
print("Phase 1: All T2 × KRYPTOS ordering + identity ordering")
print("-" * 50)

t0 = time.time()

# KRYPTOS ordering for width-7 columnar
kryptos_order = [0, 5, 3, 1, 6, 4, 2]  # K=0, R=5, Y=3, P=1, T=6, O=4, S=2
identity_order = [0, 1, 2, 3, 4, 5, 6]

test_orders = {
    'KRYPTOS': kryptos_order,
    'identity': identity_order,
    'reverse': [6, 5, 4, 3, 2, 1, 0],
    'SCHEIDT': [5, 1, 3, 2, 4, 0, 6],
    'SANBORN': [5, 0, 4, 1, 3, 6, 2],
}

best_phase1 = {'matches': 0, 'total': 0, 'config': ('', '', '')}

for order_name, order in test_orders.items():
    perm1 = build_columnar_perm(order)

    for t2_name, t2_inv in T2_transforms.items():
        for variant in VARIANTS:
            m, total = score_three_layer(perm1, t2_inv, variant)

            if m > best_phase1['matches']:
                best_phase1 = {
                    'matches': m, 'total': total,
                    'config': (order_name, t2_name, variant)
                }

            if m >= 18:
                print(f"  HIT: {m}/{total} ({order_name}, {t2_name}, {variant})")

elapsed = time.time() - t0
print(f"\n  Phase 1 done in {elapsed:.1f}s")
print(f"  Best: {best_phase1['matches']}/{best_phase1['total']} "
      f"{best_phase1['config']}")


# ── Phase 2: Top T2 candidates × all 5040 orderings ─────────────────────

print("\n" + "-" * 50)
print("Phase 2: Top T2 × all 5040 orderings")
print("-" * 50)

# Select T2 transforms that scored well in Phase 1
# First, rank all T2 by their best score across the test orderings
t2_scores = {}
for order_name, order in test_orders.items():
    perm1 = build_columnar_perm(order)
    for t2_name, t2_inv in T2_transforms.items():
        for variant in VARIANTS:
            m, total = score_three_layer(perm1, t2_inv, variant)
            if t2_name not in t2_scores or m > t2_scores[t2_name]:
                t2_scores[t2_name] = m

# Sort and take top 20 T2 transforms (excluding identity which = standard Model B)
top_t2 = sorted(t2_scores.items(), key=lambda x: -x[1])
print(f"  Top 10 T2 transforms:")
for name, score in top_t2[:10]:
    print(f"    {name}: {score}/24")

# Select T2 with score ≥ median for full sweep
median_score = sorted(t2_scores.values())[len(t2_scores) // 2]
selected_t2 = [(name, T2_transforms[name]) for name, score in top_t2
               if score >= median_score and name != 'identity']
# Limit to top 30 for runtime
selected_t2 = selected_t2[:30]
print(f"\n  Selected {len(selected_t2)} T2 transforms for full sweep")

t1 = time.time()
best_phase2 = {'matches': 0, 'total': 0, 'config': ('', '', '')}

for t2_name, t2_inv in selected_t2:
    for oi, order in enumerate(all_orders):
        order = list(order)
        perm1 = build_columnar_perm(order)

        for variant in VARIANTS:
            m, total = score_three_layer(perm1, t2_inv, variant)

            if m > best_phase2['matches']:
                best_phase2 = {
                    'matches': m, 'total': total,
                    'config': (order, t2_name, variant)
                }

            if m >= 20:
                print(f"  STRONG HIT: {m}/{total} (order={order}, {t2_name}, {variant})")

    elapsed = time.time() - t1
    print(f"  {t2_name}: done, best so far {best_phase2['matches']}/{best_phase2['total']} "
          f"[{elapsed:.1f}s]")

elapsed_p2 = time.time() - t1
print(f"\n  Phase 2 done in {elapsed_p2:.1f}s")
print(f"  Best: {best_phase2['matches']}/{best_phase2['total']} "
      f"{best_phase2['config']}")


# ── Phase 3: ALL T2 × ALL orderings (but fast: only vig) ────────────────

print("\n" + "-" * 50)
print("Phase 3: ALL T2 × ALL orderings (vig only)")
print("-" * 50)

t2 = time.time()
best_phase3 = {'matches': 0, 'total': 0, 'config': ('', '', 'vig')}
n_tested = 0

# Only test non-identity T2
nonid_t2 = [(name, inv) for name, inv in T2_transforms.items()
            if name != 'identity']

for t2_name, t2_inv in nonid_t2:
    for order in all_orders:
        order = list(order)
        perm1 = build_columnar_perm(order)
        m, total = score_three_layer(perm1, t2_inv, 'vig')

        if m > best_phase3['matches']:
            best_phase3 = {
                'matches': m, 'total': total,
                'config': (order, t2_name, 'vig')
            }

        n_tested += 1

    if n_tested % 500000 == 0:
        elapsed = time.time() - t2
        print(f"  [{n_tested:,}] {elapsed:.1f}s | "
              f"best: {best_phase3['matches']}/{best_phase3['total']}")

elapsed_p3 = time.time() - t2
print(f"\n  Phase 3 done: {n_tested:,} configs in {elapsed_p3:.1f}s")
print(f"  Best: {best_phase3['matches']}/{best_phase3['total']} "
      f"{best_phase3['config']}")


# ── Summary ──────────────────────────────────────────────────────────────

total_elapsed = time.time() - t0
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

overall_best = max(best_phase1['matches'], best_phase2['matches'],
                   best_phase3['matches'])

print(f"  Phase 1 (keyword orders): {best_phase1['matches']}/{best_phase1['total']}")
print(f"  Phase 2 (top T2 × all orders): {best_phase2['matches']}/{best_phase2['total']}")
print(f"  Phase 3 (all T2 × all orders, vig): {best_phase3['matches']}/{best_phase3['total']}")
print(f"  Total time: {total_elapsed:.1f}s")

# Expected random for period-7 with 24 cribs: ~8.2/24
# Above 15/24 would be very interesting
if overall_best >= 20:
    verdict = f"STRONG SIGNAL — {overall_best}/24, investigate!"
elif overall_best >= 15:
    verdict = f"INTERESTING — {overall_best}/24, above noise"
elif overall_best >= 10:
    verdict = f"MARGINAL — {overall_best}/24, expected ~8.2 random"
else:
    verdict = f"NO SIGNAL — {overall_best}/24, at noise floor (~8.2 expected)"

print(f"\n  Verdict: {verdict}")

output = {
    'experiment': 'E-S-86',
    'description': 'Three-layer cipher (Trans1 + period-7 Vig + Trans2)',
    'n_t2_transforms': len(T2_transforms),
    'phase1_best': {'matches': best_phase1['matches'],
                    'config': str(best_phase1['config'])},
    'phase2_best': {'matches': best_phase2['matches'],
                    'config': str(best_phase2['config'])},
    'phase3_best': {'matches': best_phase3['matches'],
                    'config': str(best_phase3['config'])},
    'elapsed_seconds': total_elapsed,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_86_three_layer.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_86_three_layer.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_86_three_layer.py")
