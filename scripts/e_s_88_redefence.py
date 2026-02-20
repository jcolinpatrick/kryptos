#!/usr/bin/env python3
"""E-S-88: Redefence Cipher + Period-7 Vig/Beau

The Redefence cipher: write text in rail fence zigzag across n rails,
then read rails in a KEY-SPECIFIED ORDER (not top-to-bottom).

This is a known classical cipher variant untested in our campaign.
With 7 rails and 5040 orderings × 3 variants, it's a small test.

Also tests: other rail counts (3-14), with key ordering.
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

print("=" * 70)
print("E-S-88: Redefence Cipher + Period-7 Vig/Beau")
print("=" * 70)


def build_redefence_perm(n_rails, order, text_len, offset=0):
    """Build Redefence permutation.

    Write text in zigzag across n_rails rails, then read rails in given order.
    perm[i] = original text position for output position i (gather).
    """
    if n_rails < 2 or n_rails > text_len:
        return None

    # Assign each text position to a rail
    rails = [[] for _ in range(n_rails)]
    rail = offset % n_rails
    direction = 1 if rail < n_rails - 1 else -1

    for i in range(text_len):
        rails[rail].append(i)
        rail += direction
        if rail >= n_rails:
            rail = n_rails - 2
            direction = -1
        elif rail < 0:
            rail = 1
            direction = 1

    # Read rails in key order
    perm = []
    for rank in range(n_rails):
        if rank >= len(order):
            break
        r = order[rank]
        if r < n_rails:
            perm.extend(rails[r])

    if len(perm) != text_len or sorted(perm) != list(range(text_len)):
        return None

    return perm


def score_period7(perm, variant):
    """Score period-7 key consistency under Model B."""
    residue_keys = {}
    for j in range(N):
        pt_pos = perm[j]
        if pt_pos in PT_NUM:
            if variant == 'vig':
                kv = (CT_NUM[j] - PT_NUM[pt_pos]) % 26
            elif variant == 'beau':
                kv = (CT_NUM[j] + PT_NUM[pt_pos]) % 26
            else:
                kv = (PT_NUM[pt_pos] - CT_NUM[j]) % 26
            r = j % 7
            if r not in residue_keys:
                residue_keys[r] = []
            residue_keys[r].append(kv)

    matches = 0
    total = 0
    for r, vals in residue_keys.items():
        counts = Counter(vals)
        matches += counts.most_common(1)[0][1]
        total += len(vals)

    return matches, total


# ── Phase 1: 7-rail Redefence × all orderings ───────────────────────────

print("\n" + "-" * 50)
print("Phase 1: 7-rail Redefence × 5040 orderings × 3 variants")
print("-" * 50)

t0 = time.time()
VARIANTS = ['vig', 'beau', 'var_beau']

best_7rail = {'matches': 0, 'total': 0, 'config': ()}

all_orders_7 = list(permutations(range(7)))
for offset in range(7):
    for order in all_orders_7:
        order = list(order)
        perm = build_redefence_perm(7, order, N, offset)
        if perm is None:
            continue

        for variant in VARIANTS:
            m, t = score_period7(perm, variant)
            if m > best_7rail['matches']:
                best_7rail = {
                    'matches': m, 'total': t,
                    'config': (7, order, offset, variant)
                }

            if m >= 15:
                print(f"  HIT: {m}/{t} (n_rails=7, order={order}, "
                      f"offset={offset}, {variant})")

elapsed = time.time() - t0
print(f"\n  7-rail done in {elapsed:.1f}s")
print(f"  Best: {best_7rail['matches']}/{best_7rail['total']} {best_7rail['config']}")


# ── Phase 2: Other rail counts (3-14) × orderings ───────────────────────

print("\n" + "-" * 50)
print("Phase 2: Rail counts 3-14 (sample orderings for large n)")
print("-" * 50)

best_other = {'matches': 0, 'total': 0, 'config': ()}

for n_rails in range(3, 15):
    if n_rails == 7:
        continue  # already done

    # For small rail counts, test all orderings; for large, sample
    if n_rails <= 7:
        orders = list(permutations(range(n_rails)))
    else:
        # Sample: identity, reverse, and shuffled orderings
        orders = [
            list(range(n_rails)),
            list(range(n_rails - 1, -1, -1)),
        ]
        # Add keyword-derived orderings
        for kw in ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "BERLINCLOCK",
                    "EASTNORTHEAST", "SCHEIDT"]:
            if len(kw) >= n_rails:
                kw_trunc = kw[:n_rails]
                indexed = sorted(range(n_rails), key=lambda i: (kw_trunc[i], i))
                if indexed not in orders:
                    orders.append(indexed)
        # Add some random orderings
        import random
        random.seed(42 + n_rails)
        for _ in range(min(100, 5040)):
            o = list(range(n_rails))
            random.shuffle(o)
            orders.append(o)

    for offset in range(min(n_rails, 7)):
        for order in orders:
            order = list(order)
            perm = build_redefence_perm(n_rails, order, N, offset)
            if perm is None:
                continue

            for variant in VARIANTS:
                m, t = score_period7(perm, variant)
                if m > best_other['matches']:
                    best_other = {
                        'matches': m, 'total': t,
                        'config': (n_rails, order, offset, variant)
                    }

                if m >= 15:
                    print(f"  HIT: {m}/{t} (n_rails={n_rails}, order={order[:7]}..., "
                          f"offset={offset}, {variant})")

    print(f"  n_rails={n_rails}: tested {len(orders)} orderings, "
          f"best so far {best_other['matches']}")

elapsed_p2 = time.time() - t0
print(f"\n  Phase 2 done in {elapsed_p2:.1f}s")
print(f"  Best other: {best_other['matches']}/{best_other['total']} "
      f"{best_other['config']}")


# ── Phase 3: Non-periodic scoring for top configurations ─────────────────

print("\n" + "-" * 50)
print("Phase 3: Non-periodic analysis of top 7-rail configurations")
print("-" * 50)

# For top scoring 7-rail configs, also check:
# - Full keystream pattern
# - IC of decrypted text
# - Whether key has any readable structure

# Collect top 7-rail configs (score ≥ 9)
top_configs = []
for offset in range(7):
    for order in all_orders_7:
        order = list(order)
        perm = build_redefence_perm(7, order, N, offset)
        if perm is None:
            continue
        for variant in VARIANTS:
            m, t = score_period7(perm, variant)
            if m >= 9:
                top_configs.append((m, t, 7, order, offset, variant, perm))

top_configs.sort(key=lambda x: -x[0])
print(f"  Configs with ≥9/24: {len(top_configs)}")

if top_configs:
    print(f"  Top 5:")
    for m, t, nr, order, offset, variant, perm in top_configs[:5]:
        # Compute full keystream
        keys = {}
        for j in range(N):
            pt_pos = perm[j]
            if pt_pos in PT_NUM:
                if variant == 'vig':
                    keys[j] = (CT_NUM[j] - PT_NUM[pt_pos]) % 26
                else:
                    keys[j] = (CT_NUM[j] + PT_NUM[pt_pos]) % 26

        key_str = ''.join(AZ[keys[j]] for j in sorted(keys.keys()))
        print(f"    {m}/{t} order={order} off={offset} {variant}: key={key_str}")


# ── Summary ──────────────────────────────────────────────────────────────

total_elapsed = time.time() - t0
overall_best = max(best_7rail['matches'], best_other['matches'])

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  7-rail Redefence: {best_7rail['matches']}/{best_7rail['total']}")
print(f"  Other rails: {best_other['matches']}/{best_other['total']}")
print(f"  Total time: {total_elapsed:.1f}s")

if overall_best >= 15:
    verdict = f"INTERESTING — {overall_best}/24 above noise"
elif overall_best >= 10:
    verdict = f"MARGINAL — {overall_best}/24 (expected ~8.2 random)"
else:
    verdict = f"NO SIGNAL — {overall_best}/24 at noise floor"

print(f"\n  Verdict: {verdict}")

output = {
    'experiment': 'E-S-88',
    'description': 'Redefence cipher + period-7 Vig/Beau',
    'best_7rail': {'matches': best_7rail['matches'], 'config': str(best_7rail['config'])},
    'best_other': {'matches': best_other['matches'], 'config': str(best_other['config'])},
    'elapsed_seconds': total_elapsed,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_88_redefence.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_88_redefence.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_88_redefence.py")
