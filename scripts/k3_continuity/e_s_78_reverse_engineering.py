#!/usr/bin/env python3
"""
Cipher: K3-method extension
Family: k3_continuity
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-78: Reverse Engineering the Key from Constraints

Instead of testing cipher families, this experiment works backward from what
we know to constrain the key/method.

Key facts:
  - Width-7 columnar transposition very likely (p ≈ 4×10⁻⁵)
  - Model B (trans→sub) preferred
  - Key is non-periodic
  - Position-dependent (proven by K5)
  - Not from standard keyword alphabet (E-S-76)
  - Not from any tested running key text

Approach: For each column ordering, compute the EXACT keystream values at
all 24 crib positions. Then analyze these values for structure:
  - Do they form English letter patterns when reordered?
  - Do they match any known sequence (Fibonacci, primes, etc.)?
  - Are there arithmetic progressions within columns?
  - Is there a simple generating function?
  - Do the same values appear in K1-K3 keystreams at matching positions?

This is a DIAGNOSTIC experiment — it generates data for human analysis.
"""

import json
import os
import sys
import time
from itertools import permutations

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
CRIB_POS = sorted(CRIB_DICT.keys())

WIDTH = 7
NROWS_FULL = N // WIDTH
NROWS_EXTRA = N % WIDTH

print("=" * 70)
print("E-S-78: Reverse Engineering Key from Constraints")
print("=" * 70)

def build_col_perm(order):
    col_lengths = []
    for col_idx in range(WIDTH):
        if col_idx < NROWS_EXTRA:
            col_lengths.append(NROWS_FULL + 1)
        else:
            col_lengths.append(NROWS_FULL)
    perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        c = order[rank]
        clen = col_lengths[c]
        for row in range(clen):
            pt_pos = row * WIDTH + c
            perm[j] = pt_pos
            j += 1
    inv_perm = [0] * N
    for j in range(N):
        inv_perm[perm[j]] = j
    return perm, inv_perm


# ── Compute keystream for all orderings ──────────────────────────────────
print("\n" + "-" * 50)
print("Computing keystream at crib positions for all orderings")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
keystream_data = []

for order in all_orders:
    order = list(order)
    _, inv_perm = build_col_perm(order)

    for variant in ['vig', 'beau']:
        ks = {}  # CT position → key value
        for p in CRIB_POS:
            j = inv_perm[p]
            pt_v = IDX[CRIB_DICT[p]]
            ct_v = CT_IDX[j]
            if variant == 'vig':
                kv = (ct_v - pt_v) % 26
            else:
                kv = (ct_v + pt_v) % 26
            ks[j] = kv

        keystream_data.append({
            'order': order,
            'variant': variant,
            'keystream': ks,  # CT_pos → key_value
        })

print(f"  {len(keystream_data)} (order, variant) combinations")

# ── Analysis 1: Period-7 consistency (sanity check) ──────────────────────
print("\n" + "-" * 50)
print("Analysis 1: Period-7 consistency score")
print("-" * 50)

p7_results = []
for kd in keystream_data:
    ks = kd['keystream']
    residue_vals = {}
    consistent = 0
    for j, kv in sorted(ks.items()):
        r = j % 7
        if r in residue_vals:
            if residue_vals[r] == kv:
                consistent += 1
        else:
            residue_vals[r] = kv
            consistent += 1

    kd['p7_consistency'] = consistent
    p7_results.append((consistent, kd['order'], kd['variant']))

p7_results.sort(reverse=True)
print(f"  Top 10 period-7 consistent:")
for score, order, variant in p7_results[:10]:
    print(f"    {variant} order={order}: {score}/24")

# ── Analysis 2: Key as text (unigram/bigram quality) ─────────────────────
print("\n" + "-" * 50)
print("Analysis 2: Key letter quality (is key readable English?)")
print("-" * 50)

# English letter frequencies (log)
ENGLISH_FREQ = {
    0: 8.167, 1: 1.492, 2: 2.782, 3: 4.253, 4: 12.702, 5: 2.228,
    6: 2.015, 7: 6.094, 8: 6.966, 9: 0.153, 10: 0.772, 11: 4.025,
    12: 2.406, 13: 6.749, 14: 7.507, 15: 1.929, 16: 0.095, 17: 5.987,
    18: 6.327, 19: 9.056, 20: 2.758, 21: 0.978, 22: 2.360, 23: 0.150,
    24: 1.974, 25: 0.074,
}

# Common English bigrams
COMMON_BG = set([
    (19, 7), (7, 4), (8, 13), (4, 17), (0, 13), (17, 4), (13, 3),
    (14, 13), (4, 18), (4, 3), (14, 5), (19, 14), (8, 19), (14, 17),
    (0, 19), (18, 19), (4, 13), (13, 19), (7, 0), (0, 11),
])

text_results = []
for kd in keystream_data:
    ks = kd['keystream']
    # Sort by CT position
    sorted_ks = sorted(ks.items())
    key_vals = [kv for _, kv in sorted_ks]
    key_pos = [j for j, _ in sorted_ks]

    # Unigram score: sum of English frequency for each key letter
    unigram_score = sum(ENGLISH_FREQ[kv] for kv in key_vals) / len(key_vals)

    # Bigram score: consecutive key letters
    bg_count = 0
    for i in range(len(key_vals) - 1):
        # Only count if positions are adjacent (j, j+1)
        if key_pos[i+1] == key_pos[i] + 1:
            if (key_vals[i], key_vals[i+1]) in COMMON_BG:
                bg_count += 1

    key_str = ''.join(AZ[kv] for kv in key_vals)
    kd['key_unigram'] = unigram_score
    kd['key_bigrams'] = bg_count
    kd['key_str'] = key_str
    text_results.append((unigram_score, bg_count, kd['order'], kd['variant'], key_str))

text_results.sort(reverse=True)
print(f"  Top 10 by unigram score:")
for ug, bg, order, variant, key_str in text_results[:10]:
    print(f"    {variant} order={order}: ug={ug:.2f} bg={bg} key='{key_str}'")

# ── Analysis 3: Arithmetic patterns in key ───────────────────────────────
print("\n" + "-" * 50)
print("Analysis 3: Arithmetic patterns in keystream")
print("-" * 50)

# For each ordering, check if key values within each column form an arithmetic sequence
arith_results = []
for kd in keystream_data:
    ks = kd['keystream']
    order = kd['order']
    _, inv_perm = build_col_perm(order)

    # Group key values by column (original PT column = p % 7)
    col_keys = {c: [] for c in range(WIDTH)}
    for p in CRIB_POS:
        j = inv_perm[p]
        col = p % WIDTH
        col_keys[col].append((j, ks[j]))

    # Check for arithmetic progressions within each column
    arith_score = 0
    for c in range(WIDTH):
        vals = col_keys[c]
        if len(vals) < 2:
            continue
        vals.sort()  # Sort by CT position
        diffs = [(vals[i+1][1] - vals[i][1]) % 26 for i in range(len(vals)-1)]
        if len(set(diffs)) == 1:
            arith_score += 1  # All consecutive diffs are the same

    arith_results.append((arith_score, kd['order'], kd['variant']))

arith_results.sort(reverse=True)
print(f"  Top 10 by arithmetic pattern score:")
for score, order, variant in arith_results[:10]:
    if score > 0:
        print(f"    {variant} order={order}: {score}/7 columns have arithmetic progressions")

# ── Analysis 4: Key vs K1-K3 keystreams ──────────────────────────────────
print("\n" + "-" * 50)
print("Analysis 4: Key overlap with K1-K3 keystreams")
print("-" * 50)

# K3 Vigenère key: KRYPTOS = [10, 17, 24, 15, 19, 14, 18]
K3_KEY = [10, 17, 24, 15, 19, 14, 18]
K3_KEY_EXT = [K3_KEY[i % 7] for i in range(100)]

# K1 key: PALIMPSEST = [15, 0, 11, 8, 12, 15, 18, 4, 18, 19]
K1_KEY = [15, 0, 11, 8, 12, 15, 18, 4, 18, 19]
K1_KEY_EXT = [K1_KEY[i % 10] for i in range(100)]

# K2 key: ABSCISSA = [0, 1, 18, 2, 8, 18, 18, 0]
K2_KEY = [0, 1, 18, 2, 8, 18, 18, 0]
K2_KEY_EXT = [K2_KEY[i % 8] for i in range(100)]

best_k3_overlap = {'count': 0}
for kd in keystream_data:
    ks = kd['keystream']

    # How many key values match K3_KEY at the same CT position?
    k3_match = 0
    for j, kv in ks.items():
        if kv == K3_KEY_EXT[j]:
            k3_match += 1

    k1_match = 0
    for j, kv in ks.items():
        if kv == K1_KEY_EXT[j]:
            k1_match += 1

    k2_match = 0
    for j, kv in ks.items():
        if kv == K2_KEY_EXT[j]:
            k2_match += 1

    total = k1_match + k2_match + k3_match
    if total > best_k3_overlap['count']:
        best_k3_overlap = {'count': total, 'k1': k1_match, 'k2': k2_match,
                           'k3': k3_match, 'order': kd['order'], 'variant': kd['variant']}

print(f"  Best K-key overlap: K1={best_k3_overlap['k1']}, K2={best_k3_overlap['k2']}, "
      f"K3={best_k3_overlap['k3']} — {best_k3_overlap['order']} {best_k3_overlap['variant']}")

# Also check: does key match K3_KEY at PT position (not CT position)?
best_pt_k3 = {'count': 0}
for kd in keystream_data:
    ks = kd['keystream']
    order = kd['order']
    _, inv_perm = build_col_perm(order)

    k3_match = 0
    for p in CRIB_POS:
        j = inv_perm[p]
        kv = ks[j]
        if kv == K3_KEY_EXT[p]:  # Key at PT position p
            k3_match += 1

    if k3_match > best_pt_k3['count']:
        best_pt_k3 = {'count': k3_match, 'order': kd['order'], 'variant': kd['variant']}

print(f"  Best K3-key at PT position: {best_pt_k3['count']}/24 — {best_pt_k3['order']} {best_pt_k3['variant']}")

# ── Analysis 5: Same key value at positions with same CT letter ──────────
print("\n" + "-" * 50)
print("Analysis 5: Key consistency by CT letter")
print("-" * 50)

# Under Model B Vigenère: CT[j] = (intermediate[j] + key[j]) % 26
# intermediate[j] = PT[perm[j]]
# So: key[j] = (CT[j] - PT[perm[j]]) % 26
# If CT[j1] == CT[j2] and key[j1] == key[j2], then PT[perm[j1]] == PT[perm[j2]]
# This is a strong constraint linking CT letter identity to PT letter identity

# For each ordering, how many pairs of same-CT-letter crib positions have the same key?
same_ct_results = []
for kd in keystream_data:
    ks = kd['keystream']
    same_ct_same_key = 0
    same_ct_total = 0

    ct_groups = {}
    for j, kv in ks.items():
        ct_letter = CT_IDX[j]
        if ct_letter not in ct_groups:
            ct_groups[ct_letter] = []
        ct_groups[ct_letter].append(kv)

    for ct_l, kvs in ct_groups.items():
        if len(kvs) >= 2:
            for i in range(len(kvs)):
                for j in range(i+1, len(kvs)):
                    same_ct_total += 1
                    if kvs[i] == kvs[j]:
                        same_ct_same_key += 1

    kd['same_ct_same_key'] = same_ct_same_key
    kd['same_ct_total'] = same_ct_total
    same_ct_results.append((same_ct_same_key, same_ct_total, kd['order'], kd['variant']))

same_ct_results.sort(reverse=True)
print(f"  Top 10 by same-CT-letter key consistency:")
for count, total, order, variant in same_ct_results[:10]:
    if total > 0:
        print(f"    {variant} order={order}: {count}/{total} pairs (same CT letter → same key)")

# Expected: if key is random, P(same key) = 1/26 for each pair
# If key is periodic with period 7, P depends on position modular arithmetic

# ── Analysis 6: Best overall orderings ───────────────────────────────────
print("\n" + "-" * 50)
print("Analysis 6: Best orderings by composite score")
print("-" * 50)

# Combine p7_consistency, unigram, arith, same_ct
for kd in keystream_data:
    composite = (kd['p7_consistency'] * 5 +
                 kd['key_unigram'] +
                 kd.get('same_ct_same_key', 0) * 10)
    kd['composite'] = composite

keystream_data.sort(key=lambda x: -x['composite'])

print(f"  Top 20 by composite score:")
for kd in keystream_data[:20]:
    print(f"    {kd['variant']} order={kd['order']}: "
          f"p7={kd['p7_consistency']}/24 ug={kd['key_unigram']:.1f} "
          f"same_ct={kd.get('same_ct_same_key',0)} "
          f"key='{kd['key_str']}'")

# ── Detailed output of top 5 orderings ───────────────────────────────────
print("\n" + "-" * 50)
print("Detailed keystream for top 5 orderings")
print("-" * 50)

for rank, kd in enumerate(keystream_data[:5]):
    print(f"\n  #{rank+1}: {kd['variant']} order={kd['order']}")
    ks = kd['keystream']
    _, inv_perm = build_col_perm(kd['order'])

    print(f"    Keystream by CT position:")
    sorted_ks = sorted(ks.items())
    for j, kv in sorted_ks:
        # Find which crib position maps here
        perm, _ = build_col_perm(kd['order'])
        pt_pos = perm[j]
        pt_letter = CRIB_DICT.get(pt_pos, '?')
        ct_letter = CT[j]
        key_letter = AZ[kv]
        print(f"      CT[{j:2d}]={ct_letter} ← PT[{pt_pos:2d}]={pt_letter} key={key_letter}({kv:2d}) "
              f"[col={pt_pos%7}, row={pt_pos//7}]")

# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Total orderings analyzed: {len(keystream_data)}")
print(f"  Best p7 consistency: {p7_results[0][0]}/24 — {p7_results[0][1]} {p7_results[0][2]}")
print(f"  Best key unigram: {text_results[0][0]:.2f}")
print(f"  Best same-CT-key consistency: {same_ct_results[0][0]}/{same_ct_results[0][1]}")
print(f"  K-key overlap best: {best_k3_overlap['count']}")
print(f"  Diagnostic data saved for human analysis.")

output = {
    'experiment': 'E-S-78',
    'description': 'Reverse engineering key from constraints',
    'best_p7': p7_results[0][0],
    'best_unigram': text_results[0][0],
    'best_same_ct': same_ct_results[0][0],
    'top5_orderings': [
        {'order': kd['order'], 'variant': kd['variant'],
         'p7': kd['p7_consistency'], 'key': kd['key_str']}
        for kd in keystream_data[:5]
    ],
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_78_reverse_engineering.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_78_reverse_engineering.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_78_reverse_engineering.py")
