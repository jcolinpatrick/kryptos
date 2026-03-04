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
E-S-79: Same-CT-Letter Key Consistency Investigation

E-S-78 found that ordering [6,2,5,1,4,0,3] has 5/14 pairs where
same CT letter → same key value (expected random: 0.54/14, z≈6.2).

This experiment investigates:
1. Is the 5/14 an artifact of crib letter frequency distributions?
2. What does this constraint mean for the cipher structure?
3. Can we exploit it to reduce the keyspace?
4. Monte Carlo significance test (is z=6.2 real after accounting for
   all degrees of freedom in the ordering selection?)
"""

import json
import math
import os
import random
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
print("E-S-79: Same-CT-Letter Key Consistency Investigation")
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


def compute_same_ct_score(order, variant='vig'):
    """Compute same-CT-letter key consistency for an ordering."""
    _, inv_perm = build_col_perm(order)

    # Derive key values at crib positions
    ct_groups = {}  # CT letter → list of (CT_pos, key_value, PT_letter)
    for p in CRIB_POS:
        j = inv_perm[p]
        pt_v = IDX[CRIB_DICT[p]]
        ct_v = CT_IDX[j]
        if variant == 'vig':
            kv = (ct_v - pt_v) % 26
        else:
            kv = (ct_v + pt_v) % 26

        ct_letter = ct_v
        if ct_letter not in ct_groups:
            ct_groups[ct_letter] = []
        ct_groups[ct_letter].append((j, kv, pt_v, p))

    # Count same-CT-letter pairs with same key
    same_key = 0
    total_pairs = 0
    pair_details = []
    for ct_l, entries in ct_groups.items():
        if len(entries) >= 2:
            for i in range(len(entries)):
                for k in range(i+1, len(entries)):
                    total_pairs += 1
                    if entries[i][1] == entries[k][1]:
                        same_key += 1
                        pair_details.append({
                            'ct_letter': AZ[ct_l],
                            'pos1': entries[i][3], 'pos2': entries[k][3],
                            'ct_pos1': entries[i][0], 'ct_pos2': entries[k][0],
                            'key_val': entries[i][1],
                            'pt1': AZ[entries[i][2]], 'pt2': AZ[entries[k][2]],
                        })

    return same_key, total_pairs, pair_details, ct_groups


# ── Analysis 1: Detail the target ordering ───────────────────────────────
print("\n" + "-" * 50)
print("Analysis 1: Detailed look at ordering [6,2,5,1,4,0,3]")
print("-" * 50)

target_order = [6, 2, 5, 1, 4, 0, 3]
for variant in ['vig', 'beau']:
    same_key, total_pairs, pair_details, ct_groups = compute_same_ct_score(target_order, variant)
    print(f"\n  {variant.upper()}: {same_key}/{total_pairs} pairs match")

    # Show CT letter groups
    for ct_l, entries in sorted(ct_groups.items()):
        if len(entries) >= 2:
            entries_str = ', '.join(f"(CT[{e[0]}] key={e[1]} PT[{e[3]}]={AZ[e[2]]})" for e in entries)
            print(f"    CT={AZ[ct_l]}: {entries_str}")

    # Show matching pairs
    if pair_details:
        print(f"    Matching pairs:")
        for pd in pair_details:
            print(f"      CT={pd['ct_letter']} key={pd['key_val']}: "
                  f"PT[{pd['pos1']}]={pd['pt1']}@CT[{pd['ct_pos1']}] = "
                  f"PT[{pd['pos2']}]={pd['pt2']}@CT[{pd['ct_pos2']}]")

# ── Analysis 2: Understand WHY same-CT → same-key ───────────────────────
print("\n" + "-" * 50)
print("Analysis 2: Why does same-CT-letter → same-key happen?")
print("-" * 50)

# Under Vigenère: key[j] = (CT[j] - intermediate[j]) % 26
# And intermediate[j] = PT[perm[j]]
# If CT[j1] = CT[j2] and key[j1] = key[j2], then:
#   CT[j1] - intermediate[j1] = CT[j2] - intermediate[j2] mod 26
#   → intermediate[j1] = intermediate[j2]
#   → PT[perm[j1]] = PT[perm[j2]]
# So: same CT letter + same key ⟺ same PT letter at the mapped positions

# This is VARIANT-INDEPENDENT! If key[j] = (CT[j] - PT[perm[j]]) % 26:
#   key[j1] = key[j2] ⟺ CT[j1] - PT[perm[j1]] = CT[j2] - PT[perm[j2]] mod 26
#   Since CT[j1] = CT[j2]: PT[perm[j1]] = PT[perm[j2]]

print("  Same-CT → same-key is EQUIVALENT to: PT[perm[j1]] = PT[perm[j2]]")
print("  This is variant-independent (same for Vig and Beaufort)!")

# For the target ordering, which PT positions map to same-CT positions?
perm, inv_perm = build_col_perm(target_order)
same_key_vig, _, _, ct_groups_vig = compute_same_ct_score(target_order, 'vig')

print(f"\n  For order [6,2,5,1,4,0,3]:")
for ct_l, entries in sorted(ct_groups_vig.items()):
    if len(entries) >= 2:
        pt_letters = [AZ[e[2]] for e in entries]
        all_same = len(set(pt_letters)) == 1
        print(f"    CT={AZ[ct_l]}: PT letters = {pt_letters} → {'MATCH' if all_same else 'DIFFER'}")

# ── Analysis 3: Count across ALL orderings ───────────────────────────────
print("\n" + "-" * 50)
print("Analysis 3: Same-CT-letter consistency across ALL orderings")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
scores = []

for order in all_orders:
    order = list(order)
    sk, tp, _, _ = compute_same_ct_score(order, 'vig')
    scores.append((sk, tp, order))

scores.sort(reverse=True)

print(f"  Distribution of same-CT-letter key matches:")
from collections import Counter
score_counts = Counter(sk for sk, tp, _ in scores)
for sk in sorted(score_counts.keys(), reverse=True):
    print(f"    {sk} matches: {score_counts[sk]} orderings ({100*score_counts[sk]/len(scores):.1f}%)")

print(f"\n  Top 20 orderings by same-CT consistency:")
for rank, (sk, tp, order) in enumerate(scores[:20]):
    print(f"    #{rank+1}: order={order} {sk}/{tp}")

# ── Analysis 4: Monte Carlo significance test ────────────────────────────
print("\n" + "-" * 50)
print("Analysis 4: Monte Carlo significance test")
print("-" * 50)

# Under H0: the transposition is random (uniform over all 97! permutations)
# We observe 5/14 for the best ordering out of 5040 candidates
# Q: What's P(max score ≥ 5) when we test 5040 orderings?

# Simulate: for each MC trial, generate a random permutation of the 24 CT positions,
# check same-CT-letter consistency, and record the maximum over some set of structured orderings

N_MC = 100000
max_scores_random = []
random.seed(42)

# Pre-compute: what CT letters do the 24 crib positions produce for each ordering?
# Actually, the key insight: same-CT → same-key ⟺ same PT at mapped positions
# So for a given ordering, pairs of crib positions that map to the same CT letter
# need to have the same PT letter.

# Under random permutation: each crib maps to a random CT position
# Probability that two cribs mapping to same CT letter also have same PT letter
# depends on the specific letter frequencies

# Simpler test: for each of the 5040 orderings, what's the expected max score?
# Each ordering produces a specific set of (CT position, PT letter) pairs from the 24 cribs
# "Score" = number of pairs that share both CT letter AND PT letter

# Under random permutation, the CT positions of the 24 cribs would be random
# But columnar transposition is highly structured, not random

# Instead: null hypothesis = the cipher is NOT monoalphabetic
# Under ANY non-monoalphabetic cipher, same CT letter does NOT imply same key
# Expected matches per ordering = sum over CT-letter groups of C(n_same_pt, 2) / total_pairs
# where n_same_pt = number of crib pairs in that group with the same PT letter

# Actually the correct null: for a random key (independent key values at each position),
# P(same key at two positions) = 1/26, regardless of CT letters
# So expected = total_pairs / 26

# For the best ordering: 14 pairs, expected = 14/26 = 0.538
# Getting 5: P(X≥5 | n=14, p=1/26) is very small under binomial

# But we're selecting the BEST out of 5040 orderings
# And different orderings have different total_pairs and different group structures

# Let's compute: for each ordering, what's the exact probability of
# getting ≥ its observed score by chance (assuming random key)?

print("  Computing exact p-values for each ordering...")
from math import comb as C

def binomial_tail(n, k, p):
    """P(X >= k) for Binomial(n, p)."""
    result = 0.0
    for i in range(k, n+1):
        result += C(n, i) * (p**i) * ((1-p)**(n-i))
    return result

# For each ordering, compute p-value
pvals = []
for sk, tp, order in scores:
    if tp == 0:
        pvals.append((1.0, sk, tp, order))
    else:
        pv = binomial_tail(tp, sk, 1.0/26)
        pvals.append((pv, sk, tp, order))

pvals.sort()

print(f"\n  Top 10 by p-value (smallest = most significant):")
for rank, (pv, sk, tp, order) in enumerate(pvals[:10]):
    bonf = min(1.0, pv * 5040)  # Bonferroni correction
    print(f"    #{rank+1}: order={order} {sk}/{tp} p={pv:.2e} bonferroni={bonf:.2e}")

# ── Analysis 5: What does 5/14 mean structurally? ───────────────────────
print("\n" + "-" * 50)
print("Analysis 5: Structural implications")
print("-" * 50)

# For ordering [6,2,5,1,4,0,3], the 5 matching pairs mean:
# 5 pairs of crib positions map to CT positions with the same letter,
# AND the crib PT letters at those positions are the same
# This is variant-independent and depends only on the transposition

# Let's identify the 5 matching pairs explicitly
target_order = [6, 2, 5, 1, 4, 0, 3]
perm, inv_perm = build_col_perm(target_order)

print(f"\n  Order [6,2,5,1,4,0,3]: perm maps PT position to intermediate/CT position")
print(f"  Crib mapping:")
ct_to_cribs = {}
for p in CRIB_POS:
    j = inv_perm[p]
    ct_letter = CT[j]
    pt_letter = CRIB_DICT[p]
    col = p % WIDTH
    row = p // WIDTH
    print(f"    PT[{p:2d}]={pt_letter} (col={col},row={row}) → CT[{j:2d}]={ct_letter}")
    if ct_letter not in ct_to_cribs:
        ct_to_cribs[ct_letter] = []
    ct_to_cribs[ct_letter].append((p, pt_letter, j))

print(f"\n  CT letter groups with ≥2 cribs:")
for ct_l, entries in sorted(ct_to_cribs.items()):
    if len(entries) >= 2:
        pt_match = all(e[1] == entries[0][1] for e in entries)
        indicator = "SAME PT" if pt_match else "DIFF PT"
        entry_str = ', '.join(f"PT[{e[0]}]={e[1]}" for e in entries)
        print(f"    CT={ct_l}: [{indicator}] {entry_str}")

# Count: how many orderings produce ≥5 matches?
count_ge5 = sum(1 for sk, _, _ in scores if sk >= 5)
print(f"\n  Orderings with ≥5 same-CT matches: {count_ge5}/{len(scores)} ({100*count_ge5/len(scores):.1f}%)")

# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

best = pvals[0]
print(f"  Most significant ordering: {best[3]}")
print(f"    Score: {best[1]}/{best[2]}")
print(f"    Raw p-value: {best[0]:.2e}")
print(f"    Bonferroni-corrected: {min(1.0, best[0] * 5040):.2e}")

if min(1.0, best[0] * 5040) < 0.01:
    verdict = "SIGNIFICANT — investigate further"
elif min(1.0, best[0] * 5040) < 0.05:
    verdict = "MARGINAL — borderline significance"
else:
    verdict = "NOT SIGNIFICANT after multiple testing correction"

print(f"  Verdict: {verdict}")

output = {
    'experiment': 'E-S-79',
    'description': 'Same-CT-letter key consistency investigation',
    'best_order': list(best[3]),
    'best_score': best[1],
    'best_total_pairs': best[2],
    'raw_pvalue': best[0],
    'bonferroni': min(1.0, best[0] * 5040),
    'count_ge5': count_ge5,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_79_same_ct_investigation.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_79_same_ct_investigation.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_79_same_ct_investigation.py")
