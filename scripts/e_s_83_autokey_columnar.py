#!/usr/bin/env python3
"""E-S-83: Autokey Variants + Width-7 Columnar

Tests autokey cipher combined with width-7 columnar transposition (Model B).

The key insight: autokey produces a NON-PERIODIC key (matching K4's proven
non-periodic keystream). It's a natural "change in methodology" from K3's
periodic Vigenère.

Three autokey types tested:
  A. Original-PT autokey: Key[j] = PT_IDX[j-m] (original PT position)
  B. Intermediate-text autokey: Key[j] = PT_IDX[σ(j-m)] (transposed PT)
  C. Ciphertext autokey: Key[j] = CT_IDX[j-m]

Each under Vigenère, Beaufort, and Variant Beaufort.
For all 5040 width-7 orderings × primer lengths 1-14.

Under Model B (trans→sub):
  Intermediate[j] = PT[σ(j)]
  CT[j] = Enc(Intermediate[j], Key[j])

For Vig:  K = (CT - PT) % 26
For Beau: K = (CT + PT) % 26  [from CT = (K - PT) % 26]
For VBeau: K = (PT - CT) % 26 [from CT = (PT - K) % 26]

Expected random: ~1/26 per checkable position.
CT autokey: ~24 checkable positions → 10+ matches for Bonferroni significance
Intermediate/OriginalPT autokey: ~6 checkable → 5/6 for significance
"""

import json
import os
import sys
import time
from itertools import permutations

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
CRIB_POS = sorted(CRIB_DICT.keys())
PT_NUM = {pos: AZ_IDX[ch] for pos, ch in CRIB_DICT.items()}

WIDTH = 7
NROWS_FULL = N // WIDTH  # 13
NROWS_EXTRA = N % WIDTH  # 6
COL_LENGTHS = [NROWS_FULL + 1 if c < NROWS_EXTRA else NROWS_FULL
               for c in range(WIDTH)]

print("=" * 70)
print("E-S-83: Autokey Variants + Width-7 Columnar")
print("=" * 70)
print(f"  CT length: {N}, Width: {WIDTH}, Col lengths: {COL_LENGTHS}")
print(f"  Cribs: {len(CRIB_POS)} positions")


def build_columnar_perm(order):
    """Build columnar perm: perm[ct_pos] = pt_pos (gather convention)."""
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


def compute_k_obs(perm, variant):
    """Compute observed key values at crib-derived positions.

    Returns dict: ct_position → key_value
    """
    k_obs = {}
    for j in range(N):
        pt_pos = perm[j]
        if pt_pos in PT_NUM:
            if variant == 'vig':
                k_obs[j] = (CT_NUM[j] - PT_NUM[pt_pos]) % 26
            elif variant == 'beau':
                k_obs[j] = (CT_NUM[j] + PT_NUM[pt_pos]) % 26
            else:  # var_beau
                k_obs[j] = (PT_NUM[pt_pos] - CT_NUM[j]) % 26
    return k_obs


def test_ct_autokey(k_obs, primer_len):
    """CT autokey: Key[j] = CT_IDX[j - primer_len].

    Checkable at all positions where k_obs is known AND j >= primer_len.
    """
    matches = 0
    checkable = 0
    for j, kv in k_obs.items():
        if j < primer_len:
            continue
        k_pred = CT_NUM[j - primer_len]
        checkable += 1
        if kv == k_pred:
            matches += 1
    return matches, checkable


def test_intermediate_autokey(k_obs, perm, primer_len):
    """Intermediate-text autokey: Key[j] = PT_NUM[perm[j - primer_len]].

    Checkable when both perm[j] and perm[j-m] are crib positions.
    """
    matches = 0
    checkable = 0
    for j, kv in k_obs.items():
        if j < primer_len:
            continue
        pt_pos_prev = perm[j - primer_len]
        if pt_pos_prev in PT_NUM:
            k_pred = PT_NUM[pt_pos_prev]
            checkable += 1
            if kv == k_pred:
                matches += 1
    return matches, checkable


def test_original_pt_autokey(k_obs, primer_len):
    """Original-PT autokey: Key[j] = PT_NUM[j - primer_len].

    Checkable when perm[j] is a crib position AND (j - primer_len) is a crib position.
    """
    matches = 0
    checkable = 0
    for j, kv in k_obs.items():
        if j < primer_len:
            continue
        orig_pos = j - primer_len
        if orig_pos in PT_NUM:
            k_pred = PT_NUM[orig_pos]
            checkable += 1
            if kv == k_pred:
                matches += 1
    return matches, checkable


# ── Main sweep ────────────────────────────────────────────────────────────

all_orders = list(permutations(range(WIDTH)))
PRIMER_RANGE = range(1, 15)
VARIANTS = ['vig', 'beau', 'var_beau']
AUTOKEY_TYPES = ['ct', 'intermediate', 'original_pt']

# Track best results by autokey type
best_by_type = {}
for ak_type in AUTOKEY_TYPES:
    best_by_type[ak_type] = {
        'matches': 0, 'checkable': 0, 'ratio': 0.0,
        'variant': '', 'order': [], 'primer': 0
    }

# Also track overall distribution for significance testing
score_dist = {ak_type: [] for ak_type in AUTOKEY_TYPES}

t0 = time.time()
n_tested = 0
n_total = len(all_orders) * len(VARIANTS) * len(PRIMER_RANGE) * len(AUTOKEY_TYPES)

print(f"\n  Total configs: {n_total:,}")
print(f"  = {len(all_orders)} orderings × {len(VARIANTS)} variants "
      f"× {len(PRIMER_RANGE)} primers × {len(AUTOKEY_TYPES)} autokey types")
print()

for oi, order in enumerate(all_orders):
    order = list(order)
    perm = build_columnar_perm(order)

    for variant in VARIANTS:
        k_obs = compute_k_obs(perm, variant)

        for primer_len in PRIMER_RANGE:
            # CT autokey
            m, c = test_ct_autokey(k_obs, primer_len)
            ratio = m / c if c > 0 else 0.0
            score_dist['ct'].append(m)
            if c > 0 and m > best_by_type['ct']['matches']:
                best_by_type['ct'] = {
                    'matches': m, 'checkable': c, 'ratio': ratio,
                    'variant': variant, 'order': order, 'primer': primer_len
                }

            # Intermediate-text autokey
            m, c = test_intermediate_autokey(k_obs, perm, primer_len)
            ratio = m / c if c > 0 else 0.0
            score_dist['intermediate'].append(m)
            if c > 0 and (m > best_by_type['intermediate']['matches'] or
                          (m == best_by_type['intermediate']['matches'] and
                           ratio > best_by_type['intermediate']['ratio'])):
                best_by_type['intermediate'] = {
                    'matches': m, 'checkable': c, 'ratio': ratio,
                    'variant': variant, 'order': order, 'primer': primer_len
                }

            # Original-PT autokey
            m, c = test_original_pt_autokey(k_obs, primer_len)
            ratio = m / c if c > 0 else 0.0
            score_dist['original_pt'].append(m)
            if c > 0 and (m > best_by_type['original_pt']['matches'] or
                          (m == best_by_type['original_pt']['matches'] and
                           ratio > best_by_type['original_pt']['ratio'])):
                best_by_type['original_pt'] = {
                    'matches': m, 'checkable': c, 'ratio': ratio,
                    'variant': variant, 'order': order, 'primer': primer_len
                }

            n_tested += 3

    if (oi + 1) % 1000 == 0:
        elapsed = time.time() - t0
        print(f"  [{oi+1}/{len(all_orders)}] {elapsed:.1f}s | "
              f"CT best: {best_by_type['ct']['matches']}, "
              f"Inter best: {best_by_type['intermediate']['matches']}, "
              f"OrigPT best: {best_by_type['original_pt']['matches']}")

elapsed = time.time() - t0
print(f"\n  Completed {n_tested:,} configs in {elapsed:.1f}s")


# ── Phase 2: Also test without transposition (direct correspondence) ─────

print("\n" + "-" * 50)
print("Phase 2: Autokey without transposition (direct correspondence)")
print("-" * 50)

# Direct: perm = identity, CT[i] = Enc(PT[i], Key[i])
identity_perm = list(range(N))
direct_results = {}

for variant in VARIANTS:
    k_obs = compute_k_obs(identity_perm, variant)

    for primer_len in PRIMER_RANGE:
        for ak_type in AUTOKEY_TYPES:
            if ak_type == 'ct':
                m, c = test_ct_autokey(k_obs, primer_len)
            elif ak_type == 'intermediate':
                m, c = test_intermediate_autokey(k_obs, identity_perm, primer_len)
            else:
                m, c = test_original_pt_autokey(k_obs, primer_len)

            key = (variant, ak_type, primer_len)
            if key not in direct_results or m > direct_results[key][0]:
                direct_results[key] = (m, c)

# Find best direct results
best_direct = {'matches': 0, 'checkable': 0, 'variant': '', 'autokey': '', 'primer': 0}
for (var, ak, prim), (m, c) in direct_results.items():
    if m > best_direct['matches']:
        best_direct = {'matches': m, 'checkable': c, 'variant': var,
                       'autokey': ak, 'primer': prim}

print(f"  Best direct: {best_direct['matches']}/{best_direct['checkable']} "
      f"({best_direct['variant']} {best_direct['autokey']} m={best_direct['primer']})")


# ── Phase 3: Also test key = CT[j-m] XOR-like (additive mod 26) ──────────

print("\n" + "-" * 50)
print("Phase 3: CT-feedback variants (Key[j] = f(CT[j-m]))")
print("-" * 50)

# Test CT-feedback where key is a FUNCTION of CT[j-m]:
# 1. Key = CT[j-m] (already tested above as ct autokey)
# 2. Key = 26 - CT[j-m] (complement)
# 3. Key = (CT[j-m] + offset) % 26 for offset 1-25
# Only test CT feedback since it gives the most checkable positions

best_feedback = {'matches': 0, 'checkable': 0, 'variant': '', 'order': [],
                 'primer': 0, 'offset': 0}

for oi, order in enumerate(all_orders):
    order = list(order)
    perm = build_columnar_perm(order)

    for variant in VARIANTS:
        k_obs = compute_k_obs(perm, variant)

        for primer_len in [1, 2, 3, 4, 5, 6, 7]:
            for offset in range(1, 26):
                matches = 0
                checkable = 0
                for j, kv in k_obs.items():
                    if j < primer_len:
                        continue
                    k_pred = (CT_NUM[j - primer_len] + offset) % 26
                    checkable += 1
                    if kv == k_pred:
                        matches += 1

                if matches > best_feedback['matches']:
                    best_feedback = {
                        'matches': matches, 'checkable': checkable,
                        'variant': variant, 'order': order,
                        'primer': primer_len, 'offset': offset
                    }

    if (oi + 1) % 1000 == 0:
        elapsed = time.time() - t0
        print(f"  [{oi+1}/{len(all_orders)}] {elapsed:.1f}s | "
              f"best feedback: {best_feedback['matches']}")

print(f"  Best CT-feedback with offset: {best_feedback['matches']}/"
      f"{best_feedback['checkable']} "
      f"(var={best_feedback['variant']}, order={best_feedback['order']}, "
      f"m={best_feedback['primer']}, offset={best_feedback['offset']})")


# ── Summary ──────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

for ak_type in AUTOKEY_TYPES:
    b = best_by_type[ak_type]
    print(f"\n  {ak_type.upper()} autokey:")
    print(f"    Best: {b['matches']}/{b['checkable']} = {b['ratio']:.3f}")
    print(f"    Config: {b['variant']} order={b['order']} primer={b['primer']}")

    # Score distribution
    from collections import Counter
    dist = Counter(score_dist[ak_type])
    max_score = max(dist.keys()) if dist else 0
    print(f"    Score dist (top): ", end="")
    for s in sorted(dist.keys(), reverse=True)[:5]:
        print(f"{s}:{dist[s]}", end="  ")
    print()

print(f"\n  Direct (no transposition): {best_direct['matches']}/"
      f"{best_direct['checkable']}")
print(f"  CT-feedback+offset: {best_feedback['matches']}/"
      f"{best_feedback['checkable']}")

# Expected random for CT autokey: ~24 checkable, 24/26 ≈ 0.92 expected matches
# Significance thresholds (Bonferroni for ~2M tests):
#   ≥10/24: p ≈ 7.5e-9 per test (significant)
#   ≥8/24:  p ≈ 1.9e-6 per test (marginal)

ct_best = best_by_type['ct']['matches']
ct_check = best_by_type['ct']['checkable']
expected_random = ct_check / 26.0 if ct_check > 0 else 0

if ct_best >= 10:
    verdict = f"SIGNAL — CT autokey {ct_best}/{ct_check} is highly significant"
elif ct_best >= 6:
    verdict = f"INTERESTING — CT autokey {ct_best}/{ct_check} above noise"
else:
    verdict = f"NO SIGNAL — best CT autokey {ct_best}/{ct_check} (expected random: {expected_random:.1f})"

# Check intermediate/original_pt too
for ak_type in ['intermediate', 'original_pt']:
    b = best_by_type[ak_type]
    if b['checkable'] > 0 and b['matches'] >= b['checkable'] * 0.8:
        verdict = (f"SIGNAL — {ak_type} autokey {b['matches']}/{b['checkable']} "
                   f"is highly significant!")

print(f"\n  Verdict: {verdict}")

# Save artifact
output = {
    'experiment': 'E-S-83',
    'description': 'Autokey variants + width-7 columnar',
    'n_configs': n_tested,
    'elapsed_seconds': elapsed,
    'best_by_type': best_by_type,
    'direct_best': best_direct,
    'ct_feedback_best': best_feedback,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_83_autokey_columnar.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_83_autokey_columnar.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_83_autokey_columnar.py")
