#!/usr/bin/env python3
"""E-S-84: Polynomial/Recurrence Key + Width-7 Columnar

Tests structured (non-periodic) keystream generation combined with width-7
columnar transposition (Model B).

Phase 1: Polynomial keys — k[j] = (c0 + c1*j + c2*j^2 + ... + cd*j^d) % 26
  For degrees 1-6, fit polynomial from crib-derived key values, check consistency.

Phase 2: Fibonacci recurrence — k[j] = (k[j-a] + k[j-b]) % 26
  For lag pairs (a,b) with 1 ≤ a < b ≤ 14, propagate from crib values and check.

Phase 3: Additive recurrence — k[j] = (k[j-1] + d) % 26 (arithmetic progression)
  Equivalent to degree-1 polynomial but tested separately for clarity.

Phase 4: Multiplicative key — k[j] = (a * j + b) % 26 (affine), and
  k[j] = (a * k[j-1] + b) % 26 (linear congruential).

All under Vig/Beau/VarBeau × 5040 width-7 orderings.
"""

import json
import os
import sys
import time
import math
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
CRIB_POS = sorted(CRIB_DICT.keys())
PT_NUM = {pos: AZ_IDX[ch] for pos, ch in CRIB_DICT.items()}

WIDTH = 7
NROWS_FULL = N // WIDTH
NROWS_EXTRA = N % WIDTH
COL_LENGTHS = [NROWS_FULL + 1 if c < NROWS_EXTRA else NROWS_FULL
               for c in range(WIDTH)]

print("=" * 70)
print("E-S-84: Polynomial/Recurrence Key + Width-7 Columnar")
print("=" * 70)
print(f"  CT length: {N}, Width: {WIDTH}")


def build_columnar_perm(order):
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
    """Compute observed key values: ct_position → key_value."""
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


def mod_inverse(a, m):
    """Modular inverse of a mod m, or None if not invertible."""
    g = math.gcd(a % m, m)
    if g != 1:
        return None
    # Extended Euclidean
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    _, x, _ = extended_gcd(a % m, m)
    return x % m


# ── Phase 1: Polynomial keys ─────────────────────────────────────────────

print("\n" + "-" * 50)
print("Phase 1: Polynomial keys (degrees 1-6)")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
VARIANTS = ['vig', 'beau', 'var_beau']
t0 = time.time()

best_poly = {'degree': 0, 'matches': 0, 'total': 0, 'variant': '',
             'order': [], 'coeffs': []}

for oi, order in enumerate(all_orders):
    order = list(order)
    perm = build_columnar_perm(order)

    for variant in VARIANTS:
        k_obs = compute_k_obs(perm, variant)
        positions = sorted(k_obs.keys())
        values = [k_obs[p] for p in positions]
        n_pts = len(positions)

        for degree in range(1, 7):
            if degree + 1 > n_pts:
                continue

            # Try fitting from the first degree+1 points
            # For degree 1: k = a + b*j → solve from 2 points
            # For higher degrees: use Gaussian elimination mod 26

            # Use a simple approach: try ALL (degree+1)-tuples from positions
            # This is expensive for high degrees; use just the first few points
            # and check the rest.

            # Fast approach for degree 1 (affine):
            if degree == 1:
                # Try all pairs of known points
                best_for_deg = 0
                for i in range(n_pts):
                    for j_idx in range(i + 1, min(i + 5, n_pts)):
                        j1, j2 = positions[i], positions[j_idx]
                        k1, k2 = values[i], values[j_idx]
                        dj = (j2 - j1) % 26
                        dk = (k2 - k1) % 26
                        inv_dj = mod_inverse(dj, 26)
                        if inv_dj is None:
                            continue
                        b = (dk * inv_dj) % 26
                        a = (k1 - b * j1) % 26

                        # Check all points
                        matches = sum(1 for idx, p in enumerate(positions)
                                      if (a + b * p) % 26 == values[idx])

                        if matches > best_for_deg:
                            best_for_deg = matches

                        if matches > best_poly['matches']:
                            best_poly = {
                                'degree': 1, 'matches': matches,
                                'total': n_pts, 'variant': variant,
                                'order': order, 'coeffs': [a, b]
                            }

            elif degree == 2:
                # Quadratic: k = a + b*j + c*j^2
                # Try first 3 points
                best_for_deg = 0
                for seed in range(min(3, n_pts - 2)):
                    j_vals = [positions[seed], positions[seed+1], positions[seed+2]]
                    k_vals_seed = [values[seed], values[seed+1], values[seed+2]]

                    # Build Vandermonde matrix mod 26
                    # [1 j0 j0^2] [a]   [k0]
                    # [1 j1 j1^2] [b] = [k1]
                    # [1 j2 j2^2] [c]   [k2]
                    V = [[1, j_vals[r], (j_vals[r]**2) % 26] for r in range(3)]

                    # Gaussian elimination mod 26
                    M = [row[:] + [k_vals_seed[r]] for r, row in enumerate(V)]
                    solved = True
                    for col in range(3):
                        # Find pivot
                        pivot = None
                        for row in range(col, 3):
                            if mod_inverse(M[row][col], 26) is not None:
                                pivot = row
                                break
                        if pivot is None:
                            solved = False
                            break
                        M[col], M[pivot] = M[pivot], M[col]
                        inv = mod_inverse(M[col][col], 26)
                        for ci in range(4):
                            M[col][ci] = (M[col][ci] * inv) % 26
                        for row in range(3):
                            if row != col and M[row][col] != 0:
                                factor = M[row][col]
                                for ci in range(4):
                                    M[row][ci] = (M[row][ci] - factor * M[col][ci]) % 26

                    if not solved:
                        continue

                    a, b, c = M[0][3], M[1][3], M[2][3]

                    # Check all points
                    matches = sum(1 for idx, p in enumerate(positions)
                                  if (a + b * p + c * p * p) % 26 == values[idx])

                    if matches > best_poly['matches']:
                        best_poly = {
                            'degree': 2, 'matches': matches,
                            'total': n_pts, 'variant': variant,
                            'order': order, 'coeffs': [a, b, c]
                        }

            # For degrees 3-6, use a simpler heuristic: sample a few seed sets
            elif degree <= 6:
                # Try fitting from first degree+1 points
                j_vals = positions[:degree+1]
                k_vals_seed = values[:degree+1]
                d = degree + 1

                # Build Vandermonde matrix mod 26
                V = [[(j_vals[r]**c) % 26 for c in range(d)] for r in range(d)]
                M = [V[r][:] + [k_vals_seed[r]] for r in range(d)]

                solved = True
                for col in range(d):
                    pivot = None
                    for row in range(col, d):
                        if mod_inverse(M[row][col], 26) is not None:
                            pivot = row
                            break
                    if pivot is None:
                        solved = False
                        break
                    M[col], M[pivot] = M[pivot], M[col]
                    inv = mod_inverse(M[col][col], 26)
                    for ci in range(d + 1):
                        M[col][ci] = (M[col][ci] * inv) % 26
                    for row in range(d):
                        if row != col and M[row][col] != 0:
                            factor = M[row][col]
                            for ci in range(d + 1):
                                M[row][ci] = (M[row][ci] - factor * M[col][ci]) % 26

                if not solved:
                    continue

                coeffs = [M[r][d] for r in range(d)]

                # Check all points
                matches = 0
                for idx, p in enumerate(positions):
                    val = sum(coeffs[c] * pow(p, c, 26) for c in range(d)) % 26
                    if val == values[idx]:
                        matches += 1

                if matches > best_poly['matches']:
                    best_poly = {
                        'degree': degree, 'matches': matches,
                        'total': n_pts, 'variant': variant,
                        'order': order, 'coeffs': coeffs
                    }

    if (oi + 1) % 1000 == 0:
        elapsed = time.time() - t0
        print(f"  [{oi+1}/{len(all_orders)}] {elapsed:.1f}s | "
              f"best poly: {best_poly['matches']}/{best_poly['total']} "
              f"deg={best_poly['degree']}")

elapsed_p1 = time.time() - t0
print(f"\n  Phase 1 done in {elapsed_p1:.1f}s")
print(f"  Best polynomial: {best_poly['matches']}/{best_poly['total']} "
      f"at degree {best_poly['degree']} ({best_poly['variant']})")
print(f"  Order: {best_poly['order']}, Coeffs: {best_poly['coeffs']}")


# ── Phase 2: Fibonacci recurrence ─────────────────────────────────────────

print("\n" + "-" * 50)
print("Phase 2: Fibonacci recurrence k[j] = (k[j-a] + k[j-b]) % 26")
print("-" * 50)

t1 = time.time()

# For each ordering, compute k_obs, then for each lag pair (a,b),
# check how many triples (j, j-a, j-b) satisfy the recurrence.
LAG_PAIRS = [(a, b) for a in range(1, 15) for b in range(a + 1, 15)]

best_fib = {'matches': 0, 'checkable': 0, 'lag_a': 0, 'lag_b': 0,
            'variant': '', 'order': []}

for oi, order in enumerate(all_orders):
    order = list(order)
    perm = build_columnar_perm(order)

    for variant in VARIANTS:
        k_obs = compute_k_obs(perm, variant)
        k_set = set(k_obs.keys())

        for a, b in LAG_PAIRS:
            matches = 0
            checkable = 0
            for j in range(b, N):
                if j in k_set and (j - a) in k_set and (j - b) in k_set:
                    checkable += 1
                    if (k_obs[j - a] + k_obs[j - b]) % 26 == k_obs[j]:
                        matches += 1

            if checkable > 0 and matches > best_fib['matches']:
                best_fib = {
                    'matches': matches, 'checkable': checkable,
                    'lag_a': a, 'lag_b': b,
                    'variant': variant, 'order': order
                }

    if (oi + 1) % 1000 == 0:
        elapsed = time.time() - t1
        print(f"  [{oi+1}/{len(all_orders)}] {elapsed:.1f}s | "
              f"best fib: {best_fib['matches']}/{best_fib['checkable']}")

elapsed_p2 = time.time() - t1
print(f"\n  Phase 2 done in {elapsed_p2:.1f}s")
print(f"  Best Fibonacci: {best_fib['matches']}/{best_fib['checkable']} "
      f"lags=({best_fib['lag_a']},{best_fib['lag_b']}) "
      f"({best_fib['variant']})")
print(f"  Order: {best_fib['order']}")


# ── Phase 3: Linear congruential ─────────────────────────────────────────

print("\n" + "-" * 50)
print("Phase 3: Linear congruential k[j] = (a*k[j-1] + b) % 26")
print("-" * 50)

t2 = time.time()

best_lcg = {'matches': 0, 'checkable': 0, 'a': 0, 'b': 0,
            'variant': '', 'order': []}

for oi, order in enumerate(all_orders):
    order = list(order)
    perm = build_columnar_perm(order)

    for variant in VARIANTS:
        k_obs = compute_k_obs(perm, variant)

        # Find consecutive pairs (j, j+1) both in k_obs
        consecutive_pairs = []
        for j in sorted(k_obs.keys()):
            if j + 1 in k_obs:
                consecutive_pairs.append((j, j + 1))

        if len(consecutive_pairs) < 2:
            continue

        # For each (a, b) pair (0-25 each), check consistency
        for a_val in range(26):
            for b_val in range(26):
                matches = 0
                for j1, j2 in consecutive_pairs:
                    if (a_val * k_obs[j1] + b_val) % 26 == k_obs[j2]:
                        matches += 1

                if matches > best_lcg['matches']:
                    best_lcg = {
                        'matches': matches,
                        'checkable': len(consecutive_pairs),
                        'a': a_val, 'b': b_val,
                        'variant': variant, 'order': order
                    }

    if (oi + 1) % 1000 == 0:
        elapsed = time.time() - t2
        print(f"  [{oi+1}/{len(all_orders)}] {elapsed:.1f}s | "
              f"best LCG: {best_lcg['matches']}/{best_lcg['checkable']}")

elapsed_p3 = time.time() - t2
print(f"\n  Phase 3 done in {elapsed_p3:.1f}s")
print(f"  Best LCG: {best_lcg['matches']}/{best_lcg['checkable']} "
      f"a={best_lcg['a']} b={best_lcg['b']} ({best_lcg['variant']})")
print(f"  Order: {best_lcg['order']}")


# ── Phase 4: Also test direct correspondence (no transposition) ──────────

print("\n" + "-" * 50)
print("Phase 4: Direct correspondence (no transposition)")
print("-" * 50)

identity = list(range(N))
direct_results = {}

for variant in VARIANTS:
    k_obs = compute_k_obs(identity, variant)
    positions = sorted(k_obs.keys())
    values = [k_obs[p] for p in positions]

    # Polynomial deg 1
    for i in range(len(positions)):
        for j_idx in range(i + 1, min(i + 5, len(positions))):
            j1, j2 = positions[i], positions[j_idx]
            k1, k2 = values[i], values[j_idx]
            dj = (j2 - j1) % 26
            dk = (k2 - k1) % 26
            inv_dj = mod_inverse(dj, 26)
            if inv_dj is None:
                continue
            b = (dk * inv_dj) % 26
            a = (k1 - b * j1) % 26
            matches = sum(1 for idx, p in enumerate(positions)
                          if (a + b * p) % 26 == values[idx])
            key = ('poly1', variant)
            if key not in direct_results or matches > direct_results[key][0]:
                direct_results[key] = (matches, len(positions), a, b)

    # Fibonacci
    k_set = set(k_obs.keys())
    for a_lag, b_lag in LAG_PAIRS:
        matches = 0
        checkable = 0
        for j in range(b_lag, N):
            if j in k_set and (j - a_lag) in k_set and (j - b_lag) in k_set:
                checkable += 1
                if (k_obs[j - a_lag] + k_obs[j - b_lag]) % 26 == k_obs[j]:
                    matches += 1
        key = ('fib', variant, a_lag, b_lag)
        if checkable > 0:
            direct_results[key] = (matches, checkable)

print(f"  Direct polynomial-1 results:")
for key, val in sorted(direct_results.items()):
    if key[0] == 'poly1':
        _, var = key
        m, total, a, b = val
        print(f"    {var}: {m}/{total} (a={a}, b={b})")

# Find best direct Fibonacci
best_direct_fib = (0, 0, 0, 0, '')
for key, val in direct_results.items():
    if key[0] == 'fib':
        _, var, a_lag, b_lag = key
        if val[0] > best_direct_fib[0]:
            best_direct_fib = (val[0], val[1], a_lag, b_lag, var)

print(f"  Direct Fibonacci: {best_direct_fib[0]}/{best_direct_fib[1]} "
      f"lags=({best_direct_fib[2]},{best_direct_fib[3]}) "
      f"({best_direct_fib[4]})")


# ── Summary ──────────────────────────────────────────────────────────────

total_elapsed = time.time() - t0
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Polynomial: best {best_poly['matches']}/{best_poly['total']} "
      f"deg={best_poly['degree']} ({best_poly['variant']})")
print(f"  Fibonacci:  best {best_fib['matches']}/{best_fib['checkable']} "
      f"lags=({best_fib['lag_a']},{best_fib['lag_b']}) "
      f"({best_fib['variant']})")
print(f"  LCG:        best {best_lcg['matches']}/{best_lcg['checkable']} "
      f"a={best_lcg['a']} b={best_lcg['b']} ({best_lcg['variant']})")
print(f"  Total time: {total_elapsed:.1f}s")

# Significance assessment
# For poly deg 1: 24 positions, expected ~2/24 (random a,b can match ~2)
# For Fibonacci: ~1-2 checkable triples, expected ~1/26
# For LCG: ~3-6 consecutive pairs, expected ~1/26 per pair

max_score = max(best_poly['matches'], best_fib['matches'], best_lcg['matches'])
if max_score >= 15:
    verdict = f"SIGNAL — {max_score} matches, investigate"
elif max_score >= 8:
    verdict = f"INTERESTING — {max_score} matches, check for underdetermination"
else:
    verdict = f"NO SIGNAL — all results at noise floor"

print(f"\n  Verdict: {verdict}")

output = {
    'experiment': 'E-S-84',
    'description': 'Polynomial/recurrence key + width-7 columnar',
    'polynomial_best': best_poly,
    'fibonacci_best': best_fib,
    'lcg_best': best_lcg,
    'elapsed_seconds': total_elapsed,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_84_polynomial_key_columnar.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_84_polynomial_key_columnar.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_84_polynomial_key_columnar.py")
