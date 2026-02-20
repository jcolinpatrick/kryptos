#!/usr/bin/env python3
"""
E-S-67: Gromark / Numeric Recurrence Key Generation + Width-7 Columnar

The Gromark cipher uses a short numeric seed to generate a non-periodic key
via Fibonacci-like recurrence:
  key[i] = (key[i-k] + key[i-k+1]) mod 10  (standard Gromark)
  key[i] = (key[i-k] + key[i-1]) mod 10    (variant)
  key[i] = (key[i-1] + key[i-2]) mod B     (generalized Fibonacci, various bases)

Properties:
- Non-periodic (for most seeds), determined by short seed
- Hand-executable with paper and pencil
- "Change in methodology" from K3's repeating key

Tests:
1. Standard Gromark (mod 10) with seed lengths 2-7, all seeds
2. Generalized Fibonacci (mod 26) with seed lengths 2-5
3. Combined with width-7 columnar (Model B) — all orderings
4. Both Vigenère and Beaufort application

The digit constraint (values 0-9 for mod-10 Gromark) is EXTREMELY restrictive:
P(24 crib positions all ≤9) = (10/26)^24 ≈ 10^{-10}. So Gromark is
practically impossible UNLESS the correct ordering makes it work.
"""

import json
import os
import sys
import time
from itertools import permutations, product

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)  # 97

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

WIDTH = 7
NROWS = 14
COL_LENS = [14, 14, 14, 14, 14, 14, 13]

print("=" * 70)
print("E-S-67: Gromark / Numeric Recurrence Key + Width-7 Columnar")
print("=" * 70)

# ── Key generation functions ──────────────────────────────────────────────

def gromark_key(seed, length, base=10):
    """Standard Gromark: key[i] = (key[i-k] + key[i-k+1]) mod base"""
    k = len(seed)
    key = list(seed)
    for i in range(k, length):
        key.append((key[i - k] + key[i - k + 1]) % base)
    return key

def fibonacci_key(seed, length, base=26):
    """Fibonacci variant: key[i] = (key[i-1] + key[i-2]) mod base"""
    key = list(seed)
    for i in range(len(seed), length):
        key.append((key[i-1] + key[i-2]) % base)
    return key

def lagged_fib_key(seed, length, lag, base=26):
    """Lagged Fibonacci: key[i] = (key[i-1] + key[i-lag]) mod base"""
    key = list(seed)
    for i in range(len(seed), length):
        if i - lag >= 0:
            key.append((key[i-1] + key[i-lag]) % base)
        else:
            key.append((key[i-1]) % base)
    return key

# ── Phase 1: Direct Gromark (no transposition) ────────────────────────────
print("\n" + "-" * 50)
print("Phase 1: Direct Gromark (mod 10), no transposition")
print("-" * 50)

crib_items = list(CRIB_DICT.items())
best_p1 = {'cribs': 0}
configs_p1 = 0
t0 = time.time()

for seed_len in range(2, 8):
    best_for_len = 0
    for seed in product(range(10), repeat=seed_len):
        key = gromark_key(seed, N, base=10)
        for var_sign in (1, -1):
            cribs = 0
            for p, expected in crib_items:
                ct_v = CT_IDX[p]
                kv = key[p]
                pt_v = (ct_v - var_sign * kv) % 26
                if AZ[pt_v] == expected:
                    cribs += 1
            configs_p1 += 1
            if cribs > best_for_len:
                best_for_len = cribs
            if cribs > best_p1['cribs']:
                vname = 'vig' if var_sign == 1 else 'beau'
                best_p1 = {'cribs': cribs, 'seed': list(seed), 'variant': vname, 'base': 10}
                if cribs >= 10:
                    print(f"  ** HIT: {cribs}/24 seed={seed} {vname}")
    print(f"  seed_len={seed_len}: {10**seed_len} seeds, best={best_for_len}/24")

t1 = time.time()
print(f"  {configs_p1:,} configs, {t1-t0:.1f}s, best={best_p1['cribs']}/24")

# ── Phase 2: Fibonacci (mod 26), no transposition ─────────────────────────
print("\n" + "-" * 50)
print("Phase 2: Fibonacci (mod 26), no transposition")
print("-" * 50)

best_p2 = {'cribs': 0}
configs_p2 = 0
t2 = time.time()

for seed_len in range(2, 5):
    best_for_len = 0
    for seed in product(range(26), repeat=seed_len):
        key = fibonacci_key(seed, N, base=26)
        for var_sign in (1, -1):
            cribs = 0
            for p, expected in crib_items:
                ct_v = CT_IDX[p]
                kv = key[p]
                pt_v = (ct_v - var_sign * kv) % 26
                if AZ[pt_v] == expected:
                    cribs += 1
            configs_p2 += 1
            if cribs > best_for_len:
                best_for_len = cribs
            if cribs > best_p2['cribs']:
                vname = 'vig' if var_sign == 1 else 'beau'
                best_p2 = {'cribs': cribs, 'seed': list(seed), 'variant': vname, 'base': 26}
                if cribs >= 10:
                    print(f"  ** HIT: {cribs}/24 seed={seed} {vname}")
    count = 26**seed_len
    print(f"  seed_len={seed_len}: {count} seeds, best={best_for_len}/24")

t3 = time.time()
print(f"  {configs_p2:,} configs, {t3-t2:.1f}s, best={best_p2['cribs']}/24")

# ── Phase 3: Lagged Fibonacci (mod 26), lags 3-7, no transposition ────────
print("\n" + "-" * 50)
print("Phase 3: Lagged Fibonacci (mod 26, lags 3-7), no transposition")
print("-" * 50)

best_p3 = {'cribs': 0}
configs_p3 = 0
t3b = time.time()

for lag in range(3, 8):
    best_for_lag = 0
    seed_len = lag  # Need at least 'lag' initial values
    # For mod 26, seed_len=lag: 26^lag configs. lag=7: 26^7 = 8B — too many
    # Limit to lag ≤ 5 for full search, sample for lag 6-7
    if seed_len <= 4:
        seeds = product(range(26), repeat=seed_len)
        total = 26 ** seed_len
    else:
        # Sample
        import random
        random.seed(42)
        total = 100000
        seeds = [tuple(random.randint(0, 25) for _ in range(seed_len)) for _ in range(total)]

    for seed in seeds:
        key = lagged_fib_key(seed, N, lag, base=26)
        for var_sign in (1, -1):
            cribs = 0
            for p, expected in crib_items:
                ct_v = CT_IDX[p]
                kv = key[p]
                pt_v = (ct_v - var_sign * kv) % 26
                if AZ[pt_v] == expected:
                    cribs += 1
            configs_p3 += 1
            if cribs > best_for_lag:
                best_for_lag = cribs
            if cribs > best_p3['cribs']:
                vname = 'vig' if var_sign == 1 else 'beau'
                best_p3 = {'cribs': cribs, 'seed': list(seed), 'lag': lag, 'variant': vname}
                if cribs >= 10:
                    print(f"  ** HIT: {cribs}/24 lag={lag} seed={seed} {vname}")
    print(f"  lag={lag}: {total} seeds, best={best_for_lag}/24")

t4 = time.time()
print(f"  {configs_p3:,} configs, {t4-t3b:.1f}s, best={best_p3['cribs']}/24")

# ── Phase 4: Gromark + Width-7 Columnar (Model B) ─────────────────────────
print("\n" + "-" * 50)
print("Phase 4: Gromark (mod 10) + Width-7 Columnar (Model B)")
print("-" * 50)
print("  Testing seed_len 2-5 × 5040 orderings × vig/beau")

best_p4 = {'cribs': 0}
configs_p4 = 0
t5 = time.time()

# For each ordering, precompute inv_perm, then test all seeds
for seed_len in range(2, 6):
    best_for_len = 0
    for order in permutations(range(WIDTH)):
        # Build inv_perm: pt_pos → ct_pos
        inv_perm = [0] * N
        pos = 0
        for grid_col in order:
            for row in range(COL_LENS[grid_col]):
                pt_pos = row * WIDTH + grid_col
                inv_perm[pt_pos] = pos
                pos += 1

        # Precompute crib CT positions
        crib_ct = [(inv_perm[p], IDX[expected]) for p, expected in crib_items]

        for seed in product(range(10), repeat=seed_len):
            key = gromark_key(seed, N, base=10)
            for var_sign in (1, -1):
                cribs = 0
                for j, exp_idx in crib_ct:
                    kv = key[j]
                    ct_v = CT_IDX[j]
                    pt_v = (ct_v - var_sign * kv) % 26
                    if pt_v == exp_idx:
                        cribs += 1
                configs_p4 += 1
                if cribs > best_for_len:
                    best_for_len = cribs
                if cribs > best_p4['cribs']:
                    vname = 'vig' if var_sign == 1 else 'beau'
                    best_p4 = {
                        'cribs': cribs, 'seed': list(seed),
                        'order': list(order), 'variant': vname,
                    }
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 seed={seed} order={list(order)} {vname}")

    elapsed = time.time() - t5
    print(f"  seed_len={seed_len}: best={best_for_len}/24, {configs_p4:,} total configs, {elapsed:.0f}s")

t6 = time.time()
print(f"  Total: {configs_p4:,} configs in {t6-t5:.1f}s, best={best_p4['cribs']}/24")

# ── Phase 5: Fibonacci (mod 26) + Width-7 Columnar (Model B) ──────────────
print("\n" + "-" * 50)
print("Phase 5: Fibonacci (mod 26) + Width-7 Columnar (Model B)")
print("-" * 50)
print("  Testing seed_len 2-3 × 5040 orderings × vig/beau")

best_p5 = {'cribs': 0}
configs_p5 = 0
t7 = time.time()

for seed_len in range(2, 4):
    best_for_len = 0
    for order in permutations(range(WIDTH)):
        inv_perm = [0] * N
        pos = 0
        for grid_col in order:
            for row in range(COL_LENS[grid_col]):
                pt_pos = row * WIDTH + grid_col
                inv_perm[pt_pos] = pos
                pos += 1
        crib_ct = [(inv_perm[p], IDX[expected]) for p, expected in crib_items]

        for seed in product(range(26), repeat=seed_len):
            key = fibonacci_key(seed, N, base=26)
            for var_sign in (1, -1):
                cribs = 0
                for j, exp_idx in crib_ct:
                    kv = key[j]
                    ct_v = CT_IDX[j]
                    pt_v = (ct_v - var_sign * kv) % 26
                    if pt_v == exp_idx:
                        cribs += 1
                configs_p5 += 1
                if cribs > best_for_len:
                    best_for_len = cribs
                if cribs > best_p5['cribs']:
                    vname = 'vig' if var_sign == 1 else 'beau'
                    best_p5 = {
                        'cribs': cribs, 'seed': list(seed),
                        'order': list(order), 'variant': vname,
                    }
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 seed={seed} order={list(order)} {vname}")

    elapsed = time.time() - t7
    print(f"  seed_len={seed_len}: best={best_for_len}/24, {configs_p5:,} total configs, {elapsed:.0f}s")

t8 = time.time()
print(f"  Total: {configs_p5:,} configs in {t8-t7:.1f}s, best={best_p5['cribs']}/24")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (Gromark mod10, direct): best {best_p1['cribs']}/24 — {best_p1}")
print(f"  Phase 2 (Fibonacci mod26, direct): best {best_p2['cribs']}/24 — {best_p2}")
print(f"  Phase 3 (Lagged Fib mod26, direct): best {best_p3['cribs']}/24 — {best_p3}")
print(f"  Phase 4 (Gromark mod10 + w7): best {best_p4['cribs']}/24 — {best_p4}")
print(f"  Phase 5 (Fibonacci mod26 + w7): best {best_p5['cribs']}/24 — {best_p5}")

max_cribs = max(best_p1['cribs'], best_p2['cribs'], best_p3['cribs'],
                best_p4['cribs'], best_p5['cribs'])

if max_cribs >= 18:
    verdict = f"SIGNAL — {max_cribs}/24"
elif max_cribs >= 10:
    verdict = f"WEAK SIGNAL — {max_cribs}/24"
else:
    verdict = f"NO SIGNAL — all at noise (best {max_cribs}/24)"

print(f"\n  Verdict: {verdict}")
total = configs_p1 + configs_p2 + configs_p3 + configs_p4 + configs_p5
print(f"  Total configs: {total:,}")

# Save
output = {
    'experiment': 'E-S-67',
    'description': 'Gromark/numeric recurrence key + width-7 columnar',
    'phase1': best_p1,
    'phase2': best_p2,
    'phase3': best_p3,
    'phase4': best_p4,
    'phase5': best_p5,
    'verdict': verdict,
    'total_configs': total,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_67_gromark.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_67_gromark.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_67_gromark_numeric_key.py")
