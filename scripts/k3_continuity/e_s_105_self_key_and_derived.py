#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: k3_continuity
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-105: Self-Keying Double Columnar + Derived Key Schemes

Two novel approaches:

A) Self-keying: The key is derived from the CT itself, read in a different
   column order than the "transposition" column order. This creates a
   non-periodic, structured key from the CT.

   For (σ_trans, σ_key) pair:
     intermediate[j] = CT[perm_trans[j]]
     key[j] = CT[perm_key[j]]
     PT[j] = (intermediate[j] - key[j]) mod 26  (or Beaufort/VBeau)

   At cribs: (CT[perm_trans[p]] - CT[perm_key[p]]) mod 26 = PT_FULL[p]
   Search: 5040² = 25.4M pairs, 24 constraints each → fast

B) Derived key from keyword: Instead of repeating a keyword, generate
   a full-length key by transforming a keyword through various algorithms.

   Schemes tested:
   1. Cumulative sum: key[i] = Σ keyword[j] for j≤i (mod 26)
   2. Fibonacci-like: key[i] = key[i-1] + key[i-2] (mod 26)
   3. Progressive shift: keyword repeated but shifted by row
   4. Multiplication: key[i] = keyword[i%p] * (i//p + 1) (mod 26)
   5. XOR chain: key[i] = keyword[i%p] ^ key[i-1]
"""

import json, os, time
from itertools import permutations
from collections import Counter

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_FULL = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())

W = 7


def build_perm(order, w=W):
    nr = (N + w - 1) // w
    ns = nr * w - N
    p = []
    for k in range(w):
        c = order[k]
        sz = nr - 1 if c >= w - ns else nr
        for r in range(sz):
            p.append(r * w + c)
    return p


def check_cribs(pt):
    return sum(1 for p in CPOS if pt[p] == PT_FULL[p])


ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
    "BERLIN", "CLOCK", "EGYPT", "CAIRO", "PYRAMID",
    "LANGLEY", "SHADOW", "LUCID", "SUBTLE", "IQLUSION",
    "COMPASS", "POINT", "MESSAGE", "SECRET", "CIPHER",
    "ENIGMA", "CARTER", "TOMB", "CANDLE", "FLAME",
    "DELIVER", "BURIED", "LOCATION", "INVISIBLE",
    "KRYPTOSABCDEFGHIJLMNQUVWXZ",  # Full KA alphabet
]


def keyword_to_nums(kw):
    return [I2N[c] for c in kw.upper() if c in AZ]


print("=" * 70)
print("E-S-105: Self-Keying Double Columnar + Derived Key Schemes")
print(f"  N={N}, W={W}, orderings={len(ORDERS)}")
print("=" * 70)

t0 = time.time()
results = {}


# ── Phase A: Self-keying double columnar ──────────────────────────────
print("\n--- PA: Self-keying double columnar ---")
print(f"  Testing {len(ORDERS)}² = {len(ORDERS)**2:,} pairs...")

pa_best = (0, None, None, None)
pa_survivors = 0

for oi_trans in range(len(ORDERS)):
    perm_t = PERMS[oi_trans]

    for oi_key in range(len(ORDERS)):
        perm_k = PERMS[oi_key]

        # Check all 3 variants
        for vi in range(3):
            matches = 0
            for p in CPOS:
                ct_t = CT_N[perm_t[p]]
                ct_k = CT_N[perm_k[p]]
                if vi == 0:  # Vig: PT = I - K
                    dec = (ct_t - ct_k) % 26
                elif vi == 1:  # Beau: PT = K - I
                    dec = (ct_k - ct_t) % 26
                else:  # VBeau: PT = I + K
                    dec = (ct_t + ct_k) % 26

                if dec == PT_FULL[p]:
                    matches += 1
                else:
                    # Early termination: if remaining can't reach 18
                    remaining = len(CPOS) - CPOS.index(p) - 1
                    if matches + remaining < 18:
                        break

            if matches > pa_best[0]:
                pa_best = (matches, ORDERS[oi_trans], ORDERS[oi_key],
                          ['Vig', 'Beau', 'VBeau'][vi])

            if matches >= 24:
                pa_survivors += 1
                pt = [0] * N
                for j in range(N):
                    ct_t = CT_N[perm_t[j]]
                    ct_k = CT_N[perm_k[j]]
                    if vi == 0:
                        pt[j] = (ct_t - ct_k) % 26
                    elif vi == 1:
                        pt[j] = (ct_k - ct_t) % 26
                    else:
                        pt[j] = (ct_t + ct_k) % 26
                pt_text = ''.join(AZ[x] for x in pt)
                print(f"  BREAKTHROUGH: trans={ORDERS[oi_trans]} key={ORDERS[oi_key]}")
                print(f"    PT: {pt_text}")

    if oi_trans % 500 == 0:
        print(f"    trans {oi_trans}/5040, best={pa_best[0]}/24, {time.time()-t0:.1f}s")

print(f"  PA: best={pa_best[0]}/24, survivors={pa_survivors}")
print(f"  Best config: {pa_best}")
print(f"  {time.time()-t0:.1f}s")
results['PA_self_key'] = {'best': pa_best[0], 'survivors': pa_survivors}


# ── Phase B1: Cumulative sum key ──────────────────────────────────────
print("\n--- PB1: Cumulative sum key ---")
# key[i] = cumsum(keyword, repeating) mod 26
# Non-periodic because cumsum grows

pb1_best = (0, None, None, None)

for kw_str in KEYWORDS:
    kw = keyword_to_nums(kw_str)
    p = len(kw)
    if p == 0:
        continue

    # Generate cumsum key
    key = [0] * N
    running_sum = 0
    for i in range(N):
        running_sum = (running_sum + kw[i % p]) % 26
        key[i] = running_sum

    for oi in range(len(ORDERS)):
        intermed = [CT_N[PERMS[oi][j]] for j in range(N)]

        for vi in range(3):
            pt = [0] * N
            for j in range(N):
                if vi == 0:
                    pt[j] = (intermed[j] - key[j]) % 26
                elif vi == 1:
                    pt[j] = (key[j] - intermed[j]) % 26
                else:
                    pt[j] = (intermed[j] + key[j]) % 26

            score = check_cribs(pt)
            if score > pb1_best[0]:
                pb1_best = (score, kw_str, ORDERS[oi], ['Vig', 'Beau', 'VBeau'][vi])

print(f"  PB1: best={pb1_best[0]}/24 ({pb1_best[1]}, {pb1_best[3]})")
results['PB1_cumsum'] = {'best': pb1_best[0]}


# ── Phase B2: Fibonacci-like key ──────────────────────────────────────
print("\n--- PB2: Fibonacci-like key ---")

pb2_best = (0, None, None, None)

for kw_str in KEYWORDS:
    kw = keyword_to_nums(kw_str)
    p = len(kw)
    if p < 2:
        continue

    # Fibonacci: start with keyword, then key[i] = key[i-1] + key[i-2]
    key = list(kw)
    while len(key) < N:
        key.append((key[-1] + key[-2]) % 26)
    key = key[:N]

    for oi in range(len(ORDERS)):
        intermed = [CT_N[PERMS[oi][j]] for j in range(N)]

        for vi in range(3):
            pt = [0] * N
            for j in range(N):
                if vi == 0:
                    pt[j] = (intermed[j] - key[j]) % 26
                elif vi == 1:
                    pt[j] = (key[j] - intermed[j]) % 26
                else:
                    pt[j] = (intermed[j] + key[j]) % 26

            score = check_cribs(pt)
            if score > pb2_best[0]:
                pb2_best = (score, kw_str, ORDERS[oi], ['Vig', 'Beau', 'VBeau'][vi])

    # Also test tribonacci: key[i] = key[i-1] + key[i-2] + key[i-3]
    if p >= 3:
        key = list(kw)
        while len(key) < N:
            key.append((key[-1] + key[-2] + key[-3]) % 26)
        key = key[:N]

        for oi in range(len(ORDERS)):
            intermed = [CT_N[PERMS[oi][j]] for j in range(N)]
            for vi in range(3):
                pt = [0] * N
                for j in range(N):
                    if vi == 0:
                        pt[j] = (intermed[j] - key[j]) % 26
                    elif vi == 1:
                        pt[j] = (key[j] - intermed[j]) % 26
                    else:
                        pt[j] = (intermed[j] + key[j]) % 26
                score = check_cribs(pt)
                if score > pb2_best[0]:
                    pb2_best = (score, kw_str + "_tri", ORDERS[oi], ['Vig', 'Beau', 'VBeau'][vi])

print(f"  PB2: best={pb2_best[0]}/24 ({pb2_best[1]}, {pb2_best[3]})")
results['PB2_fibonacci'] = {'best': pb2_best[0]}


# ── Phase B3: Multiplication chain key ────────────────────────────────
print("\n--- PB3: Multiplication chain key ---")
# key[i] = keyword[i%p] * keyword[(i+1)%p] mod 26
# Or: key[i] = keyword[i%p] * (i+1) mod 26

pb3_best = (0, None, None, None)

for kw_str in KEYWORDS:
    kw = keyword_to_nums(kw_str)
    p = len(kw)
    if p == 0:
        continue

    # Model 1: key[i] = kw[i%p] * (i//p + 1) mod 26
    key1 = [(kw[i % p] * (i // p + 1)) % 26 for i in range(N)]

    # Model 2: key[i] = kw[i%p] * kw[(i+1)%p] + i mod 26
    key2 = [(kw[i % p] * kw[(i + 1) % p] + i) % 26 for i in range(N)]

    for key, label in [(key1, "mult_row"), (key2, "mult_pair")]:
        for oi in range(len(ORDERS)):
            intermed = [CT_N[PERMS[oi][j]] for j in range(N)]
            for vi in range(3):
                pt = [0] * N
                for j in range(N):
                    if vi == 0:
                        pt[j] = (intermed[j] - key[j]) % 26
                    elif vi == 1:
                        pt[j] = (key[j] - intermed[j]) % 26
                    else:
                        pt[j] = (intermed[j] + key[j]) % 26
                score = check_cribs(pt)
                if score > pb3_best[0]:
                    pb3_best = (score, f"{kw_str}_{label}", ORDERS[oi],
                               ['Vig', 'Beau', 'VBeau'][vi])

print(f"  PB3: best={pb3_best[0]}/24 ({pb3_best[1]}, {pb3_best[3]})")
results['PB3_multiplication'] = {'best': pb3_best[0]}


# ── Phase B4: Difference/XOR chain key ────────────────────────────────
print("\n--- PB4: Difference/XOR chain key ---")

pb4_best = (0, None, None, None)

for kw_str in KEYWORDS:
    kw = keyword_to_nums(kw_str)
    p = len(kw)
    if p == 0:
        continue

    # Model 1: running difference — key[i] = (key[i-1] - kw[i%p]) mod 26
    key1 = [kw[0]]
    for i in range(1, N):
        key1.append((key1[-1] - kw[i % p]) % 26)

    # Model 2: running XOR — key[i] = key[i-1] XOR kw[i%p]
    key2 = [kw[0]]
    for i in range(1, N):
        key2.append(key2[-1] ^ kw[i % p])
    key2 = [k % 26 for k in key2]

    for key, label in [(key1, "diff_chain"), (key2, "xor_chain")]:
        for oi in range(len(ORDERS)):
            intermed = [CT_N[PERMS[oi][j]] for j in range(N)]
            for vi in range(3):
                pt = [0] * N
                for j in range(N):
                    if vi == 0:
                        pt[j] = (intermed[j] - key[j]) % 26
                    elif vi == 1:
                        pt[j] = (key[j] - intermed[j]) % 26
                    else:
                        pt[j] = (intermed[j] + key[j]) % 26
                score = check_cribs(pt)
                if score > pb4_best[0]:
                    pb4_best = (score, f"{kw_str}_{label}", ORDERS[oi],
                               ['Vig', 'Beau', 'VBeau'][vi])

print(f"  PB4: best={pb4_best[0]}/24 ({pb4_best[1]}, {pb4_best[3]})")
results['PB4_chain'] = {'best': pb4_best[0]}


# ── Phase B5: Power/modular exponentiation key ───────────────────────
print("\n--- PB5: Power key: key[i] = base^i mod 26 ---")

pb5_best = (0, None, None, None)

for base in range(2, 26):
    key = [pow(base, i, 26) for i in range(N)]

    for oi in range(len(ORDERS)):
        intermed = [CT_N[PERMS[oi][j]] for j in range(N)]
        for vi in range(3):
            pt = [0] * N
            for j in range(N):
                if vi == 0:
                    pt[j] = (intermed[j] - key[j]) % 26
                elif vi == 1:
                    pt[j] = (key[j] - intermed[j]) % 26
                else:
                    pt[j] = (intermed[j] + key[j]) % 26
            score = check_cribs(pt)
            if score > pb5_best[0]:
                pb5_best = (score, f"base={base}", ORDERS[oi],
                           ['Vig', 'Beau', 'VBeau'][vi])

# Also: base^i mod 97 mod 26 (using prime length)
for base in range(2, 97):
    key = [pow(base, i, 97) % 26 for i in range(N)]
    for oi in range(len(ORDERS)):
        intermed = [CT_N[PERMS[oi][j]] for j in range(N)]
        for vi in range(3):
            pt = [0] * N
            for j in range(N):
                if vi == 0:
                    pt[j] = (intermed[j] - key[j]) % 26
                elif vi == 1:
                    pt[j] = (key[j] - intermed[j]) % 26
                else:
                    pt[j] = (intermed[j] + key[j]) % 26
            score = check_cribs(pt)
            if score > pb5_best[0]:
                pb5_best = (score, f"base={base}_mod97", ORDERS[oi],
                           ['Vig', 'Beau', 'VBeau'][vi])

print(f"  PB5: best={pb5_best[0]}/24 ({pb5_best[1]}, {pb5_best[3]})")
results['PB5_power'] = {'best': pb5_best[0]}


# ── Phase C: Direct (no transposition) versions of all schemes ───────
print("\n--- PC: All key schemes, no transposition ---")

pc_best = (0, None)

for kw_str in KEYWORDS[:10]:  # Top 10 keywords
    kw = keyword_to_nums(kw_str)
    p = len(kw)
    if p < 2:
        continue

    keys = {}

    # Cumsum
    k = [0] * N
    s = 0
    for i in range(N):
        s = (s + kw[i % p]) % 26
        k[i] = s
    keys[f'{kw_str}_cumsum'] = k

    # Fibonacci
    k = list(kw)
    while len(k) < N:
        k.append((k[-1] + k[-2]) % 26)
    keys[f'{kw_str}_fib'] = k[:N]

    # Multiplication
    keys[f'{kw_str}_mult'] = [(kw[i % p] * (i // p + 1)) % 26 for i in range(N)]

    # Diff chain
    k = [kw[0]]
    for i in range(1, N):
        k.append((k[-1] - kw[i % p]) % 26)
    keys[f'{kw_str}_diff'] = k

    for name, key in keys.items():
        for vi in range(3):
            pt = [0] * N
            for j in range(N):
                if vi == 0:
                    pt[j] = (CT_N[j] - key[j]) % 26
                elif vi == 1:
                    pt[j] = (key[j] - CT_N[j]) % 26
                else:
                    pt[j] = (CT_N[j] + key[j]) % 26
            score = check_cribs(pt)
            if score > pc_best[0]:
                pc_best = (score, f"{name}_{['Vig','Beau','VBeau'][vi]}")

print(f"  PC: best={pc_best[0]}/24 ({pc_best[1]})")
results['PC_direct'] = {'best': pc_best[0]}


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for phase, data in sorted(results.items()):
    print(f"  {phase}: {data}")
print(f"  Total: {total_elapsed:.1f}s")

best_overall = max(v.get('best', v.get('survivors', 0)) for v in results.values())
if best_overall >= 18:
    print(f"\n  Verdict: SIGNAL — {best_overall}/24")
elif best_overall >= 10:
    print(f"\n  Verdict: ELEVATED — {best_overall}/24 (likely noise)")
else:
    print(f"\n  Verdict: NOISE — {best_overall}/24")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-105',
    'description': 'Self-keying double columnar + derived key schemes',
    'results': {k: str(v) for k, v in results.items()},
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_105_self_key_derived.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_105_self_key_derived.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_105_self_key_and_derived.py")
