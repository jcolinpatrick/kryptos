#!/usr/bin/env python3
"""
Cipher: autokey
Family: polyalphabetic
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-69: PT-Autokey Algebraic Elimination

PT-autokey cipher: CT[i] = f(PT[i], PT[i-k]) where k = primer length.

Under Vigenère: CT[i] = (PT[i] + PT[i-k]) % 26, so PT[i] = (CT[i] - PT[i-k]) % 26
Under Beaufort: CT[i] = (PT[i-k] - PT[i]) % 26, so PT[i] = (PT[i-k] - CT[i]) % 26
Under Variant: CT[i] = (PT[i] - PT[i-k]) % 26, so PT[i] = (CT[i] + PT[i-k]) % 26

Key insight: the 24 crib values create CHAIN CONSTRAINTS. If PT[p1] and
PT[p1+k] are both known, the autokey recurrence is FULLY DETERMINED and
can be checked against the CT.

Phase 1: Direct correspondence (no transposition) — check all k=1..96
Phase 2: Width-7 columnar (Model B) — all orderings × k=1..96
Phase 3: For any surviving (ordering, k, variant), propagate to get full PT
"""

import json
import os
import time
from itertools import permutations

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
CRIB_IDX = {p: IDX[c] for p, c in CRIB_DICT.items()}
CRIB_POS = sorted(CRIB_DICT.keys())

WIDTH = 7
COL_LENS = [14, 14, 14, 14, 14, 14, 13]

print("=" * 70)
print("E-S-69: PT-Autokey Algebraic Elimination")
print("=" * 70)

# ── Phase 1: Direct correspondence ────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 1: Direct PT-autokey, no transposition")
print("-" * 50)

# For each k, variant: check if crib chain is consistent
# For each pair (p, p+k) both in CRIB_DICT:
#   Vig: PT[p+k] should = (CT[p+k] - PT[p]) % 26
#   Beau: PT[p+k] should = (PT[p] - CT[p+k]) % 26
#   VB: PT[p+k] should = (CT[p+k] + PT[p]) % 26

variants = {
    'vig': lambda ct, pt_prev: (ct - pt_prev) % 26,
    'beau': lambda ct, pt_prev: (pt_prev - ct) % 26,
    'vbeau': lambda ct, pt_prev: (ct + pt_prev) % 26,
}

survivors_p1 = []
for k in range(1, N):
    for vname, decrypt in variants.items():
        consistent = True
        pairs_checked = 0
        for p in CRIB_POS:
            p2 = p + k
            if p2 in CRIB_IDX:
                expected = CRIB_IDX[p2]
                computed = decrypt(CT_IDX[p2], CRIB_IDX[p])
                pairs_checked += 1
                if computed != expected:
                    consistent = False
                    break
        if consistent and pairs_checked > 0:
            survivors_p1.append((k, vname, pairs_checked))

print(f"  Survivors (k, variant, pairs_checked):")
for k, vname, pc in survivors_p1:
    print(f"    k={k:3d} {vname:>5} checked={pc}")
    # For survivors, propagate and see what PT we get
    pt = [None] * N
    for p, c in CRIB_DICT.items():
        pt[p] = IDX[c]
    # Chain forward
    decrypt = variants[vname]
    changed = True
    while changed:
        changed = False
        for i in range(N):
            if pt[i] is not None and i + k < N and pt[i + k] is None:
                pt[i + k] = decrypt(CT_IDX[i + k], pt[i])
                changed = True
            if pt[i] is not None and i - k >= 0 and pt[i - k] is None:
                # Reverse: PT[i-k] is the "previous" in the chain
                # CT[i] = f(PT[i], PT[i-k])
                # For vig: CT[i] = (PT[i] + PT[i-k]) % 26 → PT[i-k] = (CT[i] - PT[i]) % 26
                if vname == 'vig':
                    pt[i - k] = (CT_IDX[i] - pt[i]) % 26
                elif vname == 'beau':
                    # CT[i] = (PT[i-k] - PT[i]) % 26 → PT[i-k] = (CT[i] + PT[i]) % 26
                    pt[i - k] = (CT_IDX[i] + pt[i]) % 26
                elif vname == 'vbeau':
                    # CT[i] = (PT[i] - PT[i-k]) % 26 → PT[i-k] = (PT[i] - CT[i]) % 26
                    pt[i - k] = (pt[i] - CT_IDX[i]) % 26
                changed = True

    filled = sum(1 for x in pt if x is not None)
    pt_str = ''.join(AZ[x] if x is not None else '.' for x in pt)
    print(f"      PT ({filled}/{N} filled): {pt_str}")

    # Check for contradictions in the propagated PT
    # (if the same position was filled from different chains)
    # This is already handled implicitly by the crib check above

if not survivors_p1:
    print("  NO survivors — PT-autokey ELIMINATED for all k, all variants")

# Also check: for survivors, does the PT look like English?
# (Quick check: count common English letters)

# ── Phase 2: Width-7 Columnar (Model B) ───────────────────────────────────
print("\n" + "-" * 50)
print("Phase 2: PT-autokey + Width-7 Columnar (Model B)")
print("-" * 50)

# Under Model B: intermediate = σ(PT), CT[j] = f(intermediate[j], intermediate[j-k])
# So: intermediate[j] = g(CT[j], intermediate[j-k])
# And PT[p] = intermediate[σ⁻¹(p)]
#
# For each crib position p (PT-space), σ⁻¹(p) = j (CT-space)
# We need: intermediate[j] = PT[p] (by definition of σ)
# And: intermediate[j] = g(CT[j], intermediate[j-k])
# So: PT[p] = g(CT[j], intermediate[j-k])
#
# If j-k ≥ 0 and intermediate[j-k] = PT[σ(j-k)] = PT[p2] where p2 = σ(j-k),
# and if p2 is a crib position, then:
# PT[p] = g(CT[j], PT[p2])
# This can be checked!

survivors_p2 = []
t0 = time.time()
orders_tested = 0

for order in permutations(range(WIDTH)):
    orders_tested += 1
    # Build σ: ct_pos → pt_pos (perm) and σ⁻¹: pt_pos → ct_pos (inv_perm)
    perm = [0] * N  # perm[j] = pt_pos
    inv_perm = [0] * N  # inv_perm[p] = ct_pos
    pos = 0
    for grid_col in order:
        for row in range(COL_LENS[grid_col]):
            pt_pos = row * WIDTH + grid_col
            perm[pos] = pt_pos
            inv_perm[pt_pos] = pos
            pos += 1

    for k in range(1, N):
        for vname, decrypt in variants.items():
            consistent = True
            pairs_checked = 0

            for p in CRIB_POS:
                j = inv_perm[p]  # CT position for crib position p
                j_prev = j - k   # Previous position in CT-space
                if 0 <= j_prev < N:
                    p2 = perm[j_prev]  # PT position that maps to j_prev
                    if p2 in CRIB_IDX:
                        # Check: PT[p] should = decrypt(CT[j], PT[p2])
                        expected = CRIB_IDX[p]
                        computed = decrypt(CT_IDX[j], CRIB_IDX[p2])
                        pairs_checked += 1
                        if computed != expected:
                            consistent = False
                            break

            if consistent and pairs_checked >= 3:  # Require ≥3 constraints for significance
                survivors_p2.append((list(order), k, vname, pairs_checked))

if survivors_p2:
    print(f"  {len(survivors_p2)} survivors with ≥3 constraints:")
    # Sort by pairs_checked descending
    survivors_p2.sort(key=lambda x: -x[3])
    for order, k, vname, pc in survivors_p2[:50]:
        print(f"    order={order} k={k:3d} {vname:>5} pairs={pc}")

        # Propagate to get full PT for top survivors
        if pc >= 5:
            perm_s = [0] * N
            inv_perm_s = [0] * N
            pos = 0
            for grid_col in order:
                for row in range(COL_LENS[grid_col]):
                    pt_pos = row * WIDTH + grid_col
                    perm_s[pos] = pt_pos
                    inv_perm_s[pt_pos] = pos
                    pos += 1

            # intermediate[j] = PT[perm_s[j]]
            intermediate = [None] * N
            for p, c in CRIB_DICT.items():
                j = inv_perm_s[p]
                intermediate[j] = IDX[c]

            # Propagate
            changed = True
            decrypt_fn = variants[vname]
            iters = 0
            while changed:
                changed = False
                iters += 1
                for j in range(N):
                    if intermediate[j] is not None and j + k < N and intermediate[j + k] is None:
                        intermediate[j + k] = decrypt_fn(CT_IDX[j + k], intermediate[j])
                        changed = True
                    if intermediate[j] is not None and j - k >= 0 and intermediate[j - k] is None:
                        if vname == 'vig':
                            intermediate[j - k] = (CT_IDX[j] - intermediate[j]) % 26
                        elif vname == 'beau':
                            intermediate[j - k] = (CT_IDX[j] + intermediate[j]) % 26
                        elif vname == 'vbeau':
                            intermediate[j - k] = (intermediate[j] - CT_IDX[j]) % 26
                        changed = True
                if iters > 200:
                    break

            filled = sum(1 for x in intermediate if x is not None)
            # Untranspose: PT[perm_s[j]] = intermediate[j]
            pt = [None] * N
            for j in range(N):
                if intermediate[j] is not None:
                    pt[perm_s[j]] = intermediate[j]
            pt_str = ''.join(AZ[x] if x is not None else '.' for x in pt)
            print(f"      PT ({filled}/{N}): {pt_str}")
else:
    print(f"  NO survivors with ≥3 constraints")

t1 = time.time()
print(f"\n  {orders_tested} orderings × 96 k-values × 3 variants, {t1-t0:.1f}s")

# ── Phase 3: CT-Autokey algebraic check ───────────────────────────────────
print("\n" + "-" * 50)
print("Phase 3: CT-Autokey algebraic check (direct correspondence)")
print("-" * 50)

# CT-autokey: key[i] = CT[i-k] for i ≥ k
# Vig: CT[i] = (PT[i] + CT[i-k]) % 26 → PT[i] = (CT[i] - CT[i-k]) % 26
# Beau: CT[i] = (CT[i-k] - PT[i]) % 26 → PT[i] = (CT[i-k] - CT[i]) % 26
# VB: CT[i] = (PT[i] - CT[i-k]) % 26 → PT[i] = (CT[i] + CT[i-k]) % 26

# Under direct correspondence, PT is FULLY DETERMINED by k and variant.
# Just check if PT matches all 24 cribs.

ct_auto_variants = {
    'vig': lambda i, k: (CT_IDX[i] - CT_IDX[i-k]) % 26,
    'beau': lambda i, k: (CT_IDX[i-k] - CT_IDX[i]) % 26,
    'vbeau': lambda i, k: (CT_IDX[i] + CT_IDX[i-k]) % 26,
}

best_ct_auto = {'cribs': 0}
for k in range(1, N):
    for vname, decrypt_fn in ct_auto_variants.items():
        cribs = 0
        for p, expected in CRIB_DICT.items():
            if p >= k:
                pt_v = decrypt_fn(p, k)
                if AZ[pt_v] == expected:
                    cribs += 1
            # For positions < k, we'd need the primer
            # For checking, just count positions ≥ k
        if cribs > best_ct_auto['cribs']:
            best_ct_auto = {'cribs': cribs, 'k': k, 'variant': vname}
        if cribs >= 10:
            print(f"  k={k:3d} {vname:>5}: {cribs}/24 (of positions ≥ k)")
            # Decrypt full PT
            pt = [None] * N
            for i in range(k, N):
                pt[i] = decrypt_fn(i, k)
            pt_str = ''.join(AZ[x] if x is not None else '.' for x in pt)
            print(f"    PT: {pt_str}")

print(f"  Best CT-autokey: {best_ct_auto['cribs']}/24 — {best_ct_auto}")

# ── Phase 4: CT-Autokey + Width-7 Columnar ────────────────────────────────
print("\n" + "-" * 50)
print("Phase 4: CT-Autokey + Width-7 Columnar (Model B)")
print("-" * 50)

# Under Model B: intermediate = σ(PT), key[j] = CT[j-k]
# CT[j] = (intermediate[j] + CT[j-k]) % 26 for Vig
# intermediate[j] = (CT[j] - CT[j-k]) % 26
# PT[σ(j)] = intermediate[j]
# PT is FULLY DETERMINED by (ordering, k, variant)

best_ct_w7 = {'cribs': 0}
configs_p4 = 0
t2 = time.time()

crib_items_list = list(CRIB_DICT.items())

for order in permutations(range(WIDTH)):
    # Build inv_perm for this ordering
    inv_perm_local = [0] * N
    pos = 0
    for grid_col in order:
        for row in range(COL_LENS[grid_col]):
            pt_pos = row * WIDTH + grid_col
            inv_perm_local[pt_pos] = pos
            pos += 1

    for k in range(1, N):
        for vname in ('vig', 'beau', 'vbeau'):
            cribs = 0
            for p, expected in crib_items_list:
                j = inv_perm_local[p]
                if j >= k:
                    if vname == 'vig':
                        inter_j = (CT_IDX[j] - CT_IDX[j-k]) % 26
                    elif vname == 'beau':
                        inter_j = (CT_IDX[j-k] - CT_IDX[j]) % 26
                    else:
                        inter_j = (CT_IDX[j] + CT_IDX[j-k]) % 26
                    if AZ[inter_j] == expected:
                        cribs += 1
            configs_p4 += 1
            if cribs > best_ct_w7['cribs']:
                best_ct_w7 = {'cribs': cribs, 'k': k, 'variant': vname, 'order': list(order)}
                if cribs >= 10:
                    print(f"  ** {cribs}/24 k={k} {vname} order={list(order)}")

t3 = time.time()
print(f"  {configs_p4:,} configs, {t3-t2:.1f}s, best={best_ct_w7['cribs']}/24")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
p1_status = f"{len(survivors_p1)} survivors" if survivors_p1 else "ELIMINATED"
p2_status = f"{len(survivors_p2)} survivors (≥3 pairs)" if survivors_p2 else "ELIMINATED"
print(f"  Phase 1 (PT-autokey direct): {p1_status}")
print(f"  Phase 2 (PT-autokey + w7): {p2_status}")
print(f"  Phase 3 (CT-autokey direct): best {best_ct_auto['cribs']}/24")
print(f"  Phase 4 (CT-autokey + w7): best {best_ct_w7['cribs']}/24")

output = {
    'experiment': 'E-S-69',
    'description': 'PT/CT-autokey algebraic elimination',
    'pt_auto_direct': [{'k': k, 'variant': v, 'pairs': p} for k, v, p in survivors_p1],
    'pt_auto_w7': [{'order': o, 'k': k, 'variant': v, 'pairs': p} for o, k, v, p in survivors_p2[:100]],
    'ct_auto_direct': best_ct_auto,
    'ct_auto_w7': best_ct_w7,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_69_autokey_algebraic.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_69_autokey_algebraic.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_69_pt_autokey_algebraic.py")
