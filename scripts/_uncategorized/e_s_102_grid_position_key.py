#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-102: Grid-Position Key Generation + Width-7 Columnar

Hypothesis: The K4 key is derived from the position in a 7-column grid.
If the PT is written in a 7×14 grid and read column-by-column (columnar
transposition), then each position j in the output has a (row, col) in
the original grid. The key could be:

  k[j] = f(row_j, col_j) mod 26

This produces a NON-PERIODIC key even with simple functions f, because
the relationship between output position j and grid (row, col) is
non-linear after columnar transposition.

Models tested:
  P1: Linear key: k = a*row + b*col + c (mod 26)       — 3 params
  P2: Quadratic key: k = a*r² + b*c² + d*rc + e*r + f*c + g  — 6 params
  P3: Keyword + row: k = keyword[col] + a*row (mod 26)  — 1+len(kw) params
  P4: KRYPTOS + row: k = KA_key[col%7] + a*row (mod 26) — 1 param
  P5: Keyword × row: k = keyword[col] * (row+1) (mod 26)
  P6: General keyword + polynomial(row)

With 24 cribs and 3-6 free parameters, all models are heavily
overdetermined → definitive test.

Model B convention: CT[j] = (I[j] + key[j]) mod 26
where I = columnar_transpose(PT).
Decryption: I[j] = (CT[j] - key[j]) mod 26, then PT = inverse_transpose(I).
"""

import json, os, time, math
from itertools import permutations

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
    """Build columnar transposition permutation (gather convention).
    perm[j] = original position that goes to output position j.
    """
    nr = (N + w - 1) // w
    ns = nr * w - N  # number of short columns
    perm = []
    for k in range(w):
        c = order[k]
        sz = nr - 1 if c >= w - ns else nr
        for r in range(sz):
            perm.append(r * w + c)
    return perm


def grid_pos(j, order, w=W):
    """Given output position j and column order, return (row, col) in original grid."""
    nr = (N + w - 1) // w
    ns = nr * w - N
    offset = 0
    for k in range(w):
        c = order[k]
        sz = nr - 1 if c >= w - ns else nr
        if j < offset + sz:
            row = j - offset
            col = c
            return row, col
        offset += sz
    return -1, -1  # Should not happen


ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]

# Precompute grid positions for each ordering
# grid_positions[oi][j] = (row, col) for output position j under ordering oi


# Keywords to test
KEYWORDS_BASE = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
    "BERLIN", "CLOCK", "EGYPT", "CAIRO", "PYRAMID", "PHARAOH",
    "LANGLEY", "SHADOW", "LUCID", "SUBTLE", "IQLUSION",
    "EASTNORTHEAST", "BERLINCLOCK", "COMPASS", "POINT",
    "MESSAGE", "SECRET", "DELIVER", "CIPHER", "ENIGMA",
    "TUTANKHAMUN", "CARTER", "TOMB", "CANDLE", "FLAME",
    "DESPERATELY", "SLOWLY", "INVISIBLE", "MAGNETIC",
    "UNDERGRUUND", "LOCATION", "BURIED",
]


def keyword_to_nums(kw):
    return [I2N[c] for c in kw.upper() if c in AZ]


print("=" * 70)
print("E-S-102: Grid-Position Key Generation + Width-7 Columnar")
print(f"  N={N}, W={W}, orderings={len(ORDERS)}, keywords={len(KEYWORDS_BASE)}")
print("=" * 70)

t0 = time.time()
results = {}


# ── Phase 1: Linear key k = a*r + b*c + c0 (mod 26) ──────────────────
print("\n--- P1: Linear key k = a*row + b*col + c0 (mod 26) ---")
# 3 free parameters (a, b, c0), 24 equations → 21 excess constraints

p1_survivors = 0
p1_total = 0

for oi in range(len(ORDERS)):
    perm = PERMS[oi]
    order = ORDERS[oi]

    # Compute observed keystream at crib positions
    # Under Model B: intermediate[j] = PT[perm[j]], and CT[j] = I[j] + key[j]
    # So key[j] = CT[j] - intermediate[j] = CT[j] - PT[perm[j]]
    # At crib: we need perm[j] to be a crib position
    # Actually: perm[j] = original_position. If original_position p is in cribs:
    #   j = inv_perm[p]
    #   key[j] = CT[j] - PT[p] (mod 26)

    inv_perm = [0] * N
    for j in range(N):
        inv_perm[perm[j]] = j

    crib_data = []  # (j, row, col, key_val)
    for p in CPOS:
        j = inv_perm[p]
        key_val = (CT_N[j] - PT_FULL[p]) % 26
        row, col = grid_pos(j, order)
        crib_data.append((j, row, col, key_val))

    # For each triple (a, b, c0), check if k_val ≡ a*r + b*c + c0 (mod 26)
    # Use first 3 cribs to solve, check rest
    # But 26^3 = 17,576 triples is cheap enough to brute-force per ordering
    # Actually, smarter: for each pair (a, b), c0 is determined by first crib
    # Then check remaining 23. So 26^2 = 676 per ordering.

    for a in range(26):
        for b in range(26):
            # Determine c0 from first crib
            j0, r0, c0_grid, kv0 = crib_data[0]
            c0 = (kv0 - a * r0 - b * c0_grid) % 26

            # Check all cribs
            matches = 0
            for j, r, c, kv in crib_data:
                predicted = (a * r + b * c + c0) % 26
                if predicted == kv:
                    matches += 1

            p1_total += 1
            if matches == 24:
                p1_survivors += 1
                # Full decryption
                key_full = [(a * grid_pos(j, order)[0] + b * grid_pos(j, order)[1] + c0) % 26 for j in range(N)]
                pt = [0] * N
                for j in range(N):
                    inter_j = (CT_N[j] - key_full[j]) % 26
                    pt[perm[j]] = inter_j
                pt_text = ''.join(AZ[x] for x in pt)

                from collections import Counter
                freq = Counter(pt)
                ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))

                print(f"  SURVIVOR: order={order} a={a} b={b} c0={c0} IC={ic:.4f}")
                print(f"    PT: {pt_text}")
                if ic > 0.05:
                    print(f"    *** HIGH IC — possible English! ***")

    if oi % 1000 == 0 and oi > 0:
        print(f"    {oi}/5040, survivors={p1_survivors} ({time.time()-t0:.1f}s)")

print(f"  P1: {p1_survivors} survivors from {p1_total:,} tests, {time.time()-t0:.1f}s")
results['P1_linear'] = {'survivors': p1_survivors}


# ── Phase 2: Quadratic key k = a*r² + b*c² + d*r*c + e*r + f*c + g ──
print("\n--- P2: Quadratic key (6 params) ---")
# 6 params, 24 equations → 18 excess constraints
# Too many combos to brute-force (26^6 = 300M). Use linear algebra mod 26.

# For mod 26 = mod 2 × mod 13, solve in each and CRT.
# Build matrix: X[i] = [r_i², c_i², r_i*c_i, r_i, c_i, 1], y[i] = key_val[i]
# Need X*params ≡ y (mod 26)

import numpy as np

p2_survivors = 0

for oi in range(len(ORDERS)):
    perm = PERMS[oi]
    order = ORDERS[oi]
    inv_perm = [0] * N
    for j in range(N):
        inv_perm[perm[j]] = j

    rows_data = []
    y_vals = []
    for p in CPOS:
        j = inv_perm[p]
        key_val = (CT_N[j] - PT_FULL[p]) % 26
        r, c = grid_pos(j, order)
        rows_data.append([r*r, c*c, r*c, r, c, 1])
        y_vals.append(key_val)

    X = rows_data  # 24×6 matrix
    y = y_vals     # 24 vector

    # Solve over GF(2) and GF(13), then CRT
    # For p in [2, 13]:
    #   Reduce X mod p, solve X*params ≡ y (mod p)
    #   If inconsistent, no solution
    #   If consistent, find solution(s)

    def solve_mod_p(X, y, p):
        """Solve X*params ≡ y (mod p). Returns list of solutions or empty."""
        n_rows = len(X)
        n_cols = len(X[0])
        # Gaussian elimination
        aug = [[x % p for x in row] + [y[i] % p] for i, row in enumerate(X)]
        pivot_cols = []
        pivot_row = 0
        for col in range(n_cols):
            # Find pivot
            found = -1
            for row in range(pivot_row, n_rows):
                if aug[row][col] % p != 0:
                    found = row
                    break
            if found == -1:
                continue
            # Swap
            aug[pivot_row], aug[found] = aug[found], aug[pivot_row]
            # Scale pivot row
            inv = pow(aug[pivot_row][col], -1, p)
            aug[pivot_row] = [(x * inv) % p for x in aug[pivot_row]]
            # Eliminate
            for row in range(n_rows):
                if row != pivot_row and aug[row][col] % p != 0:
                    factor = aug[row][col]
                    aug[row] = [(aug[row][k] - factor * aug[pivot_row][k]) % p for k in range(n_cols + 1)]
            pivot_cols.append(col)
            pivot_row += 1

        # Check consistency
        for row in range(pivot_row, n_rows):
            if aug[row][n_cols] % p != 0:
                return []  # Inconsistent

        # Extract solution (assuming unique for simplicity)
        if len(pivot_cols) < n_cols:
            return [None]  # Underdetermined (has solutions but not unique)

        solution = [0] * n_cols
        for i, col in enumerate(pivot_cols):
            solution[col] = aug[i][n_cols] % p
        return [solution]

    sol_2 = solve_mod_p(X, y, 2)
    if not sol_2:
        continue

    sol_13 = solve_mod_p(X, y, 13)
    if not sol_13:
        continue

    # CRT combination
    if sol_2[0] is None or sol_13[0] is None:
        # Underdetermined — skip (shouldn't happen with 24 eqs, 6 vars)
        continue

    # CRT: for each param, find x ≡ sol_2[i] (mod 2) and x ≡ sol_13[i] (mod 13)
    params = []
    for i in range(6):
        a2 = sol_2[0][i]
        a13 = sol_13[0][i]
        # x = a2 + 2*t where (a2 + 2*t) ≡ a13 (mod 13)
        # 2*t ≡ (a13 - a2) (mod 13)
        # t ≡ 7*(a13 - a2) (mod 13)  since 2^-1 ≡ 7 (mod 13)
        t = (7 * (a13 - a2)) % 13
        x = (a2 + 2 * t) % 26
        params.append(x)

    # Verify all 24 cribs
    all_match = True
    for i in range(24):
        predicted = sum(X[i][k] * params[k] for k in range(6)) % 26
        if predicted != y[i]:
            all_match = False
            break

    if all_match:
        p2_survivors += 1
        a, b, d, e, f, g = params
        # Decrypt
        key_full = []
        for j in range(N):
            r, c = grid_pos(j, order)
            kv = (a*r*r + b*c*c + d*r*c + e*r + f*c + g) % 26
            key_full.append(kv)
        pt = [0] * N
        for j in range(N):
            pt[perm[j]] = (CT_N[j] - key_full[j]) % 26
        pt_text = ''.join(AZ[x] for x in pt)

        freq = Counter(pt)
        ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))

        print(f"  SURVIVOR: order={order} params={params} IC={ic:.4f}")
        print(f"    PT: {pt_text}")
        if ic > 0.05:
            print(f"    *** HIGH IC — possible English! ***")

print(f"  P2: {p2_survivors} survivors, {time.time()-t0:.1f}s")
results['P2_quadratic'] = {'survivors': p2_survivors}


# ── Phase 3: Keyword + row shift: k = keyword[col] + a*row (mod 26) ──
print("\n--- P3: Keyword + row shift ---")
# For each keyword, keyword defines 7 column shifts.
# Additional parameter: a (row multiplier), 0-25.
# key[j] = keyword_nums[col_j] + a * row_j (mod 26)
# 1 free parameter per keyword per ordering.

p3_survivors = 0
p3_best = (0, None, None, None)

for kw_str in KEYWORDS_BASE:
    kw_nums = keyword_to_nums(kw_str)
    if len(kw_nums) < 1:
        continue

    for oi in range(len(ORDERS)):
        perm = PERMS[oi]
        order = ORDERS[oi]
        inv_perm = [0] * N
        for j in range(N):
            inv_perm[perm[j]] = j

        # Compute crib data
        crib_data = []
        for p in CPOS:
            j = inv_perm[p]
            key_val = (CT_N[j] - PT_FULL[p]) % 26
            r, c = grid_pos(j, order)
            crib_data.append((r, c, key_val))

        for a in range(26):
            matches = 0
            for r, c, kv in crib_data:
                kw_val = kw_nums[c % len(kw_nums)]
                predicted = (kw_val + a * r) % 26
                if predicted == kv:
                    matches += 1

            if matches > p3_best[0]:
                p3_best = (matches, kw_str, order, a)

            if matches == 24:
                p3_survivors += 1
                print(f"  SURVIVOR: kw={kw_str} order={order} a={a}")

                key_full = []
                for j in range(N):
                    r, c = grid_pos(j, order)
                    kv = (kw_nums[c % len(kw_nums)] + a * r) % 26
                    key_full.append(kv)
                pt = [0] * N
                for j in range(N):
                    pt[perm[j]] = (CT_N[j] - key_full[j]) % 26
                pt_text = ''.join(AZ[x] for x in pt)

                from collections import Counter
                freq = Counter(pt)
                ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))
                print(f"    PT: {pt_text}")
                print(f"    IC: {ic:.4f}")

print(f"  P3: {p3_survivors} survivors, best={p3_best[0]}/24 (kw={p3_best[1]}, a={p3_best[3]})")
print(f"  {time.time()-t0:.1f}s")
results['P3_keyword_row'] = {'survivors': p3_survivors, 'best': p3_best[0]}


# ── Phase 4: Keyword + row with Beaufort/VBeau ────────────────────────
print("\n--- P4: Keyword + row (Beaufort + VBeau variants) ---")

p4_best = (0, None, None, None, None)

for kw_str in KEYWORDS_BASE:
    kw_nums = keyword_to_nums(kw_str)
    if len(kw_nums) < 1:
        continue

    for oi in range(len(ORDERS)):
        perm = PERMS[oi]
        order = ORDERS[oi]
        inv_perm = [0] * N
        for j in range(N):
            inv_perm[perm[j]] = j

        crib_data = []
        for p in CPOS:
            j = inv_perm[p]
            r, c = grid_pos(j, order)
            ct_val = CT_N[j]
            pt_val = PT_FULL[p]
            crib_data.append((r, c, ct_val, pt_val))

        for vi, vname in enumerate(['Beau', 'VBeau']):
            for a in range(26):
                matches = 0
                for r, c, ct_val, pt_val in crib_data:
                    kw_val = kw_nums[c % len(kw_nums)]
                    key_val = (kw_val + a * r) % 26
                    if vi == 0:  # Beaufort: PT = key - CT
                        dec = (key_val - ct_val) % 26
                    else:  # VBeau: PT = CT + key
                        dec = (ct_val + key_val) % 26
                    if dec == pt_val:
                        matches += 1

                if matches > p4_best[0]:
                    p4_best = (matches, kw_str, order, a, vname)

                if matches == 24:
                    print(f"  SURVIVOR: {vname} kw={kw_str} order={order} a={a}")

print(f"  P4: best={p4_best[0]}/24 ({p4_best[4]}, kw={p4_best[1]}, a={p4_best[3]})")
print(f"  {time.time()-t0:.1f}s")
results['P4_keyword_row_beau'] = {'best': p4_best[0]}


# ── Phase 5: k = keyword[col] + a*row + b*row² (mod 26) ──────────────
print("\n--- P5: Keyword + quadratic row: k = kw[col] + a*r + b*r² ---")

p5_best = (0, None)

# For efficiency, only test KRYPTOS and top keywords
TOP_KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "BERLIN",
                "CLOCK", "SHADOW", "POINT", "MESSAGE", "LANGLEY"]

for kw_str in TOP_KEYWORDS:
    kw_nums = keyword_to_nums(kw_str)

    for oi in range(len(ORDERS)):
        perm = PERMS[oi]
        order = ORDERS[oi]
        inv_perm = [0] * N
        for j in range(N):
            inv_perm[perm[j]] = j

        crib_data = []
        for p in CPOS:
            j = inv_perm[p]
            key_val = (CT_N[j] - PT_FULL[p]) % 26
            r, c = grid_pos(j, order)
            crib_data.append((r, c, key_val))

        for a in range(26):
            for b in range(26):
                matches = 0
                for r, c, kv in crib_data:
                    kw_val = kw_nums[c % len(kw_nums)]
                    predicted = (kw_val + a * r + b * r * r) % 26
                    if predicted == kv:
                        matches += 1

                if matches > p5_best[0]:
                    p5_best = (matches, f"{kw_str} a={a} b={b} oi={oi}")

                if matches == 24:
                    print(f"  SURVIVOR: kw={kw_str} order={ORDERS[oi]} a={a} b={b}")

print(f"  P5: best={p5_best[0]}/24 ({p5_best[1]})")
print(f"  {time.time()-t0:.1f}s")
results['P5_keyword_quad_row'] = {'best': p5_best[0]}


# ── Phase 6: k depends on output position (no grid structure) ────────
print("\n--- P6: Position-only key: k = a*j + b (mod 26) ---")
# Tests: k[j] = a*j + b and k[j] = a*j² + b*j + c

p6_survivors_lin = 0
p6_survivors_quad = 0

for oi in range(len(ORDERS)):
    perm = PERMS[oi]
    inv_perm = [0] * N
    for j in range(N):
        inv_perm[perm[j]] = j

    crib_eqs = []  # (j, key_val)
    for p in CPOS:
        j = inv_perm[p]
        key_val = (CT_N[j] - PT_FULL[p]) % 26
        crib_eqs.append((j, key_val))

    # Linear: k = a*j + b
    j0, kv0 = crib_eqs[0]
    for a in range(26):
        b = (kv0 - a * j0) % 26
        matches = sum(1 for j, kv in crib_eqs if (a * j + b) % 26 == kv)
        if matches == 24:
            p6_survivors_lin += 1
            print(f"  LIN SURVIVOR: order={ORDERS[oi]} a={a} b={b}")

    # Quadratic: k = a*j² + b*j + c
    j0, kv0 = crib_eqs[0]
    j1, kv1 = crib_eqs[1]
    for a in range(26):
        # From first 2 eqs: b and c determined
        # kv0 = a*j0² + b*j0 + c
        # kv1 = a*j1² + b*j1 + c
        # kv1 - kv0 = a*(j1²-j0²) + b*(j1-j0)
        diff_j = (j1 - j0) % 26
        if diff_j == 0:
            continue
        try:
            diff_j_inv = pow(diff_j, -1, 26)
        except ValueError:
            continue  # Not invertible
        diff_k = (kv1 - kv0) % 26
        diff_j2 = (j1*j1 - j0*j0) % 26
        b = (diff_j_inv * (diff_k - a * diff_j2)) % 26
        c = (kv0 - a * j0 * j0 - b * j0) % 26

        matches = sum(1 for j, kv in crib_eqs if (a * j * j + b * j + c) % 26 == kv)
        if matches == 24:
            p6_survivors_quad += 1
            print(f"  QUAD SURVIVOR: order={ORDERS[oi]} a={a} b={b} c={c}")

print(f"  P6 linear: {p6_survivors_lin} survivors")
print(f"  P6 quadratic: {p6_survivors_quad} survivors")
print(f"  {time.time()-t0:.1f}s")
results['P6_position_only'] = {'lin': p6_survivors_lin, 'quad': p6_survivors_quad}


# ── Phase 7: k = keyword[col] * (row+1) (mod 26) — multiplicative ───
print("\n--- P7: Multiplicative: k = kw[col] * (row+1) (mod 26) ---")

p7_best = (0, None)

for kw_str in KEYWORDS_BASE:
    kw_nums = keyword_to_nums(kw_str)
    if len(kw_nums) < 1:
        continue

    for oi in range(len(ORDERS)):
        perm = PERMS[oi]
        order = ORDERS[oi]
        inv_perm = [0] * N
        for j in range(N):
            inv_perm[perm[j]] = j

        crib_data = []
        for p in CPOS:
            j = inv_perm[p]
            key_val = (CT_N[j] - PT_FULL[p]) % 26
            r, c = grid_pos(j, order)
            crib_data.append((r, c, key_val))

        matches = 0
        for r, c, kv in crib_data:
            kw_val = kw_nums[c % len(kw_nums)]
            predicted = (kw_val * (r + 1)) % 26
            if predicted == kv:
                matches += 1

        if matches > p7_best[0]:
            p7_best = (matches, f"{kw_str} oi={oi}")

        if matches == 24:
            print(f"  SURVIVOR: kw={kw_str} order={ORDERS[oi]}")

print(f"  P7: best={p7_best[0]}/24 ({p7_best[1]})")
print(f"  {time.time()-t0:.1f}s")
results['P7_multiplicative'] = {'best': p7_best[0]}


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for phase, data in sorted(results.items()):
    print(f"  {phase}: {data}")
print(f"  Total: {total_elapsed:.1f}s")

total_survivors = sum(v.get('survivors', 0) for v in results.values())
if total_survivors > 0:
    print(f"\n  Verdict: {total_survivors} SURVIVORS found — investigate!")
else:
    best_overall = max(
        results.get('P3_keyword_row', {}).get('best', 0),
        results.get('P4_keyword_row_beau', {}).get('best', 0),
        results.get('P5_keyword_quad_row', {}).get('best', 0),
        results.get('P7_multiplicative', {}).get('best', 0),
    )
    print(f"\n  Verdict: NO SURVIVORS. Best partial: {best_overall}/24")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-102',
    'description': 'Grid-position key generation + width-7 columnar',
    'results': {k: str(v) for k, v in results.items()},
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_102_grid_position_key.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_102_grid_position_key.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_102_grid_position_key.py")
