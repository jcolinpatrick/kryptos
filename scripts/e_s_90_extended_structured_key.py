#!/usr/bin/env python3
"""E-S-90: Extended Structured Key Models + Various Transpositions

Tests structured key models NOT covered in E-S-89:
  P1: Progressive key + non-columnar width-7 transpositions
      (rail fence, disrupted columnar, diagonal route)
  P2: Progressive key + columnar widths 5, 6, 8
  P3: Quadratic progression: key[j] = base[j%7] + slope[j%7]*row + curve[j%7]*row^2
  P4: Fibonacci-like column key: key[row,col] = key[row-1,col] + key[row-2,col]
  P5: Multiplicative progression: key[j] = base[j%7] * mult^(j//7) mod 26

Each model tests whether the "coding charts" use a different structure than
the simple progressive shift tested in E-S-89.
"""

import json, os, time, random
from itertools import permutations
from collections import defaultdict
from math import gcd

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_N = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())
NC = len(CPOS)
W = 7

VNAMES = ['Vig', 'Beau', 'VBeau']

def kobs(j, pt, vi):
    if vi == 0: return (CT_N[j] - pt) % 26
    if vi == 1: return (CT_N[j] + pt) % 26
    return (pt - CT_N[j]) % 26

def inv_perm(perm):
    iv = [0] * N
    for i, p in enumerate(perm):
        iv[p] = i
    return iv


# ── Transposition builders ───────────────────────────────────────────

def build_columnar(order, w):
    """Width-w columnar transposition: perm[ct] = pt."""
    nr = (N + w - 1) // w
    ns = nr * w - N
    p = []
    for k in range(w):
        c = order[k]
        sz = nr - 1 if c >= w - ns else nr
        for r in range(sz):
            p.append(r * w + c)
    if len(p) != N or sorted(p) != list(range(N)):
        return None
    return p

def build_rail_fence(n_rails, offset=0):
    """Rail fence gather perm."""
    if n_rails < 2 or n_rails > N:
        return None
    rails = [[] for _ in range(n_rails)]
    rail = offset % n_rails
    direction = 1 if rail < n_rails - 1 else -1
    for i in range(N):
        rails[rail].append(i)
        rail += direction
        if rail >= n_rails:
            rail = n_rails - 2
            direction = -1
        elif rail < 0:
            rail = 1
            direction = 1
    perm = []
    for r in range(n_rails):
        perm.extend(rails[r])
    return perm

def build_diagonal_route(w):
    """Diagonal reading of a w-column grid."""
    nr = (N + w - 1) // w
    perm = []
    for d in range(nr + w - 1):
        for r in range(nr):
            c = d - r
            if 0 <= c < w:
                pos = r * w + c
                if pos < N:
                    perm.append(pos)
    if len(perm) != N or sorted(perm) != list(range(N)):
        return None
    return perm

def build_spiral_route(w):
    """Spiral reading of a w-column grid."""
    nr = (N + w - 1) // w
    grid = []
    idx = 0
    for r in range(nr):
        row = []
        for c in range(w):
            if idx < N:
                row.append(idx)
            else:
                row.append(-1)
            idx += 1
        grid.append(row)

    perm = []
    top, bottom, left, right = 0, nr - 1, 0, w - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            if top < nr and c < w and grid[top][c] >= 0:
                perm.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            if r < nr and right < w and grid[r][right] >= 0:
                perm.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if bottom < nr and c < w and grid[bottom][c] >= 0:
                    perm.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if r < nr and left < w and grid[r][left] >= 0:
                    perm.append(grid[r][left])
            left += 1

    # Remove duplicates and validate
    seen = set()
    clean = []
    for p in perm:
        if p not in seen and 0 <= p < N:
            seen.add(p)
            clean.append(p)
    if len(clean) != N:
        return None
    return clean


def score_progressive(perm, vi, w_key=7):
    """Score global progressive model: key[j] = base[j%w] + s*(j//w).
    Returns (best_matches, best_slope).
    """
    iv = inv_perm(perm)
    cd = []
    for p in CPOS:
        j = iv[p]
        cd.append((kobs(j, PT_N[p], vi), j % w_key, j // w_key))

    best = (0, -1)
    for s in range(26):
        col_vals = {}
        col_cnt = {}
        for k, c, r in cd:
            req = (k - s * r) % 26
            if c not in col_vals:
                col_vals[c] = set()
                col_cnt[c] = 0
            col_vals[c].add(req)
            col_cnt[c] += 1
        m = sum(col_cnt[c] for c in col_vals if len(col_vals[c]) == 1)
        if m > best[0]:
            best = (m, s)
    return best


print("=" * 70)
print("E-S-90: Extended Structured Key Models")
print("=" * 70)

t0 = time.time()
R = {}


# ━━━ Phase 1: Progressive key + non-columnar transpositions ━━━━━━━━
print("\n--- P1: Progressive key + non-columnar width-7 transpositions ---")

best_p1 = (0, None)

# Rail fence with 7 rails
for offset in range(7):
    perm = build_rail_fence(7, offset)
    if perm is None:
        continue
    for vi in range(3):
        m, s = score_progressive(perm, vi)
        if m > best_p1[0]:
            best_p1 = (m, (f'railfence_7_off{offset}', VNAMES[vi], s))
        if m >= 15:
            print(f"  HIT: {m}/24 railfence 7 off={offset} {VNAMES[vi]} slope={s}")

# Rail fence with other rail counts
for nrails in [3, 4, 5, 6, 8, 9, 10, 11, 13, 14]:
    for offset in range(min(nrails, 4)):
        perm = build_rail_fence(nrails, offset)
        if perm is None:
            continue
        for vi in range(3):
            m, s = score_progressive(perm, vi)
            if m > best_p1[0]:
                best_p1 = (m, (f'railfence_{nrails}_off{offset}', VNAMES[vi], s))
            if m >= 15:
                print(f"  HIT: {m}/24 railfence {nrails} off={offset} {VNAMES[vi]} slope={s}")

# Diagonal route width 7
perm = build_diagonal_route(7)
if perm is not None:
    for vi in range(3):
        m, s = score_progressive(perm, vi)
        if m > best_p1[0]:
            best_p1 = (m, ('diagonal_7', VNAMES[vi], s))
        if m >= 15:
            print(f"  HIT: {m}/24 diagonal_7 {VNAMES[vi]} slope={s}")

# Spiral route width 7
perm = build_spiral_route(7)
if perm is not None:
    for vi in range(3):
        m, s = score_progressive(perm, vi)
        if m > best_p1[0]:
            best_p1 = (m, ('spiral_7', VNAMES[vi], s))
        if m >= 15:
            print(f"  HIT: {m}/24 spiral_7 {VNAMES[vi]} slope={s}")

# Boustrophedon (alternating row direction) width 7
nr = (N + 7 - 1) // 7
perm = []
for r in range(nr):
    if r % 2 == 0:
        for c in range(7):
            pos = r * 7 + c
            if pos < N:
                perm.append(pos)
    else:
        for c in range(6, -1, -1):
            pos = r * 7 + c
            if pos < N:
                perm.append(pos)
if len(perm) == N:
    for vi in range(3):
        m, s = score_progressive(perm, vi)
        if m > best_p1[0]:
            best_p1 = (m, ('boustrophedon_7', VNAMES[vi], s))
        if m >= 15:
            print(f"  HIT: {m}/24 boustrophedon_7 {VNAMES[vi]} slope={s}")

# Columnar with boustrophedon reading (every other column reversed)
for oi, order in enumerate(permutations(range(7))):
    order = list(order)
    ns = 14 * 7 - N
    p = []
    for k in range(7):
        c = order[k]
        sz = 14 - 1 if c >= 7 - ns else 14
        if k % 2 == 0:
            for r in range(sz):
                p.append(r * 7 + c)
        else:
            for r in range(sz - 1, -1, -1):
                p.append(r * 7 + c)
    if len(p) == N and sorted(p) == list(range(N)):
        for vi in range(3):
            m, s = score_progressive(p, vi)
            if m > best_p1[0]:
                best_p1 = (m, (f'bous_col_{order}', VNAMES[vi], s))
            if m >= 15:
                print(f"  HIT: {m}/24 bous_col {order} {VNAMES[vi]} slope={s}")

t1 = time.time()
print(f"\n  P1 done: {t1-t0:.1f}s, best={best_p1[0]}/24 {best_p1[1]}")
R['P1_noncolumnar'] = {'best': best_p1[0], 'cfg': str(best_p1[1])}


# ━━━ Phase 2: Progressive key + other columnar widths ━━━━━━━━━━━━━━
print("\n--- P2: Progressive key + columnar widths 5, 6, 8 ---")
print("  Key period = transposition width (matching grid)")

best_p2 = (0, None)

for w in [5, 6, 8]:
    all_orders = list(permutations(range(w)))
    for oi, order in enumerate(all_orders):
        order = list(order)
        perm = build_columnar(order, w)
        if perm is None:
            continue
        for vi in range(3):
            m, s = score_progressive(perm, vi, w_key=w)
            if m > best_p2[0]:
                best_p2 = (m, (w, order, VNAMES[vi], s))
            if m >= 15:
                print(f"  HIT: {m}/24 w={w} order={order} {VNAMES[vi]} slope={s}")

    print(f"  Width {w}: tested {len(all_orders)} orderings ({time.time()-t0:.0f}s)")

# Also test width != key period: columnar w=8, key period 7
print("  Testing width-8 columnar + key period 7...")
for oi, order in enumerate(permutations(range(8))):
    order = list(order)
    perm = build_columnar(order, 8)
    if perm is None:
        continue
    for vi in range(3):
        m, s = score_progressive(perm, vi, w_key=7)
        if m > best_p2[0]:
            best_p2 = (m, (8, order, 'kp7', VNAMES[vi], s))
        if m >= 15:
            print(f"  HIT: {m}/24 w=8 kp7 order={order} {VNAMES[vi]} slope={s}")
    if (oi + 1) % 10000 == 0:
        print(f"    {oi+1}/40320 ({time.time()-t0:.0f}s)")

t2 = time.time()
print(f"\n  P2 done: {t2-t1:.1f}s, best={best_p2[0]}/24 {best_p2[1]}")
R['P2_other_widths'] = {'best': best_p2[0], 'cfg': str(best_p2[1])}


# ━━━ Phase 3: Quadratic progression ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# key[j] = base[j%7] + slope[j%7]*row + curve[j%7]*row^2 mod 26
# 21 unknowns, 24 equations → 3 excess constraints
# Per column: brute force over (slope, curve), compute base from first crib
print("\n--- P3: Quadratic per-column key [21 params, 3 excess] ---")

best_p3 = (0, None)
all_orders_7 = [list(o) for o in permutations(range(7))]

for oi, order in enumerate(all_orders_7):
    perm = build_columnar(order, 7)
    if perm is None:
        continue
    iv = inv_perm(perm)

    for vi in range(3):
        # Group cribs by CT column
        cc = defaultdict(list)
        for p in CPOS:
            j = iv[p]
            k = kobs(j, PT_N[p], vi)
            cc[j % 7].append((j // 7, k))

        total = 0
        for col, cribs in cc.items():
            n = len(cribs)
            if n <= 2:
                total += n  # ≤2 cribs always fit a quadratic
                continue

            # For n>=3: brute force slope and curve, compute base from first crib
            r0, k0 = cribs[0]
            best_col = 1
            for slope in range(26):
                for curve in range(26):
                    base = (k0 - slope * r0 - curve * r0 * r0) % 26
                    cnt = sum(1 for r, k in cribs
                              if (base + slope * r + curve * r * r) % 26 == k)
                    if cnt > best_col:
                        best_col = cnt
            total += best_col

        if total > best_p3[0]:
            best_p3 = (total, (order, VNAMES[vi]))
        if total >= 20:
            print(f"  *** P3 HIT: {total}/24 order={order} {VNAMES[vi]}")

    if (oi + 1) % 500 == 0:
        print(f"  {oi+1}/5040 ({time.time()-t0:.0f}s) best={best_p3[0]}")

t3 = time.time()
print(f"\n  P3 done: {t3-t2:.1f}s, best={best_p3[0]}/24 {best_p3[1]}")
R['P3_quadratic'] = {'best': best_p3[0], 'cfg': str(best_p3[1])}


# ━━━ Phase 4: Fibonacci-like column recurrence ━━━━━━━━━━━━━━━━━━━━━
# key[row, col] = (key[row-1, col] + key[row-2, col]) mod 26
# 14 seed values (2 per column) → full 14×7 key determined
# Test: does Fibonacci recurrence produce consistent key for cribs?
print("\n--- P4: Fibonacci column recurrence [14 seeds] ---")

best_p4 = (0, None)

for oi, order in enumerate(all_orders_7):
    perm = build_columnar(order, 7)
    if perm is None:
        continue
    iv = inv_perm(perm)

    for vi in range(3):
        # Group cribs by CT column with (ct_row, k_obs)
        cc = defaultdict(list)
        for p in CPOS:
            j = iv[p]
            cc[j % 7].append((j // 7, kobs(j, PT_N[p], vi)))

        total = 0
        for col, cribs in cc.items():
            n = len(cribs)
            if n <= 2:
                total += n
                continue

            # Brute force seed0, seed1 (26^2 = 676 per column)
            best_col = 1
            for s0 in range(26):
                for s1 in range(26):
                    # Generate Fibonacci sequence for 14 rows
                    fib = [0] * 14
                    fib[0] = s0
                    fib[1] = s1
                    for r in range(2, 14):
                        fib[r] = (fib[r-1] + fib[r-2]) % 26
                    cnt = sum(1 for r, k in cribs if fib[r] == k)
                    if cnt > best_col:
                        best_col = cnt
            total += best_col

        if total > best_p4[0]:
            best_p4 = (total, (order, VNAMES[vi]))
        if total >= 20:
            print(f"  *** P4 HIT: {total}/24 order={order} {VNAMES[vi]}")

    if (oi + 1) % 500 == 0:
        print(f"  {oi+1}/5040 ({time.time()-t0:.0f}s) best={best_p4[0]}")

t4 = time.time()
print(f"\n  P4 done: {t4-t3:.1f}s, best={best_p4[0]}/24 {best_p4[1]}")
R['P4_fibonacci'] = {'best': best_p4[0], 'cfg': str(best_p4[1])}


# ━━━ Phase 5: Multiplicative progression ━━━━━━━━━━━━━━━━━━━━━━━━━━━
# key[j] = base[j%7] * mult^(j//7) mod 26
# Only mult coprime to 26 (12 values: φ(26)=12)
# 8 unknowns (7 bases + mult), 16 excess
print("\n--- P5: Multiplicative progression [8 params] ---")

best_p5 = (0, None)
# mult values coprime to 26
MULTS = [m for m in range(26) if gcd(m, 26) == 1]

def modinv(a, m):
    if gcd(a % m, m) != 1:
        return None
    g, x, _ = _ext_gcd(a % m, m)
    return x % m

def _ext_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = _ext_gcd(b % a, a)
    return g, y - (b // a) * x, x

# Precompute powers of each mult
MULT_POWS = {}
for mult in MULTS:
    pows = [1] * 14
    for r in range(1, 14):
        pows[r] = (pows[r-1] * mult) % 26
    MULT_POWS[mult] = pows

for oi, order in enumerate(all_orders_7):
    perm = build_columnar(order, 7)
    if perm is None:
        continue
    iv = inv_perm(perm)

    for vi in range(3):
        cd = []
        for p in CPOS:
            j = iv[p]
            cd.append((kobs(j, PT_N[p], vi), j % 7, j // 7))

        for mult in MULTS:
            pows = MULT_POWS[mult]
            col_vals = {}
            col_cnt = {}
            for k, c, r in cd:
                # key = base[c] * mult^r → base[c] = k * modinv(mult^r, 26)
                pw_inv = modinv(pows[r], 26)
                if pw_inv is None:
                    continue
                req = (k * pw_inv) % 26
                if c not in col_vals:
                    col_vals[c] = set()
                    col_cnt[c] = 0
                col_vals[c].add(req)
                col_cnt[c] += 1

            m = sum(col_cnt[c] for c in col_vals if len(col_vals[c]) == 1)
            if m > best_p5[0]:
                best_p5 = (m, (order, VNAMES[vi], mult))
            if m >= 15:
                print(f"  HIT: {m}/24 order={order} {VNAMES[vi]} mult={mult}")

    if (oi + 1) % 1000 == 0:
        print(f"  {oi+1}/5040 ({time.time()-t0:.0f}s) best={best_p5[0]}")

t5 = time.time()
print(f"\n  P5 done: {t5-t4:.1f}s, best={best_p5[0]}/24 {best_p5[1]}")
R['P5_multiplicative'] = {'best': best_p5[0], 'cfg': str(best_p5[1])}


# ━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
total = time.time() - t0
overall = max(v['best'] for v in R.values())

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for k, v in R.items():
    print(f"  {k}: {v['best']}/24")
print(f"  Total: {total:.1f}s")

if overall >= 20:
    verdict = f"STRONG SIGNAL — {overall}/24"
elif overall >= 15:
    verdict = f"INTERESTING — {overall}/24"
elif overall >= 10:
    verdict = f"MARGINAL — {overall}/24"
else:
    verdict = f"NO SIGNAL — {overall}/24 at noise floor"

print(f"\n  Verdict: {verdict}")

out = {
    'experiment': 'E-S-90',
    'description': 'Extended structured key models',
    'results': R,
    'elapsed_seconds': total,
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_90_extended_key.json", "w") as f:
    json.dump(out, f, indent=2)
print(f"\n  Artifact: results/e_s_90_extended_key.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_90_extended_structured_key.py")
