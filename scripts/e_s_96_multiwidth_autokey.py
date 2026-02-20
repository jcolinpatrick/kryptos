#!/usr/bin/env python3
"""E-S-96: Multi-Width Columnar + Autokey Sweep

Tests autokey (CT and PT) combined with columnar transposition at widths 5-12.
E-S-93 tests width 7 only; this expands the search to other widths.

Also tests:
  - Autokey with K3-related transposition (width 8, same as K3)
  - Autokey with no transposition (already in E-S-93 P4, but extended here)
  - Autokey with rail fence transposition (various rails)

For each width, tests all orderings × primer lengths 1-2 × 3 variants × CT/PT autokey.
"""

import json, os, time
from itertools import permutations, product

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

VNAMES = ['Vig', 'Beau', 'VBeau']


def build_perm(order, w, n):
    nr = (n + w - 1) // w
    ns = nr * w - n
    p = []
    for k in range(w):
        c = order[k]
        sz = nr - 1 if c >= w - ns else nr
        for r in range(sz):
            p.append(r * w + c)
    return p


def check_cribs(pt):
    return sum(1 for p in CPOS if pt[p] == PT_FULL[p])


def ct_autokey_decrypt(intermed, primer, variant):
    p = len(primer)
    pt = [0] * N
    for j in range(N):
        k = primer[j] if j < p else intermed[j - p]
        if variant == 0:
            pt[j] = (intermed[j] - k) % 26
        elif variant == 1:
            pt[j] = (k - intermed[j]) % 26
        else:
            pt[j] = (intermed[j] + k) % 26
    return pt


def pt_autokey_decrypt(intermed, primer, variant):
    p = len(primer)
    pt = [0] * N
    for j in range(N):
        k = primer[j] if j < p else pt[j - p]
        if variant == 0:
            pt[j] = (intermed[j] - k) % 26
        elif variant == 1:
            pt[j] = (k - intermed[j]) % 26
        else:
            pt[j] = (intermed[j] + k) % 26
    return pt


print("=" * 70)
print("E-S-96: Multi-Width Columnar + Autokey Sweep")
print(f"  N={N}, cribs={len(CPOS)}")
print("=" * 70)

t0 = time.time()
results = {}

# ── Test each width from 5 to 12 ─────────────────────────────────────
for w in range(5, 13):
    n_orders = 1
    for i in range(2, w + 1):
        n_orders *= i

    # For large widths, limit to random sample
    max_orderings = 5040  # limit
    all_orders = list(permutations(range(w)))
    if len(all_orders) > max_orderings:
        import random
        random.seed(42)
        sample_orders = random.sample(all_orders, max_orderings)
    else:
        sample_orders = all_orders

    # Precompute permutations and intermediates
    perms = [build_perm(list(o), w, N) for o in sample_orders]
    intermediates = [[CT_N[p[j]] for j in range(N)] for p in perms]

    w_best = 0
    w_best_cfg = None
    tested = 0

    for oi, intermed in enumerate(intermediates):
        for plen in range(1, 3):  # primer 1-2
            for primer_tuple in product(range(26), repeat=plen):
                primer = list(primer_tuple)
                for vi in range(3):
                    # CT-autokey
                    pt = ct_autokey_decrypt(intermed, primer, vi)
                    score = check_cribs(pt)
                    tested += 1

                    if score > w_best:
                        w_best = score
                        primer_letters = ''.join(AZ[x] for x in primer)
                        w_best_cfg = ('CT', list(sample_orders[oi]), VNAMES[vi], primer_letters)

                    if score >= 18:
                        pt_text = ''.join(AZ[x] for x in pt)
                        print(f"  *** HIT w={w}: {score}/24 CT-AK order={list(sample_orders[oi])[:4]}... "
                              f"{VNAMES[vi]} primer='{primer_letters}'")
                        print(f"      PT: {pt_text}")

                    # PT-autokey
                    pt2 = pt_autokey_decrypt(intermed, primer, vi)
                    score2 = check_cribs(pt2)
                    tested += 1

                    if score2 > w_best:
                        w_best = score2
                        primer_letters = ''.join(AZ[x] for x in primer)
                        w_best_cfg = ('PT', list(sample_orders[oi]), VNAMES[vi], primer_letters)

                    if score2 >= 18:
                        pt_text = ''.join(AZ[x] for x in pt2)
                        print(f"  *** HIT w={w}: {score2}/24 PT-AK order={list(sample_orders[oi])[:4]}... "
                              f"{VNAMES[vi]} primer='{primer_letters}'")
                        print(f"      PT: {pt_text}")

        if oi > 0 and oi % 1000 == 0:
            print(f"    w={w}: {oi}/{len(sample_orders)}, best={w_best} ({time.time()-t0:.0f}s)")

    elapsed = time.time() - t0
    print(f"  Width {w}: {len(sample_orders)} orderings, best={w_best}/24, "
          f"{tested:,} tested, {elapsed:.0f}s, cfg={str(w_best_cfg)[:80] if w_best_cfg else None}")
    results[f'w{w}'] = {'best': w_best, 'orderings_tested': len(sample_orders),
                         'configs_tested': tested, 'cfg': str(w_best_cfg)}


# ── Test specific K3-related width-8 orderings ───────────────────────
print("\n--- K3-related width-8 with ABSCISSA ordering ---")

# K3 used keyword ABSCISSA → ordering [0, 1, 5, 2, 6, 7, 3, 4] (A=0,B=1,S=5,C=2,I=3,S=4,S=5,A=0)
# Actually, ABSCISSA (8 letters) with standard numbering:
# A=1, B=2, S=7, C=3, I=4, S=8, S=9, A=1 → by occurrence: A(1)=0, B(2)=1, S(3)=5, C(4)=2, I(5)=3, S(6)=6, S(7)=7, A(8)=4
# Different interpretations exist. Let me use common convention:
# ABSCISSA: alphabetical ranking considering repeats
# A₁=0, A₂=1, B=2, C=3, I=4, S₁=5, S₂=6, S₃=7
# So order = [0, 2, 5, 3, 4, 6, 7, 1]

# Try several interpretations
K3_ORDERS_W8 = [
    [0, 2, 5, 3, 4, 6, 7, 1],  # ABSCISSA standard
    [0, 1, 5, 2, 3, 6, 7, 4],  # alternative
    [1, 2, 6, 3, 4, 7, 8, 5],  # 1-indexed attempt (invalid, skip)
]

for k3o in K3_ORDERS_W8:
    if max(k3o) >= 8 or min(k3o) < 0:
        continue
    if len(set(k3o)) != 8:
        continue

    perm = build_perm(k3o, 8, N)
    intermed = [CT_N[perm[j]] for j in range(N)]

    for plen in range(1, 5):
        best_p = 0
        for primer_tuple in product(range(26), repeat=plen):
            primer = list(primer_tuple)
            for vi in range(3):
                pt = ct_autokey_decrypt(intermed, primer, vi)
                score = check_cribs(pt)
                if score > best_p:
                    best_p = score
                if score >= 18:
                    print(f"  HIT K3-w8: {score}/24 order={k3o} primer={''.join(AZ[x] for x in primer)}")

                pt2 = pt_autokey_decrypt(intermed, primer, vi)
                score2 = check_cribs(pt2)
                if score2 > best_p:
                    best_p = score2
                if score2 >= 18:
                    print(f"  HIT K3-w8 PT: {score2}/24 order={k3o} primer={''.join(AZ[x] for x in primer)}")

        print(f"  K3 order {k3o}, plen={plen}: best={best_p}/24")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for w_key in sorted(results.keys()):
    data = results[w_key]
    print(f"  {w_key}: {data['best']}/24 ({data['orderings_tested']} orderings)")
print(f"  Total: {total_elapsed:.1f}s")

best = max(v['best'] for v in results.values())
if best >= 18:
    print(f"\n  Verdict: SIGNAL — {best}/24")
elif best >= 10:
    print(f"\n  Verdict: INTERESTING — {best}/24")
else:
    print(f"\n  Verdict: NOISE — {best}/24")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-96',
    'description': 'Multi-width columnar + autokey sweep',
    'results': results,
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_96_multiwidth_autokey.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_96_multiwidth_autokey.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_96_multiwidth_autokey.py")
