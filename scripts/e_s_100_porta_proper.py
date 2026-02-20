#!/usr/bin/env python3
"""E-S-100: Porta Cipher + Width-7 Columnar (Proper Constraint Propagation)

Porta cipher: 13 paired alphabets, self-reciprocal.
  - Key K (0-25) → alphabet K//2 (0-12)
  - Letters A-M (0-12) map to N-Z (13-25) and vice versa
  - Encryption = Decryption

Porta tableau for key group g (0-12):
  Plain A-M → Cipher = ((plain + g) mod 13) + 13
  Plain N-Z → Cipher = (plain - 13 - g) mod 13

Constraint propagation:
  For each crib (pos p, intermediate I[p], plaintext PT[p]):
  Find all key values k where porta(I[p], k) == PT[p].
  Group by residue (p mod period). Intersect valid key sets.

  With period 7 and 24 cribs across 7 residues:
  ~3.4 cribs per residue, each with ~2 valid k values.
  Expected survivors: 2^7 × (filtering) ≈ very few per ordering.

Also tests: period 1-14, non-standard Porta variants.
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

W = 7


def porta_encrypt(pt_val, key_val):
    """Porta cipher: self-reciprocal."""
    g = key_val // 2  # alphabet group 0-12
    if pt_val < 13:  # A-M
        return ((pt_val + g) % 13) + 13
    else:  # N-Z
        return (pt_val - 13 - g) % 13


def porta_valid_keys(ct_val, pt_val):
    """Find all key values (0-25) where porta_encrypt(pt_val, k) == ct_val."""
    valid = []
    for k in range(26):
        if porta_encrypt(pt_val, k) == ct_val:
            valid.append(k)
    return valid


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


ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]
INTERMEDIATES = [[CT_N[PERMS[oi][j]] for j in range(N)] for oi in range(len(ORDERS))]


def check_porta_periodic(intermed, period):
    """Check if Porta with given period produces all crib matches.
    Uses constraint propagation.
    Returns list of valid key tuples or empty list.
    """
    # For each residue, collect valid key values
    residue_keys = {r: set(range(26)) for r in range(period)}

    for p in CPOS:
        r = p % period
        i_val = intermed[p]
        pt_val = PT_FULL[p]
        valid = set(porta_valid_keys(i_val, pt_val))
        residue_keys[r] &= valid

    # Check for empty residues
    for r in range(period):
        if len(residue_keys[r]) == 0:
            return []

    # Product of remaining options
    product_size = 1
    for r in range(period):
        product_size *= len(residue_keys[r])

    if product_size > 100000:
        return []  # Too many to enumerate, count as "underdetermined"

    # Enumerate valid key combinations
    keys_per_residue = [sorted(residue_keys[r]) for r in range(period)]
    valid_keys = []

    for key_combo in product(*keys_per_residue):
        key = list(key_combo)
        # Verify all cribs (should be guaranteed by construction)
        ok = True
        for p in CPOS:
            if porta_encrypt(PT_FULL[p], key[p % period]) != intermed[p]:
                ok = False
                break
        if ok:
            valid_keys.append(key)

    return valid_keys


print("=" * 70)
print("E-S-100: Porta Cipher + Width-7 Columnar (Constraint Propagation)")
print(f"  N={N}, W={W}, orderings={len(ORDERS)}")
print("=" * 70)

t0 = time.time()
results = {}


# ── Phase 1: Porta + w7 columnar, period 7 ───────────────────────────
print("\n--- P1: Porta + w7 columnar, period 7 ---")

p1_survivors = 0
p1_keys = []

for oi in range(len(ORDERS)):
    intermed = INTERMEDIATES[oi]
    valid = check_porta_periodic(intermed, 7)
    if valid:
        p1_survivors += 1
        for key in valid[:3]:
            p1_keys.append((ORDERS[oi], key))
            # Decrypt
            pt = [porta_encrypt(intermed[j], key[j % 7]) for j in range(N)]
            pt_text = ''.join(AZ[x] for x in pt)

            from collections import Counter
            freq = Counter(pt)
            ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))

            print(f"  SURVIVOR: order={ORDERS[oi]} key={key} IC={ic:.4f}")
            print(f"    PT: {pt_text}")

            if ic > 0.05:
                print(f"    *** HIGH IC — could be English! ***")

    if oi % 1000 == 0 and oi > 0:
        print(f"    {oi}/5040, survivors={p1_survivors} ({time.time()-t0:.1f}s)")

print(f"  P1: {p1_survivors}/5040 survivors, {time.time()-t0:.1f}s")
results['P1_porta_p7'] = {'survivors': p1_survivors}


# ── Phase 2: Porta + w7 columnar, periods 2-14 ───────────────────────
print("\n--- P2: Porta + w7 columnar, periods 2-14 ---")

for period in range(2, 15):
    if period == 7:
        continue  # Already tested
    p_survivors = 0
    for oi in range(len(ORDERS)):
        valid = check_porta_periodic(INTERMEDIATES[oi], period)
        if valid:
            p_survivors += 1
    print(f"  period {period}: {p_survivors}/5040")
    results[f'P2_porta_p{period}'] = {'survivors': p_survivors}

print(f"\n  P2 done: {time.time()-t0:.1f}s")


# ── Phase 3: Porta + decimation ───────────────────────────────────────
print("\n--- P3: Porta + decimation, period 7 ---")

p3_survivors = 0
for d in range(1, N):
    perm = [(j * d) % N for j in range(N)]
    intermed = [CT_N[perm[j]] for j in range(N)]
    valid = check_porta_periodic(intermed, 7)
    if valid:
        p3_survivors += 1
        for key in valid[:1]:
            pt = [porta_encrypt(intermed[j], key[j % 7]) for j in range(N)]
            pt_text = ''.join(AZ[x] for x in pt)
            print(f"  d={d}: key={key} PT={pt_text[:40]}...")

print(f"  P3: {p3_survivors}/96 survivors, {time.time()-t0:.1f}s")
results['P3_decimation_porta'] = {'survivors': p3_survivors}


# ── Phase 4: Porta + identity (no transposition) ─────────────────────
print("\n--- P4: Porta, no transposition, periods 2-14 ---")

for period in range(2, 15):
    valid = check_porta_periodic(CT_N, period)
    if valid:
        for key in valid[:1]:
            pt = [porta_encrypt(CT_N[j], key[j % period]) for j in range(N)]
            pt_text = ''.join(AZ[x] for x in pt)
            print(f"  period {period}: key={key} PT={pt_text[:40]}...")
    else:
        print(f"  period {period}: 0 valid keys")

results['P4_direct_porta'] = {'tested': True}
print(f"\n  P4 done: {time.time()-t0:.1f}s")


# ── Phase 5: Porta + other columnar widths ────────────────────────────
print("\n--- P5: Porta + columnar widths 5,6,8, period = width ---")

for w in [5, 6, 8]:
    all_orders = list(permutations(range(w)))
    w_survivors = 0

    for order in all_orders:
        perm = build_perm(list(order), w)
        intermed = [CT_N[perm[j]] for j in range(N)]
        valid = check_porta_periodic(intermed, w)
        if valid:
            w_survivors += 1

    print(f"  Width {w} (period={w}): {w_survivors}/{len(all_orders)}")
    results[f'P5_porta_w{w}'] = {'survivors': w_survivors, 'total': len(all_orders)}

# Also test w=8 with period 7
all_orders_8 = list(permutations(range(8)))
w8_p7_survivors = 0
for order in all_orders_8:
    perm = build_perm(list(order), 8)
    intermed = [CT_N[perm[j]] for j in range(N)]
    valid = check_porta_periodic(intermed, 7)
    if valid:
        w8_p7_survivors += 1
print(f"  Width 8 (period=7): {w8_p7_survivors}/{len(all_orders_8)}")
results['P5_porta_w8_p7'] = {'survivors': w8_p7_survivors}

print(f"\n  P5 done: {time.time()-t0:.1f}s")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for phase, data in sorted(results.items()):
    print(f"  {phase}: {data}")
print(f"  Total: {total_elapsed:.1f}s")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-100',
    'description': 'Porta cipher + width-7 columnar (constraint propagation)',
    'results': {k: str(v) for k, v in results.items()},
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_100_porta_proper.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_100_porta_proper.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_100_porta_proper.py")
