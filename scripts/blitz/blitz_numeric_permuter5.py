#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
BLITZ Wave 5: Novel Permutation Derivation — Approaches Not Tried in Waves 1–4

New approaches:
  N1. GE bignum → Lehmer code → permutation (big-integer factorial-radix)
  N2. Scaled Lehmer: d[i] = floor(g[i] * (97-i) / 26)
  N3. Polynomial over GF(97): p(x) = Σ g[i]·xⁱ mod 97 for x in 0..96
  N4. Running product chain: σ(i) = Π(g[j]+1, j=0..i) mod 97
  N5. "8 Lines 73" block structure: K4 in 8 groups, intra-group perm from GE
  N6. Double-rank: rank by GE_AZ then tie-break by GE_KA
  N7. Factoradic from GE pairs: pair(g[2i], g[2i+1]) → Lehmer digit
  N8. GF(97) sequence: start from g[0], apply recurrence mod 97
  N9. Hybrid CSP: enumerate valid 24-pos partial assignments + check consistency
  N10. Grille holes direct K4 mapping via various 2D grid sizes (systematic)
  N11. Complement GE: rank by (26 - g[i]) = descending
  N12. Period-7 block permutations from GE (one key per block)
  N13. Cumulative XOR chain in GF(97)
  N14. Self-referential: K4 chars ranked by their GE POSITIONS  (not frequencies)

Usage:
  PYTHONPATH=src python3 -u scripts/blitz_numeric_permuter5.py
"""

import json
import sys
import os
import math
import itertools
from collections import defaultdict, Counter

sys.path.insert(0, 'scripts')
sys.path.insert(0, 'src')

# ── Constants ─────────────────────────────────────────────────────────────────

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
GE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
            'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA', 'ENIGMA']
N = 97
assert len(K4) == N and len(GE) == 106

# ── Index maps ────────────────────────────────────────────────────────────────

AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

GE_AZ  = [AZ_IDX[c] for c in GE]
GE_KA  = [KA_IDX[c] for c in GE]
K4_AZ  = [AZ_IDX[c] for c in K4]
K4_KA  = [KA_IDX[c] for c in K4]

# ── Quadgrams ─────────────────────────────────────────────────────────────────

QG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    qg = json.load(f)

def qgscore(text):
    return sum(qg.get(text[i:i+4], -10.0) for i in range(len(text) - 3))

def qgscore_pc(text):
    n = len(text) - 3
    return qgscore(text) / n if n > 0 else -10.0

# ── Cipher helpers ────────────────────────────────────────────────────────────

def vig_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[ct[i]] - idx[key[i % len(key)]]) % n] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ):
    n = len(alpha); idx = {c: i for i, c in enumerate(alpha)}
    return ''.join(alpha[(idx[key[i % len(key)]] - idx[ct[i]]) % n] for i in range(len(ct)))

# ── Permutation helpers ───────────────────────────────────────────────────────

def is_valid(perm, n=N):
    return len(perm) == n and sorted(perm) == list(range(n))

def apply_perm(text, perm):
    """real_CT = K4[perm[i]] for i in 0..96"""
    return ''.join(text[perm[i]] for i in range(len(perm)))

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, v in enumerate(perm): inv[v] = i
    return inv

def vals_to_rank_perm(vals, n=N):
    """Given n values, return rank-order permutation (stable, ascending)."""
    assert len(vals) == n
    indexed = sorted(range(n), key=lambda i: vals[i])
    perm = [0] * n
    for rank, idx in enumerate(indexed): perm[idx] = rank
    return perm

# ── Testing infrastructure ────────────────────────────────────────────────────

RESULTS = []
BEST_SCORE = -9999.0
TRIED = set()
COUNT = 0

CRIBS_TO_FIND = ["EASTNORTHEAST", "BERLINCLOCK"]

def check_pt(pt, label, extra=""):
    """Score PT, check for crib hits, print if new best."""
    global BEST_SCORE
    sc = qgscore(pt)
    ene = pt.find("EASTNORTHEAST")
    bc  = pt.find("BERLINCLOCK")
    if ene >= 0 or bc >= 0:
        print(f"\n{'='*70}")
        print(f"*** CRIB HIT *** {label}  {extra}")
        print(f"  ENE@{ene}  BC@{bc}")
        print(f"  PT : {pt}")
        print(f"  Score: {sc:.2f}")
        print(f"{'='*70}\n")
        RESULTS.append({'label': label, 'extra': extra, 'ene': ene, 'bc': bc,
                        'pt': pt, 'score': sc})
        return True
    if sc > BEST_SCORE:
        BEST_SCORE = sc
        print(f"  [NEW BEST] {sc:.2f}  {label}  {extra}  {pt[:50]}…")
    return False

def try_perm(perm, label):
    """Test a permutation against ALL keywords × ciphers × alphabets."""
    global COUNT
    key = tuple(perm)
    if key in TRIED:
        return
    TRIED.add(key)
    COUNT += 1
    real_ct = apply_perm(K4, perm)
    for kw in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, fn in [("vig", vig_dec), ("beau", beau_dec)]:
                pt = fn(real_ct, kw, alpha)
                if check_pt(pt, label, f"{kw}/{cname}/{alpha_name}"):
                    return

def try_perm_if_valid(perm, label):
    if is_valid(perm):
        try_perm(perm, label)
    else:
        pass  # silently skip invalid

# ── Lehmer code utilities ─────────────────────────────────────────────────────

def lehmer_decode(d, n=None):
    """
    Decode a Lehmer code (factoradic) into a permutation.
    d[i] must be in [0, n-1-i].
    n defaults to len(d).
    """
    if n is None:
        n = len(d)
    assert len(d) == n
    available = list(range(n))
    perm = []
    for i in range(n):
        idx = d[i]
        perm.append(available[idx])
        available.pop(idx)
    return perm

def bignum_to_lehmer(num, n):
    """
    Convert a non-negative integer `num` to a length-n Lehmer code.
    The mapping is: d[0] ∈ [0,n-1], d[1] ∈ [0,n-2], ..., d[n-1]=0.
    """
    d = []
    for k in range(n, 0, -1):
        d.append(int(num % k))
        num //= k
    return d

def compute_factorial(n):
    """Compute n! as a Python big integer."""
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result

# ── N1: GE bignum → Lehmer → permutation ─────────────────────────────────────

print("=" * 72)
print("N1: GE BIGNUM → LEHMER → PERMUTATION")
print("=" * 72)

def ge_bignum(ge_values):
    """Convert GE index sequence to a big base-26 integer."""
    num = 0
    for v in ge_values:
        num = num * 26 + v
    return num

count_n1 = 0

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    for use_len, label_suffix in [(97, "first97"), (106, "all106")]:
        vals = ge_vals[:use_len]
        bignum = ge_bignum(vals)

        # Variant A: direct bignum_to_lehmer on N=97
        d = bignum_to_lehmer(bignum % math.factorial(N), N)
        perm = lehmer_decode(d)
        try_perm_if_valid(perm, f"N1_bignum_{alpha_name}_{label_suffix}_direct")
        count_n1 += 1

        # Variant B: bignum mod 97! then lehmer decode
        # (same as A because bignum_to_lehmer always takes mod internally)
        # Skip duplicate.

        # Variant C: reversed GE
        r_vals = list(reversed(vals))
        bignum_r = ge_bignum(r_vals)
        d_r = bignum_to_lehmer(bignum_r % math.factorial(N), N)
        perm_r = lehmer_decode(d_r)
        try_perm_if_valid(perm_r, f"N1_bignum_{alpha_name}_{label_suffix}_reversed")
        count_n1 += 1

        # Variant D: GE interleaved (odd positions then even)
        odds = vals[1::2]; evens = vals[0::2]
        interleaved = odds + evens
        bignum_i = ge_bignum(interleaved[:use_len])
        d_i = bignum_to_lehmer(bignum_i % math.factorial(N), N)
        perm_i = lehmer_decode(d_i)
        try_perm_if_valid(perm_i, f"N1_bignum_{alpha_name}_{label_suffix}_interleaved")
        count_n1 += 1

print(f"N1 done: {count_n1} perms tested. Total so far: {COUNT}")

# ── N2: Scaled Lehmer decode ──────────────────────────────────────────────────

print("\n" + "=" * 72)
print("N2: SCALED LEHMER: d[i] = f(g[i], i) → PERMUTATION")
print("=" * 72)

count_n2 = 0

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    for use_len in [97, 106]:
        vals = ge_vals[:97]  # always use first 97 for Lehmer digits

        # Scale method A: floor(g[i] * (N-i) / 26)
        d_a = [int(vals[i] * (N - i) // 26) for i in range(N)]
        perm_a = lehmer_decode(d_a)
        try_perm_if_valid(perm_a, f"N2_scaled_floor_{alpha_name}_u{use_len}")
        count_n2 += 1

        # Scale method B: g[i] * (N-i) // 25 (clamped)
        d_b = [min(int(vals[i] * (N - i) // 25), N - 1 - i) for i in range(N)]
        perm_b = lehmer_decode(d_b)
        try_perm_if_valid(perm_b, f"N2_scaled_fl25_{alpha_name}_u{use_len}")
        count_n2 += 1

        # Scale method C: (g[i] * (N-i) + 13) // 26  (rounded)
        d_c = [min((vals[i] * (N - i) + 13) // 26, N - 1 - i) for i in range(N)]
        perm_c = lehmer_decode(d_c)
        try_perm_if_valid(perm_c, f"N2_scaled_round_{alpha_name}_u{use_len}")
        count_n2 += 1

        # Scale method D: (g[i] % (N-i)) directly — mod-based
        d_d = [vals[i] % max(1, N - i) for i in range(N)]
        perm_d = lehmer_decode(d_d)
        try_perm_if_valid(perm_d, f"N2_modraw_{alpha_name}_u{use_len}")
        count_n2 += 1

        # Reversed GE as digits
        rv = list(reversed(ge_vals[:97]))
        d_r = [int(rv[i] * (N - i) // 26) for i in range(N)]
        perm_r = lehmer_decode(d_r)
        try_perm_if_valid(perm_r, f"N2_scaled_rev_{alpha_name}")
        count_n2 += 1

print(f"N2 done: {count_n2} perms. Total: {COUNT}")

# ── N3: Polynomial over GF(97) ────────────────────────────────────────────────

print("\n" + "=" * 72)
print("N3: POLYNOMIAL EVALUATION OVER GF(97)")
print("=" * 72)

count_n3 = 0

def gf97_poly_perm(coeffs_list):
    """
    Evaluate polynomial p(x) = Σ coeffs[i]*x^i mod 97 for x in 0..96.
    coeffs_list should have 97 coefficients (indices 0..96 of GE or subseq).
    Returns a list of 97 values, may NOT be a permutation.
    """
    result = []
    for x in range(N):
        val = 0
        xpow = 1
        for c in coeffs_list:
            val = (val + c * xpow) % N
            xpow = (xpow * x) % N
        result.append(val)
    return result

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    coeffs97 = ge_vals[:97]

    # Evaluate p(x) = Σ c_i * x^i mod 97
    vals_poly = gf97_poly_perm(coeffs97)
    if len(set(vals_poly)) == N:  # check if all distinct → valid permutation
        perm = vals_poly  # the evaluation IS the permutation (σ(x) = p(x))
        try_perm_if_valid(perm, f"N3_poly97_{alpha_name}")
        count_n3 += 1
        print(f"  N3 poly {alpha_name}: VALID PERM!")
    else:
        collisions = N - len(set(vals_poly))
        print(f"  N3 poly {alpha_name}: {collisions} collisions, not a perm")

    # Also try as inverse permutation
    vals_inv = invert_perm(list(range(N)))  # just identity as placeholder
    # Instead, try evaluating as p(x) for x=1..97 (shifted domain)
    vals_shifted = [(sum(c * pow(x+1, i, N) for i, c in enumerate(coeffs97))) % N
                    for x in range(N)]
    if len(set(vals_shifted)) == N:
        try_perm_if_valid(vals_shifted, f"N3_poly97_shifted1_{alpha_name}")
        count_n3 += 1
        print(f"  N3 poly shifted {alpha_name}: VALID PERM!")
    else:
        print(f"  N3 poly shifted {alpha_name}: collisions, not a perm")

    # Linear polynomial: p(x) = g[0]*x + g[1] mod 97
    a, b = coeffs97[0] % N, coeffs97[1] % N
    if a != 0:
        lin_vals = [(a * x + b) % N for x in range(N)]
        if len(set(lin_vals)) == N:
            try_perm_if_valid(lin_vals, f"N3_linear_g01_{alpha_name}")
            count_n3 += 1

    # Quadratic: p(x) = g[0]*x^2 + g[1]*x + g[2] mod 97
    for deg in [2, 3, 4]:
        poly_coeffs = coeffs97[:deg+1]
        vals_q = [(sum(c * pow(x, i, N) for i, c in enumerate(poly_coeffs))) % N
                  for x in range(N)]
        if len(set(vals_q)) == N:
            try_perm_if_valid(vals_q, f"N3_deg{deg}_{alpha_name}")
            count_n3 += 1
            print(f"  N3 deg{deg} {alpha_name}: VALID PERM!")
        # Also try non-zero domain (x = 1..97)
        vals_q2 = [(sum(c * pow(x, i, N) for i, c in enumerate(poly_coeffs))) % N
                   for x in range(1, N+1)]
        if len(set(vals_q2)) == N:
            try_perm_if_valid(vals_q2, f"N3_deg{deg}_dom1_{alpha_name}")
            count_n3 += 1

print(f"N3 done: {count_n3} perms. Total: {COUNT}")

# ── N4: Running product chain in Z/97Z ───────────────────────────────────────

print("\n" + "=" * 72)
print("N4: RUNNING PRODUCT CHAIN in Z/97Z")
print("=" * 72)

count_n4 = 0

def product_chain(ge_vals, n=N, offset=1):
    """
    σ(0) = ge_vals[0] mod n
    σ(i) = (σ(i-1) * (ge_vals[i] + offset)) mod n
    Returns list of n values; may have collisions.
    """
    seq = []
    cur = ge_vals[0] % n
    seq.append(cur)
    for i in range(1, n):
        cur = (cur * (ge_vals[i] + offset)) % n
        seq.append(cur)
    return seq

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    for offset in [1, 2, 3]:
        chain = product_chain(ge_vals, N, offset)
        if len(set(chain)) == N:
            try_perm_if_valid(chain, f"N4_prodchain_{alpha_name}_off{offset}")
            count_n4 += 1
            print(f"  N4 prodchain {alpha_name} off{offset}: VALID PERM!")
        else:
            pass

    # Running sum mod N
    for offset in [0, 1, 13, 14]:
        seq_sum = []
        cur = (ge_vals[0] + offset) % N
        seq_sum.append(cur)
        for i in range(1, N):
            cur = (cur + ge_vals[i] + offset) % N
            seq_sum.append(cur)
        if len(set(seq_sum)) == N:
            try_perm_if_valid(seq_sum, f"N4_sumchain_{alpha_name}_off{offset}")
            count_n4 += 1
            print(f"  N4 sumchain {alpha_name} off{offset}: VALID PERM!")

    # Multiplicative starting from each GE value as seed
    for start_idx in range(10):
        seq_mul = []
        cur = (ge_vals[start_idx] + 1) % N
        if cur == 0: cur = 1
        for i in range(N):
            cur = (cur * (ge_vals[(start_idx + i) % 106] + 1)) % N
            if cur == 0: cur = 1
            seq_mul.append(cur - 1)  # map [1,97] → [0,96] (careful: 97 → 96 ok)
        if len(set(seq_mul)) == N and all(0 <= v < N for v in seq_mul):
            try_perm_if_valid(seq_mul, f"N4_mulchain_{alpha_name}_s{start_idx}")
            count_n4 += 1

print(f"N4 done: {count_n4} perms. Total: {COUNT}")

# ── N5: "8 Lines 73" block structure ─────────────────────────────────────────

print("\n" + "=" * 72)
print("N5: '8 LINES 73' BLOCK STRUCTURE")
print("=" * 72)
# "8 Lines 73": K4 has 8 lines and 73 non-crib chars (97 - 24 = 73).
# Interpretation: K4 real_CT is written in 8 "lines" of varying widths.
# The crib chars (24 total) are fixed; the 73 non-crib chars form 8 lines.

# Approach: treat the 73 non-crib positions as 8 groups of ~9 chars.
# Within each group, the permutation is defined by the GE values at those positions.

count_n5 = 0

CRIB_POSITIONS = set(range(21, 34)) | set(range(63, 74))  # 24 positions
NON_CRIB = [i for i in range(N) if i not in CRIB_POSITIONS]  # 73 positions
assert len(NON_CRIB) == 73

# Divide 73 non-crib positions into 8 groups
def divide_into_groups(positions, num_groups):
    """Divide positions into num_groups groups of ~equal size."""
    n = len(positions)
    groups = []
    start = 0
    for g in range(num_groups):
        size = (n - start) // (num_groups - g)
        groups.append(positions[start:start+size])
        start += size
    return groups

non_crib_groups = divide_into_groups(NON_CRIB, 8)

# For each group, sort within group using GE chars as key
def block_perm_from_ge(positions, ge_vals, alpha_name):
    """Sort positions within each group by GE value at that position."""
    ranked = sorted(positions, key=lambda i: (ge_vals[i % 106], i))
    # ranked[j] = which K4 position is at real_CT position j
    return ranked

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    # Build the full permutation: identity for crib positions + GE-sorted for non-crib
    for crib_identity in [True, False]:
        perm = list(range(N))  # start with identity
        for group in non_crib_groups:
            # Sort group members by their GE value
            sorted_group = sorted(group, key=lambda i: (ge_vals[i % 106], i))
            for j, pos in enumerate(sorted(group)):  # assign in original order
                perm[pos] = sorted_group[j]
        if is_valid(perm):
            try_perm(perm, f"N5_8lines_{alpha_name}_ci{crib_identity}")
            count_n5 += 1
        # Try inverse
        if is_valid(perm):
            inv = invert_perm(perm)
            try_perm(inv, f"N5_8lines_inv_{alpha_name}_ci{crib_identity}")
            count_n5 += 1
        break  # crib_identity variant only

# Variant: 8 equal-size groups of K4 (not just non-crib)
for grp_size in [12, 13]:
    for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
        perm = []
        for grp_start in range(0, N, grp_size):
            grp = list(range(grp_start, min(grp_start + grp_size, N)))
            sorted_grp = sorted(grp, key=lambda i: (ge_vals[i % 106], i))
            # Map: within group, sorted_grp defines the permutation
            for j, orig_pos in enumerate(grp):
                perm.append(sorted_grp[j])
        if is_valid(perm):
            try_perm(perm, f"N5_grpsize{grp_size}_{alpha_name}")
            count_n5 += 1

print(f"N5 done: {count_n5} perms. Total: {COUNT}")

# ── N6: Double-rank (GE_AZ then GE_KA tie-break) ─────────────────────────────

print("\n" + "=" * 72)
print("N6: DOUBLE-RANK (GE_AZ primary, GE_KA tie-break)")
print("=" * 72)

count_n6 = 0

for use_n in [97, 106]:
    ge_az_vals = GE_AZ[:use_n]
    ge_ka_vals = GE_KA[:use_n]

    # Primary AZ, tie-break KA, position secondary
    ranked_az_ka = sorted(range(use_n), key=lambda i: (ge_az_vals[i], ge_ka_vals[i], i))
    # This gives rank of each GE position. Now map to K4:
    # rank_perm[i] = rank of GE[i] → σ where σ(j) = ranked_az_ka[j]
    if use_n == 97:
        perm = ranked_az_ka[:]
        try_perm_if_valid(perm, "N6_dblrank_az_ka_97")
        count_n6 += 1
        perm_inv = invert_perm(perm)
        try_perm_if_valid(perm_inv, "N6_dblrank_az_ka_97_inv")
        count_n6 += 1
    else:
        # Take first 97 of the 106 ranked positions
        sub = [v for v in ranked_az_ka if v < 97][:97]
        if is_valid(sub):
            try_perm_if_valid(sub, "N6_dblrank_az_ka_106_sub97")
            count_n6 += 1

    # Primary KA, tie-break AZ
    ranked_ka_az = sorted(range(use_n), key=lambda i: (ge_ka_vals[i], ge_az_vals[i], i))
    if use_n == 97:
        perm = ranked_ka_az[:]
        try_perm_if_valid(perm, "N6_dblrank_ka_az_97")
        count_n6 += 1
        perm_inv = invert_perm(perm)
        try_perm_if_valid(perm_inv, "N6_dblrank_ka_az_97_inv")
        count_n6 += 1

    # Complement rank: sort by (26 - ge[i])  = descending order
    for alpha_name, ge_vals in [("AZ", GE_AZ[:use_n]), ("KA", GE_KA[:use_n])]:
        complement = [26 - v for v in ge_vals]
        ranked_comp = sorted(range(use_n), key=lambda i: (complement[i], i))
        if use_n == 97:
            perm = ranked_comp[:]
            try_perm_if_valid(perm, f"N6_complement_{alpha_name}_{use_n}")
            count_n6 += 1
            inv = invert_perm(perm)
            try_perm_if_valid(inv, f"N6_complement_{alpha_name}_{use_n}_inv")
            count_n6 += 1

print(f"N6 done: {count_n6} perms. Total: {COUNT}")

# ── N7: Factoradic from GE pairs ──────────────────────────────────────────────

print("\n" + "=" * 72)
print("N7: FACTORADIC FROM GE PAIRS (pair → Lehmer digit)")
print("=" * 72)

count_n7 = 0

def ge_pairs_to_lehmer(ge_vals, n=N):
    """
    Use consecutive PAIRS of GE values as Lehmer code digits.
    pair (a, b) → digit d = (a * 26 + b) mod (n - i)
    We need n digits, so 2n values, but GE only has 106.
    For n=97 we need 194 values; pad by repeating.
    """
    d = []
    for i in range(n):
        a = ge_vals[(2*i) % len(ge_vals)]
        b = ge_vals[(2*i + 1) % len(ge_vals)]
        combined = a * 26 + b  # base-26 pair → [0, 675]
        denom = n - i
        d.append(combined % denom)
    return d

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    d = ge_pairs_to_lehmer(ge_vals)
    perm = lehmer_decode(d)
    try_perm_if_valid(perm, f"N7_pair_lehmer_{alpha_name}")
    count_n7 += 1

    # Also try GE backwards
    rev = list(reversed(ge_vals))
    d_r = ge_pairs_to_lehmer(rev)
    perm_r = lehmer_decode(d_r)
    try_perm_if_valid(perm_r, f"N7_pair_lehmer_rev_{alpha_name}")
    count_n7 += 1

    # Triple encoding
    def ge_triples_to_lehmer(ge_vals, n=N):
        d = []
        for i in range(n):
            a = ge_vals[(3*i) % len(ge_vals)]
            b = ge_vals[(3*i+1) % len(ge_vals)]
            c = ge_vals[(3*i+2) % len(ge_vals)]
            combined = (a * 26*26 + b * 26 + c) % (n - i)
            d.append(combined)
        return d

    d_t = ge_triples_to_lehmer(ge_vals)
    perm_t = lehmer_decode(d_t)
    try_perm_if_valid(perm_t, f"N7_triple_lehmer_{alpha_name}")
    count_n7 += 1

print(f"N7 done: {count_n7} perms. Total: {COUNT}")

# ── N8: GF(97) recurrence sequences ──────────────────────────────────────────

print("\n" + "=" * 72)
print("N8: GF(97) RECURRENCE SEQUENCES")
print("=" * 72)

count_n8 = 0

# Linear recurrence: s[i] = (a * s[i-1] + b) mod 97
# where a and b are derived from GE
# Seed = GE[0] % 97

def lfsr_perm(a, b, seed, n=N):
    """Linear recurrence s[i] = (a*s[i-1] + b) mod n, starting from seed."""
    seq = [seed % n]
    cur = seed % n
    for _ in range(n - 1):
        cur = (a * cur + b) % n
        seq.append(cur)
    return seq

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    a0 = ge_vals[0]
    b0 = ge_vals[1]
    seed0 = ge_vals[2] % N

    # Try primitive roots of 97 as multiplier
    # Primitive roots mod 97: 5, 13, 15, 17, 19, 20, 22, 24, 32, 35, ...
    primitive_roots_97 = [5, 13, 15, 17, 19, 20, 22, 24, 32, 35, 42, 44, 47,
                           52, 53, 55, 57, 62, 65, 75, 77, 78, 80, 82, 84, 92]

    for a in primitive_roots_97[:6]:  # try first 6 primitive roots
        b = b0 % N
        seed = seed0
        seq = lfsr_perm(a, b, seed)
        if len(set(seq)) == N:
            try_perm_if_valid(seq, f"N8_lfsr_a{a}_{alpha_name}")
            count_n8 += 1
        # Also use GE-derived seed
        for s in [a0 % N, (a0 + b0) % N]:
            seq2 = lfsr_perm(a, b, s)
            if len(set(seq2)) == N:
                try_perm_if_valid(seq2, f"N8_lfsr_a{a}_s{s}_{alpha_name}")
                count_n8 += 1

    # GE-derived multiplier
    for a in [a0 % 97 or 1, (a0 * b0) % 97 or 1]:
        for b in [b0 % 97, (b0 + 13) % 97]:
            for seed in [seed0, (seed0 + 13) % N]:
                seq = lfsr_perm(a, b, seed)
                if len(set(seq)) == N:
                    try_perm_if_valid(seq, f"N8_lfsr_ge_a{a}b{b}_{alpha_name}")
                    count_n8 += 1

print(f"N8 done: {count_n8} perms. Total: {COUNT}")

# ── N9: Hybrid CSP — enumerate valid 24-pos assignments + structural test ─────

print("\n" + "=" * 72)
print("N9: HYBRID CSP — VALID 24-POS PARTIAL ΣASSIGNMENTS")
print("=" * 72)

# For keyword KRYPTOS / AZ / Vig, the expected real_CT at each crib position:
# PT[21..33] = EASTNORTHEAST, PT[63..73] = BERLINCLOCK
# Vigenère key KRYPTOS (AZ):
# K=10, R=17, Y=24, P=15, T=19, O=14, S=18

CRIB_DATA = [
    (21, "EASTNORTHEAST"),
    (63, "BERLINCLOCK"),
]

def compute_expected_ct(keyword, alpha, cipher_type):
    """Compute expected real_CT chars at all crib positions."""
    idx = {c: i for i, c in enumerate(alpha)}
    expected = {}
    for crib_start, crib_text in CRIB_DATA:
        for j, pt_char in enumerate(crib_text):
            pos = crib_start + j
            ki = idx[keyword[pos % len(keyword)]]
            pi = idx[pt_char]
            if cipher_type == "vig":
                expected[pos] = alpha[(pi + ki) % 26]
            else:  # beau: CT = key - PT
                expected[pos] = alpha[(ki - pi) % 26]
    return expected

def k4_positions_with_char(c, k4=K4):
    return [i for i, ch in enumerate(k4) if ch == c]

# For each keyword/cipher/alpha combination
count_n9 = 0
best_n9_score = -9999
best_n9_result = None

def backtrack_csp(positions, expected, k4=K4, partial=None, used=None):
    """
    Enumerate all valid partial permutation assignments for crib positions.
    positions: sorted list of crib positions to assign
    expected: dict mapping position → expected real_CT char
    Returns: list of valid assignments (dicts: pos → k4_pos)
    """
    if partial is None: partial = {}
    if used is None: used = set()

    if not positions:
        return [dict(partial)]

    pos = positions[0]
    rest = positions[1:]
    char = expected[pos]
    candidates = [k4p for k4p in k4_positions_with_char(char) if k4p not in used]

    results = []
    for k4p in candidates:
        partial[pos] = k4p
        used.add(k4p)
        results.extend(backtrack_csp(rest, expected, k4, partial, used))
        del partial[pos]
        used.remove(k4p)
        if len(results) > 5000:  # limit for performance
            break

    return results

# Test for KRYPTOS/AZ/Vig (primary candidate)
print("  Testing KRYPTOS/AZ/vig CSP...")
for kw, alpha_name, alpha, ctype in [
    ("KRYPTOS", "AZ", AZ, "vig"),
    ("KRYPTOS", "KA", KA, "vig"),
    ("KRYPTOS", "AZ", AZ, "beau"),
    ("PALIMPSEST", "AZ", AZ, "vig"),
    ("ABSCISSA", "AZ", AZ, "vig"),
]:
    exp = compute_expected_ct(kw, alpha, ctype)
    crib_positions = sorted(exp.keys())

    # Enumerate all valid partial assignments via backtracking
    assignments = backtrack_csp(crib_positions, exp)
    print(f"  {kw}/{ctype}/{alpha_name}: {len(assignments)} valid partial assignments")

    # For each partial assignment, try extending with simple structural rules
    for assign in assignments[:100]:  # limit to first 100
        # Build partial real_CT (97 chars, with question marks at non-crib positions)
        real_ct_partial = list('?' * N)
        for pos, k4p in assign.items():
            real_ct_partial[pos] = K4[k4p]

        # Try: rank-order GE for the 73 non-crib positions
        for ae_name, ae_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
            non_crib_ge = [(ae_vals[i % 106], i) for i in range(N) if i not in CRIB_POSITIONS]
            sorted_nc_ge = sorted(range(len(non_crib_ge)), key=lambda j: non_crib_ge[j])
            # Map: position j in non-crib → rank = some K4 position
            # This gives a candidate for the 73 non-crib positions of σ
            used_k4 = set(assign.values())
            available_k4 = [k4p for k4p in range(N) if k4p not in used_k4]
            # Sort available K4 positions by GE rank
            avail_sorted = sorted(available_k4, key=lambda k: (ae_vals[k % 106], k))

            # Assign: non-crib position sorted_nc_ge[j] → avail_sorted[j]
            perm = [0] * N
            for pos, k4p in assign.items():
                perm[pos] = k4p
            nc_positions = sorted([i for i in range(N) if i not in CRIB_POSITIONS])
            nc_sorted_by_ge = sorted(nc_positions, key=lambda i: (ae_vals[i % 106], i))
            for j, real_ct_pos in enumerate(nc_sorted_by_ge):
                if j < len(avail_sorted):
                    perm[real_ct_pos] = avail_sorted[j]

            if is_valid(perm):
                real_ct = apply_perm(K4, perm)
                pt = (vig_dec if ctype == "vig" else beau_dec)(real_ct, kw, alpha)
                sc = qgscore(pt)
                ene = pt.find("EASTNORTHEAST")
                bc = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    check_pt(pt, f"N9_csp_{kw}_{ae_name}", f"{ctype}/{alpha_name}")
                    count_n9 += 1
                elif sc > best_n9_score:
                    best_n9_score = sc
                    best_n9_result = (pt, perm, f"N9_csp_{kw}_{ae_name}_{ctype}")
                    if sc > BEST_SCORE:
                        BEST_SCORE = sc
                        print(f"  N9 new best: {sc:.2f}  {pt[:50]}")

if best_n9_result:
    pt, perm, lbl = best_n9_result
    print(f"  N9 best overall: {best_n9_score:.2f}  {lbl}  {pt[:50]}")

print(f"N9 done: {count_n9} crib hits. Total: {COUNT}")

# ── N10: Systematic 2D grid overlay (sizes not tried before) ─────────────────

print("\n" + "=" * 72)
print("N10: 2D GRID OVERLAY — K4 in VARIOUS GRIDS")
print("=" * 72)

# The grille mask has holes at (r, c). If K4 is written in a W×H grid,
# holes within that grid define reading order.

MASK_ROWS = [
    "000000001010100000000010000000001~~",  # Row 1
    "100000000010000001000100110000011~~",
    "000000000000001000000000000000011~~",
    "00000000000000000000100000010011~~",
    "00000001000000001000010000000011~~",
    "000000001000000000000000000000011~",
    "100000000000000000000000000000011",
    "00000000000000000000000100000100~~",
    "0000000000000000000100000001000~~",
    "0000000000000000000000000000100~~",
    "000000001000000000000000000000~~",
    "00000110000000000000000000000100~~",
    "00000000000000100010000000000001~~",
    "00000000000100000000000000001000~~",
    "000110100001000000000000001000010~~",
    "00001010000000000000000001000001~~",
    "001001000010010000000000000100010~~",
    "00000000000100000000010000010001~~",
    "000000000000010001001000000010001~~",
    "00000000000000001001000000000100~~",
    "000000001100000010100100010001001~~",
    "000000000000000100001010100100011~",
    "00000000100000000000100001100001~~~",
    "100000000000000000001000001000010~",
    "10000001000001000000100000000001~~",
    "000010000000000000010000100000011",
    "0000000000000000000100001000000011",
    "00000000000000100000001010000001~~",
]

# IMPORTANT: 1=HOLE, 0=SOLID (verified in v6)
# Parse holes: (row, col) for all '1' chars within col < 33
holes = []
for r, row_str in enumerate(MASK_ROWS):
    for c, ch in enumerate(row_str):
        if c < 33 and ch == '1':
            holes.append((r, c))

print(f"Total holes (1s, c<33): {len(holes)}")

# Try various K4 grid layouts
count_n10 = 0

for (W, H) in [(7, 14), (14, 7), (10, 10), (97, 1), (1, 97),
               (13, 8), (8, 13), (11, 9), (9, 11), (6, 17), (17, 6)]:
    for row_major in [True, False]:
        # Map grille (r,c) to K4 position
        sigma = []
        hole_in_grid = []
        for hr, hc in holes:
            if row_major:
                if hr < H and hc < W:
                    k4_pos = hr * W + hc
                else:
                    continue
            else:  # col-major
                if hr < H and hc < W:
                    k4_pos = hc * H + hr
                else:
                    continue
            if k4_pos < N:
                hole_in_grid.append(k4_pos)

        # Reading order: left-to-right, top-to-bottom (already in order from holes parse)
        # hole_in_grid gives the sequence of K4 positions read by the grille
        if len(set(hole_in_grid)) == N and len(hole_in_grid) >= N:
            # Take first N unique values
            sigma = []
            seen = set()
            for v in hole_in_grid:
                if v not in seen:
                    seen.add(v)
                    sigma.append(v)
                if len(sigma) == N:
                    break
            if is_valid(sigma):
                order = "rm" if row_major else "cm"
                try_perm(sigma, f"N10_grid_{W}x{H}_{order}")
                count_n10 += 1

                # Also try inverse
                inv = invert_perm(sigma)
                if is_valid(inv):
                    try_perm(inv, f"N10_grid_{W}x{H}_{order}_inv")
                    count_n10 += 1

# Also try offset overlays (shift the grid by dr, dc)
for W, H in [(7, 14), (8, 13), (10, 10)]:
    for dr in range(0, max(0, 28-H+1)):
        for dc in range(0, max(0, 33-W+1)):
            sigma = []
            seen = set()
            for hr, hc in holes:
                adjusted_r = hr - dr
                adjusted_c = hc - dc
                if 0 <= adjusted_r < H and 0 <= adjusted_c < W:
                    k4_pos = adjusted_r * W + adjusted_c
                    if k4_pos < N and k4_pos not in seen:
                        seen.add(k4_pos)
                        sigma.append(k4_pos)
            if len(sigma) == N and is_valid(sigma):
                try_perm(sigma, f"N10_offset_{W}x{H}_dr{dr}_dc{dc}")
                count_n10 += 1

print(f"N10 done: {count_n10} perms. Total: {COUNT}")

# ── N11: Complement and mirror variants ──────────────────────────────────────

print("\n" + "=" * 72)
print("N11: COMPLEMENT + MIRROR VARIANTS")
print("=" * 72)

count_n11 = 0

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    # Complement rank: sort by (25 - g[i]) descending
    comp = [25 - v for v in ge_vals[:97]]
    ranked_comp = sorted(range(97), key=lambda i: (comp[i], i))
    try_perm_if_valid(ranked_comp, f"N11_comp_rank_{alpha_name}")
    count_n11 += 1
    inv_comp = invert_perm(ranked_comp)
    try_perm_if_valid(inv_comp, f"N11_comp_rank_inv_{alpha_name}")
    count_n11 += 1

    # Interleave normal and complement: merge two sorted orders
    normal = sorted(range(97), key=lambda i: (ge_vals[i], i))
    complement = sorted(range(97), key=lambda i: (25 - ge_vals[i], i))
    interleaved = []
    for j in range(N):
        interleaved.append(normal[j // 2] if j % 2 == 0 else complement[j // 2])
    if is_valid(interleaved):
        try_perm(interleaved, f"N11_interleaved_{alpha_name}")
        count_n11 += 1

    # Use GE values 9-105 (skip first 9) → 97 values
    skip = ge_vals[9:106]
    if len(skip) == 97:
        perm_skip = sorted(range(97), key=lambda i: (skip[i], i))
        try_perm_if_valid(perm_skip, f"N11_skip9_{alpha_name}")
        count_n11 += 1

    # Use every other GE value
    every_other = ge_vals[::1][:97]  # already done; try stride 2
    stride2 = ge_vals[::2]  # 53 values, not 97 — skip

print(f"N11 done: {count_n11} perms. Total: {COUNT}")

# ── N12: Period-7 block permutations ─────────────────────────────────────────

print("\n" + "=" * 72)
print("N12: PERIOD-7 BLOCK PERMUTATIONS (KRYPTOS key period = 7)")
print("=" * 72)

count_n12 = 0

# Hypothesis: σ permutes K4 in blocks of 7 (matching key period)
# Within each block of 7, the permutation is defined by GE chars at those positions
# K4 has 97 = 13*7 + 6 chars → 13 full blocks + 1 partial (6 chars)

def period_block_perm(period, ge_vals, alpha_name):
    """Build permutation by sorting within period-sized blocks."""
    perm = []
    for block_start in range(0, N, period):
        block = list(range(block_start, min(block_start + period, N)))
        ge_keys = [(ge_vals[i % 106], i) for i in block]
        sorted_block = sorted(range(len(block)), key=lambda j: ge_keys[j])
        # sorted_block[j] = rank of block[j] within block
        # Permutation: real_CT[block_start + j] = K4[block[sorted_block[j]]]
        for j in range(len(block)):
            perm.append(block[sorted_block[j]])
    return perm

for period in [7, 8, 10, 13, 14]:
    for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
        perm = period_block_perm(period, ge_vals, alpha_name)
        if is_valid(perm):
            try_perm(perm, f"N12_period{period}_{alpha_name}")
            count_n12 += 1
        inv = invert_perm(perm) if is_valid(perm) else None
        if inv and is_valid(inv):
            try_perm(inv, f"N12_period{period}_{alpha_name}_inv")
            count_n12 += 1

        # Also: sort blocks by REVERSE order
        perm_rev = []
        for block_start in range(0, N, period):
            block = list(range(block_start, min(block_start + period, N)))
            ge_keys = [(ge_vals[i % 106], i) for i in block]
            sorted_block = sorted(range(len(block)), key=lambda j: ge_keys[j], reverse=True)
            for j in range(len(block)):
                perm_rev.append(block[sorted_block[j]])
        if is_valid(perm_rev):
            try_perm(perm_rev, f"N12_period{period}_{alpha_name}_rev")
            count_n12 += 1

print(f"N12 done: {count_n12} perms. Total: {COUNT}")

# ── N13: Cumulative XOR chain ─────────────────────────────────────────────────

print("\n" + "=" * 72)
print("N13: CUMULATIVE XOR CHAIN in Z/97Z")
print("=" * 72)

count_n13 = 0

def xor_chain(ge_vals, n=N, scale=1):
    """σ(0) = ge_vals[0], σ(i) = (σ(i-1) XOR (ge_vals[i] * scale)) mod n"""
    seq = [ge_vals[0] % n]
    for i in range(1, n):
        val = (seq[-1] ^ (ge_vals[i] * scale)) % n
        seq.append(val)
    return seq

for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    for scale in [1, 2, 3, 4, 7]:
        chain = xor_chain(ge_vals, N, scale)
        if len(set(chain)) == N:
            try_perm_if_valid(chain, f"N13_xorchain_{alpha_name}_sc{scale}")
            count_n13 += 1

    # Difference chain: σ(i) = (σ(i-1) - ge_vals[i]) mod n
    for sign in [1, -1]:
        seq = [ge_vals[0] % N]
        for i in range(1, N):
            seq.append((seq[-1] + sign * ge_vals[i]) % N)
        if len(set(seq)) == N:
            try_perm_if_valid(seq, f"N13_diffchain_{alpha_name}_s{sign}")
            count_n13 += 1

print(f"N13 done: {count_n13} perms. Total: {COUNT}")

# ── N14: K4 chars ranked by GE position ───────────────────────────────────────

print("\n" + "=" * 72)
print("N14: K4 CHARS RANKED BY GE OCCURRENCE POSITION")
print("=" * 72)

count_n14 = 0

# For each unique char in K4: find its first/last/Nth occurrence in GE
# Use this as the sort key for K4 positions

ge_first_occ = {}
ge_last_occ = {}
ge_all_occ = defaultdict(list)
for i, c in enumerate(GE):
    if c not in ge_first_occ:
        ge_first_occ[c] = i
    ge_last_occ[c] = i
    ge_all_occ[c].append(i)

for sort_by, label in [
    (lambda j: (ge_first_occ.get(K4[j], 999), j), "first_occ"),
    (lambda j: (ge_last_occ.get(K4[j], 999), j), "last_occ"),
    (lambda j: (len(ge_all_occ.get(K4[j], [])), j), "freq"),
    (lambda j: (-ge_first_occ.get(K4[j], 0), j), "first_occ_desc"),
    (lambda j: (-len(ge_all_occ.get(K4[j], [])), -ge_first_occ.get(K4[j], 0), j), "freq_desc"),
]:
    ranked = sorted(range(N), key=sort_by)
    perm = ranked  # ranked[j] = K4 position that goes to real_CT position j
    try_perm_if_valid(perm, f"N14_ge_occ_{label}")
    count_n14 += 1
    inv = invert_perm(perm)
    try_perm_if_valid(inv, f"N14_ge_occ_{label}_inv")
    count_n14 += 1

# For each K4 position j, count how many times K4[j] appears BEFORE position j in GE
# (uses cumulative GE occurrence counts up to each GE position)
ge_cumulative_count = {c: 0 for c in AZ}
k4_ge_before = []  # for each K4 position j, count of K4[j] in GE[:j]
for j in range(N):
    c = K4[j]
    k4_ge_before.append(ge_cumulative_count.get(c, 0))
    if j < len(GE):
        ge_cumulative_count[GE[j]] = ge_cumulative_count.get(GE[j], 0) + 1

ranked_cum = sorted(range(N), key=lambda j: (k4_ge_before[j], j))
try_perm_if_valid(ranked_cum, "N14_ge_cumulative_before")
count_n14 += 1

print(f"N14 done: {count_n14} perms. Total: {COUNT}")

# ── N15: GE as keyed alphabet for K4 sorting ──────────────────────────────────

print("\n" + "=" * 72)
print("N15: GE DEFINES CUSTOM ALPHABET ORDER → K4 SORT")
print("=" * 72)

count_n15 = 0

# Build a 26-char ordering from GE: first occurrence order
ge_alpha_order = []
seen_chars = set()
for c in GE:
    if c not in seen_chars:
        ge_alpha_order.append(c)
        seen_chars.add(c)
# T is absent from GE! So ge_alpha_order has 25 chars.
# Add T at the end (or some position)
for c in AZ:
    if c not in seen_chars:
        ge_alpha_order.append(c)
        seen_chars.add(c)

ge_alpha_idx = {c: i for i, c in enumerate(ge_alpha_order)}
print(f"  GE alpha order: {''.join(ge_alpha_order)}")

# Sort K4 positions by this custom alphabet ordering
for secondary_key in ["position_asc", "position_desc", "k4val_asc"]:
    if secondary_key == "position_asc":
        key_fn = lambda j: (ge_alpha_idx.get(K4[j], 25), j)
    elif secondary_key == "position_desc":
        key_fn = lambda j: (ge_alpha_idx.get(K4[j], 25), -j)
    else:
        key_fn = lambda j: (ge_alpha_idx.get(K4[j], 25), K4_AZ[j], j)

    ranked = sorted(range(N), key=key_fn)
    try_perm_if_valid(ranked, f"N15_ge_alpha_{secondary_key}")
    count_n15 += 1
    inv = invert_perm(ranked)
    try_perm_if_valid(inv, f"N15_ge_alpha_{secondary_key}_inv")
    count_n15 += 1

# Also: sort by REVERSE GE occurrence (last occurrence first)
ge_alpha_order_rev = []
seen_chars = set()
for c in reversed(GE):
    if c not in seen_chars:
        ge_alpha_order_rev.append(c)
        seen_chars.add(c)
for c in AZ:
    if c not in seen_chars:
        ge_alpha_order_rev.append(c)
        seen_chars.add(c)
ge_alpha_idx_rev = {c: i for i, c in enumerate(ge_alpha_order_rev)}
ranked_rev = sorted(range(N), key=lambda j: (ge_alpha_idx_rev.get(K4[j], 25), j))
try_perm_if_valid(ranked_rev, "N15_ge_alpha_rev_order")
count_n15 += 1

print(f"N15 done: {count_n15} perms. Total: {COUNT}")

# ── N16: MIXED APPROACHES ─────────────────────────────────────────────────────

print("\n" + "=" * 72)
print("N16: MIXED APPROACHES")
print("=" * 72)

count_n16 = 0

# N16a: GE even positions vs odd positions rank
for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    evens = ge_vals[0::2][:49]  # 49 values
    odds  = ge_vals[1::2][:48]  # 48 values (total 97)
    combined = list(evens) + list(odds)  # 97 values
    ranked = sorted(range(97), key=lambda i: (combined[i], i))
    try_perm_if_valid(ranked, f"N16a_evens_then_odds_{alpha_name}")
    count_n16 += 1
    inv = invert_perm(ranked)
    try_perm_if_valid(inv, f"N16a_evens_then_odds_{alpha_name}_inv")
    count_n16 += 1

# N16b: Sort GE first 97 by KA value, take positions as permutation
for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    sorted_ge_pos = sorted(range(97), key=lambda i: (ge_vals[i], i))
    # sorted_ge_pos[j] = GE position with j-th smallest value
    # This IS the identity of rank order; same as Approach B wave 1
    # But try with GE positions 9-105 (skip first 9)
    ge9 = ge_vals[9:106]
    if len(ge9) == 97:
        s9 = sorted(range(97), key=lambda i: (ge9[i], i))
        try_perm_if_valid(s9, f"N16b_ge9_{alpha_name}")
        count_n16 += 1

# N16c: Use GE as Straddling Checkerboard (positional encoding)
# Map K4 char to GE occurrence positions
for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    # For each K4 position j, assign rank = (index of K4[j] in GE's occurrence order)
    ge_char_rank = {}
    rank = 0
    for c in GE:
        if c not in ge_char_rank:
            ge_char_rank[c] = rank
            rank += 1
    k4_char_ranks = [ge_char_rank.get(K4[j], 25) * 97 + j for j in range(N)]
    ranked = sorted(range(N), key=lambda j: k4_char_ranks[j])
    try_perm_if_valid(ranked, f"N16c_char_rank_{alpha_name}")
    count_n16 += 1

# N16d: GE values summed per pair vs singular
for alpha_name, ge_vals in [("AZ", GE_AZ), ("KA", GE_KA)]:
    # Use sum of consecutive pairs as sort key for 97 positions (wrap at 106)
    pair_sums = [(ge_vals[i % 106] + ge_vals[(i+1) % 106]) for i in range(N)]
    ranked_pairs = sorted(range(N), key=lambda j: (pair_sums[j], j))
    try_perm_if_valid(ranked_pairs, f"N16d_pairsum_{alpha_name}")
    count_n16 += 1

# N16e: Absolute difference from median GE value
median_ge_az = sorted(GE_AZ)[len(GE_AZ)//2]
median_ge_ka = sorted(GE_KA)[len(GE_KA)//2]
for median, alpha_name in [(median_ge_az, "AZ"), (median_ge_ka, "KA")]:
    ge_vals = GE_AZ[:97] if alpha_name == "AZ" else GE_KA[:97]
    distances = [abs(ge_vals[i] - median) for i in range(N)]
    ranked_dist = sorted(range(N), key=lambda i: (distances[i], i))
    try_perm_if_valid(ranked_dist, f"N16e_dist_from_median_{alpha_name}")
    count_n16 += 1

print(f"N16 done: {count_n16} perms. Total: {COUNT}")

# ── FINAL SUMMARY ─────────────────────────────────────────────────────────────

print("\n" + "=" * 72)
print("FINAL SUMMARY")
print(f"Total permutations tested: {COUNT}")
print(f"Crib hits: {len(RESULTS)}")
print(f"Best quadgram score: {BEST_SCORE:.2f}")
print("=" * 72)

if RESULTS:
    print("\n🎉 CRIB HITS:")
    for r in RESULTS:
        print(f"  [{r['label']}] ENE@{r['ene']} BC@{r['bc']} score={r['score']:.2f}")
        print(f"  PT: {r['pt']}")
else:
    print("No crib hits found.")

# Save results
os.makedirs("results/blitz_numeric5", exist_ok=True)
out = {
    "total_tested": COUNT,
    "crib_hits": len(RESULTS),
    "best_score": BEST_SCORE,
    "hits": RESULTS,
}
with open("results/blitz_numeric5/results.json", "w") as f:
    json.dump(out, f, indent=2)
print("\nSaved to results/blitz_numeric5/results.json")
