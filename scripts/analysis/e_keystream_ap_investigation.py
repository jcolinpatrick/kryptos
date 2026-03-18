#!/usr/bin/env python3
"""
Cipher: Beaufort/Vigenere (analytical + exhaustive search)
Family: analysis
Status: active
Keyspace: see individual investigations
Last run: 2026-03-16
Best score: N/A
"""
"""KEYSTREAM AP INVESTIGATION: What cipher mechanism produces step-4 AP?

Model B: Beaufort on raw 97 chars, no transposition.
Known Beaufort keystream at 24 crib positions:
  G(6), K(10), O(14) are the top 3 values, forming AP with step=4.
  12/24 = 50% of all key values come from {6, 10, 14}.

Investigations:
  1. Verify AP pattern and compute exact statistics
  2. Linear key model: key[i] = (a*i + b) mod 26 -- exhaustive over a,b
  3. Quadratic key model: key[i] = (a*i^2 + b*i + c) mod 26 -- exhaustive
  4. Affine over position: key[i] = (a*f(i) + b) mod M -- various f,M
  5. Exhaustive search: key = (a*pos + b) mod M for all a,b,M
  6. KRYPTOS x position interactions (various binary ops)
  7. Two-keyword model: kw1 x kw2 via position
  8. Transposed keyword key: keyword repeated then col-transposed
  9. Col7 on the KEY (not the CT)
"""

import json, sys, os, time, math, itertools
from collections import Counter, defaultdict

# ── Constants ──────────────────────────────────────────────────────────
CT97 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
N2L = {i: c for i, c in enumerate(AZ)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_I2N = {c: i for i, c in enumerate(KA)}
KA_N2L = {i: c for i, c in enumerate(KA)}

ENE_START, ENE_TEXT = 21, "EASTNORTHEAST"
BCL_START, BCL_TEXT = 63, "BERLINCLOCK"

CT_NUMS = [I2N[c] for c in CT97]
CRIB_POSITIONS = list(range(ENE_START, ENE_START + len(ENE_TEXT))) + \
                 list(range(BCL_START, BCL_START + len(BCL_TEXT)))
PT_AT_POS = {}
for i, ch in enumerate(ENE_TEXT):
    PT_AT_POS[ENE_START + i] = I2N[ch]
for i, ch in enumerate(BCL_TEXT):
    PT_AT_POS[BCL_START + i] = I2N[ch]

# Beaufort keystream: K[i] = (CT[i] + PT[i]) mod 26
BEAU_KEY = {pos: (CT_NUMS[pos] + PT_AT_POS[pos]) % 26 for pos in CRIB_POSITIONS}
# Vigenere keystream: K[i] = (CT[i] - PT[i]) mod 26
VIG_KEY  = {pos: (CT_NUMS[pos] - PT_AT_POS[pos]) % 26 for pos in CRIB_POSITIONS}

KEYWORDS = {
    'KRYPTOS': 'KRYPTOS', 'DEFECTOR': 'DEFECTOR', 'ABSCISSA': 'ABSCISSA',
    'PALIMPSEST': 'PALIMPSEST', 'SEVEN': 'SEVEN', 'KOMPASS': 'KOMPASS',
    'COLOPHON': 'COLOPHON', 'PARALLAX': 'PARALLAX', 'BERLIN': 'BERLIN',
    'CLOCK': 'CLOCK', 'BERLINCLOCK': 'BERLINCLOCK', 'ENIGMA': 'ENIGMA',
    'HOROLOGE': 'HOROLOGE', 'SHADOW': 'SHADOW', 'SANBORN': 'SANBORN',
    'MEDUSA': 'MEDUSA', 'EAST': 'EAST', 'NORTH': 'NORTH',
    'FOUR': 'FOUR', 'FIVE': 'FIVE',
}

# Quadgrams
QUADGRAMS = None
try:
    qg_path = "/home/cpatrick/kryptos/data/english_quadgrams.json"
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            QUADGRAMS = json.load(f)
        QG_FLOOR = min(QUADGRAMS.values()) - 1
except Exception:
    pass

def qg_score(text):
    """Per-character quadgram log-probability."""
    if QUADGRAMS is None or len(text) < 4:
        return -99.0
    s = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return s / len(text)

def beau_decrypt(ct_nums, key_nums):
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26"""
    return [(k - c) % 26 for c, k in zip(ct_nums, key_nums)]

def vig_decrypt(ct_nums, key_nums):
    """Vigenere decrypt: PT[i] = (CT[i] - KEY[i]) mod 26"""
    return [(c - k) % 26 for c, k in zip(ct_nums, key_nums)]

def nums_to_text(nums):
    return ''.join(N2L[n] for n in nums)

def count_crib_matches(pt_nums, variant='beau'):
    """Count how many of the 24 crib positions match."""
    matches = 0
    for pos in CRIB_POSITIONS:
        if pos < len(pt_nums) and pt_nums[pos] == PT_AT_POS[pos]:
            matches += 1
    return matches

def columnar_perm(width, col_order, length=97):
    """Columnar transposition: fill rows, read by col order.
    Returns perm where output[i] = input[perm[i]]."""
    cols = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        perm.extend(cols[col_idx])
    return perm

def invert_perm(perm):
    """Invert a permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def keyword_order(kw):
    """Return columnar order from keyword."""
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * len(kw)
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order

results = {}
t0 = time.time()
print("=" * 80)
print("KEYSTREAM AP INVESTIGATION")
print("Model B: Beaufort on raw 97, cribs at original positions")
print("=" * 80)

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 1: Verify AP pattern and exact statistics
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 1: Verify AP pattern, frequency analysis")
print("=" * 70)

beau_vals = [BEAU_KEY[p] for p in sorted(CRIB_POSITIONS)]
vig_vals  = [VIG_KEY[p] for p in sorted(CRIB_POSITIONS)]
beau_letters = ''.join(N2L[v] for v in beau_vals)
vig_letters  = ''.join(N2L[v] for v in vig_vals)

print(f"\nBeaufort keystream: {beau_letters}")
print(f"Values: {beau_vals}")
print(f"\nVigenere keystream: {vig_letters}")
print(f"Values: {vig_vals}")

beau_freq = Counter(beau_vals)
print(f"\nBeaufort value frequencies (sorted by count):")
for val, cnt in beau_freq.most_common():
    print(f"  {N2L[val]}({val:2d}): {cnt}x  ({100*cnt/24:.1f}%)")

ap_values = {6, 10, 14}  # G, K, O
ap_count = sum(1 for v in beau_vals if v in ap_values)
print(f"\nAP values {{G=6, K=10, O=14}}: {ap_count}/24 = {100*ap_count/24:.1f}%")
print(f"Step = 4, start = 6")

# IC of keystream
def ic(vals):
    n = len(vals)
    freq = Counter(vals)
    return sum(f*(f-1) for f in freq.values()) / (n*(n-1)) if n > 1 else 0
beau_ic = ic(beau_vals)
vig_ic = ic(vig_vals)
print(f"\nIC(Beaufort keystream) = {beau_ic:.4f}  (random = {1/26:.4f}, English ~ 0.0667)")
print(f"IC(Vigenere keystream) = {vig_ic:.4f}")

# Where do AP values appear?
print(f"\nAP value positions in Beaufort keystream:")
for target_val in [6, 10, 14]:
    positions = [p for p in sorted(CRIB_POSITIONS) if BEAU_KEY[p] == target_val]
    print(f"  {N2L[target_val]}({target_val}): positions {positions}")

# Non-AP values
non_ap = [(p, BEAU_KEY[p]) for p in sorted(CRIB_POSITIONS) if BEAU_KEY[p] not in ap_values]
print(f"\nNon-AP values ({len(non_ap)}/24):")
for p, v in non_ap:
    print(f"  pos {p:2d}: {N2L[v]}({v:2d})  PT={N2L[PT_AT_POS[p]]}")

results['investigation_1'] = {
    'beaufort_keystream': beau_letters,
    'beaufort_ic': beau_ic,
    'ap_count': ap_count,
    'ap_fraction': ap_count / 24,
}

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 2: Linear key model key[i] = (a*i + b) mod 26
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 2: Linear key model key[i] = (a*i + b) mod 26")
print("=" * 70)

best_linear = []
for a in range(26):
    for b in range(26):
        matches = 0
        for pos in CRIB_POSITIONS:
            predicted = (a * pos + b) % 26
            if predicted == BEAU_KEY[pos]:
                matches += 1
        if matches >= 8:  # Report anything interesting
            best_linear.append((matches, a, b))

best_linear.sort(reverse=True)
print(f"\nTop linear models (matches >= 8 out of 24):")
for matches, a, b in best_linear[:20]:
    predicted_all = [(a * pos + b) % 26 for pos in range(97)]
    pt_nums = beau_decrypt(CT_NUMS, predicted_all)
    pt_text = nums_to_text(pt_nums)
    qg = qg_score(pt_text)
    print(f"  a={a:2d}, b={b:2d}: {matches}/24 matches, qg={qg:.3f}")
    print(f"    key: {''.join(N2L[(a*i+b)%26] for i in range(20))}...")
    print(f"    PT:  {pt_text[:40]}...")

# Also check over different moduli
print(f"\nLinear model over different moduli M:")
best_mod = []
for M in range(2, 40):
    for a in range(M):
        for b in range(M):
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (a * pos + b) % M
                if predicted < 26 and predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 10:
                best_mod.append((matches, a, b, M))

best_mod.sort(reverse=True)
for matches, a, b, M in best_mod[:10]:
    print(f"  a={a:2d}, b={b:2d}, M={M:2d}: {matches}/24 matches")

results['investigation_2'] = {
    'best_linear_26': [(m, a, b) for m, a, b in best_linear[:10]],
    'best_linear_other_mod': [(m, a, b, M) for m, a, b, M in best_mod[:10]],
}

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 3: Quadratic key model key[i] = (a*i^2 + b*i + c) mod 26
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 3: Quadratic key model key[i] = (a*i^2 + b*i + c) mod 26")
print("=" * 70)

best_quad = []
for a in range(26):
    for b in range(26):
        for c in range(26):
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (a * pos * pos + b * pos + c) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 12:
                best_quad.append((matches, a, b, c))

best_quad.sort(reverse=True)
print(f"\nTop quadratic models (matches >= 12 out of 24):")
for matches, a, b, c in best_quad[:20]:
    predicted_all = [(a*i*i + b*i + c) % 26 for i in range(97)]
    pt_nums = beau_decrypt(CT_NUMS, predicted_all)
    pt_text = nums_to_text(pt_nums)
    qg = qg_score(pt_text)
    print(f"  a={a:2d}, b={b:2d}, c={c:2d}: {matches}/24, qg={qg:.3f}")
    if matches >= 14:
        print(f"    PT: {pt_text}")
        print(f"    Key at cribs: {' '.join(f'{N2L[(a*p*p+b*p+c)%26]}' for p in CRIB_POSITIONS)}")
        print(f"    Expected:     {' '.join(N2L[BEAU_KEY[p]] for p in CRIB_POSITIONS)}")
        misses = [p for p in CRIB_POSITIONS if (a*p*p+b*p+c)%26 != BEAU_KEY[p]]
        print(f"    Misses at:    {misses}")

results['investigation_3'] = {
    'best_quadratic': [(m, a, b, c) for m, a, b, c in best_quad[:10]],
    'total_tested': 26**3,
}

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 4: Position-derived key with various functions
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 4: key[i] = (a * f(i) + b) mod 26 for various f")
print("=" * 70)

functions = {
    'pos': lambda i: i,
    'pos_mod_13': lambda i: i % 13,
    'pos_mod_7': lambda i: i % 7,
    'pos_mod_8': lambda i: i % 8,
    'pos//7': lambda i: i // 7,
    'pos//8': lambda i: i // 8,
    'pos//13': lambda i: i // 13,
    'pos_xor_4': lambda i: i ^ 4,
    'pos+pos//7': lambda i: i + i // 7,
    'row*col(w7)': lambda i: (i // 7) * (i % 7),
    'row+col(w7)': lambda i: (i // 7) + (i % 7),
    'row-col(w7)': lambda i: (i // 7) - (i % 7),
    'row*col(w8)': lambda i: (i // 8) * (i % 8),
    'row+col(w8)': lambda i: (i // 8) + (i % 8),
    'row*col(w14)': lambda i: (i // 14) * (i % 14),
    'row+col(w14)': lambda i: (i // 14) + (i % 14),
    'row*col(w31)': lambda i: (i // 31) * (i % 31),
    'row+col(w31)': lambda i: (i // 31) + (i % 31),
    'triangular': lambda i: i * (i + 1) // 2,
    'fibonacci': None,  # Special case
    'digit_sum': lambda i: sum(int(d) for d in str(i)),
    'popcount': lambda i: bin(i).count('1'),
}

# Fibonacci sequence mod 26
fib = [0, 1]
for _ in range(100):
    fib.append(fib[-1] + fib[-2])
functions['fibonacci'] = lambda i, _fib=fib: _fib[i] if i < len(_fib) else 0

print(f"\nBest results per function (a, b scanned 0-25):")
for fname, f in functions.items():
    if f is None:
        continue
    best_m = 0
    best_params = None
    for a in range(26):
        for b in range(26):
            matches = 0
            for pos in CRIB_POSITIONS:
                try:
                    predicted = (a * f(pos) + b) % 26
                except:
                    predicted = -1
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches > best_m:
                best_m = matches
                best_params = (a, b)
    if best_m >= 7:
        a, b = best_params
        print(f"  f={fname:20s}: {best_m}/24 (a={a}, b={b})")

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 5: Exhaustive key = (a*pos + b) mod M for all a,b,M
# (Already done in inv 2 -- extend to multiplicative/combined)
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 5: Multiplicative/power key models")
print("=" * 70)

# key[i] = a * pos^e mod 26 for various e
print("\nMultiplicative: key[i] = (a * pos^e + b) mod 26")
best_power = []
for e in range(1, 6):
    for a in range(26):
        for b in range(26):
            matches = 0
            for pos in CRIB_POSITIONS:
                predicted = (a * pow(pos, e) + b) % 26
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 10:
                best_power.append((matches, a, b, e))

best_power.sort(reverse=True)
for matches, a, b, e in best_power[:10]:
    print(f"  a={a:2d}, b={b:2d}, e={e}: {matches}/24")

# key[i] = a^pos mod M
print("\nExponential: key[i] = (a^pos + b) mod 26")
best_exp = []
for a in range(2, 26):
    for b in range(26):
        matches = 0
        for pos in CRIB_POSITIONS:
            predicted = (pow(a, pos, 26*97) + b) % 26  # avoid overflow
            if predicted == BEAU_KEY[pos]:
                matches += 1
        if matches >= 8:
            best_exp.append((matches, a, b))

best_exp.sort(reverse=True)
for matches, a, b in best_exp[:10]:
    print(f"  base={a:2d}, offset={b:2d}: {matches}/24")

results['investigation_5'] = {
    'best_power': [(m, a, b, e) for m, a, b, e in best_power[:10]],
    'best_exponential': [(m, a, b) for m, a, b in best_exp[:10]],
}

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 6: KRYPTOS x position interactions
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 6: Keyword x position interactions")
print("=" * 70)

operations = {
    'add': lambda a, b: (a + b) % 26,
    'sub': lambda a, b: (a - b) % 26,
    'rsub': lambda a, b: (b - a) % 26,
    'xor': lambda a, b: a ^ b,
    'mul': lambda a, b: (a * b) % 26,
    'add_shift4': lambda a, b: (a + 4*b) % 26,
    'shift4_add': lambda a, b: (4*a + b) % 26,
}

alphabets = {'AZ': I2N, 'KA': KA_I2N}

print(f"\nkw_letter OP position_val, with keyword repeated to fill 97 positions")
best_kw_pos = []
for kw_name, kw_text in KEYWORDS.items():
    for alpha_name, alpha in alphabets.items():
        kw_nums = [alpha[c] for c in kw_text]
        for op_name, op_fn in operations.items():
            matches = 0
            for pos in CRIB_POSITIONS:
                kw_val = kw_nums[pos % len(kw_nums)]
                try:
                    predicted = op_fn(kw_val, pos) % 26
                except:
                    predicted = -1
                if predicted == BEAU_KEY[pos]:
                    matches += 1
            if matches >= 8:
                best_kw_pos.append((matches, kw_name, alpha_name, op_name))

best_kw_pos.sort(reverse=True)
print(f"\nTop keyword x position combinations (>= 8 matches):")
for matches, kw, alpha, op in best_kw_pos[:20]:
    print(f"  {kw:15s}:{alpha}  op={op:12s}  {matches}/24")

# Extended: kw_letter OP (a*pos + b) for small a,b
print(f"\nExtended: kw[i%L] + a*pos + b mod 26, a=0..5, b=0..25")
best_kw_ext = []
for kw_name, kw_text in [('KRYPTOS', 'KRYPTOS'), ('DEFECTOR', 'DEFECTOR'),
                           ('SEVEN', 'SEVEN'), ('KOMPASS', 'KOMPASS'),
                           ('ABSCISSA', 'ABSCISSA')]:
    for alpha_name, alpha in alphabets.items():
        kw_nums = [alpha[c] for c in kw_text]
        for a_coeff in range(6):
            for b_off in range(26):
                matches = 0
                for pos in CRIB_POSITIONS:
                    kw_val = kw_nums[pos % len(kw_nums)]
                    predicted = (kw_val + a_coeff * pos + b_off) % 26
                    if predicted == BEAU_KEY[pos]:
                        matches += 1
                if matches >= 10:
                    best_kw_ext.append((matches, kw_name, alpha_name, a_coeff, b_off))

best_kw_ext.sort(reverse=True)
print(f"\nTop extended keyword + affine position (>= 10 matches):")
for matches, kw, alpha, a, b in best_kw_ext[:15]:
    print(f"  {kw:12s}:{alpha}  a={a} b={b:2d}  {matches}/24")

results['investigation_6'] = {
    'best_kw_pos': [(m, kw, a, op) for m, kw, a, op in best_kw_pos[:10]],
    'best_kw_ext': [(m, kw, a, ac, bo) for m, kw, a, ac, bo in best_kw_ext[:10]],
}

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 7: Two-keyword model
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 7: Two-keyword model kw1[i%L1] OP kw2[i%L2]")
print("=" * 70)

two_kw_ops = {
    'add': lambda a, b: (a + b) % 26,
    'sub': lambda a, b: (a - b) % 26,
    'rsub': lambda a, b: (b - a) % 26,
    'xor': lambda a, b: a ^ b,
    'mul': lambda a, b: (a * b) % 26,
}

kw_pairs = list(itertools.combinations(KEYWORDS.keys(), 2))
# Also try same keyword with different alphabets
same_kw_pairs = [(kw, kw) for kw in KEYWORDS.keys()]
all_pairs = kw_pairs + same_kw_pairs

best_two_kw = []
for kw1_name, kw2_name in all_pairs:
    kw1_text = KEYWORDS[kw1_name]
    kw2_text = KEYWORDS[kw2_name]
    for a1, alpha1 in alphabets.items():
        for a2, alpha2 in alphabets.items():
            if kw1_name == kw2_name and a1 == a2:
                continue  # Same keyword, same alphabet = periodic (already tested)
            kw1_nums = [alpha1[c] for c in kw1_text]
            kw2_nums = [alpha2[c] for c in kw2_text]
            for op_name, op_fn in two_kw_ops.items():
                matches = 0
                for pos in CRIB_POSITIONS:
                    v1 = kw1_nums[pos % len(kw1_nums)]
                    v2 = kw2_nums[pos % len(kw2_nums)]
                    try:
                        predicted = op_fn(v1, v2) % 26
                    except:
                        predicted = -1
                    if predicted == BEAU_KEY[pos]:
                        matches += 1
                if matches >= 10:
                    best_two_kw.append((matches, kw1_name, a1, kw2_name, a2, op_name))

best_two_kw.sort(reverse=True)
print(f"\nTop two-keyword combinations (>= 10 matches):")
for matches, kw1, a1, kw2, a2, op in best_two_kw[:20]:
    print(f"  {kw1:12s}:{a1} {op:5s} {kw2:12s}:{a2}  {matches}/24")
    if matches >= 14:
        kw1_nums = [alphabets[a1][c] for c in KEYWORDS[kw1]]
        kw2_nums = [alphabets[a2][c] for c in KEYWORDS[kw2]]
        op_fn = two_kw_ops[op]
        full_key = [op_fn(kw1_nums[i % len(kw1_nums)], kw2_nums[i % len(kw2_nums)]) % 26 for i in range(97)]
        pt_nums = beau_decrypt(CT_NUMS, full_key)
        pt_text = nums_to_text(pt_nums)
        qg = qg_score(pt_text)
        print(f"    PT: {pt_text}")
        print(f"    QG: {qg:.3f}")

results['investigation_7'] = {
    'best_two_kw': [(m, kw1, a1, kw2, a2, op) for m, kw1, a1, kw2, a2, op in best_two_kw[:10]],
}

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 8: Transposed keyword key
# Repeat keyword to 97 chars, then apply columnar transposition
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 8: Keyword repeated then col-transposed as key")
print("=" * 70)

widths = [5, 6, 7, 8, 9, 10, 11, 13, 14, 31]

best_transposed_key = []
for kw_name, kw_text in KEYWORDS.items():
    for alpha_name, alpha in alphabets.items():
        kw_nums = [alpha[c] for c in kw_text]
        # Repeat to 97
        repeated_key = [kw_nums[i % len(kw_nums)] for i in range(97)]

        for width in widths:
            # Try all permutations for small widths, keyword orders for larger
            if width <= 7:
                orders = list(itertools.permutations(range(width)))
            else:
                # Use keyword-derived orders for this width
                orders = []
                for trans_kw_name, trans_kw_text in KEYWORDS.items():
                    if len(trans_kw_text) == width:
                        orders.append(tuple(keyword_order(trans_kw_text)))
                    # Also try truncated/padded
                    if len(trans_kw_text) >= width:
                        orders.append(tuple(keyword_order(trans_kw_text[:width])))
                # Natural order
                orders.append(tuple(range(width)))
                orders.append(tuple(reversed(range(width))))
                orders = list(set(orders))

            for col_order in orders:
                perm = columnar_perm(width, col_order, 97)
                transposed_key = [repeated_key[perm[i]] for i in range(97)]

                # Count crib matches for Beaufort
                matches = 0
                for pos in CRIB_POSITIONS:
                    if transposed_key[pos] == BEAU_KEY[pos]:
                        matches += 1
                if matches >= 10:
                    best_transposed_key.append((matches, kw_name, alpha_name, width, col_order, 'beau'))

                # Also Vigenere
                matches_v = 0
                for pos in CRIB_POSITIONS:
                    if transposed_key[pos] == VIG_KEY[pos]:
                        matches_v += 1
                if matches_v >= 10:
                    best_transposed_key.append((matches_v, kw_name, alpha_name, width, col_order, 'vig'))

best_transposed_key.sort(reverse=True)
print(f"\nTop transposed-keyword-as-key results (>= 10 matches):")
for matches, kw, alpha, w, co, variant in best_transposed_key[:20]:
    print(f"  {kw:12s}:{alpha} w={w} order={co[:8]}{'...' if len(co)>8 else ''} {variant}: {matches}/24")
    if matches >= 14:
        kw_nums = [alphabets[alpha][c] for c in KEYWORDS[kw]]
        repeated = [kw_nums[i % len(kw_nums)] for i in range(97)]
        perm = columnar_perm(w, co, 97)
        transposed = [repeated[perm[i]] for i in range(97)]
        if variant == 'beau':
            pt_nums = beau_decrypt(CT_NUMS, transposed)
        else:
            pt_nums = vig_decrypt(CT_NUMS, transposed)
        pt_text = nums_to_text(pt_nums)
        qg = qg_score(pt_text)
        print(f"    PT: {pt_text}")
        print(f"    QG: {qg:.3f}")
        # Show key at crib positions
        crib_key = [(p, transposed[p], BEAU_KEY[p]) for p in CRIB_POSITIONS]
        miss_pos = [p for p, got, want in crib_key if got != want]
        print(f"    Misses at: {miss_pos}")

results['investigation_8'] = {
    'best_transposed_key': [(m, kw, a, w, str(co), v) for m, kw, a, w, co, v in best_transposed_key[:10]],
}

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 9: Col7 on the KEY (not the CT)
# Model: PT[i] = Beaufort_decrypt(CT[i], transposed_key[i])
# where transposed_key = col7_perm applied to periodic keyword
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 9: Col7 on the KEY (transposition applied to key, not CT)")
print("=" * 70)

# Standard col7 with natural and DEFECTOR orders
defector_order = keyword_order('DEFECTOR')  # 8-letter keyword for col7? No, DEFECTOR is 8 chars
print(f"  DEFECTOR order (8 cols): {defector_order}")

# Actually, col7 means width 7. Let me also try width 8 (DEFECTOR length)
for width in [7, 8]:
    print(f"\n  Width {width}:")

    if width <= 8:
        # For width 7, try all 5040 permutations
        # For width 8, use keyword orders
        if width == 7:
            all_orders = list(itertools.permutations(range(7)))
        else:
            all_orders = []
            for trans_kw in KEYWORDS.values():
                if len(trans_kw) == width:
                    all_orders.append(tuple(keyword_order(trans_kw)))
                if len(trans_kw) > width:
                    all_orders.append(tuple(keyword_order(trans_kw[:width])))
            all_orders.append(tuple(range(width)))
            all_orders.append(tuple(reversed(range(width))))
            all_orders = list(set(all_orders))

    best_col_key = []
    for kw_name, kw_text in KEYWORDS.items():
        for alpha_name, alpha in alphabets.items():
            kw_nums = [alpha[c] for c in kw_text]
            repeated = [kw_nums[i % len(kw_nums)] for i in range(97)]

            for col_order in all_orders:
                perm = columnar_perm(width, col_order, 97)
                # Apply perm to get transposed key
                transposed_key = [repeated[perm[i]] for i in range(97)]

                matches = sum(1 for pos in CRIB_POSITIONS if transposed_key[pos] == BEAU_KEY[pos])
                if matches >= 12:
                    best_col_key.append((matches, kw_name, alpha_name, width, col_order))

                # Also try inverse perm on key
                inv_perm = invert_perm(perm)
                inv_transposed_key = [repeated[inv_perm[i]] for i in range(97)]
                matches_inv = sum(1 for pos in CRIB_POSITIONS if inv_transposed_key[pos] == BEAU_KEY[pos])
                if matches_inv >= 12:
                    best_col_key.append((matches_inv, kw_name, alpha_name, width, tuple([-x for x in col_order])))

    best_col_key.sort(reverse=True)
    for matches, kw, alpha, w, co in best_col_key[:10]:
        print(f"    {kw:12s}:{alpha} order={co}: {matches}/24")
        if matches >= 14:
            kw_nums = [alphabets[alpha][c] for c in KEYWORDS[kw]]
            repeated = [kw_nums[i % len(kw_nums)] for i in range(97)]
            perm = columnar_perm(w, co, 97)
            transposed = [repeated[perm[i]] for i in range(97)]
            pt_nums = beau_decrypt(CT_NUMS, transposed)
            pt_text = nums_to_text(pt_nums)
            qg = qg_score(pt_text)
            print(f"      PT: {pt_text}")
            print(f"      QG: {qg:.3f}")

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 10 (bonus): Does the AP step=4 relate to K4 = "4th section"?
# Test: key[i] = plaintext_autokey_beaufort with step-4 sampling
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 10: Step-4 autokey / decimation models")
print("=" * 70)

# What if key at position i is derived from PT at position (i-4)?
# This would create an autokey with lag 4, which could produce AP-like patterns
# if PT has structure
print(f"\nAutokey with lag k: key[i] = (primer[i%L] + PT[i-k]) mod 26")
print(f"For lag=4, positions 21-33 have PT[17..29] as feedback")
print(f"Since we don't know PT[17..20], test with known PT only.")

# More precisely: under Beaufort autokey, CT[i] = (key[i] + PT[i]) mod 26
# key[i] = primer[i%L] for i < L
# key[i] = PT[i-L] for i >= L (PT-autokey)
# or key[i] = CT[i-L] for i >= L (CT-autokey)
# Test: does CT-autokey with lag 4 produce the observed keystream?
print(f"\nCT-autokey lag 4: key[i] = CT[i-4] for i >= 4, Beaufort")
ct_auto4_matches = 0
for pos in CRIB_POSITIONS:
    if pos >= 4:
        auto_key = CT_NUMS[pos - 4]
        if auto_key == BEAU_KEY[pos]:
            ct_auto4_matches += 1
print(f"  CT-autokey lag 4: {ct_auto4_matches}/24 matches")

# Try all lags 1-96
print(f"\nCT-autokey all lags (Beaufort):")
for lag in range(1, 97):
    matches = 0
    for pos in CRIB_POSITIONS:
        if pos >= lag:
            if CT_NUMS[pos - lag] == BEAU_KEY[pos]:
                matches += 1
    if matches >= 6:
        print(f"  lag={lag:2d}: {matches}/24")

# key[i] = CT[4*i mod 97]? (decimation by 4)
print(f"\nDecimation: key[i] = CT[(k*i + offset) mod 97]")
best_dec = []
for k in range(1, 97):
    for offset in range(97):
        matches = 0
        for pos in CRIB_POSITIONS:
            dec_pos = (k * pos + offset) % 97
            if CT_NUMS[dec_pos] == BEAU_KEY[pos]:
                matches += 1
        if matches >= 8:
            best_dec.append((matches, k, offset))

best_dec.sort(reverse=True)
print(f"\nTop decimation models (>= 8 matches):")
for matches, k, offset in best_dec[:10]:
    print(f"  k={k:2d}, offset={offset:2d}: {matches}/24")
    if matches >= 12:
        full_key = [CT_NUMS[(k * i + offset) % 97] for i in range(97)]
        pt_nums = beau_decrypt(CT_NUMS, full_key)
        pt_text = nums_to_text(pt_nums)
        print(f"    PT: {pt_text}")

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 11 (bonus): Same-PT-letter clustering deeper analysis
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 11: Same-PT-letter key relationship")
print("=" * 70)

# Group positions by plaintext letter
pt_groups = defaultdict(list)
for pos in sorted(CRIB_POSITIONS):
    pt_letter = N2L[PT_AT_POS[pos]]
    pt_groups[pt_letter].append(pos)

print(f"\nPositions grouped by plaintext letter:")
for letter in sorted(pt_groups.keys()):
    positions = pt_groups[letter]
    if len(positions) >= 2:
        keys = [BEAU_KEY[p] for p in positions]
        diffs = [keys[i+1] - keys[i] for i in range(len(keys)-1)]
        print(f"  PT='{letter}': pos={positions}  keys={[N2L[k] for k in keys]}({keys})  diffs={diffs}")

# What if key[i] = f(PT[i]) for some function?
# This would mean the cipher is a simple substitution!
print(f"\nIs key a function of PT letter? (monoalphabetic key)")
pt_to_keys = defaultdict(set)
for pos in CRIB_POSITIONS:
    pt_val = PT_AT_POS[pos]
    pt_to_keys[pt_val].add(BEAU_KEY[pos])

consistent = True
for pt_val, key_set in pt_to_keys.items():
    if len(key_set) > 1:
        consistent = False
print(f"  Key = f(PT): {'CONSISTENT' if consistent else 'INCONSISTENT'}")
if not consistent:
    print(f"  Conflicting PT letters:")
    for pt_val, key_set in sorted(pt_to_keys.items()):
        if len(key_set) > 1:
            print(f"    PT={N2L[pt_val]}({pt_val}): keys={sorted(key_set)} = {[N2L[k] for k in sorted(key_set)]}")

# What if key[i] = f(CT[i])?
print(f"\nIs key a function of CT letter? (key depends on ciphertext)")
ct_to_keys = defaultdict(set)
for pos in CRIB_POSITIONS:
    ct_val = CT_NUMS[pos]
    ct_to_keys[ct_val].add(BEAU_KEY[pos])

consistent_ct = True
for ct_val, key_set in ct_to_keys.items():
    if len(key_set) > 1:
        consistent_ct = False
print(f"  Key = f(CT): {'CONSISTENT' if consistent_ct else 'INCONSISTENT'}")
if not consistent_ct:
    print(f"  Conflicting CT letters:")
    for ct_val, key_set in sorted(ct_to_keys.items()):
        if len(key_set) > 1:
            print(f"    CT={N2L[ct_val]}({ct_val}): keys={sorted(key_set)} = {[N2L[k] for k in sorted(key_set)]}")

# What if key[i] = f(PT[i], pos mod something)?
# This is a polyalphabetic system dependent on PT
print(f"\nKey = f(PT, pos mod p)? Testing periods 2-13")
for period in range(2, 14):
    consistent = True
    pt_res_to_keys = defaultdict(set)
    for pos in CRIB_POSITIONS:
        pt_val = PT_AT_POS[pos]
        res = pos % period
        pt_res_to_keys[(pt_val, res)].add(BEAU_KEY[pos])
    for (pt_val, res), key_set in pt_res_to_keys.items():
        if len(key_set) > 1:
            consistent = False
            break
    if consistent:
        print(f"  Period {period}: CONSISTENT (key = f(PT, pos mod {period}))")

# ═══════════════════════════════════════════════════════════════════════
# INVESTIGATION 12 (bonus): Exhaustive 2-letter primer Beaufort CT-autokey
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("INVESTIGATION 12: Short-primer autokey Beaufort on raw 97")
print("=" * 70)

# PT-autokey Beaufort: key[i] = primer[i] for i < L, then key[i] = PT[i-L]
# CT[i] = (key[i] + PT[i]) mod 26 → PT[i] = (key[i] - CT[i]) mod 26

for primer_len in [1, 2, 3, 4]:
    best_auto = []
    total = 26 ** primer_len
    for primer_val in range(total):
        # Decode primer
        primer = []
        v = primer_val
        for _ in range(primer_len):
            primer.append(v % 26)
            v //= 26

        # Decrypt with PT-autokey Beaufort
        pt = []
        for i in range(97):
            if i < primer_len:
                k = primer[i]
            else:
                k = pt[i - primer_len]
            pt_val = (k - CT_NUMS[i]) % 26
            pt.append(pt_val)

        # Count crib matches
        matches = sum(1 for pos in CRIB_POSITIONS if pt[pos] == PT_AT_POS[pos])
        if matches >= 8:
            pt_text = nums_to_text(pt)
            best_auto.append((matches, primer, pt_text))

    best_auto.sort(reverse=True)
    if best_auto:
        print(f"\n  Primer length {primer_len} ({total} tested):")
        for matches, primer, pt_text in best_auto[:5]:
            primer_text = ''.join(N2L[p] for p in primer)
            qg = qg_score(pt_text)
            print(f"    primer={primer_text}: {matches}/24, qg={qg:.3f}")
            if matches >= 10:
                print(f"      PT: {pt_text}")
    else:
        print(f"\n  Primer length {primer_len} ({total} tested): NONE >= 8 matches")

    # Also CT-autokey: key[i] = CT[i-L] for i >= L
    best_ct_auto = []
    for primer_val in range(total):
        primer = []
        v = primer_val
        for _ in range(primer_len):
            primer.append(v % 26)
            v //= 26

        pt = []
        for i in range(97):
            if i < primer_len:
                k = primer[i]
            else:
                k = CT_NUMS[i - primer_len]
            pt_val = (k - CT_NUMS[i]) % 26
            pt.append(pt_val)

        matches = sum(1 for pos in CRIB_POSITIONS if pt[pos] == PT_AT_POS[pos])
        if matches >= 8:
            pt_text = nums_to_text(pt)
            best_ct_auto.append((matches, primer, pt_text))

    best_ct_auto.sort(reverse=True)
    if best_ct_auto:
        print(f"  CT-autokey primer length {primer_len}:")
        for matches, primer, pt_text in best_ct_auto[:5]:
            primer_text = ''.join(N2L[p] for p in primer)
            qg = qg_score(pt_text)
            print(f"    primer={primer_text}: {matches}/24, qg={qg:.3f}")
            if matches >= 10:
                print(f"      PT: {pt_text}")
    else:
        print(f"  CT-autokey primer length {primer_len}: NONE >= 8 matches")

# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════
elapsed = time.time() - t0
print("\n" + "=" * 70)
print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
print("=" * 70)

print(f"\nInvestigation 1: AP pattern confirmed. G(6):4x, K(10):5x, O(14):3x = 12/24 = 50%")
print(f"  Beaufort IC = {beau_ic:.4f} (2.07x random)")

if best_linear:
    m, a, b = best_linear[0]
    print(f"\nInvestigation 2: Best linear key[i]=(a*i+b)%26: {m}/24 (a={a}, b={b})")
else:
    print(f"\nInvestigation 2: No linear model >= 8/24")

if best_quad:
    m, a, b, c = best_quad[0]
    print(f"\nInvestigation 3: Best quadratic: {m}/24 (a={a}, b={b}, c={c})")
else:
    print(f"\nInvestigation 3: No quadratic model >= 12/24")

if best_power:
    m, a, b, e = best_power[0]
    print(f"\nInvestigation 5: Best power model: {m}/24 (a={a}, b={b}, e={e})")

if best_kw_pos:
    m, kw, alpha, op = best_kw_pos[0]
    print(f"\nInvestigation 6: Best kw x pos: {m}/24 ({kw}:{alpha} op={op})")

if best_two_kw:
    m, kw1, a1, kw2, a2, op = best_two_kw[0]
    print(f"\nInvestigation 7: Best two-keyword: {m}/24 ({kw1}:{a1} {op} {kw2}:{a2})")

if best_transposed_key:
    m, kw, alpha, w, co, v = best_transposed_key[0]
    print(f"\nInvestigation 8: Best transposed key: {m}/24 ({kw}:{alpha} w={w} {v})")

# Save results
results['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
results['elapsed_seconds'] = elapsed
results['experiment'] = 'KEYSTREAM-AP-INVESTIGATION'

out_path = '/home/cpatrick/kryptos/results/keystream_ap_investigation.json'
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nResults saved to: {out_path}")
