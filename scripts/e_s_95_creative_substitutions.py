#!/usr/bin/env python3
"""E-S-95: Creative Substitution Methods + Width-7 Columnar

Tests less conventional substitution methods combined with width-7 columnar:

Phase 1: Gromark cipher (running key from cumulative PT digits)
  - PT-derived progressive key: each PT letter's position in alphabet
    accumulates to generate the next key value
  - Non-periodic, deterministic from keyword seed

Phase 2: Porta cipher + width-7 columnar
  - Porta uses 13 paired alphabets (self-reciprocal)
  - Period-7 key selects among 13 alphabets
  - Different structure from Vigenère — worth testing

Phase 3: Beaufort with mixed keyword alphabet + width-7 columnar
  - Standard Beaufort but the tabula recta uses a keyword-mixed alphabet
  - Tests KRYPTOS, PALIMPSEST, ABSCISSA, SHADOW, BERLIN, etc.

Phase 4: Quagmire variants with width-7 columnar
  - Quagmire uses mixed alphabets for both CT and PT rows
  - Four types (I-IV) with different mixing patterns

Phase 5: Keyed Caesar per position (simple additive with non-periodic key)
  - Key derived from a formula: key[j] = f(col, row) mod 26
  - Tests modular arithmetic, prime-based, and mixed functions
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

def build_perm(order):
    nr = (N + W - 1) // W
    ns = nr * W - N
    p = []
    for k in range(W):
        c = order[k]
        sz = nr - 1 if c >= W - ns else nr
        for r in range(sz):
            p.append(r * W + c)
    return p

ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]
INTERMEDIATES = [[CT_N[PERMS[oi][j]] for j in range(N)] for oi in range(len(ORDERS))]


def check_cribs(pt):
    return sum(1 for p in CPOS if pt[p] == PT_FULL[p])


print("=" * 70)
print("E-S-95: Creative Substitution Methods + Width-7 Columnar")
print(f"  N={N}, W={W}, orderings={len(ORDERS)}")
print("=" * 70)

t0 = time.time()
results = {}


# ── Phase 1: Gromark cipher ──────────────────────────────────────────
print("\n--- P1: Gromark cipher + w7 columnar ---")

# Gromark: key derives from a numeric seed + running sum of PT digits
# Standard Gromark: key[j] = (seed[j%p] + sum(PT_digit[0..j-1])) mod 10
# But we work mod 26 for alphabetic version:
#   key[j] = (base_key[j%p] + cumulative_sum(PT[0..j-1])) mod 26

p1_best = 0
p1_cfg = None

for oi in range(len(ORDERS)):
    intermed = INTERMEDIATES[oi]

    # Try period-7 base key, Gromark running sum
    for vi in range(2):  # Vig, Beau only
        # For each possible period-7 base key...
        # But 26^7 = 8B is too large. Use cribs to constrain.
        # At crib positions, we know PT[p], so we know the cumulative sum contribution.
        # Work backwards: given cribs, what base key is needed?

        # Actually, Gromark is sequential — cumsum depends on ALL prior PT.
        # We only know PT at positions 21-33 and 63-73.
        # So we can't determine the full cumsum.

        # Instead: test with base key period 1 (single value) and see if
        # the cumsum from guessed PT makes cribs work.
        # This is equivalent to trying all 26 initial keys with sequential decryption.

        for k0 in range(26):
            pt = [0] * N
            cumsum = 0
            for j in range(N):
                key_j = (k0 + cumsum) % 26
                if vi == 0:  # Vig
                    pt[j] = (intermed[j] - key_j) % 26
                else:  # Beau
                    pt[j] = (key_j - intermed[j]) % 26
                cumsum = (cumsum + pt[j]) % 26

            score = check_cribs(pt)
            if score > p1_best:
                p1_best = score
                p1_cfg = (ORDERS[oi], ['Vig','Beau'][vi], k0)
            if score >= 18:
                pt_text = ''.join(AZ[x] for x in pt)
                print(f"  HIT: {score}/24 order={ORDERS[oi]} {['Vig','Beau'][vi]} k0={k0}")
                print(f"      PT: {pt_text}")

    if oi % 1000 == 0 and oi > 0:
        print(f"    {oi}/5040, best={p1_best} ({time.time()-t0:.0f}s)")

print(f"  P1 (Gromark p=1): best={p1_best}/24, cfg={p1_cfg}, {time.time()-t0:.1f}s")

# Also try period-7 Gromark base
p1b_best = 0
for oi in range(len(ORDERS)):
    intermed = INTERMEDIATES[oi]
    for vi in range(2):
        # Extract what the key must be at crib positions (if no cumsum)
        # Then check if adding cumsum makes it period-7
        # This is complex — use brute force on 7 base values

        # Too expensive: 26^7 per ordering. Skip full search.
        # Instead, try keyword-derived base keys
        KEYWORDS_7 = [
            [I2N[c] for c in w[:7].ljust(7, 'A')]
            for w in ['KRYPTOS', 'ABSCISS', 'PALIMPS', 'SHADOWS', 'BERLINS',
                       'CLOCKSS', 'MESSAGE', 'DELIVER', 'PYRAMID', 'PHARAOH']
        ]

        for base_key in KEYWORDS_7:
            pt = [0] * N
            cumsum = 0
            for j in range(N):
                key_j = (base_key[j % 7] + cumsum) % 26
                if vi == 0:
                    pt[j] = (intermed[j] - key_j) % 26
                else:
                    pt[j] = (key_j - intermed[j]) % 26
                cumsum = (cumsum + pt[j]) % 26

            score = check_cribs(pt)
            if score > p1b_best:
                p1b_best = score

print(f"  P1b (Gromark p=7 keywords): best={p1b_best}/24, {time.time()-t0:.1f}s")
results['P1_gromark'] = {'best': max(p1_best, p1b_best)}


# ── Phase 2: Porta cipher + w7 columnar ──────────────────────────────
print("\n--- P2: Porta cipher + w7 columnar ---")

# Porta cipher: 13 alphabets, each swaps pairs of letters
# For key letter K (0-25), use alphabet K//2 (0-12)
# Porta tableau: first half (A-M) maps to second half (N-Z) and vice versa
# P[j] = porta_decrypt(I[j], K[j])

def porta_encrypt(pt_val, key_val):
    """Porta cipher encryption (self-reciprocal for each key value)."""
    k = key_val // 2  # 0-12
    if pt_val < 13:  # A-M
        return (pt_val + k) % 13 + 13
    else:  # N-Z
        return (pt_val - 13 - k) % 13

def porta_decrypt(ct_val, key_val):
    """Same as encrypt (Porta is self-reciprocal)."""
    return porta_encrypt(ct_val, key_val)

p2_best = 0
p2_cfg = None

for oi in range(len(ORDERS)):
    intermed = INTERMEDIATES[oi]

    for key_tuple in product(range(26), repeat=W):
        key = list(key_tuple)

        # Quick check: just test first 3 cribs
        ok = True
        for idx in range(min(3, len(CPOS))):
            p = CPOS[idx]
            decrypted = porta_decrypt(intermed[p], key[p % W])
            if decrypted != PT_FULL[p]:
                ok = False
                break

        if not ok:
            continue

        # Full check
        score = 0
        for p in CPOS:
            decrypted = porta_decrypt(intermed[p], key[p % W])
            if decrypted == PT_FULL[p]:
                score += 1

        if score > p2_best:
            p2_best = score
            p2_cfg = (ORDERS[oi], key)

        if score >= 20:
            pt = [porta_decrypt(intermed[j], key[j % W]) for j in range(N)]
            pt_text = ''.join(AZ[x] for x in pt)
            print(f"  HIT: {score}/24 order={ORDERS[oi]} key={key}")
            print(f"      PT: {pt_text}")

    if oi % 500 == 0 and oi > 0:
        print(f"    {oi}/5040, best={p2_best} ({time.time()-t0:.0f}s)")

    # Porta has 13^7 ≈ 63M keys per ordering — too much for full sweep
    # Use early termination: first 3 cribs filter ~1/13^3 ≈ 1/2197
    # So 63M/2197 ≈ 28.7K full checks per ordering × 5040 orderings

# Actually 26^7 is way too large. Let me use constraint propagation instead.
# At each crib position p, porta_decrypt(I[p], key[p%7]) = PT[p]
# This determines key[p%7] from I[p] and PT[p].
# Since porta has exactly 2 possible key values per (I,PT) pair...

# RESTART P2 with constraint-based approach
print("  Restarting P2 with constraint propagation...")

p2_best = 0
p2_cfg = None
p2_tested = 0

for oi in range(len(ORDERS)):
    intermed = INTERMEDIATES[oi]

    # For each crib position p, determine which key values (mod 7) work
    residue_options = {r: set(range(26)) for r in range(W)}

    for p in CPOS:
        r = p % W
        i_val = intermed[p]
        pt_val = PT_FULL[p]

        # Find key values that decrypt correctly
        valid_keys = set()
        for k in range(26):
            if porta_decrypt(i_val, k) == pt_val:
                valid_keys.add(k)

        residue_options[r] &= valid_keys

    # Count product of remaining options
    product_size = 1
    empty = False
    for r in range(W):
        if len(residue_options[r]) == 0:
            empty = True
            break
        product_size *= len(residue_options[r])

    if empty:
        continue

    p2_tested += 1

    # If small enough, enumerate
    if product_size <= 10000:
        keys_per_residue = [sorted(residue_options[r]) for r in range(W)]

        for key_combo in product(*keys_per_residue):
            key = list(key_combo)
            score = 0
            for p in CPOS:
                if porta_decrypt(intermed[p], key[p % W]) == PT_FULL[p]:
                    score += 1

            if score > p2_best:
                p2_best = score
                p2_cfg = (ORDERS[oi], key)

            if score >= 24:
                pt = [porta_decrypt(intermed[j], key[j % W]) for j in range(N)]
                pt_text = ''.join(AZ[x] for x in pt)
                print(f"  *** PORTA BREAKTHROUGH: {score}/24 order={ORDERS[oi]} key={key}")
                print(f"      PT: {pt_text}")

elapsed = time.time() - t0
print(f"  P2 (Porta+w7): best={p2_best}/24, survivors={p2_tested}/5040, {elapsed:.1f}s")
results['P2_porta'] = {'best': p2_best, 'survivors': p2_tested}


# ── Phase 3: Mixed-alphabet Beaufort/Vig + w7 columnar ───────────────
print("\n--- P3: Keyword-mixed alphabet + period-7 + w7 columnar ---")

def make_mixed_alphabet(keyword):
    """Create a mixed alphabet from a keyword."""
    seen = set()
    alpha = []
    for c in keyword:
        if c not in seen:
            alpha.append(c)
            seen.add(c)
    for c in AZ:
        if c not in seen:
            alpha.append(c)
            seen.add(c)
    return ''.join(alpha)

KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'BERLIN',
            'CLOCK', 'EGYPT', 'PYRAMID', 'PHARAOH', 'SANBORN',
            'SCHEIDT', 'LANGLEY', 'AGENCY', 'CENTRAL', 'INTELLIGENCE',
            'CIPHER', 'SECRET', 'HIDDEN', 'COMPASS', 'FREEDOM',
            'CHARLIE', 'DELIVER', 'MESSAGE', 'BURIED', 'WELTZEITUHR']

p3_best = 0
p3_cfg = None

for kw in KEYWORDS:
    mixed = make_mixed_alphabet(kw)
    m2n = {c: i for i, c in enumerate(mixed)}
    n2m = {i: c for i, c in enumerate(mixed)}

    for oi in range(len(ORDERS)):
        intermed = INTERMEDIATES[oi]

        # For each crib, determine required key under mixed-alphabet Vig/Beau
        for vi in range(2):  # Vig, Beau
            # Determine key values at crib positions
            residue_keys = {}
            consistent = True

            for p in CPOS:
                i_val = intermed[p]  # numeric value in standard alphabet
                pt_val = PT_FULL[p]

                # Convert through mixed alphabet
                # Mixed-alphabet Vig: C_mixed = (P_mixed + K) mod 26
                # where P_mixed is the position of PT letter in mixed alphabet
                # and C_mixed is the position of CT letter in mixed alphabet
                i_mixed = m2n.get(AZ[i_val], i_val)
                pt_mixed = m2n.get(AZ[pt_val], pt_val)

                if vi == 0:  # Vig
                    k = (i_mixed - pt_mixed) % 26
                else:  # Beau
                    k = (i_mixed + pt_mixed) % 26

                r = p % W
                if r in residue_keys:
                    if residue_keys[r] != k:
                        consistent = False
                        break
                else:
                    residue_keys[r] = k

            if consistent:
                score = len([p for p in CPOS if True])  # All cribs match by construction
                # But we need to verify — the period-7 check already ensures consistency
                score = 24

                # Decrypt full text
                pt = [0] * N
                for j in range(N):
                    i_mixed = m2n.get(AZ[intermed[j]], intermed[j])
                    k = residue_keys.get(j % W, 0)
                    if vi == 0:
                        pt_mixed = (i_mixed - k) % 26
                    else:
                        pt_mixed = (k - i_mixed) % 26
                    # Convert back to standard alphabet
                    pt[j] = I2N[mixed[pt_mixed]]

                # Verify cribs
                actual_score = check_cribs(pt)

                if actual_score > p3_best:
                    p3_best = actual_score
                    p3_cfg = (kw, ORDERS[oi], ['Vig','Beau'][vi])
                    if actual_score >= 20:
                        pt_text = ''.join(AZ[x] for x in pt)
                        print(f"  HIT: {actual_score}/24 kw='{kw}' order={ORDERS[oi]} {['Vig','Beau'][vi]}")
                        print(f"      PT: {pt_text[:60]}...")

elapsed = time.time() - t0
print(f"  P3 (mixed-alpha+p7+w7): best={p3_best}/24, {elapsed:.1f}s, cfg={p3_cfg}")
results['P3_mixed_alpha'] = {'best': p3_best, 'cfg': str(p3_cfg)}


# ── Phase 4: Tabula recta shift variants ──────────────────────────────
print("\n--- P4: Progressive Tabula Recta (shifted rows) + w7 columnar ---")

# What if the tabula recta itself is shifted? Instead of standard A-Z cycling,
# each row is shifted by a different amount.
# E.g., row k encrypts as: C = (P + key + shift[k]) mod 26
# where shift[k] is a fixed offset per key value

# This is equivalent to Vigenère with a modified key: key'[j] = key[j] + shift[key[j]] mod 26
# But if shift depends on the key value itself, it's a non-linear transformation.

# Simpler: what if the "coding chart" has shifted rows?
# Standard tabula recta: row k = [k, k+1, ..., k+25] mod 26
# Shifted: row k = [(k+s[k]), (k+s[k]+1), ...] mod 26
# This is equivalent to adding s[key_val] to the ciphertext.

# Test: fixed additive mask per key value
# P = C - key - mask[key] mod 26

# This doubles the DOF: 7 key values + 26 mask values = 33 params
# Too many — would be underdetermined.

# Instead, test a simpler model: key with additive shift based on position parity
# key[j] = base[j%7] + (j//7) * step mod 26  (already tested in E-S-89)

# New idea: key depends on BOTH position and column in a specific way
# key[j] = col_key[j%7] XOR row_key[j//7]
# Using XOR in mod-26 arithmetic: key = (col_key + row_key) mod 26

# This was tested as bilinear in E-S-89. Skip.

# Instead, try MULTIPLICATIVE cipher: C = P * a + b (mod 26), affine per position
# With period-7 key: a[j%7], b[j%7]

p4_best = 0
p4_cfg = None

# Affine cipher: C = a*P + b mod 26, only works if gcd(a, 26) = 1
# Valid 'a' values: 1,3,5,7,9,11,15,17,19,21,23,25
VALID_A = [a for a in range(1, 26) if pow(a, -1, 26) if all(a % p != 0 for p in [2, 13])]
# More carefully:
VALID_A = [a for a in range(1, 26) if a % 2 != 0 and a % 13 != 0]

for oi in range(len(ORDERS)):
    intermed = INTERMEDIATES[oi]

    # For each crib position: C = a[p%7]*P + b[p%7] mod 26
    # So: a[p%7]*PT[p] + b[p%7] = I[p] mod 26
    # Two unknowns per residue. Need ≥2 cribs per residue to determine.

    # Residue 0: positions 21, 28, 63, 70 → 4 equations for 2 unknowns
    # Residue 1: positions 22, 64, 71 → 3 equations
    # Residue 2: positions 23, 30, 65, 72 → 4 equations
    # Residue 3: positions 24, 31, 66, 73 → 4 equations
    # Residue 4: positions 25, 32, 67 → 3 equations
    # Residue 5: positions 26, 33, 68 → 3 equations
    # Residue 6: positions 27, 69 → 2 equations (exactly determined)

    # For each residue with ≥2 equations, solve for (a, b)
    residue_cribs = {r: [] for r in range(W)}
    for p in CPOS:
        residue_cribs[p % W].append((intermed[p], PT_FULL[p]))

    all_ok = True
    affine_params = {}

    for r in range(W):
        eqs = residue_cribs[r]
        if len(eqs) < 2:
            all_ok = False
            break

        # Try all valid 'a' values
        found = False
        for a in VALID_A:
            # From first equation: b = I[0] - a*P[0] mod 26
            b = (eqs[0][0] - a * eqs[0][1]) % 26
            # Check remaining equations
            ok = True
            for i_val, pt_val in eqs[1:]:
                if (a * pt_val + b) % 26 != i_val:
                    ok = False
                    break
            if ok:
                affine_params[r] = (a, b)
                found = True
                break

        if not found:
            all_ok = False
            break

    if all_ok:
        # Decrypt full text
        pt = [0] * N
        for j in range(N):
            a, b = affine_params[j % W]
            # I = a*P + b → P = a_inv * (I - b) mod 26
            a_inv = pow(a, -1, 26)
            pt[j] = (a_inv * (intermed[j] - b)) % 26

        score = check_cribs(pt)
        if score > p4_best:
            p4_best = score
            p4_cfg = (ORDERS[oi], affine_params)

        if score >= 20:
            pt_text = ''.join(AZ[x] for x in pt)
            print(f"  HIT: {score}/24 affine order={ORDERS[oi]}")
            print(f"      PT: {pt_text}")

        if score >= 24:
            pt_text = ''.join(AZ[x] for x in pt)
            print(f"  *** AFFINE BREAKTHROUGH: {score}/24 ***")
            print(f"  Order: {ORDERS[oi]}")
            print(f"  Params: {affine_params}")
            print(f"  PT: {pt_text}")

elapsed = time.time() - t0
print(f"  P4 (Affine period-7 + w7): best={p4_best}/24, {elapsed:.1f}s")
results['P4_affine'] = {'best': p4_best}


# ── Phase 5: Polybius-based + w7 columnar ─────────────────────────────
print("\n--- P5: Polybius fractionation (ADFGVX-like with 26 output) ---")

# ADFGVX produces 6 symbols, not 26. But what about a modified Polybius?
# 1. Use 6×5 grid (30 cells, 26 letters + 4 nulls) or 5×6
# 2. Each letter → (row, col) coordinates
# 3. Interleave/transpose the coordinates
# 4. Read pairs back as letters from the grid

# This is basically Bifid but with a rectangular grid.
# Already tested Bifid 6×6 (eliminated) and 5×5 (impossible).
# Test 5×6 and 6×5 grids.

# Actually, for 26 letters in a non-square grid, the fractionation
# doesn't produce equal-length coordinate sequences. Skip.

print("  P5: Polybius fractionation deferred (structural issues with 26 letters)")
results['P5_polybius'] = {'best': 0, 'note': 'deferred'}


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for phase, data in sorted(results.items()):
    print(f"  {phase}: {data['best']}/24")
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
    'experiment': 'E-S-95',
    'description': 'Creative substitution methods + width-7 columnar',
    'phases': {k: v for k, v in results.items()},
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_95_creative_substitutions.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_95_creative_substitutions.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_95_creative_substitutions.py")
