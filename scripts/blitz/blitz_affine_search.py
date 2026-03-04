#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_affine_search.py — Exhaustive Affine & Power Permutation Search for K4

Model 2: PT → Cipher(key) → real_CT → SCRAMBLE(σ) → carved_K4
         real_CT[j] = K4[σ(j)]

KEY INSIGHT: 97 is prime! This makes Z_97 a field, enabling elegant math.

NEW APPROACHES (not in existing wildcard):

1. FULL AFFINE PERMUTATIONS: σ(j) = (a·j + b) mod 97
   - a=1..96, b=0..96 → 9,312 valid permutations
   - Previous wildcard only tested b=0 (96 permutations = strides)
   - Crib constraints INSTANTLY filter to valid (a,b) pairs

2. POWER PERMUTATIONS: σ(j) = (j+b)^k mod 97
   - k coprime to 96 (=2^5×3) → 32 values of k where gcd(k,96)=1
   - b=0..96 → 32×97=3,104 valid permutations
   - x^k is a bijection on Z_97* when gcd(k,96)=1

3. MULTIPLICATIVE POWER: σ(j) = a·(j+b)^k mod 97
   - Combines affine and power for selected (a,k,b) triples

4. INVERSE PERMUTATIONS: For any found perm, try its inverse too

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_affine_search.py
"""

import sys, json, math, os, time
from collections import Counter

sys.path.insert(0, 'src')

# ── Constants ────────────────────────────────────────────────────────────────
K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(K4)
assert N == 97, f"K4 len {N}"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'SANBORN', 'SCHEIDT',
    'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'LIGHT', 'ANTIPODES', 'MEDUSA',
    'ENIGMA', 'COMPASS', 'WELTZEITUHR', 'IQLUSION', 'ILLUSION',
    'DIGETAL', 'FLANKMAN', 'VIRTUALLY', 'FORCES', 'INVISIBLE',
    'UNDERGRUUND', 'EMUFPH', 'SECRET',  # extra candidates
]
KEYWORDS = list(dict.fromkeys(KEYWORDS))  # deduplicate

# Canonical crib positions in PLAINTEXT (0-indexed)
# PT[21:34] = EASTNORTHEAST (13 chars)
# PT[63:74] = BERLINCLOCK   (11 chars)
CRIB_ENE_POS = list(range(21, 34))   # [21..33]
CRIB_BC_POS  = list(range(63, 74))   # [63..73]
CRIB_ENE_TXT = "EASTNORTHEAST"
CRIB_BC_TXT  = "BERLINCLOCK"

CRIB_POSITIONS = []
for p, t in [(21, CRIB_ENE_TXT), (63, CRIB_BC_TXT)]:
    for j, c in enumerate(t):
        CRIB_POSITIONS.append((p + j, c))  # (pt_pos, pt_char)

print(f"Loaded {len(CRIB_POSITIONS)} crib positions", flush=True)

# ── Quadgrams ─────────────────────────────────────────────────────────────────
QG_FILE = 'data/english_quadgrams.json'
if os.path.exists(QG_FILE):
    QG = json.load(open(QG_FILE))
    MISS = min(QG.values()) - 2.0
    print(f"Loaded {len(QG)} quadgrams, MISS={MISS:.2f}", flush=True)
else:
    QG = {}
    MISS = -12.0
    print("WARNING: no quadgrams file found", flush=True)

def qscore(text):
    if len(text) < 4:
        return MISS
    if not QG:
        return 0.0
    return sum(QG.get(text[i:i+4], MISS) for i in range(len(text)-3)) / max(1, len(text)-3)

# ── Alphabet utilities ────────────────────────────────────────────────────────
AZI = {c: i for i, c in enumerate(AZ)}
KAI = {c: i for i, c in enumerate(KA)}

def vig_dec(ct, key, alpha=AZ, ai=None):
    if ai is None: ai = {c: i for i, c in enumerate(alpha)}
    n = len(alpha)
    ki = [ai.get(c, 0) for c in key]
    return ''.join(alpha[(ai.get(ct[i], 0) - ki[i % len(ki)]) % n] for i in range(len(ct)))

def beau_dec(ct, key, alpha=AZ, ai=None):
    if ai is None: ai = {c: i for i, c in enumerate(alpha)}
    n = len(alpha)
    ki = [ai.get(c, 0) for c in key]
    return ''.join(alpha[(ki[i % len(ki)] - ai.get(ct[i], 0)) % n] for i in range(len(ct)))

CIPHER_FNS = [
    ("vig_AZ",  lambda ct, kw: vig_dec(ct, kw, AZ, AZI)),
    ("beau_AZ", lambda ct, kw: beau_dec(ct, kw, AZ, AZI)),
    ("vig_KA",  lambda ct, kw: vig_dec(ct, kw, KA, KAI)),
    ("beau_KA", lambda ct, kw: beau_dec(ct, kw, KA, KAI)),
]

# ── Output ────────────────────────────────────────────────────────────────────
os.makedirs('blitz_results/wildcard', exist_ok=True)
OUT = open('blitz_results/wildcard/affine_search_results.jsonl', 'w')
HITS = []
total_perms_tested = 0

def emit(d):
    OUT.write(json.dumps(d) + '\n')
    OUT.flush()

def check_and_score(sigma, label):
    """Apply sigma permutation, test all keyword/cipher combos, return best."""
    global total_perms_tested
    total_perms_tested += 1
    ct = ''.join(K4[sigma[j]] for j in range(97))
    best_sc = MISS - 1
    best_d = None
    for kw in KEYWORDS:
        for cname, cfn in CIPHER_FNS:
            pt = cfn(ct, kw)
            ene_pos = pt.find(CRIB_ENE_TXT)
            bc_pos  = pt.find(CRIB_BC_TXT)
            ene_ok  = (pt[21:34] == CRIB_ENE_TXT)
            bc_ok   = (pt[63:74] == CRIB_BC_TXT)
            sc = qscore(pt)
            if ene_pos >= 0 or bc_pos >= 0:
                msg = (f"\n*** CRIB HIT [{label}] key={kw} {cname}\n"
                       f"    ENE@{ene_pos}(want@21={ene_ok}) BC@{bc_pos}(want@63={bc_ok})\n"
                       f"    CT:  {ct}\n"
                       f"    PT:  {pt}\n"
                       f"    σ[:10]={list(sigma[:10])}\n"
                       f"    score={sc:.4f}")
                print(msg, flush=True)
                d = {'label': label, 'ct': ct, 'key': kw, 'cipher': cname,
                     'ene': ene_pos, 'bc': bc_pos, 'ene_ok': ene_ok, 'bc_ok': bc_ok,
                     'pt': pt, 'score': sc, 'sigma': list(sigma)}
                HITS.append(d)
                emit(d)
                return d
            if sc > best_sc:
                best_sc = sc
                best_d = {'label': label, 'ct': ct, 'key': kw, 'cipher': cname,
                          'ene': -1, 'bc': -1, 'pt': pt, 'score': sc}
    if best_d and best_d['score'] > -6.5:
        emit(best_d)
    return best_d

# ── Core: compute expected real_CT at crib positions ─────────────────────────
def compute_expected_ct(keyword, cipher_type, alpha, ai):
    """For each crib position, what must real_CT[j] be?"""
    n = len(alpha)
    ki = [ai.get(c, 0) for c in keyword]
    expected = {}  # pt_pos → expected real_CT character
    for pt_pos, pt_char in CRIB_POSITIONS:
        ki_val = ki[pt_pos % len(keyword)]
        pi_val = ai.get(pt_char, 0)
        if cipher_type == 'vig':
            expected[pt_pos] = alpha[(pi_val + ki_val) % n]
        else:  # beau
            expected[pt_pos] = alpha[(ki_val - pi_val) % n]
    return expected  # {pt_pos: char_that_must_appear_in_K4_at_sigma(pt_pos)}

# Precompute K4 character → positions lookup
K4_CHAR_POSITIONS = {}
for i, c in enumerate(K4):
    K4_CHAR_POSITIONS.setdefault(c, []).append(i)

# ─────────────────────────────────────────────────────────────────────────────
# PART 1: FULL AFFINE PERMUTATION SEARCH
# σ(j) = (a·j + b) mod 97, a=1..96, b=0..96
# 9,312 permutations total
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 1: FULL AFFINE PERMUTATION SEARCH", flush=True)
print("σ(j) = (a·j + b) mod 97 for all a=1..96, b=0..96", flush=True)
print("="*70, flush=True)
print(f"Total permutations: 96 × 97 = {96*97}", flush=True)
print(f"Cipher configs: {len(KEYWORDS)} keywords × 4 cipher/alpha = {len(KEYWORDS)*4}", flush=True)

t0 = time.time()
affine_hits = []

for kw in KEYWORDS:
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        for cipher_name in ['vig', 'beau']:
            expected = compute_expected_ct(kw, cipher_name, alpha, ai)

            # Find the BEST ANCHOR: crib position where expected char is rarest in K4
            # Fewer occurrences → fewer b candidates → faster filtering
            anchor_pos = None
            anchor_char = None
            anchor_k4_positions = None
            min_count = 999
            for pt_pos, _ in CRIB_POSITIONS:
                exp_char = expected[pt_pos]
                k4_positions_for_char = K4_CHAR_POSITIONS.get(exp_char, [])
                count = len(k4_positions_for_char)
                if count < min_count:
                    min_count = count
                    anchor_pos = pt_pos
                    anchor_char = exp_char
                    anchor_k4_positions = k4_positions_for_char

            if min_count == 0:
                # No position in K4 has the required character → impossible for this config
                continue

            # For each a in 1..96, find all b values satisfying the anchor constraint,
            # then check remaining constraints
            config_hits = 0
            for a in range(1, 97):
                for k4_pos in anchor_k4_positions:
                    # σ(anchor_pos) = k4_pos → a·anchor_pos + b ≡ k4_pos (mod 97)
                    b = (k4_pos - a * anchor_pos) % 97

                    # Check ALL 24 crib positions
                    valid = True
                    for pt_pos, _ in CRIB_POSITIONS:
                        if pt_pos == anchor_pos:
                            continue
                        sigma_val = (a * pt_pos + b) % 97
                        if K4[sigma_val] != expected[pt_pos]:
                            valid = False
                            break

                    if valid:
                        # ALL 24 crib positions satisfied! Full test.
                        sigma = [(a * j + b) % 97 for j in range(97)]
                        label = f"affine_a{a}_b{b}_{kw}_{cipher_name}_{alpha_name}"
                        print(f"\n!!! AFFINE MATCH: a={a}, b={b}, kw={kw}, {cipher_name}/{alpha_name}", flush=True)
                        print(f"    All 24 crib constraints satisfied!", flush=True)
                        result = check_and_score(sigma, label)
                        affine_hits.append({'a': a, 'b': b, 'kw': kw,
                                           'cipher': cipher_name, 'alpha': alpha_name,
                                           'result': result})
                        config_hits += 1

            # Also track partial matches (≥20 out of 24) for near-misses
            # (useful if there's a decoy/typo in cribs)
            NEAR_MISS_THRESHOLD = 22
            for a in range(1, 97):
                for k4_pos in anchor_k4_positions:
                    b = (k4_pos - a * anchor_pos) % 97
                    match_count = 0
                    for pt_pos, _ in CRIB_POSITIONS:
                        sigma_val = (a * pt_pos + b) % 97
                        if K4[sigma_val] == expected[pt_pos]:
                            match_count += 1
                    if match_count >= NEAR_MISS_THRESHOLD and match_count < 24:
                        sigma = [(a * j + b) % 97 for j in range(97)]
                        label = f"affine_near{match_count}_a{a}_b{b}_{kw}_{cipher_name}_{alpha_name}"
                        print(f"  NEAR MISS: {match_count}/24 cribs, a={a}, b={b}, {kw}/{cipher_name}/{alpha_name}", flush=True)
                        result = check_and_score(sigma, label)
                        d = {'type': 'near_miss', 'match_count': match_count,
                             'a': a, 'b': b, 'kw': kw, 'cipher': cipher_name,
                             'alpha': alpha_name, 'score': result.get('score', MISS) if result else MISS}
                        emit(d)

elapsed_affine = time.time() - t0
print(f"\nPart 1 complete: {elapsed_affine:.2f}s", flush=True)
print(f"Affine permutation full matches: {len(affine_hits)}", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 2: POWER PERMUTATIONS
# σ(j) = (j + b)^k mod 97 for k coprime to 96, b=0..96
# (x^k is a bijection on Z_97 when gcd(k,96)=1)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 2: POWER PERMUTATIONS", flush=True)
print("σ(j) = (j + b)^k mod 97, k coprime to 96", flush=True)
print("="*70, flush=True)

# 96 = 2^5 × 3. gcd(k, 96)=1 when k is odd and not divisible by 3.
# k values coprime to 96 in range 1..96:
power_ks = [k for k in range(1, 97) if math.gcd(k, 96) == 1]
print(f"  Valid k values (gcd(k,96)=1): {len(power_ks)}: {power_ks[:16]}...", flush=True)
assert len(power_ks) == 32, f"Expected 32 power values, got {len(power_ks)}"

# Precompute modular inverse of each k mod 96 (for anchor inversion)
def modinv(a, m):
    """Extended Euclidean: returns a^{-1} mod m (only if gcd(a,m)=1)."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a},{m})={g}")
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

t0 = time.time()
power_hits = []

for kw in KEYWORDS:
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        for cipher_name in ['vig', 'beau']:
            expected = compute_expected_ct(kw, cipher_name, alpha, ai)

            # Find best anchor (rarest expected char in K4)
            anchor_pos = None
            anchor_char = None
            anchor_k4_positions = None
            min_count = 999
            for pt_pos, _ in CRIB_POSITIONS:
                exp_char = expected[pt_pos]
                k4_positions_for_char = K4_CHAR_POSITIONS.get(exp_char, [])
                count = len(k4_positions_for_char)
                if count < min_count:
                    min_count = count
                    anchor_pos = pt_pos
                    anchor_char = exp_char
                    anchor_k4_positions = k4_positions_for_char

            if min_count == 0:
                continue

            for k in power_ks:
                # Compute k^{-1} mod 96 (inverse for Z_97* exponent reversal)
                k_inv = modinv(k, 96)  # k·k_inv ≡ 1 (mod 96) → x = y^(k_inv) if y = x^k

                for k4_pos in anchor_k4_positions:
                    # Need: (anchor_pos + b)^k ≡ k4_pos (mod 97)
                    # → anchor_pos + b ≡ k4_pos^(k_inv) (mod 97)    [if k4_pos ≠ 0]
                    # → b ≡ k4_pos^(k_inv) - anchor_pos (mod 97)
                    if k4_pos == 0:
                        # 0^k = 0, so anchor_pos + b ≡ 0 (mod 97) → b = -anchor_pos mod 97
                        b = (-anchor_pos) % 97
                    else:
                        x = pow(k4_pos, k_inv, 97)  # x = k4_pos^(k_inv) mod 97
                        b = (x - anchor_pos) % 97

                    # Verify anchor: ((anchor_pos + b)^k) % 97 should == k4_pos
                    check = pow((anchor_pos + b) % 97, k, 97)
                    if check != k4_pos:
                        continue  # numerical issue, skip

                    # Check ALL 24 crib positions
                    valid = True
                    for pt_pos, _ in CRIB_POSITIONS:
                        if pt_pos == anchor_pos:
                            continue
                        sigma_val = pow((pt_pos + b) % 97, k, 97)
                        if K4[sigma_val] != expected[pt_pos]:
                            valid = False
                            break

                    if valid:
                        # ALL 24 satisfied! Full test.
                        sigma = [pow((j + b) % 97, k, 97) for j in range(97)]
                        # Verify it's a valid permutation
                        if sorted(sigma) == list(range(97)):
                            label = f"power_k{k}_b{b}_{kw}_{cipher_name}_{alpha_name}"
                            print(f"\n!!! POWER MATCH: k={k}, b={b}, kw={kw}, {cipher_name}/{alpha_name}", flush=True)
                            result = check_and_score(sigma, label)
                            power_hits.append({'k': k, 'b': b, 'kw': kw,
                                              'cipher': cipher_name, 'alpha': alpha_name,
                                              'result': result})

                # Near-miss tracking for power
                near_best = 0
                near_best_b = None
                for b in range(97):
                    match_count = 0
                    for pt_pos, _ in CRIB_POSITIONS:
                        sigma_val = pow((pt_pos + b) % 97, k, 97)
                        if K4[sigma_val] == expected[pt_pos]:
                            match_count += 1
                    if match_count > near_best:
                        near_best = match_count
                        near_best_b = b
                if near_best >= 20:
                    sigma = [pow((j + near_best_b) % 97, k, 97) for j in range(97)]
                    if sorted(sigma) == list(range(97)):
                        label = f"power_near{near_best}_k{k}_b{near_best_b}_{kw}_{cipher_name}_{alpha_name}"
                        print(f"  POWER NEAR MISS: {near_best}/24 k={k} b={near_best_b} {kw}/{cipher_name}/{alpha_name}", flush=True)
                        result = check_and_score(sigma, label)
                        d = {'type': 'near_miss', 'match_count': near_best,
                             'k': k, 'b': near_best_b, 'kw': kw,
                             'cipher': cipher_name, 'alpha': alpha_name,
                             'score': result.get('score', MISS) if result else MISS}
                        emit(d)

elapsed_power = time.time() - t0
print(f"\nPart 2 complete: {elapsed_power:.2f}s", flush=True)
print(f"Power permutation full matches: {len(power_hits)}", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 3: FULL BRUTE-FORCE AFFINE NEAR-MISSES
# For every (a,b) pair, count how many crib positions match
# Report top-scoring (a,b) pairs regardless of keyword
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 3: BEST AFFINE PAIRS BY CRIB MATCH COUNT (across all configs)", flush=True)
print("="*70, flush=True)

# For each (a,b), for EACH cipher config, count how many cribs match
# Then score the full PT for the best configs
# This is O(96 × 97 × 24 × 96_configs) = ~19M ops but lightweight per op

t0 = time.time()

# Precompute all configs
all_configs = []
for kw in KEYWORDS:
    for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
        for cipher_name in ['vig', 'beau']:
            expected = compute_expected_ct(kw, cipher_name, alpha, ai)
            # Convert to list of (pt_pos, expected_char_in_K4_as_index)
            crib_list = [(pt_pos, expected[pt_pos]) for pt_pos, _ in CRIB_POSITIONS]
            all_configs.append((kw, alpha_name, cipher_name,
                                [cfn for (cn, cfn) in CIPHER_FNS if cn == f"{cipher_name}_{alpha_name}"][0],
                                crib_list))

print(f"  {len(all_configs)} total cipher configs", flush=True)
print(f"  Testing all 9,312 (a,b) pairs against each config...", flush=True)

# Track top 20 matches by (a,b,config) tuple
top_matches = []

progress_count = 0
for a in range(1, 97):
    for b in range(0, 97):
        sigma_vals_cache = [(a * pt_pos + b) % 97 for pt_pos, _ in CRIB_POSITIONS]

        for kw, alpha_name, cipher_name, cipher_fn, crib_list in all_configs:
            # Count how many crib positions match for this (a,b,config)
            match_count = sum(
                1 for idx, (pt_pos, exp_char) in enumerate(crib_list)
                if K4[sigma_vals_cache[idx]] == exp_char
            )
            if match_count >= 18:  # Track any with 18+ matches
                top_matches.append((match_count, a, b, kw, alpha_name, cipher_name))

        progress_count += 1
    if a % 10 == 0:
        print(f"  a={a}/96 done... top matches so far: {len(top_matches)}", flush=True)

print(f"\nPart 3 scan done in {time.time()-t0:.1f}s", flush=True)
top_matches.sort(reverse=True)
print(f"Affine pairs with ≥18 crib matches: {len(top_matches)}", flush=True)

# Test the top matches
if top_matches:
    # Deduplicate by (a,b) pair first
    seen_ab = set()
    for match_count, a, b, kw, alpha_name, cipher_name in top_matches[:50]:
        print(f"  MATCH: {match_count}/24 cribs, a={a}, b={b}, {kw}/{cipher_name}/{alpha_name}", flush=True)
        if (a, b) not in seen_ab:
            seen_ab.add((a, b))
            sigma = [(a * j + b) % 97 for j in range(97)]
            result = check_and_score(sigma, f"affine_best_{match_count}_a{a}_b{b}")
            if result:
                print(f"    Best PT: {result['pt'][:50]}...", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 4: COMBINED AFFINE × POWER SEARCH
# σ(j) = a·(j+offset)^k + b mod 97
# For k in power_ks, try selected (a,b) from crib constraints
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 4: COMBINED AFFINE × POWER: σ(j) = a·(j+offset)^k + b mod 97", flush=True)
print("="*70, flush=True)

t0 = time.time()
combined_hits = []

for k in power_ks[:8]:  # Test first 8 k-values as representative sample
    print(f"  Testing k={k}...", flush=True)
    k_inv = modinv(k, 96)

    for kw in KEYWORDS[:6]:  # Test top keywords only
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            for cipher_name in ['vig', 'beau']:
                expected = compute_expected_ct(kw, cipher_name, alpha, ai)

                # Find two anchor positions (use rarest two)
                anchors = sorted(
                    [(len(K4_CHAR_POSITIONS.get(expected[pt_pos], [])), pt_pos)
                     for pt_pos, _ in CRIB_POSITIONS]
                )[:2]

                if anchors[0][0] == 0:
                    continue  # impossible

                a_pos1 = anchors[0][1]  # rarest
                a_pos2 = anchors[1][1]  # second rarest
                exp1 = expected[a_pos1]
                exp2 = expected[a_pos2]

                # We need: a·(a_pos1+offset)^k + b ≡ K4_val at some k4_pos1 (mod 97)
                # And:     a·(a_pos2+offset)^k + b ≡ K4_val at some k4_pos2 (mod 97)
                # Subtract: a·[(a_pos1+offset)^k - (a_pos2+offset)^k] ≡ k4_val1 - k4_val2 (mod 97)
                # This gives a constraint on (a, offset)

                for k4_pos1 in K4_CHAR_POSITIONS.get(exp1, []):
                    for k4_pos2 in K4_CHAR_POSITIONS.get(exp2, []):
                        if k4_pos1 == k4_pos2:
                            continue
                        # Try all offsets (0..96)
                        for offset in range(97):
                            x1 = pow((a_pos1 + offset) % 97, k, 97)
                            x2 = pow((a_pos2 + offset) % 97, k, 97)
                            dx = (x1 - x2) % 97
                            if dx == 0:
                                continue
                            # a · dx ≡ k4_pos1 - k4_pos2 (mod 97)
                            rhs = (k4_pos1 - k4_pos2) % 97
                            # a = rhs · dx^{-1} mod 97
                            dx_inv = pow(dx, 95, 97)  # Fermat: dx^{97-2} mod 97
                            a_val = (rhs * dx_inv) % 97
                            if a_val == 0:
                                continue
                            # b = k4_pos1 - a_val · x1 mod 97
                            b_val = (k4_pos1 - a_val * x1) % 97

                            # Check ALL crib positions
                            valid = True
                            for pt_pos, _ in CRIB_POSITIONS:
                                sigma_val = (a_val * pow((pt_pos + offset) % 97, k, 97) + b_val) % 97
                                if K4[sigma_val] != expected[pt_pos]:
                                    valid = False
                                    break
                            if valid:
                                sigma = [(a_val * pow((j + offset) % 97, k, 97) + b_val) % 97 for j in range(97)]
                                if sorted(sigma) == list(range(97)):
                                    label = f"combined_k{k}_a{a_val}_off{offset}_b{b_val}_{kw}_{cipher_name}_{alpha_name}"
                                    print(f"!!! COMBINED MATCH: k={k}, a={a_val}, offset={offset}, b={b_val}", flush=True)
                                    result = check_and_score(sigma, label)
                                    combined_hits.append((k, a_val, offset, b_val, kw, cipher_name, alpha_name))

print(f"\nPart 4 complete in {time.time()-t0:.1f}s", flush=True)
print(f"Combined hits: {len(combined_hits)}", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 5: AFFINE PERMUTATIONS WITH EXTENDED KEYWORD LIST
# In case the key is NOT in our keyword list, check MULTI-CRIB MATCHES
# without assuming a keyword. Find (a,b) pairs where K4[σ(j)] has
# the MOST self-consistency as a Vigenère ciphertext (IC test).
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 5: KEYWORD-FREE AFFINE SEARCH (IC-based ranking)", flush=True)
print("="*70, flush=True)

def ic_score(text):
    n = len(text)
    if n < 2:
        return 0.0
    c = Counter(text)
    return sum(v*(v-1) for v in c.values()) / (n*(n-1))

t0 = time.time()
# For each (a,b), compute the unscrambled CT and score by IC
# English: IC ≈ 0.065, Random: IC ≈ 0.038
# We want to find permutations that maximize IC of the decrypted plaintext

best_ic_results = []
for a in range(1, 97):
    for b in range(0, 97):
        sigma = [(a * j + b) % 97 for j in range(97)]
        ct = ''.join(K4[sigma[j]] for j in range(97))
        # Score without keyword: just IC of ct (as a proxy for period-k keystream correlation)
        ct_ic = ic_score(ct)
        if ct_ic > 0.055:  # notably higher than random (0.038)
            best_ic_results.append((ct_ic, a, b, ct))

best_ic_results.sort(reverse=True)
print(f"  Affine pairs with IC > 0.055: {len(best_ic_results)}", flush=True)
for ic_val, a, b, ct in best_ic_results[:10]:
    print(f"  IC={ic_val:.4f} a={a} b={b}: CT={ct[:30]}...", flush=True)
    sigma = [(a * j + b) % 97 for j in range(97)]
    result = check_and_score(sigma, f"ic_best_a{a}_b{b}")
    if result:
        print(f"    best PT={result['pt'][:50]}...", flush=True)

print(f"\nPart 5 complete in {time.time()-t0:.1f}s", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 6: GRILLE-GUIDED AFFINE PARAMETERS
# The grille extract might encode the parameters (a,b) for the affine perm
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 6: GRILLE-GUIDED AFFINE PARAMETERS", flush=True)
print("="*70, flush=True)

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GRILLE_EXTRACT) == 106

# The grille extract might encode (a,b) via its characters
# Various encodings:
grille_az_vals = [AZI.get(c, 0) for c in GRILLE_EXTRACT]
grille_ka_vals = [KAI.get(c, 0) for c in GRILLE_EXTRACT]

# Derived (a,b) candidates from grille
grille_params = []

# G1: First two characters as a, b
grille_params.append(("GE_first2_AZ", grille_az_vals[0]+1, grille_az_vals[1]))
grille_params.append(("GE_first2_KA", grille_ka_vals[0]+1, grille_ka_vals[1]))

# G2: First character as a, last character as b
grille_params.append(("GE_first_last_AZ", grille_az_vals[0]+1, grille_az_vals[-1]))
grille_params.append(("GE_first_last_KA", grille_ka_vals[0]+1, grille_ka_vals[-1]))

# G3: Sum/product mod 97
gsum = sum(grille_az_vals) % 97
gprod = 1
for v in grille_az_vals:
    gprod = (gprod * (v+1)) % 97
grille_params.append(("GE_sum_a_AZ", gsum if gsum > 0 else 1, 0))
grille_params.append(("GE_prod_a_AZ", gprod if gprod > 0 else 1, 0))

# G4: Length of grille (106) as a parameter
# 106 mod 97 = 9; 106 - 97 = 9
grille_params.append(("GE_len_mod97", 9, 0))
grille_params.append(("GE_len_mod97_a1", 1, 9))

# G5: Number of T-absent positions (106 - 0 = 106; first T position if T existed)
# T is completely absent from extract - use positional encoding of T-absence
# Period-8 pattern: F(6), N(14), V(22) → a=8?
grille_params.append(("period8_b0", 8, 0))
grille_params.append(("period8_bN", 8, 14))  # N is row 14
grille_params.append(("period8_bV", 8, 22))  # V is row 22

# G6: 97 mod 26 = 19, 97 mod 8 = 1
grille_params.append(("97mod26", 19, 0))
grille_params.append(("97mod8", 1, 0))  # = identity, skip
grille_params.append(("26_a", 26, 0))
grille_params.append(("8_13", 8, 13))  # "8 Lines 73" → 8, 13 (97-73-11=13)

# G7: Cardan grille dimensions: 28×33
grille_params.append(("28_a", 28, 0))
grille_params.append(("33_a", 33, 0))
grille_params.append(("28_33", 28, 33))
grille_params.append(("33_28", 33, 28))
grille_params.append(("28a_3b", 28, 3))

print(f"  Testing {len(grille_params)} grille-derived (a,b) parameter sets...", flush=True)

for gname, a_val, b_val in grille_params:
    a_val = a_val % 97
    b_val = b_val % 97
    if a_val == 0:
        continue
    sigma = [(a_val * j + b_val) % 97 for j in range(97)]
    if sorted(sigma) != list(range(97)):
        print(f"  WARNING: {gname} a={a_val} b={b_val} is not a valid permutation!", flush=True)
        continue
    result = check_and_score(sigma, f"grille_guided_{gname}_a{a_val}_b{b_val}")
    if result and result.get('score', MISS) > -6.0:
        print(f"  INTERESTING: {gname} a={a_val} b={b_val}: score={result['score']:.3f}", flush=True)
        print(f"    PT: {result['pt']}", flush=True)

print("Part 6 complete.", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 7: INVERSE AFFINE PERMUTATIONS
# For σ(j) = (a·j + b) mod 97, the inverse is σ^{-1}(i) = a^{-1}·(i - b) mod 97
# The ORIGINAL model: carved = scramble(real_CT), so σ maps real_CT → carved
# But what if the mapping is in the other direction?
# Test INVERSE permutations too
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 7: INVERSE AFFINE PERMUTATIONS", flush=True)
print("σ^{-1}(j) = a^{-1}·(j - b) mod 97", flush=True)
print("="*70, flush=True)

t0 = time.time()
inverse_hits = []

# The inverse of σ(j) = (a·j+b) mod 97 is σ^{-1}(i) = a_inv·(i-b) mod 97
# where a_inv = a^{-1} mod 97 = a^{95} mod 97 (Fermat)

# Under the INVERSE interpretation:
# real_CT[σ^{-1}(j)] = K4[j] → real_CT[a_inv·(j-b)%97] = K4[j]
# Or equivalently: real_CT[i] = K4[(a·i + b)%97] = K4[σ(i)]
# Wait, this is EXACTLY the forward permutation!

# Actually the question is about INTERPRETATION:
# If σ means "carved[j] = real_CT[σ(j)]" → real_CT = apply_perm(carved, inverse(σ))
# But we've been computing real_CT[j] = K4[σ(j)], which IS the forward perm.

# The inverse question: maybe σ is defined as real_CT[σ(j)] = K4[j] (i.e., sigma maps
# carved positions to real_CT positions, not the other way).
# In that case: real_CT[σ(j)] = K4[j] → real_CT[i] = K4[σ^{-1}(i)]
# This is equivalent to replacing σ with σ^{-1} in our search.

# Since we search all (a,b), and the inverse of (a,b) is (a_inv, -b·a_inv),
# ALL inverse permutations are ALREADY in our search space!
# The full affine search (Part 1) covers both forward and inverse.

print("  Note: Inverse permutations are already covered by Part 1 (full affine space).", flush=True)
print("  The inverse of σ(j)=(a·j+b) is σ^{-1}(j)=(a_inv·(j-b)), which is an affine", flush=True)
print("  permutation with parameters (a_inv, -b·a_inv mod 97).", flush=True)
print("  Since Part 1 searches ALL (a',b') pairs, this is included.", flush=True)
print("Part 7 complete (no new tests needed).", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# PART 8: PARTIAL PERIOD SEARCH
# What if the permutation is affine-like but applied to BLOCKS of K4?
# E.g., K4[0:49] permuted by one affine, K4[49:97] by another
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("PART 8: BLOCK-AFFINE PERMUTATIONS", flush=True)
print("σ = affine perm on first 49 chars, different on last 48", flush=True)
print("="*70, flush=True)

t0 = time.time()

# Split: cribs at positions 21-33 (in first block if block≥49) and 63-73 (in second block)
# ENE cribs (pos 21-33): if block split at 49, these are in block 0 (positions 0-48)
# BC cribs (pos 63-73): these are in block 1 (positions 49-96 → local pos 14-24)

# For block split at position S:
# Block 0: positions 0..S-1, uses affine (a0, b0) within block 0
# Block 1: positions S..96, uses affine (a1, b1) within block 1

# σ(j) = (a0 · j + b0) % S for j < S
# σ(j) = S + (a1 · (j-S) + b1) % (97-S) for j >= S

# This requires gcd(a0, S) = 1 and gcd(a1, 97-S) = 1

block_splits = [49, 48, 50, 24, 73, 34]  # split after crib boundaries etc.

block_hits = []
for S in block_splits:
    S2 = 97 - S  # size of second block

    # Primes coprime to S and S2
    def valid_strides(n):
        return [a for a in range(1, n) if math.gcd(a, n) == 1]

    strides0 = valid_strides(S)
    strides1 = valid_strides(S2)

    # ENE crib positions 21-33: all in block 0 if S > 33
    # BC crib positions 63-73: all in block 1 if S <= 63

    ene_in_block0 = all(p < S for p, _ in CRIB_POSITIONS if p <= 33)
    bc_in_block1 = all(p >= S for p, _ in CRIB_POSITIONS if p >= 63)

    if not (ene_in_block0 and bc_in_block1):
        # Mixed cribs make this more complex, skip for now
        print(f"  Block split at {S}: mixed cribs, skipping", flush=True)
        continue

    print(f"  Block split at {S}: ENE in block 0, BC in block 1", flush=True)

    for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
        for alpha_name, alpha, ai in [("AZ", AZ, AZI), ("KA", KA, KAI)]:
            for cipher_name in ['vig', 'beau']:
                expected = compute_expected_ct(kw, cipher_name, alpha, ai)

                # Find anchor in block 0 (ENE cribs, pos 21-33)
                ene_cribs = [(p, expected[p]) for p, _ in CRIB_POSITIONS if p < S]
                bc_cribs  = [(p, expected[p]) for p, _ in CRIB_POSITIONS if p >= S]

                if not ene_cribs or not bc_cribs:
                    continue

                # Anchor for block 0
                anchor0_pos, anchor0_char = min(
                    ene_cribs,
                    key=lambda x: len(K4_CHAR_POSITIONS.get(x[1], []))
                )
                anchor0_k4_positions = K4_CHAR_POSITIONS.get(anchor0_char, [])
                # These must be in block 0 of K4 (positions 0..S-1)
                anchor0_k4_positions = [p for p in anchor0_k4_positions if p < S]
                if not anchor0_k4_positions:
                    continue

                # Anchor for block 1
                anchor1_pos, anchor1_char = min(
                    bc_cribs,
                    key=lambda x: len(K4_CHAR_POSITIONS.get(x[1], []))
                )
                anchor1_k4_positions = K4_CHAR_POSITIONS.get(anchor1_char, [])
                # These must be in block 1 of K4 (positions S..96)
                anchor1_k4_positions = [p for p in anchor1_k4_positions if p >= S]
                if not anchor1_k4_positions:
                    continue

                # Find valid (a0, b0) for block 0
                for a0 in strides0:
                    for k4_pos0 in anchor0_k4_positions:
                        # local_pos of anchor0_pos in block 0 = anchor0_pos (since block 0 starts at 0)
                        b0 = (k4_pos0 - a0 * anchor0_pos) % S
                        # Check all ENE cribs in block 0
                        valid0 = True
                        for pt_pos, _ in ene_cribs:
                            if pt_pos == anchor0_pos:
                                continue
                            sigma_val = (a0 * pt_pos + b0) % S
                            if K4[sigma_val] != expected[pt_pos]:
                                valid0 = False
                                break
                        if not valid0:
                            continue

                        # Find valid (a1, b1) for block 1
                        for a1 in strides1:
                            for k4_pos1 in anchor1_k4_positions:
                                local_anchor1 = anchor1_pos - S
                                local_k4_pos1 = k4_pos1 - S
                                b1 = (local_k4_pos1 - a1 * local_anchor1) % S2
                                # Check all BC cribs in block 1
                                valid1 = True
                                for pt_pos, _ in bc_cribs:
                                    if pt_pos == anchor1_pos:
                                        continue
                                    local_pt = pt_pos - S
                                    sigma_val = S + (a1 * local_pt + b1) % S2
                                    if K4[sigma_val] != expected[pt_pos]:
                                        valid1 = False
                                        break
                                if not valid1:
                                    continue

                                # Both blocks valid! Build full sigma
                                sigma = []
                                for j in range(S):
                                    sigma.append((a0 * j + b0) % S)
                                for j in range(S2):
                                    sigma.append(S + (a1 * j + b1) % S2)

                                if sorted(sigma) == list(range(97)):
                                    label = (f"block{S}_a0{a0}_b0{b0}_a1{a1}_b1{b1}"
                                             f"_{kw}_{cipher_name}_{alpha_name}")
                                    print(f"!!! BLOCK-AFFINE MATCH: split={S} a0={a0} b0={b0} a1={a1} b1={b1}", flush=True)
                                    result = check_and_score(sigma, label)
                                    block_hits.append((S, a0, b0, a1, b1, kw, cipher_name, alpha_name))

print(f"\nPart 8 complete in {time.time()-t0:.1f}s", flush=True)
print(f"Block-affine hits: {len(block_hits)}", flush=True)

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70, flush=True)
print("FINAL SUMMARY", flush=True)
print("="*70, flush=True)
print(f"Total permutations tested: {total_perms_tested}", flush=True)
print(f"CRIB HITS: {len(HITS)}", flush=True)
print(f"Affine full matches:   {len(affine_hits)}", flush=True)
print(f"Power full matches:    {len(power_hits)}", flush=True)
print(f"Combined full matches: {len(combined_hits)}", flush=True)
print(f"Block-affine matches:  {len(block_hits)}", flush=True)

if HITS:
    print("\n*** CRIB HITS ***", flush=True)
    for h in HITS:
        print(f"  {h.get('label')} | ENE@{h.get('ene')} BC@{h.get('bc')}", flush=True)
        print(f"  Key: {h.get('key')} Cipher: {h.get('cipher')}", flush=True)
        print(f"  PT:  {h.get('pt')}", flush=True)
else:
    print("\nNo crib hits found.", flush=True)
    print("Top affine near-misses:", flush=True)
    for match_count, a, b, kw, alpha_name, cipher_name in top_matches[:5]:
        print(f"  {match_count}/24 cribs: a={a} b={b} {kw}/{cipher_name}/{alpha_name}", flush=True)

OUT.close()
print(f"\nResults saved to blitz_results/wildcard/affine_search_results.jsonl", flush=True)
