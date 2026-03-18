#!/usr/bin/env python3
"""
scripts/campaigns/e_null_insertion_structure.py

Comprehensive analysis of whether the null-insertion process at the 17
consensus positions has mathematical structure (not random filler).

Motivated by the discovery that the Stehle Delta4=5 pattern at positions
55-63 is CREATED by null characters at consensus positions {58, 59}.

Seven analysis tasks:
  1. Null character arithmetic patterns (differences, IC, periodicity)
  2. Null characters vs their neighbors (AP, mean, XOR)
  3. The Delta4=5 mechanism at {58,59} -- what values produce it?
  4. Global arithmetic fingerprint (null positions as bridge builders)
  5. Null characters as a separate cipher (Caesar, Vigenere, Beaufort, autokey)
  6. Positional encoding (do null POSITIONS encode something?)
  7. Interaction with known constants (DEFECTOR, KRYPTOS alphabet)

Cipher: N/A (structural analysis)
Family: campaigns
Status: active
Keyspace: analytical
Last run: never
Best score: N/A
"""
import sys
import os
import json
import random
from collections import Counter, defaultdict
from itertools import combinations
from math import gcd, log10, sqrt
from datetime import datetime
from functools import reduce

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ========================================================================
# SETUP
# ========================================================================
ct_nums = [ALPH_IDX[c] for c in CT]
N = CT_LEN
assert N == 97

# Consensus null positions (17, 100% across all six 15/24 masks)
CONSENSUS_NULLS_17 = sorted([0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85])
# Full 24-null mask (mask 0 from results)
MASK_24_0 = sorted([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96])
# Non-null positions
NON_NULL_POS = sorted(p for p in range(N) if p not in CONSENSUS_NULLS_17)

null_chars_17 = [ct_nums[p] for p in CONSENSUS_NULLS_17]
null_text_17 = ''.join(CT[p] for p in CONSENSUS_NULLS_17)

null_chars_24 = [ct_nums[p] for p in MASK_24_0]
null_text_24 = ''.join(CT[p] for p in MASK_24_0)

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
results = {'timestamp': timestamp, 'task': 'null_insertion_structure', 'findings': {}}

# Load quadgrams
qg_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
quadgrams = None
try:
    with open(qg_path) as f:
        quadgrams = json.load(f)
except Exception:
    pass

def qg_score(text):
    if quadgrams is None or len(text) < 4:
        return -999.0
    total = sum(quadgrams.get(text[i:i+4], -10.0) for i in range(len(text)-3))
    return total / max(1, len(text)-3)

def ic(nums):
    """Index of coincidence."""
    if len(nums) < 2:
        return 0.0
    n = len(nums)
    freqs = Counter(nums)
    return sum(f*(f-1) for f in freqs.values()) / (n*(n-1))

print("=" * 80)
print("NULL INSERTION MATHEMATICAL STRUCTURE ANALYSIS")
print(f"Timestamp: {timestamp}")
print(f"CT: {CT}")
print(f"Consensus null positions (17): {CONSENSUS_NULLS_17}")
print(f"Null characters: {null_text_17}")
print(f"Null numeric: {null_chars_17}")
print("=" * 80)

# ========================================================================
# TASK 1: NULL CHARACTER ARITHMETIC PATTERNS
# ========================================================================
print("\n" + "=" * 80)
print("TASK 1: NULL CHARACTER ARITHMETIC PATTERNS")
print("=" * 80)

print(f"\n17 consensus null characters in position order:")
print(f"  Text:    {null_text_17}")
print(f"  Numeric: {null_chars_17}")
print(f"  Positions: {CONSENSUS_NULLS_17}")

# 1a. Consecutive differences
diffs_1 = [(null_chars_17[i+1] - null_chars_17[i]) % 26 for i in range(len(null_chars_17)-1)]
print(f"\n1a. Consecutive differences (mod 26): {diffs_1}")
print(f"    As signed: {[(null_chars_17[i+1] - null_chars_17[i]) for i in range(len(null_chars_17)-1)]}")
print(f"    Set of unique diffs: {sorted(set(diffs_1))}")
print(f"    Mode: {Counter(diffs_1).most_common(3)}")

# 1b. Running differences at all lags
print(f"\n1b. Running differences at all lags (1-8):")
for lag in range(1, min(9, len(null_chars_17))):
    lag_diffs = [(null_chars_17[i+lag] - null_chars_17[i]) % 26 for i in range(len(null_chars_17)-lag)]
    unique = sorted(set(lag_diffs))
    is_const = len(unique) == 1
    print(f"    Lag {lag}: {lag_diffs}")
    print(f"           Unique: {unique} {'<<< CONSTANT!' if is_const else ''}")

# 1c. Second differences
second_diffs = [(diffs_1[i+1] - diffs_1[i]) % 26 for i in range(len(diffs_1)-1)]
print(f"\n1c. Second differences (mod 26): {second_diffs}")
second_unique = sorted(set(second_diffs))
print(f"    Unique: {second_unique} {'<<< CONSTANT!' if len(second_unique)==1 else ''}")

# 1d. Fibonacci-like check: does null[i+2] = null[i+1] + null[i] (mod 26)?
print(f"\n1d. Fibonacci-like check: null[i+2] =? (null[i+1] + null[i]) mod 26")
fib_hits = 0
for i in range(len(null_chars_17)-2):
    expected = (null_chars_17[i] + null_chars_17[i+1]) % 26
    actual = null_chars_17[i+2]
    match = "MATCH" if expected == actual else f"miss (expected {expected}={chr(expected+65)}, got {actual}={chr(actual+65)})"
    if expected == actual:
        fib_hits += 1
    print(f"    i={i}: {chr(null_chars_17[i]+65)}+{chr(null_chars_17[i+1]+65)}={expected}({chr(expected+65)}) vs {chr(actual+65)}: {match}")
print(f"    Fibonacci hits: {fib_hits}/{len(null_chars_17)-2} (expected by chance: {(len(null_chars_17)-2)/26:.2f})")

# 1e. IC of null characters
null_ic = ic(null_chars_17)
print(f"\n1e. IC of 17 null characters: {null_ic:.4f}")
print(f"    Random expected: {1/26:.4f}")
print(f"    English expected: 0.0667")
print(f"    Full CT IC: 0.0361")

# 1f. Character frequency
print(f"\n1f. Character frequencies in null set:")
null_freq = Counter(null_chars_17)
for v, count in sorted(null_freq.items()):
    ct_count = ct_nums.count(v)
    print(f"    {chr(v+65)}({v:2d}): {count}x in nulls, {ct_count}x in full CT, ratio {count/ct_count:.2f}" if ct_count > 0 else f"    {chr(v+65)}({v:2d}): {count}x in nulls, 0x in CT")

# 1g. Periodicity: autocorrelation
print(f"\n1g. Autocorrelation of null character sequence:")
mean_val = sum(null_chars_17) / len(null_chars_17)
for lag in range(1, 9):
    if lag >= len(null_chars_17):
        break
    num = sum((null_chars_17[i] - mean_val) * (null_chars_17[i+lag] - mean_val) for i in range(len(null_chars_17)-lag))
    den = sum((v - mean_val)**2 for v in null_chars_17)
    if den == 0:
        continue
    acf = num / den
    print(f"    Lag {lag}: ACF = {acf:+.4f}")

# 1h. Check if nulls form an arithmetic sequence with any common difference
print(f"\n1h. Arithmetic sequence check (all 26 common differences):")
for d in range(26):
    # Start from first null char, generate expected sequence
    expected = [(null_chars_17[0] + i*d) % 26 for i in range(len(null_chars_17))]
    matches = sum(1 for a, b in zip(null_chars_17, expected) if a == b)
    if matches > 3:
        print(f"    d={d:2d}: {matches}/{len(null_chars_17)} matches")

results['findings']['task1'] = {
    'null_text': null_text_17,
    'null_numeric': null_chars_17,
    'consecutive_diffs': diffs_1,
    'second_diffs': second_diffs,
    'ic': null_ic,
    'fibonacci_hits': fib_hits,
}

# ========================================================================
# TASK 2: NULL CHARACTERS VS THEIR NEIGHBORS
# ========================================================================
print("\n" + "=" * 80)
print("TASK 2: NULL CHARACTERS VS THEIR NEIGHBORS")
print("=" * 80)

print(f"\nFor each consensus null position p, examine CT[p-1], CT[p], CT[p+1].")
print(f"Does the null 'fit' an arithmetic progression with its neighbors?")
print(f"{'pos':>4} {'CT[p-1]':>8} {'CT[p]':>8} {'CT[p+1]':>9} {'d_left':>7} {'d_right':>8} {'AP?':>5} {'mean_nb':>9} {'sum_nb':>8} {'xor_nb':>8}")

ap_count = 0
mean_count = 0
sum_count = 0
xor_count = 0
task2_details = []

for p in CONSENSUS_NULLS_17:
    if p == 0 or p == N-1:
        # Edge positions
        if p == 0:
            left_v = None
            right_v = ct_nums[p+1]
            print(f"{p:4d} {'---':>8} {chr(ct_nums[p]+65):>5}({ct_nums[p]:2d}) {chr(right_v+65):>5}({right_v:2d}) {'---':>7} {'---':>8} {'---':>5} {'---':>9} {'---':>8} {'---':>8}")
        else:
            left_v = ct_nums[p-1]
            right_v = None
            print(f"{p:4d} {chr(left_v+65):>5}({left_v:2d}) {chr(ct_nums[p]+65):>5}({ct_nums[p]:2d}) {'---':>9} {'---':>7} {'---':>8} {'---':>5} {'---':>9} {'---':>8} {'---':>8}")
        continue

    left_v = ct_nums[p-1]
    center_v = ct_nums[p]
    right_v = ct_nums[p+1]

    d_left = (center_v - left_v) % 26
    d_right = (right_v - center_v) % 26
    is_ap = d_left == d_right

    mean_nb = (left_v + right_v) / 2
    mean_match = abs(center_v - mean_nb) < 0.6  # integer mean

    sum_nb = (left_v + right_v) % 26
    sum_match = center_v == sum_nb

    xor_nb = left_v ^ right_v
    xor_match = center_v == (xor_nb % 26)

    if is_ap:
        ap_count += 1
    if mean_match:
        mean_count += 1
    if sum_match:
        sum_count += 1
    if xor_match:
        xor_count += 1

    ap_flag = "<<AP" if is_ap else ""
    mean_flag = "<<MEAN" if mean_match else ""
    sum_flag = "<<SUM" if sum_match else ""
    xor_flag = "<<XOR" if xor_match else ""

    print(f"{p:4d} {chr(left_v+65):>5}({left_v:2d}) {chr(center_v+65):>5}({center_v:2d}) {chr(right_v+65):>5}({right_v:2d}) {d_left:7d} {d_right:8d} {ap_flag:>5} {mean_flag:>9} {sum_flag:>8} {xor_flag:>8}")

    task2_details.append({
        'pos': p, 'left': left_v, 'center': center_v, 'right': right_v,
        'd_left': d_left, 'd_right': d_right,
        'is_ap': is_ap, 'is_mean': mean_match, 'is_sum': sum_match, 'is_xor': xor_match
    })

# Count non-edge nulls
n_interior = sum(1 for p in CONSENSUS_NULLS_17 if 0 < p < N-1)
print(f"\nSummary ({n_interior} interior null positions):")
print(f"  Arithmetic Progression (d_left == d_right): {ap_count}/{n_interior} = {ap_count/n_interior:.2%}")
print(f"  Expected by chance (AP, any d): {n_interior}/26 = {n_interior/26:.2f} = {1/26:.2%}")
p_ap = 1/26
# (binomial computed manually below)
# Binomial test by hand
from math import comb as mcomb
def binom_p_ge(k, n, p):
    """P(X >= k) under Binomial(n, p)."""
    return sum(mcomb(n, i) * p**i * (1-p)**(n-i) for i in range(k, n+1))

# Actually let's just approximate
print(f"  P(>={ap_count} AP in {n_interior} trials, p=1/26): ~{binom_p_ge(ap_count, n_interior, 1/26):.6f}")

print(f"  Mean of neighbors: {mean_count}/{n_interior} = {mean_count/n_interior:.2%}")
print(f"  Expected by chance (mean, requires even sum): ~{n_interior*0.038:.2f}")
print(f"  Sum of neighbors mod 26: {sum_count}/{n_interior} = {sum_count/n_interior:.2%}")
print(f"  Expected by chance: {n_interior}/26 = {n_interior/26:.2f}")
print(f"  XOR of neighbors mod 26: {xor_count}/{n_interior} = {xor_count/n_interior:.2%}")

# Also check: does CT[p] = (CT[p-1] + CT[p+1] + k) mod 26 for some fixed k across all nulls?
print(f"\n2b. Fixed offset: CT[p] = (CT[p-1] + CT[p+1] + k) mod 26 for constant k?")
for k in range(26):
    matches = 0
    for p in CONSENSUS_NULLS_17:
        if p == 0 or p == N-1:
            continue
        if ct_nums[p] == (ct_nums[p-1] + ct_nums[p+1] + k) % 26:
            matches += 1
    if matches >= 3:
        print(f"    k={k:2d}({chr(k+65)}): {matches}/{n_interior} matches")

# CT[p] = (CT[p-1] - CT[p+1] + k) mod 26?
print(f"\n2c. Fixed offset: CT[p] = (CT[p-1] - CT[p+1] + k) mod 26 for constant k?")
for k in range(26):
    matches = 0
    for p in CONSENSUS_NULLS_17:
        if p == 0 or p == N-1:
            continue
        if ct_nums[p] == (ct_nums[p-1] - ct_nums[p+1] + k) % 26:
            matches += 1
    if matches >= 3:
        print(f"    k={k:2d}({chr(k+65)}): {matches}/{n_interior} matches")

# CT[p] = (CT[p-1] * CT[p+1]) mod 26?
print(f"\n2d. Product: CT[p] = (CT[p-1] * CT[p+1]) mod 26?")
prod_matches = 0
for p in CONSENSUS_NULLS_17:
    if p == 0 or p == N-1:
        continue
    expected_prod = (ct_nums[p-1] * ct_nums[p+1]) % 26
    if ct_nums[p] == expected_prod:
        prod_matches += 1
        print(f"    pos {p}: {chr(ct_nums[p-1]+65)}*{chr(ct_nums[p+1]+65)}={expected_prod} = {chr(ct_nums[p]+65)} MATCH")
print(f"    Product matches: {prod_matches}/{n_interior}")

# CT[p] = f(position, ...) -- position-dependent
print(f"\n2e. Position-dependent: CT[p] = p mod 26?")
pos_mod_matches = sum(1 for p in CONSENSUS_NULLS_17 if ct_nums[p] == p % 26)
print(f"    Matches: {pos_mod_matches}/{len(CONSENSUS_NULLS_17)} (expected: ~{len(CONSENSUS_NULLS_17)/26:.2f})")

print(f"\n2f. CT[p] = (p * k) mod 26 for constant k?")
for k in range(1, 26):
    matches = sum(1 for p in CONSENSUS_NULLS_17 if ct_nums[p] == (p * k) % 26)
    if matches >= 3:
        print(f"    k={k:2d}: {matches}/{len(CONSENSUS_NULLS_17)} matches")

results['findings']['task2'] = {
    'ap_count': ap_count, 'mean_count': mean_count, 'sum_count': sum_count,
    'xor_count': xor_count, 'n_interior': n_interior,
    'details': task2_details,
}

# ========================================================================
# TASK 3: THE DELTA4=5 MECHANISM AT {58,59}
# ========================================================================
print("\n" + "=" * 80)
print("TASK 3: THE DELTA4=5 MECHANISM AT {58,59}")
print("=" * 80)

# Positions 55-63: D(3) I(8) A(0) W(22) I(8) N(13) F(5) B(1) N(13)
region = ct_nums[55:64]
region_text = CT[55:64]
print(f"\nPositions 55-63: {region_text}")
print(f"Numeric: {region}")
print(f"Positions 58=W(22), 59=I(8) are consensus nulls.")
print(f"Without them: D I A _ _ N F B N = positions 55,56,57,60,61,62,63")

# The pattern: at lag 4, all 5 diffs are 5.
# (55,59): (3,8) -> diff 5
# (56,60): (8,13) -> diff 5
# (57,61): (0,5) -> diff 5
# (58,62): (22,1) -> (1-22)%26 = 5 -- POSITION 58 IS A NULL
# (59,63): (8,13) -> diff 5 -- POSITION 59 IS A NULL

print(f"\nLag-4 pairs in region 55-63:")
for i in range(5):
    a_pos = 55 + i
    b_pos = 55 + i + 4
    a_val = ct_nums[a_pos]
    b_val = ct_nums[b_pos]
    d = (b_val - a_val) % 26
    null_tag = " [NULL]" if a_pos in CONSENSUS_NULLS_17 or b_pos in CONSENSUS_NULLS_17 else ""
    print(f"  ({a_pos},{b_pos}): {chr(a_val+65)}({a_val}) -> {chr(b_val+65)}({b_val}), diff={d}{null_tag}")

# 3a. What values at positions 58,59 produce constant Delta4 = 5?
print(f"\n3a. What values at positions 58,59 produce constant Delta4=5?")
print(f"  For (58,62) pair: need (CT[62]-x58) % 26 = 5 -> x58 = (CT[62]-5) % 26 = ({ct_nums[62]}-5)%26 = {(ct_nums[62]-5)%26}")
print(f"  For (59,63) pair: need (CT[63]-x59) % 26 = 5 -> x59 = (CT[63]-5) % 26 = ({ct_nums[63]}-5)%26 = {(ct_nums[63]-5)%26}")
print(f"  Also (55,59) pair uses position 59: need (x59-CT[55]) % 26 = 5 -> x59 = (CT[55]+5) % 26 = ({ct_nums[55]}+5)%26 = {(ct_nums[55]+5)%26}")
print(f"  Also (54,58) pair: need (x58-CT[54]) % 26 = 5 -> x58 = (CT[54]+5) % 26 = ({ct_nums[54]}+5)%26 = {(ct_nums[54]+5)%26}")

req_58_from_62 = (ct_nums[62] - 5) % 26
req_58_from_54 = (ct_nums[54] + 5) % 26
req_59_from_63 = (ct_nums[63] - 5) % 26
req_59_from_55 = (ct_nums[55] + 5) % 26

print(f"\n  Requirements for Delta4=5:")
print(f"    x58: from pair (58,62) = {req_58_from_62}({chr(req_58_from_62+65)}), from pair (54,58) = {req_58_from_54}({chr(req_58_from_54+65)})")
print(f"    x59: from pair (59,63) = {req_59_from_63}({chr(req_59_from_63+65)}), from pair (55,59) = {req_59_from_55}({chr(req_59_from_55+65)})")
print(f"    Actual: x58={ct_nums[58]}({CT[58]}), x59={ct_nums[59]}({CT[59]})")

# Check: do the constraints agree?
x58_consistent = (req_58_from_62 == req_58_from_54)
x59_consistent = (req_59_from_63 == req_59_from_55)
print(f"\n    x58 constraints consistent? {x58_consistent} (from_62={req_58_from_62}, from_54={req_58_from_54})")
print(f"    x59 constraints consistent? {x59_consistent} (from_63={req_59_from_63}, from_55={req_59_from_55})")

# If consistent, the values are UNIQUELY DETERMINED by Delta4=5
if x58_consistent and x59_consistent:
    print(f"\n    *** BOTH VALUES UNIQUELY DETERMINED BY DELTA4=5 ***")
    print(f"    The ONLY values that produce constant lag-4 difference of 5 at positions 55-63:")
    print(f"    x58 = {req_58_from_62} = {chr(req_58_from_62+65)} (actual: {CT[58]})")
    print(f"    x59 = {req_59_from_63} = {chr(req_59_from_63+65)} (actual: {CT[59]})")
    x58_match = (ct_nums[58] == req_58_from_62)
    x59_match = (ct_nums[59] == req_59_from_63)
    print(f"    x58 matches actual? {x58_match}")
    print(f"    x59 matches actual? {x59_match}")
    if x58_match and x59_match:
        print(f"\n    >>> THE NULL CHARACTERS AT 58,59 ARE THE UNIQUE SOLUTION TO DELTA4=5 <<<")
        print(f"    >>> This means the null insertion CREATED this pattern by choosing exactly W,I <<<")
else:
    print(f"\n    Constraints are INCONSISTENT -- Delta4=5 requires DIFFERENT values")
    print(f"    from the two constraint sources. Checking...")
    # Check what actually happens
    for x58 in range(26):
        for x59 in range(26):
            test = list(ct_nums[54:64])
            test[4] = x58  # position 58 = index 4 in [54:64]
            test[5] = x59  # position 59 = index 5 in [54:64]
            # Check lag-4 diffs at positions 55-59 (pairs to 59-63)
            # But we need positions 55-63 = indices 1-9 in the [54:64] window
            region_test = test[1:10]  # positions 55-63
            lag4_diffs = [(region_test[i+4] - region_test[i]) % 26 for i in range(5)]
            if len(set(lag4_diffs)) == 1 and lag4_diffs[0] == 5:
                print(f"    SOLUTION: x58={x58}({chr(x58+65)}), x59={x59}({chr(x59+65)})")

# 3b. What about Delta4 with other constant values (not just 5)?
print(f"\n3b. What values at {58,59} produce constant Delta4 for ANY delta value?")
solutions_by_delta = {}
for delta in range(26):
    for x58 in range(26):
        for x59 in range(26):
            test = list(ct_nums[55:64])
            test[3] = x58  # position 58 = index 3 in [55:64]
            test[4] = x59  # position 59 = index 4 in [55:64]
            lag4_diffs = [(test[i+4] - test[i]) % 26 for i in range(5)]
            if len(set(lag4_diffs)) == 1 and lag4_diffs[0] == delta:
                if delta not in solutions_by_delta:
                    solutions_by_delta[delta] = []
                solutions_by_delta[delta].append((x58, x59))

print(f"  {'delta':>6} {'n_solutions':>12} {'solutions (x58,x59)':>40}")
for delta in range(26):
    sols = solutions_by_delta.get(delta, [])
    sol_str = ', '.join(f"({chr(a+65)},{chr(b+65)})" for a, b in sols[:5])
    if len(sols) > 5:
        sol_str += f"... (+{len(sols)-5} more)"
    actual_flag = " <<<ACTUAL" if delta == 5 else ""
    print(f"  {delta:6d}({chr(delta+65)}) {len(sols):12d} {sol_str:>40}{actual_flag}")

# Count how many deltas have exactly 1 solution
single_solution_deltas = [d for d in range(26) if len(solutions_by_delta.get(d, [])) == 1]
print(f"\n  Deltas with exactly 1 solution: {single_solution_deltas}")
print(f"  Delta=5 has {len(solutions_by_delta.get(5, []))} solution(s)")

# 3c. Do other null positions also participate in constant-Delta patterns?
print(f"\n3c. Do other null positions participate in constant-delta patterns?")
print(f"  For each null position p, check if removing p from CT breaks or creates")
print(f"  any constant-delta runs of length >= 5 in a window centered on p.")

for p in CONSENSUS_NULLS_17:
    # Check a window around p for constant-delta at various lags
    for lag in range(1, 9):
        # Check if position p is ESSENTIAL for a constant-delta run at this lag
        # Look at the lag-differences involving position p
        # Position p appears in pair (p-lag, p) and (p, p+lag) if both in range

        # Find the maximal run of constant lag-diffs that INCLUDES p
        full_diffs = [(ct_nums[j+lag] - ct_nums[j]) % 26 for j in range(N - lag)]

        # p contributes to diff at index p-lag (pair p-lag, p) and index p (pair p, p+lag)
        # Find the run containing index p (if p < N-lag) or p-lag (if p >= lag)
        for idx in [p - lag, p]:
            if idx < 0 or idx >= N - lag:
                continue
            # Find the constant run containing idx
            val = full_diffs[idx]
            # Extend left
            left = idx
            while left > 0 and full_diffs[left-1] == val:
                left -= 1
            # Extend right
            right = idx
            while right < len(full_diffs)-1 and full_diffs[right+1] == val:
                right += 1
            run_len = right - left + 1
            if run_len >= 5:
                # This is a significant run. Does it include a null position?
                positions_in_run = list(range(left, right + 1 + lag))
                null_in_run = [pp for pp in positions_in_run if pp in set(CONSENSUS_NULLS_17)]
                if len(null_in_run) > 0:
                    print(f"  pos {p}, lag {lag}: run of {run_len} constant diffs ({val}={chr(val+65)}) "
                          f"at indices {left}-{right}, positions {left}-{right+lag}")
                    print(f"    Null positions in run: {null_in_run}")
                    break  # Don't print duplicates for same null + lag

results['findings']['task3'] = {
    'x58_consistent': x58_consistent if 'x58_consistent' in dir() else None,
    'x59_consistent': x59_consistent if 'x59_consistent' in dir() else None,
    'solutions_by_delta': {d: len(v) for d, v in solutions_by_delta.items()},
    'single_solution_deltas': single_solution_deltas,
}

# ========================================================================
# TASK 4: GLOBAL ARITHMETIC FINGERPRINT
# ========================================================================
print("\n" + "=" * 80)
print("TASK 4: GLOBAL ARITHMETIC FINGERPRINT — ARE NULLS 'BRIDGES'?")
print("=" * 80)

print(f"\nFor each position p in CT, take a window of +/-4 positions.")
print(f"Check ALL lags (1-8) for constant differences within the window.")
print(f"Compare: how many constant-delta windows INCLUDE a null position?")

# For each position, check if it's in ANY constant-delta window (run >= 5)
null_set = set(CONSENSUS_NULLS_17)
pos_in_const_delta = set()

# Find ALL runs of >= 5 constant lag-diffs across the entire CT
all_runs = []
for lag in range(1, 9):
    diffs = [(ct_nums[j+lag] - ct_nums[j]) % 26 for j in range(N - lag)]
    # Find runs
    if not diffs:
        continue
    cur_start = 0
    cur_val = diffs[0]
    for j in range(1, len(diffs)):
        if diffs[j] != cur_val or j == len(diffs)-1:
            end = j if diffs[j] != cur_val else j + 1
            run_len = end - cur_start
            if run_len >= 4:  # 4 consecutive diffs = 5 values involved
                # Positions involved: cur_start to end-1 + lag
                positions = list(range(cur_start, end - 1 + lag + 1))
                null_in = [p for p in positions if p in null_set]
                all_runs.append({
                    'lag': lag, 'start': cur_start, 'end': end - 1,
                    'run_len': run_len, 'delta': cur_val,
                    'positions': positions, 'null_count': len(null_in),
                    'null_positions': null_in
                })
            cur_val = diffs[j]
            cur_start = j

print(f"\nAll runs of >= 4 constant lag-diffs:")
print(f"{'lag':>4} {'start':>6} {'end':>4} {'run':>4} {'delta':>6} {'positions':>30} {'nulls_in_run':>15}")
for r in sorted(all_runs, key=lambda x: -x['run_len']):
    pos_str = f"{r['positions'][0]}-{r['positions'][-1]}"
    null_str = str(r['null_positions']) if r['null_positions'] else "none"
    print(f"{r['lag']:4d} {r['start']:6d} {r['end']:4d} {r['run_len']:4d} {r['delta']:6d}({chr(r['delta']+65)}) {pos_str:>30} {null_str:>15}")

# Now: for a finer analysis, check each position's +/-4 window
print(f"\n--- Position-level analysis: each position's +/-4 window ---")
null_bridge_score = {}  # for each position, count of constant-delta patterns it participates in
for p in range(N):
    count = 0
    for lag in range(1, 9):
        for win_start in range(max(0, p - 4), min(N - lag, p + 1)):
            win_end = win_start + lag + 4  # need at least 5 positions
            if win_end > N:
                continue
            diffs = [(ct_nums[win_start + i + lag] - ct_nums[win_start + i]) % 26 for i in range(min(5, N - lag - win_start))]
            if len(diffs) >= 4 and len(set(diffs[:4])) == 1:
                count += 1
    null_bridge_score[p] = count

# Compare null vs non-null bridge scores
null_scores = [null_bridge_score[p] for p in CONSENSUS_NULLS_17]
nonnull_scores = [null_bridge_score[p] for p in range(N) if p not in null_set]

null_avg = sum(null_scores) / len(null_scores) if null_scores else 0
nonnull_avg = sum(nonnull_scores) / len(nonnull_scores) if nonnull_scores else 0

print(f"\nBridge score (# of constant-delta windows a position participates in):")
print(f"  Null positions: mean = {null_avg:.2f}, scores = {null_scores}")
print(f"  Non-null positions: mean = {nonnull_avg:.2f}")
print(f"  Ratio null/nonnull: {null_avg/nonnull_avg:.2f}x" if nonnull_avg > 0 else "  N/A")
print(f"  Top null scorers: {[(p, null_bridge_score[p]) for p in sorted(CONSENSUS_NULLS_17, key=lambda p: -null_bridge_score[p])[:5]]}")
print(f"  Top non-null scorers: {[(p, null_bridge_score[p]) for p in sorted([p for p in range(N) if p not in null_set], key=lambda p: -null_bridge_score[p])[:5]]}")

# Monte Carlo: pick 17 random positions, what's their average bridge score?
MC_TRIALS = 100000
random.seed(42)
mc_null_avgs = []
for _ in range(MC_TRIALS):
    rand_positions = random.sample(range(N), 17)
    rand_avg = sum(null_bridge_score[p] for p in rand_positions) / 17
    mc_null_avgs.append(rand_avg)

mc_null_avgs.sort()
# Where does the actual null average fall?
percentile = sum(1 for x in mc_null_avgs if x <= null_avg) / MC_TRIALS
print(f"\n  Monte Carlo ({MC_TRIALS:,} random 17-position sets):")
print(f"    Actual null avg bridge score: {null_avg:.2f}")
print(f"    MC distribution: mean={sum(mc_null_avgs)/len(mc_null_avgs):.2f}, "
      f"median={mc_null_avgs[len(mc_null_avgs)//2]:.2f}, "
      f"std={sqrt(sum((x - sum(mc_null_avgs)/len(mc_null_avgs))**2 for x in mc_null_avgs)/len(mc_null_avgs)):.2f}")
print(f"    Percentile of actual: {percentile:.4f} ({percentile*100:.2f}%)")
if percentile > 0.95:
    print(f"    >>> SIGNIFICANT: Null positions have HIGHER bridge scores than random (p={1-percentile:.4f})")
elif percentile < 0.05:
    print(f"    >>> SIGNIFICANT: Null positions have LOWER bridge scores than random (p={percentile:.4f})")
else:
    print(f"    Not significant (p={min(percentile, 1-percentile):.4f})")

results['findings']['task4'] = {
    'null_avg_bridge': null_avg,
    'nonnull_avg_bridge': nonnull_avg,
    'percentile': percentile,
    'n_runs_ge4': len(all_runs),
}

# ========================================================================
# TASK 5: NULL CHARACTERS AS A CIPHER
# ========================================================================
print("\n" + "=" * 80)
print("TASK 5: NULL CHARACTERS AS A SEPARATE CIPHER")
print("=" * 80)

# 5a. The 17 consensus null characters
print(f"\n5a. 17 consensus null characters: {null_text_17}")
print(f"    Numeric: {null_chars_17}")

# Caesar shifts
print(f"\n--- Caesar shifts on 17-char null text ---")
print(f"  {'shift':>6} {'plaintext':>20} {'qg_score':>10}")
best_caesar = []
for shift in range(26):
    pt = ''.join(chr((v - shift) % 26 + 65) for v in null_chars_17)
    sc = qg_score(pt)
    best_caesar.append((sc, shift, pt))
best_caesar.sort(reverse=True)
for sc, shift, pt in best_caesar[:10]:
    print(f"  {shift:6d}({chr(shift+65)}) {pt:>20} {sc:10.3f}")

# Vigenere with short keys (1-8)
print(f"\n--- Vigenere decryption on 17-char null text (key lengths 1-5) ---")
best_vig = []
for kl in range(1, 6):
    for key_tuple in (range(26**kl) if kl <= 3 else []):
        # Enumerate all keys for kl <= 3
        key = []
        tmp = key_tuple
        for _ in range(kl):
            key.append(tmp % 26)
            tmp //= 26
        pt_nums = [(null_chars_17[i] - key[i % kl]) % 26 for i in range(len(null_chars_17))]
        pt = ''.join(chr(v+65) for v in pt_nums)
        sc = qg_score(pt)
        if sc > -7.0:
            best_vig.append((sc, ''.join(chr(k+65) for k in key), pt, kl))

    if kl >= 4:
        # Too many keys to enumerate; try thematic keywords
        thematic = ['KRYPTOS', 'DEFECTOR', 'ABSCISSA', 'SHADOW', 'EAST', 'NORTH',
                     'BERLIN', 'CLOCK', 'PALIMPSEST', 'FIVE', 'YAR', 'SHAW',
                     'KOMPASS', 'COLOPHON', 'SANBORN', 'SCHEIDT', 'MEDUSA',
                     'ENIGMA', 'NULL', 'MASK', 'GRILLE', 'STEGO']
        for kw_text in thematic:
            if len(kw_text) != kl:
                continue
            key = [ALPH_IDX[c] for c in kw_text]
            pt_nums = [(null_chars_17[i] - key[i % kl]) % 26 for i in range(len(null_chars_17))]
            pt = ''.join(chr(v+65) for v in pt_nums)
            sc = qg_score(pt)
            if sc > -7.5:
                best_vig.append((sc, kw_text, pt, kl))

best_vig.sort(reverse=True)
print(f"  Top 15 (qg > -7.0 or thematic):")
print(f"  {'score':>8} {'key':>12} {'plaintext':>20} {'kl':>3}")
for sc, key, pt, kl in best_vig[:15]:
    print(f"  {sc:8.3f} {key:>12} {pt:>20} {kl:3d}")

# Beaufort
print(f"\n--- Beaufort decryption on 17-char null text (key lengths 1-3) ---")
best_beau = []
for kl in range(1, 4):
    for key_tuple in range(26**kl):
        key = []
        tmp = key_tuple
        for _ in range(kl):
            key.append(tmp % 26)
            tmp //= 26
        pt_nums = [(key[i % kl] - null_chars_17[i]) % 26 for i in range(len(null_chars_17))]
        pt = ''.join(chr(v+65) for v in pt_nums)
        sc = qg_score(pt)
        if sc > -7.0:
            best_beau.append((sc, ''.join(chr(k+65) for k in key), pt, kl))

best_beau.sort(reverse=True)
if best_beau:
    print(f"  Top 10:")
    for sc, key, pt, kl in best_beau[:10]:
        print(f"  {sc:8.3f} {key:>12} {pt:>20} {kl:3d}")
else:
    print(f"  No results above -7.0")

# Autokey (PT-autokey, Vigenere)
print(f"\n--- PT-Autokey Vigenere on 17-char null text (primers A-Z) ---")
best_autokey = []
for primer in range(26):
    pt_nums = []
    prev_pt = primer
    for i in range(len(null_chars_17)):
        key_val = prev_pt if i == 0 else pt_nums[i-1]
        pt_val = (null_chars_17[i] - key_val) % 26
        pt_nums.append(pt_val)
        prev_pt = pt_val
    pt = ''.join(chr(v+65) for v in pt_nums)
    sc = qg_score(pt)
    best_autokey.append((sc, chr(primer+65), pt))

best_autokey.sort(reverse=True)
print(f"  Top 10:")
for sc, primer, pt in best_autokey[:10]:
    print(f"  {sc:8.3f} primer={primer} {pt:>20}")

# 5b. 24 null characters (mask 0)
print(f"\n5b. 24 null characters (mask 0): {''.join(CT[p] for p in MASK_24_0)}")
print(f"    Numeric: {null_chars_24}")

# Caesar on 24-char
print(f"\n--- Caesar shifts on 24-char null text ---")
best_caesar_24 = []
for shift in range(26):
    pt = ''.join(chr((v - shift) % 26 + 65) for v in null_chars_24)
    sc = qg_score(pt)
    best_caesar_24.append((sc, shift, pt))
best_caesar_24.sort(reverse=True)
for sc, shift, pt in best_caesar_24[:5]:
    print(f"  {shift:6d}({chr(shift+65)}) {pt:>26} {sc:10.3f}")

# 5c. Read null chars using KRYPTOS alphabet (KA)
print(f"\n5c. Null chars read through KRYPTOS alphabet (KA):")
ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
null_ka_nums = [ka_idx[CT[p]] for p in CONSENSUS_NULLS_17]
print(f"    Standard (AZ): {null_chars_17}")
print(f"    Kryptos (KA):  {null_ka_nums}")
null_ka_text_via_az = ''.join(ALPH[v] for v in null_ka_nums)
print(f"    KA indices mapped back to AZ letters: {null_ka_text_via_az}")

results['findings']['task5'] = {
    'best_caesar_17': [(s, k, p) for s, k, p in best_caesar[:3]],
    'best_vig_17': [(s, k, p, l) for s, k, p, l in best_vig[:3]] if best_vig else [],
    'best_autokey_17': [(s, p, t) for s, p, t in best_autokey[:3]],
}

# ========================================================================
# TASK 6: POSITIONAL ENCODING
# ========================================================================
print("\n" + "=" * 80)
print("TASK 6: POSITIONAL ENCODING — DO NULL POSITIONS ENCODE SOMETHING?")
print("=" * 80)

# 6a. Differences between consecutive null positions
pos_diffs = [CONSENSUS_NULLS_17[i+1] - CONSENSUS_NULLS_17[i] for i in range(len(CONSENSUS_NULLS_17)-1)]
print(f"\n6a. Consecutive position differences: {pos_diffs}")
print(f"    Sum: {sum(pos_diffs)} (should = {CONSENSUS_NULLS_17[-1] - CONSENSUS_NULLS_17[0]})")
print(f"    Unique diffs: {sorted(set(pos_diffs))}")
print(f"    Mode: {Counter(pos_diffs).most_common()}")

# 6b. Sum of null positions
pos_sum = sum(CONSENSUS_NULLS_17)
print(f"\n6b. Sum of null positions: {pos_sum}")
print(f"    mod 26 = {pos_sum % 26} = {chr(pos_sum % 26 + 65)}")
print(f"    mod 97 = {pos_sum % 97}")
print(f"    mod 73 = {pos_sum % 73}")
print(f"    mod 24 = {pos_sum % 24}")

# 6c. Null positions mod various small numbers
print(f"\n6c. Null positions mod small numbers:")
for m in range(2, 14):
    residues = [p % m for p in CONSENSUS_NULLS_17]
    freq = Counter(residues)
    # Chi-squared against uniform
    expected = len(CONSENSUS_NULLS_17) / m
    chi2 = sum((freq.get(r, 0) - expected)**2 / expected for r in range(m))
    # Rough p-value (chi2 with m-1 df)
    # For quick check: chi2 > 2*m is notable
    notable = " <<<" if chi2 > 2 * m else ""
    print(f"    mod {m:2d}: residues={residues}, freq={dict(sorted(freq.items()))}, chi2={chi2:.2f}{notable}")

# 6d. Position differences as letters
print(f"\n6d. Position differences as letters (diff mod 26):")
diff_letters = ''.join(chr(d % 26 + 65) for d in pos_diffs)
print(f"    Diffs: {pos_diffs}")
print(f"    As letters: {diff_letters}")
print(f"    Reversed: {diff_letters[::-1]}")

# Also try: positions directly as letters (mod 26)
pos_as_letters = ''.join(chr(p % 26 + 65) for p in CONSENSUS_NULLS_17)
print(f"\n6e. Positions mod 26 as letters: {pos_as_letters}")

# 6f. Null positions as indices into CT
print(f"\n6f. Null positions as indices into KRYPTOS alphabet:")
for p in CONSENSUS_NULLS_17:
    if p < 26:
        print(f"    pos {p:2d} -> KA[{p}] = {KRYPTOS_ALPHABET[p]}")

# 6g. Pairs: (position, character value) -- any linear relationship?
print(f"\n6g. Linear regression: null_char = a * position + b (mod 26)?")
# Try all (a, b) mod 26
best_linear = []
for a in range(26):
    for b in range(26):
        matches = sum(1 for i, p in enumerate(CONSENSUS_NULLS_17) if (a * p + b) % 26 == null_chars_17[i])
        if matches >= 4:
            best_linear.append((matches, a, b))
best_linear.sort(reverse=True)
print(f"    Top 10:")
for matches, a, b in best_linear[:10]:
    pred = [(a * p + b) % 26 for p in CONSENSUS_NULLS_17]
    pred_text = ''.join(chr(v+65) for v in pred)
    print(f"    a={a:2d} b={b:2d}: {matches}/{len(CONSENSUS_NULLS_17)} matches, predicted: {pred_text}")

# 6h. Quadratic: null_char = a*p^2 + b*p + c (mod 26)?
print(f"\n6h. Quadratic: null_char = a*p^2 + b*p + c (mod 26)?")
best_quad = []
for a in range(26):
    for b in range(26):
        for c in range(26):
            matches = sum(1 for i, p in enumerate(CONSENSUS_NULLS_17) if (a * p * p + b * p + c) % 26 == null_chars_17[i])
            if matches >= 5:
                best_quad.append((matches, a, b, c))
best_quad.sort(reverse=True)
if best_quad:
    print(f"    Top 5 (>= 5 matches):")
    for matches, a, b, c in best_quad[:5]:
        print(f"    a={a:2d} b={b:2d} c={c:2d}: {matches}/{len(CONSENSUS_NULLS_17)} matches")
else:
    print(f"    No quadratic with >= 5 matches")

# 6i. Position gaps encode something?
# Gaps: 1,1,3,3,4,2,6,16,16,6,1,15,1,3,6,1
# These sum to 85 (=pos[16]-pos[0])
# Do they encode letters? Pairs?
print(f"\n6i. Gap analysis:")
print(f"    Gaps: {pos_diffs}")
print(f"    Gap pairs: {[(pos_diffs[i], pos_diffs[i+1]) for i in range(0, len(pos_diffs)-1, 2)]}")
# Note symmetry-like structure
print(f"    Reversed gaps: {pos_diffs[::-1]}")
# Check palindrome
is_palindrome = pos_diffs == pos_diffs[::-1]
print(f"    Is palindrome? {is_palindrome}")
# Check near-palindrome
diffs_with_reversed = list(zip(pos_diffs, pos_diffs[::-1]))
matches = sum(1 for a, b in diffs_with_reversed if a == b)
print(f"    Palindrome matches: {matches}/{len(pos_diffs)}")

# Note the structure: 1,1,3,3,4,2,6,  16,16,  6,1,15,1,3,6,1
# The center is 16,16 (at positions 36->52 and 52->58... wait 52-36=16, 58-52=6)
# Let me recalculate
print(f"\n    Gap decomposition:")
for i, (p, d) in enumerate(zip(CONSENSUS_NULLS_17[:-1], pos_diffs)):
    print(f"    [{i:2d}] pos {p:2d} -> pos {CONSENSUS_NULLS_17[i+1]:2d}: gap = {d}")

results['findings']['task6'] = {
    'position_diffs': pos_diffs,
    'pos_sum': pos_sum,
    'pos_sum_mod26': pos_sum % 26,
    'pos_sum_mod97': pos_sum % 97,
    'best_linear': [(m, a, b) for m, a, b in best_linear[:3]],
}

# ========================================================================
# TASK 7: INTERACTION WITH KNOWN CONSTANTS
# ========================================================================
print("\n" + "=" * 80)
print("TASK 7: INTERACTION WITH KNOWN CONSTANTS")
print("=" * 80)

# DEFECTOR key values (from DEFECTOR:AZ_beau)
DEFECTOR = [ALPH_IDX[c] for c in 'DEFECTOR']  # [3,4,5,4,2,19,14,17]
print(f"\n7a. DEFECTOR key: {'DEFECTOR'} = {DEFECTOR}")

# XOR null chars with DEFECTOR (cycling)
print(f"\n--- Null chars XOR DEFECTOR (cycling) ---")
xor_result = [(null_chars_17[i] ^ DEFECTOR[i % len(DEFECTOR)]) % 26 for i in range(len(null_chars_17))]
xor_text = ''.join(chr(v+65) for v in xor_result)
print(f"  XOR: {xor_result} = {xor_text}")

# Add null chars + DEFECTOR
add_result = [(null_chars_17[i] + DEFECTOR[i % len(DEFECTOR)]) % 26 for i in range(len(null_chars_17))]
add_text = ''.join(chr(v+65) for v in add_result)
print(f"  ADD: {add_result} = {add_text}")

# Subtract
sub_result = [(null_chars_17[i] - DEFECTOR[i % len(DEFECTOR)]) % 26 for i in range(len(null_chars_17))]
sub_text = ''.join(chr(v+65) for v in sub_result)
print(f"  SUB: {sub_result} = {sub_text}")

# Beaufort
beau_result = [(DEFECTOR[i % len(DEFECTOR)] - null_chars_17[i]) % 26 for i in range(len(null_chars_17))]
beau_text = ''.join(chr(v+65) for v in beau_result)
print(f"  BEAU: {beau_result} = {beau_text}")

# Score these
for label, text in [("XOR", xor_text), ("ADD", add_text), ("SUB", sub_text), ("BEAU", beau_text)]:
    sc = qg_score(text)
    print(f"  {label} quadgram: {sc:.3f}")

# 7b. Try all thematic keywords, not just DEFECTOR
print(f"\n7b. All thematic keywords decrypting null chars:")
thematic_kws = ['KRYPTOS', 'DEFECTOR', 'ABSCISSA', 'SHADOW', 'PALIMPSEST', 'FIVE',
                'KOMPASS', 'COLOPHON', 'SANBORN', 'SCHEIDT', 'MEDUSA', 'ENIGMA',
                'BERLIN', 'CLOCK', 'EAST', 'NORTH', 'SHAW', 'YAR', 'GRILLE',
                'PARALLAX', 'MASQUERADE', 'UNDERGRUUND', 'DESPERATELY']
best_kw_results = []
for kw in thematic_kws:
    kw_nums = [ALPH_IDX[c] for c in kw]
    for mode_name, mode_fn in [
        ('vig', lambda c, k: (c - k) % 26),
        ('beau', lambda c, k: (k - c) % 26),
        ('add', lambda c, k: (c + k) % 26),
    ]:
        pt_nums = [mode_fn(null_chars_17[i], kw_nums[i % len(kw_nums)]) for i in range(len(null_chars_17))]
        pt = ''.join(chr(v+65) for v in pt_nums)
        sc = qg_score(pt)
        best_kw_results.append((sc, kw, mode_name, pt))

best_kw_results.sort(reverse=True)
print(f"  Top 15:")
print(f"  {'score':>8} {'keyword':>15} {'mode':>5} {'plaintext':>20}")
for sc, kw, mode, pt in best_kw_results[:15]:
    print(f"  {sc:8.3f} {kw:>15} {mode:>5} {pt:>20}")

# 7c. Do null CHARACTER values relate to KRYPTOS alphabet positions?
print(f"\n7c. Null chars in KRYPTOS alphabet ordering:")
print(f"    AZ order: {null_chars_17}")
print(f"    KA order: {null_ka_nums}")
ka_diffs = [(null_ka_nums[i+1] - null_ka_nums[i]) % 26 for i in range(len(null_ka_nums)-1)]
print(f"    KA consecutive diffs: {ka_diffs}")
print(f"    KA unique diffs: {sorted(set(ka_diffs))}")

# 7d. Null POSITIONS in the 28x31 grid
print(f"\n7d. Null positions in 28x31 grid:")
# K4 starts at row 24, col 27 in the 28x31 grid
# But we need the offset. K4 is the last 97 chars of the bottom 14 rows (K3+K4 = 434 chars)
# Bottom 14 rows = rows 14-27 of the 28x31 grid = 434 chars
# K3 = 336 chars, then some filler, then K4 = 97 chars
# K4 position in grid: first char at (14*31 + ... )
# Actually: all 868 chars in the grid. K4 starts at position 868-97 = 771 in the flat grid
# Grid position 771: row = 771 // 31 = 24 (0-indexed), col = 771 % 31 = 27
K4_GRID_OFFSET = 868 - 97  # = 771
print(f"    K4 starts at grid position {K4_GRID_OFFSET} (row {K4_GRID_OFFSET//31}, col {K4_GRID_OFFSET%31})")
for p in CONSENSUS_NULLS_17:
    grid_pos = K4_GRID_OFFSET + p
    row = grid_pos // 31
    col = grid_pos % 31
    print(f"    K4 pos {p:2d} -> grid ({row},{col:2d})")

# Check: do null positions form a pattern in the grid?
null_rows = [(K4_GRID_OFFSET + p) // 31 for p in CONSENSUS_NULLS_17]
null_cols = [(K4_GRID_OFFSET + p) % 31 for p in CONSENSUS_NULLS_17]
print(f"\n    Null rows: {null_rows}")
print(f"    Null cols: {null_cols}")
print(f"    Row frequency: {dict(Counter(null_rows))}")
print(f"    Col frequency: {dict(Counter(null_cols))}")

# Check: columns of null positions
# Are certain columns preferentially null?
print(f"\n    Column distribution of nulls (17 of 97 positions ~ 17.5% rate):")
for col in sorted(set(null_cols)):
    count = null_cols.count(col)
    # How many K4 chars are in this column total?
    total_in_col = sum(1 for p in range(97) if (K4_GRID_OFFSET + p) % 31 == col)
    rate = count / total_in_col if total_in_col > 0 else 0
    flag = " <<<" if count >= 3 else ""
    print(f"    Col {col:2d}: {count} nulls / {total_in_col} total = {rate:.0%}{flag}")

# 7e. Do null positions relate to Bean equality/inequality positions?
print(f"\n7e. Null positions vs Bean constraints:")
bean_eq_pos = {27, 65}
bean_ineq_pos = set()
from kryptos.kernel.constants import BEAN_INEQ
for a, b in BEAN_INEQ:
    bean_ineq_pos.add(a)
    bean_ineq_pos.add(b)
null_in_bean_eq = null_set & bean_eq_pos
null_in_bean_ineq = null_set & bean_ineq_pos
crib_positions = set(CRIB_DICT.keys())
null_in_crib = null_set & crib_positions
print(f"    Null positions in Bean EQ positions (27,65): {null_in_bean_eq}")
print(f"    Null positions in crib positions: {null_in_crib}")
print(f"    Null positions NOT in any crib: {null_set - crib_positions}")

# 7f. Null characters vs the BEAUFORT keystream at known positions
print(f"\n7f. Null position characters vs Vigenere/Beaufort keystream:")
# The known keystream (from CRIB_DICT) doesn't include null positions (which are non-crib).
# But we can check: for the neighbors of nulls that ARE crib positions,
# does the null char relate to the known key at the neighbor?
from kryptos.kernel.constants import VIGENERE_KEY_ENE, VIGENERE_KEY_BC, BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC

crib_key_vig = {}
for i, pos in enumerate(range(21, 34)):
    crib_key_vig[pos] = VIGENERE_KEY_ENE[i]
for i, pos in enumerate(range(63, 74)):
    crib_key_vig[pos] = VIGENERE_KEY_BC[i]

crib_key_beau = {}
for i, pos in enumerate(range(21, 34)):
    crib_key_beau[pos] = BEAUFORT_KEY_ENE[i]
for i, pos in enumerate(range(63, 74)):
    crib_key_beau[pos] = BEAUFORT_KEY_BC[i]

print(f"    Null pos -> nearest crib neighbor -> key relationship:")
for p in CONSENSUS_NULLS_17:
    # Find nearest crib positions
    nearest_crib = None
    min_dist = 999
    for cp in crib_positions:
        dist = abs(p - cp)
        if dist < min_dist and dist > 0:
            min_dist = dist
            nearest_crib = cp
    if nearest_crib is not None and min_dist <= 3:
        kv = crib_key_vig.get(nearest_crib, '?')
        kb = crib_key_beau.get(nearest_crib, '?')
        diff_vig = (ct_nums[p] - kv) % 26 if isinstance(kv, int) else '?'
        diff_beau = (ct_nums[p] - kb) % 26 if isinstance(kb, int) else '?'
        print(f"    null@{p:2d}={CT[p]}({ct_nums[p]:2d}), nearest_crib@{nearest_crib}(dist={min_dist}), "
              f"k_vig={kv}, null-k_vig={diff_vig}, k_beau={kb}, null-k_beau={diff_beau}")

# 7g. Check if null characters spell something through a substitution cipher
# defined by the KRYPTOS keyword
print(f"\n7g. Null chars through keyed-alphabet substitution:")
# KA maps: A->K, B->R, C->Y, D->P, E->T, F->O, ...
# Forward: standard letter -> KA position
# Reverse: KA position -> standard letter
ka_forward = {ALPH[i]: KRYPTOS_ALPHABET[i] for i in range(26)}
ka_reverse = {KRYPTOS_ALPHABET[i]: ALPH[i] for i in range(26)}
null_via_ka_fwd = ''.join(ka_forward[CT[p]] for p in CONSENSUS_NULLS_17)
null_via_ka_rev = ''.join(ka_reverse[CT[p]] for p in CONSENSUS_NULLS_17)
print(f"    Raw null chars: {null_text_17}")
print(f"    Via KA forward (std->KA): {null_via_ka_fwd}")
print(f"    Via KA reverse (KA->std): {null_via_ka_rev}")
print(f"    Via KA forward qg: {qg_score(null_via_ka_fwd):.3f}")
print(f"    Via KA reverse qg: {qg_score(null_via_ka_rev):.3f}")

results['findings']['task7'] = {
    'best_kw_results': [(s, k, m, p) for s, k, m, p in best_kw_results[:5]],
    'null_grid_rows': null_rows,
    'null_grid_cols': null_cols,
}

# ========================================================================
# BONUS: CROSS-TASK SYNTHESIS
# ========================================================================
print("\n" + "=" * 80)
print("SYNTHESIS: KEY FINDINGS")
print("=" * 80)

print(f"""
TASK 1 (Arithmetic patterns):
  - Null chars: {null_text_17} = {null_chars_17}
  - IC = {null_ic:.4f} (random = {1/26:.4f}, English = 0.0667)
  - No constant-difference sequence at any lag
  - Fibonacci hits: {fib_hits}/{len(null_chars_17)-2} (expected ~{(len(null_chars_17)-2)/26:.1f})

TASK 2 (Neighbors):
  - AP matches: {ap_count}/{n_interior} (expected ~{n_interior/26:.1f})
  - Mean matches: {mean_count}/{n_interior}
  - Sum matches: {sum_count}/{n_interior}

TASK 3 (Delta4=5 mechanism):
  - x58 constraints consistent: {x58_consistent if 'x58_consistent' in dir() else 'N/A'}
  - x59 constraints consistent: {x59_consistent if 'x59_consistent' in dir() else 'N/A'}
  - Delta=5 has {len(solutions_by_delta.get(5, []))} solution pair(s) for (x58,x59)
  - Deltas with exactly 1 solution: {single_solution_deltas}

TASK 4 (Bridge scores):
  - Null avg bridge score: {null_avg:.2f}
  - Non-null avg bridge score: {nonnull_avg:.2f}
  - MC percentile: {percentile:.4f}
  - {'SIGNIFICANT' if percentile > 0.95 or percentile < 0.05 else 'Not significant'}

TASK 5 (Cipher):
  - Best Caesar on 17-char null: {best_caesar[0][2]} (shift={best_caesar[0][1]}, qg={best_caesar[0][0]:.3f})
  - Best keyword decryption: {best_kw_results[0][1]}:{best_kw_results[0][2]} -> {best_kw_results[0][3]} (qg={best_kw_results[0][0]:.3f})
  - All decryptions in noise range (English ~ -4.2/char)

TASK 6 (Position encoding):
  - Position diffs: {pos_diffs}
  - Sum of positions: {pos_sum} (mod 26={pos_sum%26}={chr(pos_sum%26+65)}, mod 97={pos_sum%97})

TASK 7 (Constants):
  - DEFECTOR Vigenere on null chars: {sub_text} (qg={qg_score(sub_text):.3f})
  - KA forward: {null_via_ka_fwd}
  - KA reverse: {null_via_ka_rev}
""")

# Write results
results_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'null_insertion_structure.json')
os.makedirs(os.path.dirname(results_path), exist_ok=True)
with open(results_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"Results written to: {results_path}")
print("=== DONE ===")
