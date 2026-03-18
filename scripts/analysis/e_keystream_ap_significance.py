#!/usr/bin/env python3
"""
Cipher: Beaufort (statistical analysis)
Family: analysis
Status: active
Keyspace: N/A (Monte Carlo)
Last run: 2026-03-16
Best score: N/A
"""
"""KEYSTREAM AP SIGNIFICANCE: Monte Carlo significance test for f(PT, pos mod p).

Critical question: Is the period-6 consistency of f(PT, pos mod 6) statistically
significant, or is it expected by chance given 24 constraints in 156 cells?

Method: Generate 1M random keystreams of length 24 (uniform mod 26) assigned to
the same 24 crib positions. Check what fraction are consistent with f(PT, pos mod p)
for each period p. Compare observed (consistency at p=6) vs. random baseline.

Also: deeper analysis of the AP pattern itself -- what's the probability that
12/24 values fall in an arithmetic progression of length 3, step 4?
"""

import json, sys, os, time, math, random
from collections import Counter, defaultdict

# ── Constants ──────────────────────────────────────────────────────────
CT97 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
N2L = {i: c for i, c in enumerate(AZ)}

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

BEAU_KEY = {pos: (CT_NUMS[pos] + PT_AT_POS[pos]) % 26 for pos in CRIB_POSITIONS}

results = {}
t0 = time.time()

print("=" * 80)
print("KEYSTREAM AP SIGNIFICANCE TESTS")
print("=" * 80)

# ═══════════════════════════════════════════════════════════════════════
# TEST 1: Monte Carlo for f(PT, pos mod p) consistency
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("TEST 1: Monte Carlo significance of f(PT, pos mod p) consistency")
print("=" * 70)

N_TRIALS = 500_000
random.seed(42)

# For each period, count how many random keystreams are consistent
period_hit_counts = defaultdict(int)

sorted_crib_pos = sorted(CRIB_POSITIONS)
pt_at_sorted = [PT_AT_POS[p] for p in sorted_crib_pos]

for trial in range(N_TRIALS):
    # Random keystream: 24 random values mod 26
    rand_keys = [random.randint(0, 25) for _ in range(24)]

    for period in range(2, 14):
        mapping = defaultdict(set)
        consistent = True
        for idx, pos in enumerate(sorted_crib_pos):
            pt_val = pt_at_sorted[idx]
            res = pos % period
            key_pair = (pt_val, res)
            if key_pair in mapping:
                if rand_keys[idx] not in mapping[key_pair]:
                    consistent = False
                    break
            mapping[key_pair].add(rand_keys[idx])
        if consistent:
            period_hit_counts[period] += 1

print(f"\n  {N_TRIALS:,} random keystreams tested")
print(f"\n  Period  P(consistent)  Observed(K4)  Significance")
print(f"  ------  -------------  ------------  ------------")
for period in range(2, 14):
    p_random = period_hit_counts[period] / N_TRIALS
    observed = "YES" if period >= 6 else "NO"
    if period >= 6 and p_random > 0:
        significance = f"1 in {1/p_random:.0f}"
    elif period >= 6:
        significance = f"< 1 in {N_TRIALS}"
    else:
        significance = "N/A (not consistent)"
    print(f"  p={period:2d}    {p_random:.6f}       {observed:3s}          {significance}")

# ═══════════════════════════════════════════════════════════════════════
# TEST 2: Monte Carlo for IC >= 0.0797
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("TEST 2: Monte Carlo significance of IC = 0.0797 for 24 values")
print("=" * 70)

observed_ic = 0.0797
ic_hits = 0
for trial in range(N_TRIALS):
    rand_keys = [random.randint(0, 25) for _ in range(24)]
    freq = Counter(rand_keys)
    n = 24
    ic_val = sum(f*(f-1) for f in freq.values()) / (n*(n-1))
    if ic_val >= observed_ic:
        ic_hits += 1

p_ic = ic_hits / N_TRIALS
print(f"  P(IC >= {observed_ic}) = {p_ic:.6f} = 1 in {1/p_ic:.0f}" if p_ic > 0 else f"  P(IC >= {observed_ic}) < 1 in {N_TRIALS}")

# ═══════════════════════════════════════════════════════════════════════
# TEST 3: Monte Carlo for 12/24 in a 3-value AP with step 4
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("TEST 3: Probability that >= 12/24 values fall in some 3-term AP")
print("=" * 70)

ap_hits = 0
for trial in range(N_TRIALS):
    rand_keys = [random.randint(0, 25) for _ in range(24)]
    # Check all possible 3-term APs: start s, step d, values s, s+d, s+2d (mod 26)
    best_ap_count = 0
    for s in range(26):
        for d in range(1, 26):
            ap_set = {s, (s+d) % 26, (s+2*d) % 26}
            if len(ap_set) < 3:
                continue  # degenerate
            count = sum(1 for k in rand_keys if k in ap_set)
            if count > best_ap_count:
                best_ap_count = count
    if best_ap_count >= 12:
        ap_hits += 1

p_ap = ap_hits / N_TRIALS
print(f"  P(best 3-term AP covers >= 12/24) = {p_ap:.6f} = 1 in {1/p_ap:.0f}" if p_ap > 0 else f"  P < 1/{N_TRIALS}")

# Also test specifically: >= 12/24 values in {6, 10, 14}
specific_ap_hits = 0
for trial in range(N_TRIALS):
    rand_keys = [random.randint(0, 25) for _ in range(24)]
    count = sum(1 for k in rand_keys if k in {6, 10, 14})
    if count >= 12:
        specific_ap_hits += 1

p_specific = specific_ap_hits / N_TRIALS
print(f"  P(>= 12/24 in specifically {{6,10,14}}) = {p_specific:.6f}" +
      (f" = 1 in {1/p_specific:.0f}" if p_specific > 0 else f" < 1/{N_TRIALS}"))

# Expected count of values in a specific 3-element set: 24 * 3/26 = 2.769
# Binomial: P(X >= 12) where X ~ Binomial(24, 3/26)
from math import comb
binom_p = sum(comb(24, k) * (3/26)**k * (23/26)**(24-k) for k in range(12, 25))
print(f"  Analytical (Binomial): P(X >= 12 | n=24, p=3/26) = {binom_p:.2e}")

# ═══════════════════════════════════════════════════════════════════════
# TEST 4: Same-PT clustering significance (more rigorous)
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("TEST 4: Same-PT key clustering significance")
print("=" * 70)

# For same-PT pairs in the ACTUAL cribs, compute key differences
same_pt_pairs = []
for pt_val in set(PT_AT_POS.values()):
    positions = sorted(p for p in CRIB_POSITIONS if PT_AT_POS[p] == pt_val)
    if len(positions) >= 2:
        for i in range(len(positions)):
            for j in range(i+1, len(positions)):
                same_pt_pairs.append((positions[i], positions[j]))

observed_total_diff = sum(min((BEAU_KEY[a] - BEAU_KEY[b]) % 26, (BEAU_KEY[b] - BEAU_KEY[a]) % 26) for a, b in same_pt_pairs)
n_pairs = len(same_pt_pairs)
observed_avg_diff = observed_total_diff / n_pairs

print(f"  Same-PT pairs: {n_pairs}")
print(f"  Observed average circular key difference: {observed_avg_diff:.3f}")
print(f"  Expected random: 6.5")

# Monte Carlo
mc_hits = 0
for trial in range(N_TRIALS):
    rand_keys = [random.randint(0, 25) for _ in range(24)]
    rand_key_dict = {pos: rand_keys[idx] for idx, pos in enumerate(sorted_crib_pos)}
    total_diff = sum(min((rand_key_dict[a] - rand_key_dict[b]) % 26, (rand_key_dict[b] - rand_key_dict[a]) % 26) for a, b in same_pt_pairs)
    avg_diff = total_diff / n_pairs
    if avg_diff <= observed_avg_diff:
        mc_hits += 1

p_cluster = mc_hits / N_TRIALS
print(f"  P(avg_diff <= {observed_avg_diff:.3f}) = {p_cluster:.6f} = 1 in {1/p_cluster:.0f}" if p_cluster > 0 else f"  P < 1/{N_TRIALS}")

# ═══════════════════════════════════════════════════════════════════════
# TEST 5: Period-13 cross-check: 3/11 matches between ENE and BCL
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("TEST 5: Period-13 cross-check (3/11 residue matches)")
print("=" * 70)

# ENE covers residues 0-12 mod 13. BCL covers 11 of 13 residues.
# At shared residues, 3 match.
# Monte Carlo: given the ACTUAL crib structure (same positions, same PT letters),
# generate random keystreams and count matches at shared residues mod 13.

ene_keys = {pos % 13: BEAU_KEY[pos] for pos in range(ENE_START, ENE_START + len(ENE_TEXT))}
bcl_keys = {}
for pos in range(BCL_START, BCL_START + len(BCL_TEXT)):
    r = pos % 13
    bcl_keys[r] = BEAU_KEY[pos]

shared_residues = set(ene_keys.keys()) & set(bcl_keys.keys())
observed_matches_13 = sum(1 for r in shared_residues if ene_keys[r] == bcl_keys[r])

mc_hits_13 = 0
for trial in range(N_TRIALS):
    rand_keys = [random.randint(0, 25) for _ in range(24)]
    rand_ene = {}
    rand_bcl = {}
    for idx, pos in enumerate(range(ENE_START, ENE_START + len(ENE_TEXT))):
        rand_ene[pos % 13] = rand_keys[idx]
    for idx2, pos in enumerate(range(BCL_START, BCL_START + len(BCL_TEXT))):
        rand_bcl[pos % 13] = rand_keys[13 + idx2]
    shared = set(rand_ene.keys()) & set(rand_bcl.keys())
    matches = sum(1 for r in shared if rand_ene[r] == rand_bcl[r])
    if matches >= observed_matches_13:
        mc_hits_13 += 1

p_13 = mc_hits_13 / N_TRIALS
print(f"  Shared residues mod 13: {len(shared_residues)}")
print(f"  Observed matches: {observed_matches_13}")
print(f"  P(>= {observed_matches_13} matches) = {p_13:.6f} = 1 in {1/p_13:.0f}" if p_13 > 0 else f"  P < 1/{N_TRIALS}")

# ═══════════════════════════════════════════════════════════════════════
# TEST 6: Combined significance -- how often does a random keystream
# have ALL of: IC >= 0.0797 AND f(PT,pos%6) consistent AND >= 12/24 in a 3-term AP?
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("TEST 6: Joint significance of all observed patterns")
print("=" * 70)

joint_hits = 0
for trial in range(N_TRIALS):
    rand_keys = [random.randint(0, 25) for _ in range(24)]

    # IC check
    freq = Counter(rand_keys)
    n = 24
    ic_val = sum(f*(f-1) for f in freq.values()) / (n*(n-1))
    if ic_val < 0.0797:
        continue

    # f(PT, pos%6) consistency check
    mapping = defaultdict(set)
    consistent = True
    for idx, pos in enumerate(sorted_crib_pos):
        pt_val = pt_at_sorted[idx]
        res = pos % 6
        key_pair = (pt_val, res)
        if key_pair in mapping:
            if rand_keys[idx] not in mapping[key_pair]:
                consistent = False
                break
        mapping[key_pair].add(rand_keys[idx])
    if not consistent:
        continue

    # AP check: >= 12/24 in some 3-term AP
    best_ap_count = 0
    for s in range(26):
        for d in range(1, 26):
            ap_set = {s, (s+d) % 26, (s+2*d) % 26}
            if len(ap_set) < 3:
                continue
            count = sum(1 for k in rand_keys if k in ap_set)
            if count > best_ap_count:
                best_ap_count = count
    if best_ap_count >= 12:
        joint_hits += 1

p_joint = joint_hits / N_TRIALS
if p_joint > 0:
    print(f"  P(IC>=0.0797 AND f(PT,pos%6) consistent AND AP>=12/24) = {p_joint:.6f} = 1 in {1/p_joint:.0f}")
else:
    print(f"  P(all three) < 1 in {N_TRIALS:,}")

# ═══════════════════════════════════════════════════════════════════════
# TEST 7: f(PT, pos%6) consistency -- WHY is it the structure of the cribs?
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("TEST 7: Structural analysis -- why is period 6 the boundary?")
print("=" * 70)

# At period p, the test for consistency is: no two crib positions share
# both the same PT letter AND the same residue mod p AND have different keys.
# The number of "dangerous pairs" depends on the crib structure.

print(f"\n  Dangerous pairs (same PT letter, same residue) per period:")
for period in range(2, 14):
    dangerous_pairs = []
    for i in range(24):
        for j in range(i+1, 24):
            pos_i = sorted_crib_pos[i]
            pos_j = sorted_crib_pos[j]
            if pt_at_sorted[i] == pt_at_sorted[j] and pos_i % period == pos_j % period:
                dangerous_pairs.append((pos_i, pos_j))
    n_danger = len(dangerous_pairs)
    # For the real keystream, how many dangerous pairs actually conflict?
    n_conflict = sum(1 for a, b in dangerous_pairs if BEAU_KEY[a] != BEAU_KEY[b])
    print(f"  p={period:2d}: {n_danger:2d} dangerous pairs, {n_conflict} conflicts")
    if n_conflict > 0:
        for a, b in dangerous_pairs:
            if BEAU_KEY[a] != BEAU_KEY[b]:
                print(f"         pos {a} ({N2L[PT_AT_POS[a]]}) key={N2L[BEAU_KEY[a]]} vs "
                      f"pos {b} ({N2L[PT_AT_POS[b]]}) key={N2L[BEAU_KEY[b]]}")

# ═══════════════════════════════════════════════════════════════════════
# TEST 8: Does period 6 relate to period 42 = lcm(6, 7)?
# The crib gap is 63-33 = 30 positions. 30 mod 6 = 0.
# ═══════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("TEST 8: Crib gap structure")
print("=" * 70)

gap = BCL_START - (ENE_START + len(ENE_TEXT))
print(f"  Gap between cribs: {gap} positions (pos {ENE_START+len(ENE_TEXT)} to {BCL_START-1})")
print(f"  ENE starts at {ENE_START}, BCL starts at {BCL_START}")
print(f"  BCL_START - ENE_START = {BCL_START - ENE_START} = 42")
print(f"  42 mod 6 = {42 % 6}")
print(f"  42 mod 7 = {42 % 7}")
print(f"  42 = 6 * 7 = lcm(6, 7)")

print(f"\n  ENE residues mod 6: {[p % 6 for p in range(ENE_START, ENE_START + len(ENE_TEXT))]}")
print(f"  BCL residues mod 6: {[p % 6 for p in range(BCL_START, BCL_START + len(BCL_TEXT))]}")

# Since 42 mod 6 = 0, the ENE and BCL cribs have the SAME set of residues mod 6
# (shifted by 42 positions, which is 0 mod 6).
# ENE: pos 21-33, residues 3,4,5,0,1,2,3,4,5,0,1,2,3
# BCL: pos 63-73, residues 3,4,5,0,1,2,3,4,5,0,1
# They OVERLAP in residues!

ene_residues = [(p % 6, p, PT_AT_POS[p]) for p in range(ENE_START, ENE_START + len(ENE_TEXT))]
bcl_residues = [(p % 6, p, PT_AT_POS[p]) for p in range(BCL_START, BCL_START + len(BCL_TEXT))]

print(f"\n  ENE: residue -> (pos, PT)")
for r, p, pt in ene_residues:
    print(f"    r={r}: pos={p}, PT={N2L[pt]}")
print(f"\n  BCL: residue -> (pos, PT)")
for r, p, pt in bcl_residues:
    print(f"    r={r}: pos={p}, PT={N2L[pt]}")

# For period 6, conflicts happen when same (PT_letter, residue) appears in
# both ENE and BCL with different key values.
# Since 42 mod 6 = 0, positions 21 and 63 have the SAME residue (3).
# ENE pos 21 has PT='E', BCL pos 63 has PT='B'. Different PT -> no conflict from these.
# The conflict would be: ENE pos X has same PT and same residue as BCL pos Y.

print(f"\n  Cross-crib overlaps at same (PT, residue mod 6):")
for r_e, p_e, pt_e in ene_residues:
    for r_b, p_b, pt_b in bcl_residues:
        if r_e == r_b and pt_e == pt_b:
            k_e = BEAU_KEY[p_e]
            k_b = BEAU_KEY[p_b]
            match = "MATCH" if k_e == k_b else "CONFLICT"
            print(f"    PT={N2L[pt_e]} r={r_e}: ENE pos {p_e} key={N2L[k_e]}, BCL pos {p_b} key={N2L[k_b]} -> {match}")

# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════
elapsed = time.time() - t0
print("\n" + "=" * 70)
print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
print("=" * 70)

results['test_1_p6_consistency'] = period_hit_counts.get(6, 0) / N_TRIALS
results['test_2_ic'] = p_ic
results['test_3_ap_any'] = p_ap
results['test_3_ap_specific'] = p_specific
results['test_4_clustering'] = p_cluster
results['test_5_period13'] = p_13
results['test_6_joint'] = p_joint
results['elapsed'] = elapsed
results['experiment'] = 'KEYSTREAM-AP-SIGNIFICANCE'
results['timestamp'] = time.strftime('%Y-%m-%dT%H:%M:%S')
results['n_trials'] = N_TRIALS

out_path = '/home/cpatrick/kryptos/results/keystream_ap_significance.json'
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nResults saved to: {out_path}")
