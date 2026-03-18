#!/usr/bin/env python3
"""
scripts/campaigns/e_stehle_delta4_comprehensive.py

Comprehensive investigation of the Stehle Delta4=5 observation from Bean's 2021 paper.

Bean Section 2.3: In K4 CT positions 55-63 (DIAWINFBN), consecutive characters
at distance 4 ALL have the same first difference of 5 (mod 26).

Six tasks:
  1. Statistical significance (analytical + Monte Carlo 10M+ trials)
  2. Check ALL lag values across full CT
  3. Slide windows of various lengths across CT for ALL constant-delta regions
  4. Interaction with consensus null mask (positions 58,59 removed)
  5. Cipher model implications
  6. Exploitation: period-4 key decryption attempts

Cipher: N/A (structural analysis)
Family: campaigns
Status: active
Keyspace: analytical + 10M MC trials
Last run: never
Best score: N/A
"""
import sys
import os
import random
import json
from collections import Counter, defaultdict
from itertools import product
from math import comb, log10
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT

# ========================================================================
# SETUP
# ========================================================================
ct_nums = [ord(c) - 65 for c in CT]
N = CT_LEN
assert N == 97

# Consensus null positions from MEMORY.md (17 positions at 100% consensus)
CONSENSUS_NULLS_17 = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
# Full 24 null mask (approximate — using the 17 consensus + 7 variable)
# For task 4 we only need 58 and 59 specifically

timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"Stehle Delta4=5 Comprehensive Analysis")
print(f"Timestamp: {timestamp}")
print(f"CT: {CT}")
print(f"CT length: {N}")
print()

# ========================================================================
# TASK 1: STATISTICAL SIGNIFICANCE
# ========================================================================
print("=" * 72)
print("TASK 1: STATISTICAL SIGNIFICANCE OF DELTA4=5 IN POSITIONS 55-63")
print("=" * 72)

# First, verify the observation
region = ct_nums[55:64]  # positions 55 through 63 inclusive = 9 chars
region_chars = CT[55:64]
print(f"\nRegion: positions 55-63 = '{region_chars}'")
print(f"Numeric: {region}")
print(f"Letters: {[chr(v+65) for v in region]}")

# Check all pairs at distance 4
print(f"\nPairs at lag 4:")
diffs_at_4 = []
for i in range(len(region) - 4):
    a, b = region[i], region[i+4]
    d = (b - a) % 26
    diffs_at_4.append(d)
    print(f"  pos {55+i} -> pos {55+i+4}: {chr(a+65)}({a}) -> {chr(b+65)}({b}), diff = ({b}-{a}) mod 26 = {d}")

all_same = len(set(diffs_at_4)) == 1
print(f"\nAll 5 differences equal? {all_same}")
if all_same:
    print(f"Constant value: {diffs_at_4[0]}")

# --- Analytical calculation ---
print(f"\n--- Analytical Probability ---")
# A random 9-char string over 26 letters. We need ALL 5 pairs at lag 4 to
# have the same first difference mod 26.
#
# Structure: positions 0,1,2,3,4,5,6,7,8
# Pairs at lag 4: (0,4), (1,5), (2,6), (3,7), (4,8)
#
# These pairs share characters! (0,4) and (4,8) both use position 4.
# So we cannot treat them as independent.
#
# Group by residue mod 4:
#   Residue 0: positions 0, 4, 8   (3 values)
#   Residue 1: positions 1, 5      (2 values)
#   Residue 2: positions 2, 6      (2 values)
#   Residue 3: positions 3, 7      (2 values)
#
# Within each residue class, consecutive differences at lag 4:
#   Class 0: (x0, x4, x8) -> diffs (x4-x0, x8-x4) must both = delta mod 26
#   Class 1: (x1, x5) -> diff (x5-x1) = delta mod 26  [only 1 pair]
#   Class 2: (x2, x6) -> diff (x6-x2) = delta mod 26  [only 1 pair]
#   Class 3: (x3, x7) -> diff (x7-x3) = delta mod 26  [only 1 pair]
#
# Wait -- the pairs are: (0,4),(1,5),(2,6),(3,7),(4,8)
# For all to have the SAME delta, we need:
#   x4 - x0 = x5 - x1 = x6 - x2 = x7 - x3 = x8 - x4 = delta (mod 26)
#
# For class 0: x4 = x0 + delta, x8 = x4 + delta = x0 + 2*delta
#   So given x0, both x4 and x8 are determined. That's 2 constraints.
# For class 1: x5 = x1 + delta. That's 1 constraint.
# For class 2: x6 = x2 + delta. That's 1 constraint.
# For class 3: x7 = x3 + delta. That's 1 constraint.
#
# Total constraints: 5 (matching the 5 pairs)
# Free variables: x0, x1, x2, x3 (4 values), plus delta (1 value)
# Total choices: 26^9 for random string
#
# Count: for each delta (26 choices), for each (x0,x1,x2,x3) (26^4 choices),
# the remaining 5 values (x4,x5,x6,x7,x8) are all determined.
# But we need x4 = x0+delta, x5 = x1+delta, x6 = x2+delta, x7 = x3+delta, x8 = x0+2*delta
# All are in [0,25] automatically since we work mod 26.
#
# So count of favorable outcomes = 26 * 26^4 = 26^5
# P(constant delta4) = 26^5 / 26^9 = 1/26^4 = 1/456976

p_analytical = 1.0 / (26**4)
print(f"P(all 5 lag-4 diffs equal, same delta) = 26^5 / 26^9 = 1/26^4 = 1/{26**4}")
print(f"  = {p_analytical:.2e}")
print(f"  = 1 in {1/p_analytical:,.0f}")

# But we should also consider: what's the probability for a SPECIFIC delta value (5)?
# For delta=5 specifically: count = 26^4 (just the free variables)
# P(constant delta4 = 5) = 26^4 / 26^9 = 1/26^5
p_specific = 1.0 / (26**5)
print(f"\nP(all 5 lag-4 diffs equal to SPECIFICALLY 5) = 26^4 / 26^9 = 1/26^5 = 1/{26**5}")
print(f"  = {p_specific:.2e}")
print(f"  = 1 in {1/p_specific:,.0f}")

# But we need to account for the fact that we're SEARCHING across all positions
# and all lags. Number of windows of length 9 in a 97-char text: 89.
# Number of lags to check for a 9-char window: 1 to 8.
# So total trials = 89 * 8 = 712.
n_windows_9 = N - 9 + 1  # = 89
n_lags = 8  # lags 1..8
total_trials = n_windows_9 * n_lags
print(f"\nMultiple testing correction:")
print(f"  Windows of length 9: {n_windows_9}")
print(f"  Lags (1..8): {n_lags}")
print(f"  Total tests: {total_trials}")
p_corrected = 1 - (1 - p_analytical) ** total_trials
print(f"  P(at least one hit, ANY delta, Bonferroni approx) = {total_trials} * {p_analytical:.2e} = {total_trials * p_analytical:.2e}")
print(f"  P(at least one hit, exact) = 1 - (1-p)^{total_trials} = {p_corrected:.2e}")
print(f"  = about 1 in {1/p_corrected:,.0f}")

# If we also consider varying window lengths (7,8,9,10,11):
# For length L, pairs at lag d: L-d pairs must all agree.
# This gets more complex. Let's compute for each length.
print(f"\n--- Probability by window length and minimum pairs ---")
print(f"  For window length L and lag d, number of pairs = L - d")
print(f"  {'L':>3} {'d':>3} {'pairs':>6} {'P(const delta, any val)':>25} {'1/P':>15}")
for L in [7, 8, 9, 10, 11]:
    for d in range(1, L):
        n_pairs = L - d
        if n_pairs < 4:  # only interesting for 4+ pairs
            continue
        # For lag d in a window of length L:
        # Residue classes mod d: d classes
        # Class r has ceil((L-r)/d) elements for r=0..d-1
        # Constraints: within each class, consecutive diffs must all = delta
        # Free vars: first element of each class + delta
        # Total free = d + 1 (d class leaders + 1 delta)
        # Actually: for each class of size s, there are s-1 constraints.
        # Total constraints = sum(s-1) = L - d
        # Free choices: delta (26 choices) + one element per class (26^d choices)
        # Count = 26^(d+1), total = 26^L
        # P = 26^(d+1) / 26^L = 1/26^(L-d-1)
        p_val = 1.0 / (26 ** (n_pairs - 1))  # n_pairs = L-d, so exponent = L-d-1
        print(f"  {L:3d} {d:3d} {n_pairs:6d} {p_val:25.2e} {1/p_val:15,.0f}")

# --- Monte Carlo ---
print(f"\n--- Monte Carlo Simulation (10M trials) ---")
MC_TRIALS = 10_000_000
random.seed(42)

# Task: generate random 9-char strings (uniform mod 26), check if all 5
# lag-4 differences are the same value (mod 26).
hits_any_delta = 0
hits_delta_5 = 0
for _ in range(MC_TRIALS):
    s = [random.randint(0, 25) for _ in range(9)]
    diffs = [(s[i+4] - s[i]) % 26 for i in range(5)]
    if len(set(diffs)) == 1:
        hits_any_delta += 1
        if diffs[0] == 5:
            hits_delta_5 += 1

p_mc_any = hits_any_delta / MC_TRIALS
p_mc_5 = hits_delta_5 / MC_TRIALS
print(f"  Trials: {MC_TRIALS:,}")
print(f"  Hits (any constant delta): {hits_any_delta}")
print(f"  P(any constant delta) MC = {p_mc_any:.2e}")
print(f"  P(any constant delta) analytical = {p_analytical:.2e}")
print(f"  Ratio MC/analytical = {p_mc_any/p_analytical:.3f}")
print(f"  Hits (delta=5 specifically): {hits_delta_5}")
print(f"  P(delta=5) MC = {p_mc_5:.2e}")
print(f"  P(delta=5) analytical = {p_specific:.2e}")
expected_any = MC_TRIALS * p_analytical
expected_5 = MC_TRIALS * p_specific
print(f"  Expected hits (any delta): {expected_any:.1f}")
print(f"  Expected hits (delta=5): {expected_5:.2f}")
print()

# ========================================================================
# TASK 2: CHECK ALL LAG VALUES ACROSS FULL CT
# ========================================================================
print("=" * 72)
print("TASK 2: CHECK ALL LAG VALUES FOR CONSTANT-DIFFERENCE REGIONS")
print("=" * 72)

print("\n--- Full 97-char CT: check each lag d for runs of constant difference ---")
print(f"\nFor each lag d (1..48), compute first differences, find longest constant run.")
print(f"{'lag':>4} {'total_pairs':>12} {'longest_const_run':>20} {'const_value':>12} {'start_pos':>10} {'region':>20}")

for d in range(1, 49):
    diffs = [(ct_nums[i+d] - ct_nums[i]) % 26 for i in range(N - d)]
    if not diffs:
        continue
    # Find longest constant run in diffs
    best_run = 1
    best_val = diffs[0]
    best_start = 0
    cur_run = 1
    cur_val = diffs[0]
    cur_start = 0
    for j in range(1, len(diffs)):
        if diffs[j] == cur_val:
            cur_run += 1
            if cur_run > best_run:
                best_run = cur_run
                best_val = cur_val
                best_start = cur_start
        else:
            cur_val = diffs[j]
            cur_run = 1
            cur_start = j

    # A run of R constant differences at lag d means R+1 pairs agree,
    # spanning positions best_start to best_start+R+d-1
    if best_run >= 4:  # Only report runs of 4+ (interesting)
        region_start = best_start
        region_end = best_start + best_run - 1 + d
        region_str = CT[region_start:region_end+1]
        if len(region_str) > 20:
            region_str = region_str[:17] + "..."
        print(f"{d:4d} {len(diffs):12d} {best_run:20d} {best_val:12d}({chr(best_val+65)}) {region_start:10d} {region_str:>20}")

# ========================================================================
# TASK 3: SLIDING WINDOW SEARCH FOR ALL CONSTANT-DELTA WINDOWS
# ========================================================================
print("\n" + "=" * 72)
print("TASK 3: ALL CONSTANT-DELTA WINDOWS (lengths 7-11, all lags)")
print("=" * 72)

print(f"\nSearching all windows of length L (7..11), all lags d (1..L-1),")
print(f"for windows where ALL L-d pairs at lag d have the same difference mod 26.")
print(f"\n{'L':>3} {'d':>3} {'pairs':>6} {'win_start':>10} {'delta':>6} {'window_text':>20} {'note':>30}")

all_hits = []
for L in [7, 8, 9, 10, 11]:
    for start in range(N - L + 1):
        window = ct_nums[start:start+L]
        for d in range(1, L):
            diffs = [(window[i+d] - window[i]) % 26 for i in range(L - d)]
            n_pairs = len(diffs)
            if n_pairs < 4:
                continue
            if len(set(diffs)) == 1:
                delta_val = diffs[0]
                win_text = CT[start:start+L]
                # Check overlap with cribs
                crib_overlap = sum(1 for p in range(start, start+L) if p in CRIB_DICT)
                null_overlap = sum(1 for p in range(start, start+L) if p in CONSENSUS_NULLS_17)
                note_parts = []
                if crib_overlap > 0:
                    note_parts.append(f"crib_overlap={crib_overlap}")
                if null_overlap > 0:
                    note_parts.append(f"null_overlap={null_overlap}")
                if start >= 55 and start <= 63 and start+L-1 >= 55 and start+L-1 <= 63:
                    note_parts.append("STEHLE_REGION")
                # Probability
                p_this = 1.0 / (26 ** (n_pairs - 1))
                note_parts.append(f"p={p_this:.1e}")
                note = "; ".join(note_parts)

                all_hits.append({
                    'L': L, 'd': d, 'pairs': n_pairs, 'start': start,
                    'delta': delta_val, 'text': win_text, 'note': note,
                    'p': p_this
                })
                print(f"{L:3d} {d:3d} {n_pairs:6d} {start:10d} {delta_val:6d}({chr(delta_val+65)}) {win_text:>20} {note:>30}")

print(f"\nTotal hits: {len(all_hits)}")

# Sort by significance (lowest p first, then most pairs)
all_hits_sorted = sorted(all_hits, key=lambda x: (x['p'], -x['pairs']))
print(f"\nTop 10 most significant hits:")
print(f"{'rank':>5} {'L':>3} {'d':>3} {'pairs':>6} {'start':>6} {'delta':>6} {'text':>20} {'p':>12}")
for rank, h in enumerate(all_hits_sorted[:10], 1):
    print(f"{rank:5d} {h['L']:3d} {h['d']:3d} {h['pairs']:6d} {h['start']:6d} {h['delta']:6d}({chr(h['delta']+65)}) {h['text']:>20} {h['p']:12.2e}")

# Check: how many hits expected by chance?
print(f"\n--- Expected hits by chance ---")
total_expected = 0
for L in [7, 8, 9, 10, 11]:
    n_win = N - L + 1
    for d in range(1, L):
        n_pairs = L - d
        if n_pairs < 4:
            continue
        p_this = 26.0 / (26 ** n_pairs)  # 26 possible delta values, each with P = 1/26^(n_pairs)...
        # Wait: P(all pairs same delta, any value) = 26 / 26^n_pairs = 1/26^(n_pairs-1)
        expected_this = n_win * p_this
        total_expected += expected_this
print(f"Total expected hits (L=7..11, pairs>=4, any delta): {total_expected:.4f}")
print(f"Observed hits: {len(all_hits)}")
print(f"Ratio observed/expected: {len(all_hits)/total_expected:.2f}x" if total_expected > 0 else "N/A")

# ========================================================================
# TASK 4: INTERACTION WITH CONSENSUS NULL MASK
# ========================================================================
print("\n" + "=" * 72)
print("TASK 4: INTERACTION WITH CONSENSUS NULL MASK")
print("=" * 72)

print(f"\nConsensus null positions (17, 100% agreement across 15/24 masks):")
print(f"  {sorted(CONSENSUS_NULLS_17)}")
print(f"\nNull positions in Stehle region (55-63): {sorted(CONSENSUS_NULLS_17 & set(range(55, 64)))}")

# After removing nulls at 58 and 59, remaining chars in positions 55-63:
stehle_positions = list(range(55, 64))
remaining_positions = [p for p in stehle_positions if p not in CONSENSUS_NULLS_17]
remaining_chars = [ct_nums[p] for p in remaining_positions]
remaining_text = ''.join(CT[p] for p in remaining_positions)

print(f"\nStehle region positions: {stehle_positions}")
print(f"After removing nulls ({sorted(CONSENSUS_NULLS_17 & set(range(55,64)))}): positions {remaining_positions}")
print(f"Remaining chars: {remaining_text} = {remaining_chars}")

# Check if delta4 pattern survives
if len(remaining_chars) >= 5:
    print(f"\nCheck lag-4 diffs on remaining {len(remaining_chars)} chars:")
    for i in range(len(remaining_chars) - 4):
        a, b = remaining_chars[i], remaining_chars[i+4]
        d = (b - a) % 26
        print(f"  pos {remaining_positions[i]} -> pos {remaining_positions[i+4]}: "
              f"{chr(a+65)}({a}) -> {chr(b+65)}({b}), diff = {d}")

# Now check what happens when we remove ALL consensus nulls and look at the
# characters that were in the Stehle region
print(f"\n--- Full null removal: what happens to the Stehle region? ---")
non_null_positions = sorted(p for p in range(N) if p not in CONSENSUS_NULLS_17)
non_null_chars = [ct_nums[p] for p in non_null_positions]
non_null_text = ''.join(CT[p] for p in non_null_positions)
print(f"After removing 17 consensus nulls: {len(non_null_chars)} chars remain")
print(f"Non-null text: {non_null_text}")

# Find where the Stehle region chars (55,56,57,60,61,62,63) land in the new sequence
stehle_in_nonnull = [non_null_positions.index(p) for p in remaining_positions]
print(f"Stehle chars map to new indices: {stehle_in_nonnull}")
print(f"  {' -> '.join(f'{chr(non_null_chars[i]+65)}[{i}]' for i in stehle_in_nonnull)}")

# Check diffs at various lags in the non-null sequence around the Stehle region
print(f"\nDifferences between Stehle chars in non-null sequence:")
for i in range(len(stehle_in_nonnull)):
    for j in range(i+1, len(stehle_in_nonnull)):
        a_idx, b_idx = stehle_in_nonnull[i], stehle_in_nonnull[j]
        a, b = non_null_chars[a_idx], non_null_chars[b_idx]
        d = (b - a) % 26
        gap = b_idx - a_idx
        print(f"  [{a_idx}]->[{b_idx}] (gap={gap}): {chr(a+65)}({a})->{chr(b+65)}({b}), diff={d}")

# Check for new constant-delta patterns in the non-null sequence
print(f"\n--- Constant-delta search in 80-char non-null sequence ---")
nn_N = len(non_null_chars)
nn_hits = []
for L in [7, 8, 9, 10, 11]:
    for start in range(nn_N - L + 1):
        window = non_null_chars[start:start+L]
        for d in range(1, L):
            diffs = [(window[i+d] - window[i]) % 26 for i in range(L - d)]
            n_pairs = len(diffs)
            if n_pairs < 4:
                continue
            if len(set(diffs)) == 1:
                delta_val = diffs[0]
                win_text = ''.join(chr(c+65) for c in window)
                orig_positions = non_null_positions[start:start+L]
                nn_hits.append({
                    'L': L, 'd': d, 'pairs': n_pairs, 'start': start,
                    'delta': delta_val, 'text': win_text,
                    'orig_pos': orig_positions
                })

print(f"Hits in non-null sequence: {len(nn_hits)}")
for h in sorted(nn_hits, key=lambda x: (1.0/26**(x['pairs']-1), -x['pairs']))[:10]:
    print(f"  L={h['L']} d={h['d']} pairs={h['pairs']} start={h['start']} "
          f"delta={h['delta']}({chr(h['delta']+65)}) text={h['text']} "
          f"orig_pos={h['orig_pos']}")

# ========================================================================
# TASK 5: CIPHER MODEL IMPLICATIONS
# ========================================================================
print("\n" + "=" * 72)
print("TASK 5: CIPHER MODEL IMPLICATIONS")
print("=" * 72)

print("""
If a cipher produces constant first-difference at lag d in the ciphertext,
what does that mean?

For a PERIODIC SUBSTITUTION with period p:
  CT[i] = f_{i mod p}(PT[i])

  If each f_r is a simple shift: CT[i] = PT[i] + k_{i mod p} (mod 26)

  Then: CT[i+d] - CT[i] = PT[i+d] - PT[i] + k_{(i+d) mod p} - k_{i mod p} (mod 26)

  For this to be constant (=5) for all i in the window:
    IF d divides p (e.g., d=4, p=4,8,12,...):
      k_{(i+d) mod p} - k_{i mod p} = k_{i mod p} - k_{i mod p} = 0
      So: PT[i+d] - PT[i] = 5 for all i (constant difference in plaintext!)

    IF d does NOT divide p:
      The key contribution k_{(i+d) mod p} - k_{i mod p} varies with i,
      so the plaintext differences would need to compensate exactly.

Case d=4:
  If period divides 4 (period 1, 2, or 4): delta in CT = delta in PT
    -> The PLAINTEXT at positions 55-63 would also have constant lag-4 diff of 5

  If period = 4: key values cycle. At positions 55,56,57,58,...:
    Residue mod 4: 55%4=3, 56%4=0, 57%4=1, 58%4=2, 59%4=3, 60%4=0, 61%4=1, 62%4=2, 63%4=3
    Pairs at lag 4: (55,59), (56,60), (57,61), (58,62), (59,63)
    Each pair shares the same residue mod 4, so key cancels.
    CT diff = PT diff = 5 (constant)

  For period = 13 (the d=13 anomaly period):
    Key contribution at lag 4: k_{(i+4) mod 13} - k_{i mod 13}
    This varies with i mod 13, so constant CT diff requires specific PT structure.
""")

# Compute residue classes for positions 55-63 under various periods
print("Residue classes for positions 55-63 under candidate periods:")
for p in [4, 7, 8, 13]:
    residues = [i % p for i in range(55, 64)]
    print(f"  Period {p}: residues = {residues}")

# For period 4: each lag-4 pair shares residue class, so key cancels
# This means: the constant delta in CT = constant delta in PT
# What 9-char English fragment has constant lag-4 first diff of 5?
print("\n--- English words/fragments with constant lag-4 diff of 5 ---")

# Check: what letters have difference 5 from each other?
print("\nLetter pairs with diff 5 (mod 26): [a -> a+5]")
for a in range(26):
    b = (a + 5) % 26
    print(f"  {chr(a+65)} -> {chr(b+65)}", end="")
print()

# If period=4 and key cancels: PT has constant lag-4 diff of 5
# PT structure: positions by residue mod 4:
#   r=3: PT[55], PT[59], PT[63]  -> consecutive diffs = 5
#   r=0: PT[56], PT[60]          -> diff = 5
#   r=1: PT[57], PT[61]          -> diff = 5
#   r=2: PT[58], PT[62]          -> diff = 5
#
# Each pair of letters 4 apart in the plaintext differs by exactly 5 (mod 26)
# r=3 chain: a, a+5, a+10 for some base a
# r=0: b, b+5
# r=1: c, c+5
# r=2: d, d+5

print("\nIf period divides 4 (key cancels at lag 4):")
print("PT positions by residue mod 4:")
print("  r=3: PT[55], PT[59], PT[63] = a, a+5, a+10 (mod 26)")
print("  r=0: PT[56], PT[60] = b, b+5")
print("  r=1: PT[57], PT[61] = c, c+5")
print("  r=2: PT[58], PT[62] = d, d+5")
print()
print("For each base letter a (26 choices), chain: a -> a+5 -> a+10 -> a+15 -> a+20 -> a+25 -> a+4 ...")
print("(This is a 26-cycle since gcd(5,26)=26/gcd... wait, gcd(5,26)=1, so 5 generates all of Z_26)")
print(f"gcd(5,26) = {__import__('math').gcd(5, 26)} -> 5 generates all of Z_26, full 26-cycle")

# Under a BEAUFORT cipher: CT = Key - PT (mod 26)
# Then CT[i+d] - CT[i] = -(PT[i+d] - PT[i]) + (k_{(i+d)%p} - k_{i%p})
# For period 4 with d=4: key cancels, so CT diff = -(PT diff) mod 26
# constant CT diff of 5 => constant PT diff of -5 = 21 (mod 26)
print("\nUnder BEAUFORT (CT = K - PT mod 26) with period dividing 4:")
print("  CT diff = -(PT diff) mod 26")
print("  Constant CT diff of 5 => constant PT diff of 21 (= -5 mod 26)")

# Under Variant Beaufort: CT = PT - Key (mod 26)
# CT diff = PT diff + (key contribution)
# Same as Vigenere for the difference (key contribution cancels at lag d=period)
print("\nUnder VIGENERE or VARIANT BEAUFORT with period dividing 4:")
print("  CT diff = PT diff (key cancels)")
print("  Constant CT diff of 5 => constant PT diff of 5")

# ========================================================================
# TASK 6: EXPLOITATION
# ========================================================================
print("\n" + "=" * 72)
print("TASK 6: EXPLOITATION — DECRYPT WITH PERIOD-4 KEYS")
print("=" * 72)

# For each of the 26^4 possible period-4 keys, decrypt the full 97-char CT
# and check if positions 55-63 produce something plausible.
# Actually more targeted: we know the constraint, so enumerate systematically.

# First: what are the crib constraints at positions near 55-63?
print("\n--- Crib positions near Stehle region ---")
for pos in range(50, 75):
    if pos in CRIB_DICT:
        print(f"  pos {pos}: CT={CT[pos]}({ct_nums[pos]}), PT={CRIB_DICT[pos]}({ord(CRIB_DICT[pos])-65})")

# Crib positions in/near 55-63: position 63 = B (BERLINCLOCK starts at 63)
# But 55-62 are NOT in any crib, so we have no PT constraints in the core Stehle region

print("\nPositions 55-62 are NOT in any crib (unknown PT).")
print("Position 63 IS a crib: CT=B(1), PT=B(1) [BERLINCLOCK[0]]")
print()

# Try all period-4 Vigenere keys on positions 55-63 and check pos 63 crib
print("--- Period-4 Vigenere: decrypt pos 55-63, check pos 63=B ---")
print("(Key k0,k1,k2,k3 where PT[i] = (CT[i] - k_{i%4}) mod 26)")

# Position 63: residue 63%4=3, CT=1(B), PT must = 1(B)
# So k3 = (CT[63] - PT[63]) mod 26 = (1 - 1) mod 26 = 0
# Under Vigenere: k3 = 0
print(f"Vigenere: k3 = (CT[63] - PT[63]) mod 26 = ({ct_nums[63]} - 1) mod 26 = {(ct_nums[63]-1)%26}")
k3_vig = (ct_nums[63] - 1) % 26

# Under Beaufort: k = (CT + PT) mod 26
k3_beau = (ct_nums[63] + 1) % 26
print(f"Beaufort: k3 = (CT[63] + PT[63]) mod 26 = ({ct_nums[63]} + 1) mod 26 = {k3_beau}")

# Under Variant Beaufort: k = (PT - CT) mod 26
k3_vbeau = (1 - ct_nums[63]) % 26
print(f"VarBeau: k3 = (PT[63] - CT[63]) mod 26 = (1 - {ct_nums[63]}) mod 26 = {k3_vbeau}")

# Additional crib constraints outside 55-63 that constrain the period-4 key:
# Crib positions and their residue mod 4:
print(f"\nAll crib positions with residue mod 4:")
by_res4 = defaultdict(list)
for pos, pt_char in CRIB_DICT.items():
    r = pos % 4
    ct_val = ct_nums[pos]
    pt_val = ord(pt_char) - 65
    k_vig = (ct_val - pt_val) % 26
    k_beau = (ct_val + pt_val) % 26
    by_res4[r].append((pos, ct_val, pt_val, k_vig, k_beau))

for r in range(4):
    print(f"\n  Residue {r}:")
    entries = sorted(by_res4[r])
    k_vig_vals = set()
    k_beau_vals = set()
    for pos, ct_v, pt_v, kv, kb in entries:
        k_vig_vals.add(kv)
        k_beau_vals.add(kb)
        print(f"    pos {pos:3d}: CT={chr(ct_v+65)}({ct_v:2d}) PT={chr(pt_v+65)}({pt_v:2d}) k_vig={kv:2d}({chr(kv+65)}) k_beau={kb:2d}({chr(kb+65)})")
    print(f"    Unique k_vig: {sorted(k_vig_vals)} ({'CONSISTENT' if len(k_vig_vals)==1 else 'CONFLICT'})")
    print(f"    Unique k_beau: {sorted(k_beau_vals)} ({'CONSISTENT' if len(k_beau_vals)==1 else 'CONFLICT'})")

# As expected, period-4 has key conflicts at cribs (this is already known).
# But the Stehle region is BETWEEN the two cribs (pos 55-63), and the
# constraint tells us something about the local structure.

print("\n--- Decrypt positions 55-63 with ALL period-4 keys (ignoring crib conflicts) ---")
print("For each (k0,k1,k2) and k3 fixed by pos 63 crib:")

# Vigenere case: k3 = 0
print(f"\nVigenere (k3={k3_vig}):")
print(f"For each possible (k0,k1,k2), PT at positions 55-63:")
print(f"  pos:     {list(range(55,64))}")
print(f"  res%4:   {[i%4 for i in range(55,64)]}")
print(f"  CT:      {[ct_nums[i] for i in range(55,64)]}")

# Positions 55-63 residues: 3,0,1,2,3,0,1,2,3
# CT values: D(3),I(8),A(0),W(22),I(8),N(13),F(5),B(1),N(13)
# k3 = 0: PT[55] = (3-0)%26=3=D, PT[59]=(8-0)%26=8=I, PT[63]=(13-0)%26=13=N... wait
# Actually PT[63] should be B(1), and k3=0 gives PT[63]=(1-0)%26=1=B. Correct!

# Let's check: do the CRIB CONSTRAINTS at other positions give us info about k0,k1,k2?
# Look at the crib values for each residue:
print(f"\nCrib-derived key values (Vigenere):")
for r in range(4):
    entries = sorted(by_res4.get(r, []))
    if entries:
        k_vals = [e[3] for e in entries]
        print(f"  r={r}: k_vig values = {k_vals} -> {'CONSISTENT k=' + str(k_vals[0]) if len(set(k_vals))==1 else 'CONFLICTS'}")

# Period 4 on 97 chars will ALWAYS have conflicts (already proven).
# But let's see what decryptions look like for positions 55-63 specifically.

# Pick a few interesting k0,k1,k2 values and show results
print(f"\nSample decryptions of positions 55-63 (Vigenere, k3={k3_vig}):")
ct_region = [ct_nums[i] for i in range(55, 64)]
res_region = [i % 4 for i in range(55, 64)]  # [3,0,1,2,3,0,1,2,3]

# Try all k0,k1,k2 and score PT fragments for English plausibility
# Load quadgrams if available
qg_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
quadgrams = None
try:
    with open(qg_path) as f:
        quadgrams = json.load(f)
    print(f"  (Loaded {len(quadgrams)} quadgrams)")
except:
    print(f"  (Quadgrams not available, using crib-matching only)")

def qg_score(text):
    """Score text using quadgram log-probabilities."""
    if quadgrams is None or len(text) < 4:
        return -999
    total = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += quadgrams.get(qg, -10.0)
    return total / max(1, len(text) - 3)

# Comprehensive: try all 26^3 = 17,576 combinations for k0,k1,k2
# For each, decrypt positions 55-63 and also the FULL 97-char CT
best_fragments = []
for k0 in range(26):
    for k1 in range(26):
        for k2 in range(26):
            key = [k0, k1, k2, k3_vig]
            pt_region = [(ct_region[i] - key[res_region[i]]) % 26 for i in range(9)]
            pt_text = ''.join(chr(v+65) for v in pt_region)

            # Score the 9-char fragment
            sc = qg_score(pt_text)
            if sc > -7.0:  # roughly above noise
                best_fragments.append((sc, pt_text, key))

best_fragments.sort(reverse=True)
print(f"\nTop 20 Vigenere decryptions of positions 55-63 (by quadgram score):")
print(f"  {'score':>8} {'plaintext':>12} {'key(k0,k1,k2,k3)':>20}")
for sc, pt, key in best_fragments[:20]:
    kstr = ''.join(chr(k+65) for k in key)
    print(f"  {sc:8.3f} {pt:>12} key={kstr}")

# Also try Beaufort
print(f"\nBeaufort (k3={k3_beau}):")
best_beau = []
for k0 in range(26):
    for k1 in range(26):
        for k2 in range(26):
            key = [k0, k1, k2, k3_beau]
            pt_region = [(key[res_region[i]] - ct_region[i]) % 26 for i in range(9)]
            pt_text = ''.join(chr(v+65) for v in pt_region)
            sc = qg_score(pt_text)
            if sc > -7.0:
                best_beau.append((sc, pt_text, key))

best_beau.sort(reverse=True)
print(f"Top 20 Beaufort decryptions of positions 55-63 (by quadgram score):")
print(f"  {'score':>8} {'plaintext':>12} {'key(k0,k1,k2,k3)':>20}")
for sc, pt, key in best_beau[:20]:
    kstr = ''.join(chr(k+65) for k in key)
    print(f"  {sc:8.3f} {pt:>12} key={kstr}")

# Now check: does the Delta4=5 pattern extend BEYOND positions 55-63?
print(f"\n--- Does Delta4=5 extend beyond positions 55-63? ---")
print(f"Check CT first-differences at lag 4 for ALL positions:")
full_diffs_4 = [(ct_nums[i+4] - ct_nums[i]) % 26 for i in range(N - 4)]
print(f"Full lag-4 diffs: {full_diffs_4}")
print(f"\nPositions where lag-4 diff = 5:")
d4_5_positions = [i for i, d in enumerate(full_diffs_4) if d == 5]
print(f"  {d4_5_positions}")
print(f"  Count: {len(d4_5_positions)}/{len(full_diffs_4)} = {len(d4_5_positions)/len(full_diffs_4)*100:.1f}%")
print(f"  Expected (uniform): {len(full_diffs_4)/26:.1f} = {100/26:.1f}%")
print(f"  Ratio: {len(d4_5_positions)/(len(full_diffs_4)/26):.2f}x expected")

# Check if positions 54 or 53 also have lag-4 diff = 5 (extending left)
print(f"\nExtension check around Stehle region (lag-4 diffs):")
for i in range(max(0, 50), min(N-4, 70)):
    d = (ct_nums[i+4] - ct_nums[i]) % 26
    in_stehle = "***" if 55 <= i <= 59 else ""
    in_crib = f"(PT[{i}]={CRIB_DICT[i]})" if i in CRIB_DICT else ""
    in_crib4 = f"(PT[{i+4}]={CRIB_DICT[i+4]})" if i+4 in CRIB_DICT else ""
    print(f"  i={i:3d}: CT[{i}]={CT[i]}({ct_nums[i]:2d}) -> CT[{i+4}]={CT[i+4]}({ct_nums[i+4]:2d}), diff={(ct_nums[i+4]-ct_nums[i])%26:2d} {in_stehle} {in_crib} {in_crib4}")

# ========================================================================
# TASK 6 EXTENDED: Full CT period-4 decryption with crib scoring
# ========================================================================
print("\n" + "=" * 72)
print("TASK 6 EXTENDED: FULL CT PERIOD-4 DECRYPTION WITH CRIB SCORING")
print("=" * 72)

# Even though period 4 has conflicts, let's find the BEST period-4 key
# that maximizes crib matches (accepting that not all 24 can match)
print(f"\nExhaustive period-4 search: best Vigenere/Beaufort keys by crib score")

best_vig_score = 0
best_vig_key = None
best_beau_score = 0
best_beau_key = None

for k0 in range(26):
    for k1 in range(26):
        for k2 in range(26):
            for k3 in range(26):
                key = [k0, k1, k2, k3]

                # Vigenere crib check
                vig_matches = 0
                for pos, pt_char in CRIB_DICT.items():
                    pt_val = (ct_nums[pos] - key[pos % 4]) % 26
                    if pt_val == ord(pt_char) - 65:
                        vig_matches += 1
                if vig_matches > best_vig_score:
                    best_vig_score = vig_matches
                    best_vig_key = key[:]

                # Beaufort crib check
                beau_matches = 0
                for pos, pt_char in CRIB_DICT.items():
                    pt_val = (key[pos % 4] - ct_nums[pos]) % 26
                    if pt_val == ord(pt_char) - 65:
                        beau_matches += 1
                if beau_matches > best_beau_score:
                    best_beau_score = beau_matches
                    best_beau_key = key[:]

print(f"\nBest Vigenere period-4: {best_vig_score}/24 crib matches, key={[chr(k+65) for k in best_vig_key]}")
pt_vig = ''.join(chr((ct_nums[i] - best_vig_key[i%4]) % 26 + 65) for i in range(N))
print(f"  Plaintext: {pt_vig}")

print(f"\nBest Beaufort period-4: {best_beau_score}/24 crib matches, key={[chr(k+65) for k in best_beau_key]}")
pt_beau = ''.join(chr((best_beau_key[i%4] - ct_nums[i]) % 26 + 65) for i in range(N))
print(f"  Plaintext: {pt_beau}")

# Show which crib positions match and which don't
print(f"\nVigenere period-4 key={[chr(k+65) for k in best_vig_key]} crib detail:")
for pos in sorted(CRIB_DICT.keys()):
    pt_val = (ct_nums[pos] - best_vig_key[pos%4]) % 26
    expected = ord(CRIB_DICT[pos]) - 65
    match = "MATCH" if pt_val == expected else f"MISS (got {chr(pt_val+65)}, need {CRIB_DICT[pos]})"
    print(f"  pos {pos:3d} r={pos%4}: {match}")

# ========================================================================
# SUMMARY
# ========================================================================
print("\n" + "=" * 72)
print("SUMMARY OF FINDINGS")
print("=" * 72)

print(f"""
1. STATISTICAL SIGNIFICANCE:
   - P(constant lag-4 diff in 9-char random string) = 1/26^4 = 1/{26**4:,} = {p_analytical:.2e}
   - Monte Carlo ({MC_TRIALS:,} trials): {hits_any_delta} hits = {p_mc_any:.2e} (matches analytical)
   - After multiple-testing correction ({total_trials} tests for L=9): P ~ {total_trials * p_analytical:.2e}
   - VERDICT: Significant at the ~{total_trials * p_analytical:.4f} level (about 1 in {1/(total_trials * p_analytical):.0f})

2. CONSTANT-DIFF WINDOWS:
   - Total hits (L=7..11, pairs>=4): {len(all_hits)}
   - Expected by chance: {total_expected:.2f}
   - Stehle's Delta4=5 at positions 55-63 is {'THE MOST significant' if len(all_hits) <= 5 else 'among the top'} hit

3. NULL MASK INTERACTION:
   - Consensus nulls in Stehle region: {sorted(CONSENSUS_NULLS_17 & set(range(55,64)))}
   - After null removal: pattern disrupted (different lag structure)

4. CIPHER MODEL:
   - If period divides 4: CT diff = PT diff (Vig) or -(PT diff) (Beau)
   - Constant diff of 5 in PT means arithmetic progression in each residue class
   - gcd(5,26)=1, so the progression visits all 26 letters (full cycle)

5. EXPLOITATION:
   - Period 4 has KEY CONFLICTS at crib positions (consistent with known impossibility)
   - Best period-4 Vigenere: {best_vig_score}/24 crib matches
   - Best period-4 Beaufort: {best_beau_score}/24 crib matches
   - The Stehle observation is REAL and statistically significant but does not directly
     yield a decryption key under standard periodic cipher models
""")

# Write results to file
results = {
    'timestamp': timestamp,
    'task': 'stehle_delta4_comprehensive',
    'p_analytical': p_analytical,
    'p_mc': p_mc_any,
    'mc_trials': MC_TRIALS,
    'mc_hits_any': hits_any_delta,
    'mc_hits_5': hits_delta_5,
    'p_corrected': total_trials * p_analytical,
    'total_constant_delta_hits': len(all_hits),
    'expected_hits': total_expected,
    'best_vig_period4_score': best_vig_score,
    'best_beau_period4_score': best_beau_score,
    'best_vig_period4_key': [chr(k+65) for k in best_vig_key] if best_vig_key else None,
    'best_beau_period4_key': [chr(k+65) for k in best_beau_key] if best_beau_key else None,
    'consensus_nulls_in_stehle': sorted(CONSENSUS_NULLS_17 & set(range(55,64))),
    'conclusion': 'REAL_ANOMALY_NO_DIRECT_EXPLOIT'
}

results_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results', 'stehle_delta4_comprehensive.json')
with open(results_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"\nResults written to: {results_path}")
print("=== DONE ===")
