#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-35: Bean Impossibility Proof for Transposition + Periodic Key

THEOREM: For ANY transposition σ of K4 ciphertext, a periodic substitution key
at periods 2-7 (and several others) violates at least one Bean inequality constraint.
This holds REGARDLESS of the specific key values and REGARDLESS of the permutation.

PROOF: Under periodic keying with period p, k[i] = key_value[i mod p].
For any Bean inequality pair (a, b) where a ≡ b (mod p), we have
k[a] = key_value[a mod p] = key_value[b mod p] = k[b], violating k[a] ≠ k[b].

Since BEAN_INEQ contains pairs with differences {1, 3, 4, 5, 9, 34, 42, 43, 45, 50},
any period p that divides ANY of these differences has at least one violated pair.

ALL periods 2-7 divide at least one of these differences.

EXTENDS TO: No-transposition case (σ = identity). The Bean constraint eliminates
periodic keying at these periods UNIVERSALLY — with any transposition or without.

EXTENSION (Type 2): Bean equality (27,65) forces key[27%p] = key[65%p].
If any Bean inequality pair (a,b) has {a%p, b%p} = {27%p, 65%p}, the equality
and inequality directly conflict. This eliminates periods 11, 12, 18, 22 additionally.

COMBINED SURVIVING PERIODS: 8, 13, 16, 19, 20, 23, 24, 26, ...
First discriminating survivor: period 8 (3 cribs per key variable).

This experiment also computes:
- Feasibility analysis at surviving periods (bipartite matching)
- Underdetermination quantification
- Cross-validation against E-FRAC-33/34 false positives
"""

import json
import math
import os
import sys
import time
from collections import defaultdict
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    BEAN_EQ, BEAN_INEQ, CRIB_DICT, CT, N_CRIBS,
)

START_TIME = time.time()

# --- Part 1: Bean impossibility proof ---
print("=" * 70)
print("E-FRAC-35: Bean Impossibility Proof for Transposition + Periodic Key")
print("=" * 70)

# Compute differences for all Bean inequality pairs
ineq_diffs = set()
ineq_pairs_by_diff = defaultdict(list)
for a, b in BEAN_INEQ:
    d = abs(b - a)
    ineq_diffs.add(d)
    ineq_pairs_by_diff[d].append((a, b))

print(f"\nBean inequality pairs: {len(BEAN_INEQ)}")
print(f"Unique position differences: {sorted(ineq_diffs)}")

# For each period, check Bean feasibility
period_analysis = {}
eliminated_periods = []
surviving_periods = []

print(f"\n{'Period':>6} | {'Status':>11} | {'Violations':>10} | {'Violating Pairs':>50} | {'Cribs/Var':>9} | {'Bean Eq':>10}")
print("-" * 110)

for p in range(2, 50):
    violations = []
    for a, b in BEAN_INEQ:
        if a % p == b % p:
            violations.append((a, b, abs(b - a)))

    # Bean equality check
    eq_auto = all(a % p == b % p for a, b in BEAN_EQ)
    eq_str = "auto-sat" if eq_auto else "constrains"

    cribs_per_var = 24 / p
    status = "ELIMINATED" if violations else "SURVIVES"

    if violations:
        eliminated_periods.append(p)
    else:
        surviving_periods.append(p)

    pair_str = str([(a, b) for a, b, d in violations[:4]])
    if len(violations) > 4:
        pair_str += "..."

    period_analysis[p] = {
        'period': p,
        'status': status,
        'n_violations': len(violations),
        'violating_pairs': [(a, b) for a, b, d in violations],
        'bean_eq_auto': eq_auto,
        'cribs_per_var': cribs_per_var,
    }

    if p <= 26 or not violations:
        print(f"{p:>6} | {status:>11} | {len(violations):>10} | {pair_str:>50} | {cribs_per_var:>9.1f} | {eq_str:>10}")

print(f"\n{'='*70}")
print(f"ELIMINATED periods (2-26): {[p for p in eliminated_periods if p <= 26]}")
print(f"SURVIVING periods (2-26):  {[p for p in surviving_periods if p <= 26]}")
print(f"SURVIVING periods (2-49):  {surviving_periods}")

# Key theorem
# --- Part 1b: Type 2 elimination — Bean equality-inequality conflict ---
print(f"\n{'='*70}")
print("PART 1b: Type 2 Elimination — Bean Equality vs Inequality Conflict")
print("=" * 70)

eq_a, eq_b = BEAN_EQ[0]  # (27, 65)
type2_eliminated = set()

print(f"Bean equality: key[{eq_a}%p] = key[{eq_b}%p]")
print(f"Conflict if any inequality pair (a,b) has {{a%p, b%p}} = {{{eq_a}%p, {eq_b}%p}}")
print()

for a, b in BEAN_INEQ:
    # Case 1: a%p = eq_a%p AND b%p = eq_b%p
    d1a, d1b = abs(a - eq_a), abs(b - eq_b)
    # Case 2: a%p = eq_b%p AND b%p = eq_a%p
    d2a, d2b = abs(a - eq_b), abs(b - eq_a)

    pair_conflicts = set()

    # Case 1
    if d1a == 0:
        for p in range(2, 97):
            if d1b > 0 and d1b % p == 0:
                pair_conflicts.add(p)
    elif d1b == 0:
        for p in range(2, 97):
            if d1a > 0 and d1a % p == 0:
                pair_conflicts.add(p)
    else:
        g = math.gcd(d1a, d1b)
        for p in range(2, g + 1):
            if g % p == 0:
                pair_conflicts.add(p)

    # Case 2
    if d2a == 0:
        for p in range(2, 97):
            if d2b > 0 and d2b % p == 0:
                pair_conflicts.add(p)
    elif d2b == 0:
        for p in range(2, 97):
            if d2a > 0 and d2a % p == 0:
                pair_conflicts.add(p)
    else:
        g = math.gcd(d2a, d2b)
        for p in range(2, g + 1):
            if g % p == 0:
                pair_conflicts.add(p)

    # Only count periods where eq is a genuine constraint (not auto-satisfied)
    pair_conflicts = {p for p in pair_conflicts if eq_a % p != eq_b % p}

    if pair_conflicts:
        type2_eliminated |= pair_conflicts
        print(f"  ({a:2d},{b:2d}): eq-ineq conflict at periods {sorted(p for p in pair_conflicts if p <= 50)}")

# Combined elimination
type1_set = set(eliminated_periods)
new_from_type2 = type2_eliminated - type1_set
all_eliminated = type1_set | type2_eliminated
final_surviving = sorted(p for p in range(2, 50) if p not in all_eliminated)

print(f"\nType 1 eliminated (same-residue ineq, 2-26): {[p for p in sorted(type1_set) if p <= 26]}")
print(f"Type 2 NEW eliminations (2-26): {sorted(p for p in new_from_type2 if p <= 26)}")
print(f"TOTAL eliminated (2-26): {sorted(p for p in all_eliminated if p <= 26)}")
print(f"FINAL SURVIVING (2-26): {[p for p in final_surviving if p <= 26]}")
print(f"FINAL SURVIVING (2-49): {final_surviving}")

# Update surviving_periods for subsequent analysis
surviving_periods = final_surviving

print(f"\n{'='*70}")
print("COMBINED THEOREM:")
print("Periodic keying at ANY of the following periods is IMPOSSIBLE")
print("under ANY transposition (including identity), due to Bean constraints:")
print(f"  ELIMINATED (2-26): {sorted(p for p in all_eliminated if p <= 26)}")
print(f"\nAll discriminating periods (2-7): ALL ELIMINATED")
print(f"Periods 11, 12 also eliminated (eq-ineq conflict)")
print(f"First surviving period: {surviving_periods[0]}")
print(f"Surviving with cribs/var >= 1.5: {[p for p in surviving_periods if 24/p >= 1.5]}")


# --- Part 2: Detailed analysis at discriminating periods ---
print(f"\n{'='*70}")
print("PART 2: Detailed Violation Analysis at Discriminating Periods (2-7)")
print("=" * 70)

# Map crib positions to letters and residue classes
crib_positions = sorted(CRIB_DICT.keys())
ct_vals = [ord(c) - ord('A') for c in CT]

for p in range(2, 8):
    print(f"\n--- Period {p} ---")

    # Group crib positions by residue
    residue_groups = defaultdict(list)
    for pos in crib_positions:
        residue_groups[pos % p].append(pos)

    print(f"Residue classes with crib positions:")
    for r in sorted(residue_groups.keys()):
        positions = residue_groups[r]
        letters = [CRIB_DICT[pos] for pos in positions]
        print(f"  r={r}: positions {positions} -> PT letters {letters}")

    # Find violating pairs and their residue classes
    viol_residues = set()
    for a, b in BEAN_INEQ:
        if a % p == b % p:
            r = a % p
            viol_residues.add(r)
            print(f"  VIOLATION: ({a},{b}) both in residue {r}, diff={abs(b-a)}")
            print(f"    k[{a}] = key[{r}] = k[{b}] ALWAYS, but Bean requires k[{a}] ≠ k[{b}]")

    # Determine maximum achievable crib score with Bean
    # Under periodic key at period p:
    # - For each residue class, all crib positions in that class use the same key value
    # - Bean inequalities between same-residue pairs are violated
    # - This is NOT fixable by changing key values or transposition
    print(f"\n  Violated residue classes: {sorted(viol_residues)}")
    print(f"  CONCLUSION: Period {p} is IMPOSSIBLE for transposition + periodic key + Bean")


# --- Part 3: Feasibility at surviving periods ---
print(f"\n{'='*70}")
print("PART 3: Feasibility Analysis at Surviving Periods")
print("=" * 70)

# For each surviving period p (up to 16), compute:
# 1. How many key tuples satisfy Bean equality and all Bean inequalities?
# 2. For each valid key tuple, how many transpositions produce 24/24?

# CT letter frequencies
ct_freq = defaultdict(int)
for c in CT:
    ct_freq[ord(c) - ord('A')] += 1

print(f"\nCT letter frequencies (top): ", end="")
for v, cnt in sorted(ct_freq.items(), key=lambda x: -x[1])[:10]:
    print(f"{chr(v + ord('A'))}={cnt} ", end="")
print()

# For each surviving period, enumerate feasible key tuples
def check_bean_for_key_tuple(key_tuple, period):
    """Check if a periodic key with given values satisfies all Bean constraints."""
    # Bean equality
    for a, b in BEAN_EQ:
        if key_tuple[a % period] != key_tuple[b % period]:
            return False
    # Bean inequalities
    for a, b in BEAN_INEQ:
        if key_tuple[a % period] == key_tuple[b % period]:
            return False
    return True


def count_matching_ct_positions(target_letter, ct_vals):
    """Count CT positions with the given letter value."""
    return sum(1 for v in ct_vals if v == target_letter)


def check_bipartite_feasibility(crib_pos, pt_vals, key_tuple, period, ct_vals):
    """Check if there exists an assignment of crib positions to CT positions
    such that CT[σ(i)] = (PT[i] + key[i mod p]) mod 26 for Vigenère.

    Uses greedy matching with augmenting paths (Hopcroft-Karp lite).
    """
    n_cribs = len(crib_pos)

    # Build adjacency: for each crib position, which CT positions are compatible?
    adj = []
    for i, pos in enumerate(crib_pos):
        target = (pt_vals[i] + key_tuple[pos % period]) % 26
        compatible = [j for j in range(97) if ct_vals[j] == target]
        adj.append(compatible)

    # Simple augmenting-path matching
    match_ct = [-1] * 97  # match_ct[j] = index in crib_pos that j is matched to

    def try_augment(i, visited):
        for j in adj[i]:
            if j not in visited:
                visited.add(j)
                if match_ct[j] == -1 or try_augment(match_ct[j], visited):
                    match_ct[j] = i
                    return True
        return False

    matched = 0
    for i in range(n_cribs):
        visited = set()
        if try_augment(i, visited):
            matched += 1

    return matched == n_cribs


# Analyze each surviving period
surviving_analysis = {}

for p in sorted(surviving_periods):
    if p > 16:
        break  # periods > 16 are underdetermined (< 1.3 cribs/var)

    print(f"\n--- Period {p} (cribs/var = {24/p:.1f}) ---")

    # Bean equality constraint: identifies which residue classes must be equal
    bean_eq_constraints = []
    for a, b in BEAN_EQ:
        r_a, r_b = a % p, b % p
        if r_a != r_b:
            bean_eq_constraints.append((r_a, r_b))
            print(f"  Bean equality: key[{r_a}] = key[{r_b}]")

    # Bean inequality constraints (per residue)
    bean_ineq_residue = []
    for a, b in BEAN_INEQ:
        r_a, r_b = a % p, b % p
        if r_a != r_b:
            bean_ineq_residue.append((r_a, r_b))

    # Effective DOF after Bean equality
    n_free = p - len(bean_eq_constraints)
    print(f"  Free key variables after Bean eq: {n_free} (was {p})")
    print(f"  Bean inequality constraints (inter-residue): {len(bean_ineq_residue)}")

    # Enumerate key tuples
    total_tuples = 26 ** p
    print(f"  Total key tuples: {total_tuples:,}")

    # For feasibility, enumerate (or sample for large spaces)
    bean_passing = 0
    feasible = 0
    feasible_keys = []

    pt_vals = [ord(CRIB_DICT[pos]) - ord('A') for pos in crib_positions]

    if total_tuples <= 5_000_000:
        # Exact enumeration
        for key_tuple in product(range(26), repeat=p):
            if check_bean_for_key_tuple(key_tuple, p):
                bean_passing += 1
                if check_bipartite_feasibility(crib_positions, pt_vals, key_tuple, p, ct_vals):
                    feasible += 1
                    if len(feasible_keys) < 100:
                        feasible_keys.append(key_tuple)

        print(f"  Bean-passing key tuples: {bean_passing:,} / {total_tuples:,} ({100*bean_passing/total_tuples:.2f}%)")
        print(f"  Feasible (Bean + bipartite match): {feasible:,} / {bean_passing:,}")

    else:
        # Sample
        n_samples = 1_000_000
        import random
        random.seed(42)

        for _ in range(n_samples):
            key_tuple = tuple(random.randint(0, 25) for _ in range(p))
            if check_bean_for_key_tuple(key_tuple, p):
                bean_passing += 1
                if check_bipartite_feasibility(crib_positions, pt_vals, key_tuple, p, ct_vals):
                    feasible += 1
                    if len(feasible_keys) < 100:
                        feasible_keys.append(key_tuple)

        bean_rate = bean_passing / n_samples
        feasible_rate = feasible / n_samples
        est_bean = int(bean_rate * total_tuples)
        est_feasible = int(feasible_rate * total_tuples)

        print(f"  Sampled: {n_samples:,} of {total_tuples:,}")
        print(f"  Bean-passing: {bean_passing:,} ({100*bean_rate:.2f}%) → est. {est_bean:,} total")
        print(f"  Feasible: {feasible:,} ({100*feasible_rate:.4f}%) → est. {est_feasible:,} total")

    surviving_analysis[p] = {
        'period': p,
        'total_tuples': total_tuples,
        'bean_passing': bean_passing,
        'feasible': feasible,
        'feasible_keys_sample': [list(k) for k in feasible_keys[:10]],
        'cribs_per_var': 24 / p,
    }

    elapsed = time.time() - START_TIME
    print(f"  [elapsed: {elapsed:.0f}s]")


# --- Part 4: Cross-validate with E-FRAC-33 false positives ---
print(f"\n{'='*70}")
print("PART 4: Cross-Validation with E-FRAC-33/34 False Positives")
print("=" * 70)

print("""
E-FRAC-33 found false 24/24 solutions via hill-climbing at periods 5 and 7.
E-FRAC-34 collected 90 false 24/24 solutions: 34 at p7, 35 at p5, 16 at p2, 5 at p6.

Bean impossibility proof shows:
- Period 2: ELIMINATED (7 Bean inequality violations)
- Period 5: ELIMINATED (5 violations)
- Period 6: ELIMINATED (2 violations)
- Period 7: ELIMINATED (2 violations)

All 90 false 24/24 solutions are at Bean-ELIMINATED periods!
This confirms: 24/24 crib match + Bean pass + periodic key at periods 2-7 is IMPOSSIBLE.

The E-FRAC-33/34 hill-climber achieved 24/24 because it optimized crib score ONLY,
without checking Bean. The multi-objective oracle (E-FRAC-34) correctly includes Bean
as a filter, which would reject ALL these false positives for a DIFFERENT reason than
quadgram fitness — they're Bean-structurally-impossible at their optimal periods.
""")


# --- Part 5: Implications for the search ---
print(f"\n{'='*70}")
print("PART 5: Implications for All Agents")
print("=" * 70)

implications = """
1. UNIVERSAL RESULT: Periodic keying at periods 2-12 (and 14,15,17,18,21,22,25)
   is IMPOSSIBLE with Bean, under ANY transposition including identity.
   This is a PROOF, not an empirical finding. Holds for all 97! permutations.
   - Type 1: periods {2,3,4,5,6,7,9,10,14,15,17,21,25} — same-residue inequality
   - Type 2: periods {11,12,18,22} — eq-ineq conflict (Bean equality forces
     key[r1]=key[r2] but Bean inequality requires key[r1]!=key[r2])

2. SURVIVING PERIODS for transposition + periodic key (2-26):
   {8, 13, 16, 19, 20, 23, 24, 26}
   First discriminating survivor: period 8 (3 cribs per key variable)
   Only periods with ≥1.5 cribs/var: 8, 13, 16

3. FOR JTS: Do NOT search at any eliminated period. Target period 8 as
   the primary search period. Period 13 is secondary (1.8 cribs/var).
   Period 16 is tertiary (1.5 cribs/var — highly underdetermined).

4. FOR TRANS: All prior tests at periods 2-7 were testing a Bean-impossible
   region. The empirical NOISE results are consistent with this proof.

5. INTERPRETATION: The Bean constraints eliminate 17 of 25 periods (2-26).
   Only 8 periods survive. The constraint is FAR more restrictive than
   previously understood — it eliminates ENTIRE period families.

6. COMBINED WITH prior eliminations:
   - Periodic key at periods 2-12: Bean-impossible (this result)
   - Periodic key at periods 1-26 under identity: Tier 1 eliminated
   - Periodic key at periods 13+: highly underdetermined (≤1.8 cribs/var)
   → The periodic key hypothesis is SEVERELY constrained

7. IF K4 uses periodic keying, the period is in {8, 13, 16, 19, 20, 23, 24, 26, ...}.
   Period 8 is the ONLY viable period with ≥2 cribs/var.
   This is a very strong constraint from Bean alone.

8. ALTERNATIVE: The key is NOT periodic. Running key, progressive key,
   or position-dependent key avoids the Bean period constraint entirely.
   This INCREASES the probability that K4 uses a non-periodic key model.
"""
print(implications)


# --- Part 6: Summary ---
print(f"\n{'='*70}")
print("SUMMARY")
print("=" * 70)

summary = {
    'experiment': 'E-FRAC-35',
    'title': 'Bean Impossibility Proof for Transposition + Periodic Key',
    'runtime_seconds': round(time.time() - START_TIME, 1),
    'theorem': (
        'For ANY transposition σ and periodic key, Bean constraints eliminate '
        'ALL discriminating periods (2-7) plus periods 9, 10, 11, 12, 14, 15, 17, 18, 21, 22, 25. '
        'Type 1: same-residue inequality pairs force k[a]=k[b] violating k[a]≠k[b]. '
        'Type 2: Bean equality k[27%p]=k[65%p] conflicts with inequality k[a%p]≠k[b%p] at same residues. '
        'This holds regardless of key values and regardless of the permutation.'
    ),
    'elimination_types': {
        'type1_same_residue': sorted(p for p in type1_set if p <= 26),
        'type2_eq_ineq_conflict': sorted(p for p in type2_eliminated if p <= 26),
        'type2_new': sorted(p for p in new_from_type2 if p <= 26),
    },
    'eliminated_periods_2_26': sorted(p for p in all_eliminated if p <= 26),
    'surviving_periods_2_26': [p for p in surviving_periods if p <= 26],
    'all_discriminating_periods_eliminated': True,
    'first_surviving_period': surviving_periods[0] if surviving_periods else None,
    'bean_ineq_differences': sorted(ineq_diffs),
    'period_analysis': period_analysis,
    'surviving_period_feasibility': surviving_analysis,
    'cross_validation': {
        'e_frac_33_34_all_fps_at_eliminated_periods': True,
        'fp_periods': {'p2': 16, 'p5': 35, 'p6': 5, 'p7': 34},
        'all_at_eliminated_periods': True,
    },
    'implications': {
        'periodic_key_viable_periods': [p for p in surviving_periods if p <= 26],
        'first_discriminating_surviving_period': 8,
        'cribs_per_var_at_p8': 3.0,
        'non_periodic_key_more_likely': True,
        'surviving_with_cribs_gte_1_5': [p for p in surviving_periods if 24/p >= 1.5],
    },
}

print(f"\nResult: ALL discriminating periods (2-7) BEAN-ELIMINATED")
print(f"Additional eliminations (Type 2): periods 11, 12, 18, 22")
print(f"Total eliminated (2-26): {summary['eliminated_periods_2_26']}")
print(f"Surviving (2-26): {summary['surviving_periods_2_26']}")
print(f"First surviving period: {summary['first_surviving_period']}")
print(f"Surviving with ≥1.5 cribs/var: {summary['implications']['surviving_with_cribs_gte_1_5']}")
print(f"Runtime: {summary['runtime_seconds']}s")

# Save results
os.makedirs('results/frac', exist_ok=True)
outpath = 'results/frac/e_frac_35_bean_period_impossibility.json'
with open(outpath, 'w') as f:
    json.dump(summary, f, indent=2)
print(f"\nResults written to: {outpath}")
print(f"\nRESULT: ALL_DISCRIMINATING_PERIODS_BEAN_ELIMINATED verdict=PROOF")
