#!/usr/bin/env python3
"""
Cipher: crib-based constraint
Family: crib_analysis
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-20: Algebraic Transposition Constraint Propagation

For a model CT = σ(Vig(PT, periodic_key)), the 24 known crib positions
create hard algebraic constraints on which CT positions σ^(-1) can map to.

For each residue class mod p, the crib positions have known PT values.
Under Vigenère, (CT[σ^(-1)(j)] - PT[j]) must be constant for all j in the
same residue class. This creates linear relationships between CT values at
the transposed positions.

This script:
1. Computes the exact constraints for each residue class at each period
2. Enumerates all compatible CT position tuples per residue class
3. Estimates the total number of valid transpositions (before bijection)
4. If small enough, exhaustively searches for consistent assignments

Output: results/e_s_20_constraint_propagation.json
"""
import json
import sys
import time
from collections import defaultdict
from itertools import product

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Build CT position index: letter_value -> list of positions
CT_POS_BY_LETTER = defaultdict(list)
for i, v in enumerate(CT_NUM):
    CT_POS_BY_LETTER[v].append(i)


def analyze_period(period, variant="vig"):
    """Analyze constraints for a given period and cipher variant.

    Returns per-residue analysis and total valid combinations.
    """
    print(f"\n  Period {period}, variant={variant}")
    print(f"  {'='*50}")

    # Group crib positions by residue mod period
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % period].append(j)

    # For each residue class, derive the required CT value relationships
    results = {}
    total_combos = 1
    total_positions_needed = 0

    for res in range(period):
        group = residue_groups.get(res, [])
        if len(group) <= 1:
            # Only one crib position (or none): no constraint from pairing
            if len(group) == 1:
                # Single crib — any CT position works (97 choices, minus used ones)
                results[res] = {
                    "crib_positions": group,
                    "n_cribs": 1,
                    "n_valid_tuples": CT_LEN,
                    "constraint": "unconstrained (single crib)",
                }
                total_combos *= CT_LEN
                total_positions_needed += 1
            else:
                results[res] = {
                    "crib_positions": [],
                    "n_cribs": 0,
                    "n_valid_tuples": "N/A",
                    "constraint": "no cribs",
                }
            continue

        # Multiple crib positions: derive relationships
        # For Vigenère: key = (CT[σ^(-1)(j)] - PT[j]) mod 26 = constant for all j in group
        # For Beaufort: key = (CT[σ^(-1)(j)] + PT[j]) mod 26 = constant
        # Let's use the FIRST crib as reference and express others relative to it
        j0 = group[0]
        pt0 = CRIB_PT_NUM[j0]

        # For each 'a' (CT value at σ^(-1)(j0)), compute required CT values at other positions
        # Vigenère: key = (a - pt0) mod 26
        # For other j: CT[σ^(-1)(j)] = (key + PT[j]) mod 26 = (a - pt0 + PT[j]) mod 26
        # Beaufort: key = (a + pt0) mod 26
        # For other j: CT[σ^(-1)(j)] = (key - PT[j]) mod 26 = (a + pt0 - PT[j]) mod 26

        valid_tuples = 0
        valid_tuples_by_a = {}

        for a in range(MOD):
            if variant == "vig":
                key_val = (a - pt0) % MOD
                required = [(key_val + CRIB_PT_NUM[j]) % MOD for j in group]
            else:  # beaufort
                key_val = (a + pt0) % MOD
                required = [(key_val - CRIB_PT_NUM[j]) % MOD for j in group]

            # required[i] = the CT value that must appear at σ^(-1)(group[i])
            # Count how many distinct position tuples satisfy this
            pos_lists = [CT_POS_BY_LETTER[req] for req in required]
            n_each = [len(pl) for pl in pos_lists]

            if any(n == 0 for n in n_each):
                continue  # Some required letter doesn't exist in CT

            # Upper bound: product of counts (ignoring distinctness)
            from functools import reduce
            import operator
            combo_count = reduce(operator.mul, n_each, 1)
            valid_tuples += combo_count
            valid_tuples_by_a[a] = {
                "key_val": key_val,
                "required_letters": [chr(r + ord('A')) for r in required],
                "counts_per_pos": n_each,
                "combos": combo_count,
            }

        results[res] = {
            "crib_positions": group,
            "n_cribs": len(group),
            "n_valid_tuples": valid_tuples,
            "details_by_key": valid_tuples_by_a,
            "constraint": f"{len(group)} positions linked",
        }

        total_combos *= valid_tuples
        total_positions_needed += len(group)

        # Print summary for this residue
        print(f"    Residue {res}: {len(group)} cribs at {group}")
        if variant == "vig":
            deltas = [(CRIB_PT_NUM[j] - pt0) % MOD for j in group]
        else:
            deltas = [(pt0 - CRIB_PT_NUM[j]) % MOD for j in group]
        print(f"      PT values: {[CRIB_PT_NUM[j] for j in group]} ({[CRIB_DICT[j] for j in group]})")
        print(f"      Required CT deltas from first: {deltas}")
        print(f"      Valid assignment tuples: {valid_tuples:,}")

        # Show which key values have valid assignments
        best_key = max(valid_tuples_by_a.items(), key=lambda x: x[1]["combos"]) if valid_tuples_by_a else None
        if best_key:
            a, info = best_key
            print(f"      Richest key (a={a}, key={info['key_val']}): letters={info['required_letters']}, counts={info['counts_per_pos']}, combos={info['combos']}")

    print(f"\n    Total upper bound on transpositions: {total_combos:.2e}")
    print(f"    Positions constrained by cribs: {total_positions_needed}/97")
    print(f"    Remaining unconstrained: {CT_LEN - total_positions_needed}")

    return results, total_combos


def exact_count_with_exclusion(period, variant="vig"):
    """Count exact valid assignments respecting the distinctness constraint.

    For each residue class, the σ^(-1) must map to DISTINCT CT positions.
    Uses constraint propagation with backtracking.
    """
    print(f"\n  Exact count with distinctness (period={period}, {variant})")
    print(f"  {'='*50}")

    # Group crib positions by residue mod period
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % period].append(j)

    # For each residue class, enumerate valid tuples (sets of distinct CT positions)
    residue_options = {}  # res -> list of (key_val, tuple_of_ct_positions)

    for res in range(period):
        group = residue_groups.get(res, [])
        if not group:
            continue

        j0 = group[0]
        pt0 = CRIB_PT_NUM[j0]
        options = []

        for a in range(MOD):
            if variant == "vig":
                key_val = (a - pt0) % MOD
                required = [(key_val + CRIB_PT_NUM[j]) % MOD for j in group]
            else:
                key_val = (a + pt0) % MOD
                required = [(key_val - CRIB_PT_NUM[j]) % MOD for j in group]

            pos_lists = [CT_POS_BY_LETTER[req] for req in required]
            if any(len(pl) == 0 for pl in pos_lists):
                continue

            # Enumerate all tuples of distinct positions (recursive for any group size)
            # Cap per key value to avoid explosion
            MAX_PER_KEY = 500_000
            overflow = [False]

            def enum_distinct(depth, used, partial):
                if len(options) >= MAX_PER_KEY:
                    overflow[0] = True
                    return
                if depth == len(pos_lists):
                    options.append((key_val, tuple(partial)))
                    return
                for pos in pos_lists[depth]:
                    if pos not in used:
                        used.add(pos)
                        partial.append(pos)
                        enum_distinct(depth + 1, used, partial)
                        partial.pop()
                        used.discard(pos)
                        if overflow[0]:
                            return

            enum_distinct(0, set(), [])
            if overflow[0]:
                break  # Too many — this residue class is underconstrained

        residue_options[res] = options
        overflow_tag = " [OVERFLOW — capped]" if overflow[0] else ""
        print(f"    Residue {res}: {len(group)} cribs, {len(options):,} valid distinct tuples{overflow_tag}", flush=True)

    # Now check: can we select one tuple per residue class such that ALL CT positions are distinct?
    # This is a constraint satisfaction problem.
    # Order residue classes by ascending number of options (most constrained first)
    ordered_residues = sorted(residue_options.keys(), key=lambda r: len(residue_options[r]))

    if not ordered_residues:
        print("    No constrained residue classes!")
        return 0, []

    total_options = 1
    for r in ordered_residues:
        total_options *= len(residue_options[r])

    print(f"\n    Product of options (before cross-class exclusion): {total_options:.2e}")

    if total_options > 1e12:
        print("    Too large for exhaustive search. Using sampling.")
        return total_options, []

    # Backtracking search
    solutions = []
    max_solutions = 100  # Cap to prevent memory issues

    def backtrack(idx, used_positions, assignment):
        if len(solutions) >= max_solutions:
            return

        if idx == len(ordered_residues):
            solutions.append(dict(assignment))
            return

        res = ordered_residues[idx]
        for key_val, positions in residue_options[res]:
            if any(p in used_positions for p in positions):
                continue
            # Valid: no overlap with already-used positions
            new_used = used_positions | set(positions)
            assignment[res] = (key_val, positions)
            backtrack(idx + 1, new_used, assignment)
            del assignment[res]

    print(f"    Running backtracking search (max {max_solutions} solutions)...")
    t0 = time.time()
    backtrack(0, set(), {})
    elapsed = time.time() - t0

    print(f"    Found {len(solutions)} valid cross-class assignments in {elapsed:.2f}s")

    if solutions:
        # Show first few
        for i, sol in enumerate(solutions[:5]):
            key_str = ""
            for r in range(period):
                if r in sol:
                    key_str += f"  res {r}: key={sol[r][0]}, pos={sol[r][1]}"
            print(f"    Solution {i+1}:{key_str}")

    return len(solutions), solutions


def derive_plaintext(solution, period, variant="vig"):
    """Given a valid assignment of CT positions to crib positions,
    attempt to derive more plaintext.

    For each residue class, we know the key value. Apply it to ALL CT positions
    in that residue class (not just crib positions) to get candidate PT.
    """
    # Build key from solution
    key = [None] * period
    for res, (key_val, positions) in solution.items():
        key[res] = key_val

    # Build the inverse mapping: for each crib position j, σ^(-1)(j) is known
    # from the solution's position tuple
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % period].append(j)

    sigma_inv_partial = {}
    for res, (key_val, positions) in solution.items():
        group = residue_groups.get(res, [])
        for i, j in enumerate(group):
            sigma_inv_partial[j] = positions[i]

    # Print what we know
    print(f"\n    Key (partial): {key}")
    print(f"    σ^(-1) at cribs: {sigma_inv_partial}")

    # Check: do the key values form any recognizable pattern?
    key_letters = "".join(chr((k % MOD) + ord('A')) if k is not None else '?' for k in key)
    print(f"    Key as letters: {key_letters}")

    return key, sigma_inv_partial


def main():
    print("=" * 60)
    print("E-S-20: Algebraic Transposition Constraint Propagation")
    print("=" * 60)
    print(f"Model: CT = σ(Vig(PT, periodic_key))")
    print(f"Using 24 known crib positions to constrain transposition σ")
    print()

    t0 = time.time()
    all_results = {}

    # Phase 1: Analyze upper bounds for periods 3-13
    print("=" * 60)
    print("  Phase 1: Upper bound analysis")
    print("=" * 60)

    for p in range(3, 14):
        for variant in ["vig", "beau"]:
            results, total = analyze_period(p, variant)
            all_results[f"p{p}_{variant}_bounds"] = {
                "period": p,
                "variant": variant,
                "total_upper_bound": total,
                "per_residue": {str(k): {
                    "n_cribs": v["n_cribs"],
                    "n_valid_tuples": v["n_valid_tuples"] if isinstance(v["n_valid_tuples"], (int, float)) else str(v["n_valid_tuples"]),
                } for k, v in results.items()},
            }

    # Phase 2: Exact counts for most constrained periods
    print("\n" + "=" * 60)
    print("  Phase 2: Exact count with distinctness")
    print("=" * 60)

    for p in [3, 4, 5, 6, 7]:
        for variant in ["vig", "beau"]:
            n_solutions, solutions = exact_count_with_exclusion(p, variant)
            all_results[f"p{p}_{variant}_exact"] = {
                "period": p,
                "variant": variant,
                "n_solutions": n_solutions if isinstance(n_solutions, int) else float(n_solutions),
                "solutions_found": len(solutions),
            }

            # For solutions found, try to derive plaintext
            if solutions and len(solutions) <= 10:
                print(f"\n  Deriving plaintext from {len(solutions)} solutions (p={p}, {variant}):")
                for i, sol in enumerate(solutions[:5]):
                    print(f"\n  === Solution {i+1} ===")
                    key, sigma_inv = derive_plaintext(sol, p, variant)

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Time: {elapsed:.1f}s")

    # Show the most constrained configurations
    print(f"\n  Upper bounds by period (Vig):")
    for p in range(3, 14):
        key = f"p{p}_vig_bounds"
        if key in all_results:
            ub = all_results[key]["total_upper_bound"]
            print(f"    p={p}: {ub:.2e}")

    print(f"\n  Upper bounds by period (Beau):")
    for p in range(3, 14):
        key = f"p{p}_beau_bounds"
        if key in all_results:
            ub = all_results[key]["total_upper_bound"]
            print(f"    p={p}: {ub:.2e}")

    print(f"\n  Exact counts (with distinctness):")
    for p in [3, 4, 5, 6, 7]:
        for variant in ["vig", "beau"]:
            key = f"p{p}_{variant}_exact"
            if key in all_results:
                n = all_results[key]["n_solutions"]
                print(f"    p={p} {variant}: {n} valid cross-class assignments")

    # Save
    with open("results/e_s_20_constraint_propagation.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)

    print(f"\n  Artifacts: results/e_s_20_constraint_propagation.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_20_constraint_propagation.py")


if __name__ == "__main__":
    main()
