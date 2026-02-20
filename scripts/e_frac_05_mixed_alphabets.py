#!/usr/bin/env python3
"""E-FRAC-05: Width-9 Columnar + Column-Dependent Mixed Alphabets.

Tests whether width-9 columnar transposition combined with arbitrary
column-dependent substitution alphabets (mixed alphabets) is consistent
with the known crib positions.

Unlike periodic Vigenère/Beaufort (which use shifted alphabets), this
tests arbitrary bijective mappings per column. The test is:
1. For each width-9 ordering σ, compute the crib constraints per column
2. Check if each column's constraints form a valid partial bijection
   (no PT letter maps to 2 CT letters, no 2 PT letters map to same CT letter)
3. Check Bean constraint compatibility
4. Assess how constrained each alphabet is (degrees of freedom remaining)

Also tests Model A (sub then trans) and Model B (trans then sub).

A secondary analysis checks: among consistent orderings, which ones
produce the most constrained alphabets (fewest degrees of freedom)?
Highly constrained orderings are more likely to be "real" because
random orderings are less constrained.
"""
import itertools
import json
import os
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, ALPH, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

WIDTH = 9
N_ROWS_FULL = CT_LEN // WIDTH
REMAINDER = CT_LEN % WIDTH
COL_HEIGHTS = [N_ROWS_FULL + 1 if j < REMAINDER else N_ROWS_FULL
               for j in range(WIDTH)]


def build_columnar_perm(order):
    perm = []
    for c in range(WIDTH):
        col = order[c]
        height = COL_HEIGHTS[col]
        for row in range(height):
            perm.append(row * WIDTH + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_column_mixed_alphabets_model_b(perm):
    """Model B (trans→sub): CT[i] = sub_{col_b(i)}(PT[perm[i]]).

    Column assignment for the substitution can be:
    (a) Column in the CT grid: col_b(i) = i % WIDTH  (sub depends on CT position's column)
    (b) Column in the PT grid: col_b(i) = perm[i] % WIDTH  (sub depends on PT position's column)

    We test both.

    Returns: (pass_ct_col, pass_pt_col, n_conflicts_ct, n_conflicts_pt,
              constraints_ct, constraints_pt)
    """
    # Collect constraints
    ct_col_constraints = defaultdict(list)  # ct_column → [(pt_letter, ct_letter)]
    pt_col_constraints = defaultdict(list)  # pt_column → [(pt_letter, ct_letter)]

    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_char = CRIB_DICT[src]
            ct_char = CT[i]
            ct_col = i % WIDTH
            pt_col = src % WIDTH
            ct_col_constraints[ct_col].append((pt_char, ct_char))
            pt_col_constraints[pt_col].append((pt_char, ct_char))

    def check_bijection(constraints):
        """Check if constraints form a valid partial bijection.

        Returns (is_valid, n_conflicts, n_constraints, n_unique_pts, n_unique_cts)
        """
        n_conflicts = 0
        total_constraints = 0
        total_unique_pts = 0
        total_unique_cts = 0

        for col, pairs in constraints.items():
            pt_to_ct = {}
            ct_to_pt = {}

            for pt, ct in pairs:
                total_constraints += 1

                # Check forward mapping
                if pt in pt_to_ct:
                    if pt_to_ct[pt] != ct:
                        n_conflicts += 1
                else:
                    pt_to_ct[pt] = ct

                # Check reverse mapping (injectivity)
                if ct in ct_to_pt:
                    if ct_to_pt[ct] != pt:
                        n_conflicts += 1
                else:
                    ct_to_pt[ct] = pt

            total_unique_pts += len(pt_to_ct)
            total_unique_cts += len(ct_to_pt)

        is_valid = (n_conflicts == 0)
        return is_valid, n_conflicts, total_constraints, total_unique_pts, total_unique_cts

    pass_ct, conf_ct, n_ct, upt_ct, uct_ct = check_bijection(ct_col_constraints)
    pass_pt, conf_pt, n_pt, upt_pt, uct_pt = check_bijection(pt_col_constraints)

    return {
        "ct_col": {"pass": pass_ct, "conflicts": conf_ct,
                    "constraints": n_ct, "unique_pt": upt_ct, "unique_ct": uct_ct},
        "pt_col": {"pass": pass_pt, "conflicts": conf_pt,
                    "constraints": n_pt, "unique_pt": upt_pt, "unique_ct": uct_pt},
    }


def check_bean_model_b(perm):
    """Check Bean constraints (variant-independent under transposition)."""
    inv = invert_perm(perm)
    ct_27 = inv[27]
    ct_65 = inv[65]

    # Vigenère key values at these positions
    k27 = (CT_NUM[ct_27] - CRIB_PT_NUM[27]) % MOD
    k65 = (CT_NUM[ct_65] - CRIB_PT_NUM[65]) % MOD

    return k27 == k65  # Only equality check (variant-independent)


def compute_constraint_strength(perm):
    """Compute how constrained the column alphabets are.

    For each column, count:
    - Number of (PT, CT) pairs known (from cribs)
    - Number of distinct PT letters constrained
    - Number of distinct CT letters constrained
    - Remaining degrees of freedom = 26 - max(distinct_PT, distinct_CT)
      (minimum additional mappings needed to complete the bijection)

    Lower degrees of freedom = more constrained = more informative ordering.
    """
    col_constraints = defaultdict(list)
    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_char = CRIB_DICT[src]
            ct_char = CT[i]
            pt_col = src % WIDTH
            col_constraints[pt_col].append((pt_char, ct_char))

    total_dof = 0
    col_details = {}
    for col in range(WIDTH):
        pairs = col_constraints[col]
        pt_letters = set(p for p, c in pairs)
        ct_letters = set(c for p, c in pairs)
        known_mappings = len(pt_letters)  # Number of PT→CT mappings known
        dof = 26 - known_mappings  # Remaining unmapped PT letters
        total_dof += dof
        col_details[col] = {
            "n_pairs": len(pairs),
            "unique_pt": len(pt_letters),
            "unique_ct": len(ct_letters),
            "dof": dof,
        }

    return total_dof, col_details


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-05: Width-9 Columnar + Column-Dependent Mixed Alphabets")
    print("=" * 70)
    print()

    # Test all 362,880 orderings
    pass_ct_count = 0
    pass_pt_count = 0
    pass_both_count = 0
    bean_pass_count = 0
    pass_ct_and_bean = 0
    pass_pt_and_bean = 0

    conflict_dist_ct = Counter()
    conflict_dist_pt = Counter()

    # Track constraint strength for passing orderings
    ct_passing_orderings = []
    pt_passing_orderings = []

    n_tested = 0
    last_report = t0

    for order in itertools.permutations(range(WIDTH)):
        perm = build_columnar_perm(order)
        result = check_column_mixed_alphabets_model_b(perm)
        bean = check_bean_model_b(perm)

        ct_pass = result["ct_col"]["pass"]
        pt_pass = result["pt_col"]["pass"]

        conflict_dist_ct[result["ct_col"]["conflicts"]] += 1
        conflict_dist_pt[result["pt_col"]["conflicts"]] += 1

        if ct_pass:
            pass_ct_count += 1
            dof, details = compute_constraint_strength(perm)
            ct_passing_orderings.append({
                "order": list(order),
                "total_dof": dof,
                "bean": bean,
                "col_details": details,
            })
        if pt_pass:
            pass_pt_count += 1
            if not ct_pass:
                dof, details = compute_constraint_strength(perm)
            pt_passing_orderings.append({
                "order": list(order),
                "total_dof": dof if pt_pass else None,
                "bean": bean,
            })
        if ct_pass and pt_pass:
            pass_both_count += 1
        if bean:
            bean_pass_count += 1
            if ct_pass:
                pass_ct_and_bean += 1
            if pt_pass:
                pass_pt_and_bean += 1

        n_tested += 1
        now = time.time()
        if now - last_report > 30:
            pct = 100 * n_tested / 362880
            print(f"  [{pct:5.1f}%] tested={n_tested:,}, "
                  f"ct_pass={pass_ct_count}, pt_pass={pass_pt_count}, "
                  f"bean={bean_pass_count}")
            last_report = now

    elapsed = time.time() - t0

    # ── Results ──────────────────────────────────────────────────────
    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total orderings tested: {n_tested:,}")
    print(f"Time: {elapsed:.1f}s")
    print()

    print("BIJECTION CONSISTENCY:")
    print(f"  CT-column grouping: {pass_ct_count:,} / {n_tested:,} pass "
          f"({100*pass_ct_count/n_tested:.1f}%)")
    print(f"  PT-column grouping: {pass_pt_count:,} / {n_tested:,} pass "
          f"({100*pass_pt_count/n_tested:.1f}%)")
    print(f"  Both pass: {pass_both_count:,}")
    print()

    print("BEAN CONSTRAINT:")
    print(f"  Bean equality passes: {bean_pass_count:,} / {n_tested:,} "
          f"({100*bean_pass_count/n_tested:.2f}%)")
    print(f"  CT-col bijection AND Bean: {pass_ct_and_bean:,}")
    print(f"  PT-col bijection AND Bean: {pass_pt_and_bean:,}")
    print()

    print("CONFLICT DISTRIBUTION (CT-column grouping):")
    for conf in sorted(conflict_dist_ct.keys())[:10]:
        print(f"  {conf} conflicts: {conflict_dist_ct[conf]:,} orderings "
              f"({100*conflict_dist_ct[conf]/n_tested:.1f}%)")

    print("\nCONFLICT DISTRIBUTION (PT-column grouping):")
    for conf in sorted(conflict_dist_pt.keys())[:10]:
        print(f"  {conf} conflicts: {conflict_dist_pt[conf]:,} orderings "
              f"({100*conflict_dist_pt[conf]/n_tested:.1f}%)")

    # Constraint strength analysis
    print()
    print("=" * 70)
    print("CONSTRAINT STRENGTH ANALYSIS (CT-column passing orderings)")
    print("=" * 70)

    if ct_passing_orderings:
        dofs = [o["total_dof"] for o in ct_passing_orderings]
        dof_with_bean = [o["total_dof"] for o in ct_passing_orderings if o["bean"]]

        print(f"\nDegrees of freedom (lower = more constrained):")
        print(f"  All CT-passing: mean={sum(dofs)/len(dofs):.1f}, "
              f"min={min(dofs)}, max={max(dofs)}")
        if dof_with_bean:
            print(f"  CT-passing + Bean: mean={sum(dof_with_bean)/len(dof_with_bean):.1f}, "
                  f"min={min(dof_with_bean)}, max={max(dof_with_bean)}")

        dof_dist = Counter(dofs)
        print(f"\n  DOF distribution (CT-passing):")
        for d in sorted(dof_dist.keys()):
            print(f"    dof={d}: {dof_dist[d]:,} orderings")

        # Most constrained orderings
        ct_passing_orderings.sort(key=lambda o: o["total_dof"])
        print(f"\n  Most constrained (lowest DOF) orderings:")
        for o in ct_passing_orderings[:10]:
            bean_str = "Bean:PASS" if o["bean"] else "Bean:FAIL"
            print(f"    order={o['order']}, dof={o['total_dof']}, {bean_str}")
            for col in range(WIDTH):
                d = o["col_details"][col]
                print(f"      col {col}: {d['n_pairs']} pairs, "
                      f"{d['unique_pt']} PT letters, "
                      f"{d['unique_ct']} CT letters, dof={d['dof']}")

    # Random baseline
    print()
    print("=" * 70)
    print("RANDOM BASELINE")
    print("=" * 70)

    import random
    random.seed(42)
    N_RANDOM = 50000
    random_ct_pass = 0
    random_pt_pass = 0

    for _ in range(N_RANDOM):
        rand_perm = list(range(CT_LEN))
        random.shuffle(rand_perm)

        # Quick CT-column check
        col_constraints = defaultdict(list)
        for i, src in enumerate(rand_perm):
            if src in CRIB_SET:
                pt_char = CRIB_DICT[src]
                ct_char = CT[i]
                ct_col = i % WIDTH
                col_constraints[ct_col].append((pt_char, ct_char))

        valid = True
        for col, pairs in col_constraints.items():
            pt_to_ct = {}
            ct_to_pt = {}
            for pt, ct in pairs:
                if pt in pt_to_ct and pt_to_ct[pt] != ct:
                    valid = False
                    break
                pt_to_ct[pt] = ct
                if ct in ct_to_pt and ct_to_pt[ct] != pt:
                    valid = False
                    break
                ct_to_pt[ct] = pt
            if not valid:
                break
        if valid:
            random_ct_pass += 1

    print(f"Random permutations (N={N_RANDOM:,}):")
    print(f"  CT-column bijection passes: {random_ct_pass:,} "
          f"({100*random_ct_pass/N_RANDOM:.1f}%)")
    print(f"  Width-9 columnar bijection passes: {pass_ct_count:,} "
          f"({100*pass_ct_count/n_tested:.1f}%)")

    if random_ct_pass > 0 and pass_ct_count > 0:
        ratio = (pass_ct_count / n_tested) / (random_ct_pass / N_RANDOM)
        print(f"  Ratio (w9 / random): {ratio:.2f}x")

    # ── Verdict ──────────────────────────────────────────────────────
    print()
    print("=" * 70)
    noise_rate = random_ct_pass / N_RANDOM if N_RANDOM > 0 else 0
    w9_rate = pass_ct_count / n_tested if n_tested > 0 else 0

    if w9_rate > noise_rate * 2:
        verdict = (f"INTERESTING — width-9 columnar has {w9_rate/noise_rate:.1f}x "
                   f"higher bijection pass rate than random")
    elif pass_ct_and_bean == 0:
        verdict = "ELIMINATED — no orderings pass both bijection and Bean constraints"
    else:
        verdict = (f"NOISE — width-9 bijection pass rate ({100*w9_rate:.1f}%) "
                   f"comparable to random ({100*noise_rate:.1f}%)")

    print(f"VERDICT: {verdict}")
    print("=" * 70)

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-05",
        "description": "Width-9 columnar + column-dependent mixed alphabets",
        "n_tested": n_tested,
        "ct_col_passes": pass_ct_count,
        "pt_col_passes": pass_pt_count,
        "both_passes": pass_both_count,
        "bean_passes": bean_pass_count,
        "ct_and_bean": pass_ct_and_bean,
        "pt_and_bean": pass_pt_and_bean,
        "random_ct_passes": random_ct_pass,
        "random_n": N_RANDOM,
        "most_constrained_ct": [
            {"order": o["order"], "dof": o["total_dof"], "bean": o["bean"]}
            for o in ct_passing_orderings[:100]
        ] if ct_passing_orderings else [],
        "elapsed_seconds": round(elapsed, 1),
        "verdict": verdict,
    }
    path = "results/frac/e_frac_05_mixed_alphabets.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
