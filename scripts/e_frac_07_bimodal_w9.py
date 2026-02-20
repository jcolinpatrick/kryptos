#!/usr/bin/env python3
"""E-FRAC-07: Width-9 Bimodal Fingerprint Analysis.

The bimodal fingerprint is a key constraint from the crib analysis:
- Positions 22-30 (ENE crib first half): should map NEAR themselves
  after transposition (i.e., perm[i] ≈ i for i in 22-30)
- Positions 64-74 (BC crib): should NOT all map near themselves

This constrains which width-9 orderings are plausible.

This experiment:
1. For all 362,880 width-9 orderings, check the bimodal fingerprint
2. Identify orderings where positions 22-30 are near-identity AND
   positions 64-74 are scattered
3. Cross-reference with Bean constraint
4. For surviving orderings, test all substitution models

Also: what if we flip the bimodal assumption (BC near-identity, ENE scattered)?
"""
import itertools
import json
import os
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD,
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


def bimodal_check(perm, ene_tolerance=5, bc_max_identity=4):
    """Check the bimodal fingerprint.

    Standard: positions 22-30 near identity, 64-74 scattered.

    Returns (passes, ene_displacement, bc_identity_count).
    """
    inv = invert_perm(perm)

    # After undoing transposition: intermediate[j] = CT[inv[j]]
    # The permutation maps PT position j to CT position inv[j]
    # "Near identity" means inv[j] ≈ j

    ene_displacements = []
    for i in range(22, 31):
        if i < CT_LEN:
            ene_displacements.append(abs(inv[i] - i))

    bc_identity = 0
    for i in range(64, min(75, CT_LEN)):
        if abs(inv[i] - i) <= 2:
            bc_identity += 1

    ene_max_disp = max(ene_displacements) if ene_displacements else 0
    ene_pass = ene_max_disp <= ene_tolerance
    bc_pass = bc_identity <= bc_max_identity

    return ene_pass and bc_pass, ene_max_disp, bc_identity


def bimodal_check_flipped(perm, bc_tolerance=5, ene_max_identity=4):
    """Flipped bimodal: BC near identity, ENE scattered."""
    inv = invert_perm(perm)

    bc_displacements = []
    for i in range(64, min(74, CT_LEN)):
        bc_displacements.append(abs(inv[i] - i))

    ene_identity = 0
    for i in range(22, 31):
        if abs(inv[i] - i) <= 2:
            ene_identity += 1

    bc_max_disp = max(bc_displacements) if bc_displacements else 0
    bc_pass = bc_max_disp <= bc_tolerance
    ene_pass = ene_identity <= ene_max_identity

    return bc_pass and ene_pass, bc_max_disp, ene_identity


def check_bean(perm, variant):
    inv = invert_perm(perm)
    ct_27 = inv[27]
    ct_65 = inv[65]
    pt27 = CRIB_PT_NUM[27]
    pt65 = CRIB_PT_NUM[65]
    if variant == 0:
        k27 = (CT_NUM[ct_27] - pt27) % MOD
        k65 = (CT_NUM[ct_65] - pt65) % MOD
    elif variant == 1:
        k27 = (CT_NUM[ct_27] + pt27) % MOD
        k65 = (CT_NUM[ct_65] + pt65) % MOD
    else:
        k27 = (pt27 - CT_NUM[ct_27]) % MOD
        k65 = (pt65 - CT_NUM[ct_65]) % MOD
    if k27 != k65:
        return False
    for a, b in BEAN_INEQ:
        if a in CRIB_SET and b in CRIB_SET:
            ct_a = inv[a]
            ct_b = inv[b]
            if variant == 0:
                ka = (CT_NUM[ct_a] - CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] - CRIB_PT_NUM[b]) % MOD
            elif variant == 1:
                ka = (CT_NUM[ct_a] + CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] + CRIB_PT_NUM[b]) % MOD
            else:
                ka = (CRIB_PT_NUM[a] - CT_NUM[ct_a]) % MOD
                kb = (CRIB_PT_NUM[b] - CT_NUM[ct_b]) % MOD
            if ka == kb:
                return False
    return True


def majority_score(perm, period, variant, model):
    residue_groups = defaultdict(list)
    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = CT_NUM[i]
            if variant == 0:
                k = (ct_val - pt_val) % MOD
            elif variant == 1:
                k = (ct_val + pt_val) % MOD
            else:
                k = (pt_val - ct_val) % MOD
            if model == 0:
                residue_groups[src % period].append(k)
            else:
                residue_groups[i % period].append(k)
    n_consistent = 0
    for vals in residue_groups.values():
        if vals:
            counts = Counter(vals)
            n_consistent += counts.most_common(1)[0][1]
    return n_consistent


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-07: Width-9 Bimodal Fingerprint Analysis")
    print("=" * 70)
    print()

    VARIANT_NAMES = ["vigenere", "beaufort", "variant_beaufort"]

    # Test multiple tolerance levels
    tolerances = [(3, 3), (5, 4), (7, 5), (10, 6)]

    for ene_tol, bc_max in tolerances:
        print(f"\n--- Tolerance: ENE max displacement ≤{ene_tol}, "
              f"BC identity count ≤{bc_max} ---")

        pass_count = 0
        pass_and_bean = {0: 0, 1: 0, 2: 0}
        passing_orderings = []

        for order in itertools.permutations(range(WIDTH)):
            perm = build_columnar_perm(order)
            passed, ene_disp, bc_id = bimodal_check(perm, ene_tol, bc_max)

            if passed:
                pass_count += 1
                bean_results = {}
                for v in range(3):
                    bean_results[v] = check_bean(perm, v)
                    if bean_results[v]:
                        pass_and_bean[v] += 1

                passing_orderings.append({
                    "order": list(order),
                    "ene_disp": ene_disp,
                    "bc_id": bc_id,
                    "bean": bean_results,
                })

        print(f"  Pass: {pass_count:,} / 362,880 ({100*pass_count/362880:.3f}%)")
        for v in range(3):
            print(f"  + Bean ({VARIANT_NAMES[v]}): {pass_and_bean[v]:,}")

        # For the tightest tolerance that has passes, show details
        if pass_count > 0 and pass_count <= 1000:
            # Score all passing orderings
            best_per_variant = {v: {"score": 0} for v in range(3)}
            for p_ord in passing_orderings:
                order = p_ord["order"]
                perm = build_columnar_perm(order)
                for variant in range(3):
                    for model in range(2):
                        for period in range(2, 8):
                            sc = majority_score(perm, period, variant, model)
                            if sc > best_per_variant[variant]["score"]:
                                best_per_variant[variant] = {
                                    "score": sc,
                                    "order": order,
                                    "model": "A" if model == 0 else "B",
                                    "period": period,
                                }

            print(f"\n  Best scores (periods 2-7) among bimodal-passing orderings:")
            for v in range(3):
                b = best_per_variant[v]
                print(f"    {VARIANT_NAMES[v]}: {b['score']}/24 "
                      f"(p={b.get('period','?')}, model {b.get('model','?')}, "
                      f"order={b.get('order','?')})")

    # Also test flipped bimodal
    print(f"\n{'='*70}")
    print("FLIPPED BIMODAL (BC near-identity, ENE scattered)")
    print(f"{'='*70}")

    for bc_tol, ene_max in tolerances:
        flip_count = 0
        for order in itertools.permutations(range(WIDTH)):
            perm = build_columnar_perm(order)
            passed, bc_disp, ene_id = bimodal_check_flipped(perm, bc_tol, ene_max)
            if passed:
                flip_count += 1
        print(f"  BC tol ≤{bc_tol}, ENE identity ≤{ene_max}: "
              f"{flip_count:,} / 362,880 ({100*flip_count/362880:.3f}%)")

    # ── Displacement distribution ────────────────────────────────────
    print(f"\n{'='*70}")
    print("DISPLACEMENT DISTRIBUTION")
    print(f"{'='*70}")

    ene_max_disps = []
    bc_id_counts = []
    for order in itertools.permutations(range(WIDTH)):
        perm = build_columnar_perm(order)
        _, ene_disp, bc_id = bimodal_check(perm, 999, 999)
        ene_max_disps.append(ene_disp)
        bc_id_counts.append(bc_id)

    ene_dist = Counter(ene_max_disps)
    bc_dist = Counter(bc_id_counts)

    print("\nENE max displacement distribution:")
    for d in sorted(ene_dist.keys()):
        print(f"  ≤{d:2d}: {sum(c for k, c in ene_dist.items() if k <= d):>8,} "
              f"({100*sum(c for k, c in ene_dist.items() if k <= d)/362880:.2f}%)")
        if d >= 30:
            break

    print("\nBC identity count distribution:")
    for d in sorted(bc_dist.keys()):
        pct = 100 * bc_dist[d] / 362880
        cum = sum(c for k, c in bc_dist.items() if k <= d)
        print(f"  ={d}: {bc_dist[d]:>8,} ({pct:.2f}%), "
              f"cumulative ≤{d}: {cum:,} ({100*cum/362880:.2f}%)")

    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total time: {elapsed:.1f}s")
    print()
    print("The bimodal fingerprint is a NECESSARY but not SUFFICIENT condition.")
    print("Combined with Bean and periodic consistency, it narrows the search space.")
    print()

    # For the most useful tolerance (5, 4), print the count
    for ene_tol, bc_max in [(5, 4)]:
        pass_count = sum(1 for d, b in zip(ene_max_disps, bc_id_counts)
                         if d <= ene_tol and b <= bc_max)
        print(f"At tolerance (ENE≤{ene_tol}, BC≤{bc_max}): "
              f"{pass_count:,} orderings ({100*pass_count/362880:.2f}%)")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-07",
        "description": "Width-9 bimodal fingerprint analysis",
        "ene_disp_dist": {str(k): v for k, v in sorted(ene_dist.items())},
        "bc_id_dist": {str(k): v for k, v in sorted(bc_dist.items())},
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_07_bimodal.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
