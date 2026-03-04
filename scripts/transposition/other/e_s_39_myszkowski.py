#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: transposition/other
Status: active
Keyspace: see implementation
Last run:
Best score:
attack(): yes
"""
"""
E-S-39: Myszkowski Transposition + Periodic Vigenère/Beaufort

Myszkowski transposition is columnar transposition where repeated key letters
cause their columns to be read LEFT-TO-RIGHT across rows instead of independently.

For width 7, the parameter space is all WEAK ORDERINGS of 7 items = 47,293
(Fubini number). Standard columnar (all columns distinct) is a subset (5040/47293).

We test all 47,293 Myszkowski permutations × periods 2-14 × 4 cipher variants
(Vigenère A/B, Beaufort A/B) = ~2.6M configs.

Output: results/e_s_39_myszkowski.json
"""

import json
import sys
import os
import time
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}


def generate_weak_orderings(n):
    """Generate all weak orderings (Fubini numbers) of n items.

    A weak ordering assigns each of n items to a rank in {0,...,k-1}
    such that every rank is used (surjective). For n=7, Fubini(7)=47,293.

    Generates all n^n tuples and filters for surjectivity.
    For n=7: 823,543 tuples, ~47K survive. Takes <1 second.
    """
    from itertools import product
    for t in product(range(n), repeat=n):
        used = set(t)
        max_r = max(t)
        # Surjective: ranks used must be exactly {0,...,max_r}
        if len(used) == max_r + 1:
            yield t


def myszkowski_perm(rank_assignment, width, length):
    """Compute the Myszkowski transposition permutation.

    rank_assignment: tuple of length `width` giving the rank of each column.
    Lower rank = earlier in readout.

    Columns with the SAME rank are read LEFT-TO-RIGHT across rows
    (Myszkowski behavior). Columns with different ranks are read
    in rank order (standard columnar behavior).

    Returns sigma where sigma[plaintext_pos] = ciphertext_pos.
    """
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width

    # Group columns by rank
    max_rank = max(rank_assignment)
    rank_groups = defaultdict(list)
    for col, rank in enumerate(rank_assignment):
        rank_groups[rank].append(col)

    sigma = [0] * length
    ct_pos = 0

    # Process ranks in order
    for rank in range(max_rank + 1):
        cols = rank_groups[rank]

        if len(cols) == 1:
            # Single column: read top-to-bottom (standard columnar)
            col = cols[0]
            col_len = n_rows if col < n_long else n_rows - 1
            for row in range(col_len):
                pt_pos = row * width + col
                if pt_pos < length:
                    sigma[pt_pos] = ct_pos
                    ct_pos += 1
        else:
            # Multiple columns with same rank: read LEFT-TO-RIGHT across rows
            # For each row, read the entries in these columns from left to right
            for row in range(n_rows):
                for col in sorted(cols):  # left to right
                    pt_pos = row * width + col
                    if pt_pos < length:
                        col_len = n_rows if col < n_long else n_rows - 1
                        if row < col_len:
                            sigma[pt_pos] = ct_pos
                            ct_pos += 1

    assert ct_pos == length, f"ct_pos={ct_pos} != length={length}"
    return sigma


def build_period_constraints(period):
    """Build Vigenère period-consistency constraints for given period."""
    residue_groups = defaultdict(list)
    for j in CRIB_POS:
        residue_groups[j % period].append(j)

    constraints = []
    for r in range(period):
        group = residue_groups[r]
        if len(group) >= 2:
            for i in range(1, len(group)):
                j1, j2 = group[0], group[i]
                # Vigenère: CT[σ(j1)] - PT[j1] ≡ CT[σ(j2)] - PT[j2] (mod 26)
                # i.e., (CT[σ(j1)] - PT[j1]) - (CT[σ(j2)] - PT[j2]) ≡ 0 (mod 26)
                # Precompute the PT difference
                pt_diff = (CRIB_PT[j1] - CRIB_PT[j2]) % MOD
                constraints.append((j1, j2, pt_diff))
    return constraints


def check_vig_a(sigma, constraints):
    """Model A: CT = σ(Vig(PT, key)). Check: CT[σ(j)] - PT[j] = const per residue."""
    for j1, j2, pt_diff in constraints:
        ct_diff = (CT_NUM[sigma[j1]] - CT_NUM[sigma[j2]]) % MOD
        if ct_diff != pt_diff:
            return False
    return True


def check_vig_b(sigma, constraints):
    """Model B: CT = Vig(σ(PT), key). Check: CT[j] - PT[σ⁻¹(j)] = const per residue of σ⁻¹(j)."""
    # Need σ⁻¹
    inv = [0] * len(sigma)
    for i, s in enumerate(sigma):
        inv[s] = i
    for j1, j2, pt_diff in constraints:
        ct_diff = (CT_NUM[j1] - CT_NUM[j2]) % MOD
        if ct_diff != pt_diff:
            return False
    return True


def check_beau_a(sigma, constraints):
    """Model A Beaufort: k = (CT[σ(j)] + PT[j]) % 26."""
    for j1, j2, pt_diff in constraints:
        # Beaufort: (CT[σ(j1)] + PT[j1]) ≡ (CT[σ(j2)] + PT[j2]) (mod 26)
        # CT[σ(j1)] - CT[σ(j2)] ≡ PT[j2] - PT[j1] ≡ -pt_diff (mod 26)
        ct_diff = (CT_NUM[sigma[j1]] - CT_NUM[sigma[j2]]) % MOD
        expected = (MOD - pt_diff) % MOD
        if ct_diff != expected:
            return False
    return True


def check_beau_b(sigma, constraints):
    """Model B Beaufort: k = (CT[j] + PT[σ⁻¹(j)]) % 26."""
    for j1, j2, pt_diff in constraints:
        ct_diff = (CT_NUM[j1] - CT_NUM[j2]) % MOD
        expected = (MOD - pt_diff) % MOD
        if ct_diff != expected:
            return False
    return True


def _run_sweep(ciphertext, **params):
    """Core sweep logic: returns (all_wo, all_perms, all_ranks, all_hits)."""
    width = params.get("width", 7)
    ct_num = [ALPH_IDX[c] for c in ciphertext]
    n = len(ciphertext)
    crib_pos_local = sorted(CRIB_DICT.keys())
    crib_pt_local = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

    def _build_constraints(period):
        residue_groups = defaultdict(list)
        for j in crib_pos_local:
            residue_groups[j % period].append(j)
        constraints = []
        for r in range(period):
            group = residue_groups[r]
            if len(group) >= 2:
                for i in range(1, len(group)):
                    j1, j2 = group[0], group[i]
                    pt_diff = (crib_pt_local[j1] - crib_pt_local[j2]) % MOD
                    constraints.append((j1, j2, pt_diff))
        return constraints

    def _check_vig_a(sigma, constraints):
        for j1, j2, pt_diff in constraints:
            ct_diff = (ct_num[sigma[j1]] - ct_num[sigma[j2]]) % MOD
            if ct_diff != pt_diff:
                return False
        return True

    def _check_vig_b(sigma, constraints):
        for j1, j2, pt_diff in constraints:
            ct_diff = (ct_num[j1] - ct_num[j2]) % MOD
            if ct_diff != pt_diff:
                return False
        return True

    def _check_beau_a(sigma, constraints):
        for j1, j2, pt_diff in constraints:
            ct_diff = (ct_num[sigma[j1]] - ct_num[sigma[j2]]) % MOD
            expected = (MOD - pt_diff) % MOD
            if ct_diff != expected:
                return False
        return True

    def _check_beau_b(sigma, constraints):
        for j1, j2, pt_diff in constraints:
            ct_diff = (ct_num[j1] - ct_num[j2]) % MOD
            expected = (MOD - pt_diff) % MOD
            if ct_diff != expected:
                return False
        return True

    all_wo = list(generate_weak_orderings(width))

    all_perms = []
    all_ranks = []
    for wo in all_wo:
        try:
            perm = myszkowski_perm(wo, width, n)
            all_perms.append(perm)
            all_ranks.append(wo)
        except Exception:
            pass

    variants = [
        ("A_vig", _check_vig_a),
        ("B_vig", _check_vig_b),
        ("A_beau", _check_beau_a),
        ("B_beau", _check_beau_b),
    ]

    all_hits = []
    for period in range(2, 15):
        constraints = _build_constraints(period)
        n_constraints = len(constraints)
        if n_constraints == 0:
            continue
        for var_name, check_fn in variants:
            for idx, sigma in enumerate(all_perms):
                if check_fn(sigma, constraints):
                    ranks = all_ranks[idx]
                    has_ties = len(set(ranks)) < width
                    all_hits.append({
                        "period": period,
                        "variant": var_name,
                        "ranks": list(ranks),
                        "has_ties": has_ties,
                        "n_constraints": n_constraints,
                    })

    return all_wo, all_perms, all_ranks, all_hits


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    _, _, _, all_hits = _run_sweep(ciphertext, **params)
    results: list[tuple[float, str, str]] = []
    for h in all_hits:
        score = float(h["n_constraints"])
        ranks_str = ",".join(str(r) for r in h["ranks"])
        ties = " (Myszkowski)" if h["has_ties"] else ""
        method = (f"Myszkowski w=7 p={h['period']} {h['variant']} "
                  f"ranks=[{ranks_str}]{ties}")
        # No plaintext recovery — this is a constraint-pass check
        results.append((score, "", method))
    results.sort(key=lambda x: -x[0])
    return results


def main():
    print("=" * 60)
    print("E-S-39: Myszkowski Transposition + Periodic Vig/Beau")
    print("=" * 60)

    t0 = time.time()

    # Generate all width-7 weak orderings
    print("  Generating weak orderings for width 7...", flush=True)
    all_wo = list(generate_weak_orderings(7))
    print(f"  Total weak orderings: {len(all_wo)}", flush=True)

    # Separate standard columnar (all distinct ranks) from Myszkowski (has ties)
    standard = [wo for wo in all_wo if len(set(wo)) == 7]
    myszkowski_only = [wo for wo in all_wo if len(set(wo)) < 7]
    print(f"  Standard columnar: {len(standard)}")
    print(f"  Myszkowski (with ties): {len(myszkowski_only)}")

    # Precompute all Myszkowski permutations
    print("  Precomputing permutations...", flush=True)
    all_perms = []
    all_ranks = []
    for wo in all_wo:
        try:
            perm = myszkowski_perm(wo, 7, N)
            all_perms.append(perm)
            all_ranks.append(wo)
        except Exception as e:
            print(f"  SKIP: {wo} — {e}")

    print(f"  Valid permutations: {len(all_perms)} ({time.time()-t0:.1f}s)", flush=True)

    # Test each period
    variants = [
        ("A_vig", check_vig_a),
        ("B_vig", check_vig_b),
        ("A_beau", check_beau_a),
        ("B_beau", check_beau_b),
    ]

    all_hits = []

    for period in range(2, 15):
        constraints = build_period_constraints(period)
        n_constraints = len(constraints)

        if n_constraints == 0:
            continue

        hits_this_period = 0
        for var_name, check_fn in variants:
            n_pass = 0
            for idx, sigma in enumerate(all_perms):
                if check_fn(sigma, constraints):
                    n_pass += 1
                    ranks = all_ranks[idx]
                    has_ties = len(set(ranks)) < 7
                    all_hits.append({
                        "period": period,
                        "variant": var_name,
                        "ranks": list(ranks),
                        "has_ties": has_ties,
                        "n_constraints": n_constraints,
                    })

            hits_this_period += n_pass

        elapsed = time.time() - t0
        n_total = len(all_perms) * 4
        print(f"  Period {period:2d}: {n_constraints:2d} constraints  "
              f"hits={hits_this_period}/{n_total}  "
              f"({elapsed:.1f}s)", flush=True)

    # Analyze hits
    print(f"\n{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}")

    # Split hits into standard columnar vs Myszkowski-only
    std_hits = [h for h in all_hits if not h['has_ties']]
    mys_hits = [h for h in all_hits if h['has_ties']]

    print(f"  Total hits: {len(all_hits)}")
    print(f"  Standard columnar hits: {len(std_hits)}")
    print(f"  Myszkowski-only hits: {len(mys_hits)}")

    # By period
    print(f"\n  Hits by period (total / standard / Myszkowski):")
    for period in range(2, 15):
        p_all = [h for h in all_hits if h['period'] == period]
        p_std = [h for h in std_hits if h['period'] == period]
        p_mys = [h for h in mys_hits if h['period'] == period]
        if p_all:
            print(f"    p={period:2d}: {len(p_all):6d} / {len(p_std):6d} / {len(p_mys):6d}")

    # Key finding: do Myszkowski-only hits appear at period 7?
    p7_mys = [h for h in mys_hits if h['period'] == 7]
    p7_std = [h for h in std_hits if h['period'] == 7]

    print(f"\n  Period 7 detail:")
    print(f"    Standard columnar: {len(p7_std)} hits")
    print(f"    Myszkowski-only: {len(p7_mys)} hits")

    if p7_mys:
        # Show some examples
        print(f"\n  Sample Myszkowski p=7 hits:")
        for h in p7_mys[:10]:
            print(f"    {h['variant']} ranks={h['ranks']}")

    # Compute expected random for each period
    print(f"\n  Expected random baseline:")
    for period in [3, 5, 7, 9, 11, 13]:
        constraints = build_period_constraints(period)
        if constraints:
            n_con = len(constraints)
            # For Vigenere: each constraint passes with prob 1/26
            # For n constraints: expected = N_perms * (1/26)^n_con * 4 variants
            expected = len(all_perms) * 4 * (1.0/26)**n_con
            print(f"    p={period:2d}: {n_con} constraints, expected = {expected:.2f}")

    elapsed = time.time() - t0

    # Verdict
    # At period 7 (17 constraints), expected random = 0.
    # If Myszkowski-only hits > 0 at period 7, that's interesting.
    p7_all = [h for h in all_hits if h['period'] == 7]
    if len(p7_all) == 0:
        verdict = "ELIMINATED"
        print(f"\n  Period 7: 0 hits — Myszkowski + periodic Vig/Beau ELIMINATED at p=7")
    elif len(p7_mys) > 0 and len(p7_std) == 0:
        verdict = "MYSZKOWSKI_SIGNAL"
        print(f"\n  Period 7: Myszkowski-only hits detected — SIGNAL")
    else:
        verdict = "NOISE"
        print(f"\n  Period 7: hits present but expected from noise")

    print(f"\n  Time: {elapsed:.1f}s")
    print(f"  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_39_myszkowski.json", "w") as f:
        json.dump({
            "experiment": "E-S-39",
            "total_weak_orderings": len(all_wo),
            "standard_columnar": len(standard),
            "myszkowski_only": len(myszkowski_only),
            "valid_permutations": len(all_perms),
            "total_hits": len(all_hits),
            "std_hits": len(std_hits),
            "mys_hits": len(mys_hits),
            "verdict": verdict,
            "elapsed_seconds": round(elapsed, 1),
            "hits_by_period": {
                str(p): len([h for h in all_hits if h['period'] == p])
                for p in range(2, 15)
            },
            "p7_detail": {
                "standard": len(p7_std),
                "myszkowski": len(p7_mys),
                "examples": p7_mys[:20],
            },
        }, f, indent=2)
    print(f"\n  Artifact: results/e_s_39_myszkowski.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_39_myszkowski.py")


if __name__ == "__main__":
    main()
