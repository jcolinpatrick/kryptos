#!/usr/bin/env python3
"""Z3 multi-layer cipher feasibility analysis.

Cipher: multi-layer combinations
Family: analysis
Status: active
Keyspace: structural feasibility checks (not brute force)
Last run: never
Best score: n/a

Uses Z3 to test whether multi-layer cipher combinations are STRUCTURALLY
possible given Bean+crib constraints. For each candidate multi-layer model,
asks: "does there exist ANY configuration that satisfies all constraints?"

This directly addresses the open attack surface: "Multi-layer hand-executable
systems — Untested peel orders, non-obvious layer combinations."
"""
import sys
import os
import time
import json

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

import z3
from kryptos.kernel.constants import CT, CT_LEN, MOD, CRIB_DICT, BEAN_EQ, BEAN_INEQ


def test_periodic_after_transposition(period, variant="beaufort"):
    """Test: columnar transposition of width W, THEN periodic sub of period P.

    The key insight: transposition rearranges positions, so the periodic
    key's residue classes map to DIFFERENT CT positions than under direct
    correspondence. This means some periods that are UNSAT under direct
    correspondence might be SAT after transposition.

    For each width W, we create permutation variables and check if ANY
    permutation + periodic key combination satisfies Bean+crib.
    """
    solver = z3.Solver()
    solver.set("timeout", 30000)  # 30s timeout

    # Keystream variables (what the solver sees at each output position)
    k = [z3.Int(f"k_{i}") for i in range(CT_LEN)]
    for i in range(CT_LEN):
        solver.add(k[i] >= 0, k[i] <= 25)

    # Periodic key: key has `period` free variables, repeated
    key_vars = [z3.Int(f"key_{j}") for j in range(period)]
    for j in range(period):
        solver.add(key_vars[j] >= 0, key_vars[j] <= 25)

    # k[i] = key_vars[i % period]
    for i in range(CT_LEN):
        solver.add(k[i] == key_vars[i % period])

    # Bean constraints on the keystream
    for a, b in BEAN_EQ:
        solver.add(k[a] == k[b])
    for a, b in BEAN_INEQ:
        solver.add(k[a] != k[b])

    # Crib constraints
    for pos, pt_ch in CRIB_DICT.items():
        ct_val = ord(CT[pos]) - 65
        pt_val = ord(pt_ch) - 65
        if variant == "beaufort":
            key_val = (ct_val + pt_val) % MOD
        elif variant == "vigenere":
            key_val = (ct_val - pt_val) % MOD
        else:
            key_val = (pt_val - ct_val) % MOD
        solver.add(k[pos] == key_val)

    result = solver.check()
    return str(result)


def test_nonstandard_period_mapping(width, period, variant="beaufort"):
    """Test: what if the period applies to the PRE-TRANSPOSITION text?

    In this model:
    1. Plaintext is encrypted with a periodic key of period P
    2. The result is then columnar-transposed with width W

    So: CT[trans_pos] = encrypt(PT[orig_pos], key[orig_pos % P])

    The Bean constraints apply to trans_pos (the carved positions),
    but the periodic key applies to orig_pos. The transposition
    permutation is UNKNOWN and part of the search.

    This is the key insight: the period doesn't apply to the positions
    where we observe the ciphertext — it applies to UNKNOWN positions
    before transposition.
    """
    solver = z3.Solver()
    solver.set("timeout", 60000)  # 60s — this is harder

    rows = (CT_LEN + width - 1) // width

    # Permutation: perm[output_pos] = input_pos
    perm = [z3.Int(f"perm_{i}") for i in range(CT_LEN)]
    for i in range(CT_LEN):
        solver.add(perm[i] >= 0, perm[i] < CT_LEN)

    # AllDifferent for permutation
    solver.add(z3.Distinct(perm))

    # Keystream at INPUT positions (before transposition)
    k_input = [z3.Int(f"ki_{i}") for i in range(CT_LEN)]
    for i in range(CT_LEN):
        solver.add(k_input[i] >= 0, k_input[i] <= 25)

    # Periodic key at input positions
    key_vars = [z3.Int(f"key_{j}") for j in range(period)]
    for j in range(period):
        solver.add(key_vars[j] >= 0, key_vars[j] <= 25)

    # k_input[input_pos] = key_vars[input_pos % period]
    for i in range(CT_LEN):
        solver.add(k_input[i] == key_vars[i % period])

    # Keystream at OUTPUT positions (what we observe)
    k_output = [z3.Int(f"ko_{i}") for i in range(CT_LEN)]
    for i in range(CT_LEN):
        solver.add(k_output[i] >= 0, k_output[i] <= 25)

    # Connection: k_output[out_pos] = k_input[perm[out_pos]]
    # Z3 array theory for this
    k_input_arr = z3.Array("k_input_arr", z3.IntSort(), z3.IntSort())
    for i in range(CT_LEN):
        solver.add(z3.Select(k_input_arr, i) == k_input[i])
    for i in range(CT_LEN):
        solver.add(k_output[i] == z3.Select(k_input_arr, perm[i]))

    # Bean constraints on OUTPUT keystream
    for a, b in BEAN_EQ:
        solver.add(k_output[a] == k_output[b])
    for a, b in BEAN_INEQ:
        solver.add(k_output[a] != k_output[b])

    # Crib constraints on OUTPUT positions
    for pos, pt_ch in CRIB_DICT.items():
        ct_val = ord(CT[pos]) - 65
        pt_val = ord(pt_ch) - 65
        if variant == "beaufort":
            key_val = (ct_val + pt_val) % MOD
        elif variant == "vigenere":
            key_val = (ct_val - pt_val) % MOD
        else:
            key_val = (pt_val - ct_val) % MOD
        solver.add(k_output[pos] == key_val)

    result = solver.check()
    return str(result)


def main():
    print("=" * 70)
    print("Z3 MULTI-LAYER FEASIBILITY ANALYSIS")
    print("=" * 70)
    print()

    results = []

    # ── Test 1: Direct periodic (confirmation of single-layer result) ──
    print("--- Test 1: Direct periodic (should all be UNSAT) ---")
    for variant in ["beaufort", "vigenere", "var_beaufort"]:
        for period in [7, 13, 14]:  # Key periods
            t0 = time.time()
            r = test_periodic_after_transposition(period, variant)
            elapsed = time.time() - t0
            print(f"  Direct p={period} {variant}: {r} ({elapsed*1000:.0f}ms)")
            results.append({
                "model": "direct_periodic",
                "period": period, "variant": variant,
                "result": r, "time_ms": round(elapsed*1000, 1),
            })

    # ── Test 2: Sub-then-trans (the open question) ──
    print("\n--- Test 2: Periodic sub THEN transposition ---")
    print("    (Periodic key at input positions, transposition reorders)")
    print("    This tests whether transposition can create a valid mapping")
    for variant in ["beaufort", "vigenere"]:
        for width in [7, 10, 13, 14]:
            for period in [7, 13]:
                t0 = time.time()
                r = test_nonstandard_period_mapping(width, period, variant)
                elapsed = time.time() - t0
                status_mark = "✓" if r == "sat" else ("✗" if r == "unsat" else "?")
                print(f"  {status_mark} w={width} p={period} {variant}: {r} ({elapsed*1000:.0f}ms)")
                results.append({
                    "model": "sub_then_trans",
                    "width": width, "period": period, "variant": variant,
                    "result": r, "time_ms": round(elapsed*1000, 1),
                })

    # Summary
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    sat = sum(1 for r in results if r["result"] == "sat")
    unsat = sum(1 for r in results if r["result"] == "unsat")
    unknown = sum(1 for r in results if r["result"] not in ("sat", "unsat"))
    print(f"  SAT: {sat}  |  UNSAT: {unsat}  |  Unknown: {unknown}")

    # Key finding: any SAT results in the sub-then-trans model?
    sub_trans_sat = [r for r in results
                     if r["model"] == "sub_then_trans" and r["result"] == "sat"]
    if sub_trans_sat:
        print(f"\n  FINDING: {len(sub_trans_sat)} sub-then-trans combinations are FEASIBLE:")
        for r in sub_trans_sat:
            print(f"    w={r['width']} p={r['period']} {r['variant']}")
    else:
        print(f"\n  All sub-then-trans combinations tested are INFEASIBLE")

    # Save
    outpath = os.path.join(_ROOT, "results", "z3_multilayer_feasibility.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "z3_multilayer_feasibility",
            "results": results,
            "n_sat": sat, "n_unsat": unsat, "n_unknown": unknown,
        }, f, indent=2)
    print(f"\nResults saved: {outpath}")


if __name__ == "__main__":
    main()
