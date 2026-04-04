#!/usr/bin/env python3
"""Z3 periodic key feasibility sweep across all periods and variants.

Cipher: periodic polyalphabetic (all variants)
Family: analysis
Status: active
Keyspace: 26 periods × 3 variants = 78 feasibility checks
Last run: never
Best score: n/a

Uses Z3 SMT solver to PROVE whether a periodic key at each period
is compatible with Bean + crib constraints. This replaces brute-force
enumeration with mathematical proof.

For each (period, variant), the solver answers SAT/UNSAT:
  - SAT: there exists at least one key of that period satisfying all constraints
  - UNSAT: no key of that period can satisfy all constraints → PROVEN IMPOSSIBLE

This is the first script to use the new constraint solver module.
"""
import sys
import os
import time
import json

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT_LEN, BEAN_EQ, BEAN_INEQ, CRIB_DICT
from kryptos.kernel.constraints.solver import K4ConstraintModel, HAS_Z3

if not HAS_Z3:
    print("ERROR: z3-solver required. pip install z3-solver")
    sys.exit(1)


def test_period_variant(period, variant):
    """Test if a periodic key of given period is feasible under given variant.

    Returns dict with result details.
    """
    t0 = time.time()
    model = K4ConstraintModel(variant=variant)
    model.add_bean_constraints()
    model.add_crib_constraints()
    model.add_periodic_key(period)

    result = model.check(timeout_ms=10000)
    elapsed = time.time() - t0

    out = {
        "period": period,
        "variant": variant,
        "result": result,
        "time_ms": round(elapsed * 1000, 1),
    }

    if result == "sat":
        solution = model.get_model()
        if solution:
            # Extract the key (first `period` values)
            key = [solution.get(i, -1) for i in range(period)]
            out["key"] = key
            out["key_letters"] = "".join(chr(k + 65) if 0 <= k <= 25 else '?' for k in key)

    return out


def main():
    print("=" * 70)
    print("Z3 PERIODIC KEY FEASIBILITY SWEEP")
    print("=" * 70)
    print(f"Testing all periods 1-{CT_LEN-1} × 3 variants")
    print(f"Bean constraints: {len(BEAN_EQ)} equality + {len(BEAN_INEQ)} inequality")
    print(f"Crib positions: {len(CRIB_DICT)}")
    print()

    results = []
    sat_count = 0
    unsat_count = 0
    unknown_count = 0

    for variant in ["vigenere", "beaufort", "var_beaufort"]:
        print(f"\n--- {variant.upper()} ---")
        for period in range(1, 27):  # periods 1-26
            r = test_period_variant(period, variant)
            results.append(r)

            status = r["result"]
            if status == "sat":
                sat_count += 1
                key_str = r.get("key_letters", "?")
                print(f"  p={period:2d}: SAT    ({r['time_ms']:6.1f}ms)  key={key_str}")
            elif status == "unsat":
                unsat_count += 1
                print(f"  p={period:2d}: UNSAT  ({r['time_ms']:6.1f}ms)  ← PROVEN IMPOSSIBLE")
            else:
                unknown_count += 1
                print(f"  p={period:2d}: {status:6s} ({r['time_ms']:6.1f}ms)")

    # Also test some larger periods of interest
    print(f"\n--- EXTENDED PERIODS (Beaufort) ---")
    for period in [48, 49, 73, 97]:
        r = test_period_variant(period, "beaufort")
        results.append(r)
        status = r["result"]
        if status == "sat":
            sat_count += 1
            print(f"  p={period:2d}: SAT    ({r['time_ms']:6.1f}ms)")
        elif status == "unsat":
            unsat_count += 1
            print(f"  p={period:2d}: UNSAT  ({r['time_ms']:6.1f}ms)  ← PROVEN IMPOSSIBLE")
        else:
            unknown_count += 1
            print(f"  p={period:2d}: {status:6s} ({r['time_ms']:6.1f}ms)")

    # Summary
    print(f"\n{'=' * 70}")
    print(f"SUMMARY")
    print(f"{'=' * 70}")
    print(f"  SAT (feasible):       {sat_count}")
    print(f"  UNSAT (impossible):   {unsat_count}")
    print(f"  Unknown (timeout):    {unknown_count}")
    print()

    # Group by variant
    for variant in ["vigenere", "beaufort", "var_beaufort"]:
        var_results = [r for r in results if r["variant"] == variant and r["period"] <= 26]
        sat_periods = sorted([r["period"] for r in var_results if r["result"] == "sat"])
        unsat_periods = sorted([r["period"] for r in var_results if r["result"] == "unsat"])
        print(f"  {variant}:")
        print(f"    SAT periods:   {sat_periods}")
        print(f"    UNSAT periods: {unsat_periods}")

    # Save results
    outpath = os.path.join(_ROOT, "results", "z3_periodic_feasibility.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "z3_periodic_feasibility",
            "description": "Z3 SMT proof of periodic key feasibility under Bean+crib constraints",
            "total_configs": len(results),
            "sat": sat_count,
            "unsat": unsat_count,
            "unknown": unknown_count,
            "results": results,
        }, f, indent=2)
    print(f"\nResults saved: {outpath}")


if __name__ == "__main__":
    main()
