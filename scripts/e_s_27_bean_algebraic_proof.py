#!/usr/bin/env python3
"""
E-S-27: Algebraic proof that Bean constraints eliminate Model A at many periods.

Model A: CT = σ(Vig(PT, period_key))
  - Key is periodic with period p: key[i] = key[i % p]
  - Bean INEQ requires key[a] ≠ key[b] for certain pairs (a, b)
  - Under Model A, key[a] = key[a % p], so if a % p == b % p then key[a] = key[b]
  - This creates a contradiction: key[a] MUST equal key[b] (same residue) but MUST NOT (Bean INEQ)

Model B: CT = Vig(σ(PT), period_key)
  - Key applies at CT positions, transposition σ acts on PT
  - Bean constraints restrict σ, not key. No algebraic impossibility from periodicity.

This script:
1. For each period p (2-50), checks all 21 Bean INEQ pairs for same-residue conflicts under Model A
2. Checks Bean EQ (27, 65) for residue compatibility
3. Reports which periods are algebraically impossible
4. Produces a definitive artifact

RESULT: Deterministic proof, zero randomness, fully reproducible.
"""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ

def analyze_period(p):
    """Check if period p is algebraically possible under Model A."""
    # Check INEQ conflicts: pairs where a % p == b % p
    ineq_conflicts = []
    for a, b in BEAN_INEQ:
        if a % p == b % p:
            ineq_conflicts.append((a, b, a % p))

    # Check EQ compatibility: pairs where a % p == b % p (REQUIRED for EQ to hold trivially)
    # If a % p != b % p, EQ imposes key[a%p] = key[b%p] (non-trivial but possible)
    eq_status = []
    for a, b in BEAN_EQ:
        if a % p == b % p:
            eq_status.append(("trivial", a, b, a % p))
        else:
            eq_status.append(("constraining", a, b, a % p, b % p))

    # Check EQ/INEQ cross-conflicts:
    # If EQ says key[r1] = key[r2] (because a%p=r1, b%p=r2, a≠b for EQ pair)
    # AND INEQ says key[c] ≠ key[d] where c%p=r1 and d%p=r2 (or vice versa)
    # Then we have key[r1]=key[r2] AND key[r1]≠key[r2] → IMPOSSIBLE
    eq_ineq_conflicts = []
    for eq_a, eq_b in BEAN_EQ:
        r_eq_a = eq_a % p
        r_eq_b = eq_b % p
        if r_eq_a == r_eq_b:
            continue  # EQ is trivially satisfied, no cross-constraint
        # EQ forces key[r_eq_a] = key[r_eq_b]
        # Check if any INEQ pair has residues (r_eq_a, r_eq_b) or (r_eq_b, r_eq_a)
        for ineq_a, ineq_b in BEAN_INEQ:
            r_ia = ineq_a % p
            r_ib = ineq_b % p
            if (r_ia == r_eq_a and r_ib == r_eq_b) or (r_ia == r_eq_b and r_ib == r_eq_a):
                eq_ineq_conflicts.append({
                    "eq_pair": (eq_a, eq_b),
                    "ineq_pair": (ineq_a, ineq_b),
                    "residues": (r_eq_a, r_eq_b),
                    "reason": f"EQ forces key[{r_eq_a}]=key[{r_eq_b}], INEQ forbids it"
                })

    impossible = len(ineq_conflicts) > 0 or len(eq_ineq_conflicts) > 0
    reason = []
    if ineq_conflicts:
        reason.append(f"{len(ineq_conflicts)} INEQ same-residue conflict(s)")
    if eq_ineq_conflicts:
        reason.append(f"{len(eq_ineq_conflicts)} EQ/INEQ cross-conflict(s)")

    return {
        "period": p,
        "impossible": impossible,
        "reason": "; ".join(reason) if reason else "possible",
        "ineq_conflicts": [(a, b, r) for a, b, r in ineq_conflicts],
        "eq_ineq_conflicts": eq_ineq_conflicts,
        "eq_status": [s[0] for s in eq_status],
        # How many free key positions remain after EQ constraint?
        "eq_constraining": sum(1 for s in eq_status if s[0] == "constraining"),
    }


def main():
    print("=" * 60)
    print("E-S-27: Bean Algebraic Impossibility Proof (Model A)")
    print("=" * 60)
    print(f"\nModel A: CT = σ(Vig(PT, period_key))")
    print(f"Bean EQ:  {BEAN_EQ}")
    print(f"Bean INEQ: {len(BEAN_INEQ)} pairs")
    print()

    results = {}
    impossible_periods = []
    possible_periods = []

    for p in range(2, 51):
        r = analyze_period(p)
        results[str(p)] = r
        if r["impossible"]:
            impossible_periods.append(p)
        else:
            possible_periods.append(p)

    # Print summary table
    print(f"{'Period':>6}  {'Status':>12}  {'Reason'}")
    print("-" * 70)
    for p in range(2, 51):
        r = results[str(p)]
        status = "IMPOSSIBLE" if r["impossible"] else "possible"
        detail = r["reason"]
        if r["ineq_conflicts"]:
            pairs_str = ", ".join(f"({a},{b})→r{res}" for a, b, res in r["ineq_conflicts"])
            detail += f" [{pairs_str}]"
        if r["eq_ineq_conflicts"]:
            for c in r["eq_ineq_conflicts"]:
                detail += f" [EQ({c['eq_pair']}) vs INEQ({c['ineq_pair']}) at r{c['residues']}]"
        print(f"{p:>6}  {status:>12}  {detail}")

    print()
    print("=" * 60)
    print(f"IMPOSSIBLE periods (2-50): {sorted(impossible_periods)}")
    print(f"  Count: {len(impossible_periods)}/{49}")
    print()
    print(f"POSSIBLE periods (2-50): {sorted(possible_periods)}")
    print(f"  Count: {len(possible_periods)}/{49}")
    print()

    if possible_periods:
        print(f"Smallest possible period: {min(possible_periods)}")

    # Key insight for period 7
    r7 = results["7"]
    print()
    print("=" * 60)
    print("PERIOD 7 DETAIL:")
    print("=" * 60)
    if r7["impossible"]:
        print("  Period 7 is ALGEBRAICALLY IMPOSSIBLE under Model A.")
        for a, b, res in r7["ineq_conflicts"]:
            print(f"  INEQ pair ({a}, {b}): both have residue {res} mod 7")
            print(f"    → key[{res}] = key[{a} mod 7] = key[{b} mod 7]")
            print(f"    → But INEQ requires key[{a}] ≠ key[{b}]")
            print(f"    → Contradiction: key[{res}] ≠ key[{res}]")

    # Model B note
    print()
    print("=" * 60)
    print("MODEL B: CT = Vig(σ(PT), period_key)")
    print("=" * 60)
    print("  Under Model B, key is applied at CT positions (fixed).")
    print("  Bean constraints restrict σ (transposition), not key periodicity.")
    print("  → NO algebraic impossibility from Bean INEQ.")
    print("  → ALL periods remain viable under Model B.")

    # Verify with known keystream
    print()
    print("=" * 60)
    print("VERIFICATION: Known keystream at crib positions")
    print("=" * 60)
    from kryptos.kernel.constants import VIGENERE_KEY_ENE, VIGENERE_KEY_BC
    ene_keys = list(VIGENERE_KEY_ENE)
    bc_keys = list(VIGENERE_KEY_BC)
    print(f"  ENE (pos 21-33): {ene_keys}")
    print(f"  BC  (pos 63-73): {bc_keys}")
    print(f"  Bean EQ: key[27]={ene_keys[27-21]}  key[65]={bc_keys[65-63]}")
    print(f"    {ene_keys[27-21]} == {bc_keys[65-63]}? {ene_keys[27-21] == bc_keys[65-63]}")

    # Check if known keystream is consistent with ANY period under Model A
    print()
    print("  Testing known keystream against periods (Model A / direct correspondence):")
    for p in range(2, 26):
        # Group crib positions by residue, check if all keys in same group are equal
        from collections import defaultdict
        groups = defaultdict(list)
        for i, k in zip(range(21, 34), ene_keys):
            groups[i % p].append((i, k))
        for i, k in zip(range(63, 74), bc_keys):
            groups[i % p].append((i, k))

        consistent = True
        conflicts = []
        for res, members in groups.items():
            vals = set(k for _, k in members)
            if len(vals) > 1:
                consistent = False
                conflicts.append((res, members))

        status = "CONSISTENT" if consistent else f"INCONSISTENT ({len(conflicts)} conflicts)"
        if not consistent and p <= 13:
            print(f"    Period {p:2d}: {status}")
            if p == 7:
                for res, members in conflicts:
                    pos_vals = [(pos, k) for pos, k in members]
                    print(f"      Residue {res}: {pos_vals}")

    # Save artifact
    artifact = {
        "experiment": "E-S-27",
        "description": "Algebraic proof: Bean INEQ eliminates Model A at many periods",
        "model_a_definition": "CT = σ(Vig(PT, period_key)), key[i] = key[i % p]",
        "model_b_definition": "CT = Vig(σ(PT), period_key), key at CT positions",
        "impossible_periods_model_a": sorted(impossible_periods),
        "possible_periods_model_a": sorted(possible_periods),
        "smallest_possible_period_model_a": min(possible_periods) if possible_periods else None,
        "model_b_affected": False,
        "period_details": results,
        "bean_eq": [list(pair) for pair in BEAN_EQ],
        "bean_ineq": [list(pair) for pair in BEAN_INEQ],
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_27_bean_algebraic_proof.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print()
    print(f"Artifact: results/e_s_27_bean_algebraic_proof.json")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/e_s_27_bean_algebraic_proof.py")


if __name__ == "__main__":
    main()
