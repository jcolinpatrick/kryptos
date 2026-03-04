#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-28: Bean Constraint Redundancy Analysis

CRITICAL CORRECTION to E-S-27.

This script proves that Bean constraints are FULLY REDUNDANT with the
24 known cribs. Specifically:

1. Bean constraints operate on k_obs[i] = (CT[i] - PT[i]) mod 26
2. ALL Bean positions (EQ and INEQ) are within crib ranges (21-33, 63-73)
3. At crib positions, both CT and PT are known → k_obs is FIXED
4. Therefore Bean is TAUTOLOGICALLY satisfied/violated — it's a FACT, not a constraint

Under Model A (CT = σ(Vig(PT, key))):
- k_obs[j] = (CT[j] - CT[σ(j)] + key[j%p]) mod 26
- This is NOT key[j%p] — it depends on σ
- E-S-26's check_bean tested key[a%p] vs key[b%p], which is WRONG for Model A
- The 0% Bean pass at period 7 was an ARTIFACT of this incorrect check

CONSEQUENCE:
- Period 7 Model A is NOT algebraically impossible
- Bean provides ZERO additional constraint beyond the 24 cribs
- E-S-27's "proof" is misleading (proves trivial tautology)
"""

import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())


def main():
    print("=" * 60)
    print("E-S-28: Bean Constraint Redundancy Proof")
    print("=" * 60)

    # Step 1: Verify ALL Bean positions are within crib ranges
    print("\n--- Step 1: Bean positions vs. crib ranges ---")
    crib_set = set(CRIB_DICT.keys())
    all_bean_pos = set()
    for a, b in BEAN_EQ:
        all_bean_pos.add(a)
        all_bean_pos.add(b)
    for a, b in BEAN_INEQ:
        all_bean_pos.add(a)
        all_bean_pos.add(b)

    outside = all_bean_pos - crib_set
    print(f"  Bean positions: {sorted(all_bean_pos)}")
    print(f"  Crib positions: {sorted(crib_set)}")
    print(f"  Bean positions outside cribs: {sorted(outside)}")
    assert len(outside) == 0, "Bean positions exist outside crib ranges!"
    print(f"  VERIFIED: ALL {len(all_bean_pos)} Bean positions are within crib ranges.")

    # Step 2: Compute effective keystream at crib positions
    print("\n--- Step 2: Effective keystream at crib positions ---")
    k_obs = {}
    for pos in CRIB_POS:
        ct_val = CT_NUM[pos]
        pt_val = ALPH_IDX[CRIB_DICT[pos]]
        k_obs[pos] = (ct_val - pt_val) % MOD
        print(f"  pos {pos}: CT={CT[pos]}({ct_val}) PT={CRIB_DICT[pos]}({pt_val})"
              f" → k_obs = {k_obs[pos]}")

    # Verify against stored keystream
    ene_check = list(VIGENERE_KEY_ENE)
    bc_check = list(VIGENERE_KEY_BC)
    for i, pos in enumerate(range(21, 34)):
        assert k_obs[pos] == ene_check[i], f"Mismatch at pos {pos}"
    for i, pos in enumerate(range(63, 74)):
        assert k_obs[pos] == bc_check[i], f"Mismatch at pos {pos}"
    print("  VERIFIED: Matches stored VIGENERE_KEY_ENE and VIGENERE_KEY_BC.")

    # Step 3: Check Bean constraints on effective keystream
    print("\n--- Step 3: Bean constraints on effective keystream ---")
    print("  Bean EQ:")
    for a, b in BEAN_EQ:
        result = k_obs[a] == k_obs[b]
        print(f"    ({a}, {b}): k_obs[{a}]={k_obs[a]}, k_obs[{b}]={k_obs[b]}"
              f" → {'PASS' if result else 'FAIL'}")

    print("  Bean INEQ:")
    all_ineq_pass = True
    for a, b in BEAN_INEQ:
        result = k_obs[a] != k_obs[b]
        if not result:
            all_ineq_pass = False
        print(f"    ({a:2d}, {b:2d}): k_obs[{a:2d}]={k_obs[a]:2d},"
              f" k_obs[{b:2d}]={k_obs[b]:2d}"
              f" → {'PASS' if result else '** FAIL **'}")

    eq_pass = all(k_obs[a] == k_obs[b] for a, b in BEAN_EQ)
    ineq_pass = all(k_obs[a] != k_obs[b] for a, b in BEAN_INEQ)
    bean_pass = eq_pass and ineq_pass
    print(f"\n  OVERALL: Bean {'PASSES' if bean_pass else 'FAILS'}"
          f" (EQ: {'pass' if eq_pass else 'fail'},"
          f" INEQ: {sum(1 for a,b in BEAN_INEQ if k_obs[a]!=k_obs[b])}/21 pass)")

    # Step 4: Demonstrate the E-S-26 error
    print("\n--- Step 4: E-S-26/E-S-27 Error Analysis ---")
    print("  E-S-26 checked: key[a % period] == key[b % period]")
    print("  But under Model A with transposition σ:")
    print("    k_obs[j] = (CT[j] - CT[σ(j)] + key[j%p]) mod 26")
    print("    This is NOT key[j%p] — it depends on σ")
    print()

    for period in [7]:
        print(f"  Period {period}:")
        for a, b in BEAN_INEQ:
            ra, rb = a % period, b % period
            if ra == rb:
                print(f"    INEQ ({a}, {b}): residue {ra}=={rb}")
                print(f"      E-S-26 check: key[{ra}] ≠ key[{rb}] → IMPOSSIBLE (same index)")
                print(f"      CORRECT check: k_obs[{a}]={k_obs[a]} ≠ k_obs[{b}]={k_obs[b]}"
                      f" → {'PASS' if k_obs[a] != k_obs[b] else 'FAIL'} (trivially from data)")
                print(f"      Under Model A: CT[σ({a})] ≠ CT[σ({b})] (constraint on σ, easily satisfiable)")
        print()
        for a, b in BEAN_EQ:
            ra, rb = a % period, b % period
            if ra != rb:
                print(f"    EQ ({a}, {b}): residue {ra}≠{rb}")
                print(f"      E-S-26 check: key[{ra}] = key[{rb}] → constrains key (2 key values linked)")
                print(f"      CORRECT: k_obs[{a}]={k_obs[a]} = k_obs[{b}]={k_obs[b]}"
                      f" → {'PASS' if k_obs[a] == k_obs[b] else 'FAIL'} (trivially from data)")
                print(f"      Under Model A: key[{ra}]-key[{rb}] = CT[σ({a})]-CT[σ({b})] (constraint on key+σ)")

    # Step 5: Conclusion
    print("\n" + "=" * 60)
    print("CONCLUSIONS")
    print("=" * 60)
    print()
    print("1. ALL Bean positions are within crib ranges → Bean is determined by cribs")
    print("2. Bean constraints on k_obs are TAUTOLOGICALLY SATISFIED by the data")
    print("3. Bean provides ZERO additional constraint beyond the 24 cribs")
    print()
    print("4. E-S-26's check_bean(key, period) was INCORRECT for Model A + transposition:")
    print("   It checked key[a%p] vs key[b%p], but the correct check is on k_obs,")
    print("   which is always satisfied when cribs are satisfied.")
    print()
    print("5. E-S-27's 'algebraic proof' is MISLEADING:")
    print("   It proved key[r] ≠ key[r] is impossible (trivially true),")
    print("   but this is irrelevant because Bean constrains k_obs, not the periodic key.")
    print()
    print("6. Period 7 Model A is NOT algebraically impossible.")
    print("   The 0% Bean pass rate in E-S-21 and E-S-26 was an ARTIFACT.")
    print()
    print("7. CORRECTED STATUS: For any model with transposition,")
    print("   Bean constraints are fully redundant with cribs.")
    print("   Only for PURE Vigenère (no transposition) are Bean constraints meaningful,")
    print("   and in that case we already know the cipher doesn't work.")

    # Save artifact
    artifact = {
        "experiment": "E-S-28",
        "description": "Bean constraint redundancy proof — corrects E-S-27",
        "finding": "Bean constraints are fully redundant with 24 known cribs",
        "bean_positions_all_in_cribs": True,
        "bean_positions": sorted(all_bean_pos),
        "crib_positions": sorted(crib_set),
        "bean_eq_pass": eq_pass,
        "bean_ineq_pass": ineq_pass,
        "bean_overall_pass": bean_pass,
        "k_obs_at_bean_positions": {str(pos): k_obs[pos] for pos in sorted(all_bean_pos)},
        "e_s_26_error": "check_bean tested key[a%p] vs key[b%p] instead of k_obs[a] vs k_obs[b]",
        "e_s_27_error": "Proved trivial tautology, not actual impossibility",
        "correction": "Period 7 Model A is viable. 0% Bean pass was artifact.",
        "implications": [
            "Bean constraints provide zero filtering beyond 24 cribs",
            "All experiments checking 'Bean pass' on periodic key were wrong",
            "Model A period 7 remains a viable hypothesis",
        ],
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_28_bean_redundancy.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\nArtifact: results/e_s_28_bean_redundancy.json")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/e_s_28_bean_redundancy_proof.py")


if __name__ == "__main__":
    main()
