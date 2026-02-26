#!/usr/bin/env python3
"""E-AUDIT-01: Crib Robustness Audit for Non-Periodicity Proof.

Tests the robustness of the Bean-based non-periodicity proof under:
  1. Every single-letter substitution in each crib
  2. Every single insertion/deletion in each crib
  3. Every adjacent transposition within each crib
  4. Every ±1 to ±3 positional drift of each crib
  5. Combined positional drift of both cribs

For each perturbation, re-derives the Bean equality/inequality graph from
first principles and re-runs the period elimination logic.

Reports: which periods resurrect, which constraint edges are most fragile,
and the boundary between "provably non-periodic" and "conditionally non-periodic."

[HYPOTHESIS] The non-periodicity proof is robust to small perturbations.
If it is not, the claim must be softened to "provably non-periodic under
the published orthography and indexing."
"""
import json
import sys
from collections import defaultdict
from itertools import product
from typing import Dict, FrozenSet, List, Set, Tuple

# ── Constants ────────────────────────────────────────────────────────────
from kryptos.kernel.constants import CT, CT_LEN, ALPH, MOD

# Canonical cribs
CANONICAL_CRIBS: List[Tuple[int, str]] = [
    (21, "EASTNORTHEAST"),
    (63, "BERLINCLOCK"),
]

# Periods to test
PERIODS = range(2, 27)

# Canonical eliminated periods (from E-FRAC-35, using only 22 Bean constraints)
BEAN_ONLY_ELIMINATED = {2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 14, 15, 17, 18, 21, 22, 25}
BEAN_ONLY_SURVIVING = {8, 13, 16, 19, 20, 23, 24, 26}

# The 22 published Bean constraints (1 equality + 21 inequalities)
# These are a SUBSET of all pairwise constraints derivable from 24 crib positions
BEAN_EQ = [(27, 65)]
BEAN_INEQ = [
    (24, 28), (28, 33), (24, 33), (21, 30), (21, 64), (30, 64),
    (68, 25), (22, 31), (66, 70), (26, 71), (69, 72), (23, 32),
    (71, 21), (25, 26), (24, 66), (31, 73), (29, 63), (32, 33),
    (67, 68), (27, 72), (23, 28),
]


# ── Core logic: derive Bean constraints from cribs ───────────────────────

def derive_keystream(cribs: List[Tuple[int, str]], ct: str = CT) -> Dict[int, int]:
    """Derive Vigenere keystream values at crib positions.

    k[i] = (CT[i] - PT[i]) mod 26  (standard Vigenere convention)
    """
    ks = {}
    for start, word in cribs:
        for i, ch in enumerate(word):
            pos = start + i
            if pos < len(ct):
                c = ord(ct[pos]) - 65
                p = ord(ch) - 65
                ks[pos] = (c - p) % MOD
    return ks


def derive_bean_constraints(
    keystream: Dict[int, int],
) -> Tuple[List[Tuple[int, int]], List[Tuple[int, int]]]:
    """Derive Bean equality and inequality constraints from keystream.

    Two positions with the SAME key value → equality constraint.
    Two positions with DIFFERENT key values → inequality constraint.

    Returns: (equalities, inequalities) as lists of (posA, posB) pairs.
    """
    positions = sorted(keystream.keys())
    equalities = []
    inequalities = []

    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            a, b = positions[i], positions[j]
            if keystream[a] == keystream[b]:
                equalities.append((a, b))
            else:
                inequalities.append((a, b))

    return equalities, inequalities


def eliminate_periods(
    equalities: List[Tuple[int, int]],
    inequalities: List[Tuple[int, int]],
    periods: range = PERIODS,
) -> Dict[int, dict]:
    """Run period elimination logic.

    Type 1: inequality pair (a,b) with a ≡ b (mod p) → contradiction
    Type 2: equality pair (a,b) forces key[a%p]=key[b%p], but an inequality
            pair (c,d) with c%p=a%p and d%p=b%p forbids it → contradiction

    Returns dict: period → {eliminated, type1_violations, type2_violations, reason}
    """
    results = {}

    for p in periods:
        type1 = []
        type2 = []

        # Type 1: same-residue inequality violations
        for a, b in inequalities:
            if a % p == b % p:
                type1.append((a, b))

        # Type 2: equality-inequality conflicts
        # For each equality (a,b): key[a%p] must equal key[b%p]
        # For each inequality (c,d): key[c%p] must NOT equal key[d%p]
        # Conflict if {c%p, d%p} == {a%p, b%p}
        if not type1:  # Only check Type 2 if Type 1 didn't already eliminate
            eq_residue_pairs = set()
            for a, b in equalities:
                ra, rb = a % p, b % p
                if ra != rb:
                    eq_residue_pairs.add((min(ra, rb), max(ra, rb)))

            for a, b in inequalities:
                ra, rb = a % p, b % p
                if ra != rb:
                    pair = (min(ra, rb), max(ra, rb))
                    if pair in eq_residue_pairs:
                        type2.append((a, b))

        eliminated = len(type1) > 0 or len(type2) > 0
        reason = []
        if type1:
            reason.append(f"type1({len(type1)} violations)")
        if type2:
            reason.append(f"type2({len(type2)} conflicts)")

        results[p] = {
            "eliminated": eliminated,
            "type1_count": len(type1),
            "type2_count": len(type2),
            "type1_violations": type1,
            "type2_violations": type2,
            "reason": " + ".join(reason) if reason else "survives",
        }

    return results


def get_eliminated_set(results: Dict[int, dict]) -> Set[int]:
    return {p for p, r in results.items() if r["eliminated"]}


def get_surviving_set(results: Dict[int, dict]) -> Set[int]:
    return {p for p, r in results.items() if not r["eliminated"]}


# ── Perturbation generators ──────────────────────────────────────────────

def perturb_single_letter_substitution(cribs: List[Tuple[int, str]]):
    """Yield every single-letter substitution of each crib."""
    for ci, (start, word) in enumerate(cribs):
        for pos in range(len(word)):
            for ch in ALPH:
                if ch != word[pos]:
                    new_word = word[:pos] + ch + word[pos+1:]
                    new_cribs = list(cribs)
                    new_cribs[ci] = (start, new_word)
                    yield (f"sub_{ci}_pos{pos}_{word[pos]}→{ch}", new_cribs)


def perturb_single_deletion(cribs: List[Tuple[int, str]]):
    """Yield every single-character deletion from each crib."""
    for ci, (start, word) in enumerate(cribs):
        for pos in range(len(word)):
            new_word = word[:pos] + word[pos+1:]
            new_cribs = list(cribs)
            new_cribs[ci] = (start, new_word)
            yield (f"del_{ci}_pos{pos}_{word[pos]}", new_cribs)


def perturb_single_insertion(cribs: List[Tuple[int, str]]):
    """Yield every single-character insertion into each crib."""
    for ci, (start, word) in enumerate(cribs):
        for pos in range(len(word) + 1):
            for ch in ALPH:
                new_word = word[:pos] + ch + word[pos:]
                new_cribs = list(cribs)
                new_cribs[ci] = (start, new_word)
                yield (f"ins_{ci}_pos{pos}_{ch}", new_cribs)


def perturb_adjacent_transposition(cribs: List[Tuple[int, str]]):
    """Yield every adjacent letter swap within each crib."""
    for ci, (start, word) in enumerate(cribs):
        for pos in range(len(word) - 1):
            if word[pos] != word[pos+1]:  # Skip no-ops
                new_word = word[:pos] + word[pos+1] + word[pos] + word[pos+2:]
                new_cribs = list(cribs)
                new_cribs[ci] = (start, new_word)
                yield (f"swap_{ci}_pos{pos}{pos+1}", new_cribs)


def perturb_positional_drift(cribs: List[Tuple[int, str]], max_drift: int = 3):
    """Yield every ±1 to ±max_drift positional shift of each crib independently."""
    for ci, (start, word) in enumerate(cribs):
        for delta in range(-max_drift, max_drift + 1):
            if delta == 0:
                continue
            new_start = start + delta
            if new_start < 0 or new_start + len(word) > CT_LEN:
                continue
            new_cribs = list(cribs)
            new_cribs[ci] = (new_start, word)
            yield (f"drift_{ci}_{delta:+d}", new_cribs)


def perturb_both_drift(cribs: List[Tuple[int, str]], max_drift: int = 3):
    """Yield every combination of positional drift for both cribs together."""
    for d0 in range(-max_drift, max_drift + 1):
        for d1 in range(-max_drift, max_drift + 1):
            if d0 == 0 and d1 == 0:
                continue
            new_cribs = []
            skip = False
            for ci, (start, word) in enumerate(cribs):
                delta = d0 if ci == 0 else d1
                ns = start + delta
                if ns < 0 or ns + len(word) > CT_LEN:
                    skip = True
                    break
                new_cribs.append((ns, word))
            if not skip:
                yield (f"both_drift_{d0:+d}_{d1:+d}", new_cribs)


# ── Main audit ───────────────────────────────────────────────────────────

def run_audit():
    print("=" * 72)
    print("E-AUDIT-01: Crib Robustness Audit for Non-Periodicity Proof")
    print("=" * 72)
    print()

    # Step 1a: Verify Bean-only result (matches E-FRAC-35)
    print("Step 1a: Verify Bean-only (22 constraints) non-periodicity proof")
    print("-" * 60)
    bean_results = eliminate_periods(BEAN_EQ, BEAN_INEQ)
    bean_elim = get_eliminated_set(bean_results)
    bean_surv = get_surviving_set(bean_results)
    print(f"  Bean equalities:   {len(BEAN_EQ)}")
    print(f"  Bean inequalities: {len(BEAN_INEQ)}")
    print(f"  Eliminated periods: {sorted(bean_elim)}")
    print(f"  Surviving periods:  {sorted(bean_surv)}")
    assert bean_elim == BEAN_ONLY_ELIMINATED, \
        f"Bean mismatch: got {bean_elim}, expected {BEAN_ONLY_ELIMINATED}"
    print("  ✓ Matches E-FRAC-35 canonical result")
    print()

    # Step 1b: Full pairwise constraints from all 24 crib positions
    print("Step 1b: Full pairwise constraints from 24 crib positions")
    print("-" * 60)
    ks = derive_keystream(CANONICAL_CRIBS)
    full_eq, full_ineq = derive_bean_constraints(ks)
    full_results = eliminate_periods(full_eq, full_ineq)
    full_elim = get_eliminated_set(full_results)
    full_surv = get_surviving_set(full_results)

    print(f"  Crib positions: {[(s, w) for s, w in CANONICAL_CRIBS]}")
    print(f"  Keystream entries: {len(ks)}")
    print(f"  Full equalities:   {len(full_eq)} (vs Bean's {len(BEAN_EQ)})")
    print(f"  Full inequalities: {len(full_ineq)} (vs Bean's {len(BEAN_INEQ)})")
    print(f"  Eliminated periods: {sorted(full_elim)}")
    print(f"  Surviving periods:  {sorted(full_surv)}")

    additional = full_elim - BEAN_ONLY_ELIMINATED
    if additional:
        print(f"  *** ADDITIONAL ELIMINATIONS beyond Bean: {sorted(additional)}")
        print(f"  *** Full pairwise analysis eliminates {len(additional)} more periods!")
    if not full_surv:
        print("  *** ALL periods 2-26 eliminated using full pairwise constraints!")
    print()

    # Use FULL pairwise constraints as the baseline for robustness testing
    canonical_elim = full_elim
    canonical_surv = full_surv

    # Step 2: Run all perturbation classes under BOTH constraint models
    perturbation_classes = [
        ("Single-letter substitution", perturb_single_letter_substitution),
        ("Single-character deletion", perturb_single_deletion),
        ("Single-character insertion", perturb_single_insertion),
        ("Adjacent transposition", perturb_adjacent_transposition),
        ("Single crib drift (±1..±3)", perturb_positional_drift),
        ("Both cribs drift (±1..±3)", perturb_both_drift),
    ]

    all_results = {}
    summary_table = []

    for class_name, generator in perturbation_classes:
        print(f"Step: {class_name}")
        print("-" * 48)

        n_tested = 0
        n_weaker = 0       # fewer periods eliminated than canonical
        n_stronger = 0     # more periods eliminated
        n_identical = 0    # same result
        resurrected_periods = defaultdict(int)  # period → count of resurrections
        newly_eliminated = defaultdict(int)
        worst_case = None
        worst_n_surviving = len(canonical_surv)

        for label, perturbed_cribs in generator(CANONICAL_CRIBS):
            n_tested += 1
            pks = derive_keystream(perturbed_cribs)
            peq, pineq = derive_bean_constraints(pks)
            presults = eliminate_periods(peq, pineq)
            pelim = get_eliminated_set(presults)
            psurv = get_surviving_set(presults)

            if pelim == canonical_elim:
                n_identical += 1
            elif len(pelim) < len(canonical_elim):
                n_weaker += 1
                for p in canonical_elim - pelim:
                    resurrected_periods[p] += 1
                if len(psurv) > worst_n_surviving:
                    worst_n_surviving = len(psurv)
                    worst_case = (label, sorted(psurv))
            else:
                n_stronger += 1
                for p in pelim - canonical_elim:
                    newly_eliminated[p] += 1

        print(f"  Tested: {n_tested}")
        print(f"  Identical: {n_identical} ({100*n_identical/max(n_tested,1):.1f}%)")
        print(f"  Weaker (periods resurrect): {n_weaker}")
        print(f"  Stronger (more eliminated): {n_stronger}")

        if resurrected_periods:
            print(f"  Resurrected periods:")
            for p in sorted(resurrected_periods):
                print(f"    Period {p}: resurrected in {resurrected_periods[p]}/{n_tested} perturbations")

        if worst_case:
            print(f"  Worst case: {worst_case[0]}")
            print(f"    Surviving periods: {worst_case[1]} ({len(worst_case[1])} total)")
        print()

        summary_table.append({
            "class": class_name,
            "n_tested": n_tested,
            "n_identical": n_identical,
            "n_weaker": n_weaker,
            "n_stronger": n_stronger,
            "resurrected": dict(resurrected_periods),
            "newly_eliminated": dict(newly_eliminated),
            "worst_case": worst_case,
        })
        all_results[class_name] = summary_table[-1]

    # Step 3: Summary
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print()

    total_weaker = sum(r["n_weaker"] for r in summary_table)
    total_tested = sum(r["n_tested"] for r in summary_table)

    print(f"Total perturbations tested: {total_tested}")
    print(f"Total where proof weakens:  {total_weaker} ({100*total_weaker/max(total_tested,1):.1f}%)")
    print()

    # Aggregate resurrected periods
    all_resurrected = defaultdict(int)
    for r in summary_table:
        for p, cnt in r["resurrected"].items():
            all_resurrected[p] += cnt

    if all_resurrected:
        print("Periods that resurrect under ANY perturbation:")
        for p in sorted(all_resurrected):
            print(f"  Period {p}: {all_resurrected[p]} total resurrections across all classes")
    else:
        print("No periods resurrect under any tested perturbation!")

    print()

    # Verdict
    if total_weaker == 0:
        verdict = "ROBUST: Non-periodicity proof survives all tested perturbations."
    elif total_weaker < total_tested * 0.05:
        verdict = ("MOSTLY ROBUST: Proof weakens in <5% of perturbations. "
                   "Claim should be softened to 'provably non-periodic under "
                   "the published orthography and indexing, robust to most "
                   "single-error perturbations.'")
    else:
        verdict = ("FRAGILE: Proof weakens in ≥5% of perturbations. "
                  "Claim must be softened to 'provably non-periodic under "
                  "the published orthography and indexing only.'")

    print(f"VERDICT: {verdict}")
    print()

    # Save results
    output = {
        "experiment": "E-AUDIT-01",
        "description": "Crib robustness audit for non-periodicity proof",
        "bean_only_eliminated": sorted(BEAN_ONLY_ELIMINATED),
        "bean_only_surviving": sorted(BEAN_ONLY_SURVIVING),
        "full_pairwise_eliminated": sorted(full_elim),
        "full_pairwise_surviving": sorted(full_surv),
        "full_pairwise_equalities": len(full_eq),
        "full_pairwise_inequalities": len(full_ineq),
        "total_perturbations": total_tested,
        "total_weaker": total_weaker,
        "all_resurrected_periods": dict(all_resurrected),
        "verdict": verdict,
        "perturbation_classes": [
            {k: v for k, v in r.items() if k != "worst_case"}
            | ({"worst_case_label": r["worst_case"][0],
                "worst_case_surviving": r["worst_case"][1]}
               if r["worst_case"] else {})
            for r in summary_table
        ],
    }

    import os
    os.makedirs("results/audit", exist_ok=True)
    with open("results/audit/e_audit_01_crib_robustness.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to results/audit/e_audit_01_crib_robustness.json")


if __name__ == "__main__":
    run_audit()
