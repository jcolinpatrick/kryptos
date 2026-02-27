#!/usr/bin/env python3
"""E-CFM-04: Homophonic substitution partition analysis.

[HYPOTHESIS] K4 may use letter-to-letter homophonic substitution where each
PT letter maps to a SET of CT letters. This would:
  - Explain IC-LOW (flattened frequency distribution)
  - Explain ALPHA-26 (all 26 letters used as output symbols)
  - Break the additive-key assumption underlying ~65% of eliminations

This experiment tests whether ANY homophonic partition of the 26 CT letters
is consistent with the 24 known crib positions.

The constraint: at each crib position i, the CT letter CT[i] must be one
of the homophones assigned to PT letter CRIB[i].

If no partition exists that satisfies all 24 constraints, homophonic
substitution is ELIMINATED for K4.
"""
import sys
import os
from collections import defaultdict, Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, CRIB_DICT, N_CRIBS, SELF_ENCRYPTING,
)


def main():
    print("=" * 70)
    print("E-CFM-04: Homophonic Substitution Partition Analysis")
    print("=" * 70)

    # ── Step 1: Extract required CT→PT mappings from cribs ────────────────
    print("\n── Step 1: Crib-derived CT→PT requirements ──")
    ct_to_pt_required = defaultdict(set)
    pt_to_ct_required = defaultdict(set)

    for pos, pt_ch in CRIB_DICT.items():
        ct_ch = CT[pos]
        ct_to_pt_required[ct_ch].add(pt_ch)
        pt_to_ct_required[pt_ch].add(ct_ch)

    print(f"Crib positions: {N_CRIBS}")
    print(f"Unique CT letters at crib positions: {len(ct_to_pt_required)}")
    print(f"Unique PT letters at crib positions: {len(pt_to_ct_required)}")

    # ── Step 2: Check for contradictions ──────────────────────────────────
    print("\n── Step 2: Contradiction check ──")
    # In a homophonic cipher, each CT letter maps to exactly ONE PT letter.
    # If the same CT letter appears at crib positions requiring DIFFERENT
    # PT letters, that CT letter would need to map to multiple PT letters
    # — which is impossible (homophones go PT→CT, not CT→PT).
    #
    # Wait — homophones mean: each PT letter has MULTIPLE CT letters.
    # So the direction is: PT → {set of CT letters}.
    # The INVERSE (decryption) is: each CT letter maps to exactly one PT letter.
    # So each CT letter can only decrypt to ONE PT letter.

    contradictions = []
    for ct_ch, pt_set in sorted(ct_to_pt_required.items()):
        if len(pt_set) > 1:
            contradictions.append((ct_ch, pt_set))
            print(f"  CONTRADICTION: CT letter '{ct_ch}' maps to PT letters {pt_set}")
        else:
            pt_ch = list(pt_set)[0]
            print(f"  OK: CT '{ct_ch}' → PT '{pt_ch}'")

    if contradictions:
        print(f"\n  Found {len(contradictions)} contradictions!")
        print("  In a homophonic cipher, each CT letter decrypts to exactly")
        print("  one PT letter. Multiple PT requirements for the same CT letter")
        print("  means homophonic substitution is INCONSISTENT with the cribs.")

        # But wait — this assumes DIRECT positional correspondence.
        # With a transposition layer, positions would be shuffled.
        print("\n  NOTE: These contradictions assume direct positional")
        print("  correspondence (CT[i] → PT[i]). With a transposition layer,")
        print("  the mapping changes and contradictions may resolve.")
    else:
        print("\n  No contradictions found!")
        print("  A homophonic partition exists that is consistent with all cribs.")

    # ── Step 3: Build the required partition ──────────────────────────────
    print("\n── Step 3: Building crib-consistent partition ──")
    # Assign each CT letter to a PT letter based on cribs
    ct_assignment = {}
    for ct_ch, pt_set in ct_to_pt_required.items():
        if len(pt_set) == 1:
            ct_assignment[ct_ch] = list(pt_set)[0]

    print(f"Assigned CT letters: {len(ct_assignment)}")
    print(f"Unassigned CT letters: {26 - len(ct_assignment)}")

    # Show the partial partition
    pt_homophones = defaultdict(set)
    for ct_ch, pt_ch in ct_assignment.items():
        pt_homophones[pt_ch].add(ct_ch)

    print("\nPartial partition (crib-derived):")
    for pt_ch in sorted(pt_homophones.keys()):
        ct_set = pt_homophones[pt_ch]
        print(f"  PT '{pt_ch}' ← CT {sorted(ct_set)}")

    unassigned = set(ALPH) - set(ct_assignment.keys())
    assigned_pt = set(ct_assignment.values())
    unassigned_pt = set(ALPH) - assigned_pt
    print(f"\nUnassigned CT letters: {sorted(unassigned)}")
    print(f"PT letters with no CT homophone yet: {sorted(unassigned_pt)}")

    # ── Step 4: Frequency analysis ────────────────────────────────────────
    print("\n── Step 4: Frequency consistency ──")
    ct_freq = Counter(CT)
    # For English, expected frequencies (relative)
    english_freq_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

    # If homophonic, high-frequency PT letters should have MORE homophones
    # (more CT letters assigned to them). Check if the partition makes sense.
    print("CT letter frequencies vs partition assignments:")
    for ct_ch in sorted(ALPH, key=lambda c: -ct_freq.get(c, 0)):
        freq = ct_freq.get(ct_ch, 0)
        assigned = ct_assignment.get(ct_ch, "?")
        print(f"  CT '{ct_ch}': freq={freq}, assigned to PT '{assigned}'")

    # ── Step 5: Count possible completions ────────────────────────────────
    print("\n── Step 5: Completions analysis ──")
    n_unassigned_ct = len(unassigned)
    n_unassigned_pt = len(unassigned_pt)
    print(f"Need to assign {n_unassigned_ct} CT letters to PT letters")
    print(f"  {n_unassigned_pt} PT letters have no homophone yet")
    print(f"  Each must get at least 0 (if we allow it) or 1 CT letter")

    # The unassigned CT letters can go to ANY PT letter (existing or new)
    # This is a surjective mapping problem. Very underdetermined.
    if n_unassigned_ct > 0:
        # Each unassigned CT can map to any of 26 PT letters
        # But at least the unassigned PT letters need coverage
        print(f"\n  Completions: each of {n_unassigned_ct} CT letters can map to")
        print(f"  any of 26 PT letters = {26**n_unassigned_ct:.2e} possible completions")
        print(f"  (But {n_unassigned_pt} PT letters MUST receive at least one CT letter")
        print(f"   for the cipher to be complete)")

    # ── Step 6: Self-encryption analysis ──────────────────────────────────
    print("\n── Step 6: Self-encrypting positions under homophonic model ──")
    for pos, ch in SELF_ENCRYPTING.items():
        ct_ch = CT[pos]
        pt_ch = ch
        print(f"  Position {pos}: CT='{ct_ch}', PT='{pt_ch}'")
        if ct_ch == pt_ch:
            print(f"    Self-encrypting: CT letter IS the PT letter")
            print(f"    Under homophonic model: '{ct_ch}' must be a homophone of itself")
        else:
            print(f"    NOT self-encrypting (CT≠PT at this position)")
            print(f"    Under homophonic model: '{ct_ch}' is a homophone of '{pt_ch}'")

    # ── Step 7: Detail the contradictions ─────────────────────────────────
    if contradictions:
        print("\n── Step 7: Contradiction details ──")
        for ct_ch, pt_set in contradictions:
            positions = [(pos, CRIB_DICT[pos]) for pos in CRIB_DICT
                         if CT[pos] == ct_ch]
            print(f"\n  CT letter '{ct_ch}' appears at crib positions:")
            for pos, pt_ch in positions:
                print(f"    Position {pos}: PT='{pt_ch}'")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    if contradictions:
        print(f"CONTRADICTIONS FOUND: {len(contradictions)}")
        print("Under DIRECT positional correspondence, homophonic")
        print("substitution is INCONSISTENT with K4 cribs.")
        print()
        for ct_ch, pt_set in contradictions:
            print(f"  CT '{ct_ch}' would need to decrypt to BOTH {pt_set}")
        print()
        print("[DERIVED FACT] Homophonic substitution (letter-to-letter,")
        print("direct correspondence) is ELIMINATED for K4.")
        print()
        print("[HYPOTHESIS] Homophonic + transposition remains OPEN —")
        print("transposition could resolve the contradictions by")
        print("shuffling which CT letter appears at which position.")
        print()
        print("Verdict: ELIMINATED (direct), OPEN (with transposition)")
    else:
        print("No contradictions found. Homophonic substitution is")
        print("CONSISTENT with K4 cribs under direct correspondence.")
        print("Further testing needed.")


if __name__ == "__main__":
    main()
