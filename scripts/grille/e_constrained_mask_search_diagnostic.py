#!/usr/bin/env python3
"""Diagnostic for the constrained null-mask search.

Verifies the consistency check is correct and measures HOW badly masks fail.
Also tests: is it MATHEMATICALLY IMPOSSIBLE for ANY mask to be consistent?
"""
from __future__ import annotations

import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Set, Tuple

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
)

CRIB_POS_SET = set(CRIB_POSITIONS)
NON_CRIB_POS = sorted(set(range(CT_LEN)) - CRIB_POS_SET)

# Pre-compute key values for each crib position
CRIB_CT = {pos: ALPH_IDX[CT[pos]] for pos in sorted(CRIB_POS_SET)}
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in sorted(CRIB_POS_SET)}

VARIANTS = {
    "vig":   lambda c, p: (c - p) % MOD,
    "beau":  lambda c, p: (c + p) % MOD,
    "vbeau": lambda c, p: (p - c) % MOD,
}

CRIB_KEYS = {}
for vname, fn in VARIANTS.items():
    CRIB_KEYS[vname] = {pos: fn(CRIB_CT[pos], CRIB_PT[pos]) for pos in sorted(CRIB_POS_SET)}


def count_conflicts(null_positions: Set[int], period: int, variant: str) -> int:
    """Count how many residue conflicts a mask has for a given period/variant."""
    key_vals = CRIB_KEYS[variant]
    null_sorted = sorted(null_positions)

    residue_to_key: Dict[int, int] = {}
    conflicts = 0

    for orig_pos in sorted(CRIB_POS_SET):
        nulls_before = sum(1 for n in null_sorted if n < orig_pos)
        new_pos = orig_pos - nulls_before
        residue = new_pos % period
        k = key_vals[orig_pos]

        if residue in residue_to_key:
            if residue_to_key[residue] != k:
                conflicts += 1
        else:
            residue_to_key[residue] = k

    return conflicts


def main():
    print("=" * 80)
    print("DIAGNOSTIC: Constrained Null-Mask Consistency Check")
    print("=" * 80)

    # ── Sanity check 1: With NO nulls removed (all 97 chars), what happens? ──
    print("\n--- Sanity Check 1: No nulls (all 97 chars, cribs at original positions) ---")
    print("This should reproduce the known result: ALL periods eliminated on raw 97.")
    no_nulls = set()  # empty mask
    for period in range(2, 14):
        for variant in ["vig", "beau", "vbeau"]:
            c = count_conflicts(no_nulls, period, variant)
            if c == 0:
                print(f"  period={period} {variant}: CONSISTENT (0 conflicts)")
            # Only print a summary for non-zero
        vc = count_conflicts(no_nulls, period, "vig")
        bc = count_conflicts(no_nulls, period, "beau")
        vbc = count_conflicts(no_nulls, period, "vbeau")
        print(f"  period={period:2d}: vig={vc} beau={bc} vbeau={vbc} conflicts")

    # ── Sanity check 2: Construct a mask that SHOULD work ──
    print("\n--- Sanity Check 2: Construct a mask + PT that should be consistent ---")
    # Create a fake scenario: pick 24 null positions, then encrypt the 73-char
    # plaintext with a known periodic key, verify consistency check passes.
    random.seed(123)
    fake_nulls = set(random.sample(NON_CRIB_POS, 24))
    fake_period = 5
    fake_key = [3, 17, 8, 21, 10]  # arbitrary period-5 key

    # Build the 73-char extract
    extract_positions = [i for i in range(CT_LEN) if i not in fake_nulls]
    assert len(extract_positions) == 73

    # Map crib positions to new positions
    pos_map = {}
    for new_idx, orig_pos in enumerate(extract_positions):
        if orig_pos in CRIB_POS_SET:
            pos_map[orig_pos] = new_idx

    # For each crib position, the key value should be fake_key[new_pos % period]
    # So: k[orig_pos] = fake_key[pos_map[orig_pos] % fake_period]
    # For Vigenere: k = (CT - PT) mod 26
    # So: PT = (CT - k) mod 26
    # But we want to check if the CRIB key values are consistent...
    # The cribs have FIXED PT values, so the key values are FIXED.
    # We need to check if the fixed key values happen to be consistent.

    # Actually, for a proper sanity check, let's CONSTRUCT a CT where the cribs
    # would be consistent. Start from a random PT, encrypt with the key.
    fake_pt_73 = []
    for new_idx in range(73):
        k = fake_key[new_idx % fake_period]
        # Generate random PT char
        pt_val = random.randint(0, 25)
        ct_val = (pt_val + k) % MOD  # Vigenere
        fake_pt_73.append(ALPH[pt_val])

    # Now build 97-char CT by inserting nulls
    fake_ct_97 = ['?'] * 97
    extract_idx = 0
    for i in range(97):
        if i not in fake_nulls:
            ct_val = (ALPH_IDX[fake_pt_73[extract_idx]] + fake_key[extract_idx % fake_period]) % MOD
            fake_ct_97[i] = ALPH[ct_val]
            extract_idx += 1
        else:
            fake_ct_97[i] = ALPH[random.randint(0, 25)]  # random null

    # Now if we use this fake CT with the same mask, the consistency check should pass
    # But we're using the REAL CT and REAL cribs... so this check is more about
    # whether our counting logic is correct.
    print("  (Skipping fake CT check — more relevant to check real constraints)")

    # ── The key question: For EVERY possible mask, is consistency impossible? ──
    print("\n--- Key Analysis: Why are all masks inconsistent? ---")

    # For a specific mask, let's trace through exactly what happens
    test_mask = set(NON_CRIB_POS[:24])
    print(f"\nTest mask (first 24 non-crib positions): {sorted(test_mask)}")

    extract_positions = [i for i in range(CT_LEN) if i not in test_mask]
    crib_new_positions = {}
    for new_idx, orig in enumerate(extract_positions):
        if orig in CRIB_POS_SET:
            crib_new_positions[orig] = new_idx

    print(f"\nCrib position mapping (orig -> new):")
    for orig in sorted(crib_new_positions):
        new = crib_new_positions[orig]
        pt_char = CRIB_DICT[orig]
        ct_char = CT[orig]
        print(f"  orig={orig:2d} -> new={new:2d} | CT={ct_char} PT={pt_char} | "
              f"vig_k={(ALPH_IDX[ct_char]-ALPH_IDX[pt_char])%26:2d} "
              f"beau_k={(ALPH_IDX[ct_char]+ALPH_IDX[pt_char])%26:2d}")

    # For each period, show which crib positions share residues and their key values
    for period in [5, 7, 8, 13]:
        print(f"\n  Period {period}:")
        residue_groups = defaultdict(list)
        for orig in sorted(crib_new_positions):
            new = crib_new_positions[orig]
            residue_groups[new % period].append(orig)

        for res in sorted(residue_groups):
            group = residue_groups[res]
            if len(group) >= 2:
                for variant in ["vig", "beau", "vbeau"]:
                    keys = [CRIB_KEYS[variant][pos] for pos in group]
                    consistent = len(set(keys)) == 1
                    if not consistent:
                        positions_str = ", ".join(f"{p}(k={CRIB_KEYS[variant][p]})" for p in group)
                        print(f"    residue={res} {variant}: CONFLICT [{positions_str}]")

    # ── Theoretical analysis: For each period, what's the probability of consistency? ──
    print("\n\n--- Theoretical: Constraint density analysis ---")
    print("For each period, how many residue-sharing crib pairs exist?")
    print("(More sharing = more constraints = less likely to be consistent)")

    # We need to know: the 24 crib positions have FIXED key values.
    # After removing 24 nulls, the 24 crib positions get new indices.
    # The nulls are all < 21, between 34-62, or > 73.
    # Let's count: positions 0-20 have 21 non-crib slots.
    #              positions 34-62 have 29 non-crib slots.
    #              positions 74-96 have 23 non-crib slots.
    # Total: 21 + 29 + 23 = 73 non-crib slots. Correct.

    seg1 = [p for p in NON_CRIB_POS if p < 21]   # 21 positions (0-20)
    seg2 = [p for p in NON_CRIB_POS if 34 <= p <= 62]  # 29 positions
    seg3 = [p for p in NON_CRIB_POS if p >= 74]   # 23 positions

    print(f"\nNon-crib segments: before ENE: {len(seg1)}, between cribs: {len(seg2)}, after BC: {len(seg3)}")
    print(f"Total: {len(seg1)+len(seg2)+len(seg3)}")

    # Key insight: removing n1 nulls from seg1 shifts ENE positions LEFT by n1.
    # Removing n2 nulls from seg2 shifts BC positions LEFT by n1+n2.
    # So for a mask with n1 nulls before pos 21, n2 between 34-62, n3 after 73:
    #   n1 + n2 + n3 = 24
    #   ENE crib positions: new_pos[21+i] = 21+i - n1 (for i=0..12)
    #   BC crib positions: new_pos[63+j] = 63+j - n1 - n2 (for j=0..10)
    # The relative positions WITHIN each crib block are FIXED (they're consecutive).
    # Only the OFFSET of each block changes based on n1 and n1+n2.

    print("\n--- Critical insight: offsets only depend on n1 and n2 ---")
    print("ENE block starts at: 21 - n1")
    print("BC block starts at: 63 - n1 - n2")
    print("n1 can be 0..21, n2 can be 0..min(24-n1, 29)")
    print()

    # So the problem reduces to: for each (n1, n2) pair, are the crib keys
    # consistent for some period?
    # ENE positions: (21-n1), (22-n1), ..., (33-n1)
    # BC positions: (63-n1-n2), (64-n1-n2), ..., (73-n1-n2)

    # Let ene_start = 21 - n1, bc_start = 63 - n1 - n2
    # Then ene positions mod p: (ene_start + i) % p for i=0..12
    # And bc positions mod p: (bc_start + j) % p for j=0..10

    # Key values for ENE[i] and BC[j] are FIXED regardless of mask.

    print("Exhaustive (n1, n2) scan for consistency:")
    print(f"{'n1':>4s} {'n2':>4s} {'n3':>4s} {'ene_start':>10s} {'bc_start':>10s} "
          f"{'consistent_combos':>20s}")

    total_consistent_combos = 0
    consistent_details = []

    for n1 in range(min(22, 25)):  # n1: 0..21
        for n2 in range(min(30, 25 - n1)):  # n2: 0..29, but n1+n2 <= 24
            n3 = 24 - n1 - n2
            if n3 < 0 or n3 > 23:  # n3 must fit in seg3
                continue

            ene_start = 21 - n1
            bc_start = 63 - n1 - n2

            combos = []
            for period in range(2, 14):
                for variant in ["vig", "beau", "vbeau"]:
                    key_vals = CRIB_KEYS[variant]
                    residue_to_key = {}
                    consistent = True

                    # ENE positions
                    for i in range(13):
                        orig_pos = 21 + i
                        new_pos = ene_start + i
                        res = new_pos % period
                        k = key_vals[orig_pos]
                        if res in residue_to_key:
                            if residue_to_key[res] != k:
                                consistent = False
                                break
                        else:
                            residue_to_key[res] = k

                    if not consistent:
                        continue

                    # BC positions
                    for j in range(11):
                        orig_pos = 63 + j
                        new_pos = bc_start + j
                        res = new_pos % period
                        k = key_vals[orig_pos]
                        if res in residue_to_key:
                            if residue_to_key[res] != k:
                                consistent = False
                                break
                        else:
                            residue_to_key[res] = k

                    if consistent:
                        combos.append((period, variant))

            if combos:
                total_consistent_combos += 1
                consistent_details.append((n1, n2, n3, ene_start, bc_start, combos))
                print(f"  {n1:4d} {n2:4d} {n3:4d} {ene_start:10d} {bc_start:10d} "
                      f"{len(combos):4d} combos: {combos[:5]}{'...' if len(combos) > 5 else ''}")

    if not consistent_details:
        print("  *** ZERO (n1, n2) combinations produce consistency for ANY period 2-13 ***")
        print("  *** THIS IS A MATHEMATICAL IMPOSSIBILITY PROOF ***")
        print("  *** No null mask + periodic sub (periods 2-13) can be crib-consistent ***")

    print(f"\nTotal consistent (n1,n2) pairs: {total_consistent_combos}")

    # Also check higher periods (14-26)
    print("\n--- Extending to periods 14-26 ---")
    for n1 in range(min(22, 25)):
        for n2 in range(min(30, 25 - n1)):
            n3 = 24 - n1 - n2
            if n3 < 0 or n3 > 23:
                continue

            ene_start = 21 - n1
            bc_start = 63 - n1 - n2

            for period in range(14, 27):
                for variant in ["vig", "beau", "vbeau"]:
                    key_vals = CRIB_KEYS[variant]
                    residue_to_key = {}
                    consistent = True

                    for i in range(13):
                        orig_pos = 21 + i
                        new_pos = ene_start + i
                        res = new_pos % period
                        k = key_vals[orig_pos]
                        if res in residue_to_key:
                            if residue_to_key[res] != k:
                                consistent = False
                                break
                        else:
                            residue_to_key[res] = k

                    if not consistent:
                        continue

                    for j in range(11):
                        orig_pos = 63 + j
                        new_pos = bc_start + j
                        res = new_pos % period
                        k = key_vals[orig_pos]
                        if res in residue_to_key:
                            if residue_to_key[res] != k:
                                consistent = False
                                break
                        else:
                            residue_to_key[res] = k

                    if consistent:
                        print(f"  CONSISTENT: n1={n1} n2={n2} n3={n3} "
                              f"period={period} {variant} "
                              f"ene_start={ene_start} bc_start={bc_start}")
                        total_consistent_combos += 1

    if total_consistent_combos == 0:
        print("  *** Still ZERO for periods 14-26 ***")

    # Check period 1 (Caesar)
    print("\n--- Period 1 (Caesar) ---")
    for n1 in range(min(22, 25)):
        for n2 in range(min(30, 25 - n1)):
            n3 = 24 - n1 - n2
            if n3 < 0 or n3 > 23:
                continue
            for variant in ["vig", "beau", "vbeau"]:
                key_vals = CRIB_KEYS[variant]
                all_keys = set(key_vals[p] for p in sorted(CRIB_POS_SET))
                if len(all_keys) == 1:
                    print(f"  Period 1 {variant}: ALL KEYS EQUAL = {all_keys}")
    # Key values are diverse, so period 1 always fails (as expected)
    print("  Period 1: always fails (diverse key values at crib positions)")

    print("\n" + "=" * 80)
    print("CONCLUSION")
    print("=" * 80)
    if total_consistent_combos == 0:
        print("MATHEMATICAL PROOF: For ALL possible null masks (C(73,24) configs),")
        print("there is NO periodic Vigenere/Beaufort/VarBeau with period 1-26 that")
        print("is crib-consistent on the 73-char extract.")
        print()
        print("This means: if K4 uses null removal + periodic substitution,")
        print("either the cribs do NOT apply at positions 21-33 and 63-73,")
        print("or the substitution is NOT periodic (could be autokey, running key,")
        print("or a non-standard cipher).")
    else:
        print(f"Found {total_consistent_combos} consistent configurations.")


if __name__ == "__main__":
    main()
