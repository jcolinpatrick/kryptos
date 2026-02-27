#!/usr/bin/env python3
"""E-TEAM-LAYERED: Nomenclator + Superencipherment Algebraic Verification.

Verifies the algebraic structure of the nomenclator+superencipherment model
for K4, counting degrees of freedom and enumerating constraints under
periodic key assumptions.

Model: CT[i] = (G(word_at_i)[offset] + k[i]) mod 26
where G maps plaintext words to fixed code groups and k is a superencipherment key.

Steps:
  1. Verify EAST differential independence (code group cancels in key diff)
  2. Derive all key constraints from cribs under word segmentation
  3. Analyze Bean-EQ constraint on code groups
  4. Count degrees of freedom
  5. Enumerate constraints for each Bean-surviving periodic key period
"""
import sys
import os
import json
import random
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS, CRIB_WORDS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_layered_verify.json")


def idx(ch):
    """Letter to 0-25 index."""
    return ALPH_IDX[ch]


def letter(i):
    """0-25 index to letter."""
    return ALPH[i % MOD]


def main():
    print("=" * 70)
    print("E-TEAM-LAYERED: Nomenclator + Superencipherment Verification")
    print("=" * 70)
    results = {"experiment_id": "e_team_layered_verify", "steps": {}}

    # ================================================================
    # Step 1: Verify EAST differential independence
    # ================================================================
    print("\n" + "=" * 70)
    print("STEP 1: EAST Differential Independence")
    print("=" * 70)

    # CT positions for EAST (first occurrence: 21-24, second: 30-33)
    east1_ct = CT[21:25]  # FLRV
    east2_ct = CT[30:34]  # GKSS

    # Theoretical differential: CT[30..33] - CT[21..24] (mod 26)
    # This equals k[30..33] - k[21..24] and is INDEPENDENT of G (code group)
    ct_diff = [(idx(east2_ct[i]) - idx(east1_ct[i])) % MOD for i in range(4)]
    print(f"  EAST first  (pos 21-24): CT = {east1_ct} = {[idx(c) for c in east1_ct]}")
    print(f"  EAST second (pos 30-33): CT = {east2_ct} = {[idx(c) for c in east2_ct]}")
    print(f"  CT differential (east2 - east1 mod 26): {ct_diff}")

    # Cross-check with known Vigenere key
    key_diff = [(VIGENERE_KEY_ENE[9] - VIGENERE_KEY_ENE[0]) % MOD,  # pos30-pos21
                (VIGENERE_KEY_ENE[10] - VIGENERE_KEY_ENE[1]) % MOD,  # pos31-pos22
                (VIGENERE_KEY_ENE[11] - VIGENERE_KEY_ENE[2]) % MOD,  # pos32-pos23
                (VIGENERE_KEY_ENE[12] - VIGENERE_KEY_ENE[3]) % MOD]  # pos33-pos24
    print(f"  Key differential (from known Vigenere keys): {key_diff}")
    print(f"  Match: {ct_diff == key_diff}")

    # Verify with random code groups
    random.seed(42)
    all_match = True
    test_cases = []
    for trial in range(5):
        G = [random.randint(0, 25) for _ in range(4)]  # random code group for EAST
        # k[21..24] = (CT[21..24] - G) mod 26
        k_first = [(idx(east1_ct[i]) - G[i]) % MOD for i in range(4)]
        k_second = [(idx(east2_ct[i]) - G[i]) % MOD for i in range(4)]
        diff_computed = [(k_second[i] - k_first[i]) % MOD for i in range(4)]
        match = (diff_computed == ct_diff)
        all_match = all_match and match
        test_cases.append({
            "G": G, "k_first": k_first, "k_second": k_second,
            "diff": diff_computed, "match": match
        })
        G_letters = "".join(letter(g) for g in G)
        print(f"  Trial {trial+1}: G={G_letters} ({G}), k_diff={diff_computed}, match={match}")

    step1_pass = all_match and (ct_diff == key_diff)
    print(f"\n  [RESULT] EAST differential is G-independent: {'CONFIRMED' if step1_pass else 'FAILED'}")
    print(f"  [DERIVED FACT] CT[30..33] - CT[21..24] = [1,25,1,23] regardless of code group G_EAST")

    results["steps"]["step1_east_differential"] = {
        "ct_diff": ct_diff,
        "key_diff": key_diff,
        "match": ct_diff == key_diff,
        "random_trials_all_match": all_match,
        "verdict": "CONFIRMED" if step1_pass else "FAILED"
    }

    # ================================================================
    # Step 2: All key constraints from cribs under word segmentation
    # ================================================================
    print("\n" + "=" * 70)
    print("STEP 2: Key Constraints Under Word Segmentation")
    print("=" * 70)

    # Most natural segmentation: EAST + NORTH + EAST and BERLIN + CLOCK
    # ENE crib: positions 21-33
    # EAST  = pos 21-24, code group G_E (4 letters)
    # NORTH = pos 25-29, code group G_N (5 letters)
    # EAST  = pos 30-33, code group G_E (same 4 letters, repeated word)

    # BC crib: positions 63-73
    # BERLIN = pos 63-68, code group G_B (6 letters)
    # CLOCK  = pos 69-73, code group G_C (5 letters)

    print("\n  Segmentation: EAST(21-24) + NORTH(25-29) + EAST(30-33) | BERLIN(63-68) + CLOCK(69-73)")

    # CT at each segment
    ct_east1 = [idx(CT[i]) for i in range(21, 25)]     # FLRV = [5,11,17,21]
    ct_north = [idx(CT[i]) for i in range(25, 30)]      # QQPRN = [16,16,15,17,13]
    ct_east2 = [idx(CT[i]) for i in range(30, 34)]      # GKSS = [6,10,18,18]
    ct_berlin = [idx(CT[i]) for i in range(63, 69)]     # NYPVTT = [13,24,15,21,19,19]
    ct_clock = [idx(CT[i]) for i in range(69, 74)]      # MZFPK = [12,25,5,15,10]

    print(f"  CT[21:25] (EAST1):  {[letter(c) for c in ct_east1]}  = {ct_east1}")
    print(f"  CT[25:30] (NORTH):  {[letter(c) for c in ct_north]}  = {ct_north}")
    print(f"  CT[30:34] (EAST2):  {[letter(c) for c in ct_east2]}  = {ct_east2}")
    print(f"  CT[63:69] (BERLIN): {[letter(c) for c in ct_berlin]} = {ct_berlin}")
    print(f"  CT[69:74] (CLOCK):  {[letter(c) for c in ct_clock]}  = {ct_clock}")

    # Key values as functions of code groups:
    # k[pos] = (CT[pos] - G_word[offset_in_word]) mod 26
    # For EAST (first): k[21+j] = (ct_east1[j] - G_E[j]) mod 26, j=0..3
    # For NORTH:        k[25+j] = (ct_north[j] - G_N[j]) mod 26, j=0..4
    # For EAST (second): k[30+j] = (ct_east2[j] - G_E[j]) mod 26, j=0..3
    # For BERLIN:       k[63+j] = (ct_berlin[j] - G_B[j]) mod 26, j=0..5
    # For CLOCK:        k[69+j] = (ct_clock[j] - G_C[j]) mod 26, j=0..4

    print("\n  Key expressions:")
    print("    k[21..24] = CT[21..24] - G_E[0..3] (mod 26)")
    print("    k[25..29] = CT[25..29] - G_N[0..4] (mod 26)")
    print("    k[30..33] = CT[30..33] - G_E[0..3] (mod 26)")
    print("    k[63..68] = CT[63..68] - G_B[0..5] (mod 26)")
    print("    k[69..73] = CT[69..73] - G_C[0..4] (mod 26)")

    # Constraints from shared code group EAST:
    # k[30+j] - k[21+j] = ct_east2[j] - ct_east1[j] (mod 26) for j=0..3
    # This is a HARD constraint on k, independent of G_E
    east_hard_constraints = [(ct_east2[j] - ct_east1[j]) % MOD for j in range(4)]
    print(f"\n  Hard constraints from repeated EAST:")
    print(f"    k[30]-k[21] = {east_hard_constraints[0]}")
    print(f"    k[31]-k[22] = {east_hard_constraints[1]}")
    print(f"    k[32]-k[23] = {east_hard_constraints[2]}")
    print(f"    k[33]-k[24] = {east_hard_constraints[3]}")

    results["steps"]["step2_key_constraints"] = {
        "segmentation": "EAST(21-24) + NORTH(25-29) + EAST(30-33) | BERLIN(63-68) + CLOCK(69-73)",
        "ct_segments": {
            "east1": ct_east1, "north": ct_north, "east2": ct_east2,
            "berlin": ct_berlin, "clock": ct_clock
        },
        "east_hard_constraints": east_hard_constraints,
        "east_hard_constraints_desc": "k[30+j] - k[21+j] = value (mod 26) for j=0..3"
    }

    # ================================================================
    # Step 3: Bean-EQ constraint on code groups
    # ================================================================
    print("\n" + "=" * 70)
    print("STEP 3: Bean-EQ Constraint on Code Groups")
    print("=" * 70)

    # Bean-EQ: k[27] = k[65]
    # Position 27 is in NORTH (pos 25-29), offset = 27-25 = 2 → G_N[2]
    # Position 65 is in BERLIN (pos 63-68), offset = 65-63 = 2 → G_B[2]
    #
    # k[27] = (CT[27] - G_N[2]) mod 26  where CT[27] = P = 15
    # k[65] = (CT[65] - G_B[2]) mod 26  where CT[65] = V = 21
    #
    # Bean-EQ: CT[27] - G_N[2] = CT[65] - G_B[2] (mod 26)
    # → G_B[2] - G_N[2] = CT[65] - CT[27] = 21 - 15 = 6 (mod 26)

    ct27 = idx(CT[27])  # P = 15
    ct65 = idx(CT[65])  # V = 21
    bean_diff = (ct65 - ct27) % MOD  # 6

    print(f"  Bean-EQ: k[27] = k[65]")
    print(f"  CT[27] = '{CT[27]}' = {ct27}")
    print(f"  CT[65] = '{CT[65]}' = {ct65}")
    print(f"  Position 27 is in NORTH code group, offset 2 (0-indexed): G_N[2]")
    print(f"  Position 65 is in BERLIN code group, offset 2 (0-indexed): G_B[2]")
    print(f"  Constraint: G_B[2] - G_N[2] = {ct65} - {ct27} = {bean_diff} (mod 26)")
    print(f"  → The 3rd letter of BERLIN's code exceeds NORTH's 3rd letter by {bean_diff} (mod 26)")

    # Verify: pick random G_N[2], compute required G_B[2]
    print(f"\n  Verification with random values:")
    for g_n2 in [0, 5, 10, 15, 20, 25]:
        g_b2 = (g_n2 + bean_diff) % MOD
        k27 = (ct27 - g_n2) % MOD
        k65 = (ct65 - g_b2) % MOD
        print(f"    G_N[2]={letter(g_n2)}({g_n2}), G_B[2]={letter(g_b2)}({g_b2}) → k[27]={k27}, k[65]={k65}, equal={k27==k65}")

    # Bean-INEQ: check which inequalities involve crib positions
    # For each (a,b) in BEAN_INEQ where both are crib positions:
    # k[a] != k[b], and k[a], k[b] are functions of code group values
    print(f"\n  Bean inequalities involving crib positions:")
    ineq_in_cribs = []
    for a, b in BEAN_INEQ:
        if a in CRIB_POSITIONS and b in CRIB_POSITIONS:
            # Determine which word segment each belongs to
            def segment_info(pos):
                if 21 <= pos <= 24:
                    return "G_E", pos - 21
                elif 25 <= pos <= 29:
                    return "G_N", pos - 25
                elif 30 <= pos <= 33:
                    return "G_E", pos - 21  # same G_E but via EAST2 mapping
                elif 63 <= pos <= 68:
                    return "G_B", pos - 63
                elif 69 <= pos <= 73:
                    return "G_C", pos - 69
                return "?", -1

            seg_a, off_a = segment_info(a)
            seg_b, off_b = segment_info(b)
            # For EAST second occurrence, adjust: k[30+j] = ct_east2[j] - G_E[j]
            # So we need the code group letter offset within the word
            if 30 <= a <= 33:
                off_a = a - 30
            if 30 <= b <= 33:
                off_b = b - 30

            ct_a = idx(CT[a])
            ct_b = idx(CT[b])
            print(f"    k[{a}] != k[{b}]: {seg_a}[{off_a}] from CT[{a}]='{CT[a]}', {seg_b}[{off_b}] from CT[{b}]='{CT[b]}'")
            ineq_in_cribs.append({
                "pos_a": a, "pos_b": b,
                "seg_a": seg_a, "off_a": off_a,
                "seg_b": seg_b, "off_b": off_b,
                "ct_a": ct_a, "ct_b": ct_b
            })

    print(f"\n  Total Bean inequalities involving two crib positions: {len(ineq_in_cribs)}")

    results["steps"]["step3_bean_eq"] = {
        "ct27": ct27, "ct65": ct65,
        "bean_diff": bean_diff,
        "constraint": f"G_B[2] - G_N[2] = {bean_diff} (mod 26)",
        "num_ineq_in_cribs": len(ineq_in_cribs),
        "ineq_details": ineq_in_cribs
    }

    # ================================================================
    # Step 4: Count degrees of freedom
    # ================================================================
    print("\n" + "=" * 70)
    print("STEP 4: Degrees of Freedom")
    print("=" * 70)

    # Free parameters in the nomenclator+superencipherment model:
    #
    # Code groups:
    #   G_E: 4 letters (EAST) = 4 DOF
    #   G_N: 5 letters (NORTH) = 5 DOF
    #   G_B: 6 letters (BERLIN) = 6 DOF, but G_B[2] linked to G_N[2] via Bean-EQ
    #   G_C: 5 letters (CLOCK) = 5 DOF
    #   Subtotal: 4+5+6+5 = 20 code group DOF, minus 1 Bean-EQ = 19 effective
    #
    # Key values:
    #   At crib positions (24 total): determined by code groups and CT
    #   At non-crib positions (97-24 = 73): 73 independent key values
    #
    # Total with unrestricted key: 19 + 73 = 92 DOF
    #
    # But wait: the EAST hard constraints (k[30+j]-k[21+j] = constant) are
    # AUTOMATICALLY satisfied by the model (they come FROM the model).
    # They're not additional constraints - they're consequences.
    # So the 4 EAST hard constraints don't reduce DOF further.
    #
    # Additional consideration: G_E absorbs into the key.
    # k[21+j] = CT[21+j] - G_E[j], and k[30+j] = CT[30+j] - G_E[j]
    # If we shift G_E by +1, all k values at EAST positions shift by -1.
    # The key at non-crib positions is unconstrained, so this shift is
    # indistinguishable from adjusting those key values.
    # BUT: the key values at NORTH and BERLIN/CLOCK positions are also
    # functions of their own code groups. So G_E, G_N, G_B, G_C are NOT
    # redundant with the key — they parameterize different positions.
    #
    # The actual redundancy: if the key is UNRESTRICTED (not periodic),
    # then the code groups are fully absorbed into the key.
    # k[i] = CT[i] - G(i) means we can set any G and adjust k[i] accordingly.
    # The only constraint that survives is Bean-EQ (k[27]=k[65]),
    # the Bean inequalities, and the EAST differential.
    #
    # So with unrestricted key: 97 key values - 1 (Bean-EQ) = 96 DOF.
    # The code groups don't add freedom; they're absorbed.

    print("  Model: CT[i] = (G_word[offset] + k[i]) mod 26")
    print()
    print("  Case A: Unrestricted (non-periodic) key")
    print("    Free parameters: 97 key values")
    print("    Constraints: 1 Bean-EQ (k[27]=k[65])")
    print("    Hard constraints from EAST repetition: 4 (k[30+j]-k[21+j] = const)")
    print("    NOTE: Code groups are fully absorbed into unrestricted key")
    print("    → Code groups add 0 net DOF (each G_word value simply shifts k)")
    print("    → EAST hard constraints reduce key DOF by 4 (k[30..33] determined by k[21..24] and CT)")
    print("    Effective DOF = 97 - 1 (Bean-EQ) - 4 (EAST repeat) = 92")
    print("    Bean inequalities: 21 constraints (inequality, not equality)")
    print("    These don't reduce DOF but exclude a fraction of the space")
    print()
    print("  VERDICT: With unrestricted key, model is MASSIVELY underdetermined (92 DOF)")

    # Case B: Periodic key
    print()
    print("  Case B: Periodic key with period p")
    print("    Key DOF = p (one value per residue class)")
    print("    Code group DOF = 4 + 5 + 6 + 5 = 20 (G_E, G_N, G_B, G_C)")
    print("    Constraints:")
    print("      - 1 Bean-EQ: k[27] = k[65]")
    print("      - 4 EAST repeat: k[30+j] = k[21+j] + (ct_east2[j] - ct_east1[j]) (mod 26)")
    print("        Under periodic key: k[21+j mod p] + const = k[30+j mod p] (mod 26)")
    print("        This constrains the key IF (21+j) mod p != (30+j) mod p")
    print("      - Periodicity links between key at crib positions:")
    print("        All positions with same residue class share one key value")
    print("        → Code group values must be consistent across positions with same residue")
    print()

    # For each Bean-surviving period, analyze constraints
    bean_periods = [8, 13, 16, 19, 20, 23, 24, 26]
    crib_positions_list = sorted(CRIB_POSITIONS)

    results["steps"]["step4_dof"] = {
        "unrestricted_dof": 92,
        "unrestricted_verdict": "MASSIVELY UNDERDETERMINED",
        "periodic_analysis": {}
    }

    # ================================================================
    # Step 5: Periodic key enumeration
    # ================================================================
    print("\n" + "=" * 70)
    print("STEP 5: Periodic Key Analysis for Each Bean-Surviving Period")
    print("=" * 70)

    # Map each crib position to its word segment and offset within that segment
    def get_segment(pos):
        """Returns (word_label, code_group_symbol, offset_in_code_group)."""
        if 21 <= pos <= 24:
            return ("EAST1", "G_E", pos - 21)
        elif 25 <= pos <= 29:
            return ("NORTH", "G_N", pos - 25)
        elif 30 <= pos <= 33:
            return ("EAST2", "G_E", pos - 30)
        elif 63 <= pos <= 68:
            return ("BERLIN", "G_B", pos - 63)
        elif 69 <= pos <= 73:
            return ("CLOCK", "G_C", pos - 69)
        return None

    for period in bean_periods:
        print(f"\n  ─── Period {period} ───")

        # Group crib positions by residue class
        residue_groups = defaultdict(list)
        for pos in crib_positions_list:
            residue_groups[pos % period].append(pos)

        # For each residue class with >1 crib position, we have constraints:
        # All positions in the class share the same key value k_r.
        # k_r = CT[pos_i] - G_word_i[offset_i] (mod 26)
        # So: CT[pos_i] - G_word_i[offset_i] = CT[pos_j] - G_word_j[offset_j] (mod 26)
        # → G_word_j[offset_j] - G_word_i[offset_i] = CT[pos_j] - CT[pos_i] (mod 26)

        n_residues_with_cribs = len(residue_groups)
        total_constraints = 0
        constraint_details = []

        print(f"    Crib positions span {n_residues_with_cribs} residue classes (of {period} total)")

        for r in sorted(residue_groups.keys()):
            positions = residue_groups[r]
            if len(positions) > 1:
                # (len-1) equality constraints from this group
                n_constraints = len(positions) - 1
                total_constraints += n_constraints

                segments = [get_segment(p) for p in positions]
                for i in range(len(positions) - 1):
                    p_i, p_j = positions[i], positions[i + 1]
                    seg_i, seg_j = segments[i], segments[i + 1]
                    ct_diff_val = (idx(CT[p_j]) - idx(CT[p_i])) % MOD
                    desc = f"{seg_j[1]}[{seg_j[2]}] - {seg_i[1]}[{seg_i[2]}] = {ct_diff_val} (CT[{p_j}]-CT[{p_i}])"
                    constraint_details.append(desc)

                pos_str = ", ".join(str(p) for p in positions)
                seg_str = ", ".join(f"{s[0]}:{s[1]}[{s[2]}]" for s in segments)
                print(f"    Residue {r}: positions [{pos_str}] → {seg_str}")
                print(f"      → {n_constraints} constraint(s)")
            else:
                seg = get_segment(positions[0])
                print(f"    Residue {r}: position [{positions[0]}] → {seg[0]}:{seg[1]}[{seg[2]}] (singleton)")

        # Count DOF for periodic key
        # Code group DOF: G_E(4) + G_N(5) + G_B(6) + G_C(5) = 20
        # But EAST is repeated, so G_E is shared (already counted once = 4)
        # Key DOF: p values, but we can fix one (overall shift absorbed into code groups)
        # Actually no — the key and code groups are NOT redundant when periodic.
        # k[i] = k[i mod p], and k_r = CT[pos] - G[offset] for each crib pos.
        # The key values at non-crib residues are free. For crib residues,
        # each k_r is determined by ONE code group letter (the first in its class)
        # and then all other positions in the same class constrain OTHER code group letters.

        # Free code group letters (initial):
        # G_E: 4 letters
        # G_N: 5 letters
        # G_B: 6 letters
        # G_C: 5 letters
        # = 20 code group letters total

        # Periodicity constraints: total_constraints equations linking code group letters
        # Bean-EQ: 1 additional constraint (G_B[2] - G_N[2] = 6)
        # Key variables: p values, but each residue with a crib position has its k_r
        # determined by the first code group letter. So:
        # - Residues with NO crib: 1 DOF each (free k_r)
        # - Residues with cribs: 0 DOF for k_r (determined by first code group + CT)

        n_residues_no_crib = period - n_residues_with_cribs
        code_group_dof = 20
        bean_eq_constraints = 1

        # Each residue class with m>1 crib positions gives (m-1) constraints
        # on code group letters. Plus Bean-EQ gives 1 more.
        net_code_dof = code_group_dof - total_constraints - bean_eq_constraints
        total_dof = net_code_dof + n_residues_no_crib

        # But we must also check: can net_code_dof go negative?
        # If constraints > code_group_dof + 1, the system is overconstrained
        overconstrained = total_constraints + bean_eq_constraints > code_group_dof

        print(f"\n    DOF analysis:")
        print(f"      Code group letters: {code_group_dof}")
        print(f"      Periodicity constraints: {total_constraints}")
        print(f"      Bean-EQ constraint: {bean_eq_constraints}")
        print(f"      Net code group DOF: max(0, {code_group_dof} - {total_constraints} - {bean_eq_constraints}) = {max(0, net_code_dof)}")
        print(f"      Free key residues (no crib): {n_residues_no_crib}")
        print(f"      Total DOF: {max(0, net_code_dof) + n_residues_no_crib}")
        if overconstrained:
            print(f"      ** OVERCONSTRAINED ** ({total_constraints + bean_eq_constraints} constraints > {code_group_dof} code group letters)")

        # Check EAST repeat constraints under this period
        east_repeat_consistent = True
        east_repeat_details = []
        for j in range(4):
            r21 = (21 + j) % period
            r30 = (30 + j) % period
            if r21 == r30:
                # Same residue class → k values are automatically equal
                # But we need ct_east2[j] - ct_east1[j] = 0 for this to be consistent
                # Actually: k_r = CT[21+j] - G_E[j] AND k_r = CT[30+j] - G_E[j]
                # → CT[21+j] = CT[30+j]? No! CT[21+j] - G_E[j] = CT[30+j] - G_E[j]
                # → CT[21+j] = CT[30+j] mod 26
                if ct_east1[j] != ct_east2[j]:
                    east_repeat_consistent = False
                    east_repeat_details.append(
                        f"j={j}: pos {21+j} and {30+j} share residue {r21}, "
                        f"but CT[{21+j}]={ct_east1[j]} != CT[{30+j}]={ct_east2[j]} → CONTRADICTION"
                    )
                else:
                    east_repeat_details.append(
                        f"j={j}: pos {21+j} and {30+j} share residue {r21}, CT values match → consistent"
                    )
            else:
                # Different residue classes → k values are independent → no constraint from EAST repeat
                # (the code group G_E[j] absorbs the difference)
                east_repeat_details.append(
                    f"j={j}: pos {21+j} (r={r21}) and {30+j} (r={r30}) in different classes → no constraint"
                )

        print(f"\n    EAST repeat consistency under period {period}:")
        for detail in east_repeat_details:
            print(f"      {detail}")
        if not east_repeat_consistent:
            print(f"      ** EAST repeat IMPOSSIBLE at period {period} under this model **")

        # Bean-EQ check: positions 27 and 65
        r27 = 27 % period
        r65 = 65 % period
        bean_eq_auto = (r27 == r65)  # Auto-satisfied if same residue
        if bean_eq_auto:
            # k[27] = k[65] automatically. But:
            # k_r = CT[27] - G_N[2] = CT[65] - G_B[2]
            # Since CT[27]=15, CT[65]=21: G_B[2] - G_N[2] = 6 still required
            bean_eq_note = f"r27={r27} = r65={r65}: auto-satisfied (same residue), but G_B[2]-G_N[2]={bean_diff} still required"
        else:
            bean_eq_note = f"r27={r27} != r65={r65}: different residues, so k values come from different key slots. Bean-EQ: k_{r27} = k_{r65} → constrains key."

        print(f"\n    Bean-EQ: {bean_eq_note}")

        # Bean-INEQ: which inequalities constrain the same residue?
        bean_ineq_conflicts = 0
        for a, b in BEAN_INEQ:
            if a in CRIB_POSITIONS and b in CRIB_POSITIONS:
                ra = a % period
                rb = b % period
                if ra == rb:
                    # Same residue → k[a] = k[b] automatically → VIOLATES inequality
                    # UNLESS the inequality can be satisfied by the model
                    # k[a] = CT[a] - G_A[off_a], k[b] = CT[b] - G_B[off_b]
                    # Since ra = rb: k[a] = k[b] (same key slot) → inequality says k[a] != k[b] → CONTRADICTION
                    # Wait: k[a] != k[b] but k[a] = k[b] because same residue → CONTRADICTION
                    bean_ineq_conflicts += 1

        if bean_ineq_conflicts > 0:
            print(f"    Bean-INEQ: {bean_ineq_conflicts} inequality pair(s) share a residue → CONTRADICTION")
            east_repeat_consistent = False  # Mark as impossible
        else:
            print(f"    Bean-INEQ: no conflicts (all inequality pairs in different residue classes)")

        verdict = "CONSISTENT" if east_repeat_consistent else "IMPOSSIBLE"
        print(f"\n    VERDICT for period {period}: {verdict}")
        if east_repeat_consistent:
            print(f"    Total DOF: {max(0, net_code_dof) + n_residues_no_crib}")

        results["steps"]["step4_dof"]["periodic_analysis"][str(period)] = {
            "n_residues_with_cribs": n_residues_with_cribs,
            "n_residues_no_crib": n_residues_no_crib,
            "periodicity_constraints": total_constraints,
            "bean_eq_auto_satisfied": bean_eq_auto,
            "east_repeat_consistent": east_repeat_consistent,
            "bean_ineq_conflicts": bean_ineq_conflicts,
            "net_code_dof": max(0, net_code_dof),
            "total_dof": max(0, net_code_dof) + n_residues_no_crib if east_repeat_consistent else 0,
            "overconstrained": overconstrained,
            "verdict": verdict,
            "constraint_details": constraint_details,
            "east_repeat_details": east_repeat_details
        }

    # ================================================================
    # Step 6: Alternative segmentations
    # ================================================================
    print("\n" + "=" * 70)
    print("STEP 6: Alternative Segmentations")
    print("=" * 70)

    # What if the word boundaries are different?
    # E.g., individual letters, or different word breaks
    alt_segmentations = [
        ("EAST+NORTH+EAST | BERLIN+CLOCK", [(21,4,"G_E"),(25,5,"G_N"),(30,4,"G_E"),(63,6,"G_B"),(69,5,"G_C")]),
        ("EASTNORTHEAST | BERLINCLOCK", [(21,13,"G_ENE"),(63,11,"G_BC")]),
        ("E+A+S+T+N+O+R+T+H+E+A+S+T | B+E+R+L+I+N+C+L+O+C+K",
         [(21+i,1,f"G_{CRIB_DICT[21+i]}") for i in range(13)] +
         [(63+i,1,f"G_{CRIB_DICT[63+i]}") for i in range(11)]),
    ]

    for name, segs in alt_segmentations:
        # Count unique code groups
        unique_groups = set()
        total_letters = 0
        for start, length, label in segs:
            unique_groups.add(label)
            total_letters += length

        # Repeated groups
        group_counts = defaultdict(int)
        for _, _, label in segs:
            group_counts[label] += 1
        repeated = {k: v for k, v in group_counts.items() if v > 1}

        # Total code group DOF
        code_letters = sum(length for start, length, label in
                         {label: (start, length, label) for start, length, label in segs}.values())
        # Actually: unique groups, each with their length
        group_sizes = {}
        for start, length, label in segs:
            group_sizes[label] = length  # last one wins if repeated (should be same)
        total_code_dof = sum(group_sizes.values())

        print(f"\n  Segmentation: {name}")
        print(f"    Unique code groups: {len(unique_groups)}")
        print(f"    Total code group letters: {total_code_dof}")
        print(f"    Repeated groups: {repeated if repeated else 'none'}")

        # Under individual letters: each letter is its own code group (1 letter = 1 value)
        # Repeated letters MUST map to the same code value
        if len(unique_groups) > 10:  # individual letters
            # For individual letter encoding:
            unique_pt_letters = set()
            for pos in crib_positions_list:
                unique_pt_letters.add(CRIB_DICT[pos])
            print(f"    Unique PT letters in cribs: {len(unique_pt_letters)} → {sorted(unique_pt_letters)}")
            print(f"    Code group DOF: {len(unique_pt_letters)} (one value per unique letter)")
            print(f"    With unrestricted key: model = mono substitution + key = standard polyalphabetic")
            print(f"    This reduces to the standard model already exhaustively tested")

    results["steps"]["step6_alt_segmentations"] = {
        "primary": "EAST+NORTH+EAST | BERLIN+CLOCK (20 code group DOF)",
        "full_word": "EASTNORTHEAST | BERLINCLOCK (24 code group DOF, no repeated words)",
        "individual": "Single letters (13 unique, reduces to standard polyalphabetic)"
    }

    # ================================================================
    # Final Assessment
    # ================================================================
    print("\n" + "=" * 70)
    print("FINAL ASSESSMENT")
    print("=" * 70)

    print()
    print("1. EAST Differential Independence: CONFIRMED")
    print(f"   CT[30..33] - CT[21..24] = {ct_diff} is code-group-independent")
    print()
    print("2. Bean-EQ constrains code groups: G_B[2] - G_N[2] = 6 (mod 26)")
    print()
    print("3. Degrees of Freedom:")

    # Summarize periodic results
    consistent_periods = []
    impossible_periods = []
    for period in bean_periods:
        data = results["steps"]["step4_dof"]["periodic_analysis"][str(period)]
        if data["verdict"] == "CONSISTENT":
            consistent_periods.append((period, data["total_dof"]))
        else:
            impossible_periods.append(period)

    print(f"   Unrestricted key: 92 DOF → UNDERDETERMINED")
    print(f"   Periodic key (consistent): {consistent_periods}")
    print(f"   Periodic key (impossible): {impossible_periods}")
    print()

    for period, dof in consistent_periods:
        print(f"   Period {period}: {dof} DOF → {'UNDERDETERMINED' if dof > 0 else 'FULLY CONSTRAINED'}")

    print()
    print("4. Model Confirmability:")
    all_underdetermined = all(dof > 0 for _, dof in consistent_periods)
    if all_underdetermined:
        print("   ALL surviving periodic models are UNDERDETERMINED")
        print("   The nomenclator+superencipherment model CANNOT be confirmed or")
        print("   eliminated from crib constraints alone.")
        print()
        print("   To make progress, we would need:")
        print("   - A specific candidate text for the code book")
        print("   - A specific key (periodic or otherwise)")
        print("   - Or: plaintext readability constraints (quadgram, word detection)")
    else:
        print("   Some models are fully constrained — enumeration possible")

    print()
    print("5. Key Insight: Code Group Absorption")
    print("   Under unrestricted key, code groups are REDUNDANT — they are absorbed")
    print("   into the key. The nomenclator model with unrestricted superencipherment")
    print("   key is algebraically equivalent to a standard running-key cipher.")
    print("   The nomenclator structure only constrains when the key has structure")
    print("   (e.g., periodic) AND the same word appears multiple times in cribs.")
    print("   Only EAST is repeated, giving 4 hard constraints.")
    print()
    print("VERDICT: UNDERDETERMINED — model cannot be confirmed or eliminated")
    print("from the 24 known crib positions alone.")

    results["final_verdict"] = "UNDERDETERMINED"
    results["consistent_periods"] = [{"period": p, "dof": d} for p, d in consistent_periods]
    results["impossible_periods"] = impossible_periods
    results["key_findings"] = [
        "EAST differential [1,25,1,23] is code-group-independent (CONFIRMED)",
        f"Bean-EQ constrains code groups: G_B[2] - G_N[2] = {bean_diff} (mod 26)",
        "Unrestricted key: 92 DOF (massively underdetermined)",
        f"Periodic key: {len(consistent_periods)} of {len(bean_periods)} Bean-surviving periods are consistent",
        f"Impossible periods under this model: {impossible_periods}",
        "Code groups are absorbed into unrestricted key (model = standard running-key)",
        "Model CANNOT be confirmed or eliminated from crib constraints alone"
    ]

    # Write results
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
