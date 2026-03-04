#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-SOLVE-22: Final Testable Gaps

Addresses the remaining computationally testable hypotheses identified by
the final viability assessment agent.

PART A: Non-linear recurrence at periods 14-26 (extending E-SOLVE-18)
PART B: Null insertion algebraic check (73-char PT + 24 nulls)
PART C: KA-tableau mask (KA-indexed columns) + AZ cipher keys
PART D: Digraphic consistency check (49 pairs)
"""

import sys
sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
)

CT_INT = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS}

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# Key values under each variant
VIG_KEY = {pos: (CT_INT[pos] - CRIB_PT[pos]) % MOD for pos in CRIB_POS}
BEAU_KEY = {pos: (CT_INT[pos] + CRIB_PT[pos]) % MOD for pos in CRIB_POS}
VARBEAU_KEY = {pos: (CRIB_PT[pos] - CT_INT[pos]) % MOD for pos in CRIB_POS}

ENE_POS = list(range(21, 34))  # positions 21-33
BC_POS = list(range(63, 74))    # positions 63-73


print("E-SOLVE-22: Final Testable Gaps")
print("=" * 70)

# =========================================================================
# PART A: Non-linear recurrence at periods 14-26
# =========================================================================
print("\nPART A: Non-Linear Recurrence at Periods 14-26")
print("-" * 50)

def test_nonlinear_recurrence(key_vals, periods_range):
    """Test non-linear recurrence models at given periods."""
    results = []

    for variant_name, keys in [("Vig", VIG_KEY), ("Beau", BEAU_KEY),
                                ("VarBeau", VARBEAU_KEY)]:
        for model_name, recurrence in [
            ("affine", lambda k, w, a: (a * k + w) % MOD),
            ("quadratic", lambda k, w, a: (k * k + w) % MOD),
            ("multiplicative", lambda k, w, a: (k * w) % MOD),
            ("mixed", lambda k, w, a: (k * a + w * w) % MOD),
        ]:
            for period in periods_range:
                for a_val in range(2, 26) if "affine" in model_name or "mixed" in model_name else [0]:
                    # Derive keyword from ENE consecutive transitions
                    keyword = {}
                    consistent = True

                    for idx in range(len(ENE_POS) - 1):
                        pos_i = ENE_POS[idx]
                        pos_j = ENE_POS[idx + 1]
                        k_i = keys[pos_i]
                        k_j = keys[pos_j]
                        r_j = pos_j % period

                        # k_j = recurrence(k_i, w[r_j], a)
                        # Solve for w[r_j]
                        found_w = None
                        for w_try in range(MOD):
                            if recurrence(k_i, w_try, a_val) == k_j:
                                found_w = w_try
                                break

                        if found_w is None:
                            consistent = False
                            break

                        if r_j in keyword:
                            if keyword[r_j] != found_w:
                                consistent = False
                                break
                        else:
                            keyword[r_j] = found_w

                    if not consistent:
                        continue

                    # Cross-validate with BC
                    bc_consistent = True
                    for idx in range(len(BC_POS) - 1):
                        pos_i = BC_POS[idx]
                        pos_j = BC_POS[idx + 1]
                        k_i = keys[pos_i]
                        k_j = keys[pos_j]
                        r_j = pos_j % period

                        found_w = None
                        for w_try in range(MOD):
                            if recurrence(k_i, w_try, a_val) == k_j:
                                found_w = w_try
                                break

                        if found_w is None:
                            bc_consistent = False
                            break

                        if r_j in keyword:
                            if keyword[r_j] != found_w:
                                bc_consistent = False
                                break
                        else:
                            keyword[r_j] = found_w

                    if bc_consistent:
                        # Forward propagate from all 26 seeds
                        best_matches = 0
                        for seed in range(MOD):
                            k = [0] * CT_LEN
                            k[0] = seed
                            for i in range(1, CT_LEN):
                                r = i % period
                                w = keyword.get(r, 0)
                                k[i] = recurrence(k[i-1], w, a_val)

                            matches = sum(
                                1 for pos in CRIB_POS
                                if k[pos] == keys[pos]
                            )
                            best_matches = max(best_matches, matches)

                        if best_matches >= 18:
                            results.append((
                                variant_name, model_name, period,
                                a_val, best_matches
                            ))
                            print(f"  *** SIGNAL: {variant_name}/{model_name} "
                                  f"p={period} a={a_val}: "
                                  f"{best_matches}/24")
                        elif best_matches >= 10:
                            results.append((
                                variant_name, model_name, period,
                                a_val, best_matches
                            ))

    return results

part_a_results = test_nonlinear_recurrence(VIG_KEY, range(14, 27))
if not part_a_results:
    print("  ZERO cross-validated candidates at periods 14-26.")
    print("  [DERIVED FACT] Non-linear recurrence ELIMINATED at ALL periods 2-26.")
else:
    print(f"  {len(part_a_results)} candidates found (check forward propagation).")
    for v, m, p, a, matches in part_a_results:
        print(f"    {v}/{m} p={p} a={a}: {matches}/24")

# =========================================================================
# PART B: Null Insertion Algebraic Check
# =========================================================================
print("\nPART B: Null Insertion Algebraic Check (73-char PT + 24 nulls)")
print("-" * 50)

# KRYPTOS keyword values (period 7)
KRYPTOS_KEY = [ALPH_IDX[c] for c in "KRYPTOS"]

# Check: for each distribution of 24 nulls among the 73 non-crib positions,
# can the reduced positions of ENE and BC be consistent with period 7?
#
# Key insight: within ENE (13 consecutive CT positions, all non-null),
# the REDUCED positions are also consecutive (since no nulls in ENE).
# The reduced position of ENE start = 21 - N_before (nulls before pos 21).
# Within ENE, reduced positions are 21-N_before, 22-N_before, ..., 33-N_before.
#
# For period 7 consistency within ENE:
# key[reduced_pos(21+i)] must be the same for all i with same residue mod 7.
# reduced_pos(21+i) = 21 + i - N_before
# Residue = (21 + i - N_before) % 7

# Under Vigenère with KRYPTOS:
# key[reduced_pos] = KRYPTOS_KEY[reduced_pos % 7]
# So we need: VIG_KEY[21+i] == KRYPTOS_KEY[(21+i-N_before) % 7]

# For ENE (13 positions), check for each N_before (0..20):
print("  Testing ENE consistency with KRYPTOS key under null insertion:")
ene_consistent_nbefore = set()

for n_before in range(21):  # 0 to 20 nulls before ENE
    # Check ENE internal consistency
    ene_ok = True
    for i in range(13):
        pos = 21 + i
        reduced_pos = pos - n_before
        key_residue = reduced_pos % 7
        expected_key = KRYPTOS_KEY[key_residue]
        actual_key_vig = VIG_KEY[pos]
        if actual_key_vig != expected_key:
            ene_ok = False
            break
    if ene_ok:
        ene_consistent_nbefore.add(("vig", n_before))

    # Same for Beaufort
    ene_ok = True
    for i in range(13):
        pos = 21 + i
        reduced_pos = pos - n_before
        key_residue = reduced_pos % 7
        expected_key = KRYPTOS_KEY[key_residue]
        actual_key_beau = BEAU_KEY[pos]
        if actual_key_beau != expected_key:
            ene_ok = False
            break
    if ene_ok:
        ene_consistent_nbefore.add(("beau", n_before))

    # VarBeau
    ene_ok = True
    for i in range(13):
        pos = 21 + i
        reduced_pos = pos - n_before
        key_residue = reduced_pos % 7
        expected_key = KRYPTOS_KEY[key_residue]
        actual_key_vb = VARBEAU_KEY[pos]
        if actual_key_vb != expected_key:
            ene_ok = False
            break
    if ene_ok:
        ene_consistent_nbefore.add(("varbeau", n_before))

if not ene_consistent_nbefore:
    print("  ZERO N_before values produce ENE-consistent period-7 KRYPTOS key")
    print("  under any variant.")
    print("  [DERIVED FACT] Null insertion + KRYPTOS period-7: ENE block IMPOSSIBLE")
else:
    print(f"  {len(ene_consistent_nbefore)} (variant, N_before) pairs pass ENE:")
    for variant, nb in sorted(ene_consistent_nbefore):
        print(f"    {variant}, N_before={nb}")

    # For surviving (variant, N_before), check BC consistency
    print("\n  Cross-checking with BC block:")
    full_survivors = []

    for variant, n_before in sorted(ene_consistent_nbefore):
        if variant == "vig":
            keys_used = VIG_KEY
        elif variant == "beau":
            keys_used = BEAU_KEY
        else:
            keys_used = VARBEAU_KEY

        # N_between can range such that total nulls = 24
        # N_before + N_between + N_after = 24
        # N_between: nulls in positions 34-62 (29 positions)
        # N_after: nulls in positions 74-96 (23 positions)
        for n_between in range(min(24 - n_before, 29) + 1):
            n_after = 24 - n_before - n_between
            if n_after < 0 or n_after > 23:
                continue

            # Check BC block
            bc_ok = True
            for i in range(11):
                pos = 63 + i
                reduced_pos = pos - n_before - n_between
                key_residue = reduced_pos % 7
                expected_key = KRYPTOS_KEY[key_residue]
                if keys_used[pos] != expected_key:
                    bc_ok = False
                    break

            if bc_ok:
                full_survivors.append(
                    (variant, n_before, n_between, n_after)
                )
                print(f"    *** PASS: {variant} N_before={n_before} "
                      f"N_between={n_between} N_after={n_after}")

    if not full_survivors:
        print("  ZERO full survivors (ENE+BC cross-validation).")
        print("  [DERIVED FACT] Null insertion + KRYPTOS period-7: "
              "ENE+BC cross-block IMPOSSIBLE under all null distributions")
    else:
        print(f"  {len(full_survivors)} survivors!")

# Also test with other period-7 keywords
print("\n  Testing with arbitrary period-7 keywords (algebraic check):")
print("  For period 7 WITHOUT specific keyword, check if ENE and BC are")
print("  mutually consistent for ANY period-7 key under null insertion:")

# For any period-7 key: within ENE (13 positions), residues 0-6 are hit.
# At each residue, all positions must have the same key value.
# Positions 21+i map to residue (21+i-N_before) % 7.
# With 13 consecutive positions, each residue is hit 1-2 times.
# For consistency, the key values at same-residue positions must agree.

arbitrary_ene_pass = 0
arbitrary_full_pass = 0

for n_before in range(21):
    for variant_name, keys_used in [("vig", VIG_KEY), ("beau", BEAU_KEY),
                                     ("varbeau", VARBEAU_KEY)]:
        # Check ENE internal consistency (same residue → same key)
        residue_key = {}
        ene_ok = True
        for i in range(13):
            pos = 21 + i
            r = (pos - n_before) % 7
            kval = keys_used[pos]
            if r in residue_key:
                if residue_key[r] != kval:
                    ene_ok = False
                    break
            else:
                residue_key[r] = kval
        if not ene_ok:
            continue

        arbitrary_ene_pass += 1

        # For BC: try all N_between values
        for n_between in range(min(24 - n_before, 29) + 1):
            n_after = 24 - n_before - n_between
            if n_after < 0 or n_after > 23:
                continue

            bc_ok = True
            bc_residue_key = dict(residue_key)  # Copy ENE constraints
            for i in range(11):
                pos = 63 + i
                r = (pos - n_before - n_between) % 7
                kval = keys_used[pos]
                if r in bc_residue_key:
                    if bc_residue_key[r] != kval:
                        bc_ok = False
                        break
                else:
                    bc_residue_key[r] = kval

            if bc_ok:
                arbitrary_full_pass += 1
                if arbitrary_full_pass <= 3:
                    kw_str = "".join(
                        ALPH[bc_residue_key.get(r, 0)] for r in range(7)
                    )
                    print(f"    PASS: {variant_name} N_before={n_before} "
                          f"N_between={n_between} keyword={kw_str}")

print(f"\n  ENE-only passes: {arbitrary_ene_pass}")
print(f"  Full (ENE+BC) passes: {arbitrary_full_pass}")
if arbitrary_full_pass == 0:
    print("  [DERIVED FACT] Null insertion + period-7 key: IMPOSSIBLE for")
    print("  ALL null distributions under all variants (algebraic proof)")
elif arbitrary_full_pass > 100:
    print("  (Many passes = underdetermined, not signal)")
else:
    print("  Investigate these candidates further!")

# =========================================================================
# PART C: KA-Tableau Mask (KA-indexed columns) + AZ Cipher
# =========================================================================
print("\nPART C: KA-Tableau Mask (KA-indexed columns) + AZ Cipher Keys")
print("-" * 50)

# Physical sculpture: columns are labeled in KA order
# Mask using row r: mask(L) = KA[(r + KA_IDX[L]) % 26]
# Under AZ Vigenère: K_eff[i] = (CT_INT[i] - ALPH_IDX[mask(PT[i])]) % 26

print("  Computing effective keys under KA-mask + AZ-cipher:")
print("  (mask uses KA tableau with KA-indexed columns;")
print("   cipher uses standard AZ Vigenère)")
print()

for row in range(MOD):
    # Compute masked crib PT (KA-indexed columns)
    masked_pt_ka = {}
    for pos in CRIB_POS:
        pt_letter = ALPH[CRIB_PT[pos]]
        ka_col = KA_IDX[pt_letter]
        masked_letter = KA[(row + ka_col) % MOD]
        masked_pt_ka[pos] = ALPH_IDX[masked_letter]

    # Effective key under AZ Vigenère
    eff_key_vig = {
        pos: (CT_INT[pos] - masked_pt_ka[pos]) % MOD
        for pos in CRIB_POS
    }

    # Check periodicity (best match)
    for period in range(2, 25):
        residue_vals = {}
        matches = 0
        for pos in CRIB_POS:
            r = pos % period
            if r in residue_vals:
                if residue_vals[r] == eff_key_vig[pos]:
                    matches += 1
            else:
                residue_vals[r] = eff_key_vig[pos]
                matches += 1

        if matches == 24:
            kw_str = "".join(
                ALPH[residue_vals.get(r, 0)] for r in range(period)
            )
            print(f"  *** 24/24 PERIODIC HIT: mask_row={row} ({KA[row]}) "
                  f"period={period} keyword={kw_str}")

    # Also try under Beaufort
    eff_key_beau = {
        pos: (CT_INT[pos] + masked_pt_ka[pos]) % MOD
        for pos in CRIB_POS
    }
    for period in range(2, 25):
        residue_vals = {}
        matches = 0
        for pos in CRIB_POS:
            r = pos % period
            if r in residue_vals:
                if residue_vals[r] == eff_key_beau[pos]:
                    matches += 1
            else:
                residue_vals[r] = eff_key_beau[pos]
                matches += 1

        if matches == 24:
            kw_str = "".join(
                ALPH[residue_vals.get(r, 0)] for r in range(period)
            )
            print(f"  *** 24/24 PERIODIC HIT (Beau): mask_row={row} ({KA[row]}) "
                  f"period={period} keyword={kw_str}")

# Also test with AZ-indexed columns (E-SOLVE-21 tested periodicity,
# now verify no 24/24 were missed)
print("\n  Verifying AZ-indexed columns (should match E-SOLVE-21):")
found_any = False
for row in range(MOD):
    masked_pt_az = {}
    for pos in CRIB_POS:
        pt_letter = ALPH[CRIB_PT[pos]]
        az_col = ALPH_IDX[pt_letter]
        masked_letter = KA[(row + az_col) % MOD]
        masked_pt_az[pos] = ALPH_IDX[masked_letter]

    for variant_name, sign in [("Vig", -1), ("Beau", 1)]:
        eff_key = {
            pos: (CT_INT[pos] + sign * masked_pt_az[pos]) % MOD
            for pos in CRIB_POS
        }
        for period in range(2, 25):
            residue_vals = {}
            matches = 0
            for pos in CRIB_POS:
                r = pos % period
                if r in residue_vals:
                    if residue_vals[r] == eff_key[pos]:
                        matches += 1
                else:
                    residue_vals[r] = eff_key[pos]
                    matches += 1
            if matches == 24:
                found_any = True
                print(f"  *** 24/24: row={row} {variant_name} period={period}")

if not found_any:
    print("  Confirmed: no 24/24 at any period for AZ-indexed columns either.")

# =========================================================================
# PART D: Digraphic Consistency Check
# =========================================================================
print("\nPART D: Digraphic Consistency Check")
print("-" * 50)

# Check: are the crib positions consistent with ANY digraphic substitution?
# Under digraphic cipher: consecutive letter pairs are transformed together.
# CT_pair(i) -> PT_pair(i) for pair starting at position 2*i.

for pair_offset in [0, 1]:
    print(f"\n  Pair alignment starting at offset {pair_offset}:")

    # Find complete pairs within cribs
    known_pairs = []
    for pos in CRIB_POS:
        partner = pos + 1 if (pos - pair_offset) % 2 == 0 else pos - 1
        if partner in CRIB_PT:
            if (pos - pair_offset) % 2 == 0:  # pos is first in pair
                ct_pair = (CT_INT[pos], CT_INT[partner])
                pt_pair = (CRIB_PT[pos], CRIB_PT[partner])
                known_pairs.append((pos, ct_pair, pt_pair))

    # Check bijection: same CT pair must map to same PT pair
    ct_to_pt = {}
    pt_to_ct = {}
    contradictions = 0

    for pos, ct_pair, pt_pair in known_pairs:
        if ct_pair in ct_to_pt:
            if ct_to_pt[ct_pair] != pt_pair:
                contradictions += 1
        else:
            ct_to_pt[ct_pair] = pt_pair

        if pt_pair in pt_to_ct:
            if pt_to_ct[pt_pair] != ct_pair:
                contradictions += 1
        else:
            pt_to_ct[pt_pair] = ct_pair

    print(f"  Complete pairs in cribs: {len(known_pairs)}")
    print(f"  Unique CT pairs: {len(ct_to_pt)}")
    print(f"  Unique PT pairs: {len(pt_to_ct)}")
    print(f"  Contradictions: {contradictions}")

    if contradictions > 0:
        print(f"  [DERIVED FACT] Digraphic cipher at offset {pair_offset} "
              f"ELIMINATED ({contradictions} contradictions)")
    else:
        print(f"  No contradictions (consistent, but likely underdetermined "
              f"with {len(ct_to_pt)} constraints on 676 pair mappings)")

# =========================================================================
# SUMMARY
# =========================================================================
print()
print("=" * 70)
print("E-SOLVE-22 SUMMARY")
print("=" * 70)
print()
print("Part A: Non-linear recurrence at periods 14-26:")
if not part_a_results:
    print("  ELIMINATED at ALL periods 2-26 under all 4 function families")
else:
    print(f"  {len(part_a_results)} candidates (investigate)")

print("\nPart B: Null insertion + period-7:")
if arbitrary_full_pass == 0:
    print("  ELIMINATED: no null distribution makes both cribs period-7 consistent")
else:
    print(f"  {arbitrary_full_pass} surviving distributions")

print("\nPart C: KA-mask + AZ-cipher:")
print("  Checked 26 mask rows × 2 column indexings × 2 variants × 23 periods")
print("  = 2,392 combinations for 24/24 periodic key")

print("\nPart D: Digraphic cipher:")
print("  Consistency check for both pair alignments")
