#!/usr/bin/env python3
"""E-TEAM-NOMENCLATOR-SUPER: Nomenclator + superencipherment model for K4.

Tests the model: PT_word -> code_group -> superencipher(code_group, position) -> CT

Key insight: EAST appears at positions 21 and 30 in the plaintext. Under any
fixed code group G for EAST, the superencipherment key difference between
positions 21-24 and 30-33 is fixed at [1,25,1,23] — INDEPENDENT of G.

This script:
1. Verifies the differential algebra
2. Enumerates G_east (26^4) and computes implied key at 8 EAST positions
3. Splits BERLINCLOCK as BERLIN+CLOCK, enumerates code group pairs
4. Filters using Bean-EQ (k[27]=k[65]) and Bean inequalities
5. Tests periodic key models on surviving candidates
6. Reports statistics on survivors per period
"""
import sys, os, json, math, time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.constraints.bean import verify_bean_from_implied


def main():
    print("=" * 70)
    print("E-TEAM-NOMENCLATOR-SUPER: Nomenclator + superencipherment")
    print("=" * 70)
    print()

    # ── Step 1: Verify the differential algebra ──────────────────────────
    print("--- Step 1: Verify differential independence from code group G ---")

    # EAST crib positions and CT values
    # EAST at pos 21-24: CT = FLRV
    # EAST at pos 30-33: CT = GKSS
    east1_ct = CT[21:25]   # FLRV
    east2_ct = CT[30:34]   # GKSS
    east_pt = "EAST"

    print(f"  EAST at pos 21-24: CT = {east1_ct}")
    print(f"  EAST at pos 30-33: CT = {east2_ct}")

    # Under Vigenere superencipherment: CT[i] = (G[offset] + k[i]) mod 26
    # So k[i] = (CT[i] - G[offset]) mod 26
    # For EAST at pos 21: k[21] = (F - G[0]) mod 26
    # For EAST at pos 30: k[30] = (G - G[0]) mod 26
    # Difference: k[30] - k[21] = (G_ct - F_ct) mod 26 = (6 - 5) mod 26 = 1
    # This is independent of G[0]!

    diffs = []
    for i in range(4):
        c1 = ALPH_IDX[east1_ct[i]]
        c2 = ALPH_IDX[east2_ct[i]]
        d = (c2 - c1) % MOD
        diffs.append(d)
    print(f"  Key diffs (k[30..33] - k[21..24]) mod 26 = {diffs}")
    assert diffs == [1, 25, 1, 23], f"Unexpected diffs: {diffs}"
    print(f"  Verified: [1, 25, 1, 23] — INDEPENDENT of code group G")
    print()

    # Cross-check with known Vigenere key values
    vig_east1 = list(VIGENERE_KEY_ENE[:4])  # k[21..24] under direct Vig
    vig_east2 = list(VIGENERE_KEY_ENE[9:13])  # k[30..33] under direct Vig
    vig_diffs = [(vig_east2[i] - vig_east1[i]) % MOD for i in range(4)]
    print(f"  Cross-check with Vigenere keystream: {vig_diffs}")
    assert vig_diffs == diffs, "Inconsistency with Vigenere keystream!"
    print(f"  Consistent.")
    print()

    # ── Step 2: Enumerate code groups for EAST ───────────────────────────
    print("--- Step 2: Enumerate EAST code groups (26^4 = 456,976) ---")
    t0 = time.time()

    # For each G_east (4-letter code group), compute the superencipherment
    # key at positions 21-24 and 30-33
    # Under Vigenere model: k[i] = (CT[i] - G[offset]) mod 26
    # Here offset = i - word_start_pos

    # CT values at EAST positions (numeric)
    ct_east1 = [ALPH_IDX[c] for c in east1_ct]  # FLRV = [5,11,17,21]
    ct_east2 = [ALPH_IDX[c] for c in east2_ct]  # GKSS = [6,10,18,18]

    # Position 27 is ENE crib position 6 (27-21=6), PT = 'R', CT = 'P'
    # In ENE crib: positions 21..33 = EASTNORTHEAST
    # pos 27 = N (offset 6 in crib), CT[27] = P
    # Under nomenclator model: pos 27 is inside a word. EAST = pos 21-24 (4 chars)
    # What word contains position 27? If NORTHEAS or NORTH...
    # Actually the crib words tell us PT, not how the nomenclator segments.
    # We need to think about what the nomenclator SEGMENTS are.

    # Key insight: Under the nomenclator model, we DON'T know the segmentation.
    # The cribs tell us the final plaintext, not the code words.
    # So we can only work with the SUPERENCIPHERMENT KEY values.

    # If we assume the super key is POSITION-DEPENDENT (additive Vigenere-style),
    # then regardless of segmentation, k[i] = CT[i] - G[i_offset] mod 26
    # where i_offset is the position within the current code group.

    # But without knowing segmentation, we don't know i_offset for position 27!
    # We only know i_offset for positions where we know the CODE GROUP boundaries.

    # Simplification: What if the superencipherment key is independent of code
    # group boundaries? I.e., k[i] = f(i) for some function of position only.
    # Then k[i] = (CT[i] - codegroup_char_at_i) mod 26.

    # For EAST at pos 21-24: k[21..24] = (FLRV - G) mod 26
    # For EAST at pos 30-33: k[30..33] = (GKSS - G) mod 26

    # For Bean-EQ: k[27] = k[65]
    # Position 27: PT = 'R' (offset 6 in EASTNORTHEAST)
    # Position 65: PT = 'L' (offset 2 in BERLINCLOCK)
    # But under nomenclator, the code group character at these positions is unknown!

    # Unless: we model it as "the superencipherment acts on the PLAINTEXT directly"
    # i.e., CT[i] = (PT[i] + k[i]) mod 26  (standard Vigenere, no code groups)
    # Then the "nomenclator" is just the plaintext, and the super key IS the key.
    # This reduces to standard Vigenere — already tested.

    # The ACTUAL nomenclator model is:
    # PT is segmented into words/phrases, each replaced by a code group
    # Then the code group sequence is superenciphered.
    # The code groups can be any length, so the intermediate text length
    # might differ from PT length... but K4 is 97 chars both ways.
    # So code groups must collectively be 97 chars (same length as PT).

    # Let's model it as: intermediate text I (97 chars) where I is the
    # concatenation of code groups, and CT[i] = (I[i] + k[i]) mod 26.
    # Then k[i] = (CT[i] - I[i]) mod 26.

    # For EAST at pos 21-24: I[21..24] = G_east, so k[21..24] = (FLRV - G_east) mod 26
    # For EAST at pos 30-33: I[30..33] = G_east, so k[30..33] = (GKSS - G_east) mod 26
    # The key difference [1,25,1,23] holds.

    # For position 27: I[27] is part of whatever code group spans position 27.
    # If EASTNORTHEAST = "EAST" + "NORTH" + "EAST", then:
    #   pos 21-24 = G_east, pos 25-29 = G_north, pos 30-33 = G_east
    #   I[27] = G_north[2] (3rd char of G_north's code group)
    #   k[27] = (CT[27] - G_north[2]) mod 26 = (P - G_north[2]) mod 26

    # For position 65: I[65] is part of whatever code group spans position 65.
    # If BERLINCLOCK = "BERLIN" + "CLOCK", then:
    #   pos 63-68 = G_berlin, pos 69-73 = G_clock
    #   I[65] = G_berlin[2] (3rd char of G_berlin)
    #   k[65] = (CT[65] - G_berlin[2]) mod 26

    # Bean-EQ: k[27] = k[65] means:
    #   (CT[27] - G_north[2]) = (CT[65] - G_berlin[2]) mod 26
    #   G_north[2] - G_berlin[2] = CT[27] - CT[65] mod 26

    # CT[27] = P (15), CT[65] = Y (24)
    # So G_north[2] - G_berlin[2] = 15 - 24 = -9 = 17 mod 26

    print("--- Step 2b: Nomenclator segmentation analysis ---")
    print()
    print(f"  CT[27] = {CT[27]} ({ALPH_IDX[CT[27]]})")
    print(f"  CT[65] = {CT[65]} ({ALPH_IDX[CT[65]]})")
    bean_diff = (ALPH_IDX[CT[27]] - ALPH_IDX[CT[65]]) % MOD
    print(f"  Bean-EQ constraint: G_north[2] - G_berlin[2] = {bean_diff} mod 26")
    print()

    # Segmentation: EASTNORTHEAST as EAST + NORTH + EAST
    # Positions: 21-24 = EAST(1), 25-29 = NORTH, 30-33 = EAST(2)
    # BERLINCLOCK as BERLIN + CLOCK
    # Positions: 63-68 = BERLIN, 69-73 = CLOCK

    # Free variables:
    # G_east: 4 chars (26^4)
    # G_north: 5 chars (26^5)
    # G_berlin: 6 chars (26^6)
    # G_clock: 5 chars (26^5)
    # Total: 26^20 = way too large

    # But Bean-EQ constrains: G_north[2] - G_berlin[2] = 17 mod 26
    # This eliminates 1/26 of the (G_north, G_berlin) space.

    # Additionally, any assumed periodicity of the key constrains further.

    # ── Step 3: For each period p, count Bean-EQ survivors ───────────────
    print("--- Step 3: Period analysis of superencipherment key ---")
    print()

    # For a periodic key of period p: k[i] = k[i mod p]
    # We know k at 8 EAST positions (21-24, 30-33) as functions of G_east
    # and at 13 ENE crib positions (21-33) if we know all code groups.

    # With G_east fixed:
    #   k[21..24] = (ct_east1 - G_east) mod 26  (4 values)
    #   k[30..33] = (ct_east2 - G_east) mod 26  (4 values)
    #   These are determined.

    # Periodicity constraints on EAST positions:
    #   For each pair (i,j) where i mod p = j mod p, require k[i] = k[j]
    #   Positions: 21,22,23,24,30,31,32,33

    # For each period p, check which G_east survive the consistency constraints
    # from the 8 EAST positions alone.

    results_by_period = {}

    # Precompute CT numeric values at all crib positions
    ct_vals = [ALPH_IDX[c] for c in CT]

    # EAST positions: 21-24 and 30-33
    east_positions = list(range(21, 25)) + list(range(30, 34))

    # Full crib positions and their CT values
    # ENE: pos 21-33, PT = EASTNORTHEAST
    # BC: pos 63-73, PT = BERLINCLOCK
    ene_text = "EASTNORTHEAST"
    bc_text = "BERLINCLOCK"

    print("Phase 1: EAST code group enumeration with periodic key constraints")
    print()

    for period in range(2, 27):
        # Group EAST positions by residue class
        residue_groups = defaultdict(list)
        for pos in east_positions:
            residue_groups[pos % period].append(pos)

        # For periodicity: k[i] = k[j] when i % p = j % p
        # k[i] = (ct[i] - G[offset(i)]) mod 26
        # For two positions i, j with same residue:
        # ct[i] - G[offset(i)] = ct[j] - G[offset(j)] mod 26
        # G[offset(i)] - G[offset(j)] = ct[i] - ct[j] mod 26

        # Since G_east has only 4 chars (offsets 0,1,2,3),
        # offset(i) for east1 pos 21+k = k
        # offset(i) for east2 pos 30+k = k
        # So offset is the same for both EASTs!

        # For i in east1 (pos 21+k) and j in east2 (pos 30+k), offset = k:
        # G[k] - G[k] = ct[i] - ct[j] mod 26 => ct[i] = ct[j] mod 26

        # This means for periodicity to hold between east1[k] and east2[k],
        # we need ct_east1[k] = ct_east2[k] mod 26.
        # But ct_east1 = [5,11,17,21] and ct_east2 = [6,10,18,18]
        # These are ALL different, so east1 and east2 are NEVER in same residue
        # for periodicity to work... unless their position residues don't coincide.

        # Check which east1/east2 position pairs share a residue
        constraints_on_G = []  # list of (g_offset_i, g_offset_j, diff) meaning G[oi] - G[oj] = diff
        impossible = False

        for res, positions in residue_groups.items():
            if len(positions) < 2:
                continue
            # All positions in this group must have the same key value
            # k[pos] = (ct[pos] - G[g_offset(pos)]) mod 26
            # For positions from east1: g_offset = pos - 21
            # For positions from east2: g_offset = pos - 30
            ref_pos = positions[0]
            ref_g_offset = (ref_pos - 21) if ref_pos < 25 else (ref_pos - 30)

            for other_pos in positions[1:]:
                other_g_offset = (other_pos - 21) if other_pos < 25 else (other_pos - 30)
                # G[ref_g_offset] - G[other_g_offset] = ct[ref_pos] - ct[other_pos] mod 26
                diff = (ct_vals[ref_pos] - ct_vals[other_pos]) % MOD
                if ref_g_offset == other_g_offset:
                    # Same G offset: diff must be 0
                    if diff != 0:
                        impossible = True
                        break
                else:
                    constraints_on_G.append((ref_g_offset, other_g_offset, diff))
            if impossible:
                break

        if impossible:
            results_by_period[period] = {
                "period": period,
                "east_survivors": 0,
                "eliminated": True,
                "reason": "EAST positions conflict under periodicity",
            }
            print(f"  p={period:2d}: ELIMINATED — EAST position conflict")
            continue

        # Count how many G_east (26^4) satisfy the constraints
        # Each constraint: G[a] - G[b] = c mod 26 reduces DOF by 1
        # Start with 4 DOF (G[0], G[1], G[2], G[3])
        # Simplify: union-find on G indices with offsets

        # Build equivalence classes with offsets
        parent = list(range(4))
        offset = [0] * 4  # offset[i] = G[i] - G[root(i)]

        def find(x):
            if parent[x] == x:
                return x, 0
            root, off = find(parent[x])
            parent[x] = root
            offset[x] = (offset[x] + off) % MOD
            return root, offset[x]

        def union(a, b, diff_ab):
            # G[a] - G[b] = diff_ab mod 26
            ra, oa = find(a)
            rb, ob = find(b)
            if ra == rb:
                # Check consistency: oa - ob should equal diff_ab
                return (oa - ob) % MOD == diff_ab
            parent[rb] = ra
            # G[a] = G[ra] + oa, G[b] = G[rb] + ob
            # G[a] - G[b] = diff_ab => G[ra] + oa - G[rb] - ob = diff_ab
            # G[rb] = G[ra] + oa - ob - diff_ab
            # offset[rb] = oa - ob - diff_ab (as offset from ra)
            offset[rb] = (oa - ob - diff_ab) % MOD
            return True

        for ga, gb, diff in constraints_on_G:
            if not union(ga, gb, diff):
                impossible = True
                break

        if impossible:
            results_by_period[period] = {
                "period": period,
                "east_survivors": 0,
                "eliminated": True,
                "reason": "EAST G constraints inconsistent",
            }
            print(f"  p={period:2d}: ELIMINATED — inconsistent G constraints")
            continue

        # Count free DOF
        roots = set()
        for i in range(4):
            r, _ = find(i)
            roots.add(r)
        free_dof = len(roots)
        east_survivors = 26 ** free_dof

        results_by_period[period] = {
            "period": period,
            "east_survivors": east_survivors,
            "free_dof": free_dof,
            "constraints": len(constraints_on_G),
        }
        print(f"  p={period:2d}: {east_survivors:>10,d} G_east survive ({free_dof} DOF, {len(constraints_on_G)} constraints)")

    print()

    # ── Step 4: Bean-EQ filter with NORTH + BERLIN code groups ───────────
    print("--- Step 4: Bean-EQ constraint analysis ---")
    print()

    # Segmentation: EAST(21-24) + NORTH(25-29) + EAST(30-33)
    # Bean-EQ: k[27] = k[65]
    # k[27] = (CT[27] - G_north[2]) mod 26 = (15 - G_north[2]) mod 26
    # k[65] = (CT[65] - G_berlin[2]) mod 26 = (24 - G_berlin[2]) mod 26
    # Constraint: G_north[2] - G_berlin[2] = 15 - 24 = -9 = 17 mod 26

    # This means for any choice of G_north[2], G_berlin[2] is determined.
    # It's just a single linear constraint on two independent code group chars.
    # P(random satisfaction) = 1/26.

    # Also consider alternative segmentations:
    segmentations = [
        {
            "name": "EAST+NORTH+EAST / BERLIN+CLOCK",
            "ene_segs": [("EAST", 21, 25), ("NORTH", 25, 30), ("EAST", 30, 34)],
            "bc_segs": [("BERLIN", 63, 69), ("CLOCK", 69, 74)],
        },
        {
            "name": "EASTNORTHEAST / BERLINCLOCK (single code groups)",
            "ene_segs": [("EASTNORTHEAST", 21, 34)],
            "bc_segs": [("BERLINCLOCK", 63, 74)],
        },
        {
            "name": "EAST+NORTHEAST / BERLIN+CLOCK",
            "ene_segs": [("EAST", 21, 25), ("NORTHEAST", 25, 34)],
            "bc_segs": [("BERLIN", 63, 69), ("CLOCK", 69, 74)],
        },
        {
            "name": "EAST+NORTH+EAST / BERLIN+C+LOCK",
            "ene_segs": [("EAST", 21, 25), ("NORTH", 25, 30), ("EAST", 30, 34)],
            "bc_segs": [("BERLIN", 63, 69), ("C", 69, 70), ("LOCK", 70, 74)],
        },
    ]

    seg_results = []
    for seg in segmentations:
        print(f"  Segmentation: {seg['name']}")

        # For Bean-EQ: k[27] = k[65]
        # Find which code group contains pos 27 and pos 65
        pos27_seg = None
        pos65_seg = None
        for word, start, end in seg["ene_segs"]:
            if start <= 27 < end:
                pos27_seg = (word, start, end, 27 - start)  # (word, start, end, offset_in_group)
        for word, start, end in seg["bc_segs"]:
            if start <= 65 < end:
                pos65_seg = (word, start, end, 65 - start)

        if pos27_seg and pos65_seg:
            word27, start27, end27, off27 = pos27_seg
            word65, start65, end65, off65 = pos65_seg
            print(f"    pos 27 in '{word27}' code group (offset {off27})")
            print(f"    pos 65 in '{word65}' code group (offset {off65})")

            # Bean-EQ: G_{word27}[off27] - G_{word65}[off65] = CT[27] - CT[65] = 17 mod 26
            ct27 = ALPH_IDX[CT[27]]
            ct65 = ALPH_IDX[CT[65]]
            required_diff = (ct27 - ct65) % MOD
            print(f"    Required: G_{word27}[{off27}] - G_{word65}[{off65}] = {required_diff} mod 26")

            if word27 == word65 and off27 == off65:
                # Same code group, same offset => G[off] - G[off] = 0
                # Constraint: required_diff must be 0
                if required_diff == 0:
                    print(f"    -> Tautological (same code group position)")
                    result = "tautological"
                else:
                    print(f"    -> IMPOSSIBLE (same code group position, diff != 0)")
                    result = "impossible"
            elif word27 == word65:
                # Same code group, different offsets
                # Single constraint on code group: G[off27] - G[off65] = required_diff
                print(f"    -> 1 constraint within '{word27}' code group")
                total_chars = end27 - start27
                survivors = 26 ** (total_chars - 1)  # 1 DOF consumed
                print(f"    -> {survivors:,d} survivors from 26^{total_chars}")
                result = f"1_constraint_{survivors}"
            else:
                # Different code groups: 1 constraint links them
                total_chars_27 = end27 - start27
                total_chars_65 = end65 - start65
                total_dof = total_chars_27 + total_chars_65
                survivors = 26 ** (total_dof - 1)
                print(f"    -> 1 constraint linking '{word27}' and '{word65}'")
                print(f"    -> {survivors:,d} survivors from 26^{total_dof}")
                result = f"1_constraint_cross_{survivors}"

            seg_results.append({
                "segmentation": seg["name"],
                "pos27_word": word27,
                "pos65_word": word65,
                "bean_eq_result": result,
            })
        else:
            print(f"    WARNING: pos 27 or 65 not covered by segmentation")
            seg_results.append({
                "segmentation": seg["name"],
                "bean_eq_result": "uncovered",
            })
        print()

    # ── Step 5: Bean inequality analysis ─────────────────────────────────
    print("--- Step 5: Bean inequality constraint count ---")
    print()

    # Using the EAST+NORTH+EAST / BERLIN+CLOCK segmentation
    ene_segs = [("EAST", 21, 25), ("NORTH", 25, 30), ("EAST", 30, 34)]
    bc_segs = [("BERLIN", 63, 69), ("CLOCK", 69, 74)]

    def find_segment(pos, segments):
        for word, start, end in segments:
            if start <= pos < end:
                return word, start, end, pos - start
        return None

    all_segs = ene_segs + bc_segs
    ineq_applicable = 0
    ineq_same_group = 0
    ineq_cross_group = 0

    for a, b in BEAN_INEQ:
        seg_a = find_segment(a, all_segs)
        seg_b = find_segment(b, all_segs)
        if seg_a and seg_b:
            ineq_applicable += 1
            if seg_a[0] == seg_b[0] and seg_a[1] == seg_b[1]:
                ineq_same_group += 1
            else:
                ineq_cross_group += 1

    print(f"  Bean inequalities applicable to crib segments: {ineq_applicable}/{len(BEAN_INEQ)}")
    print(f"    Same code group: {ineq_same_group}")
    print(f"    Cross code group: {ineq_cross_group}")
    print()

    # ── Step 6: Estimate total search space ──────────────────────────────
    print("--- Step 6: Total search space estimation ---")
    print()

    # Under EAST+NORTH+EAST / BERLIN+CLOCK:
    # G_east: 4 chars = 26^4 = 456,976
    # G_north: 5 chars = 26^5 = 11,881,376
    # G_berlin: 6 chars = 26^6 = 308,915,776
    # G_clock: 5 chars = 26^5 = 11,881,376
    # Total: 26^20 = 19,928,148,895,209,409,152,340,197,376

    total_space = 26**20
    print(f"  Total naive space: 26^20 = {total_space:,.0f}")
    print(f"  Bean-EQ reduces by 1/26: {total_space // 26:,.0f}")

    # With periodic key of period p, each G is further constrained
    for p in [7, 8, 13]:
        if p in results_by_period and not results_by_period[p].get("eliminated"):
            east_surv = results_by_period[p]["east_survivors"]
            # Other code groups would have similar reductions
            print(f"  Period {p}: G_east survivors = {east_surv:,d}")
    print()

    # ── Step 7: Exhaustive EAST enumeration with Bean-EQ check ───────────
    print("--- Step 7: Exhaustive EAST enumeration (456,976 code groups) ---")
    print(f"  For each G_east, compute k[21..24] and k[30..33]")
    print(f"  Then for each possible k[27] (26 values), check Bean-EQ implications")
    print()

    # Under EAST+NORTH+EAST segmentation:
    # k[21..24] = (CT[21..24] - G_east) mod 26
    # k[25..29] = (CT[25..29] - G_north) mod 26
    # k[30..33] = (CT[30..33] - G_east) mod 26  (same G!)
    # So k[21..24] and k[30..33] depend on G_east only.

    # For Bean-EQ: k[27] depends on G_north[2] (unknown)
    # k[65] depends on G_berlin[2] (unknown)
    # Constraint: G_north[2] - G_berlin[2] = 17 mod 26

    # For a periodic key of period p:
    # Additional constraints: k[i] = k[j] when i ≡ j mod p
    # Among the 8 known key positions {21,22,23,24,30,31,32,33}

    # Let's do the full analysis for interesting periods
    print("  Period-by-period Bean analysis:")
    print()

    for period in [7, 8, 13, 16, 19, 20, 23, 24, 26]:
        if period in results_by_period and results_by_period[period].get("eliminated"):
            print(f"  p={period}: Already eliminated from EAST conflicts")
            continue

        # For this period, enumerate all G_east and check:
        # 1) Periodicity consistency of k[21..24], k[30..33]
        # 2) Bean-EQ compatibility

        survivors = 0
        bean_eq_compatible = 0

        for g0 in range(MOD):
            for g1 in range(MOD):
                for g2 in range(MOD):
                    for g3 in range(MOD):
                        # k[21+i] = (ct_east1[i] - g[i]) mod 26
                        # k[30+i] = (ct_east2[i] - g[i]) mod 26
                        k = {}
                        g = [g0, g1, g2, g3]
                        for i in range(4):
                            k[21 + i] = (ct_east1[i] - g[i]) % MOD
                            k[30 + i] = (ct_east2[i] - g[i]) % MOD

                        # Check periodicity on the 8 known positions
                        consistent = True
                        for pos_a in k:
                            for pos_b in k:
                                if pos_a < pos_b and pos_a % period == pos_b % period:
                                    if k[pos_a] != k[pos_b]:
                                        consistent = False
                                        break
                            if not consistent:
                                break

                        if not consistent:
                            continue
                        survivors += 1

                        # Bean-EQ: k[27] = k[65]
                        # k[27] is among our known values (27 is in range 21-33)
                        # k[27] depends on G_north[2], which we don't know.
                        # But if 27 % p == some_pos % p where some_pos is in our
                        # known keys, then k[27] is determined!

                        k27_determined = False
                        k27_value = None
                        for known_pos, known_val in k.items():
                            if known_pos % period == 27 % period and known_pos != 27:
                                k27_determined = True
                                k27_value = known_val
                                break

                        if not k27_determined:
                            # k[27] is free — Bean-EQ can always be satisfied
                            # by choosing G_north[2] and G_berlin[2] appropriately
                            bean_eq_compatible += 1
                        else:
                            # k[27] is determined. k[65] must equal it.
                            # k[65] depends on G_berlin[2].
                            # If 65 % p == some known position, k[65] is also determined
                            k65_determined = False
                            k65_value = None
                            for known_pos, known_val in k.items():
                                if known_pos % period == 65 % period and known_pos != 65:
                                    k65_determined = True
                                    k65_value = known_val
                                    break

                            if k65_determined:
                                if k27_value == k65_value:
                                    bean_eq_compatible += 1
                            else:
                                # k[65] is free, can match k[27] by choosing G_berlin[2]
                                bean_eq_compatible += 1

        results_by_period[period]["period_survivors"] = survivors
        results_by_period[period]["bean_eq_compatible"] = bean_eq_compatible

        print(f"  p={period:2d}: {survivors:>10,d} period-consistent, {bean_eq_compatible:>10,d} Bean-EQ compatible")

    print()

    # ── Step 8: Direct Vigenere key comparison ───────────────────────────
    print("--- Step 8: Compare with standard Vigenere (no nomenclator) ---")
    print()

    # Under standard Vigenere (no nomenclator), the key at crib positions is known:
    print(f"  Vigenere ENE key: {list(VIGENERE_KEY_ENE)}")
    print(f"  Vigenere BC key:  {list(VIGENERE_KEY_BC)}")

    # Under nomenclator + super, the key at the SAME positions would be:
    # k[i] = (CT[i] - G[offset]) mod 26
    # If G = PT (i.e., no nomenclator, code group = plaintext), then
    # k[i] = (CT[i] - PT[i]) mod 26 = standard Vigenere key.

    # Check: does the Vigenere key at EAST positions factor as
    # k[21+i] = (CT[21+i] - G[i]) mod 26 for some common G?
    # G[i] = (CT[21+i] - k[21+i]) mod 26
    g_from_vig_east1 = [(ct_east1[i] - VIGENERE_KEY_ENE[i]) % MOD for i in range(4)]
    g_from_vig_east2 = [(ct_east2[i] - VIGENERE_KEY_ENE[9+i]) % MOD for i in range(4)]

    print(f"  G implied by Vig key at east1: {g_from_vig_east1} = {''.join(ALPH[v] for v in g_from_vig_east1)}")
    print(f"  G implied by Vig key at east2: {g_from_vig_east2} = {''.join(ALPH[v] for v in g_from_vig_east2)}")

    if g_from_vig_east1 == g_from_vig_east2:
        print(f"  -> SAME code group: consistent with nomenclator model!")
        print(f"  -> Code group for EAST = {''.join(ALPH[v] for v in g_from_vig_east1)}")
    else:
        print(f"  -> DIFFERENT: Vigenere key is NOT consistent with a nomenclator")
        print(f"     (The standard Vigenere key cannot be decomposed as fixed code group + position key)")
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()

    print("1. Key differential [1,25,1,23] between two EAST positions:")
    print("   CONFIRMED independent of code group G.")
    print()

    print("2. Period analysis (EAST-only constraints):")
    for p in sorted(results_by_period.keys()):
        r = results_by_period[p]
        if r.get("eliminated"):
            print(f"   p={p:2d}: ELIMINATED — {r.get('reason', 'conflict')}")
        else:
            ps = r.get("period_survivors", r.get("east_survivors", "?"))
            be = r.get("bean_eq_compatible", "?")
            print(f"   p={p:2d}: {ps:>10} period-consistent, {be:>10} Bean-EQ compatible")
    print()

    print("3. Bean-EQ constraint: G_north[2] - G_berlin[2] = 17 mod 26")
    print("   This is a single linear constraint linking two independent code groups.")
    print("   Eliminates 25/26 of random (G_north, G_berlin) combinations.")
    print()

    print("4. Standard Vigenere key decomposition:")
    if g_from_vig_east1 == g_from_vig_east2:
        print(f"   Consistent with nomenclator: EAST -> {''.join(ALPH[v] for v in g_from_vig_east1)}")
    else:
        print(f"   NOT consistent with fixed code group for EAST under standard Vigenere.")
        print(f"   The key is NOT periodic, or the model differs from Vigenere+nomenclator.")
    print()

    verdict = "UNDERDETERMINED"
    print(f"VERDICT: {verdict}")
    print("The nomenclator + superencipherment model cannot be confirmed or eliminated")
    print("from crib positions alone. The search space remains vast (26^19 after Bean-EQ).")
    print("Only a running key source or very short period could make enumeration feasible.")

    # ── Save results ─────────────────────────────────────────────────────
    output = {
        "experiment_id": "e_team_nomenclator_super",
        "description": "Nomenclator + superencipherment model analysis",
        "key_differential": [1, 25, 1, 23],
        "differential_verified": True,
        "bean_eq_constraint": "G_north[2] - G_berlin[2] = 17 mod 26",
        "period_analysis": results_by_period,
        "segmentation_analysis": seg_results,
        "vig_decomposition": {
            "g_east1": g_from_vig_east1,
            "g_east2": g_from_vig_east2,
            "consistent": g_from_vig_east1 == g_from_vig_east2,
        },
        "verdict": verdict,
    }

    results_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_nomenclator_super.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to: {results_path}")


if __name__ == "__main__":
    main()
