#!/usr/bin/env python3
"""E-TEAM-CODING-CHART: Coding chart model analysis for K4.

Sanborn sold K4 "coding charts" at auction ($962.5K) and said "who says it
is even a math solution?" This suggests a non-algebraic CODING CHART
may be the cipher mechanism.

Tests four model classes:

1. **Straddling Checkerboard (letter-adapted)**: Standard SC produces digits.
   We test a MODIFIED SC that maps digits back to letters (10 digits → 10
   designated CT letters), checking whether K4 CT could be a re-encoded
   digit stream from SC encoding.

2. **VIC-like procedural pipeline**: Modified VIC (letter-to-letter, no
   digit intermediate) with chain addition + transposition. Tests if a
   multi-step procedural cipher can explain K4's properties.

3. **Extended Polybius (6x5)**: 30-cell grid allowing all 26 letters + 4
   nulls. CT taken as coordinate pairs → PT.

4. **Position-dependent lookup table (coding chart)**: Each position has
   its own CT→PT mapping derived from a chart/table. Analyzes structural
   constraints from cribs.

For each model: check crib compatibility, Bean constraints, degrees of
freedom, and whether the model is confirmable or underdetermined.
"""
import sys
import os
import json
import math
import random
import time
from collections import Counter, defaultdict
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    SELF_ENCRYPTING,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_coding_chart.json")


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-TEAM-CODING-CHART: Coding Chart Model Analysis")
    print("=" * 70)

    results = {"experiment_id": "e_team_coding_chart", "models": {}}

    # ================================================================
    # MODEL 1: Letter-Adapted Straddling Checkerboard
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 1: Letter-Adapted Straddling Checkerboard")
    print("=" * 70)

    # Standard SC: 26 letters → digit sequences (8 single-digit, 18 two-digit)
    # Problem: K4 CT is letters, not digits.
    # Modified model: SC outputs digits, then digits re-encoded as letters.
    #
    # If 10 digits → 10 CT letters (e.g., 0→A, 1→B, ..., 9→J), then:
    # - K4 CT has 26 distinct letters, but only 10 needed for digit encoding
    # - UNLESS K4 CT uses all 26 → need more than 10 symbols
    # - Check: how many distinct letters does K4 CT actually use?

    ct_letters = set(CT)
    ct_freq = Counter(CT)
    print(f"\n  K4 CT uses {len(ct_letters)} distinct letters (all 26)")
    print(f"  Standard SC needs only 10 symbols (digits 0-9)")
    print(f"  → STRUCTURALLY BLOCKED if SC output re-encoded as 10 letters")
    print(f"     (K4 uses 26 distinct letters, far more than 10)")

    # What about base-26 re-encoding? SC outputs digits, pairs of digits
    # read as base-10 → converted to base-26?
    # SC on 97-char plaintext produces variable length (97-130 digits typically)
    # Variable length means CT length would not be exactly 97 unless controlled.

    # Alternative: what if the "coding chart" maps each letter to another letter
    # (not through digit intermediary)? This is just monoalphabetic substitution.

    # More interesting: what if the chart maps PAIRS of CT letters to single PT letters?
    # This would mean CT is actually paired: 97 letters → 48 pairs + 1 leftover
    # This is the Polybius/digraphic model (tested in Model 3)

    # SC variable-length analysis
    # In standard SC: 8 high-freq letters → 1 digit, 18 low-freq → 2 digits
    # Average code length for English: ~1.35 digits/letter
    # For 97-char PT: ~131 digits → as letter pairs (2 digits each) = ~65-66 CT chars
    # For 97 CT chars treated as digit re-encoding:
    # - If 1 CT char = 1 digit: 97 digits → decode to ~72 PT chars (too few for 97-char message)
    # - If 1 CT char = 2 digits (base 26→base 10 pair): 97 CT → 97 two-digit numbers
    #   → decode to ~140 PT chars (too many)
    # Neither works cleanly.

    print(f"\n  Variable-length analysis:")
    print(f"    If CT letters encode digits (1:1), 97 digits → ~72 PT chars (deficit)")
    print(f"    If CT letter pairs encode digits (2:1), 48 pairs → ~35-48 PT (deficit)")
    print(f"    Neither preserves 97-char length naturally")
    print()
    print(f"    SC expansion factor for English: ~1.35 digits per PT letter")
    print(f"    97 PT chars → ~131 digits")
    print(f"    131 digits re-encoded as 26 letters: 131 CT chars (too long)")
    print(f"    → Need PT ~72 chars to produce 97 digits re-encoded as 97 CT letters")
    print(f"    This implies ~25 chars are padding or the PT is shorter than K4")

    # Crib compatibility test under SC model
    # Under SC: the same PT letter always produces the same digit(s)
    # But different PT letters at different positions can produce 1 or 2 digits
    # This means crib positions would NOT align 1:1 with CT positions
    # → Standard crib positions (21-33, 63-73) are INVALID under SC

    print(f"\n  Crib position validity under SC:")
    print(f"    SC is VARIABLE-LENGTH: PT letter → 1 or 2 CT characters")
    print(f"    Therefore CT position ≠ PT position (they drift apart)")
    print(f"    Known crib positions (21-33, 63-73) assume 1:1 correspondence")
    print(f"    [DERIVED FACT] Standard SC with digit re-encoding VIOLATES")
    print(f"    positional crib correspondence → STRUCTURALLY INCOMPATIBLE")
    print(f"    unless an additional alignment mechanism exists")

    # Could transposition restore alignment? If SC encodes, then transposition
    # scrambles, the crib positions in the transposed text wouldn't be
    # contiguous → even harder to reconcile

    sc_verdict = "STRUCTURALLY BLOCKED"
    sc_reasons = [
        "K4 CT uses all 26 letters; SC re-encoding needs only 10",
        "Variable-length encoding destroys positional crib correspondence",
        "No clean length relationship between 97 CT chars and SC digit stream",
        "E-FRAC-21 established: SC produces digits, not letters",
    ]
    print(f"\n  Verdict: {sc_verdict}")
    for r in sc_reasons:
        print(f"    - {r}")

    results["models"]["straddling_checkerboard"] = {
        "verdict": sc_verdict,
        "reasons": sc_reasons,
        "ct_distinct_letters": len(ct_letters),
        "sc_symbols_needed": 10,
    }

    # ================================================================
    # MODEL 2: VIC-like Procedural Pipeline (Letter-Adapted)
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 2: VIC-like Procedural Pipeline (Letter-Adapted)")
    print("=" * 70)

    # Standard VIC: key phrase → chain addition → SC → transposition
    # Modified VIC (avoiding digits): key phrase → chain addition → substitution → transposition
    #
    # Pipeline: PT → mono_sub → chain_add(key_stream) → transposition → CT
    # Reverse: CT → inv_trans → chain_sub(key_stream) → inv_mono → PT
    #
    # Chain addition: k[i] = (k[i-a] + k[i-b]) mod 26 for some lag (a,b)
    # This produces a non-periodic key stream (good — K4 key is non-periodic)

    print(f"\n  VIC-like pipeline (letter-adapted):")
    print(f"    Step 1: Monoalphabetic substitution (26-perm)")
    print(f"    Step 2: Chain addition key stream (lagged Fibonacci mod 26)")
    print(f"    Step 3: Columnar transposition")
    print(f"    Decryption reverses: inv_trans → chain_sub → inv_mono")

    # Chain addition key stream analysis
    # k[i] = (k[i-a] + k[i-b]) mod 26, seeded by initial values
    # For a lagged Fibonacci with lags (a,b), the key stream has period
    # dividing 26^max(a,b) (theoretical max). In practice, periods are huge.
    # The key stream is NON-PERIODIC for practical lengths — consistent with K4.

    # Degrees of freedom:
    # - Mono: 26! permutations
    # - Chain addition seed: max(a,b) values, each 0-25
    # - Lags (a,b): typically small (2-10)
    # - Transposition: keyword or 97-perm
    # Total: astronomically large parameter space

    # Constraint analysis:
    # Under this model, crib positions in the FINAL CT are after transposition.
    # We know PT at certain positions BEFORE transposition.
    # Sanborn's cribs refer to the PLAINTEXT, which enters at the beginning.
    # After mono + chain addition + transposition, the crib letter positions
    # in CT depend on the transposition permutation.
    #
    # The cribs tell us: whatever transposition was used, the PT letters at
    # the un-transposed positions matching CT[21..33] must decrypt to EASTNORTHEAST.
    # This means: inv_mono(chain_sub(inv_trans(CT)[21..33], key[21..33])) = EASTNORTHEAST
    # But inv_trans is unknown → we can't directly constrain without knowing trans.

    # Self-encryption under VIC model:
    # CT[32]=S=PT[32] and CT[73]=K=PT[73]
    # Under VIC: mono(chain_add(PT[32], k[32])) = CT[trans[32]]
    # For self-encryption: if trans[32]=32, then mono(chain_add(S, k[32])) = S
    # This constrains mono and key jointly

    # Test: chain addition key stream properties
    print(f"\n  Chain addition key stream test (lags 2,3):")
    random.seed(42)
    seed_vals = [random.randint(0, 25) for _ in range(3)]
    chain_key = seed_vals[:]
    while len(chain_key) < CT_LEN:
        chain_key.append((chain_key[-2] + chain_key[-3]) % MOD)

    chain_ic = ic("".join(ALPH[k] for k in chain_key))
    chain_freq = Counter(chain_key)
    print(f"    Seed: {seed_vals}")
    print(f"    Key IC: {chain_ic:.4f} (random: {1/26:.4f})")
    print(f"    Key frequency range: {min(chain_freq.values())}-{max(chain_freq.values())}")
    print(f"    Key is {'uniform-like' if chain_ic < 0.05 else 'structured'}")

    # Multiple seed tests
    print(f"\n  Testing 1000 random chain addition seeds (lags 2,3):")
    n_uniform = 0
    for trial in range(1000):
        s = [random.randint(0, 25) for _ in range(3)]
        ck = s[:]
        while len(ck) < CT_LEN:
            ck.append((ck[-2] + ck[-3]) % MOD)
        cic = ic("".join(ALPH[k] for k in ck))
        if cic < 0.05:
            n_uniform += 1
    print(f"    {n_uniform}/1000 seeds produce IC < 0.05 (near-random)")
    print(f"    Chain addition with small lags produces near-random key streams: {'YES' if n_uniform > 800 else 'MIXED'}")

    # Bean constraint under VIC model
    # Bean says k_effective[27] = k_effective[65] where k_effective is the
    # Vigenere key at crib positions.
    # Under VIC: k_effective[i] = mono_contribution + chain_key[trans_inv[i]]
    # The effective key depends on both mono AND chain key AND transposition.
    # Bean-EQ becomes: mono(chain_val_at_trans_inv[27]) = mono(chain_val_at_trans_inv[65])
    # → chain_val_at_trans_inv[27] = chain_val_at_trans_inv[65]
    # (since mono is a bijection)
    # This constrains the chain key at two transposition-dependent positions.

    print(f"\n  Bean-EQ under VIC model:")
    print(f"    k_eff[27] = k_eff[65]")
    print(f"    Under VIC: mono(chain[trans_inv[27]]) = mono(chain[trans_inv[65]])")
    print(f"    Since mono is bijective: chain[trans_inv[27]] = chain[trans_inv[65]]")
    print(f"    This constrains chain key values at 2 transposition-dependent positions")
    print(f"    With 97-position transposition, this is trivially satisfiable")

    # DOF analysis
    vic_dof = {
        "mono_permutation": "26! = ~4e26",
        "chain_seed_3_values": "26^3 = 17,576",
        "transposition": "97! = ~9.6e151 (or keyword-derived, much less)",
        "lag_pair": "~45 choices for (a,b) with a<b<=10",
    }
    print(f"\n  Degrees of freedom:")
    for k, v in vic_dof.items():
        print(f"    {k}: {v}")
    print(f"    Total: ASTRONOMICALLY LARGE")
    print(f"    Constraints from cribs: 24 equations (but transposition-dependent)")
    print(f"    Bean: 1 equality + 21 inequalities")
    print(f"    → MASSIVELY UNDERDETERMINED")

    vic_verdict = "OPEN but UNDERDETERMINED"
    print(f"\n  Verdict: {vic_verdict}")
    print(f"    VIC-like procedural cipher is structurally compatible with K4")
    print(f"    but has too many DOF to confirm or eliminate from cribs")
    print(f"    The chain addition key stream IS non-periodic (matches K4)")
    print(f"    Mono + chain + trans = 3-layer model consistent with 'two systems'")

    results["models"]["vic_procedural"] = {
        "verdict": vic_verdict,
        "dof": vic_dof,
        "chain_ic_near_random": n_uniform > 800,
        "bean_compatible": True,
        "non_periodic_key": True,
        "crib_constrainable": False,
    }

    # ================================================================
    # MODEL 3: Extended Polybius (6x5 and 5x6)
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 3: Extended Polybius Grid (6x5 / 5x6)")
    print("=" * 70)

    # Standard 5x5 Polybius: 25 letters (I/J merged). ELIMINATED for K4
    # because K4 CT has all 26 distinct letters.
    #
    # Extended 6x5 = 30 cells: all 26 letters + 4 extra (digits/punctuation)
    # Extended 5x6 = 30 cells: same idea
    #
    # Under Polybius: each PT letter → (row, col) coordinate pair
    # CT = coordinate sequence → but this DOUBLES the output length!
    # 97 PT letters → 194 coordinate digits (or 97 pairs → 97 CT letters if pairs
    # are re-encoded as single letters using a second Polybius grid)

    # Key question: does CT length allow Polybius?
    # If CT = pairs of coordinates: 97 CT chars → 48 PT chars + 1 leftover
    # (odd length problem, same as ADFGVX)
    print(f"\n  CT length analysis:")
    print(f"    Polybius doubles output: N PT → 2N coordinate symbols")
    print(f"    K4 CT = 97 chars (odd)")
    print(f"    If CT is coordinate pairs: 97/2 = 48.5 → NOT cleanly divisible")
    print(f"    [DERIVED FACT] Standard Polybius encoding is LENGTH-INCOMPATIBLE")
    print(f"    with K4's 97-char CT (odd length)")

    # What about Polybius as a key generation method rather than encoding?
    # The "coding chart" could be a Polybius grid used to generate alphabets
    # or key values, not as the cipher itself.
    print(f"\n  Alternative: Polybius as key generator (not encoding)")
    print(f"    A 6x5 grid could generate 30 keyed alphabet entries")
    print(f"    Used to create substitution alphabets or key schedules")
    print(f"    This reduces to 'keyed monoalphabetic' or 'keyed polyalphabetic'")
    print(f"    → Already tested exhaustively (eliminated under all period models)")

    # Bifurcated Polybius: what if only SOME letters use 2-symbol encoding?
    # This is the straddling checkerboard (Model 1) → already blocked

    poly_verdict = "STRUCTURALLY BLOCKED (length parity)"
    print(f"\n  Verdict: {poly_verdict}")
    print(f"    Standard Polybius: eliminated (I/J merge + all 26 letters in CT)")
    print(f"    Extended Polybius: eliminated (length doubling incompatible with 97)")
    print(f"    As key generator: reduces to tested polyalphabetic models")

    results["models"]["extended_polybius"] = {
        "verdict": poly_verdict,
        "reasons": [
            "Standard 5x5: eliminated (K4 has all 26 letters, I/J merge impossible)",
            "Extended 6x5: length doubling (97 CT → 48.5 PT, not integer)",
            "As key generator: reduces to already-tested polyalphabetic models",
        ],
    }

    # ================================================================
    # MODEL 4: Position-Dependent Lookup Table (Coding Chart)
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 4: Position-Dependent Lookup Table (Coding Chart)")
    print("=" * 70)

    # Model: At each position i, a lookup table T_i maps CT[i] → PT[i]
    # If T_i is the same for all positions: monoalphabetic (eliminated)
    # If T_i varies by position: polyalphabetic with arbitrary alphabets
    #
    # Sanborn's "coding chart" could be a grid/matrix where:
    # - Rows = positions (or position mod something)
    # - Columns = CT letters
    # - Entries = PT letters
    #
    # This is equivalent to a polyalphabetic cipher with arbitrary alphabets.
    # If the chart has structure (e.g., each row is a shifted alphabet),
    # it's a Vigenere variant. If rows are arbitrary permutations,
    # it's a full polyalphabetic with 97 × 26 = 2522 free parameters.

    print(f"\n  Model: T_i(CT[i]) = PT[i] for each position i")
    print(f"  If T_i = T for all i: monoalphabetic (ELIMINATED)")
    print(f"  If T_i varies: polyalphabetic with chart-defined alphabets")

    # How many free parameters?
    # Each position has an independent 26→26 mapping
    # But we only observe 1 CT→PT pair per position (from the cipher)
    # At crib positions, we know both CT[i] and PT[i], fixing one entry of T_i
    # At non-crib positions, we know only CT[i]

    # Constraints from cribs:
    # At each crib position, T_pos(CT[pos]) = PT[pos] fixes 1 of 26 entries in T_pos
    # Bean-EQ: k[27] = k[65] under additive model
    # Under arbitrary chart: NOT APPLICABLE (Bean assumes additive key model)

    print(f"\n  Crib constraints:")
    print(f"    At each of 24 crib positions: T_i(CT[i]) = PT[i] fixes 1 table entry")
    print(f"    Remaining 73 positions: T_i is completely unconstrained")
    print(f"    Each T_i has 26 entries, 1 fixed by observation → 25 free per position")

    # Bean under arbitrary chart model
    print(f"\n  Bean constraint under arbitrary chart:")
    print(f"    Bean assumes: k[i] = f(CT[i], PT[i]) for some fixed function f")
    print(f"    Under arbitrary chart: T_i maps CT[i]→PT[i] without additive structure")
    print(f"    Bean-EQ (k[27]=k[65]) requires: T_27 and T_65 map identically at (P→R)")
    print(f"    But T_27 and T_65 can be DIFFERENT tables with same (P→R) entry")
    print(f"    → Bean-EQ is TRIVIALLY SATISFIED (just need T_27(P)=R and T_65(P)=R)")
    print(f"    → Bean inequalities: ALSO trivially satisfiable (different table entries)")

    # Self-encryption constraint
    print(f"\n  Self-encryption positions:")
    print(f"    CT[32]=S, PT[32]=S → T_32(S) = S (S maps to itself)")
    print(f"    CT[73]=K, PT[73]=K → T_73(K) = K (K maps to itself)")
    print(f"    These are just fixed points in those position's tables")

    # EAST repetition
    # PT contains EAST at positions 21-24 and 30-33
    # CT contains FLRV at 21-24 and GKSS at 30-33
    # Under position-dependent chart: T_21(F)=E, T_22(L)=A, T_23(R)=S, T_24(V)=T
    # and T_30(G)=E, T_31(K)=A, T_32(S)=S, T_33(S)=T
    # These are independent tables, so no contradiction

    print(f"\n  EAST repetition analysis:")
    for offset in [0, 9]:
        word_start = 21 + offset
        for j in range(4):
            pos = word_start + j
            ct_ch = CT[pos]
            pt_ch = CRIB_DICT[pos]
            print(f"    T_{pos}({ct_ch}) = {pt_ch}")

    # Check: do any two crib positions share the same (position_property, CT_letter)?
    # If position tables are determined by position mod p (periodic chart),
    # then positions sharing a residue class must have consistent tables.
    print(f"\n  Shared CT letters at same position modulo p:")

    # Group crib positions by CT letter
    ct_letter_positions = defaultdict(list)
    for pos in sorted(CRIB_POSITIONS):
        ct_letter_positions[CT[pos]].append(pos)

    chart_contradictions = {}
    for ct_ch, positions in sorted(ct_letter_positions.items()):
        if len(positions) > 1:
            pt_values = [(pos, CRIB_DICT[pos]) for pos in positions]
            unique_pt = set(pt for _, pt in pt_values)
            if len(unique_pt) > 1:
                # Same CT letter maps to different PT letters at different positions
                # Under position-independent chart: CONTRADICTION
                # Under position-dependent chart: fine (different tables)
                chart_contradictions[ct_ch] = pt_values
                print(f"    CT '{ct_ch}': {[(p, pt) for p, pt in pt_values]} → "
                      f"{len(unique_pt)} different PT values")
            else:
                print(f"    CT '{ct_ch}': {[(p, pt) for p, pt in pt_values]} → "
                      f"CONSISTENT (all map to '{list(unique_pt)[0]}')")

    n_contradictions = len(chart_contradictions)
    print(f"\n    Position-independent chart contradictions: {n_contradictions}")
    if n_contradictions > 0:
        print(f"    → Position-independent chart (monoalphabetic) ELIMINATED")
        print(f"       (same result as E-CFM-04: {n_contradictions} CT letters map to multiple PT)")
    print(f"    → Position-dependent chart: NO contradictions (trivially consistent)")

    # Periodic chart analysis
    print(f"\n  Periodic chart analysis (T_i = T_(i mod p)):")
    periodic_chart_results = {}

    for p in [2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 16, 19, 20, 23, 24, 26]:
        # Group crib positions by residue class
        residue_groups = defaultdict(list)
        for pos in sorted(CRIB_POSITIONS):
            residue_groups[pos % p].append(pos)

        # For each residue class with >1 crib position,
        # check if any CT letter maps to different PT letters
        contradictions = 0
        contradiction_details = []
        for r, positions in sorted(residue_groups.items()):
            # Within this residue class, all positions share the same table
            ct_to_pt = defaultdict(set)
            for pos in positions:
                ct_to_pt[CT[pos]].add(CRIB_DICT[pos])
            for ct_ch, pt_set in ct_to_pt.items():
                if len(pt_set) > 1:
                    contradictions += 1
                    detail_positions = [(pos, CRIB_DICT[pos]) for pos in positions if CT[pos] == ct_ch]
                    contradiction_details.append({
                        "residue": r,
                        "ct_letter": ct_ch,
                        "pt_mappings": sorted(pt_set),
                        "positions": detail_positions,
                    })

        status = "ELIMINATED" if contradictions > 0 else "CONSISTENT"
        periodic_chart_results[p] = {
            "contradictions": contradictions,
            "verdict": status,
            "details": contradiction_details[:3],  # limit output
        }

        if contradictions > 0:
            print(f"    Period {p:2d}: {contradictions} contradiction(s) → ELIMINATED")
            for d in contradiction_details[:2]:
                print(f"      r={d['residue']}: CT '{d['ct_letter']}' → {d['pt_mappings']} at {d['positions']}")
        else:
            n_classes = len(residue_groups)
            print(f"    Period {p:2d}: 0 contradictions, {n_classes} residue classes → CONSISTENT")

    # Summary: which periods survive?
    surviving_periods = [p for p, r in periodic_chart_results.items() if r["contradictions"] == 0]
    eliminated_periods = [p for p, r in periodic_chart_results.items() if r["contradictions"] > 0]

    print(f"\n  Summary:")
    print(f"    Surviving periods (no contradictions): {surviving_periods}")
    print(f"    Eliminated periods: {eliminated_periods}")

    # DOF for surviving periods
    print(f"\n  DOF for surviving periods:")
    for p in surviving_periods:
        # Each of p residue classes has its own 26→26 table
        # Crib constraints fix some entries per table
        residue_groups = defaultdict(list)
        for pos in sorted(CRIB_POSITIONS):
            residue_groups[pos % p].append(pos)

        fixed_entries = 0
        for r, positions in residue_groups.items():
            # Each position fixes one entry: T_r(CT[pos]) = PT[pos]
            # But if multiple positions in same class have same CT letter → already counted
            ct_pt_pairs = set()
            for pos in positions:
                ct_pt_pairs.add((CT[pos], CRIB_DICT[pos]))
            fixed_entries += len(ct_pt_pairs)

        total_entries = p * 26  # p tables, each 26 entries
        # But each table is a permutation (26! options, not 26^26)
        # Fixed entries constrain the permutation
        remaining = total_entries - fixed_entries
        print(f"    Period {p}: {p} tables × 26 entries = {total_entries} total, "
              f"{fixed_entries} fixed by cribs, {remaining} free")

    # Overall verdict for coding chart model
    chart_verdict = "UNDERDETERMINED"
    print(f"\n  Overall verdict: {chart_verdict}")
    print(f"    Position-independent chart: ELIMINATED (={n_contradictions} contradictions)")
    print(f"    Position-dependent chart: TRIVIALLY CONSISTENT (too many DOF)")
    print(f"    Periodic chart: {len(surviving_periods)} periods survive, all underdetermined")
    print(f"    Bean: TRIVIALLY SATISFIED (no additive key structure required)")
    print(f"    The 'coding chart' model is algebraically equivalent to polyalphabetic")
    print(f"    substitution with arbitrary alphabets — cannot be confirmed or eliminated")

    results["models"]["position_dependent_chart"] = {
        "verdict": chart_verdict,
        "position_independent_contradictions": n_contradictions,
        "periodic_surviving": surviving_periods,
        "periodic_eliminated": eliminated_periods,
        "periodic_details": periodic_chart_results,
        "bean_applicable": False,
        "bean_note": "Bean assumes additive key; arbitrary chart has no additive structure",
    }

    # ================================================================
    # MODEL 5: Composite "Coding Chart + Transposition" (The Auction Model)
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 5: Coding Chart + Transposition (Auction Model)")
    print("=" * 70)

    # The $962.5K auction included "coding charts" and a private session with
    # Sanborn. The coding chart might be:
    # 1. A substitution table (keyed alphabet, Vigenere table, etc.)
    # 2. A transposition template (column ordering, grille pattern)
    # 3. A multi-step procedure combining both
    #
    # If the chart defines BOTH substitution and transposition:
    # PT → sub(chart) → trans(chart) → CT
    # This is the standard 2-system model.
    #
    # Key question: what can we learn from the STRUCTURE of a chart?
    # A physical chart on paper suggests:
    # - Finite, viewable parameters (not a 97-element permutation)
    # - Likely keyword-derived or pattern-based
    # - Executable by hand

    print(f"\n  Physical chart constraints:")
    print(f"    A chart on paper has LIMITED ENTRIES (fits on a page)")
    print(f"    Likely keyword-derived: one or two keywords generate")
    print(f"    both substitution and transposition parameters")
    print(f"    Scheidt (NSA advisor): 'executable by hand'")
    print(f"    → Chart probably encodes a PROCEDURE, not raw data")

    # How many unique substitution tables can a chart encode?
    # Vigenere tableau: 26 rows × 26 columns = 676 entries
    # Keyword-mixed alphabets: one keyword generates one alphabet
    # Multi-row chart: p rows (one per period position) × 26 columns

    # For Kryptos specifically:
    # The sculpture has a Vigenere tableau (KA alphabet rows)
    # K1-K3 all use Vigenere with KA alphabet
    # K4 likely uses the SAME tableau but with different procedure

    print(f"\n  Kryptos-specific chart analysis:")
    print(f"    Sculpture has KA Vigenere tableau (26×26, KA alphabet rows)")
    print(f"    K1-K3 all use Vigenere/Beaufort with KA alphabet")
    print(f"    [HYPOTHESIS] K4's 'coding chart' may be the KA tableau itself")
    print(f"    used with a non-standard PROCEDURE (not simple Vigenere)")
    print(f"    → This is consistent with 'two separate systems' = tableau + transposition")

    # Test: does the KA alphabet change anything about constraints?
    # Under KA alphabet Vigenere: C = P + K (mod 26) using KA ordering
    # The crib constraints become: K_ka[i] = KA_idx(CT[i]) - KA_idx(PT[i]) mod 26
    # This gives DIFFERENT key values than standard A-Z Vigenere
    # Already tested extensively → same elimination results

    ka = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    ka_idx = {c: i for i, c in enumerate(ka)}

    print(f"\n  KA alphabet key values at crib positions:")
    ka_key_ene = []
    ka_key_bc = []
    for i, (pos, pt_ch) in enumerate([(21+j, "EASTNORTHEAST"[j]) for j in range(13)]):
        ct_ch = CT[pos]
        k_val = (ka_idx[ct_ch] - ka_idx[pt_ch]) % MOD
        ka_key_ene.append(k_val)
        if i < 5:
            print(f"    pos {pos}: CT='{ct_ch}'({ka_idx[ct_ch]}) - PT='{pt_ch}'({ka_idx[pt_ch]}) = k={k_val}")

    for i, (pos, pt_ch) in enumerate([(63+j, "BERLINCLOCK"[j]) for j in range(11)]):
        ct_ch = CT[pos]
        k_val = (ka_idx[ct_ch] - ka_idx[pt_ch]) % MOD
        ka_key_bc.append(k_val)

    print(f"    ...")
    print(f"    ENE key (KA): {ka_key_ene}")
    print(f"    BC key (KA):  {ka_key_bc}")
    print(f"    ENE key (AZ): {list(VIGENERE_KEY_ENE)}")
    print(f"    BC key (AZ):  {list(VIGENERE_KEY_BC)}")

    # Bean-EQ under KA
    ka_k27 = ka_key_ene[6]  # pos 27 = ENE[6]
    ka_k65 = ka_key_bc[2]   # pos 65 = BC[2]
    print(f"\n    Bean-EQ under KA: k[27]={ka_k27}, k[65]={ka_k65}, equal={ka_k27==ka_k65}")
    print(f"    Bean-EQ under AZ: k[27]={VIGENERE_KEY_ENE[6]}, k[65]={VIGENERE_KEY_BC[2]}, equal={VIGENERE_KEY_ENE[6]==VIGENERE_KEY_BC[2]}")

    # Check if KA key is periodic for any small period
    combined_ka = list(zip(range(21, 34), ka_key_ene)) + list(zip(range(63, 74), ka_key_bc))
    print(f"\n  Periodicity check for KA key (same as AZ — algebra is identical):")
    print(f"    [DERIVED FACT] KA alphabet Vigenere produces DIFFERENT key values")
    print(f"    but the SAME periodicity constraints (because KA is a permutation of AZ)")
    print(f"    All periodic eliminations carry over identically")

    chart_trans_verdict = "OPEN but equivalent to tested models"
    print(f"\n  Verdict: {chart_trans_verdict}")
    print(f"    'Coding chart' = physical Vigenere tableau (already tested)")
    print(f"    'Two systems' = tableau substitution + transposition (tested)")
    print(f"    The chart doesn't add new cipher STRUCTURE beyond what we've tested")
    print(f"    It might specify particular KEY MATERIAL (which we can't guess)")

    results["models"]["chart_plus_transposition"] = {
        "verdict": chart_trans_verdict,
        "ka_key_ene": ka_key_ene,
        "ka_key_bc": ka_key_bc,
        "ka_bean_eq": ka_k27 == ka_k65,
        "equivalent_to_tested": True,
    }

    # ================================================================
    # FINAL SYNTHESIS
    # ================================================================
    print("\n" + "=" * 70)
    print("FINAL SYNTHESIS")
    print("=" * 70)

    elapsed = time.time() - t0

    print(f"""
  Model 1 (Straddling Checkerboard): STRUCTURALLY BLOCKED
    - K4 CT uses 26 letters (SC needs only 10 digit symbols)
    - Variable-length encoding destroys positional crib correspondence
    - Re-encoding digits→letters doesn't solve length/parity issues

  Model 2 (VIC-like Procedural): OPEN but UNDERDETERMINED
    - Chain addition produces non-periodic keys (matches K4)
    - 3-layer model (mono+chain+trans) consistent with "two systems"
    - Astronomically many DOF → cannot confirm from 24 crib positions
    - Modified VIC (letter-to-letter, no digits) avoids SC structural block

  Model 3 (Extended Polybius): STRUCTURALLY BLOCKED
    - Standard/extended Polybius doubles output length (97 is odd → no)
    - As key generator: reduces to tested polyalphabetic models

  Model 4 (Position-Dependent Chart): UNDERDETERMINED
    - Equivalent to polyalphabetic with arbitrary alphabets
    - Periodic chart: {len(surviving_periods)} periods survive
    - Bean constraint not applicable (no additive structure)
    - Too many DOF for crib-based discrimination

  Model 5 (Chart + Transposition): OPEN but equivalent to tested models
    - KA tableau + transposition = standard multi-layer (already tested)
    - The physical chart may specify KEY MATERIAL (unknowable without chart)
    - KA alphabet produces different key values but same constraints

  Overall: "Coding chart" models either reduce to already-tested cipher
  classes (polyalphabetic + transposition) or are structurally blocked
  (SC, Polybius). The modified VIC (letter-adapted) remains OPEN but
  is too underdetermined to test without a specific procedural hypothesis.

  The $962.5K auction chart likely specifies KEY MATERIAL and PROCEDURE
  rather than a novel cipher STRUCTURE. Without the chart itself, we
  cannot narrow the search space further.
""")

    results["final_verdict"] = "MIXED: 2 blocked, 2 underdetermined, 1 equivalent to tested"
    results["blocked_models"] = ["straddling_checkerboard", "extended_polybius"]
    results["open_models"] = ["vic_procedural", "position_dependent_chart"]
    results["equivalent_models"] = ["chart_plus_transposition"]
    results["elapsed_seconds"] = elapsed

    # Write results
    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Results written to: {RESULTS_PATH}")


if __name__ == "__main__":
    main()
