#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: polyalphabetic
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-SOLVE-07: Beaufort-Focused K4 Attack.

Beaufort keystream analysis shows 1,200x more structure than Vigenère:
  - Value concentration on {6, 10, 14} (arithmetic progression d=4)
  - Triple consecutive equal at positions 30-32 (all = 10 = K)
  - Gap-39 cross-crib matches: k[22]=k[64]=11, k[27]=k[65]=10, etc.
  - Bean equality naturally satisfied by value 10

This experiment exhaustively tests five Beaufort-specific hypotheses:
  1. Gap-39 quasi-periodicity (period 13 and 39)
  2. Arithmetic progression keys: k[i] = (a + b*i) mod 26
  3. KA-alphabet Beaufort
  4. Value-10 dominant key with controlled deviations
  5. Two-keyword Beaufort (KRYPTOS + thematic word)

Usage:
    PYTHONPATH=src python3 -u scripts/e_solve_07_beaufort_focus.py
"""

import itertools
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean, verify_bean_simple, BeanResult

# ── Precomputed values ──────────────────────────────────────────────────

CT_VALS = [ALPH_IDX[c] for c in CT]
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# Known Beaufort key values at crib positions (0-indexed)
# ENE: positions 21-33, BC: positions 63-73
KNOWN_BEAU_KEY = {}
for i, v in enumerate(BEAUFORT_KEY_ENE):
    KNOWN_BEAU_KEY[21 + i] = v
for i, v in enumerate(BEAUFORT_KEY_BC):
    KNOWN_BEAU_KEY[63 + i] = v

# Gap-39 cross-crib matches (verified from known keystream)
GAP39_MATCHES = {
    (22, 64): 11,  # k[22] = k[64] = 11 (L in std alphabet)
    (27, 65): 10,  # k[27] = k[65] = 10 (K) -- Bean-EQ!
    (30, 69): 10,  # k[30] = k[69] = 10
    (31, 70): 10,  # k[31] = k[70] = 10 -- but wait, k[70]=17 in BC
}

# ── Global tracking ────────────────────────────────────────────────────

results_above_noise = []
total_tested = 0
phase_stats = {}

WORDLIST_PATH = Path(__file__).resolve().parents[1] / "wordlists" / "english.txt"


def beaufort_decrypt_standard(key_vals, ct_vals=CT_VALS):
    """Beaufort decrypt: PT[i] = (key[i] - CT[i]) mod 26, standard alphabet."""
    pt = []
    for i in range(len(ct_vals)):
        k = key_vals[i % len(key_vals)] if isinstance(key_vals, (list, tuple)) else key_vals[i]
        pt_val = (k - ct_vals[i]) % MOD
        pt.append(ALPH[pt_val])
    return "".join(pt)


def beaufort_decrypt_ka(key_vals, ct_vals=CT_VALS):
    """Beaufort decrypt using KA alphabet: PT[i] = KA[(ka_idx(key) - ka_idx(CT)) mod 26]."""
    ct_ka = [KA_IDX[c] for c in CT]
    pt = []
    for i in range(len(ct_ka)):
        k = key_vals[i % len(key_vals)] if isinstance(key_vals, (list, tuple)) else key_vals[i]
        pt_val = (k - ct_ka[i]) % MOD
        pt.append(KA[pt_val])
    return "".join(pt)


def beaufort_decrypt_full_key(full_key, ct_vals=CT_VALS, alphabet=ALPH, alph_idx=ALPH_IDX):
    """Beaufort decrypt with a full-length key (list of ints, one per CT position)."""
    pt = []
    for i in range(len(ct_vals)):
        pt_val = (full_key[i] - ct_vals[i]) % MOD
        pt.append(alphabet[pt_val])
    return "".join(pt)


def evaluate(plaintext, label, phase_name, full_key=None):
    """Evaluate a candidate and track results."""
    global total_tested
    total_tested += 1

    if phase_name not in phase_stats:
        phase_stats[phase_name] = {"tested": 0, "above_noise": 0, "best_score": 0, "best_label": ""}
    phase_stats[phase_name]["tested"] += 1

    # Quick crib check first (avoid full scoring overhead)
    crib_hits = sum(1 for pos, ch in CRIB_DICT.items() if pos < len(plaintext) and plaintext[pos] == ch)

    if crib_hits > NOISE_FLOOR:
        # Full scoring
        bean_result = None
        if full_key is not None and len(full_key) >= CT_LEN:
            bean_result = verify_bean(list(full_key))

        sb = score_candidate(plaintext, bean_result=bean_result)

        if sb.crib_score > phase_stats[phase_name]["best_score"]:
            phase_stats[phase_name]["best_score"] = sb.crib_score
            phase_stats[phase_name]["best_label"] = label

        phase_stats[phase_name]["above_noise"] += 1

        result = {
            "label": label,
            "phase": phase_name,
            "score": sb.crib_score,
            "ene": sb.ene_score,
            "bc": sb.bc_score,
            "ic": sb.ic_value,
            "bean": sb.bean_passed,
            "plaintext": plaintext[:40] + "...",
        }
        results_above_noise.append(result)
        print(f"  [ABOVE NOISE] {label}: {sb.summary}")
        print(f"    PT: {plaintext}")
        if sb.crib_score >= STORE_THRESHOLD:
            print(f"    *** INTERESTING OR BETTER: score={sb.crib_score} ***")
        return sb

    return None


# ═══════════════════════════════════════════════════════════════════════
# PHASE 1: Gap-39 Quasi-Periodicity (period 13 and period 39)
# ═══════════════════════════════════════════════════════════════════════

def phase1_gap39():
    """Test period-13 and period-39 Beaufort keys.

    Gap-39 = 3*13. We have key values at specific positions.
    For period p, key[i] = key[i mod p].

    Known constraints at crib positions define key values at specific
    residue classes. Test all possible values for unconstrained residues.
    """
    print("\n" + "=" * 72)
    print("PHASE 1: Gap-39 Quasi-Periodicity")
    print("=" * 72)

    # ── Phase 1a: Period 13 ──
    print("\n--- Phase 1a: Period-13 Beaufort ---")

    # For period 13, key[pos] = key[pos % 13]
    # Map known key values to residue classes
    residue_constraints_13 = defaultdict(set)
    for pos, kval in KNOWN_BEAU_KEY.items():
        r = pos % 13
        residue_constraints_13[r].add(kval)

    # Check for contradictions
    contradictions_13 = {}
    fixed_13 = {}
    free_13 = []
    for r in range(13):
        vals = residue_constraints_13.get(r, set())
        if len(vals) > 1:
            contradictions_13[r] = vals
        elif len(vals) == 1:
            fixed_13[r] = list(vals)[0]
        else:
            free_13.append(r)

    print(f"  Period 13: {len(fixed_13)} fixed residues, {len(free_13)} free, {len(contradictions_13)} contradictions")
    if contradictions_13:
        print(f"  Contradictions at residues: {dict(contradictions_13)}")
        print("  Period 13 is IMPOSSIBLE under strict Beaufort periodicity.")
    else:
        # Enumerate all free residue assignments
        n_free = len(free_13)
        total_p13 = 26 ** n_free
        print(f"  Free residues: {free_13} -> {total_p13} combinations")

        if total_p13 <= 10_000_000:
            tested_p13 = 0
            for combo in itertools.product(range(26), repeat=n_free):
                key_13 = [0] * 13
                for r, v in fixed_13.items():
                    key_13[r] = v
                for r, v in zip(free_13, combo):
                    key_13[r] = v

                # Build full 97-char key
                full_key = [key_13[i % 13] for i in range(CT_LEN)]
                pt = beaufort_decrypt_standard(full_key)
                evaluate(pt, f"P13-{''.join(ALPH[v] for v in key_13)}", "P1a-Period13", full_key)
                tested_p13 += 1

                if tested_p13 % 1_000_000 == 0:
                    print(f"    ... {tested_p13}/{total_p13} tested")
            print(f"  Tested {tested_p13} period-13 keys.")
        else:
            print(f"  Too many combinations ({total_p13}), skipping exhaustive search.")

    # ── Phase 1b: Period 39 ──
    print("\n--- Phase 1b: Period-39 Beaufort ---")

    residue_constraints_39 = defaultdict(set)
    for pos, kval in KNOWN_BEAU_KEY.items():
        r = pos % 39
        residue_constraints_39[r].add(kval)

    contradictions_39 = {}
    fixed_39 = {}
    free_39 = []
    for r in range(39):
        vals = residue_constraints_39.get(r, set())
        if len(vals) > 1:
            contradictions_39[r] = vals
        elif len(vals) == 1:
            fixed_39[r] = list(vals)[0]
        else:
            free_39.append(r)

    print(f"  Period 39: {len(fixed_39)} fixed residues, {len(free_39)} free, {len(contradictions_39)} contradictions")
    if contradictions_39:
        print(f"  Contradictions at residues: {dict(contradictions_39)}")
        print("  Period 39 is IMPOSSIBLE under strict Beaufort periodicity.")
    else:
        n_free_39 = len(free_39)
        total_p39 = 26 ** n_free_39
        print(f"  Free residues ({n_free_39}): {free_39}")
        print(f"  Search space: 26^{n_free_39} = {total_p39} -- too large for exhaustive.")
        print("  Testing value-10-dominant fill for free residues...")

        # Try filling free residues with the dominant values {6, 10, 14}
        # and small perturbations
        dominant_vals = [6, 10, 14]
        tested_p39 = 0
        for combo in itertools.product(dominant_vals, repeat=n_free_39):
            key_39 = [0] * 39
            for r, v in fixed_39.items():
                key_39[r] = v
            for r, v in zip(free_39, combo):
                key_39[r] = v

            full_key = [key_39[i % 39] for i in range(CT_LEN)]
            pt = beaufort_decrypt_standard(full_key)
            evaluate(pt, f"P39-dom-{tested_p39}", "P1b-Period39", full_key)
            tested_p39 += 1

        print(f"  Tested {tested_p39} dominant-value period-39 keys.")

        # Try filling with all values 0-25 but only 1 free position at a time
        print("  Testing single-free-varied (others=10)...")
        tested_single = 0
        for vary_idx in range(n_free_39):
            for val in range(26):
                key_39 = [0] * 39
                for r, v in fixed_39.items():
                    key_39[r] = v
                for j, r in enumerate(free_39):
                    if j == vary_idx:
                        key_39[r] = val
                    else:
                        key_39[r] = 10  # default to dominant value
                full_key = [key_39[i % 39] for i in range(CT_LEN)]
                pt = beaufort_decrypt_standard(full_key)
                evaluate(pt, f"P39-sv-{vary_idx}-{val}", "P1b-Period39", full_key)
                tested_single += 1
        print(f"  Tested {tested_single} single-varied period-39 keys.")

    # ── Phase 1c: Period 3 (since 39 = 3*13) ──
    print("\n--- Phase 1c: Period-3 Beaufort ---")

    residue_constraints_3 = defaultdict(set)
    for pos, kval in KNOWN_BEAU_KEY.items():
        r = pos % 3
        residue_constraints_3[r].add(kval)

    contradictions_3 = {}
    for r in range(3):
        vals = residue_constraints_3.get(r, set())
        if len(vals) > 1:
            contradictions_3[r] = vals

    if contradictions_3:
        print(f"  Contradictions: {dict(contradictions_3)}")
        print("  Period 3 is IMPOSSIBLE.")
    else:
        print("  Period 3 has no contradictions -- testing all 26^3 keys...")
        tested_p3 = 0
        for a in range(26):
            for b in range(26):
                for c in range(26):
                    key_3 = [a, b, c]
                    full_key = [key_3[i % 3] for i in range(CT_LEN)]
                    pt = beaufort_decrypt_standard(full_key)
                    evaluate(pt, f"P3-{ALPH[a]}{ALPH[b]}{ALPH[c]}", "P1c-Period3", full_key)
                    tested_p3 += 1
        print(f"  Tested {tested_p3} period-3 keys.")


# ═══════════════════════════════════════════════════════════════════════
# PHASE 2: Arithmetic Progression Keys
# ═══════════════════════════════════════════════════════════════════════

def phase2_arith():
    """Test keys based on arithmetic progressions: k[i] = (a + b*i) mod 26."""
    print("\n" + "=" * 72)
    print("PHASE 2: Arithmetic Progression Keys")
    print("=" * 72)

    # ── Phase 2a: Linear keys ──
    print("\n--- Phase 2a: k[i] = (a + b*i) mod 26 ---")
    tested = 0
    for a in range(26):
        for b in range(26):
            full_key = [(a + b * i) % MOD for i in range(CT_LEN)]
            pt = beaufort_decrypt_standard(full_key)
            evaluate(pt, f"Lin-a{a}-b{b}", "P2a-Linear", full_key)
            tested += 1
    print(f"  Tested {tested} linear keys.")

    # ── Phase 2b: Quadratic keys ──
    print("\n--- Phase 2b: k[i] = (a + b*i + c*i^2) mod 26 ---")
    tested = 0
    for a in range(26):
        for b in range(26):
            for c in range(1, 26):  # c=0 is just linear
                full_key = [(a + b * i + c * i * i) % MOD for i in range(CT_LEN)]
                pt = beaufort_decrypt_standard(full_key)
                evaluate(pt, f"Quad-a{a}-b{b}-c{c}", "P2b-Quadratic", full_key)
                tested += 1
                if tested % 1_000_000 == 0:
                    print(f"    ... {tested} tested")
    print(f"  Tested {tested} quadratic keys.")

    # ── Phase 2c: Key from arithmetic progression {6,10,14} with varying start ──
    print("\n--- Phase 2c: d=4 arithmetic progression cycles ---")
    # Cycle through values that include {6, 10, 14}
    # k[i] = (start + 4*i) mod 26 for various starts
    tested = 0
    for start in range(26):
        full_key = [(start + 4 * i) % MOD for i in range(CT_LEN)]
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"AP4-start{start}", "P2c-AP4", full_key)
        tested += 1
    print(f"  Tested {tested} d=4 progression keys.")

    # ── Phase 2d: Modular affine with different moduli ──
    print("\n--- Phase 2d: k[i] = (a + b*i) mod m, wrapped to mod 26 ---")
    tested = 0
    for m in [13, 39, 97]:
        for a in range(m):
            for b in range(m):
                full_key = [(a + b * i) % m % MOD for i in range(CT_LEN)]
                pt = beaufort_decrypt_standard(full_key)
                evaluate(pt, f"Affine-m{m}-a{a}-b{b}", "P2d-Affine", full_key)
                tested += 1
    print(f"  Tested {tested} modular affine keys.")


# ═══════════════════════════════════════════════════════════════════════
# PHASE 3: KA-Alphabet Beaufort
# ═══════════════════════════════════════════════════════════════════════

def phase3_ka():
    """Test Beaufort with KA alphabet for various key types."""
    print("\n" + "=" * 72)
    print("PHASE 3: KA-Alphabet Beaufort")
    print("=" * 72)

    # First, compute what the KA-Beaufort keystream would be at crib positions
    ct_ka = [KA_IDX[c] for c in CT]
    print("\n  KA-Beaufort keystream at crib positions:")
    print("  (Using KA_IDX for both CT and PT)")

    ka_key_ene = []
    for i in range(13):
        pos = 21 + i
        pt_ch = "EASTNORTHEAST"[i]
        pt_ka = KA_IDX[pt_ch]
        ct_ka_val = ct_ka[pos]
        k_val = (ct_ka_val + pt_ka) % MOD  # Beaufort: K = CT + PT mod 26
        ka_key_ene.append(k_val)
    print(f"  ENE (KA): {ka_key_ene}")

    ka_key_bc = []
    for i in range(11):
        pos = 63 + i
        pt_ch = "BERLINCLOCK"[i]
        pt_ka = KA_IDX[pt_ch]
        ct_ka_val = ct_ka[pos]
        k_val = (ct_ka_val + pt_ka) % MOD
        ka_key_bc.append(k_val)
    print(f"  BC  (KA): {ka_key_bc}")

    # Collect all KA key constraints
    ka_known = {}
    for i, v in enumerate(ka_key_ene):
        ka_known[21 + i] = v
    for i, v in enumerate(ka_key_bc):
        ka_known[63 + i] = v

    # ── Phase 3a: Periodic KA-Beaufort, periods 3-26 ──
    print("\n--- Phase 3a: KA-Beaufort periodic keys (periods 3-26) ---")
    for period in range(3, 27):
        # Check for contradictions
        residues = defaultdict(set)
        for pos, kval in ka_known.items():
            residues[pos % period].add(kval)

        contradictions = {r: v for r, v in residues.items() if len(v) > 1}
        fixed = {r: list(v)[0] for r, v in residues.items() if len(v) == 1}
        free = [r for r in range(period) if r not in residues]

        if contradictions:
            continue  # Skip impossible periods

        n_free = len(free)
        total = 26 ** n_free

        if total <= 500_000:
            tested = 0
            for combo in itertools.product(range(26), repeat=n_free):
                key_p = [0] * period
                for r, v in fixed.items():
                    key_p[r] = v
                for r, v in zip(free, combo):
                    key_p[r] = v

                full_key = [key_p[i % period] for i in range(CT_LEN)]
                pt = beaufort_decrypt_ka(full_key)
                evaluate(pt, f"KA-P{period}-{tested}", f"P3a-KA-Period{period}", full_key)
                tested += 1
            if tested > 0:
                print(f"  Period {period}: {tested} keys tested ({n_free} free)")

    # ── Phase 3b: KRYPTOS as KA-Beaufort key ──
    print("\n--- Phase 3b: KRYPTOS keyword as KA-Beaufort key ---")
    kryptos_key = [KA_IDX[c] for c in "KRYPTOS"]
    full_key = [kryptos_key[i % 7] for i in range(CT_LEN)]
    pt = beaufort_decrypt_ka(full_key)
    evaluate(pt, "KA-KRYPTOS", "P3b-KA-Keyword", full_key)
    print(f"  PT: {pt}")

    # Also try with standard alphabet indices
    kryptos_key_std = [ALPH_IDX[c] for c in "KRYPTOS"]
    full_key = [kryptos_key_std[i % 7] for i in range(CT_LEN)]
    pt = beaufort_decrypt_ka(full_key)
    evaluate(pt, "KA-KRYPTOS-std", "P3b-KA-Keyword", full_key)

    # ── Phase 3c: Single-letter KA keys (Caesar under KA) ──
    print("\n--- Phase 3c: KA-Beaufort Caesar (single value) ---")
    for v in range(26):
        full_key = [v] * CT_LEN
        pt = beaufort_decrypt_ka(full_key)
        evaluate(pt, f"KA-Caesar-{v}", "P3c-KA-Caesar", full_key)


# ═══════════════════════════════════════════════════════════════════════
# PHASE 4: Value-10 Dominant Key
# ═══════════════════════════════════════════════════════════════════════

def phase4_val10():
    """Test keys predominantly equal to 10, with controlled deviations.

    Value 10 appears 5 times in just 24 known positions (21%).
    If the key is predominantly 10 with sparse deviations, we can
    enumerate deviation patterns.
    """
    print("\n" + "=" * 72)
    print("PHASE 4: Value-10 Dominant Key")
    print("=" * 72)

    # ── Phase 4a: All-10 baseline ──
    print("\n--- Phase 4a: All-10 baseline ---")
    full_key = [10] * CT_LEN
    pt = beaufort_decrypt_standard(full_key)
    sb = evaluate(pt, "All-10", "P4a-All10", full_key)
    print(f"  PT: {pt}")

    # ── Phase 4b: 1-deviation from all-10 ──
    print("\n--- Phase 4b: 1-deviation from all-10 ---")
    tested = 0
    for pos in range(CT_LEN):
        for val in range(26):
            if val == 10:
                continue
            full_key = [10] * CT_LEN
            full_key[pos] = val
            pt = beaufort_decrypt_standard(full_key)
            evaluate(pt, f"Dev1-p{pos}-v{val}", "P4b-Dev1", full_key)
            tested += 1
    print(f"  Tested {tested} single-deviation keys.")

    # ── Phase 4c: 2-deviation from all-10 ──
    print("\n--- Phase 4c: 2-deviations from all-10 ---")
    tested = 0
    # Only deviate at non-crib positions (cheaper, and crib positions
    # constrain the key value anyway)
    non_crib = [i for i in range(CT_LEN) if i not in CRIB_DICT]
    for p1, p2 in itertools.combinations(non_crib, 2):
        for v1 in [6, 14]:  # Test the AP neighbors of 10
            for v2 in [6, 14]:
                full_key = [10] * CT_LEN
                full_key[p1] = v1
                full_key[p2] = v2
                pt = beaufort_decrypt_standard(full_key)
                evaluate(pt, f"Dev2-{p1}:{v1}-{p2}:{v2}", "P4c-Dev2", full_key)
                tested += 1
    print(f"  Tested {tested} two-deviation keys (AP values only).")

    # ── Phase 4d: Known-position-corrected key ──
    print("\n--- Phase 4d: Known-position-corrected key (base 10, fix cribs) ---")
    print("  NOTE: These keys are FORCED at crib positions, so 24/24 is trivial.")
    print("  Real test is whether non-crib text is meaningful.")
    # Start with all-10, correct at known positions
    full_key = [10] * CT_LEN
    for pos, kval in KNOWN_BEAU_KEY.items():
        full_key[pos] = kval
    pt = beaufort_decrypt_standard(full_key)
    sb = evaluate(pt, "Corrected-10", "P4d-Corrected", full_key)
    non_crib_text = "".join(pt[i] for i in range(CT_LEN) if i not in CRIB_DICT)
    print(f"  PT: {pt}")
    print(f"  Non-crib text: {non_crib_text}")

    # Now try {6, 10, 14} patterns at non-crib positions
    print("  Testing {6,10,14} patterns at unknown positions...")
    unknown_pos = [i for i in range(CT_LEN) if i not in KNOWN_BEAU_KEY]
    # Too many combos for full enum; try block patterns
    tested_block = 0
    for base_val in [6, 10, 14]:
        full_key = [base_val] * CT_LEN
        for pos, kval in KNOWN_BEAU_KEY.items():
            full_key[pos] = kval
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Block-{base_val}", "P4d-Corrected", full_key)
        tested_block += 1

    # Alternating patterns
    patterns = [
        [6, 10], [10, 14], [6, 14], [6, 10, 14], [14, 10, 6],
        [10, 6, 14], [10, 10, 6], [10, 10, 14], [6, 6, 10],
        [14, 14, 10], [10, 6], [10, 14, 6, 10],
    ]
    for pat in patterns:
        full_key = [pat[i % len(pat)] for i in range(CT_LEN)]
        for pos, kval in KNOWN_BEAU_KEY.items():
            full_key[pos] = kval
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Pat-{'_'.join(str(v) for v in pat)}", "P4d-Corrected", full_key)
        tested_block += 1
    print(f"  Tested {tested_block} block/pattern keys.")


# ═══════════════════════════════════════════════════════════════════════
# PHASE 5: Two-Keyword Beaufort
# ═══════════════════════════════════════════════════════════════════════

def phase5_two_keyword():
    """Test Beaufort with two keywords (Sanborn: 'two keywords expected').

    One keyword = KRYPTOS. The other = a thematic word.
    Combination methods:
      a) Alternating: odd positions use KW1, even use KW2
      b) Concatenated: KW1 + KW2 as one key
      c) XOR/addition: k[i] = (kw1[i%p1] + kw2[i%p2]) mod 26
      d) Key1 for positions 0-48, Key2 for 49-96 (halves)
    """
    print("\n" + "=" * 72)
    print("PHASE 5: Two-Keyword Beaufort")
    print("=" * 72)

    kryptos_vals = [ALPH_IDX[c] for c in "KRYPTOS"]
    p1 = len(kryptos_vals)

    # Thematic words to try with KRYPTOS
    thematic_words = [
        "PALIMPSEST", "ABSCISSA", "SHADOW", "LIGHT", "BERLIN",
        "CLOCK", "EAST", "NORTH", "IQLUSION", "UNDERGRUUND",
        "DESPERATELY", "SLOWLY", "VIRTUALLY", "INVISIBLE",
        "ILLUSION", "ENIGMA", "CIPHER", "SECRET", "HIDDEN",
        "BURIED", "TREASURE", "SANBORN", "SCHEIDT", "LANGLEY",
        "MATRIX", "VIGENERE", "BEAUFORT", "KRYPTOS",
        "CARTER", "TUTANKHAMUN", "EGYPT", "TOMB", "PYRAMID",
        "PHARAOH", "HIEROGLYPH", "ARCHAEOLOGY",
        "BERLINCLOCK", "EASTNORTHEAST", "NORTHEAST",
        "EQUINOX", "SOLSTICE", "MERIDIAN", "LATITUDE",
        "LONGITUDE", "COMPASS", "MAGNETIC", "LODESTONE",
        "QUARTZ", "GRANITE", "COPPER", "PETRIFIED",
        "WHIRLPOOL", "METEORITE", "LOOMIS", "BOWEN",
        "DECEPTION", "MASQUERADE", "OBSCURE", "CONCEAL",
        "BETWEEN", "SUBTLE", "SHADING", "ABSENCE",
        "WEBSTER", "LECARRE", "CORNWELL",
        "SPYMASTER", "TRADECRAFT", "CLANDESTINE",
        "ANTIPODES", "SCULPTURE",
        "TOTALLY", "INFORMATION", "GATHERING",
        "DIGETAL", "INTERPRETATION",
    ]

    # ── Phase 5a: Additive combination ──
    print("\n--- Phase 5a: k[i] = (KRYPTOS[i%7] + KW2[i%p2]) mod 26 ---")
    tested = 0
    for word in thematic_words:
        kw2_vals = [ALPH_IDX[c] for c in word]
        p2 = len(kw2_vals)
        full_key = [(kryptos_vals[i % p1] + kw2_vals[i % p2]) % MOD for i in range(CT_LEN)]
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Add-KRYPTOS+{word}", "P5a-Additive", full_key)
        tested += 1

        # Also try subtraction
        full_key = [(kryptos_vals[i % p1] - kw2_vals[i % p2]) % MOD for i in range(CT_LEN)]
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Sub-KRYPTOS-{word}", "P5a-Additive", full_key)
        tested += 1
    print(f"  Tested {tested} additive/subtractive combinations.")

    # ── Phase 5b: Alternating keywords ──
    print("\n--- Phase 5b: Alternating keywords ---")
    tested = 0
    for word in thematic_words:
        kw2_vals = [ALPH_IDX[c] for c in word]
        p2 = len(kw2_vals)

        # Even positions: KRYPTOS, odd: KW2
        full_key = []
        kw1_ctr, kw2_ctr = 0, 0
        for i in range(CT_LEN):
            if i % 2 == 0:
                full_key.append(kryptos_vals[kw1_ctr % p1])
                kw1_ctr += 1
            else:
                full_key.append(kw2_vals[kw2_ctr % p2])
                kw2_ctr += 1
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Alt-KRYPTOS/{word}", "P5b-Alternating", full_key)
        tested += 1

        # Odd positions: KRYPTOS, even: KW2
        full_key = []
        kw1_ctr, kw2_ctr = 0, 0
        for i in range(CT_LEN):
            if i % 2 == 1:
                full_key.append(kryptos_vals[kw1_ctr % p1])
                kw1_ctr += 1
            else:
                full_key.append(kw2_vals[kw2_ctr % p2])
                kw2_ctr += 1
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Alt-{word}/KRYPTOS", "P5b-Alternating", full_key)
        tested += 1
    print(f"  Tested {tested} alternating keywords.")

    # ── Phase 5c: Concatenated keywords ──
    print("\n--- Phase 5c: Concatenated keywords ---")
    tested = 0
    for word in thematic_words:
        kw2_vals = [ALPH_IDX[c] for c in word]

        # KRYPTOS + KW2
        concat = kryptos_vals + kw2_vals
        full_key = [concat[i % len(concat)] for i in range(CT_LEN)]
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Cat-KRYPTOS{word}", "P5c-Concatenated", full_key)
        tested += 1

        # KW2 + KRYPTOS
        concat = kw2_vals + kryptos_vals
        full_key = [concat[i % len(concat)] for i in range(CT_LEN)]
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Cat-{word}KRYPTOS", "P5c-Concatenated", full_key)
        tested += 1
    print(f"  Tested {tested} concatenated keywords.")

    # ── Phase 5d: Split key (first half / second half) ──
    print("\n--- Phase 5d: Split key (KW1 for first half, KW2 for second) ---")
    tested = 0
    split_point = 49  # Roughly halfway
    for word in thematic_words:
        kw2_vals = [ALPH_IDX[c] for c in word]
        p2 = len(kw2_vals)

        full_key = []
        for i in range(CT_LEN):
            if i < split_point:
                full_key.append(kryptos_vals[i % p1])
            else:
                full_key.append(kw2_vals[(i - split_point) % p2])
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Split-KRYPTOS|{word}", "P5d-Split", full_key)
        tested += 1

        # Reverse: KW2 first, KRYPTOS second
        full_key = []
        for i in range(CT_LEN):
            if i < split_point:
                full_key.append(kw2_vals[i % p2])
            else:
                full_key.append(kryptos_vals[(i - split_point) % p1])
        pt = beaufort_decrypt_standard(full_key)
        evaluate(pt, f"Split-{word}|KRYPTOS", "P5d-Split", full_key)
        tested += 1
    print(f"  Tested {tested} split keywords.")

    # ── Phase 5e: Expanded wordlist scan with KRYPTOS ──
    print("\n--- Phase 5e: Wordlist scan (additive with KRYPTOS, 4-12 char words) ---")
    tested = 0
    try:
        with open(WORDLIST_PATH, "r") as f:
            words = [w.strip().upper() for w in f if 4 <= len(w.strip()) <= 12 and w.strip().isalpha()]
        print(f"  Loaded {len(words)} words from wordlist")

        for word in words:
            kw2_vals = [ALPH_IDX[c] for c in word]
            p2 = len(kw2_vals)

            # Additive
            full_key = [(kryptos_vals[i % p1] + kw2_vals[i % p2]) % MOD for i in range(CT_LEN)]
            pt = beaufort_decrypt_standard(full_key)
            evaluate(pt, f"WL-Add-{word}", "P5e-Wordlist", full_key)
            tested += 1

            if tested % 100_000 == 0:
                print(f"    ... {tested} tested")

        print(f"  Tested {tested} wordlist additive combinations.")
    except FileNotFoundError:
        print(f"  Wordlist not found at {WORDLIST_PATH}, skipping.")


# ═══════════════════════════════════════════════════════════════════════
# PHASE 6: Bonus — Running-key Beaufort from KRYPTOS keyword cycling
# ═══════════════════════════════════════════════════════════════════════

def phase6_bonus():
    """Additional Beaufort-specific tests.

    6a: Autokey Beaufort (key feeds back from PT or CT)
    6b: Beaufort with period-13 key constrained by known values
    6c: Cascaded Beaufort (apply Beaufort twice)
    """
    print("\n" + "=" * 72)
    print("PHASE 6: Bonus Beaufort Variants")
    print("=" * 72)

    # ── Phase 6a: Autokey Beaufort ──
    print("\n--- Phase 6a: Autokey Beaufort (primer + PT feedback) ---")
    tested = 0
    # For each primer length 1-5 (6+ is infeasible: 26^6 = 308M)
    for primer_len in range(1, 6):
        for primer_combo in itertools.product(range(26), repeat=primer_len):
            primer = list(primer_combo)
            pt_vals = []

            # Beaufort autokey: after primer, key[i] = pt[i - primer_len]
            actual_key = []
            for i in range(CT_LEN):
                if i < primer_len:
                    k = primer[i]
                else:
                    k = pt_vals[i - primer_len]
                actual_key.append(k)
                pt_val = (k - CT_VALS[i]) % MOD
                pt_vals.append(pt_val)

            pt = "".join(ALPH[v] for v in pt_vals)
            evaluate(pt, f"AutoPT-p{primer_len}-{tested}", "P6a-Autokey", actual_key)
            tested += 1

            if tested % 500_000 == 0:
                print(f"    ... {tested} tested")
        if primer_len >= 4:
            print(f"  Primer length {primer_len}: done ({26**primer_len} combos)")

    print(f"  Tested {tested} autokey-PT keys.")

    # ── Phase 6a2: Autokey Beaufort (CT feedback) ──
    print("\n--- Phase 6a2: Autokey Beaufort (primer + CT feedback) ---")
    tested = 0
    for primer_len in range(1, 6):
        for primer_combo in itertools.product(range(26), repeat=primer_len):
            primer = list(primer_combo)
            pt_vals = []

            actual_key = []
            for i in range(CT_LEN):
                if i < primer_len:
                    k = primer[i]
                else:
                    k = CT_VALS[i - primer_len]
                actual_key.append(k)
                pt_val = (k - CT_VALS[i]) % MOD
                pt_vals.append(pt_val)

            pt = "".join(ALPH[v] for v in pt_vals)
            evaluate(pt, f"AutoCT-p{primer_len}-{tested}", "P6a2-AutokeyCT", actual_key)
            tested += 1

            if tested % 500_000 == 0:
                print(f"    ... {tested} tested")
    print(f"  Tested {tested} autokey-CT keys.")

    # ── Phase 6b: Cascaded Beaufort ──
    print("\n--- Phase 6b: Cascaded Beaufort (two layers) ---")
    tested = 0
    # Apply Beaufort twice with KRYPTOS keyword
    kryptos_vals = [ALPH_IDX[c] for c in "KRYPTOS"]
    p1 = len(kryptos_vals)

    for word in ["PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "SHADOW",
                 "LIGHT", "EQUINOX", "LODESTONE", "KRYPTOS", "SANBORN",
                 "SCHEIDT", "LANGLEY", "ENIGMA", "CIPHER", "MATRIX",
                 "CARTER", "EGYPT", "TOMB", "LOOMIS", "BOWEN",
                 "ANTIPODES", "SCULPTURE", "BEAUFORT", "VIGENERE"]:
        kw2_vals = [ALPH_IDX[c] for c in word]
        p2 = len(kw2_vals)

        # Layer 1: Beaufort with KRYPTOS
        inter = [(kryptos_vals[i % p1] - CT_VALS[i]) % MOD for i in range(CT_LEN)]
        # Layer 2: Beaufort with KW2
        pt_vals = [(kw2_vals[i % p2] - inter[i]) % MOD for i in range(CT_LEN)]
        pt = "".join(ALPH[v] for v in pt_vals)

        # The effective key for scoring is more complex; pass None for bean
        evaluate(pt, f"Cascade-KRYPTOS-{word}", "P6b-Cascade", None)
        tested += 1

        # Reverse order
        inter = [(kw2_vals[i % p2] - CT_VALS[i]) % MOD for i in range(CT_LEN)]
        pt_vals = [(kryptos_vals[i % p1] - inter[i]) % MOD for i in range(CT_LEN)]
        pt = "".join(ALPH[v] for v in pt_vals)
        evaluate(pt, f"Cascade-{word}-KRYPTOS", "P6b-Cascade", None)
        tested += 1

    print(f"  Tested {tested} cascaded Beaufort combinations.")

    # ── Phase 6c: Known-constrained period-13 search ──
    # This is separate from Phase 1 because here we also try KA alphabet
    print("\n--- Phase 6c: KA-Beaufort with constrained period-13 ---")

    ct_ka = [KA_IDX[c] for c in CT]
    ka_known = {}
    for i in range(13):
        pos = 21 + i
        pt_ch = "EASTNORTHEAST"[i]
        ka_known[pos] = (ct_ka[pos] + KA_IDX[pt_ch]) % MOD
    for i in range(11):
        pos = 63 + i
        pt_ch = "BERLINCLOCK"[i]
        ka_known[pos] = (ct_ka[pos] + KA_IDX[pt_ch]) % MOD

    residues_ka13 = defaultdict(set)
    for pos, kval in ka_known.items():
        residues_ka13[pos % 13].add(kval)

    contradictions = {r: v for r, v in residues_ka13.items() if len(v) > 1}
    fixed = {r: list(v)[0] for r, v in residues_ka13.items() if len(v) == 1}
    free = [r for r in range(13) if r not in residues_ka13]

    if contradictions:
        print(f"  KA period-13 contradictions: {dict(contradictions)}")
        print("  KA period-13 is IMPOSSIBLE.")
    else:
        n_free = len(free)
        total_combos = 26 ** n_free
        print(f"  KA period-13: {len(fixed)} fixed, {n_free} free, {total_combos} combos")
        if total_combos <= 10_000_000:
            tested = 0
            for combo in itertools.product(range(26), repeat=n_free):
                key_13 = [0] * 13
                for r, v in fixed.items():
                    key_13[r] = v
                for r, v in zip(free, combo):
                    key_13[r] = v
                full_key = [key_13[i % 13] for i in range(CT_LEN)]
                # Decrypt: PT = KA[(key - ct_ka) mod 26]
                pt = "".join(KA[(full_key[i] - ct_ka[i]) % MOD] for i in range(CT_LEN))
                evaluate(pt, f"KA-P13-{tested}", "P6c-KA-P13", full_key)
                tested += 1
                if tested % 1_000_000 == 0:
                    print(f"    ... {tested}/{total_combos} tested")
            print(f"  Tested {tested} KA period-13 keys.")


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("E-SOLVE-07: Beaufort-Focused K4 Attack")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Known Beaufort keystream (ENE): {list(BEAUFORT_KEY_ENE)}")
    print(f"Known Beaufort keystream (BC):  {list(BEAUFORT_KEY_BC)}")

    # Show key value statistics
    all_known = list(BEAUFORT_KEY_ENE) + list(BEAUFORT_KEY_BC)
    counts = Counter(all_known)
    print(f"\nKey value distribution (24 known positions):")
    for v in sorted(counts.keys()):
        print(f"  {v:2d} ({ALPH[v]}): {'#' * counts[v]} ({counts[v]})")

    # Verify gap-39 matches
    print(f"\nGap-39 cross-crib verification:")
    for pos_ene in range(21, 34):
        pos_bc = pos_ene + 39 + 3  # ENE starts at 21, BC at 63, gap = 42 in position
        # Actually: BC starts at 63. pos 21 -> 63 = gap 42. pos 22 -> 64 = gap 42.
        # The gap-39 refers to positions within the cribs: ENE pos i, BC pos i-3
        # Let's recalculate
        pass

    print(f"\nDirect cross-position matches (checking k[a] == k[b] for known positions):")
    for a in range(21, 34):
        for b in range(63, 74):
            ka = KNOWN_BEAU_KEY[a]
            kb = KNOWN_BEAU_KEY[b]
            if ka == kb:
                gap = b - a
                print(f"  k[{a}] = k[{b}] = {ka} ({ALPH[ka]})  gap={gap}")

    t0 = time.time()

    phase1_gap39()
    phase2_arith()
    phase3_ka()
    phase4_val10()
    phase5_two_keyword()
    phase6_bonus()

    elapsed = time.time() - t0

    # ── Summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total candidates tested: {total_tested:,}")
    print(f"Elapsed time: {elapsed:.1f}s")
    print(f"Results above noise (>{NOISE_FLOOR}): {len(results_above_noise)}")

    print(f"\nPer-phase breakdown:")
    for phase, stats in sorted(phase_stats.items()):
        above = stats['above_noise']
        best = stats['best_score']
        label = stats['best_label']
        print(f"  {phase:25s}: {stats['tested']:>10,} tested, {above:>5} above noise, best={best}/24 ({label})")

    if results_above_noise:
        print(f"\nAll results above noise (score > {NOISE_FLOOR}):")
        results_above_noise.sort(key=lambda r: r["score"], reverse=True)
        for r in results_above_noise[:50]:
            print(f"  [{r['phase']}] {r['label']}: score={r['score']}/24 "
                  f"(ENE={r['ene']}, BC={r['bc']}) IC={r['ic']:.4f} "
                  f"bean={'PASS' if r['bean'] else 'FAIL'}")
            print(f"    PT: {r['plaintext']}")
    else:
        print("\nNo results above noise floor. ALL NOISE.")

    # Best overall
    if results_above_noise:
        best = results_above_noise[0]
        print(f"\nBest result: {best['label']} score={best['score']}/24")
    else:
        print(f"\nBest score across all phases: 0-{NOISE_FLOOR} (noise)")

    # Save results
    results_path = Path(__file__).resolve().parents[1] / "results"
    results_path.mkdir(exist_ok=True)
    out_file = results_path / "e_solve_07_beaufort_focus.json"
    summary = {
        "experiment": "E-SOLVE-07",
        "description": "Beaufort-focused K4 attack",
        "total_tested": total_tested,
        "elapsed_seconds": elapsed,
        "above_noise_count": len(results_above_noise),
        "phase_stats": {k: {"tested": v["tested"], "above_noise": v["above_noise"],
                            "best_score": v["best_score"], "best_label": v["best_label"]}
                        for k, v in phase_stats.items()},
        "top_results": results_above_noise[:100],
    }
    with open(out_file, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to {out_file}")


if __name__ == "__main__":
    main()
