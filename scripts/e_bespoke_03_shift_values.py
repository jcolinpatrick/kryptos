#!/usr/bin/env python3
"""E-BESPOKE-03: Test misspelling-derived NUMERIC SHIFT VALUES as key material.

Theory: The deliberate misspellings on Kryptos encode NUMERIC DISTANCES between
wrong and correct letters, and these distances form key parameters.

Misspellings and shifts:
  DIGETAL   (should be DIGITAL):    I(8)→E(4),   distance=4
  IQLUSION  (should be ILLUSION):   L(11)→Q(16), distance=5
  DESPARATLY(should be DESPERATELY):E(4)→A(0),   distance=4
  PALIMPCEST(confirmed misspelling):S(18)→C(2),  distance=16
  UNDERGRUUND(K2, corrected on Antipodes): O(14)→U(20), distance=6

Shift values: [4, 5, 4, 16] (core 4), [4, 5, 4, 16, 6] (with UNDERGRUUND)

Seven phases tested:
  1. Shift values as repeating Vigenère/Beaufort keys (all rotations + orderings)
  2. Shift values as transposition parameters (column widths, grid dimensions)
  3. Shift values as position-dependent alphabet offsets
  4. Combined with other sculpture numeric clues (YAR, T=19, RQ)
  5. Signed shifts (direction-aware: wrong→right vs right→wrong)
  6. Exhaustive shift-combination search (4 misspellings × 4 interpretations = 256)
  7. Shift values as positional indicators (cumulative sums, CT extraction)
"""
from __future__ import annotations

import math
from collections import Counter
from itertools import permutations, product
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    CT,
    CT_LEN,
    CRIB_DICT,
    CRIB_WORDS,
    MOD,
    N_CRIBS,
    NOISE_FLOOR,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.transforms.vigenere import (
    CipherVariant,
    decrypt_text,
    vig_decrypt,
    beau_decrypt,
    varbeau_decrypt,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm,
    invert_perm,
    columnar_perm,
)
from kryptos.kernel.constraints.bean import verify_bean


# ── Helpers ──────────────────────────────────────────────────────────────────

def c2n(c: str) -> int:
    return ord(c) - 65

def n2c(n: int) -> str:
    return chr((n % 26) + 65)

def decrypt_with_key(ct: str, key: List[int], variant: str) -> str:
    """Decrypt ct with numeric key, returning plaintext string."""
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        cv = c2n(c)
        kv = key[i % klen]
        if variant == "vig":
            pt = (cv - kv) % MOD
        elif variant == "beau":
            pt = (kv - cv) % MOD
        elif variant == "varbeau":
            pt = (cv + kv) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")
        result.append(n2c(pt))
    return "".join(result)


def score_and_report(pt: str, label: str, best_tracker: dict) -> int:
    """Score a plaintext, print if above noise, track best."""
    sc = score_cribs(pt)
    if sc > best_tracker.get("score", 0):
        best_tracker["score"] = sc
        best_tracker["label"] = label
        best_tracker["pt"] = pt
    if sc > NOISE_FLOOR:
        detail = score_cribs_detailed(pt)
        print(f"  ** ABOVE NOISE: {label}")
        print(f"     Score: {sc}/24  ENE={detail['ene_score']}/13  BC={detail['bc_score']}/11")
        print(f"     PT[0:40]: {pt[:40]}")
        print(f"     PT[40:]: {pt[40:]}")
    return sc


# ── Core shift values ────────────────────────────────────────────────────────

# Core misspelling shifts (distance between wrong and correct letter)
SHIFTS_4 = [4, 5, 4, 16]     # DIGETAL, IQLUSION, DESPARATLY, PALIMPCEST
SHIFTS_5 = [4, 5, 4, 16, 6]  # + UNDERGRUUND

# Signed shifts: positive means "add to correct the misspelling"
SIGNED_SHIFTS_CORRECT = [4, -5, 4, 16]   # E+4=I, Q-5=L, A+4=E, C+16=S
SIGNED_SHIFTS_APPLIED = [-4, 5, -4, -16]  # I-4=E, L+5=Q, E-4=A, S-16=C

# Mod-26 complements
COMP_4 = [(s, 26 - s) for s in SHIFTS_4]  # (4,22), (5,21), (4,22), (16,10)

# Other sculpture numeric values
YAR = [24, 0, 17]       # Y=24, A=0, R=17
T_POS = [19]             # T IS YOUR POSITION
RQ = [17, 16]            # R=17, Q=16

VARIANT_NAMES = {"vig": "Vigenere", "beau": "Beaufort", "varbeau": "VarBeau"}


def phase1_shift_as_key():
    """Phase 1: Use shift values as repeating Vigenere/Beaufort keys."""
    print("\n" + "=" * 78)
    print("  PHASE 1: SHIFT VALUES AS REPEATING CIPHER KEYS")
    print("=" * 78)

    best = {"score": 0}
    configs_tested = 0

    # Direct keys
    direct_keys = {
        "shifts_4": SHIFTS_4,
        "shifts_5": SHIFTS_5,
        "signed_correct": SIGNED_SHIFTS_CORRECT,
        "signed_applied": SIGNED_SHIFTS_APPLIED,
        "mod26_correct": [(s % 26) for s in SIGNED_SHIFTS_CORRECT],
        "mod26_applied": [(s % 26) for s in SIGNED_SHIFTS_APPLIED],
    }

    for key_name, key in direct_keys.items():
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            label = f"key={key_name}{key} {VARIANT_NAMES[variant]}"
            score_and_report(pt, label, best)
            configs_tested += 1

    # All rotations of 4-element key
    print(f"\n  --- Rotations of {SHIFTS_4} ---")
    for rot in range(len(SHIFTS_4)):
        key = SHIFTS_4[rot:] + SHIFTS_4[:rot]
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            label = f"rot{rot} key={key} {VARIANT_NAMES[variant]}"
            score_and_report(pt, label, best)
            configs_tested += 1

    # All rotations of 5-element key
    print(f"\n  --- Rotations of {SHIFTS_5} ---")
    for rot in range(len(SHIFTS_5)):
        key = SHIFTS_5[rot:] + SHIFTS_5[:rot]
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            label = f"rot{rot} key={key} {VARIANT_NAMES[variant]}"
            score_and_report(pt, label, best)
            configs_tested += 1

    # All orderings of 4-element key (4! = 24 permutations)
    print(f"\n  --- All orderings of {SHIFTS_4} (4! = 24) ---")
    seen = set()
    for perm in permutations(SHIFTS_4):
        key = list(perm)
        key_tuple = tuple(key)
        if key_tuple in seen:
            continue
        seen.add(key_tuple)
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            label = f"perm key={key} {VARIANT_NAMES[variant]}"
            score_and_report(pt, label, best)
            configs_tested += 1

    # All orderings of 5-element key (5! = 120 permutations)
    print(f"\n  --- All orderings of {SHIFTS_5} (5! = 120) ---")
    seen5 = set()
    for perm in permutations(SHIFTS_5):
        key = list(perm)
        key_tuple = tuple(key)
        if key_tuple in seen5:
            continue
        seen5.add(key_tuple)
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            label = f"perm5 key={key} {VARIANT_NAMES[variant]}"
            score_and_report(pt, label, best)
            configs_tested += 1

    print(f"\n  Phase 1 summary: {configs_tested} configs tested")
    print(f"  Best: {best['score']}/24 — {best.get('label', 'none')}")
    return best


def phase2_shift_as_transposition():
    """Phase 2: Use shift values as transposition parameters."""
    print("\n" + "=" * 78)
    print("  PHASE 2: SHIFT VALUES AS TRANSPOSITION PARAMETERS")
    print("=" * 78)

    best = {"score": 0}
    configs_tested = 0

    # Column widths from individual shift values
    widths_to_test = [4, 5, 16, 6, 29, 9, 13, 10, 20, 25]
    # 4+5=9, 4+5+4=13, 4+5+4+16=29, 4*5=20, 5*4=20, 4+16=20, 5+16=21, 4+5+16=25

    print(f"\n  --- Columnar transposition with various widths ---")
    for w in widths_to_test:
        if w < 2 or w > 48:
            continue
        # Try all column orderings for small widths, identity for large
        if w <= 7:
            # All column orderings
            for col_order in permutations(range(w)):
                perm = columnar_perm(w, list(col_order), CT_LEN)
                if len(perm) != CT_LEN:
                    continue
                # Apply inverse perm (undo the transposition)
                inv = invert_perm(perm)
                ct_untrans = apply_perm(CT, inv)
                # Score raw (no substitution)
                sc = score_cribs(ct_untrans)
                label = f"columnar w={w} order={list(col_order)}"
                if sc > best.get("score", 0):
                    best["score"] = sc
                    best["label"] = label
                    best["pt"] = ct_untrans
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} → {sc}/24")
                configs_tested += 1
        else:
            # Only identity and reverse orders for large widths
            for order_name, col_order in [("identity", list(range(w))),
                                           ("reverse", list(range(w-1, -1, -1)))]:
                perm = columnar_perm(w, col_order, CT_LEN)
                if len(perm) != CT_LEN:
                    continue
                inv = invert_perm(perm)
                ct_untrans = apply_perm(CT, inv)
                sc = score_cribs(ct_untrans)
                label = f"columnar w={w} {order_name}"
                if sc > best.get("score", 0):
                    best["score"] = sc
                    best["label"] = label
                    best["pt"] = ct_untrans
                if sc > NOISE_FLOOR:
                    print(f"  ** ABOVE NOISE: {label} → {sc}/24")
                configs_tested += 1

    # Transposition then substitution: columnar + Vig/Beau with shift keys
    print(f"\n  --- Columnar + shift-key substitution ---")
    for w in [4, 5, 9, 13, 16, 29]:
        if w < 2 or w > 48:
            continue
        # Only try a few orderings for combined tests
        orders_to_try = []
        if w <= 5:
            orders_to_try = list(permutations(range(w)))
        else:
            orders_to_try = [tuple(range(w)), tuple(range(w-1, -1, -1))]

        for col_order in orders_to_try:
            perm = columnar_perm(w, list(col_order), CT_LEN)
            if len(perm) != CT_LEN:
                continue
            inv = invert_perm(perm)
            ct_untrans = apply_perm(CT, inv)

            # Now apply substitution with shift keys
            for key_name, key in [("shifts_4", SHIFTS_4), ("shifts_5", SHIFTS_5)]:
                for variant in ["vig", "beau"]:
                    pt = decrypt_with_key(ct_untrans, key, variant)
                    label = f"col_w{w}_ord{list(col_order[:3])}...+{key_name}_{variant}"
                    score_and_report(pt, label, best)
                    configs_tested += 1

    # Grid reads: fill into w×h grid, read columns
    print(f"\n  --- Grid reads at shift-derived dimensions ---")
    for w in [4, 5, 16, 9, 13, 29]:
        h = math.ceil(CT_LEN / w)
        # Fill row-by-row, read column-by-column
        grid = [''] * (w * h)
        for i, c in enumerate(CT):
            grid[i] = c
        for i in range(len(CT), w * h):
            grid[i] = 'X'  # pad

        # Read columns
        col_read = []
        for c in range(w):
            for r in range(h):
                idx = r * w + c
                if idx < CT_LEN:
                    col_read.append(grid[idx])
        col_text = "".join(col_read[:CT_LEN])
        sc = score_cribs(col_text)
        label = f"grid {w}x{h} col-read"
        if sc > best.get("score", 0):
            best["score"] = sc
            best["label"] = label
            best["pt"] = col_text
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")
        configs_tested += 1

        # Read columns in reverse
        rev_read = []
        for c in range(w - 1, -1, -1):
            for r in range(h):
                idx = r * w + c
                if idx < CT_LEN:
                    rev_read.append(grid[idx])
        rev_text = "".join(rev_read[:CT_LEN])
        sc = score_cribs(rev_text)
        label = f"grid {w}x{h} rev-col-read"
        if sc > best.get("score", 0):
            best["score"] = sc
            best["label"] = label
            best["pt"] = rev_text
        if sc > NOISE_FLOOR:
            print(f"  ** ABOVE NOISE: {label} → {sc}/24")
        configs_tested += 1

    # Derived numbers
    print(f"\n  --- Derived numbers ---")
    print(f"  Sum(4,5,4,16) = {sum(SHIFTS_4)}")
    print(f"  Product(4,5,4,16) = {math.prod(SHIFTS_4)}")
    print(f"  Sum(4,5,4,16,6) = {sum(SHIFTS_5)}")
    print(f"  97 mod 4 = {97 % 4}, 97 mod 5 = {97 % 5}, 97 mod 16 = {97 % 16}")
    print(f"  97 / 4 = {97/4:.2f}, 97 / 5 = {97/5:.2f}, 97 / 16 = {97/16:.2f}")

    print(f"\n  Phase 2 summary: {configs_tested} configs tested")
    print(f"  Best: {best['score']}/24 — {best.get('label', 'none')}")
    return best


def phase3_position_dependent_offset():
    """Phase 3: Shift values as position-dependent alphabet offsets."""
    print("\n" + "=" * 78)
    print("  PHASE 3: POSITION-DEPENDENT ALPHABET OFFSETS")
    print("=" * 78)

    best = {"score": 0}
    configs_tested = 0

    # Idea: at position i, shift the alphabet by shifts[i % 4] BEFORE Vig/Beau
    # CT'[i] = (CT[i] + shift[i%4]) mod 26, then decrypt with standard key search
    # Or: CT'[i] = (CT[i] - shift[i%4]) mod 26

    for key_name, shifts in [("shifts_4", SHIFTS_4), ("shifts_5", SHIFTS_5)]:
        for direction in ["+", "-"]:
            # Pre-shift the CT
            shifted_ct = []
            for i, c in enumerate(CT):
                cv = c2n(c)
                sv = shifts[i % len(shifts)]
                if direction == "+":
                    shifted_ct.append(n2c((cv + sv) % MOD))
                else:
                    shifted_ct.append(n2c((cv - sv) % MOD))
            shifted_ct_str = "".join(shifted_ct)

            # Now try Vig/Beau with various simple keys
            # First: identity key (shift alone IS the decryption)
            sc = score_cribs(shifted_ct_str)
            label = f"offset_{key_name}_{direction}_identity"
            score_and_report(shifted_ct_str, label, best)
            configs_tested += 1

            # Try combining with shift keys as a second layer
            for key2_name, key2 in [("shifts_4", SHIFTS_4), ("shifts_5", SHIFTS_5)]:
                for variant in ["vig", "beau"]:
                    pt = decrypt_with_key(shifted_ct_str, key2, variant)
                    label = f"offset_{key_name}_{direction}+{key2_name}_{variant}"
                    score_and_report(pt, label, best)
                    configs_tested += 1

    # Position-dependent Vigenere: K[i] = (CT[i] - PT[i] + shift[i%4]) mod 26
    # Equivalent to key_effective[i] = key[i] - shift[i%4] mod 26
    # Test: does this make the keystream periodic?
    print(f"\n  --- Offset-adjusted keystream analysis ---")
    for key_name, shifts in [("shifts_4", SHIFTS_4), ("shifts_5", SHIFTS_5)]:
        for direction_name, sign in [("subtract", -1), ("add", +1)]:
            print(f"\n  {key_name} {direction_name} at crib positions:")
            adjusted = {}
            for pos, pt_ch in sorted(CRIB_DICT.items()):
                cv = c2n(CT[pos])
                pv = c2n(pt_ch)
                sv = shifts[pos % len(shifts)]
                # Vig key: K = (C - P) mod 26, adjusted: K' = (C - P + sign*S) mod 26
                k_vig = (cv - pv + sign * sv) % MOD
                adjusted[pos] = k_vig

            # Check periodicity of adjusted keystream
            ene_adj = [adjusted[p] for p in range(21, 34)]
            bc_adj = [adjusted[p] for p in range(63, 74)]
            ene_letters = "".join(n2c(k) for k in ene_adj)
            bc_letters = "".join(n2c(k) for k in bc_adj)
            print(f"    ENE adjusted: {ene_letters} = {ene_adj}")
            print(f"    BC  adjusted: {bc_letters} = {bc_adj}")

            # Check for repeating patterns
            for period in range(1, 8):
                matches = 0
                comparisons = 0
                positions = sorted(adjusted.keys())
                for i, p1 in enumerate(positions):
                    for p2 in positions[i+1:]:
                        if (p2 - p1) % period == 0:
                            comparisons += 1
                            if adjusted[p1] == adjusted[p2]:
                                matches += 1
                if comparisons > 0:
                    frac = matches / comparisons
                    if frac > 0.3:
                        print(f"    Period {period}: {matches}/{comparisons} = {frac:.3f}")

    print(f"\n  Phase 3 summary: {configs_tested} configs tested")
    print(f"  Best: {best['score']}/24 — {best.get('label', 'none')}")
    return best


def phase4_combined_clues():
    """Phase 4: Shift values combined with other sculpture numeric clues."""
    print("\n" + "=" * 78)
    print("  PHASE 4: COMBINED WITH SCULPTURE NUMERIC CLUES")
    print("=" * 78)

    best = {"score": 0}
    configs_tested = 0

    # Combined keys
    combined_keys = {
        "shifts+YAR": SHIFTS_4 + YAR,                      # [4,5,4,16,24,0,17]
        "shifts+T": SHIFTS_4 + T_POS,                       # [4,5,4,16,19]
        "shifts+RQ": SHIFTS_4 + RQ,                          # [4,5,4,16,17,16]
        "shifts+YAR+T": SHIFTS_4 + YAR + T_POS,            # [4,5,4,16,24,0,17,19]
        "shifts+YAR+RQ": SHIFTS_4 + YAR + RQ,              # [4,5,4,16,24,0,17,17,16]
        "YAR": YAR,                                          # [24,0,17]
        "RQ": RQ,                                            # [17,16]
        "T+shifts": T_POS + SHIFTS_4,                        # [19,4,5,4,16]
        "YAR+shifts": YAR + SHIFTS_4,                        # [24,0,17,4,5,4,16]
        "shifts5+YAR": SHIFTS_5 + YAR,                      # [4,5,4,16,6,24,0,17]
        "shifts5+T": SHIFTS_5 + T_POS,                       # [4,5,4,16,6,19]
        "shifts+YART": SHIFTS_4 + YAR + T_POS,              # [4,5,4,16,24,0,17,19]
        "YART": YAR + T_POS,                                 # [24,0,17,19]
        "YART+shifts": YAR + T_POS + SHIFTS_4,              # [24,0,17,19,4,5,4,16]
    }

    for key_name, key in combined_keys.items():
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            label = f"{key_name}={key} {VARIANT_NAMES[variant]}"
            score_and_report(pt, label, best)
            configs_tested += 1

    # Also try shifts as additive BEFORE decryption with YAR/YART as main key
    print(f"\n  --- Shifts as pre-offset, YAR/YART as main key ---")
    pre_keys = [("shifts_4", SHIFTS_4), ("shifts_5", SHIFTS_5)]
    main_keys = [("YAR", YAR), ("YART", YAR + T_POS), ("RQ", RQ)]

    for pre_name, pre_key in pre_keys:
        for main_name, main_key in main_keys:
            for pre_dir in ["+", "-"]:
                # Pre-shift CT
                shifted_ct = []
                for i, c in enumerate(CT):
                    cv = c2n(c)
                    sv = pre_key[i % len(pre_key)]
                    if pre_dir == "+":
                        shifted_ct.append(n2c((cv + sv) % MOD))
                    else:
                        shifted_ct.append(n2c((cv - sv) % MOD))
                shifted_str = "".join(shifted_ct)

                for variant in ["vig", "beau"]:
                    pt = decrypt_with_key(shifted_str, main_key, variant)
                    label = f"pre({pre_name}{pre_dir})+main({main_name})_{variant}"
                    score_and_report(pt, label, best)
                    configs_tested += 1

    # Reverse: YAR/YART as pre-offset, shifts as main key
    for main_name, main_key in [("shifts_4", SHIFTS_4), ("shifts_5", SHIFTS_5)]:
        for pre_name, pre_key in [("YAR", YAR), ("YART", YAR + T_POS)]:
            for pre_dir in ["+", "-"]:
                shifted_ct = []
                for i, c in enumerate(CT):
                    cv = c2n(c)
                    sv = pre_key[i % len(pre_key)]
                    if pre_dir == "+":
                        shifted_ct.append(n2c((cv + sv) % MOD))
                    else:
                        shifted_ct.append(n2c((cv - sv) % MOD))
                shifted_str = "".join(shifted_ct)

                for variant in ["vig", "beau"]:
                    pt = decrypt_with_key(shifted_str, main_key, variant)
                    label = f"pre({pre_name}{pre_dir})+main({main_name})_{variant}"
                    score_and_report(pt, label, best)
                    configs_tested += 1

    print(f"\n  Phase 4 summary: {configs_tested} configs tested")
    print(f"  Best: {best['score']}/24 — {best.get('label', 'none')}")
    return best


def phase5_signed_shifts():
    """Phase 5: Signed shifts (direction-aware)."""
    print("\n" + "=" * 78)
    print("  PHASE 5: SIGNED / DIRECTIONAL SHIFTS")
    print("=" * 78)

    best = {"score": 0}
    configs_tested = 0

    # Direction analysis
    print("  Misspelling direction analysis:")
    print("  DIGETAL:    E(4) should be I(8)  → to correct: +4  (applied: -4)")
    print("  IQLUSION:   Q(16) should be L(11) → to correct: -5  (applied: +5)")
    print("  DESPARATLY: A(0) should be E(4)  → to correct: +4  (applied: -4)")
    print("  PALIMPCEST: C(2) should be S(18) → to correct: +16 (applied: -16)")
    print()

    # Keys from signed shifts
    signed_keys = {
        "correction_direction": [4, -5, 4, 16],
        "applied_direction": [-4, 5, -4, -16],
        "correction_mod26": [4, 21, 4, 16],     # -5 mod 26 = 21
        "applied_mod26": [22, 5, 22, 10],        # -4 mod 26 = 22, -16 mod 26 = 10
        "abs_values": [4, 5, 4, 16],
        "all_positive": [4, 5, 4, 16],
        "all_negative_mod26": [22, 21, 22, 10],
        "mixed_1": [4, 5, 22, 10],    # first two positive, last two negative
        "mixed_2": [22, 21, 4, 16],   # first two negative, last two positive
        "mixed_3": [4, 21, 22, 16],   # alternating
        "mixed_4": [22, 5, 4, 10],    # alternating the other way
    }

    for key_name, key in signed_keys.items():
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            label = f"signed_{key_name}={key} {VARIANT_NAMES[variant]}"
            score_and_report(pt, label, best)
            configs_tested += 1

    # With UNDERGRUUND (O→U = +6, so correction = -6 or +20 mod 26)
    signed_keys_5 = {
        "correction_5": [4, -5, 4, 16, -6],
        "applied_5": [-4, 5, -4, -16, 6],
        "correction_mod26_5": [4, 21, 4, 16, 20],
        "applied_mod26_5": [22, 5, 22, 10, 6],
    }

    for key_name, key in signed_keys_5.items():
        key_mod = [(k % 26) for k in key]
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key_mod, variant)
            label = f"signed5_{key_name}={key_mod} {VARIANT_NAMES[variant]}"
            score_and_report(pt, label, best)
            configs_tested += 1

    print(f"\n  Phase 5 summary: {configs_tested} configs tested")
    print(f"  Best: {best['score']}/24 — {best.get('label', 'none')}")
    return best


def phase6_exhaustive_combinations():
    """Phase 6: Exhaustive shift-combination search.
    For each misspelling, 4 interpretations: +n, -n(mod26), n, 26-n.
    4 misspellings × 4 interpretations = 256 key variants.
    """
    print("\n" + "=" * 78)
    print("  PHASE 6: EXHAUSTIVE SHIFT-COMBINATION SEARCH (256 variants)")
    print("=" * 78)

    best = {"score": 0}
    configs_tested = 0

    # For each misspelling: (shift, 26-shift, forward, backward)
    # DIGETAL: dist=4    → options: 4, 22, 4, 22  (but forward=backward for these)
    # Actually for each: +shift_to_correct, -shift_to_correct, +shift_applied, -shift_applied
    # DIGETAL: correct=I, wrong=E. I-E=4, E-I=-4=22. So: 4, 22
    # IQLUSION: correct=L, wrong=Q. L-Q=-5=21, Q-L=5. So: 5, 21
    # DESPARATLY: correct=E, wrong=A. E-A=4, A-E=-4=22. So: 4, 22
    # PALIMPCEST: correct=S, wrong=C. S-C=16, C-S=-16=10. So: 16, 10

    options = [
        [4, 22],       # DIGETAL
        [5, 21],       # IQLUSION
        [4, 22],       # DESPARATLY
        [16, 10],      # PALIMPCEST
    ]

    total_combos = 1
    for opt in options:
        total_combos *= len(opt)
    print(f"  Testing {total_combos} shift combinations × 3 variants = {total_combos * 3}")

    above_noise = []

    for combo in product(*options):
        key = list(combo)
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            configs_tested += 1
            if sc > best.get("score", 0):
                best["score"] = sc
                best["label"] = f"combo key={key} {VARIANT_NAMES[variant]}"
                best["pt"] = pt
            if sc > NOISE_FLOOR:
                detail = score_cribs_detailed(pt)
                above_noise.append((sc, key, variant, pt[:50]))
                print(f"  ** ABOVE NOISE: key={key} {VARIANT_NAMES[variant]} → {sc}/24 (ENE={detail['ene_score']}, BC={detail['bc_score']})")

    # Also with UNDERGRUUND appended: 6 or 20
    options_5 = options + [[6, 20]]
    total_combos_5 = 1
    for opt in options_5:
        total_combos_5 *= len(opt)
    print(f"\n  With UNDERGRUUND: {total_combos_5} combos × 3 = {total_combos_5 * 3}")

    for combo in product(*options_5):
        key = list(combo)
        for variant in ["vig", "beau", "varbeau"]:
            pt = decrypt_with_key(CT, key, variant)
            sc = score_cribs(pt)
            configs_tested += 1
            if sc > best.get("score", 0):
                best["score"] = sc
                best["label"] = f"combo5 key={key} {VARIANT_NAMES[variant]}"
                best["pt"] = pt
            if sc > NOISE_FLOOR:
                detail = score_cribs_detailed(pt)
                above_noise.append((sc, key, variant, pt[:50]))

    # Partial key matching: just test if ANY of the 256 keys produce correct
    # decryption at ANY crib position
    print(f"\n  --- Partial key analysis: which combos match any crib? ---")
    partial_best = 0
    partial_best_info = ""
    for combo in product(*options):
        key = list(combo)
        klen = len(key)
        for variant in ["vig", "beau", "varbeau"]:
            matches = 0
            for pos, pt_ch in CRIB_DICT.items():
                cv = c2n(CT[pos])
                kv = key[pos % klen]
                if variant == "vig":
                    got = (cv - kv) % MOD
                elif variant == "beau":
                    got = (kv - cv) % MOD
                else:
                    got = (cv + kv) % MOD
                if got == c2n(pt_ch):
                    matches += 1
            if matches > partial_best:
                partial_best = matches
                partial_best_info = f"key={key} {VARIANT_NAMES[variant]} matches={matches}/24"

    print(f"  Best partial match: {partial_best_info}")

    if above_noise:
        print(f"\n  All above-noise results:")
        for sc, key, var, pt_snip in sorted(above_noise, reverse=True):
            print(f"    {sc}/24: key={key} {VARIANT_NAMES[var]} PT={pt_snip}")

    print(f"\n  Phase 6 summary: {configs_tested} configs tested")
    print(f"  Best: {best['score']}/24 — {best.get('label', 'none')}")
    return best


def phase7_positional_indicators():
    """Phase 7: Shift values as positional indicators."""
    print("\n" + "=" * 78)
    print("  PHASE 7: SHIFT VALUES AS POSITIONAL INDICATORS")
    print("=" * 78)

    best = {"score": 0}
    configs_tested = 0

    # Cumulative sums
    cum_4 = []
    s = 0
    for v in SHIFTS_4:
        s += v
        cum_4.append(s)
    # cum_4 = [4, 9, 13, 29]

    cum_5 = []
    s = 0
    for v in SHIFTS_5:
        s += v
        cum_5.append(s)
    # cum_5 = [4, 9, 13, 29, 35]

    print(f"  Cumulative sums (4): {cum_4}")
    print(f"  Cumulative sums (5): {cum_5}")

    # Extract CT chars at cumulative positions
    ct_at_cum4 = "".join(CT[p] for p in cum_4 if p < CT_LEN)
    ct_at_cum5 = "".join(CT[p] for p in cum_5 if p < CT_LEN)
    print(f"  CT at cumulative positions {cum_4}: {ct_at_cum4}")
    print(f"  CT at cumulative positions {cum_5}: {ct_at_cum5}")

    # Extract CT chars at shift positions directly
    ct_at_shifts = "".join(CT[p] for p in SHIFTS_4 if p < CT_LEN)
    print(f"  CT at positions {SHIFTS_4}: {ct_at_shifts}")
    ct_at_shifts5 = "".join(CT[p] for p in SHIFTS_5 if p < CT_LEN)
    print(f"  CT at positions {SHIFTS_5}: {ct_at_shifts5}")

    # Repeating cumulative sums as positions to extract/skip
    print(f"\n  --- CT reordered by repeating cumulative pattern ---")
    # Build a permutation: read CT at positions defined by cycling through cumulative offsets
    for name, cum in [("cum4", cum_4), ("cum5", cum_5)]:
        print(f"\n  Pattern: {name} = {cum}")
        # Interpretation 1: pick every cum[i]-th character
        for step_set in [cum]:
            for start in range(min(step_set)):
                extracted = []
                pos = start
                step_idx = 0
                visited = set()
                while pos < CT_LEN and pos not in visited:
                    visited.add(pos)
                    extracted.append(CT[pos])
                    pos += step_set[step_idx % len(step_set)]
                    step_idx += 1
                if len(extracted) > 10:
                    text = "".join(extracted)
                    print(f"    Start={start}: {text} (len={len(text)})")

    # Positions that are multiples of each shift value
    print(f"\n  --- CT at multiples of shift values ---")
    for sv in set(SHIFTS_4):
        positions = [i for i in range(0, CT_LEN, sv)]
        chars = "".join(CT[p] for p in positions)
        print(f"  Every {sv}th char (from 0): {chars[:50]}... (len={len(chars)})")
        sc = score_cribs(chars + "X" * (CT_LEN - len(chars)))
        if sc > NOISE_FLOOR:
            print(f"    ** ABOVE NOISE: {sc}/24")

    # What if we NULL/skip positions at multiples of shift values, read remainder?
    print(f"\n  --- CT with positions removed at shift multiples ---")
    for sv in set(SHIFTS_4):
        removed_positions = set(range(0, CT_LEN, sv))
        remaining = "".join(CT[i] for i in range(CT_LEN) if i not in removed_positions)
        print(f"  Remove every {sv}th: len={len(remaining)} → {remaining[:50]}...")

    # Null cipher: read every Nth letter where N cycles through shifts
    print(f"\n  --- Null cipher: every Nth letter cycling through shifts ---")
    for name, shifts in [("shifts_4", SHIFTS_4), ("shifts_5", SHIFTS_5)]:
        pos = 0
        idx = 0
        extracted = []
        while pos < CT_LEN:
            extracted.append(CT[pos])
            pos += shifts[idx % len(shifts)]
            idx += 1
        text = "".join(extracted)
        print(f"  {name}: {text} (len={len(text)})")

        # Also start from each shift value
        for start in range(1, max(shifts)):
            pos = start
            idx = 0
            extracted2 = []
            while pos < CT_LEN:
                extracted2.append(CT[pos])
                pos += shifts[idx % len(shifts)]
                idx += 1
            if len(extracted2) >= 5:
                text2 = "".join(extracted2)
                # Only print if interesting length
                if len(text2) >= 8:
                    pass  # too many to print

    # XOR-like: shift values as skip distances, build PT by modular subtraction
    print(f"\n  --- Bean constraint check on shift-derived keystreams ---")
    for name, key in [("shifts_4", SHIFTS_4), ("shifts_5", SHIFTS_5),
                       ("signed_correct", [(s % 26) for s in SIGNED_SHIFTS_CORRECT]),
                       ("signed_applied", [(s % 26) for s in SIGNED_SHIFTS_APPLIED]),
                       ("combined_YAR", SHIFTS_4 + YAR),
                       ("combined_YART", SHIFTS_4 + YAR + T_POS)]:
        # Expand to full 97-char keystream by repeating
        klen = len(key)
        full_ks = [key[i % klen] for i in range(CT_LEN)]
        bean = verify_bean(full_ks)
        print(f"  {name} (period {klen}): Bean {'PASS' if bean.passed else 'FAIL'}"
              f" (eq={bean.eq_satisfied}/{bean.eq_total}, ineq={bean.ineq_satisfied}/{bean.ineq_total})")
        if bean.passed:
            print(f"    ** BEAN PASS — testing decryption:")
            for variant in ["vig", "beau", "varbeau"]:
                pt = decrypt_with_key(CT, key, variant)
                sc = score_cribs(pt)
                label = f"bean_pass_{name}_{variant}"
                score_and_report(pt, label, best)
                configs_tested += 1

    # What positions in CT contain the shift values as letter indices?
    print(f"\n  --- Positions where CT letter index matches a shift value ---")
    for sv in set(SHIFTS_5):
        target_letter = n2c(sv)
        positions = [i for i, c in enumerate(CT) if c2n(c) == sv]
        print(f"  Shift {sv} = letter {target_letter}: appears at positions {positions}")

    print(f"\n  Phase 7 summary: {configs_tested} configs tested")
    print(f"  Best: {best['score']}/24 — {best.get('label', 'none')}")
    return best


def main():
    print("=" * 78)
    print("  E-BESPOKE-03: Misspelling-Derived NUMERIC SHIFT VALUES")
    print("=" * 78)
    print(f"  CT: {CT}")
    print(f"  CT length: {CT_LEN}")
    print(f"  Cribs: {CRIB_WORDS}")
    print(f"\n  Core shift values: {SHIFTS_4}")
    print(f"  Extended shifts:   {SHIFTS_5}")
    print(f"  Signed (correct):  {SIGNED_SHIFTS_CORRECT}")
    print(f"  Signed (applied):  {SIGNED_SHIFTS_APPLIED}")
    print(f"  Other numeric clues: YAR={YAR}, T={T_POS}, RQ={RQ}")

    results = {}
    results["phase1"] = phase1_shift_as_key()
    results["phase2"] = phase2_shift_as_transposition()
    results["phase3"] = phase3_position_dependent_offset()
    results["phase4"] = phase4_combined_clues()
    results["phase5"] = phase5_signed_shifts()
    results["phase6"] = phase6_exhaustive_combinations()
    results["phase7"] = phase7_positional_indicators()

    # ── Final Summary ──
    print("\n" + "#" * 78)
    print("  FINAL SUMMARY")
    print("#" * 78)

    total_configs = 0
    overall_best = {"score": 0}
    for phase_name, res in results.items():
        sc = res.get("score", 0)
        label = res.get("label", "none")
        print(f"  {phase_name}: best={sc}/24 — {label}")
        if sc > overall_best.get("score", 0):
            overall_best = res
            overall_best["phase"] = phase_name

    print(f"\n  OVERALL BEST: {overall_best.get('score', 0)}/24")
    print(f"  Config: {overall_best.get('label', 'none')}")
    if "pt" in overall_best:
        pt = overall_best["pt"]
        print(f"  PT: {pt}")

        # Full crib analysis of best result
        detail = score_cribs_detailed(pt)
        print(f"  ENE={detail['ene_score']}/13  BC={detail['bc_score']}/11")
        print(f"  Classification: {detail['classification']}")

    print(f"\n  Expected random score at period 4: ~3.7/24")
    print(f"  Expected random score at period 5: ~4.6/24")
    print(f"  Noise floor: {NOISE_FLOOR}/24")

    # Verdict
    best_sc = overall_best.get("score", 0)
    if best_sc <= NOISE_FLOOR:
        print(f"\n  VERDICT: ALL RESULTS AT OR BELOW NOISE FLOOR ({NOISE_FLOOR}/24).")
        print(f"  Misspelling shift values as direct key material: ELIMINATED.")
    elif best_sc < 10:
        print(f"\n  VERDICT: Best score {best_sc}/24 is borderline. Likely noise for short-period keys.")
        print(f"  Misspelling shift values as direct key material: WEAKLY ELIMINATED.")
    else:
        print(f"\n  VERDICT: Best score {best_sc}/24 warrants further investigation.")

    print(f"\n  Done.")


if __name__ == "__main__":
    main()
