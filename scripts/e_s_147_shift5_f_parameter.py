#!/usr/bin/env python3
"""E-S-147: Shift-5 (F-parameter) and anomaly-derived cipher models for K4.

K0/K1 deliberate anomalies have three letter substitutions:
  - I->E in DIGETAL:       shift = -4 (mod 26 = +22)
  - O->T in INTERPRETATIT: shift = +5
  - L->Q in IQLUSION:      shift = +5

Two of three share shift +5 (key letter F under Vigenere).

Additional anomaly-derived parameters:
  - Inserted (wrong) letters: E=4, T=19, Q=16
  - Superscript YAR at K3/K4 boundary: Y=24, A=0, R=17
  - ABSCISSA (K1 keyword): direct Vigenere/transposition key for K4

Models tested:
  A: F-shift as key modifier (constant/alternating/period-3)
  B: ETQ as positional parameters (grid indices, transposition key)
  C: YAR as starting parameters (rotation, offset, width-3 key)
  D: Combined shift models (shift + width-7 transposition)
  E: ABSCISSA as direct K4 key (Vigenere, transposition, combined)

Output: artifacts/e_s_147/
"""

import json
import os
import sys
import time
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR,
    CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, encrypt_text, CipherVariant,
    vig_decrypt, beau_decrypt, vig_encrypt,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'artifacts', 'e_s_147')
os.makedirs(RESULTS_DIR, exist_ok=True)

BEST_OVERALL = {"model": None, "score": 0, "detail": None}
ALL_RESULTS = {}


def update_best(model_name, score, detail):
    global BEST_OVERALL
    if score > BEST_OVERALL["score"]:
        BEST_OVERALL = {"model": model_name, "score": score, "detail": detail}


def shift_ct(ct_nums, shift_pattern):
    """Apply a shift pattern to CT numerically and return text."""
    plen = len(shift_pattern)
    result = []
    for i, c in enumerate(ct_nums):
        shifted = (c + shift_pattern[i % plen]) % MOD
        result.append(ALPH[shifted])
    return "".join(result)


def check_cribs(text, label=""):
    """Score text against cribs and return (score, detail_dict)."""
    detail = score_cribs_detailed(text)
    sc = detail["score"]
    return sc, detail


def keyword_to_ranked(keyword):
    """Convert keyword string to ranked column order, handling duplicates."""
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    ranked_list = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * len(keyword)
    for rank, (_, pos) in enumerate(ranked_list):
        order[pos] = rank
    return order


# =============================================================================
# MODEL A: F-shift as key modifier
# =============================================================================
def model_a():
    print("\n" + "=" * 70)
    print("MODEL A: F-shift as key modifier")
    print("=" * 70)

    results = {}
    best_a = {"model": None, "score": 0}

    # A1: Constant shift +5 and -5 on all positions (Vigenere decrypt)
    for shift_val in [5, -5, 22, -22, 4, -4]:
        label = f"A1_const_shift_{shift_val:+d}"
        pt = shift_ct(CT_NUM, [shift_val])
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "classification": det["classification"]}
        if sc > best_a["score"]:
            best_a = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24 [{det['classification']}]")
    print(f"  A1 constant shifts: best = {best_a['score']}/24")

    # A2: Alternating shifts: +5 on even, -4 on odd (and vice versa)
    alternating_patterns = [
        ([5, -4], "A2_alt_5_m4"),
        ([-4, 5], "A2_alt_m4_5"),
        ([5, 22], "A2_alt_5_22"),
        ([22, 5], "A2_alt_22_5"),
        ([-5, 4], "A2_alt_m5_4"),
        ([4, -5], "A2_alt_4_m5"),
    ]
    for pattern, label in alternating_patterns:
        pt = shift_ct(CT_NUM, pattern)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "classification": det["classification"]}
        if sc > best_a["score"]:
            best_a = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24 [{det['classification']}]")
    print(f"  A2 alternating shifts: best = {best_a['score']}/24")

    # A3: Period-3 shift patterns [+5, +5, -4] and permutations
    base_shifts = [5, 5, -4]
    for perm_shifts in itertools.permutations(base_shifts):
        label = f"A3_p3_{perm_shifts[0]:+d}_{perm_shifts[1]:+d}_{perm_shifts[2]:+d}"
        pt = shift_ct(CT_NUM, list(perm_shifts))
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "classification": det["classification"]}
        if sc > best_a["score"]:
            best_a = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24 [{det['classification']}]")

    # Also test with mod-26 equivalents
    base_shifts_mod = [5, 5, 22]
    for perm_shifts in itertools.permutations(base_shifts_mod):
        label = f"A3_p3m_{perm_shifts[0]:+d}_{perm_shifts[1]:+d}_{perm_shifts[2]:+d}"
        pt = shift_ct(CT_NUM, list(perm_shifts))
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "classification": det["classification"]}
        if sc > best_a["score"]:
            best_a = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24 [{det['classification']}]")

    # A4: Also test Beaufort decrypt with these shifts
    for shift_val in [5, -5, 22, -22, 4, -4]:
        label = f"A4_beaufort_shift_{shift_val:+d}"
        pt_chars = []
        for i, c in enumerate(CT_NUM):
            pt_chars.append(ALPH[beau_decrypt(c, shift_val % MOD)])
        pt = "".join(pt_chars)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "classification": det["classification"]}
        if sc > best_a["score"]:
            best_a = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24 [{det['classification']}]")

    print(f"  A overall best: {best_a['model']} = {best_a['score']}/24")
    update_best(best_a["model"], best_a["score"], results.get(best_a["model"]))
    ALL_RESULTS["model_a"] = {"best": best_a, "count": len(results), "results": results}
    return best_a


# =============================================================================
# MODEL B: ETQ as positional parameters
# =============================================================================
def model_b():
    print("\n" + "=" * 70)
    print("MODEL B: ETQ as positional parameters")
    print("=" * 70)

    results = {}
    best_b = {"model": None, "score": 0}

    # B1: ETQ positions (4, 19, 16) — fix plaintext at those positions
    # CT[4]=U, CT[19]=B, CT[16]=F
    etq_positions = [4, 19, 16]
    print(f"  CT at ETQ positions: {CT[4]}, {CT[19]}, {CT[16]}")

    # Test common trigrams at these positions
    common_trigrams = [
        "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
        "HER", "WAS", "ONE", "OUR", "OUT", "HAS", "HIS", "HOW",
        "ITS", "MAY", "NEW", "OLD", "SEE", "WAY", "WHO", "BOY",
        "DID", "GET", "HIM", "LET", "SAY", "SHE", "TOO", "USE",
        "DAD", "MOM", "ETQ", "KEY", "CIA", "NSA", "WAR", "SPY",
        "ART", "REM", "BER", "SEC", "RET", "HID", "DEN", "MES",
    ]
    for trig in common_trigrams:
        # Compute what Vigenere key would be at those 3 positions
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            label = f"B1_{trig}_{variant.value[:3]}"
            # No full plaintext to score — just check if key values are interesting
            keys_at = []
            for j, pos in enumerate(etq_positions):
                c = ALPH_IDX[CT[pos]]
                p = ALPH_IDX[trig[j]]
                if variant == CipherVariant.VIGENERE:
                    k = (c - p) % MOD
                else:
                    k = (c + p) % MOD
                keys_at.append(k)
            results[label] = {"keys": keys_at, "key_letters": [ALPH[k] for k in keys_at]}

    print(f"  B1: Tested {len(common_trigrams)} trigrams x 2 variants = {len(common_trigrams)*2} key extractions")

    # B2: ETQ as column indices in width-20 grid
    for width in [20, 26, 10, 13, 16, 19]:
        # Use columns 4, 19, 16 (mod width) as reading start
        label = f"B2_w{width}_etq_cols"
        # Read CT into grid of given width, then read columns [4,16,19,...rest]
        cols_order = []
        etq_mod = [e % width for e in etq_positions]
        # Start with ETQ columns, then fill rest
        used = set(etq_mod)
        cols_order = list(etq_mod)
        for c in range(width):
            if c not in used:
                cols_order.append(c)
        # Build columnar perm from this order
        try:
            perm = columnar_perm(width, cols_order, CT_LEN)
            if validate_perm(perm, CT_LEN):
                inv = invert_perm(perm)
                pt = apply_perm(CT, inv)
                sc, det = check_cribs(pt, label)
                results[label] = {"score": sc, "width": width}
                if sc > best_b["score"]:
                    best_b = {"model": label, "score": sc}
                if sc > NOISE_FLOOR:
                    print(f"  {label}: {sc}/24")
        except Exception:
            pass

    # B3: ETQ ranked [0,2,1] as width-3 transposition key
    etq_orderings = [
        ([0, 2, 1], "ETQ_021"),
        ([1, 0, 2], "ETQ_102"),
        ([1, 2, 0], "ETQ_120"),
        ([2, 0, 1], "ETQ_201"),
        ([2, 1, 0], "ETQ_210"),
        ([0, 1, 2], "ETQ_012"),
    ]
    for order, name in etq_orderings:
        # Width-3 columnar transposition
        label = f"B3_{name}_w3"
        perm = columnar_perm(3, order, CT_LEN)
        if validate_perm(perm, CT_LEN):
            inv = invert_perm(perm)
            pt = apply_perm(CT, inv)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            if sc > best_b["score"]:
                best_b = {"model": label, "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  {label}: {sc}/24")

        # Also try: apply transposition then check if shift+5 helps
        label2 = f"B3_{name}_w3_then_shift5"
        pt_shifted = shift_ct([ALPH_IDX[c] for c in pt], [5])
        sc2, det2 = check_cribs(pt_shifted, label2)
        results[label2] = {"score": sc2}
        if sc2 > best_b["score"]:
            best_b = {"model": label2, "score": sc2}
        if sc2 > NOISE_FLOOR:
            print(f"  {label2}: {sc2}/24")

    print(f"  B overall best: {best_b['model']} = {best_b['score']}/24")
    update_best(best_b["model"], best_b["score"], results.get(best_b["model"]))
    ALL_RESULTS["model_b"] = {"best": best_b, "count": len(results), "results": {k: v for k, v in results.items() if isinstance(v, dict) and v.get("score", 0) > 0}}
    return best_b


# =============================================================================
# MODEL C: YAR as starting parameters
# =============================================================================
def model_c():
    print("\n" + "=" * 70)
    print("MODEL C: YAR as starting parameters")
    print("=" * 70)

    results = {}
    best_c = {"model": None, "score": 0}

    # C1: Begin decryption at position 24 (Y), wrapping around
    # CT[24:] + CT[:24] — then check cribs at adjusted positions
    for start_pos in [24, 17, 0]:  # Y=24, R=17, A=0
        rotated = CT[start_pos:] + CT[:start_pos]
        label = f"C1_rotate_start_{start_pos}"
        # Cribs would be at different positions now — need to adjust
        # Original cribs: 21-33 (ENE), 63-73 (BC)
        # After rotation by start_pos: new_pos = (orig_pos - start_pos) % 97
        adjusted_crib = {}
        for pos, ch in CRIB_DICT.items():
            new_pos = (pos - start_pos) % CT_LEN
            adjusted_crib[new_pos] = ch

        # Count matches
        matches = sum(1 for p, c in adjusted_crib.items() if p < len(rotated) and rotated[p] == c)
        results[label] = {"score": matches, "start": start_pos}
        if matches > best_c["score"]:
            best_c = {"model": label, "score": matches}
        if matches > NOISE_FLOOR:
            print(f"  {label}: {matches}/24")

    # C2: Rotate CT by R=17 positions, then apply various shifts
    for rotation in [17, 24, 0, 7]:  # R, Y, A, and H (from missing WHAION)
        rotated = CT[rotation:] + CT[:rotation]
        for shift_val in [0, 5, -5, 22, -22]:
            label = f"C2_rot{rotation}_shift{shift_val:+d}"
            if shift_val == 0:
                pt = rotated
            else:
                pt = shift_ct([ALPH_IDX[c] for c in rotated], [shift_val])
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            if sc > best_c["score"]:
                best_c = {"model": label, "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  {label}: {sc}/24")

    # C3: YAR = [24, 0, 17] as width-3 transposition key
    yar_orderings = [
        ([2, 0, 1], "YAR_ranked"),   # Y=24->2, A=0->0, R=17->1
        ([1, 0, 2], "YAR_102"),
        ([0, 2, 1], "YAR_021"),
    ]
    for order, name in yar_orderings:
        label = f"C3_{name}_w3"
        perm = columnar_perm(3, order, CT_LEN)
        if validate_perm(perm, CT_LEN):
            inv = invert_perm(perm)
            pt = apply_perm(CT, inv)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            if sc > best_c["score"]:
                best_c = {"model": label, "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  {label}: {sc}/24")

    # C4: YAR as first 3 values of key [24, 0, 17] repeating
    yar_key = [24, 0, 17]
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
        label = f"C4_YAR_key_{variant.value[:3]}"
        pt = decrypt_text(CT, yar_key, variant)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc}
        if sc > best_c["score"]:
            best_c = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24")

    # C5: YAR as key modifier: add [24, 0, 17] to standard Vigenere keystream
    # (i.e., key = YAR repeating as the underlying key)
    for perm_yar in itertools.permutations(yar_key):
        label = f"C5_YAR_perm_{perm_yar[0]}_{perm_yar[1]}_{perm_yar[2]}"
        pt = decrypt_text(CT, list(perm_yar), CipherVariant.VIGENERE)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc}
        if sc > best_c["score"]:
            best_c = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24")

    print(f"  C overall best: {best_c['model']} = {best_c['score']}/24")
    update_best(best_c["model"], best_c["score"], results.get(best_c["model"]))
    ALL_RESULTS["model_c"] = {"best": best_c, "count": len(results)}
    return best_c


# =============================================================================
# MODEL D: Combined shift + width-7 transposition
# =============================================================================
def model_d():
    print("\n" + "=" * 70)
    print("MODEL D: Combined shift + width-7 transposition")
    print("=" * 70)

    results = {}
    best_d = {"model": None, "score": 0}

    # Candidate width-7 transposition keys (anomaly-derived from team lead)
    w7_keys = [
        ([2, 5, 4, 6, 1, 0, 3], "WHAIONL_ranked"),
        ([6, 1, 0, 2, 5, 4, 3], "WHAIONL_alt"),
        ([3, 0, 1, 5, 4, 6, 2], "inv_WHAIONL"),
    ]

    # Also generate all permutations of a few promising shift patterns
    shift_patterns = [
        ([5], "shift_p5"),
        ([-5], "shift_m5"),
        ([22], "shift_p22"),
        ([5, 5, -4], "shift_5_5_m4"),
        ([-4, 5, 5], "shift_m4_5_5"),
        ([5, -4, 5], "shift_5_m4_5"),
        ([24, 0, 17], "shift_YAR"),
    ]

    total_configs = 0
    for w7_order, w7_name in w7_keys:
        perm = columnar_perm(7, w7_order, CT_LEN)
        if not validate_perm(perm, CT_LEN):
            continue
        inv = invert_perm(perm)

        for shift_pat, shift_name in shift_patterns:
            # Direction 1: transposition THEN shift
            label = f"D_trans_{w7_name}_then_{shift_name}"
            pt_trans = apply_perm(CT, inv)
            pt = shift_ct([ALPH_IDX[c] for c in pt_trans], shift_pat)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            total_configs += 1
            if sc > best_d["score"]:
                best_d = {"model": label, "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  {label}: {sc}/24")

            # Direction 2: shift THEN transposition
            label2 = f"D_{shift_name}_then_trans_{w7_name}"
            pt_shifted = shift_ct(CT_NUM, shift_pat)
            pt2 = apply_perm(pt_shifted, inv)
            sc2, det2 = check_cribs(pt2, label2)
            results[label2] = {"score": sc2}
            total_configs += 1
            if sc2 > best_d["score"]:
                best_d = {"model": label2, "score": sc2}
            if sc2 > NOISE_FLOOR:
                print(f"  {label2}: {sc2}/24")

            # Direction 3: Vigenere decrypt with shift as key, after transposition
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                label3 = f"D_trans_{w7_name}_then_vig_{shift_name}_{variant.value[:3]}"
                pt_trans2 = apply_perm(CT, inv)
                pt3 = decrypt_text(pt_trans2, shift_pat, variant)
                sc3, det3 = check_cribs(pt3, label3)
                results[label3] = {"score": sc3}
                total_configs += 1
                if sc3 > best_d["score"]:
                    best_d = {"model": label3, "score": sc3}
                if sc3 > NOISE_FLOOR:
                    print(f"  {label3}: {sc3}/24")

    print(f"  D: tested {total_configs} configs")
    print(f"  D overall best: {best_d['model']} = {best_d['score']}/24")
    update_best(best_d["model"], best_d["score"], results.get(best_d["model"]))
    ALL_RESULTS["model_d"] = {"best": best_d, "count": total_configs}
    return best_d


# =============================================================================
# MODEL E: ABSCISSA as direct K4 key
# =============================================================================
def model_e():
    print("\n" + "=" * 70)
    print("MODEL E: ABSCISSA as direct K4 key")
    print("=" * 70)

    results = {}
    best_e = {"model": None, "score": 0}

    # ABSCISSA as numeric key
    abscissa = "ABSCISSA"
    abscissa_key = [ALPH_IDX[c] for c in abscissa]  # [0,1,18,2,8,18,18,0]
    print(f"  ABSCISSA key: {abscissa_key}")

    # E1: ABSCISSA as Vigenere/Beaufort key (period 8)
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        label = f"E1_ABSCISSA_{variant.value}"
        pt = decrypt_text(CT, abscissa_key, variant)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "plaintext_sample": pt[:30]}
        if sc > best_e["score"]:
            best_e = {"model": label, "score": sc}
        print(f"  {label}: {sc}/24 — PT[:30]={pt[:30]}")

    # E2: ABSCISSA as transposition key (width-8)
    # ABSCISSA = A(0) B(1) S(18) C(2) I(8) S(18) S(18) A(0)
    # Ranked with duplicate handling: A=0, A=0, B=1, C=2, I=8, S=18, S=18, S=18
    # Sort by (value, position): (A,0)->0, (B,1)->1, (S,2)->5, (C,3)->2, (I,4)->3, (S,5)->6, (S,6)->7, (A,7)->4...
    # Actually rank properly:
    abscissa_ranked = keyword_to_ranked(abscissa)
    print(f"  ABSCISSA ranked: {abscissa_ranked}")  # Should handle duplicate S and A

    label = "E2_ABSCISSA_w8_columnar"
    try:
        perm = columnar_perm(8, abscissa_ranked, CT_LEN)
        if validate_perm(perm, CT_LEN):
            inv = invert_perm(perm)
            pt = apply_perm(CT, inv)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc, "ranked": abscissa_ranked}
            if sc > best_e["score"]:
                best_e = {"model": label, "score": sc}
            print(f"  {label}: {sc}/24")
    except Exception as e:
        print(f"  {label}: ERROR {e}")

    # E3: ABSCISSA + PALIMPSEST combined (K3-style)
    palimpsest = "PALIMPSEST"
    palimpsest_key = [ALPH_IDX[c] for c in palimpsest]
    kryptos = "KRYPTOS"
    kryptos_key = [ALPH_IDX[c] for c in kryptos]

    # E3a: Transpose with ABSCISSA, then Vigenere with PALIMPSEST
    if validate_perm(perm, CT_LEN):
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            label = f"E3a_trans_ABSCISSA_vig_PALIMPSEST_{variant.value[:3]}"
            pt_trans = apply_perm(CT, inv)
            pt = decrypt_text(pt_trans, palimpsest_key, variant)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            if sc > best_e["score"]:
                best_e = {"model": label, "score": sc}
            print(f"  {label}: {sc}/24")

    # E3b: Vigenere with PALIMPSEST, then transpose with ABSCISSA
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
        label = f"E3b_vig_PALIMPSEST_trans_ABSCISSA_{variant.value[:3]}"
        pt_sub = decrypt_text(CT, palimpsest_key, variant)
        if validate_perm(perm, CT_LEN):
            pt = apply_perm(pt_sub, inv)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            if sc > best_e["score"]:
                best_e = {"model": label, "score": sc}
            print(f"  {label}: {sc}/24")

    # E4: ABSCISSA + KRYPTOS combined
    # Transpose with KRYPTOS (width-7), then Vigenere with ABSCISSA
    kryptos_ranked = keyword_to_ranked(kryptos)
    print(f"  KRYPTOS ranked: {kryptos_ranked}")

    try:
        perm_k = columnar_perm(7, kryptos_ranked, CT_LEN)
        if validate_perm(perm_k, CT_LEN):
            inv_k = invert_perm(perm_k)
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                # Trans KRYPTOS then Vig ABSCISSA
                label = f"E4a_trans_KRYPTOS_vig_ABSCISSA_{variant.value[:3]}"
                pt_trans = apply_perm(CT, inv_k)
                pt = decrypt_text(pt_trans, abscissa_key, variant)
                sc, det = check_cribs(pt, label)
                results[label] = {"score": sc}
                if sc > best_e["score"]:
                    best_e = {"model": label, "score": sc}
                print(f"  {label}: {sc}/24")

                # Vig ABSCISSA then trans KRYPTOS
                label2 = f"E4b_vig_ABSCISSA_trans_KRYPTOS_{variant.value[:3]}"
                pt_sub = decrypt_text(CT, abscissa_key, variant)
                pt2 = apply_perm(pt_sub, inv_k)
                sc2, det2 = check_cribs(pt2, label2)
                results[label2] = {"score": sc2}
                if sc2 > best_e["score"]:
                    best_e = {"model": label2, "score": sc2}
                print(f"  {label2}: {sc2}/24")

                # Trans KRYPTOS then Vig PALIMPSEST
                label3 = f"E4c_trans_KRYPTOS_vig_PALIMPSEST_{variant.value[:3]}"
                pt_trans2 = apply_perm(CT, inv_k)
                pt3 = decrypt_text(pt_trans2, palimpsest_key, variant)
                sc3, det3 = check_cribs(pt3, label3)
                results[label3] = {"score": sc3}
                if sc3 > best_e["score"]:
                    best_e = {"model": label3, "score": sc3}
                print(f"  {label3}: {sc3}/24")
    except Exception as e:
        print(f"  E4 KRYPTOS: ERROR {e}")

    # E5: ABSCISSA + shift-5 combined
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
        label = f"E5_ABSCISSA_shift5_{variant.value[:3]}"
        # Add 5 to each ABSCISSA key value
        modified_key = [(k + 5) % MOD for k in abscissa_key]
        pt = decrypt_text(CT, modified_key, variant)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "modified_key": modified_key}
        if sc > best_e["score"]:
            best_e = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24")

    # E6: Full permutation of ABSCISSA column orderings (8! = 40320, feasible)
    print("  E6: Testing all 8! = 40320 ABSCISSA width-8 column orderings...")
    e6_best = 0
    e6_best_order = None
    for col_order in itertools.permutations(range(8)):
        perm8 = columnar_perm(8, list(col_order), CT_LEN)
        if not validate_perm(perm8, CT_LEN):
            continue
        inv8 = invert_perm(perm8)
        pt = apply_perm(CT, inv8)
        sc = score_cribs(pt)
        if sc > e6_best:
            e6_best = sc
            e6_best_order = list(col_order)
        if sc > NOISE_FLOOR:
            # Also try with Vigenere ABSCISSA after transposition
            for var_name, var in [("vig", CipherVariant.VIGENERE), ("beau", CipherVariant.BEAUFORT)]:
                pt2 = decrypt_text(pt, abscissa_key, var)
                sc2 = score_cribs(pt2)
                if sc2 > e6_best:
                    e6_best = sc2
                    e6_best_order = list(col_order)
                    print(f"    E6 w8 col_order={list(col_order)} + {var_name}_ABSCISSA: {sc2}/24")

    results["E6_w8_all_orderings"] = {"best_score": e6_best, "best_order": e6_best_order}
    print(f"  E6: best width-8 columnar = {e6_best}/24, order = {e6_best_order}")
    if e6_best > best_e["score"]:
        best_e = {"model": "E6_w8_all_orderings", "score": e6_best}

    print(f"  E overall best: {best_e['model']} = {best_e['score']}/24")
    update_best(best_e["model"], best_e["score"], results.get(best_e["model"]))
    ALL_RESULTS["model_e"] = {"best": best_e, "count": len(results)}
    return best_e


# =============================================================================
# MODEL F: Exhaustive shift + width-7 all orderings
# =============================================================================
def model_f():
    print("\n" + "=" * 70)
    print("MODEL F: All width-7 orderings + shift-5 / shift-22")
    print("=" * 70)

    results = {}
    best_f = {"model": None, "score": 0}

    shifts_to_test = [5, -5, 22, -22]
    total = 0

    for col_order in itertools.permutations(range(7)):
        perm7 = columnar_perm(7, list(col_order), CT_LEN)
        if not validate_perm(perm7, CT_LEN):
            continue
        inv7 = invert_perm(perm7)

        # Pure transposition
        pt_trans = apply_perm(CT, inv7)
        sc0 = score_cribs(pt_trans)
        total += 1
        if sc0 > best_f["score"]:
            best_f = {"model": f"F_w7_{list(col_order)}_pure", "score": sc0}

        # Transposition then shift
        for shift_val in shifts_to_test:
            pt = shift_ct([ALPH_IDX[c] for c in pt_trans], [shift_val])
            sc = score_cribs(pt)
            total += 1
            if sc > best_f["score"]:
                best_f = {"model": f"F_w7_{list(col_order)}_then_shift{shift_val:+d}", "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  w7={list(col_order)} + shift{shift_val:+d}: {sc}/24")

        # Shift then transposition
        for shift_val in shifts_to_test:
            pt_shifted = shift_ct(CT_NUM, [shift_val])
            pt = apply_perm(pt_shifted, inv7)
            sc = score_cribs(pt)
            total += 1
            if sc > best_f["score"]:
                best_f = {"model": f"F_shift{shift_val:+d}_then_w7_{list(col_order)}", "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  shift{shift_val:+d} + w7={list(col_order)}: {sc}/24")

    print(f"  F: tested {total} configs")
    print(f"  F overall best: {best_f['model']} = {best_f['score']}/24")
    update_best(best_f["model"], best_f["score"], None)
    ALL_RESULTS["model_f"] = {"best": best_f, "count": total}
    return best_f


# =============================================================================
# MAIN
# =============================================================================
def main():
    t0 = time.time()
    print("E-S-147: Shift-5 (F-parameter) and anomaly-derived cipher models")
    print(f"CT = {CT}")
    print(f"CT length = {CT_LEN}")
    print(f"Noise floor = {NOISE_FLOOR}")
    print()

    # Verify baseline: score raw CT against cribs (self-encrypting positions only)
    baseline_sc, baseline_det = check_cribs(CT)
    print(f"Baseline (raw CT vs cribs): {baseline_sc}/24")
    print(f"  Self-encrypting: CT[32]={CT[32]} (crib S), CT[73]={CT[73]} (crib K)")

    results_a = model_a()
    results_b = model_b()
    results_c = model_c()
    results_d = model_d()
    results_e = model_e()
    results_f = model_f()

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Time: {elapsed:.1f}s")
    print()
    for model_key in ["model_a", "model_b", "model_c", "model_d", "model_e", "model_f"]:
        if model_key in ALL_RESULTS:
            b = ALL_RESULTS[model_key]["best"]
            cnt = ALL_RESULTS[model_key].get("count", "?")
            print(f"  {model_key}: best={b['score']}/24, model={b['model']}, configs={cnt}")

    print()
    print(f"OVERALL BEST: {BEST_OVERALL['model']} = {BEST_OVERALL['score']}/24")
    print(f"Noise floor = {NOISE_FLOOR}")

    if BEST_OVERALL["score"] <= NOISE_FLOOR:
        print("VERDICT: ALL NOISE — no anomaly-derived shift/key parameter produces signal")
    elif BEST_OVERALL["score"] < 18:
        print("VERDICT: STORED — some above-noise results but no signal")
    else:
        print("VERDICT: SIGNAL — investigate further!")

    # Save results
    output = {
        "experiment": "E-S-147",
        "description": "Shift-5 (F-parameter) and anomaly-derived cipher models",
        "elapsed_seconds": elapsed,
        "best_overall": BEST_OVERALL,
        "model_summaries": {k: {"best": v["best"], "count": v.get("count", 0)} for k, v in ALL_RESULTS.items()},
        "noise_floor": NOISE_FLOOR,
    }
    out_path = os.path.join(RESULTS_DIR, "e_s_147_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
