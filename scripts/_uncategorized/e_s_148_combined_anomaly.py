#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-148: Combined anomaly-derived cipher models for K4.

Tests anomaly parameters in combination:

1. REMOVED LETTERS AS RUNNING KEY SEED
   The 7 removed letters W,H,A,I,O,N,L (values 22,7,0,8,14,13,11):
   a. First 7 values of autokey (plaintext-feedback extension)
   b. Keyword for keyed alphabet + Vigenere with PALIMPSEST/ABSCISSA/KRYPTOS
   c. Period-7 repeating key (baseline, no transposition)

2. REMOVED LETTERS + YAR COMBINED
   a. YAR(24,0,17) + WHAIONL(22,7,0,8,14,13,11) = 10-value key (period 10)
   b. WHAIONL + YAR = different 10-value key

3. CUTTING MODEL (ABSCISSA = "cut off")
   a. Cut CT at ETQ positions (4,19,16), rearrange segments, apply substitution
   b. Cut CT at YAR positions (24,0,17), rearrange segments, apply substitution

Output: artifacts/e_s_148/
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
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, CipherVariant, vig_decrypt, beau_decrypt, varbeau_decrypt,
    DECRYPT_FN,
)
from kryptos.kernel.alphabet import (
    keyword_mixed_alphabet, make_alphabet, Alphabet, AZ, KA,
)
from kryptos.kernel.constraints.bean import verify_bean

CT_NUM = [ALPH_IDX[c] for c in CT]
RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'artifacts', 'e_s_148')
os.makedirs(RESULTS_DIR, exist_ok=True)

BEST_OVERALL = {"model": None, "score": 0, "detail": None}
ALL_RESULTS = {}

# Anomaly-derived constants
WHAIONL_VALS = [22, 7, 0, 8, 14, 13, 11]  # W=22, H=7, A=0, I=8, O=14, N=13, L=11
WHAIONL_STR = "WHAIONL"
YAR_VALS = [24, 0, 17]  # Y=24, A=0, R=17
ETQ_POSITIONS = [4, 19, 16]  # insertion positions of E, T, Q


def update_best(model_name, score, detail=None):
    global BEST_OVERALL
    if score > BEST_OVERALL["score"]:
        BEST_OVERALL = {"model": model_name, "score": score, "detail": detail}


def check_cribs(text, label=""):
    detail = score_cribs_detailed(text)
    return detail["score"], detail


# =============================================================================
# AUTOKEY CIPHER IMPLEMENTATIONS
# =============================================================================

def autokey_decrypt_vigenere(ct, primer):
    """Vigenere autokey decrypt: key extends with recovered plaintext.

    Decrypt: P[i] = (C[i] - K[i]) mod 26
    Key extension: K[i] = P[i - len(primer)] for i >= len(primer)
    """
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        c_val = ALPH_IDX[c]
        k_val = key[i] if i < len(key) else pt[i - len(primer)]
        p_val = (c_val - k_val) % MOD
        pt.append(p_val)
    return "".join(ALPH[p] for p in pt)


def autokey_decrypt_beaufort(ct, primer):
    """Beaufort autokey decrypt: P = (K - C) mod 26, key extends with plaintext."""
    pt = []
    key = list(primer)
    for i, c in enumerate(ct):
        c_val = ALPH_IDX[c]
        k_val = key[i] if i < len(key) else pt[i - len(primer)]
        p_val = (k_val - c_val) % MOD
        pt.append(p_val)
    return "".join(ALPH[p] for p in pt)


def autokey_decrypt_ciphertext_feedback(ct, primer):
    """Autokey with ciphertext feedback: key extends with CT values.

    Key extension: K[i] = C[i - len(primer)] for i >= len(primer)
    """
    ct_vals = [ALPH_IDX[c] for c in ct]
    pt = []
    for i in range(len(ct)):
        if i < len(primer):
            k_val = primer[i]
        else:
            k_val = ct_vals[i - len(primer)]
        p_val = (ct_vals[i] - k_val) % MOD
        pt.append(ALPH[p_val])
    return "".join(pt)


# =============================================================================
# MODEL 1: REMOVED LETTERS AS RUNNING KEY SEED
# =============================================================================
def model_1():
    print("\n" + "=" * 70)
    print("MODEL 1: Removed letters (WHAIONL) as running key seed")
    print("=" * 70)
    print(f"  WHAIONL values: {WHAIONL_VALS}")
    print(f"  WHAIONL as letters: {[ALPH[v] for v in WHAIONL_VALS]}")

    results = {}
    best = {"model": None, "score": 0}

    # 1a: Autokey with WHAIONL as primer (plaintext feedback)
    print("\n  --- 1a: Autokey (plaintext feedback) ---")
    label = "1a_autokey_vig_WHAIONL"
    pt = autokey_decrypt_vigenere(CT, WHAIONL_VALS)
    sc, det = check_cribs(pt, label)
    results[label] = {"score": sc, "pt_sample": pt[:40]}
    if sc > best["score"]:
        best = {"model": label, "score": sc}
    print(f"  {label}: {sc}/24 — PT[:40]={pt[:40]}")

    label = "1a_autokey_beau_WHAIONL"
    pt = autokey_decrypt_beaufort(CT, WHAIONL_VALS)
    sc, det = check_cribs(pt, label)
    results[label] = {"score": sc, "pt_sample": pt[:40]}
    if sc > best["score"]:
        best = {"model": label, "score": sc}
    print(f"  {label}: {sc}/24 — PT[:40]={pt[:40]}")

    label = "1a_autokey_ctfb_WHAIONL"
    pt = autokey_decrypt_ciphertext_feedback(CT, WHAIONL_VALS)
    sc, det = check_cribs(pt, label)
    results[label] = {"score": sc, "pt_sample": pt[:40]}
    if sc > best["score"]:
        best = {"model": label, "score": sc}
    print(f"  {label}: {sc}/24 — PT[:40]={pt[:40]}")

    # Also try all 6 permutations of the autokey primer approach that reorder WHAIONL
    # (7! = 5040 is feasible but overkill for autokey — test a few meaningful orderings)
    alt_orderings = [
        (list(reversed(WHAIONL_VALS)), "rev_WHAIONL"),
        (sorted(WHAIONL_VALS), "sorted_WHAIONL"),
        (sorted(WHAIONL_VALS, reverse=True), "rsorted_WHAIONL"),
        ([0, 7, 8, 11, 13, 14, 22], "alpha_AHILNOW"),  # alphabetical by letter
        ([13, 14, 22, 0, 8, 11, 7], "NOWAHLIH"),  # shifted grouping
    ]
    for vals, name in alt_orderings:
        for ak_fn, ak_name in [(autokey_decrypt_vigenere, "vig"), (autokey_decrypt_beaufort, "beau")]:
            label = f"1a_autokey_{ak_name}_{name}"
            pt = ak_fn(CT, vals)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            if sc > best["score"]:
                best = {"model": label, "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  {label}: {sc}/24")

    print(f"  1a best: {best['score']}/24")

    # 1b: WHAIONL as keyword for keyed alphabet + Vigenere with known keywords
    print("\n  --- 1b: WHAIONL-keyed alphabet + known keyword substitution ---")
    whaionl_alpha = keyword_mixed_alphabet(WHAIONL_STR)
    print(f"  WHAIONL-keyed alphabet: {whaionl_alpha}")
    whaionl_alph = Alphabet("WHAIONL", whaionl_alpha)

    known_keywords = ["PALIMPSEST", "ABSCISSA", "KRYPTOS", "BERLINCLOCK", "EASTNORTHEAST"]
    for kw in known_keywords:
        kw_key = [ALPH_IDX[c] for c in kw]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            # Decrypt using WHAIONL-keyed alphabet for CT lookup, standard for PT
            label = f"1b_WHAIONL_alpha_{kw}_{variant.value[:3]}"
            # Map CT through keyed alphabet index, then decrypt
            ct_in_keyed = [whaionl_alph.char_to_idx(c) for c in CT]
            dec_fn = DECRYPT_FN[variant]
            pt_vals = []
            klen = len(kw_key)
            for i in range(CT_LEN):
                pt_vals.append(dec_fn(ct_in_keyed[i], kw_key[i % klen]))
            pt = "".join(ALPH[v % MOD] for v in pt_vals)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            if sc > best["score"]:
                best = {"model": label, "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  {label}: {sc}/24")

            # Also: standard CT index, keyed alphabet for PT output
            label2 = f"1b_std_ct_WHAIONL_pt_{kw}_{variant.value[:3]}"
            pt_vals2 = []
            for i in range(CT_LEN):
                p_idx = dec_fn(CT_NUM[i], kw_key[i % klen])
                pt_vals2.append(whaionl_alph.idx_to_char(p_idx))
            pt2 = "".join(pt_vals2)
            sc2, det2 = check_cribs(pt2, label2)
            results[label2] = {"score": sc2}
            if sc2 > best["score"]:
                best = {"model": label2, "score": sc2}
            if sc2 > NOISE_FLOOR:
                print(f"  {label2}: {sc2}/24")

            # Also: keyed alphabet for both CT and PT
            label3 = f"1b_WHAIONL_both_{kw}_{variant.value[:3]}"
            pt_vals3 = []
            for i in range(CT_LEN):
                p_idx = dec_fn(ct_in_keyed[i], kw_key[i % klen])
                pt_vals3.append(whaionl_alph.idx_to_char(p_idx))
            pt3 = "".join(pt_vals3)
            sc3, det3 = check_cribs(pt3, label3)
            results[label3] = {"score": sc3}
            if sc3 > best["score"]:
                best = {"model": label3, "score": sc3}
            if sc3 > NOISE_FLOOR:
                print(f"  {label3}: {sc3}/24")

    print(f"  1b best: {best['score']}/24")

    # 1c: Period-7 repeating key (WHAIONL as periodic Vigenere, no transposition)
    print("\n  --- 1c: WHAIONL as period-7 repeating key ---")
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        label = f"1c_periodic7_WHAIONL_{variant.value[:3]}"
        pt = decrypt_text(CT, WHAIONL_VALS, variant)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "pt_sample": pt[:40]}
        if sc > best["score"]:
            best = {"model": label, "score": sc}
        print(f"  {label}: {sc}/24 — PT[:40]={pt[:40]}")

    # Also reversed
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
        label = f"1c_periodic7_revWHAIONL_{variant.value[:3]}"
        pt = decrypt_text(CT, list(reversed(WHAIONL_VALS)), variant)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc}
        if sc > best["score"]:
            best = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24")

    print(f"\n  Model 1 overall best: {best['model']} = {best['score']}/24")
    update_best(best["model"], best["score"])
    ALL_RESULTS["model_1"] = {"best": best, "count": len(results)}
    return best


# =============================================================================
# MODEL 2: REMOVED LETTERS + YAR COMBINED
# =============================================================================
def model_2():
    print("\n" + "=" * 70)
    print("MODEL 2: Removed letters + YAR combined (period-10 keys)")
    print("=" * 70)

    results = {}
    best = {"model": None, "score": 0}

    # 2a: YAR + WHAIONL = [24,0,17, 22,7,0,8,14,13,11] (10 values, same period as PALIMPSEST)
    yar_whaionl = YAR_VALS + WHAIONL_VALS
    print(f"  YAR+WHAIONL key (period 10): {yar_whaionl}")
    print(f"  As letters: {''.join(ALPH[v] for v in yar_whaionl)}")

    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        label = f"2a_YAR_WHAIONL_p10_{variant.value[:3]}"
        pt = decrypt_text(CT, yar_whaionl, variant)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "pt_sample": pt[:40]}
        if sc > best["score"]:
            best = {"model": label, "score": sc}
        print(f"  {label}: {sc}/24 — PT[:40]={pt[:40]}")

    # 2a autokey: YAR+WHAIONL as autokey primer
    for ak_fn, ak_name in [(autokey_decrypt_vigenere, "vig"), (autokey_decrypt_beaufort, "beau"),
                            (autokey_decrypt_ciphertext_feedback, "ctfb")]:
        label = f"2a_autokey_{ak_name}_YAR_WHAIONL"
        pt = ak_fn(CT, yar_whaionl)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc}
        if sc > best["score"]:
            best = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24")

    # 2b: WHAIONL + YAR = [22,7,0,8,14,13,11, 24,0,17]
    whaionl_yar = WHAIONL_VALS + YAR_VALS
    print(f"\n  WHAIONL+YAR key (period 10): {whaionl_yar}")
    print(f"  As letters: {''.join(ALPH[v] for v in whaionl_yar)}")

    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        label = f"2b_WHAIONL_YAR_p10_{variant.value[:3]}"
        pt = decrypt_text(CT, whaionl_yar, variant)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc, "pt_sample": pt[:40]}
        if sc > best["score"]:
            best = {"model": label, "score": sc}
        print(f"  {label}: {sc}/24 — PT[:40]={pt[:40]}")

    # 2b autokey
    for ak_fn, ak_name in [(autokey_decrypt_vigenere, "vig"), (autokey_decrypt_beaufort, "beau"),
                            (autokey_decrypt_ciphertext_feedback, "ctfb")]:
        label = f"2b_autokey_{ak_name}_WHAIONL_YAR"
        pt = ak_fn(CT, whaionl_yar)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc}
        if sc > best["score"]:
            best = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24")

    # 2c: Also test interleaved: [Y,W,A,H,R,A,...] and other interleavings
    # Interleave YAR and WHAIONL: take from each alternately
    interleaved_yw = []
    for i in range(max(len(YAR_VALS), len(WHAIONL_VALS))):
        if i < len(YAR_VALS):
            interleaved_yw.append(YAR_VALS[i])
        if i < len(WHAIONL_VALS):
            interleaved_yw.append(WHAIONL_VALS[i])
    print(f"\n  Interleaved Y/W key (period {len(interleaved_yw)}): {interleaved_yw}")

    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
        label = f"2c_interleaved_YW_{variant.value[:3]}"
        pt = decrypt_text(CT, interleaved_yw, variant)
        sc, det = check_cribs(pt, label)
        results[label] = {"score": sc}
        if sc > best["score"]:
            best = {"model": label, "score": sc}
        if sc > NOISE_FLOOR:
            print(f"  {label}: {sc}/24")

    # 2d: PALIMPSEST (10 chars) XOR'd with WHAIONL+YAR
    palimpsest_key = [ALPH_IDX[c] for c in "PALIMPSEST"]
    combined_add = [(palimpsest_key[i] + whaionl_yar[i]) % MOD for i in range(10)]
    combined_sub = [(palimpsest_key[i] - whaionl_yar[i]) % MOD for i in range(10)]
    print(f"\n  PALIMPSEST + WHAIONL_YAR (mod 26): {combined_add}")
    print(f"  PALIMPSEST - WHAIONL_YAR (mod 26): {combined_sub}")

    for key, kname in [(combined_add, "PAL_plus_WY"), (combined_sub, "PAL_minus_WY")]:
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            label = f"2d_{kname}_{variant.value[:3]}"
            pt = decrypt_text(CT, key, variant)
            sc, det = check_cribs(pt, label)
            results[label] = {"score": sc}
            if sc > best["score"]:
                best = {"model": label, "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  {label}: {sc}/24")

    print(f"\n  Model 2 overall best: {best['model']} = {best['score']}/24")
    update_best(best["model"], best["score"])
    ALL_RESULTS["model_2"] = {"best": best, "count": len(results)}
    return best


# =============================================================================
# MODEL 3: CUTTING MODEL (ABSCISSA = "cut off")
# =============================================================================
def model_3():
    print("\n" + "=" * 70)
    print("MODEL 3: Cutting model (rearrange CT segments)")
    print("=" * 70)

    results = {}
    best = {"model": None, "score": 0}

    def cut_and_rearrange(text, cut_positions, segment_order):
        """Cut text at given positions and rearrange segments.

        cut_positions: sorted list of positions where cuts happen.
        segment_order: permutation of segment indices.
        Returns rearranged text.
        """
        cuts = sorted(cut_positions)
        segments = []
        prev = 0
        for c in cuts:
            if c > prev:
                segments.append(text[prev:c])
            prev = c
        if prev < len(text):
            segments.append(text[prev:])

        # Rearrange according to segment_order
        if len(segment_order) != len(segments):
            return None
        try:
            return "".join(segments[i] for i in segment_order)
        except IndexError:
            return None

    # 3a: Cut at ETQ positions (4, 19, 16) → sorted: [4, 16, 19]
    # This gives 4 segments: [0:4], [4:16], [16:19], [19:97]
    etq_cuts = sorted(ETQ_POSITIONS)
    n_segs = len(etq_cuts) + 1  # 4 segments
    print(f"  ETQ cuts (sorted): {etq_cuts} → {n_segs} segments")
    seg_lens = []
    prev = 0
    for c in etq_cuts:
        seg_lens.append(c - prev)
        prev = c
    seg_lens.append(CT_LEN - prev)
    print(f"  Segment lengths: {seg_lens}")

    # Test all permutations of 4 segments (4! = 24)
    sub_keys = [
        ([ALPH_IDX[c] for c in "PALIMPSEST"], "PALIMPSEST"),
        ([ALPH_IDX[c] for c in "ABSCISSA"], "ABSCISSA"),
        ([ALPH_IDX[c] for c in "KRYPTOS"], "KRYPTOS"),
    ]

    etq_best = 0
    for seg_order in itertools.permutations(range(n_segs)):
        rearranged = cut_and_rearrange(CT, etq_cuts, list(seg_order))
        if rearranged is None or len(rearranged) != CT_LEN:
            continue

        # Check raw rearranged
        sc = score_cribs(rearranged)
        if sc > etq_best:
            etq_best = sc
            label = f"3a_ETQ_cut_order_{list(seg_order)}_raw"
            results[label] = {"score": sc, "order": list(seg_order)}
            if sc > best["score"]:
                best = {"model": label, "score": sc}

        # Apply substitution after rearrangement
        for sub_key, sub_name in sub_keys:
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(rearranged, sub_key, variant)
                sc2 = score_cribs(pt)
                if sc2 > etq_best:
                    etq_best = sc2
                    label2 = f"3a_ETQ_cut_{list(seg_order)}_{sub_name}_{variant.value[:3]}"
                    results[label2] = {"score": sc2}
                    if sc2 > best["score"]:
                        best = {"model": label2, "score": sc2}

        # Apply substitution BEFORE rearrangement
        for sub_key, sub_name in sub_keys:
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt_sub = decrypt_text(CT, sub_key, variant)
                pt_rear = cut_and_rearrange(pt_sub, etq_cuts, list(seg_order))
                if pt_rear and len(pt_rear) == CT_LEN:
                    sc3 = score_cribs(pt_rear)
                    if sc3 > etq_best:
                        etq_best = sc3
                        label3 = f"3a_ETQ_{sub_name}_{variant.value[:3]}_then_cut_{list(seg_order)}"
                        results[label3] = {"score": sc3}
                        if sc3 > best["score"]:
                            best = {"model": label3, "score": sc3}

    print(f"  3a ETQ cutting best: {etq_best}/24 (tested {n_segs}! x 3 keys x 2 variants x 2 directions)")

    # 3b: Cut at YAR positions (0, 17, 24) → sorted: [0, 17, 24]
    # Position 0 means no actual cut at start, so segments are: [0:17], [17:24], [24:97]
    yar_cuts_raw = sorted(YAR_VALS)  # [0, 17, 24]
    # Remove 0 since it doesn't create a meaningful cut
    yar_cuts = [c for c in yar_cuts_raw if c > 0]
    n_segs_y = len(yar_cuts) + 1  # 3 segments
    print(f"\n  YAR cuts (sorted, 0 removed): {yar_cuts} → {n_segs_y} segments")
    seg_lens_y = []
    prev = 0
    for c in yar_cuts:
        seg_lens_y.append(c - prev)
        prev = c
    seg_lens_y.append(CT_LEN - prev)
    print(f"  Segment lengths: {seg_lens_y}")

    yar_best = 0
    for seg_order in itertools.permutations(range(n_segs_y)):
        rearranged = cut_and_rearrange(CT, yar_cuts, list(seg_order))
        if rearranged is None or len(rearranged) != CT_LEN:
            continue

        sc = score_cribs(rearranged)
        if sc > yar_best:
            yar_best = sc
            label = f"3b_YAR_cut_order_{list(seg_order)}_raw"
            results[label] = {"score": sc, "order": list(seg_order)}
            if sc > best["score"]:
                best = {"model": label, "score": sc}

        for sub_key, sub_name in sub_keys:
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(rearranged, sub_key, variant)
                sc2 = score_cribs(pt)
                if sc2 > yar_best:
                    yar_best = sc2
                    label2 = f"3b_YAR_cut_{list(seg_order)}_{sub_name}_{variant.value[:3]}"
                    results[label2] = {"score": sc2}
                    if sc2 > best["score"]:
                        best = {"model": label2, "score": sc2}

                # Substitution before cut
                pt_sub = decrypt_text(CT, sub_key, variant)
                pt_rear = cut_and_rearrange(pt_sub, yar_cuts, list(seg_order))
                if pt_rear and len(pt_rear) == CT_LEN:
                    sc3 = score_cribs(pt_rear)
                    if sc3 > yar_best:
                        yar_best = sc3
                        label3 = f"3b_YAR_{sub_name}_{variant.value[:3]}_then_cut_{list(seg_order)}"
                        results[label3] = {"score": sc3}
                        if sc3 > best["score"]:
                            best = {"model": label3, "score": sc3}

    print(f"  3b YAR cutting best: {yar_best}/24")

    # 3c: Combined cuts — use both ETQ and YAR cut positions
    # Sorted unique: [4, 16, 17, 19, 24] → 6 segments
    combined_cuts = sorted(set(etq_cuts + yar_cuts))
    n_segs_c = len(combined_cuts) + 1
    print(f"\n  Combined ETQ+YAR cuts: {combined_cuts} → {n_segs_c} segments")

    # 6! = 720 segment orders x 3 keys x 2 variants x 2 directions = 25920 — feasible
    combined_best = 0
    for seg_order in itertools.permutations(range(n_segs_c)):
        rearranged = cut_and_rearrange(CT, combined_cuts, list(seg_order))
        if rearranged is None or len(rearranged) != CT_LEN:
            continue

        sc = score_cribs(rearranged)
        if sc > combined_best:
            combined_best = sc
            label = f"3c_combined_cut_{list(seg_order)}_raw"
            results[label] = {"score": sc}
            if sc > best["score"]:
                best = {"model": label, "score": sc}

        # Only test substitution if raw score is at least 2
        if sc >= 2:
            for sub_key, sub_name in sub_keys:
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(rearranged, sub_key, variant)
                    sc2 = score_cribs(pt)
                    if sc2 > combined_best:
                        combined_best = sc2
                        label2 = f"3c_combined_{list(seg_order)}_{sub_name}_{variant.value[:3]}"
                        results[label2] = {"score": sc2}
                        if sc2 > best["score"]:
                            best = {"model": label2, "score": sc2}

        # Also substitution before cut for promising orderings
        for sub_key, sub_name in sub_keys:
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt_sub = decrypt_text(CT, sub_key, variant)
                pt_rear = cut_and_rearrange(pt_sub, combined_cuts, list(seg_order))
                if pt_rear and len(pt_rear) == CT_LEN:
                    sc3 = score_cribs(pt_rear)
                    if sc3 > combined_best:
                        combined_best = sc3
                        label3 = f"3c_{sub_name}_{variant.value[:3]}_then_combined_cut_{list(seg_order)}"
                        results[label3] = {"score": sc3}
                        if sc3 > best["score"]:
                            best = {"model": label3, "score": sc3}

    print(f"  3c Combined cutting best: {combined_best}/24")

    # 3d: Cutting + autokey — cut then apply autokey with WHAIONL primer
    print("\n  --- 3d: Best cuts + autokey WHAIONL ---")
    cut_sets = [
        (etq_cuts, "ETQ"),
        (yar_cuts, "YAR"),
        (combined_cuts, "combined"),
    ]
    for cuts, cut_name in cut_sets:
        n_seg = len(cuts) + 1
        for seg_order in itertools.permutations(range(n_seg)):
            rearranged = cut_and_rearrange(CT, cuts, list(seg_order))
            if rearranged is None or len(rearranged) != CT_LEN:
                continue
            for ak_fn, ak_name in [(autokey_decrypt_vigenere, "vig"), (autokey_decrypt_beaufort, "beau")]:
                pt = ak_fn(rearranged, WHAIONL_VALS)
                sc = score_cribs(pt)
                if sc > best["score"]:
                    label = f"3d_{cut_name}_cut_{list(seg_order)}_autokey_{ak_name}_WHAIONL"
                    results[label] = {"score": sc}
                    best = {"model": label, "score": sc}
                if sc > NOISE_FLOOR:
                    label = f"3d_{cut_name}_cut_{list(seg_order)}_autokey_{ak_name}_WHAIONL"
                    print(f"  {label}: {sc}/24")

    print(f"\n  Model 3 overall best: {best['model']} = {best['score']}/24")
    update_best(best["model"], best["score"])
    ALL_RESULTS["model_3"] = {"best": best, "count": len(results)}
    return best


# =============================================================================
# MODEL 4: WHAIONL autokey + all 5040 width-7 orderings
# =============================================================================
def model_4():
    print("\n" + "=" * 70)
    print("MODEL 4: WHAIONL autokey + all width-7 columnar orderings")
    print("=" * 70)

    from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm, validate_perm, apply_perm

    results = {}
    best = {"model": None, "score": 0}
    count = 0

    for col_order in itertools.permutations(range(7)):
        perm7 = columnar_perm(7, list(col_order), CT_LEN)
        if not validate_perm(perm7, CT_LEN):
            continue
        inv7 = invert_perm(perm7)

        # Direction 1: transpose first, then autokey
        pt_trans = apply_perm(CT, inv7)
        for ak_fn, ak_name in [(autokey_decrypt_vigenere, "vig"), (autokey_decrypt_beaufort, "beau")]:
            pt = ak_fn(pt_trans, WHAIONL_VALS)
            sc = score_cribs(pt)
            count += 1
            if sc > best["score"]:
                best = {"model": f"4_trans_w7_{list(col_order)}_autokey_{ak_name}_WHAIONL", "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  w7={list(col_order)} + autokey_{ak_name}: {sc}/24")

        # Direction 2: autokey first, then transpose
        for ak_fn, ak_name in [(autokey_decrypt_vigenere, "vig"), (autokey_decrypt_beaufort, "beau")]:
            pt_ak = ak_fn(CT, WHAIONL_VALS)
            pt = apply_perm(pt_ak, inv7)
            sc = score_cribs(pt)
            count += 1
            if sc > best["score"]:
                best = {"model": f"4_autokey_{ak_name}_WHAIONL_then_trans_w7_{list(col_order)}", "score": sc}
            if sc > NOISE_FLOOR:
                print(f"  autokey_{ak_name} + w7={list(col_order)}: {sc}/24")

    print(f"  Model 4: tested {count} configs")
    print(f"  Model 4 overall best: {best['model']} = {best['score']}/24")
    update_best(best["model"], best["score"])
    ALL_RESULTS["model_4"] = {"best": best, "count": count}
    return best


# =============================================================================
# MAIN
# =============================================================================
def main():
    t0 = time.time()
    print("E-S-148: Combined anomaly-derived cipher models for K4")
    print(f"CT = {CT}")
    print(f"CT length = {CT_LEN}")
    print(f"Noise floor = {NOISE_FLOOR}")

    # Baseline
    baseline_sc, _ = check_cribs(CT)
    print(f"Baseline (raw CT): {baseline_sc}/24")

    results_1 = model_1()
    results_2 = model_2()
    results_3 = model_3()
    results_4 = model_4()

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Time: {elapsed:.1f}s")
    print()
    for model_key in ["model_1", "model_2", "model_3", "model_4"]:
        if model_key in ALL_RESULTS:
            b = ALL_RESULTS[model_key]["best"]
            cnt = ALL_RESULTS[model_key].get("count", "?")
            print(f"  {model_key}: best={b['score']}/24, model={b['model']}, configs={cnt}")

    print()
    print(f"OVERALL BEST: {BEST_OVERALL['model']} = {BEST_OVERALL['score']}/24")
    print(f"Noise floor = {NOISE_FLOOR}")

    if BEST_OVERALL["score"] <= NOISE_FLOOR:
        print("VERDICT: ALL NOISE — no anomaly-derived combined model produces signal")
    elif BEST_OVERALL["score"] < 18:
        print("VERDICT: STORED — some above-noise results but no signal")
    else:
        print("VERDICT: SIGNAL — investigate further!")

    # Save results
    output = {
        "experiment": "E-S-148",
        "description": "Combined anomaly-derived cipher models",
        "elapsed_seconds": elapsed,
        "best_overall": BEST_OVERALL,
        "model_summaries": {k: {"best": v["best"], "count": v.get("count", 0)} for k, v in ALL_RESULTS.items()},
        "noise_floor": NOISE_FLOOR,
    }
    out_path = os.path.join(RESULTS_DIR, "e_s_148_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
