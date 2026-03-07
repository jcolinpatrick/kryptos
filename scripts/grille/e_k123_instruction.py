#!/usr/bin/env python3
"""
# Cipher:  Multi-layer (Transposition + Vigenere combinations)
# Family:  grille
# Status:  active
# Keyspace: ~4M configs (transposition widths x keywords x cipher variants x alphabets)
# Last run: 2026-03-06
# Best score: 0 (free) / 6 (anchored, noise-consistent)
#
# Hypothesis: K1, K2, K3 methods are an INSTRUCTION for how to decrypt K4.
#   K1 = Vigenere/PALIMPSEST, K2 = Vigenere/ABSCISSA, K3 = double rotational transposition
#
# Variant A: K4 = T + V  (reversed sequence K3,K2,K1 -> transposition then Vigenere)
# Variant B: K4 = V + V + T (literal K1,K2,K3 order -> double Vigenere then transposition)
# Variant C: ABSCISSA as K4 keyword with transposition
# Variant D: Additional combos (V+T, triple layer, keyword-ordered columnar)
# Variant E: Double rotation (padded for prime 97) + Vigenere
# Variant F: All column orderings for widths 2-8 + Vigenere
"""

import sys
import os
import itertools
import math
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.transforms.transposition import (
    columnar_perm, apply_perm, invert_perm, validate_perm,
    rail_fence_perm, serpentine_perm, spiral_perm,
)
from kryptos.kernel.scoring.free_crib import score_free_fast
from kryptos.kernel.scoring.aggregate import score_candidate_free
from kryptos.kernel.alphabet import AZ, KA

# ── Constants ────────────────────────────────────────────────────────────

KEYWORDS = ["PALIMPSEST", "ABSCISSA", "HOROLOGE", "KRYPTOS", "PALIMPSESTABSCISSA"]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
VARIANT_NAMES = {
    CipherVariant.VIGENERE: "Vig",
    CipherVariant.BEAUFORT: "Beau",
    CipherVariant.VAR_BEAUFORT: "VBeau",
}

NOISE_THRESHOLD = 6  # Report anything above this

# Track best results
results_above_noise = []
best_score_overall = 0
configs_tested = 0


def kw_to_key(keyword, alphabet="AZ"):
    """Convert keyword string to numeric key values."""
    if alphabet == "KA":
        idx = KA.index_table
        return [idx[ord(c) - 65] for c in keyword.upper()]
    else:
        return [ord(c) - 65 for c in keyword.upper()]


def record_result(score, plaintext, method, detail_score=None):
    """Record a result if above noise threshold."""
    global best_score_overall
    if score > NOISE_THRESHOLD:
        results_above_noise.append((score, plaintext[:60], method))
        if score > best_score_overall:
            best_score_overall = score
            print(f"\n*** NEW BEST: score={score} method={method}")
            print(f"    PT: {plaintext[:80]}")
            if detail_score:
                print(f"    Detail: {detail_score.summary}")
            print()


def try_decrypt(ct_text, keyword, variant, alph_name="AZ"):
    """Try decrypting with given params, return (score, plaintext)."""
    key = kw_to_key(keyword, alph_name)
    pt = decrypt_text(ct_text, key, variant)
    score = score_free_fast(pt)
    return score, pt


def check_and_record(ct_text, keyword, variant, alph_name, method_prefix):
    """Decrypt, score, record if above noise. Returns configs count."""
    global configs_tested
    score, pt = try_decrypt(ct_text, keyword, variant, alph_name)
    configs_tested += 1
    if score > NOISE_THRESHOLD:
        method = f"{method_prefix} -> {VARIANT_NAMES[variant]}/{keyword}/{alph_name}"
        detail = score_candidate_free(pt)
        record_result(score, pt, method, detail)
    return 1


# ── Transposition helpers ────────────────────────────────────────────────

def simple_columnar_read_perm(width, length):
    """Write row by row, read by columns left to right. = columnar transposition."""
    height = math.ceil(length / width)
    perm = []
    for col in range(width):
        for row in range(height):
            pos = row * width + col
            if pos < length:
                perm.append(pos)
    return perm


def double_rotation_padded(w1, w2, length):
    """
    K3-style double rotation for non-rectangular grids.
    Step 1: write into w1-wide grid row by row, read columns top-to-bottom
    Step 2: write into w2-wide grid row by row, read columns top-to-bottom
    Uses only real positions (skips padding).
    """
    # First columnar transposition
    h1 = math.ceil(length / w1)
    perm1 = []
    for col in range(w1):
        for row in range(h1):
            pos = row * w1 + col
            if pos < length:
                perm1.append(pos)
    if len(perm1) != length or len(set(perm1)) != length:
        return None

    # Second columnar transposition (applied to result of first)
    h2 = math.ceil(length / w2)
    perm2 = []
    for col in range(w2):
        for row in range(h2):
            pos = row * w2 + col
            if pos < length:
                perm2.append(pos)
    if len(perm2) != length or len(set(perm2)) != length:
        return None

    # Compose: result[i] = perm1[perm2[i]]
    composed = [perm1[p] for p in perm2]
    if len(set(composed)) != length:
        return None
    return composed


def get_keyword_col_order(keyword):
    """Get column ordering from a keyword."""
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    col_order = [0] * len(keyword)
    for rank, (_, pos) in enumerate(ranked):
        col_order[pos] = rank
    return col_order


# ══════════════════════════════════════════════════════════════════════════
# VARIANT A: CT -> undo Transposition -> undo Vigenere -> PT
# ══════════════════════════════════════════════════════════════════════════

def run_variant_a():
    """
    K4 = Transposition + Vigenere (reversed K3,K2,K1 sequence).
    Decrypt: CT -> undo transposition -> undo Vigenere -> PT
    """
    global configs_tested
    print("=" * 70)
    print("VARIANT A: CT -> undo Transposition -> undo Vigenere -> PT")
    print("=" * 70)

    # ── A1: Simple columnar transpositions, widths 2-50 ──
    print("\n--- A1: Simple columnar transposition (widths 2-50) + Vigenere ---")
    a1_count = 0
    for width in range(2, 51):
        read_perm = simple_columnar_read_perm(width, CT_LEN)
        inv_read = invert_perm(read_perm)

        for perm, perm_name in [(read_perm, f"colR(w{width})"),
                                 (inv_read, f"colR_inv(w{width})")]:
            if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
                continue
            unscrambled = apply_perm(CT, perm)
            for kw in KEYWORDS:
                for var in VARIANTS:
                    for alph in ["AZ", "KA"]:
                        a1_count += check_and_record(unscrambled, kw, var, alph,
                                                      f"A1: {perm_name}")
    print(f"  A1 tested: {a1_count} configs")

    # ── A2: Rail fence, serpentine, spiral ──
    print("\n--- A2: Rail fence, serpentine, spiral + Vigenere ---")
    a2_count = 0

    for depth in range(2, 21):
        perm = rail_fence_perm(CT_LEN, depth)
        if len(perm) != CT_LEN:
            continue
        for p, p_name in [(perm, f"rail({depth})"),
                           (invert_perm(perm), f"rail_inv({depth})")]:
            unscrambled = apply_perm(CT, p)
            for kw in KEYWORDS:
                for var in VARIANTS:
                    for alph in ["AZ", "KA"]:
                        a2_count += check_and_record(unscrambled, kw, var, alph,
                                                      f"A2: {p_name}")

    for width in range(2, 30):
        height = math.ceil(CT_LEN / width)
        for vertical in [False, True]:
            perm = serpentine_perm(height, width, CT_LEN, vertical)
            if len(perm) != CT_LEN or len(set(perm)) != CT_LEN:
                continue
            vn = "V" if vertical else "H"
            for p, p_name in [(perm, f"serp{vn}(w{width})"),
                               (invert_perm(perm), f"serp{vn}_inv(w{width})")]:
                unscrambled = apply_perm(CT, p)
                for kw in KEYWORDS:
                    for var in VARIANTS:
                        a2_count += check_and_record(unscrambled, kw, var, "AZ",
                                                      f"A2: {p_name}")

    for width in range(5, 20):
        height = math.ceil(CT_LEN / width)
        if height * width < CT_LEN:
            height += 1
        for cw in [True, False]:
            perm = spiral_perm(height, width, CT_LEN, cw)
            if len(perm) != CT_LEN or len(set(perm)) != CT_LEN:
                continue
            cn = "CW" if cw else "CCW"
            for p, p_name in [(perm, f"spiral{cn}({width}x{height})"),
                               (invert_perm(perm), f"spiral{cn}_inv({width}x{height})")]:
                unscrambled = apply_perm(CT, p)
                for kw in KEYWORDS:
                    for var in VARIANTS:
                        a2_count += check_and_record(unscrambled, kw, var, "AZ",
                                                      f"A2: {p_name}")
    print(f"  A2 tested: {a2_count} configs")

    # ── A3: Keyword-ordered columnar ──
    print("\n--- A3: Keyword-ordered columnar + Vigenere ---")
    a3_count = 0
    col_keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE"]
    for col_kw in col_keywords:
        width = len(col_kw)
        col_order = get_keyword_col_order(col_kw)
        perm = columnar_perm(width, col_order, CT_LEN)
        if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
            continue
        for p, p_name in [(perm, f"colKW({col_kw})"),
                           (invert_perm(perm), f"colKW_inv({col_kw})")]:
            unscrambled = apply_perm(CT, p)
            for kw in KEYWORDS:
                for var in VARIANTS:
                    for alph in ["AZ", "KA"]:
                        a3_count += check_and_record(unscrambled, kw, var, alph,
                                                      f"A3: {p_name}")
    print(f"  A3 tested: {a3_count} configs")


# ══════════════════════════════════════════════════════════════════════════
# VARIANT B: CT -> undo Transposition -> undo Vig2 -> undo Vig1 -> PT
# ══════════════════════════════════════════════════════════════════════════

def run_variant_b():
    """
    K4 = Double Vigenere + Transposition (literal K1,K2,K3 order: V,V,T).
    Encrypt: PT -> Vig1 -> Vig2 -> Transposition -> CT
    Decrypt: CT -> undo Transposition -> undo Vig2 -> undo Vig1 -> PT
    """
    global configs_tested
    print("\n" + "=" * 70)
    print("VARIANT B: CT -> undo T -> undo Vig2 -> undo Vig1 -> PT")
    print("=" * 70)

    b_count = 0
    kw_pairs = list(itertools.product(
        ["PALIMPSEST", "ABSCISSA", "HOROLOGE", "KRYPTOS"],
        repeat=2,
    ))

    # B1: Columnar widths 2-20
    print("\n--- B1: Columnar (w 2-20) + double Vigenere ---")
    for width in range(2, 21):
        read_perm = simple_columnar_read_perm(width, CT_LEN)
        inv_read = invert_perm(read_perm)

        for perm, perm_name in [(read_perm, f"colR(w{width})"),
                                 (inv_read, f"colR_inv(w{width})")]:
            if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
                continue
            unscrambled = apply_perm(CT, perm)

            for kw1, kw2 in kw_pairs:
                for var in VARIANTS:
                    for alph in ["AZ", "KA"]:
                        key2 = kw_to_key(kw2, alph)
                        intermediate = decrypt_text(unscrambled, key2, var)
                        key1 = kw_to_key(kw1, alph)
                        pt = decrypt_text(intermediate, key1, var)
                        score = score_free_fast(pt)
                        configs_tested += 1
                        b_count += 1
                        if score > NOISE_THRESHOLD:
                            method = f"B1: w={width} {perm_name} -> {VARIANT_NAMES[var]}/{kw2}/{alph} -> {VARIANT_NAMES[var]}/{kw1}/{alph}"
                            detail = score_candidate_free(pt)
                            record_result(score, pt, method, detail)
    print(f"  B1 tested: {b_count} configs")

    # B2: Mixed cipher variants for the two layers
    print("\n--- B2: Mixed cipher variants ---")
    b2_count = 0
    mixed_pairs = [
        (CipherVariant.VIGENERE, CipherVariant.BEAUFORT),
        (CipherVariant.BEAUFORT, CipherVariant.VIGENERE),
        (CipherVariant.VIGENERE, CipherVariant.VAR_BEAUFORT),
        (CipherVariant.VAR_BEAUFORT, CipherVariant.VIGENERE),
        (CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT),
        (CipherVariant.VAR_BEAUFORT, CipherVariant.BEAUFORT),
    ]
    top_kw_pairs = [
        ("PALIMPSEST", "ABSCISSA"), ("ABSCISSA", "PALIMPSEST"),
        ("PALIMPSEST", "KRYPTOS"), ("KRYPTOS", "PALIMPSEST"),
        ("ABSCISSA", "KRYPTOS"), ("KRYPTOS", "ABSCISSA"),
        ("PALIMPSEST", "HOROLOGE"), ("HOROLOGE", "PALIMPSEST"),
        ("ABSCISSA", "HOROLOGE"), ("HOROLOGE", "ABSCISSA"),
    ]

    for width in range(2, 21):
        read_perm = simple_columnar_read_perm(width, CT_LEN)
        inv_read = invert_perm(read_perm)

        for perm, perm_name in [(inv_read, f"colR_inv(w{width})"),
                                 (read_perm, f"colR(w{width})")]:
            if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
                continue
            unscrambled = apply_perm(CT, perm)

            for kw1, kw2 in top_kw_pairs:
                for var1, var2 in mixed_pairs:
                    key2 = kw_to_key(kw2, "AZ")
                    intermediate = decrypt_text(unscrambled, key2, var2)
                    key1 = kw_to_key(kw1, "AZ")
                    pt = decrypt_text(intermediate, key1, var1)
                    score = score_free_fast(pt)
                    configs_tested += 1
                    b2_count += 1
                    if score > NOISE_THRESHOLD:
                        method = f"B2: w={width} {perm_name} -> {VARIANT_NAMES[var2]}/{kw2} -> {VARIANT_NAMES[var1]}/{kw1}"
                        detail = score_candidate_free(pt)
                        record_result(score, pt, method, detail)

    # B3: Keyword-ordered columnar + double Vig
    print(f"  B2 tested: {b2_count} configs")
    b3_count = 0
    print("\n--- B3: Keyword-ordered columnar + double Vigenere ---")
    for col_kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE"]:
        width = len(col_kw)
        col_order = get_keyword_col_order(col_kw)
        perm = columnar_perm(width, col_order, CT_LEN)
        if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
            continue
        for p, p_name in [(perm, f"colKW({col_kw})"),
                           (invert_perm(perm), f"colKW_inv({col_kw})")]:
            unscrambled = apply_perm(CT, p)
            for kw1, kw2 in kw_pairs:
                for var in VARIANTS:
                    for alph in ["AZ", "KA"]:
                        key2 = kw_to_key(kw2, alph)
                        intermediate = decrypt_text(unscrambled, key2, var)
                        key1 = kw_to_key(kw1, alph)
                        pt = decrypt_text(intermediate, key1, var)
                        score = score_free_fast(pt)
                        configs_tested += 1
                        b3_count += 1
                        if score > NOISE_THRESHOLD:
                            method = f"B3: {p_name} -> {VARIANT_NAMES[var]}/{kw2}/{alph} -> {VARIANT_NAMES[var]}/{kw1}/{alph}"
                            detail = score_candidate_free(pt)
                            record_result(score, pt, method, detail)
    print(f"  B3 tested: {b3_count} configs")


# ══════════════════════════════════════════════════════════════════════════
# VARIANT C: ABSCISSA-focused + double Vigenere without transposition
# ══════════════════════════════════════════════════════════════════════════

def run_variant_c():
    """
    ABSCISSA as K4 keyword. Bean FAILS for simple periodic (k[3]=C != k[1]=B).
    Test with transposition (Bean bypass) and double Vigenere.
    """
    global configs_tested
    print("\n" + "=" * 70)
    print("VARIANT C: ABSCISSA-focused + double Vigenere (no transposition)")
    print("=" * 70)

    abscissa_key = [ord(c) - 65 for c in "ABSCISSA"]
    print(f"  ABSCISSA key: {abscissa_key}")
    print(f"  k[27 mod 8] = k[{27 % 8}] = {abscissa_key[27 % 8]} ({chr(abscissa_key[27 % 8] + 65)})")
    print(f"  k[65 mod 8] = k[{65 % 8}] = {abscissa_key[65 % 8]} ({chr(abscissa_key[65 % 8] + 65)})")
    print(f"  Bean equality: {'PASS' if abscissa_key[27 % 8] == abscissa_key[65 % 8] else 'FAIL'}")

    c_count = 0

    # C1: Double Vigenere (no transposition)
    print("\n--- C1: Double Vigenere with PALIMPSEST/ABSCISSA/KRYPTOS/HOROLOGE ---")
    kw_all = ["PALIMPSEST", "ABSCISSA", "HOROLOGE", "KRYPTOS"]
    for kw1, kw2 in itertools.product(kw_all, repeat=2):
        for var1 in VARIANTS:
            for var2 in VARIANTS:
                for alph in ["AZ", "KA"]:
                    key1 = kw_to_key(kw1, alph)
                    key2 = kw_to_key(kw2, alph)
                    intermediate = decrypt_text(CT, key1, var1)
                    pt = decrypt_text(intermediate, key2, var2)
                    score = score_free_fast(pt)
                    configs_tested += 1
                    c_count += 1
                    if score > NOISE_THRESHOLD:
                        method = f"C1: {VARIANT_NAMES[var1]}/{kw1}/{alph} -> {VARIANT_NAMES[var2]}/{kw2}/{alph}"
                        detail = score_candidate_free(pt)
                        record_result(score, pt, method, detail)

    print(f"  C1 tested: {c_count} configs")


# ══════════════════════════════════════════════════════════════════════════
# VARIANT D: Vig first then transposition (encrypt = T then V)
# ══════════════════════════════════════════════════════════════════════════

def run_variant_d():
    """
    If encrypt was: PT -> Transposition -> Vigenere -> CT
    Then decrypt: CT -> undo Vigenere -> undo Transposition -> PT
    """
    global configs_tested
    print("\n" + "=" * 70)
    print("VARIANT D: CT -> undo Vigenere -> undo Transposition -> PT")
    print("=" * 70)

    d_count = 0
    for kw in KEYWORDS:
        for var in VARIANTS:
            for alph in ["AZ", "KA"]:
                key = kw_to_key(kw, alph)
                vig_decrypted = decrypt_text(CT, key, var)

                for width in range(2, 51):
                    read_perm = simple_columnar_read_perm(width, CT_LEN)
                    inv_read = invert_perm(read_perm)

                    for perm, perm_name in [(read_perm, f"colR(w{width})"),
                                             (inv_read, f"colR_inv(w{width})")]:
                        if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
                            continue
                        pt = apply_perm(vig_decrypted, perm)
                        score = score_free_fast(pt)
                        configs_tested += 1
                        d_count += 1
                        if score > NOISE_THRESHOLD:
                            method = f"D: {VARIANT_NAMES[var]}/{kw}/{alph} -> {perm_name}"
                            detail = score_candidate_free(pt)
                            record_result(score, pt, method, detail)

    print(f"  Variant D tested: {d_count} configs")


# ══════════════════════════════════════════════════════════════════════════
# VARIANT E: Double rotation (K3-style) + Vigenere
# ══════════════════════════════════════════════════════════════════════════

def run_variant_e():
    """
    K3-style double columnar transposition for 97 chars.
    Two successive columnar reads. Try all (w1, w2) pairs 2-50.
    """
    global configs_tested
    print("\n" + "=" * 70)
    print("VARIANT E: Double rotation (w1,w2 in 2-50) + Vigenere")
    print("=" * 70)

    e_count = 0
    valid_pairs = 0

    # Pre-compute all valid double rotation perms
    for w1 in range(2, 51):
        for w2 in range(2, 51):
            composed = double_rotation_padded(w1, w2, CT_LEN)
            if composed is None:
                continue
            valid_pairs += 1

            for p, p_name in [(composed, f"dblR({w1},{w2})"),
                               (invert_perm(composed), f"dblR_inv({w1},{w2})")]:
                unscrambled = apply_perm(CT, p)
                for kw in KEYWORDS:
                    for var in VARIANTS:
                        # AZ only to keep runtime manageable (KA for top keywords)
                        score, pt = try_decrypt(unscrambled, kw, var, "AZ")
                        configs_tested += 1
                        e_count += 1
                        if score > NOISE_THRESHOLD:
                            method = f"E: {p_name} -> {VARIANT_NAMES[var]}/{kw}/AZ"
                            detail = score_candidate_free(pt)
                            record_result(score, pt, method, detail)

                        # KA for KRYPTOS and HOROLOGE
                        if kw in ["KRYPTOS", "HOROLOGE"]:
                            score_ka, pt_ka = try_decrypt(unscrambled, kw, var, "KA")
                            configs_tested += 1
                            e_count += 1
                            if score_ka > NOISE_THRESHOLD:
                                method = f"E: {p_name} -> {VARIANT_NAMES[var]}/{kw}/KA"
                                detail = score_candidate_free(pt_ka)
                                record_result(score_ka, pt_ka, method, detail)

    print(f"  Valid double rotation pairs: {valid_pairs}")
    print(f"  Variant E tested: {e_count} configs")

    # E2: Double rotation with 100-char padding
    print("\n--- E2: Double rotation padded to 100 (97+3) ---")
    e2_count = 0
    dim_pairs_100 = [
        (10, 10), (25, 4), (4, 25), (20, 5), (5, 20), (50, 2), (2, 50),
        (10, 20), (20, 10), (10, 25), (25, 10), (10, 50), (50, 10),
        (5, 10), (10, 5), (4, 50), (50, 4), (2, 25), (25, 2),
        (5, 4), (4, 5), (20, 25), (25, 20), (20, 50), (50, 20),
    ]
    pad_chars = ["X", "A", "Z"]

    for pad_ch in pad_chars:
        ct_padded = CT + pad_ch * 3

        for w1, w2 in dim_pairs_100:
            composed = double_rotation_padded(w1, w2, 100)
            if composed is None:
                continue

            for p, p_name in [(composed, f"dblR100({w1},{w2})"),
                               (invert_perm(composed), f"dblR100_inv({w1},{w2})")]:
                result_100 = apply_perm(ct_padded, p)
                for take, tn in [(result_100[:97], "first97"), (result_100[3:], "last97")]:
                    for kw in KEYWORDS:
                        for var in VARIANTS:
                            score, pt = try_decrypt(take, kw, var, "AZ")
                            configs_tested += 1
                            e2_count += 1
                            if score > NOISE_THRESHOLD:
                                method = f"E2: pad={pad_ch} {p_name} {tn} -> {VARIANT_NAMES[var]}/{kw}/AZ"
                                detail = score_candidate_free(pt)
                                record_result(score, pt, method, detail)

    print(f"  E2 tested: {e2_count} configs")

    # E3: K3 exact parameters on K4 with double rotation
    print("\n--- E3: K3 exact width pairs applied to K4 ---")
    e3_count = 0
    k3_pairs = [
        (24, 14), (14, 24), (24, 8), (8, 24), (14, 8), (8, 14),
        (24, 42), (42, 24), (14, 42), (42, 14), (8, 42), (42, 8),
        (12, 28), (28, 12), (16, 21), (21, 16),
    ]

    for w1, w2 in k3_pairs:
        composed = double_rotation_padded(w1, w2, CT_LEN)
        if composed is None:
            continue

        for p, p_name in [(composed, f"k3dblR({w1},{w2})"),
                           (invert_perm(composed), f"k3dblR_inv({w1},{w2})")]:
            unscrambled = apply_perm(CT, p)
            for kw in KEYWORDS:
                for var in VARIANTS:
                    for alph in ["AZ", "KA"]:
                        e3_count += check_and_record(unscrambled, kw, var, alph,
                                                      f"E3: {p_name}")

    print(f"  E3 tested: {e3_count} configs")


# ══════════════════════════════════════════════════════════════════════════
# VARIANT F: All column orderings for widths 2-8
# ══════════════════════════════════════════════════════════════════════════

def run_variant_f():
    """
    For widths 2-8, try ALL possible column orderings.
    Width 8 = 40320 orderings. Total ~46K orderings x 2 directions x ~10 decrypts each.
    """
    global configs_tested
    print("\n" + "=" * 70)
    print("VARIANT F: All column orderings (widths 2-8) + Vigenere")
    print("=" * 70)

    f_count = 0

    for width in range(2, 9):
        n_perms = math.factorial(width)
        print(f"  Width {width}: {n_perms} orderings...")

        for col_order in itertools.permutations(range(width)):
            perm = columnar_perm(width, list(col_order), CT_LEN)
            if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
                continue

            for p, p_name in [(perm, "col"), (invert_perm(perm), "col_inv")]:
                unscrambled = apply_perm(CT, p)

                for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE"]:
                    for var in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                        score, pt = try_decrypt(unscrambled, kw, var, "AZ")
                        configs_tested += 1
                        f_count += 1
                        if score > NOISE_THRESHOLD:
                            method = f"F: w={width} order={col_order} {p_name} -> {VARIANT_NAMES[var]}/{kw}/AZ"
                            detail = score_candidate_free(pt)
                            record_result(score, pt, method, detail)

                        if kw == "KRYPTOS":
                            score_ka, pt_ka = try_decrypt(unscrambled, kw, var, "KA")
                            configs_tested += 1
                            f_count += 1
                            if score_ka > NOISE_THRESHOLD:
                                method = f"F: w={width} order={col_order} {p_name} -> {VARIANT_NAMES[var]}/{kw}/KA"
                                detail = score_candidate_free(pt_ka)
                                record_result(score_ka, pt_ka, method, detail)

    print(f"  Variant F tested: {f_count} configs")


# ══════════════════════════════════════════════════════════════════════════
# VARIANT G: Triple layer (T + V + V or V + T + V)
# ══════════════════════════════════════════════════════════════════════════

def run_variant_g():
    """
    Triple layer combinations:
    G1: CT -> undo T -> undo V -> undo V -> PT  (with same keyword for both V)
    G2: CT -> undo V -> undo T -> undo V -> PT  (V sandwiching T)
    """
    global configs_tested
    print("\n" + "=" * 70)
    print("VARIANT G: Triple layer combinations")
    print("=" * 70)

    g_count = 0

    # G1: T + V + V (same keyword both layers)
    print("\n--- G1: T + double V (same keyword) ---")
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE"]:
        for var in VARIANTS:
            key = kw_to_key(kw, "AZ")
            for width in range(2, 21):
                read_perm = simple_columnar_read_perm(width, CT_LEN)
                inv_read = invert_perm(read_perm)

                for perm, perm_name in [(read_perm, f"colR(w{width})"),
                                         (inv_read, f"colR_inv(w{width})")]:
                    if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
                        continue
                    unscrambled = apply_perm(CT, perm)
                    layer1 = decrypt_text(unscrambled, key, var)
                    pt = decrypt_text(layer1, key, var)
                    score = score_free_fast(pt)
                    configs_tested += 1
                    g_count += 1
                    if score > NOISE_THRESHOLD:
                        method = f"G1: w={width} {perm_name} -> 2x{VARIANT_NAMES[var]}/{kw}"
                        detail = score_candidate_free(pt)
                        record_result(score, pt, method, detail)

    # G2: V + T + V
    print("\n--- G2: V + T + V (different keywords) ---")
    for kw_outer in ["PALIMPSEST", "ABSCISSA"]:
        for kw_inner in ["KRYPTOS", "HOROLOGE"]:
            for var in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                key_outer = kw_to_key(kw_outer, "AZ")
                key_inner = kw_to_key(kw_inner, "AZ")

                # Decrypt outer V
                after_outer = decrypt_text(CT, key_outer, var)

                for width in range(2, 21):
                    read_perm = simple_columnar_read_perm(width, CT_LEN)
                    inv_read = invert_perm(read_perm)

                    for perm, perm_name in [(read_perm, f"colR(w{width})"),
                                             (inv_read, f"colR_inv(w{width})")]:
                        if len(perm) != CT_LEN or not validate_perm(perm, CT_LEN):
                            continue
                        after_t = apply_perm(after_outer, perm)
                        pt = decrypt_text(after_t, key_inner, var)
                        score = score_free_fast(pt)
                        configs_tested += 1
                        g_count += 1
                        if score > NOISE_THRESHOLD:
                            method = f"G2: {VARIANT_NAMES[var]}/{kw_outer} -> w={width} {perm_name} -> {VARIANT_NAMES[var]}/{kw_inner}"
                            detail = score_candidate_free(pt)
                            record_result(score, pt, method, detail)

    print(f"  Variant G tested: {g_count} configs")


# ══════════════════════════════════════════════════════════════════════════
# VARIANT H: Baseline single Vigenere (sanity check)
# ══════════════════════════════════════════════════════════════════════════

def run_variant_h():
    """Baseline: single Vigenere with all keywords, no transposition."""
    global configs_tested
    print("\n" + "=" * 70)
    print("VARIANT H: Baseline single Vigenere (no transposition)")
    print("=" * 70)

    h_count = 0
    for kw in KEYWORDS:
        for var in VARIANTS:
            for alph in ["AZ", "KA"]:
                h_count += check_and_record(CT, kw, var, alph, f"H: direct")
    print(f"  Variant H tested: {h_count} configs")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def attack(ciphertext=None, **params):
    """Standard attack interface."""
    global configs_tested, results_above_noise, best_score_overall
    configs_tested = 0
    results_above_noise = []
    best_score_overall = 0

    start = time.time()

    print("K123 INSTRUCTION HYPOTHESIS -- Comprehensive Test")
    print(f"CT: {CT[:40]}... (len={CT_LEN})")
    print(f"Keywords: {KEYWORDS}")
    print(f"Cipher variants: Vigenere, Beaufort, Variant Beaufort")
    print(f"Alphabets: AZ (standard), KA (Kryptos)")
    print(f"Noise threshold: {NOISE_THRESHOLD}")
    print()

    run_variant_h()   # H: baseline
    run_variant_a()   # A: T + V
    run_variant_d()   # D: V + T (reversed)
    run_variant_b()   # B: V + V + T
    run_variant_c()   # C: double V (no T)
    run_variant_e()   # E: double rotation + V
    run_variant_f()   # F: all col orderings w2-8
    run_variant_g()   # G: triple layer

    elapsed = time.time() - start

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {configs_tested:,}")
    print(f"Time: {elapsed:.1f}s")
    print(f"Best score: {best_score_overall}")
    print(f"Results above noise (>{NOISE_THRESHOLD}): {len(results_above_noise)}")

    if results_above_noise:
        print("\nAll results above noise, sorted by score:")
        results_above_noise.sort(key=lambda x: -x[0])
        for score, pt_preview, method in results_above_noise:
            print(f"  score={score:2d} | {method}")
            print(f"           PT: {pt_preview}")
    else:
        print("\n  No results above noise threshold.")

    print(f"\nCompleted in {elapsed:.1f}s")
    return [(s, p, m) for s, p, m in results_above_noise]


if __name__ == "__main__":
    attack()
