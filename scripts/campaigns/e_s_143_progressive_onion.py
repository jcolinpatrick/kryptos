#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-143: Progressive Onion — K0/K1/K2/K3 layers stacked on K4.

HYPOTHESIS: K4 ciphertext has MULTIPLE encryption layers derived from K0-K3.
Sanborn: "pull up one layer... pull up another layer" (onion metaphor).
Sanborn: Gillogly didn't solve it "the right way" — he skipped the progressive method.

If K4 = encrypt_K1(encrypt_K2(encrypt_K3(plaintext))), then to decrypt:
  1. Undo K3's method (transposition + Vigenère)
  2. Undo K2's method (Vigenère with ABSCISSA)
  3. Undo K1's method (Vigenère with PALIMPSEST)

K1 method: Vigenère, key=PALIMPSEST (period 10), KA alphabet
K2 method: Vigenère, key=ABSCISSA (period 8), KA alphabet
K3 method: Columnar transposition (KRYPTOS, width 7) → Vigenère (PALIMPSEST, period 10, std alphabet)

Tests:
  Phase A: All 2-layer combinations (L1×L2, L1×L3, L2×L3) × orderings × variants
  Phase B: All 3-layer orderings × variants (the full onion)
  Phase C: Full K3 method as single layer + K1 or K2 as second layer
  Phase D: Additive key stacking (keys combined mod 26 rather than sequential)
  Phase E: K0 contribution (T=19 offset, E-group pattern) + layers
  Phase F: Full onion with ALL w7 columnar orderings (5040 × variants)
  Phase G: Quadruple layer — K0+K1+K2+K3 combined

Output: results/e_s_143_progressive_onion.json
"""

import json
import os
import sys
import time as time_mod
import math
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR, STORE_THRESHOLD,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic

# ═══════════════════════════════════════════════════════════════════════════════
# CIPHER PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════════

# Standard alphabet
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}

# Kryptos Alphabet
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def vig_dec_std(ct_text, key_nums):
    """Vigenère decrypt with standard alphabet."""
    period = len(key_nums)
    result = []
    for i, c in enumerate(ct_text):
        ct_val = AZ_IDX[c]
        pt_val = (ct_val - key_nums[i % period]) % 26
        result.append(AZ[pt_val])
    return ''.join(result)


def beau_dec_std(ct_text, key_nums):
    """Beaufort decrypt with standard alphabet."""
    period = len(key_nums)
    result = []
    for i, c in enumerate(ct_text):
        ct_val = AZ_IDX[c]
        pt_val = (key_nums[i % period] - ct_val) % 26
        result.append(AZ[pt_val])
    return ''.join(result)


def vbeau_dec_std(ct_text, key_nums):
    """Variant Beaufort decrypt with standard alphabet."""
    period = len(key_nums)
    result = []
    for i, c in enumerate(ct_text):
        ct_val = AZ_IDX[c]
        pt_val = (ct_val + key_nums[i % period]) % 26
        result.append(AZ[pt_val])
    return ''.join(result)


def vig_dec_ka(ct_text, key_nums):
    """Vigenère decrypt with Kryptos Alphabet."""
    period = len(key_nums)
    result = []
    for i, c in enumerate(ct_text):
        ct_val = KA_IDX[c]
        pt_val = (ct_val - key_nums[i % period]) % 26
        result.append(KA[pt_val])
    return ''.join(result)


def beau_dec_ka(ct_text, key_nums):
    """Beaufort decrypt with Kryptos Alphabet."""
    period = len(key_nums)
    result = []
    for i, c in enumerate(ct_text):
        ct_val = KA_IDX[c]
        pt_val = (key_nums[i % period] - ct_val) % 26
        result.append(KA[pt_val])
    return ''.join(result)


def vbeau_dec_ka(ct_text, key_nums):
    """Variant Beaufort decrypt with Kryptos Alphabet."""
    period = len(key_nums)
    result = []
    for i, c in enumerate(ct_text):
        ct_val = KA_IDX[c]
        pt_val = (ct_val + key_nums[i % period]) % 26
        result.append(KA[pt_val])
    return ''.join(result)


def columnar_decrypt(ct_text, col_order, width):
    """Decrypt columnar transposition.

    CT was created by: write PT into grid row-by-row, read columns in col_order.
    To decrypt: write CT into columns in col_order, read row-by-row.
    """
    n = len(ct_text)
    nrows = math.ceil(n / width)
    short_cols = nrows * width - n  # columns with nrows-1 entries

    # Determine column lengths
    col_lengths = []
    for c in range(width):
        if c >= width - short_cols:
            col_lengths.append(nrows - 1)
        else:
            col_lengths.append(nrows)

    # Fill columns in read order
    columns = [[] for _ in range(width)]
    pos = 0
    for rank in range(width):
        col_idx = col_order[rank]
        clen = col_lengths[col_idx]
        columns[col_idx] = list(ct_text[pos:pos + clen])
        pos += clen

    # Read row-by-row
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(columns[col]):
                result.append(columns[col][row])

    return ''.join(result)


def make_key(text, alphabet_idx=None):
    """Convert text to numeric key."""
    if alphabet_idx is None:
        alphabet_idx = AZ_IDX
    return [alphabet_idx[c] for c in text.upper() if c in alphabet_idx]


def keyword_to_col_order(keyword):
    """Derive column read order from keyword."""
    indexed = [(ch, i) for i, ch in enumerate(keyword.upper())]
    indexed.sort(key=lambda x: (x[0], x[1]))
    read_order = [orig_idx for _, orig_idx in indexed]
    return read_order


# ═══════════════════════════════════════════════════════════════════════════════
# K1/K2/K3 PARAMETERS
# ═══════════════════════════════════════════════════════════════════════════════

# K1: Vigenère with PALIMPSEST, KA alphabet
K1_KEY_TEXT = "PALIMPSEST"
K1_KEY_KA = make_key(K1_KEY_TEXT, KA_IDX)  # In KA index space
K1_KEY_AZ = make_key(K1_KEY_TEXT, AZ_IDX)  # In standard index space

# K2: Vigenère with ABSCISSA, KA alphabet
K2_KEY_TEXT = "ABSCISSA"
K2_KEY_KA = make_key(K2_KEY_TEXT, KA_IDX)
K2_KEY_AZ = make_key(K2_KEY_TEXT, AZ_IDX)

# K3 transposition: columnar with KRYPTOS keyword, width 7
K3_TRANS_KEYWORD = "KRYPTOS"
K3_COL_ORDER = keyword_to_col_order(K3_TRANS_KEYWORD)  # [0, 5, 3, 1, 6, 4, 2]
K3_WIDTH = 7

# K3 substitution: Vigenère with PALIMPSEST, standard alphabet
K3_SUB_KEY = K1_KEY_AZ  # Same keyword, but standard alphabet

# K0 contribution
K0_T_OFFSET = 19  # T=19 (0-indexed), from "T IS YOUR POSITION"
K0_E_GROUPS = [2, 1, 5, 1, 3, 2, 2, 5, 3, 1, 1]  # Extra E group sizes


# ═══════════════════════════════════════════════════════════════════════════════
# LAYER OPERATIONS (decryption direction)
# ═══════════════════════════════════════════════════════════════════════════════

# Each "layer" is a function: text → text
# We build named layers and test all orderings

def make_sub_layers():
    """Create all substitution layer variants."""
    layers = {}

    # K1 layers (KA alphabet, PALIMPSEST)
    layers["K1_Vig_KA"] = lambda t: vig_dec_ka(t, K1_KEY_KA)
    layers["K1_Beau_KA"] = lambda t: beau_dec_ka(t, K1_KEY_KA)
    layers["K1_VB_KA"] = lambda t: vbeau_dec_ka(t, K1_KEY_KA)

    # K1 layers (standard alphabet, PALIMPSEST) — in case K4 uses std
    layers["K1_Vig_AZ"] = lambda t: vig_dec_std(t, K1_KEY_AZ)
    layers["K1_Beau_AZ"] = lambda t: beau_dec_std(t, K1_KEY_AZ)
    layers["K1_VB_AZ"] = lambda t: vbeau_dec_std(t, K1_KEY_AZ)

    # K2 layers (KA alphabet, ABSCISSA)
    layers["K2_Vig_KA"] = lambda t: vig_dec_ka(t, K2_KEY_KA)
    layers["K2_Beau_KA"] = lambda t: beau_dec_ka(t, K2_KEY_KA)
    layers["K2_VB_KA"] = lambda t: vbeau_dec_ka(t, K2_KEY_KA)

    # K2 layers (standard alphabet, ABSCISSA)
    layers["K2_Vig_AZ"] = lambda t: vig_dec_std(t, K2_KEY_AZ)
    layers["K2_Beau_AZ"] = lambda t: beau_dec_std(t, K2_KEY_AZ)
    layers["K2_VB_AZ"] = lambda t: vbeau_dec_std(t, K2_KEY_AZ)

    # K3 sub-only (standard alphabet, PALIMPSEST) — just the Vig part
    layers["K3sub_Vig_AZ"] = lambda t: vig_dec_std(t, K3_SUB_KEY)
    layers["K3sub_Beau_AZ"] = lambda t: beau_dec_std(t, K3_SUB_KEY)

    return layers


def make_trans_layer(col_order, width=7):
    """Create a transposition layer."""
    return lambda t: columnar_decrypt(t, col_order, width)


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    t0 = time_mod.time()
    results = []
    best_score = 0
    total_tests = 0

    print("=" * 72)
    print("E-S-143: Progressive Onion — K0/K1/K2/K3 Layers on K4")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"K1 key: {K1_KEY_TEXT} (period {len(K1_KEY_TEXT)})")
    print(f"K2 key: {K2_KEY_TEXT} (period {len(K2_KEY_TEXT)})")
    print(f"K3 trans: {K3_TRANS_KEYWORD} (width {K3_WIDTH}, order {K3_COL_ORDER})")
    print(f"K3 sub: PALIMPSEST (std alphabet)")
    print(f"K0 T-offset: {K0_T_OFFSET}")
    print()

    sub_layers = make_sub_layers()
    k3_trans = make_trans_layer(K3_COL_ORDER, K3_WIDTH)

    def test_and_record(label, text):
        nonlocal best_score, total_tests
        total_tests += 1
        sc = score_cribs(text)
        if sc > best_score:
            best_score = sc
            print(f"  NEW BEST: {sc}/24 — {label}")
            print(f"    PT: {text[:50]}...")
        if sc > NOISE_FLOOR:
            ic_val = ic(text)
            results.append({
                "test": label,
                "score": sc,
                "ic": round(ic_val, 4),
                "pt_snippet": text[:60],
            })
            if sc >= STORE_THRESHOLD:
                print(f"  *** STORE: {label}: score={sc}")
        return sc

    # ──────────────────────────────────────────────────────────────────────
    # PHASE A: Single layers (sanity check — should match prior results)
    # ──────────────────────────────────────────────────────────────────────
    print("─" * 72)
    print("PHASE A: Single layers (sanity baseline)")
    print("─" * 72)

    for name, layer_fn in sub_layers.items():
        pt = layer_fn(CT)
        test_and_record(f"single_{name}", pt)

    # K3 transposition only
    pt = k3_trans(CT)
    test_and_record("single_K3trans", pt)

    # K3 full method (sub + trans)
    intermediate = vig_dec_std(CT, K3_SUB_KEY)
    pt = k3_trans(intermediate)  # Wait -- this is wrong for K3 decrypt
    # K3 encrypt = transpose THEN vig encrypt
    # K3 decrypt = vig decrypt THEN inverse transpose
    # But columnar_decrypt already handles the inverse
    # Actually: K3 encrypt: PT → columnar_encrypt → vig_encrypt = CT
    # K3 decrypt: CT → vig_decrypt → columnar_decrypt = PT
    # So: vig_dec first, then columnar_dec
    test_and_record("single_K3full_Vig_trans", pt)

    # Also try trans first then sub (wrong order for K3 but test it)
    intermediate2 = k3_trans(CT)
    pt2 = vig_dec_std(intermediate2, K3_SUB_KEY)
    test_and_record("single_K3full_trans_Vig", pt2)

    print(f"  Phase A: {total_tests} tests, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # PHASE B: Two-layer combinations
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE B: Two-layer combinations (sub × sub)")
    print("─" * 72)

    # Test all pairs of substitution layers
    sub_names = list(sub_layers.keys())
    for i, name1 in enumerate(sub_names):
        for j, name2 in enumerate(sub_names):
            if i == j:
                continue
            # Skip same-section same-variant pairs (redundant)
            sec1 = name1.split('_')[0]  # K1, K2, K3sub
            sec2 = name2.split('_')[0]
            if sec1 == sec2:
                continue

            pt = sub_layers[name2](sub_layers[name1](CT))
            test_and_record(f"2L_{name1}_then_{name2}", pt)

    # Sub + trans combinations
    for name, layer_fn in sub_layers.items():
        # Sub first, then trans
        intermediate = layer_fn(CT)
        pt = k3_trans(intermediate)
        test_and_record(f"2L_{name}_then_K3trans", pt)

        # Trans first, then sub
        intermediate = k3_trans(CT)
        pt = layer_fn(intermediate)
        test_and_record(f"2L_K3trans_then_{name}", pt)

    print(f"  Phase B: {total_tests} tests, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # PHASE C: Three-layer combinations (the full onion)
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE C: Three-layer onion (K1 sub + K2 sub + K3 trans)")
    print("─" * 72)

    # Core K1 sub variants × K2 sub variants × K3 trans
    k1_variants = {k: v for k, v in sub_layers.items() if k.startswith("K1_")}
    k2_variants = {k: v for k, v in sub_layers.items() if k.startswith("K2_")}

    # All 6 orderings of (K1_sub, K2_sub, K3_trans)
    for k1_name, k1_fn in k1_variants.items():
        for k2_name, k2_fn in k2_variants.items():
            # Order 1: K1 → K2 → trans
            t1 = k1_fn(CT)
            t2 = k2_fn(t1)
            pt = k3_trans(t2)
            test_and_record(f"3L_{k1_name}_{k2_name}_K3trans", pt)

            # Order 2: K1 → trans → K2
            t1 = k1_fn(CT)
            t2 = k3_trans(t1)
            pt = k2_fn(t2)
            test_and_record(f"3L_{k1_name}_K3trans_{k2_name}", pt)

            # Order 3: K2 → K1 → trans
            t1 = k2_fn(CT)
            t2 = k1_fn(t1)
            pt = k3_trans(t2)
            test_and_record(f"3L_{k2_name}_{k1_name}_K3trans", pt)

            # Order 4: K2 → trans → K1
            t1 = k2_fn(CT)
            t2 = k3_trans(t1)
            pt = k1_fn(t2)
            test_and_record(f"3L_{k2_name}_K3trans_{k1_name}", pt)

            # Order 5: trans → K1 → K2
            t1 = k3_trans(CT)
            t2 = k1_fn(t1)
            pt = k2_fn(t2)
            test_and_record(f"3L_K3trans_{k1_name}_{k2_name}", pt)

            # Order 6: trans → K2 → K1
            t1 = k3_trans(CT)
            t2 = k2_fn(t1)
            pt = k1_fn(t2)
            test_and_record(f"3L_K3trans_{k2_name}_{k1_name}", pt)

    print(f"  Phase C: {total_tests} tests, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # PHASE D: Additive key stacking
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE D: Additive key stacking (keys combined mod 26)")
    print("─" * 72)

    # PALIMPSEST (p10) + ABSCISSA (p8) → period LCM(10,8) = 40
    combined_pa = [(K1_KEY_AZ[i % 10] + K2_KEY_AZ[i % 8]) % 26 for i in range(CT_LEN)]
    combined_pa_ka = [(K1_KEY_KA[i % 10] + K2_KEY_KA[i % 8]) % 26 for i in range(CT_LEN)]

    for label, key in [
        ("add_PAL+ABS_AZ", combined_pa),
        ("add_PAL+ABS_KA", combined_pa_ka),
    ]:
        # Direct
        pt = vig_dec_std(CT, key)
        test_and_record(f"D_{label}_Vig", pt)
        pt = beau_dec_std(CT, key)
        test_and_record(f"D_{label}_Beau", pt)

        # With K3 trans before
        intermediate = k3_trans(CT)
        pt = vig_dec_std(intermediate, key)
        test_and_record(f"D_K3trans_{label}_Vig", pt)
        pt = beau_dec_std(intermediate, key)
        test_and_record(f"D_K3trans_{label}_Beau", pt)

        # With K3 trans after
        pt_pre = vig_dec_std(CT, key)
        pt = k3_trans(pt_pre)
        test_and_record(f"D_{label}_Vig_K3trans", pt)
        pt_pre = beau_dec_std(CT, key)
        pt = k3_trans(pt_pre)
        test_and_record(f"D_{label}_Beau_K3trans", pt)

    # Triple additive: PALIMPSEST + ABSCISSA + KRYPTOS_alphabetical_values
    kryptos_key = make_key("KRYPTOS", AZ_IDX)  # [10,17,24,15,19,14,18]
    combined_pak = [(K1_KEY_AZ[i % 10] + K2_KEY_AZ[i % 8] + kryptos_key[i % 7]) % 26
                    for i in range(CT_LEN)]

    pt = vig_dec_std(CT, combined_pak)
    test_and_record("D_add_PAL+ABS+KRY_Vig", pt)
    pt = beau_dec_std(CT, combined_pak)
    test_and_record("D_add_PAL+ABS+KRY_Beau", pt)

    # With T offset from K0
    combined_pa_t = [(v + K0_T_OFFSET) % 26 for v in combined_pa]
    pt = vig_dec_std(CT, combined_pa_t)
    test_and_record("D_add_PAL+ABS+T19_Vig", pt)
    pt = beau_dec_std(CT, combined_pa_t)
    test_and_record("D_add_PAL+ABS+T19_Beau", pt)

    combined_pak_t = [(v + K0_T_OFFSET) % 26 for v in combined_pak]
    pt = vig_dec_std(CT, combined_pak_t)
    test_and_record("D_add_PAL+ABS+KRY+T19_Vig", pt)
    pt = beau_dec_std(CT, combined_pak_t)
    test_and_record("D_add_PAL+ABS+KRY+T19_Beau", pt)

    print(f"  Phase D: {total_tests} tests, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # PHASE E: K0 E-group pattern as additional layer
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE E: K0 contribution (E-groups + T-offset)")
    print("─" * 72)

    # E-group sizes as key: [2,1,5,1,3,2,2,5,3,1,1] (period 11)
    e_group_key = K0_E_GROUPS

    # E-group cumulative: [2,3,8,9,12,14,16,21,24,25,26]
    e_group_cum = [sum(K0_E_GROUPS[:i+1]) for i in range(len(K0_E_GROUPS))]

    for k0_name, k0_key in [
        ("E_groups", e_group_key),
        ("E_cumulative", e_group_cum),
    ]:
        full_k0 = [(k0_key[i % len(k0_key)]) % 26 for i in range(CT_LEN)]

        # K0 alone
        pt = vig_dec_std(CT, full_k0)
        test_and_record(f"E_{k0_name}_Vig", pt)

        # K0 + K1
        combined = [(full_k0[i] + K1_KEY_AZ[i % 10]) % 26 for i in range(CT_LEN)]
        pt = vig_dec_std(CT, combined)
        test_and_record(f"E_{k0_name}+K1_Vig", pt)

        # K0 + K2
        combined = [(full_k0[i] + K2_KEY_AZ[i % 8]) % 26 for i in range(CT_LEN)]
        pt = vig_dec_std(CT, combined)
        test_and_record(f"E_{k0_name}+K2_Vig", pt)

        # K0 + K1 + K2
        combined = [(full_k0[i] + K1_KEY_AZ[i % 10] + K2_KEY_AZ[i % 8]) % 26
                    for i in range(CT_LEN)]
        pt = vig_dec_std(CT, combined)
        test_and_record(f"E_{k0_name}+K1+K2_Vig", pt)
        pt = beau_dec_std(CT, combined)
        test_and_record(f"E_{k0_name}+K1+K2_Beau", pt)

        # K0 + K1 + K2 + K3 trans
        intermediate = k3_trans(CT)
        pt = vig_dec_std(intermediate, combined)
        test_and_record(f"E_K3trans_{k0_name}+K1+K2_Vig", pt)

        # K0 + K1 + K2 + KRYPTOS
        combined_full = [(full_k0[i] + K1_KEY_AZ[i % 10] + K2_KEY_AZ[i % 8]
                         + kryptos_key[i % 7]) % 26 for i in range(CT_LEN)]
        pt = vig_dec_std(CT, combined_full)
        test_and_record(f"E_{k0_name}+K1+K2+KRY_Vig", pt)
        pt = beau_dec_std(CT, combined_full)
        test_and_record(f"E_{k0_name}+K1+K2+KRY_Beau", pt)

    print(f"  Phase E: {total_tests} tests, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # PHASE F: Full onion with ALL w7 columnar orderings
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE F: Onion layers × ALL 5040 w7 orderings")
    print("─" * 72)

    # Best substitution combinations from phases above, with all w7 orderings
    # Key combos to test with transposition:
    key_combos = {
        "PAL_AZ": K1_KEY_AZ,
        "ABS_AZ": K2_KEY_AZ,
        "add_PA": combined_pa,
        "add_PAK": combined_pak,
        "add_PA_T": combined_pa_t,
        "add_PAK_T": combined_pak_t,
    }

    phase_f_best = 0
    phase_f_count = 0

    for perm_tuple in itertools.permutations(range(7)):
        col_order = list(perm_tuple)
        trans_fn = make_trans_layer(col_order, 7)

        for kc_name, kc_vals in key_combos.items():
            # Trans → Sub (undo trans first, then sub)
            intermediate = trans_fn(CT)
            for vname, vfn in [("Vig", vig_dec_std), ("Beau", beau_dec_std)]:
                pt = vfn(intermediate, kc_vals)
                sc = score_cribs(pt)
                total_tests += 1
                phase_f_count += 1

                if sc > phase_f_best:
                    phase_f_best = sc
                    label = f"F_w7perm_then_{kc_name}_{vname}"
                    print(f"  New best: {sc}/24 — order={col_order} {kc_name} {vname}")
                    if sc > NOISE_FLOOR:
                        results.append({
                            "test": label,
                            "score": sc,
                            "col_order": col_order,
                            "key_combo": kc_name,
                            "pt_snippet": pt[:60],
                        })

                # Sub → Trans (undo sub first, then trans)
                pt_sub = vfn(CT, kc_vals)
                pt = trans_fn(pt_sub)
                sc2 = score_cribs(pt)
                total_tests += 1
                phase_f_count += 1

                if sc2 > phase_f_best:
                    phase_f_best = sc2
                    label = f"F_{kc_name}_{vname}_then_w7perm"
                    print(f"  New best: {sc2}/24 — {kc_name} {vname} then order={col_order}")
                    if sc2 > NOISE_FLOOR:
                        results.append({
                            "test": label,
                            "score": sc2,
                            "col_order": col_order,
                            "key_combo": kc_name,
                            "pt_snippet": pt[:60],
                        })

        if (phase_f_count % 100000) == 0 and phase_f_count > 0:
            elapsed = time_mod.time() - t0
            print(f"  ... {phase_f_count} configs, best={phase_f_best}, {elapsed:.1f}s")

    print(f"  Phase F: {phase_f_count} configs, best={phase_f_best}")

    # ──────────────────────────────────────────────────────────────────────
    # PHASE G: Subtractive key stacking (in case layers subtract)
    # ──────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE G: Subtractive and alternating key combinations")
    print("─" * 72)

    # PAL - ABS, ABS - PAL, etc.
    sub_combos = {
        "PAL-ABS": [(K1_KEY_AZ[i % 10] - K2_KEY_AZ[i % 8]) % 26 for i in range(CT_LEN)],
        "ABS-PAL": [(K2_KEY_AZ[i % 8] - K1_KEY_AZ[i % 10]) % 26 for i in range(CT_LEN)],
        "PAL*ABS": [(K1_KEY_AZ[i % 10] * K2_KEY_AZ[i % 8]) % 26 for i in range(CT_LEN)],
        "PAL_xor_ABS": [(K1_KEY_AZ[i % 10] ^ K2_KEY_AZ[i % 8]) % 26 for i in range(CT_LEN)],
    }

    for sc_name, sc_key in sub_combos.items():
        for vname, vfn in [("Vig", vig_dec_std), ("Beau", beau_dec_std)]:
            # Direct
            pt = vfn(CT, sc_key)
            test_and_record(f"G_{sc_name}_{vname}", pt)

            # With K3 trans
            intermediate = k3_trans(CT)
            pt = vfn(intermediate, sc_key)
            test_and_record(f"G_K3trans_{sc_name}_{vname}", pt)

            pt_sub = vfn(CT, sc_key)
            pt = k3_trans(pt_sub)
            test_and_record(f"G_{sc_name}_{vname}_K3trans", pt)

    print(f"  Phase G: {total_tests} tests, best={best_score}")

    # ──────────────────────────────────────────────────────────────────────
    # SUMMARY
    # ──────────────────────────────────────────────────────────────────────
    elapsed = time_mod.time() - t0

    above_noise = [r for r in results if r["score"] > NOISE_FLOOR]
    above_store = [r for r in results if r["score"] >= STORE_THRESHOLD]

    if results:
        best = max(results, key=lambda r: r["score"])
    else:
        best = {"score": 0, "test": "none"}

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configurations tested: {total_tests}")
    print(f"Above NOISE ({NOISE_FLOOR}): {len(above_noise)}")
    print(f"Above STORE ({STORE_THRESHOLD}): {len(above_store)}")
    print(f"Best score: {best_score} ({best.get('test', 'N/A')})")
    print(f"Elapsed: {elapsed:.1f}s")

    if above_noise:
        print(f"\nTop results:")
        for r in sorted(above_noise, key=lambda x: -x["score"])[:15]:
            print(f"  score={r['score']} | {r['test']}")

    print(f"\nConclusion: ", end="")
    if best_score >= STORE_THRESHOLD:
        print(f"SIGNAL — best score {best_score} warrants investigation")
    elif best_score > NOISE_FLOOR:
        print(f"Marginal (best={best_score}), logged but likely noise")
    else:
        print(f"No signal from progressive onion model with known K0-K3 parameters.")

    # Save results
    os.makedirs("results", exist_ok=True)
    output = {
        "experiment": "E-S-143",
        "description": "Progressive onion: K0/K1/K2/K3 layers stacked on K4",
        "total_tests": total_tests,
        "best_score": best_score,
        "best_test": best.get("test"),
        "above_noise": len(above_noise),
        "above_store": len(above_store),
        "elapsed_s": round(elapsed, 1),
        "results": sorted(results, key=lambda r: -r["score"])[:50],
    }

    outpath = "results/e_s_143_progressive_onion.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {outpath}")


if __name__ == "__main__":
    main()
