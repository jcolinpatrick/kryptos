#!/usr/bin/env python3
"""
Cipher: encoding/extraction
Family: encoding
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
"""E-02: Test misspelling substitution deltas as K4 cipher key material.

Hypothesis: The deltas from Kryptos misspellings {22, 10, 5, 6, 22}
function as a Vigenère key, transposition selector, or primer for K4.

Misspelling delta derivation:
  K0 Morse:  DIGITAL→DIGETAL,   I(8)→E(4),   delta = -4 mod 26 = 22
  K1 key:    PALIMPSEST→PALIMPCEST, S(18)→C(2), delta = -16 mod 26 = 10
  K1 pt:     ILLUSION→IQLUSION, L(11)→Q(16),  delta = +5 = 5
  K2 pt:     UNDERGROUND→UNDERGRUUND, O(14)→U(20), delta = +6 = 6
  K3 pt:     DESPERATELY→DESPARATLY, E(4)→A(0), delta = -4 mod 26 = 22

Also tests: wrong letters as direct values (C=2, Q=16, U=20, A=0, E=4),
EQUAL anagram values, YAR/DYARO numeric values, and combinations.
"""

import itertools
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC, BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]


def char_to_num(c):
    return ALPH_IDX[c]


def num_to_char(n):
    return chr(ord('A') + (n % 26))


def vig_decrypt(ct_nums, key_nums):
    """Vigenère decrypt: PT = (CT - K) mod 26"""
    period = len(key_nums)
    return [(ct_nums[i] - key_nums[i % period]) % MOD for i in range(len(ct_nums))]


def beaufort_decrypt(ct_nums, key_nums):
    """Beaufort decrypt: PT = (K - CT) mod 26"""
    period = len(key_nums)
    return [(key_nums[i % period] - ct_nums[i]) % MOD for i in range(len(ct_nums))]


def var_beaufort_decrypt(ct_nums, key_nums):
    """Variant Beaufort decrypt: PT = (CT + K) mod 26"""
    period = len(key_nums)
    return [(ct_nums[i] + key_nums[i % period]) % MOD for i in range(len(ct_nums))]


def score_cribs(pt_nums):
    """Score against known cribs. Returns (matches, total)."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == ALPH_IDX[ch]:
            matches += 1
    return matches


def check_bean(pt_nums):
    """Check Bean equality and inequality constraints on keystream."""
    # Compute keystream
    key = [(CT_NUM[i] - pt_nums[i]) % MOD for i in range(len(pt_nums))]
    for a, b in BEAN_EQ:
        if a < len(key) and b < len(key) and key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if a < len(key) and b < len(key) and key[a] == key[b]:
            return False
    return True


def apply_transposition(ct, perm):
    """Apply a transposition permutation to ciphertext."""
    block_size = len(perm)
    result = []
    for start in range(0, len(ct), block_size):
        block = ct[start:start + block_size]
        if len(block) == block_size:
            result.extend(block[perm[j]] for j in range(block_size))
        else:
            result.extend(block)  # partial block unchanged
    return result


def test_key_sequence(name, key_nums, ct_num, ct_len, verbose=True):
    """Test a numeric key sequence as Vigenère/Beaufort key at all rotations.

    Returns list of (score, pt_text, method_description) tuples.
    """
    results = []
    period = len(key_nums)

    for rotation in range(period):
        rotated = key_nums[rotation:] + key_nums[:rotation]

        for variant_name, decrypt_fn in [
            ("Vigenere", vig_decrypt),
            ("Beaufort", beaufort_decrypt),
            ("VarBeaufort", var_beaufort_decrypt),
        ]:
            pt = decrypt_fn(ct_num, rotated)
            score = score_cribs(pt)
            bean = check_bean(pt)

            pt_text = ''.join(num_to_char(n) for n in pt)
            key_text = ''.join(num_to_char(n) for n in rotated)
            method = (f"Phase1 {name} {variant_name} rot={rotation} "
                      f"key={key_text} bean={'PASS' if bean else 'FAIL'}")
            results.append((float(score), pt_text, method))

    return results


def test_transposition_then_vig(name, perm, key_nums, ct_num, ct_len):
    """Test: transpose CT, then Vigenère decrypt.

    Returns list of (score, pt_text, method_description) tuples.
    """
    results = []
    for rotation in range(len(key_nums)):
        rotated = key_nums[rotation:] + key_nums[:rotation]
        for vig_period in range(1, 27):
            vig_key = rotated[:vig_period] if vig_period <= len(rotated) else rotated
            transposed = apply_transposition(ct_num, perm)
            pt = vig_decrypt(transposed, vig_key)
            score = score_cribs(pt)
            if score >= 3:
                pt_text = ''.join(num_to_char(n) for n in pt)
                method = (f"Phase3_trans {name} trans+Vig rot={rotation} "
                          f"p={vig_period} score={score}/{N_CRIBS}")
                results.append((float(score), pt_text, method))
    return results


def attack(ciphertext, **params):
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    ct_num = [ALPH_IDX[c] for c in ciphertext]
    ct_len = len(ciphertext)

    all_results = []

    # ── Primary delta sequences ──────────────────────────────────────────────

    deltas_wrong_minus_correct = [
        (4 - 8) % 26,   # E-I = 22
        (2 - 18) % 26,  # C-S = 10
        (16 - 11) % 26, # Q-L = 5
        (20 - 14) % 26, # U-O = 6
        (0 - 4) % 26,   # A-E = 22
    ]

    deltas_correct_minus_wrong = [(26 - d) % 26 for d in deltas_wrong_minus_correct]

    wrong_letters = [2, 16, 20, 0, 4]
    correct_letters = [8, 18, 11, 14, 4]
    equal_values = [4, 16, 20, 0, 11]
    yar_values = [24, 0, 17]
    dyaro_values = [3, 24, 0, 17, 14]

    # ── Phase 1: Direct key tests ──────────────────────────────────────────

    sequences = {
        "deltas(wrong-correct)=[22,10,5,6,22]": deltas_wrong_minus_correct,
        "deltas(correct-wrong)=[4,16,21,20,4]": deltas_correct_minus_wrong,
        "wrong_letters=[2,16,20,0,4]": wrong_letters,
        "correct_letters=[8,18,11,14,4]": correct_letters,
        "EQUAL=[4,16,20,0,11]": equal_values,
        "YAR=[24,0,17]": yar_values,
        "DYARO=[3,24,0,17,14]": dyaro_values,
    }

    for name, seq in sequences.items():
        results = test_key_sequence(name, seq, ct_num, ct_len, verbose=False)
        all_results.extend(results)

    # ── Phase 2: Combined sequences ──────────────────────────────────────

    for combo_name, combo in [
        ("deltas+YAR", deltas_wrong_minus_correct + yar_values),
        ("YAR+deltas", yar_values + deltas_wrong_minus_correct),
        ("deltas+DYARO", deltas_wrong_minus_correct + dyaro_values),
        ("DYARO+deltas", dyaro_values + deltas_wrong_minus_correct),
        ("EQUAL+YAR", equal_values + yar_values),
        ("EQUAL+DYARO", equal_values + dyaro_values),
        ("wrong+YAR", wrong_letters + yar_values),
        ("wrong+DYARO", wrong_letters + dyaro_values),
    ]:
        results = test_key_sequence(combo_name, combo, ct_num, ct_len, verbose=False)
        all_results.extend(results)

    # ── Phase 3: As transposition column selectors ─────────────────────────

    for name, seq in [
        ("deltas", deltas_wrong_minus_correct),
        ("DYARO", dyaro_values),
        ("EQUAL", equal_values),
    ]:
        width = len(seq)
        ranked = sorted(range(width), key=lambda i: (seq[i], i))
        perm = [0] * width
        for rank, idx in enumerate(ranked):
            perm[idx] = rank

        for direction in ["encrypt", "decrypt"]:
            n_rows = (ct_len + width - 1) // width
            grid = []
            for r in range(n_rows):
                row = []
                for c in range(width):
                    idx = r * width + c
                    if idx < ct_len:
                        row.append(ct_num[idx])
                    else:
                        row.append(0)
                grid.append(row)

            if direction == "encrypt":
                result = []
                for col in perm:
                    for r in range(n_rows):
                        idx = r * width + col
                        if idx < ct_len:
                            result.append(grid[r][col])
            else:
                inv_perm = [0] * width
                for i, p in enumerate(perm):
                    inv_perm[p] = i

                result = []
                for col in inv_perm:
                    for r in range(n_rows):
                        idx = r * width + col
                        if idx < ct_len:
                            result.append(grid[r][col])

            result = result[:ct_len]
            score = score_cribs(result)
            if score >= 3:
                text = ''.join(num_to_char(n) for n in result)
                method = (f"Phase3_columnar {name} {direction} "
                          f"perm={perm} score={score}/{N_CRIBS}")
                all_results.append((float(score), text, method))

    # ── Phase 4: Deltas as additive mask ─────────────────────────────────

    for name, seq in sequences.items():
        period = len(seq)
        for offset in range(period):
            pt = [(ct_num[i] - seq[(i + offset) % period]) % MOD for i in range(ct_len)]
            score = score_cribs(pt)
            if score >= 3:
                bean = check_bean(pt)
                pt_text = ''.join(num_to_char(n) for n in pt)
                method = (f"Phase4_mask {name} offset={offset} "
                          f"bean={'PASS' if bean else 'FAIL'}")
                all_results.append((float(score), pt_text, method))

    # ── Phase 5: Extended delta sequences ────────────────────────────────

    base = deltas_wrong_minus_correct
    for repeat in [2, 3, 4]:
        extended = (base * repeat)[:26]
        results = test_key_sequence(
            f"deltas_x{repeat}(len={len(extended)})", extended,
            ct_num, ct_len, verbose=False
        )
        all_results.extend(results)

    # ── Phase 6: Delta-seeded linear recurrence ──────────────────────────

    for order in range(2, 6):
        seed = base[:order]
        key = list(seed)
        for i in range(order, ct_len):
            key.append(sum(key[i - order:i]) % MOD)

        for variant_name, decrypt_fn in [
            ("Vigenere", vig_decrypt),
            ("Beaufort", beaufort_decrypt),
        ]:
            pt = decrypt_fn(ct_num, key)
            score = score_cribs(pt)
            if score >= 3:
                bean = check_bean(pt)
                pt_text = ''.join(num_to_char(n) for n in pt)
                method = (f"Phase6_recurrence additive order={order} {variant_name} "
                          f"bean={'PASS' if bean else 'FAIL'}")
                all_results.append((float(score), pt_text, method))

    # Multiplicative: k[i] = (a * k[i-1] + b) mod 26
    for a_val in range(1, 26):
        for b_val in range(26):
            key = [base[0]]
            for i in range(1, ct_len):
                key.append((a_val * key[-1] + b_val) % MOD)

            pt = vig_decrypt(ct_num, key)
            score = score_cribs(pt)
            if score >= 6:
                bean = check_bean(pt)
                pt_text = ''.join(num_to_char(n) for n in pt)
                method = (f"Phase6_linear k[i]=({a_val}*k[i-1]+{b_val})mod26 "
                          f"seed={base[0]} bean={'PASS' if bean else 'FAIL'}")
                all_results.append((float(score), pt_text, method))

    # Sort by score descending
    all_results.sort(key=lambda r: r[0], reverse=True)
    return all_results


def main():
    print("=" * 80)
    print("E-02: Misspelling Delta Sequence as K4 Key Material")
    print("=" * 80)

    results = attack(CT)

    # ── Print phase-by-phase summary ──────────────────────────────────────

    print("\n── Phase 1: Direct key tests (all rotations, all variants) ──")
    phase1 = [r for r in results if r[2].startswith("Phase1")]
    above_noise_1 = [r for r in phase1 if r[0] >= 6]
    for score, pt, method in above_noise_1:
        print(f"  ** ABOVE NOISE: {method} -> {score:.0f}/{N_CRIBS}")

    print("\n── Phase 2: Combined sequences ──")
    phase2 = [r for r in results if r[2].startswith("Phase1") and any(
        c in r[2] for c in ["deltas+", "YAR+", "DYARO+", "EQUAL+", "wrong+"])]
    above_noise_2 = [r for r in phase2 if r[0] >= 6]
    for score, pt, method in above_noise_2:
        print(f"  ** ABOVE NOISE: {method} -> {score:.0f}/{N_CRIBS}")

    print("\n── Phase 3: As transposition column selectors ──")
    phase3 = [r for r in results if r[2].startswith("Phase3")]
    for score, pt, method in phase3:
        print(f"  {method}")

    print("\n── Phase 4: Deltas as additive mask ──")
    phase4 = [r for r in results if r[2].startswith("Phase4")]
    for score, pt, method in phase4:
        if score >= 6:
            print(f"  ** {method} score={score:.0f}/{N_CRIBS}")
            print(f"     PT: {pt}")

    print("\n── Phase 5: Extended delta sequences (repeat patterns) ──")
    phase5 = [r for r in results if "deltas_x" in r[2]]
    above_noise_5 = [r for r in phase5 if r[0] >= 6]
    for score, pt, method in above_noise_5:
        print(f"  ** {method} -> {score:.0f}/{N_CRIBS}")

    print("\n── Phase 6: Delta values as seeds for recurrence keystreams ──")
    phase6 = [r for r in results if r[2].startswith("Phase6")]
    for score, pt, method in phase6:
        if score >= 6:
            print(f"  ** {method} score={score:.0f}/{N_CRIBS}")

    # ── Summary ──────────────────────────────────────────────────────────

    print("\n" + "=" * 80)
    print("SUMMARY: Top results")
    print("=" * 80)
    for score, pt, method in results[:10]:
        print(f"  {score:.0f}/{N_CRIBS} | {method}")

    best_score = results[0][0] if results else 0
    print(f"\nBest score: {best_score:.0f}/{N_CRIBS}")
    if best_score >= 17:
        print("SUCCESS: Above threshold for misspelling-delta hypothesis")
    elif best_score >= 10:
        print("INTERESTING: Above noise but below signal threshold")
    else:
        print("FAILURE: Misspelling deltas as direct key material -> at noise floor")

    print("\n[E-02 COMPLETE]")
    return best_score


if __name__ == "__main__":
    main()
