#!/usr/bin/env python3
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


def test_key_sequence(name, key_nums, verbose=True):
    """Test a numeric key sequence as Vigenère/Beaufort key at all rotations."""
    best = (0, "", "", 0)
    period = len(key_nums)

    for rotation in range(period):
        rotated = key_nums[rotation:] + key_nums[:rotation]

        for variant_name, decrypt_fn in [
            ("Vigenère", vig_decrypt),
            ("Beaufort", beaufort_decrypt),
            ("VarBeaufort", var_beaufort_decrypt),
        ]:
            pt = decrypt_fn(CT_NUM, rotated)
            score = score_cribs(pt)
            bean = check_bean(pt)

            if score > best[0] or (score == best[0] and bean):
                pt_text = ''.join(num_to_char(n) for n in pt)
                best = (score, f"{variant_name} rot={rotation}", pt_text, bean)

            if score >= 6 or (verbose and rotation == 0 and variant_name == "Vigenère"):
                pt_text = ''.join(num_to_char(n) for n in pt)
                key_text = ''.join(num_to_char(n) for n in rotated)
                bean_str = "BEAN✓" if bean else "bean✗"
                if verbose or score >= 6:
                    print(f"  {name} | {variant_name} rot={rotation} | key={key_text} | "
                          f"score={score}/{N_CRIBS} {bean_str}")

    return best


def test_transposition_then_vig(name, perm, key_nums):
    """Test: transpose CT, then Vigenère decrypt."""
    best = (0, "", "")
    for rotation in range(len(key_nums)):
        rotated = key_nums[rotation:] + key_nums[:rotation]
        for vig_period in range(1, 27):
            vig_key = rotated[:vig_period] if vig_period <= len(rotated) else rotated
            transposed = apply_transposition(CT_NUM, perm)
            pt = vig_decrypt(transposed, vig_key)
            score = score_cribs(pt)
            if score > best[0]:
                pt_text = ''.join(num_to_char(n) for n in pt)
                best = (score, f"trans+Vig rot={rotation} p={vig_period}", pt_text)
                if score >= 10:
                    print(f"  ** {name} | trans→Vig rot={rotation} p={vig_period} | score={score}/{N_CRIBS}")
    return best


def main():
    print("=" * 80)
    print("E-02: Misspelling Delta Sequence as K4 Key Material")
    print("=" * 80)

    # ── Primary delta sequences ──────────────────────────────────────────────

    # Delta = (wrong - correct) mod 26
    deltas_wrong_minus_correct = [
        (4 - 8) % 26,   # E-I = 22
        (2 - 18) % 26,  # C-S = 10
        (16 - 11) % 26, # Q-L = 5
        (20 - 14) % 26, # U-O = 6
        (0 - 4) % 26,   # A-E = 22
    ]

    # Delta = (correct - wrong) mod 26
    deltas_correct_minus_wrong = [(26 - d) % 26 for d in deltas_wrong_minus_correct]

    # Wrong letter values directly: C=2, Q=16, U=20, A=0, E=4
    wrong_letters = [2, 16, 20, 0, 4]

    # Correct letter values: I=8, S=18, L=11, O=14, E=4
    correct_letters = [8, 18, 11, 14, 4]

    # "EQUAL" = E,Q,U,A,L = 4,16,20,0,11
    equal_values = [4, 16, 20, 0, 11]

    # YAR numeric: Y=24, A=0, R=17
    yar_values = [24, 0, 17]

    # DYARO numeric: D=3, Y=24, A=0, R=17, O=14
    dyaro_values = [3, 24, 0, 17, 14]

    # ── Test each as cyclic Vigenère key ─────────────────────────────────────

    print("\n── Phase 1: Direct key tests (all rotations, all variants) ──")

    sequences = {
        "deltas(wrong-correct)=[22,10,5,6,22]": deltas_wrong_minus_correct,
        "deltas(correct-wrong)=[4,16,21,20,4]": deltas_correct_minus_wrong,
        "wrong_letters=[2,16,20,0,4]": wrong_letters,
        "correct_letters=[8,18,11,14,4]": correct_letters,
        "EQUAL=[4,16,20,0,11]": equal_values,
        "YAR=[24,0,17]": yar_values,
        "DYARO=[3,24,0,17,14]": dyaro_values,
    }

    all_results = []
    for name, seq in sequences.items():
        best = test_key_sequence(name, seq, verbose=False)
        all_results.append((best[0], name, best[1], best[3]))
        if best[0] >= 6:
            print(f"  ** ABOVE NOISE: {name} → {best[0]}/{N_CRIBS} ({best[1]}) bean={best[3]}")

    # ── Test combined sequences ──────────────────────────────────────────────

    print("\n── Phase 2: Combined sequences ──")

    # Delta + YAR
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
        best = test_key_sequence(combo_name, combo, verbose=False)
        all_results.append((best[0], combo_name, best[1], best[3]))
        if best[0] >= 6:
            print(f"  ** ABOVE NOISE: {combo_name} → {best[0]}/{N_CRIBS} ({best[1]}) bean={best[3]}")

    # ── Test as transposition column selectors ───────────────────────────────

    print("\n── Phase 3: As transposition column selectors ──")

    # Use delta values as column read-order for columnar transposition
    for name, seq in [
        ("deltas", deltas_wrong_minus_correct),
        ("DYARO", dyaro_values),
        ("EQUAL", equal_values),
    ]:
        width = len(seq)
        # Rank the values to get a permutation
        ranked = sorted(range(width), key=lambda i: (seq[i], i))
        perm = [0] * width
        for rank, idx in enumerate(ranked):
            perm[idx] = rank

        print(f"  {name} values={seq} → rank perm={perm}")

        # Columnar transposition read-off
        # Fill CT into rows of width `width`, then read off by column order
        for direction in ["encrypt", "decrypt"]:
            n_rows = (CT_LEN + width - 1) // width
            grid = []
            for r in range(n_rows):
                row = []
                for c in range(width):
                    idx = r * width + c
                    if idx < CT_LEN:
                        row.append(CT_NUM[idx])
                    else:
                        row.append(0)
                grid.append(row)

            if direction == "encrypt":
                # Read off by column in perm order
                result = []
                for col in perm:
                    for r in range(n_rows):
                        idx = r * width + col
                        if idx < CT_LEN:
                            result.append(grid[r][col])
            else:
                # Inverse: write into columns in perm order, read off by rows
                inv_perm = [0] * width
                for i, p in enumerate(perm):
                    inv_perm[p] = i

                result = []
                for col in inv_perm:
                    for r in range(n_rows):
                        idx = r * width + col
                        if idx < CT_LEN:
                            result.append(grid[r][col])

            result = result[:CT_LEN]
            score = score_cribs(result)
            if score >= 3:
                text = ''.join(num_to_char(n) for n in result)
                print(f"    {name} columnar {direction}: score={score}/{N_CRIBS}")

    # ── Phase 4: Deltas as additive mask (position-dependent offset) ─────────

    print("\n── Phase 4: Deltas as additive mask ──")

    for name, seq in sequences.items():
        period = len(seq)
        # Apply as cyclic additive mask: PT[i] = (CT[i] - seq[i%p]) mod 26
        for offset in range(period):
            pt = [(CT_NUM[i] - seq[(i + offset) % period]) % MOD for i in range(CT_LEN)]
            score = score_cribs(pt)
            if score >= 6:
                bean = check_bean(pt)
                pt_text = ''.join(num_to_char(n) for n in pt)
                print(f"  ** {name} offset={offset}: score={score}/{N_CRIBS} bean={bean}")
                print(f"     PT: {pt_text}")

    # ── Phase 5: Extended delta sequences ────────────────────────────────────

    print("\n── Phase 5: Extended delta sequences (repeat patterns) ──")

    # Try doubling, tripling the delta sequence
    base = deltas_wrong_minus_correct
    for repeat in [2, 3, 4]:
        extended = (base * repeat)[:26]  # Cap at 26
        best = test_key_sequence(f"deltas×{repeat} (len={len(extended)})", extended, verbose=False)
        all_results.append((best[0], f"deltas×{repeat}", best[1], best[3]))
        if best[0] >= 6:
            print(f"  ** deltas×{repeat} → {best[0]}/{N_CRIBS} ({best[1]})")

    # ── Phase 6: Delta-seeded linear recurrence ──────────────────────────────

    print("\n── Phase 6: Delta values as seeds for recurrence keystreams ──")

    base = deltas_wrong_minus_correct  # [22, 10, 5, 6, 22]

    # Simple additive recurrence: k[i] = (k[i-1] + k[i-2] + ... + k[i-order]) mod 26
    for order in range(2, 6):
        seed = base[:order]
        key = list(seed)
        for i in range(order, CT_LEN):
            key.append(sum(key[i - order:i]) % MOD)

        for variant_name, decrypt_fn in [
            ("Vigenère", vig_decrypt),
            ("Beaufort", beaufort_decrypt),
        ]:
            pt = decrypt_fn(CT_NUM, key)
            score = score_cribs(pt)
            if score >= 6:
                bean = check_bean(pt)
                print(f"  ** additive recurrence order={order} {variant_name}: "
                      f"score={score}/{N_CRIBS} bean={bean}")

    # Multiplicative: k[i] = (a * k[i-1] + b) mod 26 for various a, b
    for a_val in range(1, 26):
        for b_val in range(26):
            key = [base[0]]
            for i in range(1, CT_LEN):
                key.append((a_val * key[-1] + b_val) % MOD)

            pt = vig_decrypt(CT_NUM, key)
            score = score_cribs(pt)
            if score >= 10:
                bean = check_bean(pt)
                print(f"  ** linear k[i]=({a_val}*k[i-1]+{b_val}) mod 26, seed={base[0]}: "
                      f"score={score}/{N_CRIBS} bean={bean}")

    # ── Summary ──────────────────────────────────────────────────────────────

    print("\n" + "=" * 80)
    print("SUMMARY: Top results")
    print("=" * 80)
    all_results.sort(reverse=True)
    for score, name, detail, bean in all_results[:10]:
        bean_str = "BEAN✓" if bean else "bean✗"
        print(f"  {score}/{N_CRIBS} {bean_str} | {name} | {detail}")

    best_score = all_results[0][0] if all_results else 0
    print(f"\nBest score: {best_score}/{N_CRIBS}")
    if best_score >= 17:
        print("SUCCESS: Above threshold for misspelling-delta hypothesis")
    elif best_score >= 10:
        print("INTERESTING: Above noise but below signal threshold")
    else:
        print("FAILURE: Misspelling deltas as direct key material → at noise floor")

    print("\n[E-02 COMPLETE]")
    return best_score


if __name__ == "__main__":
    main()
