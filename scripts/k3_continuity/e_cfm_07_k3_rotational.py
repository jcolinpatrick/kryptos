#!/usr/bin/env python3
"""
Cipher: K3-method extension
Family: k3_continuity
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-CFM-07: K3-style rotational transposition applied to K4.

[HYPOTHESIS] K3 uses double CW rotational transposition:
  Encrypt: PT → 24×14 grid → CW rotate → 8×42 grid → CW rotate → CT
  (both grids have 336 = K3 length)

K4 is 97 characters (prime), so no rectangular grid fits exactly. But with
1-5 padding characters, K4 could use the same method:
  98 = 2×49 = 7×14
  99 = 9×11 = 3×33
  100 = 4×25 = 5×20 = 10×10 = 2×50
  102 = 2×51 = 3×34 = 6×17

This experiment:
1. Implements CW/CCW grid rotation as position permutations
2. Tests single and double rotations for all padded grid sizes
3. Handles padding at end, start, and distributed positions
4. Scores each configuration against cribs
5. For promising configs, extracts the implied key fragment

Note: K3's second grid re-factorizes the SAME total length. E.g., 336 = 24×14
first, then 336 = 8×42 second. We follow this pattern.

VM: 28 vCPUs, 31GB RAM — compute budget is generous.
"""
import sys
import os
import math
from collections import defaultdict
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, compose_perms, validate_perm,
)
from kryptos.kernel.transforms.vigenere import vig_recover_key


# ══════════════════════════════════════════════════════════════════════════
# Grid rotation permutation generators
# ══════════════════════════════════════════════════════════════════════════

def cw_rotate_perm(nrows: int, ncols: int) -> list[int]:
    """Permutation for 90° clockwise rotation of an nrows×ncols grid.

    CW rotation: old[r][c] → new[c][nrows-1-r]
    New grid is ncols rows × nrows cols.

    Convention: output[new_pos] = input[old_pos] (gather).
    Text positions: pos = row * width + col.
    """
    length = nrows * ncols
    perm = [0] * length
    for old_pos in range(length):
        old_r, old_c = divmod(old_pos, ncols)
        new_r = old_c
        new_c = nrows - 1 - old_r
        new_pos = new_r * nrows + new_c  # new grid: ncols rows × nrows cols
        perm[new_pos] = old_pos
    return perm


def ccw_rotate_perm(nrows: int, ncols: int) -> list[int]:
    """Permutation for 90° counter-clockwise rotation.

    CCW rotation: old[r][c] → new[ncols-1-c][r]
    New grid is ncols rows × nrows cols.
    """
    length = nrows * ncols
    perm = [0] * length
    for old_pos in range(length):
        old_r, old_c = divmod(old_pos, ncols)
        new_r = ncols - 1 - old_c
        new_c = old_r
        new_pos = new_r * nrows + new_c
        perm[new_pos] = old_pos
    return perm


def factorizations(n: int, min_dim: int = 2) -> list[tuple[int, int]]:
    """All (nrows, ncols) pairs where nrows * ncols = n, nrows >= min_dim, ncols >= min_dim."""
    facts = []
    for r in range(min_dim, int(math.sqrt(n)) + 1):
        if n % r == 0:
            c = n // r
            if c >= min_dim:
                facts.append((r, c))
                if r != c:
                    facts.append((c, r))
    return sorted(facts)


def score_against_cribs(text: str) -> int:
    """Count crib position matches."""
    matches = 0
    for pos, expected in CRIB_DICT.items():
        if pos < len(text) and text[pos] == expected:
            matches += 1
    return matches


def check_bean(key_vals: dict[int, int]) -> tuple[bool, int]:
    """Check Bean EQ and count inequality passes."""
    eq_pass = True
    for i, j in BEAN_EQ:
        if i in key_vals and j in key_vals:
            if key_vals[i] != key_vals[j]:
                eq_pass = False

    ineq_count = 0
    for i, j in BEAN_INEQ:
        if i in key_vals and j in key_vals:
            if key_vals[i] != key_vals[j]:
                ineq_count += 1

    return eq_pass, ineq_count


def extract_key_fragment(ct_text: str, pt_text: str) -> dict[int, int]:
    """Extract Vigenere key values where PT is known (crib positions)."""
    key_vals = {}
    for pos, expected_pt in CRIB_DICT.items():
        if pos < len(ct_text) and pos < len(pt_text):
            ct_val = ALPH_IDX[ct_text[pos]]
            pt_val = ALPH_IDX[expected_pt]
            key_vals[pos] = (ct_val - pt_val) % MOD
    return key_vals


def main():
    print("=" * 70)
    print("E-CFM-07: K3-Style Rotational Transposition on K4")
    print("=" * 70)
    print(f"K4 CT length: {CT_LEN} (prime)")
    print(f"K3 method: PT → 24×14 → CW → 8×42 → CW → CT (length 336)")

    # ── Step 1: Enumerate padded lengths and factorizations ─────────────
    print("\n── Step 1: Padded grid dimensions ──")
    pad_configs = {}
    for pad in range(0, 6):
        L = CT_LEN + pad
        facts = factorizations(L, min_dim=2)
        if facts:
            pad_configs[pad] = (L, facts)
            fact_str = ", ".join(f"{r}×{c}" for r, c in facts)
            print(f"  pad={pad} → L={L}: {fact_str}")
        else:
            print(f"  pad={pad} → L={L}: no factorizations (skipping)")

    # ── Step 2: Single rotation tests ───────────────────────────────────
    print("\n── Step 2: Single rotation (CW and CCW) ──")
    print("Testing: apply rotation to CT (decrypt direction), score against cribs")
    print("Pad positions tested: END, START")

    best_single = 0
    best_single_config = ""
    single_results = []

    for pad, (L, facts) in pad_configs.items():
        for nrows, ncols in facts:
            for direction, rotate_fn, dir_name in [
                ("CW", cw_rotate_perm, "CW"),
                ("CCW", ccw_rotate_perm, "CCW"),
            ]:
                perm = rotate_fn(nrows, ncols)
                inv_perm = invert_perm(perm)

                for pad_loc in ["end", "start"]:
                    # Build padded CT
                    if pad == 0:
                        padded_ct = CT
                    elif pad_loc == "end":
                        padded_ct = CT + "X" * pad
                    else:
                        padded_ct = "X" * pad + CT

                    if len(padded_ct) != L:
                        continue

                    # Apply INVERSE rotation to get candidate PT
                    # (We're decrypting: CT was produced by rotation, so undo it)
                    candidate = apply_perm(padded_ct, inv_perm)

                    # Extract the K4 portion (remove padding)
                    if pad == 0:
                        pt_candidate = candidate
                    elif pad_loc == "end":
                        pt_candidate = candidate[:CT_LEN]
                    else:
                        pt_candidate = candidate[pad:]

                    if len(pt_candidate) < CT_LEN:
                        pt_candidate = pt_candidate + "?" * (CT_LEN - len(pt_candidate))

                    score = score_against_cribs(pt_candidate)

                    if score > NOISE_FLOOR or score > best_single:
                        config = f"pad={pad}({pad_loc}) {nrows}×{ncols} {dir_name}"
                        single_results.append((score, config, pt_candidate))
                        if score > best_single:
                            best_single = score
                            best_single_config = config

    print(f"\n  Best single rotation: {best_single}/24 — {best_single_config}")
    if single_results:
        # Show top 5
        single_results.sort(key=lambda x: -x[0])
        for score, config, pt in single_results[:5]:
            print(f"    {score}/24 | {config}")

    # ── Step 3: Double rotation (K3-style) ──────────────────────────────
    print("\n── Step 3: Double rotation (K3-style) ──")
    print("For each padded length L, try all pairs of factorizations (r1×c1 → r2×c2)")
    print("K3 pattern: first rotation output feeds directly into second grid")

    best_double = 0
    best_double_config = ""
    double_results = []
    configs_tested = 0

    for pad, (L, facts) in pad_configs.items():
        if len(facts) < 1:
            continue

        for (r1, c1) in facts:
            for (r2, c2) in facts:
                if r2 * c2 != L:
                    continue  # same total length required

                for d1_name, d1_fn in [("CW", cw_rotate_perm), ("CCW", ccw_rotate_perm)]:
                    for d2_name, d2_fn in [("CW", cw_rotate_perm), ("CCW", ccw_rotate_perm)]:
                        # First rotation: r1×c1 grid
                        perm1 = d1_fn(r1, c1)
                        # After first rotation, grid is c1×r1 (for CW) or c1×r1 (for CCW)
                        # But text is re-read linearly and written into r2×c2
                        # So perm1 takes the text from r1×c1 layout to rotated layout
                        # Then perm2 takes from r2×c2 layout to its rotated layout
                        perm2 = d2_fn(r2, c2)

                        # Combined encryption perm: apply perm1, then perm2
                        combined = compose_perms(perm1, perm2)
                        inv_combined = invert_perm(combined)

                        for pad_loc in ["end", "start"]:
                            if pad == 0:
                                padded_ct = CT
                            elif pad_loc == "end":
                                padded_ct = CT + "X" * pad
                            else:
                                padded_ct = "X" * pad + CT

                            if len(padded_ct) != L:
                                continue

                            # Decrypt
                            candidate = apply_perm(padded_ct, inv_combined)

                            if pad == 0:
                                pt_candidate = candidate
                            elif pad_loc == "end":
                                pt_candidate = candidate[:CT_LEN]
                            else:
                                pt_candidate = candidate[pad:]

                            if len(pt_candidate) < CT_LEN:
                                pt_candidate += "?" * (CT_LEN - len(pt_candidate))

                            score = score_against_cribs(pt_candidate)
                            configs_tested += 1

                            if score > NOISE_FLOOR:
                                config = (f"pad={pad}({pad_loc}) "
                                          f"{r1}×{c1}→{d1_name}→{r2}×{c2}→{d2_name}")
                                double_results.append((score, config, pt_candidate))
                                if score > best_double:
                                    best_double = score
                                    best_double_config = config

    print(f"\n  Configs tested: {configs_tested}")
    print(f"  Best double rotation: {best_double}/24 — {best_double_config}")
    if double_results:
        double_results.sort(key=lambda x: -x[0])
        for score, config, pt in double_results[:10]:
            print(f"    {score}/24 | {config}")

    # ── Step 4: K3-exact pattern (same first/second dimension sharing) ──
    print("\n── Step 4: K3-exact pattern (shared dimension) ──")
    print("K3: 24×14 → CW → then 8×42. Note: 14 and 42 share factor 14; 24 and 8 share factor 8.")
    print("Testing: pairs where grid dimensions share a common factor")

    shared_dim_results = []
    for pad, (L, facts) in pad_configs.items():
        for (r1, c1) in facts:
            for (r2, c2) in facts:
                if r2 * c2 != L:
                    continue
                # Check for shared dimension (like K3's pattern)
                shared = set()
                for d in [r1, c1]:
                    for d2 in [r2, c2]:
                        if d == d2 or (d > 1 and d2 % d == 0) or (d2 > 1 and d % d2 == 0):
                            shared.add((d, d2))
                if not shared:
                    continue

                perm1 = cw_rotate_perm(r1, c1)
                perm2 = cw_rotate_perm(r2, c2)
                combined = compose_perms(perm1, perm2)
                inv_combined = invert_perm(combined)

                for pad_loc in ["end"]:
                    padded_ct = CT + "X" * pad if pad > 0 else CT
                    if len(padded_ct) != L:
                        continue

                    candidate = apply_perm(padded_ct, inv_combined)
                    pt_candidate = candidate[:CT_LEN]
                    score = score_against_cribs(pt_candidate)

                    if score > 2:  # even low scores interesting here
                        config = f"pad={pad} {r1}×{c1}→CW→{r2}×{c2}→CW shared={shared}"
                        shared_dim_results.append((score, config, pt_candidate))

    if shared_dim_results:
        shared_dim_results.sort(key=lambda x: -x[0])
        print(f"  Found {len(shared_dim_results)} configs with score > 2")
        for score, config, pt in shared_dim_results[:10]:
            print(f"    {score}/24 | {config}")
    else:
        print("  No shared-dimension configs scored above 2/24")

    # ── Step 5: Pure transposition test (no substitution) ───────────────
    print("\n── Step 5: Pure transposition (CT=Trans(PT)) ──")
    print("If K4 is ONLY rotational transposition (like K3), CT frequencies = PT frequencies")
    print("K4 CT has 2 E's but cribs need 3 E's → IMPOSSIBLE for pure transposition")

    ct_freq = {}
    for c in CT:
        ct_freq[c] = ct_freq.get(c, 0) + 1
    crib_letters = list(CRIB_DICT.values())
    crib_freq = {}
    for c in crib_letters:
        crib_freq[c] = crib_freq.get(c, 0) + 1

    print(f"  CT has {ct_freq.get('E', 0)} E's, cribs need {crib_freq.get('E', 0)} E's")
    print(f"  [DERIVED FACT] Pure rotational transposition is IMPOSSIBLE for K4")
    print(f"  (already known, confirming here)")

    # ── Step 6: Transposition + Vigenere combined ───────────────────────
    print("\n── Step 6: Best rotations + Vigenere key analysis ──")
    print("For top-scoring transpositions, extract the implied Vigenere key")
    print("and check if it resembles English text (running key)")

    all_results = single_results + double_results
    all_results.sort(key=lambda x: -x[0])

    for score, config, pt_candidate in all_results[:15]:
        # The "pt_candidate" is what we get from pure transposition of CT
        # Under trans+sub model: CT = Trans(Sub(PT))
        # Decrypting trans: Trans_inv(CT) = Sub(PT)
        # So pt_candidate = Sub(PT), and at crib positions:
        # pt_candidate[i] = Sub(PT[i]) = (PT[i] + K[i]) mod 26
        # K[i] = (pt_candidate[i] - PT[i]) mod 26

        key_vals = {}
        for pos, expected_pt in CRIB_DICT.items():
            if pos < len(pt_candidate) and pt_candidate[pos] != "?":
                ct_rotated = ALPH_IDX[pt_candidate[pos]]
                pt_val = ALPH_IDX[expected_pt]
                key_vals[pos] = (ct_rotated - pt_val) % MOD

        if len(key_vals) < 20:
            continue

        # Check Bean
        eq_pass, ineq_count = check_bean(key_vals)

        # Key fragment as letters
        key_str_ene = "".join(ALPH[key_vals.get(p, 0)] for p in range(21, 34))
        key_str_bc = "".join(ALPH[key_vals.get(p, 0)] for p in range(63, 74))

        bean_str = f"Bean: EQ={'PASS' if eq_pass else 'FAIL'}, INEQ={ineq_count}/21"
        print(f"  {score}/24 | {config}")
        print(f"    Key@ENE: {key_str_ene} | Key@BC: {key_str_bc} | {bean_str}")

        if eq_pass and ineq_count >= 20:
            print(f"    *** Bean-passing config! Key fragments worth investigating ***")
            # Check vowel ratio of key
            all_key = key_str_ene + key_str_bc
            vowels = sum(1 for c in all_key if c in "AEIOU")
            print(f"    Key vowel ratio: {vowels}/{len(all_key)} = {vowels/len(all_key):.1%}")

    # ── Summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Grid sizes tested: pad 0-5 → lengths {[v[0] for v in pad_configs.values()]}")
    total_facts = sum(len(v[1]) for v in pad_configs.values())
    print(f"Total factorizations: {total_facts}")
    print(f"Single rotations tested: {len(single_results)} above noise floor")
    print(f"Double rotations tested: {configs_tested} total, {len(double_results)} above noise")
    print()
    print(f"Best single rotation: {best_single}/24")
    if best_single_config:
        print(f"  Config: {best_single_config}")
    print(f"Best double rotation: {best_double}/24")
    if best_double_config:
        print(f"  Config: {best_double_config}")
    print()

    best_overall = max(best_single, best_double)
    if best_overall >= SIGNAL_THRESHOLD:
        print(f"[SIGNAL] Score {best_overall}/24 exceeds signal threshold!")
        print("Verdict: SIGNAL — investigate!")
    elif best_overall > NOISE_FLOOR:
        print(f"[STORE] Score {best_overall}/24 above noise floor but below signal")
        print("Verdict: STORE — log but likely noise")
    else:
        print(f"[NOISE] Best score {best_overall}/24 at or below noise floor ({NOISE_FLOOR})")
        print()
        print("[INTERNAL RESULT] K3-style rotational transposition (single and double)")
        print("with padding 0-5 produces only noise-level crib scores.")
        print()
        print("Note: This tests PURE transposition applied to CT. Under a combined")
        print("trans+sub model, the transposition must be evaluated jointly with")
        print("the substitution layer. The Step 6 key analysis above checks whether")
        print("any rotation produces an English-like key fragment at crib positions.")
        print()
        print("Verdict: NOISE")


if __name__ == "__main__":
    main()
