#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-SOLVE-01: Novel K4 attack hypotheses not previously tested.

Tests five distinct hypotheses:
  1. 2D Matrix Key: key[i] = A[row(i)] + B[col(i)] mod 26 for all grid widths
  2. Interleaved Dual-Cipher: different cipher systems for position subsets
  3. KA Pre-Substitution: apply KA permutation before/after standard ciphers
  4. Kryptos-Derived Running Keys: tableau reads, K1-K3 CT, Antipodes text
  5. Position-Dependent Key Formulas: novel position functions not yet tested

Usage:
    PYTHONPATH=src python3 -u scripts/e_solve_01_novel_attacks.py
"""
from __future__ import annotations

import json
import sys
import time
from collections import defaultdict
from pathlib import Path

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, MOD,
    CRIB_DICT, CRIB_ENTRIES, CRIB_WORDS, N_CRIBS,
    KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)

# ── Helpers ──────────────────────────────────────────────────────────────

def vig_decrypt(ct_char: str, key_val: int) -> str:
    """Vigenere decrypt: PT = (CT - K) mod 26"""
    return ALPH[(ALPH_IDX[ct_char] - key_val) % MOD]

def beau_decrypt(ct_char: str, key_val: int) -> str:
    """Beaufort decrypt: PT = (K - CT) mod 26"""
    return ALPH[(key_val - ALPH_IDX[ct_char]) % MOD]

def var_beau_decrypt(ct_char: str, key_val: int) -> str:
    """Variant Beaufort: PT = (CT + K) mod 26"""
    return ALPH[(ALPH_IDX[ct_char] + key_val) % MOD]

def crib_score(candidate: str) -> int:
    """Count matching crib positions."""
    if len(candidate) != CT_LEN:
        return 0
    return sum(1 for pos, ch in CRIB_ENTRIES if candidate[pos] == ch)

def bean_check(keystream: list[int]) -> bool:
    """Check Bean equality and inequality constraints on keystream."""
    for a, b in BEAN_EQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] != keystream[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(keystream) and b < len(keystream):
            if keystream[a] == keystream[b]:
                return False
    return True

def decrypt_with_key(ct: str, keystream: list[int], variant: str = "vig") -> str:
    """Decrypt CT with given keystream using specified variant."""
    result = []
    for i, c in enumerate(ct):
        k = keystream[i % len(keystream)] if i < len(keystream) else keystream[i % len(keystream)]
        if variant == "vig":
            result.append(vig_decrypt(c, k))
        elif variant == "beau":
            result.append(beau_decrypt(c, k))
        elif variant == "var_beau":
            result.append(var_beau_decrypt(c, k))
    return "".join(result)

# Build KA permutation tables
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
KA_FORWARD = [KA_IDX[ALPH[i]] for i in range(26)]  # std_pos -> KA_pos
KA_INVERSE = [ALPH_IDX[KRYPTOS_ALPHABET[i]] for i in range(26)]  # KA_pos -> std_pos

def ka_perm_forward(text: str) -> str:
    """Replace each letter with its KA index mapped to standard alphabet."""
    return "".join(ALPH[KA_IDX[c]] for c in text)

def ka_perm_inverse(text: str) -> str:
    """Inverse of ka_perm_forward."""
    return "".join(KRYPTOS_ALPHABET[ALPH_IDX[c]] for c in text)


# ── Hypothesis 1: 2D Matrix Key ─────────────────────────────────────────

def test_2d_matrix_key():
    """
    Test if key[i] = A[floor(i/w)] + B[i%w] mod 26 is consistent with cribs.

    This models a "matrix code" where the key has separate row and column
    components. For each grid width w (2-96), check if the crib constraints
    form a consistent system of linear equations mod 26.
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 1: 2D Matrix Key (A[row] + B[col] mod 26)")
    print("="*70)

    # Known keystream at crib positions (Vigenere)
    crib_keys = {}
    for start, word in CRIB_WORDS:
        for i, ch in enumerate(word):
            pos = start + i
            crib_keys[pos] = (ALPH_IDX[CT[pos]] - ALPH_IDX[ch]) % MOD

    consistent_widths = []

    for w in range(2, CT_LEN):
        # For each width, build the system of equations:
        # key[pos] = A[pos//w] + B[pos%w] (mod 26)
        # From cribs: A[pos//w] + B[pos%w] = crib_keys[pos]

        # Collect equations
        equations = []
        for pos, kval in crib_keys.items():
            r = pos // w
            c = pos % w
            equations.append((r, c, kval))

        # Try to solve: set B[0] = 0 if any equation has col 0
        # More general: try all assignments

        # Collect unique rows and cols from equations
        rows_seen = set()
        cols_seen = set()
        for r, c, k in equations:
            rows_seen.add(r)
            cols_seen.add(c)

        # Build constraint graph: for each pair of equations sharing a row or col,
        # derive a constraint between B values or A values
        consistent = True

        # Group by row
        by_row = defaultdict(list)
        for r, c, k in equations:
            by_row[r].append((c, k))

        # Within each row, check consistency:
        # A[r] + B[c1] = k1 and A[r] + B[c2] = k2 → B[c2] - B[c1] = k2 - k1
        b_constraints = []  # (c1, c2, diff) meaning B[c2] - B[c1] ≡ diff mod 26
        for r, entries in by_row.items():
            for i in range(len(entries)):
                for j in range(i+1, len(entries)):
                    c1, k1 = entries[i]
                    c2, k2 = entries[j]
                    b_constraints.append((c1, c2, (k2 - k1) % MOD))

        # Group by column
        by_col = defaultdict(list)
        for r, c, k in equations:
            by_col[c].append((r, k))

        # Within each column, check consistency:
        # A[r1] + B[c] = k1 and A[r2] + B[c] = k2 → A[r2] - A[r1] = k2 - k1
        a_constraints = []
        for c, entries in by_col.items():
            for i in range(len(entries)):
                for j in range(i+1, len(entries)):
                    r1, k1 = entries[i]
                    r2, k2 = entries[j]
                    a_constraints.append((r1, r2, (k2 - k1) % MOD))

        # Now verify consistency: build equivalence classes with assigned values
        # using union-find on B values
        b_values = {}  # col -> assigned value (mod 26)

        # Assign B[first_col] = 0
        if not cols_seen:
            continue
        first_col = min(cols_seen)
        b_values[first_col] = 0

        # Propagate B constraints
        changed = True
        while changed:
            changed = False
            for c1, c2, diff in b_constraints:
                if c1 in b_values and c2 not in b_values:
                    b_values[c2] = (b_values[c1] + diff) % MOD
                    changed = True
                elif c2 in b_values and c1 not in b_values:
                    b_values[c1] = (b_values[c2] - diff) % MOD
                    changed = True
                elif c1 in b_values and c2 in b_values:
                    if (b_values[c2] - b_values[c1]) % MOD != diff:
                        consistent = False
                        break
            if not consistent:
                break

        if not consistent:
            continue

        # Derive A values from assigned B values + equations
        a_values = {}
        for r, c, k in equations:
            if c in b_values:
                a_val = (k - b_values[c]) % MOD
                if r in a_values:
                    if a_values[r] != a_val:
                        consistent = False
                        break
                else:
                    a_values[r] = a_val

        if not consistent:
            continue

        # Verify A constraints
        for r1, r2, diff in a_constraints:
            if r1 in a_values and r2 in a_values:
                if (a_values[r2] - a_values[r1]) % MOD != diff:
                    consistent = False
                    break

        if consistent:
            # Build full keystream and check Bean
            keystream = []
            has_all = True
            for i in range(CT_LEN):
                r = i // w
                c = i % w
                if r in a_values and c in b_values:
                    keystream.append((a_values[r] + b_values[c]) % MOD)
                elif r in a_values:
                    keystream.append(None)
                    has_all = False
                elif c in b_values:
                    keystream.append(None)
                    has_all = False
                else:
                    keystream.append(None)
                    has_all = False

            # Check Bean on assigned positions
            bean_ok = True
            for a_pos, b_pos in BEAN_EQ:
                if keystream[a_pos] is not None and keystream[b_pos] is not None:
                    if keystream[a_pos] != keystream[b_pos]:
                        bean_ok = False

            for a_pos, b_pos in BEAN_INEQ:
                if keystream[a_pos] is not None and keystream[b_pos] is not None:
                    if keystream[a_pos] == keystream[b_pos]:
                        bean_ok = False

            # Try all 26 possible base offsets for A[0] (since we fixed B[first_col]=0)
            for offset in range(26):
                full_keystream = []
                can_decrypt = True
                for i in range(CT_LEN):
                    r = i // w
                    c = i % w
                    a_val = a_values.get(r)
                    b_val = b_values.get(c)
                    if a_val is not None and b_val is not None:
                        full_keystream.append((a_val + b_val) % MOD)
                    elif a_val is not None:
                        # B unknown — try offset
                        full_keystream.append((a_val + offset) % MOD)
                    elif b_val is not None:
                        full_keystream.append((offset + b_val) % MOD)
                    else:
                        full_keystream.append(offset)

                pt = decrypt_with_key(CT, full_keystream, "vig")
                score = crib_score(pt)
                if score > NOISE_FLOOR:
                    consistent_widths.append({
                        "width": w,
                        "score": score,
                        "bean": bean_ok,
                        "a_values": {str(k): v for k, v in a_values.items()},
                        "b_values": {str(k): v for k, v in b_values.items()},
                        "plaintext_fragment": pt[:40],
                    })

            if not consistent_widths or consistent_widths[-1].get("width") != w:
                # Record consistent width even without high score
                consistent_widths.append({
                    "width": w,
                    "score": crib_score(decrypt_with_key(CT,
                        [(a_values.get(i//w, 0) + b_values.get(i%w, 0)) % MOD for i in range(CT_LEN)], "vig")),
                    "bean": bean_ok,
                    "consistent": True,
                })

    # Also test Beaufort and Variant Beaufort for consistent widths
    print(f"  Consistent widths found: {len(consistent_widths)}")
    if consistent_widths:
        best = max(consistent_widths, key=lambda x: x.get("score", 0))
        print(f"  Best: width={best['width']}, score={best.get('score', 0)}, bean={best.get('bean')}")
    else:
        print("  RESULT: 2D matrix key (A[row]+B[col]) is INCONSISTENT with cribs for ALL widths 2-96.")
        print("  This eliminates the simplest 'matrix code' interpretation.")

    return consistent_widths


# ── Hypothesis 2: Interleaved Dual-Cipher ────────────────────────────────

def test_interleaved_dual_cipher():
    """
    Test if K4 uses two different cipher systems applied to alternating positions.

    Patterns tested:
    - Even/odd positions
    - Every 3rd, 4th, 5th position
    - Modular patterns (i % k == j for various k, j)
    - Keyword-derived patterns (KRYPTOS = 7 letters → mod 7)
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 2: Interleaved Dual-Cipher")
    print("="*70)

    # Compute Vigenere keystream at all crib positions
    crib_keys_vig = {}
    for pos, ch in CRIB_ENTRIES:
        crib_keys_vig[pos] = (ALPH_IDX[CT[pos]] - ALPH_IDX[ch]) % MOD

    # For each interleave pattern, check if we can split the keystream
    # into two periodic components
    results = []

    # Test: positions split by i % k == j for k in 2..13
    for k in range(2, 14):
        for j_split in range(k):
            # Group A: positions where i % k == j_split
            # Group B: all other positions
            group_a_cribs = {p: v for p, v in crib_keys_vig.items() if p % k == j_split}
            group_b_cribs = {p: v for p, v in crib_keys_vig.items() if p % k != j_split}

            # Check if each group has a periodic pattern
            for period_a in range(1, 8):
                # Check group A for period_a periodicity
                a_consistent = True
                a_values = {}
                for p, v in group_a_cribs.items():
                    # Position within group A
                    residue = p % period_a
                    if residue in a_values:
                        if a_values[residue] != v:
                            a_consistent = False
                            break
                    else:
                        a_values[residue] = v

                if not a_consistent:
                    continue

                for period_b in range(1, 8):
                    b_consistent = True
                    b_values = {}
                    for p, v in group_b_cribs.items():
                        residue = p % period_b
                        if residue in b_values:
                            if b_values[residue] != v:
                                b_consistent = False
                                break
                        else:
                            b_values[residue] = v

                    if not b_consistent:
                        continue

                    # Both groups are periodic — build full keystream and decrypt
                    keystream = []
                    for i in range(CT_LEN):
                        if i % k == j_split:
                            keystream.append(a_values.get(i % period_a, 0))
                        else:
                            keystream.append(b_values.get(i % period_b, 0))

                    pt = decrypt_with_key(CT, keystream, "vig")
                    score = crib_score(pt)
                    bean = bean_check(keystream)

                    if score > NOISE_FLOOR:
                        results.append({
                            "pattern": f"i%{k}=={j_split}",
                            "period_a": period_a,
                            "period_b": period_b,
                            "score": score,
                            "bean": bean,
                            "pt_fragment": pt[:50],
                        })

    # Also test with Beaufort variants
    for variant_name, decrypt_fn in [("beau", beau_decrypt), ("var_beau", var_beau_decrypt)]:
        crib_keys_var = {}
        for pos, ch in CRIB_ENTRIES:
            if variant_name == "beau":
                # Beaufort: K = (CT + PT) mod 26
                crib_keys_var[pos] = (ALPH_IDX[CT[pos]] + ALPH_IDX[ch]) % MOD
            else:
                # Variant Beaufort: K = (PT - CT) mod 26
                crib_keys_var[pos] = (ALPH_IDX[ch] - ALPH_IDX[CT[pos]]) % MOD

        for k in [2, 3, 5, 7]:  # Most promising moduli
            for j_split in range(k):
                group_a = {p: v for p, v in crib_keys_var.items() if p % k == j_split}
                group_b = {p: v for p, v in crib_keys_var.items() if p % k != j_split}

                for period_a in range(1, 8):
                    a_ok = True
                    a_vals = {}
                    for p, v in group_a.items():
                        r = p % period_a
                        if r in a_vals and a_vals[r] != v:
                            a_ok = False
                            break
                        a_vals[r] = v
                    if not a_ok:
                        continue

                    for period_b in range(1, 8):
                        b_ok = True
                        b_vals = {}
                        for p, v in group_b.items():
                            r = p % period_b
                            if r in b_vals and b_vals[r] != v:
                                b_ok = False
                                break
                            b_vals[r] = v
                        if not b_ok:
                            continue

                        ks = []
                        for i in range(CT_LEN):
                            if i % k == j_split:
                                ks.append(a_vals.get(i % period_a, 0))
                            else:
                                ks.append(b_vals.get(i % period_b, 0))

                        pt = decrypt_with_key(CT, ks, variant_name)
                        score = crib_score(pt)
                        bean = bean_check(ks)

                        if score > NOISE_FLOOR:
                            results.append({
                                "variant": variant_name,
                                "pattern": f"i%{k}=={j_split}",
                                "period_a": period_a,
                                "period_b": period_b,
                                "score": score,
                                "bean": bean,
                            })

    print(f"  Tested {sum(1 for k in range(2,14) for _ in range(k))} interleave patterns")
    print(f"  × 7×7 period combinations × 3 variants = ~{7*7*3*sum(range(2,14))} configs")
    if results:
        results.sort(key=lambda x: -x["score"])
        print(f"  Above-noise results: {len(results)}")
        for r in results[:10]:
            print(f"    {r}")
    else:
        print("  RESULT: No interleaved dual-cipher pattern produces above-noise scores")
        print("  at discriminating periods (1-7).")

    return results


# ── Hypothesis 3: KA Pre-Substitution ────────────────────────────────────

def test_ka_pre_substitution():
    """
    Test if K4 uses the KA alphabet as a monoalphabetic pre-substitution (masking)
    before applying a standard cipher.

    Model: CT = Vig(KA_perm(PT), K) or CT = Vig(KA_inv(PT), K)
    This changes the keystream values at crib positions. Check if the modified
    keystream shows structure (periodicity, English running key, etc.)
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 3: KA Pre-Substitution (Masking)")
    print("="*70)

    results = []

    # Test both KA forward and inverse permutations
    for perm_name, perm_fn in [("KA_forward", ka_perm_forward), ("KA_inverse", ka_perm_inverse)]:
        # Apply KA permutation to the known plaintext at crib positions
        # Then compute the modified keystream
        modified_keys = {}
        for pos, ch in CRIB_ENTRIES:
            masked_ch = perm_fn(ch)
            modified_keys[pos] = (ALPH_IDX[CT[pos]] - ALPH_IDX[masked_ch]) % MOD

        # Check if modified keystream is periodic at any period 1-7
        for period in range(1, 8):
            consistent = True
            period_vals = {}
            for pos, kval in modified_keys.items():
                r = pos % period
                if r in period_vals:
                    if period_vals[r] != kval:
                        consistent = False
                        break
                else:
                    period_vals[r] = kval

            if consistent:
                # Build full keystream and decrypt
                ks = [period_vals.get(i % period, 0) for i in range(CT_LEN)]
                # Need to undo KA perm after Vig decrypt
                pt_masked = decrypt_with_key(CT, ks, "vig")
                # Undo mask
                if perm_name == "KA_forward":
                    pt = ka_perm_inverse(pt_masked)
                else:
                    pt = ka_perm_forward(pt_masked)

                score = crib_score(pt)
                bean = bean_check(ks)

                results.append({
                    "permutation": perm_name,
                    "period": period,
                    "score": score,
                    "bean": bean,
                    "consistent": True,
                    "pt_fragment": pt[:40],
                })
                print(f"  CONSISTENT: {perm_name} + period {period}, score={score}, bean={bean}")

        # Also check for Beaufort and Variant Beaufort
        for variant in ["beau", "var_beau"]:
            mod_keys_v = {}
            for pos, ch in CRIB_ENTRIES:
                masked_ch = perm_fn(ch)
                if variant == "beau":
                    mod_keys_v[pos] = (ALPH_IDX[CT[pos]] + ALPH_IDX[masked_ch]) % MOD
                else:
                    mod_keys_v[pos] = (ALPH_IDX[masked_ch] - ALPH_IDX[CT[pos]]) % MOD

            for period in range(1, 8):
                ok = True
                pvals = {}
                for pos, kval in mod_keys_v.items():
                    r = pos % period
                    if r in pvals:
                        if pvals[r] != kval:
                            ok = False
                            break
                    else:
                        pvals[r] = kval

                if ok:
                    ks = [pvals.get(i % period, 0) for i in range(CT_LEN)]
                    pt_masked = decrypt_with_key(CT, ks, variant)
                    if perm_name == "KA_forward":
                        pt = ka_perm_inverse(pt_masked)
                    else:
                        pt = ka_perm_forward(pt_masked)
                    score = crib_score(pt)
                    bean = bean_check(ks)

                    results.append({
                        "permutation": perm_name,
                        "variant": variant,
                        "period": period,
                        "score": score,
                        "bean": bean,
                        "consistent": True,
                    })
                    if score > NOISE_FLOOR:
                        print(f"  SIGNAL: {perm_name}+{variant} period {period}, score={score}")

    # Check if modified keystream looks like a running key (English-like fragments)
    for perm_name, perm_fn in [("KA_forward", ka_perm_forward), ("KA_inverse", ka_perm_inverse)]:
        modified_keys_vig = {}
        for pos, ch in CRIB_ENTRIES:
            masked_ch = perm_fn(ch)
            modified_keys_vig[pos] = (ALPH_IDX[CT[pos]] - ALPH_IDX[masked_ch]) % MOD

        # Convert key values to letters
        key_ene = "".join(ALPH[modified_keys_vig[i]] for i in range(21, 34))
        key_bc = "".join(ALPH[modified_keys_vig[i]] for i in range(63, 74))

        # Check Bean on modified keystream
        bean_eq_ok = modified_keys_vig.get(27) == modified_keys_vig.get(65)

        print(f"  {perm_name} + Vig keystream: ENE={key_ene}, BC={key_bc}, Bean-EQ={bean_eq_ok}")

    total_consistent = sum(1 for r in results if r.get("consistent"))
    above_noise = sum(1 for r in results if r.get("score", 0) > NOISE_FLOOR)
    print(f"  Total consistent period/perm combos: {total_consistent}")
    print(f"  Above noise: {above_noise}")
    if not above_noise:
        print("  RESULT: KA pre-substitution does NOT produce periodic key consistency")
        print("  at discriminating periods (1-7) under any variant.")

    return results


# ── Hypothesis 4: Kryptos-Derived Running Keys ──────────────────────────

def test_kryptos_running_keys():
    """
    Test running keys derived from the Kryptos sculpture itself:
    - KA tableau read in various orders (rows, columns, diagonals, spirals)
    - K1-K3 CIPHERTEXT (not plaintext, which was tested in E-JTS-12)
    - K1-K3 combined ciphertext
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 4: Kryptos-Derived Running Keys")
    print("="*70)

    # Build the KA tableau (26 rows, each a cyclic shift of KA)
    tableau_rows = []
    for r in range(26):
        row = KRYPTOS_ALPHABET[r:] + KRYPTOS_ALPHABET[:r]
        tableau_rows.append(row)

    # Generate running key texts from tableau
    running_keys = {}

    # Row-major reading (all rows concatenated)
    running_keys["tableau_row_major"] = "".join(tableau_rows)

    # Column-major reading
    col_major = ""
    for c in range(26):
        for r in range(26):
            col_major += tableau_rows[r][c]
    running_keys["tableau_col_major"] = col_major

    # Diagonal reading (main diagonal then wrap)
    diag = ""
    for d in range(26):
        for i in range(26):
            diag += tableau_rows[i][(i + d) % 26]
    running_keys["tableau_diagonal"] = diag

    # Anti-diagonal
    anti_diag = ""
    for d in range(26):
        for i in range(26):
            anti_diag += tableau_rows[i][(25 - i + d) % 26]
    running_keys["tableau_anti_diagonal"] = anti_diag

    # Spiral reading (CW from top-left)
    def spiral_read(grid, rows, cols):
        result = []
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                result.append(grid[top][c])
            top += 1
            for r in range(top, bottom + 1):
                result.append(grid[r][right])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    result.append(grid[bottom][c])
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    result.append(grid[r][left])
                left += 1
        return "".join(result)

    running_keys["tableau_spiral"] = spiral_read(tableau_rows, 26, 26)

    # Serpentine (boustrophedon) reading
    serp = ""
    for r in range(26):
        if r % 2 == 0:
            serp += tableau_rows[r]
        else:
            serp += tableau_rows[r][::-1]
    running_keys["tableau_serpentine"] = serp

    # Full Kryptos ciphertext (K1+K2+K3+K4)
    # K1-K3 ciphertext from known sources
    k1_ct = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    k2_ct = "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ"
    k3_ct = "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNETPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIPFEIMEHNLSSTTRTVDOHW"

    running_keys["k1_ct"] = k1_ct
    running_keys["k2_ct"] = k2_ct
    running_keys["k3_ct"] = k3_ct
    running_keys["k123_ct"] = k1_ct + k2_ct + k3_ct
    running_keys["k1_ct_reversed"] = k1_ct[::-1]
    running_keys["k2_ct_reversed"] = k2_ct[::-1]
    running_keys["k3_ct_reversed"] = k3_ct[::-1]

    # KA alphabet repeated
    running_keys["ka_repeated"] = (KRYPTOS_ALPHABET * 4)[:CT_LEN + 50]

    # KA alphabet reversed repeated
    running_keys["ka_reversed_repeated"] = (KRYPTOS_ALPHABET[::-1] * 4)[:CT_LEN + 50]

    results = []
    best_score = 0

    for rk_name, rk_text in running_keys.items():
        # Try every offset in the running key text
        max_offset = len(rk_text) - CT_LEN
        if max_offset < 0:
            continue

        for offset in range(max_offset + 1):
            key_segment = rk_text[offset:offset + CT_LEN]
            ks = [ALPH_IDX[c] for c in key_segment]

            for variant in ["vig", "beau", "var_beau"]:
                pt = decrypt_with_key(CT, ks, variant)
                score = crib_score(pt)

                if score > best_score:
                    best_score = score

                if score > NOISE_FLOOR:
                    bean = bean_check(ks)
                    results.append({
                        "source": rk_name,
                        "offset": offset,
                        "variant": variant,
                        "score": score,
                        "bean": bean,
                        "pt_fragment": pt[:50],
                    })

    total_configs = sum(max(0, len(v) - CT_LEN + 1) for v in running_keys.values()) * 3
    print(f"  Tested {len(running_keys)} running key sources × offsets × 3 variants = {total_configs} configs")
    print(f"  Best score: {best_score}/24")
    if results:
        results.sort(key=lambda x: -x["score"])
        print(f"  Above-noise results: {len(results)}")
        for r in results[:5]:
            print(f"    {r['source']} offset={r['offset']} {r['variant']}: {r['score']}/24 bean={r['bean']}")
    else:
        print("  RESULT: No Kryptos-derived running key produces above-noise scores.")

    return results


# ── Hypothesis 5: Position-Dependent Key Formulas ────────────────────────

def test_position_formulas():
    """
    Test novel position-dependent key generation formulas not previously tested.

    Formulas tested:
    - k[i] = floor(i/n) + (i mod m) for various n, m
    - k[i] = (i * a + b) mod 26 (affine, tested but verify)
    - k[i] = (i * i * a + i * b + c) mod 26 (quadratic)
    - k[i] = floor(i * phi) mod 26 where phi = golden ratio
    - k[i] = digit_sum(i) mod 26
    - k[i] = popcount(i) mod 26 (number of 1-bits)
    - k[i] = reverse_bits(i) mod 26
    - k[i] = (i XOR key_val) mod 26
    - k[i] = tribonacci(i) mod 26
    """
    print("\n" + "="*70)
    print("HYPOTHESIS 5: Position-Dependent Key Formulas")
    print("="*70)

    import math

    results = []
    best_score = 0
    total_tested = 0

    # Golden ratio-based
    phi = (1 + math.sqrt(5)) / 2

    # Formula generators: name -> function(i, params) -> key_value
    formula_generators = []

    # Floor division + modular: k[i] = (floor(i/n) + (i%m)*c) mod 26
    for n in range(2, 20):
        for m in range(2, 20):
            for c in range(1, 26):
                formula_generators.append(
                    (f"floor_mod_n{n}_m{m}_c{c}",
                     lambda i, _n=n, _m=m, _c=c: (i // _n + (i % _m) * _c) % MOD)
                )

    # Golden ratio: k[i] = floor(i * phi * a) mod 26
    for a in range(1, 26):
        formula_generators.append(
            (f"golden_a{a}",
             lambda i, _a=a: int(i * phi * _a) % MOD)
        )

    # Digit sum: k[i] = (digit_sum(i) * a + b) mod 26
    for a in range(1, 26):
        for b in range(26):
            formula_generators.append(
                (f"digitsum_a{a}_b{b}",
                 lambda i, _a=a, _b=b: (sum(int(d) for d in str(i)) * _a + _b) % MOD)
            )

    # Popcount: k[i] = (popcount(i) * a + b) mod 26
    for a in range(1, 26):
        for b in range(26):
            formula_generators.append(
                (f"popcount_a{a}_b{b}",
                 lambda i, _a=a, _b=b: (bin(i).count('1') * _a + _b) % MOD)
            )

    # XOR with constant: k[i] = (i XOR c) mod 26
    for c in range(1, 128):
        formula_generators.append(
            (f"xor_{c}",
             lambda i, _c=c: (i ^ _c) % MOD)
        )

    # Tribonacci: precompute
    trib = [0, 0, 1]
    for i in range(3, CT_LEN + 1):
        trib.append(trib[-1] + trib[-2] + trib[-3])
    for a in range(1, 26):
        for b in range(26):
            formula_generators.append(
                (f"tribonacci_a{a}_b{b}",
                 lambda i, _a=a, _b=b: (trib[i] * _a + _b) % MOD)
            )

    # Test each formula
    for fname, ffunc in formula_generators:
        total_tested += 1

        # Check crib consistency first (fast filter)
        crib_ok = True
        ks_at_cribs = {}
        for pos, ch in CRIB_ENTRIES:
            k_val = ffunc(pos)
            expected_pt = vig_decrypt(CT[pos], k_val)
            if expected_pt != ch:
                crib_ok = False
                break
            ks_at_cribs[pos] = k_val

        if not crib_ok:
            continue

        # Full decrypt
        ks = [ffunc(i) for i in range(CT_LEN)]
        pt = decrypt_with_key(CT, ks, "vig")
        score = crib_score(pt)
        bean = bean_check(ks)

        if score > best_score:
            best_score = score
            print(f"  New best: {fname} score={score} bean={bean} pt={pt[:40]}")

        if score > NOISE_FLOOR:
            results.append({
                "formula": fname,
                "score": score,
                "bean": bean,
                "pt_fragment": pt[:50],
            })

    print(f"  Tested {total_tested} position-dependent formulas")
    print(f"  Best score: {best_score}/24")
    if results:
        results.sort(key=lambda x: -x["score"])
        print(f"  Above-noise: {len(results)}")
        for r in results[:5]:
            print(f"    {r['formula']}: score={r['score']}, bean={r['bean']}")
    else:
        print("  RESULT: No position-dependent formula produces above-noise scores.")

    return results


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("E-SOLVE-01: Novel K4 Attack Hypotheses")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Cribs: {CRIB_WORDS}")
    print()

    start = time.time()
    all_results = {}

    # Run all hypotheses
    all_results["h1_2d_matrix"] = test_2d_matrix_key()
    all_results["h2_interleaved"] = test_interleaved_dual_cipher()
    all_results["h3_ka_presub"] = test_ka_pre_substitution()
    all_results["h4_running_keys"] = test_kryptos_running_keys()
    all_results["h5_position_formulas"] = test_position_formulas()

    elapsed = time.time() - start

    # Summary
    print("\n" + "="*70)
    print(f"E-SOLVE-01 SUMMARY ({elapsed:.1f}s)")
    print("="*70)

    total_signal = 0
    for hname, hresults in all_results.items():
        above = [r for r in hresults if isinstance(r, dict) and r.get("score", 0) > NOISE_FLOOR]
        print(f"  {hname}: {len(above)} above-noise results")
        total_signal += len(above)

    if total_signal == 0:
        print("\n  OVERALL: ALL NOISE — no novel hypothesis produced signal above noise floor.")
    else:
        print(f"\n  OVERALL: {total_signal} above-noise results found — investigate further!")

    # Save results
    output_path = Path("results")
    output_path.mkdir(exist_ok=True)

    # Serialize: filter out non-serializable items
    serializable = {}
    for k, v in all_results.items():
        if isinstance(v, list):
            serializable[k] = [
                {kk: vv for kk, vv in item.items() if isinstance(vv, (str, int, float, bool, list, dict, type(None)))}
                for item in v if isinstance(item, dict)
            ]
        else:
            serializable[k] = str(v)

    with open(output_path / "e_solve_01_results.json", "w") as f:
        json.dump(serializable, f, indent=2)

    print(f"\n  Results saved to results/e_solve_01_results.json")


if __name__ == "__main__":
    main()
