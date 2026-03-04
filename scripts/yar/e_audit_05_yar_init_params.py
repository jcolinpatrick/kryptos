#!/usr/bin/env python3
"""
Cipher: YAR grille
Family: yar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-AUDIT-05: Test YAR superscript values as cipher initialization parameters.

Tests Y=24, A=0, R=17 (standard) and Y=2, A=7, R=1 (KA) as cipher init params:
  1. Weltzeituhr 24-facet cycling (KA tableau rows as substitution alphabets)
  2. Progressive key from YAR (multiple progression strategies)
  3. Period 24 with YAR offset (Bean-compatible period)
  4. YAR as tableau row selectors (period 3)

Uses canonical scoring from kryptos.kernel.scoring.aggregate.
"""
from __future__ import annotations

import itertools
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Dict

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR,
)
from kryptos.kernel.alphabet import Alphabet, AZ, KA
from kryptos.kernel.scoring.aggregate import score_candidate, ScoreBreakdown
from kryptos.kernel.scoring.crib_score import score_cribs_detailed
from kryptos.kernel.constraints.bean import verify_bean, BeanResult
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, DECRYPT_FN,
)

# ── YAR values in both indexing systems ─────────────────────────────────────

YAR_STANDARD = {"Y": 24, "A": 0, "R": 17}   # A=0 standard
YAR_KA = {"Y": 2, "A": 7, "R": 1}           # K=0 KA ordering

KA_SEQ = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_SEQ)}

# ── Build the KA tableau (26 rows, each a cyclic shift of KA) ───────────────

def build_ka_tableau() -> List[str]:
    """Build the Kryptos tableau: 26 rows, each a cyclic left-shift of KA."""
    rows = []
    for i in range(26):
        row = KA_SEQ[i:] + KA_SEQ[:i]
        rows.append(row)
    return rows

KA_TABLEAU = build_ka_tableau()


# ── Result tracking ────────────────────────────────────────────────────────

@dataclass
class Result:
    test_name: str
    config: str
    plaintext: str
    crib_score: int
    ene_score: int
    bc_score: int
    ic_value: float
    bean_passed: bool
    classification: str

    @property
    def sort_key(self):
        return (self.crib_score, self.ic_value)


ALL_RESULTS: List[Result] = []


def record(test_name: str, config: str, pt: str) -> Result:
    """Score a candidate and record the result."""
    sb = score_candidate(pt)

    # Also check Bean on Vigenere keystream
    keystream = [(ord(CT[i]) - ord(pt[i])) % 26 for i in range(len(pt))]
    bean = verify_bean(keystream)

    r = Result(
        test_name=test_name,
        config=config,
        plaintext=pt,
        crib_score=sb.crib_score,
        ene_score=sb.ene_score,
        bc_score=sb.bc_score,
        ic_value=sb.ic_value,
        bean_passed=bean.passed,
        classification=sb.crib_classification,
    )
    ALL_RESULTS.append(r)
    return r


def decrypt_with_tableau_row(ct: str, row_idx: int) -> str:
    """Decrypt ciphertext using a single KA tableau row as a monoalphabetic sub.

    The KA tableau row maps plaintext letter at column position to ciphertext.
    Row r: tableau[r][col] = encrypted char.
    To decrypt: for CT char c, find its column position in the row => that's the PT char.
    The column headers are KA_SEQ itself (the first row = KA_SEQ).
    So PT = KA_SEQ[col] where col = position of c in tableau[r].
    """
    row = KA_TABLEAU[row_idx % 26]
    # Build reverse lookup: CT char -> PT char (column header)
    reverse = {}
    for col_idx, ct_char in enumerate(row):
        reverse[ct_char] = KA_SEQ[col_idx]
    return "".join(reverse.get(c, c) for c in ct)


def decrypt_with_tableau_sequence(ct: str, row_sequence: List[int]) -> str:
    """Decrypt using a cycling sequence of tableau rows."""
    period = len(row_sequence)
    result = []
    # Precompute reverse lookups for each row in the sequence
    reverses = []
    for r in row_sequence:
        row = KA_TABLEAU[r % 26]
        rev = {}
        for col_idx, ct_char in enumerate(row):
            rev[ct_char] = KA_SEQ[col_idx]
        reverses.append(rev)

    for i, c in enumerate(ct):
        rev = reverses[i % period]
        result.append(rev.get(c, c))
    return "".join(result)


def decrypt_vigenere_ka(ct: str, key_indices: List[int]) -> str:
    """Decrypt using Vigenere with KA alphabet and a repeating key.

    CT[i] = KA_SEQ[(KA_IDX[PT[i]] + key[i % period]) % 26]
    => PT[i] = KA_SEQ[(KA_IDX[CT[i]] - key[i % period]) % 26]
    """
    period = len(key_indices)
    result = []
    for i, c in enumerate(ct):
        c_idx = KA_IDX[c]
        k = key_indices[i % period]
        p_idx = (c_idx - k) % 26
        result.append(KA_SEQ[p_idx])
    return "".join(result)


def decrypt_beaufort_ka(ct: str, key_indices: List[int]) -> str:
    """Decrypt Beaufort with KA alphabet: PT = KA[(key - KA_IDX[CT]) % 26]."""
    period = len(key_indices)
    result = []
    for i, c in enumerate(ct):
        c_idx = KA_IDX[c]
        k = key_indices[i % period]
        p_idx = (k - c_idx) % 26
        result.append(KA_SEQ[p_idx])
    return "".join(result)


# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: Weltzeituhr 24-facet cycling
# Use 24 (or all 26) rows of KA tableau, cycle with various step sizes.
# ═══════════════════════════════════════════════════════════════════════════

def test_1_weltzeituhr_cycling():
    print("=" * 78)
    print("TEST 1: Weltzeituhr 24-facet cycling")
    print("  Use KA tableau rows as substitution alphabets, cycle through them.")
    print("=" * 78)
    count = 0

    for indexing_name, yar in [("STD", YAR_STANDARD), ("KA", YAR_KA)]:
        y_val, a_val, r_val = yar["Y"], yar["A"], yar["R"]

        # 1a. Cycle 24 facets with various starting positions and step sizes
        for n_facets in [24, 26]:
            for start in range(n_facets):
                for step in range(1, n_facets):
                    # Generate the row sequence
                    row_seq = [(start + i * step) % n_facets for i in range(n_facets)]
                    pt = decrypt_with_tableau_sequence(CT, row_seq)
                    config = f"idx={indexing_name} facets={n_facets} start={start} step={step}"
                    record("1_weltzeituhr_cycle", config, pt)
                    count += 1

        # 1b. YAR-offset starts specifically
        for n_facets in [24, 26]:
            for yar_start in [y_val, a_val, r_val]:
                for step in range(1, n_facets):
                    row_seq = [(yar_start + i * step) % n_facets for i in range(n_facets)]
                    pt = decrypt_with_tableau_sequence(CT, row_seq)
                    config = f"idx={indexing_name} facets={n_facets} yar_start={yar_start} step={step}"
                    record("1_weltzeituhr_yar_start", config, pt)
                    count += 1

        # 1c. YAR as a 3-element step pattern: step sizes cycle Y, A, R
        for n_facets in [24, 26]:
            for start in range(n_facets):
                steps = [y_val, a_val, r_val]
                row_seq = []
                pos = start
                for i in range(CT_LEN):
                    row_seq.append(pos % n_facets)
                    pos += steps[i % 3]
                pt = decrypt_with_tableau_sequence(CT, row_seq)
                config = f"idx={indexing_name} facets={n_facets} start={start} steps=YAR({steps})"
                record("1_weltzeituhr_yar_steps", config, pt)
                count += 1

    print(f"  Tested {count} configurations")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: Progressive key from YAR
# ═══════════════════════════════════════════════════════════════════════════

def test_2_progressive_key():
    print("=" * 78)
    print("TEST 2: Progressive key from YAR")
    print("  Various progressions starting with Y, A, R values.")
    print("=" * 78)
    count = 0

    for indexing_name, yar in [("STD", YAR_STANDARD), ("KA", YAR_KA)]:
        y_val, a_val, r_val = yar["Y"], yar["A"], yar["R"]

        # 2a. YAR then continue KA sequentially from after R
        # In KA: Y=pos 2, A=pos 7, R=pos 1
        # In STD: Y=pos 24, A=pos 0, R=pos 17
        for alph_name, alph_seq in [("KA", KA_SEQ), ("AZ", ALPH)]:
            alph_idx = {c: i for i, c in enumerate(alph_seq)}
            r_pos = alph_idx["R"]
            # Continue from position after R in the alphabet
            key = [alph_idx["Y"], alph_idx["A"], alph_idx["R"]]
            for j in range(3, CT_LEN):
                key.append((r_pos + 1 + (j - 3)) % 26)

            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort"), ("varbeau", "var_beaufort")]:
                pt = decrypt_text(CT, key, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} alph={alph_name} YAR_then_continue variant={variant_name}"
                record("2_progressive_yar_continue", config, pt)
                count += 1

                # Also try with KA-alphabet decryption
                if alph_name == "KA":
                    pt_ka = decrypt_vigenere_ka(CT, key)
                    config_ka = f"idx={indexing_name} alph=KA vig_KA YAR_then_continue"
                    record("2_progressive_yar_continue_ka", config_ka, pt_ka)
                    pt_beau_ka = decrypt_beaufort_ka(CT, key)
                    config_beau = f"idx={indexing_name} alph=KA beau_KA YAR_then_continue"
                    record("2_progressive_yar_continue_ka", config_beau, pt_beau_ka)
                    count += 2

        # 2b. YAR repeated (period 3)
        for alph_name, alph_seq in [("KA", KA_SEQ), ("AZ", ALPH)]:
            alph_idx_local = {c: i for i, c in enumerate(alph_seq)}
            key3 = [alph_idx_local["Y"], alph_idx_local["A"], alph_idx_local["R"]]

            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort"), ("varbeau", "var_beaufort")]:
                pt = decrypt_text(CT, key3, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} alph={alph_name} period3_YAR variant={variant_name}"
                record("2_yar_period3", config, pt)
                count += 1

                if alph_name == "KA":
                    pt_ka = decrypt_vigenere_ka(CT, key3)
                    config_ka = f"idx={indexing_name} alph=KA vig_KA period3_YAR"
                    record("2_yar_period3_ka", config_ka, pt_ka)
                    pt_beau_ka = decrypt_beaufort_ka(CT, key3)
                    config_beau = f"idx={indexing_name} alph=KA beau_KA period3_YAR"
                    record("2_yar_period3_ka", config_beau, pt_beau_ka)
                    count += 2

        # 2c. Progressive with YAR increment pattern
        # key[i] = (Y + i*A + floor(i/something)*R) mod 26 etc.
        for alph_name, alph_seq in [("KA", KA_SEQ), ("AZ", ALPH)]:
            alph_idx_local = {c: i for i, c in enumerate(alph_seq)}

            # 2c-i: key[i] = (Y + i*A) mod 26 — linear progression
            key_lin_a = [(y_val + i * a_val) % 26 for i in range(CT_LEN)]
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key_lin_a, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} alph={alph_name} key=Y+i*A variant={variant_name}"
                record("2_yar_linear_a", config, pt)
                count += 1

            # 2c-ii: key[i] = (Y + i*R) mod 26 — linear with R step
            key_lin_r = [(y_val + i * r_val) % 26 for i in range(CT_LEN)]
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key_lin_r, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} alph={alph_name} key=Y+i*R variant={variant_name}"
                record("2_yar_linear_r", config, pt)
                count += 1

            # 2c-iii: key[i] = (A + i*R) mod 26
            key_lin_ar = [(a_val + i * r_val) % 26 for i in range(CT_LEN)]
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key_lin_ar, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} alph={alph_name} key=A+i*R variant={variant_name}"
                record("2_yar_linear_ar", config, pt)
                count += 1

            # 2c-iv: Quadratic: key[i] = (Y + A*i + R*i^2) mod 26
            key_quad = [(y_val + a_val * i + r_val * i * i) % 26 for i in range(CT_LEN)]
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key_quad, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} alph={alph_name} key=Y+A*i+R*i^2 variant={variant_name}"
                record("2_yar_quadratic", config, pt)
                count += 1

            # 2c-v: Autokey starting with YAR
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                key_auto = [y_val, a_val, r_val]
                pt_chars = []
                dfn = DECRYPT_FN[CipherVariant(decrypt_fn)]
                for i in range(CT_LEN):
                    c_idx = ord(CT[i]) - 65
                    k = key_auto[i]
                    p_idx = dfn(c_idx, k)
                    pt_chars.append(chr(p_idx + 65))
                    # Autokey: next key is the plaintext char
                    if i >= 2:
                        key_auto.append(p_idx)
                pt = "".join(pt_chars)
                config = f"idx={indexing_name} alph={alph_name} autokey_YAR variant={variant_name}"
                record("2_yar_autokey", config, pt)
                count += 1

            # 2c-vi: CT autokey starting with YAR
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                key_auto_ct = [y_val, a_val, r_val]
                pt_chars2 = []
                dfn = DECRYPT_FN[CipherVariant(decrypt_fn)]
                for i in range(CT_LEN):
                    c_idx = ord(CT[i]) - 65
                    k = key_auto_ct[i]
                    p_idx = dfn(c_idx, k)
                    pt_chars2.append(chr(p_idx + 65))
                    # CT autokey: next key is the ciphertext char
                    if i >= 2:
                        key_auto_ct.append(c_idx)
                pt = "".join(pt_chars2)
                config = f"idx={indexing_name} alph={alph_name} ct_autokey_YAR variant={variant_name}"
                record("2_yar_ct_autokey", config, pt)
                count += 1

        # 2d. Progressive key through entire KA from each YAR starting point
        for start_val, start_name in [(y_val, "Y"), (a_val, "A"), (r_val, "R")]:
            key_prog = [(start_val + i) % 26 for i in range(CT_LEN)]
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key_prog, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} progressive_from_{start_name}={start_val} variant={variant_name}"
                record("2_yar_progressive", config, pt)
                count += 1

        # 2e. Fibonacci-like from YAR: key[0]=Y, key[1]=A, key[i]=(key[i-1]+key[i-2])%26
        key_fib = [y_val, a_val]
        for i in range(2, CT_LEN):
            key_fib.append((key_fib[-1] + key_fib[-2]) % 26)
        for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
            pt = decrypt_text(CT, key_fib, CipherVariant(decrypt_fn))
            config = f"idx={indexing_name} fibonacci_YA variant={variant_name}"
            record("2_yar_fibonacci", config, pt)
            count += 1

        # Also Fibonacci from Y,R and A,R
        for pair_name, v1, v2 in [("YR", y_val, r_val), ("AR", a_val, r_val), ("YAR3", y_val, a_val)]:
            key_fib2 = [v1, v2]
            for i in range(2, CT_LEN):
                key_fib2.append((key_fib2[-1] + key_fib2[-2]) % 26)
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key_fib2, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} fibonacci_{pair_name} variant={variant_name}"
                record("2_yar_fibonacci", config, pt)
                count += 1

        # 2f. Tribonacci from YAR: key[0]=Y, key[1]=A, key[2]=R, key[i]=(k[i-1]+k[i-2]+k[i-3])%26
        key_trib = [y_val, a_val, r_val]
        for i in range(3, CT_LEN):
            key_trib.append((key_trib[-1] + key_trib[-2] + key_trib[-3]) % 26)
        for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
            pt = decrypt_text(CT, key_trib, CipherVariant(decrypt_fn))
            config = f"idx={indexing_name} tribonacci_YAR variant={variant_name}"
            record("2_yar_tribonacci", config, pt)
            count += 1

        # 2g. LCG: key[i] = (A * key[i-1] + R) mod 26, seed = Y
        for seed, mult, inc, label in [
            (y_val, a_val, r_val, "seed=Y,mult=A,inc=R"),
            (y_val, r_val, a_val, "seed=Y,mult=R,inc=A"),
            (a_val, y_val, r_val, "seed=A,mult=Y,inc=R"),
            (a_val, r_val, y_val, "seed=A,mult=R,inc=Y"),
            (r_val, y_val, a_val, "seed=R,mult=Y,inc=A"),
            (r_val, a_val, y_val, "seed=R,mult=A,inc=Y"),
        ]:
            key_lcg = [seed]
            for i in range(1, CT_LEN):
                key_lcg.append((mult * key_lcg[-1] + inc) % 26)
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key_lcg, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} LCG({label}) variant={variant_name}"
                record("2_yar_lcg", config, pt)
                count += 1

    print(f"  Tested {count} configurations")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 3: Period 24 with YAR offset
# ═══════════════════════════════════════════════════════════════════════════

def test_3_period24_yar():
    print("=" * 78)
    print("TEST 3: Period 24 with YAR offset")
    print("  Bean-compatible period, with starting key derived from YAR.")
    print("=" * 78)
    count = 0

    for indexing_name, yar in [("STD", YAR_STANDARD), ("KA", YAR_KA)]:
        y_val, a_val, r_val = yar["Y"], yar["A"], yar["R"]

        # 3a. Period 24 with offset Y: key[i] = (Y + (i % 24) * step) % 26
        for step in range(26):
            key24 = [(y_val + (i % 24) * step) % 26 for i in range(CT_LEN)]
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key24, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} period24 offset_Y={y_val} step={step} variant={variant_name}"
                record("3_period24_yar_offset", config, pt)
                count += 1

        # 3b. Period 24, key = 24 entries starting at YAR offset in KA
        for start, start_name in [(y_val, "Y"), (a_val, "A"), (r_val, "R")]:
            key24_ka = [(start + j) % 26 for j in range(24)]
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key24_ka, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} period24 ka_run_from_{start_name}={start} variant={variant_name}"
                record("3_period24_ka_run", config, pt)
                count += 1

        # 3c. Period 24, interleave Y,A,R across the 24 positions
        # Pattern: Y,A,R,Y,A,R,...,Y,A,R,Y,A,R (24 = 8*3)
        key24_interleave = []
        for j in range(24):
            key24_interleave.append([y_val, a_val, r_val][j % 3])
        for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
            pt = decrypt_text(CT, key24_interleave, CipherVariant(decrypt_fn))
            config = f"idx={indexing_name} period24 interleave_YAR variant={variant_name}"
            record("3_period24_interleave", config, pt)
            count += 1

        # 3d. Period 24 using KA tableau rows, offset by YAR
        for offset, offset_name in [(y_val, "Y"), (a_val, "A"), (r_val, "R")]:
            row_seq = [(offset + i) % 26 for i in range(24)]
            pt = decrypt_with_tableau_sequence(CT, row_seq)
            config = f"idx={indexing_name} period24 tableau_rows offset_{offset_name}={offset}"
            record("3_period24_tableau", config, pt)
            count += 1

    # 3e. Period 24 full brute force of single-value keys at each period-24 slot
    # For each of 26 possible key values, use it uniformly across all period-24 slots
    # rotated by YAR offsets
    for indexing_name, yar in [("STD", YAR_STANDARD), ("KA", YAR_KA)]:
        y_val, a_val, r_val = yar["Y"], yar["A"], yar["R"]
        for base_key in range(26):
            # All 24 positions get (base_key + YAR rotation) % 26
            key24 = [((base_key + y_val + j * r_val) % 26) for j in range(24)]
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                pt = decrypt_text(CT, key24, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} period24 base={base_key} key=(base+Y+j*R)%26 variant={variant_name}"
                record("3_period24_base_yar", config, pt)
                count += 1

    # 3f. Other Bean-compatible periods with YAR offsets
    bean_periods = [8, 13, 16, 19, 20, 23, 26]
    for period in bean_periods:
        for indexing_name, yar in [("STD", YAR_STANDARD), ("KA", YAR_KA)]:
            y_val, a_val, r_val = yar["Y"], yar["A"], yar["R"]
            for step in [1, y_val, a_val, r_val]:
                if step == 0:
                    continue
                key_p = [(y_val + (j % period) * step) % 26 for j in range(CT_LEN)]
                for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort")]:
                    pt = decrypt_text(CT, key_p, CipherVariant(decrypt_fn))
                    config = f"idx={indexing_name} period={period} offset_Y={y_val} step={step} variant={variant_name}"
                    record(f"3_period{period}_yar", config, pt)
                    count += 1

    print(f"  Tested {count} configurations")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 4: YAR as tableau row selectors (period 3)
# ═══════════════════════════════════════════════════════════════════════════

def test_4_yar_row_selectors():
    print("=" * 78)
    print("TEST 4: YAR as tableau row selectors")
    print("  Use row Y, row A, row R of KA tableau in sequence (period 3).")
    print("=" * 78)
    count = 0

    for indexing_name, yar in [("STD", YAR_STANDARD), ("KA", YAR_KA)]:
        y_val, a_val, r_val = yar["Y"], yar["A"], yar["R"]

        # 4a. Direct YAR rows cycling
        row_seq = [y_val, a_val, r_val]
        pt = decrypt_with_tableau_sequence(CT, row_seq)
        config = f"idx={indexing_name} rows=[{y_val},{a_val},{r_val}] period=3"
        record("4_yar_rows_p3", config, pt)
        count += 1

        # 4b. All permutations of YAR
        for perm in itertools.permutations([y_val, a_val, r_val]):
            row_seq = list(perm)
            pt = decrypt_with_tableau_sequence(CT, row_seq)
            config = f"idx={indexing_name} rows={list(perm)} period=3"
            record("4_yar_rows_perm", config, pt)
            count += 1

        # 4c. YAR repeated to fill various periods (6, 9, 12, 24)
        for mult in [2, 3, 4, 8]:
            extended = list(perm) * mult
            period = len(extended)
            pt = decrypt_with_tableau_sequence(CT, extended)
            config = f"idx={indexing_name} rows={list(perm)[:3]}x{mult} period={period}"
            record(f"4_yar_rows_x{mult}", config, pt)
            count += 1

        # 4d. YAR as Vigenere key values (period 3), all 6 orderings
        for perm in itertools.permutations([y_val, a_val, r_val]):
            key3 = list(perm)
            for variant_name, decrypt_fn in [("vig", "vigenere"), ("beau", "beaufort"), ("varbeau", "var_beaufort")]:
                pt = decrypt_text(CT, key3, CipherVariant(decrypt_fn))
                config = f"idx={indexing_name} key={key3} variant={variant_name}"
                record("4_yar_vig_p3", config, pt)
                count += 1

            # KA-algebra versions
            pt_ka = decrypt_vigenere_ka(CT, key3)
            config_ka = f"idx={indexing_name} key={key3} vig_KA"
            record("4_yar_vig_ka_p3", config_ka, pt_ka)
            pt_beau_ka = decrypt_beaufort_ka(CT, key3)
            config_beau = f"idx={indexing_name} key={key3} beau_KA"
            record("4_yar_beau_ka_p3", config_beau, pt_beau_ka)
            count += 2

        # 4e. Rows derived from YAR letter positions in KA
        # Y is at position 2 in KA, so use row 2 of tableau
        ka_y = KA_IDX["Y"]  # always 2
        ka_a = KA_IDX["A"]  # always 7
        ka_r = KA_IDX["R"]  # always 1
        az_y = ALPH_IDX["Y"]  # always 24
        az_a = ALPH_IDX["A"]  # always 0
        az_r = ALPH_IDX["R"]  # always 17

        for label, rows in [
            ("KA_positions", [ka_y, ka_a, ka_r]),
            ("AZ_positions", [az_y, az_a, az_r]),
        ]:
            for perm in itertools.permutations(rows):
                row_seq = list(perm)
                pt = decrypt_with_tableau_sequence(CT, row_seq)
                config = f"idx={indexing_name} {label} rows={row_seq}"
                record(f"4_yar_letter_rows", config, pt)
                count += 1

    print(f"  Tested {count} configurations")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    print("E-AUDIT-05: YAR Superscript as Cipher Initialization Parameters")
    print(f"CT = {CT}")
    print(f"CT length = {CT_LEN}")
    print(f"KA alphabet = {KA_SEQ}")
    print(f"YAR (standard A=0): Y={YAR_STANDARD['Y']}, A={YAR_STANDARD['A']}, R={YAR_STANDARD['R']}")
    print(f"YAR (KA K=0):       Y={YAR_KA['Y']}, A={YAR_KA['A']}, R={YAR_KA['R']}")
    print()

    # Verify KA tableau
    print("KA Tableau (first 5 rows):")
    for i in range(5):
        print(f"  Row {i:2d}: {KA_TABLEAU[i]}")
    print(f"  ... ({26} rows total)")
    print()

    test_1_weltzeituhr_cycling()
    test_2_progressive_key()
    test_3_period24_yar()
    test_4_yar_row_selectors()

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    print("=" * 78)
    print(f"SUMMARY: {len(ALL_RESULTS)} total configurations tested in {elapsed:.1f}s")
    print("=" * 78)

    # Sort by crib score descending, then IC descending
    ALL_RESULTS.sort(key=lambda r: (-r.crib_score, -r.ic_value))

    # Score distribution
    score_dist: Dict[int, int] = {}
    for r in ALL_RESULTS:
        score_dist[r.crib_score] = score_dist.get(r.crib_score, 0) + 1
    print("\nScore distribution:")
    for sc in sorted(score_dist.keys(), reverse=True):
        label = ""
        if sc >= 24:
            label = " *** BREAKTHROUGH ***"
        elif sc >= 18:
            label = " ** SIGNAL **"
        elif sc >= 10:
            label = " * INTERESTING *"
        elif sc > 6:
            label = " (above noise)"
        print(f"  Score {sc:2d}: {score_dist[sc]:6d} configs{label}")

    # Bean pass distribution
    bean_pass_count = sum(1 for r in ALL_RESULTS if r.bean_passed)
    print(f"\nBean-passing configs: {bean_pass_count}/{len(ALL_RESULTS)}")

    # Top 10
    print("\n" + "-" * 78)
    print("TOP 10 RESULTS (by crib score, then IC):")
    print("-" * 78)
    for i, r in enumerate(ALL_RESULTS[:10]):
        print(f"\n#{i+1}: [{r.test_name}] {r.config}")
        print(f"     Crib: {r.crib_score}/{N_CRIBS} (ENE={r.ene_score}/13, BC={r.bc_score}/11)")
        print(f"     IC: {r.ic_value:.4f}  Bean: {'PASS' if r.bean_passed else 'FAIL'}  [{r.classification}]")
        print(f"     PT: {r.plaintext[:50]}...")
        print(f"         {r.plaintext[50:]}")
        # Show crib alignment
        pt = r.plaintext
        ene_actual = pt[21:34] if len(pt) >= 34 else "?"
        bc_actual = pt[63:74] if len(pt) >= 74 else "?"
        print(f"     ENE@21: {ene_actual} (want EASTNORTHEAST)")
        print(f"     BC@63:  {bc_actual} (want BERLINCLOCK)")

    # Check for any above-noise results
    above_noise = [r for r in ALL_RESULTS if r.crib_score > NOISE_FLOOR]
    if above_noise:
        print(f"\n{'='*78}")
        print(f"ABOVE-NOISE RESULTS ({len(above_noise)} configs with score > {NOISE_FLOOR}):")
        print(f"{'='*78}")
        for r in above_noise[:20]:
            print(f"  Score {r.crib_score}: [{r.test_name}] {r.config}")
            print(f"    PT: {r.plaintext}")
    else:
        print(f"\nNo results above noise floor ({NOISE_FLOOR}).")

    # Write results to JSON
    os.makedirs("results", exist_ok=True)
    output = {
        "experiment": "E-AUDIT-05",
        "description": "YAR superscript as cipher initialization parameters",
        "total_configs": len(ALL_RESULTS),
        "elapsed_seconds": round(elapsed, 1),
        "score_distribution": {str(k): v for k, v in sorted(score_dist.items(), reverse=True)},
        "bean_passing": bean_pass_count,
        "max_crib_score": ALL_RESULTS[0].crib_score if ALL_RESULTS else 0,
        "top_10": [
            {
                "test": r.test_name,
                "config": r.config,
                "crib_score": r.crib_score,
                "ene_score": r.ene_score,
                "bc_score": r.bc_score,
                "ic": round(r.ic_value, 4),
                "bean": r.bean_passed,
                "plaintext": r.plaintext,
            }
            for r in ALL_RESULTS[:10]
        ],
        "verdict": "NOISE" if (ALL_RESULTS[0].crib_score if ALL_RESULTS else 0) <= NOISE_FLOOR else "INVESTIGATE",
    }
    outpath = "results/e_audit_05_yar_init_params.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {outpath}")

    print(f"\nVERDICT: {output['verdict']}")
    if output["verdict"] == "NOISE":
        print("All YAR initialization parameter configurations produce noise-level scores.")
        print("YAR as cipher initialization does not unlock K4 under these models.")


if __name__ == "__main__":
    main()
