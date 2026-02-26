#!/usr/bin/env python3
"""E-BESPOKE-02: ABSCISSA as Linear Transformation Instruction.

HYPOTHESIS: The K1 riddle answer "ABSCISSA" (= x-coordinate, the first element
of a coordinate pair (x,y) on the Cartesian plane) is not just thematic — it is
a MATHEMATICAL INSTRUCTION to apply a linear transformation to positions.

ABSCISSA also means "cut off" in Latin (from abscindere). The Morse K0 has "WHA"
which is "WHAT" cut off. Could "abscissa" mean TRUNCATION or CUTTING of the CT?

Tests:
  Phase 1: LINEAR TRANSPOSITION — j = (m*i + b) mod 97
           For ALL valid m (1–96, all coprime to 97 since 97 is prime)
           and sculpture-derived b values.
           Then apply Vigenere/Beaufort crib checking.

  Phase 2: AFFINE SUBSTITUTION — CT_mod[i] = (m * CT[i] + b) mod 26
           Standard affine cipher on the ciphertext letter values.
           m must be coprime to 26 (m in {1,3,5,7,9,11,15,17,19,21,23,25}).

  Phase 3: POSITION-DEPENDENT LINEAR KEY — key[i] = (m*i + b) mod 26
           A linearly increasing key (the "x-coordinate" IS the key).
           This is the most direct "abscissa" interpretation.

  Phase 4: COMBINED — linear transposition THEN position-dependent key.

  Phase 5: CUT-OFF / TRUNCATION models — remove chars, null extraction,
           split at various points suggested by sculpture clues.

  Phase 6: LINEAR TRANSPOSITION + sculpture-derived periodic keys.

  Phase 7: Coordinate pair reading — treat CT as (x,y) pairs.

Sculpture-derived parameter candidates:
  - T=19 ("T IS YOUR POSITION")
  - Y=24, A=0, R=17 (YAR superscript)
  - ABSCISSA letter values: [0,1,18,2,8,18,18,0]
  - KRYPTOS letter values: [10,17,24,15,19,14,18]
  - PALIMPSEST letter values: [15,0,11,8,12,15,18,4,18,19]
  - 5, 8 from DESPARATLY error positions
  - 97 (K4 length, prime)
  - 26 (alphabet size)
"""
import json
import os
import sys
import time
from math import gcd

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, N_CRIBS,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Global tracking ──
best_score = 0
best_config = ""
best_pt = ""
total_configs = 0
start_time = time.time()
above_noise = []  # score >= 7

RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)


# ── Cipher helpers ──

def vig_decrypt(ct_str, key_vals):
    """Vigenere: PT[i] = (CT[i] - key[i]) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def beau_decrypt(ct_str, key_vals):
    """Beaufort: PT[i] = (key[i] - CT[i]) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


def varbeau_decrypt(ct_str, key_vals):
    """Variant Beaufort: PT[i] = (CT[i] + key[i]) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ci + ki) % 26])
    return ''.join(pt)


VARIANTS = [('vig', vig_decrypt), ('beau', beau_decrypt), ('varbeau', varbeau_decrypt)]


def check(pt, config_str):
    """Score a candidate and update global tracking."""
    global total_configs, best_score, best_config, best_pt
    total_configs += 1
    sc = score_cribs(pt)
    if sc > best_score:
        best_score = sc
        best_config = config_str
        best_pt = pt
        print(f"  NEW BEST: {sc}/24 -- {config_str}")
        if sc >= 10:
            print(f"    PT: {pt}")
    if sc >= 7:
        above_noise.append({
            'config': config_str,
            'score': sc,
            'pt_snippet': pt[:60],
        })
    return sc


def apply_linear_transposition(text, m, b, n):
    """Apply linear transposition: output[j] = input[(m*j + b) mod n].
    This is the 'gather' convention: position j in the output reads from
    position (m*j + b) mod n in the input.

    Since n=97 is prime and m != 0, this is always a valid permutation.
    """
    result = []
    for j in range(n):
        src = (m * j + b) % n
        result.append(text[src])
    return ''.join(result)


def apply_affine_sub(text, m, b):
    """Affine substitution: new_char[i] = (m * old_char[i] + b) mod 26.
    m must be coprime to 26.
    """
    result = []
    for c in text:
        ci = ALPH_IDX[c]
        result.append(ALPH[(m * ci + b) % 26])
    return ''.join(result)


def linear_key(m, b, length):
    """Generate position-dependent linear key: key[i] = (m*i + b) mod 26."""
    return [(m * i + b) % 26 for i in range(length)]


# ── Sculpture-derived parameter values ──

# b values for linear transposition (offset)
SCULPTURE_B_VALUES = [
    0,           # identity offset
    1,           # minimal offset
    17,          # R=17 (from YAR)
    19,          # T=19 ("T IS YOUR POSITION")
    24,          # Y=24 (from YAR)
    5,           # from DESPARATLY error pos
    8,           # from DESPARATLY error pos
    10,          # X=10 (Roman numeral)
    6,           # Chapter VI
    11,          # Chapter XI
    38,          # k[27]=k[65], 65-27=38
    48,          # 97-49 (midpoint complement)
    16,          # Feb 16 (burial chamber)
    26,          # Nov 26 (breach), also alphabet size
    4,           # Nov 4 (discovery)
    7,           # KRYPTOS has 7 letters
    9,           # width-9 hypothesis
    13,          # EASTNORTHEAST has 13 letters
    97,          # K4 length (mod 97 = 0)
    67,          # ENE bearing 67.5 degrees, rounded
    68,          # ENE bearing rounded up
    3,           # D=3 (DYARO)
    14,          # O=14 (DYARO)
]

# Thematic keyword values for periodic keys
KEYWORD_KEYS = {
    'KRYPTOS': [ALPH_IDX[c] for c in 'KRYPTOS'],
    'PALIMPSEST': [ALPH_IDX[c] for c in 'PALIMPSEST'],
    'ABSCISSA': [ALPH_IDX[c] for c in 'ABSCISSA'],
    'YAR': [24, 0, 17],
    'DYAR': [3, 24, 0, 17],
    'DYARO': [3, 24, 0, 17, 14],
}

# m values coprime to 26 (for affine substitution)
AFFINE_M_VALUES = [m for m in range(1, 26) if gcd(m, 26) == 1]
# = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


def main():
    global total_configs, best_score, best_config, best_pt

    print("=" * 70)
    print("E-BESPOKE-02: ABSCISSA as Linear Transformation Instruction")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT_LEN: {CT_LEN} (prime)")
    print(f"All m values 1-96 are coprime to 97 (97 is prime)")
    print(f"Sculpture b values: {len(SCULPTURE_B_VALUES)}")
    print(f"Affine m values (coprime to 26): {AFFINE_M_VALUES}")
    print()

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: LINEAR TRANSPOSITION — j = (m*i + b) mod 97
    # All m from 1-96, selected b values from sculpture.
    # Then check cribs directly on transposed CT (identity substitution)
    # and with all three cipher variants using crib-derived key checking.
    # ═══════════════════════════════════════════════════════════════════
    print("--- Phase 1: Linear Transposition j=(m*i+b) mod 97 ---")
    p1_start = total_configs

    for m in range(1, 97):
        for b in SCULPTURE_B_VALUES:
            b_mod = b % 97
            transposed = apply_linear_transposition(CT, m, b_mod, CT_LEN)

            # Check identity (no substitution) — does transposed text match cribs?
            check(transposed, f"p1-lintrans/m={m}/b={b_mod}/identity")

            # Check with Vigenere/Beaufort using crib-derived key analysis:
            # For each crib position, compute what the key WOULD be, then
            # check consistency. But easier: just score_cribs on the raw transposed.
            # The crib check already does this.

        if m % 20 == 0:
            elapsed = time.time() - start_time
            rate = total_configs / elapsed if elapsed > 0 else 0
            print(f"  m={m}/96: {total_configs} configs, {rate:.0f}/s, best {best_score}/24")
            sys.stdout.flush()

    print(f"  Phase 1: {total_configs - p1_start} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: AFFINE SUBSTITUTION — CT_mod[i] = (m * CT[i] + b) mod 26
    # Then score the modified CT against cribs.
    # Also test: affine THEN linear transposition, and vice versa.
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 2: Affine Substitution (m*CT[i]+b) mod 26 ---")
    p2_start = total_configs

    for m in AFFINE_M_VALUES:
        for b in range(26):
            modified = apply_affine_sub(CT, m, b)
            check(modified, f"p2-affine/m={m}/b={b}")

    # Affine sub then linear transposition (small m_trans sweep)
    print("  Phase 2b: Affine + linear transposition...")
    for aff_m in AFFINE_M_VALUES:
        for aff_b in range(26):
            modified = apply_affine_sub(CT, aff_m, aff_b)
            # Only test a subset of transposition m values
            for trans_m in [1, 2, 3, 5, 7, 10, 17, 19, 24, 38, 48, 67, 96]:
                for trans_b in [0, 17, 19, 24]:
                    transposed = apply_linear_transposition(modified, trans_m, trans_b % 97, CT_LEN)
                    check(transposed, f"p2b-aff+lt/am={aff_m}/ab={aff_b}/tm={trans_m}/tb={trans_b%97}")

    print(f"  Phase 2: {total_configs - p2_start} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3: POSITION-DEPENDENT LINEAR KEY — key[i] = (m*i + b) mod 26
    # The "abscissa IS the key" interpretation.
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 3: Position-dependent linear key (m*i+b) mod 26 ---")
    p3_start = total_configs

    for m in range(0, 26):
        for b in range(26):
            key = linear_key(m, b, CT_LEN)
            for vname, vfunc in VARIANTS:
                pt = vfunc(CT, key)
                check(pt, f"p3-linkey/m={m}/b={b}/{vname}")

    print(f"  Phase 3: {total_configs - p3_start} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4: COMBINED — linear transposition THEN position-dependent key
    # Most direct "ABSCISSA" interpretation: rearrange by linear perm,
    # then decrypt with linear key.
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 4: Linear transposition + linear key ---")
    p4_start = total_configs

    # Focus on sculpture-derived m values for transposition
    TRANS_M_FOCUS = [1, 2, 3, 5, 7, 8, 9, 10, 11, 13, 17, 19, 24, 38, 48, 67, 96]
    TRANS_B_FOCUS = [0, 5, 8, 17, 19, 24]

    for trans_m in TRANS_M_FOCUS:
        for trans_b in TRANS_B_FOCUS:
            transposed = apply_linear_transposition(CT, trans_m, trans_b, CT_LEN)
            for key_m in range(0, 26):
                for key_b in range(26):
                    key = linear_key(key_m, key_b, CT_LEN)
                    for vname, vfunc in VARIANTS:
                        pt = vfunc(transposed, key)
                        check(pt, f"p4-lt+lk/tm={trans_m}/tb={trans_b}/km={key_m}/kb={key_b}/{vname}")

        if trans_m in [5, 10, 17, 38, 96]:
            elapsed = time.time() - start_time
            rate = total_configs / elapsed if elapsed > 0 else 0
            print(f"  trans_m={trans_m}: {total_configs:,} configs, {rate:.0f}/s, best {best_score}/24")
            sys.stdout.flush()

    print(f"  Phase 4: {total_configs - p4_start:,} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 5: CUT-OFF / TRUNCATION models
    # ABSCISSA = "cut off" (Latin). What if we cut the CT?
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 5: Cut-off / truncation models ---")
    p5_start = total_configs

    # 5a: Remove every Nth character (null extraction)
    for step in range(2, 10):
        # Extract characters NOT at positions divisible by step
        extracted = ''.join(CT[i] for i in range(CT_LEN) if i % step != 0)
        check(extracted, f"p5a-remove-every-{step}")
        # Also: extract ONLY characters at positions divisible by step
        extracted2 = ''.join(CT[i] for i in range(CT_LEN) if i % step == 0)
        check(extracted2, f"p5a-keep-every-{step}")

    # 5b: Split at sculpture-derived positions
    SPLIT_POSITIONS = [
        19,   # T=19
        21,   # start of EASTNORTHEAST crib
        34,   # end of EASTNORTHEAST crib + 1
        48,   # midpoint of 97
        63,   # start of BERLINCLOCK crib
        74,   # end of BERLINCLOCK crib + 1
        24,   # Y=24
        17,   # R=17
        38,   # gap 65-27
        5,    # DESPARATLY
        8,    # DESPARATLY
        10,   # X=10
    ]

    for split_pos in SPLIT_POSITIONS:
        if 0 < split_pos < CT_LEN:
            # Swap halves
            swapped = CT[split_pos:] + CT[:split_pos]
            check(swapped, f"p5b-swap-at-{split_pos}")

            # Reverse first half, keep second
            rev_first = CT[:split_pos][::-1] + CT[split_pos:]
            check(rev_first, f"p5b-rev-first-{split_pos}")

            # Keep first, reverse second
            rev_second = CT[:split_pos] + CT[split_pos:][::-1]
            check(rev_second, f"p5b-rev-second-{split_pos}")

            # Interleave the two halves
            half1 = CT[:split_pos]
            half2 = CT[split_pos:]
            interleaved = []
            for i in range(max(len(half1), len(half2))):
                if i < len(half1):
                    interleaved.append(half1[i])
                if i < len(half2):
                    interleaved.append(half2[i])
            interleaved_str = ''.join(interleaved)
            check(interleaved_str, f"p5b-interleave-at-{split_pos}")

    # 5c: Remove characters at specific positions (ABSCISSA "cut off")
    # Cut positions derived from ABSCISSA letter values [0,1,18,2,8,18,18,0]
    abscissa_vals = [ALPH_IDX[c] for c in 'ABSCISSA']
    cut_positions = set()
    for i, v in enumerate(abscissa_vals):
        # Interpret as positions to remove
        cut_positions.add(v)
        # Also try cumulative
        if i > 0:
            cut_positions.add(sum(abscissa_vals[:i+1]) % CT_LEN)

    for pos_to_cut in sorted(cut_positions):
        if 0 <= pos_to_cut < CT_LEN:
            remaining = CT[:pos_to_cut] + CT[pos_to_cut+1:]
            check(remaining, f"p5c-cut-pos-{pos_to_cut}")

    # 5d: Use ABSCISSA values as a list of positions to remove
    positions_to_remove = set(v % CT_LEN for v in abscissa_vals)
    remaining = ''.join(CT[i] for i in range(CT_LEN) if i not in positions_to_remove)
    check(remaining, f"p5d-cut-abscissa-positions")

    # Also remove at cumulative sums of ABSCISSA values
    cum_positions = set()
    running = 0
    for v in abscissa_vals:
        running += v
        cum_positions.add(running % CT_LEN)
    remaining2 = ''.join(CT[i] for i in range(CT_LEN) if i not in cum_positions)
    check(remaining2, f"p5d-cut-abscissa-cumulative")

    print(f"  Phase 5: {total_configs - p5_start} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 6: LINEAR TRANSPOSITION + sculpture-derived PERIODIC keys
    # (e.g., KRYPTOS, PALIMPSEST, ABSCISSA as key after linear trans)
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 6: Linear transposition + periodic keyword keys ---")
    p6_start = total_configs

    # Focus on the most promising m values
    TRANS_M_SWEEP = list(range(1, 97))
    TRANS_B_SMALL = [0, 17, 19, 24]

    for kw_name, kw_vals in KEYWORD_KEYS.items():
        for trans_m in TRANS_M_SWEEP:
            for trans_b in TRANS_B_SMALL:
                transposed = apply_linear_transposition(CT, trans_m, trans_b, CT_LEN)
                for vname, vfunc in VARIANTS:
                    pt = vfunc(transposed, kw_vals)
                    check(pt, f"p6-lt+kw/tm={trans_m}/tb={trans_b}/{vname}_{kw_name}")

        elapsed = time.time() - start_time
        rate = total_configs / elapsed if elapsed > 0 else 0
        print(f"  Keyword {kw_name}: {total_configs:,} configs, {rate:.0f}/s, best {best_score}/24")
        sys.stdout.flush()

    print(f"  Phase 6: {total_configs - p6_start:,} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 7: Coordinate pair reading
    # If CT encodes (x,y) pairs, with 97 chars that's 48 pairs + 1 extra.
    # The extra char could be a null, separator, or checksum.
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 7: Coordinate pair models ---")
    p7_start = total_configs

    ct_vals = [ALPH_IDX[c] for c in CT]

    # 7a: Treat pairs as (x,y) coordinates, try to read from a grid
    for null_pos in [-1, 0, 48, 96]:  # position of the null/extra char
        if null_pos == -1:
            # No null — use first 96 chars (drop last)
            pairs = [(ct_vals[i], ct_vals[i+1]) for i in range(0, 96, 2)]
        elif null_pos == 96:
            # Last char is null — use first 96
            pairs = [(ct_vals[i], ct_vals[i+1]) for i in range(0, 96, 2)]
        elif null_pos == 0:
            # First char is null — use chars 1-97
            remaining = ct_vals[1:]
            pairs = [(remaining[i], remaining[i+1]) for i in range(0, 96, 2)]
        elif null_pos == 48:
            # Middle char is null
            remaining = ct_vals[:48] + ct_vals[49:]
            pairs = [(remaining[i], remaining[i+1]) for i in range(0, 96, 2)]

        # Build grid and try to read message from coordinate pairs
        # Interpretation 1: x selects column, y selects row in a 26x26 grid
        # containing ALPH repeatedly
        message = []
        for x, y in pairs:
            # Various combination functions
            message.append(ALPH[(x + y) % 26])
        check(''.join(message), f"p7a-pairs/null={null_pos}/x+y")

        message2 = []
        for x, y in pairs:
            message2.append(ALPH[(x - y) % 26])
        check(''.join(message2), f"p7a-pairs/null={null_pos}/x-y")

        message3 = []
        for x, y in pairs:
            message3.append(ALPH[(x * y) % 26])
        check(''.join(message3), f"p7a-pairs/null={null_pos}/x*y")

        message4 = []
        for x, y in pairs:
            message4.append(ALPH[(y - x) % 26])
        check(''.join(message4), f"p7a-pairs/null={null_pos}/y-x")

    # 7b: CT as coordinate stream with period-2 key mixing
    # Odd positions = x-coordinate, even = y-coordinate
    for key_shift in range(26):
        x_stream = [ct_vals[i] for i in range(0, CT_LEN, 2)]
        y_stream = [ct_vals[i] for i in range(1, CT_LEN, 2)]
        # Combine: PT[j] = (x[j] + y[j] + shift) mod 26
        combined = []
        for j in range(min(len(x_stream), len(y_stream))):
            combined.append(ALPH[(x_stream[j] + y_stream[j] + key_shift) % 26])
        check(''.join(combined), f"p7b-xy-stream/shift={key_shift}/add")

        combined2 = []
        for j in range(min(len(x_stream), len(y_stream))):
            combined2.append(ALPH[(x_stream[j] - y_stream[j] + key_shift) % 26])
        check(''.join(combined2), f"p7b-xy-stream/shift={key_shift}/sub")

    print(f"  Phase 7: {total_configs - p7_start} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 8: Linear transposition with INVERSE direction
    # Instead of output[j] = input[(m*j+b) mod 97] (gather),
    # try output[(m*i+b) mod 97] = input[i] (scatter).
    # This is the inverse permutation.
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 8: Inverse linear transposition (scatter) ---")
    p8_start = total_configs

    def apply_scatter_transposition(text, m, b, n):
        """Scatter convention: output[(m*i+b) mod n] = input[i]."""
        result = [''] * n
        for i in range(n):
            dest = (m * i + b) % n
            result[dest] = text[i]
        return ''.join(result)

    for m in range(1, 97):
        for b in SCULPTURE_B_VALUES[:10]:  # Smaller subset for speed
            b_mod = b % 97
            transposed = apply_scatter_transposition(CT, m, b_mod, CT_LEN)
            check(transposed, f"p8-scatter/m={m}/b={b_mod}")

        if m % 20 == 0:
            elapsed = time.time() - start_time
            rate = total_configs / elapsed if elapsed > 0 else 0
            print(f"  m={m}/96: {total_configs:,} configs, {rate:.0f}/s, best {best_score}/24")
            sys.stdout.flush()

    print(f"  Phase 8: {total_configs - p8_start:,} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 9: Quadratic/polynomial position transform
    # j = (a*i^2 + b*i + c) mod 97 — "abscissa" could mean the
    # x-axis value in a PARABOLA (y = ax^2 + bx + c).
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 9: Quadratic position transform ---")
    p9_start = total_configs

    # Test small a values (quadratic coefficient)
    for a in range(1, 10):
        for b_coeff in [0, 1, 5, 17, 19, 24]:
            for c_coeff in [0, 17, 19, 24]:
                # Check if this generates a valid permutation (all positions unique mod 97)
                positions = [(a * i * i + b_coeff * i + c_coeff) % 97 for i in range(97)]
                if len(set(positions)) == 97:  # Valid permutation
                    result = ''.join(CT[positions[j]] for j in range(97))
                    check(result, f"p9-quad/a={a}/b={b_coeff}/c={c_coeff}")

    print(f"  Phase 9: {total_configs - p9_start} configs, best {best_score}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 10: Linear key with linear transposition — full score_candidate
    # Re-test the top-scoring configs from phase 4 with full scoring.
    # ═══════════════════════════════════════════════════════════════════
    print("\n--- Phase 10: Full scoring on best phase 4 candidates ---")
    p10_start = total_configs

    # Just re-run phase 3 with score_candidate for more detail
    best_full = 0
    best_full_config = ""
    best_full_pt = ""

    for m in range(0, 26):
        for b in range(26):
            key = linear_key(m, b, CT_LEN)
            for vname, vfunc in VARIANTS:
                pt = vfunc(CT, key)
                sc = score_candidate(pt)
                total_configs += 1
                if sc.crib_score > best_full:
                    best_full = sc.crib_score
                    best_full_config = f"p10-full/m={m}/b={b}/{vname}"
                    best_full_pt = pt
                    if sc.crib_score >= 7:
                        print(f"  Full score {sc.crib_score}/24: {best_full_config}")
                        print(f"    {sc.summary}")

    print(f"  Phase 10: {total_configs - p10_start} configs, best full score {best_full}/24")

    # ═══════════════════════════════════════════════════════════════════
    # Summary
    # ═══════════════════════════════════════════════════════════════════
    elapsed = time.time() - start_time

    print()
    print("=" * 70)
    print("FINAL SUMMARY: E-BESPOKE-02 — ABSCISSA Linear Transform")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Elapsed time: {elapsed:.1f}s ({total_configs/elapsed:.0f} configs/s)" if elapsed > 0 else "")
    print(f"Best score: {best_score}/24")

    if best_score <= 6:
        classification = "NOISE"
    elif best_score <= 17:
        classification = "STORE"
    elif best_score <= 23:
        classification = "SIGNAL -- INVESTIGATE!"
    else:
        classification = "BREAKTHROUGH"

    print(f"Classification: {classification}")
    print(f"Best config: {best_config}")
    if best_pt:
        print(f"Best PT (first 60): {best_pt[:60]}")
    print(f"Results above noise (>=7): {len(above_noise)}")

    if above_noise:
        print("\nTop 20 results:")
        for r in sorted(above_noise, key=lambda x: -x['score'])[:20]:
            print(f"  {r['score']}/24: {r['config'][:80]}")

    # Save results
    output = {
        'experiment': 'E-BESPOKE-02',
        'description': 'ABSCISSA as linear transformation instruction',
        'hypothesis': 'K1 answer ABSCISSA = mathematical instruction for linear position/key transform',
        'total_configs': total_configs,
        'best_score': best_score,
        'best_config': best_config,
        'best_pt_snippet': best_pt[:60] if best_pt else None,
        'classification': classification,
        'elapsed_seconds': round(elapsed, 1),
        'phases': {
            'p1_linear_transposition': 'j=(m*i+b) mod 97, all m, sculpture b values',
            'p2_affine_substitution': '(m*CT[i]+b) mod 26, affine + linear trans combos',
            'p3_linear_key': 'key[i]=(m*i+b) mod 26, all m,b with Vig/Beau/VB',
            'p4_combined': 'linear trans + linear key',
            'p5_truncation': 'ABSCISSA="cut off": null extraction, splits, removals',
            'p6_lt_plus_periodic': 'linear trans + KRYPTOS/PALIMPSEST/ABSCISSA/YAR keys',
            'p7_coordinate_pairs': 'CT as (x,y) coordinate pairs',
            'p8_scatter_trans': 'inverse linear transposition (scatter convention)',
            'p9_quadratic': 'j=(a*i^2+b*i+c) mod 97 polynomial transform',
            'p10_full_scoring': 'Full score_candidate on linear key results',
        },
        'above_noise': sorted(above_noise, key=lambda x: -x['score'])[:50],
    }

    outpath = os.path.join(RESULTS_DIR, 'e_bespoke_02_abscissa_linear.json')
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nArtifact: {outpath}")


if __name__ == '__main__':
    main()
