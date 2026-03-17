#!/usr/bin/env python3
"""
Straddling Checkerboard Digit-Level Attack on K4.

Cipher:  Straddling Checkerboard (digit-level, NOT letter-level)
Family:  analysis
Status:  active
Keyspace: see implementation (~10M+ configs)
Last run: never
Best score: N/A

HYPOTHESIS: K4's "two systems" are:
  System 1 (inner): substitution cipher on plaintext
  System 2 (outer): straddling checkerboard EXPANSION (73 PT chars -> 97 digits -> 97 CT letters)

Each of the 26 CT letters maps to a digit (0-9) via a keyed 26-to-10 mapping.
The 97 CT letters produce a 97-digit stream. This stream is parsed as straddling
checkerboard output: 8-9 common letters get 1-digit codes, 17-18 rare letters get
2-digit codes. Parsing yields ~73 plaintext characters.

For 73 PT -> 97 digits: exactly 24 of 73 PT letters need 2-digit codes (rare letters).
49 get 1-digit codes (common letters). 49*1 + 24*2 = 97.

This is NOVEL and DISTINCT from:
- e_vic_model.py (130.7M configs): used LETTER-level parsing (prefix letters as escape)
- E-FRAC-21: "proved" SC impossible by noting SC outputs digits, not letters --
  but that argument ignores the digit-to-letter conversion step

PHASES:
1. Letter-to-digit mapping search (keyed alphabets mod 10)
2. Checkerboard layout search (escape digit pairs x keyword alphabets)
3. Crib-in-digit-space validation (encode cribs, match against digit stream)
4. Two-layer models (checkerboard + substitution cipher)
5. Expansion ratio validation
6. Reverse crib dragging
"""

import sys
import json
import time
import math
from pathlib import Path
from itertools import combinations
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, KRYPTOS_ALPHABET, CRIB_WORDS

# ── Constants ────────────────────────────────────────────────────────────────
AZ = ALPH  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"

CRIB_ENE_POS = 21  # 0-indexed position in 73-char PT
CRIB_ENE = "EASTNORTHEAST"
CRIB_BC_POS = 63
CRIB_BC = "BERLINCLOCK"

# Thematic keywords to test as checkerboard keys
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
    "BERLINCLOCK", "EASTNORTHEAST", "SHADOW", "ENIGMA", "CIPHER",
    "SANBORN", "SCHEIDT", "MEDUSA", "COLOPHON", "PARALLAX",
    "TOWER", "CHART", "LAYER",  # from mod-35 table matches
    "FIVE", "CLOCK", "NORTH",
]

# English letter frequencies (approximate, for expansion ratio calc)
ENGLISH_FREQ = {
    'E': 0.127, 'T': 0.091, 'A': 0.082, 'O': 0.075, 'I': 0.070,
    'N': 0.067, 'S': 0.063, 'H': 0.061, 'R': 0.060, 'D': 0.043,
    'L': 0.040, 'C': 0.028, 'U': 0.028, 'M': 0.024, 'W': 0.024,
    'F': 0.022, 'G': 0.020, 'Y': 0.020, 'P': 0.019, 'B': 0.015,
    'V': 0.010, 'K': 0.008, 'J': 0.002, 'X': 0.002, 'Q': 0.001,
    'Z': 0.001,
}


def keyword_mixed_alphabet(kw, base=AZ):
    """Build keyword-mixed alphabet."""
    seen = set()
    out = []
    for ch in kw.upper():
        if ch in set(base) and ch not in seen:
            seen.add(ch)
            out.append(ch)
    for ch in base:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)
    return ''.join(out)


def letter_to_digit_mapping(alphabet):
    """Map each letter to digit = position_in_alphabet mod 10.
    Returns dict: letter -> digit (int 0-9)."""
    return {ch: i % 10 for i, ch in enumerate(alphabet)}


def ct_to_digits(ct, mapping):
    """Convert CT string to digit list using letter-to-digit mapping."""
    return [mapping[ch] for ch in ct]


def build_checkerboard(alphabet, escape1, escape2):
    """Build a straddling checkerboard from a 26-letter alphabet and 2 escape digits.

    Row 0: 8 letters at non-escape columns (1-digit codes)
    Row escape1: 10 letters (2-digit codes: escape1 + col)
    Row escape2: 8 letters (2-digit codes: escape2 + col)

    Total: 8 + 10 + 8 = 26 letters.

    Returns: dict mapping letter -> tuple of digits, and inverse dict.
    """
    cols = list(range(10))
    non_escape_cols = [c for c in cols if c != escape1 and c != escape2]

    # Row 0: first 8 letters at non-escape columns -> single digits
    # Row escape1: next 10 letters -> (escape1, col) for col in 0-9
    # Row escape2: last 8 letters -> (escape2, col) for col in non-escape columns

    letter_to_code = {}
    code_to_letter = {}

    idx = 0
    # Row 0: 8 single-digit codes
    for col in non_escape_cols:
        if idx < len(alphabet):
            letter_to_code[alphabet[idx]] = (col,)
            code_to_letter[(col,)] = alphabet[idx]
            idx += 1

    # Row escape1: 10 two-digit codes
    for col in cols:
        if idx < len(alphabet):
            letter_to_code[alphabet[idx]] = (escape1, col)
            code_to_letter[(escape1, col)] = alphabet[idx]
            idx += 1

    # Row escape2: 8 two-digit codes (only non-escape columns)
    for col in non_escape_cols:
        if idx < len(alphabet):
            letter_to_code[alphabet[idx]] = (escape2, col)
            code_to_letter[(escape2, col)] = alphabet[idx]
            idx += 1

    return letter_to_code, code_to_letter


def decode_digit_stream(digits, escape1, escape2, code_to_letter):
    """Parse a digit stream using straddling checkerboard.
    Returns decoded string or None if parsing fails."""
    result = []
    i = 0
    while i < len(digits):
        d = digits[i]
        if d == escape1 or d == escape2:
            if i + 1 >= len(digits):
                return None  # incomplete 2-digit code
            code = (d, digits[i + 1])
            if code not in code_to_letter:
                return None
            result.append(code_to_letter[code])
            i += 2
        else:
            code = (d,)
            if code not in code_to_letter:
                return None
            result.append(code_to_letter[code])
            i += 1
    return ''.join(result)


def encode_text(text, letter_to_code):
    """Encode plaintext through checkerboard -> digit tuple sequence."""
    digits = []
    for ch in text.upper():
        if ch not in letter_to_code:
            return None
        digits.extend(letter_to_code[ch])
    return digits


def check_cribs_at_positions(decoded, ene_pos=21, bc_pos=63):
    """Check if decoded text has cribs at expected positions."""
    score = 0
    if decoded is None:
        return 0
    n = len(decoded)

    # Check ENE
    if ene_pos + 13 <= n:
        for i, ch in enumerate(CRIB_ENE):
            if decoded[ene_pos + i] == ch:
                score += 1

    # Check BC
    if bc_pos + 11 <= n:
        for i, ch in enumerate(CRIB_BC):
            if decoded[bc_pos + i] == ch:
                score += 1

    return score


def check_cribs_free(decoded):
    """Search for cribs at any position in decoded text."""
    if decoded is None or len(decoded) < 11:
        return 0, -1, -1

    best_score = 0
    best_ene_pos = -1
    best_bc_pos = -1
    n = len(decoded)

    # Search for ENE
    for p in range(n - 12):
        s = sum(1 for i, ch in enumerate(CRIB_ENE) if p + i < n and decoded[p + i] == ch)
        if s > 0:
            # For this ENE position, search for BC
            for q in range(n - 10):
                s2 = sum(1 for i, ch in enumerate(CRIB_BC) if q + i < n and decoded[q + i] == ch)
                total = s + s2
                if total > best_score:
                    best_score = total
                    best_ene_pos = p
                    best_bc_pos = q

    return best_score, best_ene_pos, best_bc_pos


def expected_expansion(alphabet, escape1, escape2):
    """Compute expected expansion ratio for English plaintext."""
    letter_to_code, _ = build_checkerboard(alphabet, escape1, escape2)
    total_digits = 0
    for letter, freq in ENGLISH_FREQ.items():
        if letter in letter_to_code:
            code_len = len(letter_to_code[letter])
            total_digits += freq * code_len
    return total_digits  # digits per PT char


def run():
    t0 = time.time()
    all_results = []

    print("=" * 70)
    print("STRADDLING CHECKERBOARD DIGIT-LEVEL ATTACK ON K4")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Target: 73 PT chars -> 97 digits (ratio 1.329)")
    print(f"Requires: 49 single-digit + 24 double-digit PT letters")
    print()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1: Build alphabets and letter-to-digit mappings
    # ══════════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PHASE 1: Letter-to-digit mappings from keyed alphabets")
    print("=" * 70)

    alphabets = {}
    for kw in KEYWORDS:
        alpha = keyword_mixed_alphabet(kw)
        if alpha not in alphabets.values():
            alphabets[kw] = alpha
    # Always include AZ and KA
    alphabets["AZ_STANDARD"] = AZ
    alphabets["KA_STANDARD"] = KA

    print(f"Unique alphabets: {len(alphabets)}")
    for name, alpha in list(alphabets.items())[:5]:
        print(f"  {name}: {alpha[:20]}...")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2: Direct checkerboard decode (no intermediate substitution)
    # For each alphabet (letter-to-digit mapping) x each escape pair:
    #   CT -> digits -> checkerboard decode -> PT
    #   Check if PT has cribs at expected positions or anywhere
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 2: Direct decode (CT -> digits -> checkerboard -> PT)")
    print("=" * 70)

    phase2_configs = 0
    phase2_hits = []
    best_fixed = 0
    best_free = 0

    escape_pairs = list(combinations(range(10), 2))  # C(10,2) = 45 pairs

    for alpha_name, alpha_outer in alphabets.items():
        # The outer alphabet maps CT letters to digits
        outer_mapping = letter_to_digit_mapping(alpha_outer)
        digits = ct_to_digits(CT, outer_mapping)

        for alpha_inner_name, alpha_inner in alphabets.items():
            for e1, e2 in escape_pairs:
                phase2_configs += 1

                # Build checkerboard from inner alphabet
                l2c, c2l = build_checkerboard(alpha_inner, e1, e2)

                # Decode digit stream
                decoded = decode_digit_stream(digits, e1, e2, c2l)
                if decoded is None:
                    continue

                pt_len = len(decoded)

                # Check expansion ratio
                if pt_len < 50 or pt_len > 90:
                    continue

                # Fixed-position crib check
                fixed_score = check_cribs_at_positions(decoded)

                # Free crib check
                free_score, free_ene, free_bc = check_cribs_free(decoded)

                if fixed_score > best_fixed:
                    best_fixed = fixed_score
                if free_score > best_free:
                    best_free = free_score

                if fixed_score >= 3 or free_score >= 4:
                    hit = {
                        'phase': 2,
                        'outer_alpha': alpha_name,
                        'inner_alpha': alpha_inner_name,
                        'escape_pair': (e1, e2),
                        'pt_length': pt_len,
                        'fixed_score': fixed_score,
                        'free_score': free_score,
                        'free_ene_pos': free_ene,
                        'free_bc_pos': free_bc,
                        'decoded': decoded[:80],
                    }
                    phase2_hits.append(hit)
                    print(f"  HIT: {alpha_name}+{alpha_inner_name} esc=({e1},{e2}) "
                          f"len={pt_len} fixed={fixed_score} free={free_score}")
                    print(f"    PT: {decoded[:60]}...")

    print(f"\nPhase 2: {phase2_configs:,} configs tested")
    print(f"  Best fixed score: {best_fixed}/24")
    print(f"  Best free score: {best_free}/24")
    print(f"  Hits (fixed>=3 or free>=4): {len(phase2_hits)}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3: Same-alphabet model (outer and inner use SAME keyed alphabet)
    # This is the simplest model: one keyword defines everything
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 3: Same-alphabet model (one keyword for both mappings)")
    print("=" * 70)

    phase3_configs = 0
    phase3_best_fixed = 0
    phase3_best_free = 0

    for alpha_name, alpha in alphabets.items():
        mapping = letter_to_digit_mapping(alpha)
        digits = ct_to_digits(CT, mapping)

        for e1, e2 in escape_pairs:
            phase3_configs += 1
            l2c, c2l = build_checkerboard(alpha, e1, e2)
            decoded = decode_digit_stream(digits, e1, e2, c2l)
            if decoded is None:
                continue

            pt_len = len(decoded)
            if pt_len < 50 or pt_len > 90:
                continue

            fixed_score = check_cribs_at_positions(decoded)
            free_score, free_ene, free_bc = check_cribs_free(decoded)

            if fixed_score > phase3_best_fixed:
                phase3_best_fixed = fixed_score
            if free_score > phase3_best_free:
                phase3_best_free = free_score

            if fixed_score >= 3 or free_score >= 4 or pt_len == 73:
                print(f"  {alpha_name} esc=({e1},{e2}) len={pt_len} "
                      f"fixed={fixed_score} free={free_score}")
                if pt_len == 73:
                    print(f"    *** LENGTH 73 *** PT: {decoded}")

    print(f"\nPhase 3: {phase3_configs} configs, best fixed={phase3_best_fixed}, "
          f"best free={phase3_best_free}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4: Crib encoding fingerprint
    # Encode cribs through every checkerboard layout, check if the resulting
    # digit pattern appears in any CT-derived digit stream
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 4: Crib-in-digit-space (encode cribs, match against digit stream)")
    print("=" * 70)

    phase4_configs = 0
    phase4_hits = []
    phase4_best = 0

    for alpha_outer_name, alpha_outer in alphabets.items():
        outer_mapping = letter_to_digit_mapping(alpha_outer)
        digit_stream = ct_to_digits(CT, outer_mapping)
        digit_str = ''.join(str(d) for d in digit_stream)

        for alpha_inner_name, alpha_inner in alphabets.items():
            for e1, e2 in escape_pairs:
                phase4_configs += 1
                l2c, c2l = build_checkerboard(alpha_inner, e1, e2)

                # Encode ENE through checkerboard
                ene_digits = encode_text(CRIB_ENE, l2c)
                bc_digits = encode_text(CRIB_BC, l2c)

                if ene_digits is None or bc_digits is None:
                    continue

                ene_str = ''.join(str(d) for d in ene_digits)
                bc_str = ''.join(str(d) for d in bc_digits)

                # Check if encoded cribs appear in the digit stream
                ene_matches = []
                bc_matches = []

                # Search for ENE digit pattern
                for i in range(len(digit_str) - len(ene_str) + 1):
                    match = sum(1 for j in range(len(ene_str)) if digit_str[i+j] == ene_str[j])
                    if match >= len(ene_str) * 0.7:
                        ene_matches.append((i, match, len(ene_str)))

                # Search for BC digit pattern
                for i in range(len(digit_str) - len(bc_str) + 1):
                    match = sum(1 for j in range(len(bc_str)) if digit_str[i+j] == bc_str[j])
                    if match >= len(bc_str) * 0.7:
                        bc_matches.append((i, match, len(bc_str)))

                if ene_matches or bc_matches:
                    score = 0
                    if ene_matches:
                        score += max(m[1] for m in ene_matches)
                    if bc_matches:
                        score += max(m[1] for m in bc_matches)

                    if score > phase4_best:
                        phase4_best = score

                    if score >= 15:
                        hit = {
                            'phase': 4,
                            'outer_alpha': alpha_outer_name,
                            'inner_alpha': alpha_inner_name,
                            'escape_pair': (e1, e2),
                            'ene_digit_len': len(ene_str),
                            'bc_digit_len': len(bc_str),
                            'ene_matches': ene_matches[:5],
                            'bc_matches': bc_matches[:5],
                            'score': score,
                        }
                        phase4_hits.append(hit)
                        print(f"  HIT: {alpha_outer_name}+{alpha_inner_name} esc=({e1},{e2}) "
                              f"score={score} ene_len={len(ene_str)} bc_len={len(bc_str)}")

    print(f"\nPhase 4: {phase4_configs:,} configs tested")
    print(f"  Best digit-match score: {phase4_best}")
    print(f"  Hits (score>=15): {len(phase4_hits)}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 5: Expansion ratio analysis
    # Which checkerboard layouts produce ratio ~1.329 for English text?
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 5: Expansion ratio analysis (target: 97/73 = 1.329)")
    print("=" * 70)

    target_ratio = 97.0 / 73.0
    tolerance = 0.05

    viable_layouts = []
    for alpha_name, alpha in alphabets.items():
        for e1, e2 in escape_pairs:
            ratio = expected_expansion(alpha, e1, e2)
            if abs(ratio - target_ratio) < tolerance:
                viable_layouts.append((alpha_name, e1, e2, ratio))

    print(f"Viable layouts (ratio within {tolerance} of {target_ratio:.3f}): {len(viable_layouts)}")
    for name, e1, e2, ratio in viable_layouts[:20]:
        print(f"  {name} esc=({e1},{e2}) ratio={ratio:.4f}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 6: Two-layer model
    # PT -> checkerboard -> digits -> simple substitution (digit shift) -> CT digits -> CT letters
    # Try additive shifts on the digit stream before decoding
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 6: Two-layer (checkerboard + digit-level substitution)")
    print("=" * 70)

    phase6_configs = 0
    phase6_best_fixed = 0
    phase6_best_free = 0
    phase6_hits = []

    for alpha_name, alpha in alphabets.items():
        mapping = letter_to_digit_mapping(alpha)
        base_digits = ct_to_digits(CT, mapping)

        for e1, e2 in escape_pairs:
            l2c, c2l = build_checkerboard(alpha, e1, e2)

            # Try additive shifts on the digit stream (mod 10)
            for shift in range(1, 10):
                phase6_configs += 1
                shifted = [(d + shift) % 10 for d in base_digits]
                decoded = decode_digit_stream(shifted, e1, e2, c2l)
                if decoded is None:
                    continue
                pt_len = len(decoded)
                if pt_len < 50 or pt_len > 90:
                    continue

                fixed_score = check_cribs_at_positions(decoded)
                free_score, free_ene, free_bc = check_cribs_free(decoded)

                if fixed_score > phase6_best_fixed:
                    phase6_best_fixed = fixed_score
                if free_score > phase6_best_free:
                    phase6_best_free = free_score

                if fixed_score >= 3 or free_score >= 4:
                    phase6_hits.append({
                        'phase': 6,
                        'alpha': alpha_name,
                        'escape_pair': (e1, e2),
                        'shift': shift,
                        'pt_length': pt_len,
                        'fixed_score': fixed_score,
                        'free_score': free_score,
                        'decoded': decoded[:80],
                    })

            # Try multiplicative transformations (mod 10, coprime to 10: 1,3,7,9)
            for mult in [3, 7, 9]:
                phase6_configs += 1
                transformed = [(d * mult) % 10 for d in base_digits]
                decoded = decode_digit_stream(transformed, e1, e2, c2l)
                if decoded is None:
                    continue
                pt_len = len(decoded)
                if pt_len < 50 or pt_len > 90:
                    continue

                fixed_score = check_cribs_at_positions(decoded)
                free_score, free_ene, free_bc = check_cribs_free(decoded)

                if fixed_score > phase6_best_fixed:
                    phase6_best_fixed = fixed_score
                if free_score > phase6_best_free:
                    phase6_best_free = free_score

                if fixed_score >= 3 or free_score >= 4:
                    phase6_hits.append({
                        'phase': 6,
                        'alpha': alpha_name,
                        'escape_pair': (e1, e2),
                        'mult': mult,
                        'pt_length': pt_len,
                        'fixed_score': fixed_score,
                        'free_score': free_score,
                        'decoded': decoded[:80],
                    })

    print(f"Phase 6: {phase6_configs:,} configs")
    print(f"  Best fixed: {phase6_best_fixed}, Best free: {phase6_best_free}")
    print(f"  Hits: {len(phase6_hits)}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 7: Reverse approach — compute digit fingerprints of cribs
    # under all checkerboard layouts and find exact matches in CT digit
    # stream at the expected positions
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 7: Reverse crib dragging (exact digit matching)")
    print("=" * 70)

    phase7_configs = 0
    phase7_hits = []
    phase7_best = 0

    # For each checkerboard layout, encode ENE and BC
    # For each letter-to-digit mapping, convert CT to digits
    # Check if encoded-crib digit sequence appears at the correct digit offset

    for alpha_outer_name, alpha_outer in alphabets.items():
        outer_mapping = letter_to_digit_mapping(alpha_outer)
        digit_stream = ct_to_digits(CT, outer_mapping)

        for alpha_inner_name, alpha_inner in alphabets.items():
            for e1, e2 in escape_pairs:
                phase7_configs += 1
                l2c, c2l = build_checkerboard(alpha_inner, e1, e2)

                ene_digits = encode_text(CRIB_ENE, l2c)
                bc_digits = encode_text(CRIB_BC, l2c)

                if ene_digits is None or bc_digits is None:
                    continue

                # In a 73-char PT with fixed crib positions, the digit offset
                # of each crib depends on how many 1-digit vs 2-digit letters
                # precede it. We don't know this, so we need to search.

                # ENE at PT position 21: digit offset is between 21 (all 1-digit before)
                # and 42 (all 2-digit before). Most likely ~28-32.
                ene_len = len(ene_digits)

                # Try all possible digit offsets for ENE
                for ene_offset in range(97 - ene_len + 1):
                    match = 0
                    for j in range(ene_len):
                        if digit_stream[ene_offset + j] == ene_digits[j]:
                            match += 1

                    if match == ene_len:  # EXACT match
                        # Now check BC at various offsets
                        bc_len = len(bc_digits)
                        for bc_offset in range(97 - bc_len + 1):
                            bc_match = 0
                            for j in range(bc_len):
                                if digit_stream[bc_offset + j] == bc_digits[j]:
                                    bc_match += 1

                            if bc_match == bc_len:
                                # Both cribs have exact digit matches!
                                score = ene_len + bc_len
                                if score > phase7_best:
                                    phase7_best = score

                                phase7_hits.append({
                                    'phase': 7,
                                    'outer_alpha': alpha_outer_name,
                                    'inner_alpha': alpha_inner_name,
                                    'escape_pair': (e1, e2),
                                    'ene_offset': ene_offset,
                                    'bc_offset': bc_offset,
                                    'ene_digit_len': ene_len,
                                    'bc_digit_len': bc_len,
                                    'total_match': score,
                                })
                                print(f"  EXACT HIT: {alpha_outer_name}+{alpha_inner_name} "
                                      f"esc=({e1},{e2}) ene@{ene_offset} bc@{bc_offset} "
                                      f"score={score}")

                                # Decode the full stream
                                decoded = decode_digit_stream(digit_stream, e1, e2, c2l)
                                if decoded:
                                    print(f"    Full decode ({len(decoded)} chars): {decoded}")

    print(f"\nPhase 7: {phase7_configs:,} configs tested")
    print(f"  Best exact match score: {phase7_best}")
    print(f"  Exact double-crib hits: {len(phase7_hits)}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 8: Null palette {B,G,I,K,O,W,Z} as escape indicators
    # These 7 letters indicate "next char is second digit of 2-digit code"
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 8: Palette letters as escape indicators")
    print("=" * 70)

    PALETTE = set("BGIKOWZ")
    palette_positions = [i for i, ch in enumerate(CT) if ch in PALETTE]
    print(f"Palette {PALETTE} positions in CT: {palette_positions}")
    print(f"Count: {len(palette_positions)}")

    # If palette letters are escape indicators, then at each palette position,
    # that letter + the next letter form a 2-digit code.
    # The remaining letters are 1-digit codes.
    # Total plaintext length = 97 - len(palette_positions) = 97 - N
    non_palette_count = 97 - len(palette_positions)
    print(f"If palette = escape indicators: PT length = {non_palette_count}")

    # More sophisticated: each palette letter starts a 2-char pair.
    # But palette letters can be adjacent — need careful parsing.
    phase8_configs = 0
    phase8_best = 0

    # For each keyed alphabet, use palette membership as the escape criterion
    # Parse: if CT[i] is in PALETTE, consume CT[i:i+2] as a 2-char code; else CT[i] as 1-char code
    # This is the letter-level model from e_vic_model.py but specifically with the palette

    for alpha_name, alpha in alphabets.items():
        phase8_configs += 1

        # Parse CT using palette as prefix set
        tokens = []
        i = 0
        while i < len(CT):
            if CT[i] in PALETTE and i + 1 < len(CT):
                tokens.append(CT[i:i+2])
                i += 2
            else:
                tokens.append(CT[i])
                i += 1

        pt_len = len(tokens)

        if 65 <= pt_len <= 80:
            # Check pattern matching for cribs
            # Use the repetition-pattern check from e_vic_model.py
            ene_check = False
            bc_check = False

            if pt_len >= 34:
                for p in range(pt_len - 12):
                    t = tokens
                    # ENE: E(0,9) A(1,10) S(2,11) T(3,7,12) unique groups=8
                    if (p + 12 < pt_len and
                        t[p] == t[p+9] and t[p+1] == t[p+10] and
                        t[p+2] == t[p+11] and t[p+3] == t[p+7] and
                        t[p+3] == t[p+12]):
                        vals = {t[p], t[p+1], t[p+2], t[p+3], t[p+4], t[p+5], t[p+6], t[p+8]}
                        if len(vals) == 8:
                            ene_check = True
                            print(f"  ENE pattern at token {p} ({alpha_name}), PT len={pt_len}")

            if pt_len >= 74:
                for q in range(pt_len - 10):
                    t = tokens
                    if (q + 10 < pt_len and
                        t[q+3] == t[q+7] and t[q+6] == t[q+9]):
                        vals = {t[q], t[q+1], t[q+2], t[q+3], t[q+4], t[q+5], t[q+6], t[q+8], t[q+10]}
                        if len(vals) == 9:
                            bc_check = True
                            print(f"  BC pattern at token {q} ({alpha_name}), PT len={pt_len}")

        if pt_len == 73:
            print(f"  *** EXACT 73 *** {alpha_name}: tokens={tokens[:10]}...")

    print(f"Phase 8: {phase8_configs} configs tested")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 9: Morse-derived checkerboard structure
    # Misspelling deltas [22, 6, 10, 5, 22] mod 10 = [2, 6, 0, 5, 2]
    # Could define escape columns or row assignments
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 9: Misspelling-derived checkerboard parameters")
    print("=" * 70)

    misspelling_deltas = [22, 6, 10, 5, 22]
    delta_mod10 = [d % 10 for d in misspelling_deltas]
    print(f"Misspelling deltas: {misspelling_deltas}")
    print(f"Deltas mod 10: {delta_mod10}")

    # Unique digits from deltas mod 10: {0, 2, 5, 6}
    unique_delta_digits = sorted(set(delta_mod10))
    print(f"Unique delta digits: {unique_delta_digits}")

    # Try pairs from these digits as escape digits
    phase9_configs = 0
    phase9_best = 0

    morse_escape_pairs = list(combinations(unique_delta_digits, 2))
    # Also try specific interpretations
    morse_escape_pairs.extend([(2, 6), (0, 5), (2, 5), (0, 6)])
    morse_escape_pairs = list(set(morse_escape_pairs))

    print(f"Morse-derived escape pairs: {morse_escape_pairs}")

    for alpha_name, alpha in alphabets.items():
        mapping = letter_to_digit_mapping(alpha)
        digits = ct_to_digits(CT, mapping)

        for e1, e2 in morse_escape_pairs:
            phase9_configs += 1
            l2c, c2l = build_checkerboard(alpha, e1, e2)
            decoded = decode_digit_stream(digits, e1, e2, c2l)
            if decoded is None:
                continue

            pt_len = len(decoded)
            fixed_score = check_cribs_at_positions(decoded) if 50 <= pt_len <= 90 else 0
            free_score, _, _ = check_cribs_free(decoded) if 50 <= pt_len <= 90 else (0, -1, -1)

            total = max(fixed_score, free_score)
            if total > phase9_best:
                phase9_best = total

            if pt_len == 73 or total >= 3:
                print(f"  {alpha_name} esc=({e1},{e2}) len={pt_len} "
                      f"fixed={fixed_score} free={free_score}")
                if pt_len == 73:
                    print(f"    *** LENGTH 73 *** {decoded}")

    print(f"Phase 9: {phase9_configs} configs, best score: {phase9_best}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 10: Exhaustive 26-to-10 mapping search (beyond mod-10)
    # Try all possible assignments of 26 letters to 10 digits where
    # each digit gets 2 or 3 letters (balanced partition)
    # This is astronomically large (~10^26), so we use constraint propagation
    # from cribs instead.
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 10: Crib-constrained digit assignment search")
    print("=" * 70)

    # Key insight: if we know the checkerboard layout, we know what digits
    # each crib letter maps to. The CT letters at those positions must map
    # to exactly those digits.

    # For each checkerboard layout (alphabet + escape pair):
    #   1. Encode ENE and BC through checkerboard -> digit sequences
    #   2. The digit sequence tells us what digits the CT positions must produce
    #   3. Check if any consistent 26-to-10 letter-to-digit mapping exists
    #   4. If the mapping is consistent so far, extend to remaining positions

    phase10_configs = 0
    phase10_hits = []

    for alpha_name, alpha in alphabets.items():
        for e1, e2 in escape_pairs:
            phase10_configs += 1
            l2c, c2l = build_checkerboard(alpha, e1, e2)

            # Encode cribs
            ene_digits = encode_text(CRIB_ENE, l2c)
            bc_digits = encode_text(CRIB_BC, l2c)
            if ene_digits is None or bc_digits is None:
                continue

            ene_total_digits = len(ene_digits)  # number of digits ENE encodes to
            bc_total_digits = len(bc_digits)

            # For cribs at PT positions 21 and 63, the digit offset depends on
            # how many 2-digit letters precede them. We scan offsets.
            # But we can constrain: total digits before ENE (PT pos 21) = 21 + k
            # where k = number of 2-digit letters among PT[0:21]. k in [0,21].
            # Similarly for BC at PT pos 63.

            for k_before_ene in range(22):  # 0 to 21 two-digit letters before ENE
                ene_digit_start = 21 + k_before_ene
                ene_digit_end = ene_digit_start + ene_total_digits

                if ene_digit_end > 97:
                    break

                # Build required letter-to-digit constraints from ENE
                constraints = {}  # letter -> required digit
                consistent = True
                for j in range(ene_total_digits):
                    ct_pos = ene_digit_start + j
                    ct_letter = CT[ct_pos]
                    required_digit = ene_digits[j]

                    if ct_letter in constraints:
                        if constraints[ct_letter] != required_digit:
                            consistent = False
                            break
                    else:
                        constraints[ct_letter] = required_digit

                if not consistent:
                    continue

                # Now check BC at various offsets
                # Between ENE end (PT pos 34) and BC start (PT pos 63),
                # there are 29 PT chars. Digit span = 29 + k2 where k2 in [0,29].
                for k_between in range(30):
                    bc_digit_start = ene_digit_end + (63 - 34) + k_between - k_before_ene
                    # Actually, more precisely:
                    # PT positions 0..20 use (21 + k_before_ene) digits
                    # PT positions 21..33 (ENE) use ene_total_digits digits
                    # PT positions 34..62 use (29 + k_middle) digits where k_middle in [0,29]
                    # So BC starts at digit: (21 + k_before_ene) + ene_total_digits + (29 + k_middle)
                    bc_digit_start = (21 + k_before_ene) + ene_total_digits + (29 + k_between)
                    bc_digit_end = bc_digit_start + bc_total_digits

                    if bc_digit_end > 97:
                        break
                    if bc_digit_start <= ene_digit_end:
                        continue

                    # Check BC constraints
                    bc_constraints = dict(constraints)
                    bc_consistent = True
                    for j in range(bc_total_digits):
                        ct_pos = bc_digit_start + j
                        ct_letter = CT[ct_pos]
                        required_digit = bc_digits[j]

                        if ct_letter in bc_constraints:
                            if bc_constraints[ct_letter] != required_digit:
                                bc_consistent = False
                                break
                        else:
                            bc_constraints[ct_letter] = required_digit

                    if bc_consistent:
                        # Check that no digit is assigned to too many letters
                        # (max 3 letters per digit for 26/10)
                        digit_counts = Counter(bc_constraints.values())
                        if max(digit_counts.values()) <= 4:
                            # Also check total digit budget
                            # PT positions after BC: 73 - 74 = -1... wait,
                            # BC is at pos 63-73 (11 chars), last PT pos = 72
                            # Remaining after BC: 73 - 73 = 0 (BC ends at 73)
                            # Total digits used: bc_digit_end
                            # Remaining digits: 97 - bc_digit_end
                            # Remaining PT: 0 chars after BC (if BC ends at PT 73)
                            # Wait, crib positions: ENE at 21-33 (13 chars), BC at 63-73 (11 chars)
                            # BC ends at PT position 73 (exclusive), so last BC char at PT pos 72
                            # Remaining PT: positions 73 (but we only have 73 chars: 0-72!)
                            # So BC actually ends at position 73 = end of PT.
                            # Remaining digits after BC = 97 - bc_digit_end should be 0.

                            remaining = 97 - bc_digit_end
                            if remaining == 0:
                                # PERFECT: all 97 digits accounted for
                                n_constrained = len(bc_constraints)
                                phase10_hits.append({
                                    'phase': 10,
                                    'alpha': alpha_name,
                                    'escape_pair': (e1, e2),
                                    'k_before_ene': k_before_ene,
                                    'k_between': k_between,
                                    'ene_digit_start': ene_digit_start,
                                    'bc_digit_start': bc_digit_start,
                                    'constraints': {k: v for k, v in bc_constraints.items()},
                                    'n_constrained': n_constrained,
                                })
                                if len(phase10_hits) <= 10:
                                    print(f"  HIT: {alpha_name} esc=({e1},{e2}) "
                                          f"k_pre={k_before_ene} k_mid={k_between} "
                                          f"ENE@dig{ene_digit_start} BC@dig{bc_digit_start} "
                                          f"constrained={n_constrained}/26")

    print(f"\nPhase 10: {phase10_configs:,} configs x offset combos")
    print(f"  Exact-budget hits (remaining=0): {len(phase10_hits)}")
    if phase10_hits:
        # Show the best (most constrained)
        best_hit = max(phase10_hits, key=lambda h: h['n_constrained'])
        print(f"  Best constrained: {best_hit['n_constrained']}/26 letters assigned")
        print(f"    Alpha: {best_hit['alpha']}, Escape: {best_hit['escape_pair']}")
        print(f"    Constraints: {best_hit['constraints']}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 11: Comprehensive statistics
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 11: Decode length distribution")
    print("=" * 70)

    # For each alphabet x escape pair, what length do we get?
    len_counts = Counter()
    len_73_configs = []

    for alpha_name, alpha in alphabets.items():
        mapping = letter_to_digit_mapping(alpha)
        digits = ct_to_digits(CT, mapping)

        for e1, e2 in escape_pairs:
            l2c, c2l = build_checkerboard(alpha, e1, e2)
            decoded = decode_digit_stream(digits, e1, e2, c2l)
            if decoded is not None:
                pl = len(decoded)
                len_counts[pl] += 1
                if pl == 73:
                    len_73_configs.append((alpha_name, e1, e2))

    print("Decoded length distribution (top 20):")
    for length, count in len_counts.most_common(20):
        marker = " *** TARGET ***" if length == 73 else ""
        print(f"  Length {length}: {count} configs{marker}")

    if len_73_configs:
        print(f"\nConfigs producing exactly 73 chars ({len(len_73_configs)}):")
        for name, e1, e2 in len_73_configs[:20]:
            print(f"  {name} esc=({e1},{e2})")

    # ══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    total_configs = (phase2_configs + phase3_configs + phase4_configs +
                     phase6_configs + phase7_configs + phase8_configs +
                     phase9_configs + phase10_configs)

    print(f"Total configs tested: {total_configs:,}")
    print(f"Total elapsed: {elapsed:.1f}s")
    print()
    print(f"Phase 2 (direct decode, cross-alphabet): "
          f"{phase2_configs:,} configs, best fixed={best_fixed}, best free={best_free}")
    print(f"Phase 3 (same-alphabet): "
          f"{phase3_configs} configs, best fixed={phase3_best_fixed}, best free={phase3_best_free}")
    print(f"Phase 4 (crib digit matching): "
          f"{phase4_configs:,} configs, best={phase4_best}")
    print(f"Phase 6 (two-layer digit sub): "
          f"{phase6_configs:,} configs, best fixed={phase6_best_fixed}, best free={phase6_best_free}")
    print(f"Phase 7 (exact reverse crib): "
          f"{phase7_configs:,} configs, exact hits={len(phase7_hits)}")
    print(f"Phase 8 (palette as escape): {phase8_configs} configs")
    print(f"Phase 9 (morse-derived): {phase9_configs} configs, best={phase9_best}")
    print(f"Phase 10 (crib-constrained assignment): hits={len(phase10_hits)}")
    print(f"Phase 11 (length distribution): 73-char configs={len(len_73_configs)}")

    all_hits = phase2_hits + phase4_hits + phase6_hits + phase7_hits + phase10_hits

    # Determine verdict
    if any(h.get('fixed_score', 0) >= 18 or h.get('free_score', 0) >= 18 for h in all_hits):
        verdict = "SIGNAL"
    elif any(h.get('fixed_score', 0) >= 10 or h.get('free_score', 0) >= 10 for h in all_hits):
        verdict = "INTERESTING"
    elif len(all_hits) > 0:
        verdict = "WEAK_HITS"
    else:
        verdict = "NOISE"

    print(f"\nVerdict: {verdict}")

    # Save results
    output = {
        'experiment': 'e_straddling_checkerboard_k4',
        'description': 'Straddling checkerboard digit-level attack on K4',
        'model': 'CT(97 letters) -> digit mapping -> 97 digits -> checkerboard decode -> PT(~73)',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'elapsed_seconds': elapsed,
        'phases': {
            'phase2_direct_decode': {
                'configs': phase2_configs,
                'best_fixed': best_fixed,
                'best_free': best_free,
                'hits': len(phase2_hits),
            },
            'phase3_same_alpha': {
                'configs': phase3_configs,
                'best_fixed': phase3_best_fixed,
                'best_free': phase3_best_free,
            },
            'phase4_crib_digit_match': {
                'configs': phase4_configs,
                'best_score': phase4_best,
                'hits': len(phase4_hits),
            },
            'phase6_two_layer': {
                'configs': phase6_configs,
                'best_fixed': phase6_best_fixed,
                'best_free': phase6_best_free,
                'hits': len(phase6_hits),
            },
            'phase7_exact_reverse_crib': {
                'configs': phase7_configs,
                'exact_hits': len(phase7_hits),
                'best': phase7_best,
            },
            'phase8_palette_escape': {
                'configs': phase8_configs,
            },
            'phase9_morse_derived': {
                'configs': phase9_configs,
                'best': phase9_best,
            },
            'phase10_crib_constrained': {
                'hits': len(phase10_hits),
                'details': phase10_hits[:20],
            },
            'phase11_length_dist': {
                'len_73_count': len(len_73_configs),
                'len_73_configs': len_73_configs[:20],
                'top_lengths': len_counts.most_common(10),
            },
        },
        'expansion_ratio_analysis': {
            'target_ratio': target_ratio,
            'viable_layouts': len(viable_layouts),
            'samples': [(n, e1, e2, f"{r:.4f}") for n, e1, e2, r in viable_layouts[:10]],
        },
        'all_hits': all_hits[:50],
        'verdict': verdict,
    }

    results_path = Path(__file__).resolve().parents[2] / "results" / "straddling_checkerboard_k4.json"
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with open(results_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)

    print(f"\nResults saved to: {results_path}")
    return output


if __name__ == "__main__":
    run()
