#!/usr/bin/env python3
"""
K2 Coordinates as Straddling Checkerboard Configuration Data.

Cipher:  Straddling Checkerboard (K2-derived configuration)
Family:  analysis
Status:  active
Keyspace: ~50K+ configs (row label pairs x header perms x keywords x digit mappings x additive keys)
Last run: never
Best score: N/A

HYPOTHESIS: K2 plaintext numbers are NOT geographic coordinates but
straddling checkerboard configuration data:
  38 -> row labels (3, 8)
  digits 3,8,5,7,6,5,7,7,8,4,4 -> header permutation
  KRYPTOS fills the 8 non-blank top-row positions

Construction 1 (User's primary):
     0    1    2    3    4    5    6    7    8    9
     K    R    Y   [3]   P    T    O    S   [8]   A
3:   B    C    D    E    F    G    H    I    J    L
8:   M    N    Q    U    V    W    X    Z    .    /

Single-digit: 0->K, 1->R, 2->Y, 4->P, 5->T, 6->O, 7->S, 9->A
Double-digit: 30->B, 31->C, ..., 39->L, 80->M, 81->N, ..., 87->Z

Step 1: Convert CT97 letters to digits via alphabet position mod 10
Step 2: Parse digit stream through checkerboard
Step 3: Check if output is ~73 chars with crib matches
"""

import sys
import json
import time
from pathlib import Path
from itertools import combinations, permutations
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, KRYPTOS_ALPHABET, CRIB_WORDS

# ── Constants ────────────────────────────────────────────────────────────────
AZ = ALPH  # ABCDEFGHIJKLMNOPQRSTUVWXYZ
KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"

# K2 plaintext numbers
# THIRTY EIGHT = 38, FIFTY SEVEN = 57, SIX POINT FIVE = 6.5,
# SEVENTY SEVEN = 77, EIGHT = 8, FORTY FOUR = 44
K2_DIGITS_IN_ORDER = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
K2_UNIQUE_IN_ORDER = []  # unique digits preserving first-seen order
_seen = set()
for d in K2_DIGITS_IN_ORDER:
    if d not in _seen:
        K2_UNIQUE_IN_ORDER.append(d)
        _seen.add(d)
# Result: [3, 8, 5, 7, 6, 4]
K2_REMAINING = [d for d in range(10) if d not in _seen]
# Result: [0, 1, 2, 9]

# Thematic keywords
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
    "BERLINCLOCK", "EASTNORTHEAST", "SHADOW", "ENIGMA", "CIPHER",
    "SANBORN", "SCHEIDT", "COLOPHON", "PARALLAX",
    "TOWER", "CHART", "LAYER", "FIVE", "CLOCK", "NORTH",
    "MEDUSA", "KRYPTEIA",
]


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


def build_checkerboard_from_header(header, row_labels, fill_alphabet):
    """Build a straddling checkerboard from explicit header, row labels, and fill alphabet.

    header: list of 10 digits (permutation of 0-9) defining column order
    row_labels: tuple of 2 digits (the escape/row digits)
    fill_alphabet: 26-char string (keyword mixed alphabet for grid fill)

    Grid layout:
      header:  h0  h1  h2  h3  h4  h5  h6  h7  h8  h9
      top row: letters at non-row-label columns (8 letters, single-digit codes)
      row R1:  10 letters (2-digit codes: R1 + column_header_digit)
      row R2:  8 letters at non-row-label columns (2-digit codes: R2 + column_header_digit)

    Returns: (letter_to_code, code_to_letter) dicts
    """
    r1, r2 = row_labels

    # Find which column positions have row labels
    # Row label columns are where header[col] == r1 or header[col] == r2
    non_escape_cols = [i for i in range(10) if header[i] != r1 and header[i] != r2]

    letter_to_code = {}
    code_to_letter = {}
    idx = 0

    # Top row: 8 letters at non-escape columns, single-digit codes
    for col in non_escape_cols:
        if idx < len(fill_alphabet):
            digit = header[col]
            letter_to_code[fill_alphabet[idx]] = (digit,)
            code_to_letter[(digit,)] = fill_alphabet[idx]
            idx += 1

    # Row r1: 10 letters, 2-digit codes (r1, header[col]) for all 10 columns
    for col in range(10):
        if idx < len(fill_alphabet):
            digit = header[col]
            letter_to_code[fill_alphabet[idx]] = (r1, digit)
            code_to_letter[(r1, digit)] = fill_alphabet[idx]
            idx += 1

    # Row r2: 8 letters at non-escape columns, 2-digit codes
    for col in non_escape_cols:
        if idx < len(fill_alphabet):
            digit = header[col]
            letter_to_code[fill_alphabet[idx]] = (r2, digit)
            code_to_letter[(r2, digit)] = fill_alphabet[idx]
            idx += 1

    return letter_to_code, code_to_letter


def decode_digits(digits, row_labels, code_to_letter):
    """Parse a digit stream using straddling checkerboard.
    Returns decoded string or None if parsing fails."""
    r1, r2 = row_labels
    result = []
    i = 0
    while i < len(digits):
        d = digits[i]
        if d == r1 or d == r2:
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


def check_cribs_fixed(decoded, ene_pos=21, bc_pos=63):
    """Check cribs at expected 73-char positions."""
    if decoded is None:
        return 0, 0, 0
    n = len(decoded)
    ene_score = 0
    bc_score = 0
    if ene_pos + 13 <= n:
        for i, ch in enumerate(CRIB_ENE):
            if decoded[ene_pos + i] == ch:
                ene_score += 1
    if bc_pos + 11 <= n:
        for i, ch in enumerate(CRIB_BC):
            if decoded[bc_pos + i] == ch:
                bc_score += 1
    return ene_score + bc_score, ene_score, bc_score


def check_cribs_free(decoded):
    """Search for cribs at any position."""
    if decoded is None or len(decoded) < 11:
        return 0, -1, -1
    best = 0
    best_ep = -1
    best_bp = -1
    n = len(decoded)
    for p in range(max(0, n - 12)):
        s = sum(1 for i, ch in enumerate(CRIB_ENE) if p + i < n and decoded[p + i] == ch)
        if s >= 3:
            for q in range(max(0, n - 10)):
                s2 = sum(1 for i, ch in enumerate(CRIB_BC) if q + i < n and decoded[q + i] == ch)
                total = s + s2
                if total > best:
                    best = total
                    best_ep = p
                    best_bp = q
    return best, best_ep, best_bp


def letter_to_digit_ka(letter):
    """KA positions mod 10."""
    return KA.index(letter) % 10


def letter_to_digit_az(letter):
    """AZ positions mod 10."""
    return AZ.index(letter) % 10


def ct_to_digits(ct, mapping_fn):
    """Convert CT to digit stream using a letter->digit function."""
    return [mapping_fn(ch) for ch in ct]


def run():
    t0 = time.time()
    all_results = []
    global_best_fixed = 0
    global_best_free = 0
    total_configs = 0
    total_len73 = 0

    print("=" * 70)
    print("K2 COORDINATES AS STRADDLING CHECKERBOARD CONFIGURATION")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"K2 digits in order: {K2_DIGITS_IN_ORDER}")
    print(f"K2 unique in order: {K2_UNIQUE_IN_ORDER}")
    print(f"Remaining digits: {K2_REMAINING}")
    print()

    # ══════════════════════════════════════════════════════════════════════
    # Define all row label pairs to test
    # ══════════════════════════════════════════════════════════════════════
    ROW_LABEL_PAIRS = [
        (3, 8),  # from "thirty eight" -- PRIMARY
        (5, 7),  # from "fifty seven"
        (7, 8),  # from "seventy seven, eight"
        (3, 5),  # first digits of 38, 57
        (8, 7),  # second digits of 38, 57
        (6, 5),  # from "six point five" -- BUT these are same pair as (5,6)
    ]
    # Also add all 45 pairs for completeness
    ALL_PAIRS = list(combinations(range(10), 2))

    # ══════════════════════════════════════════════════════════════════════
    # Define header permutations to test
    # ══════════════════════════════════════════════════════════════════════
    HEADERS = {}

    # Primary: K2 unique digits in order, then remaining in order
    HEADERS["k2_unique_then_remaining"] = K2_UNIQUE_IN_ORDER + sorted(K2_REMAINING)
    # = [3, 8, 5, 7, 6, 4, 0, 1, 2, 9]

    # Variation: unique then remaining reversed
    HEADERS["k2_unique_then_rem_rev"] = K2_UNIQUE_IN_ORDER + sorted(K2_REMAINING, reverse=True)

    # Standard ascending
    HEADERS["standard_0_9"] = list(range(10))

    # Reversed
    HEADERS["reversed_9_0"] = list(range(9, -1, -1))

    # K2 digits as positions (header[i] = K2_UNIQUE_IN_ORDER[i] for i<6, rest fill)
    # This IS the primary header already

    # All K2 digits with repeats truncated to first 10
    k2_all = K2_DIGITS_IN_ORDER[:10]
    # But has repeats, so not a valid permutation. Make it valid by deduplication:
    k2_dedup = []
    k2_seen = set()
    for d in K2_DIGITS_IN_ORDER:
        if d not in k2_seen:
            k2_dedup.append(d)
            k2_seen.add(d)
    for d in range(10):
        if d not in k2_seen:
            k2_dedup.append(d)
            k2_seen.add(d)
    HEADERS["k2_all_dedup"] = k2_dedup  # same as primary

    # From K2 numbers directly: 38, 57, 65, 77, 8, 44
    # Digits: 3,8,5,7,6,5,7,7,8,4,4 -- use mod arithmetic to create header
    # Each number mod 10: 8, 7, 5, 7, 8, 4 -> not unique either
    # Just use various orderings of the 6 unique K2 digits
    for perm in permutations(K2_UNIQUE_IN_ORDER):
        name = f"k2perm_{''.join(str(d) for d in perm)}"
        HEADERS[name] = list(perm) + sorted(K2_REMAINING)

    # KRYPTOS as digit positions: K=10,R=17,Y=24,P=15,T=19,O=14,S=18
    # mod 10: 0,7,4,5,9,4,8 -- has collision at 4. Not a valid header basis.

    # From KRYPTOS in KA: K=0,R=1,Y=2,P=3,T=4,O=5,S=6 -> first 7 digits
    HEADERS["ka_first7"] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]  # same as standard

    print(f"Header permutations: {len(HEADERS)} (including {len(list(permutations(K2_UNIQUE_IN_ORDER)))} K2 permutations)")

    # ══════════════════════════════════════════════════════════════════════
    # Define letter-to-digit mappings
    # ══════════════════════════════════════════════════════════════════════
    DIGIT_MAPPINGS = {
        "KA_mod10": letter_to_digit_ka,
        "AZ_mod10": letter_to_digit_az,
    }

    # Also build keyed alphabet mappings
    for kw in KEYWORDS:
        alpha = keyword_mixed_alphabet(kw, AZ)
        name = f"kw_{kw}_AZ_mod10"
        mapping = {ch: i % 10 for i, ch in enumerate(alpha)}
        DIGIT_MAPPINGS[name] = lambda ch, m=mapping: m[ch]

        alpha_ka = keyword_mixed_alphabet(kw, KA)
        name_ka = f"kw_{kw}_KA_mod10"
        mapping_ka = {ch: i % 10 for i, ch in enumerate(alpha_ka)}
        DIGIT_MAPPINGS[name_ka] = lambda ch, m=mapping_ka: m[ch]

    print(f"Digit mappings: {len(DIGIT_MAPPINGS)}")

    # ══════════════════════════════════════════════════════════════════════
    # Define fill alphabets for the checkerboard grid
    # ══════════════════════════════════════════════════════════════════════
    FILL_ALPHABETS = {"AZ": AZ, "KA": KA}
    for kw in KEYWORDS:
        fa = keyword_mixed_alphabet(kw, AZ)
        FILL_ALPHABETS[f"kw_{kw}_AZ"] = fa
        fa_ka = keyword_mixed_alphabet(kw, KA)
        FILL_ALPHABETS[f"kw_{kw}_KA"] = fa_ka

    print(f"Fill alphabets: {len(FILL_ALPHABETS)}")
    print()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1: User's Primary Construction
    # Row labels (3,8), header [3,8,5,7,6,4,0,1,2,9], fill=KRYPTOS+AZ
    # ══════════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PHASE 1: User's Primary Construction")
    print("  Row labels: (3, 8)")
    print(f"  Header: {HEADERS['k2_unique_then_remaining']}")
    print("  Fill: KRYPTOS keyword alphabet (AZ base)")
    print("=" * 70)

    header = HEADERS["k2_unique_then_remaining"]
    row_labels = (3, 8)
    fill = keyword_mixed_alphabet("KRYPTOS", AZ)

    l2c, c2l = build_checkerboard_from_header(header, row_labels, fill)

    print(f"\nCheckerboard layout:")
    print(f"  Header: {' '.join(str(h) for h in header)}")
    print(f"  Row 0 (single-digit):")
    for col in range(10):
        if header[col] not in row_labels:
            code = (header[col],)
            if code in c2l:
                print(f"    col {col} (digit {header[col]}): {c2l[code]}")
    print(f"  Row {row_labels[0]} (double-digit):")
    for col in range(10):
        code = (row_labels[0], header[col])
        if code in c2l:
            print(f"    col {col} (code {row_labels[0]}{header[col]}): {c2l[code]}")
    print(f"  Row {row_labels[1]} (double-digit):")
    for col in range(10):
        code = (row_labels[1], header[col])
        if code in c2l:
            print(f"    col {col} (code {row_labels[1]}{header[col]}): {c2l[code]}")

    # Test with both KA and AZ digit mappings
    for map_name, map_fn in [("KA_mod10", letter_to_digit_ka), ("AZ_mod10", letter_to_digit_az)]:
        digits = ct_to_digits(CT, map_fn)
        print(f"\n  Digit stream ({map_name}): {''.join(str(d) for d in digits[:50])}...")

        decoded = decode_digits(digits, row_labels, c2l)
        if decoded is not None:
            pt_len = len(decoded)
            fixed, ene_s, bc_s = check_cribs_fixed(decoded)
            free, free_ep, free_bp = check_cribs_free(decoded)
            print(f"  Decoded ({map_name}): len={pt_len}, fixed={fixed}/24 (ene={ene_s}, bc={bc_s}), free={free}/24")
            print(f"  PT: {decoded}")
            if pt_len == 73:
                print(f"  *** EXACTLY 73 CHARACTERS ***")
                total_len73 += 1
            if fixed > global_best_fixed:
                global_best_fixed = fixed
            if free > global_best_free:
                global_best_free = free
        else:
            print(f"  Decoded ({map_name}): PARSE FAILURE")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2: Systematic sweep - K2-derived row labels x headers x fills x mappings
    # Focus on the 6 specific K2-derived row label pairs
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 2: Systematic K2-derived configurations")
    print(f"  Row label pairs: {ROW_LABEL_PAIRS}")
    print(f"  Headers: {len(HEADERS)}")
    print(f"  Fill alphabets: {len(FILL_ALPHABETS)}")
    print(f"  Digit mappings: {len(DIGIT_MAPPINGS)}")
    print("=" * 70)

    phase2_configs = 0
    phase2_best_fixed = 0
    phase2_best_free = 0
    phase2_len73 = 0
    phase2_hits = []

    # Limit headers for the systematic sweep to avoid combinatorial explosion
    # Use the primary + a few important variations + all K2 permutations
    sweep_headers = {k: v for k, v in HEADERS.items()}
    # Use top fill alphabets
    sweep_fills = {k: v for k, v in FILL_ALPHABETS.items()}
    # Use all digit mappings
    sweep_mappings = DIGIT_MAPPINGS

    for rl in ROW_LABEL_PAIRS:
        for hdr_name, hdr in sweep_headers.items():
            for fill_name, fill_alpha in sweep_fills.items():
                l2c, c2l = build_checkerboard_from_header(hdr, rl, fill_alpha)

                for map_name, map_fn in sweep_mappings.items():
                    phase2_configs += 1
                    total_configs += 1

                    digits = ct_to_digits(CT, map_fn)
                    decoded = decode_digits(digits, rl, c2l)
                    if decoded is None:
                        continue

                    pt_len = len(decoded)
                    if pt_len < 50 or pt_len > 90:
                        continue

                    fixed, ene_s, bc_s = check_cribs_fixed(decoded)
                    free, free_ep, free_bp = check_cribs_free(decoded)

                    if pt_len == 73:
                        phase2_len73 += 1
                        total_len73 += 1

                    if fixed > phase2_best_fixed:
                        phase2_best_fixed = fixed
                    if free > phase2_best_free:
                        phase2_best_free = free
                    if fixed > global_best_fixed:
                        global_best_fixed = fixed
                    if free > global_best_free:
                        global_best_free = free

                    if fixed >= 5 or free >= 7 or pt_len == 73:
                        hit = {
                            'phase': 2,
                            'row_labels': rl,
                            'header': hdr_name,
                            'fill': fill_name,
                            'digit_map': map_name,
                            'pt_len': pt_len,
                            'fixed': fixed,
                            'ene_score': ene_s,
                            'bc_score': bc_s,
                            'free': free,
                            'free_ene_pos': free_ep,
                            'free_bc_pos': free_bp,
                            'decoded': decoded[:80],
                        }
                        phase2_hits.append(hit)
                        if pt_len == 73 or fixed >= 5 or free >= 8:
                            print(f"  HIT: rl={rl} hdr={hdr_name} fill={fill_name} "
                                  f"map={map_name} len={pt_len} fixed={fixed} free={free}")
                            if pt_len == 73:
                                print(f"    *** LEN 73 *** {decoded}")

    print(f"\nPhase 2: {phase2_configs:,} configs")
    print(f"  Best fixed: {phase2_best_fixed}/24, Best free: {phase2_best_free}/24")
    print(f"  Length-73 hits: {phase2_len73}")
    print(f"  Notable hits (fixed>=5 or free>=7 or len=73): {len(phase2_hits)}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 3: All 45 row label pairs x primary header x top fills x top mappings
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 3: All 45 row label pairs with primary header")
    print("=" * 70)

    phase3_configs = 0
    phase3_best_fixed = 0
    phase3_best_free = 0
    phase3_len73 = 0

    primary_header = HEADERS["k2_unique_then_remaining"]
    top_fills = ["AZ", "KA", "kw_KRYPTOS_AZ", "kw_KRYPTOS_KA",
                 "kw_DEFECTOR_AZ", "kw_PALIMPSEST_AZ", "kw_ABSCISSA_AZ",
                 "kw_KOMPASS_AZ", "kw_BERLINCLOCK_AZ"]
    top_maps = ["KA_mod10", "AZ_mod10", "kw_KRYPTOS_AZ_mod10", "kw_KRYPTOS_KA_mod10",
                "kw_DEFECTOR_AZ_mod10", "kw_PALIMPSEST_AZ_mod10"]

    for rl in ALL_PAIRS:
        for fill_name in top_fills:
            if fill_name not in FILL_ALPHABETS:
                continue
            fill_alpha = FILL_ALPHABETS[fill_name]
            l2c, c2l = build_checkerboard_from_header(primary_header, rl, fill_alpha)

            for map_name in top_maps:
                if map_name not in DIGIT_MAPPINGS:
                    continue
                map_fn = DIGIT_MAPPINGS[map_name]
                phase3_configs += 1
                total_configs += 1

                digits = ct_to_digits(CT, map_fn)
                decoded = decode_digits(digits, rl, c2l)
                if decoded is None:
                    continue

                pt_len = len(decoded)
                if pt_len < 50 or pt_len > 90:
                    continue

                fixed, ene_s, bc_s = check_cribs_fixed(decoded)
                free, free_ep, free_bp = check_cribs_free(decoded)

                if pt_len == 73:
                    phase3_len73 += 1
                    total_len73 += 1

                if fixed > phase3_best_fixed:
                    phase3_best_fixed = fixed
                if free > phase3_best_free:
                    phase3_best_free = free
                if fixed > global_best_fixed:
                    global_best_fixed = fixed
                if free > global_best_free:
                    global_best_free = free

                if fixed >= 5 or free >= 7 or pt_len == 73:
                    print(f"  rl={rl} fill={fill_name} map={map_name} "
                          f"len={pt_len} fixed={fixed} free={free}")

    print(f"\nPhase 3: {phase3_configs:,} configs")
    print(f"  Best fixed: {phase3_best_fixed}/24, Best free: {phase3_best_free}/24")
    print(f"  Length-73 hits: {phase3_len73}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 4: VIC-style mod-10 additive before checkerboard decode
    # Subtract constant or repeating key from digit stream before parsing
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 4: Mod-10 additive key before checkerboard decode")
    print("=" * 70)

    phase4_configs = 0
    phase4_best_fixed = 0
    phase4_best_free = 0
    phase4_len73 = 0
    phase4_hits = []

    # Key sources for VIC-style additive
    additive_keys = {}

    # Constant additives (0-9)
    for shift in range(10):
        additive_keys[f"const_{shift}"] = [shift] * 97

    # KRYPTOS as mod-10 repeating key
    kryptos_digits_ka = [KA.index(ch) % 10 for ch in "KRYPTOS"]
    kryptos_key = (kryptos_digits_ka * 14)[:97]
    additive_keys["KRYPTOS_KA_rep"] = kryptos_key

    kryptos_digits_az = [AZ.index(ch) % 10 for ch in "KRYPTOS"]
    kryptos_key_az = (kryptos_digits_az * 14)[:97]
    additive_keys["KRYPTOS_AZ_rep"] = kryptos_key_az

    # K2 digits as repeating key
    k2_key = (K2_DIGITS_IN_ORDER * 9)[:97]
    additive_keys["K2_digits_rep"] = k2_key

    # K2 unique digits as repeating key
    k2u_key = (K2_UNIQUE_IN_ORDER * 17)[:97]
    additive_keys["K2_unique_rep"] = k2u_key

    # Chain addition from K2 digits (VIC-style)
    chain = list(K2_DIGITS_IN_ORDER)
    while len(chain) < 97:
        chain.append((chain[-len(K2_DIGITS_IN_ORDER)] + chain[-len(K2_DIGITS_IN_ORDER) + 1]) % 10)
    additive_keys["K2_chain_add"] = chain[:97]

    # Fibonacci-like chain from first two K2 digits
    fib_chain = [3, 8]
    while len(fib_chain) < 97:
        fib_chain.append((fib_chain[-1] + fib_chain[-2]) % 10)
    additive_keys["fib_38"] = fib_chain[:97]

    # Fibonacci from 5, 7
    fib57 = [5, 7]
    while len(fib57) < 97:
        fib57.append((fib57[-1] + fib57[-2]) % 10)
    additive_keys["fib_57"] = fib57[:97]

    print(f"Additive keys: {len(additive_keys)}")

    # Test with primary construction + additive keys
    for rl in ROW_LABEL_PAIRS:
        for hdr_name in ["k2_unique_then_remaining", "standard_0_9"]:
            hdr = HEADERS[hdr_name]
            for fill_name in ["kw_KRYPTOS_AZ", "kw_KRYPTOS_KA", "AZ", "KA",
                              "kw_DEFECTOR_AZ", "kw_PALIMPSEST_AZ"]:
                if fill_name not in FILL_ALPHABETS:
                    continue
                fill_alpha = FILL_ALPHABETS[fill_name]
                l2c, c2l = build_checkerboard_from_header(hdr, rl, fill_alpha)

                for map_name in ["KA_mod10", "AZ_mod10", "kw_KRYPTOS_AZ_mod10"]:
                    if map_name not in DIGIT_MAPPINGS:
                        continue
                    map_fn = DIGIT_MAPPINGS[map_name]
                    base_digits = ct_to_digits(CT, map_fn)

                    for add_name, add_key in additive_keys.items():
                        phase4_configs += 1
                        total_configs += 1

                        # Subtract additive key mod 10
                        digits = [(base_digits[i] - add_key[i]) % 10 for i in range(97)]

                        decoded = decode_digits(digits, rl, c2l)
                        if decoded is None:
                            continue

                        pt_len = len(decoded)
                        if pt_len < 50 or pt_len > 90:
                            continue

                        fixed, ene_s, bc_s = check_cribs_fixed(decoded)
                        free, free_ep, free_bp = check_cribs_free(decoded)

                        if pt_len == 73:
                            phase4_len73 += 1
                            total_len73 += 1

                        if fixed > phase4_best_fixed:
                            phase4_best_fixed = fixed
                        if free > phase4_best_free:
                            phase4_best_free = free
                        if fixed > global_best_fixed:
                            global_best_fixed = fixed
                        if free > global_best_free:
                            global_best_free = free

                        if fixed >= 5 or free >= 7 or pt_len == 73:
                            hit = {
                                'phase': 4,
                                'row_labels': rl,
                                'header': hdr_name,
                                'fill': fill_name,
                                'digit_map': map_name,
                                'additive': add_name,
                                'pt_len': pt_len,
                                'fixed': fixed,
                                'free': free,
                                'decoded': decoded[:80],
                            }
                            phase4_hits.append(hit)
                            print(f"  HIT: rl={rl} hdr={hdr_name} fill={fill_name} "
                                  f"map={map_name} add={add_name} len={pt_len} "
                                  f"fixed={fixed} free={free}")

                        # Also try adding (instead of subtracting)
                        phase4_configs += 1
                        total_configs += 1
                        digits_add = [(base_digits[i] + add_key[i]) % 10 for i in range(97)]
                        decoded_add = decode_digits(digits_add, rl, c2l)
                        if decoded_add is None:
                            continue
                        pt_len_a = len(decoded_add)
                        if pt_len_a < 50 or pt_len_a > 90:
                            continue
                        fixed_a, _, _ = check_cribs_fixed(decoded_add)
                        free_a, _, _ = check_cribs_free(decoded_add)
                        if pt_len_a == 73:
                            phase4_len73 += 1
                            total_len73 += 1
                        if fixed_a > phase4_best_fixed:
                            phase4_best_fixed = fixed_a
                        if free_a > phase4_best_free:
                            phase4_best_free = free_a
                        if fixed_a > global_best_fixed:
                            global_best_fixed = fixed_a
                        if free_a > global_best_free:
                            global_best_free = free_a
                        if fixed_a >= 5 or free_a >= 7 or pt_len_a == 73:
                            print(f"  HIT(+): rl={rl} hdr={hdr_name} fill={fill_name} "
                                  f"map={map_name} add={add_name} len={pt_len_a} "
                                  f"fixed={fixed_a} free={free_a}")

    print(f"\nPhase 4: {phase4_configs:,} configs")
    print(f"  Best fixed: {phase4_best_fixed}/24, Best free: {phase4_best_free}/24")
    print(f"  Length-73 hits: {phase4_len73}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 5: REVERSE direction - CT letters ARE the checkerboard output
    # Each CT letter -> look up in checkerboard -> 1 or 2 digit code
    # The digit stream should represent something (the underlying cipher)
    # If exactly 73 of 97 are single-digit and 24 are double-digit,
    # total digits = 73 + 48 = 121. Hmm, not obvious what to expect.
    # Actually user's model: PT(73) -> checkerboard -> digits(97) -> letter mapping -> CT(97)
    # So DECODE: CT(97) -> digit mapping -> digits(97) -> checkerboard parse -> PT(73)
    # This is what phases 1-4 test. Phase 5 tests: what if the letter IS the code?
    # CT letter encodes directly through the checkerboard (no digit intermediate)
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 5: Direct letter-as-code model (CT letters map to checkerboard cells)")
    print("=" * 70)

    phase5_configs = 0
    phase5_best_fixed = 0
    phase5_best_free = 0
    phase5_hits = []

    # In this model, each CT letter is converted to a digit not via position
    # but via a DIRECT letter-to-digit table. The table IS the checkerboard read backward:
    # Given a checkerboard, each letter maps to its code (1 or 2 digits).
    # But we need CT letters to produce DIGITS, then parse those digits.
    # The digit mapping could be: letter -> its CODE's first digit.
    # Or: letter -> AZ_position mod 10, then parse.

    # Actually, let's try a different approach: what if each CT letter directly
    # represents a digit (A=0..Z=25 doesn't work for 0-9, but A=1,B=2,...,J=0
    # or A=0,B=1,...,I=8,J=9,K=0,L=1... [cycling])

    # Simple cycling: letter position in AZ mod 10
    # Already tested above. Skip.

    # What about: the checkerboard output IS the CT letters directly, not via digits.
    # I.e., the 8 single-letter codes are specific CT letters, and the 18 double-letter
    # codes use prefix letters as escape characters (like in the VIC model).
    # This is what e_vic_model.py tested (130.7M configs, 0 hits). Skip.

    print("  (Skipped - covered by VIC model elimination, 130.7M configs)")
    print()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 6: Expansion ratio diagnostic
    # For each configuration, track exactly how many chars decode to 73
    # ══════════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PHASE 6: Length distribution for K2 primary construction")
    print("=" * 70)

    len_dist = Counter()
    for map_name in ["KA_mod10", "AZ_mod10"]:
        map_fn = DIGIT_MAPPINGS[map_name]
        digits = ct_to_digits(CT, map_fn)

        for rl in ALL_PAIRS:
            for hdr_name in ["k2_unique_then_remaining", "standard_0_9"]:
                hdr = HEADERS[hdr_name]
                for fill_name in ["kw_KRYPTOS_AZ", "AZ", "KA"]:
                    fill_alpha = FILL_ALPHABETS[fill_name]
                    l2c, c2l = build_checkerboard_from_header(hdr, rl, fill_alpha)
                    decoded = decode_digits(digits, rl, c2l)
                    if decoded is not None:
                        len_dist[len(decoded)] += 1

    print("Decoded length distribution (top 15):")
    for length, count in len_dist.most_common(15):
        marker = " *** TARGET ***" if length == 73 else ""
        print(f"  Length {length}: {count} configs{marker}")

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 7: ASINTOER-style top row (common English letters in top row)
    # Standard VIC uses ASINTOER or similar high-frequency letters for single-digit
    # ══════════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PHASE 7: High-frequency letter arrangements (ASINTOER-style)")
    print("=" * 70)

    # Common English letters: E, T, A, O, I, N, S, H, R, D
    # For 8 single-digit positions: pick 8 of the top 10
    TOP8_SETS = [
        "ETAOINSHR"[:8],  # ETAOINSH
        "ETAOINSRD"[:8],  # ETAOINSR
        "ETAOINSHRD"[:8],  # ETAOINSH
        "ASINTOER",  # classic VIC style
    ]

    phase7_configs = 0
    phase7_best_fixed = 0
    phase7_best_free = 0

    for top8_str in TOP8_SETS:
        top8 = list(top8_str)
        remaining = [ch for ch in AZ if ch not in top8]

        for rl in ROW_LABEL_PAIRS + [(3, 8)]:
            rl = tuple(sorted(set(rl)))  # deduplicate
            if len(rl) != 2:
                continue

            for hdr_name in ["k2_unique_then_remaining", "standard_0_9"]:
                hdr = HEADERS[hdr_name]

                # Build custom fill: top8 first, then remaining 18 in order
                custom_fill = ''.join(top8 + remaining[:18])
                if len(custom_fill) != 26 or len(set(custom_fill)) != 26:
                    continue

                l2c, c2l = build_checkerboard_from_header(hdr, rl, custom_fill)

                for map_name in ["KA_mod10", "AZ_mod10", "kw_KRYPTOS_AZ_mod10"]:
                    if map_name not in DIGIT_MAPPINGS:
                        continue
                    map_fn = DIGIT_MAPPINGS[map_name]
                    digits = ct_to_digits(CT, map_fn)

                    phase7_configs += 1
                    total_configs += 1

                    decoded = decode_digits(digits, rl, c2l)
                    if decoded is None:
                        continue
                    pt_len = len(decoded)
                    if pt_len < 50 or pt_len > 90:
                        continue

                    fixed, ene_s, bc_s = check_cribs_fixed(decoded)
                    free, free_ep, free_bp = check_cribs_free(decoded)

                    if fixed > phase7_best_fixed:
                        phase7_best_fixed = fixed
                    if free > phase7_best_free:
                        phase7_best_free = free
                    if fixed > global_best_fixed:
                        global_best_fixed = fixed
                    if free > global_best_free:
                        global_best_free = free

                    if pt_len == 73:
                        total_len73 += 1
                        print(f"  *** LEN 73 *** rl={rl} top8={top8_str} map={map_name}")

                    if fixed >= 5 or free >= 7:
                        print(f"  HIT: rl={rl} top8={top8_str} hdr={hdr_name} map={map_name} "
                              f"len={pt_len} fixed={fixed} free={free}")

    print(f"\nPhase 7: {phase7_configs} configs")
    print(f"  Best fixed: {phase7_best_fixed}/24, Best free: {phase7_best_free}/24")

    # ══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total configs: {total_configs:,}")
    print(f"Total elapsed: {elapsed:.1f}s")
    print(f"Global best fixed score: {global_best_fixed}/24")
    print(f"Global best free score: {global_best_free}/24")
    print(f"Total length-73 decodes: {total_len73}")
    print()

    if global_best_fixed >= 18 or global_best_free >= 18:
        verdict = "SIGNAL"
    elif global_best_fixed >= 10 or global_best_free >= 10:
        verdict = "INTERESTING"
    elif global_best_fixed >= 5 or global_best_free >= 7:
        verdict = "WEAK_HITS"
    else:
        verdict = "NOISE"

    print(f"Verdict: {verdict}")

    # Collect top results from all phases
    all_hits = phase2_hits + phase4_hits + phase5_hits
    all_hits.sort(key=lambda h: max(h.get('fixed', 0), h.get('free', 0)), reverse=True)

    # Save results
    output = {
        'experiment': 'e_k2_checkerboard_decode',
        'description': 'K2 coordinates as straddling checkerboard configuration',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'elapsed_seconds': elapsed,
        'global_best_fixed': global_best_fixed,
        'global_best_free': global_best_free,
        'total_len73_decodes': total_len73,
        'verdict': verdict,
        'phase_summary': {
            'phase2_systematic': {
                'configs': phase2_configs,
                'best_fixed': phase2_best_fixed,
                'best_free': phase2_best_free,
                'len73': phase2_len73,
                'hits': len(phase2_hits),
            },
            'phase3_all_pairs': {
                'configs': phase3_configs,
                'best_fixed': phase3_best_fixed,
                'best_free': phase3_best_free,
                'len73': phase3_len73,
            },
            'phase4_additive': {
                'configs': phase4_configs,
                'best_fixed': phase4_best_fixed,
                'best_free': phase4_best_free,
                'len73': phase4_len73,
                'hits': len(phase4_hits),
            },
            'phase7_asintoer': {
                'configs': phase7_configs,
                'best_fixed': phase7_best_fixed,
                'best_free': phase7_best_free,
            },
        },
        'top_hits': [
            {k: (v if not isinstance(v, tuple) else list(v)) for k, v in h.items()}
            for h in all_hits[:20]
        ],
        'k2_construction': {
            'k2_digits': K2_DIGITS_IN_ORDER,
            'k2_unique': K2_UNIQUE_IN_ORDER,
            'remaining': K2_REMAINING,
            'primary_header': HEADERS['k2_unique_then_remaining'],
            'primary_row_labels': [3, 8],
        },
    }

    outpath = Path(__file__).resolve().parents[2] / "results" / "k2_checkerboard_decode.json"
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {outpath}")


if __name__ == "__main__":
    run()
