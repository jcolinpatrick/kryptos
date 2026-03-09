#!/usr/bin/env python3
"""
Cipher: K2 coordinate digits as punch card addressing for 24-null removal
Family: team
Status: active
Keyspace: ~500K (addressing schemes * keywords * cipher variants)
Last run:
Best score:
"""
"""E-COORDINATE-PUNCH: Test K2 coordinate digits as K4 null-position selectors.

Hypothesis: K2 coordinates (38°57'6.5"N 77°8'44"W) encode numbers that specify
how to "punch" K4 — identifying 24 null positions. The word POINT was deliberately
spelled out to separate two number sequences.

Tests A-G explore different interpretations of the coordinate digits as:
  A) Stepping pattern
  B) Grid row/column addressing
  C) Modular selectors
  D) Two-number linear congruential addressing
  E) Period/offset
  F) Columnar transposition key
  G) Two-layer Vigenère with digit-derived keys
"""
import sys
import os
import json
import time
from collections import Counter
from itertools import product
from math import gcd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD

# ── Constants ──────────────────────────────────────────────────────────────

FULL_DIGITS = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
LEFT_DIGITS = [3, 8, 5, 7, 6]       # Left of POINT (latitude)
RIGHT_DIGITS = [5, 7, 7, 8, 4, 4]   # Right of POINT (longitude)
LAT_COMPONENTS = (38, 57, 6, 5)     # degrees, minutes, seconds, tenths
LON_COMPONENTS = (77, 8, 44)        # degrees, minutes, seconds
ALL_COMPONENTS = [38, 57, 6, 5, 77, 8, 44]

DECRYPT_KEYS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "POINT", "DEFECTOR",
    "PARALLAX", "COLOPHON", "HOROLOGE", "SHADOW",
]

CRIBS = [
    "EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "BERLIN",
    "CLOCK", "THE", "SLOWLY", "INVISIBLE",
]

TARGET_NULLS = 24
TARGET_REAL = CT_LEN - TARGET_NULLS  # 73

# ── Quadgram scorer ───────────────────────────────────────────────────────

QG_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "english_quadgrams.json")
print(f"Loading quadgrams from {QG_PATH}...")
with open(QG_PATH) as f:
    QUADGRAMS = json.load(f)
QG_FLOOR = min(QUADGRAMS.values()) - 2.0
print(f"  Loaded {len(QUADGRAMS)} quadgrams, floor={QG_FLOOR:.3f}")


def qg_score(text: str) -> float:
    """Quadgram log-probability per character."""
    if len(text) < 4:
        return QG_FLOOR
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        gram = text[i:i+4]
        total += QUADGRAMS.get(gram, QG_FLOOR)
        n += 1
    return total / n if n > 0 else QG_FLOOR


def ic_score(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def check_cribs(text: str) -> list:
    """Check for crib substrings."""
    found = []
    for crib in CRIBS:
        pos = text.find(crib)
        if pos >= 0:
            found.append((crib, pos))
    return found


# ── Cipher operations ─────────────────────────────────────────────────────

def decrypt_vig(ct_text: str, key_str: str) -> str:
    """Vigenere decrypt: P = (C - K) mod 26"""
    key = [ALPH_IDX[c] for c in key_str]
    klen = len(key)
    return "".join(
        ALPH[(ALPH_IDX[c] - key[i % klen]) % MOD]
        for i, c in enumerate(ct_text)
    )


def decrypt_beau(ct_text: str, key_str: str) -> str:
    """Beaufort decrypt: P = (K - C) mod 26"""
    key = [ALPH_IDX[c] for c in key_str]
    klen = len(key)
    return "".join(
        ALPH[(key[i % klen] - ALPH_IDX[c]) % MOD]
        for i, c in enumerate(ct_text)
    )


def decrypt_varbeau(ct_text: str, key_str: str) -> str:
    """Variant Beaufort decrypt: P = (C + K) mod 26"""
    key = [ALPH_IDX[c] for c in key_str]
    klen = len(key)
    return "".join(
        ALPH[(ALPH_IDX[c] + key[i % klen]) % MOD]
        for i, c in enumerate(ct_text)
    )


CIPHER_FNS = {
    "vig": decrypt_vig,
    "beau": decrypt_beau,
    "vbeau": decrypt_varbeau,
}


def try_decrypt(ct_text: str, method_label: str, null_positions=None) -> list:
    """Try all keywords and cipher types. Return list of (score, ic, cribs, pt, method)."""
    results = []
    for kw in DECRYPT_KEYS:
        for cname, cfn in CIPHER_FNS.items():
            pt = cfn(ct_text, kw)
            sc = qg_score(pt)
            ic = ic_score(pt)
            cr = check_cribs(pt)
            label = f"{method_label} | {cname}/{kw}"
            if null_positions is not None:
                label += f" | nulls={sorted(null_positions)[:6]}..."
            results.append((sc, ic, cr, pt, label))
    # Also try no decryption (CT as PT)
    sc = qg_score(ct_text)
    ic = ic_score(ct_text)
    cr = check_cribs(ct_text)
    results.append((sc, ic, cr, ct_text, f"{method_label} | raw (no decrypt)"))
    return results


def remove_nulls(positions: set) -> str:
    """Remove null positions from CT, return remaining chars."""
    return "".join(CT[i] for i in range(CT_LEN) if i not in positions)


# ── Global results collector ──────────────────────────────────────────────

ALL_RESULTS = []
CONFIGS_TESTED = 0


def collect(results: list):
    global ALL_RESULTS, CONFIGS_TESTED
    ALL_RESULTS.extend(results)
    CONFIGS_TESTED += len(results)


# ══════════════════════════════════════════════════════════════════════════
# TEST A: Digits as stepping pattern
# ══════════════════════════════════════════════════════════════════════════

def test_a():
    print("\n" + "="*70)
    print("TEST A: Digits as stepping pattern")
    print("="*70)

    digit_sequences = {
        "full_digits": FULL_DIGITS,
        "left_digits": LEFT_DIGITS,
        "right_digits": RIGHT_DIGITS,
        "reversed_full": list(reversed(FULL_DIGITS)),
        "reversed_left": list(reversed(LEFT_DIGITS)),
        "reversed_right": list(reversed(RIGHT_DIGITS)),
    }

    # Also try starting at different positions
    start_positions = [0, 1, 20, 21, 38, 57, 63, 77]

    count = 0
    for seq_name, digits in digit_sequences.items():
        for start in start_positions:
            # Method 1: Cumulative stepping
            positions = set()
            pos = start
            dlen = len(digits)
            for step_idx in range(TARGET_NULLS):
                pos = (pos + digits[step_idx % dlen]) % CT_LEN
                positions.add(pos)
                if len(positions) > TARGET_NULLS:
                    break
            if len(positions) == TARGET_NULLS:
                real_ct = remove_nulls(positions)
                if len(real_ct) == TARGET_REAL:
                    label = f"A-step-cumul | seq={seq_name} start={start}"
                    collect(try_decrypt(real_ct, label, positions))
                    count += 1

            # Method 2: Each digit is a direct position offset from start
            # positions = {(start + d) % CT_LEN for d in digits}
            # Too few positions for most sequences

            # Method 3: Step with multiplication
            positions = set()
            pos = start
            for step_idx in range(TARGET_NULLS):
                d = digits[step_idx % dlen]
                if d == 0:
                    d = 1
                pos = (pos * d + step_idx) % CT_LEN
                positions.add(pos)
            if len(positions) == TARGET_NULLS:
                real_ct = remove_nulls(positions)
                if len(real_ct) == TARGET_REAL:
                    label = f"A-step-mult | seq={seq_name} start={start}"
                    collect(try_decrypt(real_ct, label, positions))
                    count += 1

    print(f"  Tested {count} stepping configurations")


# ══════════════════════════════════════════════════════════════════════════
# TEST B: Digits as grid row/column pairs
# ══════════════════════════════════════════════════════════════════════════

def test_b():
    print("\n" + "="*70)
    print("TEST B: Digits as grid row/column addressing")
    print("="*70)

    grids = [
        (8, 12, "8x12"),    # 96 + 1 tail
        (4, 24, "4x24"),    # 96 + 1 tail
        (14, 7, "14x7"),    # 98, close to 97
        (7, 14, "7x14"),    # 98
        (11, 9, "11x9"),    # 99
        (9, 11, "9x11"),    # 99
        (3, 33, "3x33"),    # 99
    ]

    count = 0
    for nrows, ncols, gname in grids:
        # Pair up full digits as (row, col)
        pairs = []
        for i in range(0, len(FULL_DIGITS) - 1, 2):
            r = FULL_DIGITS[i] % nrows
            c = FULL_DIGITS[i+1] % ncols
            pairs.append((r, c))

        # Method B1: Mark specific (row,col) cells as null
        positions = set()
        for r, c in pairs:
            idx = r * ncols + c
            if idx < CT_LEN:
                positions.add(idx)
        # Not enough for 24 nulls usually — but try marking entire rows or cols

        # Method B2: For each pair, mark entire column as null
        null_cols = set()
        for _, c in pairs:
            null_cols.add(c)
        positions = set()
        for c in null_cols:
            for r in range(nrows):
                idx = r * ncols + c
                if idx < CT_LEN:
                    positions.add(idx)
        if len(positions) == TARGET_NULLS:
            real_ct = remove_nulls(positions)
            if len(real_ct) == TARGET_REAL:
                label = f"B-grid-cols | grid={gname} null_cols={sorted(null_cols)}"
                collect(try_decrypt(real_ct, label, positions))
                count += 1

        # Method B3: For each pair, mark entire row as null
        null_rows = set()
        for r, _ in pairs:
            null_rows.add(r)
        positions = set()
        for r in null_rows:
            for c in range(ncols):
                idx = r * ncols + c
                if idx < CT_LEN:
                    positions.add(idx)
        if len(positions) == TARGET_NULLS:
            real_ct = remove_nulls(positions)
            if len(real_ct) == TARGET_REAL:
                label = f"B-grid-rows | grid={gname} null_rows={sorted(null_rows)}"
                collect(try_decrypt(real_ct, label, positions))
                count += 1

        # Method B4: Use coordinate components as row indices to mark
        for row_set_label, row_indices in [
            ("lat_comp", [c % nrows for c in LAT_COMPONENTS]),
            ("lon_comp", [c % nrows for c in LON_COMPONENTS]),
        ]:
            null_row_set = set(row_indices)
            positions = set()
            for r in null_row_set:
                for c in range(ncols):
                    idx = r * ncols + c
                    if idx < CT_LEN:
                        positions.add(idx)
            if len(positions) == TARGET_NULLS:
                real_ct = remove_nulls(positions)
                if len(real_ct) == TARGET_REAL:
                    label = f"B-grid-comprows | grid={gname} rows={row_set_label}={sorted(null_row_set)}"
                    collect(try_decrypt(real_ct, label, positions))
                    count += 1

    # Special: 4x24 with one null per column selected by coordinate digit cycle
    print("  Testing 4x24 with digit-cycled row selection per column...")
    nrows, ncols = 4, 24
    for seq_name, digits in [("full", FULL_DIGITS), ("left", LEFT_DIGITS), ("right", RIGHT_DIGITS)]:
        positions = set()
        dlen = len(digits)
        for col in range(ncols):
            row = digits[col % dlen] % nrows
            idx = row * ncols + col
            if idx < CT_LEN:
                positions.add(idx)
        if len(positions) == TARGET_NULLS:
            real_ct = remove_nulls(positions)
            if len(real_ct) == TARGET_REAL:
                label = f"B-4x24-digit-row | seq={seq_name}"
                collect(try_decrypt(real_ct, label, positions))
                count += 1

    # 8x12 with digit-cycled row selection
    nrows, ncols = 8, 12
    for seq_name, digits in [("full", FULL_DIGITS), ("left", LEFT_DIGITS), ("right", RIGHT_DIGITS)]:
        positions = set()
        dlen = len(digits)
        for col in range(ncols):
            # Need 2 nulls per column to get 24 from 12 columns
            for offset in range(2):
                row = (digits[(col * 2 + offset) % dlen]) % nrows
                idx = row * ncols + col
                if idx < CT_LEN:
                    positions.add(idx)
        if len(positions) == TARGET_NULLS:
            real_ct = remove_nulls(positions)
            if len(real_ct) == TARGET_REAL:
                label = f"B-8x12-digit-row | seq={seq_name}"
                collect(try_decrypt(real_ct, label, positions))
                count += 1

    print(f"  Tested {count} grid configurations")


# ══════════════════════════════════════════════════════════════════════════
# TEST C: Coordinate numbers as modular selectors
# ══════════════════════════════════════════════════════════════════════════

def test_c():
    print("\n" + "="*70)
    print("TEST C: Coordinate numbers as modular selectors")
    print("="*70)

    # Collect all coordinate-derived numbers
    coord_nums = [3, 4, 5, 6, 7, 8, 38, 44, 57, 65, 77,
                  385765, 577844, 38576, 77844,
                  385, 576, 778, 844,
                  35, 87, 65, 57, 78, 44]
    coord_nums = list(set(coord_nums))

    count = 0
    exact_24_rules = []

    # Form: null if i mod M in S (where M and S come from coordinates)
    for modulus in coord_nums:
        if modulus < 2 or modulus > CT_LEN:
            continue
        for offset_set_src in coord_nums:
            if offset_set_src < 0:
                continue
            # Try: null if i mod modulus == offset_set_src mod modulus
            off = offset_set_src % modulus
            positions = {i for i in range(CT_LEN) if i % modulus == off}
            if len(positions) == TARGET_NULLS:
                real_ct = remove_nulls(positions)
                if len(real_ct) == TARGET_REAL:
                    label = f"C-mod | i%{modulus}=={off}"
                    exact_24_rules.append(label)
                    collect(try_decrypt(real_ct, label, positions))
                    count += 1

    # Form: null if (i + A) mod B < C
    for a in ALL_COMPONENTS:
        for b in ALL_COMPONENTS:
            if b < 2:
                continue
            for c in ALL_COMPONENTS:
                if c >= b:
                    continue
                positions = {i for i in range(CT_LEN) if (i + a) % b < c}
                if len(positions) == TARGET_NULLS:
                    real_ct = remove_nulls(positions)
                    if len(real_ct) == TARGET_REAL:
                        label = f"C-range | (i+{a})%{b}<{c}"
                        exact_24_rules.append(label)
                        collect(try_decrypt(real_ct, label, positions))
                        count += 1

    # Form: null if i mod M in {set of digits}
    for modulus in range(2, 50):
        for subset_src in [LEFT_DIGITS, RIGHT_DIGITS, FULL_DIGITS]:
            null_residues = set(d % modulus for d in subset_src)
            positions = {i for i in range(CT_LEN) if i % modulus in null_residues}
            if len(positions) == TARGET_NULLS:
                real_ct = remove_nulls(positions)
                if len(real_ct) == TARGET_REAL:
                    label = f"C-multimod | i%{modulus} in {sorted(null_residues)}"
                    if label not in exact_24_rules:
                        exact_24_rules.append(label)
                        collect(try_decrypt(real_ct, label, positions))
                        count += 1

    print(f"  Found {len(exact_24_rules)} rules giving exactly 24 nulls")
    for rule in exact_24_rules[:20]:
        print(f"    {rule}")
    print(f"  Tested {count} modular configurations")


# ══════════════════════════════════════════════════════════════════════════
# TEST D: Two-number linear congruential addressing
# ══════════════════════════════════════════════════════════════════════════

def test_d():
    print("\n" + "="*70)
    print("TEST D: Two-number linear congruential addressing")
    print("="*70)

    # Pairs of (multiplier, additive) from coordinate components
    pairs = [
        (385765, 577844), (577844, 385765),
        (38576, 77844), (77844, 38576),
        (38, 57), (57, 38),
        (77, 44), (44, 77),
        (6, 5), (5, 6),
        (38, 77), (77, 38),
        (57, 44), (44, 57),
        (57, 8), (8, 57),
        (38, 44), (44, 38),
        (6, 44), (44, 6),
        (5, 8), (8, 5),
        (65, 77), (77, 65),
        (38, 8), (8, 38),
        (57, 77), (77, 57),
    ]

    count = 0
    for a, b in pairs:
        # Form 1: positions = {(a*i + b) mod 97 for i in range(24)}
        positions = set()
        for i in range(TARGET_NULLS):
            positions.add((a * i + b) % CT_LEN)
        if len(positions) == TARGET_NULLS:
            real_ct = remove_nulls(positions)
            if len(real_ct) == TARGET_REAL:
                label = f"D-lcg1 | ({a}*i+{b})%97"
                collect(try_decrypt(real_ct, label, positions))
                count += 1

        # Form 2: positions = {(a + i*b) mod 97 for i in range(24)}
        positions = set()
        for i in range(TARGET_NULLS):
            positions.add((a + i * b) % CT_LEN)
        if len(positions) == TARGET_NULLS:
            real_ct = remove_nulls(positions)
            if len(real_ct) == TARGET_REAL:
                label = f"D-lcg2 | ({a}+i*{b})%97"
                collect(try_decrypt(real_ct, label, positions))
                count += 1

        # Form 3: positions = {(a*i*i + b*i) mod 97 for i in range(24)}  (quadratic)
        positions = set()
        for i in range(TARGET_NULLS):
            positions.add((a * i * i + b * i) % CT_LEN)
        if len(positions) == TARGET_NULLS:
            real_ct = remove_nulls(positions)
            if len(real_ct) == TARGET_REAL:
                label = f"D-quad | ({a}*i²+{b}*i)%97"
                collect(try_decrypt(real_ct, label, positions))
                count += 1

    # Also: single generator {(n*i) mod 97 for i in range(24)} for various n
    for n in coord_nums_global():
        if n <= 0:
            continue
        g = gcd(n % CT_LEN, CT_LEN)
        # Can only generate 97/gcd(n,97) unique values
        positions = set()
        for i in range(TARGET_NULLS):
            positions.add((n * i) % CT_LEN)
        if len(positions) == TARGET_NULLS:
            real_ct = remove_nulls(positions)
            if len(real_ct) == TARGET_REAL:
                label = f"D-single | ({n}*i)%97"
                collect(try_decrypt(real_ct, label, positions))
                count += 1

    print(f"  Tested {count} LCG configurations")


def coord_nums_global():
    return [3, 4, 5, 6, 7, 8, 38, 44, 57, 65, 77,
            385765, 577844, 38576, 77844, 385, 576, 778, 844]


# ══════════════════════════════════════════════════════════════════════════
# TEST E: Digits define period and offset
# ══════════════════════════════════════════════════════════════════════════

def test_e():
    print("\n" + "="*70)
    print("TEST E: Coordinate components as period/offset")
    print("="*70)

    components = [3, 4, 5, 6, 7, 8, 38, 44, 57, 65, 77, 24, 73, 97]

    count = 0
    for period in components:
        if period < 1 or period > CT_LEN:
            continue
        for offset in components:
            if offset < 0:
                continue
            # Generate positions: offset, offset+period, offset+2*period, ... (mod 97)
            positions = set()
            pos = offset % CT_LEN
            for _ in range(TARGET_NULLS):
                positions.add(pos)
                pos = (pos + period) % CT_LEN
            if len(positions) == TARGET_NULLS:
                real_ct = remove_nulls(positions)
                if len(real_ct) == TARGET_REAL:
                    label = f"E-periodic | period={period} offset={offset}"
                    collect(try_decrypt(real_ct, label, positions))
                    count += 1

    # Also try: within each period, select specific residues from digits
    for period in range(2, 30):
        for digit_seq_name, digit_seq in [("full", FULL_DIGITS), ("left", LEFT_DIGITS), ("right", RIGHT_DIGITS)]:
            residues = set(d % period for d in digit_seq)
            positions = {i for i in range(CT_LEN) if i % period in residues}
            if len(positions) == TARGET_NULLS:
                real_ct = remove_nulls(positions)
                if len(real_ct) == TARGET_REAL:
                    label = f"E-residues | period={period} seq={digit_seq_name} res={sorted(residues)}"
                    collect(try_decrypt(real_ct, label, positions))
                    count += 1

    print(f"  Tested {count} period/offset configurations")


# ══════════════════════════════════════════════════════════════════════════
# TEST F: Coordinate as columnar transposition key
# ══════════════════════════════════════════════════════════════════════════

def test_f():
    print("\n" + "="*70)
    print("TEST F: Digits as columnar transposition key")
    print("="*70)

    count = 0

    for seq_name, digits in [
        ("full_11", FULL_DIGITS),
        ("left_5", LEFT_DIGITS),
        ("right_6", RIGHT_DIGITS),
    ]:
        ncols = len(digits)
        nrows = (CT_LEN + ncols - 1) // ncols  # ceiling division

        # Pad CT to fill grid
        padded = CT + "X" * (nrows * ncols - CT_LEN)

        # Write into grid by rows
        grid = []
        for r in range(nrows):
            grid.append(padded[r * ncols: (r + 1) * ncols])

        # Determine column read order from digit values
        # Sort columns by digit value (stable sort for ties)
        col_order_asc = sorted(range(ncols), key=lambda c: (digits[c], c))
        col_order_desc = sorted(range(ncols), key=lambda c: (-digits[c], c))

        for order_name, col_order in [("asc", col_order_asc), ("desc", col_order_desc)]:
            # Read off columns in this order
            result = ""
            for c in col_order:
                for r in range(nrows):
                    ch = grid[r][c]
                    result += ch
            # Trim to CT_LEN
            result = result[:CT_LEN]

            label = f"F-columnar | seq={seq_name} order={order_name}"
            collect(try_decrypt(result, label))
            count += 1

        # Also try: write by columns, read by rows
        # Write into grid by column order
        grid2 = [[""] * ncols for _ in range(nrows)]
        idx = 0
        for c in col_order_asc:
            for r in range(nrows):
                if idx < CT_LEN:
                    grid2[r][c] = CT[idx]
                else:
                    grid2[r][c] = "X"
                idx += 1
        result = ""
        for r in range(nrows):
            for c in range(ncols):
                result += grid2[r][c]
        result = result[:CT_LEN]

        label = f"F-col-write-row-read | seq={seq_name}"
        collect(try_decrypt(result, label))
        count += 1

    # Also: use the full coordinate string digits as a numeric key for disrupted columnar
    # Key = 3 8 5 7 6 5 7 7 8 4 4, columns sorted by key digit
    # After transposition, try null removal (every Nth)
    # Already covered by the main transposition above

    print(f"  Tested {count} columnar transposition configurations")


# ══════════════════════════════════════════════════════════════════════════
# TEST G: Two-layer Vigenère with digit-derived keys
# ══════════════════════════════════════════════════════════════════════════

def test_g():
    print("\n" + "="*70)
    print("TEST G: Two-layer cipher with digit-derived keys")
    print("="*70)

    count = 0

    # Convert digit sequences to key letters (digit -> letter: 0=A, 1=B, ..., 9=J)
    def digits_to_key(digits):
        return "".join(ALPH[d % MOD] for d in digits)

    # Also try: digits as direct letter indices
    left_key = digits_to_key(LEFT_DIGITS)   # "DIFHG" (3=D,8=I,5=F,7=H,6=G)
    right_key = digits_to_key(RIGHT_DIGITS)  # "FHHIEE" (5=F,7=H,7=H,8=I,4=E,4=E)
    full_key = digits_to_key(FULL_DIGITS)    # "DIFHGFHHIEE"

    # Also try coordinate component numbers as letter indices
    comp_key1 = "".join(ALPH[c % MOD] for c in LAT_COMPONENTS)  # 38,57,6,5 -> M,F,G,F
    comp_key2 = "".join(ALPH[c % MOD] for c in LON_COMPONENTS)  # 77,8,44 -> V,I,S

    digit_keys = {
        "left_DIFHG": left_key,
        "right_FHHIEE": right_key,
        "full_DIFHGFHHIEE": full_key,
        "lat_comp": comp_key1,
        "lon_comp": comp_key2,
    }

    # Single-layer with digit-derived keys
    for kname, kval in digit_keys.items():
        for cname, cfn in CIPHER_FNS.items():
            pt = cfn(CT, kval)
            sc = qg_score(pt)
            ic = ic_score(pt)
            cr = check_cribs(pt)
            label = f"G-single | key={kname}({kval}) cipher={cname}"
            ALL_RESULTS.append((sc, ic, cr, pt, label))
            count += 1

    # Two-layer: first layer with one key, second layer with another
    for k1name, k1val in digit_keys.items():
        for k2name, k2val in digit_keys.items():
            if k1name == k2name:
                continue
            for c1name, c1fn in CIPHER_FNS.items():
                for c2name, c2fn in CIPHER_FNS.items():
                    intermediate = c1fn(CT, k1val)
                    pt = c2fn(intermediate, k2val)
                    sc = qg_score(pt)
                    ic = ic_score(pt)
                    cr = check_cribs(pt)
                    label = f"G-2layer | L1={c1name}/{k1name} L2={c2name}/{k2name}"
                    ALL_RESULTS.append((sc, ic, cr, pt, label))
                    count += 1

    # Two-layer with one digit key and one word key
    for kname, kval in digit_keys.items():
        for wk in DECRYPT_KEYS:
            for c1name, c1fn in CIPHER_FNS.items():
                for c2name, c2fn in CIPHER_FNS.items():
                    # digit key first, then word key
                    inter = c1fn(CT, kval)
                    pt = c2fn(inter, wk)
                    sc = qg_score(pt)
                    ic = ic_score(pt)
                    cr = check_cribs(pt)
                    label = f"G-digit+word | L1={c1name}/{kname} L2={c2name}/{wk}"
                    ALL_RESULTS.append((sc, ic, cr, pt, label))
                    count += 1

                    # word key first, then digit key
                    inter = c1fn(CT, wk)
                    pt = c2fn(inter, kval)
                    sc = qg_score(pt)
                    ic = ic_score(pt)
                    cr = check_cribs(pt)
                    label = f"G-word+digit | L1={c1name}/{wk} L2={c2name}/{kname}"
                    ALL_RESULTS.append((sc, ic, cr, pt, label))
                    count += 1

    print(f"  Tested {count} digit-key configurations")


# ══════════════════════════════════════════════════════════════════════════
# BONUS: Combined null removal + digit key
# ══════════════════════════════════════════════════════════════════════════

def test_bonus():
    print("\n" + "="*70)
    print("BONUS: Best null-position rules + digit-derived keys")
    print("="*70)

    # Re-derive some null position sets that give exactly 24
    null_sets = []

    # From Test A stepping
    for seq_name, digits in [("full", FULL_DIGITS), ("left", LEFT_DIGITS), ("right", RIGHT_DIGITS)]:
        for start in range(CT_LEN):
            positions = set()
            pos = start
            dlen = len(digits)
            for step_idx in range(TARGET_NULLS):
                pos = (pos + digits[step_idx % dlen]) % CT_LEN
                positions.add(pos)
            if len(positions) == TARGET_NULLS:
                null_sets.append((f"step_{seq_name}_s{start}", positions))

    # From LCG
    lcg_params = [(38, 57), (57, 38), (77, 44), (44, 77), (6, 5), (5, 6)]
    for a, b in lcg_params:
        positions = set()
        for i in range(TARGET_NULLS):
            positions.add((a + i * b) % CT_LEN)
        if len(positions) == TARGET_NULLS:
            null_sets.append((f"lcg_{a}+i*{b}", positions))
        positions = set()
        for i in range(TARGET_NULLS):
            positions.add((a * i + b) % CT_LEN)
        if len(positions) == TARGET_NULLS:
            null_sets.append((f"lcg_{a}*i+{b}", positions))

    # Deduplicate by frozenset
    seen = set()
    unique_null_sets = []
    for name, pos in null_sets:
        key = frozenset(pos)
        if key not in seen:
            seen.add(key)
            unique_null_sets.append((name, pos))

    print(f"  Found {len(unique_null_sets)} unique null position sets")

    count = 0
    # For each, try digit-derived keys
    left_key = "".join(ALPH[d % MOD] for d in LEFT_DIGITS)
    right_key = "".join(ALPH[d % MOD] for d in RIGHT_DIGITS)
    full_key = "".join(ALPH[d % MOD] for d in FULL_DIGITS)

    all_keys = {
        "left_dig": left_key,
        "right_dig": right_key,
        "full_dig": full_key,
    }
    all_keys.update({kw: kw for kw in DECRYPT_KEYS})

    for ns_name, positions in unique_null_sets[:50]:  # cap at 50 to limit runtime
        real_ct = remove_nulls(positions)
        if len(real_ct) != TARGET_REAL:
            continue
        for kname, kval in all_keys.items():
            for cname, cfn in CIPHER_FNS.items():
                pt = cfn(real_ct, kval)
                sc = qg_score(pt)
                ic = ic_score(pt)
                cr = check_cribs(pt)
                label = f"BONUS | nulls={ns_name} {cname}/{kname}"
                ALL_RESULTS.append((sc, ic, cr, pt, label))
                count += 1

    print(f"  Tested {count} bonus configurations")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()

    print("K2 COORDINATE PUNCH CARD ADDRESSING FOR K4")
    print("=" * 70)
    print(f"K4 CT: {CT} ({CT_LEN} chars)")
    print(f"Target: remove {TARGET_NULLS} nulls → {TARGET_REAL}-char real CT")
    print(f"Coordinate digits: {FULL_DIGITS}")
    print(f"Left of POINT: {LEFT_DIGITS}")
    print(f"Right of POINT: {RIGHT_DIGITS}")
    print(f"Components: lat=({LAT_COMPONENTS}) lon=({LON_COMPONENTS})")
    print()

    test_a()
    test_b()
    test_c()
    test_d()
    test_e()
    test_f()
    test_g()
    test_bonus()

    elapsed = time.time() - t0

    # ── Report ─────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"RESULTS SUMMARY — {len(ALL_RESULTS)} total candidates in {elapsed:.1f}s")
    print("=" * 70)

    # Check for any crib matches first
    crib_hits = [(sc, ic, cr, pt, label) for sc, ic, cr, pt, label in ALL_RESULTS if cr]
    if crib_hits:
        print(f"\n*** CRIB MATCHES FOUND: {len(crib_hits)} ***")
        for sc, ic, cr, pt, label in sorted(crib_hits, key=lambda x: -x[0])[:20]:
            print(f"  QG={sc:.3f} IC={ic:.4f} CRIBS={cr}")
            print(f"  PT: {pt[:80]}...")
            print(f"  Method: {label}")
            print()

    # Top 30 by QG score
    ALL_RESULTS.sort(key=lambda x: -x[0])
    print(f"\nTOP 30 BY QUADGRAM SCORE:")
    print("-" * 70)
    for rank, (sc, ic, cr, pt, label) in enumerate(ALL_RESULTS[:30], 1):
        crib_flag = " *** CRIB ***" if cr else ""
        print(f"#{rank:2d} QG={sc:.3f}  IC={ic:.4f}{crib_flag}")
        print(f"    PT: {pt[:80]}")
        print(f"    Method: {label}")
        if cr:
            print(f"    Cribs: {cr}")
        print()

    # Stats by test
    print("\n" + "=" * 70)
    print("STATISTICS")
    print(f"  Total configs tested: {len(ALL_RESULTS)}")
    print(f"  Elapsed time: {elapsed:.1f}s")
    print(f"  Crib matches: {len(crib_hits)}")

    # Score distribution
    scores = [x[0] for x in ALL_RESULTS]
    if scores:
        print(f"  Best QG/char: {max(scores):.3f}")
        print(f"  Median QG/char: {sorted(scores)[len(scores)//2]:.3f}")
        print(f"  Worst QG/char: {min(scores):.3f}")

    # IC distribution
    ics = [x[1] for x in ALL_RESULTS]
    high_ic = [(sc, ic, cr, pt, label) for sc, ic, cr, pt, label in ALL_RESULTS if ic > 0.050]
    if high_ic:
        print(f"\n  High IC (>0.050) candidates: {len(high_ic)}")
        for sc, ic, cr, pt, label in sorted(high_ic, key=lambda x: -x[1])[:10]:
            print(f"    IC={ic:.4f} QG={sc:.3f} Method: {label[:60]}")

    print("\nDone.")


if __name__ == "__main__":
    main()
