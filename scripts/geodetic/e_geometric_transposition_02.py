#!/usr/bin/env python3
"""Geometric Transposition Derivation — Key Intersections.

Family:    geodetic
Cipher:    geometry-defined transposition + substitution
Status:    active
Keyspace:  ~2000 transposition candidates from geometric encodings
Last run:  never
Best score: n/a

Tests whether geometric relationships define the TRANSPOSITION layer.
Under the two-system model: PT → transposition → substitution → carved text.
If geometry defines the transposition, we can invert it and then test substitution.

Key discovery from e_geometric_keys_01.py:
- SC→K2 × LODESTONE_ENE intersection at bearing **73.4°** from LOOMIS
  (73 = hypothesized real CT length)
- LOOMIS→Sculpture = 64.7m ≈ 65 = Bean equality position k[27]=k[65]
- CR→SCULPTURE bearing = 45.16° ≈ LOOMIS→ABBOTT published azimuth (45.58°)
"""
import math
import sys
import os
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT, N_CRIBS, ALPH, CT_LEN
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.crib_score import score_cribs


# ── Geometric values from e_geometric_keys_01 ──

# Key bearings from LOOMIS (sorted by angle):
BEARINGS_FROM_LOOMIS = {
    'ABBOTT':    45.47,
    'SCULPTURE': 52.77,
    'SMALL_POOL': 54.09,
    'K2':        85.03,
    'COMPASS':  141.90,
}

# Key distances from LOOMIS (meters):
DISTANCES_FROM_LOOMIS = {
    'COMPASS':    8.6,
    'SCULPTURE': 64.7,
    'K2':        99.9,
    'SMALL_POOL': 102.7,
    'LARGE_POOL': 113.9,
    'ABBOTT':   2008.1,
}

# Key intersection bearings from LOOMIS:
INTERSECTION_BEARINGS = {
    'SCxK2_ENE':     73.4,  # sculpture→K2 × lodestone ENE
    'SCxK2_ENE_MAG': 63.9,  # sculpture→K2 × lodestone ENE (magnetic)
    'LOOMxABB_SCxK2': 45.6,  # LOOMIS→ABBOTT × SC→K2
    'LOOMxK2_CRxSC':  85.0,  # LOOMIS→K2 × CR→sculpture
}

# Key angles at LOOMIS vertex:
ANGLES_AT_LOOMIS = {
    'ABB_K2':  39.56,  # ABBOTT-LOOMIS-K2
    'ABB_SC':   7.30,  # ABBOTT-LOOMIS-Sculpture
    'SC_K2':   32.26,  # Sculpture-LOOMIS-K2
}


def columnar_read(text, width, col_order=None):
    """Read text into grid of given width, read out by columns in given order."""
    n = len(text)
    nrows = (n + width - 1) // width
    # Fill grid row by row
    grid = []
    for r in range(nrows):
        row = []
        for c in range(width):
            idx = r * width + c
            if idx < n:
                row.append(text[idx])
            else:
                row.append('')
        grid.append(row)

    if col_order is None:
        col_order = list(range(width))

    # Read columns in specified order
    result = []
    for c in col_order:
        for r in range(nrows):
            if grid[r][c]:
                result.append(grid[r][c])
    return ''.join(result)


def columnar_unread(text, width, col_order=None):
    """Inverse of columnar_read: given text read out by columns, reconstruct row order."""
    n = len(text)
    nrows = (n + width - 1) // width
    ncols = width
    # Compute column lengths
    full_cols = n % width if n % width != 0 else width
    col_lens = []
    for c in range(ncols):
        if n % width == 0:
            col_lens.append(nrows)
        elif c < (n % width):
            col_lens.append(nrows)
        else:
            col_lens.append(nrows - 1)

    if col_order is None:
        col_order = list(range(width))

    # Distribute text to columns in col_order
    grid = [[''] * ncols for _ in range(nrows)]
    idx = 0
    for c in col_order:
        for r in range(col_lens[c]):
            if idx < n:
                grid[r][c] = text[idx]
                idx += 1

    # Read row by row
    result = []
    for r in range(nrows):
        for c in range(ncols):
            if grid[r][c]:
                result.append(grid[r][c])
    return ''.join(result)


def bearing_to_column_order(bearings, width):
    """Convert a sequence of bearing values to a column order for width columns.

    Various encodings: mod width, proportional ranking, digit extraction.
    Returns list of candidate column orders.
    """
    orders = []

    # Method 1: bearing mod width → column index (may have collisions)
    vals = [round(b) % width for b in bearings]
    if len(set(vals)) == width and max(vals) < width:
        orders.append(('mod', vals))

    # Method 2: rank by bearing value
    ranked = sorted(range(len(bearings)), key=lambda i: bearings[i])
    if len(bearings) == width:
        orders.append(('rank', ranked))

    # Method 3: bearing digits as column indices
    for b in bearings[:1]:  # just the first bearing
        digits = [int(d) for d in f"{b:.1f}".replace('.', '')]
        if len(digits) >= width:
            order = digits[:width]
            if len(set(order)) == width and max(order) < width:
                orders.append(('digits', order))

    return orders


def test_transposition_then_sub(intermediate_text, label):
    """Given intermediate text (CT after undoing transposition), test all substitution keys."""
    best = (0, '', '', '')

    # Test with known cribs: if intermediate has cribs at correct positions,
    # the transposition was correct and there's NO substitution needed
    sc = score_cribs(intermediate_text)
    if sc > best[0]:
        best = (sc, 'identity', label, intermediate_text[:40])

    # Test with single-letter keys (monoalphabetic shift)
    for k in range(26):
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(intermediate_text, [k], variant)
            sc = score_cribs(pt)
            if sc > best[0]:
                best = (sc, f"{variant.value}(key={ALPH[k]})", label, pt[:40])

    return best


def main():
    print("=" * 80)
    print("GEOMETRIC TRANSPOSITION DERIVATION")
    print("=" * 80)
    print(f"CT = {CT}")
    print(f"Testing whether geometric values define the transposition layer")
    print()

    all_results = []

    # ── Strategy 1: Grid widths from geometric values ──
    print("── Strategy 1: Grid widths from geometric values ──")

    # Interesting widths derived from geometry
    geometric_widths = {
        7:  "LOOMIS→ABBOTT-SCULPTURE delta ≈ 7.3°",
        8:  "LOOMIS→compass rose ≈ 8.6m",
        13: "d=13 anomaly, EASTNORTHEAST length",
        14: "28×31 grid has 14 rows per half",
        31: "28×31 grid width (CONFIRMED)",
        39: "ABBOTT-LOOMIS-K2 angle ≈ 39.6°",
        45: "LOOMIS→ABBOTT ≈ 45.6°",
        53: "LOOMIS→Sculpture ≈ 52.8°",
        65: "LOOMIS→Sculpture ≈ 64.7m (≈ pos 65)",
        73: "73-char hypothesis, SC×K2 ENE bearing 73.4°",
        85: "LOOMIS→K2 bearing ≈ 85°",
    }

    for width, reason in geometric_widths.items():
        if width < 2 or width > CT_LEN:
            continue
        nrows = (CT_LEN + width - 1) // width

        # Standard columnar (read in order)
        intermediate = columnar_unread(CT, width)
        result = test_transposition_then_sub(intermediate, f"columnar_unread(w={width})")
        if result[0] > 0:
            all_results.append(result)

        # Reverse column order
        rev_order = list(range(width-1, -1, -1))
        intermediate = columnar_unread(CT, width, rev_order)
        result = test_transposition_then_sub(intermediate, f"columnar_unread(w={width},rev)")
        if result[0] > 0:
            all_results.append(result)

    # ── Strategy 2: Column order from bearing sequence ──
    print("── Strategy 2: Column order from bearing sequence ──")

    # The 5 sorted bearings from LOOMIS might define a 5-column order
    sorted_bearings = [45.47, 52.77, 54.09, 85.03, 141.90]
    bearing_names = ['ABBOTT', 'SCULPTURE', 'SMALL_POOL', 'K2', 'COMPASS']

    # Width 5: bearings rank = [0,1,2,3,4] (already sorted)
    for perm in itertools.permutations(range(5)):
        intermediate = columnar_unread(CT, 5, list(perm))
        result = test_transposition_then_sub(intermediate, f"w5_perm{list(perm)}")
        if result[0] >= 3:
            all_results.append(result)

    # Width 7 with various column orders
    # 97 = 7 × 13 + 6, so 14 rows, 6 full columns + 1 short
    # Try column orders derived from bearing values
    print("  Testing all 7-column permutations (5040)...")
    best_w7 = (0, '', '', '')
    for perm in itertools.permutations(range(7)):
        intermediate = columnar_unread(CT, 7, list(perm))
        result = test_transposition_then_sub(intermediate, f"w7_perm{list(perm)}")
        if result[0] > best_w7[0]:
            best_w7 = result
        if result[0] >= 5:
            all_results.append(result)
    print(f"  Best w=7: {best_w7[0]}/24 ({best_w7[1]})")
    if best_w7[0] >= 3:
        all_results.append(best_w7)

    # Width 8 (8.6m LOOMIS→CR, "8 lines")
    print("  Testing all 8-column permutations (40320)...")
    best_w8 = (0, '', '', '')
    for perm in itertools.permutations(range(8)):
        intermediate = columnar_unread(CT, 8, list(perm))
        result = test_transposition_then_sub(intermediate, f"w8_perm{list(perm)}")
        if result[0] > best_w8[0]:
            best_w8 = result
        if result[0] >= 5:
            all_results.append(result)
    print(f"  Best w=8: {best_w8[0]}/24 ({best_w8[1]})")
    if best_w8[0] >= 3:
        all_results.append(best_w8)

    # ── Strategy 3: Bearing-defined null mask ──
    print("\n── Strategy 3: Bearing-defined null mask (73-char) ──")

    # The bearing 73.4° from LOOMIS to the SC×K2/ENE intersection
    # suggests the number 73. What if the bearings to each feature
    # define which positions are null?

    # Idea: position i is null if bearing_from_LOOMIS(feature_at_i) < threshold
    # Or: position i is null if i maps to a geometric value below/above threshold

    # Simple: positions divisible by certain geometric values
    null_strategies = [
        # Every 4th position (97/24 ≈ 4.04)
        ("every_4th", [i for i in range(CT_LEN) if i % 4 == 0]),
        # W positions + every 4th
        ("W_positions", [20, 36, 48, 58, 74]),
        # Positions from bearings mod 97
        ("bearing_mod97", [round(b) % CT_LEN for b in sorted_bearings]),
        # Positions matching floor(bearing) for various features
        ("bearing_floors", [45, 52, 54, 85, 141 % 97]),
    ]

    for name, null_positions in null_strategies:
        # Need exactly 24 nulls for 73-char hypothesis
        if len(null_positions) != 24:
            # Try extending with pattern
            if len(null_positions) < 24:
                # Use the pattern as a seed, extend by stepping
                extended = list(set(null_positions))
                step = CT_LEN // (24 - len(extended) + 1)
                for s in range(0, CT_LEN, max(1, step)):
                    if s not in extended and len(extended) < 24:
                        extended.append(s)
                null_positions = sorted(extended[:24])
            else:
                null_positions = null_positions[:24]

        # Extract 73-char CT
        kept = [CT[i] for i in range(CT_LEN) if i not in null_positions]
        if len(kept) != 73:
            continue

        extracted_ct = ''.join(kept)

        # Test with various substitution keys
        for k in range(26):
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(extracted_ct, [k], variant)
                # Check for crib fragments (can't use standard positions)
                ene_count = sum(1 for c in "EASTNORTHEAST" if c in pt)
                bc_count = sum(1 for c in "BERLINCLOCK" if c in pt)
                if ene_count >= 10 and bc_count >= 8:  # high letter overlap
                    all_results.append((ene_count + bc_count, f"mask({name})+{variant.value}(k={k})",
                                      f"nulls={null_positions[:5]}...", pt[:40]))

    # ── Strategy 4: The 73.4° bearing as the KEY angle ──
    print("\n── Strategy 4: 73.4° bearing — direct key tests ──")

    # The SC×K2/ENE intersection bearing of 73.4° might encode the key
    key_angle = 73.4

    # 73 mod 26 = 21 → position 21 = start of EASTNORTHEAST!
    print(f"  73 mod 26 = {73 % 26} → position {73 % 26} = START of EASTNORTHEAST crib!")
    print(f"  73.4° bearing points to intersection of SC→K2 and ENE lodestone line")

    # Try 73 as a key element in various ways
    for period in range(1, 14):
        key73 = [73 % 26]  # = [21] = V
        # Pad to period length with other geometric values
        geo_vals = [73, 45, 53, 85, 100, 65, 39, 7, 32, 142, 64, 54, 8]
        key = [(geo_vals[i % len(geo_vals)]) % 26 for i in range(period)]

        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            if sc >= 3:
                key_str = ''.join(ALPH[k] for k in key)
                all_results.append((sc, f"{variant.value}(key={key_str})",
                                  f"p{period}_73geo", pt[:40]))

    # ── Strategy 5: K2 coordinate digits as transposition key ──
    print("\n── Strategy 5: Coordinate digits as transposition ──")

    # K2: 38 57 6.5 N, 77 8 44 W → digits 3,8,5,7,6,5,7,7,8,4,4
    # LOOMIS: 38 57 6.22 N, 77 8 48.14 W

    coord_sequences = {
        "K2_digits": [3,8,5,7,6,5,7,7,8,4,4],
        "K2_dms":    [38,57,6,5,77,8,44],
        "LOOMIS_lat_dms": [38,57,6,2,2],
        "LOOMIS_lon_dms": [77,8,48,1,4],
        "ABBOTT_az": [4,5,5,8],
        "ABBOTT_az_dms": [45,34,46],
    }

    for name, digits in coord_sequences.items():
        # Use digits as column order for matching width
        width = len(digits)
        if width < 2 or width > CT_LEN:
            continue

        # Check if digits form a valid permutation for this width
        max_d = max(digits)
        if max_d >= width:
            # Map to ranks
            ranked = sorted(range(len(digits)), key=lambda i: (digits[i], i))
            order = [0] * len(digits)
            for rank, idx in enumerate(ranked):
                order[idx] = rank
        else:
            order = digits

        if len(set(order)) == width:
            intermediate = columnar_unread(CT, width, order)
            result = test_transposition_then_sub(intermediate, f"coord_trans({name},w={width})")
            if result[0] >= 2:
                all_results.append(result)

    # ── Results ──
    print(f"\n{'=' * 80}")
    print(f"ALL RESULTS (score >= 3)")
    print(f"{'=' * 80}")

    all_results.sort(key=lambda x: -x[0])
    for sc, method, label, preview in all_results[:30]:
        print(f"  {sc:3d}/24  {method:40s}  {label:30s}  {preview}")

    best = all_results[0][0] if all_results else 0
    print(f"\nBest overall: {best}/24")

    if best < 10:
        print(f"\nAll noise. But important observation:")
        print(f"  73 mod 26 = {73 % 26} = position of EASTNORTHEAST crib start")
        print(f"  The SC→K2 × LODESTONE_ENE intersection bearing (73.4°)")
        print(f"  encodes BOTH the 73-char hypothesis AND the ENE crib position")
        print(f"  This may be a GEOMETRIC CONFIRMATION of the 73-char model")
        print(f"  rather than direct key material")


if __name__ == '__main__':
    main()
