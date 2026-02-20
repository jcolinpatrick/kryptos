#!/usr/bin/env python3
"""E-S-60: Coordinate and Date-Derived Key Experiments.

Use K2's embedded coordinates (38°57'6.5"N, 77°8'44"W) and historical dates
(1986 Egypt trip, 1989 Berlin Wall fall) to derive cipher keys.

Test each derived key as:
1. Vigenère/Beaufort key (direct mod 26)
2. Column ordering for width-7 transposition
3. Combined: width-7 transposition + coordinate-derived Vigenère key
4. Position offset for running key

Also tests: compass-derived keys from "What's the point?", degree/minute/second
arithmetic, concatenated digit sequences.
"""
import json
import time
import sys
import os
from collections import Counter
from itertools import permutations

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_IDX = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)

# Known Vigenère keystream at crib positions
VIG_KEY = {}
for i, pos in enumerate(range(21, 34)):
    VIG_KEY[pos] = VIGENERE_KEY_ENE[i]
for i, pos in enumerate(range(63, 74)):
    VIG_KEY[pos] = VIGENERE_KEY_BC[i]

BEAU_KEY = {}
for i, pos in enumerate(range(21, 34)):
    BEAU_KEY[pos] = BEAUFORT_KEY_ENE[i]
for i, pos in enumerate(range(63, 74)):
    BEAU_KEY[pos] = BEAUFORT_KEY_BC[i]

# ── Coordinate Data ──────────────────────────────────────────────────────

# K2 decoded coordinates: 38°57'6.5"N, 77°8'44"W
# (These point to a location near the Kryptos sculpture at CIA HQ)

COORD_DATA = {
    "lat_deg": 38, "lat_min": 57, "lat_sec": 6.5,
    "lon_deg": 77, "lon_min": 8, "lon_sec": 44,
    "lat_dir": "N",  # N=13 (0-indexed)
    "lon_dir": "W",  # W=22 (0-indexed)
}

# Digit sequences from coordinates
COORD_DIGITS = {
    "lat_full": [3, 8, 5, 7, 6, 5],        # 38 57 6.5 → 385765
    "lon_full": [7, 7, 8, 4, 4],            # 77 8 44 → 77844
    "all_digits": [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],  # concatenated
    "all_no_decimal": [3, 8, 5, 7, 0, 6, 5, 7, 7, 0, 8, 4, 4],  # with separators
    "deg_min_sec": [38, 57, 6, 77, 8, 44],  # as raw numbers
    "deg_only": [38, 77],
    "min_only": [57, 8],
    "sec_only": [6, 44],                     # or [7, 44] rounding 6.5→7
    "sec_rounded": [7, 44],
}

# Date-derived sequences
DATE_KEYS = {
    "berlin_wall_1989": [1, 9, 8, 9],
    "berlin_wall_110989": [1, 1, 0, 9, 8, 9],    # 11/09/1989
    "berlin_wall_091189": [0, 9, 1, 1, 8, 9],    # 09/11/1989 (European)
    "egypt_1986": [1, 9, 8, 6],
    "both_years": [1, 9, 8, 6, 1, 9, 8, 9],
    "year_diff": [3],                              # 1989-1986=3
    "berlin_digits_mod26": [11, 9, 89 % 26],      # 11, 09, 89→11 mod 26
    "nov9": [14, 9],                               # N=14(1-indexed), 9
    "dedication_1990": [1, 9, 9, 0],
    "dedication_110390": [1, 1, 0, 3, 9, 0],      # 11/03/1990
}

# Compass-derived from "What's the point?"
COMPASS_KEYS = {
    "NESW": [13, 4, 18, 22],                # N=13,E=4,S=18,W=22 (0-indexed)
    "NEWS": [13, 4, 22, 18],
    "NSEW": [13, 18, 4, 22],
    "ENE": [4, 13, 4],                       # EASTNORTHEAST compass bearing
    "NE": [13, 4],
    "compass_67_5": [6, 7, 5],              # ENE = 67.5 degrees
    "compass_deg": [0, 6, 7],               # 067 degrees (ENE bearing)
    "bearing_248": [2, 4, 8],               # WSW = 247.5 → 248
}

# Letter-value keys from coordinate words
WORD_KEYS = {
    "NORTH": [13, 14, 17, 19, 7],
    "EAST": [4, 0, 18, 19],
    "SOUTH": [18, 14, 20, 19, 7],
    "WEST": [22, 4, 18, 19],
    "NORTHEAST": [13, 14, 17, 19, 7, 4, 0, 18, 19],
    "EASTNORTHEAST": [4, 0, 18, 19, 13, 14, 17, 19, 7, 4, 0, 18, 19],
    "BERLINCLOCK": [1, 4, 17, 11, 8, 13, 2, 11, 14, 2, 10],
    "POINT": [15, 14, 8, 13, 19],
    "THEPOINT": [19, 7, 4, 15, 14, 8, 13, 19],
    "WHATSTHEPOINT": [22, 7, 0, 19, 18, 19, 7, 4, 15, 14, 8, 13, 19],
    "KRYPTOS": [10, 17, 24, 15, 19, 14, 18],
    "PALIMPSEST": [15, 0, 11, 8, 12, 15, 18, 4, 18, 19],
    "ABSCISSA": [0, 1, 18, 2, 8, 18, 18, 0],
    "CIA": [2, 8, 0],
    "LANGLEY": [11, 0, 13, 6, 11, 4, 24],
    "SCHEIDT": [18, 2, 7, 4, 8, 3, 19],
    "SANBORN": [18, 0, 13, 1, 14, 17, 13],
    "EGYPT": [4, 6, 24, 15, 19],
    "BERLIN": [1, 4, 17, 11, 8, 13],
    "DELIVER": [3, 4, 11, 8, 21, 4, 17],
    "MESSAGE": [12, 4, 18, 18, 0, 6, 4],
}

# Arithmetic combinations
ARITH_KEYS = {
    "lat+lon_mod26": [(38 + 77) % 26, (57 + 8) % 26, (7 + 44) % 26],  # [11, 13, 25]
    "lat-lon_mod26": [(38 - 77) % 26, (57 - 8) % 26, (7 - 44) % 26],  # [13, 23, 15]
    "lat*lon_mod26": [(38 * 77) % 26, (57 * 8) % 26, (7 * 44) % 26],  # [16, 14, 22]
    "coord_interleave": [3, 7, 8, 7, 5, 8, 7, 4, 6, 4, 5],            # interleave lat/lon digits
    "dms_sum": [38 + 57 + 7, 77 + 8 + 44],  # [102, 129]
    "dms_sum_mod26": [(38 + 57 + 7) % 26, (77 + 8 + 44) % 26],  # [24, 25]
}


def columnar_perm(order, text_len):
    """Standard columnar transposition permutation."""
    width = len(order)
    n_full_rows = text_len // width
    extra = text_len % width
    col_heights = [n_full_rows + (1 if c < extra else 0) for c in range(width)]
    perm = []
    for read_idx in range(width):
        col = order[read_idx]
        for row in range(col_heights[col]):
            pt_pos = row * width + col
            perm.append(pt_pos)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def score_key_sequence(key_seq, variant="vig"):
    """Score a key sequence against known keystream at crib positions.

    key_seq: list of int values, applied cyclically starting at position 0.
    Returns (matches, bean_pass).
    """
    known = VIG_KEY if variant == "vig" else BEAU_KEY
    period = len(key_seq)
    if period == 0:
        return 0, False

    matches = 0
    for pos in CRIB_POS_SORTED:
        expected = known[pos]
        actual = key_seq[pos % period]
        if actual % MOD == expected:
            matches += 1

    # Bean check
    bean_pass = True
    for p1, p2 in BEAN_EQ:
        k1 = key_seq[p1 % period] % MOD
        k2 = key_seq[p2 % period] % MOD
        if k1 != k2:
            bean_pass = False

    return matches, bean_pass


def score_key_at_positions(key_at_pos, variant="vig"):
    """Score key values assigned to specific positions."""
    known = VIG_KEY if variant == "vig" else BEAU_KEY
    matches = 0
    for pos in CRIB_POS_SORTED:
        if pos in key_at_pos:
            if key_at_pos[pos] % MOD == known[pos]:
                matches += 1
    return matches


def score_with_transposition(order, key_seq, variant="vig"):
    """Score: width-7 columnar transposition (Model B: trans→sub) + periodic key.

    Model B: CT[i] = Sub(PT[perm[i]], k[i])
    So k[i] = CT[i] - PT[perm[i]] (Vig) or CT[i] + PT[perm[i]] (Beau)

    We check: does k[i] = key_seq[i % period] at positions where perm[i] is a crib?
    """
    perm = columnar_perm(order, CT_LEN)
    period = len(key_seq)
    if period == 0:
        return 0, False

    matches = 0
    for ct_pos in range(CT_LEN):
        pt_pos = perm[ct_pos]
        if pt_pos in PT_IDX:
            # Derive key at ct_pos
            if variant == "vig":
                k_actual = (CT_IDX[ct_pos] - PT_IDX[pt_pos]) % MOD
            else:
                k_actual = (CT_IDX[ct_pos] + PT_IDX[pt_pos]) % MOD
            k_expected = key_seq[ct_pos % period] % MOD
            if k_actual == k_expected:
                matches += 1

    # Bean check (under transposition, Bean applies to transposed positions)
    bean_pass = True
    # Under Model B, we need k[inv_perm[27]] = k[inv_perm[65]]
    # where k is applied at CT positions
    inv_perm = invert_perm(perm)
    for p1, p2 in BEAN_EQ:
        ct1, ct2 = inv_perm[p1], inv_perm[p2]
        k1 = key_seq[ct1 % period] % MOD
        k2 = key_seq[ct2 % period] % MOD
        if k1 != k2:
            bean_pass = False

    return matches, bean_pass


def test_all_keys_direct():
    """Phase A: Test all key sequences as direct periodic Vigenère/Beaufort keys."""
    print("=" * 70)
    print("PHASE A: Direct Periodic Key Application (no transposition)")
    print("=" * 70)

    all_keys = {}
    all_keys.update({f"coord_{k}": v for k, v in COORD_DIGITS.items()})
    all_keys.update({f"date_{k}": v for k, v in DATE_KEYS.items()})
    all_keys.update({f"compass_{k}": v for k, v in COMPASS_KEYS.items()})
    all_keys.update({f"word_{k}": v for k, v in WORD_KEYS.items()})
    all_keys.update({f"arith_{k}": v for k, v in ARITH_KEYS.items()})

    results = []

    for name, key_seq in sorted(all_keys.items()):
        for variant in ["vig", "beau"]:
            # Test key as-is (mod 26)
            key_mod = [v % MOD for v in key_seq]
            m, bp = score_key_sequence(key_mod, variant)
            results.append((m, name, variant, "direct", key_mod, bp))

            # Test shifted by each value 0-25
            for shift in range(1, 26):
                key_shifted = [(v + shift) % MOD for v in key_seq]
                m2, bp2 = score_key_sequence(key_shifted, variant)
                if m2 > m:
                    results.append((m2, name, variant, f"shift+{shift}", key_shifted, bp2))

    results.sort(key=lambda x: -x[0])

    print(f"\n  Total tests: {len(results)}")
    print(f"\n  Top 15 by crib matches:")
    for i, (m, name, var, mode, key, bp) in enumerate(results[:15]):
        bean_flag = "BEAN" if bp else "    "
        key_str = ','.join(str(v) for v in key[:10])
        if len(key) > 10:
            key_str += "..."
        print(f"  {i+1:3d}. {m:2d}/24 {bean_flag} {var:4s} {mode:12s} {name:30s} [{key_str}]")

    # Expected: period-dependent noise. Report expected random for each period.
    periods_seen = set(len(v) for v in all_keys.values())
    print(f"\n  Key periods tested: {sorted(periods_seen)}")
    for p in sorted(periods_seen):
        # Expected matches for period p: 24 * (1/26) * (period coverage)
        # But with cycling, each residue class has ~97/p positions
        # Number of crib hits at period p = sum over crib pos: P(key[pos%p] matches)
        # If period covers all 24 cribs: expected = 24/26 ≈ 0.92
        # Actually: for periodic key of period p, each of the 24 cribs is independently 1/26
        # Expected = 24/26 ≈ 0.92 for shift-optimized (but we test 26 shifts!)
        # With 26 shifts: expected best ≈ ?
        n_residues = min(p, 24)  # number of distinct residue classes hit by cribs
        # Each residue constrains independently. Probability all match = (1/26)^n_residues
        # Over 26 shifts: P(at least one shift matches all) = 1-(1-(1/26)^n_residues)^26
        # For n_residues>=3, this is ~0. So expected best is much less than 24.
        print(f"    Period {p:2d}: {n_residues} independent constraints from 24 cribs")

    return results


def test_transposition_plus_key():
    """Phase B: Test coordinate/date keys combined with width-7 transposition."""
    print("\n" + "=" * 70)
    print("PHASE B: Width-7 Transposition (Model B) + Periodic Key")
    print("=" * 70)

    # Select most promising key sequences (short periods for meaningful discrimination)
    candidate_keys = {}
    for name, seq in COORD_DIGITS.items():
        candidate_keys[f"coord_{name}"] = seq
    for name, seq in DATE_KEYS.items():
        candidate_keys[f"date_{name}"] = seq
    for name, seq in COMPASS_KEYS.items():
        candidate_keys[f"compass_{name}"] = seq
    for name, seq in WORD_KEYS.items():
        if len(seq) <= 14:  # Only test periods ≤ 14 (meaningful discrimination)
            candidate_keys[f"word_{name}"] = seq
    for name, seq in ARITH_KEYS.items():
        candidate_keys[f"arith_{name}"] = seq

    results = []
    n_tested = 0
    t0 = time.time()

    # Test all 5040 width-7 orderings × candidate keys × variants × shifts
    for order in permutations(range(7)):
        order = list(order)
        for name, key_seq in candidate_keys.items():
            for variant in ["vig", "beau"]:
                key_mod = [v % MOD for v in key_seq]
                m, bp = score_with_transposition(order, key_mod, variant)
                if m >= 6 or bp:
                    results.append((m, name, variant, "direct", order, key_mod, bp))

                # Test a few promising shifts
                for shift in [1, 7, 13, 25]:
                    key_shifted = [(v + shift) % MOD for v in key_seq]
                    m2, bp2 = score_with_transposition(order, key_shifted, variant)
                    if m2 >= 6 or bp2:
                        results.append((m2, name, variant, f"shift+{shift}", order, key_shifted, bp2))

                n_tested += 5  # direct + 4 shifts

        if (list(order) == [0, 1, 2, 3, 4, 5, 6] or
            list(order) == [1, 0, 2, 3, 4, 5, 6] or
            n_tested % 100000 == 0):
            elapsed = time.time() - t0
            print(f"  [{n_tested:8d}] order={order} hits={len(results)} ({elapsed:.1f}s)")

    results.sort(key=lambda x: -x[0])
    elapsed = time.time() - t0

    print(f"\n  Total tested: {n_tested} ({elapsed:.1f}s)")
    print(f"  Hits (≥6 or Bean): {len(results)}")

    if results:
        print(f"\n  Top 15:")
        for i, (m, name, var, mode, order, key, bp) in enumerate(results[:15]):
            bean_flag = "BEAN" if bp else "    "
            key_str = ','.join(str(v) for v in key[:8])
            print(f"  {i+1:3d}. {m:2d}/24 {bean_flag} {var:4s} {mode:10s} order={order} "
                  f"{name:25s} [{key_str}]")

    # Bean-passing configs
    bean_hits = [r for r in results if r[6]]
    if bean_hits:
        print(f"\n  Bean-passing ({len(bean_hits)}):")
        for m, name, var, mode, order, key, bp in bean_hits[:10]:
            print(f"    {m:2d}/24 {var:4s} {mode:10s} order={order} {name}")

    return results


def test_key_as_column_order():
    """Phase C: Use coordinate/date values to derive column orderings."""
    print("\n" + "=" * 70)
    print("PHASE C: Coordinate-Derived Column Orderings")
    print("=" * 70)

    # Generate width-7 orderings from coordinate data
    orderings = {}

    # Method 1: Sort digits to get ordering
    for name, digits in COORD_DIGITS.items():
        if len(digits) >= 7:
            # Take first 7, sort to get order
            d7 = digits[:7]
            indexed = sorted(range(7), key=lambda i: (d7[i], i))
            orderings[f"sort_{name}"] = indexed

    # Method 2: Direct mod 7
    for name, digits in {**COORD_DIGITS, **DATE_KEYS}.items():
        if len(digits) >= 7:
            order = [d % 7 for d in digits[:7]]
            # Check if it's a valid permutation
            if sorted(order) == list(range(7)):
                orderings[f"mod7_{name}"] = order

    # Method 3: Known keyword orderings
    keywords_7 = {
        "KRYPTOS": [0, 5, 3, 1, 6, 4, 2],  # K3's key
        "PALIMPS": [4, 0, 3, 2, 5, 6, 1],   # First 7 of PALIMPSEST
        "ABSCISS": [0, 1, 6, 2, 3, 5, 4],   # First 7 of ABSCISSA
        "SCHEIDT": [5, 1, 3, 2, 4, 0, 6],
        "SANBORN": [5, 0, 4, 1, 3, 6, 2],
        "LANGLEY": [3, 0, 4, 2, 5, 1, 6],
        "DELIVER": [0, 1, 4, 3, 6, 2, 5],
        "MESSAGE": [3, 1, 5, 6, 0, 2, 4],
        "WHATSTH": [6, 2, 0, 5, 4, 3, 1],
        "THEPOIN": [5, 2, 1, 4, 3, 0, 6],
        "COMPASS": [0, 3, 2, 4, 1, 5, 6],
        "BERLINN": [0, 2, 5, 3, 1, 4, 6],  # BERLIN + N
        "EGYPTRI": [2, 3, 6, 4, 5, 1, 0],  # EGYPT + RI
        "CLOCKKK": [0, 3, 4, 1, 2, 5, 6],  # CLOCK + KK
    }
    orderings.update(keywords_7)

    # Method 4: Coordinate-derived orderings
    orderings["coord_lat_dms"] = [3 % 7, 8 % 7, 5 % 7, 7 % 7, 6 % 7, 5 % 7, 0]  # padded
    orderings["coord_38577"] = [3, 8 % 7, 5, 7 % 7, 7 % 7, 0, 0]  # not valid perm, skip

    # Filter to valid permutations only
    valid_orderings = {}
    for name, order in orderings.items():
        if sorted(order) == list(range(7)):
            valid_orderings[name] = order

    print(f"  Valid width-7 orderings: {len(valid_orderings)}")

    results = []

    # For each ordering, test with various periodic keys
    key_sources = {}
    key_sources.update({f"coord_{k}": v for k, v in COORD_DIGITS.items()})
    key_sources.update({f"date_{k}": v for k, v in DATE_KEYS.items()})
    key_sources.update({f"compass_{k}": v for k, v in COMPASS_KEYS.items()})
    # Also test no periodic key (identity)
    key_sources["identity"] = [0]  # No substitution offset

    for order_name, order in sorted(valid_orderings.items()):
        for key_name, key_seq in key_sources.items():
            for variant in ["vig", "beau"]:
                key_mod = [v % MOD for v in key_seq]
                m, bp = score_with_transposition(order, key_mod, variant)
                if m >= 5 or bp:
                    results.append((m, order_name, key_name, variant, order, key_mod, bp))

    results.sort(key=lambda x: -x[0])

    print(f"  Total keyword combos: {len(valid_orderings) * len(key_sources) * 2}")
    print(f"  Hits (≥5 or Bean): {len(results)}")

    if results:
        print(f"\n  Top 15:")
        for i, (m, oname, kname, var, order, key, bp) in enumerate(results[:15]):
            bean_flag = "BEAN" if bp else "    "
            print(f"  {i+1:3d}. {m:2d}/24 {bean_flag} {var:4s} order={order} "
                  f"col={oname:15s} key={kname}")

    return results


def test_position_offset_keys():
    """Phase D: Test coordinate values as position offsets for key derivation."""
    print("\n" + "=" * 70)
    print("PHASE D: Position-Offset Key Derivation")
    print("=" * 70)

    # Hypothesis: key[i] = f(i + offset) where offset comes from coordinates
    # Or: key[i] = coordinate_digit[(i + offset) mod n]

    offsets = [0, 6, 7, 21, 38, 44, 57, 63, 65, 77]
    results = []

    # Test 1: Key is coordinate digits cycled from various offsets
    coord_seqs = {
        "lat385765": [3, 8, 5, 7, 6, 5],
        "lon77844": [7, 7, 8, 4, 4],
        "all38576577844": [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],
        "reversed": [4, 4, 8, 7, 7, 5, 6, 7, 5, 8, 3],
    }

    for name, seq in coord_seqs.items():
        period = len(seq)
        for offset in offsets:
            for variant in ["vig", "beau"]:
                # Key at position i = seq[(i + offset) % period]
                key_at_pos = {}
                for pos in CRIB_POS_SORTED:
                    key_at_pos[pos] = seq[(pos + offset) % period]

                m = score_key_at_positions(key_at_pos, variant)
                if m >= 4:
                    results.append((m, name, variant, f"offset={offset}", None, False))

    # Test 2: Key is position-derived: k[i] = (a*i + b) mod 26 where a,b from coords
    for a in [3, 5, 6, 7, 8, 38, 44, 57, 77]:
        for b in [0, 3, 5, 6, 7, 8, 38, 44, 57, 77]:
            for variant in ["vig", "beau"]:
                known = VIG_KEY if variant == "vig" else BEAU_KEY
                matches = sum(1 for pos in CRIB_POS_SORTED
                            if (a * pos + b) % MOD == known[pos])
                if matches >= 4:
                    results.append((matches, f"linear_a={a}_b={b}", variant, "linear", None, False))

    # Test 3: Key is quadratic: k[i] = (a*i^2 + b*i + c) mod 26
    for a in [1, 3, 5, 7]:
        for b in [0, 3, 7, 13, 19]:
            for c in [0, 6, 8, 38, 44, 57, 77]:
                for variant in ["vig", "beau"]:
                    known = VIG_KEY if variant == "vig" else BEAU_KEY
                    matches = sum(1 for pos in CRIB_POS_SORTED
                                if (a * pos * pos + b * pos + c) % MOD == known[pos])
                    if matches >= 5:
                        results.append((matches, f"quad_a={a}_b={b}_c={c}", variant, "quadratic", None, False))

    results.sort(key=lambda x: -x[0])

    print(f"  Hits (≥4): {len(results)}")
    if results:
        print(f"\n  Top 15:")
        for i, (m, name, var, mode, _, bp) in enumerate(results[:15]):
            print(f"  {i+1:3d}. {m:2d}/24 {var:4s} {mode:12s} {name}")

    return results


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-60: Coordinate and Date-Derived Key Experiments")
    print("=" * 70)
    print(f"Coordinates: 38°57'6.5\"N, 77°8'44\"W")
    print(f"Dates: 1986 Egypt, 11/9/1989 Berlin Wall")
    print(f"Clue: \"What's the point?\"")
    print()

    results_a = test_all_keys_direct()
    results_b = test_transposition_plus_key()
    results_c = test_key_as_column_order()
    results_d = test_position_offset_keys()

    elapsed = time.time() - t0

    # Overall summary
    print("\n" + "=" * 70)
    print("OVERALL SUMMARY")
    print("=" * 70)

    all_results = []
    for m, name, var, mode, key, bp in results_a[:10]:
        all_results.append((m, f"A:{name}", var, mode, bp))
    for r in results_b[:10]:
        all_results.append((r[0], f"B:{r[1]}", r[2], r[3], r[6]))
    for r in results_c[:10]:
        all_results.append((r[0], f"C:{r[1]}+{r[2]}", r[3], "col_order", r[6]))
    for r in results_d[:10]:
        all_results.append((r[0], f"D:{r[1]}", r[2], r[3], r[5]))

    all_results.sort(key=lambda x: -x[0])

    best_score = all_results[0][0] if all_results else 0
    n_bean = sum(1 for r in all_results if r[4])

    print(f"  Best score: {best_score}/24")
    print(f"  Bean-passing: {n_bean}")
    print(f"  Time: {elapsed:.1f}s")

    # Expected random at various periods
    print(f"\n  Context: Expected random best (with 26 shifts) ~3-5/24 for short periods")

    if best_score >= 8:
        verdict = f"INTERESTING — best {best_score}/24, investigate"
    elif best_score >= 6:
        verdict = f"MARGINAL — best {best_score}/24, likely noise"
    else:
        verdict = f"NO SIGNAL — best {best_score}/24 = noise floor"

    print(f"\n  Verdict: {verdict}")

    # Save artifact
    artifact = {
        "experiment": "E-S-60",
        "description": "Coordinate and date-derived key experiments",
        "elapsed_seconds": elapsed,
        "best_score": best_score,
        "n_bean": n_bean,
        "verdict": verdict,
        "top_results": [{"score": m, "name": n, "variant": v, "mode": mode, "bean": bp}
                       for m, n, v, mode, bp in all_results[:50]],
        "phase_a_top": [{"score": r[0], "name": r[1], "variant": r[2], "mode": r[3],
                         "bean": r[5]} for r in results_a[:20]],
        "phase_b_top": [{"score": r[0], "name": r[1], "variant": r[2], "mode": r[3],
                         "order": r[4], "bean": r[6]} for r in results_b[:20]],
        "phase_c_top": [{"score": r[0], "col_order": r[1], "key": r[2], "variant": r[3],
                         "order": r[4], "bean": r[6]} for r in results_c[:20]],
        "phase_d_top": [{"score": r[0], "name": r[1], "variant": r[2], "mode": r[3],
                         "bean": r[5]} for r in results_d[:20]],
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_60_coordinate_date_keys.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_60_coordinate_date_keys.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_60_coordinate_date_keys.py")


if __name__ == "__main__":
    main()
