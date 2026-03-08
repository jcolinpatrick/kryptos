#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""blitz_coordinates_key.py — K2 coordinates as numerical key material for K4.

Tests all numerical derivations of the K2 coordinates (38°57'6.5"N, 77°8'44"W)
and Berlin coordinates (52°31'12"N, 13°24'18"E) as Vigenere/Beaufort keys.

Derivations tested:
  1. Raw DMS components as shifts (mod 26)
  2. Decimal degree digit sequences
  3. Sums, differences, products of components
  4. Grid dimensions (38×, 77×, etc.)
  5. Berlin minus CIA coordinate differences
  6. Coordinate digits as letter positions
  7. Digit sequences from various representations
  8. Compass bearings and angles
  9. UTM-like numeric sequences
 10. Cross-coordinate derivations (lat×lon, etc.)
 11. Timezone differences (Berlin=UTC+1, CIA=UTC-5)
 12. Special numbers: 6.5×2=13, 44=position in K4, etc.
 13. Keys from coordinate substrings mapped to alphabet
 14. Coordinate-derived transposition permutations

Run: PYTHONPATH=src python3 -u scripts/blitz/blitz_coordinates_key.py
"""
from __future__ import annotations

import sys
import os
import json
import time
import math
import itertools
from collections import defaultdict
from pathlib import Path
from typing import List, Tuple, Dict, Any

sys.path.insert(0, 'scripts')
from kbot_harness import (
    test_perm, test_unscramble, score_text, score_text_per_char,
    has_cribs, vig_decrypt, beau_decrypt, apply_permutation,
    K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
N = 97

# K2 Coordinates: 38°57'6.5"N, 77°8'44"W
CIA_LAT_D, CIA_LAT_M, CIA_LAT_S = 38, 57, 6.5
CIA_LON_D, CIA_LON_M, CIA_LON_S = 77, 8, 44
CIA_LAT_DEC = 38 + 57/60 + 6.5/3600   # 38.951806
CIA_LON_DEC = 77 + 8/60 + 44/3600     # 77.145556

# Berlin Weltzeituhr: 52°31'12"N, 13°24'18"E
BER_LAT_D, BER_LAT_M, BER_LAT_S = 52, 31, 12
BER_LON_D, BER_LON_M, BER_LON_S = 13, 24, 18
BER_LAT_DEC = 52 + 31/60 + 12/3600    # 52.520000
BER_LON_DEC = 13 + 24/60 + 18/3600    # 13.405000

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

results: List[Dict[str, Any]] = []
best_score = -99999.0
best_result: Dict[str, Any] | None = None
configs_tested = 0
REPORT_THRESHOLD = -5.5  # per-char threshold for reporting

def nums_to_key(nums: List[int], name: str) -> str:
    """Convert list of ints to key string via mod 26 -> AZ letter."""
    return "".join(AZ[n % 26] for n in nums)

def test_key(key: str, label: str, alpha_name: str = "AZ", alpha: str = AZ):
    """Test a key against K4 with Vigenere and Beaufort."""
    global configs_tested, best_score, best_result
    if not key or len(key) == 0:
        return

    for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
        try:
            pt = cipher_fn(K4_CARVED, key, alpha)
        except (ValueError, IndexError):
            continue

        configs_tested += 1
        sc = score_text(pt)
        sc_per = score_text_per_char(pt)
        crib_hits = has_cribs(pt)

        if crib_hits:
            entry = {
                "label": label, "key": key, "key_len": len(key),
                "cipher": cipher_name, "alpha": alpha_name,
                "score": sc, "score_per_char": sc_per,
                "crib_hits": crib_hits, "pt_snippet": pt[:40],
                "pt_full": pt,
            }
            print(f"\n{'='*70}")
            print(f"*** CRIB HIT *** {label}")
            print(f"  Key: {key} | Cipher: {cipher_name}/{alpha_name}")
            print(f"  Score: {sc:.1f} ({sc_per:.3f}/char)")
            print(f"  Cribs: {crib_hits}")
            print(f"  PT: {pt}")
            print(f"{'='*70}\n")
            results.append(entry)

        if sc > best_score:
            best_score = sc
            best_result = {
                "label": label, "key": key, "key_len": len(key),
                "cipher": cipher_name, "alpha": alpha_name,
                "score": sc, "score_per_char": sc_per,
                "pt_snippet": pt[:50], "pt_full": pt,
            }

        if sc_per > REPORT_THRESHOLD:
            entry = {
                "label": label, "key": key, "key_len": len(key),
                "cipher": cipher_name, "alpha": alpha_name,
                "score": sc, "score_per_char": sc_per,
                "pt_snippet": pt[:50],
            }
            results.append(entry)

def test_key_both_alphas(key: str, label: str):
    """Test key against both AZ and KA alphabets."""
    test_key(key, label + " [AZ]", "AZ", AZ)
    test_key(key, label + " [KA]", "KA", KA)

def test_numeric_key(nums: List[int], label: str):
    """Convert numbers to key letters (mod 26) and test."""
    key = nums_to_key(nums, label)
    test_key_both_alphas(key, label)

def ints_to_digits(nums: List[int]) -> List[int]:
    """Flatten list of ints to individual digits."""
    digits = []
    for n in nums:
        for ch in str(abs(n)):
            digits.append(int(ch))
    return digits

# ─────────────────────────────────────────────────────────────────────────────
# 1. RAW DMS COMPONENTS AS SHIFTS
# ─────────────────────────────────────────────────────────────────────────────
def test_raw_dms():
    print("\n=== 1. RAW DMS COMPONENTS ===")

    # CIA coordinates: 38, 57, 6, 5, 77, 8, 44
    cia_raw = [38, 57, 6, 5, 77, 8, 44]
    test_numeric_key(cia_raw, "CIA raw DMS [38,57,6,5,77,8,44]")

    # Just the numbers as appearing: 3,8,5,7,6,5,7,7,8,4,4
    cia_digits = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
    test_numeric_key(cia_digits, "CIA all digits")

    # Berlin: 52, 31, 12, 13, 24, 18
    ber_raw = [52, 31, 12, 13, 24, 18]
    test_numeric_key(ber_raw, "Berlin raw DMS")

    ber_digits = [5, 2, 3, 1, 1, 2, 1, 3, 2, 4, 1, 8]
    test_numeric_key(ber_digits, "Berlin all digits")

    # Both combined
    both = cia_raw + ber_raw
    test_numeric_key(both, "CIA+Berlin raw DMS combined")

    both_digits = cia_digits + ber_digits
    test_numeric_key(both_digits, "CIA+Berlin all digits combined")

    # Just latitude components
    test_numeric_key([38, 57, 6], "CIA lat only [38,57,6]")
    test_numeric_key([77, 8, 44], "CIA lon only [77,8,44]")
    test_numeric_key([52, 31, 12], "Berlin lat only")
    test_numeric_key([13, 24, 18], "Berlin lon only")

    # Interleaved lat/lon
    test_numeric_key([38, 77, 57, 8, 6, 44], "CIA lat/lon interleaved")
    test_numeric_key([52, 13, 31, 24, 12, 18], "Berlin lat/lon interleaved")

    # DMS as single numbers: 385765, 77844
    for n in [385765, 77844, 523112, 132418]:
        digs = [int(d) for d in str(n)]
        test_numeric_key(digs, f"DMS concatenated {n}")

    # N=14, W=23 (positions in AZ), E=5
    test_numeric_key([38, 57, 6, 5, 14, 77, 8, 44, 23], "CIA DMS+compass letters")
    test_numeric_key([52, 31, 12, 14, 13, 24, 18, 5], "Berlin DMS+compass letters")

# ─────────────────────────────────────────────────────────────────────────────
# 2. DECIMAL DEGREES
# ─────────────────────────────────────────────────────────────────────────────
def test_decimal_degrees():
    print("\n=== 2. DECIMAL DEGREES ===")

    # 38.951806 -> digits: 3,8,9,5,1,8,0,6
    cia_lat_str = f"{CIA_LAT_DEC:.6f}"  # "38.951806"
    cia_lon_str = f"{CIA_LON_DEC:.6f}"  # "77.145556"
    ber_lat_str = f"{BER_LAT_DEC:.6f}"
    ber_lon_str = f"{BER_LON_DEC:.6f}"

    for name, val_str in [
        ("CIA lat decimal", cia_lat_str),
        ("CIA lon decimal", cia_lon_str),
        ("Berlin lat decimal", ber_lat_str),
        ("Berlin lon decimal", ber_lon_str),
    ]:
        digits = [int(d) for d in val_str if d.isdigit()]
        test_numeric_key(digits, name)

    # Combined CIA
    cia_combined = [int(d) for d in cia_lat_str + cia_lon_str if d.isdigit()]
    test_numeric_key(cia_combined, "CIA lat+lon decimal digits")

    # Combined Berlin
    ber_combined = [int(d) for d in ber_lat_str + ber_lon_str if d.isdigit()]
    test_numeric_key(ber_combined, "Berlin lat+lon decimal digits")

    # All four
    all_digits = cia_combined + ber_combined
    test_numeric_key(all_digits, "All coords decimal digits")

    # As pairs of digits -> 2-digit numbers
    for name, digs in [
        ("CIA lat pairs", [int(d) for d in cia_lat_str if d.isdigit()]),
        ("CIA lon pairs", [int(d) for d in cia_lon_str if d.isdigit()]),
    ]:
        pairs = [digs[i]*10 + digs[i+1] for i in range(0, len(digs)-1, 2)]
        test_numeric_key(pairs, name + " (2-digit pairs)")

# ─────────────────────────────────────────────────────────────────────────────
# 3. SUMS, DIFFERENCES, PRODUCTS
# ─────────────────────────────────────────────────────────────────────────────
def test_arithmetic():
    print("\n=== 3. ARITHMETIC DERIVATIONS ===")

    cia_parts = [38, 57, 6, 5, 77, 8, 44]
    ber_parts = [52, 31, 12, 13, 24, 18]

    # Sums
    cia_sum = sum(cia_parts)  # 235
    ber_sum = sum(ber_parts)  # 150
    print(f"  CIA sum={cia_sum}, Berlin sum={ber_sum}")

    # Sum mod 26
    test_numeric_key([cia_sum], f"CIA sum {cia_sum}")
    test_numeric_key([ber_sum], f"Berlin sum {ber_sum}")
    test_numeric_key([cia_sum, ber_sum], f"CIA+Berlin sums [{cia_sum},{ber_sum}]")

    # Sum digits
    test_numeric_key([int(d) for d in str(cia_sum)], f"CIA sum digits {cia_sum}")
    test_numeric_key([int(d) for d in str(ber_sum)], f"Berlin sum digits {ber_sum}")

    # Differences: Berlin - CIA
    diff_parts = [BER_LAT_D - CIA_LAT_D, BER_LAT_M - CIA_LAT_M,
                  int(BER_LAT_S - CIA_LAT_S),
                  BER_LON_D - CIA_LON_D, BER_LON_M - CIA_LON_M,
                  BER_LON_S - CIA_LON_S]
    # [14, -26, 6, -64, 16, -26]
    print(f"  Berlin-CIA diffs: {diff_parts}")
    test_numeric_key([abs(d) for d in diff_parts], "Berlin-CIA abs diffs")
    test_numeric_key(diff_parts, "Berlin-CIA signed diffs")

    # Decimal degree differences
    lat_diff = BER_LAT_DEC - CIA_LAT_DEC   # ~13.568
    lon_diff = BER_LON_DEC - CIA_LON_DEC   # ~-63.741 (negative = Berlin is east)
    lon_diff_abs = abs(lon_diff)
    print(f"  Lat diff={lat_diff:.6f}, Lon diff={lon_diff:.6f}")

    for name, val in [
        ("Lat diff decimal", lat_diff),
        ("Lon diff abs decimal", lon_diff_abs),
    ]:
        digits = [int(d) for d in f"{val:.6f}" if d.isdigit()]
        test_numeric_key(digits, name)

    # Products of DMS
    cia_lat_prod = 38 * 57 * 6  # 12996
    cia_lon_prod = 77 * 8 * 44  # 27104
    test_numeric_key([int(d) for d in str(cia_lat_prod)], f"CIA lat product {cia_lat_prod}")
    test_numeric_key([int(d) for d in str(cia_lon_prod)], f"CIA lon product {cia_lon_prod}")

    # Cross products
    test_numeric_key([38*77, 57*8, 6*44], "CIA lat×lon products")

    # Running cumulative sums
    running = []
    s = 0
    for v in cia_parts:
        s += v
        running.append(s)
    test_numeric_key(running, "CIA running sums")

    # XOR pairs
    test_numeric_key([38^77, 57^8, 6^44], "CIA XOR pairs")

    # Modular arithmetic with 97 and 26
    test_numeric_key([v % 26 for v in cia_parts], "CIA parts mod 26")
    test_numeric_key([v % 97 for v in cia_parts], "CIA parts mod 97")
    test_numeric_key([v % 26 for v in ber_parts], "Berlin parts mod 26")

# ─────────────────────────────────────────────────────────────────────────────
# 4. GRID DIMENSIONS
# ─────────────────────────────────────────────────────────────────────────────
def test_grid_dimensions():
    print("\n=== 4. GRID / TRANSPOSITION DIMENSIONS ===")

    # Use coordinate numbers as columnar transposition key lengths
    # The "key" for columnar transposition is the column read order
    # derived from the coordinate number

    dim_keys = [
        (38, "dim-38"), (57, "dim-57"), (77, "dim-77"),
        (44, "dim-44"), (13, "dim-13"), (6, "dim-6"),
        (7, "dim-7"), (8, "dim-8"),
        (65, "dim-65=6.5*10"),
    ]

    for dim, label in dim_keys:
        if dim <= 0 or dim > 97:
            continue
        # Simple columnar: write in rows of width `dim`, read by columns
        nrows = math.ceil(N / dim)
        perm = []
        for col in range(dim):
            for row in range(nrows):
                idx = row * dim + col
                if idx < N:
                    perm.append(idx)
        if len(perm) == N:
            real_ct = apply_permutation(K4_CARVED, perm)
            result = test_unscramble(real_ct)
            if result and result.get("crib_hits"):
                print(f"  *** CRIB HIT *** Columnar dim={dim}")
                print(f"  {result}")

        # Reverse column read order
        perm_rev = []
        for col in range(dim - 1, -1, -1):
            for row in range(nrows):
                idx = row * dim + col
                if idx < N:
                    perm_rev.append(idx)
        if len(perm_rev) == N:
            real_ct = apply_permutation(K4_CARVED, perm_rev)
            result = test_unscramble(real_ct)
            if result and result.get("crib_hits"):
                print(f"  *** CRIB HIT *** Columnar rev dim={dim}")
                print(f"  {result}")

    # 38×77 related: 38*77 = 2926. Interesting factorizations of 97
    # 97 is prime, so no exact grid. But with padding...
    # Try using coordinate-derived numbers as transposition key ordering
    # E.g., "385765" -> sorted digit order = key
    for coord_str, label in [
        ("385765", "CIA lat DMS concat"),
        ("77844", "CIA lon DMS concat"),
        ("385765077844", "CIA full concat"),
        ("523112", "Berlin lat DMS concat"),
        ("132418", "Berlin lon DMS concat"),
    ]:
        # Derive columnar transposition key from digit ordering
        # Each digit gets a position based on its value (stable sort)
        digits = [int(d) for d in coord_str]
        klen = len(digits)
        if klen < 2 or klen > 50:
            continue

        # Create ordering: assign rank to each position based on digit value
        indexed = sorted(range(klen), key=lambda i: (digits[i], i))
        order = [0] * klen
        for rank, idx in enumerate(indexed):
            order[idx] = rank

        # Apply this as columnar transposition key
        nrows = math.ceil(N / klen)
        perm = []
        # Read columns in the order defined by the key
        col_read_order = [i for i, _ in sorted(enumerate(order), key=lambda x: x[1])]
        for col in col_read_order:
            for row in range(nrows):
                idx = row * klen + col
                if idx < N:
                    perm.append(idx)

        if len(perm) == N and len(set(perm)) == N:
            real_ct = apply_permutation(K4_CARVED, perm)
            result = test_unscramble(real_ct)
            if result and result.get("crib_hits"):
                print(f"  *** CRIB HIT *** Columnar keyed by {label}")
                print(f"  {result}")

# ─────────────────────────────────────────────────────────────────────────────
# 5. COORDINATE DIFFERENCES (BERLIN - CIA)
# ─────────────────────────────────────────────────────────────────────────────
def test_differences():
    print("\n=== 5. BERLIN-CIA DIFFERENCES ===")

    # DMS differences
    lat_d_diff = BER_LAT_D - CIA_LAT_D  # 14
    lat_m_diff = BER_LAT_M - CIA_LAT_M  # -26
    lat_s_diff = BER_LAT_S - CIA_LAT_S  # 5.5
    lon_d_diff = BER_LON_D - CIA_LON_D  # -64
    lon_m_diff = BER_LON_M - CIA_LON_M  # 16
    lon_s_diff = BER_LON_S - CIA_LON_S  # -26

    # Various representations of differences
    diff_abs = [abs(lat_d_diff), abs(lat_m_diff), abs(int(lat_s_diff)),
                abs(lon_d_diff), abs(lon_m_diff), abs(lon_s_diff)]
    # [14, 26, 6, 64, 16, 26]

    test_numeric_key(diff_abs, "Abs differences [14,26,6,64,16,26]")

    # Interesting: 14, 26 appear
    # 14 = rows in half-grid, 26 = alphabet size
    print(f"  Note: diff abs = {diff_abs} (14=half-grid rows, 26=alpha size!)")

    # Just the digits of all differences
    diff_digits = []
    for d in diff_abs:
        for ch in str(d):
            diff_digits.append(int(ch))
    test_numeric_key(diff_digits, "Diff abs all digits")

    # Signed differences mod 26
    signed = [lat_d_diff, lat_m_diff, int(lat_s_diff), lon_d_diff, lon_m_diff, lon_s_diff]
    test_numeric_key([d % 26 for d in signed], "Signed diffs mod 26")

    # Great circle bearing from CIA to Berlin
    # Using simplified bearing formula
    lat1, lon1 = math.radians(CIA_LAT_DEC), math.radians(CIA_LON_DEC)
    lat2, lon2 = math.radians(BER_LAT_DEC), math.radians(BER_LON_DEC)
    dlon = lon2 - (-lon1)  # Note: CIA is West (negative), Berlin is East (positive)
    y = math.sin(dlon) * math.cos(lat2)
    x = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(lat2) * math.cos(dlon)
    bearing = math.degrees(math.atan2(y, x)) % 360
    print(f"  Bearing CIA->Berlin: {bearing:.2f}°")

    bearing_digits = [int(d) for d in f"{bearing:.2f}" if d.isdigit()]
    test_numeric_key(bearing_digits, f"Bearing CIA->Berlin {bearing:.2f}")

    # Great circle distance in km
    a = math.sin((lat2-lat1)/2)**2 + math.cos(lat1)*math.cos(lat2)*math.sin(dlon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    dist_km = 6371 * c
    print(f"  Distance CIA->Berlin: {dist_km:.1f} km")

    dist_digits = [int(d) for d in str(int(round(dist_km)))]
    test_numeric_key(dist_digits, f"Distance km digits {int(round(dist_km))}")

# ─────────────────────────────────────────────────────────────────────────────
# 6. COORDINATE DIGITS AS VIGENERE KEY LETTERS
# ─────────────────────────────────────────────────────────────────────────────
def test_digit_to_letter():
    print("\n=== 6. DIGITS → LETTERS ===")

    # Method 1: digit -> AZ position (0=A, 1=B, ... 9=J)
    cia_digits = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
    key1 = "".join(AZ[d] for d in cia_digits)  # DIFHGFHHIEE
    test_key_both_alphas(key1, "CIA digits 0=A")

    ber_digits = [5, 2, 3, 1, 1, 2, 1, 3, 2, 4, 1, 8]
    key2 = "".join(AZ[d] for d in ber_digits)
    test_key_both_alphas(key2, "Berlin digits 0=A")

    # Method 2: digit -> phone keypad mapping
    # 2=ABC, 3=DEF, 4=GHI, 5=JKL, 6=MNO, 7=PQRS, 8=TUV, 9=WXYZ
    phone = {0: 'A', 1: 'B', 2: 'C', 3: 'F', 4: 'I', 5: 'L',
             6: 'O', 7: 'S', 8: 'V', 9: 'Z'}
    key3 = "".join(phone[d] for d in cia_digits)
    test_key_both_alphas(key3, "CIA phone keypad")

    key4 = "".join(phone[d] for d in ber_digits)
    test_key_both_alphas(key4, "Berlin phone keypad")

    # Method 3: digit as 1-indexed (1=A, ..., 9=I, 0=Z/J/nothing)
    for zero_val, zero_label in [(0, 'A'), (25, 'Z'), (9, 'J')]:
        key = "".join(AZ[d - 1] if d > 0 else AZ[zero_val] for d in cia_digits)
        test_key_both_alphas(key, f"CIA 1-indexed 0={AZ[zero_val]}")

    # Method 4: Two-digit numbers as letter positions
    # 38=L(12), 57=E(5), 06=F(6), 05=E(5), 77=C(3), 08=H(8), 44=R(18)
    pairs_cia = [38, 57, 6, 5, 77, 8, 44]
    key5 = "".join(AZ[n % 26] for n in pairs_cia)
    test_key_both_alphas(key5, "CIA DMS values mod26 as letters")

    # Method 5: Concatenate all DMS then take 2-digit chunks
    full_cia = "38570657708440"
    for start in range(2):
        chunks = []
        i = start
        while i + 1 < len(full_cia):
            chunks.append(int(full_cia[i:i+2]))
            i += 2
        key = "".join(AZ[n % 26] for n in chunks)
        test_key_both_alphas(key, f"CIA full 2-digit chunks offset {start}")

    # Method 6: Map DMS -> specific keywords
    # 38°57 -> N38 -> row 38 of something?
    # The coordinate numbers spell something if you map to alphabet
    # 3=D, 8=I, 5=F, 7=H, 6=G, 5=F -> DIFHGF...
    # Or: using values from KA alphabet
    key6 = "".join(KA[d] for d in cia_digits)
    test_key_both_alphas(key6, "CIA digits in KA")

# ─────────────────────────────────────────────────────────────────────────────
# 7. SPECIAL NUMBER DERIVATIONS
# ─────────────────────────────────────────────────────────────────────────────
def test_special_numbers():
    print("\n=== 7. SPECIAL NUMBER DERIVATIONS ===")

    # 6.5 × 2 = 13 = len(EASTNORTHEAST)
    # 44 = K4 position 44 = letter 'J' in K4
    # 38 + 57 + 6 = 101 (prime)
    # 77 + 8 + 44 = 129
    # 38 + 77 = 115
    # 57 + 8 = 65 (=Bean eq position!)
    # 6 + 44 = 50 (=position of J in K4)
    print("  38+77=115, 57+8=65(=Bean!), 6+44=50, 38-6=32(self-encrypt!)")
    print("  65=Bean EQ pos, 32=self-encrypt S pos -- noteworthy!")

    # Use these special sums
    specials = [115, 65, 50, 32, 13, 44]
    test_numeric_key(specials, "Special sums [115,65,50,32,13,44]")

    # Permutation-relevant numbers
    test_numeric_key([57, 8, 65], "57+8=65 as key")
    test_numeric_key([38, 6, 32], "38-6=32 as key")
    test_numeric_key([6, 5, 13], "6.5*2=13 as key")

    # Fibonacci-like: each = sum of prev two, seeded with coordinates
    fib = [3, 8]
    for _ in range(20):
        fib.append((fib[-1] + fib[-2]) % 26)
    test_numeric_key(fib[:7], "Fib seed 3,8 len 7")
    test_numeric_key(fib[:8], "Fib seed 3,8 len 8")
    test_numeric_key(fib[:13], "Fib seed 3,8 len 13")

    fib2 = [7, 7]
    for _ in range(20):
        fib2.append((fib2[-1] + fib2[-2]) % 26)
    test_numeric_key(fib2[:7], "Fib seed 7,7 len 7")
    test_numeric_key(fib2[:8], "Fib seed 7,7 len 8")

    # 97 (K4 length) related
    # 97 - 38 = 59, 97 - 77 = 20
    test_numeric_key([97 - 38, 97 - 77, 97 - 57, 97 - 8], "97 minus coords")
    test_numeric_key([38 % 26, 57 % 26, 77 % 26, 8 % 26, 44 % 26], "Coords mod 26")

    # Cross-multiply lat/lon
    test_numeric_key([38*77 % 26, 57*8 % 26, 6*44 % 26], "Cross products mod 26")

    # Powers
    test_numeric_key([3**8 % 26, 5**7 % 26, 7**7 % 26, 8**4 % 26], "Digit powers mod 26")

# ─────────────────────────────────────────────────────────────────────────────
# 8. TIMEZONE AND CLOCK DERIVATIONS
# ─────────────────────────────────────────────────────────────────────────────
def test_timezone():
    print("\n=== 8. TIMEZONE / CLOCK DERIVATIONS ===")

    # Berlin = UTC+1 (CET), CIA/Langley = UTC-5 (EST)
    # Difference = 6 hours
    tz_diff = 6

    # Weltzeituhr has 24 timezone columns
    # Berlin is at hour 1 (UTC+1), CIA at hour 19 (24 - 5)
    berlin_tz_pos = 1
    cia_tz_pos = 19  # (24 - 5) = 19

    test_numeric_key([tz_diff], f"TZ diff = {tz_diff}")
    test_numeric_key([berlin_tz_pos, cia_tz_pos], "TZ positions [1,19]")
    test_numeric_key([tz_diff, berlin_tz_pos, cia_tz_pos], "TZ combo [6,1,19]")

    # 24-hour clock: 6 hours = 360/24 * 6 = 90 degrees
    test_numeric_key([90], "TZ angular diff 90°")
    test_numeric_key([9, 0], "TZ angular diff digits")

    # Clock face positions
    # If Berlin=1 o'clock, CIA=7 o'clock (on 24h) or 19
    test_numeric_key([1, 19], "Clock positions Berlin/CIA")
    test_numeric_key([1, 7], "12h clock positions")

    # 6 hour difference → could relate to period
    # KRYPTOS has 7 letters, 6 = 7-1
    test_numeric_key([6, 7, 1, 19, 24], "TZ+alpha derivations")

    # Weltzeituhr has 24 columns × N rows
    # 24 * 4 = 96 (close to 97!)
    # 24 * 5 = 120
    print(f"  24×4=96 (one short of 97!), 24×5=120")

    # Time as key: if the clock shows some specific time for Berlin/CIA
    for h in range(24):
        for m_step in [0, 15, 30, 44, 45, 57]:
            # Various time encodings
            if h < 10:
                time_digits = [0, h, m_step // 10, m_step % 10]
            else:
                time_digits = [h // 10, h % 10, m_step // 10, m_step % 10]
            key = "".join(AZ[d] for d in time_digits)
            if m_step in [44, 57]:  # Only report coordinate-linked times
                test_key_both_alphas(key, f"Time {h:02d}:{m_step:02d}")

# ─────────────────────────────────────────────────────────────────────────────
# 9. COORDINATE-DERIVED ALPHABETS AND KEYWORD KEYS
# ─────────────────────────────────────────────────────────────────────────────
def test_coordinate_keywords():
    print("\n=== 9. COORDINATE-DERIVED KEYWORDS ===")

    # "NORTH" from the coordinate directions
    # N and W from CIA, N and E from Berlin
    # NW = Northwest = bearing ~315
    # Combine with existing keywords
    coord_words = [
        "NW", "NE", "NWNE",
        "NORTHWEST", "NORTHEAST",
        "EASTNORTHEAST",  # the crib itself!
        "NORTH", "EAST", "WEST",
        "LANGLEY", "VIRGINIA", "BERLIN", "GERMANY",
        "CIA", "NCIA",
        "LATITUDE", "LONGITUDE",
        "COORDINATES", "LOCATION",
        "DEGREES", "MINUTES", "SECONDS",
    ]

    for word in coord_words:
        word = word.upper()
        if word.isalpha() and len(word) > 0:
            test_key_both_alphas(word, f"Keyword '{word}'")

    # Coordinate as spelled out: THIRTYEIGHT, FIFTYSEVEN, etc.
    spelled = [
        "THIRTYEIGHT", "FIFTYSEVEN", "SIX",
        "SEVENTYSEVEN", "EIGHT", "FORTYFOUR",
    ]
    for word in spelled:
        test_key_both_alphas(word, f"Spelled coord '{word}'")

    # Combinations of coordinate-themed keywords with KRYPTOS
    for base in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for coord_word in ["NW", "LANGLEY", "BERLIN"]:
            combined = base + coord_word
            test_key_both_alphas(combined, f"Combined '{combined}'")

    # Roman numerals of coordinates: 38=XXXVIII, 77=LXXVII
    roman_keys = ["XXXVIII", "LVII", "LXXVII", "VIII", "XLIV"]
    for r in roman_keys:
        test_key_both_alphas(r, f"Roman '{r}'")

# ─────────────────────────────────────────────────────────────────────────────
# 10. PERMUTATION FROM COORDINATES
# ─────────────────────────────────────────────────────────────────────────────
def test_coordinate_permutations():
    print("\n=== 10. COORDINATE-DERIVED PERMUTATIONS ===")

    # Generate permutations from coordinate numbers
    # Method 1: Use coordinate digits as seed for a linear congruential generator
    seeds = [
        (38576577844, "CIA full"),
        (523112132418, "Berlin full"),
        (385765, "CIA lat"),
        (77844, "CIA lon"),
        (389518, "CIA lat dec6"),
        (771456, "CIA lon dec6"),
    ]

    for seed_val, label in seeds:
        # LCG: x_{n+1} = (a*x_n + c) mod m
        # Use various multipliers
        for a in [3, 7, 11, 13, 17, 19, 23]:
            perm = []
            x = seed_val
            used = set()
            for _ in range(N):
                x = (a * x + 1) % (N * 1000)
                pos = x % N
                attempts = 0
                while pos in used and attempts < N * 10:
                    x = (a * x + 1) % (N * 1000)
                    pos = x % N
                    attempts += 1
                if pos in used:
                    break
                perm.append(pos)
                used.add(pos)

            if len(perm) == N and len(set(perm)) == N:
                real_ct = apply_permutation(K4_CARVED, perm)
                result = test_unscramble(real_ct)
                if result and result.get("crib_hits"):
                    print(f"  *** CRIB HIT *** LCG a={a} seed={label}")
                    print(f"  {result}")

    # Method 2: Route cipher using coordinate-sized grid
    # Write K4 into a grid, read by spiral/diagonal using coordinates
    for width in [6, 7, 8, 13, 14, 38, 44]:
        if width <= 0 or width >= N:
            continue
        height = math.ceil(N / width)

        # Spiral read from coordinate corner
        grid = []
        idx = 0
        for r in range(height):
            row = []
            for c in range(width):
                if idx < N:
                    row.append(idx)
                else:
                    row.append(-1)
                idx += 1
            grid.append(row)

        # Read by columns
        perm = []
        for c in range(width):
            for r in range(height):
                if grid[r][c] >= 0:
                    perm.append(grid[r][c])
        if len(perm) == N and len(set(perm)) == N:
            real_ct = apply_permutation(K4_CARVED, perm)
            result = test_unscramble(real_ct)
            if result and result.get("crib_hits"):
                print(f"  *** CRIB HIT *** Route cipher width={width}")

        # Read by columns reversed
        perm_rev = []
        for c in range(width - 1, -1, -1):
            for r in range(height):
                if grid[r][c] >= 0:
                    perm_rev.append(grid[r][c])
        if len(perm_rev) == N and len(set(perm_rev)) == N:
            real_ct = apply_permutation(K4_CARVED, perm_rev)
            result = test_unscramble(real_ct)
            if result and result.get("crib_hits"):
                print(f"  *** CRIB HIT *** Route cipher rev width={width}")

    # Method 3: Diagonal read of coordinate-dimensioned grid
    for width in [7, 8, 13, 14]:
        height = math.ceil(N / width)
        grid = []
        idx = 0
        for r in range(height):
            row = []
            for c in range(width):
                if idx < N:
                    row.append(idx)
                else:
                    row.append(-1)
                idx += 1
            grid.append(row)

        # Read by diagonals (top-left to bottom-right)
        perm = []
        for d in range(height + width - 1):
            for r in range(max(0, d - width + 1), min(height, d + 1)):
                c = d - r
                if 0 <= c < width and grid[r][c] >= 0:
                    perm.append(grid[r][c])

        if len(perm) == N and len(set(perm)) == N:
            real_ct = apply_permutation(K4_CARVED, perm)
            result = test_unscramble(real_ct)
            if result and result.get("crib_hits"):
                print(f"  *** CRIB HIT *** Diagonal read width={width}")

# ─────────────────────────────────────────────────────────────────────────────
# 11. AUTOKEY AND RUNNING KEY FROM COORDINATES
# ─────────────────────────────────────────────────────────────────────────────
def test_autokey():
    print("\n=== 11. AUTOKEY / RUNNING KEY FROM COORDINATES ===")

    # Autokey Vigenere: key is seed + preceding plaintext
    cia_nums = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

    for seed_len in [3, 4, 5, 6, 7, 8, 11]:
        seed = cia_nums[:seed_len] if seed_len <= len(cia_nums) else cia_nums
        seed_key = "".join(AZ[d % 26] for d in seed)

        # Autokey decrypt: PT[i] = (CT[i] - key[i]) mod 26
        # where key = seed || PT[0] || PT[1] || ...
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            pt = []
            key_stream = list(seed)
            for i, c in enumerate(K4_CARVED):
                ci = alpha.index(c)
                ki = key_stream[i] % 26
                pi = (ci - ki) % 26
                pt.append(alpha[pi])
                if i >= len(seed) - 1:
                    pass
                key_stream.append(pi)

            pt_str = "".join(pt)
            sc = score_text(pt_str)
            sc_per = score_text_per_char(pt_str)
            crib_hits = has_cribs(pt_str)

            if crib_hits or sc_per > REPORT_THRESHOLD:
                print(f"  Autokey seed={seed_key} alpha={alpha_name}")
                print(f"  Score: {sc:.1f} ({sc_per:.3f}/char)")
                if crib_hits:
                    print(f"  *** CRIB HIT *** {crib_hits}")
                    print(f"  PT: {pt_str}")

# ─────────────────────────────────────────────────────────────────────────────
# 12. COORDINATE-DERIVED MODULAR ARITHMETIC KEYS
# ─────────────────────────────────────────────────────────────────────────────
def test_modular():
    print("\n=== 12. MODULAR ARITHMETIC KEYS ===")

    # Generate keys using coordinate-seeded modular sequences
    cia_vals = [38, 57, 6, 5, 77, 8, 44]
    ber_vals = [52, 31, 12, 13, 24, 18]

    # Affine sequences: key[i] = (a*i + b) mod 26
    for a, b in [(38, 57), (77, 44), (57, 8), (38, 77), (52, 13), (31, 24),
                 (6, 5), (44, 38), (13, 18), (3, 8), (7, 7)]:
        key_nums = [(a * i + b) % 26 for i in range(26)]
        key = "".join(AZ[n] for n in key_nums)
        test_key_both_alphas(key[:7], f"Affine a={a},b={b} len7")
        test_key_both_alphas(key[:8], f"Affine a={a},b={b} len8")
        test_key_both_alphas(key[:13], f"Affine a={a},b={b} len13")

    # Polynomial: key[i] = (a*i^2 + b*i + c) mod 26
    for a, b, c in [(3, 8, 5), (7, 7, 8), (38, 57, 6), (5, 2, 13)]:
        key_nums = [(a * i * i + b * i + c) % 26 for i in range(20)]
        key = "".join(AZ[n] for n in key_nums)
        test_key_both_alphas(key[:7], f"Poly a={a},b={b},c={c} len7")
        test_key_both_alphas(key[:8], f"Poly a={a},b={b},c={c} len8")

    # Geometric: key[i] = (base^i * mult) mod 26
    for base, mult in [(3, 8), (7, 7), (5, 6), (38, 1), (77, 1), (13, 1)]:
        key_nums = []
        val = mult
        for i in range(20):
            key_nums.append(val % 26)
            val = (val * base) % (26 * 100)  # keep manageable
        key = "".join(AZ[n] for n in key_nums)
        test_key_both_alphas(key[:7], f"Geom base={base},mult={mult} len7")
        test_key_both_alphas(key[:8], f"Geom base={base},mult={mult} len8")

# ─────────────────────────────────────────────────────────────────────────────
# 13. USGS SURVEY MARKER AND OFFSET
# ─────────────────────────────────────────────────────────────────────────────
def test_usgs_marker():
    print("\n=== 13. USGS SURVEY MARKER OFFSET ===")

    # The USGS survey marker on CIA grounds that Sanborn says "remains important"
    # K2 coordinates: 38°57'6.5"N, 77°8'44"W
    # Kryptos sculpture actual location: ~38°57'6.5"N, 77°8'44"W (same as K2!)
    # But the USGS marker might be at a slightly different position
    # Common USGS markers near CIA: "Langley" benchmark

    # Try small offsets (in arc-seconds) from K2 coordinates
    # Each arc-second of latitude = ~30.87 meters
    # Sanborn might have used a specific offset

    for lat_offset_s in range(-10, 11):  # +/- 10 arc-seconds
        for lon_offset_s in range(-10, 11):
            if lat_offset_s == 0 and lon_offset_s == 0:
                continue
            new_lat_s = CIA_LAT_S + lat_offset_s  # 6.5 + offset
            new_lon_s = CIA_LON_S + lon_offset_s  # 44 + offset

            # The offset itself as a key
            if abs(lat_offset_s) + abs(lon_offset_s) <= 5:
                key_nums = [abs(lat_offset_s), abs(lon_offset_s)]
                key = "".join(AZ[n % 26] for n in key_nums)
                test_key_both_alphas(key, f"USGS offset lat={lat_offset_s}s lon={lon_offset_s}s")

    # Try treating the K2 coordinates as approximate, and the USGS marker
    # coordinates as the "true" values that Sanborn used
    # Without knowing the exact USGS marker position, test common nearby coordinates

    # Nearby rounded coordinates
    nearby_coords = [
        (38, 57, 7, 77, 8, 44, "Rounded seconds"),
        (38, 57, 6, 77, 8, 44, "Integer seconds lat"),
        (38, 57, 0, 77, 9, 0, "Rounded to minutes"),
        (38, 57, 7, 77, 8, 45, "Both rounded up"),
        (38, 57, 10, 77, 8, 40, "Round to 10s"),
    ]

    for lat_d, lat_m, lat_s, lon_d, lon_m, lon_s, label in nearby_coords:
        nums = [lat_d, lat_m, lat_s, lon_d, lon_m, lon_s]
        test_numeric_key(nums, f"USGS variant {label}")

        # Diff from K2
        diff = [lat_d - CIA_LAT_D, lat_m - CIA_LAT_M, lat_s - int(CIA_LAT_S),
                lon_d - CIA_LON_D, lon_m - CIA_LON_M, lon_s - CIA_LON_S]
        if any(d != 0 for d in diff):
            test_numeric_key([abs(d) for d in diff if d != 0], f"USGS diff {label}")

# ─────────────────────────────────────────────────────────────────────────────
# 14. CREATIVE / LATERAL DERIVATIONS
# ─────────────────────────────────────────────────────────────────────────────
def test_creative():
    print("\n=== 14. CREATIVE / LATERAL DERIVATIONS ===")

    # The text "WHO KNOWS THE EXACT LOCATION ONLY WW" from K2
    # WW = William Webster (CIA director). W=22 in AZ. WW = [22,22]
    test_numeric_key([22, 22], "WW (William Webster)")
    test_key_both_alphas("WW", "WW key")
    test_key_both_alphas("WILLIAMWEBSTER", "WILLIAMWEBSTER")
    test_key_both_alphas("WEBSTER", "WEBSTER")
    test_key_both_alphas("WILLIAM", "WILLIAM")

    # "IT'S BURIED OUT THERE SOMEWHERE" — the location IS the key
    test_key_both_alphas("BURIED", "BURIED")
    test_key_both_alphas("SOMEWHERE", "SOMEWHERE")
    test_key_both_alphas("OUTTHERE", "OUTTHERE")

    # Coordinate string literally: THIRTYEIGHTDEGREESFIFTYSEVEN...
    coord_strings = [
        "THIRTYEIGHTFIFTYSEVENSIXPOINTEIGHT",
        "THIRTYEIGHTFIFTYSEVEN",
        "SEVENTYSEVENEIGHTFORTYFOUR",
        "THIRTYSEVENEIGHT",  # Digits 3,8
        "SEVENSEVEN",  # Digits 7,7
    ]
    for s in coord_strings:
        if len(s) > 0:
            test_key_both_alphas(s, f"Coord string '{s[:20]}...'")

    # K2 plaintext contains coordinates → use the KEY from K2 as K4 key?
    # K2 was decrypted with keyword KRYPTOS and ABSCISSA
    # K2 key might contain the K4 key encoded in the coordinates

    # Try: the ciphertext at the coordinate positions in K2
    # K2 CT is known, let's use it
    # K2 positions of the coordinate digits in the plaintext would give
    # specific CT letters that could be the key

    # Integer coordinates as alphabet positions with wraparound
    # 38 mod 26 = 12 = M, 57 mod 26 = 5 = F, 6, 5, 77 mod 26 = 25 = Z,
    # 8 = I, 44 mod 26 = 18 = S
    wrap_key = "".join(AZ[n % 26] for n in [38, 57, 6, 5, 77, 8, 44])
    print(f"  Wrap key: {wrap_key}")  # MFGFZIS
    test_key_both_alphas(wrap_key, "Coord wrap mod26")

    # In KA: same but with KA alphabet
    wrap_key_ka = "".join(KA[n % 26] for n in [38, 57, 6, 5, 77, 8, 44])
    print(f"  Wrap key KA: {wrap_key_ka}")
    test_key_both_alphas(wrap_key_ka, "Coord wrap mod26 KA-mapped")

    # Sum of lat and lon components
    # 38+57+6 = 101, 77+8+44 = 129
    # 101, 129 → digits: 1,0,1,1,2,9
    test_numeric_key([1, 0, 1, 1, 2, 9], "Lat/Lon sums digits [101,129]")

    # Difference: 129 - 101 = 28 (= number of rows in master grid!)
    print("  129 - 101 = 28 = master grid rows!")
    test_numeric_key([28], "Lat-Lon sum diff = 28")
    test_numeric_key([2, 8], "Lat-Lon sum diff digits")

    # 38°57'6.5" → total seconds: 38*3600 + 57*60 + 6.5 = 140226.5
    # 77°8'44" → total seconds: 77*3600 + 8*60 + 44 = 277724
    cia_lat_total_s = 38 * 3600 + 57 * 60 + 6.5   # 140226.5
    cia_lon_total_s = 77 * 3600 + 8 * 60 + 44      # 277724
    print(f"  CIA total seconds: lat={cia_lat_total_s}, lon={cia_lon_total_s}")

    for val, label in [
        (int(cia_lat_total_s), "CIA lat total secs"),
        (cia_lon_total_s, "CIA lon total secs"),
        (int(cia_lon_total_s - cia_lat_total_s), "Lon-Lat total secs diff"),
    ]:
        digits = [int(d) for d in str(int(val))]
        test_numeric_key(digits, label)

    # 277724 - 140226 = 137498 → digits as key
    diff_s = int(cia_lon_total_s - cia_lat_total_s)
    print(f"  Total seconds diff: {diff_s}")
    test_numeric_key([int(d) for d in str(diff_s)], f"Total secs diff = {diff_s}")

    # 277724 / 140226.5 ≈ 1.9805... → digits
    ratio = cia_lon_total_s / cia_lat_total_s
    ratio_digits = [int(d) for d in f"{ratio:.6f}" if d.isdigit()]
    test_numeric_key(ratio_digits, f"Lon/Lat ratio = {ratio:.6f}")

# ─────────────────────────────────────────────────────────────────────────────
# 15. EXHAUSTIVE SHORT NUMERIC KEYS FROM COORDINATES
# ─────────────────────────────────────────────────────────────────────────────
def test_exhaustive_short():
    print("\n=== 15. EXHAUSTIVE SHORT KEYS FROM COORDINATE NUMBERS ===")

    # Take ALL the numbers from both sets of coordinates and try
    # every combination of 3-8 of them as key values
    all_nums = [38, 57, 6, 5, 77, 8, 44, 52, 31, 12, 13, 24, 18,
                # Also include derived numbers
                65, 14, 26, 28, 7, 97, 13, 24, 6, 1, 19]
    all_nums = list(set(all_nums))  # deduplicate
    all_nums.sort()

    count = 0
    for length in [7, 8]:  # Focus on KRYPTOS (7) and ABSCISSA (8) lengths
        for combo in itertools.combinations(all_nums, length):
            # Try all permutations would be too many, so just use the combination as-is
            key = "".join(AZ[n % 26] for n in combo)
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    try:
                        pt = cipher_fn(K4_CARVED, key, alpha)
                    except (ValueError, IndexError):
                        continue
                    count += 1
                    crib_hits = has_cribs(pt)
                    if crib_hits:
                        sc = score_text(pt)
                        print(f"  *** CRIB HIT *** combo={combo} {cipher_name}/{alpha_name}")
                        print(f"  Key: {key} Score: {sc:.1f}")
                        print(f"  PT: {pt}")
                        results.append({
                            "label": f"Exhaustive combo {combo}",
                            "key": key, "cipher": cipher_name,
                            "alpha": alpha_name, "score": sc,
                            "crib_hits": crib_hits, "pt_full": pt,
                        })

    print(f"  Tested {count} exhaustive short key combinations")

# ─────────────────────────────────────────────────────────────────────────────
# 16. COORDINATE-BASED VIGENERE WITH SCRAMBLE
# ─────────────────────────────────────────────────────────────────────────────
def test_scramble_then_decrypt():
    print("\n=== 16. COORDINATE-BASED PERMUTATION + DECRYPT ===")

    # Use coordinates to define a permutation, THEN decrypt
    # This tests the Model 2 paradigm: scrambled CT → unscramble → decrypt

    # Method: use coordinate numbers as column read order for columnar transposition
    coord_keys = [
        ([3, 8, 5, 7, 6, 5, 7], "CIA digits 7"),
        ([3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4], "CIA all digits 11"),
        ([7, 7, 8, 4, 4], "CIA lon digits 5"),
        ([5, 2, 3, 1, 1, 2], "Berlin lat digits 6"),
        ([1, 3, 2, 4, 1, 8], "Berlin lon digits 6"),
        ([3, 8, 5, 7, 0, 6, 5], "CIA lat with 0 for ."),
        ([7, 7, 0, 8, 4, 4], "CIA lon with 0"),
        ([1, 4, 2, 6, 6, 6, 1, 6, 2, 6], "Diffs [14,26,6,64,16,26] digits"),
    ]

    for key_nums, label in coord_keys:
        klen = len(key_nums)
        if klen < 2:
            continue

        # Create columnar transposition from key
        indexed = sorted(range(klen), key=lambda i: (key_nums[i], i))
        nrows = math.ceil(N / klen)

        # Build permutation: write row-by-row, read column-by-column in key order
        perm = []
        for rank in range(klen):
            col = indexed[rank]
            for row in range(nrows):
                idx = row * klen + col
                if idx < N:
                    perm.append(idx)

        if len(perm) == N and len(set(perm)) == N:
            real_ct = apply_permutation(K4_CARVED, perm)
            result = test_unscramble(real_ct)
            if result and result.get("crib_hits"):
                print(f"  *** CRIB HIT *** Columnar key={label}")
                print(f"  {result}")

            # Also try inverse permutation
            inv_perm = [0] * N
            for i, p in enumerate(perm):
                inv_perm[p] = i
            real_ct_inv = apply_permutation(K4_CARVED, inv_perm)
            result = test_unscramble(real_ct_inv)
            if result and result.get("crib_hits"):
                print(f"  *** CRIB HIT *** Columnar inv key={label}")
                print(f"  {result}")

    # Double columnar: use CIA lat as first key, CIA lon as second
    double_keys = [
        ([3, 8, 5, 7, 6, 5, 7], [7, 7, 8, 4, 4], "CIA lat/lon"),
        ([3, 8, 5, 7, 6], [7, 7, 8, 4, 4], "CIA lat5/lon5"),
        ([3, 8, 5, 7, 0, 6, 5], [7, 7, 0, 8, 4, 4], "CIA with 0s"),
    ]

    for key1_nums, key2_nums, label in double_keys:
        # First columnar transposition
        k1len = len(key1_nums)
        indexed1 = sorted(range(k1len), key=lambda i: (key1_nums[i], i))
        nrows1 = math.ceil(N / k1len)

        perm1 = []
        for rank in range(k1len):
            col = indexed1[rank]
            for row in range(nrows1):
                idx = row * k1len + col
                if idx < N:
                    perm1.append(idx)

        if len(perm1) != N or len(set(perm1)) != N:
            continue

        intermediate = apply_permutation(K4_CARVED, perm1)

        # Second columnar transposition
        k2len = len(key2_nums)
        indexed2 = sorted(range(k2len), key=lambda i: (key2_nums[i], i))
        nrows2 = math.ceil(N / k2len)

        perm2 = []
        for rank in range(k2len):
            col = indexed2[rank]
            for row in range(nrows2):
                idx = row * k2len + col
                if idx < N:
                    perm2.append(idx)

        if len(perm2) != N or len(set(perm2)) != N:
            continue

        real_ct = apply_permutation(intermediate, perm2)
        result = test_unscramble(real_ct)
        if result and result.get("crib_hits"):
            print(f"  *** CRIB HIT *** Double columnar {label}")
            print(f"  {result}")

        # Try inverse of second
        inv_perm2 = [0] * N
        for i, p in enumerate(perm2):
            inv_perm2[p] = i
        real_ct_inv = apply_permutation(intermediate, inv_perm2)
        result = test_unscramble(real_ct_inv)
        if result and result.get("crib_hits"):
            print(f"  *** CRIB HIT *** Double columnar inv2 {label}")
            print(f"  {result}")

# ─────────────────────────────────────────────────────────────────────────────
# 17. MIXED APPROACHES: COORDINATES + KNOWN KEYWORDS
# ─────────────────────────────────────────────────────────────────────────────
def test_mixed():
    print("\n=== 17. MIXED: COORDINATES + KEYWORDS ===")

    # XOR/add/subtract coordinate-derived key with keyword-derived key
    coord_shifts = [38 % 26, 57 % 26, 6, 5, 77 % 26, 8, 44 % 26]  # [12,5,6,5,25,8,18]
    coord7 = coord_shifts[:7]

    for keyword in KEYWORDS:
        kw_shifts = [AZ.index(c) for c in keyword]

        # Method 1: Add coordinate shifts to keyword shifts
        combined_len = max(len(kw_shifts), len(coord7))
        add_key = []
        for i in range(combined_len):
            k = (kw_shifts[i % len(kw_shifts)] + coord7[i % len(coord7)]) % 26
            add_key.append(AZ[k])
        add_key_str = "".join(add_key)
        test_key_both_alphas(add_key_str, f"{keyword}+coords add")

        # Method 2: Subtract
        sub_key = []
        for i in range(combined_len):
            k = (kw_shifts[i % len(kw_shifts)] - coord7[i % len(coord7)]) % 26
            sub_key.append(AZ[k])
        sub_key_str = "".join(sub_key)
        test_key_both_alphas(sub_key_str, f"{keyword}-coords sub")

        # Method 3: XOR
        xor_key = []
        for i in range(combined_len):
            k = (kw_shifts[i % len(kw_shifts)] ^ coord7[i % len(coord7)]) % 26
            xor_key.append(AZ[k])
        xor_key_str = "".join(xor_key)
        test_key_both_alphas(xor_key_str, f"{keyword} XOR coords")

    # Also: use coordinate digits to select letters from keywords
    # E.g., KRYPTOS[3]=P, KRYPTOS[8%7]=KRYPTOS[1]=R, etc.
    for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        cia_digits = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
        selected = "".join(keyword[d % len(keyword)] for d in cia_digits)
        test_key_both_alphas(selected, f"Select from {keyword} by CIA digits")

        ber_digits = [5, 2, 3, 1, 1, 2, 1, 3, 2, 4, 1, 8]
        selected_b = "".join(keyword[d % len(keyword)] for d in ber_digits)
        test_key_both_alphas(selected_b, f"Select from {keyword} by Berlin digits")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    start = time.time()
    print("=" * 70)
    print("BLITZ: K2 COORDINATES AS KEY MATERIAL FOR K4")
    print("=" * 70)
    print(f"K4: {K4_CARVED}")
    print(f"CIA: {CIA_LAT_D}°{CIA_LAT_M}'{CIA_LAT_S}\"N, {CIA_LON_D}°{CIA_LON_M}'{CIA_LON_S}\"W")
    print(f"CIA decimal: {CIA_LAT_DEC:.6f}°N, {CIA_LON_DEC:.6f}°W")
    print(f"Berlin: {BER_LAT_D}°{BER_LAT_M}'{BER_LAT_S}\"N, {BER_LON_D}°{BER_LON_M}'{BER_LON_S}\"E")
    print(f"Berlin decimal: {BER_LAT_DEC:.6f}°N, {BER_LON_DEC:.6f}°E")
    print()

    test_raw_dms()
    test_decimal_degrees()
    test_arithmetic()
    test_grid_dimensions()
    test_differences()
    test_digit_to_letter()
    test_special_numbers()
    test_timezone()
    test_coordinate_keywords()
    test_coordinate_permutations()
    test_autokey()
    test_modular()
    test_usgs_marker()
    test_creative()
    test_exhaustive_short()
    test_scramble_then_decrypt()
    test_mixed()

    elapsed = time.time() - start

    print("\n" + "=" * 70)
    print(f"COMPLETE — {configs_tested} configs tested in {elapsed:.1f}s")
    print("=" * 70)

    if best_result:
        print(f"\nBest overall: {best_result['score']:.1f} ({best_result['score_per_char']:.3f}/char)")
        print(f"  Label: {best_result['label']}")
        print(f"  Key: {best_result['key']} ({best_result['cipher']}/{best_result['alpha']})")
        print(f"  PT: {best_result['pt_snippet']}...")

    above_threshold = [r for r in results if r.get("score_per_char", -99) > REPORT_THRESHOLD]
    crib_hits = [r for r in results if r.get("crib_hits")]

    if crib_hits:
        print(f"\n*** {len(crib_hits)} CRIB HITS FOUND ***")
        for r in crib_hits:
            print(f"  {r['label']}: {r['crib_hits']}")

    if above_threshold:
        print(f"\n{len(above_threshold)} results above {REPORT_THRESHOLD}/char threshold:")
        for r in sorted(above_threshold, key=lambda x: x.get("score_per_char", -99), reverse=True)[:20]:
            print(f"  {r.get('score_per_char', -99):.3f}/char | {r['label']} | key={r['key']}")

    # Save results
    output = {
        "experiment": "blitz_coordinates_key",
        "elapsed_seconds": elapsed,
        "configs_tested": configs_tested,
        "best_result": best_result,
        "above_threshold_count": len(above_threshold),
        "crib_hit_count": len(crib_hits),
        "top_results": sorted(results, key=lambda x: x.get("score", -99999), reverse=True)[:50],
    }

    os.makedirs("kbot_results", exist_ok=True)
    out_path = Path("kbot_results/coordinates_key_results.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")

if __name__ == "__main__":
    main()
