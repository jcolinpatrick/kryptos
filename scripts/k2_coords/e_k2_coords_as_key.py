#!/usr/bin/env python3
"""
# Cipher: Mixed (Vigenere/Beaufort/Transposition/Grid)
# Family: k2_coords
# Status: active
# Keyspace: ~500 configs
# Last run: 2026-03-13
# Best score: TBD

Test whether K2 coordinate numbers encode cipher keys for K4.
K2: 38°57'6.5"N 77°8'44"W
"""
import sys
import itertools
from typing import List, Tuple, Dict

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, CRIB_POSITIONS,
    NOISE_FLOOR, KRYPTOS_ALPHABET,
)

KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

# ── Helpers ──────────────────────────────────────────────────────────────

def crib_score(plaintext: str) -> int:
    """Count how many crib positions match."""
    score = 0
    for pos, expected_char in CRIB_DICT.items():
        if pos < len(plaintext) and plaintext[pos] == expected_char:
            score += 1
    return score


def free_crib_score(plaintext: str) -> Tuple[int, int]:
    """Search for EASTNORTHEAST and BERLINCLOCK at any position. Return (best_score, best_offset)."""
    cribs = ["EASTNORTHEAST", "BERLINCLOCK"]
    best = 0
    best_off = -1
    for crib in cribs:
        for i in range(len(plaintext) - len(crib) + 1):
            matches = sum(1 for j, c in enumerate(crib) if plaintext[i + j] == c)
            if matches > best:
                best = matches
                best_off = i
    return best, best_off


def vig_decrypt(ct: str, key_nums: List[int], alphabet: str = ALPH) -> str:
    """Vigenere decrypt: PT[i] = (CT[i] - K[i]) mod 26"""
    idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct):
        k = key_nums[i % klen]
        pt_num = (idx[c] - k) % MOD
        pt.append(alphabet[pt_num])
    return "".join(pt)


def beau_decrypt(ct: str, key_nums: List[int], alphabet: str = ALPH) -> str:
    """Beaufort decrypt: PT[i] = (K[i] - CT[i]) mod 26"""
    idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct):
        k = key_nums[i % klen]
        pt_num = (k - idx[c]) % MOD
        pt.append(alphabet[pt_num])
    return "".join(pt)


def vbeau_decrypt(ct: str, key_nums: List[int], alphabet: str = ALPH) -> str:
    """Variant Beaufort decrypt: PT[i] = (CT[i] + K[i]) mod 26"""
    idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct):
        k = key_nums[i % klen]
        pt_num = (idx[c] + k) % MOD
        pt.append(alphabet[pt_num])
    return "".join(pt)


def columnar_decrypt(ct: str, key_order: List[int]) -> str:
    """Columnar transposition decrypt given column read order."""
    ncols = len(key_order)
    nrows = (len(ct) + ncols - 1) // ncols
    n_full = len(ct) - ncols * (nrows - 1)  # columns with full rows

    # Build sorted order: columns with more chars come first if they are in key_order < n_full
    # Actually: standard columnar - key_order gives reading order of columns
    # Columns 0..n_full-1 have nrows chars, columns n_full..ncols-1 have nrows-1 chars

    # Create (rank, original_col) pairs sorted by rank
    ranked = sorted(range(ncols), key=lambda c: key_order[c])

    # Read off columns in ranked order
    grid = [[''] * ncols for _ in range(nrows)]
    pos = 0
    for col in ranked:
        col_len = nrows if col < n_full else nrows - 1
        for row in range(col_len):
            if pos < len(ct):
                grid[row][col] = ct[pos]
                pos += 1

    # Read row by row
    pt = []
    for row in grid:
        pt.extend(row)
    return "".join(pt)[:len(ct)]


def myszkowski_decrypt(ct: str, key_nums: List[int]) -> str:
    """Myszkowski transposition decrypt (identical key digits read across rows together)."""
    ncols = len(key_nums)
    nrows = (len(ct) + ncols - 1) // ncols
    n_full_cols = len(ct) % ncols if len(ct) % ncols != 0 else ncols

    # Get unique key values in sorted order
    unique_vals = sorted(set(key_nums))

    grid = [[''] * ncols for _ in range(nrows)]
    pos = 0

    for val in unique_vals:
        # Get columns with this key value
        cols = [c for c in range(ncols) if key_nums[c] == val]

        if len(cols) == 1:
            # Single column: read vertically
            col = cols[0]
            col_len = nrows if col < n_full_cols else nrows - 1
            for row in range(col_len):
                if pos < len(ct):
                    grid[row][col] = ct[pos]
                    pos += 1
        else:
            # Multiple columns: read across rows
            for row in range(nrows):
                for col in cols:
                    if row < nrows - 1 or col < n_full_cols:
                        if pos < len(ct):
                            grid[row][col] = ct[pos]
                            pos += 1

    pt = []
    for row in grid:
        pt.extend(c for c in row if c)
    return "".join(pt)[:len(ct)]


def rail_fence_decrypt(ct: str, nrails: int) -> str:
    """Rail fence decrypt."""
    n = len(ct)
    if nrails <= 1 or nrails >= n:
        return ct
    # Build the zigzag pattern
    rails = [[] for _ in range(nrails)]
    rail = 0
    direction = 1
    pattern = []
    for i in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == nrails - 1:
            direction = -1
        rail += direction

    # Count chars per rail
    counts = [0] * nrails
    for r in pattern:
        counts[r] += 1

    # Fill rails from ciphertext
    pos = 0
    rail_chars = [[] for _ in range(nrails)]
    for r in range(nrails):
        for _ in range(counts[r]):
            rail_chars[r].append(ct[pos])
            pos += 1

    # Read off in zigzag order
    rail_idx = [0] * nrails
    pt = []
    for r in pattern:
        pt.append(rail_chars[r][rail_idx[r]])
        rail_idx[r] += 1
    return "".join(pt)


def route_decrypt(ct: str, nrows: int, ncols: int, route: str = "spiral_cw") -> str:
    """Route cipher decrypt: fill grid by route, read row by row."""
    if nrows * ncols < len(ct):
        return ct
    # Fill grid row by row
    grid = [[''] * ncols for _ in range(nrows)]
    pos = 0
    for r in range(nrows):
        for c in range(ncols):
            if pos < len(ct):
                grid[r][c] = ct[pos]
                pos += 1

    # Read in route order
    if route == "col_first":
        pt = []
        for c in range(ncols):
            for r in range(nrows):
                if grid[r][c]:
                    pt.append(grid[r][c])
        return "".join(pt)[:len(ct)]
    elif route == "serpentine":
        pt = []
        for r in range(nrows):
            row = list(range(ncols)) if r % 2 == 0 else list(range(ncols - 1, -1, -1))
            for c in row:
                if grid[r][c]:
                    pt.append(grid[r][c])
        return "".join(pt)[:len(ct)]
    elif route == "spiral_cw":
        pt = []
        top, bottom, left, right = 0, nrows - 1, 0, ncols - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                if grid[top][c]: pt.append(grid[top][c])
            top += 1
            for r in range(top, bottom + 1):
                if grid[r][right]: pt.append(grid[r][right])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    if grid[bottom][c]: pt.append(grid[bottom][c])
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    if grid[r][left]: pt.append(grid[r][left])
                left += 1
        return "".join(pt)[:len(ct)]
    return ct


def report(label: str, score: int, pt: str, threshold: int = NOISE_FLOOR):
    """Print result, highlight if above threshold."""
    if score > threshold:
        print(f"  *** ABOVE NOISE: {label}: score={score}/24, PT={pt[:40]}...")
    # Always log to summary
    return score


# ── Key derivations from K2 coordinates ──────────────────────────────────

# Raw digit sequence: 38 57 6.5 77 8 44
DIGITS_FULL = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
# Without the .5 (just integer parts): 38 57 6 77 8 44
DIGITS_NO_DECIMAL = [3, 8, 5, 7, 6, 7, 7, 8, 4, 4]
# Individual numbers
NUMBERS = [38, 57, 6, 5, 77, 8, 44]
NUMBERS_NO_DECIMAL = [38, 57, 6, 77, 8, 44]
# Numbers mod 26
NUMBERS_MOD26 = [n % 26 for n in NUMBERS]  # [12, 5, 6, 5, 25, 8, 18]
NUMBERS_NO_DEC_MOD26 = [n % 26 for n in NUMBERS_NO_DECIMAL]  # [12, 5, 6, 25, 8, 18]

# Decimal degrees
LAT_DD = 38.9518056  # 38 + 57/60 + 6.5/3600
LON_DD = 77.1455556  # 77 + 8/60 + 44/3600
LAT_DIGITS = [3, 8, 9, 5, 1, 8, 0, 5, 6]
LON_DIGITS = [7, 7, 1, 4, 5, 5, 5, 5, 6]

# Total seconds
LAT_SECS = 140226  # 38*3600 + 57*60 + 6 (integer part)
LON_SECS = 277724  # 77*3600 + 8*60 + 44
LAT_SEC_DIGITS = [1, 4, 0, 2, 2, 6]
LON_SEC_DIGITS = [2, 7, 7, 7, 2, 4]
COMBINED_SEC_DIGITS = [1, 4, 0, 2, 2, 6, 2, 7, 7, 7, 2, 4]

# Products
PRODUCTS = {
    "38*57": 2166,
    "77*44": 3388,
    "8*6": 48,
    "38+57+6+5+77+8+44": 235,
    "38+57+6+77+8+44": 230,
    "38*57*6": 12996,
    "77*8*44": 27104,
}

# NORTH/WEST letter sums (A1Z26)
NORTH_SUM = sum(ALPH_IDX[c] + 1 for c in "NORTH")  # N=14,O=15,R=18,T=20,H=8 = 75
WEST_SUM = sum(ALPH_IDX[c] + 1 for c in "WEST")    # W=23,E=5,S=19,T=20 = 67
X_VAL_ALPHA = 24  # X is 24th letter (1-indexed)
X_VAL_IDX = 23    # X is index 23 (0-indexed)
X_ROMAN = 10      # X = 10 in Roman numerals

# Derived key sequences
ALL_KEY_SEQUENCES = {}

# 1. Raw digits
ALL_KEY_SEQUENCES["digits_full_11"] = DIGITS_FULL
ALL_KEY_SEQUENCES["digits_no_decimal_10"] = DIGITS_NO_DECIMAL

# 2. Numbers mod 26
ALL_KEY_SEQUENCES["numbers_mod26_7"] = NUMBERS_MOD26
ALL_KEY_SEQUENCES["numbers_no_dec_mod26_6"] = NUMBERS_NO_DEC_MOD26

# 3. Decimal degree digits
ALL_KEY_SEQUENCES["lat_dd_digits_9"] = LAT_DIGITS
ALL_KEY_SEQUENCES["lon_dd_digits_9"] = LON_DIGITS
ALL_KEY_SEQUENCES["latlon_dd_digits_18"] = LAT_DIGITS + LON_DIGITS

# 4. Total-second digits
ALL_KEY_SEQUENCES["lat_sec_digits_6"] = LAT_SEC_DIGITS
ALL_KEY_SEQUENCES["lon_sec_digits_6"] = LON_SEC_DIGITS
ALL_KEY_SEQUENCES["combined_sec_digits_12"] = COMBINED_SEC_DIGITS

# 5. Product/sum digit sequences
for name, val in PRODUCTS.items():
    digits = [int(d) for d in str(val)]
    ALL_KEY_SEQUENCES[f"product_{name}_digits"] = digits

# 6. Reversed digits
ALL_KEY_SEQUENCES["digits_full_reversed"] = DIGITS_FULL[::-1]
ALL_KEY_SEQUENCES["digits_no_dec_reversed"] = DIGITS_NO_DECIMAL[::-1]

# 7. Digits +/- offset
for offset in [1, -1, 13]:
    ALL_KEY_SEQUENCES[f"digits_full_offset_{offset}"] = [(d + offset) % 26 for d in DIGITS_FULL]

# 8. X-modified keys
ALL_KEY_SEQUENCES["digits_full_xor24"] = [(d ^ X_VAL_ALPHA) for d in DIGITS_FULL]
ALL_KEY_SEQUENCES["digits_plus_X24"] = [(d + X_VAL_ALPHA) % 26 for d in DIGITS_FULL]
ALL_KEY_SEQUENCES["digits_plus_X10"] = [(d + X_ROMAN) % 26 for d in DIGITS_FULL]

# 9. NORTH=75, WEST=67 as shifts applied to digit keys
ALL_KEY_SEQUENCES["digits_shift_north75"] = [(d + 75) % 26 for d in DIGITS_FULL]
ALL_KEY_SEQUENCES["digits_shift_west67"] = [(d + 67) % 26 for d in DIGITS_FULL]

# 10. Coordinate numbers as letter indices (A=0): 3=D, 8=I, 5=F, 7=H, ...
ALL_KEY_SEQUENCES["digits_as_letters"] = DIGITS_FULL  # same numerically

# 11. DMS components as key: [38, 57, 6, 77, 8, 44] each mod 26
ALL_KEY_SEQUENCES["dms_components_mod26"] = [38 % 26, 57 % 26, 6, 77 % 26, 8, 44 % 26]

# 12. Interleaved lat/lon digits
lat_raw = [3, 8, 5, 7, 6, 5]  # from 38°57'6.5"
lon_raw = [7, 7, 8, 4, 4]     # from 77°8'44"
interleaved = []
for i in range(max(len(lat_raw), len(lon_raw))):
    if i < len(lat_raw):
        interleaved.append(lat_raw[i])
    if i < len(lon_raw):
        interleaved.append(lon_raw[i])
ALL_KEY_SEQUENCES["interleaved_latlon"] = interleaved

# 13. Differences between consecutive digits
ALL_KEY_SEQUENCES["digit_diffs"] = [(DIGITS_FULL[i+1] - DIGITS_FULL[i]) % 26 for i in range(len(DIGITS_FULL)-1)]

# 14. Cumulative sum of digits mod 26
cumsum = []
s = 0
for d in DIGITS_FULL:
    s = (s + d) % 26
    cumsum.append(s)
ALL_KEY_SEQUENCES["digit_cumsum_mod26"] = cumsum

# 15. Two-digit numbers from coordinate: 38, 57, 65, 77, 84, 4 (or wrapped)
ALL_KEY_SEQUENCES["two_digit_pairs_mod26"] = [38 % 26, 57 % 26, 65 % 26, 77 % 26, 84 % 26, 4]

# 16. KRYPTOS alphabet indices of digits treated as letters
# 3=D, 8=I, 5=F, 7=H, 6=G, 5=F, 7=H, 7=H, 8=I, 4=E, 4=E -> KA indices
digit_letters = "DIFHGFHHIEE"
ALL_KEY_SEQUENCES["digits_as_ka_indices"] = [KA_IDX[c] for c in digit_letters]


print("=" * 80)
print("K2 COORDINATES AS K4 CIPHER KEY — COMPREHENSIVE TEST")
print("=" * 80)
print(f"CT: {CT}")
print(f"CT length: {CT_LEN}")
print(f"Crib positions: 21-33=EASTNORTHEAST, 63-73=BERLINCLOCK")
print()

results = []  # (score, label, pt)

# ════════════════════════════════════════════════════════════════════════
# TEST 1: All key sequences as Vigenere/Beaufort/VBeaufort keys
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 1: Key sequences as Vigenere/Beaufort/VBeaufort keys")
print("=" * 80)

for key_name, key_nums in ALL_KEY_SEQUENCES.items():
    if not key_nums or all(k == 0 for k in key_nums):
        continue
    for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
            pt = decrypt_fn(CT, key_nums, alph)
            sc = crib_score(pt)
            label = f"{cipher_name}/{alph_name} key={key_name}"
            if sc > NOISE_FLOOR:
                report(label, sc, pt)
            results.append((sc, label, pt))

# Also try the raw coordinate numbers as a period-6 or period-7 key
for coord_key in [
    ("coords_6", [38, 57, 6, 77, 8, 44]),
    ("coords_7", [38, 57, 6, 5, 77, 8, 44]),
    ("coords_reversed_6", [44, 8, 77, 6, 57, 38]),
]:
    key_name, key_nums_raw = coord_key
    key_nums = [k % 26 for k in key_nums_raw]
    for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
            pt = decrypt_fn(CT, key_nums, alph)
            sc = crib_score(pt)
            label = f"{cipher_name}/{alph_name} key={key_name} ({key_nums})"
            if sc > NOISE_FLOOR:
                report(label, sc, pt)
            results.append((sc, label, pt))

print(f"  Total sub configs tested: {len(results)}")
best_sub = max(results, key=lambda x: x[0])
print(f"  Best substitution score: {best_sub[0]}/24 — {best_sub[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# TEST 2: Digit sequence as columnar transposition key (11 columns)
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 2: Columnar transposition with K2-derived keys")
print("=" * 80)

trans_results = []

# 2a. DIGITS_FULL as column key (11 columns, repeated digits → Myszkowski)
for key_name, key_nums in [
    ("digits_full_11", DIGITS_FULL),
    ("digits_no_decimal_10", DIGITS_NO_DECIMAL),
    ("dms_6", [38, 57, 6, 77, 8, 44]),
    ("dms_7", [38, 57, 6, 5, 77, 8, 44]),
    ("lat_sec_6", LAT_SEC_DIGITS),
    ("lon_sec_6", LON_SEC_DIGITS),
    ("combined_sec_12", COMBINED_SEC_DIGITS),
    ("lat_dd_9", LAT_DIGITS),
    ("lon_dd_9", LON_DIGITS),
]:
    # Regular columnar (use rank as order, break ties left-to-right)
    ranked = sorted(range(len(key_nums)), key=lambda i: (key_nums[i], i))
    order = [0] * len(key_nums)
    for rank, orig in enumerate(ranked):
        order[orig] = rank

    pt = columnar_decrypt(CT, order)
    sc = crib_score(pt)
    fsc, foff = free_crib_score(pt)
    label = f"Columnar key={key_name} order={order}"
    if sc > NOISE_FLOOR:
        report(label, sc, pt)
    if fsc > 5:
        print(f"  Free crib: {label}: free_score={fsc} at offset={foff}, PT={pt[:40]}...")
    trans_results.append((sc, label, pt))

    # Also try Myszkowski
    pt_m = myszkowski_decrypt(CT, key_nums)
    sc_m = crib_score(pt_m)
    fsc_m, foff_m = free_crib_score(pt_m)
    label_m = f"Myszkowski key={key_name}"
    if sc_m > NOISE_FLOOR:
        report(label_m, sc_m, pt_m)
    if fsc_m > 5:
        print(f"  Free crib: {label_m}: free_score={fsc_m} at offset={foff_m}, PT={pt_m[:40]}...")
    trans_results.append((sc_m, label_m, pt_m))

    # Rail fence with number of rails from key
    for nrails in set(key_nums):
        if 2 <= nrails <= 20:
            pt_r = rail_fence_decrypt(CT, nrails)
            sc_r = crib_score(pt_r)
            label_r = f"RailFence nrails={nrails} from {key_name}"
            if sc_r > NOISE_FLOOR:
                report(label_r, sc_r, pt_r)
            trans_results.append((sc_r, label_r, pt_r))

print(f"  Total transposition configs tested: {len(trans_results)}")
best_trans = max(trans_results, key=lambda x: x[0])
print(f"  Best transposition score: {best_trans[0]}/24 — {best_trans[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# TEST 3: Grid dimensions from K2 numbers
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 3: Grid dimensions from K2 numbers")
print("=" * 80)

grid_results = []

# Find all grid dimensions that can hold 97 chars
candidate_dims = []
for n in [6, 7, 8, 11, 38, 44, 57, 77, 4, 5, 3, 24, 10]:
    if n <= 0 or n > 97:
        continue
    other = (97 + n - 1) // n
    if n * other >= 97:
        candidate_dims.append((n, other))
        candidate_dims.append((other, n))

# Add explicit K2-derived dims
candidate_dims.extend([
    (8, 13),   # 8 lines, 13 = ENE length
    (11, 9),   # 11 digits, 9 rows
    (7, 14),   # 7 numbers, 14 = half of 28
    (14, 7),
    (8, 14),   # 8 = K4 lines per legal pad
    (14, 8),
])

# Deduplicate
candidate_dims = list(set((r, c) for r, c in candidate_dims if r * c >= 97 and r > 0 and c > 0 and r <= 50 and c <= 50))

for nrows, ncols in candidate_dims:
    for route in ["col_first", "serpentine", "spiral_cw"]:
        pt = route_decrypt(CT, nrows, ncols, route)
        sc = crib_score(pt)
        fsc, _ = free_crib_score(pt)
        label = f"Route {route} grid={nrows}x{ncols}"
        if sc > NOISE_FLOOR:
            report(label, sc, pt)
        if fsc > 5:
            print(f"  Free crib: {label}: free_score={fsc}, PT={pt[:40]}...")
        grid_results.append((sc, label, pt))

        # Also: fill by route, read row by row (inverse direction)
        # Fill grid via route, read rows
        grid = [[''] * ncols for _ in range(nrows)]
        pos = 0
        if route == "col_first":
            for c in range(ncols):
                for r in range(nrows):
                    if pos < len(CT):
                        grid[r][c] = CT[pos]
                        pos += 1
        elif route == "serpentine":
            for r in range(nrows):
                cols = list(range(ncols)) if r % 2 == 0 else list(range(ncols - 1, -1, -1))
                for c in cols:
                    if pos < len(CT):
                        grid[r][c] = CT[pos]
                        pos += 1
        elif route == "spiral_cw":
            top, bottom, left, right = 0, nrows - 1, 0, ncols - 1
            while top <= bottom and left <= right and pos < len(CT):
                for c in range(left, right + 1):
                    if pos < len(CT): grid[top][c] = CT[pos]; pos += 1
                top += 1
                for r in range(top, bottom + 1):
                    if pos < len(CT): grid[r][right] = CT[pos]; pos += 1
                right -= 1
                if top <= bottom:
                    for c in range(right, left - 1, -1):
                        if pos < len(CT): grid[bottom][c] = CT[pos]; pos += 1
                    bottom -= 1
                if left <= right:
                    for r in range(bottom, top - 1, -1):
                        if pos < len(CT): grid[r][left] = CT[pos]; pos += 1
                    left += 1

        inv_pt = "".join(grid[r][c] for r in range(nrows) for c in range(ncols) if grid[r][c])[:len(CT)]
        inv_sc = crib_score(inv_pt)
        inv_label = f"Route-fill {route} grid={nrows}x{ncols} read-rows"
        if inv_sc > NOISE_FLOOR:
            report(inv_label, inv_sc, inv_pt)
        grid_results.append((inv_sc, inv_label, inv_pt))

print(f"  Total grid configs tested: {len(grid_results)}")
best_grid = max(grid_results, key=lambda x: x[0])
print(f"  Best grid score: {best_grid[0]}/24 — {best_grid[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# TEST 4: Combined transposition + substitution
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 4: Transposition then substitution (K2 keys for both)")
print("=" * 80)

combo_results = []

# Use top transposition keys to permute, then apply top substitution keys
trans_keys = [
    ("digits_full_11", DIGITS_FULL),
    ("digits_no_decimal_10", DIGITS_NO_DECIMAL),
    ("dms_6", [38 % 26, 57 % 26, 6, 77 % 26, 8, 44 % 26]),
    ("lat_sec_6", LAT_SEC_DIGITS),
    ("lon_sec_6", LON_SEC_DIGITS),
]

sub_keys = [
    ("digits_full_11", DIGITS_FULL),
    ("dms_mod26_6", NUMBERS_NO_DEC_MOD26),
    ("numbers_mod26_7", NUMBERS_MOD26),
    ("lat_dd_9", LAT_DIGITS),
    ("lon_dd_9", LON_DIGITS),
    ("combined_sec_12", COMBINED_SEC_DIGITS),
    ("interleaved", interleaved),
    ("digit_cumsum", cumsum),
]

for tk_name, tk_nums in trans_keys:
    # Columnar decrypt
    ranked = sorted(range(len(tk_nums)), key=lambda i: (tk_nums[i], i))
    order = [0] * len(tk_nums)
    for rank, orig in enumerate(ranked):
        order[orig] = rank
    trans_pt = columnar_decrypt(CT, order)
    mysz_pt = myszkowski_decrypt(CT, tk_nums)

    for intermediate, int_name in [(trans_pt, "col"), (mysz_pt, "mysz")]:
        for sk_name, sk_nums in sub_keys:
            for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
                for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
                    pt = decrypt_fn(intermediate, sk_nums, alph)
                    sc = crib_score(pt)
                    fsc, _ = free_crib_score(pt)
                    label = f"{int_name}({tk_name})+{cipher_name}/{alph_name}({sk_name})"
                    if sc > NOISE_FLOOR:
                        report(label, sc, pt)
                    if fsc > 7:
                        print(f"  Free crib: {label}: free_score={fsc}, PT={pt[:40]}...")
                    combo_results.append((sc, label, pt))

    # Also try sub THEN transposition (reverse order)
    for sk_name, sk_nums in sub_keys:
        for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
            sub_first = decrypt_fn(CT, sk_nums, ALPH)
            # Then columnar
            ranked = sorted(range(len(tk_nums)), key=lambda i: (tk_nums[i], i))
            order = [0] * len(tk_nums)
            for rank, orig in enumerate(ranked):
                order[orig] = rank
            pt = columnar_decrypt(sub_first, order)
            sc = crib_score(pt)
            label = f"{cipher_name}/AZ({sk_name})+col({tk_name})"
            if sc > NOISE_FLOOR:
                report(label, sc, pt)
            combo_results.append((sc, label, pt))

print(f"  Total combo configs tested: {len(combo_results)}")
best_combo = max(combo_results, key=lambda x: x[0])
print(f"  Best combo score: {best_combo[0]}/24 — {best_combo[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# TEST 5: X=24 as a parameter
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 5: X=24 as parameter (null mask, shift, etc.)")
print("=" * 80)

x_results = []

# 5a. Remove every 24th character (or first 24 positions)
# Skip positions that are multiples of some X-derived step
for step in [4, 8, 24]:
    # Remove every step-th char
    mask_pt = "".join(c for i, c in enumerate(CT) if i % step != 0)
    sc = crib_score(mask_pt)
    label = f"Remove every {step}th char"
    if sc > NOISE_FLOOR:
        report(label, sc, mask_pt)
    x_results.append((sc, label, mask_pt))

# 5b. Caesar shift of 24
for shift in [24, 10, 23]:
    pt = "".join(ALPH[(ALPH_IDX[c] - shift) % 26] for c in CT)
    sc = crib_score(pt)
    label = f"Caesar shift={shift}"
    if sc > NOISE_FLOOR:
        report(label, sc, pt)
    x_results.append((sc, label, pt))

# 5c. Period-24 Vigenere with digit keys
for key_name, key_nums in ALL_KEY_SEQUENCES.items():
    if len(key_nums) == 24 or len(key_nums) <= 4:
        # Pad to 24 if shorter
        padded = (key_nums * ((24 // len(key_nums)) + 1))[:24]
        pt = vig_decrypt(CT, padded)
        sc = crib_score(pt)
        label = f"Vig p=24 key={key_name}"
        if sc > NOISE_FLOOR:
            report(label, sc, pt)
        x_results.append((sc, label, pt))

# 5d. Use X=24 to select null positions: every 4th position (97/24 ≈ 4)
# Remove positions 0, 4, 8, ... (24 positions) and check if remaining 73 have cribs
null_positions_step4 = set(range(0, 97, 4))  # 25 positions, too many
null_positions_step4 = set(list(range(0, 97, 4))[:24])
remaining = "".join(c for i, c in enumerate(CT) if i not in null_positions_step4)
sc = crib_score(remaining)
label = f"Null mask: every 4th (first 24)"
x_results.append((sc, label, remaining))

print(f"  Total X-parameter configs tested: {len(x_results)}")
best_x = max(x_results, key=lambda x: x[0])
print(f"  Best X-parameter score: {best_x[0]}/24 — {best_x[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# TEST 6: Autokey with K2-derived primers
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 6: Autokey with K2-derived primers")
print("=" * 80)

autokey_results = []

def autokey_vig_decrypt(ct: str, primer_nums: List[int]) -> str:
    """Autokey Vigenere decrypt: key = primer || plaintext"""
    pt = []
    key = list(primer_nums)
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else ALPH_IDX[pt[i - len(primer_nums)]]
        pt_num = (ALPH_IDX[c] - k) % MOD
        pt.append(ALPH[pt_num])
    return "".join(pt)

def autokey_beau_decrypt(ct: str, primer_nums: List[int]) -> str:
    """Autokey Beaufort decrypt: key = primer || plaintext"""
    pt = []
    key = list(primer_nums)
    for i, c in enumerate(ct):
        k = key[i] if i < len(key) else ALPH_IDX[pt[i - len(primer_nums)]]
        pt_num = (k - ALPH_IDX[c]) % MOD
        pt.append(ALPH[pt_num])
    return "".join(pt)

# Try various K2-derived primers
primer_candidates = [
    ("digits_full", DIGITS_FULL),
    ("digits_no_dec", DIGITS_NO_DECIMAL),
    ("numbers_mod26", NUMBERS_MOD26),
    ("dms_mod26", NUMBERS_NO_DEC_MOD26),
    ("lat_sec", LAT_SEC_DIGITS),
    ("lon_sec", LON_SEC_DIGITS),
    ("combined_sec", COMBINED_SEC_DIGITS),
    ("lat_dd", LAT_DIGITS),
    ("lon_dd", LON_DIGITS),
    ("interleaved", interleaved),
    ("cumsum", cumsum),
    ("digit_diffs", ALL_KEY_SEQUENCES["digit_diffs"]),
]

# Also try keyword "KRYPTOS" + coordinate digits as combined primer
kryptos_nums = [ALPH_IDX[c] for c in "KRYPTOS"]
primer_candidates.append(("KRYPTOS+digits", kryptos_nums + DIGITS_FULL))
primer_candidates.append(("KRYPTOS", kryptos_nums))
primer_candidates.append(("NORTH", [ALPH_IDX[c] for c in "NORTH"]))
primer_candidates.append(("WEST", [ALPH_IDX[c] for c in "WEST"]))
primer_candidates.append(("NORTHWEST", [ALPH_IDX[c] for c in "NORTHWEST"]))
primer_candidates.append(("PALIMPSEST", [ALPH_IDX[c] for c in "PALIMPSEST"]))
primer_candidates.append(("ABSCISSA", [ALPH_IDX[c] for c in "ABSCISSA"]))

for pname, primer in primer_candidates:
    for ak_fn, ak_name in [(autokey_vig_decrypt, "AK-Vig"), (autokey_beau_decrypt, "AK-Beau")]:
        pt = ak_fn(CT, primer)
        sc = crib_score(pt)
        fsc, _ = free_crib_score(pt)
        label = f"{ak_name} primer={pname}"
        if sc > NOISE_FLOOR:
            report(label, sc, pt)
        if fsc > 7:
            print(f"  Free crib: {label}: free_score={fsc}, PT={pt[:40]}...")
        autokey_results.append((sc, label, pt))

print(f"  Total autokey configs tested: {len(autokey_results)}")
best_ak = max(autokey_results, key=lambda x: x[0])
print(f"  Best autokey score: {best_ak[0]}/24 — {best_ak[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# TEST 7: NORTH/WEST sums as shifts or key modifiers
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 7: NORTH/WEST letter sums as key modifiers")
print("=" * 80)

nw_results = []

# 7a. Use NORTH=75, WEST=67 as two-element key
for key_nums in [
    [75 % 26, 67 % 26],              # [23, 15]
    [NORTH_SUM, WEST_SUM],            # raw [75, 67] → mod 26 same as above
    [75, 67],                          # will mod 26 in decrypt
    [67, 75],                          # reversed
]:
    key_mod = [k % 26 for k in key_nums]
    for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        pt = decrypt_fn(CT, key_mod)
        sc = crib_score(pt)
        label = f"{cipher_name} key=NW_sums {key_mod}"
        if sc > NOISE_FLOOR:
            report(label, sc, pt)
        nw_results.append((sc, label, pt))

# 7b. Combine NORTH/WEST sums with digit sequence
for modifier in [NORTH_SUM, WEST_SUM, NORTH_SUM + WEST_SUM]:
    key_mod = [(d + modifier) % 26 for d in DIGITS_FULL]
    for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
        pt = decrypt_fn(CT, key_mod)
        sc = crib_score(pt)
        label = f"{cipher_name} digits+{modifier}mod26"
        if sc > NOISE_FLOOR:
            report(label, sc, pt)
        nw_results.append((sc, label, pt))

# 7c. NORTH as word key, WEST as word key
for keyword in ["NORTH", "WEST", "NORTHWESTX", "XNORTHWEST",
                "NORTHEAST", "EASTNORTHEAST", "BERLINCLOCK",
                "THIRTYEIGHT", "SEVENTYSEVEN", "FORTYFOUR"]:
    key_nums = [ALPH_IDX[c] for c in keyword]
    for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
        for alph_name, alph in [("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)]:
            idx_map = {c: i for i, c in enumerate(alph)}
            key_nums_alph = [idx_map.get(c, ALPH_IDX[c]) for c in keyword]
            pt = decrypt_fn(CT, key_nums_alph, alph)
            sc = crib_score(pt)
            label = f"{cipher_name}/{alph_name} keyword={keyword}"
            if sc > NOISE_FLOOR:
                report(label, sc, pt)
            nw_results.append((sc, label, pt))

print(f"  Total NW configs tested: {len(nw_results)}")
best_nw = max(nw_results, key=lambda x: x[0])
print(f"  Best NW score: {best_nw[0]}/24 — {best_nw[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# TEST 8: Stride/step transpositions using K2 numbers
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 8: Stride/step transpositions with K2-derived steps")
print("=" * 80)

stride_results = []

# Read CT at stride s: positions 0, s, 2s, ... (mod 97)
for s in [3, 4, 5, 6, 7, 8, 11, 24, 38, 44, 57, 77]:
    if s <= 0 or s >= 97:
        continue
    from math import gcd
    if gcd(s, 97) != 1:
        continue  # stride must be coprime to length for full coverage
    pt = "".join(CT[(i * s) % 97] for i in range(97))
    sc = crib_score(pt)
    fsc, _ = free_crib_score(pt)
    label = f"Stride s={s}"
    if sc > NOISE_FLOOR:
        report(label, sc, pt)
    if fsc > 5:
        print(f"  Free crib: {label}: free_score={fsc}, PT={pt[:40]}...")
    stride_results.append((sc, label, pt))

    # Also try inverse stride
    inv_pt = [''] * 97
    for i in range(97):
        inv_pt[(i * s) % 97] = CT[i]
    inv_pt_str = "".join(inv_pt)
    sc_inv = crib_score(inv_pt_str)
    label_inv = f"InvStride s={s}"
    if sc_inv > NOISE_FLOOR:
        report(label_inv, sc_inv, inv_pt_str)
    stride_results.append((sc_inv, label_inv, inv_pt_str))

print(f"  Total stride configs tested: {len(stride_results)}")
best_stride = max(stride_results, key=lambda x: x[0])
print(f"  Best stride score: {best_stride[0]}/24 — {best_stride[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# TEST 9: K2 numbers as Quagmire III / keyed-Vigenere parameters
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("TEST 9: Quagmire III (keyed alphabet + K2 key)")
print("=" * 80)

quag_results = []

def quagmire3_decrypt(ct: str, pt_alph: str, ct_alph: str, key_nums: List[int], indicator: int = 0) -> str:
    """Quagmire III decrypt: both PT and CT use keyed alphabets, key shifts CT alphabet."""
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct):
        k = key_nums[i % klen]
        # Shift the CT alphabet by k positions
        shifted_pos = ct_alph.index(c)
        pt_pos = (shifted_pos - k + indicator) % 26
        pt.append(pt_alph[pt_pos])
    return "".join(pt)

# Try KRYPTOS as keyed alphabet with K2 digit keys
for key_name, key_nums in [
    ("digits_full", DIGITS_FULL),
    ("dms_mod26", NUMBERS_NO_DEC_MOD26),
    ("numbers_mod26", NUMBERS_MOD26),
    ("lat_dd", LAT_DIGITS),
    ("lon_dd", LON_DIGITS),
]:
    for ct_alph_name, ct_alph in [("KA", KRYPTOS_ALPHABET), ("AZ", ALPH)]:
        for pt_alph_name, pt_alph in [("KA", KRYPTOS_ALPHABET), ("AZ", ALPH)]:
            for indicator in range(26):
                pt = quagmire3_decrypt(CT, pt_alph, ct_alph, key_nums, indicator)
                sc = crib_score(pt)
                label = f"Quag3 pt={pt_alph_name} ct={ct_alph_name} key={key_name} ind={indicator}"
                if sc > NOISE_FLOOR:
                    report(label, sc, pt)
                quag_results.append((sc, label, pt))

print(f"  Total Quag3 configs tested: {len(quag_results)}")
best_quag = max(quag_results, key=lambda x: x[0])
print(f"  Best Quag3 score: {best_quag[0]}/24 — {best_quag[1]}")
print()

# ════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("FINAL SUMMARY")
print("=" * 80)

all_results = results + trans_results + grid_results + combo_results + x_results + autokey_results + nw_results + stride_results + quag_results

total = len(all_results)
above_noise = [(s, l, p) for s, l, p in all_results if s > NOISE_FLOOR]
above_store = [(s, l, p) for s, l, p in all_results if s >= 10]

print(f"Total configurations tested: {total}")
print(f"Above noise floor (>{NOISE_FLOOR}): {len(above_noise)}")
print(f"Above store threshold (>=10): {len(above_store)}")
print()

# Score distribution
from collections import Counter
dist = Counter(s for s, _, _ in all_results)
print("Score distribution:")
for score in sorted(dist.keys(), reverse=True):
    print(f"  Score {score:2d}: {dist[score]:5d} configs")
print()

if above_noise:
    print("ALL configs above noise floor:")
    for sc, label, pt in sorted(above_noise, key=lambda x: -x[0]):
        print(f"  Score {sc:2d}/24: {label}")
        print(f"           PT: {pt[:60]}...")
        # Show which crib chars match
        matches = [(pos, CRIB_DICT[pos]) for pos in sorted(CRIB_POSITIONS) if pos < len(pt) and pt[pos] == CRIB_DICT[pos]]
        if matches:
            print(f"           Matches: {matches}")
        print()
else:
    print("NO configurations scored above noise floor.")
    print()

# Show the absolute best results
print("Top 10 results:")
top10 = sorted(all_results, key=lambda x: -x[0])[:10]
for sc, label, pt in top10:
    print(f"  Score {sc}/24: {label}")
    print(f"    PT: {pt[:60]}")
print()

print("CONCLUSION: ", end="")
if above_store:
    print(f"Found {len(above_store)} config(s) at store threshold or above. INVESTIGATE.")
elif above_noise:
    print(f"Found {len(above_noise)} config(s) above noise but below store threshold. Likely noise.")
else:
    print("All configurations at or below noise floor. K2 coordinate numbers alone do not directly key K4.")
