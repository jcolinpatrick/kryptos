#!/usr/bin/env python3
"""
Test K2 coordinates as transposition keys for K4.

Cipher: Transposition
Family: transposition
Status: active
Keyspace: ~500 configs
Last run: 2026-03-13
Best score: TBD
"""
import sys
import math
from itertools import product as iproduct
from typing import List, Tuple, Optional

sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_WORDS, N_CRIBS

# ── K2 coordinate key extractions ─────────────────────────────────────────
DIGITS_11 = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
NUMBERS_7 = [38, 57, 6, 5, 77, 8, 44]
NUMBERS_9 = [24, 38, 57, 6, 5, 77, 8, 44, 24]  # X=24 flanking
NORTH_DIGITS = [3, 8, 5, 7, 6, 5]
WEST_DIGITS = [7, 7, 8, 4, 4]
N_SECONDS = [1, 4, 0, 2, 2, 6]  # 140226 total seconds N
W_SECONDS = [2, 7, 7, 7, 2, 4]  # 277724 total seconds W
NORTH_HALF = [3, 8, 5, 7, 6, 5]
WEST_HALF = [7, 7, 8, 4, 4]

# ── Helpers ───────────────────────────────────────────────────────────────

def rank_key(digits: List[int], myszkowski: bool = False) -> List[int]:
    """Convert digit sequence to rank order (0-indexed).
    If myszkowski=True, equal digits get the same rank.
    Otherwise, ties broken left-to-right."""
    n = len(digits)
    if myszkowski:
        sorted_unique = sorted(set(digits))
        rank_map = {v: i for i, v in enumerate(sorted_unique)}
        return [rank_map[d] for d in digits]
    else:
        indexed = sorted(range(n), key=lambda i: (digits[i], i))
        ranks = [0] * n
        for rank, idx in enumerate(indexed):
            ranks[idx] = rank
        return ranks


def columnar_encrypt(text: str, key: List[int], ncols: int) -> str:
    """Columnar transposition: write text into rows of ncols, read by column order."""
    nrows = math.ceil(len(text) / ncols)
    padded = text.ljust(nrows * ncols, 'X')
    grid = []
    for r in range(nrows):
        grid.append(list(padded[r * ncols:(r + 1) * ncols]))
    # Read columns in key order
    order = sorted(range(ncols), key=lambda c: key[c])
    result = []
    for c in order:
        for r in range(nrows):
            result.append(grid[r][c])
    return ''.join(result)[:len(text)]


def columnar_decrypt(text: str, key: List[int], ncols: int) -> str:
    """Reverse columnar transposition."""
    nrows = math.ceil(len(text) / ncols)
    total = nrows * ncols
    short_cols = total - len(text)  # number of columns with nrows-1 chars

    order = sorted(range(ncols), key=lambda c: key[c])
    # Figure out which columns are short (last 'short_cols' in reading order)
    col_lengths = {}
    for rank, c in enumerate(order):
        if rank >= ncols - short_cols:
            col_lengths[c] = nrows - 1
        else:
            col_lengths[c] = nrows

    # Fill columns in reading order
    cols = {}
    pos = 0
    for c in order:
        length = col_lengths[c]
        cols[c] = list(text[pos:pos + length])
        pos += length

    # Read off by rows
    result = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return ''.join(result)[:len(text)]


def myszkowski_encrypt(text: str, key: List[int], ncols: int) -> str:
    """Myszkowski transposition: equal-rank columns read left-to-right together."""
    nrows = math.ceil(len(text) / ncols)
    padded = text.ljust(nrows * ncols, 'X')
    grid = []
    for r in range(nrows):
        grid.append(list(padded[r * ncols:(r + 1) * ncols]))

    max_rank = max(key)
    result = []
    for rank in range(max_rank + 1):
        cols_with_rank = [c for c in range(ncols) if key[c] == rank]
        for r in range(nrows):
            for c in cols_with_rank:
                result.append(grid[r][c])
    return ''.join(result)[:len(text)]


def myszkowski_decrypt(text: str, key: List[int], ncols: int) -> str:
    """Reverse Myszkowski transposition."""
    nrows = math.ceil(len(text) / ncols)
    total = nrows * ncols
    short_count = total - len(text)

    max_rank = max(key)
    # Determine column lengths
    order = sorted(range(ncols), key=lambda c: key[c])
    col_lengths = {}
    for i, c in enumerate(order):
        if i >= ncols - short_count:
            col_lengths[c] = nrows - 1
        else:
            col_lengths[c] = nrows

    # Fill in Myszkowski order
    cols = {c: [] for c in range(ncols)}
    pos = 0
    for rank in range(max_rank + 1):
        cols_with_rank = [c for c in range(ncols) if key[c] == rank]
        for r in range(nrows):
            for c in cols_with_rank:
                if len(cols[c]) < col_lengths[c]:
                    if pos < len(text):
                        cols[c].append(text[pos])
                        pos += 1

    result = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return ''.join(result)[:len(text)]


def check_cribs_fixed(text: str) -> int:
    """Check how many crib characters match at fixed positions."""
    score = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            score += 1
    return score


def check_cribs_free(text: str) -> List[Tuple[str, int, int]]:
    """Search for crib words anywhere in text. Returns (word, position, length)."""
    results = []
    for _, word in CRIB_WORDS:
        idx = text.find(word)
        if idx >= 0:
            results.append((word, idx, len(word)))
        # Check substrings of length >= 4
        for sublen in range(len(word), 3, -1):
            for start in range(len(word) - sublen + 1):
                sub = word[start:start + sublen]
                idx = text.find(sub)
                if idx >= 0 and sublen >= 4:
                    results.append((sub, idx, sublen))
    # Deduplicate
    return list(set(results))


def chain_addition(digits: List[int], target_len: int) -> List[int]:
    """VIC-style chain addition mod 10."""
    result = list(digits)
    while len(result) < target_len:
        result.append((result[-len(digits)] + result[-len(digits) + 1]) % 10)
    # More standard: each new = (d[i] + d[i+1]) % 10
    result2 = list(digits)
    while len(result2) < target_len:
        i = len(result2) - len(digits)
        result2.append((result2[-2] + result2[-1]) % 10)
    return result2[:target_len]


def reverse_text(text: str) -> str:
    return text[::-1]


def route_spiral_read(grid: List[List[str]], nrows: int, ncols: int) -> str:
    """Read grid in clockwise spiral order."""
    result = []
    top, bottom, left, right = 0, nrows - 1, 0, ncols - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            if top < nrows and c < ncols:
                result.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            if r < nrows and right < ncols:
                result.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if bottom < nrows and c < ncols:
                    result.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if r < nrows and left < ncols:
                    result.append(grid[r][left])
            left += 1
    return ''.join(result)


def route_snake_read(grid: List[List[str]], nrows: int, ncols: int) -> str:
    """Read grid in snake/boustrophedon order."""
    result = []
    for r in range(nrows):
        if r % 2 == 0:
            for c in range(ncols):
                result.append(grid[r][c])
        else:
            for c in range(ncols - 1, -1, -1):
                result.append(grid[r][c])
    return ''.join(result)


def route_diagonal_read(grid: List[List[str]], nrows: int, ncols: int) -> str:
    """Read grid in diagonal order (top-left to bottom-right diagonals)."""
    result = []
    for d in range(nrows + ncols - 1):
        for r in range(max(0, d - ncols + 1), min(d + 1, nrows)):
            c = d - r
            if c < ncols:
                result.append(grid[r][c])
    return ''.join(result)


def write_to_grid(text: str, nrows: int, ncols: int) -> List[List[str]]:
    """Write text into grid row by row."""
    padded = text.ljust(nrows * ncols, 'X')
    grid = []
    for r in range(nrows):
        grid.append(list(padded[r * ncols:(r + 1) * ncols]))
    return grid


def report(label: str, result: str, threshold: int = 2):
    """Report results if they show any crib matches."""
    fixed = check_cribs_fixed(result)
    free = check_cribs_free(result)
    free_long = [f for f in free if f[2] >= 4]
    if fixed >= threshold or free_long:
        print(f"  ** {label}")
        print(f"     Fixed crib score: {fixed}/{N_CRIBS}")
        if free_long:
            print(f"     Free matches: {free_long}")
        print(f"     Result: {result[:50]}...")
        print()
    return fixed


# ══════════════════════════════════════════════════════════════════════════
# MAIN TEST BATTERY
# ══════════════════════════════════════════════════════════════════════════

best_score = 0
best_label = ""
best_text = ""
all_results = []

def track(label, text, score):
    global best_score, best_label, best_text
    all_results.append((score, label, text))
    if score > best_score:
        best_score = score
        best_label = label
        best_text = text


print("=" * 80)
print("K2 COORDINATES AS TRANSPOSITION KEY FOR K4")
print("=" * 80)
print(f"CT: {CT}")
print(f"CT length: {CT_LEN}")
print()

# ── 1. Columnar transposition with 11-digit key ──────────────────────────
print("=" * 80)
print("1. COLUMNAR TRANSPOSITION WITH 11-DIGIT KEY [3,8,5,7,6,5,7,7,8,4,4]")
print("=" * 80)

key_std = rank_key(DIGITS_11, myszkowski=False)
key_mys = rank_key(DIGITS_11, myszkowski=True)
print(f"  Standard rank: {key_std}")
print(f"  Myszkowski rank: {key_mys}")
print()

for direction in ["encrypt", "decrypt"]:
    for ktype, key in [("standard", key_std), ("Myszkowski", key_mys)]:
        if direction == "encrypt":
            if ktype == "Myszkowski":
                result = myszkowski_encrypt(CT, key, 11)
            else:
                result = columnar_encrypt(CT, key, 11)
        else:
            if ktype == "Myszkowski":
                result = myszkowski_decrypt(CT, key, 11)
            else:
                result = columnar_decrypt(CT, key, 11)

        label = f"11-col {ktype} {direction}"
        sc = report(label, result)
        track(label, result, sc)

# Also try the raw digits as column order (not ranked)
for direction in ["encrypt", "decrypt"]:
    if direction == "encrypt":
        result = columnar_encrypt(CT, DIGITS_11, 11)
    else:
        result = columnar_decrypt(CT, DIGITS_11, 11)
    label = f"11-col raw-digits {direction}"
    sc = report(label, result)
    track(label, result, sc)

print()

# ── 2. Columnar with sub-sequences ───────────────────────────────────────
print("=" * 80)
print("2. COLUMNAR WITH SUB-SEQUENCES")
print("=" * 80)

# 7-column key from numbers
key7_std = rank_key(NUMBERS_7, myszkowski=False)
key7_mys = rank_key(NUMBERS_7, myszkowski=True)
print(f"  7-number key {NUMBERS_7} -> std rank: {key7_std}, Mys rank: {key7_mys}")

for direction in ["encrypt", "decrypt"]:
    for ktype, key in [("standard", key7_std), ("Myszkowski", key7_mys)]:
        if direction == "encrypt":
            fn = myszkowski_encrypt if ktype == "Myszkowski" else columnar_encrypt
            result = fn(CT, key, 7)
        else:
            fn = myszkowski_decrypt if ktype == "Myszkowski" else columnar_decrypt
            result = fn(CT, key, 7)
        label = f"7-col {ktype} {direction} (numbers)"
        sc = report(label, result)
        track(label, result, sc)

# 9-column key with X flanking
key9_std = rank_key(NUMBERS_9, myszkowski=False)
key9_mys = rank_key(NUMBERS_9, myszkowski=True)
print(f"  9-number key {NUMBERS_9} -> std rank: {key9_std}, Mys rank: {key9_mys}")

for direction in ["encrypt", "decrypt"]:
    for ktype, key in [("standard", key9_std), ("Myszkowski", key9_mys)]:
        if direction == "encrypt":
            fn = myszkowski_encrypt if ktype == "Myszkowski" else columnar_encrypt
            result = fn(CT, key, 9)
        else:
            fn = myszkowski_decrypt if ktype == "Myszkowski" else columnar_decrypt
            result = fn(CT, key, 9)
        label = f"9-col {ktype} {direction} (X-flanked)"
        sc = report(label, result)
        track(label, result, sc)

# Double transposition: North digits x West digits
print(f"\n  Double transposition: N={NORTH_DIGITS} x W={WEST_DIGITS}")
key_n = rank_key(NORTH_DIGITS, myszkowski=False)
key_w = rank_key(WEST_DIGITS, myszkowski=False)
key_n_mys = rank_key(NORTH_DIGITS, myszkowski=True)
key_w_mys = rank_key(WEST_DIGITS, myszkowski=True)
print(f"  N std rank: {key_n}, W std rank: {key_w}")

for first_label, first_key, first_ncols in [
    ("N-std", key_n, 6), ("N-Mys", key_n_mys, 6),
    ("W-std", key_w, 5), ("W-Mys", key_w_mys, 5)
]:
    for second_label, second_key, second_ncols in [
        ("N-std", key_n, 6), ("N-Mys", key_n_mys, 6),
        ("W-std", key_w, 5), ("W-Mys", key_w_mys, 5)
    ]:
        if first_label == second_label:
            continue
        for d1 in ["enc", "dec"]:
            for d2 in ["enc", "dec"]:
                fn1e = myszkowski_encrypt if "Mys" in first_label else columnar_encrypt
                fn1d = myszkowski_decrypt if "Mys" in first_label else columnar_decrypt
                fn2e = myszkowski_encrypt if "Mys" in second_label else columnar_encrypt
                fn2d = myszkowski_decrypt if "Mys" in second_label else columnar_decrypt

                if d1 == "enc":
                    mid = fn1e(CT, first_key, first_ncols)
                else:
                    mid = fn1d(CT, first_key, first_ncols)
                if d2 == "enc":
                    result = fn2e(mid, second_key, second_ncols)
                else:
                    result = fn2d(mid, second_key, second_ncols)

                label = f"Double {first_label}({d1})+{second_label}({d2})"
                sc = report(label, result)
                track(label, result, sc)

# Also split key [3,8,5,7,6] and [5,7,7,8,4,4]
key_a = rank_key([3, 8, 5, 7, 6])
key_b = rank_key([5, 7, 7, 8, 4, 4])
key_a_mys = rank_key([3, 8, 5, 7, 6], myszkowski=True)
key_b_mys = rank_key([5, 7, 7, 8, 4, 4], myszkowski=True)
print(f"\n  Split key [3,8,5,7,6] -> {key_a} and [5,7,7,8,4,4] -> {key_b}")

for d1 in ["enc", "dec"]:
    for d2 in ["enc", "dec"]:
        for mys in [False, True]:
            k1 = key_a_mys if mys else key_a
            k2 = key_b_mys if mys else key_b
            fn_e = myszkowski_encrypt if mys else columnar_encrypt
            fn_d = myszkowski_decrypt if mys else columnar_decrypt
            mid = fn_e(CT, k1, 5) if d1 == "enc" else fn_d(CT, k1, 5)
            result = fn_e(mid, k2, 6) if d2 == "enc" else fn_d(mid, k2, 6)
            kname = "Mys" if mys else "std"
            label = f"Split5+6 {kname} ({d1},{d2})"
            sc = report(label, result)
            track(label, result, sc)

print()

# ── 3. Route transposition on derived grids ──────────────────────────────
print("=" * 80)
print("3. ROUTE TRANSPOSITION ON DERIVED GRIDS")
print("=" * 80)

route_configs = [
    (9, 11, "11-digit key", DIGITS_11),
    (11, 9, "11-digit key transposed", DIGITS_11[:9]),
    (14, 7, "7-number key", NUMBERS_7),
    (7, 14, "7-number key transposed", list(range(14))),
]

for nrows, ncols, label_base, col_key in route_configs:
    if nrows * ncols < CT_LEN:
        continue
    grid = write_to_grid(CT, nrows, ncols)

    # Apply column reorder if key fits
    if len(col_key) == ncols:
        col_order = rank_key(col_key)
        reordered = []
        for r in range(nrows):
            row = ['X'] * ncols
            for c in range(ncols):
                row[col_order[c]] = grid[r][c] if c < len(grid[r]) else 'X'
            reordered.append(row)
    else:
        reordered = grid

    for read_name, read_fn in [("spiral", route_spiral_read),
                                 ("snake", route_snake_read),
                                 ("diagonal", route_diagonal_read)]:
        result_raw = read_fn(grid, nrows, ncols)[:CT_LEN]
        label = f"Route {nrows}x{ncols} {label_base} {read_name} raw"
        sc = report(label, result_raw)
        track(label, result_raw, sc)

        if len(col_key) == ncols:
            result_reord = read_fn(reordered, nrows, ncols)[:CT_LEN]
            label2 = f"Route {nrows}x{ncols} {label_base} {read_name} reordered"
            sc2 = report(label2, result_reord)
            track(label2, result_reord, sc2)

    # Also read columns in key order
    if len(col_key) == ncols:
        ranked = rank_key(col_key)
        col_read_order = sorted(range(ncols), key=lambda c: ranked[c])
        result_col = []
        for c in col_read_order:
            for r in range(nrows):
                if c < len(grid[r]):
                    result_col.append(grid[r][c])
        result_col = ''.join(result_col)[:CT_LEN]
        label = f"Route {nrows}x{ncols} column-order read"
        sc = report(label, result_col)
        track(label, result_col, sc)

print()

# ── 4. Double transposition with seconds keys ────────────────────────────
print("=" * 80)
print("4. DOUBLE TRANSPOSITION WITH SECONDS KEYS")
print("=" * 80)

key_ns = rank_key(N_SECONDS)
key_ws = rank_key(W_SECONDS)
key_ns_mys = rank_key(N_SECONDS, myszkowski=True)
key_ws_mys = rank_key(W_SECONDS, myszkowski=True)
print(f"  N seconds {N_SECONDS} -> std: {key_ns}, Mys: {key_ns_mys}")
print(f"  W seconds {W_SECONDS} -> std: {key_ws}, Mys: {key_ws_mys}")

for d1 in ["enc", "dec"]:
    for d2 in ["enc", "dec"]:
        for mys in [False, True]:
            k1 = key_ns_mys if mys else key_ns
            k2 = key_ws_mys if mys else key_ws
            fn_e = myszkowski_encrypt if mys else columnar_encrypt
            fn_d = myszkowski_decrypt if mys else columnar_decrypt
            mid = fn_e(CT, k1, 6) if d1 == "enc" else fn_d(CT, k1, 6)
            result = fn_e(mid, k2, 6) if d2 == "enc" else fn_d(mid, k2, 6)
            kname = "Mys" if mys else "std"
            label = f"Seconds {kname} N({d1})+W({d2})"
            sc = report(label, result)
            track(label, result, sc)

# Also try as row x column keys
print(f"\n  Row x Column: N_seconds as rows, W_seconds as cols")
for d1 in ["enc", "dec"]:
    for d2 in ["enc", "dec"]:
        mid = columnar_encrypt(CT, key_ns, 6) if d1 == "enc" else columnar_decrypt(CT, key_ns, 6)
        # Transpose: read the intermediate into a grid with 6 columns, then
        # apply W_seconds key to that
        result = columnar_encrypt(mid, key_ws, 6) if d2 == "enc" else columnar_decrypt(mid, key_ws, 6)
        label = f"RowCol N({d1})+W({d2})"
        sc = report(label, result)
        track(label, result, sc)

print()

# ── 5. NORTH/WEST directional grid reading ───────────────────────────────
print("=" * 80)
print("5. NORTH/WEST DIRECTIONAL GRID READING")
print("=" * 80)

for ncols in [7, 8, 9, 11, 14]:
    nrows = math.ceil(CT_LEN / ncols)
    grid = write_to_grid(CT, nrows, ncols)

    # Bottom-to-top, left-to-right (NORTH = up)
    result_north = []
    for c in range(ncols):
        for r in range(nrows - 1, -1, -1):
            if r < len(grid) and c < len(grid[r]):
                result_north.append(grid[r][c])
    result_north = ''.join(result_north)[:CT_LEN]
    label = f"North-read {nrows}x{ncols} (bottom-up, L-R)"
    sc = report(label, result_north)
    track(label, result_north, sc)

    # Right-to-left, top-to-bottom (WEST = left)
    result_west = []
    for r in range(nrows):
        for c in range(ncols - 1, -1, -1):
            if c < len(grid[r]):
                result_west.append(grid[r][c])
    result_west = ''.join(result_west)[:CT_LEN]
    label = f"West-read {nrows}x{ncols} (R-L, top-down)"
    sc = report(label, result_west)
    track(label, result_west, sc)

    # Bottom-to-top, right-to-left (NORTHWEST)
    result_nw = []
    for c in range(ncols - 1, -1, -1):
        for r in range(nrows - 1, -1, -1):
            if r < len(grid) and c < len(grid[r]):
                result_nw.append(grid[r][c])
    result_nw = ''.join(result_nw)[:CT_LEN]
    label = f"NW-read {nrows}x{ncols} (bottom-up, R-L)"
    sc = report(label, result_nw)
    track(label, result_nw, sc)

    # Column-by-column bottom-to-top, then reverse row direction alternating
    result_snake_vert = []
    for c in range(ncols):
        if c % 2 == 0:
            for r in range(nrows - 1, -1, -1):
                if r < len(grid) and c < len(grid[r]):
                    result_snake_vert.append(grid[r][c])
        else:
            for r in range(nrows):
                if r < len(grid) and c < len(grid[r]):
                    result_snake_vert.append(grid[r][c])
    result_snake_vert = ''.join(result_snake_vert)[:CT_LEN]
    label = f"VertSnake {nrows}x{ncols}"
    sc = report(label, result_snake_vert)
    track(label, result_snake_vert, sc)

print()

# ── 6. VIC-style chain addition key derivation ───────────────────────────
print("=" * 80)
print("6. VIC-STYLE CHAIN ADDITION KEY DERIVATION")
print("=" * 80)

# Chain addition from 11 digits to length 97
extended = chain_addition(DIGITS_11, CT_LEN)
print(f"  Chain-extended key (first 30): {extended[:30]}")
ext_ranked = rank_key(extended)

# Use as direct transposition permutation
result_perm = [''] * CT_LEN
for i in range(CT_LEN):
    result_perm[ext_ranked[i]] = CT[i]
result_perm = ''.join(result_perm)
label = "VIC chain perm (gather)"
sc = report(label, result_perm)
track(label, result_perm, sc)

result_inv = [''] * CT_LEN
for i in range(CT_LEN):
    result_inv[i] = CT[ext_ranked[i]]
result_inv = ''.join(result_inv)
label = "VIC chain perm (scatter)"
sc = report(label, result_inv)
track(label, result_inv, sc)

# VIC chain for various grid widths
for ncols in [7, 8, 9, 10, 11, 13, 14]:
    ext_col = chain_addition(DIGITS_11, ncols)
    ext_col_ranked = rank_key(ext_col)
    for direction in ["encrypt", "decrypt"]:
        if direction == "encrypt":
            result = columnar_encrypt(CT, ext_col_ranked, ncols)
        else:
            result = columnar_decrypt(CT, ext_col_ranked, ncols)
        label = f"VIC chain col-{ncols} {direction}"
        sc = report(label, result)
        track(label, result, sc)

# VIC chain from different seed sequences
for seed_name, seed in [("N_seconds", N_SECONDS), ("W_seconds", W_SECONDS),
                          ("North_half", NORTH_HALF), ("West_half", WEST_HALF)]:
    for ncols in [7, 9, 11, 13]:
        ext = chain_addition(seed, ncols)
        ranked = rank_key(ext)
        for direction in ["encrypt", "decrypt"]:
            if direction == "encrypt":
                result = columnar_encrypt(CT, ranked, ncols)
            else:
                result = columnar_decrypt(CT, ranked, ncols)
            label = f"VIC {seed_name} col-{ncols} {direction}"
            sc = report(label, result)
            track(label, result, sc)

# VIC chain as full-length permutation from different seeds
for seed_name, seed in [("N_seconds", N_SECONDS), ("W_seconds", W_SECONDS),
                          ("digits11", DIGITS_11)]:
    ext = chain_addition(seed, CT_LEN)
    ranked = rank_key(ext)
    result_g = [''] * CT_LEN
    result_s = [''] * CT_LEN
    for i in range(CT_LEN):
        result_g[ranked[i]] = CT[i]
        result_s[i] = CT[ranked[i]]
    rg = ''.join(result_g)
    rs = ''.join(result_s)
    label_g = f"VIC {seed_name} full-perm gather"
    label_s = f"VIC {seed_name} full-perm scatter"
    sc_g = report(label_g, rg)
    sc_s = report(label_s, rs)
    track(label_g, rg, sc_g)
    track(label_s, rs, sc_s)

print()

# ── 7. Additional: coordinate-literal keys ───────────────────────────────
print("=" * 80)
print("7. ADDITIONAL COORDINATE-DERIVED KEYS")
print("=" * 80)

# Degrees as key: 38, 57, 6.5, 77, 8, 44 -> [38,57,7,77,8,44] (round 6.5)
deg_key = [38, 57, 7, 77, 8, 44]
deg_ranked = rank_key(deg_key)
print(f"  Degree key {deg_key} -> rank: {deg_ranked}")
for direction in ["encrypt", "decrypt"]:
    if direction == "encrypt":
        result = columnar_encrypt(CT, deg_ranked, 6)
    else:
        result = columnar_decrypt(CT, deg_ranked, 6)
    label = f"Degree 6-col {direction}"
    sc = report(label, result)
    track(label, result, sc)

# Decimal degrees: 38.9518, 77.1456 -> digits [3,8,9,5,1,8,7,7,1,4,5,6]
dec_digits = [3, 8, 9, 5, 1, 8, 7, 7, 1, 4, 5, 6]
dec_ranked = rank_key(dec_digits)
print(f"  Decimal degree digits {dec_digits} -> rank: {dec_ranked}")
for direction in ["encrypt", "decrypt"]:
    if direction == "encrypt":
        result = columnar_encrypt(CT, dec_ranked, 12)
    else:
        result = columnar_decrypt(CT, dec_ranked, 12)
    label = f"Decimal-deg 12-col {direction}"
    sc = report(label, result)
    track(label, result, sc)

# Combined all unique digits in order: 3 8 5 7 6 4 -> 6 unique digits
unique_digits = []
seen = set()
for d in DIGITS_11:
    if d not in seen:
        unique_digits.append(d)
        seen.add(d)
print(f"  Unique digits: {unique_digits}")
unique_ranked = rank_key(unique_digits)
for direction in ["encrypt", "decrypt"]:
    if direction == "encrypt":
        result = columnar_encrypt(CT, unique_ranked, len(unique_digits))
    else:
        result = columnar_decrypt(CT, unique_ranked, len(unique_digits))
    label = f"Unique-digit {len(unique_digits)}-col {direction}"
    sc = report(label, result)
    track(label, result, sc)

# All 11 digits concatenated as a text key -> KRYPTOS alphabet mapping
# Map digits to letters: 3->D, 8->I, 5->F, 7->H, 6->G, 4->E
digit_to_letter = {d: chr(ord('A') + d) for d in range(10)}
text_key_from_digits = ''.join(digit_to_letter[d] for d in DIGITS_11)
print(f"  Digits as letters: {text_key_from_digits}")
text_ranked = rank_key([ord(c) - ord('A') for c in text_key_from_digits])
for direction in ["encrypt", "decrypt"]:
    if direction == "encrypt":
        result = columnar_encrypt(CT, text_ranked, 11)
    else:
        result = columnar_decrypt(CT, text_ranked, 11)
    label = f"DigitLetters 11-col {direction}"
    sc = report(label, result)
    track(label, result, sc)

print()

# ── 8. Stride/skip transpositions ────────────────────────────────────────
print("=" * 80)
print("8. STRIDE/SKIP TRANSPOSITIONS FROM COORDINATE VALUES")
print("=" * 80)

stride_values = set()
for v in DIGITS_11 + NUMBERS_7 + [97, 38, 57, 77, 44, 6, 5, 8, 14, 31]:
    if v > 0:
        stride_values.add(v)
stride_values = sorted(stride_values)

for stride in stride_values:
    if stride >= CT_LEN:
        continue
    # Read every stride-th character
    result = []
    visited = set()
    pos = 0
    while len(result) < CT_LEN:
        if pos < CT_LEN and pos not in visited:
            result.append(CT[pos])
            visited.add(pos)
            pos = (pos + stride) % CT_LEN
        else:
            # Find next unvisited
            found = False
            for p in range(CT_LEN):
                if p not in visited:
                    pos = p
                    result.append(CT[pos])
                    visited.add(pos)
                    pos = (pos + stride) % CT_LEN
                    found = True
                    break
            if not found:
                break
    result_str = ''.join(result)
    label = f"Stride-{stride}"
    sc = report(label, result_str)
    track(label, result_str, sc)

    # Inverse stride
    inv_result = [''] * CT_LEN
    visited2 = set()
    pos2 = 0
    src_idx = 0
    while src_idx < CT_LEN:
        if pos2 < CT_LEN and pos2 not in visited2:
            inv_result[pos2] = CT[src_idx]
            visited2.add(pos2)
            src_idx += 1
            pos2 = (pos2 + stride) % CT_LEN
        else:
            for p in range(CT_LEN):
                if p not in visited2:
                    pos2 = p
                    inv_result[pos2] = CT[src_idx]
                    visited2.add(pos2)
                    src_idx += 1
                    pos2 = (pos2 + stride) % CT_LEN
                    break
    inv_str = ''.join(inv_result)
    label = f"InvStride-{stride}"
    sc = report(label, inv_str)
    track(label, inv_str, sc)

print()

# ── 9. Rail fence with coordinate-derived rails ─────────────────────────
print("=" * 80)
print("9. RAIL FENCE WITH COORDINATE-DERIVED RAILS")
print("=" * 80)

def rail_fence_encrypt(text: str, rails: int) -> str:
    if rails <= 1:
        return text
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for ch in text:
        fence[rail].append(ch)
        rail += direction
        if rail >= rails:
            rail = rails - 2
            direction = -1
        elif rail < 0:
            rail = 1
            direction = 1
    return ''.join(''.join(row) for row in fence)


def rail_fence_decrypt(text: str, rails: int) -> str:
    if rails <= 1:
        return text
    n = len(text)
    # Determine the pattern
    pattern = []
    rail = 0
    direction = 1
    for i in range(n):
        pattern.append(rail)
        rail += direction
        if rail >= rails:
            rail = rails - 2
            direction = -1
        elif rail < 0:
            rail = 1
            direction = 1
    # Count chars per rail
    counts = [0] * rails
    for r in pattern:
        counts[r] += 1
    # Fill rails
    rail_chars = []
    pos = 0
    for r in range(rails):
        rail_chars.append(list(text[pos:pos + counts[r]]))
        pos += counts[r]
    # Read off
    indices = [0] * rails
    result = []
    for r in pattern:
        result.append(rail_chars[r][indices[r]])
        indices[r] += 1
    return ''.join(result)


for nrails in set([3, 4, 5, 6, 7, 8, 11, 14, 38, 44, 57]):
    if nrails >= CT_LEN or nrails < 2:
        continue
    for direction in ["encrypt", "decrypt"]:
        if direction == "encrypt":
            result = rail_fence_encrypt(CT, nrails)
        else:
            result = rail_fence_decrypt(CT, nrails)
        label = f"Rail-{nrails} {direction}"
        sc = report(label, result)
        track(label, result, sc)

print()

# ── 10. Specific grid: 8 lines × ~12 cols (from legal pad "8 lines 73") ─
print("=" * 80)
print("10. GRID CONFIGS INSPIRED BY LEGAL PAD + COORDINATES")
print("=" * 80)

# 8 lines of 73 chars -> 8x10 = 80 (close), 8x13 = 104
# But with 97 chars: 8x13 = 104 (7 padding), or 7x14 = 98 (1 padding)
for nrows, ncols in [(8, 13), (7, 14), (8, 14), (14, 7), (13, 8)]:
    if nrows * ncols < CT_LEN:
        continue
    grid = write_to_grid(CT, nrows, ncols)

    # Column read with K2 coordinate key truncated/extended
    for key_name, raw_key in [("digits11", DIGITS_11), ("numbers7", NUMBERS_7)]:
        if len(raw_key) != ncols:
            continue
        ranked = rank_key(raw_key)
        for direction in ["encrypt", "decrypt"]:
            if direction == "encrypt":
                result = columnar_encrypt(CT, ranked, ncols)
            else:
                result = columnar_decrypt(CT, ranked, ncols)
            label = f"Grid {nrows}x{ncols} {key_name} {direction}"
            sc = report(label, result)
            track(label, result, sc)

    # Also try 38-57-6-5 as column subset reordering for 7-col grids
    if ncols == 7:
        keys_7 = rank_key(NUMBERS_7)
        for direction in ["encrypt", "decrypt"]:
            if direction == "encrypt":
                result = columnar_encrypt(CT, keys_7, 7)
            else:
                result = columnar_decrypt(CT, keys_7, 7)
            label = f"Grid {nrows}x{ncols} numbers7 {direction}"
            sc = report(label, result)
            track(label, result, sc)

print()

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("SUMMARY")
print("=" * 80)

all_results.sort(key=lambda x: -x[0])
print(f"\nTotal configurations tested: {len(all_results)}")
print(f"Best fixed crib score: {best_score}/{N_CRIBS}")

if best_score > 0:
    print(f"Best label: {best_label}")
    print(f"Best text: {best_text}")

print("\nAll results with score >= 1:")
for score, label, text in all_results:
    if score >= 1:
        print(f"  {score:2d}/{N_CRIBS} | {label}")
        print(f"         {text}")

print("\nAll results with score == 0 (sample of first 10):")
count = 0
for score, label, text in all_results:
    if score == 0:
        count += 1
        if count <= 10:
            print(f"  {score:2d}/{N_CRIBS} | {label}: {text[:40]}...")

print(f"\n  ... and {len([r for r in all_results if r[0] == 0]) - min(10, count)} more with score 0")

# Free crib search on all results
print("\n" + "=" * 80)
print("FREE CRIB SEARCH (substrings >= 5 chars anywhere)")
print("=" * 80)
for score, label, text in all_results:
    free = check_cribs_free(text)
    long_free = [f for f in free if f[2] >= 5]
    if long_free:
        print(f"  {label}: {long_free}")
        print(f"    Text: {text}")

print("\nDone.")
