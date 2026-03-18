#!/usr/bin/env python3
"""
Cipher: route transposition (incomplete)
Family: transposition/other
Status: active
Keyspace: ~8000 configs
Last run:
Best score:
"""
"""E-INCOMPLETE-ROUTE-73: Bean's incomplete route transposition on null-extracted 73-char text.

MOTIVATION: Bean (2021 video) suggests K4 may use "incomplete route transpositions —
perhaps with 7 and 3 rows in each rectangle", paralleling K3's double rotational
transposition method.

K3 method: write into 24x14 grid, rotate 90 CW, read; write into 8x42, rotate 90 CW, read.
K3 is 336 chars. K4 carved = 97, but the two-system model says 24 are nulls, leaving 73.

KEY INSIGHT: 73 is PRIME — no clean factor pairs. But:
  - 73+1 = 74 = 2x37
  - 73+2 = 75 = 3x25 = 5x15
  - 73+4 = 77 = 7x11  (WIDTH 7 = KRYPTOS length!)
  - 73+5 = 78 = 6x13  (period 13 significant)
  - 73+3 = 76 = 4x19 = 2x38

So with 4 padding chars, we get a PERFECT 7x11 grid — the prime candidate.

ARCHITECTURE:
  Phase 1: Single route transpositions on ct73 at all widths 2-37
           (write row-major, read by multiple routes, and inverse)
           + substitution (Beaufort DEFECTOR AZ, Vigenere KRYPTOS KA, etc.)
  Phase 2: K3-style double rotation on ct73 (with padding for clean grids)
           Focus on 7x11 (77=73+4), 3x25/5x15 (75=73+2), 2x37 (74=73+1)
  Phase 3: Bean-specific "7 and 3 rows" — double transposition col7 then col3
  Phase 4: Incomplete route (partial last row) read orders
  Phase 5: Route on the 28x31 grid cells occupied by K4

Cribs in 73-char text (shifted due to null extraction):
  ENE at positions 13-25, BCL at positions 47-57 (approximate, depends on mask)

Scoring: both anchored (at shifted crib positions) and free (substring search).
"""
import json
import math
import os
import sys
import time
from collections import Counter, defaultdict
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.scoring.free_crib import score_free_fast
from kryptos.kernel.scoring.ic import ic

# ══════════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════════

# Consensus null mask from MEMORY.md (17 consensus + variable positions)
# Using the best-known 24 null positions from the DEFECTOR:AZ_beau+col7 model
CONSENSUS_NULLS_17 = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}

# The user-specified mask
USER_MASK = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40, 52, 55, 58, 59, 74, 75, 78, 84, 85, 88, 94, 96]

# Several plausible masks (from 15/24 scoring masks)
MASKS = {
    "user_mask": USER_MASK,
}


def extract_73(ct97, null_positions):
    """Extract 73 chars by removing null positions."""
    return ''.join(c for i, c in enumerate(ct97) if i not in set(null_positions))


def find_shifted_cribs(ct97, null_positions):
    """Find where the cribs end up in the 73-char extracted text."""
    null_set = set(null_positions)
    mapping = {}  # old_pos -> new_pos
    new_pos = 0
    for old_pos in range(len(ct97)):
        if old_pos not in null_set:
            mapping[old_pos] = new_pos
            new_pos += 1

    ene_start_97 = 21  # EASTNORTHEAST starts at pos 21 in 97-char
    bc_start_97 = 63   # BERLINCLOCK starts at pos 63 in 97-char

    # Map crib positions to 73-char positions
    ene_positions_73 = []
    for i in range(13):
        pos97 = ene_start_97 + i
        if pos97 in mapping:
            ene_positions_73.append(mapping[pos97])
        else:
            ene_positions_73.append(None)  # This crib char is a null!?

    bc_positions_73 = []
    for i in range(11):
        pos97 = bc_start_97 + i
        if pos97 in mapping:
            bc_positions_73.append(mapping[pos97])
        else:
            bc_positions_73.append(None)

    return ene_positions_73, bc_positions_73, mapping


# ══════════════════════════════════════════════════════════════════════════
# Substitution primitives
# ══════════════════════════════════════════════════════════════════════════

KRYPTOS_ALPHABET = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}

def az_beau_decrypt(ct, key):
    """Beaufort decrypt with AZ alphabet: PT = (K - CT) mod 26."""
    result = []
    klen = len(key)
    for i, ch in enumerate(ct):
        c = ALPH_IDX[ch]
        k = ALPH_IDX[key[i % klen]]
        result.append(ALPH[(k - c) % MOD])
    return ''.join(result)

def az_vig_decrypt(ct, key):
    """Vigenere decrypt with AZ: PT = (CT - K) mod 26."""
    result = []
    klen = len(key)
    for i, ch in enumerate(ct):
        c = ALPH_IDX[ch]
        k = ALPH_IDX[key[i % klen]]
        result.append(ALPH[(c - k) % MOD])
    return ''.join(result)

def ka_vig_decrypt(ct, key):
    """Vigenere decrypt with KA alphabet."""
    result = []
    klen = len(key)
    for i, ch in enumerate(ct):
        c = KA_IDX[ch]
        k = KA_IDX[key[i % klen]]
        result.append(KRYPTOS_ALPHABET[(c - k) % MOD])
    return ''.join(result)

def ka_beau_decrypt(ct, key):
    """Beaufort decrypt with KA alphabet."""
    result = []
    klen = len(key)
    for i, ch in enumerate(ct):
        c = KA_IDX[ch]
        k = KA_IDX[key[i % klen]]
        result.append(KRYPTOS_ALPHABET[(k - c) % MOD])
    return ''.join(result)

def az_beau_autokey_decrypt(ct, primer):
    """Beaufort autokey decrypt (key = primer + preceding PT)."""
    result = []
    key_stream = list(primer)
    for i, ch in enumerate(ct):
        c = ALPH_IDX[ch]
        k = ALPH_IDX[key_stream[i]]
        p = (k - c) % MOD
        result.append(ALPH[p])
        if i + len(primer) < len(ct):
            key_stream.append(ALPH[p])
    return ''.join(result)

def ka_vig_autokey_decrypt(ct, primer):
    """KA Vigenere autokey decrypt (key = primer + preceding PT)."""
    result = []
    key_stream = list(primer)
    for i, ch in enumerate(ct):
        c = KA_IDX[ch]
        k = KA_IDX[key_stream[i]]
        p = (c - k) % MOD
        result.append(KRYPTOS_ALPHABET[p])
        if i + len(primer) < len(ct):
            key_stream.append(KRYPTOS_ALPHABET[p])
    return ''.join(result)


CIPHER_FNS = {
    "AZ_beau_DEFECTOR": lambda ct: az_beau_decrypt(ct, "DEFECTOR"),
    "AZ_vig_DEFECTOR": lambda ct: az_vig_decrypt(ct, "DEFECTOR"),
    "KA_vig_KRYPTOS": lambda ct: ka_vig_decrypt(ct, "KRYPTOS"),
    "KA_beau_KRYPTOS": lambda ct: ka_beau_decrypt(ct, "KRYPTOS"),
    "AZ_beau_PALIMPSEST": lambda ct: az_beau_decrypt(ct, "PALIMPSEST"),
    "AZ_vig_PALIMPSEST": lambda ct: az_vig_decrypt(ct, "PALIMPSEST"),
    "KA_vig_ABSCISSA": lambda ct: ka_vig_decrypt(ct, "ABSCISSA"),
    "AZ_beau_KRYPTOS": lambda ct: az_beau_decrypt(ct, "KRYPTOS"),
    "KA_vig_KOMPASS": lambda ct: ka_vig_decrypt(ct, "KOMPASS"),
    "AZ_beau_autokey_DEFECTOR": lambda ct: az_beau_autokey_decrypt(ct, "DEFECTOR"),
    "KA_vig_autokey_KRYPTOS": lambda ct: ka_vig_autokey_decrypt(ct, "KRYPTOS"),
    "IDENTITY": lambda ct: ct,
}


# ══════════════════════════════════════════════════════════════════════════
# Grid/Route primitives
# ══════════════════════════════════════════════════════════════════════════

def write_grid_rowmajor(text, rows, cols, pad_char='X'):
    """Write text into rows x cols grid, row-major. Pad if needed."""
    n = rows * cols
    padded = text + pad_char * (n - len(text))
    grid = []
    for r in range(rows):
        grid.append(list(padded[r * cols:(r + 1) * cols]))
    return grid


def read_grid_rowmajor(grid):
    return ''.join(ch for row in grid for ch in row)


def read_grid_colmajor(grid, rows, cols):
    return ''.join(grid[r][c] for c in range(cols) for r in range(rows))


def read_serpentine_h(grid, rows, cols):
    result = []
    for r in range(rows):
        if r % 2 == 0:
            for c in range(cols): result.append(grid[r][c])
        else:
            for c in range(cols - 1, -1, -1): result.append(grid[r][c])
    return ''.join(result)


def read_serpentine_v(grid, rows, cols):
    result = []
    for c in range(cols):
        if c % 2 == 0:
            for r in range(rows): result.append(grid[r][c])
        else:
            for r in range(rows - 1, -1, -1): result.append(grid[r][c])
    return ''.join(result)


def read_spiral_cw(grid, rows, cols):
    result = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            result.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            result.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                result.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                result.append(grid[r][left])
            left += 1
    return ''.join(result)


def read_spiral_ccw(grid, rows, cols):
    result = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for r in range(top, bottom + 1):
            result.append(grid[r][left])
        left += 1
        if top <= bottom:
            for c in range(left, right + 1):
                result.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                result.append(grid[r][right])
            right -= 1
        for c in range(right, left - 1, -1):
            result.append(grid[top][c])
        top += 1
    return ''.join(result)


def read_diagonal_nwse(grid, rows, cols):
    result = []
    for d in range(rows + cols - 1):
        for r in range(max(0, d - cols + 1), min(rows, d + 1)):
            c = d - r
            if 0 <= c < cols:
                result.append(grid[r][c])
    return ''.join(result)


def read_diagonal_nesw(grid, rows, cols):
    result = []
    for d in range(rows + cols - 1):
        for r in range(max(0, d - cols + 1), min(rows, d + 1)):
            c = cols - 1 - (d - r)
            if 0 <= c < cols:
                result.append(grid[r][c])
    return ''.join(result)


def read_colmajor_reverse(grid, rows, cols):
    """Columns right-to-left, top-to-bottom."""
    return ''.join(grid[r][c] for c in range(cols - 1, -1, -1) for r in range(rows))


def read_rowmajor_reverse(grid, rows, cols):
    """Rows bottom-to-top, left-to-right."""
    return ''.join(grid[r][c] for r in range(rows - 1, -1, -1) for c in range(cols))


READ_METHODS = {
    "col_major": read_grid_colmajor,
    "serpentine_h": read_serpentine_h,
    "serpentine_v": read_serpentine_v,
    "spiral_cw": read_spiral_cw,
    "spiral_ccw": read_spiral_ccw,
    "diag_nwse": read_diagonal_nwse,
    "diag_nesw": read_diagonal_nesw,
    "col_rev": read_colmajor_reverse,
    "row_rev": read_rowmajor_reverse,
}


def rotate_cw(grid):
    """Rotate grid 90 degrees clockwise."""
    rows, cols = len(grid), len(grid[0])
    new_grid = []
    for c in range(cols):
        new_row = []
        for r in range(rows - 1, -1, -1):
            new_row.append(grid[r][c])
        new_grid.append(new_row)
    return new_grid


def rotate_ccw(grid):
    """Rotate grid 90 degrees counter-clockwise."""
    rows, cols = len(grid), len(grid[0])
    new_grid = []
    for c in range(cols - 1, -1, -1):
        new_row = []
        for r in range(rows):
            new_row.append(grid[r][c])
        new_grid.append(new_row)
    return new_grid


def rotate_180(grid):
    return [row[::-1] for row in grid[::-1]]


ROTATIONS = {"cw": rotate_cw, "ccw": rotate_ccw, "180": rotate_180}


# ══════════════════════════════════════════════════════════════════════════
# Scoring
# ══════════════════════════════════════════════════════════════════════════

def score_text(text, ene_pos_73=None, bc_pos_73=None):
    """Score candidate plaintext. Returns (free_score, anchored_score, ic_val)."""
    free = score_free_fast(text)
    ic_val = ic(text) if len(text) >= 20 else 0.0

    # Anchored score against shifted crib positions
    anchored = 0
    if ene_pos_73 is not None:
        ene = "EASTNORTHEAST"
        for i, pos73 in enumerate(ene_pos_73):
            if pos73 is not None and pos73 < len(text) and text[pos73] == ene[i]:
                anchored += 1
    if bc_pos_73 is not None:
        bc = "BERLINCLOCK"
        for i, pos73 in enumerate(bc_pos_73):
            if pos73 is not None and pos73 < len(text) and text[pos73] == bc[i]:
                anchored += 1

    return free, anchored, ic_val


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Single route transposition on ct73
# ══════════════════════════════════════════════════════════════════════════

def run_phase1(ct73, ene_pos_73, bc_pos_73):
    """Test all single route transpositions on ct73."""
    print("=" * 72)
    print("PHASE 1: Single route transposition on 73-char extracted text")
    print("=" * 72)

    n = len(ct73)
    best_free = 0
    best_anch = 0
    best_cfg = None
    configs = 0
    hits = []

    t0 = time.time()

    # Test widths 2 through 37
    for w in range(2, 38):
        nrows = math.ceil(n / w)

        # Write row-major, read by various routes (UNDO transposition)
        grid = write_grid_rowmajor(ct73, nrows, w)

        for route_name, read_fn in READ_METHODS.items():
            reordered = read_fn(grid, nrows, w)[:n]

            # Also try: the inverse direction (write in route order, read row-major)
            # This means we build an inverse permutation
            # The read_fn gives us the permutation; its inverse undoes it
            # For decryption: if encryptor wrote row-major and read route,
            # we write route and read row-major (or equivalently, apply inverse perm)

            for direction in ["forward", "inverse"]:
                if direction == "inverse":
                    # Build the permutation from reading order
                    # read_fn reads positions in some order; that order IS the perm
                    # The inverse: write CT into the route order, read row-major
                    # We need to build this differently
                    # Position map: route_positions[i] = position in row-major grid
                    # For the inverse, we create a grid, fill in route order, read row-major
                    inv_grid = [['X'] * w for _ in range(nrows)]
                    # Get reading order positions
                    positions = []
                    if route_name == "col_major":
                        positions = [(r, c) for c in range(w) for r in range(nrows)]
                    elif route_name == "serpentine_h":
                        for r in range(nrows):
                            if r % 2 == 0:
                                for c in range(w): positions.append((r, c))
                            else:
                                for c in range(w - 1, -1, -1): positions.append((r, c))
                    elif route_name == "serpentine_v":
                        for c in range(w):
                            if c % 2 == 0:
                                for r in range(nrows): positions.append((r, c))
                            else:
                                for r in range(nrows - 1, -1, -1): positions.append((r, c))
                    elif route_name == "col_rev":
                        positions = [(r, c) for c in range(w - 1, -1, -1) for r in range(nrows)]
                    elif route_name == "row_rev":
                        positions = [(r, c) for r in range(nrows - 1, -1, -1) for c in range(w)]
                    else:
                        # For spiral/diagonal, skip inverse (complex to enumerate positions)
                        continue

                    # Fill grid in route order with ct73 chars
                    for idx, (r, c) in enumerate(positions):
                        if idx < n:
                            inv_grid[r][c] = ct73[idx]
                    reordered = read_grid_rowmajor(inv_grid)[:n]

                # Now try each substitution cipher
                for cipher_name, cipher_fn in CIPHER_FNS.items():
                    pt = cipher_fn(reordered)[:n]
                    free, anch, ic_val = score_text(pt, ene_pos_73, bc_pos_73)
                    configs += 1

                    if free > best_free or anch > best_anch:
                        best_free = max(best_free, free)
                        best_anch = max(best_anch, anch)
                        cfg = {
                            "width": w, "route": route_name, "dir": direction,
                            "cipher": cipher_name, "free": free, "anch": anch,
                            "ic": round(ic_val, 4), "pt_prefix": pt[:40],
                        }
                        if free >= 11 or anch >= 6:
                            best_cfg = cfg
                            hits.append(cfg)
                            print(f"  HIT: w={w} {route_name} {direction} "
                                  f"{cipher_name}: free={free}, anch={anch}, "
                                  f"ic={ic_val:.4f}")

        if w % 10 == 0:
            elapsed = time.time() - t0
            print(f"  w={w}: {configs:,} configs, best_free={best_free}, "
                  f"best_anch={best_anch} [{elapsed:.1f}s]")

    elapsed = time.time() - t0
    print(f"\n  Phase 1: {configs:,} configs, best_free={best_free}/24, "
          f"best_anch={best_anch}/24, {len(hits)} hits [{elapsed:.1f}s]")
    if best_cfg:
        print(f"  Best: {best_cfg}")

    return best_free, best_anch, configs, hits


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: K3-style double rotation with padding
# ══════════════════════════════════════════════════════════════════════════

def run_phase2(ct73, ene_pos_73, bc_pos_73):
    """K3-style double rotational transposition on ct73 with padding."""
    print("\n" + "=" * 72)
    print("PHASE 2: K3-style double rotation on 73-char text (with padding)")
    print("=" * 72)

    n = len(ct73)
    best_free = 0
    best_anch = 0
    best_cfg = None
    configs = 0
    hits = []
    t0 = time.time()

    # Padded lengths and their factor pairs
    paddings = {
        0: [(1, 73)],  # trivial, but include for completeness
        1: [(2, 37), (37, 2)],
        2: [(3, 25), (25, 3), (5, 15), (15, 5)],
        4: [(7, 11), (11, 7)],  # THE KEY CANDIDATE
        5: [(6, 13), (13, 6), (2, 39), (39, 2), (3, 26), (26, 3)],
    }

    # Pad positions to try: start, end, split
    pad_modes = ["end", "start"]

    for n_pad, dim_pairs in paddings.items():
        for pad_mode in pad_modes:
            if pad_mode == "end":
                padded_text = ct73 + 'X' * n_pad
            elif pad_mode == "start":
                padded_text = 'X' * n_pad + ct73

            padded_len = len(padded_text)

            for r1, c1 in dim_pairs:
                if r1 * c1 != padded_len:
                    continue

                # Single rotation first
                for rot_name, rot_fn in ROTATIONS.items():
                    grid1 = write_grid_rowmajor(padded_text, r1, c1)
                    rotated1 = rot_fn(grid1)
                    intermediate = read_grid_rowmajor(rotated1)

                    # Score the single rotation directly
                    for cipher_name, cipher_fn in CIPHER_FNS.items():
                        pt = cipher_fn(intermediate[:n])
                        free, anch, ic_val = score_text(pt, ene_pos_73, bc_pos_73)
                        configs += 1

                        if free > best_free or anch > best_anch:
                            best_free = max(best_free, free)
                            best_anch = max(best_anch, anch)
                            cfg = {
                                "type": "single_rot", "pad": n_pad, "pad_mode": pad_mode,
                                "grid": f"{r1}x{c1}", "rot": rot_name,
                                "cipher": cipher_name, "free": free, "anch": anch,
                                "pt_prefix": pt[:40],
                            }
                            if free >= 11 or anch >= 6:
                                best_cfg = cfg
                                hits.append(cfg)
                                print(f"  HIT: pad={n_pad}({pad_mode}) {r1}x{c1} "
                                      f"rot={rot_name} {cipher_name}: "
                                      f"free={free}, anch={anch}")

                    # Double rotation: try all second grid dims
                    for r2, c2 in dim_pairs:
                        if r2 * c2 != padded_len:
                            continue

                        for rot2_name, rot2_fn in ROTATIONS.items():
                            grid2 = write_grid_rowmajor(intermediate, r2, c2)
                            rotated2 = rot2_fn(grid2)
                            doubly_transposed = read_grid_rowmajor(rotated2)

                            for cipher_name, cipher_fn in CIPHER_FNS.items():
                                pt = cipher_fn(doubly_transposed[:n])
                                free, anch, ic_val = score_text(pt, ene_pos_73, bc_pos_73)
                                configs += 1

                                if free > best_free or anch > best_anch:
                                    best_free = max(best_free, free)
                                    best_anch = max(best_anch, anch)
                                    cfg = {
                                        "type": "double_rot",
                                        "pad": n_pad, "pad_mode": pad_mode,
                                        "grid1": f"{r1}x{c1}", "rot1": rot_name,
                                        "grid2": f"{r2}x{c2}", "rot2": rot2_name,
                                        "cipher": cipher_name, "free": free,
                                        "anch": anch, "pt_prefix": pt[:40],
                                    }
                                    if free >= 11 or anch >= 6:
                                        best_cfg = cfg
                                        hits.append(cfg)
                                        print(f"  HIT: pad={n_pad}({pad_mode}) "
                                              f"{r1}x{c1}→{rot_name}→{r2}x{c2}→{rot2_name} "
                                              f"{cipher_name}: free={free}, anch={anch}")

    elapsed = time.time() - t0
    print(f"\n  Phase 2: {configs:,} configs, best_free={best_free}/24, "
          f"best_anch={best_anch}/24, {len(hits)} hits [{elapsed:.1f}s]")
    if best_cfg:
        print(f"  Best: {best_cfg}")

    return best_free, best_anch, configs, hits


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Bean-specific "7 and 3 rows" double transposition
# ══════════════════════════════════════════════════════════════════════════

def run_phase3(ct73, ene_pos_73, bc_pos_73):
    """Bean's specific suggestion: widths 7 and 3 in each rectangle."""
    print("\n" + "=" * 72)
    print("PHASE 3: Bean's '7 and 3 rows' double transposition")
    print("=" * 72)

    n = len(ct73)
    best_free = 0
    best_anch = 0
    best_cfg = None
    configs = 0
    hits = []
    t0 = time.time()

    # "7 and 3 rows in each rectangle" could mean:
    # 1. First rectangle has 7 rows (width = ceil(73/7) = 11), second has 3 rows (width = ceil(73/3) = 25)
    # 2. First rectangle has width 7, second has width 3
    # 3. One is 7 columns, other is 3 columns

    grid_configs = [
        # (rows1, cols1, rows2, cols2) - interpret "rows" literally
        (7, 11, 3, 25),   # 7 rows x 11 cols (77) → 3 rows x 25 cols (75)
        (11, 7, 25, 3),   # swap: 11 rows x 7 cols → 25 rows x 3 cols
        (7, 11, 25, 3),   # 7 rows x 11 → 25 rows x 3
        (11, 7, 3, 25),   # 11 rows x 7 → 3 rows x 25

        # Width interpretation
        (11, 7, 25, 3),   # width 7, then width 3
        (25, 3, 11, 7),   # width 3, then width 7

        # KRYPTOS-length width 7 variants
        (11, 7, 15, 5),   # width 7 → width 5
        (15, 5, 11, 7),   # width 5 → width 7

        # Width 7 combined with period-relevant widths
        (11, 7, 6, 13),   # width 7 → width 13
        (6, 13, 11, 7),   # width 13 → width 7
    ]

    for r1, c1, r2, c2 in grid_configs:
        for rot1_name, rot1_fn in ROTATIONS.items():
            # Write into first grid (with padding)
            pad1 = r1 * c1 - n
            if pad1 < 0:
                continue
            padded1 = ct73 + 'X' * pad1
            grid1 = write_grid_rowmajor(padded1, r1, c1)
            rotated1 = rot1_fn(grid1)
            intermediate = read_grid_rowmajor(rotated1)

            for rot2_name, rot2_fn in ROTATIONS.items():
                pad2 = r2 * c2 - len(intermediate)
                if pad2 < 0:
                    # Trim or skip
                    intermediate_trimmed = intermediate[:r2 * c2]
                else:
                    intermediate_trimmed = intermediate + 'X' * pad2

                grid2 = write_grid_rowmajor(intermediate_trimmed, r2, c2)
                rotated2 = rot2_fn(grid2)
                result = read_grid_rowmajor(rotated2)[:n]

                for cipher_name, cipher_fn in CIPHER_FNS.items():
                    pt = cipher_fn(result)
                    free, anch, ic_val = score_text(pt, ene_pos_73, bc_pos_73)
                    configs += 1

                    if free > best_free or anch > best_anch:
                        best_free = max(best_free, free)
                        best_anch = max(best_anch, anch)
                        cfg = {
                            "type": "bean_7_3",
                            "grid1": f"{r1}x{c1}", "rot1": rot1_name,
                            "grid2": f"{r2}x{c2}", "rot2": rot2_name,
                            "cipher": cipher_name, "free": free, "anch": anch,
                            "pt_prefix": pt[:40],
                        }
                        if free >= 11 or anch >= 6:
                            best_cfg = cfg
                            hits.append(cfg)
                            print(f"  HIT: {r1}x{c1}→{rot1_name}→{r2}x{c2}→{rot2_name} "
                                  f"{cipher_name}: free={free}, anch={anch}")

    # Also try: columnar transposition (not rotation) at widths 7 and 3
    # Columnar = write row-major, read column-major
    print("  + Columnar (non-rotation) at widths 7 and 3...")
    for w1, w2 in [(7, 3), (3, 7), (7, 7), (3, 3), (7, 11), (11, 7)]:
        nrows1 = math.ceil(n / w1)
        grid1 = write_grid_rowmajor(ct73, nrows1, w1)
        col_read1 = read_grid_colmajor(grid1, nrows1, w1)[:n]

        nrows2 = math.ceil(n / w2)
        grid2 = write_grid_rowmajor(col_read1, nrows2, w2)
        col_read2 = read_grid_colmajor(grid2, nrows2, w2)[:n]

        for cipher_name, cipher_fn in CIPHER_FNS.items():
            pt = cipher_fn(col_read2)
            free, anch, ic_val = score_text(pt, ene_pos_73, bc_pos_73)
            configs += 1

            if free > best_free or anch > best_anch:
                best_free = max(best_free, free)
                best_anch = max(best_anch, anch)
                cfg = {
                    "type": "double_columnar",
                    "w1": w1, "w2": w2,
                    "cipher": cipher_name, "free": free, "anch": anch,
                    "pt_prefix": pt[:40],
                }
                if free >= 11 or anch >= 6:
                    best_cfg = cfg
                    hits.append(cfg)
                    print(f"  HIT: col{w1}→col{w2} {cipher_name}: "
                          f"free={free}, anch={anch}")

    elapsed = time.time() - t0
    print(f"\n  Phase 3: {configs:,} configs, best_free={best_free}/24, "
          f"best_anch={best_anch}/24, {len(hits)} hits [{elapsed:.1f}s]")
    if best_cfg:
        print(f"  Best: {best_cfg}")

    return best_free, best_anch, configs, hits


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Incomplete route (partial last row) — various read orders
# ══════════════════════════════════════════════════════════════════════════

def run_phase4(ct73, ene_pos_73, bc_pos_73):
    """Incomplete route transposition: grid not fully filled, read various routes."""
    print("\n" + "=" * 72)
    print("PHASE 4: Incomplete route transposition (partial last row)")
    print("=" * 72)

    n = len(ct73)
    best_free = 0
    best_anch = 0
    best_cfg = None
    configs = 0
    hits = []
    t0 = time.time()

    # Key widths: 7 (KRYPTOS), 3, 11, 13, 5, 8, 9
    widths = [3, 5, 7, 8, 9, 11, 13, 14, 15, 19, 25, 31, 37]

    for w in widths:
        nrows = math.ceil(n / w)
        full_rows = n // w
        remainder = n % w  # chars in partial last row

        # Create grid with partial fill (-1 for empty cells)
        grid = []
        pos = 0
        for r in range(nrows):
            row = []
            for c in range(w):
                if pos < n:
                    row.append(ct73[pos])
                    pos += 1
                else:
                    row.append(None)
            grid.append(row)

        # Read by columns, handling incomplete last row
        # "Incomplete route" = some columns are shorter than others
        # Columns 0..remainder-1 have nrows chars, rest have nrows-1

        # Route 1: Column-by-column, skip None
        col_read = []
        for c in range(w):
            for r in range(nrows):
                if grid[r][c] is not None:
                    col_read.append(grid[r][c])
        col_text = ''.join(col_read)

        # Route 2: Column-by-column, reversed column order
        col_rev = []
        for c in range(w - 1, -1, -1):
            for r in range(nrows):
                if grid[r][c] is not None:
                    col_rev.append(grid[r][c])
        col_rev_text = ''.join(col_rev)

        # Route 3: Column serpentine (alternating T-B, B-T)
        col_serp = []
        for c in range(w):
            if c % 2 == 0:
                for r in range(nrows):
                    if grid[r][c] is not None:
                        col_serp.append(grid[r][c])
            else:
                for r in range(nrows - 1, -1, -1):
                    if grid[r][c] is not None:
                        col_serp.append(grid[r][c])
        col_serp_text = ''.join(col_serp)

        # Route 4: Diagonal NW-SE
        diag = []
        for d in range(nrows + w - 1):
            for r in range(max(0, d - w + 1), min(nrows, d + 1)):
                c = d - r
                if 0 <= c < w and grid[r][c] is not None:
                    diag.append(grid[r][c])
        diag_text = ''.join(diag)

        # Route 5: Row reversed (bottom to top, left to right)
        row_rev = []
        for r in range(nrows - 1, -1, -1):
            for c in range(w):
                if grid[r][c] is not None:
                    row_rev.append(grid[r][c])
        row_rev_text = ''.join(row_rev)

        # Route 6: Spiral CW (skip Nones)
        spiral = []
        visited = [[False] * w for _ in range(nrows)]
        r, c = 0, 0
        dr, dc = 0, 1  # start moving right
        for _ in range(nrows * w):
            if 0 <= r < nrows and 0 <= c < w and not visited[r][c]:
                visited[r][c] = True
                if grid[r][c] is not None:
                    spiral.append(grid[r][c])
            nr, nc = r + dr, c + dc
            if 0 <= nr < nrows and 0 <= nc < w and not visited[nr][nc]:
                r, c = nr, nc
            else:
                # Turn CW: right->down->left->up
                dr, dc = dc, -dr
                nr, nc = r + dr, c + dc
                if 0 <= nr < nrows and 0 <= nc < w and not visited[nr][nc]:
                    r, c = nr, nc
                else:
                    break
        spiral_text = ''.join(spiral)

        route_variants = {
            "col": col_text,
            "col_rev": col_rev_text,
            "col_serp": col_serp_text,
            "diag_nwse": diag_text,
            "row_rev": row_rev_text,
            "spiral_cw": spiral_text,
        }

        for route_name, reordered in route_variants.items():
            if len(reordered) < n:
                continue
            reordered = reordered[:n]

            for cipher_name, cipher_fn in CIPHER_FNS.items():
                pt = cipher_fn(reordered)[:n]
                free, anch, ic_val = score_text(pt, ene_pos_73, bc_pos_73)
                configs += 1

                if free > best_free or anch > best_anch:
                    best_free = max(best_free, free)
                    best_anch = max(best_anch, anch)
                    cfg = {
                        "type": "incomplete_route",
                        "width": w, "nrows": nrows, "remainder": remainder,
                        "route": route_name, "cipher": cipher_name,
                        "free": free, "anch": anch, "pt_prefix": pt[:40],
                    }
                    if free >= 11 or anch >= 6:
                        best_cfg = cfg
                        hits.append(cfg)
                        print(f"  HIT: w={w} {route_name} {cipher_name}: "
                              f"free={free}, anch={anch}")

            # Also try the inverse: write IN route order, read row-major
            # This is: positions that route_name would visit, fill with ct73, read linearly
            # Only do for col (simplest inverse)
            if route_name == "col":
                inv_grid = [[None] * w for _ in range(nrows)]
                idx = 0
                for c_fill in range(w):
                    col_len = nrows if c_fill < remainder else (nrows - 1 if remainder > 0 else nrows)
                    for r_fill in range(col_len):
                        if idx < n:
                            inv_grid[r_fill][c_fill] = ct73[idx]
                            idx += 1
                inv_text = ''.join(ch for row in inv_grid for ch in row if ch is not None)

                for cipher_name, cipher_fn in CIPHER_FNS.items():
                    pt = cipher_fn(inv_text[:n])
                    free, anch, ic_val = score_text(pt, ene_pos_73, bc_pos_73)
                    configs += 1

                    if free > best_free or anch > best_anch:
                        best_free = max(best_free, free)
                        best_anch = max(best_anch, anch)
                        cfg = {
                            "type": "incomplete_route_inv",
                            "width": w, "route": "col_inv",
                            "cipher": cipher_name, "free": free, "anch": anch,
                            "pt_prefix": pt[:40],
                        }
                        if free >= 11 or anch >= 6:
                            best_cfg = cfg
                            hits.append(cfg)
                            print(f"  HIT: w={w} col_inv {cipher_name}: "
                                  f"free={free}, anch={anch}")

    elapsed = time.time() - t0
    print(f"\n  Phase 4: {configs:,} configs, best_free={best_free}/24, "
          f"best_anch={best_anch}/24, {len(hits)} hits [{elapsed:.1f}s]")
    if best_cfg:
        print(f"  Best: {best_cfg}")

    return best_free, best_anch, configs, hits


# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Route on 28x31 grid cells occupied by K4
# ══════════════════════════════════════════════════════════════════════════

def run_phase5(ct73, null_positions, ene_pos_73, bc_pos_73):
    """Read K4 cells from the 28x31 master grid in route order."""
    print("\n" + "=" * 72)
    print("PHASE 5: Route reading on 28x31 grid K4 positions")
    print("=" * 72)

    n = len(ct73)
    best_free = 0
    best_anch = 0
    best_cfg = None
    configs = 0
    hits = []
    t0 = time.time()

    # K4 occupies rows 24-27 (last 4 rows), columns 0-30 in the 28x31 grid
    # K4 starts at row 24, col 27 (97 chars wrapping across rows)
    # Actually, from CLAUDE.md: "K4 at row 24 col 27"
    # The 97 chars fill: row 24 cols 27-30 (4 chars), rows 25-27 full (31 each = 93),
    # total = 4 + 93 = 97. Check: 4 + 3*31 = 4 + 93 = 97. Yes.

    # Build the 97 CT positions in the 28x31 grid
    ct97_grid_positions = []  # (row, col) for each of 97 CT chars
    # Row 24, cols 27-30
    for c in range(27, 31):
        ct97_grid_positions.append((24, c))
    # Rows 25, 26, 27 (full rows)
    for r in range(25, 28):
        for c in range(31):
            ct97_grid_positions.append((r, c))

    assert len(ct97_grid_positions) == 97

    # Build the 73 non-null positions in the grid
    null_set = set(null_positions)
    ct73_grid_positions = []
    ct73_chars = []
    for idx97, (r, c) in enumerate(ct97_grid_positions):
        if idx97 not in null_set:
            ct73_grid_positions.append((r, c))
            ct73_chars.append(CT[idx97])

    assert len(ct73_grid_positions) == 73
    assert ''.join(ct73_chars) == ct73

    # Now read these 73 positions in various orders based on grid coordinates
    # Sorted by column-major
    col_order = sorted(range(73), key=lambda i: (ct73_grid_positions[i][1], ct73_grid_positions[i][0]))
    col_text = ''.join(ct73_chars[i] for i in col_order)

    # Sorted by row then reverse column
    row_rev_order = sorted(range(73), key=lambda i: (ct73_grid_positions[i][0], -ct73_grid_positions[i][1]))
    row_rev_text = ''.join(ct73_chars[i] for i in row_rev_order)

    # Reverse row order
    rev_row_order = sorted(range(73), key=lambda i: (-ct73_grid_positions[i][0], ct73_grid_positions[i][1]))
    rev_row_text = ''.join(ct73_chars[i] for i in rev_row_order)

    # Diagonal order (by sum r+c)
    diag_order = sorted(range(73), key=lambda i: (ct73_grid_positions[i][0] + ct73_grid_positions[i][1],
                                                    ct73_grid_positions[i][0]))
    diag_text = ''.join(ct73_chars[i] for i in diag_order)

    # Anti-diagonal (by r-c)
    adiag_order = sorted(range(73), key=lambda i: (ct73_grid_positions[i][0] - ct73_grid_positions[i][1],
                                                     ct73_grid_positions[i][0]))
    adiag_text = ''.join(ct73_chars[i] for i in adiag_order)

    # Serpentine by row (alternating direction)
    serp_order = sorted(range(73), key=lambda i: (
        ct73_grid_positions[i][0],
        ct73_grid_positions[i][1] if ct73_grid_positions[i][0] % 2 == 0
        else -ct73_grid_positions[i][1]
    ))
    serp_text = ''.join(ct73_chars[i] for i in serp_order)

    grid_routes = {
        "grid_col_major": col_text,
        "grid_row_revcol": row_rev_text,
        "grid_rev_row": rev_row_text,
        "grid_diagonal": diag_text,
        "grid_anti_diag": adiag_text,
        "grid_serpentine": serp_text,
        "grid_reversed": ct73[::-1],
    }

    for route_name, reordered in grid_routes.items():
        for cipher_name, cipher_fn in CIPHER_FNS.items():
            pt = cipher_fn(reordered[:n])
            free, anch, ic_val = score_text(pt, ene_pos_73, bc_pos_73)
            configs += 1

            if free > best_free or anch > best_anch:
                best_free = max(best_free, free)
                best_anch = max(best_anch, anch)
                cfg = {
                    "type": "grid28x31_route",
                    "route": route_name, "cipher": cipher_name,
                    "free": free, "anch": anch, "pt_prefix": pt[:40],
                }
                if free >= 11 or anch >= 6:
                    best_cfg = cfg
                    hits.append(cfg)
                    print(f"  HIT: {route_name} {cipher_name}: "
                          f"free={free}, anch={anch}")

    elapsed = time.time() - t0
    print(f"\n  Phase 5: {configs:,} configs, best_free={best_free}/24, "
          f"best_anch={best_anch}/24, {len(hits)} hits [{elapsed:.1f}s]")
    if best_cfg:
        print(f"  Best: {best_cfg}")

    return best_free, best_anch, configs, hits


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    t_start = time.time()

    print("=" * 72)
    print("E-INCOMPLETE-ROUTE-73: Bean's incomplete route transposition")
    print("on null-extracted 73-char K4 text")
    print("=" * 72)
    print(f"CT97: {CT}")
    print(f"Null mask: {USER_MASK}")

    # Extract 73-char text
    ct73 = extract_73(CT, USER_MASK)
    print(f"CT73: {ct73}")
    print(f"CT73 length: {len(ct73)}")
    assert len(ct73) == 73, f"Expected 73, got {len(ct73)}"

    # Find shifted crib positions
    ene_pos_73, bc_pos_73, mapping = find_shifted_cribs(CT, USER_MASK)
    print(f"ENE positions in ct73: {ene_pos_73}")
    print(f"BCL positions in ct73: {bc_pos_73}")

    # Verify cribs are intact
    ene_intact = all(p is not None for p in ene_pos_73)
    bc_intact = all(p is not None for p in bc_pos_73)
    print(f"ENE intact: {ene_intact}, BCL intact: {bc_intact}")

    # Verify ct73 at crib positions
    ene_ct = ''.join(ct73[p] for p in ene_pos_73 if p is not None)
    bc_ct = ''.join(ct73[p] for p in bc_pos_73 if p is not None)
    print(f"CT at ENE positions: {ene_ct}")
    print(f"CT at BCL positions: {bc_ct}")
    print()

    # Phase 1-5
    f1, a1, n1, h1 = run_phase1(ct73, ene_pos_73, bc_pos_73)
    f2, a2, n2, h2 = run_phase2(ct73, ene_pos_73, bc_pos_73)
    f3, a3, n3, h3 = run_phase3(ct73, ene_pos_73, bc_pos_73)
    f4, a4, n4, h4 = run_phase4(ct73, ene_pos_73, bc_pos_73)
    f5, a5, n5, h5 = run_phase5(ct73, USER_MASK, ene_pos_73, bc_pos_73)

    total_configs = n1 + n2 + n3 + n4 + n5
    best_free = max(f1, f2, f3, f4, f5)
    best_anch = max(a1, a2, a3, a4, a5)
    all_hits = h1 + h2 + h3 + h4 + h5
    elapsed = time.time() - t_start

    print("\n" + "=" * 72)
    print("FINAL SUMMARY")
    print("=" * 72)
    print(f"Phase 1 (single route):        free={f1}/24, anch={a1}/24 ({n1:,} configs)")
    print(f"Phase 2 (K3-style double rot): free={f2}/24, anch={a2}/24 ({n2:,} configs)")
    print(f"Phase 3 (Bean 7-and-3):        free={f3}/24, anch={a3}/24 ({n3:,} configs)")
    print(f"Phase 4 (incomplete route):    free={f4}/24, anch={a4}/24 ({n4:,} configs)")
    print(f"Phase 5 (28x31 grid route):    free={f5}/24, anch={a5}/24 ({n5:,} configs)")
    print(f"")
    print(f"Total configs: {total_configs:,}")
    print(f"Best free: {best_free}/24")
    print(f"Best anchored: {best_anch}/24")
    print(f"Total hits: {len(all_hits)}")
    print(f"Time: {elapsed:.1f}s")

    if best_free >= 24:
        verdict = "BREAKTHROUGH"
    elif best_free >= 11 or best_anch >= 13:
        verdict = "SIGNAL — investigate"
    elif best_free >= 7 or best_anch >= 6:
        verdict = "INTERESTING — above noise"
    else:
        verdict = "NOISE — incomplete route transposition on ct73 does not yield cribs"

    print(f"\nVERDICT: {verdict}")

    if all_hits:
        print(f"\nAll hits (free>=11 or anch>=6):")
        for h in sorted(all_hits, key=lambda x: (-x.get('free', 0), -x.get('anch', 0)))[:20]:
            print(f"  {h}")

    # Save results
    os.makedirs("results", exist_ok=True)
    result = {
        "experiment": "E-INCOMPLETE-ROUTE-73",
        "description": "Bean's incomplete route transposition on null-extracted 73-char text",
        "null_mask": USER_MASK,
        "ct73": ct73,
        "ct73_len": len(ct73),
        "phases": {
            "phase1_single_route": {"free": f1, "anch": a1, "configs": n1},
            "phase2_double_rotation": {"free": f2, "anch": a2, "configs": n2},
            "phase3_bean_7_3": {"free": f3, "anch": a3, "configs": n3},
            "phase4_incomplete": {"free": f4, "anch": a4, "configs": n4},
            "phase5_grid28x31": {"free": f5, "anch": a5, "configs": n5},
        },
        "best_free": best_free,
        "best_anchored": best_anch,
        "total_configs": total_configs,
        "verdict": verdict,
        "elapsed_seconds": round(elapsed, 1),
        "hits": all_hits[:50],
    }
    outpath = "results/e_incomplete_route_73.json"
    with open(outpath, 'w') as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\nArtifacts: {outpath}")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/transposition/other/e_incomplete_route_73.py")


if __name__ == "__main__":
    main()
