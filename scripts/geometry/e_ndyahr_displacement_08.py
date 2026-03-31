#!/usr/bin/env python3
"""
Cipher: geometry/physical
Family: geometry
Status: active
Keyspace: ~10K configs across 8 hypothesis classes
Last run: 2026-03-14
Best score: TBD
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""E-NDYAHR-DISPLACEMENT-08: Test directional displacement hypotheses for NDYAHR.

Six letters at the K3/K4 boundary (NDYAHR from ENDYAHROHN) are physically
displaced from their grid positions in SPECIFIC DIRECTIONS:

    N: LEFT  (West)       ←
    D: RIGHT (East)       →
    Y: UP    (North)      ↑
    A: UP    (North)      ↑
    H: RIGHT (East)       →
    R: UP-LEFT (Northwest) ↖

These are deliberate (Sanborn: "You could not make any mistake with 1,800 letters").
They sit at the K3/K4 boundary — INSTRUCTIONS for K4, not part of the ciphertext.

Hypotheses tested:
  H1. Cardinal direction encoding (directions → compass letters → key)
  H2. Grid navigation (follow directions from a start position on 31-wide grid)
  H3. Column/row offsets (displacement vectors as transposition offsets)
  H4. Binary/ternary encoding (direction → numeric bits)
  H5. Semaphore flag signaling (directions → semaphore alphabet)
  H6. Letter numerology (NDYAHR as numbers, sums, anagram)
  H7. Period-6 shift key (directions as alphabet shifts applied cyclically)
  H8. Null mask rule (direction pattern determines which positions are real/null)

Run: PYTHONPATH=src python3 -u scripts/geometry/e_ndyahr_displacement_08.py
"""

import sys
import os
import json
import math
from collections import Counter
from itertools import product as iter_product

sys.path.insert(0, 'src')

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS, CRIB_WORDS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.vigenere import (
    decrypt_text, encrypt_text, CipherVariant,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

# ══════════════════════════════════════════════════════════════════════════
# Core Data
# ══════════════════════════════════════════════════════════════════════════

# The six displaced letters and their directions
DISPLACED_LETTERS = "NDYAHR"
# Directions: ← → ↑ ↑ → ↖
# As compass: W E N N E NW
DIRECTIONS = ["W", "E", "N", "N", "E", "NW"]

# Direction vectors (col_delta, row_delta) in grid coordinates
# Right = +col, Up = -row (screen convention: row 0 at top)
DIR_VECTORS = {
    "W":  (-1,  0),  # left
    "E":  (+1,  0),  # right
    "N":  ( 0, -1),  # up
    "S":  ( 0, +1),  # down
    "NW": (-1, -1),  # up-left
    "NE": (+1, -1),  # up-right
    "SW": (-1, +1),  # down-left
    "SE": (+1, +1),  # down-right
}

DISPLACEMENT_VECS = [DIR_VECTORS[d] for d in DIRECTIONS]
# [(-1,0), (+1,0), (0,-1), (0,-1), (+1,0), (-1,-1)]

# A=0 numbering for the displaced letters
LETTER_VALS = [ALPH_IDX[c] for c in DISPLACED_LETTERS]  # N=13, D=3, Y=24, A=0, H=7, R=17

# K4 on 28x31 grid: K4 starts at row 24, col 27 (0-indexed)
# But in the 14-row bottom half (rows 14-27), K4 starts at bottom-half row 10, col 27
K4_START_ROW = 24  # in 28-row grid
K4_START_COL = 27  # in 31-wide grid
GRID_WIDTH = 31

# ENDYAHR positions in the full sculpture grid
# K3 starts at row 14, col 0. ENDYAHR = first 7 chars of K3 CT.
# E is at (14, 0), N at (14, 1), D at (14, 2), Y at (14, 3),
# A at (14, 4), H at (14, 5), R at (14, 6)
ENDYAHR_ROW = 14
ENDYAHR_COLS = list(range(7))  # cols 0-6
# NDYAHR = indices 1-6 of ENDYAHR
NDYAHR_START_COL = 1

# Full K3 ciphertext for reference
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

results = {}
best_overall = {"score": 0, "method": "", "detail": ""}


def update_best(score, method, detail):
    global best_overall
    if score > best_overall["score"]:
        best_overall = {"score": score, "method": method, "detail": detail}


def report(hypothesis, score, method, detail):
    if score > NOISE_FLOOR:
        print(f"  ** ABOVE NOISE: {score}/24 — {method}")
        print(f"     {detail[:120]}")
    update_best(score, method, detail)


# ══════════════════════════════════════════════════════════════════════════
# H1: Cardinal Direction Encoding
# ══════════════════════════════════════════════════════════════════════════

def test_h1_cardinal():
    """Test directions as compass letters forming a key."""
    print("\n" + "="*72)
    print("H1: CARDINAL DIRECTION ENCODING")
    print("="*72)

    # Directions as compass letters: W, E, N, N, E, NW
    # As single letters: W=22, E=4, N=13, N=13, E=4
    # NW is problematic — could be N(13) or W(22) or combined

    # Interpretation 1: Just the cardinal letter (first letter of direction)
    # W, E, N, N, E, N → WENNEN
    key_letters_1 = "WENNEN"
    key_nums_1 = [ALPH_IDX[c] for c in key_letters_1]

    # Interpretation 2: Use both letters for diagonals
    # W, E, N, N, E, NW → W, E, N, N, E, N, W → WENNEW? No...
    # Or: collapse NW → mean of N(13) and W(22) = 17.5 → 17 or 18
    key_nums_2a = [22, 4, 13, 13, 4, 17]  # NW → R(17)
    key_nums_2b = [22, 4, 13, 13, 4, 18]  # NW → S(18)

    # Interpretation 3: Compass bearing / 15° increments
    # W=270, E=90, N=0, N=0, E=90, NW=315
    bearings = [270, 90, 0, 0, 90, 315]
    # As 15° increments: 18, 6, 0, 0, 6, 21
    bearing_15 = [b // 15 for b in bearings]
    # Mod 26: same values

    # Interpretation 4: 8-point compass (0-7): N=0, NE=1, E=2, SE=3, S=4, SW=5, W=6, NW=7
    compass_8 = {"N": 0, "NE": 1, "E": 2, "SE": 3, "S": 4, "SW": 5, "W": 6, "NW": 7}
    key_nums_8pt = [compass_8[d] for d in DIRECTIONS]  # [6, 2, 0, 0, 2, 7]

    # Interpretation 5: 4-point encoding — L/R/U/D as 0-3
    dir4 = {"W": 0, "E": 1, "N": 2, "S": 3, "NW": 2, "NE": 1, "SW": 3, "SE": 3}
    key_nums_4pt = [dir4[d] for d in DIRECTIONS]  # [0, 1, 2, 2, 1, 2]

    configs = [
        ("WENNEN_period6", key_nums_1, "W,E,N,N,E,N as period-6 Vigenere key"),
        ("NW_as_R_period6", key_nums_2a, "NW→R(17): [22,4,13,13,4,17]"),
        ("NW_as_S_period6", key_nums_2b, "NW→S(18): [22,4,13,13,4,18]"),
        ("bearing_15deg", bearing_15, f"Bearings/15°: {bearing_15}"),
        ("compass_8pt", key_nums_8pt, f"8-pt compass: {key_nums_8pt}"),
        ("compass_4pt", key_nums_4pt, f"4-pt encoding: {key_nums_4pt}"),
    ]

    best_h1 = 0
    for name, key, desc in configs:
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            method = f"H1:{name}:{variant.value}"
            if sc > best_h1:
                best_h1 = sc
            report("H1", sc, method, f"{desc} → PT={pt[:30]}...")

    # Also test as single-use key (pad-style, just first 6 chars shifted)
    # and as additive offset to KRYPTOS/DEFECTOR keywords
    for kw_name, kw in [("KRYPTOS", "KRYPTOS"), ("DEFECTOR", "DEFECTOR"), ("BERLINCLOCK", "BERLINCLOCK")]:
        kw_nums = [ALPH_IDX[c] for c in kw]
        for interp_name, dir_key in [("WENNEN", key_nums_1), ("8pt", key_nums_8pt)]:
            # Add direction offsets to keyword cyclically
            modified_key = [(kw_nums[i] + dir_key[i % len(dir_key)]) % 26 for i in range(len(kw_nums))]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
                pt = decrypt_text(CT, modified_key, variant)
                sc = score_cribs(pt)
                method = f"H1:{kw_name}+{interp_name}:{variant.value}"
                if sc > best_h1:
                    best_h1 = sc
                report("H1", sc, method, f"keyword+dir_offset → PT={pt[:30]}...")

    results["H1"] = {"best_score": best_h1, "configs_tested": len(configs) * 3 + 3 * 2 * 3}
    print(f"\n  H1 best: {best_h1}/24")
    return best_h1


# ══════════════════════════════════════════════════════════════════════════
# H2: Grid Navigation (Follow Directions on 31-wide Grid)
# ══════════════════════════════════════════════════════════════════════════

def test_h2_grid_navigation():
    """Follow NDYAHR directions on a grid to trace a path through K4."""
    print("\n" + "="*72)
    print("H2: GRID NAVIGATION ON 31-WIDE GRID")
    print("="*72)

    # K4 on 31-wide grid (4 rows: rows 24-27 of the 28-row grid)
    # Row 24: cols 27-30 = OBKR (4 chars)
    # Row 25: cols 0-30 = UOXOGHULBSOLIFBBWFLRVQQPRNGKSSOT (31 chars)
    # Row 26: cols 0-30 = WTQSJQSSEKZZWATJKLUDIAWINFBNYPVT (31 chars)
    # Row 27: cols 0-30 = TMZFPKWGDKZXTJCDIGKUHUAUEKCAR (29 chars, last row incomplete)
    # Total: 4 + 31 + 31 + 31 = 97 ✓ (actually last row = 97 - 4 - 31 - 31 = 31)

    # Let's build the grid properly
    k4_grid = {}
    idx = 0
    for row in range(4):  # 4 rows in the K4 region
        if row == 0:
            # First partial row: starts at col 27
            for col in range(K4_START_COL, GRID_WIDTH):
                if idx < CT_LEN:
                    k4_grid[(row, col)] = (idx, CT[idx])
                    idx += 1
        else:
            for col in range(GRID_WIDTH):
                if idx < CT_LEN:
                    k4_grid[(row, col)] = (idx, CT[idx])
                    idx += 1

    print(f"  Grid has {len(k4_grid)} cells, K4 has {CT_LEN} chars")

    # Print the grid for reference
    for row in range(4):
        line = ""
        for col in range(GRID_WIDTH):
            if (row, col) in k4_grid:
                line += k4_grid[(row, col)][1]
            else:
                line += "."
        print(f"  Row {row}: {line}")

    # Strategy: start at various positions, follow the 6-direction sequence
    # cyclically, collecting letters. This defines a reading order.

    best_h2 = 0
    nav_results = []

    # Try starting from every cell in the grid
    for start_row in range(4):
        for start_col in range(GRID_WIDTH):
            if (start_row, start_col) not in k4_grid:
                continue

            # Follow directions cyclically for up to 97 steps
            path = []
            r, c = start_row, start_col
            visited = set()

            for step in range(CT_LEN):
                if (r, c) in k4_grid and (r, c) not in visited:
                    path.append(k4_grid[(r, c)])
                    visited.add((r, c))

                # Get next direction
                dc, dr = DISPLACEMENT_VECS[step % 6]
                r_new = r + dr
                c_new = c + dc

                # Wrap around grid
                c_new = c_new % GRID_WIDTH
                if r_new < 0:
                    r_new = 3
                elif r_new > 3:
                    r_new = 0

                r, c = r_new, c_new

            if len(path) >= CT_LEN * 0.5:  # Only consider paths that visit many cells
                # Build permutation from path
                perm_indices = [p[0] for p in path]
                if len(set(perm_indices)) == len(perm_indices):  # unique
                    # Pad with remaining positions
                    remaining = [i for i in range(CT_LEN) if i not in set(perm_indices)]
                    full_perm = perm_indices + remaining
                    if len(full_perm) == CT_LEN:
                        reordered = "".join(CT[p] for p in full_perm)
                        sc = score_cribs(reordered)
                        if sc > best_h2:
                            best_h2 = sc
                            nav_results.append((sc, start_row, start_col, len(path)))
                        report("H2", sc, f"H2:nav_start=({start_row},{start_col})",
                               f"path_len={len(path)} → PT={reordered[:30]}...")

    # Also try: directions define which positions to EXTRACT (null mask)
    # Direction encodes: N/NW = real (upward = revealed), E/W = null (horizontal = hidden)
    # Pattern: W=null, E=null, N=real, N=real, E=null, NW=real → period-6 mask: 0,0,1,1,0,1
    masks = [
        ("N_up=real", [0, 0, 1, 1, 0, 1]),    # N/NW=real, E/W=null
        ("N_up=null", [1, 1, 0, 0, 1, 0]),    # inverse
        ("E_right=real", [0, 1, 0, 0, 1, 0]),  # E=real, others=null
        ("horiz=real", [1, 1, 0, 0, 1, 0]),    # horizontal=real, vertical=null
        ("all_but_NW", [1, 1, 1, 1, 1, 0]),   # NW is special
        ("diag_only", [0, 0, 0, 0, 0, 1]),    # only diagonal
    ]

    for mask_name, mask_6 in masks:
        # Apply mask cyclically to 97 positions
        real_positions = [i for i in range(CT_LEN) if mask_6[i % 6] == 1]
        null_positions = [i for i in range(CT_LEN) if mask_6[i % 6] == 0]

        n_real = len(real_positions)
        n_null = len(null_positions)

        if 70 <= n_real <= 76:  # Close to 73
            extracted = "".join(CT[i] for i in real_positions)
            # Try scoring the extracted text with shifted cribs
            # (cribs may have moved after null removal)
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                for kw in ["KRYPTOS", "DEFECTOR", "PALIMPSEST"]:
                    key = [ALPH_IDX[c] for c in kw]
                    pt = decrypt_text(extracted, key, variant)
                    # Use free-position scoring (cribs may be anywhere)
                    # Quick check: just scan for EAST, NORTH, BERLIN, CLOCK
                    found = []
                    for crib in ["EASTNORTHEAST", "BERLINCLOCK", "EAST", "NORTH", "BERLIN", "CLOCK"]:
                        if crib in pt:
                            found.append(crib)
                    if found:
                        print(f"  !! CRIB FRAGMENT in {mask_name}/{kw}/{variant.value}: {found}")
                        print(f"     PT={pt[:60]}")

            print(f"  Mask {mask_name}: {n_real} real, {n_null} null (target: 73 real, 24 null)")

    results["H2"] = {"best_score": best_h2, "nav_results": nav_results[:5]}
    print(f"\n  H2 best: {best_h2}/24")
    return best_h2


# ══════════════════════════════════════════════════════════════════════════
# H3: Column/Row Offsets (Displacement Vectors as Transposition)
# ══════════════════════════════════════════════════════════════════════════

def test_h3_offsets():
    """Apply displacement vectors as position offsets to create transposition."""
    print("\n" + "="*72)
    print("H3: DISPLACEMENT VECTORS AS TRANSPOSITION OFFSETS")
    print("="*72)

    # Each direction = (dx, dy) offset vector
    # Applied cyclically to positions on a grid
    # "Real" position of char at grid pos (r,c) = (r+dy, c+dx)

    best_h3 = 0

    for width in [7, 13, 14, 31]:  # Key widths to test
        nrows = math.ceil(CT_LEN / width)

        for interp_name, vecs in [
            ("standard", DISPLACEMENT_VECS),
            ("negated", [(-dx, -dy) for dx, dy in DISPLACEMENT_VECS]),
            ("swap_xy", [(dy, dx) for dx, dy in DISPLACEMENT_VECS]),
        ]:
            # Build transposition: for each position i, compute source position
            perm = []
            valid = True
            for i in range(CT_LEN):
                r, c = divmod(i, width)
                dx, dy = vecs[i % 6]

                # New position
                nr = (r + dy) % nrows
                nc = (c + dx) % width
                src = nr * width + nc

                if src >= CT_LEN:
                    src = i  # identity for out-of-bounds
                perm.append(src)

            # Check if it's a valid permutation
            if len(set(perm)) == CT_LEN:
                reordered = apply_perm(CT, perm)
                sc = score_cribs(reordered)
                if sc > best_h3:
                    best_h3 = sc
                report("H3", sc, f"H3:offset_w{width}_{interp_name}",
                       f"Displacement offset transposition → PT={reordered[:30]}...")

                # Also try inverse
                inv = invert_perm(perm)
                reordered_inv = apply_perm(CT, inv)
                sc_inv = score_cribs(reordered_inv)
                if sc_inv > best_h3:
                    best_h3 = sc_inv
                report("H3", sc_inv, f"H3:offset_w{width}_{interp_name}_inv",
                       f"Inverse offset → PT={reordered_inv[:30]}...")

            # Also: use direction to determine column read order
            # Directions at cols 1-6 map to KRYPTOS cols 1-6
            # Col ordering from displacement: W=-1, E=+1, N=0, N=0, E=+1, NW=-1
            # Horizontal component: [-1, +1, 0, 0, +1, -1] → sum = 0

    # Special: use the 6 direction vectors to define a 7-column reading order
    # Col 0 (E) = stationary = rank 3 (middle)
    # Col 1 (N) = left = rank 0
    # Col 2 (D) = right = rank 6
    # Col 3 (Y) = up = rank 2
    # Col 4 (A) = up = rank 2 (tie)
    # Col 5 (H) = right = rank 5
    # Col 6 (R) = up-left = rank 1
    # This is ambiguous, try all interpretations

    # Simple: sort by x-component of displacement
    x_components = [0, -1, +1, 0, 0, +1, -1]  # E(none), N(W), D(E), Y(N), A(N), H(E), R(NW)
    y_components = [0, 0, 0, -1, -1, 0, -1]

    # Sort by x, then y to get column order
    indexed = [(x_components[i], y_components[i], i) for i in range(7)]
    sorted_cols = [item[2] for item in sorted(indexed)]

    if len(set(sorted_cols)) == 7:
        col_order = [0] * 7
        for rank, col in enumerate(sorted_cols):
            col_order[col] = rank

        perm7 = columnar_perm(7, col_order, CT_LEN)
        if len(perm7) == CT_LEN:
            reordered = apply_perm(CT, perm7)
            sc = score_cribs(reordered)
            if sc > best_h3:
                best_h3 = sc
            report("H3", sc, "H3:col7_from_displacements",
                   f"Col-7 order from displacement x-sort: {col_order} → PT={reordered[:30]}...")

            inv7 = invert_perm(perm7)
            reordered_inv = apply_perm(CT, inv7)
            sc_inv = score_cribs(reordered_inv)
            if sc_inv > best_h3:
                best_h3 = sc_inv
            report("H3", sc_inv, "H3:col7_from_displacements_inv",
                   f"Inverse col-7 → PT={reordered_inv[:30]}...")

    results["H3"] = {"best_score": best_h3}
    print(f"\n  H3 best: {best_h3}/24")
    return best_h3


# ══════════════════════════════════════════════════════════════════════════
# H4: Binary/Ternary Encoding
# ══════════════════════════════════════════════════════════════════════════

def test_h4_binary():
    """Test directions as binary/ternary number encodings."""
    print("\n" + "="*72)
    print("H4: BINARY / TERNARY ENCODING")
    print("="*72)

    best_h4 = 0

    # Multiple encoding schemes
    encodings = {}

    # Scheme A: horizontal component (L=-1, center=0, R=+1 → 0,1,2 ternary)
    # W=-1→0, E=+1→2, N=0→1, N=0→1, E=+1→2, NW=-1→0
    ternary_h = [0, 2, 1, 1, 2, 0]
    val_t3_h = sum(d * (3**i) for i, d in enumerate(ternary_h))  # LSB first
    val_t3_h_msb = sum(d * (3**(5-i)) for i, d in enumerate(ternary_h))  # MSB first
    encodings["ternary_horiz_lsb"] = val_t3_h
    encodings["ternary_horiz_msb"] = val_t3_h_msb

    # Scheme B: vertical component (U=-1→0, center=0→1, D=+1→2)
    # W=0→1, E=0→1, N=-1→0, N=-1→0, E=0→1, NW=-1→0
    ternary_v = [1, 1, 0, 0, 1, 0]
    val_t3_v = sum(d * (3**i) for i, d in enumerate(ternary_v))
    val_t3_v_msb = sum(d * (3**(5-i)) for i, d in enumerate(ternary_v))
    encodings["ternary_vert_lsb"] = val_t3_v
    encodings["ternary_vert_msb"] = val_t3_v_msb

    # Scheme C: binary — vertical movement = 1, no vertical = 0
    # W=0, E=0, N=1, N=1, E=0, NW=1
    binary_vert = [0, 0, 1, 1, 0, 1]
    val_b_lsb = sum(d * (2**i) for i, d in enumerate(binary_vert))
    val_b_msb = sum(d * (2**(5-i)) for i, d in enumerate(binary_vert))
    encodings["binary_vert_lsb"] = val_b_lsb
    encodings["binary_vert_msb"] = val_b_msb

    # Scheme D: binary — horizontal movement = 1
    binary_horiz = [1, 1, 0, 0, 1, 1]
    val_bh_lsb = sum(d * (2**i) for i, d in enumerate(binary_horiz))
    val_bh_msb = sum(d * (2**(5-i)) for i, d in enumerate(binary_horiz))
    encodings["binary_horiz_lsb"] = val_bh_lsb
    encodings["binary_horiz_msb"] = val_bh_msb

    # Scheme E: 8-point compass as 3-bit octal
    compass_8 = {"N": 0, "NE": 1, "E": 2, "SE": 3, "S": 4, "SW": 5, "W": 6, "NW": 7}
    octal_vals = [compass_8[d] for d in DIRECTIONS]  # [6, 2, 0, 0, 2, 7]
    val_oct = sum(d * (8**i) for i, d in enumerate(octal_vals))
    val_oct_msb = sum(d * (8**(5-i)) for i, d in enumerate(octal_vals))
    encodings["octal_compass_lsb"] = val_oct
    encodings["octal_compass_msb"] = val_oct_msb

    # Scheme F: signed displacement sum
    x_sum = sum(dx for dx, dy in DISPLACEMENT_VECS)  # -1+1+0+0+1-1 = 0
    y_sum = sum(dy for dx, dy in DISPLACEMENT_VECS)  # 0+0-1-1+0-1 = -3
    encodings["displacement_x_sum"] = x_sum
    encodings["displacement_y_sum"] = y_sum
    encodings["displacement_magnitude"] = abs(x_sum) + abs(y_sum)

    print("  Encoded values:")
    for name, val in sorted(encodings.items()):
        print(f"    {name}: {val}")
        if 1 <= val <= 25:
            print(f"      As letter: {ALPH[val]}")
        if val > 0 and val <= 97:
            print(f"      As K4 position: CT[{val}] = {CT[val] if val < CT_LEN else '?'}")

    # Use each value as: period for Vigenere, starting position, shift amount
    for name, val in encodings.items():
        if val <= 0 or val > 26:
            continue
        # As a single-letter Vigenere key (shift)
        key = [val % 26]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            if sc > best_h4:
                best_h4 = sc
            report("H4", sc, f"H4:{name}_shift:{variant.value}", f"shift={val} → PT={pt[:30]}...")

    # Special: binary_vert = [0,0,1,1,0,1] = period-6 null mask
    # 0=null, 1=real: positions 2,3,5,8,9,11,14,15,17,...
    real_mask = [i for i in range(CT_LEN) if binary_vert[i % 6] == 1]
    null_mask = [i for i in range(CT_LEN) if binary_vert[i % 6] == 0]
    print(f"\n  Binary vert [0,0,1,1,0,1] as null mask: {len(real_mask)} real, {len(null_mask)} null")
    # 97 * 3/6 = 48.5 → not close to 73

    # binary_horiz = [1,1,0,0,1,1] → 97 * 4/6 = 64.7 → not close either
    real_mask_h = [i for i in range(CT_LEN) if binary_horiz[i % 6] == 1]
    print(f"  Binary horiz [1,1,0,0,1,1] as null mask: {len(real_mask_h)} real")

    # What about combined 2-bit: (horiz_bit, vert_bit)?
    # Position i: (binary_horiz[i%6], binary_vert[i%6])
    # (0,0) = stationary impossible
    # (0,1) = vertical only = N or NW
    # (1,0) = horizontal only = W or E
    # (1,1) = diagonal = NW
    # Actual: W=(1,0), E=(1,0), N=(0,1), N=(0,1), E=(1,0), NW=(1,1)
    # 4 categories, 2 bits each

    results["H4"] = {
        "best_score": best_h4,
        "encodings": {k: v for k, v in encodings.items()},
    }
    print(f"\n  H4 best: {best_h4}/24")

    # Notable: displacement sums: x=0 (symmetric!), y=-3 (net upward)
    print(f"\n  NOTABLE: x_sum=0 (perfectly balanced L/R), y_sum=-3 (net 3 steps upward)")
    print(f"  The displacements are HORIZONTALLY SYMMETRIC but vertically biased UPWARD by 3")

    return best_h4


# ══════════════════════════════════════════════════════════════════════════
# H5: Semaphore / Flag Signaling
# ══════════════════════════════════════════════════════════════════════════

def test_h5_semaphore():
    """Test directions as semaphore flag positions."""
    print("\n" + "="*72)
    print("H5: SEMAPHORE / FLAG SIGNALING")
    print("="*72)

    # In semaphore, each letter is encoded by TWO flag positions (left + right hand)
    # 8 positions: Down, Down-Left, Left, Up-Left, Up, Up-Right, Right, Down-Right
    # Numbered 1-8 starting from Down going clockwise

    # We have 6 single directions. Semaphore uses pairs of directions.
    # Possible: pair adjacent directions (N,D), (Y,A), (H,R) or other groupings

    # Standard semaphore encoding (position numbers, clockwise from down):
    # 1=Down, 2=Down-Left, 3=Left, 4=Up-Left, 5=Up, 6=Up-Right, 7=Right, 8=Down-Right

    # Map our directions to semaphore position numbers:
    sem_pos = {"S": 1, "SW": 2, "W": 3, "NW": 4, "N": 5, "NE": 6, "E": 7, "SE": 8}

    dir_sem = [sem_pos[d] for d in DIRECTIONS]  # [3, 7, 5, 5, 7, 4]

    # Semaphore alphabet (left_pos, right_pos) → letter:
    # This is a standard encoding. Let me check if our pairs match.
    semaphore_table = {
        (1,2): 'A', (1,3): 'B', (1,4): 'C', (1,5): 'D', (1,6): 'E',
        (1,7): 'F', (1,8): 'G', (2,3): 'H', (2,4): 'I', (2,5): 'J',
        (3,4): 'K', (2,6): 'J',  # J has alt
        (2,7): 'L', (2,8): 'M',
        (3,5): 'N', (3,6): 'O', (3,7): 'P', (3,8): 'Q',
        (4,5): 'R', (4,6): 'S', (4,7): 'T', (4,8): 'U',
        (5,6): 'V', (5,8): 'X', (6,7): 'Y', (6,8): 'Z',
        (5,7): 'W',
    }
    # Also add reversed pairs
    sem_full = {}
    for (a,b), ch in semaphore_table.items():
        sem_full[(a,b)] = ch
        sem_full[(b,a)] = ch

    # Try pairing: consecutive pairs
    pairs_consecutive = [(dir_sem[i], dir_sem[i+1]) for i in range(0, 6, 2)]
    # (3,7)=P, (5,5)=??, (7,4)=T
    print("  Consecutive pairs (N+D, Y+A, H+R):")
    for i, (a, b) in enumerate(pairs_consecutive):
        letter = sem_full.get((a, b), sem_full.get((b, a), '?'))
        print(f"    ({a},{b}) → {letter}")

    # Overlapping pairs
    pairs_overlap = [(dir_sem[i], dir_sem[i+1]) for i in range(5)]
    print("  Overlapping pairs:")
    for i, (a, b) in enumerate(pairs_overlap):
        letter = sem_full.get((a, b), '?')
        print(f"    ({a},{b}) → {letter}")

    # Individual positions as letters (position → letter in some code)
    # Flag position 1-8 could map to something
    print(f"\n  Raw semaphore positions: {dir_sem}")
    print(f"  As A1Z26 (1=A...): {''.join(ALPH[d-1] for d in dir_sem)}")

    results["H5"] = {"semaphore_positions": dir_sem}
    print(f"\n  H5: interpretive (no score)")
    return 0


# ══════════════════════════════════════════════════════════════════════════
# H6: Letter Numerology (NDYAHR)
# ══════════════════════════════════════════════════════════════════════════

def test_h6_numerology():
    """Analyze NDYAHR letter values, sums, products, anagrams."""
    print("\n" + "="*72)
    print("H6: NDYAHR LETTER NUMEROLOGY")
    print("="*72)

    best_h6 = 0

    letters = DISPLACED_LETTERS  # "NDYAHR"
    vals = LETTER_VALS  # [13, 3, 24, 0, 7, 17]

    print(f"  Letters: {letters}")
    print(f"  A=0 values: {vals}")
    print(f"  A=1 values: {[v+1 for v in vals]}")
    print(f"  Sum (A=0): {sum(vals)}")
    print(f"  Sum (A=1): {sum(v+1 for v in vals)}")
    print(f"  Product (A=1): {math.prod(v+1 for v in vals)}")

    s0 = sum(vals)  # 64
    s1 = sum(v+1 for v in vals)  # 70

    # Notable observations:
    print(f"\n  NOTABLE:")
    print(f"    Sum(A=0) = {s0} = 2^6 (power of 2!)")
    print(f"    Sum(A=1) = {s1}")
    print(f"    {s0} + 1 = 65 = position of Bean EQ (k[27]=k[65])")
    print(f"    {s0} mod 26 = {s0 % 26} = {ALPH[s0 % 26]}")
    print(f"    {s1} mod 26 = {s1 % 26} = {ALPH[s1 % 26]}")

    # Check if 64 is relevant
    print(f"    CT[64] = {CT[64]} (position 64 in K4)")
    print(f"    CT[65] = {CT[65]} (Bean EQ position)")
    print(f"    Crib at 63: B (BERLINCLOCK starts)")

    # Sorted: A(0), D(3), H(7), N(13), R(17), Y(24)
    sorted_vals = sorted(vals)
    print(f"\n  Sorted values: {sorted_vals}")
    print(f"  Differences: {[sorted_vals[i+1]-sorted_vals[i] for i in range(5)]}")
    # [3, 4, 6, 4, 7]

    # As positions in K4
    print(f"\n  K4 chars at NDYAHR positions (A=0):")
    for letter, val in zip(letters, vals):
        if val < CT_LEN:
            print(f"    {letter}={val}: CT[{val}] = {CT[val]}")

    # Anagram analysis
    from itertools import permutations
    print(f"\n  Anagrams of NDYAHR:")
    # Check against wordlists? Just show notable ones
    anagrams = set()
    for p in permutations(letters):
        w = "".join(p)
        anagrams.add(w)

    # Check for English words (basic check)
    known_words = {"HYDRA", "HANDY", "HARDY", "RANDY", "HARRY", "DAIRY",
                   "DIARY", "RAINY", "DRAIN", "YARN", "HARD", "HAND", "YARD",
                   "DRAY", "NARD", "RAND", "RANDAN", "HYDRAN"}
    found = anagrams.intersection(known_words)
    if found:
        print(f"  English words found: {found}")

    # Partial anagrams
    print(f"  Notable partial anagrams:")
    print(f"    HANDR_Y → HANDRY? (not a word)")
    print(f"    _HYDRA + N → NHYDRA? Or HYDRA with N left over")
    print(f"    YARN + DH → YARN is a word (4 letters)")
    print(f"    HARD + NY → HARD is a word")
    print(f"    RAND + HY → RAND (random, as in RAND corporation)")
    print(f"    DRAY + HN → DRAY (a cart)")
    print(f"    HANDY + R → HANDY with R")

    # Use NDYAHR as a 6-letter key
    key_ndyahr = vals  # [13, 3, 24, 0, 7, 17]
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(CT, key_ndyahr, variant)
        sc = score_cribs(pt)
        if sc > best_h6:
            best_h6 = sc
        report("H6", sc, f"H6:NDYAHR_as_key:{variant.value}", f"key={vals} → PT={pt[:30]}...")

    # Try ENDYAHR (7 letters, including E=4)
    key_endyahr = [ALPH_IDX[c] for c in "ENDYAHR"]
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(CT, key_endyahr, variant)
        sc = score_cribs(pt)
        if sc > best_h6:
            best_h6 = sc
        report("H6", sc, f"H6:ENDYAHR_as_key:{variant.value}", f"key={key_endyahr} → PT={pt[:30]}...")

    # Try reversed: RHAYDNE
    key_rev = list(reversed(key_endyahr))
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(CT, key_rev, variant)
        sc = score_cribs(pt)
        if sc > best_h6:
            best_h6 = sc
        report("H6", sc, f"H6:RHAYDNE_as_key:{variant.value}", f"reversed → PT={pt[:30]}...")

    # Try sum=64 and sum+1=65 as single shifts
    for shift_val in [s0 % 26, s1 % 26, 6, 4]:  # 64%26=12, 70%26=18
        key = [shift_val]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(CT, key, variant)
            sc = score_cribs(pt)
            if sc > best_h6:
                best_h6 = sc
            report("H6", sc, f"H6:sum_shift={shift_val}:{variant.value}", f"→ PT={pt[:30]}...")

    results["H6"] = {
        "best_score": best_h6,
        "sum_a0": s0,
        "sum_a1": s1,
        "values": vals,
    }
    print(f"\n  H6 best: {best_h6}/24")
    return best_h6


# ══════════════════════════════════════════════════════════════════════════
# H7: Period-6 Shift Key (Directions as Alphabet Shifts)
# ══════════════════════════════════════════════════════════════════════════

def test_h7_period6():
    """Use directions as a period-6 substitution key with various mappings."""
    print("\n" + "="*72)
    print("H7: PERIOD-6 DIRECTIONAL SHIFT KEY")
    print("="*72)

    best_h7 = 0
    configs_tested = 0

    # Multiple ways to map directions to shift values
    shift_mappings = {
        # Horizontal component as shift
        "horiz": [-1, +1, 0, 0, +1, -1],
        # Vertical component as shift
        "vert": [0, 0, -1, -1, 0, -1],
        # Magnitude (Manhattan distance from center)
        "magnitude": [1, 1, 1, 1, 1, 2],  # NW has magnitude sqrt(2) ~ 2
        # 8-point compass number
        "compass8": [6, 2, 0, 0, 2, 7],
        # Angle/45 degrees
        "angle45": [4, 2, 0, 0, 2, 7],  # W=180→4, E=90→2, N=0→0, NW=315→7
        # Angle/15 degrees mod 26
        "angle15": [18, 6, 0, 0, 6, 21],
        # Letter value of direction name first letter
        "dir_letter": [22, 4, 13, 13, 4, 13],  # W,E,N,N,E,N
        # NDYAHR letter values directly
        "letter_vals": [13, 3, 24, 0, 7, 17],
        # ENDYAHR letter values (period 7)
        "endyahr_vals": [4, 13, 3, 24, 0, 7, 17],
    }

    # Also add modular variations
    for base_name, base_shifts in list(shift_mappings.items()):
        # Mod 26 positive
        shift_mappings[f"{base_name}_mod26"] = [s % 26 for s in base_shifts]
        # Negated mod 26
        shift_mappings[f"{base_name}_neg"] = [(-s) % 26 for s in base_shifts]

    for name, shifts in shift_mappings.items():
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            pt = decrypt_text(CT, shifts, variant)
            sc = score_cribs(pt)
            configs_tested += 1
            if sc > best_h7:
                best_h7 = sc
            report("H7", sc, f"H7:{name}:{variant.value}", f"shifts={shifts[:7]} → PT={pt[:30]}...")

    # Combine with DEFECTOR keyword (current best lead uses DEFECTOR:AZ_beau)
    defector_key = [ALPH_IDX[c] for c in "DEFECTOR"]
    for name, shifts in [("horiz", [-1,+1,0,0,+1,-1]), ("compass8", [6,2,0,0,2,7]),
                          ("letter_vals", [13,3,24,0,7,17])]:
        # XOR-like combination: add direction shift to DEFECTOR key position
        combined = [(defector_key[i % 8] + shifts[i % len(shifts)]) % 26
                    for i in range(max(8, len(shifts)) * 2)]  # LCM-period key
        # Use first LCM(8,6)=24 or LCM(8,7)=56 values as key
        lcm_len = len(combined)
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(CT, combined[:lcm_len], variant)
            sc = score_cribs(pt)
            configs_tested += 1
            if sc > best_h7:
                best_h7 = sc
            report("H7", sc, f"H7:DEFECTOR+{name}:{variant.value}",
                   f"combined key → PT={pt[:30]}...")

    # Test direction sequence as column transposition key for col-7
    # Column order derived from direction: sort directions to get column read order
    # W=6→col0, E=2→col1, N=0→col2, N=0→col3, E=2→col4, NW=7→col5
    # Add E(undisplaced)=neutral→col6
    # Rank by compass value: N(0)=first, E(2)=second, W(6)=third, NW(7)=fourth
    compass_vals = [6, 2, 0, 0, 2, 7]
    # With E as position 0 (value = 1 for center)
    full_compass = [1] + compass_vals  # E, N, D, Y, A, H, R
    # Rank: 0→pos2, 0→pos3, 1→pos0, 2→pos1, 2→pos4, 6→pos5(was W→N), 7→pos6(was NW→R)
    # Stable sort: [0(col2), 0(col3), 1(col0), 2(col1), 2(col4), 6(col5), 7(col6)]
    indexed_compass = [(v, i) for i, v in enumerate(full_compass)]
    sorted_compass = sorted(indexed_compass, key=lambda x: (x[0], x[1]))
    col_order_from_compass = [0] * 7
    for rank, (_, orig_col) in enumerate(sorted_compass):
        col_order_from_compass[orig_col] = rank

    print(f"\n  Column order from compass encoding: {col_order_from_compass}")
    perm = columnar_perm(7, col_order_from_compass, CT_LEN)
    if len(perm) == CT_LEN and len(set(perm)) == CT_LEN:
        reordered = apply_perm(CT, perm)
        sc = score_cribs(reordered)
        if sc > best_h7:
            best_h7 = sc
        report("H7", sc, "H7:col7_compass_order",
               f"order={col_order_from_compass} → PT={reordered[:30]}...")

        # Also with DEFECTOR:AZ_beau on the transposed text
        defector_beau_key = [ALPH_IDX[c] for c in "DEFECTOR"]
        pt_sub = decrypt_text(reordered, defector_beau_key, CipherVariant.BEAUFORT)
        sc_sub = score_cribs(pt_sub)
        if sc_sub > best_h7:
            best_h7 = sc_sub
        report("H7", sc_sub, "H7:col7_compass+DEFECTOR_beau",
               f"trans+sub → PT={pt_sub[:30]}...")

        # Inverse
        inv = invert_perm(perm)
        reordered_inv = apply_perm(CT, inv)
        pt_sub_inv = decrypt_text(reordered_inv, defector_beau_key, CipherVariant.BEAUFORT)
        sc_inv = score_cribs(pt_sub_inv)
        if sc_inv > best_h7:
            best_h7 = sc_inv
        report("H7", sc_inv, "H7:col7_compass_inv+DEFECTOR_beau",
               f"inv_trans+sub → PT={pt_sub_inv[:30]}...")

    results["H7"] = {"best_score": best_h7, "configs_tested": configs_tested}
    print(f"\n  H7 best: {best_h7}/24")
    return best_h7


# ══════════════════════════════════════════════════════════════════════════
# H8: Null Mask Rule (Direction Pattern → Real/Null Determination)
# ══════════════════════════════════════════════════════════════════════════

def test_h8_null_mask():
    """Test if direction pattern defines which K4 positions are real vs null."""
    print("\n" + "="*72)
    print("H8: DIRECTION PATTERN AS NULL MASK RULE")
    print("="*72)

    best_h8 = 0

    # The 6 directions encode a pattern. If applied cyclically to 97 positions,
    # each position gets a direction. The direction determines real/null.

    # But 97/6 gives 16 full cycles + 1 remainder. That gives various counts.

    # More interesting: the DISPLACED LETTERS themselves are at specific positions
    # in the 31-wide grid. NDYAHR are at row 14, cols 1-6.
    # What if the COLUMN of a K4 character determines its null/real status?
    # Cols 1,2,3,4,5,6 have specific directions.
    # Col 0 (E in ENDYAHR) is NOT displaced → "real" (or baseline)

    # Hypothesis: column-based null mask
    # Columns where direction is vertical (N, NW) → real
    # Columns where direction is horizontal (W, E) → null
    # Col 0: E (undisplaced) → real (default)
    # Col 1: N (W/left) → null
    # Col 2: D (E/right) → null
    # Col 3: Y (N/up) → real
    # Col 4: A (N/up) → real
    # Col 5: H (E/right) → null
    # Col 6: R (NW) → real (has vertical component)

    # This partitions 31 columns into real/null based on col % 7
    col_masks = {
        "vert_real": {0: 1, 1: 0, 2: 0, 3: 1, 4: 1, 5: 0, 6: 1},  # 4/7 real
        "vert_null": {0: 0, 1: 1, 2: 1, 3: 0, 4: 0, 5: 1, 6: 0},  # 3/7 real
        "horiz_real": {0: 0, 1: 1, 2: 1, 3: 0, 4: 0, 5: 1, 6: 0}, # same as vert_null
        "left_real": {0: 1, 1: 1, 2: 0, 3: 0, 4: 0, 5: 0, 6: 1},  # L/NW=real
        "moved_null": {0: 1, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0}, # displaced=null
        "moved_real": {0: 0, 1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1}, # displaced=real
    }

    for mask_name, col_rule in col_masks.items():
        # Apply to K4 positions on 31-wide grid
        real_positions = []
        null_positions = []

        for i in range(CT_LEN):
            # K4 position i → grid column
            if i < 4:  # First 4 chars start at col 27
                grid_col = K4_START_COL + i
            else:
                grid_col = (i - 4) % GRID_WIDTH

            col_mod7 = grid_col % 7
            if col_rule.get(col_mod7, 1) == 1:
                real_positions.append(i)
            else:
                null_positions.append(i)

        n_real = len(real_positions)
        n_null = len(null_positions)

        print(f"  Mask '{mask_name}': {n_real} real, {n_null} null")

        if n_real == 0:
            continue

        extracted = "".join(CT[i] for i in real_positions)

        # Score extracted text with various keys
        if 60 <= n_real <= 97:
            for kw_name, kw in [("KRYPTOS", "KRYPTOS"), ("DEFECTOR", "DEFECTOR"),
                                 ("PALIMPSEST", "PALIMPSEST"), ("ABSCISSA", "ABSCISSA")]:
                key = [ALPH_IDX[c] for c in kw]
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(extracted, key, variant)
                    # Check for crib fragments
                    for crib_name, crib in [("ENE", "EASTNORTHEAST"), ("BC", "BERLINCLOCK"),
                                             ("EAST", "EAST"), ("NORTH", "NORTH"),
                                             ("BERLIN", "BERLIN"), ("CLOCK", "CLOCK")]:
                        if crib in pt:
                            print(f"  !! CRIB '{crib_name}' found in {mask_name}/{kw_name}/{variant.value}!")
                            print(f"     PT={pt}")

        # For masks near 73 real, try direct crib scoring
        if abs(n_real - 73) <= 5:
            print(f"    ** Near target (73±5): {n_real} real positions")

    # Also test: position-based mask where NDYAHR letter VALUES define null positions
    # N=13, D=3, Y=24, A=0, H=7, R=17 → positions 0,3,7,13,17,24 are null
    null_from_vals = set(LETTER_VALS)
    print(f"\n  NDYAHR values as null positions: {sorted(null_from_vals)}")
    print(f"    CT at those positions: {''.join(CT[i] for i in sorted(null_from_vals))}")

    # Extended: positions ≡ NDYAHR values mod 6
    for mod_val in [6, 7, 13, 24]:
        null_set = set()
        for v in LETTER_VALS:
            for i in range(CT_LEN):
                if i % mod_val == v % mod_val:
                    null_set.add(i)
        n_null_mod = len(null_set)
        n_real_mod = CT_LEN - n_null_mod
        if abs(n_real_mod - 73) <= 3:
            print(f"    mod-{mod_val}: {n_real_mod} real, {n_null_mod} null (CLOSE TO 73!)")

    # The displacement DIRECTION at each ENDYAHR column maps to KRYPTOS column:
    # E=K(col0), N=R(col1), D=Y(col2), Y=P(col3), A=T(col4), H=O(col5), R=S(col6)
    # KRYPTOS maps: col0=K(10), col1=R(17), col2=Y(24), col3=P(15), col4=T(19), col5=O(14), col6=S(18)
    # The direction at col i might modify the KRYPTOS letter at that column

    kryptos_vals = [ALPH_IDX[c] for c in "KRYPTOS"]
    endyahr_vals = [ALPH_IDX[c] for c in "ENDYAHR"]

    print(f"\n  ENDYAHR → KRYPTOS column mapping:")
    for i in range(7):
        e_ch = "ENDYAHR"[i]
        k_ch = "KRYPTOS"[i]
        direction = (["—"] + DIRECTIONS)[i] if i > 0 else "—"
        print(f"    Col {i}: {e_ch}({endyahr_vals[i]}) → {k_ch}({kryptos_vals[i]})  dir={direction}  diff={(kryptos_vals[i]-endyahr_vals[i])%26}")

    # Differences: K-E=6, R-N=4, Y-D=21, P-Y=17, T-A=19, O-H=7, S-R=1
    diffs = [(kryptos_vals[i] - endyahr_vals[i]) % 26 for i in range(7)]
    print(f"  KRYPTOS - ENDYAHR differences (mod 26): {diffs}")
    print(f"  As letters: {''.join(ALPH[d] for d in diffs)}")

    # Use these differences as a key
    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
        pt = decrypt_text(CT, diffs, variant)
        sc = score_cribs(pt)
        if sc > best_h8:
            best_h8 = sc
        report("H8", sc, f"H8:KRYPTOS-ENDYAHR_diff:{variant.value}",
               f"key={diffs} → PT={pt[:30]}...")

    results["H8"] = {"best_score": best_h8}
    print(f"\n  H8 best: {best_h8}/24")
    return best_h8


# ══════════════════════════════════════════════════════════════════════════
# H9 (BONUS): Cross-check with DEFECTOR:AZ_beau + col7 best lead
# ══════════════════════════════════════════════════════════════════════════

def test_h9_defector_integration():
    """Test if NDYAHR directions modify the DEFECTOR:AZ_beau+col7 model."""
    print("\n" + "="*72)
    print("H9: INTEGRATION WITH DEFECTOR:AZ_BEAU+COL7 BEST LEAD")
    print("="*72)

    best_h9 = 0

    defector_key = [ALPH_IDX[c] for c in "DEFECTOR"]

    # The best lead uses col7 transposition. NDYAHR has 6 letters at cols 1-6
    # of the KRYPTOS-keyword row. What if the directions specify the col7 ORDER?

    # Sort columns by direction "priority":
    # N (up) = highest priority = first column read
    # E (right) = second
    # W (left) = third
    # NW (up-left) = fourth? Or between N and W?
    # S (down) = lowest

    # Various priority orderings
    priority_schemes = {
        # Compass clockwise from N: N=0, NE=1, E=2, SE=3, S=4, SW=5, W=6, NW=7
        "clockwise_from_N": {"N": 0, "NE": 1, "E": 2, "SE": 3, "S": 4, "SW": 5, "W": 6, "NW": 7},
        # Counter-clockwise from N
        "ccw_from_N": {"N": 0, "NW": 1, "W": 2, "SW": 3, "S": 4, "SE": 5, "E": 6, "NE": 7},
        # By vertical component (up first)
        "vert_first": {"N": 0, "NW": 1, "NE": 2, "W": 3, "E": 4, "SW": 5, "SE": 6, "S": 7},
        # By horizontal component (left first)
        "horiz_first": {"W": 0, "NW": 1, "SW": 2, "N": 3, "S": 4, "NE": 5, "E": 6, "SE": 7},
    }

    for scheme_name, priority in priority_schemes.items():
        # Assign priority to cols 1-6 based on direction
        # Col 0 (E, undisplaced) gets middle priority
        col_priorities = [3]  # col 0 = neutral, middle rank
        for d in DIRECTIONS:
            col_priorities.append(priority[d])

        # Convert priorities to column order (rank)
        indexed = [(p, i) for i, p in enumerate(col_priorities)]
        sorted_idx = sorted(indexed, key=lambda x: (x[0], x[1]))
        col_order = [0] * 7
        for rank, (_, col) in enumerate(sorted_idx):
            col_order[col] = rank

        # Apply col7 transposition
        perm = columnar_perm(7, col_order, CT_LEN)
        if len(perm) != CT_LEN or len(set(perm)) != CT_LEN:
            continue

        reordered = apply_perm(CT, perm)

        # Then apply DEFECTOR:AZ_beau
        pt = decrypt_text(reordered, defector_key, CipherVariant.BEAUFORT)
        sc = score_cribs(pt)
        if sc > best_h9:
            best_h9 = sc
        report("H9", sc, f"H9:col7_{scheme_name}+DEFECTOR_beau",
               f"order={col_order} → PT={pt[:30]}...")

        # Also try inverse transposition
        inv = invert_perm(perm)
        reordered_inv = apply_perm(CT, inv)
        pt_inv = decrypt_text(reordered_inv, defector_key, CipherVariant.BEAUFORT)
        sc_inv = score_cribs(pt_inv)
        if sc_inv > best_h9:
            best_h9 = sc_inv
        report("H9", sc_inv, f"H9:col7_{scheme_name}_inv+DEFECTOR_beau",
               f"inv_order → PT={pt_inv[:30]}...")

    # Try: directions modify the column order of the existing best col7
    # Standard col7 uses keyword_to_order. Try with KRYPTOS, DEFECTOR
    for kw_name, kw in [("KRYPTOS", "KRYPTOS"), ("DEFECTOR", "DEFECTO")]:
        base_order = keyword_to_order(kw[:7], 7)
        if base_order is None:
            continue

        # Modify order based on directions
        # Direction adds an offset to the rank
        dir_offsets = [0, -1, +1, 0, 0, +1, -1]  # from horizontal components
        modified = [(base_order[i] + dir_offsets[i]) for i in range(7)]
        # Re-rank to valid column order
        indexed_mod = [(v, i) for i, v in enumerate(modified)]
        sorted_mod = sorted(indexed_mod, key=lambda x: (x[0], x[1]))
        new_order = [0] * 7
        for rank, (_, col) in enumerate(sorted_mod):
            new_order[col] = rank

        perm = columnar_perm(7, new_order, CT_LEN)
        if len(perm) == CT_LEN and len(set(perm)) == CT_LEN:
            reordered = apply_perm(CT, perm)
            pt = decrypt_text(reordered, defector_key, CipherVariant.BEAUFORT)
            sc = score_cribs(pt)
            if sc > best_h9:
                best_h9 = sc
            report("H9", sc, f"H9:{kw_name}_col7_dir_modified+DEFECTOR_beau",
                   f"modified_order={new_order} → PT={pt[:30]}...")

    # Try all 7! = 5040 column orderings and score with DEFECTOR:AZ_beau
    from itertools import permutations as perms
    print(f"\n  Exhaustive col7 × DEFECTOR:AZ_beau scan (5040 orders)...")
    best_exhaustive = 0
    best_order_exh = None
    for order in perms(range(7)):
        perm = columnar_perm(7, list(order), CT_LEN)
        reordered = apply_perm(CT, perm)
        pt = decrypt_text(reordered, defector_key, CipherVariant.BEAUFORT)
        sc = score_cribs(pt)
        if sc > best_exhaustive:
            best_exhaustive = sc
            best_order_exh = order
            if sc > best_h9:
                best_h9 = sc

    print(f"  Exhaustive best: {best_exhaustive}/24, order={best_order_exh}")

    # Check if the best exhaustive order matches any of our direction-derived orders
    if best_order_exh:
        print(f"  Best col7 order: {best_order_exh}")
        # What directions would produce this order?
        # If we assign compass values by rank...
        print(f"  (For reference: NDYAHR direction-derived orders tested above)")

    results["H9"] = {"best_score": best_h9, "best_exhaustive": best_exhaustive,
                      "best_order": list(best_order_exh) if best_order_exh else None}
    print(f"\n  H9 best: {best_h9}/24")
    return best_h9


# ══════════════════════════════════════════════════════════════════════════
# H10: Additional structural analysis
# ══════════════════════════════════════════════════════════════════════════

def test_h10_structural():
    """Structural analysis: displacement sum properties, K2 connection."""
    print("\n" + "="*72)
    print("H10: STRUCTURAL / NUMEROLOGICAL ANALYSIS")
    print("="*72)

    # Sum of A=0 values: N(13)+D(3)+Y(24)+A(0)+H(7)+R(17) = 64
    # 64 = 2^6. Six letters, 2^6. This is exact.
    # 64 mod 26 = 12 = M
    # 65 = 64+1 = position of Bean EQ (k[27]=k[65])

    print("  Key observations about NDYAHR:")
    print(f"    Letters: N(13) D(3) Y(24) A(0) H(7) R(17)")
    print(f"    Sum = {sum(LETTER_VALS)} = 2^6 (SIX letters, 2^SIX)")
    print(f"    Sum + 1 = 65 = Bean EQ position (k[27]=k[65])")
    print(f"    Sum mod 26 = {sum(LETTER_VALS) % 26} = M")
    print()

    # Connection to K2 coordinates: 38°57'6.5"
    # 3+8=11, 5+7=12, 6+5=11
    # NDYAHR sum = 64. 64/8 = 8. 64/4 = 16.
    # 6*4 = 24 (number of nulls!)
    # 6+4 = 10
    print("  K2 coordinate connections:")
    print(f"    64 = 8 × 8 (8 lines of K4)")
    print(f"    64 = 4 × 16 (4 blocks of 24 + 1 remainder)")
    print(f"    6 letters, sum 64: 6×4=24, 6+4=10")
    print(f"    24 = number of null positions")
    print()

    # NDYAHR vs KRYPTOS mapping (from anomaly registry):
    # E↔K, N↔R, D↔Y, Y↔P, A↔T, H↔O, R↔S
    # Displaced: N↔R, D↔Y, Y↔P, A↔T, H↔O, R↔S
    # The letters they map TO: R,Y,P,T,O,S = anagram of KRYPTOS minus K!

    mapped_to = "RYPTO S"  # KRYPTOS without K
    print("  NDYAHR ↔ KRYPTOS mapping:")
    print("    N↔R, D↔Y, Y↔P, A↔T, H↔O, R↔S")
    print(f"    Mapped-to letters: R,Y,P,T,O,S = KRYPTOS without K!")
    print(f"    E (undisplaced) ↔ K")
    print(f"    So: DISPLACED letters = exactly those mapping to RYPTOS")
    print(f"    UNDISPLACED letter = the one mapping to K")
    print(f"    This is consistent with K being 'KEY' or 'KRYPTOS' initial")
    print()

    # The directions are applied to RYPTOS columns only:
    # R(col1)→W, Y(col2)→E, P(col3)→N, T(col4)→N, O(col5)→E, S(col6)→NW
    print("  Directions applied to KRYPTOS columns (K excluded):")
    for col, kch, ech, d in zip(range(1,7), "RYPTOS", "NDYAHR", DIRECTIONS):
        dx, dy = DIR_VECTORS[d]
        print(f"    Col {col}: KRYPTOS={kch}, ENDYAHR={ech}, dir={d} ({dx:+d},{dy:+d})")

    # What if the direction tells you HOW to traverse that column?
    # W = read column leftward (backward)?
    # E = read column rightward (forward)?
    # N = read column upward?
    # NW = read column upward-leftward (diagonal)?

    print("\n  Column reading interpretation:")
    print("    Col 1 (K=R): read LEFTWARD (W)")
    print("    Col 2 (K=Y): read RIGHTWARD (E)")
    print("    Col 3 (K=P): read UPWARD (N)")
    print("    Col 4 (K=T): read UPWARD (N)")
    print("    Col 5 (K=O): read RIGHTWARD (E)")
    print("    Col 6 (K=S): read UP-LEFT (NW) — diagonal!")

    # Test: col7 with alternating read directions
    # Col 0: normal (undisplaced)
    # Col 1: reversed (W=backward)
    # Col 2: normal (E=forward)
    # Col 3: reversed (N=up=backward in vertical reading)
    # Col 4: reversed (N=up=backward)
    # Col 5: normal (E=forward)
    # Col 6: reversed (NW=has backward component)

    # Forward/backward interpretation based on direction
    # E = forward (right), W = backward (left)
    # N = backward (up), S = forward (down)
    # NW = backward (both components backward)
    col_forward = [True, False, True, False, False, True, False]
    # True = read top to bottom, False = read bottom to top

    # Build serpentine-like column reading
    nrows = math.ceil(CT_LEN / 7)

    # Fill grid row by row
    grid_7 = {}
    for i in range(CT_LEN):
        r, c = divmod(i, 7)
        grid_7[(r, c)] = i

    # Read columns in standard order (0,1,2,3,4,5,6) but with direction
    perm = []
    for col in range(7):
        col_positions = []
        for row in range(nrows):
            if (row, col) in grid_7:
                col_positions.append(grid_7[(row, col)])

        if not col_forward[col]:
            col_positions = list(reversed(col_positions))
        perm.extend(col_positions)

    if len(perm) == CT_LEN and len(set(perm)) == CT_LEN:
        reordered = apply_perm(CT, perm)
        sc = score_cribs(reordered)
        print(f"\n  Direction-serpentine col7 (fwd/bwd per direction): {sc}/24")
        report("H10", sc, "H10:serpentine_col7_by_direction",
               f"col_forward={col_forward} → PT={reordered[:30]}...")

        # Also try with DEFECTOR:AZ_beau
        defector_key = [ALPH_IDX[c] for c in "DEFECTOR"]
        pt = decrypt_text(reordered, defector_key, CipherVariant.BEAUFORT)
        sc2 = score_cribs(pt)
        print(f"  + DEFECTOR:AZ_beau: {sc2}/24")
        report("H10", sc2, "H10:serpentine_col7+DEFECTOR_beau",
               f"→ PT={pt[:30]}...")

    # Check: W positions in K4 vs NDYAHR
    w_positions = [i for i, c in enumerate(CT) if c == 'W']
    print(f"\n  W positions in K4: {w_positions}")
    print(f"  N value = 13: CT[13] = {CT[13]}")
    print(f"  D value = 3: CT[3] = {CT[3]}")
    print(f"  Y value = 24: CT[24] = {CT[24]}")
    print(f"  H value = 7: CT[7] = {CT[7]}")
    print(f"  R value = 17: CT[17] = {CT[17]}")

    results["H10"] = {"note": "structural analysis, see output"}
    return 0


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("="*72)
    print("E-NDYAHR-DISPLACEMENT-08: Directional Displacement Analysis")
    print("="*72)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Displaced letters: {DISPLACED_LETTERS}")
    print(f"Directions: {DIRECTIONS}")
    print(f"Vectors: {DISPLACEMENT_VECS}")
    print(f"Letter values (A=0): {LETTER_VALS}")
    print(f"Sum: {sum(LETTER_VALS)} = 2^6")

    scores = {}
    scores["H1"] = test_h1_cardinal()
    scores["H2"] = test_h2_grid_navigation()
    scores["H3"] = test_h3_offsets()
    scores["H4"] = test_h4_binary()
    scores["H5"] = test_h5_semaphore()
    scores["H6"] = test_h6_numerology()
    scores["H7"] = test_h7_period6()
    scores["H8"] = test_h8_null_mask()
    scores["H9"] = test_h9_defector_integration()
    scores["H10"] = test_h10_structural()

    print("\n" + "="*72)
    print("SUMMARY")
    print("="*72)
    for h, sc in sorted(scores.items()):
        status = "ABOVE NOISE" if sc > NOISE_FLOOR else "noise"
        print(f"  {h}: {sc}/24 [{status}]")

    print(f"\n  Overall best: {best_overall['score']}/24")
    print(f"  Method: {best_overall['method']}")
    print(f"  Detail: {best_overall['detail'][:200]}")

    # Write results
    results["summary"] = {
        "best_overall": best_overall,
        "hypothesis_scores": scores,
    }

    os.makedirs("results", exist_ok=True)
    with open("results/ndyahr_displacement.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n  Results written to results/ndyahr_displacement.json")
    return best_overall["score"]


if __name__ == "__main__":
    main()
