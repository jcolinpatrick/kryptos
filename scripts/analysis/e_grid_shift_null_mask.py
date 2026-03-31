#!/usr/bin/env python3
"""Four 6x4 grids stacked with all possible shifts — null mask derivation.

CT96 (drop last or first char from CT97) -> four blocks of 24 chars ->
four 6x4 grids. Fix Grid 0 in place. Shift Grids 1,2,3 independently:
- Horizontal shift: 0-5 (mod 6)
- Vertical shift: 0-3 (mod 4)
- Total: 24^3 = 13,824 combinations per drop variant

A position is NULL if it contains a palette letter {B,G,I,K,O,W,Z}
AND at least one other grid has a palette letter at the SAME cell
position (after shifting).

Extract non-null chars, apply:
  - DEFECTOR:AZ_beau + col6 ascending
  - ABSCISSA:AZ_beau + col6 ascending
  - DEFECTOR:AZ_beau + col7 ascending
Score against shifted cribs (EASTNORTHEAST, BERLINCLOCK).

Also tests NDYAHR movement interpretations as grid shifts.

Cipher: null_mask_derivation
Family: analysis
Status: active
Keyspace: ~28K exhaustive + NDYAHR interpretations
Last run: never
Best score: TBD
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys
import os
import json
import time
from datetime import datetime
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET

# -- Constants ---------------------------------------------------------------
CT97 = CT
N = 97
N_NULLS_TARGET = 24
N_PT_TARGET = 73
PALETTE = frozenset('BGIKOWZ')
ENE_WORD = "EASTNORTHEAST"
BCL_WORD = "BERLINCLOCK"
ENE_START_97 = 21   # 0-indexed position in CT97
BCL_START_97 = 63

GRID_COLS = 6
GRID_ROWS = 4
BLOCK_SIZE = GRID_COLS * GRID_ROWS  # 24

KA_STR = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA_STR)}

# Consensus null positions (17 positions, 100% agreement across all 6 known 15/24 masks)
CONSENSUS_17 = frozenset({0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85})


# -- Transposition helpers ---------------------------------------------------
def columnar_perm(n, width):
    """Write row-by-row, read column-by-col. Returns gather perm."""
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm


def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# -- Beaufort decrypt --------------------------------------------------------
def beaufort_decrypt(ct_nums, keyword_str):
    """Beaufort: PT[i] = (KW[i % len(KW)] - CT[i]) mod 26. AZ alphabet."""
    kw = [ord(c) - 65 for c in keyword_str.upper()]
    L = len(kw)
    pt = []
    for i, c in enumerate(ct_nums):
        k = kw[i % L]
        p = (k - c) % 26
        pt.append(p)
    return pt


# -- Autokey decrypt (AZ Beaufort) -------------------------------------------
def autokey_decrypt_az_beau(ct_nums, keyword_str):
    """AZ autokey Beaufort: PT[i] = (key[i] - CT[i]) mod 26,
    key = keyword + PT prefix."""
    kw = [ord(c) - 65 for c in keyword_str.upper()]
    L = len(kw)
    pt = []
    for i, c in enumerate(ct_nums):
        k = kw[i] if i < L else pt[i - L]
        p = (k - c) % 26
        pt.append(p)
    return pt


# -- Crib scoring ------------------------------------------------------------
def count_crib_hits(pt_nums, ene_s, bcl_s, n_pt):
    """Score cribs against plaintext (list of ints 0-25). Returns (total, ene, bcl)."""
    ene_nums = [ord(c) - 65 for c in ENE_WORD]
    bcl_nums = [ord(c) - 65 for c in BCL_WORD]
    e = sum(1 for j, c in enumerate(ene_nums)
            if ene_s + j < n_pt and pt_nums[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(bcl_nums)
            if bcl_s + j < n_pt and pt_nums[bcl_s + j] == c)
    return e + b, e, b


def nums_to_text(nums):
    return ''.join(chr(p + 65) for p in nums)


# -- Consensus scoring -------------------------------------------------------
def score_mask_consensus(null_set):
    """Score a null mask against the 17 consensus nulls. Returns (tp, fp, fn, f1)."""
    tp = len(null_set & CONSENSUS_17)
    fp = len(null_set - CONSENSUS_17)
    fn = len(CONSENSUS_17 - null_set)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    return tp, fp, fn, f1


# -- Cipher evaluation -------------------------------------------------------
def evaluate_mask(null_set, ct_str, ct_len, ct_offset=0):
    """Evaluate a null mask with DEFECTOR:AZ_beau+col6, ABSCISSA:AZ_beau+col6,
    DEFECTOR:AZ_beau+col7, and autokey variants.

    ct_offset: number of chars dropped from front of CT97 (0 or 1).
    Maps null positions back to CT97 positions for crib alignment.

    Returns list of (score, ene, bcl, pt_text, method) for all configs.
    """
    n_nulls = len(null_set)
    if n_nulls < 15 or n_nulls > 35:
        return []

    n_pt = ct_len - n_nulls

    # Extract non-null chars
    ct_extract = [ct_str[i] for i in range(ct_len) if i not in null_set]
    ct_az = [ord(c) - 65 for c in ct_extract]

    # Map null positions to CT97 positions to compute crib shifts
    null_97 = frozenset(p + ct_offset for p in null_set)
    n1 = sum(1 for p in null_97 if p < ENE_START_97)
    n2 = sum(1 for p in null_97 if p < BCL_START_97)
    ene_s = ENE_START_97 - n1 - ct_offset  # adjust for dropped leading chars
    bcl_s = BCL_START_97 - n2 - ct_offset

    if ene_s < 0 or bcl_s < 0:
        return []
    if ene_s + len(ENE_WORD) > n_pt or bcl_s + len(BCL_WORD) > n_pt:
        return []

    results = []

    # Cipher configs: (keyword, use_col_trans, col_width, label, use_autokey)
    configs = [
        ("DEFECTOR", 6, "DEFECTOR:AZ_beau+col6", False),
        ("ABSCISSA", 6, "ABSCISSA:AZ_beau+col6", False),
        ("DEFECTOR", 7, "DEFECTOR:AZ_beau+col7", False),
        ("DEFECTOR", 0, "DEFECTOR:AZ_beau_direct", False),
        ("ABSCISSA", 0, "ABSCISSA:AZ_beau_direct", False),
        ("DEFECTOR", 6, "DEFECTOR:AZ_beau+col6_autokey", True),
        ("ABSCISSA", 6, "ABSCISSA:AZ_beau+col6_autokey", True),
        ("DEFECTOR", 7, "DEFECTOR:AZ_beau+col7_autokey", True),
    ]

    for kw, col_w, label, autokey in configs:
        work = list(ct_az)

        if col_w > 0:
            perm = columnar_perm(n_pt, col_w)
            inv = reverse_perm(perm)
            work = [ct_az[inv[i]] for i in range(n_pt)]

        if autokey:
            pt = autokey_decrypt_az_beau(work, kw)
        else:
            pt = beaufort_decrypt(work, kw)

        total, e, b = count_crib_hits(pt, ene_s, bcl_s, n_pt)
        pt_text = nums_to_text(pt)
        results.append((total, e, b, pt_text, label))

    return results


# -- Grid shift null mask computation ----------------------------------------
def compute_null_mask_shifted_grids(ct_str, shifts):
    """Given ct_str (96 chars) and shifts = [(h1,v1), (h2,v2), (h3,v3)] for grids 1-3
    (grid 0 is fixed), compute null positions.

    A position is NULL if:
    - The char at that position is in PALETTE
    - AND at least one other grid has a palette letter at the SAME cell
      (after shifting)

    Returns frozenset of null positions in ct_str.
    """
    ct_len = len(ct_str)
    n_blocks = 4

    # Precompute: for each grid, which cells (row, col) have palette letters,
    # and their original position in ct_str
    # Grid i covers positions i*24 .. (i+1)*24-1
    # Cell (r, c) within grid i = position i*24 + r*GRID_COLS + c

    # For grid 0: shift = (0, 0)
    # For grid g (1-3): shift = shifts[g-1]
    all_shifts = [(0, 0)] + list(shifts)

    # Build mapping: shifted_cell -> list of (grid_idx, original_position)
    cell_to_entries = {}  # (shifted_row, shifted_col) -> [(grid_idx, orig_pos), ...]

    for g in range(n_blocks):
        h_shift, v_shift = all_shifts[g]
        base = g * BLOCK_SIZE
        for local_pos in range(BLOCK_SIZE):
            orig_pos = base + local_pos
            if orig_pos >= ct_len:
                break
            if ct_str[orig_pos] not in PALETTE:
                continue
            r = local_pos // GRID_COLS
            c = local_pos % GRID_COLS
            shifted_r = (r + v_shift) % GRID_ROWS
            shifted_c = (c + h_shift) % GRID_COLS
            cell = (shifted_r, shifted_c)
            if cell not in cell_to_entries:
                cell_to_entries[cell] = []
            cell_to_entries[cell].append((g, orig_pos))

    # A position is null if it's in a cell where 2+ grids contribute palette letters
    null_set = set()
    for cell, entries in cell_to_entries.items():
        grids_present = set(g for g, _ in entries)
        if len(grids_present) >= 2:
            for _, pos in entries:
                null_set.add(pos)

    return frozenset(null_set)


# -- NDYAHR interpretations as grid shifts -----------------------------------
def ndyahr_interpretations():
    """Return list of (label, [(h1,v1), (h2,v2), (h3,v3)]) based on
    various readings of N-D-Y-A-H-R as movement instructions."""

    # Movement mappings for individual letters
    # N = North = up 1 = (0, -1)
    # D = Down = (0, +1)
    # Y = unknown (several options)
    # A = unknown (several options)
    # H = Horizontal right = (1, 0)
    # R = Right = (1, 0)

    # Basic direction mappings
    moves = {
        'N': (0, -1),   # North = up
        'D': (0, 1),    # Down
        'H': (1, 0),    # Horizontal = right
        'R': (1, 0),    # Right
    }

    # Y interpretations
    y_options = [
        (0, 0),    # Y = no movement (why?)
        (0, -1),   # Y = up (like N)
        (0, 1),    # Y = down
        (1, 0),    # Y = right
        (-1, 0),   # Y = left
        (24 % 6, 24 % 4),  # Y = 25th letter -> (0, 0)
    ]

    # A interpretations
    a_options = [
        (0, 0),    # A = no shift (A=0)
        (1, 0),    # A = across = right 1
        (-1, 0),   # A = across left
        (0, -1),   # A = ascend = up
        (0, 1),    # A = lower (opposite)
    ]

    results = []

    # Interpretation 1: Each pair of letters = one grid's shift
    # Grid 1: N,D  Grid 2: Y,A  Grid 3: H,R
    for y_move in y_options:
        for a_move in a_options:
            # Sum pairs
            g1 = ((moves['N'][0] + moves['D'][0]) % 6, (moves['N'][1] + moves['D'][1]) % 4)
            g2 = ((y_move[0] + a_move[0]) % 6, (y_move[1] + a_move[1]) % 4)
            g3 = ((moves['H'][0] + moves['R'][0]) % 6, (moves['H'][1] + moves['R'][1]) % 4)
            label = f"NDYAHR_pairs_Y={y_move}_A={a_move}"
            results.append((label, [g1, g2, g3]))

    # Interpretation 2: Single letter per grid (first 3 after fixed grid 0)
    # Grid 1: N  Grid 2: D  Grid 3: Y
    for y_move in y_options:
        g1 = (moves['N'][0] % 6, moves['N'][1] % 4)
        g2 = (moves['D'][0] % 6, moves['D'][1] % 4)
        g3 = (y_move[0] % 6, y_move[1] % 4)
        label = f"NDYAHR_single_NDY_Y={y_move}"
        results.append((label, [g1, g2, g3]))

    # Interpretation 3: Letters 2,3,4 (D,Y,A) for grids 1,2,3 (N=reference, H,R=extra)
    for y_move in y_options:
        for a_move in a_options:
            g1 = (moves['D'][0] % 6, moves['D'][1] % 4)
            g2 = (y_move[0] % 6, y_move[1] % 4)
            g3 = (a_move[0] % 6, a_move[1] % 4)
            label = f"NDYAHR_DYA_Y={y_move}_A={a_move}"
            results.append((label, [g1, g2, g3]))

    # Interpretation 4: All 6 letters as cumulative shifts
    # Grid g gets shift = sum of first (g+1)*2 letters divided somehow
    for y_move in y_options:
        for a_move in a_options:
            all_moves = [moves['N'], moves['D'], y_move, a_move, moves['H'], moves['R']]
            # Grid 1: first 2 letters N,D
            g1_h = sum(m[0] for m in all_moves[:2]) % 6
            g1_v = sum(m[1] for m in all_moves[:2]) % 4
            # Grid 2: first 4 letters N,D,Y,A
            g2_h = sum(m[0] for m in all_moves[:4]) % 6
            g2_v = sum(m[1] for m in all_moves[:4]) % 4
            # Grid 3: all 6 letters
            g3_h = sum(m[0] for m in all_moves[:6]) % 6
            g3_v = sum(m[1] for m in all_moves[:6]) % 4
            label = f"NDYAHR_cumulative_Y={y_move}_A={a_move}"
            results.append((label, [(g1_h, g1_v), (g2_h, g2_v), (g3_h, g3_v)])
            )

    # Interpretation 5: Alphabet position mod dimensions
    # N=13, D=3, Y=24, A=0, H=7, R=17
    alpha_pos = {'N': 13, 'D': 3, 'Y': 24, 'A': 0, 'H': 7, 'R': 17}
    # Grid 1: (N%6, D%4) = (1, 3)
    # Grid 2: (Y%6, A%4) = (0, 0)
    # Grid 3: (H%6, R%4) = (1, 1)
    results.append(("NDYAHR_alphamod",
                    [(alpha_pos['N'] % 6, alpha_pos['D'] % 4),
                     (alpha_pos['Y'] % 6, alpha_pos['A'] % 4),
                     (alpha_pos['H'] % 6, alpha_pos['R'] % 4)]))

    # Also reversed: (D%6, N%4) etc
    results.append(("NDYAHR_alphamod_rev",
                    [(alpha_pos['D'] % 6, alpha_pos['N'] % 4),
                     (alpha_pos['A'] % 6, alpha_pos['Y'] % 4),
                     (alpha_pos['R'] % 6, alpha_pos['H'] % 4)]))

    # KA position
    ka_pos = {c: i for i, c in enumerate(KA_STR)}
    results.append(("NDYAHR_KAmod",
                    [(ka_pos['N'] % 6, ka_pos['D'] % 4),
                     (ka_pos['Y'] % 6, ka_pos['A'] % 4),
                     (ka_pos['H'] % 6, ka_pos['R'] % 4)]))

    results.append(("NDYAHR_KAmod_rev",
                    [(ka_pos['D'] % 6, ka_pos['N'] % 4),
                     (ka_pos['A'] % 6, ka_pos['Y'] % 4),
                     (ka_pos['R'] % 6, ka_pos['H'] % 4)]))

    return results


# -- Main --------------------------------------------------------------------
def main():
    t0 = time.time()

    print("=" * 72)
    print("FOUR 6x4 GRIDS STACKED WITH INDEPENDENT SHIFTS")
    print("=" * 72)
    print(f"CT97 = {CT97}")
    print(f"Palette: {sorted(PALETTE)}")
    print(f"Grid: {GRID_COLS}x{GRID_ROWS} = {BLOCK_SIZE} cells per block")
    print(f"Blocks: 4 (from 96 chars = 4 x 24)")
    print()

    all_hits = []  # configs scoring >= 10/24
    stats = {
        'drop_last': {'tested': 0, 'max_crib': 0, 'max_n_nulls': 0, 'hits_12': 0},
        'drop_first': {'tested': 0, 'max_crib': 0, 'max_n_nulls': 0, 'hits_12': 0},
        'ndyahr_drop_last': {'tested': 0, 'max_crib': 0, 'hits_12': 0},
        'ndyahr_drop_first': {'tested': 0, 'max_crib': 0, 'hits_12': 0},
    }

    # -- Variant 1: Drop last char (R) from CT97 --
    ct96_drop_last = CT97[:-1]  # 96 chars, offset = 0
    ct96_drop_first = CT97[1:]  # 96 chars, offset = 1

    variants = [
        ("drop_last", ct96_drop_last, 0),
        ("drop_first", ct96_drop_first, 1),
    ]

    # Precompute palette positions per block for each variant
    for var_name, ct96, ct_offset in variants:
        print(f"--- {var_name.upper()}: CT96 = {ct96[:20]}...{ct96[-10:]} (offset={ct_offset}) ---")

        # Precompute palette bitmask per grid cell for each block
        block_palette = []  # block_palette[g] = set of (local_pos) that are palette
        for g in range(4):
            base = g * BLOCK_SIZE
            pals = set()
            for lp in range(BLOCK_SIZE):
                pos = base + lp
                if pos < len(ct96) and ct96[pos] in PALETTE:
                    pals.add(lp)
            block_palette.append(pals)

        print(f"  Palette per block: {[len(s) for s in block_palette]}")
        print(f"  Total palette positions: {sum(len(s) for s in block_palette)}")

        # Precompute: for each block g and each shift (h,v), which cells are occupied
        # cell = (shifted_row, shifted_col)
        block_shifted_cells = {}  # (g, h, v) -> dict{cell: [orig_pos]}
        for g in range(4):
            base = g * BLOCK_SIZE
            for h in range(GRID_COLS):
                for v in range(GRID_ROWS):
                    cell_map = {}
                    for lp in block_palette[g]:
                        r = lp // GRID_COLS
                        c = lp % GRID_COLS
                        sr = (r + v) % GRID_ROWS
                        sc = (c + h) % GRID_COLS
                        cell = (sr, sc)
                        if cell not in cell_map:
                            cell_map[cell] = []
                        cell_map[cell].append(base + lp)
                    block_shifted_cells[(g, h, v)] = cell_map

        # Grid 0 is always at shift (0, 0)
        g0_cells = block_shifted_cells[(0, 0, 0)]

        tested = 0
        max_crib = 0
        n_null_counts = {}

        # Exhaustive: all 24^3 shift combos for grids 1, 2, 3
        for h1 in range(GRID_COLS):
            for v1 in range(GRID_ROWS):
                g1_cells = block_shifted_cells[(1, h1, v1)]
                for h2 in range(GRID_COLS):
                    for v2 in range(GRID_ROWS):
                        g2_cells = block_shifted_cells[(2, h2, v2)]
                        for h3 in range(GRID_COLS):
                            for v3 in range(GRID_ROWS):
                                g3_cells = block_shifted_cells[(3, h3, v3)]
                                tested += 1

                                # Build cell -> grids mapping
                                cell_grids = {}
                                for cell, positions in g0_cells.items():
                                    if cell not in cell_grids:
                                        cell_grids[cell] = {}
                                    cell_grids[cell][0] = positions
                                for cell, positions in g1_cells.items():
                                    if cell not in cell_grids:
                                        cell_grids[cell] = {}
                                    cell_grids[cell][1] = positions
                                for cell, positions in g2_cells.items():
                                    if cell not in cell_grids:
                                        cell_grids[cell] = {}
                                    cell_grids[cell][2] = positions
                                for cell, positions in g3_cells.items():
                                    if cell not in cell_grids:
                                        cell_grids[cell] = {}
                                    cell_grids[cell][3] = positions

                                # Find nulls
                                null_set = set()
                                for cell, grids in cell_grids.items():
                                    if len(grids) >= 2:
                                        for g_positions in grids.values():
                                            for pos in g_positions:
                                                null_set.add(pos)

                                n_nulls = len(null_set)
                                n_null_counts[n_nulls] = n_null_counts.get(n_nulls, 0) + 1

                                # Only evaluate if plausible null count
                                if n_nulls < 15 or n_nulls > 35:
                                    continue

                                null_frozen = frozenset(null_set)

                                # Evaluate with ciphers
                                cipher_results = evaluate_mask(
                                    null_frozen, ct96, len(ct96), ct_offset)

                                for total, e, b, pt_text, method in cipher_results:
                                    if total > max_crib:
                                        max_crib = total
                                    if total >= 10:
                                        tp, fp, fn, f1 = score_mask_consensus(
                                            frozenset(p + ct_offset for p in null_set))
                                        all_hits.append({
                                            'variant': var_name,
                                            'shifts': [(h1, v1), (h2, v2), (h3, v3)],
                                            'n_nulls': n_nulls,
                                            'null_positions': sorted(null_set),
                                            'null_97': sorted(p + ct_offset for p in null_set),
                                            'crib_score': total,
                                            'crib_ene': e,
                                            'crib_bcl': b,
                                            'method': method,
                                            'pt_text': pt_text,
                                            'consensus_tp': tp,
                                            'consensus_f1': round(f1, 4),
                                            'source': 'exhaustive',
                                        })

        stats[var_name]['tested'] = tested
        stats[var_name]['max_crib'] = max_crib
        stats[var_name]['hits_12'] = sum(1 for h in all_hits
                                         if h['variant'] == var_name and h['crib_score'] >= 12)

        print(f"  Tested: {tested:,} shift combinations")
        print(f"  Max crib score: {max_crib}/24")
        print(f"  Null count distribution (top 10): ", end="")
        top_counts = sorted(n_null_counts.items(), key=lambda x: -x[1])[:10]
        print(", ".join(f"{k}:{v}" for k, v in sorted(top_counts)))
        print(f"  Hits >= 10: {sum(1 for h in all_hits if h['variant'] == var_name and h['crib_score'] >= 10)}")
        print(f"  Hits >= 12: {sum(1 for h in all_hits if h['variant'] == var_name and h['crib_score'] >= 12)}")
        print()

    # -- NDYAHR interpretations --
    print("=" * 72)
    print("NDYAHR SHIFT INTERPRETATIONS")
    print("=" * 72)

    ndyahr_configs = ndyahr_interpretations()
    print(f"Testing {len(ndyahr_configs)} NDYAHR interpretations x 2 drop variants")
    print()

    for var_name, ct96, ct_offset in variants:
        stat_key = f"ndyahr_{var_name}"
        ndyahr_tested = 0
        ndyahr_max_crib = 0

        for label, shifts in ndyahr_configs:
            ndyahr_tested += 1
            null_set_frozen = compute_null_mask_shifted_grids(ct96, shifts)
            n_nulls = len(null_set_frozen)

            if n_nulls < 15 or n_nulls > 35:
                continue

            cipher_results = evaluate_mask(null_set_frozen, ct96, len(ct96), ct_offset)

            for total, e, b, pt_text, method in cipher_results:
                if total > ndyahr_max_crib:
                    ndyahr_max_crib = total
                if total >= 10:
                    tp, fp, fn, f1 = score_mask_consensus(
                        frozenset(p + ct_offset for p in null_set_frozen))
                    all_hits.append({
                        'variant': f"ndyahr_{var_name}",
                        'shifts_label': label,
                        'shifts': list(shifts),
                        'n_nulls': n_nulls,
                        'null_positions': sorted(null_set_frozen),
                        'null_97': sorted(p + ct_offset for p in null_set_frozen),
                        'crib_score': total,
                        'crib_ene': e,
                        'crib_bcl': b,
                        'method': method,
                        'pt_text': pt_text,
                        'consensus_tp': tp,
                        'consensus_f1': round(f1, 4),
                        'source': 'ndyahr',
                    })

        stats[stat_key]['tested'] = ndyahr_tested
        stats[stat_key]['max_crib'] = ndyahr_max_crib
        stats[stat_key]['hits_12'] = sum(1 for h in all_hits
                                          if h.get('variant') == f"ndyahr_{var_name}"
                                          and h['crib_score'] >= 12)

        print(f"  {var_name}: {ndyahr_tested} configs, max crib = {ndyahr_max_crib}/24, "
              f"hits >= 12: {stats[stat_key]['hits_12']}")

    print()

    # -- Summary --
    elapsed = time.time() - t0
    total_tested = sum(s['tested'] for s in stats.values())
    overall_max = max(s['max_crib'] for s in stats.values()) if stats else 0

    print("=" * 72)
    print(f"TOTAL: {total_tested:,} configs in {elapsed:.1f}s")
    print(f"Overall max crib: {overall_max}/24")
    print(f"Total hits >= 10: {len([h for h in all_hits if h['crib_score'] >= 10])}")
    print(f"Total hits >= 12: {len([h for h in all_hits if h['crib_score'] >= 12])}")
    print()

    # Print top 20 hits
    top_hits = sorted(all_hits, key=lambda x: (-x['crib_score'], -x.get('consensus_f1', 0)))[:30]
    if top_hits:
        print("--- TOP 30 HITS ---")
        for i, h in enumerate(top_hits):
            shifts_str = str(h.get('shifts_label', h.get('shifts', '?')))
            print(f"  {i+1:2d}. {h['variant']:20s} shifts={shifts_str:40s}"
                  f"  crib={h['crib_score']}/24 (e={h['crib_ene']}/13, b={h['crib_bcl']}/11)"
                  f"  n_null={h['n_nulls']}"
                  f"  [{h['method']}]"
                  f"  F1={h.get('consensus_f1', 0):.3f}")
            print(f"      PT={h['pt_text'][:70]}")
    else:
        print("No hits >= 10/24.")

    # -- Determine conclusion --
    if overall_max >= 18:
        conclusion = "SIGNAL"
    elif overall_max >= 12:
        conclusion = "INTERESTING"
    elif overall_max >= 10:
        conclusion = "BORDERLINE"
    else:
        conclusion = "NOISE"

    print()
    print(f"VERDICT: {conclusion}")

    # -- Save results --
    output = {
        "experiment": "grid_shift_null_mask",
        "description": "Four 6x4 grids stacked with independent shifts. "
                       "Palette overlap = null. DEFECTOR/ABSCISSA AZ_beau + col6/col7.",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ct97": CT97,
        "palette": sorted(PALETTE),
        "grid_dims": f"{GRID_COLS}x{GRID_ROWS}",
        "block_size": BLOCK_SIZE,
        "total_configs": total_tested,
        "elapsed_seconds": round(elapsed, 1),
        "stats": stats,
        "overall_max_crib": overall_max,
        "conclusion": conclusion,
        "hits_count": len(all_hits),
        "top_hits": top_hits,
        "all_hits_ge10": all_hits,
    }

    outpath = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '..', '..', 'results', 'grid_shift_null_mask.json')
    outpath = os.path.normpath(outpath)
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {outpath}")
    print(f"Elapsed: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
