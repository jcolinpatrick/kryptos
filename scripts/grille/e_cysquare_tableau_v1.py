#!/usr/bin/env python3
"""
Cysquare cipher on the Kryptos Vigenere Tableau.

Cipher:  Cysquare (26x26 grid stencil, predecessor to RS 44)
Family:  grille
Status:  active
Keyspace: ~50M+ configs
Last run: never
Best score: N/A

HYPOTHESIS: The Kryptos Vigenere tableau IS a Cysquare grid.
- 26x26 = 676 cells (tableau body, excluding key column and header/footer)
- KA alphabet across top = "randomly shuffled alphabet" (shuffled by KRYPTOS keyword)
- AZ key column down left = "numbers 1 to 26" (letter indices)
- "Intentionally flipped" = grid can be read from 4 orientations
- "Kryptos Decoding Filter" = the physical Cysquare stencil
- K2 coordinates = Cysquare indicator (grid position, start cell, read-off column)

Cysquare mechanism:
1. Grid = 26x26 with open cells (10/row standard) and black cells (16/row)
2. Message written L-to-R in open cells starting from indicator-derived start cell
3. Ciphertext read column-by-column in keyed order from indicator-derived read-off column
4. For DECRYPTION: reverse the column reading, then read open cells to get plaintext

For K4: The tableau cells are ALREADY FILLED with letters (the KA Vigenere square).
A stencil over the tableau READS letters, producing a sequence. That sequence
could be: the key, the ciphertext, or the plaintext itself.
"""

import sys
import os
import json
import time
import math
from pathlib import Path
from multiprocessing import Pool, cpu_count
from itertools import permutations

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ========================================================================
# BUILD THE KRYPTOS TABLEAU (26x26 body)
# ========================================================================

KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"

def build_tableau():
    """Build the 26x26 Kryptos Vigenere tableau body.

    Row i (key letter = ALPH[i]) contains KA shifted by i positions:
        body[row][col] = KA[(AZ_index(row_key_letter) + col) mod 26]

    Returns 26x26 list of lists.
    """
    tableau = []
    for row in range(26):
        # Row keyed by ALPH[row] (A=0, B=1, ..., Z=25)
        # Body = KA rotated by row positions
        tableau_row = []
        for col in range(26):
            tableau_row.append(KA[(row + col) % 26])
        tableau.append(tableau_row)
    return tableau

TABLEAU = build_tableau()

# Verify: Row 0 (key=A) should start with K (KA[0])
assert TABLEAU[0][0] == 'K', f"Tableau[0][0] should be K, got {TABLEAU[0][0]}"
assert TABLEAU[0] == list(KA), f"Row 0 should be KA alphabet"


def read_tableau_rotated(tableau, rotation):
    """Read the 26x26 tableau in one of 4 orientations.

    rotation 0: normal (top-left origin, read L-to-R, T-to-B)
    rotation 1: 90° CW (top-right origin)
    rotation 2: 180° (bottom-right origin) — "intentionally flipped"
    rotation 3: 270° CW (bottom-left origin)

    Returns a new 26x26 grid.
    """
    if rotation == 0:
        return [row[:] for row in tableau]
    elif rotation == 1:
        # 90° CW: new[r][c] = old[25-c][r]
        return [[tableau[25 - c][r] for c in range(26)] for r in range(26)]
    elif rotation == 2:
        # 180°: new[r][c] = old[25-r][25-c]
        return [[tableau[25 - r][25 - c] for c in range(26)] for r in range(26)]
    elif rotation == 3:
        # 270° CW: new[r][c] = old[c][25-r]
        return [[tableau[c][25 - r] for c in range(26)] for r in range(26)]
    return tableau


# ========================================================================
# CYSQUARE STENCIL OPERATIONS
# ========================================================================

def cysquare_read(tableau_grid, open_positions, col_order, start_col=0):
    """Read through Cysquare stencil holes in keyed column order.

    Args:
        tableau_grid: 26x26 grid of letters
        open_positions: set of (row, col) tuples that are "open" (holes)
        col_order: list of column indices in reading order
        start_col: which column in col_order to start reading from

    Returns: string of letters read through the stencil
    """
    result = []
    n_cols = len(col_order)
    for i in range(n_cols):
        col = col_order[(start_col + i) % n_cols]
        for row in range(26):
            if (row, col) in open_positions:
                result.append(tableau_grid[row][col])
    return ''.join(result)


def cysquare_read_from_start(tableau_grid, open_positions, col_order, start_row, start_col):
    """Read from a specific starting cell, wrapping around.

    Reads column-by-column in col_order, within each column top-to-bottom,
    starting from the column containing start_col and the row at/after start_row.
    """
    result = []
    # Find which position in col_order contains start_col
    try:
        start_idx = col_order.index(start_col)
    except ValueError:
        start_idx = 0

    n_cols = len(col_order)
    for i in range(n_cols):
        col = col_order[(start_idx + i) % n_cols]
        for row in range(26):
            # On first column, start from start_row
            if i == 0 and row < start_row:
                continue
            if (row, col) in open_positions:
                result.append(tableau_grid[row][col])

    # Wrap: read the skipped cells from the first column
    if start_row > 0:
        col = col_order[start_idx]
        for row in range(start_row):
            if (row, col) in open_positions:
                result.append(tableau_grid[row][col])

    return ''.join(result)


# ========================================================================
# STENCIL GENERATORS
# ========================================================================

def generate_standard_stencils(n_open_per_row=10, n_stencils=2000, seed=42):
    """Generate stencils with fixed number of open cells per row (Cysquare standard: 10/26)."""
    import random
    rng = random.Random(seed)
    stencils = []
    for _ in range(n_stencils):
        positions = set()
        for row in range(26):
            cols = rng.sample(range(26), n_open_per_row)
            for col in cols:
                positions.add((row, col))
        stencils.append(frozenset(positions))
    return stencils


def generate_variable_stencils(target_cells, n_stencils=2000, seed=123):
    """Generate stencils with a target total number of open cells."""
    import random
    rng = random.Random(seed)
    stencils = []
    all_cells = [(r, c) for r in range(26) for c in range(26)]
    for _ in range(n_stencils):
        chosen = rng.sample(all_cells, target_cells)
        stencils.append(frozenset(chosen))
    return stencils


def generate_structured_stencils():
    """Generate stencils based on structural properties of the Kryptos tableau."""
    stencils = []

    # 1. KA cycle membership: 17-cycle positions
    cycle17 = set("AHOFLSGNTELIRBKDPM"[:17])  # A→H→O→F→M→S→G→N→T→E→L→R→B→I→P→D→K
    cycle8 = set("CJQUVWXY")

    # Open cells where row letter is in 17-cycle
    positions_17 = set()
    for row in range(26):
        if ALPH[row] in cycle17:
            for col in range(26):
                if KA[col] in cycle17:
                    positions_17.add((row, col))
    stencils.append(("cycle17x17", frozenset(positions_17)))

    # Open cells where row OR col letter is in 17-cycle (not both)
    positions_xor = set()
    for row in range(26):
        for col in range(26):
            r_in = ALPH[row] in cycle17
            c_in = KA[col] in cycle17
            if r_in != c_in:  # XOR
                positions_xor.add((row, col))
    stencils.append(("cycle17_xor", frozenset(positions_xor)))

    # 2. Diagonal stencils
    for offset in range(26):
        positions = set()
        for i in range(26):
            positions.add((i, (i + offset) % 26))
        stencils.append((f"diag_{offset}", frozenset(positions)))

    # 3. Every-Nth-cell patterns
    for step in [3, 5, 7, 8, 10, 13]:
        positions = set()
        for i in range(0, 676, step):
            positions.add((i // 26, i % 26))
        stencils.append((f"step_{step}", frozenset(positions)))

    # 4. KRYPTOS-letter columns/rows
    kryptos_cols = set()
    for i, c in enumerate(KA):
        if c in "KRYPTOS":
            for row in range(26):
                kryptos_cols.add((row, i))
    stencils.append(("kryptos_cols", frozenset(kryptos_cols)))

    return stencils


# ========================================================================
# K2 COORDINATES AS CYSQUARE INDICATOR
# ========================================================================

def k2_indicator_configs():
    """Generate Cysquare indicator interpretations from K2 coordinates.

    K2 coordinates: 38°57'6.5"N, 77°8'44"W
    Numbers: 38, 57, 6(.5), 44, 77, 8

    Cysquare indicator = 4 numbers:
      1st = grid position (1-4, which rotation)
      2nd = starting row (1-26)
      3rd = starting column (1-26)
      4th = initial read-off column (1-26)
    """
    configs = []

    # Direct mappings (mod 26 for row/col, mod 4 for rotation)
    candidates = [
        # (rotation, start_row, start_col, readoff_col, label)
        (38 % 4, (57 - 1) % 26, (6 - 1) % 26, (44 - 1) % 26, "38-57-6-44"),
        (38 % 4, (57 - 1) % 26, (44 - 1) % 26, (6 - 1) % 26, "38-57-44-6"),
        (44 % 4, (38 - 1) % 26, (57 - 1) % 26, (6 - 1) % 26, "44-38-57-6"),
        (6 % 4, (38 - 1) % 26, (57 - 1) % 26, (44 - 1) % 26, "6-38-57-44"),
        (8 % 4, (38 - 1) % 26, (57 - 1) % 26, (6 - 1) % 26, "8-38-57-6"),
        (77 % 4, (8 - 1) % 26, (44 - 1) % 26, (38 - 1) % 26, "77-8-44-38"),
        # K2 progressive solve: 38→24, 77→14, 8→8
        (0, 23, 13, 7, "prog_24-14-8"),
        (1, 23, 13, 7, "prog_r1_24-14-8"),
        (2, 23, 13, 7, "prog_r2_24-14-8"),
        (3, 23, 13, 7, "prog_r3_24-14-8"),
        # Simple sequential
        (0, 2, 5, 7, "simple_3-6-8"),  # 38→3,8  57→5,7
        (1, 2, 5, 7, "simple_r1"),
        (2, 2, 5, 7, "simple_r2"),
        (3, 2, 5, 7, "simple_r3"),
        # Digits as-is (3,8,5,7)
        (3 % 4, 7, 4, 6, "digits_3857"),
        # Row/col labels: 38→row, 57→col (mod 26)
        (0, 38 % 26, 57 % 26, 6, "rowcol_38-57-6"),
        (0, 38 % 26, 57 % 26, 44 % 26, "rowcol_38-57-44"),
    ]

    return candidates


# ========================================================================
# SUBSTITUTION DECRYPTION
# ========================================================================

KA_IDX = {c: i for i, c in enumerate(KA)}

def decrypt_beaufort_az(ct_str, key_str):
    result = []
    klen = len(key_str)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX.get(c, -1)
        ki = ALPH_IDX.get(key_str[i % klen], -1)
        if ci < 0 or ki < 0:
            result.append('?')
        else:
            result.append(ALPH[(ki - ci) % 26])
    return ''.join(result)

def decrypt_vigenere_az(ct_str, key_str):
    result = []
    klen = len(key_str)
    for i, c in enumerate(ct_str):
        ci = ALPH_IDX.get(c, -1)
        ki = ALPH_IDX.get(key_str[i % klen], -1)
        if ci < 0 or ki < 0:
            result.append('?')
        else:
            result.append(ALPH[(ci - ki) % 26])
    return ''.join(result)


# ========================================================================
# SCORING
# ========================================================================

ENE = "EASTNORTHEAST"
BC = "BERLINCLOCK"

def score_free(pt):
    s = 0
    if ENE in pt:
        s += 13
    if BC in pt:
        s += 11
    return s

def score_anchored(pt):
    total = 0
    if len(pt) >= 34:
        for i, ch in enumerate(ENE):
            if 21 + i < len(pt) and pt[21 + i] == ch:
                total += 1
    if len(pt) >= 74:
        for i, ch in enumerate(BC):
            if 63 + i < len(pt) and pt[63 + i] == ch:
                total += 1
    return total


# ========================================================================
# WORKER
# ========================================================================

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "SEVEN", "BERLIN", "FIVE", "CLOCK", "SANBORN", "SCHEIDT",
]

def worker(args):
    """Process a batch of stencils with all rotations, indicators, and substitutions."""
    stencils, k2_configs = args

    results = []
    configs = 0

    for stencil_label, stencil in stencils:
        for rotation in range(4):
            grid = read_tableau_rotated(TABLEAU, rotation)

            for rot_idx, start_row, start_col, readoff_col, ind_label in k2_configs:
                if rot_idx != rotation:
                    continue

                # Build column order: start from readoff_col, go sequentially
                col_order = [(readoff_col + i) % 26 for i in range(26)]

                # Read through stencil
                extracted = cysquare_read_from_start(grid, stencil, col_order, start_row, start_col)
                if len(extracted) < 20:
                    continue

                configs += 1

                # Mode 1: Extracted text IS the plaintext (stencil reveals message directly)
                fs = score_free(extracted)
                if fs >= 11:
                    results.append({
                        'score': fs, 'mode': 'direct_read',
                        'stencil': stencil_label, 'rotation': rotation,
                        'indicator': ind_label, 'extract_len': len(extracted),
                        'pt': extracted[:80],
                    })

                # Mode 2: Extracted text is the KEY for K4 decryption
                for keyword in KEYWORDS:
                    configs += 1
                    # Use extracted as running key for Beaufort on K4
                    if len(extracted) >= CT_LEN:
                        pt_beau = decrypt_beaufort_az(CT, extracted[:CT_LEN])
                        fs2 = score_free(pt_beau)
                        anch2 = score_anchored(pt_beau)
                        if fs2 >= 11 or anch2 >= 8:
                            results.append({
                                'score': max(fs2, anch2), 'mode': 'running_key_beau',
                                'stencil': stencil_label, 'rotation': rotation,
                                'indicator': ind_label,
                                'pt': pt_beau[:80],
                            })

                        pt_vig = decrypt_vigenere_az(CT, extracted[:CT_LEN])
                        fs3 = score_free(pt_vig)
                        anch3 = score_anchored(pt_vig)
                        if fs3 >= 11 or anch3 >= 8:
                            results.append({
                                'score': max(fs3, anch3), 'mode': 'running_key_vig',
                                'stencil': stencil_label, 'rotation': rotation,
                                'indicator': ind_label,
                                'pt': pt_vig[:80],
                            })

                # Mode 3: Read all 26 columns in KEYWORD order (not sequential)
                for kw in KEYWORDS[:5]:
                    kw_order = sorted(range(min(len(kw), 26)),
                                     key=lambda i: (kw[i % len(kw)], i))
                    # Pad to 26 if keyword shorter
                    if len(kw_order) < 26:
                        remaining = [c for c in range(26) if c not in kw_order]
                        kw_order.extend(remaining)

                    extracted_kw = cysquare_read(grid, stencil, kw_order)
                    configs += 1

                    fs4 = score_free(extracted_kw)
                    if fs4 >= 11:
                        results.append({
                            'score': fs4, 'mode': 'keyword_read',
                            'stencil': stencil_label, 'rotation': rotation,
                            'keyword': kw, 'extract_len': len(extracted_kw),
                            'pt': extracted_kw[:80],
                        })

                    # Also use as running key
                    if len(extracted_kw) >= CT_LEN:
                        configs += 1
                        pt_rk = decrypt_beaufort_az(CT, extracted_kw[:CT_LEN])
                        fs5 = score_free(pt_rk)
                        anch5 = score_anchored(pt_rk)
                        if fs5 >= 11 or anch5 >= 8:
                            results.append({
                                'score': max(fs5, anch5), 'mode': 'kw_running_key',
                                'stencil': stencil_label, 'rotation': rotation,
                                'keyword': kw,
                                'pt': pt_rk[:80],
                            })

    return results, configs


# ========================================================================
# MAIN
# ========================================================================

def run():
    t0 = time.time()
    ncores = min(cpu_count(), 28)

    print("=" * 72)
    print("CYSQUARE ON KRYPTOS VIGENERE TABLEAU")
    print("=" * 72)
    print(f"Tableau: 26x26 = 676 cells (KA Vigenere body)")
    print(f"CT: {CT[:40]}... ({CT_LEN} chars)")
    print(f"Cores: {ncores}")
    print()

    # Verify tableau
    print("Tableau row 0 (key=A):", ''.join(TABLEAU[0]))
    print("Tableau row 1 (key=B):", ''.join(TABLEAU[1]))
    print("Tableau[0][0]:", TABLEAU[0][0], "(should be K)")
    print()

    # Generate stencils
    print("Generating stencils...")

    # Standard Cysquare: 10 open per row = 260 open cells
    stencils_10 = [("std10_" + str(i), s) for i, s in
                   enumerate(generate_standard_stencils(10, 3000, seed=42))]

    # 73 total open cells (K4 plaintext length)
    stencils_73 = [("t73_" + str(i), s) for i, s in
                   enumerate(generate_variable_stencils(73, 2000, seed=73))]

    # 97 total open cells (K4 ciphertext length)
    stencils_97 = [("t97_" + str(i), s) for i, s in
                   enumerate(generate_variable_stencils(97, 2000, seed=97))]

    # Structured stencils
    stencils_struct = generate_structured_stencils()

    all_stencils = stencils_10 + stencils_73 + stencils_97 + stencils_struct
    print(f"  Standard (10/row): {len(stencils_10)}")
    print(f"  73-cell target: {len(stencils_73)}")
    print(f"  97-cell target: {len(stencils_97)}")
    print(f"  Structured: {len(stencils_struct)}")
    print(f"  Total: {len(all_stencils)}")

    # K2 indicator configs
    k2_configs = k2_indicator_configs()
    print(f"K2 indicator configs: {len(k2_configs)}")

    # Build work items
    batch_size = max(1, len(all_stencils) // (ncores * 4))
    work_items = []
    for i in range(0, len(all_stencils), batch_size):
        batch = all_stencils[i:i + batch_size]
        work_items.append((batch, k2_configs))

    print(f"Work items: {len(work_items)}")
    print("Running...", flush=True)

    all_results = []
    total_configs = 0

    with Pool(ncores) as pool:
        for batch_results, batch_configs in pool.imap_unordered(worker, work_items, chunksize=1):
            all_results.extend(batch_results)
            total_configs += batch_configs

    elapsed = time.time() - t0
    all_results.sort(key=lambda r: r['score'], reverse=True)

    # Summary
    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print(f"Total configs: {total_configs:,}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/60:.1f}m)")
    print(f"Results: {len(all_results)} hits")

    best_score = all_results[0]['score'] if all_results else 0
    print(f"Best score: {best_score}/24")

    if all_results:
        print(f"\nTop 30:")
        for i, r in enumerate(all_results[:30]):
            print(f"  {i+1:3d}. {r['score']:2d}/24 | {r['mode']} | "
                  f"stencil={r.get('stencil','')} rot={r.get('rotation','')} "
                  f"ind={r.get('indicator','')} | PT: {r.get('pt','')[:50]}")

    verdict = "SIGNAL" if best_score >= 18 else ("INTERESTING" if best_score >= 10 else "NOISE")
    print(f"\nVERDICT: {verdict}")

    # Save
    out_path = Path(__file__).resolve().parents[2] / "results" / "e_cysquare_tableau_v1.json"
    os.makedirs(out_path.parent, exist_ok=True)
    output = {
        'experiment': 'e_cysquare_tableau_v1',
        'description': 'Cysquare cipher on Kryptos Vigenere tableau (26x26 body)',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'elapsed_seconds': round(elapsed, 1),
        'best_score': best_score,
        'verdict': verdict,
        'top_50': all_results[:50],
    }
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    run()
