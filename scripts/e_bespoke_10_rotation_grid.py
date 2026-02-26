#!/usr/bin/env python3
"""E-BESPOKE-10: K3-style physical rotation grid attack on K4.

K3 was encrypted using a physical grid: write plaintext row-by-row, rotate
the grid 90 degrees clockwise, then read out. This script tests whether
K4 uses the same geometric permutation approach.

Phases:
  1. Padded 97-char grids (multiple sizes, rotations, padding positions)
  2. L-insertion to make 98 chars (7x14 exact fit — highest priority)
  3. Column-first writing (inverse of K3 method)
  4. Double rotation + hybrid columnar
  5. K3 exact method reproduction

For each geometric permutation, both operation orders are tested:
  - Order A: Decrypt substitution first, THEN undo rotation
  - Order B: Undo rotation first, THEN decrypt substitution

Uses canonical scoring from kryptos.kernel.scoring.aggregate.
"""
from __future__ import annotations

import json
import os
import string
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from kryptos.kernel.constants import (
    CT, CRIB_WORDS, CRIB_DICT, ALPH, ALPH_IDX, MOD, CT_LEN,
)
from kryptos.kernel.scoring.crib_score import score_cribs


# ── Grid rotation primitives ───────────────────────────────────────────────

def make_grid(text: str, cols: int, rows: int) -> list[list[str]]:
    """Write text into a grid row-by-row. Pad with X if needed."""
    padded = text.ljust(cols * rows, 'X')
    grid = []
    for r in range(rows):
        grid.append(list(padded[r * cols: r * cols + cols]))
    return grid


def grid_to_str(grid: list[list[str]]) -> str:
    return ''.join(''.join(row) for row in grid)


def rotate_90cw(grid: list[list[str]]) -> list[list[str]]:
    """Rotate grid 90 degrees clockwise.
    Original: rows x cols -> New: cols x rows
    new[c][rows-1-r] = old[r][c]
    """
    rows = len(grid)
    cols = len(grid[0])
    new_grid = [[''] * rows for _ in range(cols)]
    for r in range(rows):
        for c in range(cols):
            new_grid[c][rows - 1 - r] = grid[r][c]
    return new_grid


def rotate_90ccw(grid: list[list[str]]) -> list[list[str]]:
    """Rotate grid 90 degrees counter-clockwise.
    new[cols-1-c][r] = old[r][c]
    """
    rows = len(grid)
    cols = len(grid[0])
    new_grid = [[''] * rows for _ in range(cols)]
    for r in range(rows):
        for c in range(cols):
            new_grid[cols - 1 - c][r] = grid[r][c]
    return new_grid


def rotate_180(grid: list[list[str]]) -> list[list[str]]:
    """Rotate grid 180 degrees.
    new[rows-1-r][cols-1-c] = old[r][c]
    """
    rows = len(grid)
    cols = len(grid[0])
    new_grid = [[''] * cols for _ in range(rows)]
    for r in range(rows):
        for c in range(cols):
            new_grid[rows - 1 - r][cols - 1 - c] = grid[r][c]
    return new_grid


ROTATIONS = {
    'CW90': rotate_90cw,
    'CCW90': rotate_90ccw,
    '180': rotate_180,
}


def apply_rotation(text: str, cols: int, rows: int, rotation: str) -> str:
    """Write text into grid (row-by-row), rotate, read out (row-by-row)."""
    grid = make_grid(text, cols, rows)
    rotated = ROTATIONS[rotation](grid)
    return grid_to_str(rotated)


def undo_rotation(text: str, cols: int, rows: int, rotation: str) -> str:
    """Undo a rotation: apply the inverse rotation.
    If original was CW90, inverse is CCW90 and vice versa.
    For 180, inverse is 180.
    Note: after CW90 on a (rows x cols) grid, the output grid is (cols x rows).
    So to undo CW90, we apply CCW90 with swapped dimensions.
    """
    if rotation == 'CW90':
        # Output of CW90(rows x cols) is a (cols x rows) grid
        # To undo: apply CCW90 on (cols x rows) grid -> (rows x cols)
        grid = make_grid(text, rows, cols)  # read into cols-wide, rows-tall
        inv = rotate_90ccw(grid)
        return grid_to_str(inv)
    elif rotation == 'CCW90':
        grid = make_grid(text, rows, cols)
        inv = rotate_90cw(grid)
        return grid_to_str(inv)
    elif rotation == '180':
        grid = make_grid(text, cols, rows)
        inv = rotate_180(grid)
        return grid_to_str(inv)
    else:
        raise ValueError(f"Unknown rotation: {rotation}")


def write_by_columns(text: str, cols: int, rows: int) -> list[list[str]]:
    """Write text into grid column-by-column (top to bottom, left to right)."""
    padded = text.ljust(cols * rows, 'X')
    grid = [[''] * cols for _ in range(rows)]
    idx = 0
    for c in range(cols):
        for r in range(rows):
            grid[r][c] = padded[idx]
            idx += 1
    return grid


# ── Substitution ciphers ──────────────────────────────────────────────────

def vig_decrypt(ct: str, key: str) -> str:
    """Vigenere decryption: PT = (CT - KEY) mod 26"""
    pt = []
    klen = len(key)
    for i, c in enumerate(ct):
        if c in ALPH_IDX:
            ct_val = ALPH_IDX[c]
            k_val = ALPH_IDX[key[i % klen]]
            pt.append(ALPH[(ct_val - k_val) % MOD])
        else:
            pt.append(c)
    return ''.join(pt)


def beau_decrypt(ct: str, key: str) -> str:
    """Beaufort decryption: PT = (KEY - CT) mod 26"""
    pt = []
    klen = len(key)
    for i, c in enumerate(ct):
        if c in ALPH_IDX:
            ct_val = ALPH_IDX[c]
            k_val = ALPH_IDX[key[i % klen]]
            pt.append(ALPH[(k_val - ct_val) % MOD])
        else:
            pt.append(c)
    return ''.join(pt)


CIPHER_FUNCS = {
    'vigenere': vig_decrypt,
    'beaufort': beau_decrypt,
}

# Keywords to test
KEYWORDS = [
    'KRYPTOS',
    'PALIMPSEST',
    'ABSCISSA',
    'BERLINCLOCK',
    'EASTNORTHEAST',
    'DESPARATLY',
]


# ── Columnar transposition (for Phase 4 hybrid) ──────────────────────────

def columnar_read(grid: list[list[str]], keyword: str) -> str:
    """Read columns in keyword-alphabetical order."""
    cols = len(grid[0])
    if len(keyword) != cols:
        return ''  # keyword must match column count
    # Get column order from keyword
    order = sorted(range(len(keyword)), key=lambda i: (keyword[i], i))
    result = []
    for c in order:
        for r in range(len(grid)):
            result.append(grid[r][c])
    return ''.join(result)


# ── Scoring helper ────────────────────────────────────────────────────────

@dataclass
class Result:
    phase: str
    score: int
    plaintext: str
    config: str

    def __repr__(self):
        return f"[{self.phase}] score={self.score}/24 | {self.config} | PT={self.plaintext[:40]}..."


def evaluate(pt: str, phase: str, config: str, results: list[Result],
             best: list[int], threshold: int = 0) -> int:
    """Score and track a plaintext candidate. Returns score."""
    # Only score the first 97 chars
    pt97 = pt[:CT_LEN] if len(pt) > CT_LEN else pt
    sc = score_cribs(pt97)
    if sc > best[0]:
        best[0] = sc
        results.append(Result(phase, sc, pt97, config))
    if sc >= 7:  # above noise
        results.append(Result(phase, sc, pt97, config))
    return sc


# ── Phase 1: Padded 97-char grids ────────────────────────────────────────

def phase1(results: list[Result], best: list[int]) -> int:
    """Test standard grid sizes with padding."""
    print("\n=== PHASE 1: Padded 97-char grids ===")
    count = 0

    grid_sizes = [
        (7, 14),   # 98 cells, 1 pad
        (14, 7),   # 98 cells, 1 pad
        (10, 10),  # 100 cells, 3 pad
        (9, 11),   # 99 cells, 2 pad
        (11, 9),   # 99 cells, 2 pad
        (8, 13),   # 104 cells, 7 pad
        (13, 8),   # 104 cells, 7 pad
    ]

    for cols, rows in grid_sizes:
        total = cols * rows
        pad_needed = total - CT_LEN

        for rotation_name in ROTATIONS:
            # --- Order A: decrypt sub first, then undo rotation ---
            for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                for kw in KEYWORDS:
                    # Pad at end
                    for pad_char in ALPH:
                        padded_ct = CT + pad_char * pad_needed
                        decrypted = cipher_fn(padded_ct, kw)
                        pt = undo_rotation(decrypted, cols, rows, rotation_name)
                        count += 1
                        evaluate(pt, "P1-A-end", f"{cols}x{rows} rot={rotation_name} "
                                 f"cipher={cipher_name} key={kw} pad={pad_char}@end",
                                 results, best)

                    # Pad at beginning
                    for pad_char in ALPH:
                        padded_ct = pad_char * pad_needed + CT
                        decrypted = cipher_fn(padded_ct, kw)
                        pt = undo_rotation(decrypted, cols, rows, rotation_name)
                        count += 1
                        evaluate(pt, "P1-A-begin", f"{cols}x{rows} rot={rotation_name} "
                                 f"cipher={cipher_name} key={kw} pad={pad_char}@begin",
                                 results, best)

            # --- Order B: undo rotation first, then decrypt sub ---
            for pad_pos in ['end', 'begin']:
                for pad_char in ALPH:
                    if pad_pos == 'end':
                        padded_ct = CT + pad_char * pad_needed
                    else:
                        padded_ct = pad_char * pad_needed + CT
                    unrotated = undo_rotation(padded_ct, cols, rows, rotation_name)

                    for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                        for kw in KEYWORDS:
                            pt = cipher_fn(unrotated, kw)
                            count += 1
                            evaluate(pt, f"P1-B-{pad_pos}", f"{cols}x{rows} rot={rotation_name} "
                                     f"cipher={cipher_name} key={kw} pad={pad_char}@{pad_pos}",
                                     results, best)

            # --- No substitution (rotation only) ---
            for pad_pos in ['end', 'begin']:
                for pad_char in ALPH:
                    if pad_pos == 'end':
                        padded_ct = CT + pad_char * pad_needed
                    else:
                        padded_ct = pad_char * pad_needed + CT
                    pt = undo_rotation(padded_ct, cols, rows, rotation_name)
                    count += 1
                    evaluate(pt, f"P1-none-{pad_pos}", f"{cols}x{rows} rot={rotation_name} "
                             f"no_sub pad={pad_char}@{pad_pos}",
                             results, best)

    print(f"  Phase 1: {count:,} configs tested, best={best[0]}/24")
    return count


# ── Phase 2: L-insertion (98 = 7 x 14 exact fit) ─────────────────────────

def phase2(results: list[Result], best: list[int]) -> int:
    """Insert L at each position to make 98 chars, test 7x14 and 14x7."""
    print("\n=== PHASE 2: L-insertion (98 = 7x14) ===")
    count = 0

    insert_chars = ['L']  # Primary: L (from "extra L" anomaly)
    # Also test all 26 letters
    insert_chars = list(ALPH)

    grid_sizes_98 = [(7, 14), (14, 7)]

    for insert_ch in insert_chars:
        for insert_pos in range(CT_LEN + 1):  # 0 to 97 inclusive
            ct_ins = CT[:insert_pos] + insert_ch + CT[insert_pos:]
            assert len(ct_ins) == 98, f"Expected 98, got {len(ct_ins)}"

            for cols, rows in grid_sizes_98:
                for rotation_name in ROTATIONS:
                    # Order A: decrypt sub, then undo rotation
                    for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                        for kw in KEYWORDS:
                            decrypted = cipher_fn(ct_ins, kw)
                            pt = undo_rotation(decrypted, cols, rows, rotation_name)
                            count += 1
                            evaluate(pt, "P2-A", f"{cols}x{rows} rot={rotation_name} "
                                     f"ins={insert_ch}@{insert_pos} cipher={cipher_name} key={kw}",
                                     results, best)

                    # Order B: undo rotation, then decrypt sub
                    unrotated = undo_rotation(ct_ins, cols, rows, rotation_name)
                    for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                        for kw in KEYWORDS:
                            pt = cipher_fn(unrotated, kw)
                            count += 1
                            evaluate(pt, "P2-B", f"{cols}x{rows} rot={rotation_name} "
                                     f"ins={insert_ch}@{insert_pos} cipher={cipher_name} key={kw}",
                                     results, best)

                    # No substitution
                    pt = undo_rotation(ct_ins, cols, rows, rotation_name)
                    count += 1
                    evaluate(pt, "P2-none", f"{cols}x{rows} rot={rotation_name} "
                             f"ins={insert_ch}@{insert_pos} no_sub",
                             results, best)

    print(f"  Phase 2: {count:,} configs tested, best={best[0]}/24")
    return count


# ── Phase 3: Write-by-columns, rotate, read-by-rows ──────────────────────

def phase3(results: list[Result], best: list[int]) -> int:
    """Inverse of K3: write CT into grid column-by-column, rotate, read rows."""
    print("\n=== PHASE 3: Column-first writing ===")
    count = 0

    grid_sizes = [
        (7, 14), (14, 7), (10, 10), (9, 11), (11, 9), (8, 13), (13, 8),
    ]

    for cols, rows in grid_sizes:
        total = cols * rows
        pad_needed = total - CT_LEN

        for pad_char in ALPH:
            for pad_pos in ['end', 'begin']:
                if pad_pos == 'end':
                    padded = CT + pad_char * pad_needed
                else:
                    padded = pad_char * pad_needed + CT

                for rotation_name, rot_fn in ROTATIONS.items():
                    # Write by columns, rotate, read by rows
                    col_grid = write_by_columns(padded, cols, rows)
                    rotated_grid = rot_fn(col_grid)
                    intermediate = grid_to_str(rotated_grid)

                    # No substitution
                    count += 1
                    evaluate(intermediate, f"P3-none-{pad_pos}",
                             f"colwrite {cols}x{rows} rot={rotation_name} pad={pad_char}@{pad_pos}",
                             results, best)

                    # With substitution decryption
                    for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                        for kw in KEYWORDS:
                            pt = cipher_fn(intermediate, kw)
                            count += 1
                            evaluate(pt, f"P3-sub-{pad_pos}",
                                     f"colwrite {cols}x{rows} rot={rotation_name} "
                                     f"cipher={cipher_name} key={kw} pad={pad_char}@{pad_pos}",
                                     results, best)

                    # Also: decrypt sub first, THEN column-write + rotate
                    for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                        for kw in KEYWORDS:
                            decrypted = cipher_fn(padded, kw)
                            col_grid2 = write_by_columns(decrypted, cols, rows)
                            rotated_grid2 = rot_fn(col_grid2)
                            pt = grid_to_str(rotated_grid2)
                            count += 1
                            evaluate(pt, f"P3-subfirst-{pad_pos}",
                                     f"sub-then-colwrite {cols}x{rows} rot={rotation_name} "
                                     f"cipher={cipher_name} key={kw} pad={pad_char}@{pad_pos}",
                                     results, best)

    print(f"  Phase 3: {count:,} configs tested, best={best[0]}/24")
    return count


# ── Phase 4: Double rotation + hybrid columnar ───────────────────────────

def phase4(results: list[Result], best: list[int]) -> int:
    """Rotation + columnar transposition hybrid."""
    print("\n=== PHASE 4: Hybrid rotation + columnar ===")
    count = 0

    grid_sizes = [
        (7, 14), (14, 7), (10, 10), (9, 11), (11, 9),
    ]

    columnar_keywords = ['KRYPTOS', 'ABSCISSA', 'PALIMPSEST']

    for cols, rows in grid_sizes:
        total = cols * rows
        pad_needed = total - CT_LEN

        for pad_char in ['X', 'A', 'Z']:
            padded_ct = CT + pad_char * pad_needed

            for rotation_name, rot_fn in ROTATIONS.items():
                # Rotate CT grid, then read in columnar keyword order
                grid = make_grid(padded_ct, cols, rows)
                rotated_grid = rot_fn(grid)

                for col_kw in columnar_keywords:
                    # The rotated grid may have different dimensions
                    rot_cols = len(rotated_grid[0])
                    if len(col_kw) == rot_cols:
                        col_read = columnar_read(rotated_grid, col_kw)

                        # No further sub
                        count += 1
                        evaluate(col_read, "P4-colread",
                                 f"{cols}x{rows} rot={rotation_name} colkey={col_kw} pad={pad_char}",
                                 results, best)

                        # With sub decryption
                        for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                            for kw in KEYWORDS:
                                pt = cipher_fn(col_read, kw)
                                count += 1
                                evaluate(pt, "P4-colread-sub",
                                         f"{cols}x{rows} rot={rotation_name} colkey={col_kw} "
                                         f"cipher={cipher_name} key={kw} pad={pad_char}",
                                         results, best)

                # Also: decrypt sub THEN rotate THEN columnar read
                for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                    for kw in KEYWORDS:
                        decrypted = cipher_fn(padded_ct, kw)
                        grid2 = make_grid(decrypted, cols, rows)
                        rotated_grid2 = rot_fn(grid2)
                        for col_kw in columnar_keywords:
                            rot_cols2 = len(rotated_grid2[0])
                            if len(col_kw) == rot_cols2:
                                col_read2 = columnar_read(rotated_grid2, col_kw)
                                count += 1
                                evaluate(col_read2, "P4-sub-rot-col",
                                         f"{cols}x{rows} rot={rotation_name} cipher={cipher_name} "
                                         f"key={kw} colkey={col_kw} pad={pad_char}",
                                         results, best)

    print(f"  Phase 4: {count:,} configs tested, best={best[0]}/24")
    return count


# ── Phase 5: K3 exact method reproduction ─────────────────────────────────

def phase5(results: list[Result], best: list[int]) -> int:
    """Try K3 exact method: row-write, rotate 90 CW, row-read.
    Also tests applying the method as decryption (inverse rotation).
    Tests various grid widths systematically."""
    print("\n=== PHASE 5: K3 exact method (systematic widths) ===")
    count = 0

    # Test all reasonable widths from 2 to 48
    for cols in range(2, 49):
        rows = -(-CT_LEN // cols)  # ceiling division
        total = cols * rows

        # Also test the transposed grid
        for actual_cols, actual_rows in [(cols, rows), (rows, cols)]:
            actual_total = actual_cols * actual_rows
            if actual_total < CT_LEN:
                continue

            pad_needed = actual_total - CT_LEN

            for pad_char in ['X']:
                padded_ct = CT + pad_char * pad_needed

                for rotation_name in ROTATIONS:
                    # Forward: apply rotation to CT (as if CT = rotated(intermediate))
                    # This means: undo rotation to get intermediate
                    pt_inv = undo_rotation(padded_ct, actual_cols, actual_rows, rotation_name)
                    count += 1
                    evaluate(pt_inv, "P5-inv",
                             f"inv_rot {actual_cols}x{actual_rows} rot={rotation_name} pad=X@end",
                             results, best)

                    # Forward: apply rotation (as if we need to apply it)
                    pt_fwd = apply_rotation(padded_ct, actual_cols, actual_rows, rotation_name)
                    count += 1
                    evaluate(pt_fwd, "P5-fwd",
                             f"fwd_rot {actual_cols}x{actual_rows} rot={rotation_name} pad=X@end",
                             results, best)

                    # With substitution (Order A: sub then undo rot)
                    for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                        for kw in KEYWORDS:
                            dec = cipher_fn(padded_ct, kw)
                            pt_a = undo_rotation(dec, actual_cols, actual_rows, rotation_name)
                            count += 1
                            evaluate(pt_a, "P5-A",
                                     f"{actual_cols}x{actual_rows} rot={rotation_name} "
                                     f"cipher={cipher_name} key={kw}",
                                     results, best)

                    # Order B: undo rot then sub
                    unrot = undo_rotation(padded_ct, actual_cols, actual_rows, rotation_name)
                    for cipher_name, cipher_fn in CIPHER_FUNCS.items():
                        for kw in KEYWORDS:
                            pt_b = cipher_fn(unrot, kw)
                            count += 1
                            evaluate(pt_b, "P5-B",
                                     f"{actual_cols}x{actual_rows} rot={rotation_name} "
                                     f"cipher={cipher_name} key={kw}",
                                     results, best)

    print(f"  Phase 5: {count:,} configs tested, best={best[0]}/24")
    return count


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("E-BESPOKE-10: K3-style Physical Rotation Grid Attack on K4")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Keywords: {KEYWORDS}")
    print(f"Cipher variants: {list(CIPHER_FUNCS.keys())}")
    print(f"Rotations: {list(ROTATIONS.keys())}")
    print(f"Grid sizes (Phase 1): 7x14, 14x7, 10x10, 9x11, 11x9, 8x13, 13x8")
    print(f"Phase 2: L-insertion (98=7x14 exact)")
    t0 = time.time()

    results: list[Result] = []
    best = [0]
    total_configs = 0

    total_configs += phase1(results, best)
    total_configs += phase2(results, best)
    total_configs += phase3(results, best)
    total_configs += phase4(results, best)
    total_configs += phase5(results, best)

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 72)
    print(f"TOTAL: {total_configs:,} configs in {elapsed:.1f}s")
    print(f"BEST SCORE: {best[0]}/24")
    print("=" * 72)

    # Show top results
    above_noise = [r for r in results if r.score >= 7]
    if above_noise:
        above_noise.sort(key=lambda r: -r.score)
        print(f"\nResults above noise floor (>= 7/24): {len(above_noise)}")
        for r in above_noise[:20]:
            print(f"  {r}")
    else:
        print("\nNo results above noise floor (all <= 6/24).")

    # Unique top results by score
    unique_top = sorted(set((r.score, r.phase, r.config) for r in results),
                        key=lambda x: -x[0])[:10]
    print("\nTop 10 unique configs:")
    for sc, phase, cfg in unique_top:
        print(f"  [{phase}] score={sc}/24 | {cfg}")

    # Save to results file
    os.makedirs('results', exist_ok=True)
    out = {
        'experiment': 'E-BESPOKE-10',
        'description': 'K3-style rotation grid attack on K4',
        'total_configs': total_configs,
        'elapsed_s': elapsed,
        'best_score': best[0],
        'above_noise_count': len(above_noise),
        'top_results': [
            {'phase': r.phase, 'score': r.score, 'config': r.config,
             'plaintext': r.plaintext}
            for r in sorted(results, key=lambda r: -r.score)[:50]
        ],
    }
    outpath = 'results/e_bespoke_10_rotation_grid.json'
    with open(outpath, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\nResults written to {outpath}")


if __name__ == '__main__':
    main()
