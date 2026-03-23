#!/usr/bin/env python3
"""
e_modified_polybius_grids.py — "Staff of Ra" hypothesis.

What if the KA Polybius grid needs a small modification before it works?
Every prior test used the standard KA grid. If even one row swap or column
reversal is needed, ALL prior results are invalid for the true grid.

MODIFICATIONS TESTED:
  1. Row swaps (all 15 pairs)
  2. Column swaps (all 10 pairs)
  3. Row reversals (each of 6 rows, all rows, alternating)
  4. Column reversals (each of 5 cols, all cols, alternating)
  5. Reflections (horizontal, vertical, both)
  6. Rotations (90°, 180°, 270° — adapted for non-square)
  7. NDYAHR-derived: swap rows/cols indicated by raised letter positions
  8. K2-coordinate-derived: shift by 38, 57, 6, 77, 8, 44 values
  9. "Column-first" reading (transpose the grid)
  10. Combinations of the above

For EACH modified grid, test:
  A. Bifid at periods 2-50 (decrypt + encrypt) on CT97
  B. Split-coordinate Beaufort with periodic row/col keys (periods 1-7)
  C. Coupling check: does the palette still concentrate in 2 columns?
     Does keystream clustering improve?
"""

import sys
import os
import json
import time
import itertools
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    CONSENSUS_NULL_POSITIONS, KRYPTOS_ALPHABET, ALPH, ALPH_IDX,
    BEAUFORT_KEYSTREAM_AT_CRIBS,
)

GRID_ROWS = 6
GRID_COLS = 5


# ── Grid operations ───────────────────────────────────────────────────────

def alpha_to_grid(alphabet: str) -> list:
    """Convert 26-char alphabet to 6×5 grid (list of lists)."""
    grid = []
    for r in range(GRID_ROWS):
        row = []
        for c in range(GRID_COLS):
            idx = r * GRID_COLS + c
            if idx < len(alphabet):
                row.append(alphabet[idx])
            else:
                row.append(None)
        grid.append(row)
    return grid


def grid_to_alpha(grid: list) -> str:
    """Convert 6×5 grid back to alphabet string."""
    return "".join(
        grid[r][c] for r in range(GRID_ROWS) for c in range(GRID_COLS)
        if grid[r][c] is not None
    )


def grid_to_lookup(grid: list) -> tuple:
    """Build lookup tables from grid."""
    ltr_to_rc = {}
    rc_to_ltr = {}
    for r in range(GRID_ROWS):
        for c in range(GRID_COLS):
            ch = grid[r][c]
            if ch is not None:
                ltr_to_rc[ch] = (r, c)
                rc_to_ltr[(r, c)] = ch
    return ltr_to_rc, rc_to_ltr


def swap_rows(grid, r1, r2):
    """Swap two rows."""
    g = [row[:] for row in grid]
    g[r1], g[r2] = g[r2], g[r1]
    return g


def swap_cols(grid, c1, c2):
    """Swap two columns."""
    g = [row[:] for row in grid]
    for r in range(GRID_ROWS):
        g[r][c1], g[r][c2] = g[r][c2], g[r][c1]
    return g


def reverse_row(grid, r):
    """Reverse a single row."""
    g = [row[:] for row in grid]
    g[r] = g[r][::-1]
    return g


def reverse_all_rows(grid):
    """Reverse every row."""
    g = [row[::-1] for row in grid]
    return g


def reverse_col(grid, c):
    """Reverse a single column."""
    g = [row[:] for row in grid]
    vals = [g[r][c] for r in range(GRID_ROWS)]
    vals.reverse()
    for r in range(GRID_ROWS):
        g[r][c] = vals[r]
    return g


def reverse_all_cols(grid):
    """Reverse every column (flip vertically)."""
    return list(reversed([row[:] for row in grid]))


def transpose_grid(grid):
    """Read column-first: 5 rows × 6 cols → then flatten back to 6×5.
    This changes the letter ordering to column-major."""
    # Read column by column
    alpha = ""
    for c in range(GRID_COLS):
        for r in range(GRID_ROWS):
            if grid[r][c] is not None:
                alpha += grid[r][c]
    return alpha_to_grid(alpha)


def rotate_180(grid):
    """Rotate 180°: reverse all rows then reverse all columns."""
    g = reverse_all_rows(grid)
    g = reverse_all_cols(g)
    return g


def alternating_row_reverse(grid):
    """Reverse every other row (boustrophedon/serpentine reading)."""
    g = [row[:] for row in grid]
    for r in range(GRID_ROWS):
        if r % 2 == 1:
            g[r] = g[r][::-1]
    return g


def shift_rows(grid, n):
    """Cyclically shift rows by n positions."""
    g = [row[:] for row in grid]
    n = n % GRID_ROWS
    return g[n:] + g[:n]


def shift_cols(grid, n):
    """Cyclically shift columns by n positions."""
    g = [row[:] for row in grid]
    n = n % GRID_COLS
    return [[row[(c + n) % GRID_COLS] for c in range(GRID_COLS)] for row in g]


# ── Cipher operations ─────────────────────────────────────────────────────

def bifid_decrypt(ct: str, period: int, ltr_to_rc: dict, rc_to_ltr: dict) -> str:
    """Bifid decryption on any grid."""
    result = []
    for start in range(0, len(ct), period):
        block = ct[start:start + period]
        p = len(block)
        rows = [ltr_to_rc[ch][0] for ch in block]
        cols = [ltr_to_rc[ch][1] for ch in block]
        # CT coords → intermediate
        intermediate = []
        for i in range(p):
            intermediate.append(rows[i])
            intermediate.append(cols[i])
        pt_rows = intermediate[:p]
        pt_cols = intermediate[p:]
        for i in range(p):
            r, c = pt_rows[i] % GRID_ROWS, pt_cols[i] % GRID_COLS
            ch = rc_to_ltr.get((r, c))
            if ch is None:
                # Handle empty cell (row 5, col > 0)
                linear = (r * GRID_COLS + c) % 26
                ch = grid_to_alpha(alpha_to_grid(
                    "".join(rc_to_ltr.get((rr, cc), "")
                            for rr in range(GRID_ROWS) for cc in range(GRID_COLS))))[linear]
            result.append(ch)
    return "".join(result)


def bifid_encrypt(pt: str, period: int, ltr_to_rc: dict, rc_to_ltr: dict) -> str:
    """Bifid encryption on any grid."""
    result = []
    for start in range(0, len(pt), period):
        block = pt[start:start + period]
        p = len(block)
        rows = [ltr_to_rc[ch][0] for ch in block]
        cols = [ltr_to_rc[ch][1] for ch in block]
        intermediate = rows + cols
        for i in range(p):
            r = intermediate[2 * i] % GRID_ROWS
            c = intermediate[2 * i + 1] % GRID_COLS
            ch = rc_to_ltr.get((r, c))
            if ch is None:
                alpha = "".join(rc_to_ltr.get((rr, cc), "")
                                for rr in range(GRID_ROWS) for cc in range(GRID_COLS))
                ch = alpha[(r * GRID_COLS + c) % 26]
            result.append(ch)
    return "".join(result)


def beaufort_1d_decrypt(ct: str, key: str, ltr_to_rc: dict, rc_to_ltr: dict) -> str:
    """Standard 1D Beaufort on the grid's linear ordering."""
    alpha = "".join(rc_to_ltr.get((r, c), "")
                    for r in range(GRID_ROWS) for c in range(GRID_COLS)
                    if rc_to_ltr.get((r, c)) is not None)
    alpha_idx = {ch: i for i, ch in enumerate(alpha)}
    result = []
    for i, ch in enumerate(ct):
        k = key[i % len(key)]
        pt_idx = (alpha_idx[k] - alpha_idx[ch]) % 26
        result.append(alpha[pt_idx])
    return "".join(result)


def score_cribs(candidate: str, crib_dict: dict = None) -> int:
    if crib_dict is None:
        crib_dict = CRIB_DICT
    return sum(1 for pos, ch in crib_dict.items()
               if 0 <= pos < len(candidate) and candidate[pos] == ch)


def palette_in_columns(ltr_to_rc: dict) -> dict:
    """Check how the null palette maps to columns on this grid."""
    palette = "BGIKOWZ"
    cols = [ltr_to_rc[ch][1] for ch in palette]
    col_counts = Counter(cols)
    unique_cols = len(col_counts)
    max_2col = 0
    for c1 in range(GRID_COLS):
        for c2 in range(c1, GRID_COLS):
            count = sum(1 for c in cols if c == c1 or c == c2)
            max_2col = max(max_2col, count)
    return {
        "unique_cols": unique_cols,
        "max_in_2_cols": max_2col,
        "col_distribution": dict(col_counts),
    }


def keystream_row_clustering(ltr_to_rc: dict) -> dict:
    """Measure keystream row clustering on this grid."""
    ks = BEAUFORT_KEYSTREAM_AT_CRIBS
    rows = [ltr_to_rc[ch][0] for ch in ks]
    same_row = sum(1 for i in range(len(rows) - 1) if rows[i] == rows[i + 1])
    row_dist = dict(Counter(rows))
    return {
        "same_row_consecutive": same_row,
        "expected": round(23 / GRID_ROWS, 1),
        "row_distribution": row_dist,
    }


# ── Generate all grid modifications ──────────────────────────────────────

def generate_modifications(base_grid):
    """Generate all small grid modifications."""
    mods = []

    # Identity (baseline)
    mods.append(("identity", base_grid))

    # Row swaps (C(6,2) = 15)
    for r1 in range(GRID_ROWS):
        for r2 in range(r1 + 1, GRID_ROWS):
            mods.append((f"swap_rows_{r1}_{r2}", swap_rows(base_grid, r1, r2)))

    # Column swaps (C(5,2) = 10)
    for c1 in range(GRID_COLS):
        for c2 in range(c1 + 1, GRID_COLS):
            mods.append((f"swap_cols_{c1}_{c2}", swap_cols(base_grid, c1, c2)))

    # Individual row reversals (6)
    for r in range(GRID_ROWS):
        mods.append((f"reverse_row_{r}", reverse_row(base_grid, r)))

    # Individual column reversals (5)
    for c in range(GRID_COLS):
        mods.append((f"reverse_col_{c}", reverse_col(base_grid, c)))

    # Global reflections
    mods.append(("reverse_all_rows", reverse_all_rows(base_grid)))
    mods.append(("reverse_all_cols", reverse_all_cols(base_grid)))
    mods.append(("rotate_180", rotate_180(base_grid)))
    mods.append(("serpentine", alternating_row_reverse(base_grid)))

    # Transpose (column-first reading)
    mods.append(("transpose", transpose_grid(base_grid)))

    # Row shifts (5 non-trivial)
    for n in range(1, GRID_ROWS):
        mods.append((f"shift_rows_{n}", shift_rows(base_grid, n)))

    # Column shifts (4 non-trivial)
    for n in range(1, GRID_COLS):
        mods.append((f"shift_cols_{n}", shift_cols(base_grid, n)))

    # NDYAHR-derived modifications
    # N=(3,4), D=(2,0), Y=(0,2), A=(1,2), H=(2,4), R=(0,1)
    # Interpretation 1: swap rows indicated by row coords
    ndyahr_rows = [3, 2, 0, 1, 2, 0]  # unique: 0,1,2,3
    mods.append(("ndyahr_swap_r0_r3", swap_rows(base_grid, 0, 3)))
    mods.append(("ndyahr_swap_r1_r2", swap_rows(base_grid, 1, 2)))
    g = swap_rows(base_grid, 0, 3)
    g = swap_rows(g, 1, 2)
    mods.append(("ndyahr_swap_r03_r12", g))

    # Interpretation 2: swap cols indicated by col coords
    # cols: 4, 0, 2, 2, 4, 1 → swap col 0↔4, swap col 1↔2
    mods.append(("ndyahr_swap_c0_c4", swap_cols(base_grid, 0, 4)))
    mods.append(("ndyahr_swap_c1_c2", swap_cols(base_grid, 1, 2)))
    g = swap_cols(base_grid, 0, 4)
    g = swap_cols(g, 1, 2)
    mods.append(("ndyahr_swap_c04_c12", g))

    # Interpretation 3: use NDYAHR letter positions as row shift amounts
    # N=13, D=3, Y=24, A=0, H=7, R=17 in AZ
    for shift_val in [13, 3, 24, 0, 7, 17]:
        mods.append((f"ndyahr_rowshift_{shift_val}",
                      shift_rows(base_grid, shift_val % GRID_ROWS)))

    # K2 coordinate-derived
    # 38°57'6.5"N, 77°8'44"W
    for val in [38, 57, 6, 77, 8, 44]:
        mods.append((f"k2_rowshift_{val}", shift_rows(base_grid, val % GRID_ROWS)))
        mods.append((f"k2_colshift_{val}", shift_cols(base_grid, val % GRID_COLS)))

    # "Take back one kadam" — shift by -1 (or equivalently +5 for rows, +4 for cols)
    mods.append(("take_back_one_row", shift_rows(base_grid, -1)))
    mods.append(("take_back_one_col", shift_cols(base_grid, -1)))

    # Double modifications: transpose + reverse
    t = transpose_grid(base_grid)
    mods.append(("transpose_then_serpentine", alternating_row_reverse(t)))
    mods.append(("transpose_then_reverse_all_rows", reverse_all_rows(t)))

    return mods


# ── Main experiment ───────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("EXPERIMENT: Modified KA Polybius Grids ('Staff of Ra')")
    print("=" * 70)

    base_grid = alpha_to_grid(KRYPTOS_ALPHABET)
    mods = generate_modifications(base_grid)
    print(f"Grid modifications to test: {len(mods)}")

    # Test periods for Bifid
    bifid_periods = list(range(2, 51))

    # Keywords for 1D Beaufort
    keywords_1d = ["KRYPTOS", "SEVEN", "CHART", "ABSCISSA", "PALIMPSEST",
                    "DEFECTOR", "BERLIN", "ORDINATE"]

    best_overall = {"score": 0}
    best_coupling = {"palette_2col": 0, "row_cluster": 0}
    results_above_threshold = []
    coupling_improvements = []
    total_configs = 0

    t0 = time.time()

    for mod_name, mod_grid in mods:
        ltr_to_rc, rc_to_ltr = grid_to_lookup(mod_grid)

        # Check if all 26 letters are present
        if len(ltr_to_rc) != 26:
            continue

        # ── Coupling check first (fast) ──────────────────────────────
        pal = palette_in_columns(ltr_to_rc)
        ks_clust = keystream_row_clustering(ltr_to_rc)

        if pal["max_in_2_cols"] == 7:  # All palette in 2 cols
            coupling_improvements.append({
                "mod": mod_name,
                "palette_cols": pal["col_distribution"],
                "row_clustering": ks_clust["same_row_consecutive"],
                "row_expected": ks_clust["expected"],
            })

        # ── Bifid at key periods ─────────────────────────────────────
        for period in bifid_periods:
            for direction in ["decrypt", "encrypt"]:
                try:
                    if direction == "decrypt":
                        candidate = bifid_decrypt(CT, period, ltr_to_rc, rc_to_ltr)
                    else:
                        candidate = bifid_encrypt(CT, period, ltr_to_rc, rc_to_ltr)
                    score = score_cribs(candidate)
                except Exception:
                    score = 0
                total_configs += 1

                if score > best_overall.get("score", 0):
                    best_overall = {
                        "score": score, "mod": mod_name,
                        "period": period, "direction": direction,
                        "cipher": "bifid",
                    }
                if score >= 6:
                    results_above_threshold.append({
                        "score": score, "mod": mod_name,
                        "period": period, "direction": direction,
                        "cipher": "bifid",
                    })

        # ── 1D Beaufort with keywords on modified alphabet ───────────
        for kw in keywords_1d:
            try:
                candidate = beaufort_1d_decrypt(CT, kw, ltr_to_rc, rc_to_ltr)
                score = score_cribs(candidate)
            except Exception:
                score = 0
            total_configs += 1

            if score > best_overall.get("score", 0):
                best_overall = {
                    "score": score, "mod": mod_name,
                    "keyword": kw, "cipher": "beaufort_1d",
                }
            if score >= 6:
                results_above_threshold.append({
                    "score": score, "mod": mod_name,
                    "keyword": kw, "cipher": "beaufort_1d",
                })

    elapsed = time.time() - t0

    # ── Output ────────────────────────────────────────────────────────
    print(f"\nTotal configs tested: {total_configs}")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"\nBest overall: {best_overall}")
    print(f"Scores >= 6: {len(results_above_threshold)}")

    if results_above_threshold:
        print("\nAll scores >= 6:")
        for r in sorted(results_above_threshold, key=lambda x: -x["score"])[:20]:
            print(f"  {r['score']}/24 — {r}")

    print(f"\nGrid mods where palette concentrates in 2 columns: {len(coupling_improvements)}")
    if coupling_improvements:
        # Sort by row clustering (higher = better coupling)
        coupling_improvements.sort(key=lambda x: -x["row_clustering"])
        print("Top 10 by row clustering:")
        for c in coupling_improvements[:10]:
            print(f"  {c['mod']}: palette_cols={c['palette_cols']}, "
                  f"row_cluster={c['row_clustering']}/23 (expected {c['row_expected']})")

    # Check identity baseline
    base_ltr, base_rc = grid_to_lookup(base_grid)
    base_pal = palette_in_columns(base_ltr)
    base_clust = keystream_row_clustering(base_ltr)
    print(f"\nBaseline (identity): palette_2col={base_pal['max_in_2_cols']}, "
          f"row_cluster={base_clust['same_row_consecutive']}/23")

    results = {
        "experiment": "e_modified_polybius_grids",
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "total_mods": len(mods),
        "total_configs": total_configs,
        "elapsed_seconds": round(elapsed, 1),
        "best_overall": best_overall,
        "scores_above_6": results_above_threshold,
        "coupling_improvements": coupling_improvements,
        "verdict": (
            "BREAKTHROUGH" if best_overall["score"] >= 24 else
            "SIGNAL" if best_overall["score"] >= 18 else
            "INTERESTING" if best_overall["score"] >= 10 else
            "NOISE"
        ),
    }

    out_path = os.path.join(_ROOT, "results", "e_modified_polybius_grids.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults: {out_path}")
    print(f"Verdict: {results['verdict']}")


if __name__ == "__main__":
    main()
