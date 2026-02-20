#!/usr/bin/env python3
"""E-FRAC-45: Grid-Based Non-Columnar Reading Orders.

Tests structured reading orders on grids of various widths — primarily width-9
(FRAC mandate) but also widths 6-13 for completeness. These are transpositions
a sculptor working on a grid might use: serpentine (boustrophedon), spiral,
diagonal, and rotational reading orders.

For each grid width W, the CT is written row-by-row into a W-column grid,
then read out using various non-standard reading orders. Each reading order
defines a permutation σ (gather convention: output[i] = input[perm[i]]).

Reading order families:
1. Serpentine (boustrophedon): alternating L-R / R-L across rows
2. Column-major: read columns top-to-bottom (standard columnar is a special case)
3. Spiral inward: clockwise spiral from top-left corner
4. Spiral outward: clockwise spiral from center outward
5. Diagonal: NW-SE diagonal reading
6. Anti-diagonal: NE-SW diagonal reading
7. Snake-column: serpentine but column-wise (alternating top-down / bottom-up)
8. Zigzag-row: zigzag pattern within each row then snake between rows
9. Reverse-row: rows read R-L, columns top-down
10. Reverse-col: rows L-R, columns bottom-up

For each permutation, score at discriminating periods (2-7) with 3 cipher variants
(Vigenère, Beaufort, Variant Beaufort) × 2 models (PT-residue, CT-residue).

Compare to random baseline (E-FRAC-31: max 15/24 from 500K random) and
width-9 columnar baseline (E-FRAC-12: max 14/24 from 362,880 orderings).

This experiment fills the gap in FRAC Priority 2: "Width-9 non-columnar
reading orders (spiral, diagonal, serpentine on 9-wide grid)."
"""
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN  # 97

PERIODS = [2, 3, 4, 5, 6, 7]
VARIANTS = ["vigenere", "beaufort", "variant_beaufort"]
MODELS = ["A", "B"]


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_eq_only(inv_perm):
    for eq_a, eq_b in BEAN_EQ:
        if CT_NUM[inv_perm[eq_a]] != CT_NUM[inv_perm[eq_b]]:
            return False
    return True


def check_bean_full(inv_perm, variant="vigenere"):
    def key_at(pt_pos):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            return (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            return (ct_val + pt_val) % MOD
        else:
            return (pt_val - ct_val) % MOD

    for eq_a, eq_b in BEAN_EQ:
        if key_at(eq_a) != key_at(eq_b):
            return False
    for ineq_a, ineq_b in BEAN_INEQ:
        if key_at(ineq_a) == key_at(ineq_b):
            return False
    return True


def strict_periodic_score(inv_perm, period, variant, model):
    residue_keys = defaultdict(list)
    for pt_pos in sorted(CRIB_SET):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        else:
            k = (pt_val - ct_val) % MOD

        if model == "A":
            residue = pt_pos % period
        else:
            residue = ct_pos % period
        residue_keys[residue].append(k)

    total = 0
    for keys in residue_keys.values():
        if len(keys) == 1:
            total += 1
        else:
            total += Counter(keys).most_common(1)[0][1]
    return total


# ============================================================
# Grid Reading Order Generators
# ============================================================

def grid_dims(width):
    """Return (nrows, ncols, n_full_cols) for a grid of given width.
    N chars in width columns: first n_full_cols have ceil(N/width) rows,
    remaining have floor(N/width) rows.
    """
    nrows_full = math.ceil(N / width)
    nrows_short = N // width
    n_full_cols = N - nrows_short * width  # number of columns with extra row
    return nrows_full, width, n_full_cols


def fill_grid_rowmajor(width):
    """Fill a grid row-by-row with positions 0..N-1.
    Returns grid[row][col] = position in CT, or -1 for empty cells.
    """
    nrows = math.ceil(N / width)
    grid = []
    pos = 0
    for r in range(nrows):
        row = []
        for c in range(width):
            if pos < N:
                row.append(pos)
                pos += 1
            else:
                row.append(-1)
        grid.append(row)
    return grid, nrows


def read_order_from_grid(grid, nrows, ncols, cell_order):
    """Given a grid and an ordering of (row, col) pairs, return the permutation.
    cell_order is a list of (r, c) tuples specifying read order.
    Returns perm such that output[i] = input[perm[i]].
    """
    perm = []
    for r, c in cell_order:
        if 0 <= r < nrows and 0 <= c < ncols:
            val = grid[r][c]
            if val >= 0:
                perm.append(val)
    return perm


def gen_serpentine(width):
    """Boustrophedon: row-by-row but alternating L→R and R→L."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    for r in range(nrows):
        if r % 2 == 0:
            for c in range(width):
                order.append((r, c))
        else:
            for c in range(width - 1, -1, -1):
                order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("serpentine", f"w={width}", perm)]
    return []


def gen_column_major(width):
    """Read column-by-column, top to bottom. (Standard columnar with natural order.)"""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    for c in range(width):
        for r in range(nrows):
            order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("column_major", f"w={width}", perm)]
    return []


def gen_snake_column(width):
    """Serpentine column-wise: columns read alternating top-down / bottom-up."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    for c in range(width):
        if c % 2 == 0:
            for r in range(nrows):
                order.append((r, c))
        else:
            for r in range(nrows - 1, -1, -1):
                order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("snake_column", f"w={width}", perm)]
    return []


def gen_reverse_row(width):
    """Rows read R→L, top to bottom."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    for r in range(nrows):
        for c in range(width - 1, -1, -1):
            order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("reverse_row", f"w={width}", perm)]
    return []


def gen_reverse_col(width):
    """Rows L→R, but bottom row first."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    for r in range(nrows - 1, -1, -1):
        for c in range(width):
            order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("reverse_col", f"w={width}", perm)]
    return []


def gen_reverse_both(width):
    """Rows R→L, bottom row first."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    for r in range(nrows - 1, -1, -1):
        for c in range(width - 1, -1, -1):
            order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("reverse_both", f"w={width}", perm)]
    return []


def gen_spiral_inward(width):
    """Clockwise spiral from top-left corner inward."""
    grid, nrows = fill_grid_rowmajor(width)
    visited = [[False] * width for _ in range(nrows)]
    order = []
    # Directions: right, down, left, up
    dr = [0, 1, 0, -1]
    dc = [1, 0, -1, 0]
    r, c, d = 0, 0, 0
    for _ in range(nrows * width):
        if 0 <= r < nrows and 0 <= c < width and not visited[r][c]:
            order.append((r, c))
            visited[r][c] = True
        # Try to continue in current direction
        nr, nc = r + dr[d], c + dc[d]
        if 0 <= nr < nrows and 0 <= nc < width and not visited[nr][nc]:
            r, c = nr, nc
        else:
            # Turn right
            d = (d + 1) % 4
            nr, nc = r + dr[d], c + dc[d]
            if 0 <= nr < nrows and 0 <= nc < width and not visited[nr][nc]:
                r, c = nr, nc
            else:
                break
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("spiral_inward_cw", f"w={width}", perm)]
    return []


def gen_spiral_inward_ccw(width):
    """Counter-clockwise spiral from top-left corner inward."""
    grid, nrows = fill_grid_rowmajor(width)
    visited = [[False] * width for _ in range(nrows)]
    order = []
    # Directions: down, right, up, left
    dr = [1, 0, -1, 0]
    dc = [0, 1, 0, -1]
    r, c, d = 0, 0, 0
    for _ in range(nrows * width):
        if 0 <= r < nrows and 0 <= c < width and not visited[r][c]:
            order.append((r, c))
            visited[r][c] = True
        nr, nc = r + dr[d], c + dc[d]
        if 0 <= nr < nrows and 0 <= nc < width and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            nr, nc = r + dr[d], c + dc[d]
            if 0 <= nr < nrows and 0 <= nc < width and not visited[nr][nc]:
                r, c = nr, nc
            else:
                break
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("spiral_inward_ccw", f"w={width}", perm)]
    return []


def gen_spiral_outward(width):
    """Clockwise spiral from center outward."""
    grid, nrows = fill_grid_rowmajor(width)
    visited = [[False] * width for _ in range(nrows)]
    order = []
    # Start from center
    cr, cc = nrows // 2, width // 2
    r, c = cr, cc
    dr = [0, 1, 0, -1]
    dc = [1, 0, -1, 0]
    d = 0
    steps = 1
    step_count = 0
    turns = 0
    for _ in range(nrows * width + 10):
        if 0 <= r < nrows and 0 <= c < width and not visited[r][c]:
            order.append((r, c))
            visited[r][c] = True
        step_count += 1
        if step_count >= steps:
            step_count = 0
            d = (d + 1) % 4
            turns += 1
            if turns % 2 == 0:
                steps += 1
        r, c = r + dr[d], c + dc[d]
        if len(order) >= nrows * width:
            break
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("spiral_outward_cw", f"w={width}", perm)]
    return []


def gen_diagonal_nwse(width):
    """Read diagonals NW→SE (top-right to bottom-left sweep)."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    # Each diagonal d has r+c = d, d from 0 to nrows+width-2
    for d in range(nrows + width - 1):
        for r in range(max(0, d - width + 1), min(nrows, d + 1)):
            c = d - r
            order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("diagonal_nwse", f"w={width}", perm)]
    return []


def gen_diagonal_nesw(width):
    """Read diagonals NE→SW (top-left to bottom-right sweep)."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    # Each anti-diagonal d has r - c = d, d from -(width-1) to nrows-1
    for d in range(-(width - 1), nrows):
        for r in range(max(0, d), min(nrows, d + width)):
            c = r - d
            if 0 <= c < width:
                order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("diagonal_nesw", f"w={width}", perm)]
    return []


def gen_serpentine_reversed(width):
    """Boustrophedon starting R→L on first row."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    for r in range(nrows):
        if r % 2 == 0:
            for c in range(width - 1, -1, -1):
                order.append((r, c))
        else:
            for c in range(width):
                order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("serpentine_rev", f"w={width}", perm)]
    return []


def gen_column_major_reversed(width):
    """Read columns right to left, top to bottom."""
    grid, nrows = fill_grid_rowmajor(width)
    order = []
    for c in range(width - 1, -1, -1):
        for r in range(nrows):
            order.append((r, c))
    perm = read_order_from_grid(grid, nrows, width, order)
    if len(perm) == N:
        return [("column_major_rev", f"w={width}", perm)]
    return []


def gen_all_reading_orders(width):
    """Generate all non-columnar reading orders for a given grid width."""
    generators = [
        gen_serpentine,
        gen_serpentine_reversed,
        gen_column_major,
        gen_column_major_reversed,
        gen_snake_column,
        gen_reverse_row,
        gen_reverse_col,
        gen_reverse_both,
        gen_spiral_inward,
        gen_spiral_inward_ccw,
        gen_spiral_outward,
        gen_diagonal_nwse,
        gen_diagonal_nesw,
    ]
    all_perms = []
    for gen in generators:
        try:
            perms = gen(width)
            all_perms.extend(perms)
        except Exception as e:
            print(f"  Warning: {gen.__name__}(w={width}) failed: {e}")
    return all_perms


def score_perm(perm):
    """Score a permutation at all periods/variants/models."""
    inv = invert_perm(perm)
    bean_eq = check_bean_eq_only(inv)

    best_score = 0
    best_config = None
    results = []

    for period in PERIODS:
        for variant in VARIANTS:
            for model in MODELS:
                score = strict_periodic_score(inv, period, variant, model)
                if score > best_score:
                    best_score = score
                    best_config = {
                        "period": period,
                        "variant": variant,
                        "model": model,
                    }
                results.append({
                    "period": period,
                    "variant": variant,
                    "model": model,
                    "score": score,
                })

    bean_full = {}
    if bean_eq:
        for variant in VARIANTS:
            bean_full[variant] = check_bean_full(inv, variant)

    return {
        "best_score": best_score,
        "best_config": best_config,
        "bean_eq": bean_eq,
        "bean_full": bean_full,
        "all_scores": results,
    }


def run_random_baseline(n_samples=50000):
    """Random baseline for comparison."""
    print(f"\n=== Random Baseline ({n_samples:,} samples) ===")
    max_score = 0
    score_counts = Counter()

    for i in range(n_samples):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)
        for period in PERIODS:
            for variant in VARIANTS:
                for model in MODELS:
                    score = strict_periodic_score(inv, period, variant, model)
                    score_counts[score] += 1
                    if score > max_score:
                        max_score = score

    total = sum(score_counts.values())
    print(f"  Max score: {max_score}/24")
    print(f"  Score distribution (top 5):")
    for s, cnt in sorted(score_counts.items(), reverse=True)[:10]:
        print(f"    {s}/24: {cnt:,} ({100*cnt/total:.2f}%)")

    return max_score, dict(score_counts)


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-45: Grid-Based Non-Columnar Reading Orders")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"N = {N}")
    print(f"Periods: {PERIODS}")
    print(f"Variants: {VARIANTS}")
    print(f"Models: {MODELS}")
    print()

    # Widths to test
    widths = [5, 6, 7, 8, 9, 10, 11, 12, 13]

    all_results = {}
    global_max_score = 0
    global_max_config = None
    total_perms = 0
    total_configs = 0

    for width in widths:
        nrows = math.ceil(N / width)
        n_full_cols = N - (N // width) * width
        print(f"\n{'='*60}")
        print(f"Width {width}: {nrows} rows × {width} cols "
              f"({n_full_cols} full cols of {nrows}, "
              f"{width - n_full_cols} short cols of {nrows - 1})")
        print(f"{'='*60}")

        perms = gen_all_reading_orders(width)
        # Filter to unique permutations
        seen = set()
        unique_perms = []
        for family, params, perm in perms:
            perm_tuple = tuple(perm)
            if perm_tuple not in seen and perm_tuple != tuple(range(N)):
                seen.add(perm_tuple)
                unique_perms.append((family, params, perm))

        print(f"  Generated {len(perms)} reading orders, {len(unique_perms)} unique (non-identity)")

        width_results = []
        width_max = 0
        width_max_info = None

        for family, params, perm in unique_perms:
            result = score_perm(perm)
            result["family"] = family
            result["params"] = params
            result["width"] = width
            width_results.append(result)

            if result["best_score"] > width_max:
                width_max = result["best_score"]
                width_max_info = result

            if result["best_score"] > global_max_score:
                global_max_score = result["best_score"]
                global_max_config = result

            total_configs += len(PERIODS) * len(VARIANTS) * len(MODELS)

        total_perms += len(unique_perms)

        # Print width summary
        print(f"  Best score at width {width}: {width_max}/24")
        if width_max_info:
            print(f"    Family: {width_max_info['family']}")
            print(f"    Config: {width_max_info['best_config']}")
            print(f"    Bean eq: {width_max_info['bean_eq']}")
            if width_max_info['bean_full']:
                print(f"    Bean full: {width_max_info['bean_full']}")

        # Show all results sorted by score
        width_results.sort(key=lambda x: -x["best_score"])
        print(f"  All reading orders (sorted by best score):")
        for r in width_results:
            bean_str = "Bean:Y" if r["bean_eq"] else "Bean:N"
            bean_full_str = ""
            if r["bean_full"]:
                passes = [v for v, p in r["bean_full"].items() if p]
                if passes:
                    bean_full_str = f" FullBean:{','.join(p[:3] for p in passes)}"
            print(f"    {r['best_score']:2d}/24  {r['family']:20s}  "
                  f"p={r['best_config']['period']} "
                  f"{r['best_config']['variant'][:3]} "
                  f"mod={r['best_config']['model']}  "
                  f"{bean_str}{bean_full_str}")

        all_results[width] = width_results

    # Random baseline
    random_max, random_dist = run_random_baseline(50000)

    # Per-width random baseline: how likely is the observed max from k trials?
    print(f"\n{'='*60}")
    print("Per-width statistical significance")
    print(f"{'='*60}")
    # Compute P(random score >= observed) from random distribution
    total_random_scores = sum(random_dist.values())
    for width in widths:
        if width not in all_results or not all_results[width]:
            continue
        width_max = max(r["best_score"] for r in all_results[width])
        n_trials = len(all_results[width]) * len(PERIODS) * len(VARIANTS) * len(MODELS)
        # P(single random trial >= width_max)
        p_exceed = sum(v for k, v in random_dist.items() if k >= width_max) / total_random_scores
        # Corrected: P(max of n_trials >= width_max) = 1 - (1-p_exceed)^n_trials
        if p_exceed > 0:
            p_corrected = 1 - (1 - p_exceed) ** n_trials
        else:
            p_corrected = 0.0
        print(f"  Width {width}: max={width_max}/24, "
              f"n_trials={n_trials}, "
              f"p_trial={p_exceed:.6f}, "
              f"p_corrected={p_corrected:.6f}")

    elapsed = time.time() - t0

    # Summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Total reading orders tested: {total_perms}")
    print(f"Total configs scored: {total_configs:,}")
    print(f"Global max score: {global_max_score}/24")
    if global_max_config:
        print(f"  Family: {global_max_config['family']}")
        print(f"  Width: {global_max_config.get('width', '?')}")
        print(f"  Config: {global_max_config['best_config']}")
        print(f"  Bean eq: {global_max_config['bean_eq']}")
        if global_max_config['bean_full']:
            print(f"  Bean full: {global_max_config['bean_full']}")
    print(f"Random baseline max: {random_max}/24")
    print(f"Elapsed: {elapsed:.1f}s")

    # Verdict
    if global_max_score <= random_max:
        print(f"\nVERDICT: NOISE — best grid reading order score ({global_max_score}/24) "
              f"does not exceed random baseline ({random_max}/24)")
    elif global_max_score >= 18:
        print(f"\nVERDICT: SIGNAL — score {global_max_score}/24 warrants investigation")
    else:
        print(f"\nVERDICT: STORE — score {global_max_score}/24 exceeds random baseline "
              f"({random_max}/24) but below SIGNAL threshold")

    print(f"\nRESULT: best={global_max_score}/24 configs={total_configs} "
          f"verdict={'ELIMINATED' if global_max_score <= 14 else 'STORE'}")

    # Save results
    os.makedirs("results/frac", exist_ok=True)
    output = {
        "experiment": "E-FRAC-45",
        "description": "Grid-based non-columnar reading orders",
        "widths_tested": widths,
        "total_reading_orders": total_perms,
        "total_configs": total_configs,
        "global_max_score": global_max_score,
        "global_max_config": global_max_config,
        "random_max": random_max,
        "random_distribution": random_dist,
        "elapsed_seconds": elapsed,
        "per_width": {},
    }
    for width in widths:
        if width in all_results:
            output["per_width"][str(width)] = {
                "n_reading_orders": len(all_results[width]),
                "max_score": max((r["best_score"] for r in all_results[width]), default=0),
                "results": [
                    {
                        "family": r["family"],
                        "params": r["params"],
                        "best_score": r["best_score"],
                        "best_config": r["best_config"],
                        "bean_eq": r["bean_eq"],
                        "bean_full": r["bean_full"],
                    }
                    for r in sorted(all_results[width], key=lambda x: -x["best_score"])
                ],
            }

    outpath = "results/frac/e_frac_45_grid_reading_orders.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nArtifacts: {outpath}")


if __name__ == "__main__":
    main()
