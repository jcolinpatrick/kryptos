#!/usr/bin/env python3
"""E-FRAC-03: Width-9 Non-Columnar Reading Orders.

Tests non-standard reading orders on a 9-wide grid as transposition
mechanisms, combined with periodic substitution.

Reading orders tested:
1. Serpentine (boustrophedon) — alternate rows read L→R and R→L
2. Diagonal — read along diagonals (NW→SE and NE→SW)
3. Spiral — read in a spiral from outside in and inside out
4. Zigzag (rail fence on grid) — follow a zigzag pattern
5. Column-serpentine — read columns top-down, alternating direction

For each reading order, test periodic substitution at periods 2-14
with Vigenère, Beaufort, and Variant Beaufort.

Also tests these reading orders on an 11×9 grid (writing by columns,
reading by various orders) — the "inverse" of the standard model.

Usage: PYTHONPATH=src python3 -u jobs/pending/e_frac_03_w9_reading_orders.py [--workers N]
"""
import argparse
import json
import os
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH_IDX, MOD,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

WIDTH = 9
N_ROWS_FULL = CT_LEN // WIDTH      # 10
REMAINDER = CT_LEN % WIDTH          # 7
# When writing row-by-row into width-9 grid:
# 10 full rows of 9 + 1 partial row of 7
NROWS = N_ROWS_FULL + 1  # 11 rows total (last row has 7 chars)

# Column heights for columnar model
COL_HEIGHTS = [N_ROWS_FULL + 1 if j < REMAINDER else N_ROWS_FULL
               for j in range(WIDTH)]


# ═══════════════════════════════════════════════════════════════════════════
# Reading order generators
# Each returns a permutation: perm[i] = j means CT position i came from
# PT position j (gather convention).
# ═══════════════════════════════════════════════════════════════════════════

def grid_pos(row, col, width=WIDTH):
    """Convert (row, col) to linear position in row-major order."""
    return row * width + col


def is_valid(row, col, nrows=NROWS, width=WIDTH, length=CT_LEN):
    """Check if (row, col) is a valid position in the grid."""
    pos = grid_pos(row, col, width)
    return 0 <= row < nrows and 0 <= col < width and pos < length


def reading_order_to_perm(read_order):
    """Convert a reading order (list of positions) to a gather permutation.

    read_order[i] = the i-th position read from the grid.
    This defines encryption as: CT[i] = PT[read_order[i]] (after sub).
    So perm = read_order (gather convention).
    """
    assert len(read_order) == CT_LEN, f"Expected {CT_LEN} positions, got {len(read_order)}"
    assert len(set(read_order)) == CT_LEN, "Duplicate positions in reading order"
    assert all(0 <= p < CT_LEN for p in read_order), "Out of range position"
    return read_order


def gen_row_major():
    """Standard row-major reading (identity permutation)."""
    return list(range(CT_LEN))


def gen_serpentine():
    """Serpentine/boustrophedon: odd rows read right-to-left."""
    order = []
    for row in range(NROWS):
        row_positions = []
        for col in range(WIDTH):
            pos = grid_pos(row, col)
            if pos < CT_LEN:
                row_positions.append(pos)
        if row % 2 == 1:
            row_positions.reverse()
        order.extend(row_positions)
    return order


def gen_serpentine_start_right():
    """Serpentine starting right-to-left."""
    order = []
    for row in range(NROWS):
        row_positions = []
        for col in range(WIDTH):
            pos = grid_pos(row, col)
            if pos < CT_LEN:
                row_positions.append(pos)
        if row % 2 == 0:
            row_positions.reverse()
        order.extend(row_positions)
    return order


def gen_diagonal_nw_se():
    """Diagonal reading NW→SE."""
    order = []
    visited = set()
    # Diagonals: sum of (row + col) is constant along each diagonal
    for diag_sum in range(NROWS + WIDTH - 1):
        for row in range(NROWS):
            col = diag_sum - row
            if 0 <= col < WIDTH:
                pos = grid_pos(row, col)
                if pos < CT_LEN and pos not in visited:
                    order.append(pos)
                    visited.add(pos)
    return order


def gen_diagonal_ne_sw():
    """Diagonal reading NE→SW."""
    order = []
    visited = set()
    for diag_diff in range(-(WIDTH - 1), NROWS):
        for row in range(NROWS):
            col = row - diag_diff
            if 0 <= col < WIDTH:
                pos = grid_pos(row, col)
                if pos < CT_LEN and pos not in visited:
                    order.append(pos)
                    visited.add(pos)
    return order


def gen_diagonal_zigzag():
    """Alternating diagonal directions (NW→SE then SE→NW)."""
    order = []
    visited = set()
    for diag_sum in range(NROWS + WIDTH - 1):
        diag_positions = []
        for row in range(NROWS):
            col = diag_sum - row
            if 0 <= col < WIDTH:
                pos = grid_pos(row, col)
                if pos < CT_LEN and pos not in visited:
                    diag_positions.append(pos)
                    visited.add(pos)
        if diag_sum % 2 == 1:
            diag_positions.reverse()
        order.extend(diag_positions)
    return order


def gen_spiral_inward():
    """Spiral reading from outside to inside (clockwise)."""
    order = []
    visited = [[False] * WIDTH for _ in range(NROWS)]
    # Direction: right, down, left, up
    dr = [0, 1, 0, -1]
    dc = [1, 0, -1, 0]
    row, col, d = 0, 0, 0

    for _ in range(CT_LEN):
        pos = grid_pos(row, col)
        if pos < CT_LEN:
            order.append(pos)
            visited[row][col] = True
        # Try to continue in current direction
        nr, nc = row + dr[d], col + dc[d]
        if (0 <= nr < NROWS and 0 <= nc < WIDTH and
                not visited[nr][nc] and grid_pos(nr, nc) < CT_LEN):
            row, col = nr, nc
        else:
            # Turn right
            d = (d + 1) % 4
            nr, nc = row + dr[d], col + dc[d]
            if (0 <= nr < NROWS and 0 <= nc < WIDTH and
                    not visited[nr][nc] and grid_pos(nr, nc) < CT_LEN):
                row, col = nr, nc
            else:
                break

    # Handle any missed positions (edge case with partial last row)
    if len(order) < CT_LEN:
        remaining = set(range(CT_LEN)) - set(order)
        order.extend(sorted(remaining))

    return order[:CT_LEN]


def gen_spiral_outward():
    """Spiral reading from inside to outside."""
    inward = gen_spiral_inward()
    return list(reversed(inward))


def gen_column_serpentine():
    """Read columns top→bottom, alternating direction."""
    order = []
    for col in range(WIDTH):
        col_positions = []
        for row in range(COL_HEIGHTS[col]):
            col_positions.append(grid_pos(row, col))
        if col % 2 == 1:
            col_positions.reverse()
        order.extend(col_positions)
    return order


def gen_column_major():
    """Read columns top→bottom, all same direction."""
    order = []
    for col in range(WIDTH):
        for row in range(COL_HEIGHTS[col]):
            order.append(grid_pos(row, col))
    return order


def gen_reverse_row_major():
    """Row-major but bottom to top."""
    order = []
    for row in range(NROWS - 1, -1, -1):
        for col in range(WIDTH):
            pos = grid_pos(row, col)
            if pos < CT_LEN:
                order.append(pos)
    return order


def gen_reverse_column_major():
    """Column-major but right to left."""
    order = []
    for col in range(WIDTH - 1, -1, -1):
        for row in range(COL_HEIGHTS[col]):
            order.append(grid_pos(row, col))
    return order


def gen_knight_move():
    """Knight's move pattern starting from (0,0)."""
    # Knight moves: all 8 L-shaped moves
    moves = [(-2, -1), (-2, 1), (-1, -2), (-1, 2),
             (1, -2), (1, 2), (2, -1), (2, 1)]
    visited = set()
    order = []
    row, col = 0, 0

    # Greedy: always move to the position with fewest onward moves (Warnsdorff)
    for _ in range(CT_LEN):
        pos = grid_pos(row, col)
        if pos < CT_LEN:
            order.append(pos)
            visited.add((row, col))

        # Find next move
        best_moves = []
        for dr, dc in moves:
            nr, nc = row + dr, col + dc
            if (0 <= nr < NROWS and 0 <= nc < WIDTH and
                    (nr, nc) not in visited and grid_pos(nr, nc) < CT_LEN):
                # Count onward moves from (nr, nc)
                count = 0
                for dr2, dc2 in moves:
                    nnr, nnc = nr + dr2, nc + dc2
                    if (0 <= nnr < NROWS and 0 <= nnc < WIDTH and
                            (nnr, nnc) not in visited and
                            grid_pos(nnr, nnc) < CT_LEN):
                        count += 1
                best_moves.append((count, nr, nc))

        if best_moves:
            best_moves.sort()
            _, row, col = best_moves[0]
        else:
            break

    # Fill any remaining positions
    if len(order) < CT_LEN:
        remaining = sorted(set(range(CT_LEN)) - set(order))
        order.extend(remaining)

    return order[:CT_LEN]


# ═══════════════════════════════════════════════════════════════════════════
# Scoring functions
# ═══════════════════════════════════════════════════════════════════════════

def check_periodic_consistency(perm, period, variant, model):
    """Check periodic key consistency. Returns (n_consistent, n_constrained)."""
    residue_groups = defaultdict(list)

    for i, src in enumerate(perm):
        if src in CRIB_SET:
            pt_val = CRIB_PT_NUM[src]
            ct_val = CT_NUM[i]
            if variant == 0:
                k = (ct_val - pt_val) % MOD
            elif variant == 1:
                k = (ct_val + pt_val) % MOD
            else:
                k = (pt_val - ct_val) % MOD

            if model == 0:  # Model A: key at PT position
                residue_groups[src % period].append(k)
            else:           # Model B: key at CT position
                residue_groups[i % period].append(k)

    n_consistent = 0
    for vals in residue_groups.values():
        if vals:
            counts = Counter(vals)
            n_consistent += counts.most_common(1)[0][1]

    n_constrained = sum(len(v) for v in residue_groups.values())
    return n_consistent, n_constrained


def check_bean(perm, variant):
    """Check Bean constraints under Model B."""
    inv_perm = [0] * CT_LEN
    for i, p in enumerate(perm):
        inv_perm[p] = i

    ct_27 = inv_perm[27]
    ct_65 = inv_perm[65]
    pt27 = CRIB_PT_NUM[27]
    pt65 = CRIB_PT_NUM[65]

    if variant == 0:
        k27 = (CT_NUM[ct_27] - pt27) % MOD
        k65 = (CT_NUM[ct_65] - pt65) % MOD
    elif variant == 1:
        k27 = (CT_NUM[ct_27] + pt27) % MOD
        k65 = (CT_NUM[ct_65] + pt65) % MOD
    else:
        k27 = (pt27 - CT_NUM[ct_27]) % MOD
        k65 = (pt65 - CT_NUM[ct_65]) % MOD

    if k27 != k65:
        return False

    for a, b in BEAN_INEQ:
        if a in CRIB_SET and b in CRIB_SET:
            ct_a = inv_perm[a]
            ct_b = inv_perm[b]
            if variant == 0:
                ka = (CT_NUM[ct_a] - CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] - CRIB_PT_NUM[b]) % MOD
            elif variant == 1:
                ka = (CT_NUM[ct_a] + CRIB_PT_NUM[a]) % MOD
                kb = (CT_NUM[ct_b] + CRIB_PT_NUM[b]) % MOD
            else:
                ka = (CRIB_PT_NUM[a] - CT_NUM[ct_a]) % MOD
                kb = (CRIB_PT_NUM[b] - CT_NUM[ct_b]) % MOD
            if ka == kb:
                return False
    return True


def test_reading_order(name, perm, periods=None):
    """Test a single reading order against periodic substitution.

    Returns dict with best scores and details.
    """
    if periods is None:
        periods = list(range(2, 15))

    VARIANT_NAMES = ["vigenere", "beaufort", "variant_beaufort"]
    best = {"score": 0}

    for variant in range(3):
        for model in range(2):
            model_name = "A" if model == 0 else "B"
            for period in periods:
                n_con, n_tot = check_periodic_consistency(
                    perm, period, variant, model)

                if n_con > best["score"]:
                    best = {
                        "name": name,
                        "score": n_con,
                        "constrained": n_tot,
                        "variant": VARIANT_NAMES[variant],
                        "model": model_name,
                        "period": period,
                    }

    # Also check Bean constraints
    bean_results = {}
    for variant in range(3):
        bean_results[VARIANT_NAMES[variant]] = check_bean(perm, variant)
    best["bean"] = bean_results

    return best


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=3)
    args = parser.parse_args()

    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-03: Width-9 Non-Columnar Reading Orders")
    print("=" * 70)
    print()

    # Generate all reading orders
    reading_orders = {
        "row_major": gen_row_major,
        "serpentine_lr": gen_serpentine,
        "serpentine_rl": gen_serpentine_start_right,
        "diagonal_nw_se": gen_diagonal_nw_se,
        "diagonal_ne_sw": gen_diagonal_ne_sw,
        "diagonal_zigzag": gen_diagonal_zigzag,
        "spiral_inward": gen_spiral_inward,
        "spiral_outward": gen_spiral_outward,
        "column_major": gen_column_major,
        "column_serpentine": gen_column_serpentine,
        "reverse_row_major": gen_reverse_row_major,
        "reverse_column_major": gen_reverse_column_major,
        "knight_move": gen_knight_move,
    }

    # Also test all reading orders on the INVERSE grid
    # (write by reading order, read row-major — the "un-transpose" direction)
    inverse_orders = {}
    for name, gen_fn in list(reading_orders.items()):
        perm = gen_fn()
        # Inverse: if orig[i] = j, then inv[j] = i
        inv = [0] * CT_LEN
        for i, p in enumerate(perm):
            inv[p] = i
        inverse_orders[f"inv_{name}"] = inv

    results = []
    all_best = {"score": 0}

    print(f"Testing {len(reading_orders)} reading orders + "
          f"{len(inverse_orders)} inverse orders...")
    print()

    # Test original reading orders
    for name, gen_fn in reading_orders.items():
        perm = gen_fn()
        result = test_reading_order(name, perm)
        results.append(result)
        print(f"  {name:25s}: best={result['score']:2d}/24 "
              f"(p={result.get('period','?')}, {result.get('variant','?')}, "
              f"model {result.get('model','?')}) "
              f"bean_vig={result['bean']['vigenere']}")
        if result["score"] > all_best["score"]:
            all_best = result

    print()

    # Test inverse reading orders
    for name, perm in inverse_orders.items():
        result = test_reading_order(name, perm)
        results.append(result)
        print(f"  {name:25s}: best={result['score']:2d}/24 "
              f"(p={result.get('period','?')}, {result.get('variant','?')}, "
              f"model {result.get('model','?')}) "
              f"bean_vig={result['bean']['vigenere']}")
        if result["score"] > all_best["score"]:
            all_best = result

    # ── Summary ──────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print(f"Total reading orders tested: {len(results)}")
    print(f"Time: {elapsed:.1f}s")
    print()

    # Sort by score
    results.sort(key=lambda r: r["score"], reverse=True)

    print("TOP 10:")
    for i, r in enumerate(results[:10]):
        print(f"  #{i+1}: {r['name']:25s} {r['score']:2d}/24 "
              f"(p={r.get('period','?')}, {r.get('variant','?')}, "
              f"model {r.get('model','?')})")
    print()

    # Noise floor analysis
    print("NOISE FLOOR:")
    print("  Identity permutation at various periods:")
    identity = list(range(CT_LEN))
    for p in [2, 3, 5, 7, 9, 11, 13]:
        for v in range(3):
            for m in range(2):
                n_con, _ = check_periodic_consistency(identity, p, v, m)
                if n_con > 5:
                    vname = ["Vig", "Beau", "VB"][v]
                    mname = "A" if m == 0 else "B"
                    print(f"    p={p}, {vname}, model {mname}: {n_con}/24")

    # Verdict
    best_score = all_best["score"]
    noise_bound = 8  # approximate noise for period <= 7
    if best_score >= 18:
        verdict = "SIGNAL — investigate further"
    elif best_score > noise_bound:
        verdict = f"STORE — best {best_score}/24, above basic noise but not strong signal"
    else:
        verdict = f"NOISE — best {best_score}/24, within expected random range"

    print()
    print(f"BEST OVERALL: {all_best['name']} — {best_score}/24")
    print(f"VERDICT: {verdict}")
    print("=" * 70)

    # Check for underdetermination at high periods
    high_period_max = 0
    for r in results:
        if r.get("period", 0) >= 13:
            high_period_max = max(high_period_max, r["score"])
    if high_period_max >= 15:
        print(f"WARNING: Best score at period >=13 is {high_period_max}/24.")
        print("  This is likely an underdetermination artifact (see CLAUDE.md Key Gotchas).")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-03",
        "description": "Width-9 non-columnar reading orders + periodic substitution",
        "n_orders_tested": len(results),
        "best_overall": all_best,
        "all_results": results,
        "elapsed_seconds": round(elapsed, 1),
        "verdict": verdict,
    }
    path = "results/frac/e_frac_03_w9_reading_orders.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")
    print(f"\nRESULT: best={best_score}/24 configs={len(results)} "
          f"verdict={'SIGNAL' if best_score >= 18 else 'ELIMINATED' if best_score <= noise_bound else 'STORE'}")


if __name__ == "__main__":
    main()
