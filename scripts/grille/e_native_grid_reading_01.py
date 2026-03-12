#!/usr/bin/env python3
"""Test native 28x31 grid reading orders on the 73-char column mask extract.

The grid has an irregular structure:
  - Row 24: only cols 27-30 (4 chars)
  - Rows 25-27: cols 0-8, [kept], 17-30 (23 chars each)
  - Total: 4 + 23×3 = 73

Column-reading gives groups of 3 (cols 0-8, 17-26) or 4 (cols 27-30).
This is an IRREGULAR transposition not captured by standard columnar widths.

Tests periodic sub at all periods 1-26 with Vig/Beau/VBeau on:
  - Column-by-column reading (L→R, T→B and R→L variants)
  - Diagonal reading
  - Serpentine column reading
  - Paired column reading (col 0+30, 1+29, etc.)

Also tests reading the FULL 97-char text in various grid orders,
without null removal, to check if the transposition IS the "second system".

Cipher: native-grid-transposition × periodic sub
Family: grille
Status: active
Keyspace: ~5K configs
"""
import sys
import os
from collections import defaultdict, Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, MOD, CRIB_WORDS, ALPH_IDX


def build_grid_map(keep_col: int) -> list[tuple[int, int, int]]:
    """Returns [(73_pos, row, col), ...] for non-null grid positions."""
    null_cols = set(range(8, 17)) - {keep_col}
    entries = []  # (orig_pos, row, col)

    # Row 24: cols 27-30
    for c in range(27, 31):
        entries.append((c - 27, 24, c))

    # Rows 25-27
    for r in range(25, 28):
        for c in range(31):
            if c not in null_cols:
                entries.append((4 + (r - 25) * 31 + c, r, c))

    entries.sort(key=lambda x: x[0])
    pos73_to_grid = [(i, e[1], e[2]) for i, e in enumerate(entries)]
    return pos73_to_grid


def get_crib_pairs():
    pairs = []
    for orig_start, word in CRIB_WORDS:
        shift = 8 if orig_start == 21 else 16
        for i, ch in enumerate(word):
            pairs.append((orig_start + i - shift, ord(ch) - 65))
    return pairs


def extract_73(ct97, keep_col):
    null_cols = set(range(8, 17)) - {keep_col}
    nulls = set()
    for r_offset, r in enumerate(range(25, 28)):
        for c in null_cols:
            nulls.add(4 + r_offset * 31 + c)
    return ''.join(ct97[i] for i in range(len(ct97)) if i not in nulls)


def make_reading_orders(grid_map: list[tuple[int, int, int]]) -> dict[str, list[int]]:
    """Generate various reading orders for the 73 non-null grid positions.

    Each order is a permutation: reading_order[output_pos] = 73_pos.
    """
    orders = {}

    # Index by (row, col)
    by_row_col = {}
    for pos73, row, col in grid_map:
        by_row_col[(row, col)] = pos73

    # Get all non-null columns in order
    cols_present = sorted(set(col for _, _, col in grid_map))
    rows_present = sorted(set(row for _, row, _ in grid_map))

    # 1. Column-by-column, top to bottom, left to right
    order = []
    for c in cols_present:
        for r in rows_present:
            if (r, c) in by_row_col:
                order.append(by_row_col[(r, c)])
    orders["col_LR_TB"] = order

    # 2. Column-by-column, top to bottom, right to left
    order = []
    for c in reversed(cols_present):
        for r in rows_present:
            if (r, c) in by_row_col:
                order.append(by_row_col[(r, c)])
    orders["col_RL_TB"] = order

    # 3. Column-by-column, bottom to top, left to right
    order = []
    for c in cols_present:
        for r in reversed(rows_present):
            if (r, c) in by_row_col:
                order.append(by_row_col[(r, c)])
    orders["col_LR_BT"] = order

    # 4. Column-by-column, bottom to top, right to left
    order = []
    for c in reversed(cols_present):
        for r in reversed(rows_present):
            if (r, c) in by_row_col:
                order.append(by_row_col[(r, c)])
    orders["col_RL_BT"] = order

    # 5. Serpentine columns (alternate direction per column)
    order = []
    for i, c in enumerate(cols_present):
        rows_in_col = [r for r in rows_present if (r, c) in by_row_col]
        if i % 2 == 1:
            rows_in_col = list(reversed(rows_in_col))
        for r in rows_in_col:
            order.append(by_row_col[(r, c)])
    orders["serpentine_col"] = order

    # 6. Serpentine rows
    order = []
    for i, r in enumerate(rows_present):
        cols_in_row = [c for c in cols_present if (r, c) in by_row_col]
        if i % 2 == 1:
            cols_in_row = list(reversed(cols_in_row))
        for c in cols_in_row:
            order.append(by_row_col[(r, c)])
    orders["serpentine_row"] = order

    # 7. Diagonal reading (top-left to bottom-right diagonals)
    min_diag = min(c - r for _, r, c in grid_map)
    max_diag = max(c - r for _, r, c in grid_map)
    order = []
    for d in range(min_diag, max_diag + 1):
        for r in rows_present:
            c = r + d
            if (r, c) in by_row_col:
                order.append(by_row_col[(r, c)])
    orders["diagonal_TLBR"] = order

    # 8. Anti-diagonal reading
    min_adiag = min(c + r for _, r, c in grid_map)
    max_adiag = max(c + r for _, r, c in grid_map)
    order = []
    for d in range(min_adiag, max_adiag + 1):
        for r in rows_present:
            c = d - r
            if (r, c) in by_row_col:
                order.append(by_row_col[(r, c)])
    orders["diagonal_TRBL"] = order

    # 9. Spiral reading (outside-in, clockwise from top-left)
    # Build a 2D grid and spiral through it
    grid_2d = {}
    for pos73, row, col in grid_map:
        grid_2d[(row, col)] = pos73

    order = []
    visited = set()
    # Direction: right, down, left, up
    dr = [0, 1, 0, -1]
    dc = [1, 0, -1, 0]
    r, c, d = min(rows_present), min(cols_present), 0

    # Start from top-left of non-null area
    for _ in range(73 * 4):  # max iterations
        if (r, c) in grid_2d and (r, c) not in visited:
            order.append(grid_2d[(r, c)])
            visited.add((r, c))
        if len(order) == 73:
            break
        # Try to continue in current direction
        nr, nc = r + dr[d], c + dc[d]
        if (nr, nc) in grid_2d and (nr, nc) not in visited:
            r, c = nr, nc
        else:
            # Turn clockwise
            d = (d + 1) % 4
            nr, nc = r + dr[d], c + dc[d]
            if (nr, nc) in grid_2d and (nr, nc) not in visited:
                r, c = nr, nc
            else:
                break
    if len(order) == 73:
        orders["spiral_CW"] = order

    # 10. Paired columns (cols 0+30, 1+29, etc. — mirror reading)
    paired_cols = []
    left_cols = [c for c in cols_present if c <= 15]
    right_cols = [c for c in cols_present if c >= 17]
    for i in range(max(len(left_cols), len(right_cols))):
        if i < len(left_cols):
            paired_cols.append(left_cols[i])
        if i < len(right_cols):
            paired_cols.append(right_cols[-(i + 1)] if i < len(right_cols) else None)
    order = []
    for c in paired_cols:
        if c is not None:
            for r in rows_present:
                if (r, c) in by_row_col:
                    order.append(by_row_col[(r, c)])
    if len(order) == 73:
        orders["paired_cols"] = order

    # 11. Row-reversed (standard row reading but reversed)
    order = list(reversed(range(73)))
    orders["row_reversed"] = order

    return orders


def check_periodic(ct73: str, reading_order: list[int], crib_pairs: list[tuple[int, int]],
                    period: int, variant: str) -> tuple[int, list]:
    """Check periodic sub consistency after applying reading-order transposition.

    Model: PT → write in reading order → intermediate → periodic sub → CT
    Decryption: read CT in reading order, undo sub, get PT.

    The reading order IS the transposition: intermediate[i] = PT[reading_order[i]]
    CT[i] = sub(intermediate[i], key[i % period])

    Crib at PT position j → find i where reading_order[i] = j → CT[i]
    key[i % period] = (CT[i] - PT[j]) mod 26  [Vig]
    """
    n = len(ct73)
    # Inverse: for each PT position, find its intermediate position
    inv = [0] * n
    for i, j in enumerate(reading_order):
        inv[j] = i

    residue_keys = defaultdict(list)
    for pt_pos, pt_val in crib_pairs:
        int_pos = inv[pt_pos]
        ct_val = ord(ct73[int_pos]) - 65

        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "var_beaufort":
            k = (pt_val - ct_val) % MOD
        residue_keys[int_pos % period].append(k)

    score = 0
    key = [None] * period
    for residue, key_vals in residue_keys.items():
        mc_val, mc_count = Counter(key_vals).most_common(1)[0]
        score += mc_count
        key[residue] = mc_val

    return score, key


def main():
    print("=" * 70)
    print("NATIVE 28×31 GRID READING ORDER TEST")
    print("=" * 70)

    crib_pairs = get_crib_pairs()
    variants = ["vigenere", "beaufort", "var_beaufort"]

    best_score = 0
    best_configs = []
    total = 0

    for keep_col in [8, 12, 16]:  # Test 3 representative column keeps
        ct73 = extract_73(CT, keep_col)
        grid_map = build_grid_map(keep_col)
        reading_orders = make_reading_orders(grid_map)

        print(f"\nKeep col {keep_col}: {len(reading_orders)} reading orders")

        for name, order in reading_orders.items():
            if len(order) != 73:
                print(f"  SKIP {name}: length {len(order)}")
                continue
            if len(set(order)) != 73:
                print(f"  SKIP {name}: not a permutation")
                continue

            for period in range(1, 27):
                for variant in variants:
                    score, key = check_periodic(ct73, order, crib_pairs, period, variant)
                    total += 1

                    if score > best_score:
                        best_score = score
                        best_configs = []
                    if score >= best_score and score >= 12:
                        best_configs.append(
                            (score, f"{name}/{variant}/p{period}/col{keep_col}",
                             key))

    print(f"\n{'='*70}")
    print(f"RESULTS: {total:,} configs tested")
    print(f"Best score: {best_score}/24")
    print(f"{'='*70}")

    if best_configs:
        seen = set()
        for score, desc, key in sorted(best_configs, reverse=True)[:20]:
            if desc not in seen:
                seen.add(desc)
                key_str = ''.join(chr(k + 65) if k is not None else '?'
                                 for k in key) if key else "?"
                print(f"  {score}/24  {desc}  key={key_str}")
    else:
        print("  No configs scored >= 12/24")

    # ── Also test on FULL 97-char text with grid column reading ─────────
    print(f"\n{'='*70}")
    print("FULL 97-CHAR TEXT WITH GRID READING ORDERS")
    print("(No null removal — tests if transposition IS the second system)")
    print(f"{'='*70}")

    # Build reading orders for full 97-char grid
    by_rc_97 = {}
    for r in range(24, 28):
        for c in range(31):
            if r == 24 and c < 27:
                continue  # Row 24 only has cols 27-30
            pos = (r - 24) * 31 + c if r > 24 else c - 27
            # Recompute positions
            if r == 24:
                pos = c - 27  # 0-3
            else:
                pos = 4 + (r - 25) * 31 + c  # 4-96
            by_rc_97[(r, c)] = pos

    # Crib pairs for raw 97
    crib_pairs_97 = []
    for orig_start, word in CRIB_WORDS:
        for i, ch in enumerate(word):
            crib_pairs_97.append((orig_start + i, ord(ch) - 65))

    cols_97 = sorted(set(c for _, c in by_rc_97))
    rows_97 = [24, 25, 26, 27]

    # Column reading
    order_97 = []
    for c in cols_97:
        for r in rows_97:
            if (r, c) in by_rc_97:
                order_97.append(by_rc_97[(r, c)])

    best97 = 0
    for period in range(1, 27):
        for variant in variants:
            n = 97
            inv = [0] * n
            for i, j in enumerate(order_97):
                inv[j] = i

            residue_keys = defaultdict(list)
            for pt_pos, pt_val in crib_pairs_97:
                int_pos = inv[pt_pos]
                ct_val = ord(CT[int_pos]) - 65
                if variant == "vigenere":
                    k = (ct_val - pt_val) % MOD
                elif variant == "beaufort":
                    k = (ct_val + pt_val) % MOD
                elif variant == "var_beaufort":
                    k = (pt_val - ct_val) % MOD
                residue_keys[int_pos % period].append(k)

            score = sum(Counter(v).most_common(1)[0][1] for v in residue_keys.values())
            if score > best97:
                best97 = score
                print(f"  NEW BEST: {score}/24 at p={period}/{variant} (column reading)")

    print(f"  Best on full 97 with column reading: {best97}/24")

    print(f"\n{'='*70}")
    if best_score <= 14:
        print("VERDICT: Native grid reading orders do NOT unlock periodic sub.")
    else:
        print(f"VERDICT: Best {best_score}/24 — check period for significance.")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
