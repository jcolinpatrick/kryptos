#!/usr/bin/env python3
"""Cylindrical/geometric reading orders for K4 on the 28×31 grid.

Cipher: Vigenere/Beaufort + geometric transposition
Family: grille
Status: active
Keyspace: ~2000 reading patterns × 20 keywords × 3 variants
Last run: never
Best score: n/a

Motivation: The Code Room (1990) shows the Kryptos Vigenere tableau wrapped
into a cylinder lit from inside. The projection onto the floor creates
concentric rings of text — a completely different reading order from flat rows.
Sanborn said he used "matrix codes" and "double matrixes." The half-high
Code Room cylinder may correspond to the K3+K4 half of the 28×31 grid.

If K4's ciphertext was written onto a 31-wide grid and read off cylindrically
(helically, diagonally, spirally, etc.), the "scrambled" carved text is
what you get from the normal left-to-right reading, while the "real" CT
follows a geometric path on the cylinder.

Grid layout (bottom half, 14 rows × 31 cols):
  K3: rows 0-10 (cols 0-25 of row 10)
  ?: row 10, col 26
  K4: row 10 cols 27-30, rows 11-13 full
  K4 grid positions:
    (10,27)=O (10,28)=B (10,29)=K (10,30)=R
    (11,0-30)=UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO
    (12,0-30)=TWTQSJQSSEKZZWATJKLUDIAWINFBNYP
    (13,0-30)=VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR
"""
from __future__ import annotations

import sys
import os
import math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast

# ── Grid constants ──────────────────────────────────────────────────────
GRID_WIDTH = 31
# K4 on the bottom-half grid (14 rows × 31 cols)
# K4 starts at row 10, col 27 (0-indexed within bottom half)
# Bottom half rows 0-9 = K3[0:310], row 10 cols 0-25 = K3[310:336], col 26 = ?

K4_GRID_POSITIONS = []  # list of (row, col) for each K4 character
# First 4 chars: row 10, cols 27-30
for c in range(27, 31):
    K4_GRID_POSITIONS.append((10, c))
# Rows 11-13: full rows
for r in range(11, 14):
    for c in range(31):
        K4_GRID_POSITIONS.append((r, c))
assert len(K4_GRID_POSITIONS) == 97

# Verify grid positions produce the CT
K4_ROWS = {
    10: "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # full row 10 (partial K3 + ? + K4 start)
    11: "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
    12: "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
    13: "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
}
ct_check = ""
for r, c in K4_GRID_POSITIONS:
    ct_check += K4_ROWS[r][c]
assert ct_check == CT, f"Grid position check failed: {ct_check}"

# Priority keywords
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
    "DEFECTOR", "PARALLAX", "COLOPHON", "SHADOW",
    "OMBRE", "POINT", "FILTER", "DECODE",
    "URANIA", "QUARTZ", "LODESTONE", "MAGNETIC",
    "BERLIN", "CLOCK",
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


def apply_reading_order(reading_order: list[int]) -> str:
    """Given a reading order (list of K4 linear indices 0-96),
    produce the 'unscrambled' ciphertext by reading K4 in that order.

    reading_order[i] = which K4 position to read at step i.
    The output is the sequence of CT characters in reading order.
    """
    assert len(reading_order) == CT_LEN
    assert len(set(reading_order)) == CT_LEN  # bijection
    return "".join(CT[reading_order[i]] for i in range(CT_LEN))


def grid_to_linear(row: int, col: int) -> int | None:
    """Convert grid (row, col) to K4 linear index (0-96), or None if not K4."""
    for i, (r, c) in enumerate(K4_GRID_POSITIONS):
        if r == row and c == col:
            return i
    return None


def make_grid_index() -> dict[tuple[int, int], int]:
    """Map (row, col) -> K4 linear index."""
    return {(r, c): i for i, (r, c) in enumerate(K4_GRID_POSITIONS)}


def try_decrypt_and_score(unscrambled_ct: str, method_desc: str,
                          results: list, threshold: int = 5):
    """Try all keywords × variants on unscrambled CT, collect hits."""
    for kw in KEYWORDS:
        key_nums = [ALPH_IDX[c] for c in kw]
        for variant in VARIANTS:
            pt = decrypt_text(unscrambled_ct, key_nums, variant)
            score = score_free_fast(pt)
            if score >= threshold:
                results.append((score, pt, kw, variant.value, method_desc))


# ── Reading pattern generators ──────────────────────────────────────────

def gen_column_reads():
    """Read K4 grid positions column by column (top to bottom within each col).
    On a cylinder, this means reading vertical strips around the circumference."""
    gi = make_grid_index()
    k4_rows = [10, 11, 12, 13]

    # Column-first, left-to-right
    for start_col in range(31):
        order = []
        for c in range(31):
            col = (start_col + c) % 31
            for r in k4_rows:
                idx = gi.get((r, col))
                if idx is not None:
                    order.append(idx)
        if len(order) == 97:
            yield order, f"col_read_start{start_col}"

    # Column-first, right-to-left
    for start_col in range(31):
        order = []
        for c in range(31):
            col = (start_col - c) % 31
            for r in k4_rows:
                idx = gi.get((r, col))
                if idx is not None:
                    order.append(idx)
        if len(order) == 97:
            yield order, f"col_read_rev_start{start_col}"


def gen_diagonal_reads():
    """Diagonal reading paths on the cylindrical grid.
    Step (dr, dc) with wrapping on columns."""
    gi = make_grid_index()
    k4_rows = sorted(set(r for r, c in K4_GRID_POSITIONS))
    min_row, max_row = min(k4_rows), max(k4_rows)

    # Try various diagonal steps
    for dc in range(1, 31):  # column step (wrapping)
        for dr in [1, -1]:  # down or up
            for start_col in range(31):
                for start_row in k4_rows:
                    visited = set()
                    order = []
                    r, c = start_row, start_col
                    while len(order) < 97:
                        idx = gi.get((r, c))
                        if idx is not None and idx not in visited:
                            order.append(idx)
                            visited.add(idx)
                        # Step
                        c = (c + dc) % 31
                        r = r + dr
                        if r > max_row:
                            r = min_row
                        elif r < min_row:
                            r = max_row
                        # Detect cycle
                        if (r, c) == (start_row, start_col):
                            break
                    if len(order) == 97:
                        yield order, f"diag_dr{dr}_dc{dc}_r{start_row}_c{start_col}"


def gen_helical_reads():
    """Helical reading: move right by 1 col per step, wrapping around cylinder.
    When you complete a full revolution (31 steps), advance to next row.
    With an offset (shift per revolution), this creates a helix."""
    gi = make_grid_index()
    k4_rows = sorted(set(r for r, c in K4_GRID_POSITIONS))

    for shift in range(0, 31):  # column offset per row change
        for start_col in range(31):
            for row_order_desc, row_seq in [
                ("top_down", k4_rows),
                ("bot_up", list(reversed(k4_rows))),
            ]:
                order = []
                visited = set()
                col = start_col
                for row_idx, r in enumerate(row_seq):
                    adj_col = (col + shift * row_idx) % 31
                    for step in range(31):
                        c = (adj_col + step) % 31
                        idx = gi.get((r, c))
                        if idx is not None and idx not in visited:
                            order.append(idx)
                            visited.add(idx)
                if len(order) == 97:
                    yield order, f"helix_shift{shift}_{row_order_desc}_c{start_col}"


def gen_boustrophedon():
    """Alternating row direction (serpentine) reading."""
    gi = make_grid_index()
    k4_rows = sorted(set(r for r, c in K4_GRID_POSITIONS))

    for start_col in range(31):
        for start_dir in [1, -1]:
            order = []
            visited = set()
            direction = start_dir
            for r in k4_rows:
                if direction == 1:
                    cols = range(31)
                else:
                    cols = range(30, -1, -1)
                for c in cols:
                    idx = gi.get((r, c))
                    if idx is not None and idx not in visited:
                        order.append(idx)
                        visited.add(idx)
                direction *= -1
            if len(order) == 97:
                yield order, f"boustro_dir{start_dir}"
                break  # start_col doesn't matter for simple boustrophedon


def gen_spiral_reads():
    """Spiral from center outward or edges inward, on the K4 grid section."""
    gi = make_grid_index()
    # K4 occupies a roughly 4×31 block (rows 10-13, but row 10 only cols 27-30)
    # For spiral, work with the full rows 11-13 (93 chars) + the 4 chars at row 10

    # Spiral inward on rows 11-13 (3×31 block)
    for direction in ["inward", "outward"]:
        order = []
        visited = set()
        top, bot, left, right = 11, 13, 0, 30
        while top <= bot and left <= right:
            # Top row left to right
            for c in range(left, right + 1):
                idx = gi.get((top, c))
                if idx is not None and idx not in visited:
                    order.append(idx)
                    visited.add(idx)
            top += 1
            # Right column top to bottom
            for r in range(top, bot + 1):
                idx = gi.get((r, right))
                if idx is not None and idx not in visited:
                    order.append(idx)
                    visited.add(idx)
            right -= 1
            # Bottom row right to left
            if top <= bot:
                for c in range(right, left - 1, -1):
                    idx = gi.get((bot, c))
                    if idx is not None and idx not in visited:
                        order.append(idx)
                        visited.add(idx)
                bot -= 1
            # Left column bottom to top
            if left <= right:
                for r in range(bot, top - 1, -1):
                    idx = gi.get((r, left))
                    if idx is not None and idx not in visited:
                        order.append(idx)
                        visited.add(idx)
                left += 1

        # Append the 4 row-10 chars
        for c in range(27, 31):
            idx = gi.get((10, c))
            if idx is not None and idx not in visited:
                order.append(idx)
                visited.add(idx)

        if direction == "outward":
            order = list(reversed(order))

        if len(order) == 97:
            yield order, f"spiral_{direction}"


def gen_reverse_reads():
    """Simple reversal and mirror operations."""
    # Reverse the linear K4 sequence
    yield list(range(96, -1, -1)), "reverse_linear"

    gi = make_grid_index()
    k4_rows = sorted(set(r for r, c in K4_GRID_POSITIONS))

    # Mirror columns (read each row right-to-left)
    order = []
    for r in k4_rows:
        for c in range(30, -1, -1):
            idx = gi.get((r, c))
            if idx is not None:
                order.append(idx)
    if len(order) == 97:
        yield order, "mirror_cols"

    # Mirror rows (read bottom row first)
    order = []
    for r in reversed(k4_rows):
        for c in range(31):
            idx = gi.get((r, c))
            if idx is not None:
                order.append(idx)
    if len(order) == 97:
        yield order, "mirror_rows"

    # Both mirrors
    order = []
    for r in reversed(k4_rows):
        for c in range(30, -1, -1):
            idx = gi.get((r, c))
            if idx is not None:
                order.append(idx)
    if len(order) == 97:
        yield order, "mirror_both"


def gen_concentric_rings():
    """Floor projection pattern: concentric rings outward from cylinder base.
    Bottom row = innermost ring, top row = outermost ring.
    Each ring read clockwise or counterclockwise."""
    gi = make_grid_index()
    k4_rows = sorted(set(r for r, c in K4_GRID_POSITIONS))

    for ring_dir in ["inner_first", "outer_first"]:
        for read_dir in ["cw", "ccw"]:
            row_seq = list(reversed(k4_rows)) if ring_dir == "inner_first" else k4_rows
            order = []
            for r in row_seq:
                if read_dir == "cw":
                    cols = range(31)
                else:
                    cols = range(30, -1, -1)
                for c in cols:
                    idx = gi.get((r, c))
                    if idx is not None:
                        order.append(idx)
            if len(order) == 97:
                yield order, f"rings_{ring_dir}_{read_dir}"


def gen_step_reads():
    """Read every Nth character on the cylinder, wrapping.
    This covers coprime-step patterns on the linear K4 text arranged cylindrically."""
    for step in range(2, 97):
        if math.gcd(step, 97) != 1:
            continue  # Not a full cycle
        order = []
        pos = 0
        for _ in range(97):
            order.append(pos)
            pos = (pos + step) % 97
        yield order, f"step_{step}"


# ── Main ────────────────────────────────────────────────────────────────

def main():
    print("CYLINDRICAL/GEOMETRIC READING ORDER EXPERIMENTS")
    print(f"CT: {CT}")
    print(f"Grid: K4 on 14×31 bottom half, rows 10-13")
    print(f"Keywords: {len(KEYWORDS)}, Variants: 3")
    print()

    all_results = []
    patterns_tested = 0

    generators = [
        ("Column reads", gen_column_reads),
        ("Boustrophedon", gen_boustrophedon),
        ("Spiral reads", gen_spiral_reads),
        ("Reverse/mirror", gen_reverse_reads),
        ("Concentric rings", gen_concentric_rings),
        ("Step reads (coprime)", gen_step_reads),
        ("Helical reads", gen_helical_reads),
        ("Diagonal reads", gen_diagonal_reads),
    ]

    for gen_name, gen_fn in generators:
        print(f"--- {gen_name} ---")
        count = 0
        gen_results = []

        for reading_order, desc in gen_fn():
            unscrambled = apply_reading_order(reading_order)
            try_decrypt_and_score(unscrambled, desc, gen_results)
            count += 1
            patterns_tested += 1

            # Progress for large generators
            if count % 500 == 0:
                print(f"  ... {count} patterns tested")

            # Cap diagonal/helical which can be huge
            if count >= 5000:
                print(f"  (capped at {count} patterns)")
                break

        if gen_results:
            gen_results.sort(key=lambda x: -x[0])
            best = gen_results[0]
            print(f"  {count} patterns, best score: {best[0]}/24")
            print(f"    method: {best[4]}, key: {best[2]} ({best[3]})")
            print(f"    PT: {best[1]}")
            all_results.extend(gen_results)
        else:
            print(f"  {count} patterns, no hits above threshold")

        print()

    # Final summary
    print("=" * 70)
    print(f"TOTAL: {patterns_tested} reading patterns × {len(KEYWORDS)} keywords × 3 variants")
    print(f"Total configs: {patterns_tested * len(KEYWORDS) * 3}")
    print()

    if all_results:
        all_results.sort(key=lambda x: -x[0])
        print(f"TOP 20 RESULTS (score >= 5):")
        for i, (score, pt, kw, var, desc) in enumerate(all_results[:20]):
            print(f"  {i+1:2d}. score={score:2d} key={kw:12s} {var:15s} {desc}")
            print(f"      PT: {pt}")
    else:
        print("No results above threshold.")

    print("\nDONE")


if __name__ == "__main__":
    main()
