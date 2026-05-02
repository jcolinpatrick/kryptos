"""Transposition cipher primitives.

Supports both full-text and block-based transpositions:
- Columnar (standard keyword-ordered)
- Myszkowski (tied columns)
- Rail fence (zigzag)
- Serpentine (boustrophedon)
- Spiral
- Strip reordering
- Partial transposition
- Block-based (24-char blocks for clock-face permutations)

Convention: output[i] = input[perm[i]]
Inverse via invert_perm().
"""
from __future__ import annotations

import math
from collections import defaultdict
from typing import List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════
# Permutation utilities
# ══════════════════════════════════════════════════════════════════════════

def invert_perm(perm: List[int]) -> List[int]:
    """Compute inverse permutation. If perm[i]=j, then inv[j]=i."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def apply_perm(text: str, perm: List[int]) -> str:
    """Apply permutation: output[i] = text[perm[i]]."""
    return "".join(text[p] for p in perm)


def compose_perms(perm1: List[int], perm2: List[int]) -> List[int]:
    """Compose permutations: result[i] = perm1[perm2[i]]."""
    return [perm1[p] for p in perm2]


def validate_perm(perm: List[int], length: Optional[int] = None) -> bool:
    """Check that perm is a valid permutation of [0..n-1]."""
    n = length if length is not None else len(perm)
    return len(perm) == n and set(perm) == set(range(n))


# ══════════════════════════════════════════════════════════════════════════
# Full-text transposition generators
# ══════════════════════════════════════════════════════════════════════════

def keyword_to_order(keyword: str, width: int) -> Optional[Tuple[int, ...]]:
    """Convert keyword to column order. Returns None if keyword too short."""
    kw = keyword[:width].upper()
    if len(kw) < width:
        return None
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return tuple(order)


def columnar_perm(
    width: int,
    col_order: List[int] | Tuple[int, ...],
    length: int = 97,
) -> List[int]:
    """Columnar transposition: fill rows, read by column order.
    Returns perm where output[i] = input[perm[i]].
    """
    cols: dict[int, list[int]] = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm: list[int] = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        perm.extend(cols[col_idx])
    return perm


def myszkowski_perm(keyword: str, length: int = 97) -> List[int]:
    """Myszkowski transposition: tied columns read row-by-row across ties."""
    kw = keyword.upper()
    width = len(kw)
    nrows = math.ceil(length / width)

    unique_sorted = sorted(set(kw))
    letter_rank = {ch: i for i, ch in enumerate(unique_sorted)}
    col_ranks = [letter_rank[ch] for ch in kw]

    rank_to_cols: dict[int, list[int]] = defaultdict(list)
    for col_idx, rank in enumerate(col_ranks):
        rank_to_cols[rank].append(col_idx)

    cols: dict[int, list[int]] = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)

    perm: list[int] = []
    for rank in sorted(rank_to_cols):
        tied_cols = rank_to_cols[rank]
        if len(tied_cols) == 1:
            perm.extend(cols[tied_cols[0]])
        else:
            for row in range(nrows):
                for c in tied_cols:
                    pos = row * width + c
                    if pos < length:
                        perm.append(pos)
    return perm


def rail_fence_perm(length: int, depth: int) -> List[int]:
    """Rail fence (zigzag) transposition permutation."""
    if depth <= 1 or depth >= length:
        return list(range(length))
    rails: list[list[int]] = [[] for _ in range(depth)]
    rail, direction = 0, 1
    for i in range(length):
        rails[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == depth - 1:
            direction = -1
        rail += direction
    perm: list[int] = []
    for r in rails:
        perm.extend(r)
    return perm


def serpentine_perm(
    rows: int, cols: int, length: int = 97, vertical: bool = False,
) -> List[int]:
    """Serpentine (boustrophedon) reading on a grid."""
    perm: list[int] = []
    if not vertical:
        for r in range(rows):
            rng = range(cols) if r % 2 == 0 else range(cols - 1, -1, -1)
            for c in rng:
                pos = r * cols + c
                if pos < length:
                    perm.append(pos)
    else:
        for c in range(cols):
            rng = range(rows) if c % 2 == 0 else range(rows - 1, -1, -1)
            for r in rng:
                pos = r * cols + c
                if pos < length:
                    perm.append(pos)
    return perm


def spiral_perm(
    rows: int,
    cols: int,
    length: int = 97,
    clockwise: bool = True,
    *,
    start_corner: str = "top_left",
) -> List[int]:
    """Spiral reading from outside in.

    ``start_corner`` defaults to the historical repo behavior:
    top-left start, moving right for clockwise spirals and down for
    counter-clockwise spirals.
    """
    visited = [[False] * cols for _ in range(rows)]
    starts = {
        "top_left": (0, 0),
        "top_right": (0, cols - 1),
        "bottom_right": (rows - 1, cols - 1),
        "bottom_left": (rows - 1, 0),
    }
    clockwise_dirs = {
        "top_left": [(0, 1), (1, 0), (0, -1), (-1, 0)],
        "top_right": [(1, 0), (0, -1), (-1, 0), (0, 1)],
        "bottom_right": [(0, -1), (-1, 0), (0, 1), (1, 0)],
        "bottom_left": [(-1, 0), (0, 1), (1, 0), (0, -1)],
    }
    counterclockwise_dirs = {
        "top_left": [(1, 0), (0, 1), (-1, 0), (0, -1)],
        "top_right": [(0, -1), (1, 0), (0, 1), (-1, 0)],
        "bottom_right": [(-1, 0), (0, -1), (1, 0), (0, 1)],
        "bottom_left": [(0, 1), (-1, 0), (0, -1), (1, 0)],
    }
    if start_corner not in starts:
        raise ValueError(
            "start_corner must be one of "
            "{'top_left', 'top_right', 'bottom_right', 'bottom_left'}"
        )
    dirs = (
        clockwise_dirs[start_corner]
        if clockwise
        else counterclockwise_dirs[start_corner]
    )
    perm: list[int] = []
    r, c = starts[start_corner]
    d = 0
    for _ in range(rows * cols):
        pos = r * cols + c
        if pos < length:
            perm.append(pos)
        visited[r][c] = True
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if 0 <= nr < rows and 0 <= nc < cols and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            nr, nc = r + dirs[d][0], c + dirs[d][1]
            if 0 <= nr < rows and 0 <= nc < cols and not visited[nr][nc]:
                r, c = nr, nc
            else:
                break
    return perm


def diagonal_perm(
    rows: int,
    cols: int,
    length: int = 97,
    *,
    axis: str = "main",
    order: str = "forward",
    start_edge: str = "top_then_left",
    cell_order: str = "forward",
) -> List[int]:
    """Diagonal grid-route transposition (LESSON-016 / LESSON-020).

    Reads an ``rows x cols`` grid in diagonal-stripe order and emits
    a permutation in the standard ``output[i] = input[perm[i]]``
    convention. Ragged grids are supported by trimming positions
    >= ``length`` (mirrors ``serpentine_perm`` / ``spiral_perm``).

    Length-preserving and bijective when ``rows * cols >= length``;
    each grid cell maps to a unique input position and every position
    in [0, length) is reached exactly once.

    Parameters:

      ``axis``
        ``"main"``   — main diagonals (NW->SE / down-right). A main
                        diagonal is the set of cells where
                        ``r - c`` is constant. Indexed by
                        ``a = r - c``, ranging from ``-(cols-1)`` to
                        ``rows-1``.
        ``"anti"``   — anti-diagonals (NE->SW / down-left). An
                        anti-diagonal is the set of cells where
                        ``r + c`` is constant. Indexed by
                        ``d = r + c``, ranging from 0 to
                        ``rows + cols - 2``.

      ``order``
        ``"forward"`` — visit diagonals in increasing index order
                        (``a`` ascending for main, ``d`` ascending
                        for anti).
        ``"reverse"`` — visit diagonals in decreasing index order.

      ``start_edge``
        Within each diagonal there are two ends; ``start_edge``
        names which end is read first. The valid values depend on
        ``axis``:

        For ``axis="main"``:
          ``"top_then_left"`` — start at the smallest-row end (the
                                 cell on the top or right edge of
                                 the grid) and traverse down-right
                                 to the largest-row end.
          ``"left_then_top"`` — start at the largest-row end (the
                                 cell on the left or bottom edge)
                                 and traverse up-left to the
                                 smallest-row end.

        For ``axis="anti"``:
          ``"top_then_right"``— start at the smallest-row end (top
                                 or left edge) and traverse
                                 down-left to the largest-row end.
          ``"right_then_top"``— start at the largest-row end
                                 (right or bottom edge) and
                                 traverse up-right to the
                                 smallest-row end.

      ``cell_order``  (LESSON-020)
        Independent within-diagonal ordering applied AFTER the
        ``start_edge`` selection. Decouples the "which-end-starts"
        choice (``start_edge``) from the "which-direction-each-
        diagonal-is-read" choice when callers want both varied
        explicitly. Values:

          ``"forward"`` — preserve the cell order as produced by
                           ``start_edge`` selection. Default.
                           Backward-compatible: every existing
                           caller that omits ``cell_order`` gets
                           identical output to the pre-LESSON-020
                           implementation.
          ``"reverse"`` — reverse each diagonal's cell list AFTER
                           ``start_edge`` selection. Note that for a
                           uniform reversal this is mathematically
                           equivalent to swapping ``start_edge``
                           between its two valid values, but
                           exposing it as an orthogonal parameter
                           lets the HCC enumerate cell-order
                           variants without touching ``start_edge``
                           and lets callers reason about the two
                           dimensions independently.
          ``"alternate"``— alternate forward/reverse by diagonal
                           group index — even-indexed diagonals
                           (after ``order="reverse"`` flip is
                           applied) preserve the ``start_edge``
                           direction; odd-indexed diagonals are
                           reversed. This is a boustrophedon
                           traversal on the diagonal-stripe sequence
                           and is genuinely distinct from any
                           ``start_edge`` setting.

    Raises:
      ValueError: if ``rows`` or ``cols`` < 1, or ``axis`` /
        ``order`` / ``start_edge`` / ``cell_order`` is invalid (the
        valid ``start_edge`` values are constrained by ``axis``).
    """
    if rows < 1 or cols < 1:
        raise ValueError(
            f"diagonal_perm: rows={rows} cols={cols} must be >= 1"
        )
    if axis not in ("main", "anti"):
        raise ValueError(
            f"diagonal_perm: axis must be 'main' or 'anti'; got {axis!r}"
        )
    if order not in ("forward", "reverse"):
        raise ValueError(
            f"diagonal_perm: order must be 'forward' or 'reverse'; "
            f"got {order!r}"
        )
    valid_start_edges = {
        "main": ("top_then_left", "left_then_top"),
        "anti": ("top_then_right", "right_then_top"),
    }
    if start_edge not in valid_start_edges[axis]:
        raise ValueError(
            f"diagonal_perm: start_edge {start_edge!r} not valid "
            f"for axis={axis!r}; valid values: "
            f"{valid_start_edges[axis]}"
        )
    if cell_order not in ("forward", "reverse", "alternate"):
        raise ValueError(
            f"diagonal_perm: cell_order must be 'forward', 'reverse', "
            f"or 'alternate'; got {cell_order!r}"
        )

    diagonals: list[list[tuple[int, int]]] = []
    if axis == "main":
        # diagonal index a = r - c, range -(cols-1) to rows-1.
        for a in range(-(cols - 1), rows):
            cells: list[tuple[int, int]] = []
            r_start = max(0, a)
            r_stop = min(rows, a + cols)
            for r in range(r_start, r_stop):
                c = r - a
                cells.append((r, c))
            # cells now in increasing-r order = "top_then_left".
            if start_edge == "left_then_top":
                cells.reverse()
            diagonals.append(cells)
    else:  # axis == "anti"
        # diagonal index d = r + c, range 0 to rows+cols-2.
        for d in range(0, rows + cols - 1):
            cells = []
            r_start = max(0, d - cols + 1)
            r_stop = min(rows, d + 1)
            for r in range(r_start, r_stop):
                c = d - r
                cells.append((r, c))
            # cells in increasing-r order = "top_then_right".
            if start_edge == "right_then_top":
                cells.reverse()
            diagonals.append(cells)

    if order == "reverse":
        diagonals.reverse()

    # LESSON-020: within-diagonal cell ordering. Applied AFTER
    # start_edge AND order so it composes orthogonally.
    if cell_order == "reverse":
        diagonals = [list(reversed(d)) for d in diagonals]
    elif cell_order == "alternate":
        diagonals = [
            list(reversed(d)) if (i % 2 == 1) else d
            for i, d in enumerate(diagonals)
        ]

    perm: list[int] = []
    for diag in diagonals:
        for r, c in diag:
            pos = r * cols + c
            if pos < length:
                perm.append(pos)
    return perm


# ════════════════════════════════════════════════════════════════════════════
# LESSON-021: canonical width-only diagonal route alias
# ════════════════════════════════════════════════════════════════════════════
#
# Some hand-cipher descriptions specify a diagonal route ONLY by its
# width — "diagonal grid of width N" — without exposing axis,
# start-edge, or within-diagonal cell-order terms. The expanded
# diagonal_perm parameter set (axis × order × start_edge × cell_order)
# enumerates all combinations, but downstream telemetry can lose track
# of WHICH combination is "the" canonical width-only reading. Bench
# clue authors reasonably expect a single deterministic convention to
# exist as its own auditable surface.
#
# LESSON-021 fixes the canonical convention:
#
#   axis        = "anti"
#   order       = "forward"
#   start_edge  = "top_then_right"
#   cell_order  = "forward"
#   rows        = ceil(length / width)
#   cols        = width
#
# This is the natural top-left-to-bottom-right anti-diagonal reading
# of a row-major-filled width-N rectangle: cells are visited in
# strictly increasing (row + col) groups, and within each group cells
# go top-then-right (smallest row first). It is one of the eight
# (axis, order, start_edge) combinations diagonal_perm already
# supports — LESSON-021 does NOT introduce a new kernel mechanism, it
# just NAMES the canonical convention so HCC, dispatcher, and
# downstream telemetry can refer to it directly.
#
# Backward compatibility: pre-LESSON-021 callers that want the same
# permutation can call diagonal_perm directly with the four explicit
# parameters above; they will get the same output.

CANONICAL_DIAGONAL_AXIS: str = "anti"
CANONICAL_DIAGONAL_ORDER: str = "forward"
CANONICAL_DIAGONAL_START_EDGE: str = "top_then_right"
CANONICAL_DIAGONAL_CELL_ORDER: str = "forward"


def canonical_diagonal_perm(
    width: int, length: int = 97,
) -> List[int]:
    """LESSON-021: canonical width-only diagonal route.

    Width-only alias for ``diagonal_perm`` with the canonical
    convention pinned (axis="anti", order="forward",
    start_edge="top_then_right", cell_order="forward"). rows is
    inferred as ceil(length / width); cols is width. Bijective and
    length-preserving for any width >= 1 such that
    ``ceil(length / width) * width >= length`` (always true by
    construction).

    Use this alias when a hand-cipher clue specifies "diagonal grid
    of width N" without supplying axis / start-edge / cell-order
    terms. Use ``diagonal_perm`` directly when those dimensions ARE
    specified by the clue. The two paths produce identical output
    when the explicit parameters match the canonical defaults.

    Raises:
      ValueError: if width < 1 or length < 1.
    """
    if not isinstance(width, int) or width < 1:
        raise ValueError(
            f"canonical_diagonal_perm: width must be int >= 1; "
            f"got {width!r}"
        )
    if length < 1:
        raise ValueError(
            f"canonical_diagonal_perm: length must be >= 1; got {length!r}"
        )
    rows = (length + width - 1) // width
    cols = width
    return diagonal_perm(
        rows, cols, length,
        axis=CANONICAL_DIAGONAL_AXIS,
        order=CANONICAL_DIAGONAL_ORDER,
        start_edge=CANONICAL_DIAGONAL_START_EDGE,
        cell_order=CANONICAL_DIAGONAL_CELL_ORDER,
    )


def strip_perm(width: int, strip_order: List[int], length: int = 97) -> List[int]:
    """Row/strip reordering transposition."""
    perm: list[int] = []
    for target in range(len(strip_order)):
        src = strip_order[target]
        start = src * width
        end = min(start + width, length)
        perm.extend(range(start, end))
    return perm


def partial_perm(
    boundary: int, sub_perm: List[int], length: int = 97,
) -> List[int]:
    """Partial transposition: fixed prefix, permuted suffix."""
    fixed = list(range(boundary))
    moved = [boundary + p for p in sub_perm]
    return fixed + moved


# ══════════════════════════════════════════════════════════════════════════
# Block-based transposition (24-char blocks, for clock-face ciphers)
# ══════════════════════════════════════════════════════════════════════════

BLOCK_SIZE: int = 24

# Mengenlehreuhr bands (physical clock layout)
MENGEN_BANDS: Tuple[Tuple[int, ...], ...] = (
    tuple(range(0, 1)),      # Band A: 1 indicator
    tuple(range(1, 5)),      # Band B: 4 indicators
    tuple(range(5, 9)),      # Band C: 4 indicators
    tuple(range(9, 20)),     # Band D: 11 indicators
    tuple(range(20, 24)),    # Band E: 4 indicators
)


def make_mengen_route(base_route: str, boustro_parity: int = 0) -> List[int]:
    """Build a 24-element route from a named Mengenlehreuhr pattern."""
    if base_route == "identity":
        return list(range(BLOCK_SIZE))
    if base_route == "band_boustro":
        route: list[int] = []
        for i, band in enumerate(MENGEN_BANDS):
            if (i + boustro_parity) % 2 == 1:
                route.extend(reversed(band))
            else:
                route.extend(band)
        return route
    if base_route == "all_forward":
        return [idx for band in MENGEN_BANDS for idx in band]
    if base_route == "all_reversed":
        return [idx for band in MENGEN_BANDS for idx in reversed(band)]
    if base_route == "reverse_bands":
        return [idx for band in reversed(MENGEN_BANDS) for idx in band]
    raise ValueError(f"Unknown base_route: {base_route!r}")


def apply_rotation(route: List[int], r: int) -> List[int]:
    """Cyclic rotation of route by r positions."""
    n = len(route)
    if r == 0:
        return list(route)
    return [route[(j + r) % n] for j in range(n)]


def apply_reflection(route: List[int]) -> List[int]:
    """Reverse (reflect) the route."""
    return list(reversed(route))


def unmask_block_transposition(
    ct: str,
    perm: List[int],
    cycle_boustro: bool = False,
) -> str:
    """Remove block transposition from ciphertext.

    Applies inverse permutation to BLOCK_SIZE-char blocks.
    Remainder passes through unchanged.

    If cycle_boustro is True, odd blocks use the reversed permutation.
    """
    inv = invert_perm(perm)
    inv_rev = invert_perm(list(reversed(perm)))
    out = list(ct)
    blocks = len(ct) // BLOCK_SIZE

    for block in range(blocks):
        base = block * BLOCK_SIZE
        use_inv = inv_rev if (cycle_boustro and block % 2 == 1) else inv
        for j in range(BLOCK_SIZE):
            src = base + use_inv[j]
            if src < len(ct):
                out[base + j] = ct[src]

    return "".join(out)
