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
    rows: int, cols: int, length: int = 97, clockwise: bool = True,
) -> List[int]:
    """Spiral reading from outside in."""
    visited = [[False] * cols for _ in range(rows)]
    dirs = (
        [(0, 1), (1, 0), (0, -1), (-1, 0)]
        if clockwise
        else [(1, 0), (0, 1), (-1, 0), (0, -1)]
    )
    perm: list[int] = []
    r, c, d = 0, 0, 0
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
