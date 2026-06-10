"""Transposition primitives (independent reference).

Layer of primitives, each represented as / convertible to an explicit
permutation `perm` of {0..n-1} such that encrypted[i] = plaintext[perm[i]].

Provided here:
- columnar (standard keyed)            — uniqueness-by-rank
- myszkowski (rank-grouped keyed)      — repeated letters share rank
- rail_fence (zigzag, depth N)
- route_spiral (rectangle, padding-skipping; CW/CCW; from each corner)
- route_serpentine (boustrophedon, width N)
"""

import math


def keyword_order(keyword: str) -> list:
    """Return the column read-order induced by `keyword`.

    Example: keyword 'KRYPTOS' -> sorted indices of letters by (letter, idx).
    """
    keyword = keyword.upper()
    pairs = sorted([(ch, i) for i, ch in enumerate(keyword)])
    order = [0] * len(keyword)
    for rank, (_, original_pos) in enumerate(pairs):
        order[rank] = original_pos
    return order  # order[r] = column index to read at rank r


def columnar_encrypt(plaintext: str, keyword: str, pad: str = "X") -> str:
    """Write PT row-by-row into a grid of `len(keyword)` columns, padding
    the last row with `pad`, then read columns in keyword-order."""
    width = len(keyword)
    pt = plaintext.upper()
    n = len(pt)
    rows = math.ceil(n / width)
    padded = pt + (pad * (rows * width - n))
    grid = [padded[r * width:(r + 1) * width] for r in range(rows)]
    order = keyword_order(keyword)
    out = []
    for col in order:
        for r in range(rows):
            out.append(grid[r][col])
    return "".join(out)


def columnar_decrypt(ciphertext: str, keyword: str, original_len: int) -> str:
    """Inverse of columnar_encrypt. Caller must supply original_len so that
    short-column accounting works on non-rectangular sizes."""
    width = len(keyword)
    rows = math.ceil(original_len / width)
    total = rows * width
    short_cols_count = total - original_len  # last `short_cols_count` cols are short by 1
    order = keyword_order(keyword)
    # Build column lengths in *original* column order
    col_len = [rows] * width
    for s in range(short_cols_count):
        # short columns are the rightmost ones in the original grid
        col_len[width - 1 - s] = rows - 1
    # Slice ciphertext into columns in read order
    cols_by_orig = [""] * width
    idx = 0
    for col_orig in order:
        L = col_len[col_orig]
        cols_by_orig[col_orig] = ciphertext[idx:idx + L]
        idx += L
    # Read rows
    out = []
    for r in range(rows):
        for c in range(width):
            if r < col_len[c]:
                out.append(cols_by_orig[c][r])
    return "".join(out)[:original_len]


# ---- helpers: perm-based primitives ----

def apply_perm(text: str, perm: list) -> str:
    """encrypted[i] = text[perm[i]]; perm must be a bijection of [0..n-1]."""
    if len(perm) != len(text):
        raise ValueError(f"perm length {len(perm)} != text length {len(text)}")
    return "".join(text[perm[i]] for i in range(len(text)))


def invert_perm(perm: list) -> list:
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ---- Myszkowski (rank-grouped columnar) ----

def myszkowski_perm(keyword: str, n: int) -> list:
    """Return a permutation `perm` of [0..n-1] such that encrypted[i] =
    plaintext[perm[i]] under Myszkowski transposition of the given keyword
    interpreted as a width.

    Standard semantics:
    - Width = len(keyword).
    - Write plaintext into rows of `width` cols (last row possibly short).
    - Sort *unique* letters of keyword; group columns by letter.
    - For each rank group in sorted-letter order, read its columns *row by
      row, left to right within the group* until exhausted.
    """
    keyword = keyword.upper()
    width = len(keyword)
    rows = math.ceil(n / width)
    # Column lengths (last cells of the last row may be missing)
    total_cells = rows * width
    short = total_cells - n
    col_len = [rows] * width
    for s in range(short):
        col_len[width - 1 - s] = rows - 1
    # Cell -> original index mapping (row-major fill, skipping missing cells)
    cell_to_idx = {}
    idx = 0
    for r in range(rows):
        for c in range(width):
            if r < col_len[c]:
                cell_to_idx[(r, c)] = idx
                idx += 1
    # Rank groups: sorted unique letters
    unique_sorted = sorted(set(keyword))
    rank_groups = [[] for _ in unique_sorted]
    for c, letter in enumerate(keyword):
        rank_groups[unique_sorted.index(letter)].append(c)
    # Read order
    perm = []
    for group in rank_groups:
        # Within a rank group: read row by row, left to right in original column order
        max_rows_in_group = max(col_len[c] for c in group)
        for r in range(max_rows_in_group):
            for c in group:
                if r < col_len[c]:
                    perm.append(cell_to_idx[(r, c)])
    assert len(perm) == n
    assert sorted(perm) == list(range(n))
    return perm


# ---- Rail-fence (zigzag, depth N) ----

def rail_fence_perm(depth: int, n: int) -> list:
    """Encryption: write in zigzag depth `depth`, read off rail by rail."""
    if depth < 2:
        raise ValueError("rail-fence depth must be >= 2")
    rails = [[] for _ in range(depth)]
    row = 0
    step = 1
    for i in range(n):
        rails[row].append(i)
        if row == 0:
            step = 1
        elif row == depth - 1:
            step = -1
        row += step
    perm = []
    for rail in rails:
        perm.extend(rail)
    return perm


# ---- Route-spiral on a rectangle ----

def _spiral_walk(rows: int, cols: int, start_rc, init_drdc, cw: bool):
    """Generic spiral walker; yields cells in spiral order."""
    visited = [[False] * cols for _ in range(rows)]
    r, c = start_rc
    dr, dc = init_drdc
    yielded = 0
    total = rows * cols
    while yielded < total:
        if 0 <= r < rows and 0 <= c < cols and not visited[r][c]:
            visited[r][c] = True
            yielded += 1
            yield (r, c)
            r += dr
            c += dc
        else:
            # back up to last visited
            r -= dr
            c -= dc
            # turn
            if cw:
                dr, dc = dc, -dr
            else:
                dr, dc = -dc, dr
            r += dr
            c += dc


def route_spiral_perm(rows: int, cols: int, n: int, direction: str) -> list:
    """Spiral-read a rows x cols rectangle filled row-major with positions
    [0..n-1]; cells beyond n are skipped.

    direction in {"CW_from_NW", "CW_from_NE", "CW_from_SE", "CW_from_SW",
                  "CCW_from_NW", "CCW_from_NE", "CCW_from_SE", "CCW_from_SW"}
    """
    if rows * cols < n:
        raise ValueError(f"rectangle {rows}x{cols} too small for {n} chars")
    grid = [[None] * cols for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < n:
                grid[r][c] = idx
                idx += 1
    starts = {
        "CW_from_NW":  ((0, 0),         (0, 1)),
        "CW_from_NE":  ((0, cols - 1),  (1, 0)),
        "CW_from_SE":  ((rows - 1, cols - 1), (0, -1)),
        "CW_from_SW":  ((rows - 1, 0),  (-1, 0)),
        "CCW_from_NW": ((0, 0),         (1, 0)),
        "CCW_from_NE": ((0, cols - 1),  (0, -1)),
        "CCW_from_SE": ((rows - 1, cols - 1), (-1, 0)),
        "CCW_from_SW": ((rows - 1, 0),  (0, 1)),
    }
    (start, init) = starts[direction]
    cw = direction.startswith("CW")
    perm = []
    for r, c in _spiral_walk(rows, cols, start, init, cw):
        if grid[r][c] is not None:
            perm.append(grid[r][c])
    if sorted(perm) != list(range(n)):
        raise ValueError(
            f"route_spiral_perm produced non-permutation for {rows}x{cols} {direction}"
        )
    return perm


# ---- Route-serpentine (boustrophedon) ----

def route_serpentine_perm(width: int, n: int) -> list:
    """Write into rows of `width`; read in serpentine order (row 0 L->R,
    row 1 R->L, row 2 L->R, ...). Last row possibly short."""
    rows = math.ceil(n / width)
    perm = []
    idx = 0
    for r in range(rows):
        row_indices = []
        for c in range(width):
            if idx + c < n:
                row_indices.append(idx + c)
        if r % 2 == 1:
            row_indices.reverse()
        perm.extend(row_indices)
        idx += width
    assert sorted(perm) == list(range(n))
    return perm

