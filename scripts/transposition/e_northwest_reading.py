#!/usr/bin/env python3
"""
E-NORTHWEST-READING: Test northwest reading orders on the 28×31 master grid.

Hypothesis: K2's "NORTH" and "WEST" aren't geographic — they're reading
directions for the transposition grid. "North" = upward, "West" = right-to-left.
Various northwest-oriented reading paths on the 28×31 grid (and K4's 4-row
sub-grid) could define the transposition that undoes K4's scrambling.

Reading paths tested:
  1. Bottom-right to top-left (pure NW diagonal)
  2. Right-to-left, bottom-to-top (NW row scan)
  3. Bottom-to-top, right-to-left (NW column scan)
  4. NW serpentine (boustrophedon starting from bottom-right)
  5. NW spiral (inward from bottom-right corner)
  6. Anti-diagonal reads (NW diagonals across the grid)
  7. All of the above on the K4 sub-grid (4 rows: row24-27, cols 0-30)
  8. Reversed versions (SE readings — in case NW means the origin, not direction)

Each reading order generates a permutation. Apply inverse to get the
"un-transposed" CT, then try substitution ciphers.

Cipher: northwest-reading
Family: transposition
Status: active
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT

# --- Config ---
DEFECTOR_NULLS = [0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

K4_GRID_WIDTH = 31
K4_START_COL = 27
K4_ROWS = 4  # row 0 partial (cols 27-30), rows 1-3 full

def extract_ct(null_pos):
    ns = set(null_pos)
    return "".join(c for i, c in enumerate(CT) if i not in ns)

def remap_cribs(null_pos):
    ns = set(null_pos)
    cribs = {}
    new_idx = 0
    for i in range(len(CT)):
        if i not in ns:
            if i in CRIB_DICT:
                cribs[new_idx] = CRIB_DICT[i]
            new_idx += 1
    return cribs

def score(pt, cribs):
    s = sorted(cribs.keys())
    ene_p, bc_p = s[:13], s[13:]
    ene = sum(1 for p in ene_p if p < len(pt) and pt[p] == cribs[p])
    bc = sum(1 for p in bc_p if p < len(pt) and pt[p] == cribs[p])
    return ene + bc, ene, bc

# --- Cipher implementations ---
def vig(ct, key, a):
    return "".join(a[(a.index(c) - a.index(key[i%len(key)])) % 26] for i, c in enumerate(ct))
def beau(ct, key, a):
    return "".join(a[(a.index(key[i%len(key)]) - a.index(c)) % 26] for i, c in enumerate(ct))
def avig(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(c) - a.index(fk[i])) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)
def abeau(ct, key, a):
    pt, fk = [], list(key)
    for i, c in enumerate(ct):
        p = (a.index(fk[i]) - a.index(c)) % 26
        pt.append(a[p]); fk.append(a[p])
    return "".join(pt)

CIPHERS = [
    ("vig_AZ", vig, AZ), ("beau_AZ", beau, AZ),
    ("vig_KA", vig, KA), ("beau_KA", beau, KA),
    ("avig_AZ", avig, AZ), ("abeau_AZ", abeau, AZ),
    ("avig_KA", avig, KA), ("abeau_KA", abeau, KA),
]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
            "COLOPHON", "SHADOW", "INVISIBLE", "NORTHWEST", "NORTH",
            "WEST", "COMPASS", "POSITION", "LAYERTWO", "BERLINCLOCK",
            "NORTHEAST", "EASTNORTHEAST", "POINT"]

# --- Build K4 position grid ---
# K4 on the sculpture: 4 rows in the 31-wide grid
# Row 0 (row 24): cols 27-30 → CT positions 0-3
# Row 1 (row 25): cols 0-30  → CT positions 4-34
# Row 2 (row 26): cols 0-30  → CT positions 35-65
# Row 3 (row 27): cols 0-30  → CT positions 66-96

def build_k4_grid():
    """Returns grid[row][col] = CT position or -1 for empty."""
    grid = []
    for r in range(K4_ROWS):
        row = []
        for c in range(K4_GRID_WIDTH):
            if r == 0:
                if c < K4_START_COL:
                    row.append(-1)
                else:
                    row.append(c - K4_START_COL)
            else:
                pos = 4 + (r - 1) * K4_GRID_WIDTH + c
                row.append(pos if pos < 97 else -1)
        grid.append(row)
    return grid

GRID = build_k4_grid()

def grid_positions(grid):
    """Return all valid (row, col, ct_pos) tuples."""
    positions = []
    for r in range(len(grid)):
        for c in range(len(grid[0])):
            if grid[r][c] >= 0:
                positions.append((r, c, grid[r][c]))
    return positions

# --- Reading order generators ---
# Each returns a list of CT position indices in reading order

def read_normal():
    """Standard left-to-right, top-to-bottom (eastward, southward)."""
    perm = []
    for r in range(K4_ROWS):
        for c in range(K4_GRID_WIDTH):
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_nw_rowscan():
    """Right-to-left, bottom-to-top (NW row scan)."""
    perm = []
    for r in range(K4_ROWS - 1, -1, -1):
        for c in range(K4_GRID_WIDTH - 1, -1, -1):
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_nw_colscan():
    """Bottom-to-top, right-to-left (NW column scan)."""
    perm = []
    for c in range(K4_GRID_WIDTH - 1, -1, -1):
        for r in range(K4_ROWS - 1, -1, -1):
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_se_colscan():
    """Top-to-bottom, left-to-right (SE column scan)."""
    perm = []
    for c in range(K4_GRID_WIDTH):
        for r in range(K4_ROWS):
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_w_rowscan():
    """Right-to-left, top-to-bottom (W rows, S progression)."""
    perm = []
    for r in range(K4_ROWS):
        for c in range(K4_GRID_WIDTH - 1, -1, -1):
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_n_colscan():
    """Left-to-right columns, bottom-to-top (N columns, E progression)."""
    perm = []
    for c in range(K4_GRID_WIDTH):
        for r in range(K4_ROWS - 1, -1, -1):
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_nw_serpentine():
    """Serpentine starting from bottom-right, alternating row direction."""
    perm = []
    for ri, r in enumerate(range(K4_ROWS - 1, -1, -1)):
        cols = range(K4_GRID_WIDTH - 1, -1, -1) if ri % 2 == 0 else range(K4_GRID_WIDTH)
        for c in cols:
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_se_serpentine():
    """Serpentine starting from top-left, alternating row direction."""
    perm = []
    for r in range(K4_ROWS):
        cols = range(K4_GRID_WIDTH) if r % 2 == 0 else range(K4_GRID_WIDTH - 1, -1, -1)
        for c in cols:
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_nw_vert_serpentine():
    """Vertical serpentine from bottom-right, alternating column direction."""
    perm = []
    for ci, c in enumerate(range(K4_GRID_WIDTH - 1, -1, -1)):
        rows = range(K4_ROWS - 1, -1, -1) if ci % 2 == 0 else range(K4_ROWS)
        for r in rows:
            if GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_nw_spiral():
    """Spiral inward from bottom-right corner."""
    rows = K4_ROWS
    cols = K4_GRID_WIDTH
    visited = [[False]*cols for _ in range(rows)]
    # Start bottom-right, go left (west), then up (north), then right, then down
    dirs = [(0, -1), (-1, 0), (0, 1), (1, 0)]  # W, N, E, S
    perm = []
    r, c, d = rows - 1, cols - 1, 0
    for _ in range(rows * cols):
        if GRID[r][c] >= 0:
            perm.append(GRID[r][c])
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

def read_se_spiral():
    """Spiral inward from top-left corner."""
    rows = K4_ROWS
    cols = K4_GRID_WIDTH
    visited = [[False]*cols for _ in range(rows)]
    dirs = [(0, 1), (1, 0), (0, -1), (-1, 0)]  # E, S, W, N
    perm = []
    r, c, d = 0, 0, 0
    for _ in range(rows * cols):
        if GRID[r][c] >= 0:
            perm.append(GRID[r][c])
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

def read_nw_diagonal():
    """Read NW diagonals (anti-diagonals from bottom-right)."""
    rows = K4_ROWS
    cols = K4_GRID_WIDTH
    perm = []
    # Anti-diagonals: r+c = constant, starting from max
    for s in range(rows + cols - 2, -1, -1):
        for r in range(min(s, rows - 1), max(s - cols, -1), -1):
            c = s - r
            if 0 <= c < cols and GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

def read_se_diagonal():
    """Read SE diagonals from top-left."""
    rows = K4_ROWS
    cols = K4_GRID_WIDTH
    perm = []
    for s in range(rows + cols - 1):
        for r in range(max(0, s - cols + 1), min(s + 1, rows)):
            c = s - r
            if 0 <= c < cols and GRID[r][c] >= 0:
                perm.append(GRID[r][c])
    return perm

# --- Also test on arbitrary width grids (not just 31) ---
def build_width_grid(text, width):
    """Arrange text in rows of given width, return grid of indices."""
    rows = -(-len(text) // width)
    grid = []
    for r in range(rows):
        row = []
        for c in range(width):
            idx = r * width + c
            row.append(idx if idx < len(text) else -1)
        grid.append(row)
    return grid, rows

def read_grid_nw_rowscan(grid, rows, width):
    perm = []
    for r in range(rows - 1, -1, -1):
        for c in range(width - 1, -1, -1):
            if grid[r][c] >= 0:
                perm.append(grid[r][c])
    return perm

def read_grid_nw_colscan(grid, rows, width):
    perm = []
    for c in range(width - 1, -1, -1):
        for r in range(rows - 1, -1, -1):
            if grid[r][c] >= 0:
                perm.append(grid[r][c])
    return perm

def read_grid_nw_serpentine(grid, rows, width):
    perm = []
    for ri, r in enumerate(range(rows - 1, -1, -1)):
        cols = range(width - 1, -1, -1) if ri % 2 == 0 else range(width)
        for c in cols:
            if grid[r][c] >= 0:
                perm.append(grid[r][c])
    return perm


def apply_reading_order(text, perm):
    """Given text and a reading order (perm[i] = which position to read i-th),
    produce the un-transposed text. perm is the order chars were written;
    to undo, we invert: result[perm[i]] = text[i]."""
    if len(perm) != len(text):
        return None
    result = [''] * len(text)
    for i, p in enumerate(perm):
        result[p] = text[i]
    return "".join(result)

def apply_reading_gather(text, perm):
    """Gather convention: result[i] = text[perm[i]]."""
    if len(perm) != len(text):
        return None
    return "".join(text[p] for p in perm)


def main():
    print("=" * 70)
    print("NORTHWEST READING ORDERS ON K4 GRID")
    print("=" * 70)

    # All reading orders on the sculpture grid (31-wide)
    READINGS_31 = {
        "normal_SE": read_normal(),
        "NW_rowscan": read_nw_rowscan(),
        "NW_colscan": read_nw_colscan(),
        "SE_colscan": read_se_colscan(),
        "W_rowscan": read_w_rowscan(),
        "N_colscan": read_n_colscan(),
        "NW_serpentine": read_nw_serpentine(),
        "SE_serpentine": read_se_serpentine(),
        "NW_vert_serp": read_nw_vert_serpentine(),
        "NW_spiral": read_nw_spiral(),
        "SE_spiral": read_se_spiral(),
        "NW_diagonal": read_nw_diagonal(),
        "SE_diagonal": read_se_diagonal(),
    }

    results = []
    tested = 0

    for mask_name, null_pos in [("raw97", []), ("defector73", DEFECTOR_NULLS)]:
        ect = extract_ct(null_pos)
        cribs = remap_cribs(null_pos) if null_pos else CRIB_DICT
        ct_len = len(ect)

        print(f"\n--- MASK: {mask_name} (CT={ct_len}) ---")

        # --- Sculpture grid readings (only for raw 97) ---
        if ct_len == 97:
            print("\n[1] Sculpture grid (31-wide) reading orders...")
            for rname, perm in READINGS_31.items():
                if len(perm) != 97:
                    print(f"  {rname}: SKIP (perm len {len(perm)} != 97)")
                    continue
                # Try both scatter and gather
                for convention, apply_fn in [("scatter", apply_reading_order), ("gather", apply_reading_gather)]:
                    transposed = apply_fn(ect, perm)
                    if transposed is None:
                        continue
                    for kw in KEYWORDS:
                        for cn, cf, alpha in CIPHERS:
                            try:
                                pt = cf(transposed, kw, alpha)
                            except:
                                continue
                            tested += 1
                            s, ene, bc = score(pt, cribs)
                            if s >= 6:
                                results.append((s, ene, bc, f"{mask_name} grid31_{rname}_{convention}+{kw}:{cn}"))

        # --- Arbitrary width grids with NW readings ---
        print(f"\n[2] NW readings on width-N grids (N=5..19)...")
        for width in [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 19]:
            grid, rows = build_width_grid(ect, width)

            for rname, read_fn in [
                ("NW_row", lambda g, r, w: read_grid_nw_rowscan(g, r, w)),
                ("NW_col", lambda g, r, w: read_grid_nw_colscan(g, r, w)),
                ("NW_serp", lambda g, r, w: read_grid_nw_serpentine(g, r, w)),
            ]:
                perm = read_fn(grid, rows, width)
                if len(perm) != ct_len:
                    continue
                for convention, apply_fn in [("scatter", apply_reading_order), ("gather", apply_reading_gather)]:
                    transposed = apply_fn(ect, perm)
                    if transposed is None:
                        continue
                    for kw in KEYWORDS:
                        for cn, cf, alpha in CIPHERS:
                            try:
                                pt = cf(transposed, kw, alpha)
                            except:
                                continue
                            tested += 1
                            s, ene, bc = score(pt, cribs)
                            if s >= 6:
                                results.append((s, ene, bc, f"{mask_name} w{width}_{rname}_{convention}+{kw}:{cn}"))

    results.sort(key=lambda x: (-x[0], -x[1]))

    print(f"\nTested: {tested} configs")
    print(f"Scores >= 6: {len(results)}")

    print(f"\n{'='*70}")
    print("TOP 20 RESULTS:")
    print("-" * 70)
    if results:
        for s, ene, bc, desc in results[:20]:
            print(f"  {s:2d}/24 (ene={ene:2d}/13 bc={bc:2d}/11) {desc}")
    else:
        print("  No results >= 6")
    print("=" * 70)

    if results and results[0][0] >= 10:
        print(f"\n*** ABOVE NOISE ({results[0][0]}/24) — INVESTIGATE ***")
    elif results:
        print(f"\nBest: {results[0][0]}/24 — {'marginal' if results[0][0] >= 7 else 'noise floor'}.")
    else:
        print("\nAll noise. NW reading orders don't produce crib matches with tested ciphers.")


if __name__ == "__main__":
    main()
