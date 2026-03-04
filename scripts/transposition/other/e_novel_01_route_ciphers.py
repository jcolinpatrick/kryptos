#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Novel Method A: Route Ciphers on Sculpture-Related Grids.

Write CT into grids of various dimensions and read off in non-standard orders:
spiral, diagonal, snake/boustrophedon, column-first. Also try write-one/read-another.
"""
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results', 'novel_methods')
os.makedirs(RESULTS_DIR, exist_ok=True)

best_overall = {"score": 0, "method": "", "text": ""}
all_results = []


def check_candidate(text, method_name):
    global best_overall
    if len(text) < CT_LEN:
        text = text + "A" * (CT_LEN - len(text))
    text = text[:CT_LEN].upper()
    sc = score_cribs(text)
    if sc > best_overall["score"]:
        best_overall = {"score": sc, "method": method_name, "text": text}
    if sc > 2:
        detail = score_cribs_detailed(text)
        all_results.append({"method": method_name, "score": sc,
                           "ene": detail["ene_score"], "bc": detail["bc_score"],
                           "text": text[:50] + "..."})
        print(f"  [ABOVE NOISE] {method_name}: {sc}/24 (ENE={detail['ene_score']}, BC={detail['bc_score']})")
    return sc


def write_grid(text, rows, cols):
    """Write text row-major into a grid, pad with X if needed."""
    padded = text + "X" * (rows * cols - len(text))
    grid = []
    for r in range(rows):
        grid.append(list(padded[r * cols:(r + 1) * cols]))
    return grid


def read_row_major(grid, rows, cols):
    return "".join(grid[r][c] for r in range(rows) for c in range(cols))


def read_col_major(grid, rows, cols):
    return "".join(grid[r][c] for c in range(cols) for r in range(rows))


def read_spiral_cw(grid, rows, cols):
    """Read grid in clockwise spiral from top-left."""
    result = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            result.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            result.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                result.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                result.append(grid[r][left])
            left += 1
    return "".join(result)


def read_spiral_ccw(grid, rows, cols):
    """Read grid in counter-clockwise spiral from top-left."""
    result = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for r in range(top, bottom + 1):
            result.append(grid[r][left])
        left += 1
        if top <= bottom:
            for c in range(left, right + 1):
                result.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                result.append(grid[r][right])
            right -= 1
        for c in range(right, left - 1, -1):
            result.append(grid[top][c])
        top += 1
    return "".join(result)


def read_diagonal(grid, rows, cols):
    """Read grid diagonally (top-left to bottom-right diagonals)."""
    result = []
    for d in range(rows + cols - 1):
        for r in range(max(0, d - cols + 1), min(rows, d + 1)):
            c = d - r
            result.append(grid[r][c])
    return "".join(result)


def read_anti_diagonal(grid, rows, cols):
    """Read grid anti-diagonally (top-right to bottom-left)."""
    result = []
    for d in range(rows + cols - 1):
        for r in range(max(0, d - cols + 1), min(rows, d + 1)):
            c = cols - 1 - (d - r)
            if 0 <= c < cols:
                result.append(grid[r][c])
    return "".join(result)


def read_snake(grid, rows, cols):
    """Read grid in boustrophedon (snake) order."""
    result = []
    for r in range(rows):
        if r % 2 == 0:
            for c in range(cols):
                result.append(grid[r][c])
        else:
            for c in range(cols - 1, -1, -1):
                result.append(grid[r][c])
    return "".join(result)


def read_snake_vertical(grid, rows, cols):
    """Read grid in vertical snake order."""
    result = []
    for c in range(cols):
        if c % 2 == 0:
            for r in range(rows):
                result.append(grid[r][c])
        else:
            for r in range(rows - 1, -1, -1):
                result.append(grid[r][c])
    return "".join(result)


# Grid dimensions to try
GRIDS = [
    (7, 14),   # 7 = KRYPTOS length
    (14, 7),
    (11, 9),   # ~97
    (9, 11),
    (8, 13),   # 104, pad
    (13, 8),   # 104, pad
    (1, 97),   # trivial row
    (97, 1),   # trivial column
    (10, 10),  # round grid, pad
]

READ_METHODS = {
    "row_major": read_row_major,
    "col_major": read_col_major,
    "spiral_cw": read_spiral_cw,
    "spiral_ccw": read_spiral_ccw,
    "diagonal": read_diagonal,
    "anti_diagonal": read_anti_diagonal,
    "snake": read_snake,
    "snake_vertical": read_snake_vertical,
}

print("=" * 60)
print("NOVEL METHOD A: Route Ciphers on Grids")
print("=" * 60)

total_tested = 0

# Strategy 1: Write row-major, read in various orders
# Then try applying simple substitution (Vigenere with CT letters as key)
for rows, cols in GRIDS:
    grid = write_grid(CT, rows, cols)
    for read_name, read_func in READ_METHODS.items():
        reordered = read_func(grid, rows, cols)[:CT_LEN]
        method = f"grid_{rows}x{cols}_write_row_read_{read_name}"
        check_candidate(reordered, method)
        total_tested += 1

        # Also try: the reordered text IS the plaintext (transposition only)
        # AND try: the reordering defines a permutation, apply to CT
        # to get the read order as a transposition decryption

# Strategy 2: Write in one non-standard order, read row-major
# This means: permute CT first, then read linearly
for rows, cols in GRIDS:
    for write_name, write_func in READ_METHODS.items():
        if write_name == "row_major":
            continue
        # Build inverse: where does each position go?
        # Create a template grid, read in write_func order to get position mapping
        template = write_grid(CT, rows, cols)
        order = write_func(template, rows, cols)
        # The order string tells us the read sequence; use it as permutation
        method = f"grid_{rows}x{cols}_write_{write_name}_read_row"
        check_candidate(order[:CT_LEN], method)
        total_tested += 1

# Strategy 3: Write col-major, read in various orders
for rows, cols in GRIDS:
    # Write column-major
    padded = CT + "X" * (rows * cols - len(CT))
    grid = [["X"] * cols for _ in range(rows)]
    idx = 0
    for c in range(cols):
        for r in range(rows):
            if idx < len(padded):
                grid[r][c] = padded[idx]
                idx += 1
    for read_name, read_func in READ_METHODS.items():
        reordered = read_func(grid, rows, cols)[:CT_LEN]
        method = f"grid_{rows}x{cols}_write_col_read_{read_name}"
        check_candidate(reordered, method)
        total_tested += 1

# Strategy 4: Spiral-write, various reads
for rows, cols in GRIDS:
    padded = CT + "X" * (rows * cols - len(CT))
    grid = [["X"] * cols for _ in range(rows)]
    # Write in spiral CW order
    positions = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            positions.append((top, c))
        top += 1
        for r in range(top, bottom + 1):
            positions.append((r, right))
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                positions.append((bottom, c))
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                positions.append((r, left))
            left += 1
    for i, (r, c) in enumerate(positions):
        if i < len(padded):
            grid[r][c] = padded[i]
    for read_name, read_func in READ_METHODS.items():
        reordered = read_func(grid, rows, cols)[:CT_LEN]
        method = f"grid_{rows}x{cols}_write_spiral_read_{read_name}"
        check_candidate(reordered, method)
        total_tested += 1

# Strategy 5: Apply Caesar shifts (0-25) to each reordered text from best grid configs
print(f"\nTesting Caesar shifts on all grid reorderings...")
caesar_tested = 0
for rows, cols in GRIDS:
    grid = write_grid(CT, rows, cols)
    for read_name, read_func in READ_METHODS.items():
        reordered = read_func(grid, rows, cols)[:CT_LEN]
        for shift in range(26):
            shifted = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in reordered)
            method = f"grid_{rows}x{cols}_{read_name}_caesar_{shift}"
            check_candidate(shifted, method)
            caesar_tested += 1
            total_tested += 1

# Strategy 6: Atbash on each reordered text
for rows, cols in GRIDS:
    grid = write_grid(CT, rows, cols)
    for read_name, read_func in READ_METHODS.items():
        reordered = read_func(grid, rows, cols)[:CT_LEN]
        atbash = "".join(chr(155 - ord(c)) for c in reordered)  # 155 = 65 + 90
        method = f"grid_{rows}x{cols}_{read_name}_atbash"
        check_candidate(atbash, method)
        total_tested += 1

print(f"\nTotal route cipher configs tested: {total_tested}")
print(f"Best: {best_overall['method']} -> {best_overall['score']}/24")
if best_overall['score'] > 0:
    print(f"  Text: {best_overall['text'][:60]}...")

# Save results
with open(os.path.join(RESULTS_DIR, "route_ciphers.json"), "w") as f:
    json.dump({
        "method": "route_ciphers_on_grids",
        "total_tested": total_tested,
        "best_score": best_overall["score"],
        "best_method": best_overall["method"],
        "best_text": best_overall["text"],
        "above_noise": all_results,
    }, f, indent=2)

print(f"\nResults saved to results/novel_methods/route_ciphers.json")
