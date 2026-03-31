#!/usr/bin/env python3
"""
Cipher: Compass-Rose Route Transposition
Family: transposition/other
Status: active
Keyspace: grid widths 7-14 × 8 compass directions × 4 start corners × 2 read modes
Last run: 2026-03-31
Best score: 0.0 (crib_score)

Compass-rose directed route cipher: write CT into a grid, read out following
compass direction sequences. Motivated by: (1) Sanborn's "compass cipher"
reference, (2) EASTNORTHEAST crib is a compass bearing, (3) the sculpture's
compass rose with deflected needle.

Tests:
  - Single-direction routes (N, S, E, W, NE, NW, SE, SW)
  - Compass-bearing sequences (e.g., ENE pattern: E,N,E repeated)
  - Spiral reads from each corner
  - Zigzag reads following compass patterns
  - Grid widths matching K4 factors and sculpture layout
"""
import sys
import os
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# Compass direction vectors (row_delta, col_delta)
DIRECTIONS = {
    'N':  (-1,  0),
    'S':  ( 1,  0),
    'E':  ( 0,  1),
    'W':  ( 0, -1),
    'NE': (-1,  1),
    'NW': (-1, -1),
    'SE': ( 1,  1),
    'SW': ( 1, -1),
}

# Compass bearing sequences to test (thematic)
BEARING_SEQUENCES = {
    'ENE': ['E', 'N', 'E'],           # EASTNORTHEAST bearing
    'ENE_full': ['E', 'NE', 'E'],     # Alternative ENE interpretation
    'WSW': ['W', 'S', 'W'],           # Opposite bearing
    'NNE': ['N', 'N', 'E'],           # 22.5° bearing
    'compass_8': ['N', 'NE', 'E', 'SE', 'S', 'SW', 'W', 'NW'],  # Full rotation
    'cross': ['N', 'E', 'S', 'W'],    # Cardinal cross
    'diag': ['NE', 'SE', 'SW', 'NW'], # Diagonal cross
    'needle_67': ['E', 'NE'],          # ~67.5° deflection direction
}


def write_grid(text: str, width: int) -> list:
    """Write text into a grid row by row."""
    rows = (len(text) + width - 1) // width
    grid = []
    for r in range(rows):
        row = []
        for c in range(width):
            idx = r * width + c
            if idx < len(text):
                row.append(text[idx])
            else:
                row.append(None)
        grid.append(row)
    return grid


def route_read(grid: list, rows: int, cols: int, direction: str,
               start_row: int, start_col: int) -> str:
    """Read grid following a single compass direction, wrapping at boundaries."""
    dr, dc = DIRECTIONS[direction]
    visited = set()
    result = []
    r, c = start_row, start_col

    for _ in range(rows * cols):
        if 0 <= r < rows and 0 <= c < cols and (r, c) not in visited:
            visited.add((r, c))
            ch = grid[r][c]
            if ch is not None:
                result.append(ch)
            r += dr
            c += dc
        else:
            # Hit boundary or visited — advance perpendicular and continue
            # Try wrapping: move to next unvisited in reading order
            found = False
            for nr in range(rows):
                for nc in range(cols):
                    if (nr, nc) not in visited and grid[nr][nc] is not None:
                        r, c = nr, nc
                        found = True
                        break
                if found:
                    break
            if not found:
                break

    return ''.join(result)


def bearing_route_read(grid: list, rows: int, cols: int,
                       bearing_seq: list, start_row: int, start_col: int) -> str:
    """Read grid following a repeating compass bearing sequence."""
    visited = set()
    result = []
    r, c = start_row, start_col
    step = 0

    for _ in range(rows * cols):
        if 0 <= r < rows and 0 <= c < cols and (r, c) not in visited:
            visited.add((r, c))
            ch = grid[r][c]
            if ch is not None:
                result.append(ch)

        # Get next direction from bearing sequence
        direction = bearing_seq[step % len(bearing_seq)]
        dr, dc = DIRECTIONS[direction]
        nr, nc = r + dr, c + dc
        step += 1

        if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in visited:
            r, c = nr, nc
        else:
            # Can't go that way — try all directions in bearing order
            moved = False
            for alt_dir in bearing_seq:
                adr, adc = DIRECTIONS[alt_dir]
                ar, ac = r + adr, c + adc
                if 0 <= ar < rows and 0 <= ac < cols and (ar, ac) not in visited:
                    r, c = ar, ac
                    moved = True
                    break
            if not moved:
                # Find nearest unvisited
                found = False
                for sr in range(rows):
                    for sc in range(cols):
                        if (sr, sc) not in visited and grid[sr][sc] is not None:
                            r, c = sr, sc
                            found = True
                            break
                    if found:
                        break
                if not found:
                    break

    return ''.join(result)


def spiral_read(grid: list, rows: int, cols: int, clockwise: bool = True,
                start_corner: str = 'TL') -> str:
    """Read grid in spiral from a given corner."""
    result = []
    visited = set()

    if start_corner == 'TL':
        r, c = 0, 0
    elif start_corner == 'TR':
        r, c = 0, cols - 1
    elif start_corner == 'BL':
        r, c = rows - 1, 0
    else:  # BR
        r, c = rows - 1, cols - 1

    if clockwise:
        if start_corner == 'TL':
            dirs = [(0, 1), (1, 0), (0, -1), (-1, 0)]  # R, D, L, U
        elif start_corner == 'TR':
            dirs = [(1, 0), (0, -1), (-1, 0), (0, 1)]  # D, L, U, R
        elif start_corner == 'BL':
            dirs = [(-1, 0), (0, 1), (1, 0), (0, -1)]  # U, R, D, L
        else:
            dirs = [(0, -1), (-1, 0), (0, 1), (1, 0)]  # L, U, R, D
    else:
        if start_corner == 'TL':
            dirs = [(1, 0), (0, 1), (-1, 0), (0, -1)]  # D, R, U, L
        elif start_corner == 'TR':
            dirs = [(0, -1), (1, 0), (0, 1), (-1, 0)]  # L, D, R, U
        elif start_corner == 'BL':
            dirs = [(0, 1), (-1, 0), (0, -1), (1, 0)]  # R, U, L, D
        else:
            dirs = [(-1, 0), (0, -1), (1, 0), (0, 1)]  # U, L, D, R

    di = 0
    for _ in range(rows * cols):
        if 0 <= r < rows and 0 <= c < cols and (r, c) not in visited:
            visited.add((r, c))
            ch = grid[r][c]
            if ch is not None:
                result.append(ch)

        dr, dc = dirs[di]
        nr, nc = r + dr, c + dc
        if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in visited:
            r, c = nr, nc
        else:
            # Turn
            di = (di + 1) % 4
            dr, dc = dirs[di]
            nr, nc = r + dr, c + dc
            if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in visited:
                r, c = nr, nc
            else:
                break

    return ''.join(result)


def test_config(args):
    """Test one route configuration."""
    width, config_type, config_params = args
    rows = (CT_LEN + width - 1) // width
    grid = write_grid(CT, width)
    results = []

    if config_type == 'single_dir':
        direction, start_corner = config_params
        sr = 0 if 'T' in start_corner else rows - 1
        sc = 0 if 'L' in start_corner else width - 1
        pt = route_read(grid, rows, width, direction, sr, sc)
    elif config_type == 'bearing':
        bearing_name, bearing_seq, start_corner = config_params
        sr = 0 if 'T' in start_corner else rows - 1
        sc = 0 if 'L' in start_corner else width - 1
        pt = bearing_route_read(grid, rows, width, bearing_seq, sr, sc)
    elif config_type == 'spiral':
        clockwise, start_corner = config_params
        pt = spiral_read(grid, rows, width, clockwise, start_corner)
    else:
        return results

    if len(pt) < 74:
        return results

    # Score both anchored and free
    sb = score_candidate(pt[:97] if len(pt) >= 97 else pt.ljust(97, 'X'))
    score = float(sb.crib_score)

    sb_free = score_candidate_free(pt)
    free_score = float(sb_free.crib_score)

    best = max(score, free_score)
    if best >= 3:
        method = f"CompassRoute w={width} {config_type} {config_params} anch={score} free={free_score}"
        results.append((best, pt[:97], method))

    return results


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack contract."""
    all_results = []
    workers = max(1, cpu_count() - 2)
    tasks = []

    corners = ['TL', 'TR', 'BL', 'BR']

    for width in range(7, 15):
        # Single direction routes
        for direction in DIRECTIONS:
            for corner in corners:
                tasks.append((width, 'single_dir', (direction, corner)))

        # Compass bearing sequences
        for bearing_name, bearing_seq in BEARING_SEQUENCES.items():
            for corner in corners:
                tasks.append((width, 'bearing', (bearing_name, bearing_seq, corner)))

        # Spiral reads
        for clockwise in [True, False]:
            for corner in corners:
                tasks.append((width, 'spiral', (clockwise, corner)))

    print(f"  Testing {len(tasks)} route configurations with {workers} workers...")

    with Pool(workers) as pool:
        for batch_results in pool.imap_unordered(test_config, tasks, chunksize=20):
            all_results.extend(batch_results)

    all_results.sort(key=lambda x: -x[0])
    return all_results


def main():
    print("=" * 70)
    print("Compass-Rose Route Transposition Sweep")
    print("=" * 70)
    print(f"CT: {CT[:50]}...")
    print(f"CT length: {CT_LEN}")
    print()

    results = attack(CT)

    if results:
        print(f"\nResults with score >= 3: {len(results)}")
        print(f"\nTop 10:")
        for score, pt, method in results[:10]:
            print(f"  {score:5.1f}  {method}")
            print(f"         pt={pt[:60]}...")
        best = results[0][0]
    else:
        best = 0.0
        print("\nNo results with score >= 3")

    print(f"\nBest score: {best}/24")
    if best < 10:
        print("VERDICT: NOISE — Compass-rose route transposition does not decrypt K4")
    elif best < 18:
        print("VERDICT: INTERESTING — investigate further")
    else:
        print("VERDICT: SIGNAL — requires detailed analysis!")


if __name__ == "__main__":
    main()
