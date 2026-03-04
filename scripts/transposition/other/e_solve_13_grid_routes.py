#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-SOLVE-13: Grid Route Cipher Hypothesis

HYPOTHESIS: K4 uses a grid-based route cipher where the 97-char ciphertext is
written into a rectangular grid and read out in a non-standard route (spiral,
diagonal, zigzag, etc.), potentially combined with simple substitution.

Since 97 is prime, no exact rectangle exists. We test padded grid sizes:
  7x14=98, 14x7=98, 9x11=99, 11x9=99, 10x10=100, 4x25=100, 25x4=100,
  5x20=100, 20x5=100, 8x13=104, 13x8=104

Route types (11):
  spiral_cw_tl, spiral_cw_tr, spiral_cw_bl, spiral_cw_br,
  spiral_ccw_tl, spiral_ccw_tr, spiral_ccw_bl, spiral_ccw_br,
  diagonal_tl, diagonal_tr, zigzag_lr, zigzag_td,
  column_td, column_bt

Directions: write-route/read-row (inverse) AND write-row/read-route (forward)
Substitutions: Caesar 0-25 + KRYPTOS alphabet (Caesar 0-25)

Total: ~11 grids x ~14 routes x 2 directions x 26 Caesar x 2 alphabets = ~15,000+ configs
"""

import sys
import time
import json
import os

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR,
    KRYPTOS_ALPHABET,
)

# ── Grid dimensions ──────────────────────────────────────────────────────────

GRID_SIZES = [
    (7, 14),   # 98, pad 1
    (14, 7),   # 98, pad 1
    (9, 11),   # 99, pad 2
    (11, 9),   # 99, pad 2
    (10, 10),  # 100, pad 3
    (4, 25),   # 100, pad 3
    (25, 4),   # 100, pad 3
    (5, 20),   # 100, pad 3
    (20, 5),   # 100, pad 3
    (8, 13),   # 104, pad 7
    (13, 8),   # 104, pad 7
]

PAD_CHARS = ['X', 'Z']  # Two padding options

# ── Route generators ─────────────────────────────────────────────────────────

def spiral_cw(rows, cols, start_corner='tl'):
    """Generate spiral clockwise reading order from given corner.

    Returns list of (row, col) positions.
    """
    # Generate canonical TL spiral, then transform coordinates
    positions = _spiral_cw_tl(rows, cols)
    return _transform_positions(positions, rows, cols, start_corner)


def _spiral_cw_tl(rows, cols):
    """Clockwise spiral from top-left corner."""
    positions = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1

    while top <= bottom and left <= right:
        # Go right along top
        for c in range(left, right + 1):
            positions.append((top, c))
        top += 1

        # Go down along right
        for r in range(top, bottom + 1):
            positions.append((r, right))
        right -= 1

        # Go left along bottom
        if top <= bottom:
            for c in range(right, left - 1, -1):
                positions.append((bottom, c))
            bottom -= 1

        # Go up along left
        if left <= right:
            for r in range(bottom, top - 1, -1):
                positions.append((r, left))
            left += 1

    return positions


def _transform_positions(positions, rows, cols, corner):
    """Transform TL-spiral positions to start from a different corner."""
    if corner == 'tl':
        return positions
    elif corner == 'tr':
        # Mirror horizontally
        return [(r, cols - 1 - c) for r, c in positions]
    elif corner == 'bl':
        # Mirror vertically
        return [(rows - 1 - r, c) for r, c in positions]
    elif corner == 'br':
        # Mirror both
        return [(rows - 1 - r, cols - 1 - c) for r, c in positions]
    return positions


def spiral_ccw(rows, cols, start_corner='tl'):
    """Counter-clockwise spiral from given corner."""
    positions = _spiral_ccw_tl(rows, cols)
    return _transform_positions(positions, rows, cols, start_corner)


def _spiral_ccw_tl(rows, cols):
    """Counter-clockwise spiral from top-left corner."""
    positions = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1

    while top <= bottom and left <= right:
        # Go down along left
        for r in range(top, bottom + 1):
            positions.append((r, left))
        left += 1

        # Go right along bottom
        if left <= right:
            for c in range(left, right + 1):
                positions.append((bottom, c))
            bottom -= 1

        # Go up along right
        if top <= bottom and left <= right:
            for r in range(bottom, top - 1, -1):
                positions.append((r, right))
            right -= 1

        # Go left along top
        if top <= bottom and left <= right:
            for c in range(right, left - 1, -1):
                positions.append((top, c))
            top += 1

    return positions


def diagonal_route(rows, cols, start_corner='tl'):
    """Read diagonals from given corner.

    For TL: read top-left to bottom-right diagonals,
    starting from top-left, going to bottom-right.
    """
    positions = []
    if start_corner == 'tl':
        # Diagonals: (0,0), (0,1)+(1,0), (0,2)+(1,1)+(2,0), ...
        for d in range(rows + cols - 1):
            for r in range(max(0, d - cols + 1), min(d + 1, rows)):
                c = d - r
                positions.append((r, c))
    elif start_corner == 'tr':
        # Mirror horizontally
        for d in range(rows + cols - 1):
            for r in range(max(0, d - cols + 1), min(d + 1, rows)):
                c = d - r
                positions.append((r, cols - 1 - c))
    return positions


def zigzag_lr(rows, cols):
    """Snake/zigzag: alternating left-right and right-left rows."""
    positions = []
    for r in range(rows):
        if r % 2 == 0:
            for c in range(cols):
                positions.append((r, c))
        else:
            for c in range(cols - 1, -1, -1):
                positions.append((r, c))
    return positions


def zigzag_td(rows, cols):
    """Snake/zigzag: alternating top-down and bottom-up columns."""
    positions = []
    for c in range(cols):
        if c % 2 == 0:
            for r in range(rows):
                positions.append((r, c))
        else:
            for r in range(rows - 1, -1, -1):
                positions.append((r, c))
    return positions


def column_td(rows, cols):
    """Column-major: top to bottom, left to right."""
    positions = []
    for c in range(cols):
        for r in range(rows):
            positions.append((r, c))
    return positions


def column_bt(rows, cols):
    """Column-major: bottom to top, left to right."""
    positions = []
    for c in range(cols):
        for r in range(rows - 1, -1, -1):
            positions.append((r, c))
    return positions


def boustrophedon(rows, cols):
    """Boustrophedon: alternating column direction."""
    positions = []
    for c in range(cols):
        if c % 2 == 0:
            for r in range(rows):
                positions.append((r, c))
        else:
            for r in range(rows - 1, -1, -1):
                positions.append((r, c))
    return positions


# ── Build all routes for a grid ──────────────────────────────────────────────

def build_routes(rows, cols):
    """Build all route reading orders for a given grid size.

    Returns dict of route_name -> list of (row, col) positions.
    """
    routes = {}

    # Spiral clockwise from 4 corners
    for corner in ['tl', 'tr', 'bl', 'br']:
        routes[f'spiral_cw_{corner}'] = spiral_cw(rows, cols, corner)

    # Spiral counter-clockwise from 4 corners
    for corner in ['tl', 'tr', 'bl', 'br']:
        routes[f'spiral_ccw_{corner}'] = spiral_ccw(rows, cols, corner)

    # Diagonal
    routes['diagonal_tl'] = diagonal_route(rows, cols, 'tl')
    routes['diagonal_tr'] = diagonal_route(rows, cols, 'tr')

    # Zigzag
    routes['zigzag_lr'] = zigzag_lr(rows, cols)
    routes['zigzag_td'] = zigzag_td(rows, cols)

    # Column-major
    routes['column_td'] = column_td(rows, cols)
    routes['column_bt'] = column_bt(rows, cols)

    # Boustrophedon
    routes['boustrophedon'] = boustrophedon(rows, cols)

    return routes


# ── Apply route to grid ──────────────────────────────────────────────────────

def apply_route_read(padded_ct, rows, cols, route_positions):
    """Write CT into grid row-by-row, read out in route order.

    This is the 'forward' direction: CT fills grid normally,
    route extracts characters.
    """
    # Fill grid row-by-row
    grid = []
    idx = 0
    for r in range(rows):
        row = []
        for c in range(cols):
            if idx < len(padded_ct):
                row.append(padded_ct[idx])
            else:
                row.append('X')  # shouldn't happen if padded correctly
            idx += 1
        grid.append(row)

    # Read out in route order
    result = []
    for r, c in route_positions:
        if 0 <= r < rows and 0 <= c < cols:
            result.append(grid[r][c])
    return ''.join(result)


def apply_route_write(padded_ct, rows, cols, route_positions):
    """Write CT into grid in route order, read out row-by-row.

    This is the 'inverse' direction: CT fills grid via route,
    then read normally.
    """
    grid = [['X'] * cols for _ in range(rows)]

    # Write CT following the route
    for idx, (r, c) in enumerate(route_positions):
        if idx < len(padded_ct) and 0 <= r < rows and 0 <= c < cols:
            grid[r][c] = padded_ct[idx]

    # Read out row-by-row
    result = []
    for r in range(rows):
        for c in range(cols):
            result.append(grid[r][c])
    return ''.join(result)


# ── Substitution ─────────────────────────────────────────────────────────────

def caesar_shift(text, shift, alphabet=ALPH):
    """Apply Caesar shift using given alphabet."""
    alpha_idx = {c: i for i, c in enumerate(alphabet)}
    n = len(alphabet)
    result = []
    for ch in text:
        if ch in alpha_idx:
            result.append(alphabet[(alpha_idx[ch] + shift) % n])
        else:
            result.append(ch)
    return ''.join(result)


# ── Crib scoring (fast, inline) ──────────────────────────────────────────────

def quick_crib_score(text):
    """Count matching crib positions. Fast inline version."""
    score = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            score += 1
    return score


# ── Main experiment ──────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("E-SOLVE-13: Grid Route Cipher Hypothesis")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Grid sizes to test: {len(GRID_SIZES)}")
    print()

    total_tested = 0
    above_noise = 0
    best_score = 0
    best_config = ""
    best_plaintext = ""
    hits = []  # Store all above-noise hits

    t0 = time.time()

    alphabets = [
        ("AZ", ALPH),
        ("KA", KRYPTOS_ALPHABET),
    ]

    for rows, cols in GRID_SIZES:
        total_cells = rows * cols
        pad_needed = total_cells - CT_LEN

        print(f"\n--- Grid {rows}x{cols} = {total_cells} cells (pad {pad_needed}) ---")

        # Build all routes for this grid
        routes = build_routes(rows, cols)
        print(f"  Routes: {len(routes)}")

        # For each padding option
        for pad_char in PAD_CHARS:
            padded_ct = CT + pad_char * pad_needed

            for route_name, route_positions in routes.items():
                # Validate route covers all cells
                assert len(route_positions) == total_cells, \
                    f"Route {route_name} has {len(route_positions)} positions, expected {total_cells}"

                for direction in ['read', 'write']:
                    # Apply the route transposition
                    if direction == 'read':
                        transposed = apply_route_read(padded_ct, rows, cols, route_positions)
                    else:
                        transposed = apply_route_write(padded_ct, rows, cols, route_positions)

                    # Trim to CT_LEN (remove padding artifacts)
                    # Actually, the transposed text may be longer than 97 chars
                    # We need exactly 97 chars for scoring. Take first 97.
                    candidate_full = transposed[:CT_LEN]

                    for alph_name, alph in alphabets:
                        for shift in range(26):
                            candidate = caesar_shift(candidate_full, shift, alph)
                            total_tested += 1

                            score = quick_crib_score(candidate)

                            if score > NOISE_FLOOR:
                                above_noise += 1
                                config_str = (
                                    f"grid={rows}x{cols} pad={pad_char} "
                                    f"route={route_name} dir={direction} "
                                    f"alph={alph_name} shift={shift}"
                                )
                                hits.append({
                                    "score": score,
                                    "config": config_str,
                                    "plaintext": candidate,
                                })
                                if score > best_score:
                                    best_score = score
                                    best_config = config_str
                                    best_plaintext = candidate
                                    print(f"  NEW BEST: score={score}/{N_CRIBS} | {config_str}")
                                    if score >= 10:
                                        print(f"    PT: {candidate}")

        elapsed = time.time() - t0
        print(f"  Cumulative: {total_tested:,} configs, {above_noise} above noise, "
              f"best={best_score}/{N_CRIBS}, {elapsed:.1f}s")

    elapsed = time.time() - t0

    # ── Also try: no padding (truncate route to 97 positions) ────────────────
    print(f"\n{'=' * 72}")
    print("Phase 2: No-padding variants (truncate route to 97 positions)")
    print(f"{'=' * 72}")

    for rows, cols in GRID_SIZES:
        total_cells = rows * cols
        pad_needed = total_cells - CT_LEN

        # Fill grid with CT (leaving some cells empty)
        # Write CT row-by-row, empty cells get sentinel
        EMPTY = '\x00'

        routes = build_routes(rows, cols)

        for route_name, route_positions in routes.items():
            # Forward: write CT row-by-row (only 97 chars), read in route order
            # (skip empty cells)
            grid_fwd = [[EMPTY] * cols for _ in range(rows)]
            idx = 0
            for r in range(rows):
                for c in range(cols):
                    if idx < CT_LEN:
                        grid_fwd[r][c] = CT[idx]
                        idx += 1

            # Read in route order, skip empty
            transposed_fwd = []
            for r, c in route_positions:
                if 0 <= r < rows and 0 <= c < cols and grid_fwd[r][c] != EMPTY:
                    transposed_fwd.append(grid_fwd[r][c])

            # Inverse: write CT in route order (only 97 chars), read row-by-row
            grid_inv = [[EMPTY] * cols for _ in range(rows)]
            for idx, (r, c) in enumerate(route_positions):
                if idx < CT_LEN and 0 <= r < rows and 0 <= c < cols:
                    grid_inv[r][c] = CT[idx]

            transposed_inv = []
            for r in range(rows):
                for c in range(cols):
                    if grid_inv[r][c] != EMPTY:
                        transposed_inv.append(grid_inv[r][c])

            for candidate_full, direction in [
                (''.join(transposed_fwd), 'read_nopad'),
                (''.join(transposed_inv), 'write_nopad'),
            ]:
                if len(candidate_full) < CT_LEN:
                    continue  # Skip if we lost characters

                candidate_full = candidate_full[:CT_LEN]

                for alph_name, alph in alphabets:
                    for shift in range(26):
                        candidate = caesar_shift(candidate_full, shift, alph)
                        total_tested += 1

                        score = quick_crib_score(candidate)

                        if score > NOISE_FLOOR:
                            above_noise += 1
                            config_str = (
                                f"grid={rows}x{cols} "
                                f"route={route_name} dir={direction} "
                                f"alph={alph_name} shift={shift}"
                            )
                            hits.append({
                                "score": score,
                                "config": config_str,
                                "plaintext": candidate,
                            })
                            if score > best_score:
                                best_score = score
                                best_config = config_str
                                best_plaintext = candidate
                                print(f"  NEW BEST: score={score}/{N_CRIBS} | {config_str}")
                                if score >= 10:
                                    print(f"    PT: {candidate}")

    elapsed = time.time() - t0

    # ── Also try: use free crib scoring for route-only (no substitution) ─────
    print(f"\n{'=' * 72}")
    print("Phase 3: Route-only (no substitution), free crib scoring")
    print(f"{'=' * 72}")

    from kryptos.kernel.scoring.free_crib import score_free

    free_best_score = 0
    free_hits = []

    for rows, cols in GRID_SIZES:
        total_cells = rows * cols
        pad_needed = total_cells - CT_LEN

        routes = build_routes(rows, cols)

        for pad_char in PAD_CHARS:
            padded_ct = CT + pad_char * pad_needed

            for route_name, route_positions in routes.items():
                for direction in ['read', 'write']:
                    if direction == 'read':
                        transposed = apply_route_read(padded_ct, rows, cols, route_positions)
                    else:
                        transposed = apply_route_write(padded_ct, rows, cols, route_positions)

                    candidate = transposed[:CT_LEN]
                    total_tested += 1

                    # Check free crib (position-independent)
                    fcr = score_free(candidate, find_fragments_flag=False)
                    if fcr.ene_found or fcr.bc_found:
                        config_str = (
                            f"grid={rows}x{cols} pad={pad_char} "
                            f"route={route_name} dir={direction}"
                        )
                        free_hits.append({
                            "score": fcr.score,
                            "ene": fcr.ene_found,
                            "bc": fcr.bc_found,
                            "config": config_str,
                            "plaintext": candidate,
                        })
                        if fcr.score > free_best_score:
                            free_best_score = fcr.score
                            print(f"  FREE CRIB HIT: score={fcr.score} ENE={fcr.ene_found} "
                                  f"BC={fcr.bc_found} | {config_str}")

    elapsed = time.time() - t0

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("FINAL SUMMARY")
    print(f"{'=' * 72}")
    print(f"Total configurations tested: {total_tested:,}")
    print(f"Above noise (>{NOISE_FLOOR}/24): {above_noise}")
    print(f"Best anchored crib score: {best_score}/{N_CRIBS}")
    if best_score > 0:
        print(f"Best config: {best_config}")
        print(f"Best PT: {best_plaintext}")
    print(f"Free crib hits: {len(free_hits)}")
    if free_hits:
        print(f"Best free crib score: {free_best_score}")
    print(f"Elapsed: {elapsed:.1f}s")

    # Score distribution
    if hits:
        from collections import Counter
        score_dist = Counter(h["score"] for h in hits)
        print(f"\nScore distribution (anchored, >{NOISE_FLOOR}):")
        for s in sorted(score_dist.keys(), reverse=True):
            print(f"  score {s}: {score_dist[s]} configs")

    # Top 10 hits
    if hits:
        hits.sort(key=lambda h: h["score"], reverse=True)
        print(f"\nTop 10 hits:")
        for i, h in enumerate(hits[:10]):
            print(f"  {i+1}. score={h['score']}/{N_CRIBS} | {h['config']}")
            print(f"     PT: {h['plaintext'][:60]}...")

    # Classification
    if best_score <= NOISE_FLOOR:
        verdict = "ALL NOISE"
    elif best_score < 10:
        verdict = "MARGINAL (above noise floor but below store threshold)"
    elif best_score < 18:
        verdict = "INTERESTING (stored, worth investigating)"
    elif best_score < 24:
        verdict = "SIGNAL (statistically significant)"
    else:
        verdict = "BREAKTHROUGH"

    print(f"\nVERDICT: {verdict}")
    print(f"HYPOTHESIS: Grid route cipher {'NOT ELIMINATED' if best_score >= 18 else 'ELIMINATED (single-layer)'}")

    # Save results
    result = {
        "experiment": "E-SOLVE-13",
        "hypothesis": "Grid route cipher (spiral, diagonal, zigzag) + Caesar/KA substitution",
        "total_tested": total_tested,
        "above_noise": above_noise,
        "best_score": best_score,
        "best_config": best_config,
        "best_plaintext": best_plaintext,
        "free_crib_hits": len(free_hits),
        "free_best_score": free_best_score,
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "grid_sizes": [f"{r}x{c}" for r, c in GRID_SIZES],
        "route_types": 15,  # 8 spiral + 2 diagonal + 2 zigzag + 2 column + 1 boustrophedon
        "top_hits": [
            {"score": h["score"], "config": h["config"], "plaintext": h["plaintext"]}
            for h in (sorted(hits, key=lambda x: x["score"], reverse=True)[:20] if hits else [])
        ],
    }

    os.makedirs("results", exist_ok=True)
    out_path = "results/e_solve_13_grid_routes.json"
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
