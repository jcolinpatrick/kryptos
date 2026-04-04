#!/usr/bin/env python3 -u
"""
Cipher: shaped grille (hourglass/Clinton variant)
Family: grille
Status: active
Keyspace: ~20 grid sizes x ~200 mask shapes x 8 orientations = ~32K masks
Last run:
Best score:

CRYPTIANA HOURGLASS GRILLE: Non-Symmetric Shaped Mask Extraction

Hypothesis: K4 text arranged in a grid, with an irregularly shaped mask
(hourglass, diamond, cross, L-shape, triangle) selecting real characters.
Characters NOT selected are nulls.

This differs from existing Cardan/Fleissner grille tests which use
4-rotation symmetric masks. Historical hourglass ciphers (Sir Henry
Clinton, American Revolution) used 2-position or asymmetric shaped
cutouts. Sanborn's AAA archive contains a "Code Breaker" overlay sketch.

For each grid dimension and mask shape:
  1. Arrange CT in the grid
  2. Extract characters visible through the mask
  3. Score extracted text for IC (English signal) and crib matches
  4. If IC > 0.055: test Beaufort/Vigenere on extracted text

Two-system connection:
  System 1: shaped grille extraction (selects real CT from nulls)
  System 2: substitution cipher on the extracted text
"""

import sys
import os
import json
import time
import math
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate_free

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT_LEN = len(CT)


def ic(text):
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


# ---- Mask shape generators ----

def hourglass_mask(rows, cols, waist_width, top_width=None):
    """Generate hourglass-shaped mask positions.

    The hourglass narrows from top_width to waist_width at the middle,
    then widens back. Centered horizontally.
    """
    if top_width is None:
        top_width = cols
    mid_row = rows // 2
    positions = set()
    for r in range(rows):
        if r <= mid_row:
            # Narrowing from top to waist
            frac = r / max(mid_row, 1)
            width = int(top_width + frac * (waist_width - top_width))
        else:
            # Widening from waist to bottom
            frac = (r - mid_row) / max(rows - 1 - mid_row, 1)
            width = int(waist_width + frac * (top_width - waist_width))
        width = max(1, min(width, cols))
        start = (cols - width) // 2
        for c in range(start, start + width):
            positions.add(r * cols + c)
    return positions


def diamond_mask(rows, cols):
    """Generate diamond-shaped mask positions."""
    mid_r = rows // 2
    mid_c = cols // 2
    positions = set()
    for r in range(rows):
        for c in range(cols):
            # Manhattan distance from center
            dist = abs(r - mid_r) + abs(c - mid_c)
            max_dist = mid_r + mid_c
            if dist <= max_dist * 0.6:  # ~60% of max distance
                positions.add(r * cols + c)
    return positions


def cross_mask(rows, cols, arm_width=1):
    """Generate cross-shaped mask positions."""
    mid_r = rows // 2
    mid_c = cols // 2
    positions = set()
    for r in range(rows):
        for c in range(cols):
            if abs(r - mid_r) <= arm_width or abs(c - mid_c) <= arm_width:
                positions.add(r * cols + c)
    return positions


def triangle_mask(rows, cols, pointing_up=True):
    """Generate triangle-shaped mask positions."""
    positions = set()
    for r in range(rows):
        if pointing_up:
            # Narrows toward top
            frac = r / max(rows - 1, 1)
            width = max(1, int(cols * frac))
        else:
            # Narrows toward bottom
            frac = 1.0 - r / max(rows - 1, 1)
            width = max(1, int(cols * frac))
        start = (cols - width) // 2
        for c in range(start, start + width):
            positions.add(r * cols + c)
    return positions


def l_shape_mask(rows, cols, arm_rows=None, arm_cols=None):
    """Generate L-shaped mask positions."""
    if arm_rows is None:
        arm_rows = rows // 2
    if arm_cols is None:
        arm_cols = cols // 2
    positions = set()
    # Vertical bar (full height, left side)
    for r in range(rows):
        for c in range(arm_cols):
            positions.add(r * cols + c)
    # Horizontal bar (bottom, full width)
    for r in range(rows - arm_rows, rows):
        for c in range(cols):
            positions.add(r * cols + c)
    return positions


def border_mask(rows, cols, thickness=1):
    """Generate border/frame mask (outer ring only)."""
    positions = set()
    for r in range(rows):
        for c in range(cols):
            if r < thickness or r >= rows - thickness or c < thickness or c >= cols - thickness:
                positions.add(r * cols + c)
    return positions


def center_block_mask(rows, cols, block_rows=None, block_cols=None):
    """Generate centered rectangular block mask."""
    if block_rows is None:
        block_rows = rows // 2
    if block_cols is None:
        block_cols = cols // 2
    positions = set()
    sr = (rows - block_rows) // 2
    sc = (cols - block_cols) // 2
    for r in range(sr, sr + block_rows):
        for c in range(sc, sc + block_cols):
            positions.add(r * cols + c)
    return positions


def generate_all_masks(rows, cols):
    """Generate all mask shapes for a given grid dimension."""
    total_cells = rows * cols
    masks = []

    # Hourglass variants
    for waist in range(1, cols):
        for top_w in [cols, cols - 1, cols - 2]:
            if top_w < waist:
                continue
            m = hourglass_mask(rows, cols, waist, top_w)
            m = {p for p in m if p < total_cells}
            n = len(m)
            if 30 <= n <= 85:
                masks.append((f"hourglass_w{waist}_t{top_w}", m))

    # Diamond
    m = diamond_mask(rows, cols)
    m = {p for p in m if p < total_cells}
    if 30 <= len(m) <= 85:
        masks.append(("diamond", m))

    # Cross variants
    for arm_w in range(1, min(rows, cols) // 2 + 1):
        m = cross_mask(rows, cols, arm_w)
        m = {p for p in m if p < total_cells}
        if 30 <= len(m) <= 85:
            masks.append((f"cross_a{arm_w}", m))

    # Triangles
    for up in [True, False]:
        m = triangle_mask(rows, cols, up)
        m = {p for p in m if p < total_cells}
        if 30 <= len(m) <= 85:
            d = "up" if up else "down"
            masks.append((f"triangle_{d}", m))

    # L-shapes
    for ar in range(rows // 3, 2 * rows // 3 + 1):
        for ac in range(cols // 3, 2 * cols // 3 + 1):
            m = l_shape_mask(rows, cols, ar, ac)
            m = {p for p in m if p < total_cells}
            if 30 <= len(m) <= 85:
                masks.append((f"L_ar{ar}_ac{ac}", m))

    # Border/frame
    for t in range(1, min(rows, cols) // 2):
        m = border_mask(rows, cols, t)
        m = {p for p in m if p < total_cells}
        if 30 <= len(m) <= 85:
            masks.append((f"border_t{t}", m))

    # Complement masks (extract what's NOT in the shape)
    complement_masks = []
    all_cells = set(range(min(total_cells, CT_LEN)))
    for label, m in masks:
        comp = all_cells - m
        if 30 <= len(comp) <= 85:
            complement_masks.append((f"inv_{label}", comp))
    masks.extend(complement_masks)

    return masks


# ---- Worker function ----

def test_grid_config(args):
    """Test one (rows, cols, mask) configuration."""
    rows, cols, mask_label, mask_positions = args

    # Pad CT to fill grid if needed
    total = rows * cols
    ct_padded = CT + 'X' * max(0, total - CT_LEN)
    ct_padded = ct_padded[:total]

    # Extract characters at mask positions (sorted by position for reading order)
    sorted_pos = sorted(p for p in mask_positions if p < CT_LEN)
    extracted = ''.join(ct_padded[p] for p in sorted_pos)
    n_extracted = len(extracted)

    if n_extracted < 24:
        return None

    # Score: IC
    ic_val = ic(extracted)

    # Score: free crib search
    score_result = score_candidate_free(extracted)
    crib_score = score_result.crib_score if hasattr(score_result, 'crib_score') else 0

    # Also try reading in column order instead of row order
    col_order_pos = []
    for c in range(cols):
        for r in range(rows):
            p = r * cols + c
            if p in mask_positions and p < CT_LEN:
                col_order_pos.append(p)
    if col_order_pos:
        col_extracted = ''.join(ct_padded[p] for p in col_order_pos)
        col_ic = ic(col_extracted)
        col_score = score_candidate_free(col_extracted)
        col_crib = col_score.crib_score if hasattr(col_score, 'crib_score') else 0
    else:
        col_ic = 0
        col_crib = 0

    best_ic = max(ic_val, col_ic)
    best_crib = max(crib_score, col_crib)

    if best_ic >= 0.050 or best_crib >= 6:
        return {
            "grid": f"{rows}x{cols}",
            "mask": mask_label,
            "n_extracted": n_extracted,
            "row_ic": round(ic_val, 4),
            "col_ic": round(col_ic, 4),
            "row_crib": crib_score,
            "col_crib": col_crib,
            "best_ic": round(best_ic, 4),
            "best_crib": best_crib,
            "row_text": extracted[:40],
            "col_text": col_extracted[:40] if col_order_pos else "",
        }
    return None


def main():
    print("=" * 70)
    print("CRYPTIANA HOURGLASS GRILLE: Shaped Mask Extraction")
    print("=" * 70)
    t0 = time.time()

    # Generate grid dimensions where rows*cols >= 97
    grid_dims = []
    for rows in range(5, 25):
        for cols in range(5, 25):
            total = rows * cols
            if 97 <= total <= 120:  # allow some padding
                grid_dims.append((rows, cols))

    print(f"\nPhase 1: {len(grid_dims)} grid dimensions")

    # Generate masks for each grid
    print("Phase 2: Generating mask shapes...")
    work_items = []
    for rows, cols in grid_dims:
        masks = generate_all_masks(rows, cols)
        for mask_label, mask_pos in masks:
            work_items.append((rows, cols, mask_label, mask_pos))

    print(f"  {len(work_items)} total (grid, mask) configurations")

    # Scan
    print(f"\nPhase 3: Scanning (IC >= 0.050 or crib >= 6)...")
    n_workers = max(1, cpu_count() - 2)
    results = []

    with Pool(n_workers) as pool:
        for result in pool.imap_unordered(test_grid_config, work_items, chunksize=50):
            if result is not None:
                results.append(result)

    elapsed = time.time() - t0

    # Sort by best IC, then by best crib
    results.sort(key=lambda r: (-r['best_crib'], -r['best_ic']))

    print(f"\n  Scan complete in {elapsed:.1f}s")
    print(f"  {len(results)} configurations above threshold")

    print("\n" + "=" * 70)
    print("RESULTS (sorted by crib score, then IC)")
    print("=" * 70)

    for r in results[:30]:
        print(f"\n  Grid: {r['grid']}, Mask: {r['mask']}, Extracted: {r['n_extracted']} chars")
        print(f"  IC: row={r['row_ic']}, col={r['col_ic']}")
        print(f"  Crib: row={r['row_crib']}, col={r['col_crib']}")
        print(f"  Row text: {r['row_text']}...")
        if r['col_text']:
            print(f"  Col text: {r['col_text']}...")

    # IC distribution
    if results:
        ics = [r['best_ic'] for r in results]
        print(f"\n  IC distribution: min={min(ics):.4f}, max={max(ics):.4f}, "
              f"mean={sum(ics)/len(ics):.4f}")
        english_like = sum(1 for x in ics if x >= 0.060)
        print(f"  IC >= 0.060 (English-like): {english_like}")

    # Save
    out = {
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "grid_dims": len(grid_dims),
        "total_configs": len(work_items),
        "above_threshold": len(results),
        "runtime_s": round(elapsed, 1),
        "top_30": results[:30],
    }
    out_path = os.path.join(_ROOT, "results", "e_cryptiana_hourglass_grille_01.json")
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\n  Saved to {out_path}")
    print(f"  Total runtime: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
