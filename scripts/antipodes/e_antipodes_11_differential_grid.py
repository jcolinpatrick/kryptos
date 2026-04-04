#!/usr/bin/env python3
"""
Cipher: transposition/grid
Family: antipodes
Status: active
Keyspace: ~50,000 configs
Last run:
Best score:

E-ANTIPODES-11: Differential Grid Analysis — Kryptos vs Antipodes Layout

HYPOTHESIS: Antipodes' full-justified layout defines a different physical grid
from Kryptos' ragged-right layout. If K4 involves a grid-based transposition
step, the correct grid is embedded in one sculpture's layout. By testing
multiple plausible row widths for both sculptures — and reading K4 by columns,
diagonals, spirals, and other standard routes — we can determine whether any
physically-motivated permutation produces crib matches above noise.

This is the single most Antipodes-distinctive test that has NEVER been run.
Identified as highest-value computational action by the 2026-04-01 Team of
Rivals adversarial review.

APPROACH:
1. For each plausible width (2-48), wrap K4 CT into a grid
2. Read the grid by multiple routes (column-major, boustrophedon, spiral,
   diagonal, reverse variants)
3. Apply the resulting permutation to K4 CT
4. Score the permuted text against both anchored and free cribs
5. Also test: applying substitution (Beaufort/Vigenere with thematic keywords)
   AFTER the transposition, since the hypothesis is trans + sub

Key widths to test with extra attention:
- 31 (Kryptos panel width)
- 32-36 (Antipodes character range per row)
- 7, 14 (KRYPTOS period / half-panel)
- 25 (COF-English Small row width)
- 8, 12 (from Sanborn's "8 lines 73" notation)
"""

import sys
import os
import time
import itertools
from multiprocessing import Pool, cpu_count
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CRIB_POSITIONS, CONSENSUS_NULL_POSITIONS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.transforms.vigenere import vig_decrypt, beau_decrypt
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet

# ── Constants ──────────────────────────────────────────────────────────────
CT97 = CT
CT_LEN = len(CT97)
assert CT_LEN == 97

# Widths of special interest
PRIORITY_WIDTHS = [7, 8, 10, 12, 14, 17, 21, 25, 31, 32, 33, 34, 35, 36]
ALL_WIDTHS = list(range(2, 49))

# Thematic keywords for substitution layer
KEYWORDS = [
    "", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "DECEIT",
    "SEVEN", "BERLINCLOCK", "ANTIPODES",
]

# ── Permutation generators ─────────────────────────────────────────────────

def row_major_perm(width, length):
    """Standard left-to-right, top-to-bottom. Identity permutation."""
    return list(range(length))


def col_major_perm(width, length):
    """Read columns top-to-bottom, left-to-right."""
    nrows = (length + width - 1) // width
    perm = []
    for col in range(width):
        for row in range(nrows):
            idx = row * width + col
            if idx < length:
                perm.append(idx)
    return perm


def col_major_rev_perm(width, length):
    """Read columns bottom-to-top, left-to-right."""
    nrows = (length + width - 1) // width
    perm = []
    for col in range(width):
        for row in range(nrows - 1, -1, -1):
            idx = row * width + col
            if idx < length:
                perm.append(idx)
    return perm


def boustrophedon_perm(width, length):
    """Serpentine: even rows L→R, odd rows R→L."""
    nrows = (length + width - 1) // width
    perm = []
    for row in range(nrows):
        start = row * width
        end = min(start + width, length)
        indices = list(range(start, end))
        if row % 2 == 1:
            indices.reverse()
        perm.extend(indices)
    return perm


def spiral_perm(width, length):
    """Clockwise spiral from outside in."""
    nrows = (length + width - 1) // width
    # Build grid of indices
    grid = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(width):
            if idx < length:
                row.append(idx)
            else:
                row.append(-1)
            idx += 1
        grid.append(row)

    perm = []
    top, bottom, left, right = 0, nrows - 1, 0, width - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            if grid[top][c] >= 0:
                perm.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            if grid[r][right] >= 0:
                perm.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if grid[bottom][c] >= 0:
                    perm.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if grid[r][left] >= 0:
                    perm.append(grid[r][left])
            left += 1
    return perm


def diagonal_perm(width, length):
    """Read diagonals top-left to bottom-right."""
    nrows = (length + width - 1) // width
    perm = []
    for d in range(nrows + width - 1):
        for row in range(max(0, d - width + 1), min(nrows, d + 1)):
            col = d - row
            if col < width:
                idx = row * width + col
                if idx < length:
                    perm.append(idx)
    return perm


def antidiag_perm(width, length):
    """Read anti-diagonals top-right to bottom-left."""
    nrows = (length + width - 1) // width
    perm = []
    for d in range(nrows + width - 1):
        for row in range(max(0, d - width + 1), min(nrows, d + 1)):
            col = width - 1 - (d - row)
            if 0 <= col < width:
                idx = row * width + col
                if idx < length:
                    perm.append(idx)
    return perm


def reverse_perm(perm):
    """Reverse a permutation."""
    return list(reversed(perm))


def invert_perm(perm):
    """Invert a permutation (scatter → gather)."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# All reading orders
ROUTES = {
    "col_major": col_major_perm,
    "col_major_rev": col_major_rev_perm,
    "boustrophedon": boustrophedon_perm,
    "spiral": spiral_perm,
    "diagonal": diagonal_perm,
    "antidiag": antidiag_perm,
}


def apply_perm(text, perm):
    """Apply a gather-convention permutation: output[i] = input[perm[i]]."""
    return "".join(text[p] for p in perm)


# ── Scoring ────────────────────────────────────────────────────────────────

def score_text(text, method_desc):
    """Score a candidate text. Returns (score, text, method)."""
    result = score_candidate(text)
    return (result.crib_score, text, method_desc)


def score_text_free(text, method_desc):
    """Score with free crib search (for scrambled CT)."""
    result = score_candidate_free(text)
    return (result.crib_score, text, method_desc)


# ── Single-config worker ──────────────────────────────────────────────────

def test_config(args):
    """Test one (width, route, direction, keyword, variant) config."""
    width, route_name, route_fn, use_inverse, keyword, variant = args

    # Generate permutation
    perm = route_fn(width, CT_LEN)
    if len(perm) != CT_LEN:
        return []

    if use_inverse:
        perm = invert_perm(perm)

    # Apply transposition
    permuted = apply_perm(CT97, perm)

    results = []
    dir_label = "inv" if use_inverse else "fwd"

    if keyword == "":
        # Pure transposition — score directly
        desc = f"w={width} {route_name} {dir_label}"
        s_anchored = score_candidate(permuted)
        s_free = score_candidate_free(permuted)
        best_score = max(s_anchored.crib_score, s_free.crib_score)
        best_type = "anchored" if s_anchored.crib_score >= s_free.crib_score else "free"
        if best_score >= NOISE_FLOOR:
            results.append((best_score, permuted, f"{desc} [{best_type}]"))
    else:
        # Transposition + substitution
        for v_name, decrypt_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            if variant != "" and variant != v_name:
                continue
            try:
                decrypted = decrypt_fn(permuted, keyword)
                desc = f"w={width} {route_name} {dir_label} + {v_name}({keyword})"
                s_anchored = score_candidate(decrypted)
                s_free = score_candidate_free(decrypted)
                best_score = max(s_anchored.crib_score, s_free.crib_score)
                best_type = "anchored" if s_anchored.crib_score >= s_free.crib_score else "free"
                if best_score >= NOISE_FLOOR:
                    results.append((best_score, decrypted, f"{desc} [{best_type}]"))
            except Exception:
                pass

    return results


# ── Main ───────────────────────────────────────────────────────────────────

def attack(ciphertext=CT97, **params):
    """Standard attack contract."""
    t0 = time.time()
    all_results = []

    # Build work items
    configs = []
    for width in ALL_WIDTHS:
        for route_name, route_fn in ROUTES.items():
            for use_inverse in [False, True]:
                for keyword in KEYWORDS:
                    # For keywords, test both variants
                    if keyword:
                        for variant in ["vig", "beau"]:
                            configs.append((width, route_name, route_fn,
                                           use_inverse, keyword, variant))
                    else:
                        configs.append((width, route_name, route_fn,
                                       use_inverse, keyword, ""))

    total = len(configs)
    print(f"Differential Grid Analysis: {total} configs")
    print(f"  Widths: {min(ALL_WIDTHS)}-{max(ALL_WIDTHS)} ({len(ALL_WIDTHS)} widths)")
    print(f"  Routes: {len(ROUTES)} ({', '.join(ROUTES.keys())})")
    print(f"  Directions: fwd + inv")
    print(f"  Keywords: {len(KEYWORDS)} (inc. pure transposition)")
    print(f"  Variants: vig + beau (for keyed configs)")
    print()

    # Parallel execution
    n_workers = max(1, cpu_count() - 2)
    print(f"Running on {n_workers} workers...")

    batch_size = 500
    best_score = 0
    n_stored = 0

    with Pool(n_workers) as pool:
        for i in range(0, total, batch_size):
            batch = configs[i:i + batch_size]
            batch_results = pool.map(test_config, batch)
            for result_list in batch_results:
                for score, text, desc in result_list:
                    all_results.append((score, text, desc))
                    n_stored += 1
                    if score > best_score:
                        best_score = score
                        print(f"  NEW BEST: {score}/24 — {desc}")
                        if score >= 10:
                            print(f"    TEXT: {text[:60]}...")

            done = min(i + batch_size, total)
            elapsed = time.time() - t0
            rate = done / elapsed if elapsed > 0 else 0
            print(f"  [{done}/{total}] ({rate:.0f}/s) best={best_score}/24 stored={n_stored}")

    # Sort and report
    all_results.sort(key=lambda x: -x[0])
    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print(f"DIFFERENTIAL GRID ANALYSIS COMPLETE")
    print(f"  Total configs: {total}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Results above noise: {len(all_results)}")
    print(f"  Best score: {best_score}/24")

    if all_results:
        print(f"\nTop 20 results:")
        for score, text, desc in all_results[:20]:
            print(f"  {score:2d}/24  {desc}")
            print(f"         {text[:70]}")

    # Priority width analysis
    print(f"\n{'='*70}")
    print(f"PRIORITY WIDTH ANALYSIS")
    priority_results = [(s, t, d) for s, t, d in all_results
                        if any(f"w={w} " in d for w in PRIORITY_WIDTHS)]
    if priority_results:
        print(f"  Results at priority widths ({PRIORITY_WIDTHS}):")
        for score, text, desc in priority_results[:10]:
            print(f"  {score:2d}/24  {desc}")
    else:
        print(f"  No results above noise at priority widths")

    # Antipodes-specific widths
    print(f"\nANTIPODES WIDTHS (32-36):")
    anti_results = [(s, t, d) for s, t, d in all_results
                    if any(f"w={w} " in d for w in [32, 33, 34, 35, 36])]
    if anti_results:
        for score, text, desc in anti_results[:10]:
            print(f"  {score:2d}/24  {desc}")
    else:
        print(f"  No results above noise at Antipodes widths")

    return all_results[:50]


if __name__ == "__main__":
    results = attack()
