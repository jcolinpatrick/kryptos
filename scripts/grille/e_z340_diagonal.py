#!/usr/bin/env python3
"""
Cipher: transposition + substitution
Family: grille
Status: active
Keyspace: ~650000
Last run:
Best score:
"""
"""E-Z340-DIAGONAL: Z340-inspired bespoke reading orders for K4.

The Zodiac Z340 cipher (solved Dec 2020) combined homophonic substitution
with a bespoke transposition: the 17x20 grid was split into vertical
segments (9,9,2 rows) and read via a 1,2-decimation (knight's move:
down 1, right 2, wrapping toroidally). This script applies similar
bespoke reading patterns to K4.

Key Z340 lessons applied:
1. DECIMATION: skip-d reading (already tested in e_s_97 for single
   decimation on 97 chars; here we test MULTI-STEP and SEGMENTED decimation)
2. KNIGHT'S MOVE: (dr, dc) toroidal walk on grids of various dimensions
3. VERTICAL SEGMENT SPLITTING: split grid into vertical strips, apply
   different reading orders to each
4. DIAGONAL STRIP reading at various angles
5. Combined: segment + decimation + substitution (Vig/Beau, AZ/KA)

Grid dimensions tested:
  97 = prime (no factorization possible; pad to 98, 99, 100)
  98 = 2x49 = 7x14
  99 = 9x11
  100 = 10x10 = 4x25 = 5x20
  Also: K4 in the 28x31 master grid (rows 25-28, read positions only)

For each reading order, decrypt with top keyword candidates via
Vig/Beaufort on AZ and KA alphabets, score with score_candidate_free().

Usage: PYTHONPATH=src python3 -u scripts/grille/e_z340_diagonal.py
"""

import sys
import os
import time
from itertools import product
from math import gcd
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.scoring.aggregate import score_candidate_free

# ── Constants ──────────────────────────────────────────────────────────────
EXPERIMENT_ID = "E-Z340-DIAGONAL"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
    "DEFECTOR", "PARALLAX", "COLOPHON", "VERDIGRIS",
]

N = CT_LEN  # 97

# Grid dimensions to try: (rows, cols, pad_char)
GRID_DIMS = [
    (7, 14, 98),
    (14, 7, 98),
    (2, 49, 98),
    (49, 2, 98),
    (9, 11, 99),
    (11, 9, 99),
    (10, 10, 100),
    (4, 25, 100),
    (25, 4, 100),
    (5, 20, 100),
    (20, 5, 100),
]


# ── Cipher functions ───────────────────────────────────────────────────────

def vig_decrypt_az(ct_str, key):
    pt = []
    klen = len(key)
    for i, c in enumerate(ct_str):
        ci = AZ_IDX[c]
        ki = AZ_IDX[key[i % klen]]
        pt.append(AZ[(ci - ki) % 26])
    return "".join(pt)


def beau_decrypt_az(ct_str, key):
    pt = []
    klen = len(key)
    for i, c in enumerate(ct_str):
        ci = AZ_IDX[c]
        ki = AZ_IDX[key[i % klen]]
        pt.append(AZ[(ki - ci) % 26])
    return "".join(pt)


def vig_decrypt_ka(ct_str, key):
    pt = []
    klen = len(key)
    for i, c in enumerate(ct_str):
        ci = KA_IDX[c]
        ki = KA_IDX[key[i % klen]]
        pt.append(KA[(ci - ki) % 26])
    return "".join(pt)


def beau_decrypt_ka(ct_str, key):
    pt = []
    klen = len(key)
    for i, c in enumerate(ct_str):
        ci = KA_IDX[c]
        ki = KA_IDX[key[i % klen]]
        pt.append(KA[(ki - ci) % 26])
    return "".join(pt)


DECRYPT_FNS = [
    ("Vig-AZ", vig_decrypt_az),
    ("Beau-AZ", beau_decrypt_az),
    ("Vig-KA", vig_decrypt_ka),
    ("Beau-KA", beau_decrypt_ka),
]


# ── Reading order generators ──────────────────────────────────────────────

def pad_ct(ct, target_len):
    """Pad CT with X's to target length."""
    if len(ct) >= target_len:
        return ct[:target_len]
    return ct + 'X' * (target_len - len(ct))


def toroidal_walk(nrows, ncols, dr, dc, start_r=0, start_c=0):
    """Generate a toroidal walk permutation: step (dr, dc) on an nrows x ncols grid.
    Returns list of (row, col) positions in walk order."""
    total = nrows * ncols
    visited = set()
    path = []
    r, c = start_r, start_c
    for _ in range(total):
        if (r, c) in visited:
            # Find next unvisited cell (row-major)
            found = False
            for rr in range(nrows):
                for cc in range(ncols):
                    if (rr, cc) not in visited:
                        r, c = rr, cc
                        found = True
                        break
                if found:
                    break
            if not found:
                break
        visited.add((r, c))
        path.append((r, c))
        r = (r + dr) % nrows
        c = (c + dc) % ncols
    return path


def diagonal_strips(nrows, ncols, direction='tl_br'):
    """Read along diagonal strips.
    tl_br: top-left to bottom-right diagonals
    tr_bl: top-right to bottom-left diagonals
    """
    path = []
    if direction == 'tl_br':
        for d in range(nrows + ncols - 1):
            for r in range(nrows):
                c = d - r
                if 0 <= c < ncols:
                    path.append((r, c))
    elif direction == 'tr_bl':
        for d in range(-(ncols - 1), nrows):
            for r in range(nrows):
                c = r - d
                if 0 <= c < ncols:
                    path.append((r, c))
    elif direction == 'bl_tr':
        for d in range(nrows + ncols - 1):
            for r in range(nrows - 1, -1, -1):
                c = d - r
                if 0 <= c < ncols:
                    path.append((r, c))
    elif direction == 'br_tl':
        for d in range(nrows + ncols - 2, -1, -1):
            for r in range(nrows - 1, -1, -1):
                c = d - r
                if 0 <= c < ncols:
                    path.append((r, c))
    return path


def segmented_decimation(nrows, ncols, segments, dr, dc):
    """Z340-style: split grid into horizontal segments, apply decimation to each.
    segments: list of row counts, e.g. [9, 9, 2] for Z340.
    dr, dc: decimation step within each segment.
    """
    path = []
    row_offset = 0
    for seg_rows in segments:
        seg_path = toroidal_walk(seg_rows, ncols, dr, dc)
        for r, c in seg_path:
            path.append((r + row_offset, c))
        row_offset += seg_rows
    return path


def vertical_segment_decimation(nrows, ncols, segments, dr, dc):
    """Split grid into VERTICAL segments (column groups), apply decimation to each.
    segments: list of column counts.
    """
    path = []
    col_offset = 0
    for seg_cols in segments:
        seg_path = toroidal_walk(nrows, seg_cols, dr, dc)
        for r, c in seg_path:
            path.append((r, c + col_offset))
        col_offset += seg_cols
    return path


def path_to_perm(path, nrows, ncols):
    """Convert a (row, col) path to a 1D permutation index list."""
    return [r * ncols + c for r, c in path]


def apply_reading_order(ct_padded, perm):
    """Apply reading order permutation: read ct_padded in order given by perm."""
    return ''.join(ct_padded[p] for p in perm if p < len(ct_padded))


# ── Scoring ────────────────────────────────────────────────────────────────

def score_candidate(pt_text):
    """Score using free crib search (position-independent)."""
    result = score_candidate_free(pt_text)
    return result.crib_score


# ── Main experiment ────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print(f"  {EXPERIMENT_ID}: Z340-Inspired Bespoke Reading Orders for K4")
    print("=" * 72)
    print(f"CT ({N} chars): {CT}")
    print()

    best_overall = 0
    best_desc = ""
    best_pt = ""
    results = []
    total_configs = 0
    t0 = time.time()

    # ── Phase 1: Toroidal Knight's Move on Various Grids ──────────────
    print("\n[Phase 1] Toroidal (dr,dc) walks on padded grids")
    print("-" * 60)

    for nrows, ncols, pad_len in GRID_DIMS:
        ct_padded = pad_ct(CT, pad_len)

        # Test various step sizes (like Z340's (1,2) knight move)
        steps_to_try = []
        for dr in range(nrows):
            for dc in range(ncols):
                if dr == 0 and dc == 0:
                    continue
                # Only try steps that generate full permutation
                # (i.e., gcd(step_linear, total) divides well)
                steps_to_try.append((dr, dc))

        for dr, dc in steps_to_try:
            path = toroidal_walk(nrows, ncols, dr, dc)
            perm = path_to_perm(path, nrows, ncols)
            reordered = apply_reading_order(ct_padded, perm)
            # Trim back to 97 chars (remove padding positions)
            # Actually, we need the first 97 meaningful chars
            reordered_97 = reordered[:N]

            for key in KEYWORDS:
                for dec_name, dec_fn in DECRYPT_FNS:
                    pt = dec_fn(reordered_97, key)
                    sc = score_candidate(pt)
                    total_configs += 1
                    if sc > best_overall:
                        best_overall = sc
                        desc = f"Toroidal({nrows}x{ncols}, dr={dr}, dc={dc}) {dec_name} key={key}"
                        best_desc = desc
                        best_pt = pt
                        if sc >= 6:
                            results.append((sc, desc, pt))
                            print(f"  [HIT] score={sc}: {desc}")
                            print(f"         PT: {pt[:60]}...")

        sys.stdout.flush()

    elapsed1 = time.time() - t0
    print(f"\n  Phase 1: {total_configs} configs tested in {elapsed1:.1f}s")
    print(f"  Best so far: {best_overall} — {best_desc}")

    # ── Phase 2: Diagonal Strip Reading ───────────────────────────────
    print("\n[Phase 2] Diagonal strip reading on padded grids")
    print("-" * 60)
    t1 = time.time()
    phase2_configs = 0

    directions = ['tl_br', 'tr_bl', 'bl_tr', 'br_tl']

    for nrows, ncols, pad_len in GRID_DIMS:
        ct_padded = pad_ct(CT, pad_len)

        for direction in directions:
            path = diagonal_strips(nrows, ncols, direction)
            perm = path_to_perm(path, nrows, ncols)
            reordered = apply_reading_order(ct_padded, perm)
            reordered_97 = reordered[:N]

            for key in KEYWORDS:
                for dec_name, dec_fn in DECRYPT_FNS:
                    pt = dec_fn(reordered_97, key)
                    sc = score_candidate(pt)
                    phase2_configs += 1
                    total_configs += 1
                    if sc > best_overall:
                        best_overall = sc
                        desc = f"DiagStrip({nrows}x{ncols}, {direction}) {dec_name} key={key}"
                        best_desc = desc
                        best_pt = pt
                    if sc >= 6:
                        results.append((sc, desc, pt))
                        print(f"  [HIT] score={sc}: DiagStrip({nrows}x{ncols}, {direction}) {dec_name} key={key}")
                        print(f"         PT: {pt[:60]}...")

    elapsed2 = time.time() - t1
    print(f"\n  Phase 2: {phase2_configs} configs in {elapsed2:.1f}s")
    print(f"  Best so far: {best_overall} — {best_desc}")

    # ── Phase 3: Segmented Decimation (Z340-style) ────────────────────
    print("\n[Phase 3] Segmented decimation (Z340-style)")
    print("-" * 60)
    t2 = time.time()
    phase3_configs = 0

    # For each grid, try splitting into 2 and 3 horizontal segments
    for nrows, ncols, pad_len in GRID_DIMS:
        ct_padded = pad_ct(CT, pad_len)

        # Generate segment splits
        segment_splits = []
        # 2-segment splits
        for s1 in range(1, nrows):
            s2 = nrows - s1
            segment_splits.append([s1, s2])
        # 3-segment splits
        for s1 in range(1, nrows - 1):
            for s2 in range(1, nrows - s1):
                s3 = nrows - s1 - s2
                if s3 > 0:
                    segment_splits.append([s1, s2, s3])

        # Limit to manageable segment splits
        if len(segment_splits) > 50:
            # Sample: keep 2-splits and a subset of 3-splits
            two_splits = [s for s in segment_splits if len(s) == 2]
            three_splits = [s for s in segment_splits if len(s) == 3]
            import random
            random.seed(42)
            if len(three_splits) > 30:
                three_splits = random.sample(three_splits, 30)
            segment_splits = two_splits + three_splits

        # Also try vertical segment splits
        v_segment_splits = []
        for s1 in range(1, ncols):
            s2 = ncols - s1
            v_segment_splits.append([s1, s2])

        # Knight-move steps to try (the Z340 used (1,2))
        km_steps = [(1, 2), (2, 1), (1, 3), (3, 1), (1, 4), (4, 1),
                    (2, 3), (3, 2), (1, 1), (2, 2)]

        for segs in segment_splits:
            for dr, dc in km_steps:
                path = segmented_decimation(nrows, ncols, segs, dr, dc)
                perm = path_to_perm(path, nrows, ncols)
                # Remove duplicates and out-of-range
                seen = set()
                clean_perm = []
                for p in perm:
                    if p < pad_len and p not in seen:
                        clean_perm.append(p)
                        seen.add(p)

                if len(clean_perm) < N:
                    continue

                reordered = ''.join(ct_padded[p] for p in clean_perm[:pad_len])
                reordered_97 = reordered[:N]

                for key in KEYWORDS:
                    for dec_name, dec_fn in DECRYPT_FNS:
                        pt = dec_fn(reordered_97, key)
                        sc = score_candidate(pt)
                        phase3_configs += 1
                        total_configs += 1
                        if sc > best_overall:
                            best_overall = sc
                            desc = f"SegDec({nrows}x{ncols}, segs={segs}, dr={dr}, dc={dc}) {dec_name} key={key}"
                            best_desc = desc
                            best_pt = pt
                        if sc >= 6:
                            results.append((sc, desc, pt))
                            print(f"  [HIT] score={sc}: SegDec({nrows}x{ncols}, segs={segs}, dr={dr}, dc={dc}) {dec_name} key={key}")
                            print(f"         PT: {pt[:60]}...")

        # Vertical segments
        for segs in v_segment_splits[:10]:  # limit
            for dr, dc in km_steps:
                path = vertical_segment_decimation(nrows, ncols, segs, dr, dc)
                perm = path_to_perm(path, nrows, ncols)
                seen = set()
                clean_perm = []
                for p in perm:
                    if p < pad_len and p not in seen:
                        clean_perm.append(p)
                        seen.add(p)

                if len(clean_perm) < N:
                    continue

                reordered = ''.join(ct_padded[p] for p in clean_perm[:pad_len])
                reordered_97 = reordered[:N]

                for key in KEYWORDS:
                    for dec_name, dec_fn in DECRYPT_FNS:
                        pt = dec_fn(reordered_97, key)
                        sc = score_candidate(pt)
                        phase3_configs += 1
                        total_configs += 1
                        if sc > best_overall:
                            best_overall = sc
                            desc = f"VSegDec({nrows}x{ncols}, segs={segs}, dr={dr}, dc={dc}) {dec_name} key={key}"
                            best_desc = desc
                            best_pt = pt
                        if sc >= 6:
                            results.append((sc, desc, pt))
                            print(f"  [HIT] score={sc}: VSegDec({nrows}x{ncols}, segs={segs}, dr={dr}, dc={dc}) {dec_name} key={key}")
                            print(f"         PT: {pt[:60]}...")

    elapsed3 = time.time() - t2
    print(f"\n  Phase 3: {phase3_configs} configs in {elapsed3:.1f}s")
    print(f"  Best so far: {best_overall} — {best_desc}")

    # ── Phase 4: Multi-step decimation on raw 97 (prime) ──────────────
    print("\n[Phase 4] Multi-step decimation on 97 chars (no padding)")
    print("-" * 60)
    t3 = time.time()
    phase4_configs = 0

    # Double decimation: apply d1, then d2
    # Since 97 is prime, every d from 1-96 is coprime and generates a full cycle
    d_values = list(range(1, N))

    for d1 in d_values:
        for d2 in d_values:
            if d1 == d2:
                continue
            # Apply double decimation
            perm1 = [(j * d1) % N for j in range(N)]
            # Apply second decimation to result of first
            perm2 = [perm1[(j * d2) % N] for j in range(N)]

            reordered = ''.join(CT[p] for p in perm2)

            for key in KEYWORDS:
                for dec_name, dec_fn in DECRYPT_FNS:
                    pt = dec_fn(reordered, key)
                    sc = score_candidate(pt)
                    phase4_configs += 1
                    total_configs += 1
                    if sc > best_overall:
                        best_overall = sc
                        desc = f"DoubleDec(d1={d1}, d2={d2}) {dec_name} key={key}"
                        best_desc = desc
                        best_pt = pt
                    if sc >= 6:
                        results.append((sc, desc, pt))
                        print(f"  [HIT] score={sc}: DoubleDec(d1={d1}, d2={d2}) {dec_name} key={key}")
                        print(f"         PT: {pt[:60]}...")

            # Limit: only test first 20 d2 values per d1 with full keyword set
            # For remaining, only test HOROLOGE + KRYPTOS
            if d2 > 20:
                break

    elapsed4 = time.time() - t3
    print(f"\n  Phase 4: {phase4_configs} configs in {elapsed4:.1f}s")
    print(f"  Best so far: {best_overall} — {best_desc}")

    # ── Phase 5: K4 in the full 28x31 grid — diagonal reading ─────────
    print("\n[Phase 5] K4 positions in 28x31 master grid — diagonal/knight reading")
    print("-" * 60)
    t4 = time.time()
    phase5_configs = 0

    # K4 occupies rows 25-28 (0-indexed: 24-27) in the 28x31 grid
    # Row 25 (0-idx 24): cols 28-30 = "OBKR" (partial)
    # Actually, K4 starts at row 25, col 28 in 1-indexed terms
    # Let's use the known layout:
    # Row 25 (1-idx): ...OBKR (cols 28-31)
    # Row 26: UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO (cols 1-31, 31 chars but K4 portion = 31)
    # Row 27: TWTQSJQSSEKZZWATJKLUDIAWINFBNYP (31 chars)
    # Row 28: VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR (31 chars)

    # In 0-indexed 28x31 grid, K4 starts at position (24, 27) -> ?OBKR
    # This is complex. For now, test reading the 97 K4 chars as if they
    # were laid out across the full grid in various diagonal patterns.

    # Simplified: arrange K4 in rows of width 31 (like the sculpture)
    # K4 fits in: 4 chars on first row, 31 on second, 31 on third, 31 on fourth = 97
    # Grid: 4 rows, but first row only has 4 chars starting at col 27

    # Let's create a 4-row grid where:
    # row 0: [None]*27 + [O,B,K,R] (31 cols)
    # row 1: [U,O,X,...,O] (31 cols)
    # row 2: [T,W,T,...,P] (31 cols)
    # row 3: [V,T,T,...,R] (31 cols)

    NROWS_FULL = 4
    NCOLS_FULL = 31

    # Map CT positions to grid positions
    ct_grid_pos = {}  # grid (r,c) -> CT index
    ct_idx = 0
    # Row 0: positions 27-30
    for c in range(27, 31):
        ct_grid_pos[(0, c)] = ct_idx
        ct_idx += 1
    # Rows 1-3: full rows
    for r in range(1, 4):
        for c in range(31):
            ct_grid_pos[(r, c)] = ct_idx
            ct_idx += 1

    assert ct_idx == 97, f"Expected 97, got {ct_idx}"

    # Generate reading orders through occupied cells only
    occupied = sorted(ct_grid_pos.keys())

    # Diagonal readings
    for direction in ['tl_br', 'tr_bl', 'bl_tr', 'br_tl']:
        path = diagonal_strips(NROWS_FULL, NCOLS_FULL, direction)
        # Filter to only occupied cells
        filtered_path = [(r, c) for r, c in path if (r, c) in ct_grid_pos]
        reordered = ''.join(CT[ct_grid_pos[(r, c)]] for r, c in filtered_path)

        if len(reordered) != N:
            continue

        for key in KEYWORDS:
            for dec_name, dec_fn in DECRYPT_FNS:
                pt = dec_fn(reordered, key)
                sc = score_candidate(pt)
                phase5_configs += 1
                total_configs += 1
                if sc > best_overall:
                    best_overall = sc
                    desc = f"Grid31-Diag({direction}) {dec_name} key={key}"
                    best_desc = desc
                    best_pt = pt
                if sc >= 6:
                    results.append((sc, desc, pt))
                    print(f"  [HIT] score={sc}: Grid31-Diag({direction}) {dec_name} key={key}")
                    print(f"         PT: {pt[:60]}...")

    # Knight moves through occupied cells
    for dr in range(1, 4):
        for dc in range(1, 31):
            path = toroidal_walk(NROWS_FULL, NCOLS_FULL, dr, dc)
            filtered_path = [(r, c) for r, c in path if (r, c) in ct_grid_pos]
            if len(filtered_path) != N:
                continue
            reordered = ''.join(CT[ct_grid_pos[(r, c)]] for r, c in filtered_path)

            for key in KEYWORDS:
                for dec_name, dec_fn in DECRYPT_FNS:
                    pt = dec_fn(reordered, key)
                    sc = score_candidate(pt)
                    phase5_configs += 1
                    total_configs += 1
                    if sc > best_overall:
                        best_overall = sc
                        desc = f"Grid31-Knight(dr={dr},dc={dc}) {dec_name} key={key}"
                        best_desc = desc
                        best_pt = pt
                    if sc >= 6:
                        results.append((sc, desc, pt))
                        print(f"  [HIT] score={sc}: Grid31-Knight(dr={dr},dc={dc}) {dec_name} key={key}")
                        print(f"         PT: {pt[:60]}...")

    elapsed5 = time.time() - t4
    print(f"\n  Phase 5: {phase5_configs} configs in {elapsed5:.1f}s")

    # ── Summary ───────────────────────────────────────────────────────
    total_time = time.time() - t0
    print("\n" + "=" * 72)
    print(f"  SUMMARY — {EXPERIMENT_ID}")
    print("=" * 72)
    print(f"  Total configs tested: {total_configs}")
    print(f"  Total time: {total_time:.1f}s")
    print(f"  Best overall score: {best_overall}")
    print(f"  Best description: {best_desc}")
    if best_pt:
        print(f"  Best PT: {best_pt}")
    print()

    if results:
        print(f"  All hits (score >= 6):")
        results.sort(key=lambda x: -x[0])
        for sc, desc, pt in results[:20]:
            print(f"    score={sc}: {desc}")
            print(f"      PT: {pt[:70]}")
    else:
        print("  No hits above score 6.")

    print("\n[DONE]")


if __name__ == "__main__":
    main()
