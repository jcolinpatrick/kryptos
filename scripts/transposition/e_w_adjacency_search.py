#!/usr/bin/env python3
"""
W-Adjacency Transposition Search
=================================
Cipher: columnar, rail fence, serpentine, spiral
Family: transposition
Status: active
Keyspace: ~billions (exhaustive width≤8, sampled width 9-16, keyword width 17+)
Last run: never
Best score: n/a

Search ALL transposition types for column/row orders that maximize
W-adjacency (WW digraphs) after undoing the transposition on K4 CT.
"""

import sys
import os
import itertools
import random
import time
from math import factorial
from collections import defaultdict

# Import constants
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RANDOM_SEED = 42
SAMPLE_SIZE_W9_W16 = 500_000
TOP_N = 20

# Thematic keywords for keyword-derived permutations (width 17+)
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "UNDERDOG",
    "LUCID", "KOMPASS", "DEFECTOR", "COLOPHON", "ENIGMA",
    "BERLINCLOCK", "EASTNORTHEAST", "HOROLOGE", "QUAGMIRE",
    "VIGENERE", "BEAUFORT", "CIPHER", "SECRET", "HIDDEN",
    "COORDINATE", "COMPASS", "LODESTONE", "MAGNETIC", "INVISIBLE",
    "VIRTUALLY", "IMPOSSIBLE", "DESPERATE", "ILLUSION", "IQLUSION",
    "SLOWLY", "DIGETAL", "INTERPRET", "PASSAGE", "DARKNESS",
    "UNDERGROUND", "SCULPTURE", "LANGLEY", "INTELLIGENCE",
    "CRYPTOGRAPHY", "STEGANOGRAPHY", "TRANSPOSITION", "SUBSTITUTION",
    "SANBORN", "SCHEIDT", "CARTER", "HOWARD", "EGYPT",
    "TUTANKHAMUN", "PHARAOH", "TOMB", "PYRAMID", "SPHINX",
    "ANTIPODESANBORN", "VERDIGRIS", "FIVE", "CLOCK", "BERLIN",
    "NORTH", "EAST", "POINT", "MATRIX", "TABLEAU",
    "GRILLE", "CARDAN", "MASK", "NULL", "TELEGRAPH",
    "TELEGRAM", "WORLD", "TIME", "LIGHT", "WATER",
]

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def w_stats(text):
    """Compute W-adjacency statistics for a string."""
    w_positions = [i for i, c in enumerate(text) if c == 'W']
    if len(w_positions) == 0:
        return 0, len(text), False, w_positions

    # Count adjacent W pairs (WW digraphs)
    adj_pairs = 0
    for i in range(len(text) - 1):
        if text[i] == 'W' and text[i+1] == 'W':
            adj_pairs += 1

    # W-span
    span = w_positions[-1] - w_positions[0]

    # All 5 W's within contiguous window of ≤10 chars
    contiguous = (len(w_positions) == 5 and span <= 10)

    return adj_pairs, span, contiguous, w_positions


def columnar_undo(text, width, col_order):
    """Undo columnar transposition.
    col_order[i] = rank of column i (0-based).
    We read columns in rank order (0, 1, 2, ...).
    """
    n = len(text)
    nrows = (n + width - 1) // width
    remainder = n % width
    full_cols = remainder if remainder != 0 else width

    result = [''] * n
    pos = 0
    for rank in range(width):
        # Find which column has this rank
        col = col_order.index(rank)
        col_len = nrows if col < full_cols else nrows - 1
        for r in range(col_len):
            idx = r * width + col
            if idx < n:
                result[idx] = text[pos]
                pos += 1
    return ''.join(result)


def keyword_to_order(keyword, width):
    """Convert a keyword to a column order for a given width.
    Returns a list of length `width` where order[i] = rank of column i.
    If keyword is shorter than width, remaining columns get sequential ranks.
    For width > 26, we cycle through the keyword to fill remaining slots.
    """
    kw = keyword.upper()

    if len(kw) < width:
        # Extend by cycling keyword then appending alphabet
        extended = kw
        # First, try padding with unused letters
        used = set(kw)
        extras = [chr(c) for c in range(ord('A'), ord('Z')+1) if chr(c) not in used]
        extended = kw + ''.join(extras)
        # If still not enough, cycle with numeric suffixes (just use indices)
        if len(extended) < width:
            # Fall back: use keyword repeated then sequential
            extended = (kw * ((width // len(kw)) + 1))[:width]
        kw = extended[:width]
    else:
        kw = kw[:width]

    # Convert to ranks (alphabetical order, ties broken left-to-right)
    indexed = [(c, i) for i, c in enumerate(kw)]
    sorted_indexed = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, col) in enumerate(sorted_indexed):
        order[col] = rank
    return order


def rail_fence_undo(text, depth):
    """Undo rail fence cipher with given depth."""
    n = len(text)
    if depth <= 1 or depth >= n:
        return text

    # Build the rail pattern
    rails = [[] for _ in range(depth)]
    rail = 0
    direction = 1
    for i in range(n):
        rails[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == depth - 1:
            direction = -1
        rail += direction

    # Fill rails from ciphertext
    result = [''] * n
    pos = 0
    for rail_positions in rails:
        for idx in rail_positions:
            result[idx] = text[pos]
            pos += 1
    return ''.join(result)


def serpentine_h_perm(width, n):
    """Generate read-off permutation for horizontal serpentine (boustrophedon).
    Row 0: L→R, Row 1: R→L, Row 2: L→R, ...
    Returns perm where output[i] = input[perm[i]] for the ENCRYPTION direction.
    """
    nrows = (n + width - 1) // width
    perm = []
    for r in range(nrows):
        row_start = r * width
        row_end = min(row_start + width, n)
        row_indices = list(range(row_start, row_end))
        if r % 2 == 1:
            row_indices = row_indices[::-1]
        perm.extend(row_indices)
    return perm


def serpentine_v_perm(width, n):
    """Generate read-off permutation for vertical serpentine.
    Col 0: top→bottom, Col 1: bottom→top, Col 2: top→bottom, ...
    """
    nrows = (n + width - 1) // width
    perm = []
    for c in range(width):
        col_indices = []
        for r in range(nrows):
            idx = r * width + c
            if idx < n:
                col_indices.append(idx)
        if c % 2 == 1:
            col_indices = col_indices[::-1]
        perm.extend(col_indices)
    return perm


def spiral_cw_perm(width, n):
    """Generate read-off permutation for clockwise spiral read of a grid."""
    nrows = (n + width - 1) // width
    # Build grid indices
    grid = []
    for r in range(nrows):
        row = []
        for c in range(width):
            idx = r * width + c
            row.append(idx if idx < n else -1)
        grid.append(row)

    perm = []
    top, bottom, left, right = 0, nrows - 1, 0, width - 1
    while top <= bottom and left <= right:
        # Top row, left to right
        for c in range(left, right + 1):
            if grid[top][c] != -1:
                perm.append(grid[top][c])
        top += 1
        # Right column, top to bottom
        for r in range(top, bottom + 1):
            if r < nrows and right < width and grid[r][right] != -1:
                perm.append(grid[r][right])
        right -= 1
        # Bottom row, right to left
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if grid[bottom][c] != -1:
                    perm.append(grid[bottom][c])
            bottom -= 1
        # Left column, bottom to top
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if r < nrows and left < width and grid[r][left] != -1:
                    perm.append(grid[r][left])
            left += 1
    return perm


def spiral_ccw_perm(width, n):
    """Generate read-off permutation for counter-clockwise spiral."""
    nrows = (n + width - 1) // width
    grid = []
    for r in range(nrows):
        row = []
        for c in range(width):
            idx = r * width + c
            row.append(idx if idx < n else -1)
        grid.append(row)

    perm = []
    top, bottom, left, right = 0, nrows - 1, 0, width - 1
    while top <= bottom and left <= right:
        # Left column, top to bottom
        for r in range(top, bottom + 1):
            if r < nrows and left < width and grid[r][left] != -1:
                perm.append(grid[r][left])
        left += 1
        # Bottom row, left to right
        if top <= bottom:
            for c in range(left, right + 1):
                if grid[bottom][c] != -1:
                    perm.append(grid[bottom][c])
            bottom -= 1
        # Right column, bottom to top
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if r < nrows and right < width and grid[r][right] != -1:
                    perm.append(grid[r][right])
            right -= 1
        # Top row, right to left
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if grid[top][c] != -1:
                    perm.append(grid[top][c])
            top += 1
    return perm


def apply_inverse_perm(text, perm):
    """Apply inverse of permutation to text.
    If encryption was: ct[i] = pt[perm[i]], then decryption is: pt[perm[i]] = ct[i]
    i.e., pt[j] = ct[inv_perm[j]] where inv_perm[perm[i]] = i.
    """
    n = len(text)
    # Only use perm entries that are valid
    valid_perm = [p for p in perm if p < n]
    if len(valid_perm) != n:
        return None

    inv = [0] * n
    for i, p in enumerate(valid_perm):
        inv[p] = i

    result = [text[inv[j]] for j in range(n)]
    return ''.join(result)


# ---------------------------------------------------------------------------
# Main search
# ---------------------------------------------------------------------------

def main():
    ct = CT
    n = len(ct)
    print(f"K4 CT ({n} chars): {ct}")
    print(f"W positions in CT: {[i for i, c in enumerate(ct) if c == 'W']}")
    print()

    # Collect all results: (adj_pairs, span, contiguous, w_positions, trans_type, width, order_str, undone_text)
    results = []

    random.seed(RANDOM_SEED)
    t0 = time.time()

    # ===================================================================
    # 1. COLUMNAR TRANSPOSITION (width 3-48)
    # ===================================================================
    print("=" * 70)
    print("COLUMNAR TRANSPOSITION SEARCH")
    print("=" * 70)

    total_columnar = 0

    for width in range(3, 49):
        nperms = factorial(width)

        if width <= 8:
            # Exhaustive
            mode = "exhaustive"
            count = 0
            best_for_width = (0, n, False, [], None, "")

            for perm in itertools.permutations(range(width)):
                col_order = list(perm)
                undone = columnar_undo(ct, width, col_order)
                adj, span, contig, wpos = w_stats(undone)
                count += 1

                if adj > 0 or (span < 20):
                    results.append((adj, span, contig, wpos, "columnar", width, str(col_order), undone))

                if adj > best_for_width[0] or (adj == best_for_width[0] and span < best_for_width[1]):
                    best_for_width = (adj, span, contig, wpos, col_order, undone)

            total_columnar += count
            adj, span, contig, wpos, order, undone = best_for_width
            print(f"  Width {width:2d}: {count:>8d} perms (exhaustive) | best adj={adj}, span={span}, contig={contig}")

        elif width <= 16:
            # Random sampling
            mode = "sampled"
            count = 0
            best_for_width = (0, n, False, [], None, "")

            seen = set()
            attempts = 0
            target = min(SAMPLE_SIZE_W9_W16, nperms)

            while count < target and attempts < target * 3:
                perm = list(range(width))
                random.shuffle(perm)
                key = tuple(perm)
                if key in seen:
                    attempts += 1
                    continue
                seen.add(key)

                col_order = perm
                undone = columnar_undo(ct, width, col_order)
                adj, span, contig, wpos = w_stats(undone)
                count += 1
                attempts += 1

                if adj > 0 or (span < 20):
                    results.append((adj, span, contig, wpos, "columnar", width, str(col_order), undone))

                if adj > best_for_width[0] or (adj == best_for_width[0] and span < best_for_width[1]):
                    best_for_width = (adj, span, contig, wpos, col_order, undone)

            total_columnar += count
            adj, span, contig, wpos, order, undone = best_for_width
            print(f"  Width {width:2d}: {count:>8d} perms (sampled/{nperms:.1e}) | best adj={adj}, span={span}, contig={contig}")

        else:
            # Keyword-derived only
            mode = "keyword"
            count = 0
            best_for_width = (0, n, False, [], None, "")

            for kw in KEYWORDS:
                if len(kw) < width:
                    # Pad with identity for remaining columns
                    order = keyword_to_order(kw, width)
                else:
                    order = keyword_to_order(kw[:width], width)

                undone = columnar_undo(ct, width, order)
                adj, span, contig, wpos = w_stats(undone)
                count += 1

                if adj > 0 or (span < 20):
                    results.append((adj, span, contig, wpos, f"columnar(kw={kw})", width, str(order), undone))

                if adj > best_for_width[0] or (adj == best_for_width[0] and span < best_for_width[1]):
                    best_for_width = (adj, span, contig, wpos, order, undone)

                # Also try reverse order
                rev_order = [width - 1 - o for o in order]
                undone2 = columnar_undo(ct, width, rev_order)
                adj2, span2, contig2, wpos2 = w_stats(undone2)
                count += 1

                if adj2 > 0 or (span2 < 20):
                    results.append((adj2, span2, contig2, wpos2, f"columnar(kw={kw},rev)", width, str(rev_order), undone2))

                if adj2 > best_for_width[0] or (adj2 == best_for_width[0] and span2 < best_for_width[1]):
                    best_for_width = (adj2, span2, contig2, wpos2, rev_order, undone2)

            # Also try identity and reverse
            for label, order in [("identity", list(range(width))), ("reverse", list(range(width-1, -1, -1)))]:
                undone = columnar_undo(ct, width, order)
                adj, span, contig, wpos = w_stats(undone)
                count += 1
                if adj > 0 or (span < 20):
                    results.append((adj, span, contig, wpos, f"columnar({label})", width, str(order), undone))
                if adj > best_for_width[0] or (adj == best_for_width[0] and span < best_for_width[1]):
                    best_for_width = (adj, span, contig, wpos, order, undone)

            total_columnar += count
            adj, span, contig, wpos, order, undone = best_for_width
            if adj > 0 or span < 30:
                print(f"  Width {width:2d}: {count:>8d} perms (keyword) | best adj={adj}, span={span}, contig={contig}")

    t1 = time.time()
    print(f"\nColumnar total: {total_columnar:,} configs in {t1-t0:.1f}s")

    # ===================================================================
    # 2. RAIL FENCE (depth 2-20)
    # ===================================================================
    print("\n" + "=" * 70)
    print("RAIL FENCE SEARCH")
    print("=" * 70)

    for depth in range(2, 21):
        undone = rail_fence_undo(ct, depth)
        adj, span, contig, wpos = w_stats(undone)
        results.append((adj, span, contig, wpos, "rail_fence", depth, f"depth={depth}", undone))
        print(f"  Depth {depth:2d}: adj={adj}, span={span}, contig={contig}, W@{wpos}")

    # ===================================================================
    # 3. SERPENTINE / BOUSTROPHEDON (width 5-16)
    # ===================================================================
    print("\n" + "=" * 70)
    print("SERPENTINE SEARCH")
    print("=" * 70)

    for width in range(5, 17):
        # Horizontal serpentine
        perm = serpentine_h_perm(width, n)
        if len(perm) == n:
            undone = apply_inverse_perm(ct, perm)
            if undone:
                adj, span, contig, wpos = w_stats(undone)
                results.append((adj, span, contig, wpos, "serpentine_h", width, f"width={width}", undone))
                print(f"  Horiz width {width:2d}: adj={adj}, span={span}, contig={contig}, W@{wpos}")

            # Also try direct application (ct might BE the encryption output)
            direct = ''.join(ct[perm[i]] for i in range(n) if perm[i] < n)
            if len(direct) == n:
                adj2, span2, contig2, wpos2 = w_stats(direct)
                results.append((adj2, span2, contig2, wpos2, "serpentine_h(direct)", width, f"width={width}", direct))

        # Vertical serpentine
        perm = serpentine_v_perm(width, n)
        if len(perm) == n:
            undone = apply_inverse_perm(ct, perm)
            if undone:
                adj, span, contig, wpos = w_stats(undone)
                results.append((adj, span, contig, wpos, "serpentine_v", width, f"width={width}", undone))
                print(f"  Vert  width {width:2d}: adj={adj}, span={span}, contig={contig}, W@{wpos}")

            direct = ''.join(ct[perm[i]] for i in range(n) if perm[i] < n)
            if len(direct) == n:
                adj2, span2, contig2, wpos2 = w_stats(direct)
                results.append((adj2, span2, contig2, wpos2, "serpentine_v(direct)", width, f"width={width}", direct))

    # ===================================================================
    # 4. SPIRAL (width 5-16, CW and CCW)
    # ===================================================================
    print("\n" + "=" * 70)
    print("SPIRAL SEARCH")
    print("=" * 70)

    for width in range(5, 17):
        # Clockwise spiral
        perm = spiral_cw_perm(width, n)
        valid_perm = [p for p in perm if p < n]
        if len(valid_perm) == n and len(set(valid_perm)) == n:
            undone = apply_inverse_perm(ct, valid_perm)
            if undone:
                adj, span, contig, wpos = w_stats(undone)
                results.append((adj, span, contig, wpos, "spiral_cw", width, f"width={width}", undone))
                print(f"  CW  width {width:2d}: adj={adj}, span={span}, contig={contig}, W@{wpos}")

            direct = ''.join(ct[valid_perm[i]] for i in range(n))
            adj2, span2, contig2, wpos2 = w_stats(direct)
            results.append((adj2, span2, contig2, wpos2, "spiral_cw(direct)", width, f"width={width}", direct))

        # Counter-clockwise spiral
        perm = spiral_ccw_perm(width, n)
        valid_perm = [p for p in perm if p < n]
        if len(valid_perm) == n and len(set(valid_perm)) == n:
            undone = apply_inverse_perm(ct, valid_perm)
            if undone:
                adj, span, contig, wpos = w_stats(undone)
                results.append((adj, span, contig, wpos, "spiral_ccw", width, f"width={width}", undone))
                print(f"  CCW width {width:2d}: adj={adj}, span={span}, contig={contig}, W@{wpos}")

            direct = ''.join(ct[valid_perm[i]] for i in range(n))
            adj2, span2, contig2, wpos2 = w_stats(direct)
            results.append((adj2, span2, contig2, wpos2, "spiral_ccw(direct)", width, f"width={width}", direct))

    # ===================================================================
    # RESULTS
    # ===================================================================
    t2 = time.time()
    print(f"\nTotal time: {t2-t0:.1f}s")
    print(f"Total results collected: {len(results)}")

    # Sort: adjacent_pairs DESC, span ASC
    results.sort(key=lambda x: (-x[0], x[1]))

    # Check for 3+ adjacent pairs
    has_3plus = [r for r in results if r[0] >= 3]

    print("\n" + "=" * 70)
    print(f"TOP {TOP_N} RESULTS (by adjacent_pairs DESC, span ASC)")
    print("=" * 70)

    # Header
    print(f"{'Rank':>4} | {'Type':<25} | {'W':>3} | {'Order/Key':<30} | {'AdjP':>4} | {'Span':>4} | {'Cont':>5} | {'W positions':<25} | Text")
    print("-" * 180)

    seen_texts = set()
    printed = 0
    for i, (adj, span, contig, wpos, ttype, width, order_str, text) in enumerate(results):
        if text in seen_texts:
            continue
        seen_texts.add(text)
        printed += 1
        if printed > TOP_N:
            break

        # Truncate order string for display
        order_disp = order_str[:28] + ".." if len(order_str) > 30 else order_str
        wpos_str = str(wpos)
        contig_str = "YES" if contig else "no"

        print(f"{printed:>4} | {ttype:<25} | {width:>3} | {order_disp:<30} | {adj:>4} | {span:>4} | {contig_str:>5} | {wpos_str:<25} | {text}")

    # ===================================================================
    # Special analysis: 3+ adjacent pairs
    # ===================================================================
    print(f"\n{'=' * 70}")
    print(f"RESULTS WITH 3+ ADJACENT W PAIRS: {len(has_3plus)}")
    print(f"{'=' * 70}")

    if has_3plus:
        seen_texts2 = set()
        for adj, span, contig, wpos, ttype, width, order_str, text in has_3plus:
            if text in seen_texts2:
                continue
            seen_texts2.add(text)
            print(f"  {ttype} w={width}: adj={adj}, span={span}, contig={contig}")
            print(f"    Order: {order_str}")
            print(f"    W@: {wpos}")
            print(f"    Text: {text}")
            print()
    else:
        print("  None found.")

    # ===================================================================
    # Special analysis: contiguous window ≤10
    # ===================================================================
    contiguous_results = [r for r in results if r[2]]
    print(f"\n{'=' * 70}")
    print(f"RESULTS WITH ALL 5 W's IN ≤10-CHAR WINDOW: {len(contiguous_results)}")
    print(f"{'=' * 70}")

    if contiguous_results:
        seen_texts3 = set()
        for adj, span, contig, wpos, ttype, width, order_str, text in contiguous_results[:20]:
            if text in seen_texts3:
                continue
            seen_texts3.add(text)
            print(f"  {ttype} w={width}: adj={adj}, span={span}")
            print(f"    Order: {order_str}")
            print(f"    W@: {wpos}")
            print(f"    Text: {text}")
            print()
    else:
        print("  None found.")

    # ===================================================================
    # Summary statistics
    # ===================================================================
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print(f"{'=' * 70}")

    max_adj = results[0][0] if results else 0
    print(f"Maximum adjacent W pairs found: {max_adj}")

    adj_counts = defaultdict(int)
    for r in results:
        adj_counts[r[0]] += 1
    print("Distribution of adjacent pair counts:")
    for k in sorted(adj_counts.keys(), reverse=True):
        if k > 0 or adj_counts[k] < 100:
            print(f"  {k} adjacent pairs: {adj_counts[k]} configs")
        else:
            print(f"  {k} adjacent pairs: {adj_counts[k]} configs (only those with span<20 stored)")

    # Baseline
    print(f"\nBaseline (no transposition):")
    adj0, span0, contig0, wpos0 = w_stats(ct)
    print(f"  CT W positions: {wpos0}")
    print(f"  Adjacent pairs: {adj0}, Span: {span0}, Contiguous: {contig0}")


if __name__ == "__main__":
    main()
