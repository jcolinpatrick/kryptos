#!/usr/bin/env python3
"""
RS 44-style grid mask + keyed column reading for K4.

Cipher:  RS 44 variant (grid mask selects open cells, read by keyed column order)
Family:  grille
Status:  exhausted
Keyspace: ~50M+ configs (widths x masks x column orders x substitutions)
Last run: never
Best score: N/A

KEY INSIGHT: RS 44 FUSES mask + column reading into one operation. Prior null-mask
tests removed 24 nulls linearly, then applied columnar transposition separately.
RS 44 reads the open cells COLUMN-BY-COLUMN in keyed order -- this produces a
COMPLETELY DIFFERENT 73-char sequence than linear extraction + transposition.

This mechanism matches:
- Sanborn's 1994 "Kryptos Decoding Filter" (physical perforated stencil)
- Scheidt's confirmed use of steganography ("I used a bit of stego")
- TICOM RS 44 (German field cipher: grid stencil + keyed column reading)
- Hand-executable by non-mathematician (designed for field troops)
"""

import sys
import json
import time
import math
from pathlib import Path
from multiprocessing import Pool, cpu_count
from itertools import permutations

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_POSITIONS,
)

# ========================================================================
# RS 44 CORE OPERATIONS
# ========================================================================

def place_in_grid(text, width):
    """Place text into a grid of given width. Returns list of rows."""
    rows = math.ceil(len(text) / width)
    grid = []
    for r in range(rows):
        row = []
        for c in range(width):
            idx = r * width + c
            row.append(text[idx] if idx < len(text) else None)
        grid.append(row)
    return grid


def rs44_extract(ct, width, null_positions, col_order):
    """RS 44 extraction: place CT in grid, read open cells by keyed column order.

    Args:
        ct: ciphertext string (97 chars)
        width: grid width
        null_positions: set of positions (0-indexed in the flat CT) that are nulls
        col_order: list of column indices in reading order (e.g. [3,0,5,1,...])

    Returns:
        string of open-cell characters read column-by-column in col_order
    """
    n = len(ct)
    rows = math.ceil(n / width)
    result = []
    for col in col_order:
        for row in range(rows):
            pos = row * width + col
            if pos < n and pos not in null_positions:
                result.append(ct[pos])
    return ''.join(result)


def rs44_extract_precomputed(ct, extraction_indices):
    """Fast RS 44 extraction using precomputed index list."""
    return ''.join(ct[i] for i in extraction_indices)


def precompute_extraction(n, width, null_positions, col_order):
    """Precompute the flat indices for rs44_extract. Reusable across substitutions."""
    rows = math.ceil(n / width)
    indices = []
    for col in col_order:
        for row in range(rows):
            pos = row * width + col
            if pos < n and pos not in null_positions:
                indices.append(pos)
    return indices


# ========================================================================
# SUBSTITUTION DECRYPTION (inline for speed)
# ========================================================================

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}


def decrypt_text(ct_str, keyword, variant, alphabet):
    """Decrypt ct_str with keyword using variant cipher on alphabet."""
    alpha = ALPH if alphabet == "AZ" else KRYPTOS_ALPHABET
    aidx = ALPH_IDX if alphabet == "AZ" else KA_IDX
    klen = len(keyword)
    result = []
    for i, c in enumerate(ct_str):
        ci = aidx.get(c)
        ki = aidx.get(keyword[i % klen])
        if ci is None or ki is None:
            result.append('?')
            continue
        if variant == "beaufort":
            pi = (ki - ci) % 26
        elif variant == "vigenere":
            pi = (ci - ki) % 26
        else:  # var_beaufort
            pi = (ci + ki) % 26
        result.append(alpha[pi])
    return ''.join(result)


# ========================================================================
# SCORING (fast free-crib search)
# ========================================================================

ENE = "EASTNORTHEAST"
BC = "BERLINCLOCK"


def score_free(pt):
    """Fast free-crib score: check if ENE or BC appear anywhere as substrings."""
    s = 0
    if ENE in pt:
        s += 13
    if BC in pt:
        s += 11
    return s


def score_anchored(pt):
    """Anchored crib score at standard positions (for Model B: cribs in carved text)."""
    total = 0
    if len(pt) >= 34:
        for i, ch in enumerate(ENE):
            if 21 + i < len(pt) and pt[21 + i] == ch:
                total += 1
    if len(pt) >= 74:
        for i, ch in enumerate(BC):
            if 63 + i < len(pt) and pt[63 + i] == ch:
                total += 1
    return total


# ========================================================================
# PARAMETER SPACE
# ========================================================================

# Null palette: positions where CT char is in {B,G,I,K,O,W,Z}
NULL_PALETTE = frozenset("BGIKOWZ")
PALETTE_POSITIONS = frozenset(i for i, c in enumerate(CT) if c in NULL_PALETTE)
NON_PALETTE_POSITIONS = frozenset(range(CT_LEN)) - PALETTE_POSITIONS

# W positions (known delimiters)
W_POSITIONS = {20, 36, 48, 58, 74}

# Keywords to test
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "SEVEN", "BERLIN", "FIVE", "CLOCK",
    "EASTNORTHEAST", "BERLINCLOCK",
    "SANBORN", "SCHEIDT", "HAYDN",
]

# Substitution configs: (variant, keyword, alphabet)
SUB_CONFIGS = []
for kw in KEYWORDS:
    for variant in ["beaufort", "vigenere"]:
        for alpha in ["AZ", "KA"]:
            SUB_CONFIGS.append((variant, kw, alpha))

# Grid widths
WIDTHS = [7, 5, 8, 10, 11, 13, 14, 31]

# Column orders derived from keywords
def keyword_col_order(keyword, width):
    """Derive column reading order from keyword (VIC-style ranking)."""
    kw = keyword.upper()
    # Extend to at least width characters by cycling the alphabet
    while len(kw) < width:
        kw += ALPH
    kw = kw[:width]
    indexed = [(kw[i], i) for i in range(width)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    order = [x[1] for x in indexed]
    return order


COL_ORDER_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "BERLINCLOCK", "EASTNORTHEAST", "SANBORN", "SCHEIDT",
    "FIVE", "SEVEN", "NDYAHR", "HAYDN", "RHAYDN",
]


# ========================================================================
# MASK GENERATORS
# ========================================================================

def generate_palette_masks_random(n_masks=2000, seed=42):
    """Generate random masks where all 24 nulls are at palette positions."""
    import random
    rng = random.Random(seed)
    palette_list = sorted(PALETTE_POSITIONS - CRIB_POSITIONS)
    if len(palette_list) < 24:
        return []
    masks = set()
    for _ in range(n_masks * 5):
        chosen = tuple(sorted(rng.sample(palette_list, 24)))
        masks.add(chosen)
        if len(masks) >= n_masks:
            break
    return [frozenset(m) for m in masks]


def generate_w_anchored_masks(n_masks=1000, seed=123):
    """Generate masks with W positions always null, rest from palette."""
    import random
    rng = random.Random(seed)
    # W positions that are also palette positions
    w_palette = W_POSITIONS & PALETTE_POSITIONS
    remaining_palette = sorted((PALETTE_POSITIONS - CRIB_POSITIONS) - w_palette)
    needed = 24 - len(w_palette)
    if needed < 0 or len(remaining_palette) < needed:
        return []
    masks = set()
    base = frozenset(w_palette)
    for _ in range(n_masks * 5):
        extra = tuple(sorted(rng.sample(remaining_palette, needed)))
        masks.add(tuple(sorted(base | frozenset(extra))))
        if len(masks) >= n_masks:
            break
    return [frozenset(m) for m in masks]


def generate_even_spread_masks(width, n_masks=500, seed=456):
    """Generate masks where nulls are spread roughly evenly across columns."""
    import random
    rng = random.Random(seed)
    palette_list = sorted(PALETTE_POSITIONS - CRIB_POSITIONS)
    if len(palette_list) < 24:
        return []
    masks = set()
    for _ in range(n_masks * 10):
        # Try to spread nulls across columns
        by_col = {}
        for p in palette_list:
            c = p % width
            by_col.setdefault(c, []).append(p)
        # Target ~24/width nulls per column
        target = max(1, 24 // width)
        chosen = []
        cols = sorted(by_col.keys())
        rng.shuffle(cols)
        for c in cols:
            avail = by_col[c]
            take = min(target + rng.randint(0, 1), len(avail))
            chosen.extend(rng.sample(avail, take))
            if len(chosen) >= 24:
                break
        if len(chosen) >= 24:
            chosen = chosen[:24]
            masks.add(tuple(sorted(chosen)))
        if len(masks) >= n_masks:
            break
    return [frozenset(m) for m in masks]


# ========================================================================
# WORKER FUNCTION
# ========================================================================

def worker(args):
    """Process one (width, mask, col_order_set) combination."""
    width, mask_list, col_orders, sub_configs_chunk = args

    results = []
    configs = 0

    for mask in mask_list:
        null_set = set(mask)
        for col_order in col_orders:
            # Precompute extraction indices once per (mask, col_order)
            indices = precompute_extraction(CT_LEN, width, null_set, col_order)
            if len(indices) < 30:  # Too few open cells
                continue

            ct73 = rs44_extract_precomputed(CT, indices)

            for variant, keyword, alphabet in sub_configs_chunk:
                configs += 1
                pt = decrypt_text(ct73, keyword, variant, alphabet)

                # Free crib search (position-independent)
                fs = score_free(pt)
                if fs >= 11:
                    results.append({
                        'score': fs, 'mode': 'free',
                        'width': width, 'mask_size': len(mask),
                        'col_order': list(col_order),
                        'variant': variant, 'keyword': keyword,
                        'alphabet': alphabet,
                        'pt': pt[:80], 'pt_len': len(pt),
                        'open_cells': len(indices),
                    })

                # Also try identity sub (no decryption) — just the reordered CT
                if variant == "beaufort" and alphabet == "AZ" and keyword == "KRYPTOS":
                    # Test once: does the reordering alone place cribs?
                    fs_raw = score_free(ct73)
                    if fs_raw >= 11:
                        results.append({
                            'score': fs_raw, 'mode': 'raw_reorder',
                            'width': width, 'col_order': list(col_order),
                            'pt': ct73[:80], 'pt_len': len(ct73),
                            'open_cells': len(indices),
                        })

    return results, configs


# ========================================================================
# MAIN
# ========================================================================

def run():
    t0 = time.time()
    ncores = min(cpu_count(), 28)

    print("=" * 72)
    print("RS 44 GRID MASK + KEYED COLUMN READING")
    print("=" * 72)
    print(f"CT: {CT} ({CT_LEN} chars)")
    print(f"Palette positions: {len(PALETTE_POSITIONS)} (chars in {{B,G,I,K,O,W,Z}})")
    print(f"Crib positions: {len(CRIB_POSITIONS)}")
    print(f"Available palette (non-crib): {len(PALETTE_POSITIONS - CRIB_POSITIONS)}")
    print(f"Widths: {WIDTHS}")
    print(f"Keywords: {len(KEYWORDS)}")
    print(f"Sub configs: {len(SUB_CONFIGS)}")
    print(f"Cores: {ncores}")
    print(flush=True)

    all_results = []
    total_configs = 0

    for width in WIDTHS:
        wt0 = time.time()
        rows = math.ceil(CT_LEN / width)
        print(f"\n{'='*60}")
        print(f"WIDTH {width} ({rows} rows x {width} cols = {rows*width} cells)")
        print(f"{'='*60}", flush=True)

        # Generate masks
        masks_palette = generate_palette_masks_random(n_masks=1500, seed=width * 100)
        masks_w = generate_w_anchored_masks(n_masks=500, seed=width * 200)
        masks_spread = generate_even_spread_masks(width, n_masks=500, seed=width * 300)
        all_masks = list({tuple(sorted(m)) for m in masks_palette + masks_w + masks_spread})
        all_masks = [frozenset(m) for m in all_masks]
        print(f"  Masks: {len(all_masks)} ({len(masks_palette)} palette + {len(masks_w)} W-anchored + {len(masks_spread)} spread, deduped)")

        # Generate column orders
        col_orders = []
        # Ascending
        col_orders.append(tuple(range(width)))
        # Descending
        col_orders.append(tuple(range(width - 1, -1, -1)))
        # Keyword-derived
        for kw in COL_ORDER_KEYWORDS:
            order = keyword_col_order(kw, width)
            col_orders.append(tuple(order))
            # Also reversed
            col_orders.append(tuple(reversed(order)))
        # For small widths, enumerate all permutations
        if width <= 7:
            print(f"  Enumerating all {math.factorial(width)} column permutations for width {width}")
            for perm in permutations(range(width)):
                col_orders.append(perm)
        # Deduplicate
        col_orders = list(set(col_orders))
        print(f"  Column orders: {len(col_orders)}")

        est_configs = len(all_masks) * len(col_orders) * len(SUB_CONFIGS)
        print(f"  Estimated configs: {est_configs:,}")

        # Build work items — split masks across workers
        batch_size = max(1, len(all_masks) // (ncores * 4))
        work_items = []
        for i in range(0, len(all_masks), batch_size):
            mask_batch = all_masks[i:i + batch_size]
            work_items.append((width, mask_batch, col_orders, SUB_CONFIGS))

        print(f"  Work items: {len(work_items)} batches")
        print(f"  Running...", flush=True)

        width_configs = 0
        width_results = []

        with Pool(ncores) as pool:
            for batch_results, batch_configs in pool.imap_unordered(worker, work_items, chunksize=1):
                width_results.extend(batch_results)
                width_configs += batch_configs

        total_configs += width_configs
        all_results.extend(width_results)

        wt = time.time() - wt0
        best_w = max((r['score'] for r in width_results), default=0)
        print(f"  Done: {width_configs:,} configs, {len(width_results)} hits, best={best_w}/24, {wt:.1f}s")

    elapsed = time.time() - t0

    # Sort results
    all_results.sort(key=lambda r: r['score'], reverse=True)

    # Summary
    print()
    print("=" * 72)
    print("RESULTS")
    print("=" * 72)
    print(f"Total configs: {total_configs:,}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/60:.1f}m)")
    print(f"Results with full crib match: {len(all_results)}")

    best_score = all_results[0]['score'] if all_results else 0
    print(f"Best score: {best_score}/24")

    if all_results:
        print(f"\nTop 30:")
        for i, r in enumerate(all_results[:30]):
            print(f"  {i+1:3d}. {r['score']:2d}/24 | w={r['width']} {r['mode']} "
                  f"| {r.get('variant','')}/{r.get('keyword','')} "
                  f"| open={r.get('open_cells','')} "
                  f"| PT: {r['pt'][:50]}")

    verdict = "SIGNAL" if best_score >= 18 else ("BREAKTHROUGH" if best_score >= 24 else "NOISE")
    print(f"\nVERDICT: {verdict}")

    # Save
    out_path = Path(__file__).resolve().parents[2] / "results" / "e_rs44_grid_mask_v1.json"
    import os; os.makedirs(out_path.parent, exist_ok=True)
    output = {
        'experiment': 'e_rs44_grid_mask_v1',
        'description': 'RS 44-style grid mask + keyed column reading (TICOM-inspired)',
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_configs': total_configs,
        'elapsed_seconds': round(elapsed, 1),
        'widths_tested': WIDTHS,
        'n_keywords': len(KEYWORDS),
        'n_sub_configs': len(SUB_CONFIGS),
        'best_score': best_score,
        'verdict': verdict,
        'top_50': all_results[:50],
    }
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nSaved: {out_path}")


if __name__ == "__main__":
    run()
