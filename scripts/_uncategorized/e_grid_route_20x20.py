#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRID-ROUTE-20x20: Exhaustive rectangular grid route analysis up to 20x20.

Enumerates ALL rectangular grids where rows*cols >= 97 with max dimension 20.
For each grid, reads off CT using 6 route families (both directions).
Scores every result with:
  - Anchored crib score (0-24)
  - English quadgram log-probability per character
Reports top 10 results per route type.

NOTE: Pure transposition is already ELIMINATED (CT has 2 E's, cribs need 3).
This is a confirmatory sweep + quadgram analysis to detect any grid geometry
that produces unusually English-like output (potential transposition layer clue).

Routes: row_major, column_major, spiral_cw, spiral_ccw, diagonal, boustrophedon
"""

import sys
import time
import json
import os
from collections import defaultdict

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, MOD,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR,
)
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.scoring.crib_score import score_cribs

# ── Grid enumeration ─────────────────────────────────────────────────────

MAX_DIM = 20

def enumerate_grids():
    """All (rows, cols) where rows*cols >= 97, both <= 20."""
    grids = []
    for r in range(1, MAX_DIM + 1):
        min_c = max(1, -(-CT_LEN // r))  # ceil(97/r)
        for c in range(min_c, MAX_DIM + 1):
            grids.append((r, c))
    return grids

# ── Route generators ─────────────────────────────────────────────────────

def route_row_major(rows, cols):
    """Standard row-by-row, left-to-right, top-to-bottom."""
    return [(r, c) for r in range(rows) for c in range(cols)]

def route_column_major(rows, cols):
    """Column-by-column, top-to-bottom, left-to-right."""
    return [(r, c) for c in range(cols) for r in range(rows)]

def route_spiral_cw(rows, cols):
    """Clockwise spiral from top-left corner inward."""
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
    return positions

def route_spiral_ccw(rows, cols):
    """Counter-clockwise spiral from top-left corner inward."""
    positions = []
    top, bottom, left, right = 0, rows - 1, 0, cols - 1
    while top <= bottom and left <= right:
        for r in range(top, bottom + 1):
            positions.append((r, left))
        left += 1
        if left <= right:
            for c in range(left, right + 1):
                positions.append((bottom, c))
            bottom -= 1
        if top <= bottom and left <= right:
            for r in range(bottom, top - 1, -1):
                positions.append((r, right))
            right -= 1
        if top <= bottom and left <= right:
            for c in range(right, left - 1, -1):
                positions.append((top, c))
            top += 1
    return positions

def route_diagonal(rows, cols):
    """Diagonal read: top-left to bottom-right diagonals."""
    positions = []
    for d in range(rows + cols - 1):
        for r in range(max(0, d - cols + 1), min(d + 1, rows)):
            c = d - r
            positions.append((r, c))
    return positions

def route_boustrophedon(rows, cols):
    """Boustrophedon (serpentine): alternating row direction."""
    positions = []
    for r in range(rows):
        if r % 2 == 0:
            for c in range(cols):
                positions.append((r, c))
        else:
            for c in range(cols - 1, -1, -1):
                positions.append((r, c))
    return positions

ROUTE_BUILDERS = {
    "row_major": route_row_major,
    "column_major": route_column_major,
    "spiral_cw": route_spiral_cw,
    "spiral_ccw": route_spiral_ccw,
    "diagonal": route_diagonal,
    "boustrophedon": route_boustrophedon,
}

# ── Grid transposition ───────────────────────────────────────────────────

def apply_route_forward(ct_padded, rows, cols, route_positions):
    """Write CT into grid row-by-row, read out via route.

    Models: encryptor wrote row-by-row, we read via route to recover order.
    """
    grid = [[None] * cols for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(ct_padded):
                grid[r][c] = ct_padded[idx]
            else:
                grid[r][c] = 'X'
            idx += 1
    result = []
    for r, c in route_positions:
        if 0 <= r < rows and 0 <= c < cols and grid[r][c] is not None:
            result.append(grid[r][c])
    return ''.join(result)

def apply_route_inverse(ct_padded, rows, cols, route_positions):
    """Write CT into grid via route order, read out row-by-row.

    Models: encryptor wrote via route, we read row-by-row to recover order.
    """
    grid = [[None] * cols for _ in range(rows)]
    for idx, (r, c) in enumerate(route_positions):
        if idx < len(ct_padded) and 0 <= r < rows and 0 <= c < cols:
            grid[r][c] = ct_padded[idx]
    result = []
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] is not None:
                result.append(grid[r][c])
    return ''.join(result)

# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("E-GRID-ROUTE-20x20: Exhaustive Grid Route Sweep")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print()

    # Load quadgram scorer
    scorer = get_default_scorer()
    print("Quadgram scorer loaded.")

    # Baseline: quadgram score of raw CT
    ct_qg = scorer.score_per_char(CT)
    print(f"Baseline CT quadgram/char: {ct_qg:.4f}")

    # Baseline: quadgram score of known English text of similar length
    english_sample = "ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESSITWASITWASIT"
    eng_qg = scorer.score_per_char(english_sample)
    print(f"Baseline English quadgram/char: {eng_qg:.4f}")

    # Random permutation baseline (10 samples)
    import random
    random.seed(42)
    rand_qg_samples = []
    ct_list = list(CT)
    for _ in range(100):
        random.shuffle(ct_list)
        rand_qg_samples.append(scorer.score_per_char(''.join(ct_list)))
    rand_qg_mean = sum(rand_qg_samples) / len(rand_qg_samples)
    rand_qg_max = max(rand_qg_samples)
    print(f"Random permutation quadgram/char: mean={rand_qg_mean:.4f}, max={rand_qg_max:.4f} (100 samples)")
    print()

    grids = enumerate_grids()
    print(f"Grid dimensions to test: {len(grids)}")
    print(f"Route types: {list(ROUTE_BUILDERS.keys())}")
    print(f"Directions: forward (write-row/read-route), inverse (write-route/read-row)")
    print(f"Pad character: X")
    print()

    # Results storage: per route type
    results_by_route = defaultdict(list)  # route_name -> [(score_tuple, config_dict), ...]

    total_tested = 0
    best_crib = 0
    best_qg = -999.0
    best_config_crib = ""
    best_config_qg = ""

    t0 = time.time()

    for gi, (rows, cols) in enumerate(grids):
        total_cells = rows * cols
        pad_needed = total_cells - CT_LEN
        ct_padded = CT + 'X' * pad_needed

        for route_name, route_builder in ROUTE_BUILDERS.items():
            route_positions = route_builder(rows, cols)
            assert len(route_positions) == total_cells, \
                f"{route_name} at {rows}x{cols}: got {len(route_positions)} positions, expected {total_cells}"

            for direction, apply_fn in [("forward", apply_route_forward), ("inverse", apply_route_inverse)]:
                candidate_full = apply_fn(ct_padded, rows, cols, route_positions)
                candidate = candidate_full[:CT_LEN]

                if len(candidate) < CT_LEN:
                    continue

                total_tested += 1

                # Score
                crib_sc = score_cribs(candidate)
                qg_sc = scorer.score_per_char(candidate)

                config = {
                    "grid": f"{rows}x{cols}",
                    "rows": rows,
                    "cols": cols,
                    "pad": pad_needed,
                    "route": route_name,
                    "direction": direction,
                    "crib_score": crib_sc,
                    "quadgram_per_char": round(qg_sc, 4),
                    "plaintext": candidate,
                }

                # Composite sort key: crib score primary, quadgram secondary
                sort_key = (crib_sc, qg_sc)
                results_by_route[route_name].append((sort_key, config))

                if crib_sc > best_crib:
                    best_crib = crib_sc
                    best_config_crib = f"{rows}x{cols} {route_name} {direction}"
                    print(f"  NEW BEST CRIB: {crib_sc}/{N_CRIBS} | {best_config_crib} | qg={qg_sc:.4f}")
                    if crib_sc >= 3:
                        print(f"    PT: {candidate[:60]}...")

                if qg_sc > best_qg:
                    best_qg = qg_sc
                    best_config_qg = f"{rows}x{cols} {route_name} {direction}"

        # Progress
        if (gi + 1) % 25 == 0 or gi == len(grids) - 1:
            elapsed = time.time() - t0
            print(f"  [{gi+1}/{len(grids)}] {total_tested:,} configs, "
                  f"best_crib={best_crib}/{N_CRIBS}, best_qg={best_qg:.4f}, "
                  f"{elapsed:.1f}s")

    elapsed = time.time() - t0

    # ── Results ──────────────────────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("RESULTS BY ROUTE TYPE (Top 10 each)")
    print(f"{'=' * 72}")

    all_top = []

    for route_name in ROUTE_BUILDERS:
        entries = results_by_route[route_name]
        entries.sort(key=lambda x: x[0], reverse=True)
        top10 = entries[:10]

        print(f"\n── {route_name.upper()} ──")
        print(f"  Total configs: {len(entries)}")
        if top10:
            print(f"  {'Rank':<5} {'Grid':<8} {'Dir':<9} {'Crib':<6} {'QG/char':<10} {'Plaintext (first 50)'}")
            print(f"  {'─'*5} {'─'*8} {'─'*9} {'─'*6} {'─'*10} {'─'*50}")
            for i, (sk, cfg) in enumerate(top10):
                print(f"  {i+1:<5} {cfg['grid']:<8} {cfg['direction']:<9} "
                      f"{cfg['crib_score']:<6} {cfg['quadgram_per_char']:<10.4f} "
                      f"{cfg['plaintext'][:50]}")
                all_top.append(cfg)

    # ── Global top 10 by crib score ──────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("GLOBAL TOP 10 BY CRIB SCORE")
    print(f"{'=' * 72}")
    all_entries = []
    for entries in results_by_route.values():
        all_entries.extend(entries)
    all_entries.sort(key=lambda x: x[0], reverse=True)

    for i, (sk, cfg) in enumerate(all_entries[:10]):
        print(f"  {i+1}. crib={cfg['crib_score']}/{N_CRIBS} qg={cfg['quadgram_per_char']:.4f} "
              f"| {cfg['grid']} {cfg['route']} {cfg['direction']}")
        print(f"     PT: {cfg['plaintext'][:70]}")

    # ── Global top 10 by quadgram ────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("GLOBAL TOP 10 BY QUADGRAM SCORE")
    print(f"{'=' * 72}")
    all_entries.sort(key=lambda x: x[0][1], reverse=True)  # sort by quadgram

    for i, (sk, cfg) in enumerate(all_entries[:10]):
        print(f"  {i+1}. qg={cfg['quadgram_per_char']:.4f} crib={cfg['crib_score']}/{N_CRIBS} "
              f"| {cfg['grid']} {cfg['route']} {cfg['direction']}")
        print(f"     PT: {cfg['plaintext'][:70]}")

    # ── Quadgram distribution ────────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("QUADGRAM STATISTICS")
    print(f"{'=' * 72}")
    all_qg = [x[0][1] for x in all_entries]
    all_qg.sort()
    n = len(all_qg)
    print(f"  Configs tested: {n}")
    print(f"  Quadgram/char range: [{all_qg[0]:.4f}, {all_qg[-1]:.4f}]")
    print(f"  Mean: {sum(all_qg)/n:.4f}")
    print(f"  Median: {all_qg[n//2]:.4f}")
    print(f"  P95: {all_qg[int(n*0.95)]:.4f}")
    print(f"  P99: {all_qg[int(n*0.99)]:.4f}")
    print(f"  Raw CT: {ct_qg:.4f}")
    print(f"  Random perm mean: {rand_qg_mean:.4f}")
    print(f"  Random perm max: {rand_qg_max:.4f}")
    print(f"  English baseline: {eng_qg:.4f}")

    # ── Crib score distribution ──────────────────────────────────────────
    from collections import Counter
    crib_dist = Counter(x[0][0] for x in all_entries)
    print(f"\n  Crib score distribution:")
    for sc in sorted(crib_dist.keys(), reverse=True):
        print(f"    score {sc}: {crib_dist[sc]} configs ({100*crib_dist[sc]/n:.1f}%)")

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'=' * 72}")
    print("FINAL SUMMARY")
    print(f"{'=' * 72}")
    print(f"Total configurations tested: {total_tested:,}")
    print(f"Best crib score: {best_crib}/{N_CRIBS}")
    print(f"Best crib config: {best_config_crib}")
    print(f"Best quadgram/char: {best_qg:.4f}")
    print(f"Best quadgram config: {best_config_qg}")
    print(f"Elapsed: {elapsed:.1f}s")

    threshold_qg = rand_qg_max + 0.5  # signal threshold: 0.5 above random max
    above_threshold = sum(1 for x in all_qg if x > threshold_qg)
    print(f"\nSignal check: configs with qg > {threshold_qg:.4f} (random_max + 0.5): {above_threshold}")

    if best_crib <= NOISE_FLOOR and best_qg < eng_qg * 0.7:
        verdict = "ALL NOISE — no grid route produces meaningful crib alignment or English-like text"
    elif best_crib > NOISE_FLOOR:
        verdict = f"MARGINAL CRIB SIGNAL at {best_config_crib}"
    else:
        verdict = "NOISE — quadgram scores indistinguishable from random permutations"

    print(f"\nVERDICT: {verdict}")
    print(f"\nNOTE: Pure transposition is already ELIMINATED (CT has 2 E's, cribs need 3).")
    print(f"This confirms: no rectangular grid route alone deciphers K4.")

    # ── Save results ─────────────────────────────────────────────────────
    os.makedirs("results", exist_ok=True)
    result = {
        "experiment": "E-GRID-ROUTE-20x20",
        "hypothesis": "Rectangular grid route transposition (6 routes, all grids up to 20x20)",
        "total_tested": total_tested,
        "best_crib_score": best_crib,
        "best_crib_config": best_config_crib,
        "best_quadgram_per_char": round(best_qg, 4),
        "best_quadgram_config": best_config_qg,
        "baselines": {
            "ct_quadgram": round(ct_qg, 4),
            "random_perm_mean": round(rand_qg_mean, 4),
            "random_perm_max": round(rand_qg_max, 4),
            "english_baseline": round(eng_qg, 4),
        },
        "grid_count": len(grids),
        "route_types": list(ROUTE_BUILDERS.keys()),
        "elapsed_seconds": round(elapsed, 1),
        "verdict": verdict,
        "top_by_crib": [
            {"crib": cfg["crib_score"], "qg": cfg["quadgram_per_char"],
             "grid": cfg["grid"], "route": cfg["route"], "dir": cfg["direction"],
             "pt": cfg["plaintext"]}
            for _, cfg in sorted(all_entries, key=lambda x: x[0], reverse=True)[:20]
        ],
        "top_by_quadgram": [
            {"crib": cfg["crib_score"], "qg": cfg["quadgram_per_char"],
             "grid": cfg["grid"], "route": cfg["route"], "dir": cfg["direction"],
             "pt": cfg["plaintext"]}
            for _, cfg in sorted(all_entries, key=lambda x: x[0][1], reverse=True)[:20]
        ],
    }
    out_path = "results/e_grid_route_20x20.json"
    with open(out_path, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
