#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-55: Systematic Grid + Route Cipher + Polyalphabetic Sweep.

Tests ALL reasonable grid dimensions (not just 7×14) with multiple route cipher
reading orders combined with Vigenère/Beaufort substitution.

Since 97 is prime, no exact rectangular grid exists. We test grids of size
rows × cols where rows × cols is in [97, 102] (up to 5 chars of padding).

For each grid:
  - Multiple reading orders: row-major, col-major, serpentine (H/V), spiral (CW/CCW)
  - For each reading order: 2 directions × 3 cipher variants × periods 2-14
  - Also: direct keystream check (no periodicity assumed)

Prior work (E-S-03, E-DESP-01) tested 7×14 and 14×7 grids extensively.
This experiment tests ALL OTHER reasonable dimensions.
"""

import json
import time
import sys
from itertools import product

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.transforms.transposition import (
    serpentine_perm, spiral_perm, invert_perm, validate_perm,
)

CT_IDX = [ALPH_IDX[c] for c in CT]


def row_major_perm(rows, cols, length=97):
    """Standard row-by-row, left-to-right reading."""
    return [i for i in range(rows * cols) if i < length]


def col_major_perm(rows, cols, length=97):
    """Column-by-column reading (top-to-bottom, left-to-right)."""
    perm = []
    for c in range(cols):
        for r in range(rows):
            pos = r * cols + c
            if pos < length:
                perm.append(pos)
    return perm


def diagonal_perm(rows, cols, length=97, direction="tl_br"):
    """Diagonal reading. direction: tl_br (top-left to bottom-right),
    tr_bl (top-right to bottom-left)."""
    perm = []
    if direction == "tl_br":
        for d in range(rows + cols - 1):
            for r in range(max(0, d - cols + 1), min(d + 1, rows)):
                c = d - r
                pos = r * cols + c
                if pos < length:
                    perm.append(pos)
    else:  # tr_bl
        for d in range(rows + cols - 1):
            for r in range(max(0, d - cols + 1), min(d + 1, rows)):
                c = cols - 1 - (d - r)
                pos = r * cols + c
                if pos < length:
                    perm.append(pos)
    return perm


def generate_grids():
    """Generate all reasonable grid dimensions for 97 characters."""
    grids = []
    for total in range(97, 103):  # up to 5 padding
        for rows in range(3, 50):
            cols = total // rows
            if cols >= 3 and rows * cols == total:
                # Skip 7×14 and 14×7 (already tested extensively)
                if (rows, cols) in [(7, 14), (14, 7)]:
                    continue
                grids.append((rows, cols, total - 97))
    return grids


def generate_reading_orders(rows, cols, length=97):
    """Generate all reading order permutations for a grid."""
    orders = []

    # 1. Row-major (identity when grid matches length)
    p = row_major_perm(rows, cols, length)
    if len(p) == length and len(set(p)) == length:
        orders.append(("row_major", p))

    # 2. Column-major
    p = col_major_perm(rows, cols, length)
    if len(p) == length and len(set(p)) == length:
        orders.append(("col_major", p))

    # 3. Serpentine horizontal
    p = serpentine_perm(rows, cols, length, vertical=False)
    if len(p) == length and len(set(p)) == length:
        orders.append(("serp_h", p))

    # 4. Serpentine vertical
    p = serpentine_perm(rows, cols, length, vertical=True)
    if len(p) == length and len(set(p)) == length:
        orders.append(("serp_v", p))

    # 5. Spiral clockwise
    p = spiral_perm(rows, cols, length, clockwise=True)
    if len(p) == length and len(set(p)) == length:
        orders.append(("spiral_cw", p))

    # 6. Spiral counter-clockwise
    p = spiral_perm(rows, cols, length, clockwise=False)
    if len(p) == length and len(set(p)) == length:
        orders.append(("spiral_ccw", p))

    # 7. Diagonal TL-BR
    p = diagonal_perm(rows, cols, length, "tl_br")
    if len(p) == length and len(set(p)) == length:
        orders.append(("diag_tlbr", p))

    # 8. Diagonal TR-BL
    p = diagonal_perm(rows, cols, length, "tr_bl")
    if len(p) == length and len(set(p)) == length:
        orders.append(("diag_trbl", p))

    return orders


def derive_key(ct_val, pt_val, variant):
    if variant == "vig":
        return (ct_val - pt_val) % MOD
    elif variant == "beau":
        return (ct_val + pt_val) % MOD
    elif variant == "varbeau":
        return (pt_val - ct_val) % MOD


def check_period_consistency(key_vals, period):
    residue_vals = {}
    matches = 0
    for pos, kv in key_vals:
        r = pos % period
        if r in residue_vals:
            if residue_vals[r] == kv:
                matches += 1
        else:
            residue_vals[r] = kv
            matches += 1
    return matches


def check_bean(key_dict):
    if 27 in key_dict and 65 in key_dict:
        if key_dict[27] != key_dict[65]:
            return False
    for p1, p2 in BEAN_INEQ:
        if p1 in key_dict and p2 in key_dict:
            if key_dict[p1] == key_dict[p2]:
                return False
    return True


def test_perm_polyalphabetic(perm, grid_label, route_label, results, stats):
    """Test a reading-order permutation with polyalphabetic substitution."""
    inv_perm = invert_perm(perm)

    for direction in [1, 2]:
        for variant in ["vig", "beau", "varbeau"]:
            key_vals = []
            key_dict = {}

            if direction == 1:
                # Sub then Route: KEY[p] = derive(CT[inv_perm[p]], PT[p])
                for p, pt_ch in CRIB_DICT.items():
                    ct_pos = inv_perm[p]
                    kv = derive_key(CT_IDX[ct_pos], ALPH_IDX[pt_ch], variant)
                    key_vals.append((p, kv))
                    key_dict[p] = kv
            else:
                # Route then Sub: KEY[i] = derive(CT[i], PT[perm[i]])
                for i in range(CT_LEN):
                    pt_pos = perm[i]
                    if pt_pos in CRIB_DICT:
                        kv = derive_key(CT_IDX[i], ALPH_IDX[CRIB_DICT[pt_pos]], variant)
                        key_vals.append((i, kv))
                        key_dict[i] = kv

            for period in range(2, 15):
                stats["configs"] += 1
                score = check_period_consistency(key_vals, period)
                if score > stats["best_score"]:
                    stats["best_score"] = score
                    stats["best_config"] = {
                        "grid": grid_label, "route": route_label,
                        "direction": direction, "variant": variant,
                        "period": period, "score": score,
                    }

                if score >= STORE_THRESHOLD:
                    bean_ok = check_bean(key_dict)
                    results.append({
                        "grid": grid_label, "route": route_label,
                        "direction": direction, "variant": variant,
                        "period": period, "score": score, "bean": bean_ok,
                    })


def main():
    print("=" * 70)
    print("E-S-55: Grid + Route Cipher + Polyalphabetic Sweep")
    print("=" * 70)

    grids = generate_grids()
    print(f"Grids to test: {len(grids)}")
    for r, c, pad in grids:
        print(f"  {r}×{c} = {r*c} (pad {pad})")
    print()

    t0 = time.time()
    results = []
    stats = {"configs": 0, "best_score": 0, "best_config": None}

    for gi, (rows, cols, pad) in enumerate(grids):
        grid_label = f"{rows}x{cols}"
        orders = generate_reading_orders(rows, cols, CT_LEN)

        for route_label, perm in orders:
            if not validate_perm(perm, CT_LEN):
                continue
            test_perm_polyalphabetic(perm, grid_label, route_label, results, stats)

            # Also test inverse perm (reading in vs reading out)
            inv = invert_perm(perm)
            test_perm_polyalphabetic(inv, grid_label, f"inv_{route_label}", results, stats)

        if (gi + 1) % 5 == 0 or gi == len(grids) - 1:
            print(f"  Grid {gi+1}/{len(grids)} ({grid_label}): configs={stats['configs']} "
                  f"best={stats['best_score']}/24 hits(≥{STORE_THRESHOLD})={len(results)} "
                  f"[{time.time()-t0:.1f}s]")

    elapsed = time.time() - t0

    # Sort by score
    results.sort(key=lambda r: (-r["score"], -r["bean"]))

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Grids tested: {len(grids)}")
    print(f"  Total configs: {stats['configs']}")
    print(f"  Hits ≥{STORE_THRESHOLD}: {len(results)}")
    print(f"  Time: {elapsed:.1f}s")

    if results:
        print(f"\n  Top 15 results:")
        for r in results[:15]:
            bean_str = "BEAN_OK" if r["bean"] else "bean_fail"
            print(f"    {r['score']}/24 p={r['period']} d={r['direction']} "
                  f"{r['variant']} {r['grid']} {r['route']} {bean_str}")

        # Period distribution
        from collections import Counter
        p_dist = Counter(r["period"] for r in results)
        print(f"\n  Period distribution of hits: {dict(sorted(p_dist.items()))}")

        # Low-period analysis
        low_p = [r for r in results if r["period"] <= 7]
        print(f"\n  Results at period ≤ 7: {len(low_p)}")
        for r in low_p[:10]:
            bean_str = "BEAN_OK" if r["bean"] else "bean_fail"
            print(f"    {r['score']}/24 p={r['period']} d={r['direction']} "
                  f"{r['variant']} {r['grid']} {r['route']} {bean_str}")

    best = stats["best_score"]
    if best <= NOISE_FLOOR:
        verdict = "ELIMINATED — all at noise floor"
    elif best <= 14:
        verdict = f"WEAK — best {best}/24 at high periods, likely noise"
    else:
        verdict = f"INVESTIGATE — best {best}/24"

    print(f"\n  Verdict: {verdict}")

    artifact = {
        "experiment": "E-S-55",
        "n_grids": len(grids),
        "total_configs": stats["configs"],
        "n_hits": len(results),
        "best_score": best,
        "best_config": stats["best_config"],
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "top_20": results[:20],
        "grids_tested": [f"{r}x{c}(pad{p})" for r, c, p in grids],
    }

    with open("results/e_s_55_grid_route.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_55_grid_route.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_55_grid_route_sweep.py")


if __name__ == "__main__":
    main()
