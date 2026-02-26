#!/usr/bin/env python3
"""E-ROMAN-04b: ABSCISSA=x-coordinate Hypothesis (addendum to E-ROMAN-04).

Insight: ABSCISSA literally means "x-coordinate." The three K1-K3 answer words
may each define a "threading string" / coordinate addressing:
  - ABSCISSA → x-coordinate (column addressing)
  - PALIMPSEST → y-coordinate (row addressing / depth)
  - KRYPTOS → z-coordinate or substitution alphabet

Tests:
  Part 4: ABSCISSA-dimensioned grids (dim=8 variants)
  Part 5: Targeted collar model (ABSCISSA=x, PALIMPSEST=y, KRYPTOS=z)
  Part 6: ABSCISSA-mod-width column read ordering
  Part 7: All 6 keyword-to-axis assignments with exhaustive sub/direction combos
"""
import json
import itertools
import os
import sys
import time

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, CRIB_DICT
from kryptos.kernel.scoring.crib_score import score_cribs


# ── Cipher helpers ──

def vig_decrypt(ct, key_vals):
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def beau_decrypt(ct, key_vals):
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


def vb_decrypt(ct, key_vals):
    """Variant Beaufort: PT = (CT - KEY) mod 26 reversed = (KEY + CT) ... no.
    Variant Beaufort: K = (PT - CT) mod 26, so PT = (K + CT) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ki + ci) % 26])
    return ''.join(pt)


def keyword_to_vals(kw):
    return [ALPH_IDX[c] for c in kw.upper()]


# ── Core keywords and their letter values ──

KW_ABSCISSA = "ABSCISSA"
KW_PALIMPSEST = "PALIMPSEST"
KW_KRYPTOS = "KRYPTOS"

VALS_ABSCISSA = keyword_to_vals(KW_ABSCISSA)      # [0,1,18,2,8,18,18,0]
VALS_PALIMPSEST = keyword_to_vals(KW_PALIMPSEST)  # [15,0,11,8,12,15,18,4,18,19]
VALS_KRYPTOS = keyword_to_vals(KW_KRYPTOS)        # [10,17,24,15,19,14,18]

# All keywords for substitution
ALL_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "CARTER",
    "HERBERT", "LABORATORY", "TUTANKHAMUN", "DISCOVERY",
]
ALL_KW_VALS = {kw: keyword_to_vals(kw) for kw in ALL_KEYWORDS}

# The three "threading" keywords
THREE_KWS = [KW_ABSCISSA, KW_PALIMPSEST, KW_KRYPTOS]
THREE_VALS = {KW_ABSCISSA: VALS_ABSCISSA, KW_PALIMPSEST: VALS_PALIMPSEST, KW_KRYPTOS: VALS_KRYPTOS}

# ABSCISSA-dimensioned grids (one dim = 8 = len(ABSCISSA))
ABSCISSA_DIMS = [
    (8, 13, 1),  # 104, pad 7 (degenerate z=1 but still valid 3D addressing)
    (8, 7, 2),   # 112, pad 15
    (8, 5, 3),   # 120, pad 23
    (8, 4, 4),   # 128, pad 31
    (13, 8, 1),  # 104
    (7, 8, 2),   # 112
    (5, 8, 3),   # 120
    (4, 8, 4),   # 128
    (1, 8, 13),  # 104
    (2, 8, 7),   # 112
    (3, 8, 5),   # 120
    (4, 4, 8),   # 128
]

# Also KRYPTOS-length dim (7) x PALIMPSEST-length dim (10)
SEMANTIC_DIMS = [
    (7, 10, 2),  # 140, pad 43  (KRYPTOS × PALIMPSEST × 2)
    (10, 7, 2),  # 140
    (2, 7, 10),  # 140
    (2, 10, 7),  # 140
    (7, 2, 10),  # 140
    (10, 2, 7),  # 140
    (8, 10, 2),  # 160 (ABSCISSA × PALIMPSEST × 2)
    (8, 7, 2),   # 112 (ABSCISSA × KRYPTOS × 2) - already in ABSCISSA_DIMS
    (7, 10, 1),  # 70 < 97, skip
]
# Filter to product >= 97
SEMANTIC_DIMS = [d for d in SEMANTIC_DIMS if d[0]*d[1]*d[2] >= 97]

ALL_DIMS = list(set(ABSCISSA_DIMS + SEMANTIC_DIMS))

AXIS_PERMS = list(itertools.permutations(range(3)))
DIR_COMBOS = list(itertools.product([False, True], repeat=3))


def fill_3d_grid(text, d1, d2, d3, pad_char='X'):
    total = d1 * d2 * d3
    padded = text + pad_char * (total - len(text))
    grid = [[[' ' for _ in range(d3)] for _ in range(d2)] for _ in range(d1)]
    idx = 0
    for i in range(d1):
        for j in range(d2):
            for k in range(d3):
                grid[i][j][k] = padded[idx]
                idx += 1
    return grid


def read_3d_grid(grid, d1, d2, d3, axis_perm, directions, ct_len):
    dims = [d1, d2, d3]
    ranges = []
    for ax in range(3):
        r = list(range(dims[ax]))
        if directions[ax]:
            r = r[::-1]
        ranges.append(r)
    result = []
    for a in ranges[axis_perm[0]]:
        for b in ranges[axis_perm[1]]:
            for c in ranges[axis_perm[2]]:
                coords = [0, 0, 0]
                coords[axis_perm[0]] = a
                coords[axis_perm[1]] = b
                coords[axis_perm[2]] = c
                result.append(grid[coords[0]][coords[1]][coords[2]])
                if len(result) >= ct_len:
                    return ''.join(result[:ct_len])
    return ''.join(result[:ct_len])


def keyword_order(keyword_vals, dim_size):
    """Column-ordering permutation from keyword values (cycling as needed)."""
    assignments = [(keyword_vals[i % len(keyword_vals)], i) for i in range(dim_size)]
    assignments.sort()
    return [pos for _, pos in assignments]


def fill_3d_grid_keyword(text, d1, d2, d3, kv1, kv2, kv3, pad_char='X'):
    """Fill using keyword-derived orderings along each dimension."""
    total = d1 * d2 * d3
    padded = text + pad_char * (total - len(text))
    order1 = keyword_order(kv1, d1)
    order2 = keyword_order(kv2, d2)
    order3 = keyword_order(kv3, d3)
    grid = [[[' ' for _ in range(d3)] for _ in range(d2)] for _ in range(d1)]
    idx = 0
    for i in order1:
        for j in order2:
            for k in order3:
                grid[i][j][k] = padded[idx]
                idx += 1
    return grid


def collar_model(ct_text, d1, d2, d3, kv1, kv2, kv3, ct_len):
    """Three independent keyword streams select (z,y,x) coordinates."""
    total = d1 * d2 * d3
    padded = ct_text + 'X' * (total - len(ct_text))
    grid = [[[' ' for _ in range(d3)] for _ in range(d2)] for _ in range(d1)]
    idx = 0
    for i in range(d1):
        for j in range(d2):
            for k in range(d3):
                grid[i][j][k] = padded[idx]
                idx += 1

    result = []
    for i in range(ct_len):
        z = kv1[i % len(kv1)] % d1
        y = kv2[i % len(kv2)] % d2
        x = kv3[i % len(kv3)] % d3
        result.append(grid[z][y][x])
    return ''.join(result)


def abscissa_column_read(ct_text, width, kv_abscissa):
    """Write CT into rows of given width, read columns in ABSCISSA-value order.

    ABSCISSA values mod width determine column read order.
    """
    nrows = (len(ct_text) + width - 1) // width
    padded = ct_text + 'X' * (nrows * width - len(ct_text))
    # Build grid
    grid = []
    for r in range(nrows):
        grid.append(list(padded[r*width:(r+1)*width]))

    # Column order from ABSCISSA values mod width
    col_order_raw = [v % width for v in kv_abscissa]
    # Deduplicate while preserving order, then append remaining columns
    seen = set()
    col_order = []
    for c in col_order_raw:
        if c not in seen:
            col_order.append(c)
            seen.add(c)
    for c in range(width):
        if c not in seen:
            col_order.append(c)
            seen.add(c)

    result = []
    for c in col_order:
        for r in range(nrows):
            result.append(grid[r][c])
    return ''.join(result)[:len(ct_text)]


def evaluate(candidate, config_desc, best, results_store):
    if len(candidate) < CT_LEN:
        return best
    sc = score_cribs(candidate[:CT_LEN])
    if sc > best['score']:
        best = {'score': sc, 'config': config_desc, 'plaintext': candidate[:CT_LEN]}
    if sc >= 7:
        results_store.append({'score': sc, 'config': config_desc, 'pt_snippet': candidate[:40]})
    return best


def main():
    t0 = time.time()
    best = {'score': 0, 'config': '', 'plaintext': ''}
    stored = []
    total_configs = 0

    # Build substitution modes
    sub_modes = [('identity', None, None)]
    for kw in ALL_KEYWORDS:
        sub_modes.append(('vig_' + kw, 'vig', ALL_KW_VALS[kw]))
        sub_modes.append(('beau_' + kw, 'beau', ALL_KW_VALS[kw]))
        sub_modes.append(('vb_' + kw, 'vb', ALL_KW_VALS[kw]))

    def apply_sub(text, mode, key_vals):
        if mode is None:
            return text
        elif mode == 'vig':
            return vig_decrypt(text, key_vals)
        elif mode == 'beau':
            return beau_decrypt(text, key_vals)
        elif mode == 'vb':
            return vb_decrypt(text, key_vals)
        return text

    # ═══════════════════════════════════════════════════════════════════
    # Part 4: ABSCISSA-dimensioned grids (sequential + keyword fill)
    # ═══════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PART 4: ABSCISSA-dimensioned 3D grids")
    print(f"  Dimensions: {len(ALL_DIMS)} triples")
    print(f"  Sub modes: {len(sub_modes)}")
    print("=" * 70)

    part4_configs = 0
    for dims in ALL_DIMS:
        d1, d2, d3 = dims
        # 4a: Sequential fill, all 48 read patterns, all subs
        for pad_char in ['X', 'A']:
            grid = fill_3d_grid(CT, d1, d2, d3, pad_char)
            for axis_perm in AXIS_PERMS:
                for dir_combo in DIR_COMBOS:
                    transposed = read_3d_grid(grid, d1, d2, d3, axis_perm, dir_combo, CT_LEN)
                    for sub_name, sub_mode, sub_key in sub_modes:
                        candidate = apply_sub(transposed, sub_mode, sub_key)
                        desc = f"P4a:dims={dims},pad={pad_char},ax={axis_perm},dir={dir_combo},sub={sub_name}"
                        best = evaluate(candidate, desc, best, stored)
                        part4_configs += 1

        # 4b: Keyword-ordered fill with all 6 permutations of (ABSCISSA, PALIMPSEST, KRYPTOS)
        for perm in itertools.permutations(THREE_KWS):
            kv1, kv2, kv3 = THREE_VALS[perm[0]], THREE_VALS[perm[1]], THREE_VALS[perm[2]]
            grid = fill_3d_grid_keyword(CT, d1, d2, d3, kv1, kv2, kv3, 'X')
            for axis_perm in AXIS_PERMS:
                for dir_combo in DIR_COMBOS:
                    transposed = read_3d_grid(grid, d1, d2, d3, axis_perm, dir_combo, CT_LEN)
                    for sub_name, sub_mode, sub_key in sub_modes:
                        candidate = apply_sub(transposed, sub_mode, sub_key)
                        desc = f"P4b:dims={dims},fill=({perm[0]},{perm[1]},{perm[2]}),ax={axis_perm},dir={dir_combo},sub={sub_name}"
                        best = evaluate(candidate, desc, best, stored)
                        part4_configs += 1

        print(f"  P4 dims={dims}: {part4_configs:,} configs, best: {best['score']}/24")
        sys.stdout.flush()

    total_configs += part4_configs
    print(f"  Part 4 done: {part4_configs:,} configs, best: {best['score']}/24")
    print(f"  Time: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════
    # Part 5: Targeted Collar Model — ABSCISSA=x, PALIMPSEST=y, KRYPTOS=z
    # All 6 keyword-to-axis assignments
    # ═══════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PART 5: Targeted Collar Model (all keyword-axis assignments)")
    print("=" * 70)

    part5_configs = 0
    for dims in ALL_DIMS:
        d1, d2, d3 = dims
        # All 6 permutations of which keyword controls which axis
        for perm in itertools.permutations(THREE_KWS):
            kv_z, kv_y, kv_x = THREE_VALS[perm[0]], THREE_VALS[perm[1]], THREE_VALS[perm[2]]
            transposed = collar_model(CT, d1, d2, d3, kv_z, kv_y, kv_x, CT_LEN)
            for sub_name, sub_mode, sub_key in sub_modes:
                candidate = apply_sub(transposed, sub_mode, sub_key)
                desc = f"P5:dims={dims},z={perm[0]},y={perm[1]},x={perm[2]},sub={sub_name}"
                best = evaluate(candidate, desc, best, stored)
                part5_configs += 1

        # Also try with reversed keyword values (read keyword backwards)
        for perm in itertools.permutations(THREE_KWS):
            kv_z = list(reversed(THREE_VALS[perm[0]]))
            kv_y = list(reversed(THREE_VALS[perm[1]]))
            kv_x = list(reversed(THREE_VALS[perm[2]]))
            transposed = collar_model(CT, d1, d2, d3, kv_z, kv_y, kv_x, CT_LEN)
            for sub_name, sub_mode, sub_key in sub_modes:
                candidate = apply_sub(transposed, sub_mode, sub_key)
                desc = f"P5r:dims={dims},z=rev({perm[0]}),y=rev({perm[1]}),x=rev({perm[2]}),sub={sub_name}"
                best = evaluate(candidate, desc, best, stored)
                part5_configs += 1

    total_configs += part5_configs
    print(f"  Part 5 done: {part5_configs:,} configs, best: {best['score']}/24")
    print(f"  Time: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════
    # Part 6: ABSCISSA-mod-width Column Read Ordering
    # ═══════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PART 6: ABSCISSA-mod-width Column Read Ordering")
    print("=" * 70)

    part6_configs = 0
    # Test widths 3-20
    for width in range(3, 21):
        # Use ABSCISSA values as column ordering
        transposed = abscissa_column_read(CT, width, VALS_ABSCISSA)
        for sub_name, sub_mode, sub_key in sub_modes:
            candidate = apply_sub(transposed, sub_mode, sub_key)
            desc = f"P6a:w={width},col_key=ABSCISSA,sub={sub_name}"
            best = evaluate(candidate, desc, best, stored)
            part6_configs += 1

        # Also try PALIMPSEST and KRYPTOS as column ordering
        for kw_name, kv in [("PALIMPSEST", VALS_PALIMPSEST), ("KRYPTOS", VALS_KRYPTOS)]:
            transposed = abscissa_column_read(CT, width, kv)
            for sub_name, sub_mode, sub_key in sub_modes:
                candidate = apply_sub(transposed, sub_mode, sub_key)
                desc = f"P6a:w={width},col_key={kw_name},sub={sub_name}"
                best = evaluate(candidate, desc, best, stored)
                part6_configs += 1

        # Reverse read: read columns bottom-to-top
        nrows = (CT_LEN + width - 1) // width
        padded = CT + 'X' * (nrows * width - CT_LEN)
        grid = []
        for r in range(nrows):
            grid.append(list(padded[r*width:(r+1)*width]))

        for kw_name, kv in [("ABSCISSA", VALS_ABSCISSA), ("PALIMPSEST", VALS_PALIMPSEST), ("KRYPTOS", VALS_KRYPTOS)]:
            col_order_raw = [v % width for v in kv]
            seen = set()
            col_order = []
            for c in col_order_raw:
                if c not in seen:
                    col_order.append(c)
                    seen.add(c)
            for c in range(width):
                if c not in seen:
                    col_order.append(c)
                    seen.add(c)

            # Bottom-to-top read
            result = []
            for c in col_order:
                for r in range(nrows - 1, -1, -1):
                    result.append(grid[r][c])
            transposed = ''.join(result)[:CT_LEN]

            for sub_name, sub_mode, sub_key in sub_modes:
                candidate = apply_sub(transposed, sub_mode, sub_key)
                desc = f"P6b:w={width},col_key={kw_name},rev_rows,sub={sub_name}"
                best = evaluate(candidate, desc, best, stored)
                part6_configs += 1

    total_configs += part6_configs
    print(f"  Part 6 done: {part6_configs:,} configs, best: {best['score']}/24")
    print(f"  Time: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════
    # Part 7: Combined keyword fill + keyword read with all substitutions
    # Focus on "semantically correct" assignments:
    # ABSCISSA controls columns (x), PALIMPSEST controls rows (y),
    # KRYPTOS controls pages/depth (z)
    # ═══════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PART 7: Semantic Assignment — ABSCISSA=col, PALIMPSEST=row, KRYPTOS=depth")
    print("=" * 70)

    part7_configs = 0
    # Use keyword lengths as dimension hints
    # ABSCISSA=8 (columns), PALIMPSEST=10 (rows), KRYPTOS=7 (depth)
    SEMANTIC_GRIDS = [
        (7, 10, 8),   # z=KRYPTOS(7), y=PALIMPSEST(10), x=ABSCISSA(8) → 560
        (7, 8, 10),   # 560
        (10, 7, 8),   # 560
        (10, 8, 7),   # 560
        (8, 7, 10),   # 560
        (8, 10, 7),   # 560
        # Smaller: use keyword lengths mod smaller dims
        (7, 10, 2),   # 140
        (7, 8, 2),    # 112
        (8, 10, 2),   # 160
        (10, 10, 1),  # 100
        (8, 13, 1),   # 104
        (7, 14, 1),   # 98
        (10, 10, 2),  # 200
    ]

    for dims in SEMANTIC_GRIDS:
        d1, d2, d3 = dims
        if d1 * d2 * d3 < CT_LEN:
            continue

        # Try all 6 keyword-to-axis assignments for fill ordering
        for fill_perm in itertools.permutations(THREE_KWS):
            fv1, fv2, fv3 = THREE_VALS[fill_perm[0]], THREE_VALS[fill_perm[1]], THREE_VALS[fill_perm[2]]
            grid = fill_3d_grid_keyword(CT, d1, d2, d3, fv1, fv2, fv3, 'X')

            # Try all 6 keyword-to-axis assignments for read ordering
            for read_perm in itertools.permutations(THREE_KWS):
                # Use read keyword values to determine axis traversal order
                # The keyword with smallest average value goes first (outermost loop)
                # This gives a data-driven axis ordering
                avg_vals = []
                for kw in read_perm:
                    kv = THREE_VALS[kw]
                    avg_vals.append(sum(kv) / len(kv))

                # Also try all 48 standard read patterns
                for axis_perm in AXIS_PERMS:
                    for dir_combo in DIR_COMBOS:
                        transposed = read_3d_grid(grid, d1, d2, d3, axis_perm, dir_combo, CT_LEN)
                        # Test identity + the three threading keywords as subs
                        for sub_name, sub_mode, sub_key in sub_modes[:7]:  # id + vig/beau for 3 core kws
                            candidate = apply_sub(transposed, sub_mode, sub_key)
                            desc = f"P7:dims={dims},fill=({fill_perm[0]},{fill_perm[1]},{fill_perm[2]}),read=({read_perm[0]},{read_perm[1]},{read_perm[2]}),ax={axis_perm},dir={dir_combo},sub={sub_name}"
                            best = evaluate(candidate, desc, best, stored)
                            part7_configs += 1

        if part7_configs % 500000 == 0:
            print(f"  P7 dims={dims}: {part7_configs:,} configs, best: {best['score']}/24")
            sys.stdout.flush()

    total_configs += part7_configs
    print(f"  Part 7 done: {part7_configs:,} configs, best: {best['score']}/24")
    print(f"  Time: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════
    # Final Summary
    # ═══════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print()
    print("=" * 70)
    print("FINAL SUMMARY: E-ROMAN-04b — ABSCISSA=x-coordinate Hypothesis")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"  Part 4 (ABSCISSA-dim grids):     {part4_configs:,}")
    print(f"  Part 5 (targeted collar):         {part5_configs:,}")
    print(f"  Part 6 (col-read ordering):       {part6_configs:,}")
    print(f"  Part 7 (semantic assignment):      {part7_configs:,}")
    print(f"Elapsed time: {elapsed:.1f}s")
    print(f"Best score: {best['score']}/24")

    if best['score'] <= 6:
        classification = "NOISE"
    elif best['score'] <= 17:
        classification = "STORE"
    elif best['score'] <= 23:
        classification = "SIGNAL"
    else:
        classification = "BREAKTHROUGH"

    print(f"Classification: {classification}")
    print(f"Best config: {best['config']}")
    if best['plaintext']:
        print(f"Best PT (first 50): {best['plaintext'][:50]}")

    stored_above_noise = [s for s in stored if s['score'] > 6]
    print(f"Results above noise (>6): {len(stored_above_noise)}")
    if stored_above_noise:
        print("Top 10:")
        for r in sorted(stored_above_noise, key=lambda x: -x['score'])[:10]:
            print(f"  {r['score']}/24: {r['config'][:80]}")

    # Save results
    os.makedirs("results", exist_ok=True)
    output = {
        "experiment": "E-ROMAN-04b",
        "description": "ABSCISSA=x-coordinate hypothesis (addendum to E-ROMAN-04)",
        "total_configs": total_configs,
        "parts": {
            "part4_abscissa_dims": part4_configs,
            "part5_targeted_collar": part5_configs,
            "part6_col_read_ordering": part6_configs,
            "part7_semantic_assignment": part7_configs,
        },
        "elapsed_seconds": round(elapsed, 1),
        "best_score": best['score'],
        "best_config": best['config'],
        "best_plaintext": best['plaintext'],
        "classification": classification,
        "stored_results_count": len(stored),
        "above_noise_count": len(stored_above_noise),
        "top_results": sorted(stored, key=lambda x: -x['score'])[:20],
    }

    outpath = "results/e_roman_04b_abscissa_coords.json"
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to {outpath}")


if __name__ == '__main__':
    main()
