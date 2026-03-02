#!/usr/bin/env python3
"""E-ROUTE-DEFINITIVE: Comprehensive Route Transposition at Bean-Surviving Periods.

GAP ANALYSIS:
Prior experiments tested route transpositions extensively:
  - E-NOVEL-01, E-S-12, E-S-03, E-S-55, E-FRAC-45, E-SOLVE-13, Op Final Vector
  - Total: ~80K+ configs across 11+ grid sizes and 15+ route families

But these gaps remain:
  1. Route transpositions at Bean-surviving periods {8, 13, 16} with FULL Bean
     enforcement (eq + all 21 inequalities). E-FRAC-45 only tested p=2-7.
     E-S-55 tested p=2-14 but without full Bean inequality checking.
  2. Double route compositions (route1 ∘ route2): not previously tested.
  3. Route transpositions with all 4 spiral corners × 2 directions at wider
     grids (width 14-20).

This experiment closes these gaps definitively.

ARCHITECTURE:
  Phase 1: All route permutations × widths 5-20 × Bean-surviving periods {8,13,16}
           × 3 variants × 2 models (PT-residue, CT-residue) × full Bean
  Phase 2: Double route compositions for widths 7-13 × same scoring
  Phase 3: score_candidate() on any hits above noise

THEORETICAL NOTE:
  E-FRAC-35 proved periods {2-7,9-12,14,15,17,18,21,22,25} are Bean-impossible
  for ANY transposition. Only {8,13,16,19,20,23,24,26} survive.
  Periods >=16 are severely underdetermined (expected random: 16+/24).
  Periods 8 and 13 are the only discriminating Bean-surviving periods.
"""
import json
import math
import os
import sys
import time
from collections import Counter, defaultdict
from itertools import combinations

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    invert_perm, validate_perm, compose_perms,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
N = CT_LEN  # 97

# Bean-surviving periods that are discriminating (p<=13)
BEAN_SURVIVING_PERIODS = [8, 13]
# Also test 16 for completeness (higher = more underdetermined)
ALL_BEAN_PERIODS = [8, 13, 16]

VARIANTS = ["vigenere", "beaufort", "variant_beaufort"]


# ═══ Route Permutation Generators ════════════════════════════════════════

def fill_grid_rowmajor(width):
    """Fill grid row-by-row with positions 0..N-1, -1 for empty."""
    nrows = math.ceil(N / width)
    grid = []
    pos = 0
    for r in range(nrows):
        row = []
        for c in range(width):
            if pos < N:
                row.append(pos)
                pos += 1
            else:
                row.append(-1)
        grid.append(row)
    return grid, nrows


def read_order_to_perm(grid, nrows, ncols, cell_order):
    """Convert a reading order to a permutation (output[i] = input[perm[i]])."""
    perm = []
    for r, c in cell_order:
        if 0 <= r < nrows and 0 <= c < ncols:
            val = grid[r][c]
            if val >= 0:
                perm.append(val)
    return perm


def gen_serpentine(grid, nrows, width, reverse_start=False):
    """Boustrophedon: row-by-row, alternating L→R/R→L."""
    order = []
    for r in range(nrows):
        even = (r % 2 == 0) if not reverse_start else (r % 2 == 1)
        if even:
            for c in range(width): order.append((r, c))
        else:
            for c in range(width - 1, -1, -1): order.append((r, c))
    return read_order_to_perm(grid, nrows, width, order)


def gen_snake_column(grid, nrows, width, reverse_start=False):
    """Column-serpentine: columns alternating T→B/B→T."""
    order = []
    for c in range(width):
        even = (c % 2 == 0) if not reverse_start else (c % 2 == 1)
        if even:
            for r in range(nrows): order.append((r, c))
        else:
            for r in range(nrows - 1, -1, -1): order.append((r, c))
    return read_order_to_perm(grid, nrows, width, order)


def gen_column_major(grid, nrows, width, reverse_cols=False, reverse_rows=False):
    """Column-major reading with optional reversals."""
    order = []
    col_range = range(width - 1, -1, -1) if reverse_cols else range(width)
    for c in col_range:
        row_range = range(nrows - 1, -1, -1) if reverse_rows else range(nrows)
        for r in row_range:
            order.append((r, c))
    return read_order_to_perm(grid, nrows, width, order)


def gen_row_major(grid, nrows, width, reverse_rows=False, reverse_cols=False):
    """Row-major reading with optional reversals."""
    order = []
    row_range = range(nrows - 1, -1, -1) if reverse_rows else range(nrows)
    for r in row_range:
        col_range = range(width - 1, -1, -1) if reverse_cols else range(width)
        for c in col_range:
            order.append((r, c))
    return read_order_to_perm(grid, nrows, width, order)


def gen_spiral(grid, nrows, width, clockwise=True, start_corner='tl'):
    """Spiral reading from given corner."""
    visited = [[False] * width for _ in range(nrows)]
    if clockwise:
        dirs = [(0, 1), (1, 0), (0, -1), (-1, 0)]  # right, down, left, up
    else:
        dirs = [(1, 0), (0, 1), (-1, 0), (0, -1)]  # down, right, up, left

    # Starting position based on corner
    if start_corner == 'tl':
        r, c = 0, 0
    elif start_corner == 'tr':
        r, c = 0, width - 1
    elif start_corner == 'bl':
        r, c = nrows - 1, 0
    elif start_corner == 'br':
        r, c = nrows - 1, width - 1

    # Adjust direction based on corner for CW
    if clockwise:
        if start_corner == 'tr': dirs = [(1, 0), (0, -1), (-1, 0), (0, 1)]
        elif start_corner == 'br': dirs = [(0, -1), (-1, 0), (0, 1), (1, 0)]
        elif start_corner == 'bl': dirs = [(-1, 0), (0, 1), (1, 0), (0, -1)]
    else:
        if start_corner == 'tr': dirs = [(0, -1), (1, 0), (0, 1), (-1, 0)]
        elif start_corner == 'br': dirs = [(-1, 0), (0, -1), (1, 0), (0, 1)]
        elif start_corner == 'bl': dirs = [(0, 1), (-1, 0), (0, -1), (1, 0)]

    order = []
    d = 0
    for _ in range(nrows * width):
        if 0 <= r < nrows and 0 <= c < width and not visited[r][c]:
            order.append((r, c))
            visited[r][c] = True
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if 0 <= nr < nrows and 0 <= nc < width and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            nr, nc = r + dirs[d][0], c + dirs[d][1]
            if 0 <= nr < nrows and 0 <= nc < width and not visited[nr][nc]:
                r, c = nr, nc
            else:
                break
    return read_order_to_perm(grid, nrows, width, order)


def gen_diagonal(grid, nrows, width, anti=False):
    """Diagonal reading (NW-SE or NE-SW)."""
    order = []
    if not anti:
        for d in range(nrows + width - 1):
            for r in range(max(0, d - width + 1), min(nrows, d + 1)):
                c = d - r
                order.append((r, c))
    else:
        for d in range(nrows + width - 1):
            for r in range(max(0, d - width + 1), min(nrows, d + 1)):
                c = width - 1 - (d - r)
                if 0 <= c < width:
                    order.append((r, c))
    return read_order_to_perm(grid, nrows, width, order)


def gen_all_routes(width):
    """Generate all route permutations for a given grid width."""
    grid, nrows = fill_grid_rowmajor(width)
    routes = {}

    # Row-major variants (4)
    routes[f'row_lr_td'] = gen_row_major(grid, nrows, width)
    routes[f'row_rl_td'] = gen_row_major(grid, nrows, width, reverse_cols=True)
    routes[f'row_lr_bt'] = gen_row_major(grid, nrows, width, reverse_rows=True)
    routes[f'row_rl_bt'] = gen_row_major(grid, nrows, width, reverse_rows=True, reverse_cols=True)

    # Column-major variants (4)
    routes[f'col_td_lr'] = gen_column_major(grid, nrows, width)
    routes[f'col_td_rl'] = gen_column_major(grid, nrows, width, reverse_cols=True)
    routes[f'col_bt_lr'] = gen_column_major(grid, nrows, width, reverse_rows=True)
    routes[f'col_bt_rl'] = gen_column_major(grid, nrows, width, reverse_rows=True, reverse_cols=True)

    # Serpentine variants (4)
    routes[f'serp_h'] = gen_serpentine(grid, nrows, width)
    routes[f'serp_h_rev'] = gen_serpentine(grid, nrows, width, reverse_start=True)
    routes[f'serp_v'] = gen_snake_column(grid, nrows, width)
    routes[f'serp_v_rev'] = gen_snake_column(grid, nrows, width, reverse_start=True)

    # Spiral variants: 4 corners × 2 directions = 8
    for corner in ['tl', 'tr', 'bl', 'br']:
        for cw in [True, False]:
            name = f"spiral_{'cw' if cw else 'ccw'}_{corner}"
            routes[name] = gen_spiral(grid, nrows, width, clockwise=cw, start_corner=corner)

    # Diagonal variants (4)
    routes[f'diag_nwse'] = gen_diagonal(grid, nrows, width, anti=False)
    routes[f'diag_nesw'] = gen_diagonal(grid, nrows, width, anti=True)
    # Reversed
    perm = gen_diagonal(grid, nrows, width, anti=False)
    if perm:
        routes[f'diag_nwse_rev'] = list(reversed(perm))
    perm = gen_diagonal(grid, nrows, width, anti=True)
    if perm:
        routes[f'diag_nesw_rev'] = list(reversed(perm))

    # Filter to valid permutations only
    valid = {}
    seen = set()
    for name, perm in routes.items():
        if len(perm) == N and len(set(perm)) == N:
            pt = tuple(perm)
            if pt not in seen and pt != tuple(range(N)):
                seen.add(pt)
                valid[name] = perm
    return valid


# ═══ Scoring Functions ═══════════════════════════════════════════════════

def derive_key(ct_val, pt_val, variant):
    """Derive key value from CT and PT under given variant."""
    if variant == "vigenere":
        return (ct_val - pt_val) % MOD
    elif variant == "beaufort":
        return (ct_val + pt_val) % MOD
    else:  # variant_beaufort
        return (pt_val - ct_val) % MOD


def check_bean_full(key_dict, variant):
    """Check full Bean constraints (equality + all 21 inequalities)."""
    for eq_a, eq_b in BEAN_EQ:
        if eq_a in key_dict and eq_b in key_dict:
            if key_dict[eq_a] != key_dict[eq_b]:
                return False
    for ineq_a, ineq_b in BEAN_INEQ:
        if ineq_a in key_dict and ineq_b in key_dict:
            if key_dict[ineq_a] == key_dict[ineq_b]:
                return False
    return True


def score_route_at_period(inv_perm, period, variant, model):
    """Score a route permutation at a given period.

    model='A': key residue = PT position % period
    model='B': key residue = CT position % period

    Returns (crib_score, key_dict, bean_passed)
    """
    residue_keys = defaultdict(list)
    key_dict = {}  # position -> key value

    for pt_pos in sorted(CRIB_SET):
        ct_pos = inv_perm[pt_pos]
        ct_val = CT_NUM[ct_pos]
        pt_val = CRIB_PT_NUM[pt_pos]
        k = derive_key(ct_val, pt_val, variant)

        if model == 'A':
            residue = pt_pos % period
        else:
            residue = ct_pos % period

        residue_keys[residue].append(k)
        key_dict[pt_pos] = k  # Store at PT position for Bean

    # Count consistency: most common key in each residue class
    total = 0
    for keys in residue_keys.values():
        if len(keys) == 1:
            total += 1
        else:
            total += Counter(keys).most_common(1)[0][1]

    # Check Bean constraints on key values at PT positions
    bean_ok = check_bean_full(key_dict, variant)

    return total, key_dict, bean_ok


# ═══ Phase 1: All Routes × Bean-Surviving Periods ═══════════════════════

def run_phase1():
    """Test all route transpositions at Bean-surviving periods."""
    print("=" * 72)
    print("PHASE 1: Route Transpositions at Bean-Surviving Periods {8, 13, 16}")
    print("=" * 72)

    widths = list(range(5, 21))  # widths 5 through 20
    models = ['A', 'B']

    global_best = 0
    global_best_cfg = None
    all_hits = []  # score >= STORE_THRESHOLD
    bean_pass_count = 0
    total_configs = 0
    total_routes = 0

    t0 = time.time()

    for width in widths:
        nrows = math.ceil(N / width)
        routes = gen_all_routes(width)
        total_routes += len(routes)

        width_best = 0
        width_best_cfg = None

        for route_name, perm in routes.items():
            inv_perm = invert_perm(perm)

            for period in ALL_BEAN_PERIODS:
                for variant in VARIANTS:
                    for model in models:
                        total_configs += 1
                        score, key_dict, bean_ok = score_route_at_period(
                            inv_perm, period, variant, model
                        )

                        if bean_ok:
                            bean_pass_count += 1

                        if score > width_best:
                            width_best = score
                            width_best_cfg = {
                                'width': width, 'route': route_name,
                                'period': period, 'variant': variant,
                                'model': model, 'score': score,
                                'bean': bean_ok,
                            }

                        if score > global_best:
                            global_best = score
                            global_best_cfg = width_best_cfg.copy()

                        if score >= STORE_THRESHOLD and bean_ok:
                            all_hits.append({
                                'width': width, 'route': route_name,
                                'period': period, 'variant': variant,
                                'model': model, 'score': score,
                                'bean': bean_ok,
                            })

        elapsed = time.time() - t0
        print(f"  w={width:2d} ({nrows}×{width}): {len(routes):3d} routes, "
              f"best={width_best}/24, configs={total_configs:,}, "
              f"bean_pass={bean_pass_count}, [{elapsed:.1f}s]")
        if width_best_cfg and width_best >= STORE_THRESHOLD:
            print(f"    → best: {width_best_cfg}")

    elapsed = time.time() - t0

    print(f"\n  Phase 1 Summary:")
    print(f"    Widths: {widths[0]}-{widths[-1]}")
    print(f"    Total routes: {total_routes}")
    print(f"    Total configs: {total_configs:,}")
    print(f"    Bean passes: {bean_pass_count}")
    print(f"    Global best: {global_best}/24")
    if global_best_cfg:
        print(f"    Best config: {global_best_cfg}")
    print(f"    Hits ≥{STORE_THRESHOLD} w/ Bean: {len(all_hits)}")
    print(f"    Time: {elapsed:.1f}s")

    return global_best, global_best_cfg, all_hits, total_configs


# ═══ Phase 2: Double Route Compositions ══════════════════════════════════

def run_phase2():
    """Test compositions of two different route permutations."""
    print("\n" + "=" * 72)
    print("PHASE 2: Double Route Compositions (route1 ∘ route2)")
    print("=" * 72)

    # Focus on widths 7-13 (most physically relevant)
    widths = [7, 8, 9, 10, 11, 13]
    models = ['A', 'B']
    periods = [8, 13]  # Only the two most discriminating

    global_best = 0
    global_best_cfg = None
    all_hits = []
    bean_pass_count = 0
    total_configs = 0
    total_compositions = 0

    t0 = time.time()

    for width in widths:
        routes = gen_all_routes(width)
        route_list = list(routes.items())

        width_best = 0
        width_compositions = 0

        # Test all pairs of routes
        for i in range(len(route_list)):
            name1, perm1 = route_list[i]
            for j in range(len(route_list)):
                if i == j:
                    continue
                name2, perm2 = route_list[j]

                # Compose: apply perm1 then perm2
                composed = compose_perms(perm1, perm2)
                if not validate_perm(composed, N):
                    continue

                # Skip if composed = identity
                if composed == list(range(N)):
                    continue

                width_compositions += 1
                total_compositions += 1
                inv_composed = invert_perm(composed)

                for period in periods:
                    for variant in VARIANTS:
                        for model in models:
                            total_configs += 1
                            score, key_dict, bean_ok = score_route_at_period(
                                inv_composed, period, variant, model
                            )

                            if bean_ok:
                                bean_pass_count += 1

                            if score > width_best:
                                width_best = score

                            if score > global_best:
                                global_best = score
                                global_best_cfg = {
                                    'width': width,
                                    'route1': name1, 'route2': name2,
                                    'period': period, 'variant': variant,
                                    'model': model, 'score': score,
                                    'bean': bean_ok,
                                }

                            if score >= STORE_THRESHOLD and bean_ok:
                                all_hits.append({
                                    'width': width,
                                    'route1': name1, 'route2': name2,
                                    'period': period, 'variant': variant,
                                    'model': model, 'score': score,
                                    'bean': bean_ok,
                                })

        elapsed = time.time() - t0
        print(f"  w={width:2d}: {width_compositions} compositions, "
              f"best={width_best}/24, configs={total_configs:,}, "
              f"bean_pass={bean_pass_count}, [{elapsed:.1f}s]")

    elapsed = time.time() - t0

    print(f"\n  Phase 2 Summary:")
    print(f"    Total compositions: {total_compositions}")
    print(f"    Total configs: {total_configs:,}")
    print(f"    Bean passes: {bean_pass_count}")
    print(f"    Global best: {global_best}/24")
    if global_best_cfg:
        print(f"    Best config: {global_best_cfg}")
    print(f"    Hits ≥{STORE_THRESHOLD} w/ Bean: {len(all_hits)}")
    print(f"    Time: {elapsed:.1f}s")

    return global_best, global_best_cfg, all_hits, total_configs


# ═══ Phase 3: Cross-Width Route Compositions ═════════════════════════════

def run_phase3():
    """Test compositions where the two routes use different grid widths."""
    print("\n" + "=" * 72)
    print("PHASE 3: Cross-Width Route Compositions")
    print("=" * 72)

    # Test interesting width pairs
    width_pairs = [(7, 14), (14, 7), (8, 13), (13, 8), (9, 11), (11, 9),
                   (7, 8), (8, 7), (7, 9), (9, 7), (7, 13), (13, 7)]
    periods = [8, 13]
    models = ['A', 'B']

    global_best = 0
    global_best_cfg = None
    all_hits = []
    bean_pass_count = 0
    total_configs = 0
    total_compositions = 0

    t0 = time.time()

    for w1, w2 in width_pairs:
        routes1 = gen_all_routes(w1)
        routes2 = gen_all_routes(w2)

        # Sample a limited number of compositions (top 5 from each)
        r1_list = list(routes1.items())[:8]  # Limit to prevent explosion
        r2_list = list(routes2.items())[:8]

        pair_best = 0
        pair_compositions = 0

        for name1, perm1 in r1_list:
            for name2, perm2 in r2_list:
                composed = compose_perms(perm1, perm2)
                if not validate_perm(composed, N):
                    continue
                if composed == list(range(N)):
                    continue

                pair_compositions += 1
                total_compositions += 1
                inv_composed = invert_perm(composed)

                for period in periods:
                    for variant in VARIANTS:
                        for model in models:
                            total_configs += 1
                            score, key_dict, bean_ok = score_route_at_period(
                                inv_composed, period, variant, model
                            )

                            if bean_ok:
                                bean_pass_count += 1

                            if score > pair_best:
                                pair_best = score

                            if score > global_best:
                                global_best = score
                                global_best_cfg = {
                                    'w1': w1, 'w2': w2,
                                    'route1': name1, 'route2': name2,
                                    'period': period, 'variant': variant,
                                    'model': model, 'score': score,
                                    'bean': bean_ok,
                                }

                            if score >= STORE_THRESHOLD and bean_ok:
                                all_hits.append({
                                    'w1': w1, 'w2': w2,
                                    'route1': name1, 'route2': name2,
                                    'period': period, 'variant': variant,
                                    'model': model, 'score': score,
                                    'bean': bean_ok,
                                })

        elapsed = time.time() - t0
        print(f"  w={w1}×w={w2}: {pair_compositions} compositions, "
              f"best={pair_best}/24, [{elapsed:.1f}s]")

    elapsed = time.time() - t0

    print(f"\n  Phase 3 Summary:")
    print(f"    Width pairs: {len(width_pairs)}")
    print(f"    Total compositions: {total_compositions}")
    print(f"    Total configs: {total_configs:,}")
    print(f"    Bean passes: {bean_pass_count}")
    print(f"    Global best: {global_best}/24")
    if global_best_cfg:
        print(f"    Best config: {global_best_cfg}")
    print(f"    Hits ≥{STORE_THRESHOLD} w/ Bean: {len(all_hits)}")
    print(f"    Time: {elapsed:.1f}s")

    return global_best, global_best_cfg, all_hits, total_configs


# ═══ Main ════════════════════════════════════════════════════════════════

def main():
    t_start = time.time()

    print("=" * 72)
    print("E-ROUTE-DEFINITIVE: Comprehensive Route Transposition Attack")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"N = {N}")
    print(f"Bean-surviving periods: {ALL_BEAN_PERIODS}")
    print(f"Variants: {VARIANTS}")
    print()

    # Phase 1: Single routes at Bean-surviving periods
    p1_best, p1_cfg, p1_hits, p1_configs = run_phase1()

    # Phase 2: Double route compositions (same width)
    p2_best, p2_cfg, p2_hits, p2_configs = run_phase2()

    # Phase 3: Cross-width route compositions
    p3_best, p3_cfg, p3_hits, p3_configs = run_phase3()

    total_configs = p1_configs + p2_configs + p3_configs
    overall_best = max(p1_best, p2_best, p3_best)
    elapsed = time.time() - t_start

    # ── Expected random baselines ──
    # Period 8: 24 cribs into 8 residues → ~3 per residue → expected ~14/24 random
    # Period 13: 24 cribs into 13 residues → ~1.8 per → expected ~18/24 random
    # Period 16: 24 cribs into 16 residues → ~1.5 per → expected ~20/24 random
    random_expected = {8: 14, 13: 18, 16: 20}

    print(f"\n{'=' * 72}")
    print("FINAL SUMMARY")
    print(f"{'=' * 72}")
    print(f"Phase 1 (single routes):           best = {p1_best}/24  "
          f"({p1_configs:,} configs, {len(p1_hits)} Bean+STORE hits)")
    print(f"Phase 2 (double route same-width):  best = {p2_best}/24  "
          f"({p2_configs:,} configs, {len(p2_hits)} Bean+STORE hits)")
    print(f"Phase 3 (cross-width routes):       best = {p3_best}/24  "
          f"({p3_configs:,} configs, {len(p3_hits)} Bean+STORE hits)")
    print(f"Overall best: {overall_best}/24")
    print(f"Total configs: {total_configs:,}")
    print(f"Time: {elapsed:.1f}s")

    print(f"\nExpected random baselines:")
    for p, exp in random_expected.items():
        print(f"  Period {p}: ~{exp}/24")

    # Determine if any score exceeds random baseline at its period
    signal_found = False
    if p1_cfg and p1_cfg.get('score', 0) > random_expected.get(p1_cfg.get('period', 8), 24):
        signal_found = True
    if p2_cfg and p2_cfg.get('score', 0) > random_expected.get(p2_cfg.get('period', 8), 24):
        signal_found = True
    if p3_cfg and p3_cfg.get('score', 0) > random_expected.get(p3_cfg.get('period', 8), 24):
        signal_found = True

    # Check: any 24/24 + Bean PASS hits?
    total_bean_hits = len(p1_hits) + len(p2_hits) + len(p3_hits)
    breakthrough_hits = [h for hl in [p1_hits, p2_hits, p3_hits]
                         for h in hl if h['score'] >= 24 and h['bean']]

    if breakthrough_hits:
        verdict = "BREAKTHROUGH"
    elif signal_found:
        verdict = "INVESTIGATE"
    elif overall_best > random_expected.get(8, 14):
        verdict = f"WEAK — best {overall_best}/24 at high period (likely noise)"
    else:
        verdict = "ELIMINATED — all at or below noise floor"

    print(f"\nVERDICT: {verdict}")

    # Print all Bean+Store hits
    all_phase_hits = p1_hits + p2_hits + p3_hits
    if all_phase_hits:
        all_phase_hits.sort(key=lambda h: (-h['score'], -h.get('bean', 0)))
        print(f"\nAll {len(all_phase_hits)} Bean+STORE hits:")
        for h in all_phase_hits[:20]:
            print(f"  {h['score']}/24 p={h['period']} {h['variant'][:3]} "
                  f"mod={h['model']} bean={h['bean']} | {h}")

    # Save results
    os.makedirs("results", exist_ok=True)
    result = {
        "experiment": "E-ROUTE-DEFINITIVE",
        "description": "Route transposition at Bean-surviving periods + double routes",
        "phase1_best": p1_best,
        "phase1_configs": p1_configs,
        "phase1_hits": len(p1_hits),
        "phase2_best": p2_best,
        "phase2_configs": p2_configs,
        "phase2_hits": len(p2_hits),
        "phase3_best": p3_best,
        "phase3_configs": p3_configs,
        "phase3_hits": len(p3_hits),
        "overall_best": overall_best,
        "total_configs": total_configs,
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "random_baselines": random_expected,
        "all_hits": all_phase_hits[:50],
        "best_configs": {
            "phase1": p1_cfg,
            "phase2": p2_cfg,
            "phase3": p3_cfg,
        },
    }
    outpath = "results/e_route_definitive.json"
    with open(outpath, 'w') as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\nArtifacts: {outpath}")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/e_route_definitive.py")


if __name__ == "__main__":
    main()
