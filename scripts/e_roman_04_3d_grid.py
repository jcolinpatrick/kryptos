#!/usr/bin/env python3
"""E-ROMAN-04: 3D Grid Transposition Experiment.

Hypothesis: Howard Carter's "Tomb of Tut-Ankh-Amen" Chapter X describes beadwork
with "three independent threading strings to every bead." This suggests K4 uses a
THREE-DIMENSIONAL arrangement — letters placed in a 3D grid and read out along
different axes.

Parts:
  1. 3D Grid Transposition: Write CT into d1×d2×d3 grid, read out by varying
     axis traversal order (6 perms) × direction per axis (8 combos) = 48 patterns.
     Apply identity + Vig/Beau with keyword keys.
  2. Keyword-Ordered 3D Grid: Use keyword-derived orderings for fill along each dim.
  3. "Collar" Model: Three independent keyword-derived streams select (x,y,z) coords.
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
    """Vigenere: PT = (CT - KEY) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def beau_decrypt(ct, key_vals):
    """Beaufort: PT = (KEY - CT) mod 26."""
    pt = []
    klen = len(key_vals)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = key_vals[i % klen]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


def keyword_to_vals(kw):
    """Convert keyword string to list of int values (A=0..Z=25)."""
    return [ALPH_IDX[c] for c in kw.upper()]


# ── Keywords for substitution and dimension ordering ──

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "CARTER",
    "HERBERT", "LABORATORY", "TUTANKHAMUN", "DISCOVERY",
    "THREADING", "PATTERN",
]

KEYWORD_VALS = {kw: keyword_to_vals(kw) for kw in KEYWORDS}

PAD_CHARS = ['X', 'A']  # pad strategies (also try repeating last CT char)

# ── 3D grid dimensions (product >= 97, minimize padding) ──

DIM_TRIPLES = [
    (5, 5, 4),   # 100, pad 3
    (7, 7, 2),   # 98, pad 1
    (7, 5, 3),   # 105, pad 8
    (3, 11, 3),  # 99, pad 2
    (2, 7, 7),   # 98, pad 1
    (5, 10, 2),  # 100, pad 3
    (2, 5, 10),  # 100, pad 3
    (4, 5, 5),   # 100, pad 3
    (3, 5, 7),   # 105, pad 8
    (3, 3, 11),  # 99, pad 2
    (2, 10, 5),  # 100, pad 3
]

# ── Axis permutations and direction combos ──

AXIS_PERMS = list(itertools.permutations(range(3)))  # 6 orderings
DIR_COMBOS = list(itertools.product([False, True], repeat=3))  # 8 direction combos
# Total: 48 reading patterns per dimension set


def fill_3d_grid(text, d1, d2, d3, pad_char='X'):
    """Fill a d1×d2×d3 grid sequentially with text, padding as needed."""
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
    """Read out a 3D grid in a given axis order and direction combo.

    axis_perm: tuple of 3 ints (permutation of 0,1,2) — traversal order of axes
    directions: tuple of 3 bools — True means reverse that axis

    Returns string of length ct_len (truncated to remove padding).
    """
    dims = [d1, d2, d3]
    # Build ranges for each axis
    ranges = []
    for ax in range(3):
        r = list(range(dims[ax]))
        if directions[ax]:
            r = r[::-1]
        ranges.append(r)

    # Traverse in axis_perm order
    result = []
    # axis_perm[0] is outermost loop, axis_perm[2] is innermost
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


def keyword_order(keyword, dim_size):
    """Generate a permutation of range(dim_size) based on keyword letter values.

    Assigns keyword letters (cycling) to positions, sorts by (letter_value, position)
    to get a stable ordering.
    """
    kv = keyword_to_vals(keyword)
    assignments = [(kv[i % len(kv)], i) for i in range(dim_size)]
    assignments.sort()
    return [pos for _, pos in assignments]


def fill_3d_grid_keyword(text, d1, d2, d3, kw1, kw2, kw3, pad_char='X'):
    """Fill a 3D grid using keyword-derived orderings along each dimension."""
    total = d1 * d2 * d3
    padded = text + pad_char * (total - len(text))

    order1 = keyword_order(kw1, d1)
    order2 = keyword_order(kw2, d2)
    order3 = keyword_order(kw3, d3)

    grid = [[[' ' for _ in range(d3)] for _ in range(d2)] for _ in range(d1)]
    idx = 0
    for i in order1:
        for j in order2:
            for k in order3:
                grid[i][j][k] = padded[idx]
                idx += 1
    return grid


def collar_model(ct_text, d1, d2, d3, kw1, kw2, kw3, ct_len):
    """Collar model: three independent keyword-derived streams select 3D coords.

    For position i:
      x = keyword1_vals[i % len(kw1)] % d3
      y = keyword2_vals[i % len(kw2)] % d2
      z = keyword3_vals[i % len(kw3)] % d1

    Place CT chars into grid at these coords, read out sequentially.
    Actually: read FROM grid at these coords to produce transposed output.
    """
    # Fill grid sequentially with CT
    total = d1 * d2 * d3
    padded = ct_text + 'X' * (total - len(ct_text))
    grid = [[[' ' for _ in range(d3)] for _ in range(d2)] for _ in range(d1)]
    idx = 0
    for i in range(d1):
        for j in range(d2):
            for k in range(d3):
                grid[i][j][k] = padded[idx]
                idx += 1

    kv1 = keyword_to_vals(kw1)
    kv2 = keyword_to_vals(kw2)
    kv3 = keyword_to_vals(kw3)

    result = []
    for i in range(ct_len):
        z = kv1[i % len(kv1)] % d1
        y = kv2[i % len(kv2)] % d2
        x = kv3[i % len(kv3)] % d3
        result.append(grid[z][y][x])
    return ''.join(result)


def evaluate(candidate, config_desc, best, results_store):
    """Score candidate, update best, store if above noise."""
    if len(candidate) < CT_LEN:
        return best
    sc = score_cribs(candidate[:CT_LEN])
    if sc > best['score']:
        best = {'score': sc, 'config': config_desc, 'plaintext': candidate[:CT_LEN]}
    if sc >= 7:  # STORE threshold
        results_store.append({'score': sc, 'config': config_desc, 'pt_snippet': candidate[:40]})
    return best


def main():
    t0 = time.time()
    best = {'score': 0, 'config': '', 'plaintext': ''}
    stored = []
    total_configs = 0

    # Substitution modes: identity + Vig/Beau with each keyword
    sub_modes = [('identity', None, None)]
    for kw in KEYWORDS:
        sub_modes.append(('vig_' + kw, 'vig', KEYWORD_VALS[kw]))
        sub_modes.append(('beau_' + kw, 'beau', KEYWORD_VALS[kw]))

    def apply_sub(text, mode, key_vals):
        if mode is None:
            return text
        elif mode == 'vig':
            return vig_decrypt(text, key_vals)
        elif mode == 'beau':
            return beau_decrypt(text, key_vals)
        return text

    # ═══════════════════════════════════════════════════════════════════
    # Part 1: 3D Grid Transposition (sequential fill)
    # ═══════════════════════════════════════════════════════════════════
    print("=" * 70)
    print("PART 1: 3D Grid Transposition (sequential fill)")
    print("=" * 70)

    part1_configs = 0
    for dims in DIM_TRIPLES:
        d1, d2, d3 = dims
        for pad_char in PAD_CHARS:
            grid = fill_3d_grid(CT, d1, d2, d3, pad_char)
            for axis_perm in AXIS_PERMS:
                for dir_combo in DIR_COMBOS:
                    transposed = read_3d_grid(grid, d1, d2, d3, axis_perm, dir_combo, CT_LEN)
                    for sub_name, sub_mode, sub_key in sub_modes:
                        candidate = apply_sub(transposed, sub_mode, sub_key)
                        desc = f"P1:dims={dims},pad={pad_char},ax={axis_perm},dir={dir_combo},sub={sub_name}"
                        best = evaluate(candidate, desc, best, stored)
                        part1_configs += 1

    total_configs += part1_configs
    print(f"  Part 1 done: {part1_configs:,} configs, best so far: {best['score']}/24")
    print(f"  Time: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════
    # Part 2: Keyword-Ordered 3D Grid
    # ═══════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PART 2: Keyword-Ordered 3D Grid Fill")
    print("=" * 70)

    part2_configs = 0
    # For each dim triple, try keyword-ordered fill with subset of keyword combos
    # To keep manageable: pick top 6 keywords for fill ordering
    FILL_KWS = KEYWORDS[:6]  # KRYPTOS, PALIMPSEST, ABSCISSA, CARTER, HERBERT, LABORATORY

    for dims in DIM_TRIPLES:
        d1, d2, d3 = dims
        for kw1 in FILL_KWS:
            for kw2 in FILL_KWS:
                for kw3 in FILL_KWS:
                    grid = fill_3d_grid_keyword(CT, d1, d2, d3, kw1, kw2, kw3, 'X')
                    # Test all 48 read patterns but only identity + top 4 substitutions
                    sub_subset = sub_modes[:9]  # identity + vig/beau for first 4 keywords
                    for axis_perm in AXIS_PERMS:
                        for dir_combo in DIR_COMBOS:
                            transposed = read_3d_grid(grid, d1, d2, d3, axis_perm, dir_combo, CT_LEN)
                            for sub_name, sub_mode, sub_key in sub_subset:
                                candidate = apply_sub(transposed, sub_mode, sub_key)
                                desc = f"P2:dims={dims},kw=({kw1},{kw2},{kw3}),ax={axis_perm},dir={dir_combo},sub={sub_name}"
                                best = evaluate(candidate, desc, best, stored)
                                part2_configs += 1

        # Progress per dim triple
        if part2_configs % 100000 < 1000:
            print(f"  P2 dims={dims}: {part2_configs:,} configs so far, best: {best['score']}/24")
            sys.stdout.flush()

    total_configs += part2_configs
    print(f"  Part 2 done: {part2_configs:,} configs, best so far: {best['score']}/24")
    print(f"  Time: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════
    # Part 3: "Collar" Model — Three Independent Key Streams
    # ═══════════════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("PART 3: Collar Model — Three Independent Key Streams")
    print("=" * 70)

    part3_configs = 0
    for dims in DIM_TRIPLES:
        d1, d2, d3 = dims
        for kw1 in KEYWORDS:
            for kw2 in KEYWORDS:
                for kw3 in KEYWORDS:
                    transposed = collar_model(CT, d1, d2, d3, kw1, kw2, kw3, CT_LEN)
                    # Identity + Vig/Beau with each keyword
                    for sub_name, sub_mode, sub_key in sub_modes:
                        candidate = apply_sub(transposed, sub_mode, sub_key)
                        desc = f"P3:dims={dims},streams=({kw1},{kw2},{kw3}),sub={sub_name}"
                        best = evaluate(candidate, desc, best, stored)
                        part3_configs += 1

        print(f"  P3 dims={dims}: {part3_configs:,} configs so far, best: {best['score']}/24")
        sys.stdout.flush()

    total_configs += part3_configs
    print(f"  Part 3 done: {part3_configs:,} configs, best so far: {best['score']}/24")
    print(f"  Time: {time.time()-t0:.1f}s")
    sys.stdout.flush()

    # ═══════════════════════════════════════════════════════════════════
    # Final Summary
    # ═══════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print()
    print("=" * 70)
    print("FINAL SUMMARY: E-ROMAN-04 — 3D Grid Transposition")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"  Part 1 (sequential fill):    {part1_configs:,}")
    print(f"  Part 2 (keyword fill):       {part2_configs:,}")
    print(f"  Part 3 (collar model):       {part3_configs:,}")
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

    # Save results
    os.makedirs("results", exist_ok=True)
    output = {
        "experiment": "E-ROMAN-04",
        "description": "3D Grid Transposition (Carter beadwork hypothesis)",
        "total_configs": total_configs,
        "parts": {
            "part1_sequential": part1_configs,
            "part2_keyword_fill": part2_configs,
            "part3_collar_model": part3_configs,
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

    outpath = "results/e_roman_04_3d_grid.json"
    with open(outpath, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to {outpath}")


if __name__ == '__main__':
    main()
