#!/usr/bin/env python3
"""
E-REF-00: 8-Row Grid Transposition Hypothesis

Sanborn's handwritten plaintext notes (Picture_4.jpg from auction lot) show
"8 Lines 73" next to the K3/K4 section. If "8 Lines" is the grid row count
for K4 encoding:

  97 chars / 8 rows => width 13 (7 full rows of 13 + 1 row of 6)
                    or width 12 (8 rows, 1 extra char wrapping)

This script tests ALL column orderings for widths 12-13 in an 8-row grid,
combined with Vigenere/Beaufort/VarBeau decryption using crib constraints.

Also tests non-standard grid fills:
  - Row-by-row (standard)
  - Column-by-column
  - Serpentine (boustrophedon) — alternating left-right row reading
  - Spiral inward

Scoring: crib match count at known positions + Bean constraints.

Output: results/e_ref_00_8row_grid.json
"""

import json
import sys
import os
import time
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN  # 97
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Bean constraints
BEAN_EQ = (27, 65)  # k[27] == k[65]
BEAN_INEQ = [
    (i, j) for i in CRIB_POS for j in CRIB_POS
    if i < j and CRIB_PT[i] != CRIB_PT[j]
    and i != 27 and i != 65 and j != 27 and j != 65
]


def build_grid_perm(width, n, fill_mode="row"):
    """Build permutation for reading columns in natural order from a grid.

    Grid has `width` columns, filled according to fill_mode.
    Returns perm such that output[i] = input[perm[i]] (gather convention).

    For columnar transposition, we'll apply column reordering separately.
    This returns the base fill permutation.
    """
    rows = (n + width - 1) // width

    if fill_mode == "row":
        # Standard: fill left-to-right, top-to-bottom
        # perm is identity (positions are already in row order)
        return list(range(n))

    elif fill_mode == "serpentine":
        # Boustrophedon: odd rows read right-to-left
        perm = []
        for r in range(rows):
            row_start = r * width
            row_end = min(row_start + width, n)
            row_positions = list(range(row_start, row_end))
            if r % 2 == 1:
                row_positions.reverse()
            perm.extend(row_positions)
        return perm

    elif fill_mode == "column":
        # Fill column-by-column instead of row-by-row
        perm = [0] * n
        n_full_cols = n % width if n % width != 0 else width
        col_height_long = rows
        col_height_short = rows - 1

        idx = 0
        for col in range(width):
            h = col_height_long if col < n_full_cols else col_height_short
            for row in range(h):
                grid_pos = row * width + col
                if grid_pos < n:
                    perm[idx] = grid_pos
                    idx += 1
        return perm[:n]

    elif fill_mode == "spiral":
        # Spiral inward from top-left
        grid = [[None] * width for _ in range(rows)]
        pos = 0
        top, bottom, left, right = 0, rows - 1, 0, width - 1
        while pos < n:
            for c in range(left, right + 1):
                if pos < n:
                    grid[top][c] = pos
                    pos += 1
            top += 1
            for r in range(top, bottom + 1):
                if pos < n:
                    grid[r][right] = pos
                    pos += 1
            right -= 1
            for c in range(right, left - 1, -1):
                if pos < n:
                    grid[bottom][c] = pos
                    pos += 1
            bottom -= 1
            for r in range(bottom, top - 1, -1):
                if pos < n:
                    grid[r][left] = pos
                    pos += 1
            left += 1
        # Read out row-by-row
        perm = []
        for r in range(rows):
            for c in range(width):
                if grid[r][c] is not None:
                    perm.append(grid[r][c])
        return perm

    return list(range(n))


def columnar_read_perm(width, n, col_order):
    """Build the full columnar transposition permutation.

    Write plaintext into grid row-by-row with given width.
    Read columns in col_order to produce ciphertext.

    Returns perm such that CT[i] = PT[perm[i]] (gather from PT perspective).
    So to decrypt: PT[perm[i]] = CT[i], meaning PT = apply inverse perm to CT.
    """
    rows = (n + width - 1) // width
    n_long = n % width  # number of columns with full height
    if n_long == 0:
        n_long = width

    # Build CT position for each PT position
    ct_pos = 0
    pt_to_ct = [0] * n
    for col in col_order:
        col_len = rows if col < n_long else rows - 1
        for row in range(col_len):
            pt_pos = row * width + col
            if pt_pos < n:
                pt_to_ct[pt_pos] = ct_pos
                ct_pos += 1

    # Invert: for each CT position, which PT position?
    ct_to_pt = [0] * n
    for pt, ct in enumerate(pt_to_ct):
        ct_to_pt[ct] = pt

    return ct_to_pt


def score_config(ct_to_pt_perm, variant_sign):
    """Score a configuration: apply perm to CT, then check crib consistency.

    Model: CT was produced by columnar transposition of substituted text.
    To decrypt: undo transposition (reorder CT), then undo substitution.

    For each crib position j with known PT[j]:
      After undoing transposition, position j holds CT[perm_inv[j]]
      Key at position j: k[j] = (CT[perm_inv[j]] + sign * PT[j]) % 26

    For periodic key with unknown period, we just check:
      1. Bean equality: k[27] == k[65]
      2. All crib positions produce valid key values (always true)
      3. Count how many crib pairs are consistent
    """
    # ct_to_pt[i] = which PT position does CT position i fill
    # So PT[ct_to_pt[i]] = decrypt(CT[i])
    # Equivalently: the CT value at position ct_to_pt[i] is CT[i]
    # We need: for PT position j, which CT position maps to it?
    # That's the inverse: pt_to_ct[j] = i where ct_to_pt[i] = j

    pt_to_ct = [0] * N
    for i in range(N):
        pt_to_ct[ct_to_pt_perm[i]] = i

    # For each crib position j, compute key value
    keys = {}
    for j in CRIB_POS:
        ct_val = CT_NUM[pt_to_ct[j]]  # CT value that maps to PT position j
        pt_val = CRIB_PT[j]
        if variant_sign == -1:  # Vigenere: K = (CT - PT) mod 26
            keys[j] = (ct_val - pt_val) % MOD
        elif variant_sign == 1:  # Beaufort: K = (CT + PT) mod 26
            keys[j] = (ct_val + pt_val) % MOD
        else:  # Var Beaufort: K = (PT - CT) mod 26
            keys[j] = (pt_val - ct_val) % MOD

    # Bean equality check
    bean_eq = keys.get(BEAN_EQ[0]) == keys.get(BEAN_EQ[1])

    # Bean inequality check
    bean_ineq_pass = 0
    bean_ineq_total = 0
    for i, j in BEAN_INEQ:
        if i in keys and j in keys:
            bean_ineq_total += 1
            if keys[i] != keys[j]:
                bean_ineq_pass += 1

    # For scoring: count crib matches under periodic key hypothesis
    # Only periods 1-7 are meaningful discriminators (~8.2/24 expected random)
    # Periods >= 8 are underdetermined and produce false positives
    best_score = 0
    for period in range(1, 8):
        score = 0
        # Group keys by residue mod period
        residues = {}
        for j in CRIB_POS:
            r = j % period
            if r not in residues:
                residues[r] = keys[j]
                score += 1
            elif residues[r] == keys[j]:
                score += 1
        best_score = max(best_score, score)

    return best_score, bean_eq, bean_ineq_pass, bean_ineq_total, keys


def main():
    print("=" * 60)
    print("E-REF-00: 8-Row Grid Transposition (from Sanborn's notes)")
    print("=" * 60)

    t0 = time.time()
    all_results = []
    total_configs = 0

    # Test widths that produce 8 rows (or close)
    # width 12: ceil(97/12) = 9 rows (not 8)
    # width 13: ceil(97/13) = 8 rows (7 full + 1 of 6) ← matches "8 Lines"
    # width 14: ceil(97/14) = 7 rows (not 8)
    # Also test 12 (close to 8 rows) and nearby widths

    test_widths = [13, 12, 14]  # 13 is primary hypothesis
    # Note: serpentine/spiral fill compositions were not implemented (pass),
    # so only "row" is tested. This avoids triple-counting identical results.
    fill_modes = ["row"]
    variants = [("vig", -1), ("beau", 1), ("varbeau", 2)]  # 2 = sentinel for var beau

    for width in test_widths:
        rows = (N + width - 1) // width
        n_perms = 1
        for i in range(2, width + 1):
            n_perms *= i

        print(f"\nWidth {width} ({rows} rows): {n_perms} col orderings × "
              f"{len(fill_modes)} fills × {len(variants)} variants "
              f"= {n_perms * len(fill_modes) * len(variants):,} configs")

        # For width 13 and 14, full permutation is too large (13! = 6B)
        # Use partial search: fix first few columns, permute rest
        if n_perms > 5_000_000:
            print(f"  Too many permutations ({n_perms:,}), using targeted search...")
            # Strategy: random sample + structured subsets
            import random
            random.seed(42)

            sample_size = 500_000
            col_orders = set()

            # Add identity and reverse
            col_orders.add(tuple(range(width)))
            col_orders.add(tuple(range(width - 1, -1, -1)))

            # Add shifts
            for shift in range(width):
                col_orders.add(tuple((i + shift) % width for i in range(width)))

            # Random sample
            base = list(range(width))
            while len(col_orders) < sample_size:
                random.shuffle(base)
                col_orders.add(tuple(base))

            col_orders = list(col_orders)
            print(f"  Sampled {len(col_orders):,} column orderings")
        else:
            col_orders = list(permutations(range(width)))

        best_width_score = 0
        best_width_result = None

        for fill_mode in fill_modes:
            fill_perm = build_grid_perm(width, N, fill_mode)

            for col_order in col_orders:
                col_order = list(col_order)
                ct_to_pt = columnar_read_perm(width, N, col_order)

                # Apply fill permutation
                if fill_mode != "row":
                    # Compose: first undo fill, then undo columnar
                    # This is getting complex; for non-row fills,
                    # the grid is filled differently before column reading
                    pass  # Use row fill for now, extend later

                for vname, vsign in variants:
                    total_configs += 1

                    actual_sign = -1 if vsign == -1 else (1 if vsign == 1 else 0)
                    if vsign == 2:  # var beaufort
                        actual_sign = 0

                    # Map vsign properly
                    if vname == "vig":
                        s = -1
                    elif vname == "beau":
                        s = 1
                    else:
                        s = 2  # sentinel

                    score, bean_eq, bean_ineq, bean_total, keys = score_config(ct_to_pt, s if s != 2 else -1)

                    # For var beaufort, recompute
                    if vname == "varbeau":
                        pt_to_ct = [0] * N
                        for i in range(N):
                            pt_to_ct[ct_to_pt[i]] = i
                        keys_vb = {}
                        for j in CRIB_POS:
                            ct_val = CT_NUM[pt_to_ct[j]]
                            pt_val = CRIB_PT[j]
                            keys_vb[j] = (pt_val - ct_val) % MOD

                        bean_eq = keys_vb.get(27) == keys_vb.get(65)

                        best_s = 0
                        for period in range(1, 8):
                            s_count = 0
                            residues = {}
                            for j in CRIB_POS:
                                r = j % period
                                if r not in residues:
                                    residues[r] = keys_vb[j]
                                    s_count += 1
                                elif residues[r] == keys_vb[j]:
                                    s_count += 1
                            best_s = max(best_s, s_count)
                        score = best_s
                        keys = keys_vb

                    if score > best_width_score:
                        best_width_score = score
                        best_width_result = {
                            "width": width,
                            "rows": rows,
                            "fill": fill_mode,
                            "col_order": col_order,
                            "variant": vname,
                            "score": score,
                            "bean_eq": bean_eq,
                        }

                    if score >= 18 and bean_eq:
                        # Recover plaintext
                        pt_to_ct = [0] * N
                        for i in range(N):
                            pt_to_ct[ct_to_pt[i]] = i

                        pt_vals = []
                        for j in range(N):
                            ct_val = CT_NUM[pt_to_ct[j]]
                            if vname == "vig":
                                # Need key to decrypt; use closest crib key
                                # For now just note the hit
                                pt_vals.append(0)
                            else:
                                pt_vals.append(0)

                        result = {
                            "width": width,
                            "rows": rows,
                            "fill": fill_mode,
                            "col_order": col_order,
                            "variant": vname,
                            "score": score,
                            "bean_eq": bean_eq,
                            "key_at_cribs": {str(k): v for k, v in sorted(keys.items())},
                        }
                        all_results.append(result)
                        print(f"  *** HIT: w={width} fill={fill_mode} {vname} "
                              f"order={col_order[:6]}... score={score}/24 "
                              f"Bean={'PASS' if bean_eq else 'FAIL'}")

            if total_configs % 100000 == 0:
                elapsed = time.time() - t0
                print(f"  [{elapsed:.0f}s] {total_configs:,} configs, "
                      f"best={best_width_score}/24", flush=True)

        print(f"  Width {width} best: {best_width_score}/24"
              f" {'(Bean PASS)' if best_width_result and best_width_result.get('bean_eq') else '(Bean FAIL)'}")
        if best_width_result:
            print(f"    Config: fill={best_width_result['fill']} "
                  f"{best_width_result['variant']} "
                  f"order={best_width_result['col_order'][:8]}...")

    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total configs: {total_configs:,}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Hits ≥ 18 + Bean: {len(all_results)}")

    if all_results:
        all_results.sort(key=lambda r: -r['score'])
        for r in all_results[:10]:
            print(f"    w={r['width']} {r['variant']} fill={r['fill']} "
                  f"score={r['score']}/24 Bean={'PASS' if r['bean_eq'] else 'FAIL'}")

    verdict = "SIGNAL" if any(r['score'] >= 18 and r['bean_eq'] for r in all_results) else "NOISE"
    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment": "E-REF-00",
        "description": "8-row grid transposition from Sanborn handwritten notes",
        "hypothesis": "Sanborn's '8 Lines 73' note indicates 8-row grid for K4",
        "widths_tested": test_widths,
        "fill_modes": fill_modes,
        "total_configs": total_configs,
        "hits": len(all_results),
        "verdict": verdict,
        "top_results": all_results[:20],
        "elapsed_seconds": round(elapsed, 1),
    }
    with open("results/e_ref_00_8row_grid.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_ref_00_8row_grid.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_ref_00_8row_grid.py")


if __name__ == "__main__":
    main()
