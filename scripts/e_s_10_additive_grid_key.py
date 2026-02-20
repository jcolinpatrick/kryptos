#!/usr/bin/env python3
"""E-S-10: Algebraic test of additive row+column key model.

Model: key[i] = row_key[i // W] + col_key[i % W] mod 26
       CT[i] = PT[i] + key[i] mod 26  (Vigenère)
  or:  CT[i] = PT[i] - key[i] mod 26  (Beaufort)

For each grid width W (2-48), the 24 known key values from cribs give
a linear system in (num_rows + W - 1) unknowns (one degree of freedom
is absorbed by WLOG setting r[first_row] = 0).

If the system is consistent: the model PASSES for this width.
If contradictions exist: the model FAILS for this width.

This is instant algebra — no search.
"""

import json
import os
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_ENTRIES, MOD

# ═══ Setup ════════════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
CRIB_DICT = {p: c for p, c in _sorted}

# Vigenère key values: k = (CT - PT) mod 26
VIG_KEY = {}
for p in CRIB_POS:
    VIG_KEY[p] = (CT_INT[p] - (ord(CRIB_DICT[p]) - 65)) % 26

# Beaufort key values: k = (CT + PT) mod 26
BEAU_KEY = {}
for p in CRIB_POS:
    BEAU_KEY[p] = (CT_INT[p] + (ord(CRIB_DICT[p]) - 65)) % 26


def test_additive_grid(width, key_dict, mod=26):
    """Test if key values are consistent with row+col additive model.

    Returns (is_consistent, row_vals, col_vals, contradictions).
    """
    # Group crib positions by row and column
    row_groups = defaultdict(list)  # row_idx -> [(pos, key_val)]
    col_groups = defaultdict(list)  # col_idx -> [(pos, key_val)]

    for p in CRIB_POS:
        row = p // width
        col = p % width
        kv = key_dict[p]
        row_groups[row].append((p, col, kv))
        col_groups[col].append((p, row, kv))

    # Union-Find approach: build a constraint graph
    # Nodes = row indices and column indices (prefixed to distinguish)
    # Edge (row_r, col_c) with weight k means: r[row_r] + c[col_c] = k (mod 26)

    # Use BFS/DFS to assign values
    row_val = {}  # row_idx -> value
    col_val = {}  # col_idx -> value
    contradictions = []

    # Start from the first crib position
    # Set r[first_row] = 0
    first_pos = CRIB_POS[0]
    first_row = first_pos // width
    row_val[first_row] = 0

    # BFS queue: propagate constraints
    # When we know r[row], for each crib pos in that row: c[col] = k - r[row]
    # When we know c[col], for each crib pos in that col: r[row] = k - c[col]

    queue = [('row', first_row)]
    visited_rows = {first_row}
    visited_cols = set()

    while queue:
        node_type, node_idx = queue.pop(0)

        if node_type == 'row':
            # We know r[node_idx]. Derive column values.
            r = row_val[node_idx]
            for p, col, kv in row_groups[node_idx]:
                expected_c = (kv - r) % mod
                if col in col_val:
                    if col_val[col] != expected_c:
                        contradictions.append(
                            f"col {col}: need {expected_c} from pos {p} "
                            f"(row {node_idx}, k={kv}), have {col_val[col]}")
                else:
                    col_val[col] = expected_c
                    if col not in visited_cols:
                        visited_cols.add(col)
                        queue.append(('col', col))

        elif node_type == 'col':
            # We know c[node_idx]. Derive row values.
            c = col_val[node_idx]
            for p, row, kv in col_groups[node_idx]:
                expected_r = (kv - c) % mod
                if row in row_val:
                    if row_val[row] != expected_r:
                        contradictions.append(
                            f"row {row}: need {expected_r} from pos {p} "
                            f"(col {node_idx}, k={kv}), have {row_val[row]}")
                else:
                    row_val[row] = expected_r
                    if row not in visited_rows:
                        visited_rows.add(row)
                        queue.append(('row', row))

    # Check if the constraint graph is connected
    n_assigned = len(row_val) + len(col_val)
    n_total_rows = len(row_groups)
    n_total_cols = len(col_groups)
    connected = (len(row_val) >= n_total_rows and len(col_val) >= n_total_cols)

    return len(contradictions) == 0, row_val, col_val, contradictions, connected


def decrypt_with_grid_key(width, row_val, col_val, variant='vigenere'):
    """Decrypt full CT using the additive grid key."""
    pt = []
    for i in range(CT_LEN):
        row = i // width
        col = i % width
        r = row_val.get(row, 0)
        c = col_val.get(col, 0)
        k = (r + c) % 26
        if variant == 'vigenere':
            pt_val = (CT_INT[i] - k) % 26
        else:  # beaufort
            pt_val = (k - CT_INT[i]) % 26
        pt.append(chr(pt_val + 65))
    return ''.join(pt)


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-10: Additive Row+Column Grid Key Test")
    print("=" * 60)
    print(f"Model: key[i] = row_key[i//W] + col_key[i%W] mod 26")
    print(f"Testing widths 2-48 for both Vigenère and Beaufort")
    print()

    all_results = {}
    passes = []

    for variant_name, key_dict in [('vigenere', VIG_KEY), ('beaufort', BEAU_KEY)]:
        print(f"\n{'=' * 60}")
        print(f"  Variant: {variant_name.upper()}")
        print(f"{'=' * 60}")

        for width in range(2, 49):
            ok, rv, cv, contras, connected = test_additive_grid(width, key_dict)

            num_rows = (CT_LEN + width - 1) // width
            n_unknowns = num_rows + width - 1  # minus 1 for WLOG

            result = {
                "width": width,
                "variant": variant_name,
                "num_rows": num_rows,
                "n_unknowns": n_unknowns,
                "consistent": ok,
                "connected": connected,
                "n_contradictions": len(contras),
                "n_row_vals": len(rv),
                "n_col_vals": len(cv),
            }

            if ok:
                # Check if connected (fully determined)
                if connected:
                    pt = decrypt_with_grid_key(width, rv, cv, variant_name)
                    # Check crib positions
                    crib_ok = sum(1 for p in CRIB_POS
                                  if pt[p] == CRIB_DICT[p])
                    result["crib_matches"] = crib_ok
                    result["plaintext"] = pt

                    # Simple English-likeness check
                    from collections import Counter
                    freq = Counter(pt)
                    top5 = [c for c, _ in freq.most_common(5)]
                    result["top5_letters"] = ''.join(top5)

                    passes.append((width, variant_name, crib_ok, pt[:40]))
                    tag = "*** PASS ***"
                else:
                    tag = "PASS (disconnected — underdetermined)"
                    result["plaintext"] = ""
            else:
                tag = f"FAIL ({len(contras)} contradictions)"
                if contras:
                    result["first_contradiction"] = contras[0]

            all_results[f"{variant_name}_w{width}"] = result

            # Print notable results
            if ok or width <= 15 or width % 10 == 0:
                print(f"  W={width:>2} ({num_rows}×{width}): {tag}"
                      + (f"  — {connected=}" if ok else ""))

    # ═══ Summary ═════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Time: {elapsed:.3f}s")
    print()

    if passes:
        print(f"  PASSING CONFIGURATIONS:")
        for w, v, cm, pt_preview in passes:
            print(f"    W={w} {v}: {cm}/24 cribs  PT={pt_preview}...")
    else:
        print(f"  NO passing configurations found.")

    # Count failures by variant
    for var in ['vigenere', 'beaufort']:
        fails = sum(1 for k, v in all_results.items()
                    if k.startswith(var) and not v['consistent'])
        ok = sum(1 for k, v in all_results.items()
                 if k.startswith(var) and v['consistent'])
        print(f"  {var}: {fails} fail, {ok} pass")

    verdict = "NO SIGNAL" if not passes else "INVESTIGATE"
    print(f"\n  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_10_additive_grid_key.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-10",
            "hypothesis": "Additive row+column grid key (all widths 2-48)",
            "total_time_s": round(elapsed, 3),
            "verdict": verdict,
            "passes": [{"width": w, "variant": v, "cribs": c}
                       for w, v, c, _ in passes],
            "results": all_results,
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_10_additive_grid_key.py")
    print(f"\nRESULT: passes={len(passes)} verdict={verdict}")


if __name__ == "__main__":
    main()
