#!/usr/bin/env python3
"""
Cipher: Bifid
Family: substitution
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-09: Algebraic bifid/trifid contradiction finder for ALL periods.

For each period p and grid size (5x5 or 6x6), checks whether the known
crib positions force the same grid cell to contain two different letters.
If so, that (cipher, period) combo is algebraically eliminated.

This extends E-S-05 which only checked periods 2-8 and 11.
Now checks ALL periods from 2 to 50.

Also checks: does the same cell pair appear in multiple blocks with
different CT values? (indirect contradiction through shared grid lookups)
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
CT_LIST = list(CT)

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
CRIB_DICT = {p: c for p, c in _sorted}
CRIB_SET = set(CRIB_POS)


def bifid_cell_constraints(period, grid_rows):
    """For bifid with given period and grid size, find all grid cell constraints.

    Returns list of (cell_key, required_value, block_idx, detail_str) tuples.
    cell_key = (coordinate_type, letters_involved) identifying the grid lookup.

    For bifid period p, block starting at pos b:
    Combined sequence = [row(PT[b]), row(PT[b+1]), ..., row(PT[b+p-1]),
                         col(PT[b]), col(PT[b+1]), ..., col(PT[b+p-1])]
    CT[b+j] = grid[combined[2j], combined[2j+1]]

    Each combined[k] is either row(PT[b+m]) or col(PT[b+m]) for some m.
    If PT[b+m] is known (crib), then we know the symbolic identity of that coordinate.
    If PT[b+m] is unknown, the coordinate is free.

    A constraint is useful when BOTH coordinates in a pair are known (from cribs).
    Then grid[coord1, coord2] = CT[b+j] is a concrete constraint.
    """
    constraints = []
    n = CT_LEN

    # Process each block
    num_full_blocks = n // period
    for block_idx in range(num_full_blocks + (1 if n % period else 0)):
        b = block_idx * period
        block_len = min(period, n - b)

        if block_len < 2:
            continue

        # Build the combined coordinate sequence
        # combined[k] for k=0..block_len-1 is row(PT[b+k])
        # combined[k] for k=block_len..2*block_len-1 is col(PT[b + k - block_len])

        # For each output position j (CT[b+j]):
        # CT[b+j] = grid[combined[2j], combined[2j+1]]
        # We need both combined[2j] and combined[2j+1] to be from known crib positions

        for j in range(block_len):
            idx1 = 2 * j
            idx2 = 2 * j + 1

            if idx2 >= 2 * block_len:
                break  # shouldn't happen for full blocks

            # Map combined index to (type, position)
            def combined_to_source(idx):
                if idx < block_len:
                    return ('row', b + idx)
                else:
                    return ('col', b + idx - block_len)

            type1, pos1 = combined_to_source(idx1)
            type2, pos2 = combined_to_source(idx2)

            # Both positions must be in the crib set
            if pos1 in CRIB_SET and pos2 in CRIB_SET:
                pt1 = CRIB_DICT[pos1]
                pt2 = CRIB_DICT[pos2]
                ct_val = CT_LIST[b + j]

                cell_key = (type1, pt1, type2, pt2)
                constraints.append((cell_key, ct_val, block_idx,
                    f"block {block_idx} (pos {b}-{b+block_len-1}), "
                    f"j={j}: grid[{type1}({pt1}@{pos1}), {type2}({pt2}@{pos2})] = {ct_val} (CT[{b+j}])"))

    return constraints


def find_contradictions(constraints):
    """Find cell keys that are forced to equal two different CT values."""
    cell_values = defaultdict(list)
    for cell_key, ct_val, block_idx, detail in constraints:
        cell_values[cell_key].append((ct_val, block_idx, detail))

    contradictions = []
    for cell_key, entries in cell_values.items():
        vals = set(e[0] for e in entries)
        if len(vals) > 1:
            contradictions.append((cell_key, entries))

    return contradictions


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-09: Algebraic Bifid Contradiction Analysis")
    print("=" * 60)
    print(f"CT length: {CT_LEN}")
    print(f"Crib positions: {len(CRIB_POS)}")
    print(f"ENE: positions {min(p for p,_ in CRIB_ENTRIES if 20 <= p <= 35)}-{max(p for p,_ in CRIB_ENTRIES if 20 <= p <= 35)}")
    print(f"BC:  positions {min(p for p,_ in CRIB_ENTRIES if 60 <= p <= 75)}-{max(p for p,_ in CRIB_ENTRIES if 60 <= p <= 75)}")
    print()

    all_results = {}
    eliminated_periods = []
    surviving_periods = []

    for period in range(2, 50):
        constraints = bifid_cell_constraints(period, grid_rows=6)
        contradictions = find_contradictions(constraints)

        status = "ELIMINATED" if contradictions else "SURVIVES"
        n_constraints = len(constraints)
        n_unique_cells = len(set(c[0] for c in constraints))

        result = {
            "period": period,
            "status": status,
            "n_constraints": n_constraints,
            "n_unique_cells": n_unique_cells,
            "n_contradictions": len(contradictions),
            "contradiction_details": [],
        }

        if contradictions:
            eliminated_periods.append(period)
            for cell_key, entries in contradictions:
                detail = {
                    "cell": str(cell_key),
                    "conflicting_values": list(set(e[0] for e in entries)),
                    "sources": [e[2] for e in entries],
                }
                result["contradiction_details"].append(detail)
        else:
            surviving_periods.append(period)

        all_results[f"period_{period}"] = result

        # Print summary line
        tag = "X" if contradictions else " "
        contra_str = ""
        if contradictions:
            first = contradictions[0]
            vals = sorted(set(e[0] for e in first[1]))
            contra_str = f"  {first[0]} → {vals}"

        if period <= 15 or contradictions or period in [20, 25, 30, 40, 49]:
            print(f"  [{tag}] p={period:>2}: {n_constraints:>3} constraints, "
                  f"{n_unique_cells:>3} unique cells, "
                  f"{len(contradictions)} contradictions{contra_str}")

    # ═══ Summary ═════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Total time: {elapsed:.3f}s")
    print()
    print(f"  ELIMINATED periods: {eliminated_periods}")
    print(f"  SURVIVING periods:  {surviving_periods}")
    print()

    # Check if the surviving periods are just the ones with too few constraints
    for p in surviving_periods:
        r = all_results[f"period_{p}"]
        print(f"  p={p}: {r['n_constraints']} constraints, {r['n_unique_cells']} unique cells "
              f"{'(insufficient data)' if r['n_constraints'] < 4 else ''}")

    print()

    # Also check: for surviving periods, are constraints consistent?
    # (i.e., do all multi-occurrence cells agree on their value?)
    print("  Consistency check on surviving periods:")
    for p in surviving_periods:
        constraints = bifid_cell_constraints(p, grid_rows=6)
        cell_values = defaultdict(set)
        for cell_key, ct_val, _, _ in constraints:
            cell_values[cell_key].add(ct_val)
        n_multi = sum(1 for v in cell_values.values() if len(v) > 1)
        n_confirmed = sum(1 for v in cell_values.values() if len(v) == 1 and
                         sum(1 for c in constraints if c[0] == next(iter(v))) > 0)
        print(f"    p={p}: {len(cell_values)} cells referenced, "
              f"{sum(1 for v in cell_values.values() if len(v) >= 2)} with 2+ refs, "
              f"{n_multi} contradictions")

    # Final verdict
    print()
    if len(surviving_periods) == 0:
        verdict = "ALL PERIODS ELIMINATED"
    elif all(all_results[f"period_{p}"]["n_constraints"] < 4 for p in surviving_periods):
        verdict = "SURVIVING PERIODS HAVE INSUFFICIENT CONSTRAINTS"
    else:
        verdict = f"{len(surviving_periods)} PERIODS SURVIVE"

    print(f"  VERDICT: {verdict}")
    print(f"  Bifid 6×6: eliminated at {len(eliminated_periods)}/{48} periods tested")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_09_bifid_algebraic.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-09",
            "hypothesis": "Bifid 6x6 at periods 2-49 (algebraic contradiction analysis)",
            "total_time_s": round(elapsed, 3),
            "verdict": verdict,
            "eliminated_periods": eliminated_periods,
            "surviving_periods": surviving_periods,
            "results_by_period": all_results,
        }, f, indent=2)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_09_bifid_algebraic.py")
    print(f"\nRESULT: eliminated={len(eliminated_periods)}/48 verdict={verdict}")


if __name__ == "__main__":
    main()
