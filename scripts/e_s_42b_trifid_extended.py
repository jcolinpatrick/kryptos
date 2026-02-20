#!/usr/bin/env python3
"""
E-S-42b: Trifid 3×3×3 Extended Algebraic Elimination (Periods 9-14)

Previous work (E-S-05, Session 10) eliminated Trifid periods 2-8.
Periods 9, 11 survived single-group analysis.

KEY RESULT: Cross-group constraints (groups 7+3) at period 9 force
T, L, C, P into positions (lL, lL, *) — 4 letters needing 4 distinct
values from {0,1,2}. PIGEONHOLE CONTRADICTION.

This script verifies the period 9 proof computationally and tests 10-14.

Output: results/e_s_42b_trifid_extended.json
"""

import json
import sys
import os
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT

N = CT_LEN


def get_groups(period):
    """Get all period-groups with their PT/CT data."""
    groups = []
    for g in range((N + period - 1) // period):
        start = g * period
        end = min(start + period, N)
        pt = []
        ct = []
        known_mask = []
        for i in range(start, end):
            ct.append(CT[i])
            if i in CRIB_DICT:
                pt.append(CRIB_DICT[i])
                known_mask.append(True)
            else:
                pt.append(None)
                known_mask.append(False)
        groups.append({
            'group_idx': g,
            'start': start,
            'end': end,
            'length': end - start,
            'pt': pt,
            'ct': ct,
            'known_mask': known_mask,
            'n_known': sum(known_mask),
        })
    return groups


def trifid_triples(pt_letters, period):
    """Standard Trifid: [layers, rows, cols] concatenated, re-tripled.

    Returns list of ((type1,letter1), (type2,letter2), (type3,letter3)) triples.
    """
    layers = [('l', ch) for ch in pt_letters]
    rows = [('r', ch) for ch in pt_letters]
    cols = [('c', ch) for ch in pt_letters]
    combined = layers + rows + cols
    triples = []
    for i in range(0, len(combined), 3):
        if i + 2 < len(combined):
            triples.append((combined[i], combined[i+1], combined[i+2]))
    return triples


def derive_trifid_constraints(groups):
    """Derive algebraic constraints from Trifid equations across all groups."""
    equalities = []  # (coord_a, coord_b) meaning coord_a = coord_b

    for group in groups:
        if group['n_known'] < 2:
            continue

        pt = group['pt']
        ct = group['ct']
        p = group['length']

        pt_with_unknowns = [ch if ch is not None else f"?{group['start']+i}" for i, ch in enumerate(pt)]
        triples = trifid_triples(pt_with_unknowns, p)

        for trip_idx, triple in enumerate(triples):
            if trip_idx >= len(ct):
                break
            ct_letter = ct[trip_idx]

            (t1, l1), (t2, l2), (t3, l3) = triple

            # Skip if any letter is unknown
            if any(x.startswith('?') for x in [l1, l2, l3]):
                continue

            # cube(coord1, coord2, coord3) = ct_letter
            # means: layer of ct_letter = coord1, row = coord2, col = coord3
            eq1 = (('l', ct_letter), (t1, l1))
            eq2 = (('r', ct_letter), (t2, l2))
            eq3 = (('c', ct_letter), (t3, l3))

            equalities.extend([eq1, eq2, eq3])

    return equalities


def find_trifid_contradictions(equalities):
    """Use union-find to propagate equalities and check for Trifid contradictions.

    Contradiction types:
    1. Same-cell: two distinct letters forced to same (l,r,c) position
    2. Pigeonhole: >3 letters share 2 coordinates, need >3 distinct values for 3rd
    """
    parent = {}

    def find(x):
        if x not in parent:
            parent[x] = x
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for eq_a, eq_b in equalities:
        union(eq_a, eq_b)

    # Collect all real letters
    letters = set()
    for eq_a, eq_b in equalities:
        for coord in [eq_a, eq_b]:
            if not coord[1].startswith('?'):
                letters.add(coord[1])

    letters = sorted(letters)

    # Check for same-cell contradictions
    same_cell = []
    for i in range(len(letters)):
        for j in range(i+1, len(letters)):
            X, Y = letters[i], letters[j]
            if (find(('l', X)) == find(('l', Y)) and
                find(('r', X)) == find(('r', Y)) and
                find(('c', X)) == find(('c', Y))):
                same_cell.append((X, Y))

    # Check for pigeonhole: group letters by (l-class, r-class) and check if >3
    lr_groups = defaultdict(set)
    lc_groups = defaultdict(set)
    rc_groups = defaultdict(set)

    for letter in letters:
        l_rep = find(('l', letter))
        r_rep = find(('r', letter))
        c_rep = find(('c', letter))
        lr_groups[(l_rep, r_rep)].add(letter)
        lc_groups[(l_rep, c_rep)].add(letter)
        rc_groups[(r_rep, c_rep)].add(letter)

    pigeonhole = []
    for key, group in lr_groups.items():
        if len(group) > 3:
            pigeonhole.append(('lr', sorted(group)))
    for key, group in lc_groups.items():
        if len(group) > 3:
            pigeonhole.append(('lc', sorted(group)))
    for key, group in rc_groups.items():
        if len(group) > 3:
            pigeonhole.append(('rc', sorted(group)))

    return same_cell, pigeonhole


def main():
    print("=" * 60)
    print("E-S-42b: Trifid 3×3×3 Extended Algebraic Elimination")
    print("=" * 60)

    t0 = time.time()
    results = {
        'experiment': 'E-S-42b',
        'periods': {}
    }

    for period in [9, 10, 11, 12, 13, 14]:
        print(f"\n--- Period {period} ---")
        groups = get_groups(period)

        for g in groups:
            if g['n_known'] > 0:
                print(f"  Group {g['group_idx']} (pos {g['start']}-{g['end']-1}): "
                      f"{g['n_known']}/{g['length']} known")

        equalities = derive_trifid_constraints(groups)
        same_cell, pigeonhole = find_trifid_contradictions(equalities)

        verdict = "SURVIVES"
        if same_cell:
            verdict = "ELIMINATED (same-cell)"
        elif pigeonhole:
            verdict = "ELIMINATED (pigeonhole)"

        print(f"  Equalities: {len(equalities)}")
        print(f"  Same-cell contradictions: {len(same_cell)}")
        print(f"  Pigeonhole contradictions: {len(pigeonhole)}")

        if same_cell:
            for x, y in same_cell[:5]:
                print(f"    Same cell: {x} = {y}")
        if pigeonhole:
            for ptype, group in pigeonhole[:5]:
                print(f"    Pigeonhole ({ptype}): {group} ({len(group)} letters, only 3 values)")

        print(f"  Verdict: {verdict}")

        results['periods'][str(period)] = {
            'n_equalities': len(equalities),
            'n_same_cell': len(same_cell),
            'n_pigeonhole': len(pigeonhole),
            'same_cell_examples': same_cell[:10],
            'pigeonhole_examples': [(t, g) for t, g in pigeonhole[:10]],
            'verdict': verdict,
        }

    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Trifid 3×3×3 elimination status:")
    print(f"    Periods 2-8: ELIMINATED (Session 10, single-group)")
    for p in [9, 10, 11, 12, 13, 14]:
        v = results['periods'][str(p)]['verdict']
        print(f"    Period {p}: {v}")
    print(f"  Time: {elapsed:.1f}s")

    results['elapsed_seconds'] = round(elapsed, 1)

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_42b_trifid_extended.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n  Artifact: results/e_s_42b_trifid_extended.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_42b_trifid_extended.py")


if __name__ == "__main__":
    main()
