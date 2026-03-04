#!/usr/bin/env python3
"""
Cipher: monoalphabetic substitution
Family: substitution
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-44: Trifid 3×3×3 Period 16 — Deep Analysis + Computational Search

Period 16 is the SOLE algebraic survivor from E-S-42b (Trifid 3×3×3).
All other periods 2-97 were eliminated by cross-group constraint propagation.

This script:
1. Re-verifies algebraic constraints at period 16 (with detailed logging)
2. Builds the full constraint graph from BOTH crib groups
3. Enumerates valid 3×3×3 cube assignments compatible with constraints
4. Either finds a valid cube → further testing, or eliminates period 16

Output: results/e_s_44_trifid_p16.json
"""

import json
import sys
import os
import time
from collections import defaultdict
from itertools import permutations, product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH

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


def derive_trifid_equations(groups):
    """Derive ALL equations from Trifid encryption at given period.

    Returns list of equations, each of form:
    ((coord_type, letter), (coord_type, letter))  meaning they're equal

    Also returns 'lookup' equations: cube(a,b,c) = letter
    """
    equalities = []
    lookups = []  # (coord_a, coord_b, coord_c, ct_letter) — cube(a,b,c) = ct_letter

    for group in groups:
        if group['n_known'] < 2:
            continue

        pt = group['pt']
        ct = group['ct']
        p = group['length']

        # Build intermediate sequence: layers ++ rows ++ cols
        layers = [(('l', pt[i]) if pt[i] else ('l', f"?{group['start']+i}")) for i in range(p)]
        rows = [(('r', pt[i]) if pt[i] else ('r', f"?{group['start']+i}")) for i in range(p)]
        cols = [(('c', pt[i]) if pt[i] else ('c', f"?{group['start']+i}")) for i in range(p)]

        combined = layers + rows + cols  # 3p elements

        # Re-triple: read in groups of 3
        for trip_idx in range(p):
            if trip_idx >= len(ct):
                break
            idx = trip_idx * 3
            if idx + 2 >= len(combined):
                break

            a, b, c = combined[idx], combined[idx+1], combined[idx+2]
            ct_letter = ct[trip_idx]

            # Check if all three are known (no '?' letters)
            a_known = not a[1].startswith('?')
            b_known = not b[1].startswith('?')
            c_known = not c[1].startswith('?')

            # cube(a, b, c) = ct_letter means:
            # l(ct_letter) = a, r(ct_letter) = b, c(ct_letter) = c
            # We can extract equalities for EACH known element, even in partial triples
            if a_known:
                equalities.append((('l', ct_letter), a))
            if b_known:
                equalities.append((('r', ct_letter), b))
            if c_known:
                equalities.append((('c', ct_letter), c))

            if a_known and b_known and c_known:
                lookups.append((a, b, c, ct_letter))

    return equalities, lookups


def union_find_analysis(equalities):
    """Build union-find from equalities, return equivalence classes."""
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

    # Build equivalence classes
    classes = defaultdict(set)
    for key in parent:
        classes[find(key)].add(key)

    return classes, find


def check_contradictions(equalities):
    """Check for same-cell and pigeonhole contradictions."""
    classes, find = union_find_analysis(equalities)

    # Collect real letters
    letters = set()
    for eq_a, eq_b in equalities:
        for coord in [eq_a, eq_b]:
            if not coord[1].startswith('?'):
                letters.add(coord[1])
    letters = sorted(letters)

    # Same-cell check
    same_cell = []
    for i in range(len(letters)):
        for j in range(i+1, len(letters)):
            X, Y = letters[i], letters[j]
            if (find(('l', X)) == find(('l', Y)) and
                find(('r', X)) == find(('r', Y)) and
                find(('c', X)) == find(('c', Y))):
                same_cell.append((X, Y))

    # Pigeonhole: letters sharing 2 of 3 coordinate classes
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

    return same_cell, pigeonhole, letters, classes, find


def analyze_constraint_graph(equalities, find, letters):
    """Detailed analysis of constraint structure at period 16."""
    # For each letter, identify its equivalence class for l, r, c
    letter_coords = {}
    for letter in letters:
        l_class = find(('l', letter))
        r_class = find(('r', letter))
        c_class = find(('c', letter))
        letter_coords[letter] = (l_class, r_class, c_class)

    # Count unique classes per coordinate type
    l_classes = set()
    r_classes = set()
    c_classes = set()
    for letter in letters:
        l_classes.add(find(('l', letter)))
        r_classes.add(find(('r', letter)))
        c_classes.add(find(('c', letter)))

    # Count cross-type equalities (e.g., l(X) = r(Y))
    cross_type = 0
    for eq_a, eq_b in equalities:
        if eq_a[0][0] != eq_b[0][0]:  # different coord type (l vs r, etc.)
            cross_type += 1

    return {
        'n_letters': len(letters),
        'n_l_classes': len(l_classes),
        'n_r_classes': len(r_classes),
        'n_c_classes': len(c_classes),
        'n_cross_type_equalities': cross_type,
        'letter_coords': letter_coords,
    }


def try_enumerate_cubes(equalities, lookups, find, letters):
    """Try to enumerate valid 3×3×3 cube assignments.

    Each of 26 letters gets (l, r, c) ∈ {0,1,2}³.
    No two letters can share the same (l,r,c) triple.
    One of the 27 cells is empty.

    The equalities constrain which coordinates must be equal.
    """
    print("\n  === Cube Enumeration ===")

    # Build equivalence classes for known letters
    classes, find2 = union_find_analysis(equalities)

    # Identify unique coordinate variables
    # Each letter has 3 coordinates: l(X), r(X), c(X) in {0,1,2}
    # Equalities link some of these together

    # Collect all equivalence class representatives involving known letters
    var_reps = set()
    for letter in ALPH:
        for coord_type in ['l', 'r', 'c']:
            var_reps.add(find2((coord_type, letter)))

    # Map each representative to the set of (coord_type, letter) pairs it covers
    rep_to_members = defaultdict(set)
    for letter in ALPH:
        for coord_type in ['l', 'r', 'c']:
            rep = find2((coord_type, letter))
            rep_to_members[rep].add((coord_type, letter))

    unique_reps = sorted(rep_to_members.keys(), key=str)
    print(f"  Unique coordinate variables: {len(unique_reps)}")
    print(f"  Total assignments: 26 letters × 3 coords = 78")
    print(f"  Reduction: {78 - len(unique_reps)} equalities merge variables")

    # Each unique rep must take a value in {0, 1, 2}
    # The cube constraint: no two letters share the same (l,r,c) triple
    # Since 27 cells hold 26 letters + 1 empty, exactly one triple is unused

    # For the constrained letters (those involved in equalities),
    # check how many free variables remain
    constrained_letters = set(letters)
    free_letters = [l for l in ALPH if l not in constrained_letters]

    print(f"  Constrained letters: {len(constrained_letters)} ({', '.join(sorted(constrained_letters))})")
    print(f"  Free letters: {len(free_letters)} ({', '.join(sorted(free_letters))})")

    # For each constrained letter, its (l,r,c) coordinates are determined
    # by the equivalence class values. Let's count the number of independent
    # variables for constrained letters.
    constrained_reps = set()
    for letter in constrained_letters:
        for coord_type in ['l', 'r', 'c']:
            constrained_reps.add(find2((coord_type, letter)))

    print(f"  Independent variables for constrained letters: {len(constrained_reps)}")
    print(f"  Each takes value in {{0, 1, 2}}")
    print(f"  Naive search space: 3^{len(constrained_reps)} = {3**len(constrained_reps):.1e}")

    # If the search space is small enough, enumerate
    if len(constrained_reps) > 30:
        print(f"  Search space too large for direct enumeration. Trying constraint propagation...")
        return constraint_propagation_search(equalities, lookups, find2, letters, constrained_reps, rep_to_members)

    return brute_force_search(equalities, lookups, find2, letters, constrained_reps, rep_to_members)


def constraint_propagation_search(equalities, lookups, find, letters, constrained_reps, rep_to_members):
    """Use constraint propagation to reduce search space."""
    print("\n  --- Constraint Propagation ---")

    # Initialize domains: each rep can be {0, 1, 2}
    constrained_reps_list = sorted(constrained_reps, key=str)
    domains = {rep: {0, 1, 2} for rep in constrained_reps_list}

    # Build "cell uniqueness" constraints
    # For each pair of distinct letters, they can't share the same (l,r,c) triple
    # This is hard to propagate directly, but we can use lookup constraints

    # From lookups: cube(a, b, c) = ct_letter
    # This means: the letter at position (val(a), val(b), val(c)) is ct_letter
    # So l(ct_letter) = val(a), r(ct_letter) = val(b), c(ct_letter) = val(c)
    # But we already encoded this as equalities. The ADDITIONAL constraint is
    # that different lookups mapping to different letters must have different triples.

    # Let's check: how many lookup equations do we have?
    print(f"  Lookup equations: {len(lookups)}")

    # Group lookups by CT letter
    ct_to_lookups = defaultdict(list)
    for a, b, c, ct_letter in lookups:
        ct_to_lookups[ct_letter].append((a, b, c))

    # If same CT letter appears multiple times, the lookup triples must be identical
    # (already encoded as equalities). If different CT letters, triples must differ.

    # Count how many distinct CT letters appear in lookups
    print(f"  Distinct CT letters in lookups: {len(ct_to_lookups)}")
    for ct_letter, lups in sorted(ct_to_lookups.items()):
        if len(lups) > 1:
            print(f"    {ct_letter}: {len(lups)} lookups (triples must be identical)")

    # Try arc consistency: for each pair of reps that form part of a cell,
    # check if their domain combination is compatible with uniqueness

    # Actually, let's just count the constraint structure
    # For each letter in ALPH, count which rep determines each coordinate
    letter_to_reps = {}
    for letter in ALPH:
        l_rep = find(('l', letter))
        r_rep = find(('r', letter))
        c_rep = find(('c', letter))
        letter_to_reps[letter] = (l_rep, r_rep, c_rep)

    # Check which letters share reps (and thus are constrained to have equal coordinates)
    # This is the key: if l(A) = l(B) (same rep), then A and B are in the same layer
    for coord_type in ['l', 'r', 'c']:
        rep_groups = defaultdict(set)
        for letter in ALPH:
            idx = {'l': 0, 'r': 1, 'c': 2}[coord_type]
            rep = letter_to_reps[letter][idx]
            if rep in constrained_reps:
                rep_groups[rep].add(letter)

        for rep, group in sorted(rep_groups.items(), key=lambda x: -len(x[1])):
            if len(group) > 1:
                # These letters all share the same coordinate value
                # In a 3×3×3 cube, at most 9 letters can share the same layer/row/col value
                pass

    # KEY INSIGHT: cell uniqueness means for each (l_val, r_val, c_val) triple,
    # at most ONE letter can occupy it. 27 cells, 26 letters, 1 empty.

    # Let's identify groups of letters that MUST share the same cell
    # (i.e., all three coordinates are in the same equivalence classes)
    cell_groups = defaultdict(set)
    for letter in ALPH:
        cell_key = letter_to_reps[letter]
        cell_groups[cell_key].add(letter)

    max_cell = max(len(g) for g in cell_groups.values())
    print(f"\n  Cell groups (letters with identical coordinate reps):")
    for cell_key, group in sorted(cell_groups.items(), key=lambda x: -len(x[1])):
        if len(group) > 1:
            print(f"    {sorted(group)} — share all 3 coord reps")

    if max_cell > 1:
        print(f"\n  *** CONTRADICTION: {max_cell} letters forced into same cell! ***")
        return {'verdict': 'ELIMINATED', 'reason': 'same-cell', 'max_cell_size': max_cell}

    # If no same-cell contradiction, check pigeonhole more carefully
    # For each pair of coordinate types, group letters by their rep pair
    for ct1, ct2, ct_name in [('l','r','lr'), ('l','c','lc'), ('r','c','rc')]:
        pair_groups = defaultdict(set)
        for letter in ALPH:
            idx1 = {'l': 0, 'r': 1, 'c': 2}[ct1]
            idx2 = {'l': 0, 'r': 1, 'c': 2}[ct2]
            pair_key = (letter_to_reps[letter][idx1], letter_to_reps[letter][idx2])
            pair_groups[pair_key].add(letter)

        for pair_key, group in pair_groups.items():
            if len(group) > 3:
                print(f"  Pigeonhole ({ct_name}): {sorted(group)} — {len(group)} letters, only 3 values for 3rd coord")
                return {'verdict': 'ELIMINATED', 'reason': f'pigeonhole-{ct_name}', 'group': sorted(group)}

    # If still no contradiction, count degrees of freedom
    n_free_reps = len(constrained_reps)
    n_unconstrained = len([l for l in ALPH if all(r not in constrained_reps for r in letter_to_reps[l])])

    print(f"\n  No algebraic contradiction found.")
    print(f"  Free coordinate variables: {n_free_reps} (each ∈ {{0,1,2}})")
    print(f"  Unconstrained letters: {n_unconstrained}")
    print(f"  Total search space: 3^{n_free_reps} × placement of {n_unconstrained} unconstrained letters")

    # Try systematic search with backtracking
    return backtracking_search(find, letter_to_reps, constrained_reps, lookups)


def backtracking_search(find, letter_to_reps, constrained_reps, lookups):
    """Backtracking search over constrained coordinate variables."""
    print("\n  --- Backtracking Search ---")

    reps_list = sorted(constrained_reps, key=str)
    n_reps = len(reps_list)
    rep_idx = {rep: i for i, rep in enumerate(reps_list)}

    print(f"  Variables: {n_reps}")
    print(f"  Domain: {{0, 1, 2}} each")
    print(f"  Search space: 3^{n_reps} = {3**n_reps:.1e}")

    if 3**n_reps > 1e12:
        print(f"  Too large for exhaustive backtracking. Reporting constraints only.")
        return {'verdict': 'UNDERDETERMINED', 'n_vars': n_reps, 'search_space': f'3^{n_reps}'}

    # Build constraint list for cell uniqueness
    # For each pair of letters, their (l_rep, r_rep, c_rep) triples should not
    # map to the same (val, val, val) triple (unless they share reps)

    letter_rep_indices = {}
    for letter in ALPH:
        l_rep, r_rep, c_rep = letter_to_reps[letter]
        li = rep_idx.get(l_rep)
        ri = rep_idx.get(r_rep)
        ci = rep_idx.get(c_rep)
        letter_rep_indices[letter] = (li, ri, ci)

    # For letters where all reps are constrained, we can check cell uniqueness
    constrained_letters = [l for l in ALPH if all(idx is not None for idx in letter_rep_indices[l])]
    print(f"  Fully constrained letters: {len(constrained_letters)}")

    # Backtracking: assign values to reps_list[0..n_reps-1]
    assignment = [None] * n_reps
    solutions_found = 0
    nodes_explored = 0
    t0 = time.time()

    def is_valid_partial():
        """Check if current partial assignment violates any constraint."""
        # Check cell uniqueness among fully-assigned constrained letters
        cells_used = {}
        for letter in constrained_letters:
            li, ri, ci = letter_rep_indices[letter]
            lv = assignment[li] if li is not None else None
            rv = assignment[ri] if ri is not None else None
            cv = assignment[ci] if ci is not None else None

            if lv is not None and rv is not None and cv is not None:
                cell = (lv, rv, cv)
                if cell in cells_used:
                    return False  # Two letters in same cell
                cells_used[cell] = letter
        return True

    def backtrack(idx):
        nonlocal solutions_found, nodes_explored

        if idx == n_reps:
            # Full assignment — verify
            if is_valid_partial():
                solutions_found += 1
                if solutions_found <= 10:
                    cells = {}
                    for letter in constrained_letters:
                        li, ri, ci = letter_rep_indices[letter]
                        cell = (assignment[li], assignment[ri], assignment[ci])
                        cells[letter] = cell
                    print(f"    Solution #{solutions_found}: {dict(sorted(cells.items()))}")
                if solutions_found % 1000 == 0:
                    elapsed = time.time() - t0
                    print(f"    ... {solutions_found} solutions found ({elapsed:.1f}s)")
            return

        nodes_explored += 1
        if nodes_explored % 1000000 == 0:
            elapsed = time.time() - t0
            print(f"    [{nodes_explored:,} nodes, {solutions_found} solutions, {elapsed:.1f}s]")

        for val in range(3):
            assignment[idx] = val
            if is_valid_partial():
                backtrack(idx + 1)
            assignment[idx] = None

    if n_reps <= 25:
        print(f"  Starting backtracking search...")
        backtrack(0)
        elapsed = time.time() - t0
        print(f"  Search complete: {solutions_found} solutions in {nodes_explored:,} nodes ({elapsed:.1f}s)")

        if solutions_found == 0:
            return {'verdict': 'ELIMINATED', 'reason': 'exhaustive-search',
                    'nodes': nodes_explored, 'time': round(elapsed, 1)}
        else:
            return {'verdict': 'SURVIVES', 'n_solutions': solutions_found,
                    'nodes': nodes_explored, 'time': round(elapsed, 1)}
    else:
        print(f"  Too many variables ({n_reps}) for pure backtracking.")
        return {'verdict': 'UNDERDETERMINED', 'n_vars': n_reps}


def brute_force_search(equalities, lookups, find, letters, constrained_reps, rep_to_members):
    """Brute force for small search spaces."""
    print(f"  Direct enumeration of 3^{len(constrained_reps)} = {3**len(constrained_reps)} assignments")
    # (redirect to constraint propagation which handles this)
    return constraint_propagation_search(equalities, lookups, find, letters, constrained_reps, rep_to_members)


def main():
    print("=" * 70)
    print("E-S-44: Trifid 3×3×3 Period 16 — Deep Analysis")
    print("=" * 70)

    t0 = time.time()
    period = 16

    # Step 1: Get groups and analyze coverage
    groups = get_groups(period)
    print(f"\nPeriod {period}: {len(groups)} groups")
    for g in groups:
        known_positions = [g['start'] + i for i, k in enumerate(g['known_mask']) if k]
        if g['n_known'] > 0:
            pt_str = ''.join(ch if ch else '.' for ch in g['pt'])
            ct_str = ''.join(g['ct'])
            print(f"  Group {g['group_idx']} (pos {g['start']}-{g['end']-1}): "
                  f"{g['n_known']}/{g['length']} known")
            print(f"    PT: {pt_str}")
            print(f"    CT: {ct_str}")

    # Step 2: Derive algebraic equations
    print(f"\n--- Deriving Trifid equations ---")
    equalities, lookups = derive_trifid_equations(groups)
    print(f"  Total equalities: {len(equalities)}")
    print(f"  Total lookup equations: {len(lookups)}")

    # Step 3: Check for contradictions
    print(f"\n--- Checking contradictions ---")
    same_cell, pigeonhole, letters, classes, find = check_contradictions(equalities)

    print(f"  Same-cell contradictions: {len(same_cell)}")
    if same_cell:
        for x, y in same_cell[:10]:
            print(f"    {x} = {y}")

    print(f"  Pigeonhole contradictions: {len(pigeonhole)}")
    if pigeonhole:
        for ptype, group in pigeonhole[:10]:
            print(f"    ({ptype}): {group}")

    if same_cell or pigeonhole:
        verdict = "ELIMINATED"
        reason = "same-cell" if same_cell else "pigeonhole"
        print(f"\n  *** VERDICT: ELIMINATED ({reason}) ***")
    else:
        # Step 4: Detailed constraint analysis
        print(f"\n--- Constraint graph analysis ---")
        analysis = analyze_constraint_graph(equalities, find, letters)
        print(f"  Letters involved: {analysis['n_letters']}")
        print(f"  Layer equivalence classes: {analysis['n_l_classes']}")
        print(f"  Row equivalence classes: {analysis['n_r_classes']}")
        print(f"  Col equivalence classes: {analysis['n_c_classes']}")
        print(f"  Cross-type equalities: {analysis['n_cross_type_equalities']}")

        # Step 5: Try enumeration
        print(f"\n--- Attempting cube enumeration ---")
        enum_result = try_enumerate_cubes(equalities, lookups, find, letters)
        verdict = enum_result.get('verdict', 'UNKNOWN')
        reason = enum_result.get('reason', '')

        print(f"\n  *** VERDICT: {verdict} ***")
        if reason:
            print(f"  Reason: {reason}")

    elapsed = time.time() - t0

    results = {
        'experiment': 'E-S-44',
        'period': period,
        'n_equalities': len(equalities),
        'n_lookups': len(lookups),
        'n_same_cell': len(same_cell),
        'n_pigeonhole': len(pigeonhole),
        'same_cell_examples': same_cell[:20],
        'pigeonhole_examples': [(t, g) for t, g in pigeonhole[:10]],
        'verdict': verdict,
        'elapsed_seconds': round(elapsed, 1),
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_44_trifid_p16.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*70}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  Artifact: results/e_s_44_trifid_p16.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_44_trifid_p16.py")


if __name__ == "__main__":
    main()
