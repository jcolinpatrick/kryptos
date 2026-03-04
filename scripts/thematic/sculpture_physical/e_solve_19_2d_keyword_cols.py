#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: thematic/sculpture_physical
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-SOLVE-19: 2D Matrix Code with Keyword-Ordered Columnar Transposition

E-SOLVE-17 eliminated the additive 2D key model k[r][c] = A[r] + B[c]
for DIRECT positional correspondence and NATURAL column order.

But with keyword-ordered columns, different CT characters map to each
grid cell, producing DIFFERENT equation systems that may be consistent.

This script tests ALL column orderings at widths 7-10 (5K to 3.6M orderings)
to see if ANY ordering produces a consistent 2D key system.

Model:
  - Write PT row-by-row into grid of width W
  - Encrypt each cell: E[r][c] = (PT[r*W+c] + A[r] + B[c]) % 26
  - Read columns in order sigma(0), sigma(1), ... → CT

For each crib at flat PT position p:
  Grid cell (p//W, p%W) → CT position determined by sigma
  A[p//W] + B[p%W] = (CT[sigma_pos] - PT[p]) % 26
"""

import sys
from itertools import permutations

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

CT_INT = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS}


def solve_2d_consistency(equations):
    """
    Check if the system A[r] + B[c] = d (mod 26) is consistent.
    equations: list of (r, c, d)
    Returns True if consistent, False otherwise.
    """
    A = {}
    B = {}

    # Build adjacency
    adj_row = {}
    adj_col = {}
    rows = set()
    cols = set()
    for r, c, d in equations:
        rows.add(r)
        cols.add(c)
        adj_row.setdefault(r, []).append((c, d))
        adj_col.setdefault(c, []).append((r, d))

    # Find connected components and check consistency via BFS
    visited_rows = set()
    visited_cols = set()

    for start_r in rows:
        if start_r in visited_rows:
            continue
        # BFS from start_r with A[start_r] = 0
        A[start_r] = 0
        visited_rows.add(start_r)
        queue = [('r', start_r)]

        while queue:
            node_type, node = queue.pop(0)
            if node_type == 'r':
                for c, d in adj_row.get(node, []):
                    b_val = (d - A[node]) % MOD
                    if c in B:
                        if B[c] != b_val:
                            return False, A, B
                    else:
                        B[c] = b_val
                        if c not in visited_cols:
                            visited_cols.add(c)
                            queue.append(('c', c))
            else:  # node_type == 'c'
                for r, d in adj_col.get(node, []):
                    a_val = (d - B[node]) % MOD
                    if r in A:
                        if A[r] != a_val:
                            return False, A, B
                    else:
                        A[r] = a_val
                        if r not in visited_rows:
                            visited_rows.add(r)
                            queue.append(('r', r))

    return True, A, B


def check_bean(full_key):
    """Check Bean constraints."""
    for a, b in BEAN_EQ:
        if full_key[a] is not None and full_key[b] is not None:
            if full_key[a] != full_key[b]:
                return False
    for a, b in BEAN_INEQ:
        if full_key[a] is not None and full_key[b] is not None:
            if full_key[a] == full_key[b]:
                return False
    return True


print("E-SOLVE-19: 2D Matrix + Keyword-Ordered Columnar Transposition")
print("=" * 70)
print()

total_orderings_tested = 0
total_consistent = 0
total_bean_pass = 0

for variant_name, key_func in [
    ("Vigenère", lambda ct, pt: (ct - pt) % MOD),
    ("Beaufort", lambda ct, pt: (ct + pt) % MOD),
    ("VarBeaufort", lambda ct, pt: (pt - ct) % MOD),
]:
    print(f"\n{'='*70}")
    print(f"Variant: {variant_name}")
    print(f"{'='*70}")

    for width in range(7, 11):  # widths 7-10
        n_rows = (CT_LEN + width - 1) // width
        last_row_len = CT_LEN - (n_rows - 1) * width

        # Column lengths
        col_lengths = []
        for c in range(width):
            if c < last_row_len:
                col_lengths.append(n_rows)
            else:
                col_lengths.append(n_rows - 1)

        n_perms = 1
        for i in range(1, width + 1):
            n_perms *= i

        print(f"\n  Width {width} ({n_rows} rows, {n_perms:,} orderings)...", flush=True)

        consistent_count = 0
        bean_pass_count = 0
        best_candidates = []

        for perm_idx, sigma in enumerate(permutations(range(width))):
            total_orderings_tested += 1

            if perm_idx % 100000 == 0 and perm_idx > 0:
                print(f"    Progress: {perm_idx:,}/{n_perms:,} ({100*perm_idx/n_perms:.1f}%)",
                      flush=True)

            # Compute column offsets in CT under this ordering
            col_ct_offset = {}
            offset = 0
            for j in range(width):
                col = sigma[j]
                col_ct_offset[col] = offset
                offset += col_lengths[col]

            # Build equations from crib positions
            equations = []
            valid = True
            for pos in CRIB_POS:
                r = pos // width
                c = pos % width

                # Check grid bounds
                if r >= n_rows or (r == n_rows - 1 and c >= last_row_len):
                    valid = False
                    break

                # CT position for grid cell (r, c) under column ordering sigma
                ct_pos = col_ct_offset[c] + r
                if ct_pos >= CT_LEN:
                    valid = False
                    break

                ct_val = CT_INT[ct_pos]
                pt_val = CRIB_PT[pos]
                d = key_func(ct_val, pt_val)
                equations.append((r, c, d))

            if not valid:
                continue

            consistent, A, B = solve_2d_consistency(equations)

            if consistent:
                consistent_count += 1

                # Build full key and check Bean
                full_key = [None] * CT_LEN
                for i in range(CT_LEN):
                    r = i // width
                    c = i % width
                    if r >= n_rows or (r == n_rows - 1 and c >= last_row_len):
                        continue
                    if r in A and c in B:
                        full_key[i] = (A[r] + B[c]) % MOD

                bean_ok = check_bean(full_key)
                if bean_ok:
                    bean_pass_count += 1

                    # Decrypt
                    pt_chars = ['?'] * CT_LEN
                    for i in range(CT_LEN):
                        r = i // width
                        c = i % width
                        if r >= n_rows or (r == n_rows - 1 and c >= last_row_len):
                            continue
                        ct_pos = col_ct_offset.get(c, -1) + r
                        if ct_pos < 0 or ct_pos >= CT_LEN:
                            continue
                        ct_val = CT_INT[ct_pos]
                        k = full_key[i]
                        if k is None:
                            continue
                        if variant_name == "Vigenère":
                            p = (ct_val - k) % MOD
                        elif variant_name == "Beaufort":
                            p = (k - ct_val) % MOD
                        else:
                            p = (ct_val + k) % MOD
                        pt_chars[i] = ALPH[p]

                    pt = "".join(pt_chars[:CT_LEN])

                    a_str = "".join(ALPH[A.get(r, 0)] for r in range(n_rows))
                    b_str = "".join(ALPH[B.get(c, 0)] for c in range(width))

                    best_candidates.append((sigma, a_str, b_str, pt))

                    if bean_pass_count <= 5:
                        print(f"    *** BEAN PASS: sigma={sigma}")
                        print(f"        Row key: {a_str}, Col key: {b_str}")
                        print(f"        PT: {pt}")

        total_consistent += consistent_count
        total_bean_pass += bean_pass_count

        print(f"    Result: {consistent_count} consistent / {n_perms:,} orderings"
              f" ({bean_pass_count} Bean PASS)")

        if bean_pass_count > 5:
            print(f"    (showing first 5 of {bean_pass_count})")

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total orderings tested: {total_orderings_tested:,}")
print(f"Total consistent: {total_consistent}")
print(f"Total Bean PASS: {total_bean_pass}")
print()

if total_bean_pass == 0 and total_consistent == 0:
    print("RESULT: ALL column orderings produce INCONSISTENT 2D systems")
    print("at widths 7-10 under all cipher variants.")
    print("The 2D additive model is DEFINITIVELY ELIMINATED even with")
    print("keyword-ordered columnar transposition.")
elif total_bean_pass == 0:
    print(f"RESULT: {total_consistent} consistent orderings found, but ALL fail Bean.")
    print("The 2D model is Bean-incompatible with columnar transposition.")
else:
    print(f"RESULT: {total_bean_pass} solutions pass ALL constraints!")
    print("INVESTIGATE THESE CANDIDATES.")
