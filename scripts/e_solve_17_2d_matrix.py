#!/usr/bin/env python3
"""
E-SOLVE-17: 2D Matrix Code (IDBYROWS) — The Convergent Hypothesis

Three independent reasoning agents converged on this untested model:
  k[r][c] = A[r] + B[c] (mod 26)

where plaintext is written into a grid of width W, each cell encrypted with
a key that depends on BOTH the row and column, then read off as ciphertext.

This is:
  - "Two separate systems" = row key + column key
  - "IDBYROWS" = literal instruction
  - "8 Lines 73" = 8-row grid
  - "Shifting matrices" / "matrix codes" = 2D grid operation
  - CKM key-split combiner = two independent key components

The system is OVERDETERMINED: 24 crib equations in ~21 unknowns.
If ANY width produces a consistent solution, this is a candidate decryption.
If NO width is consistent, the model is DEFINITIVELY ELIMINATED.

Tests:
  Model A: No transposition (read/write both row-by-row)
  Model B: Columnar transposition (write row-by-row, read column-by-column)
  Model C: Shifting matrix variant: k[r][c] = keyword[c % p] + m*r (mod 26)
"""

import sys
from collections import Counter

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)

CT_INT = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS}

# Known keystream values for each variant
def compute_keystream(variant):
    """Compute known keystream values at crib positions."""
    keys = {}
    for pos in CRIB_POS:
        pt = CRIB_PT[pos]
        ct = CT_INT[pos]
        if variant == "vig":
            keys[pos] = (ct - pt) % MOD
        elif variant == "beau":
            keys[pos] = (ct + pt) % MOD
        elif variant == "varbeau":
            keys[pos] = (pt - ct) % MOD
    return keys


def check_bean(full_key):
    """Check Bean EQ and INEQ constraints on a full 97-element key."""
    # Bean EQ
    for a, b in BEAN_EQ:
        if full_key[a] is not None and full_key[b] is not None:
            if full_key[a] != full_key[b]:
                return False, "Bean EQ fail"
    # Bean INEQ
    for a, b in BEAN_INEQ:
        if full_key[a] is not None and full_key[b] is not None:
            if full_key[a] == full_key[b]:
                return False, f"Bean INEQ fail at ({a},{b})"
    return True, "ok"


def decrypt(ct_ints, full_key, variant):
    """Decrypt using the full key."""
    pt = []
    for i in range(len(ct_ints)):
        k = full_key[i]
        if k is None:
            pt.append("?")
            continue
        if variant == "vig":
            p = (ct_ints[i] - k) % MOD
        elif variant == "beau":
            p = (k - ct_ints[i]) % MOD
        elif variant == "varbeau":
            p = (ct_ints[i] + k) % MOD  # PT = CT + K for varbeau
        else:
            raise ValueError(f"Unknown variant {variant}")
        pt.append(ALPH[p])
    return "".join(pt)


def solve_2d_system(known_keys, width, ct_len=97):
    """
    Solve the 2D key system: k[i] = A[row(i)] + B[col(i)] mod 26
    where row(i) = i // width, col(i) = i % width.

    Returns (A_dict, B_dict, consistent) where A_dict maps row->value,
    B_dict maps col->value, consistent is True/False.
    """
    n_rows = (ct_len + width - 1) // width

    # Build equations: A[r] + B[c] = d (mod 26)
    equations = []
    for pos, kval in known_keys.items():
        r = pos // width
        c = pos % width
        equations.append((r, c, kval))

    # Constraint propagation
    A = {}  # row -> value
    B = {}  # col -> value

    # Fix A[0] = 0 as normalization (WLOG)
    # Actually, we need to find a row that has crib positions.
    # Let's find which rows and columns are involved
    rows_with_cribs = set()
    cols_with_cribs = set()
    for r, c, d in equations:
        rows_with_cribs.add(r)
        cols_with_cribs.add(c)

    # Build adjacency: which (row, col) pairs are connected by cribs
    # This forms a bipartite graph
    adj_row = {}  # row -> [(col, d), ...]
    adj_col = {}  # col -> [(row, d), ...]
    for r, c, d in equations:
        adj_row.setdefault(r, []).append((c, d))
        adj_col.setdefault(c, []).append((r, d))

    # Find connected components in the bipartite graph
    visited_rows = set()
    visited_cols = set()
    components = []  # list of (rows_in_component, cols_in_component)

    def bfs(start_row):
        comp_rows = set()
        comp_cols = set()
        queue_r = [start_row]
        visited_rows.add(start_row)
        while queue_r:
            next_queue_c = []
            for r in queue_r:
                comp_rows.add(r)
                for c, d in adj_row.get(r, []):
                    if c not in visited_cols:
                        visited_cols.add(c)
                        next_queue_c.append(c)
                    comp_cols.add(c)
            queue_r = []
            for c in next_queue_c:
                for r, d in adj_col.get(c, []):
                    if r not in visited_rows:
                        visited_rows.add(r)
                        queue_r.append(r)
        return comp_rows, comp_cols

    for r in rows_with_cribs:
        if r not in visited_rows:
            cr, cc = bfs(r)
            components.append((cr, cc))

    # For each connected component, fix one variable and propagate
    for comp_rows, comp_cols in components:
        # Pick the first row in the component and set A[row] = 0
        seed_row = min(comp_rows)
        A[seed_row] = 0

        # Propagate
        changed = True
        while changed:
            changed = False
            for r, c, d in equations:
                if r not in comp_rows:
                    continue
                if r in A and c not in B:
                    B[c] = (d - A[r]) % MOD
                    changed = True
                elif c in B and r not in A:
                    A[r] = (d - B[c]) % MOD
                    changed = True
                elif r in A and c in B:
                    # Consistency check
                    expected = (A[r] + B[c]) % MOD
                    if expected != d:
                        return A, B, False

    return A, B, True


def test_model_a(variant_name, known_keys):
    """Model A: No transposition. Position i -> grid(i//W, i%W)."""
    print(f"\n  === Model A: No Transposition, {variant_name} ===")

    consistent_widths = []

    for width in range(7, 25):
        n_rows = (CT_LEN + width - 1) // width
        A, B, consistent = solve_2d_system(known_keys, width)

        if consistent:
            # Build full key
            full_key = [None] * CT_LEN
            for i in range(CT_LEN):
                r = i // width
                c = i % width
                if r in A and c in B:
                    full_key[i] = (A[r] + B[c]) % MOD

            # Check Bean
            bean_ok, bean_msg = check_bean(full_key)

            # Count determined positions
            n_det = sum(1 for k in full_key if k is not None)

            # Decrypt
            pt = decrypt(CT_INT, full_key, variant_name.lower()[:3] if variant_name != "VarBeaufort" else "varbeau")

            # Verify crib match
            crib_match = 0
            for pos in CRIB_POS:
                if full_key[pos] is not None:
                    vname = variant_name.lower()[:3] if variant_name != "VarBeaufort" else "varbeau"
                    if vname == "vig":
                        p = (CT_INT[pos] - full_key[pos]) % MOD
                    elif vname == "beau":
                        p = (full_key[pos] - CT_INT[pos]) % MOD
                    else:
                        p = (CT_INT[pos] + full_key[pos]) % MOD
                    if p == CRIB_PT[pos]:
                        crib_match += 1

            status = "CONSISTENT"
            if not bean_ok:
                status += f" (but {bean_msg})"

            # Show A and B keys
            a_str = "".join(ALPH[A.get(r, 0)] for r in range(n_rows))
            b_str = "".join(ALPH[B.get(c, 0)] for c in range(width))

            print(f"    Width {width:2d} ({n_rows} rows): {status}")
            print(f"      Row key A: {a_str}")
            print(f"      Col key B: {b_str}")
            print(f"      Determined: {n_det}/97, Crib match: {crib_match}/24")
            print(f"      PT: {pt}")
            if bean_ok:
                print(f"      *** BEAN PASS ***")

            consistent_widths.append((width, n_rows, bean_ok, crib_match, pt))
        else:
            print(f"    Width {width:2d} ({n_rows} rows): INCONSISTENT → ELIMINATED")

    return consistent_widths


def test_model_b(variant_name, known_keys):
    """Model B: Columnar transposition. Write row-by-row, read column-by-column.

    CT position j corresponds to grid[j % n_rows][j // n_rows] (natural col order).
    So if we know PT at flat position p (row-by-row), the grid cell is at (p//W, p%W).
    When read column-by-column, this grid cell appears at CT position (p%W)*n_rows + (p//W).
    """
    print(f"\n  === Model B: Columnar Transposition (natural col order), {variant_name} ===")

    consistent_widths = []

    for width in range(7, 25):
        n_rows = (CT_LEN + width - 1) // width
        last_row_len = CT_LEN - (n_rows - 1) * width  # chars in last row

        # Build the transposition mapping
        # grid[r][c] -> CT position when reading column-by-column
        # Column c contains n_rows elements if c < last_row_len, else n_rows-1
        def grid_to_ct_pos(r, c):
            """Map grid position (r,c) to flat CT position when reading by columns."""
            pos = 0
            # Count all positions in columns before c
            for cc in range(c):
                col_len = n_rows if cc < last_row_len else n_rows - 1
                pos += col_len
            # Add the row within this column
            pos += r
            return pos

        # For each crib position (which is a PT flat position = row-by-row),
        # find the corresponding CT position (column-by-column reading)
        # and use the CT value there
        adjusted_keys = {}
        valid = True
        for pt_pos, kval_unused in known_keys.items():
            r = pt_pos // width
            c = pt_pos % width
            # Check if this grid cell exists
            if r >= n_rows or (r == n_rows - 1 and c >= last_row_len):
                valid = False
                break
            ct_pos = grid_to_ct_pos(r, c)
            if ct_pos >= CT_LEN:
                valid = False
                break
            # The CT value at this position
            ct_val = CT_INT[ct_pos]
            pt_val = CRIB_PT[pt_pos]
            # Compute keystream
            vname = variant_name.lower()[:3] if variant_name != "VarBeaufort" else "varbeau"
            if vname == "vig":
                k = (ct_val - pt_val) % MOD
            elif vname == "beau":
                k = (ct_val + pt_val) % MOD
            else:
                k = (pt_val - ct_val) % MOD
            adjusted_keys[pt_pos] = k

        if not valid:
            print(f"    Width {width:2d} ({n_rows} rows): Grid too small for cribs")
            continue

        A, B, consistent = solve_2d_system(adjusted_keys, width)

        if consistent:
            # Build full key and decrypt
            full_key_grid = {}
            for r in range(n_rows):
                for c in range(width):
                    if r == n_rows - 1 and c >= last_row_len:
                        continue
                    if r in A and c in B:
                        full_key_grid[(r, c)] = (A[r] + B[c]) % MOD

            # Decrypt: for each grid cell, get the CT value from the column-read position
            pt_chars = ['?'] * CT_LEN
            vname = variant_name.lower()[:3] if variant_name != "VarBeaufort" else "varbeau"
            for r in range(n_rows):
                for c in range(width):
                    if r == n_rows - 1 and c >= last_row_len:
                        continue
                    pt_flat_pos = r * width + c
                    ct_flat_pos = grid_to_ct_pos(r, c)
                    if (r, c) in full_key_grid:
                        k = full_key_grid[(r, c)]
                        ct_val = CT_INT[ct_flat_pos]
                        if vname == "vig":
                            p = (ct_val - k) % MOD
                        elif vname == "beau":
                            p = (k - ct_val) % MOD
                        else:
                            p = (ct_val + k) % MOD
                        pt_chars[pt_flat_pos] = ALPH[p]

            pt = "".join(pt_chars[:CT_LEN])

            # Build full_key array for Bean check
            full_key = [None] * CT_LEN
            for r in range(n_rows):
                for c in range(width):
                    if r == n_rows - 1 and c >= last_row_len:
                        continue
                    flat_pos = r * width + c
                    if (r, c) in full_key_grid and flat_pos < CT_LEN:
                        full_key[flat_pos] = full_key_grid[(r, c)]

            bean_ok, bean_msg = check_bean(full_key)

            n_det = sum(1 for k in full_key if k is not None)
            a_str = "".join(ALPH[A.get(r, 0)] for r in range(n_rows))
            b_str = "".join(ALPH[B.get(c, 0)] for c in range(width))

            status = "CONSISTENT"
            if not bean_ok:
                status += f" (but {bean_msg})"

            print(f"    Width {width:2d} ({n_rows} rows): {status}")
            print(f"      Row key A: {a_str}")
            print(f"      Col key B: {b_str}")
            print(f"      Determined: {n_det}/97")
            print(f"      PT: {pt}")
            if bean_ok:
                print(f"      *** BEAN PASS ***")

            consistent_widths.append((width, n_rows, bean_ok, pt))
        else:
            print(f"    Width {width:2d} ({n_rows} rows): INCONSISTENT → ELIMINATED")

    return consistent_widths


def test_model_c(variant_name, known_keys):
    """Model C: Shifting matrix. k[r][c] = keyword[c % p] + m*r (mod 26).

    This is a special case of 2D where A[r] = m*r and B[c] = keyword[c % p].
    The row key has a specific linear structure.
    """
    print(f"\n  === Model C: Shifting Matrix, {variant_name} ===")

    # For each width and keyword period, try to solve
    results = []

    for width in range(7, 25):
        n_rows = (CT_LEN + width - 1) // width

        # First solve the general 2D system
        A, B, consistent = solve_2d_system(known_keys, width)

        if not consistent:
            continue

        # Check if A values satisfy A[r] = m*r (mod 26) for some m
        # Need at least 2 determined A values
        known_A = [(r, v) for r, v in A.items()]
        if len(known_A) < 2:
            continue

        # Try each m from 0 to 25
        for m in range(26):
            # Check if A[r] = A[0] + m*r (mod 26) for all known rows
            base = A.get(min(A.keys()), 0)
            r0 = min(A.keys())
            ok = True
            for r, v in known_A:
                expected = (base + m * (r - r0)) % MOD
                if v != expected:
                    ok = False
                    break

            if ok:
                # Check if B values are periodic
                known_B = [(c, v) for c, v in B.items()]
                for period in range(1, width + 1):
                    periodic_ok = True
                    for c, v in known_B:
                        # B[c] should equal B[c % period]
                        c_ref = c % period
                        if c_ref in B and B[c_ref] != v:
                            periodic_ok = False
                            break

                    if periodic_ok and period <= 8:  # Only report short periods
                        # Reconstruct keyword
                        keyword = [None] * period
                        for c, v in known_B:
                            c_ref = c % period
                            if keyword[c_ref] is None:
                                keyword[c_ref] = v
                            elif keyword[c_ref] != v:
                                periodic_ok = False
                                break

                        if periodic_ok and all(k is not None for k in keyword):
                            kw_str = "".join(ALPH[k] for k in keyword)
                            print(f"    Width {width:2d}, m={m:2d}, period={period}: "
                                  f"keyword={kw_str}, base_row={ALPH[base]}")
                            results.append((width, m, period, kw_str))

    if not results:
        print("    No shifting matrix solutions found.")
    return results


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

print("E-SOLVE-17: 2D Matrix Code — The Convergent Hypothesis")
print("=" * 70)
print()
print("Model: k[r][c] = A[r] + B[c] (mod 26)")
print("24 crib equations in ~21 unknowns → OVERDETERMINED")
print()

total_consistent = 0
total_bean_pass = 0

for variant_name, variant_code in [("Vigenère", "vig"), ("Beaufort", "beau"), ("VarBeaufort", "varbeau")]:
    print(f"\n{'='*70}")
    print(f"Cipher variant: {variant_name}")
    print(f"{'='*70}")

    known_keys = compute_keystream(variant_code)

    # Model A: No transposition
    results_a = test_model_a(variant_name, known_keys)
    for w, nr, bean, cm, pt in results_a:
        total_consistent += 1
        if bean:
            total_bean_pass += 1

    # Model B: Columnar transposition
    results_b = test_model_b(variant_name, known_keys)
    for w, nr, bean, pt in results_b:
        total_consistent += 1
        if bean:
            total_bean_pass += 1

    # Model C: Shifting matrix
    results_c = test_model_c(variant_name, known_keys)

print()
print("=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"Total consistent solutions: {total_consistent}")
print(f"Total with Bean PASS: {total_bean_pass}")
print()

if total_consistent == 0:
    print("RESULT: ALL widths INCONSISTENT under all variants and models.")
    print("The 2D matrix code hypothesis k[r][c] = A[r] + B[c] (mod 26)")
    print("is DEFINITIVELY ELIMINATED.")
    print()
    print("This means: no assignment of row keys and column keys can produce")
    print("the observed keystream values at the 24 crib positions,")
    print("for ANY grid width from 7 to 24.")
elif total_bean_pass == 0:
    print(f"RESULT: {total_consistent} consistent solutions found, but ALL fail Bean.")
    print("The 2D matrix code is ELIMINATED (Bean-incompatible).")
else:
    print(f"RESULT: {total_bean_pass} solutions pass ALL constraints!")
    print("INVESTIGATE THESE CANDIDATES.")
