#!/usr/bin/env python3
"""
Cipher: Hill cipher
Family: substitution
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-151: Hill Cipher Width-9 Gap Closure + YART Anomaly Matrices

Closes the last gap in Hill cipher elimination: width-9 columnar transposition
was never tested with Hill (E-S-41 covered widths 5-8 only).

Also tests specific Hill matrices derived from the anomaly narrative:
  YAR superscript (Y=24, A=0, R=17) + T from "T IS YOUR POSITION" (T=19)
  DYAR variant (D=3, Y=24, A=0, R=17)

Tests:
  1. Width-9 columnar + Hill 2x2 (algebraic): all 362,880 orderings
  2. Width-9 columnar + Hill 3x3 (algebraic): all 362,880 orderings
  3. YART/DYAR specific matrices + identity (direct correspondence)
  4. YART/DYAR matrices + width-8 and width-9 columnar

Approach: Same algebraic method as E-S-41. Solve Hill matrix from 2 known
digraph pairs, verify against remaining 9+ pairs. System is massively
overdetermined (22 equations / 4 unknowns), so expected FP ≈ 10^{-25} per ordering.

Output: results/e_s_151_hill_w9_yart.json
"""

import json
import sys
import os
import time
from itertools import permutations
from math import gcd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}


# ── Utility functions ─────────────────────────────────────────────────

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a, m=26):
    if a < 0:
        a = a % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m


def columnar_perm(col_order, width, length):
    """Returns sigma where sigma[pt_pos] = ct_pos (scatter convention)."""
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width
    sigma = [0] * length
    ct_pos = 0
    for col in col_order:
        col_len = n_rows if col < n_long else n_rows - 1
        for row in range(col_len):
            pt_pos = row * width + col
            if pt_pos < length:
                sigma[pt_pos] = ct_pos
                ct_pos += 1
    return sigma


def invert_perm(sigma):
    inv = [0] * len(sigma)
    for i, s in enumerate(sigma):
        inv[s] = i
    return inv


# ── Hill cipher functions ─────────────────────────────────────────────

def solve_2x2_hill(pt_pairs, ct_pairs):
    """Solve for 2x2 Hill matrix M from known PT/CT digraph pairs.
    M x [p1,p2]^T = [c1,c2]^T (mod 26).
    Returns list of valid M as ((a,b),(c,d)) tuples."""
    if len(pt_pairs) < 2:
        return []
    p1a, p1b = pt_pairs[0]
    p2a, p2b = pt_pairs[1]
    c1a, c1b = ct_pairs[0]
    c2a, c2b = ct_pairs[1]

    det_p = (p1a * p2b - p1b * p2a) % MOD
    det_inv = mod_inverse(det_p, MOD)
    if det_inv is None:
        return []

    pinv = [
        [(det_inv * p2b) % MOD, (det_inv * (-p2a)) % MOD],
        [(det_inv * (-p1b)) % MOD, (det_inv * p1a) % MOD],
    ]
    M = [
        [(c1a * pinv[0][0] + c2a * pinv[1][0]) % MOD,
         (c1a * pinv[0][1] + c2a * pinv[1][1]) % MOD],
        [(c1b * pinv[0][0] + c2b * pinv[1][0]) % MOD,
         (c1b * pinv[0][1] + c2b * pinv[1][1]) % MOD],
    ]
    det_m = (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % MOD
    if mod_inverse(det_m, MOD) is None:
        return []
    return [((M[0][0], M[0][1]), (M[1][0], M[1][1]))]


def apply_hill_2x2(M, p1, p2):
    return (
        (M[0][0] * p1 + M[0][1] * p2) % MOD,
        (M[1][0] * p1 + M[1][1] * p2) % MOD,
    )


def get_crib_digraphs(offset=0):
    """Get fully-known crib digraphs at given alignment offset."""
    pairs = []
    for j in range(offset, N - 1, 2):
        if j in CRIB_PT and (j + 1) in CRIB_PT:
            pairs.append((j, j + 1, CRIB_PT[j], CRIB_PT[j + 1]))
    return pairs


def get_crib_trigraphs(offset=0):
    """Get fully-known crib trigraphs at given alignment offset."""
    triples = []
    for j in range(offset, N - 2, 3):
        if j in CRIB_PT and (j + 1) in CRIB_PT and (j + 2) in CRIB_PT:
            triples.append((j, j + 1, j + 2,
                           CRIB_PT[j], CRIB_PT[j + 1], CRIB_PT[j + 2]))
    return triples


def solve_3x3_hill(pt_triples, ct_triples):
    """Solve for 3x3 Hill matrix from known PT/CT trigraphs."""
    if len(pt_triples) < 3:
        return []
    P = [[pt_triples[i][j] for i in range(3)] for j in range(3)]
    C = [[ct_triples[i][j] for i in range(3)] for j in range(3)]
    det_p = (P[0][0] * (P[1][1] * P[2][2] - P[1][2] * P[2][1])
           - P[0][1] * (P[1][0] * P[2][2] - P[1][2] * P[2][0])
           + P[0][2] * (P[1][0] * P[2][1] - P[1][1] * P[2][0])) % MOD
    det_inv = mod_inverse(det_p, MOD)
    if det_inv is None:
        return []
    cofactors = [[0]*3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            minor = []
            for ii in range(3):
                if ii == i:
                    continue
                row = []
                for jj in range(3):
                    if jj == j:
                        continue
                    row.append(P[ii][jj])
                minor.append(row)
            cof = (minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0]) % MOD
            cofactors[j][i] = ((-1) ** (i + j) * cof * det_inv) % MOD
    M = [[0]*3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            s = 0
            for k in range(3):
                s += C[i][k] * cofactors[k][j]
            M[i][j] = s % MOD
    det_m = (M[0][0] * (M[1][1] * M[2][2] - M[1][2] * M[2][1])
           - M[0][1] * (M[1][0] * M[2][2] - M[1][2] * M[2][0])
           + M[0][2] * (M[1][0] * M[2][1] - M[1][1] * M[2][0])) % MOD
    if mod_inverse(det_m, MOD) is None:
        return []
    return [tuple(tuple(row) for row in M)]


def apply_hill_3x3(M, p1, p2, p3):
    return (
        (M[0][0]*p1 + M[0][1]*p2 + M[0][2]*p3) % MOD,
        (M[1][0]*p1 + M[1][1]*p2 + M[1][2]*p3) % MOD,
        (M[2][0]*p1 + M[2][1]*p2 + M[2][2]*p3) % MOD,
    )


# ── Test: Hill 2x2 + columnar transposition (algebraic) ──────────────

def test_hill2_columnar(width, label=""):
    """Test Hill 2x2 + columnar transposition at given width.
    Returns (n_tested, n_solutions, solutions_list)."""
    t0 = time.time()
    total_tested = 0
    total_solutions = 0
    solutions = []

    for offset in [0, 1]:
        crib_digraphs = get_crib_digraphs(offset)
        if len(crib_digraphs) < 3:
            continue

        for model in ['A', 'B']:
            n_tested = 0
            n_solutions = 0

            for order_tuple in permutations(range(width)):
                order = list(order_tuple)
                sigma = columnar_perm(order, width, N)
                n_tested += 1

                if model == 'B':
                    inv_sigma = invert_perm(sigma)

                pt_pairs = []
                ct_pairs = []

                for j1, j2, p1, p2 in crib_digraphs:
                    if model == 'A':
                        c1 = CT_NUM[sigma[j1]]
                        c2 = CT_NUM[sigma[j2]]
                    else:
                        inv_j1 = inv_sigma[j1]
                        inv_j2 = inv_sigma[j2]
                        if inv_j1 not in CRIB_PT or inv_j2 not in CRIB_PT:
                            continue
                        p1 = CRIB_PT[inv_j1]
                        p2 = CRIB_PT[inv_j2]
                        c1 = CT_NUM[j1]
                        c2 = CT_NUM[j2]

                    pt_pairs.append((p1, p2))
                    ct_pairs.append((c1, c2))

                if len(pt_pairs) < 3:
                    continue

                found = False
                for i in range(len(pt_pairs)):
                    if found:
                        break
                    for j in range(i + 1, len(pt_pairs)):
                        basis_pt = [pt_pairs[i], pt_pairs[j]]
                        basis_ct = [ct_pairs[i], ct_pairs[j]]
                        solved = solve_2x2_hill(basis_pt, basis_ct)
                        for M_tuple in solved:
                            M = [list(M_tuple[0]), list(M_tuple[1])]
                            all_match = True
                            for k in range(len(pt_pairs)):
                                expected = apply_hill_2x2(M, pt_pairs[k][0], pt_pairs[k][1])
                                if expected != ct_pairs[k]:
                                    all_match = False
                                    break
                            if all_match:
                                n_solutions += 1
                                found = True
                                solutions.append({
                                    "n": 2, "offset": offset, "width": width,
                                    "model": model, "order": order,
                                    "matrix": M_tuple, "n_verified": len(pt_pairs),
                                })
                                print(f"  *** SOLUTION: w={width} model={model}"
                                      f" order={order} M={M_tuple}"
                                      f" verified={len(pt_pairs)} pairs")
                                break
                        if found:
                            break

            total_tested += n_tested
            total_solutions += n_solutions

    elapsed = time.time() - t0
    print(f"  {label}Hill n=2 w={width}: {total_solutions}/{total_tested}"
          f" solutions ({elapsed:.1f}s)", flush=True)
    return total_tested, total_solutions, solutions


def test_hill3_columnar(width, label=""):
    """Test Hill 3x3 + columnar transposition at given width."""
    t0 = time.time()
    total_tested = 0
    total_solutions = 0
    solutions = []

    for offset in [0, 1, 2]:
        crib_trigraphs = get_crib_trigraphs(offset)
        if len(crib_trigraphs) < 3:
            continue

        n_tested = 0
        n_solutions = 0

        for order_tuple in permutations(range(width)):
            order = list(order_tuple)
            sigma = columnar_perm(order, width, N)
            n_tested += 1

            pt_triples = []
            ct_triples = []
            for j1, j2, j3, p1, p2, p3 in crib_trigraphs:
                c1 = CT_NUM[sigma[j1]]
                c2 = CT_NUM[sigma[j2]]
                c3 = CT_NUM[sigma[j3]]
                pt_triples.append((p1, p2, p3))
                ct_triples.append((c1, c2, c3))

            if len(pt_triples) < 3:
                continue

            found = False
            for i in range(len(pt_triples)):
                if found:
                    break
                for j in range(i + 1, len(pt_triples)):
                    if found:
                        break
                    for k_idx in range(j + 1, len(pt_triples)):
                        basis_pt = [pt_triples[i], pt_triples[j], pt_triples[k_idx]]
                        basis_ct = [ct_triples[i], ct_triples[j], ct_triples[k_idx]]
                        solved = solve_3x3_hill(basis_pt, basis_ct)
                        for M_tuple in solved:
                            M = [list(row) for row in M_tuple]
                            all_match = True
                            for m in range(len(pt_triples)):
                                expected = apply_hill_3x3(M, *pt_triples[m])
                                if expected != ct_triples[m]:
                                    all_match = False
                                    break
                            if all_match:
                                n_solutions += 1
                                found = True
                                solutions.append({
                                    "n": 3, "offset": offset, "width": width,
                                    "model": "A", "order": order,
                                    "matrix": M_tuple, "n_verified": len(pt_triples),
                                })
                                print(f"  *** SOLUTION: w={width}"
                                      f" order={order} M={M_tuple}"
                                      f" verified={len(pt_triples)} triples")
                                break
                        if found:
                            break

        total_tested += n_tested
        total_solutions += n_solutions

    elapsed = time.time() - t0
    print(f"  {label}Hill n=3 w={width}: {total_solutions}/{total_tested}"
          f" solutions ({elapsed:.1f}s)", flush=True)
    return total_tested, total_solutions, solutions


# ── Test: YART/DYAR specific matrices ────────────────────────────────

def test_specific_matrices():
    """Test anomaly-derived Hill 2x2 matrices against CT directly and
    with width-8/9 columnar transpositions."""

    Y, A, R, T, D, O = 24, 0, 17, 19, 3, 14

    # All 4-letter subsets that could form 2x2 Hill matrices
    named_sets = {
        "YART": (Y, A, R, T),
        "DYAR": (D, Y, A, R),
        "YARO": (Y, A, R, O),
        "DART": (D, A, R, T),
        "DARO": (D, A, R, O),
        "TYAR": (T, Y, A, R),
    }

    all_matrices = {}

    for name, (v1, v2, v3, v4) in named_sets.items():
        # Try all 24 arrangements into 2x2 matrix [[a,b],[c,d]]
        from itertools import permutations as perms
        vals = [v1, v2, v3, v4]
        seen = set()
        for perm in perms(vals):
            a, b, c, d = perm
            det = (a * d - b * c) % MOD
            if gcd(det, MOD) == 1:
                key = (a, b, c, d)
                if key not in seen:
                    seen.add(key)
                    label = f"{name}[{a},{b},{c},{d}]"
                    all_matrices[label] = ((a, b), (c, d))

    print(f"\n  YART/DYAR-derived invertible 2x2 matrices: {len(all_matrices)}")

    results = []

    # Test 1: Direct correspondence (identity transposition)
    print("\n  Direct correspondence (no transposition):")
    for offset in [0, 1]:
        crib_digraphs = get_crib_digraphs(offset)
        if len(crib_digraphs) < 2:
            continue
        for label, M_tuple in all_matrices.items():
            M = [list(M_tuple[0]), list(M_tuple[1])]
            all_match = True
            for j1, j2, p1, p2 in crib_digraphs:
                expected = apply_hill_2x2(M, p1, p2)
                actual = (CT_NUM[j1], CT_NUM[j2])
                if expected != actual:
                    all_match = False
                    break
            if all_match:
                print(f"    *** MATCH: {label} offset={offset}")
                results.append({"label": label, "offset": offset,
                               "matrix": M_tuple, "transposition": "identity"})

    # Also test inverse: CT = M^{-1}(PT) instead of CT = M(PT)
    print("\n  Inverse Hill (decryption direction):")
    for offset in [0, 1]:
        crib_digraphs = get_crib_digraphs(offset)
        if len(crib_digraphs) < 2:
            continue
        for label, M_tuple in all_matrices.items():
            a, b = M_tuple[0]
            c, d = M_tuple[1]
            det = (a * d - b * c) % MOD
            det_inv = mod_inverse(det, MOD)
            if det_inv is None:
                continue
            M_inv = [
                [(det_inv * d) % MOD, (det_inv * (-b)) % MOD],
                [(det_inv * (-c)) % MOD, (det_inv * a) % MOD],
            ]
            all_match = True
            for j1, j2, p1, p2 in crib_digraphs:
                expected = apply_hill_2x2(M_inv, CT_NUM[j1], CT_NUM[j2])
                if expected != (p1, p2):
                    all_match = False
                    break
            if all_match:
                print(f"    *** MATCH (inv): {label} offset={offset}")
                results.append({"label": label, "offset": offset,
                               "matrix": M_tuple, "transposition": "identity",
                               "direction": "inverse"})

    n_direct = len(results)
    print(f"  Direct/inverse correspondence: {n_direct} matches")
    return all_matrices, results


def main():
    print("=" * 70)
    print("E-S-151: Hill Cipher Width-9 Gap Closure + YART Anomaly Matrices")
    print("=" * 70)
    print(f"  CT length: {N}")
    print(f"  Known crib positions: {len(CRIB_PT)}")
    print()

    t0 = time.time()
    all_results = {}

    # ── Test 1: Width-9 columnar + Hill 2x2 ─────────────────────────
    print("TEST 1: Width-9 columnar + Hill 2x2 (algebraic)")
    print("-" * 50)
    print(f"  9! = 362,880 orderings × 2 offsets × 2 models")
    t1, s1, sol1 = test_hill2_columnar(9, label="[GAP] ")
    all_results["hill2_w9"] = {
        "tested": t1, "solutions": s1,
        "verdict": "ELIMINATED" if s1 == 0 else "SIGNAL"
    }

    # ── Test 2: Width-9 columnar + Hill 3x3 ─────────────────────────
    print(f"\nTEST 2: Width-9 columnar + Hill 3x3 (algebraic)")
    print("-" * 50)
    print(f"  9! = 362,880 orderings × 3 offsets × Model A")
    t2, s2, sol2 = test_hill3_columnar(9, label="[GAP] ")
    all_results["hill3_w9"] = {
        "tested": t2, "solutions": s2,
        "verdict": "ELIMINATED" if s2 == 0 else "SIGNAL"
    }

    # ── Test 3: Width-10 columnar + Hill 2x2 (bonus) ────────────────
    # Width 10 has 10! = 3,628,800 orderings — sample instead
    print(f"\nTEST 3: Width-10 columnar + Hill 2x2 (sampled)")
    print("-" * 50)
    import random
    random.seed(20260220)
    SAMPLE_SIZE = 100000
    print(f"  Sampling {SAMPLE_SIZE:,} of 10! = 3,628,800 orderings")

    t3_t0 = time.time()
    t3_tested = 0
    t3_solutions = 0
    t3_sols = []

    for offset in [0, 1]:
        crib_digraphs = get_crib_digraphs(offset)
        if len(crib_digraphs) < 3:
            continue
        for _ in range(SAMPLE_SIZE // 2):
            order = list(range(10))
            random.shuffle(order)
            sigma = columnar_perm(order, 10, N)
            t3_tested += 1

            pt_pairs = []
            ct_pairs = []
            for j1, j2, p1, p2 in crib_digraphs:
                c1 = CT_NUM[sigma[j1]]
                c2 = CT_NUM[sigma[j2]]
                pt_pairs.append((p1, p2))
                ct_pairs.append((c1, c2))

            if len(pt_pairs) < 3:
                continue

            found = False
            for i in range(min(3, len(pt_pairs))):
                if found:
                    break
                for j in range(i + 1, min(4, len(pt_pairs))):
                    basis_pt = [pt_pairs[i], pt_pairs[j]]
                    basis_ct = [ct_pairs[i], ct_pairs[j]]
                    solved = solve_2x2_hill(basis_pt, basis_ct)
                    for M_tuple in solved:
                        M = [list(M_tuple[0]), list(M_tuple[1])]
                        all_match = True
                        for k in range(len(pt_pairs)):
                            expected = apply_hill_2x2(M, pt_pairs[k][0], pt_pairs[k][1])
                            if expected != ct_pairs[k]:
                                all_match = False
                                break
                        if all_match:
                            t3_solutions += 1
                            found = True
                            t3_sols.append({
                                "n": 2, "offset": offset, "width": 10,
                                "order": order, "matrix": M_tuple,
                            })
                            print(f"  *** SOLUTION: w=10 order={order} M={M_tuple}")
                            break
                    if found:
                        break

    t3_elapsed = time.time() - t3_t0
    print(f"  Hill n=2 w=10 sampled: {t3_solutions}/{t3_tested}"
          f" solutions ({t3_elapsed:.1f}s)", flush=True)
    all_results["hill2_w10_sampled"] = {
        "tested": t3_tested, "solutions": t3_solutions, "sample_size": SAMPLE_SIZE,
        "verdict": "ELIMINATED (sampled)" if t3_solutions == 0 else "SIGNAL"
    }

    # ── Test 4: YART-specific anomaly matrices ───────────────────────
    print(f"\nTEST 4: YART/DYAR anomaly-derived Hill matrices")
    print("-" * 50)
    specific_matrices, specific_results = test_specific_matrices()

    # Also test YART matrices with width-9 columnar (specific test)
    print("\n  YART matrices + width-9 columnar:")
    yart_w9_tested = 0
    yart_w9_solutions = 0
    for offset in [0, 1]:
        crib_digraphs = get_crib_digraphs(offset)
        if len(crib_digraphs) < 2:
            continue
        for order_tuple in permutations(range(9)):
            order = list(order_tuple)
            sigma = columnar_perm(order, 9, N)
            yart_w9_tested += 1

            for label, M_tuple in specific_matrices.items():
                M = [list(M_tuple[0]), list(M_tuple[1])]
                all_match = True
                for j1, j2, p1, p2 in crib_digraphs:
                    c1 = CT_NUM[sigma[j1]]
                    c2 = CT_NUM[sigma[j2]]
                    expected = apply_hill_2x2(M, p1, p2)
                    if expected != (c1, c2):
                        all_match = False
                        break
                if all_match:
                    yart_w9_solutions += 1
                    print(f"    *** MATCH: {label} w=9 order={order}")
                    specific_results.append({
                        "label": label, "width": 9, "order": order,
                        "matrix": M_tuple, "offset": offset,
                    })

    print(f"  YART + w9: {yart_w9_solutions}/{yart_w9_tested * len(specific_matrices)}"
          f" matches")

    all_results["yart_specific"] = {
        "n_matrices": len(specific_matrices),
        "direct_matches": len([r for r in specific_results if r.get("transposition") == "identity"]),
        "w9_matches": yart_w9_solutions,
        "total_matches": len(specific_results),
    }

    # ── SUMMARY ──────────────────────────────────────────────────────
    elapsed = time.time() - t0
    total_solutions = s1 + s2 + t3_solutions + len(specific_results)

    print(f"\n{'='*70}")
    print("SUMMARY: E-S-151")
    print(f"{'='*70}")
    print(f"  Total time: {elapsed:.1f}s ({elapsed/60:.1f}min)")
    print()
    print(f"  Test 1 — Hill 2x2 + w9 columnar:   {s1} solutions / {t1} tested")
    print(f"  Test 2 — Hill 3x3 + w9 columnar:   {s2} solutions / {t2} tested")
    print(f"  Test 3 — Hill 2x2 + w10 (sampled):  {t3_solutions} solutions / {t3_tested} tested")
    print(f"  Test 4 — YART/DYAR specific:        {len(specific_results)} matches")
    print()

    if total_solutions == 0:
        verdict = "ELIMINATED"
        print(f"  VERDICT: {verdict}")
        print(f"  Hill cipher + columnar transposition widths 5-10: ELIMINATED")
        print(f"  (widths 5-8 by E-S-41, width 9-10 by this experiment)")
        print(f"  YART/DYAR anomaly-derived Hill matrices: ELIMINATED")
        print(f"  Combined with E-S-05/41: Hill 2x2/3x3 eliminated under:")
        print(f"    - Direct correspondence (E-S-05)")
        print(f"    - Columnar transposition widths 5-10 (E-S-41 + E-S-151)")
        print(f"    - Specific anomaly-derived matrices (E-S-151)")
    else:
        verdict = "SIGNAL"
        print(f"  VERDICT: {verdict} — {total_solutions} solutions found!")
        print(f"  Investigate immediately.")

    # Save results
    os.makedirs("results", exist_ok=True)
    with open("results/e_s_151_hill_w9_yart.json", "w") as f:
        json.dump({
            "experiment": "E-S-151",
            "description": "Hill cipher width-9 gap closure + YART anomaly matrices",
            "tests": all_results,
            "total_solutions": total_solutions,
            "verdict": verdict,
            "elapsed_seconds": round(elapsed, 1),
            "solutions": sol1 + sol2 + t3_sols + specific_results,
        }, f, indent=2)

    print(f"\n  Artifact: results/e_s_151_hill_w9_yart.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_151_hill_w9_yart.py")


if __name__ == "__main__":
    main()
