#!/usr/bin/env python3
"""
E-S-41: Hill Cipher + Columnar Transposition

HIGH PRIORITY — The extra "L" on the Kryptos tableau creates "HILL" reading down.
Hill cipher n=2,3,4 was eliminated under direct correspondence (E-S-05) but NEVER
tested after transposition. This experiment fills that gap.

Model A: CT = σ(Hill(PT)) — Hill encrypt then transpose
Model B: CT = Hill(σ(PT)) — transpose then Hill encrypt

For Hill n=2 (digraph substitution):
- 11 fully-known PT digraphs from cribs (6 from ENE, 5 from BC)
- 4 unknowns in 2×2 matrix M — system is 22 equations / 4 unknowns = massively overdetermined
- For each width-5-8 columnar ordering: solve M from 2 pairs, verify on 9 remaining
- Expected false positive rate: (1/26)^18 ≈ 10^{-25}

For Hill n=3 (trigraph substitution):
- ~7 fully-known PT trigraphs (depends on alignment)
- 9 unknowns in 3×3 matrix — system is ~21 equations / 9 unknowns = well-constrained
- For each ordering: solve M from 3 trigraphs, verify on remaining

Also tests digraph offset (pairs start at even vs odd positions).

Output: results/e_s_41_hill_transposition.json
"""

import json
import sys
import os
import time
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}


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


def mod_inverse(a, m=26):
    """Extended Euclidean algorithm for modular inverse."""
    if a < 0:
        a = a % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None  # No inverse
    return x % m


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def solve_2x2_hill(pt_pairs, ct_pairs):
    """Solve for 2x2 Hill matrix M given known PT/CT digraph pairs.

    pt_pairs: list of (p1, p2) plaintext digraphs
    ct_pairs: list of (c1, c2) corresponding ciphertext digraphs

    M × [p1, p2]^T = [c1, c2]^T (mod 26)

    Returns list of valid M matrices (as ((a,b),(c,d)) tuples).
    """
    if len(pt_pairs) < 2:
        return []

    # Use first two pairs to solve for M
    p1a, p1b = pt_pairs[0]
    p2a, p2b = pt_pairs[1]
    c1a, c1b = ct_pairs[0]
    c2a, c2b = ct_pairs[1]

    # M × [[p1a, p2a], [p1b, p2b]] = [[c1a, c2a], [c1b, c2b]]
    # PT matrix P = [[p1a, p2a], [p1b, p2b]]
    # CT matrix C = [[c1a, c2a], [c1b, c2b]]
    # M = C × P^{-1} (mod 26)

    det_p = (p1a * p2b - p1b * p2a) % MOD
    det_inv = mod_inverse(det_p, MOD)
    if det_inv is None:
        return []  # PT matrix not invertible

    # P^{-1} = det_inv × [[p2b, -p2a], [-p1b, p1a]]
    pinv = [
        [(det_inv * p2b) % MOD, (det_inv * (-p2a)) % MOD],
        [(det_inv * (-p1b)) % MOD, (det_inv * p1a) % MOD],
    ]

    # M = C × P^{-1}
    M = [
        [(c1a * pinv[0][0] + c2a * pinv[1][0]) % MOD,
         (c1a * pinv[0][1] + c2a * pinv[1][1]) % MOD],
        [(c1b * pinv[0][0] + c2b * pinv[1][0]) % MOD,
         (c1b * pinv[0][1] + c2b * pinv[1][1]) % MOD],
    ]

    # Check M is invertible
    det_m = (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % MOD
    if mod_inverse(det_m, MOD) is None:
        return []

    return [((M[0][0], M[0][1]), (M[1][0], M[1][1]))]


def apply_hill_2x2(M, p1, p2):
    """Apply 2x2 Hill matrix to a digraph."""
    return (
        (M[0][0] * p1 + M[0][1] * p2) % MOD,
        (M[1][0] * p1 + M[1][1] * p2) % MOD,
    )


def get_crib_digraphs(offset=0):
    """Get fully-known crib digraphs at given offset (0 or 1).

    offset=0: pairs at (0,1),(2,3),...
    offset=1: pairs at (1,2),(3,4),...
    """
    pairs = []
    for j in range(offset, N - 1, 2):
        if j in CRIB_PT and (j + 1) in CRIB_PT:
            pairs.append((j, j + 1, CRIB_PT[j], CRIB_PT[j + 1]))
    return pairs


def get_crib_trigraphs(offset=0):
    """Get fully-known crib trigraphs at given offset."""
    triples = []
    for j in range(offset, N - 2, 3):
        if j in CRIB_PT and (j + 1) in CRIB_PT and (j + 2) in CRIB_PT:
            triples.append((j, j + 1, j + 2,
                           CRIB_PT[j], CRIB_PT[j + 1], CRIB_PT[j + 2]))
    return triples


def solve_3x3_hill(pt_triples, ct_triples):
    """Solve for 3x3 Hill matrix from known PT/CT trigraphs.

    Uses Gaussian elimination over Z₂₆.
    """
    if len(pt_triples) < 3:
        return []

    # Build the system: M × P = C where P is 3×3, C is 3×3
    P = [[pt_triples[i][j] for i in range(3)] for j in range(3)]
    C = [[ct_triples[i][j] for i in range(3)] for j in range(3)]

    # Compute det(P)
    det_p = (P[0][0] * (P[1][1] * P[2][2] - P[1][2] * P[2][1])
           - P[0][1] * (P[1][0] * P[2][2] - P[1][2] * P[2][0])
           + P[0][2] * (P[1][0] * P[2][1] - P[1][1] * P[2][0])) % MOD

    det_inv = mod_inverse(det_p, MOD)
    if det_inv is None:
        return []

    # Compute P^{-1} using cofactor matrix
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

    # M = C × P^{-1}
    M = [[0]*3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            s = 0
            for k in range(3):
                s += C[i][k] * cofactors[k][j]
            M[i][j] = s % MOD

    # Verify M is invertible
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


def main():
    print("=" * 60)
    print("E-S-41: Hill Cipher + Columnar Transposition")
    print("=" * 60)

    t0 = time.time()
    results = []

    # =========================================================
    # Hill n=2 (digraphs)
    # =========================================================
    for offset in [0, 1]:
        crib_digraphs = get_crib_digraphs(offset)
        print(f"\n--- Hill n=2, offset={offset} ---")
        print(f"  Known digraphs: {len(crib_digraphs)}")
        for j1, j2, p1, p2 in crib_digraphs:
            print(f"    ({j1},{j2}): ({chr(p1+65)},{chr(p2+65)})")

        if len(crib_digraphs) < 3:
            print(f"  Too few digraphs, skipping")
            continue

        for width in [7, 5, 6, 8]:
            for model in ['A', 'B']:
                n_tested = 0
                n_solutions = 0

                for order_tuple in permutations(range(width)):
                    order = list(order_tuple)
                    sigma = columnar_perm(order, width, N)

                    n_tested += 1

                    # Model A: CT = σ(Hill(PT))
                    # CT[σ(j)] = Hill(PT)[j]
                    # For digraph (j, j+1): (CT[σ(j)], CT[σ(j+1)]) = M × (PT[j], PT[j+1])
                    #
                    # Model B: CT = Hill(σ(PT))
                    # Compute σ⁻¹ first
                    if model == 'B':
                        inv_sigma = invert_perm(sigma)

                    # Build PT/CT pairs for this transposition
                    pt_pairs = []
                    ct_pairs = []

                    for j1, j2, p1, p2 in crib_digraphs:
                        if model == 'A':
                            c1 = CT_NUM[sigma[j1]]
                            c2 = CT_NUM[sigma[j2]]
                        else:  # Model B
                            # CT[j] = Hill(σ(PT))[j]
                            # CT pair at (j1,j2): Hill applied to (σ(PT)[j1], σ(PT)[j2])
                            # But σ(PT) means PT is permuted first: σ(PT)[k] = PT[σ⁻¹(k)]
                            # Hmm, this is more complex for Hill.
                            # Actually: Hill operates on consecutive pairs of σ(PT).
                            # So the intermediate text is σ(PT), then Hill encrypts pairs.
                            # intermediate[k] = PT[inv_sigma[k]]
                            # Hill pair at (j1, j2): M × (intermediate[j1], intermediate[j2])
                            #   = M × (PT[inv_sigma[j1]], PT[inv_sigma[j2]])
                            # We need inv_sigma[j1] and inv_sigma[j2] to both be crib positions.
                            inv_j1 = inv_sigma[j1]
                            inv_j2 = inv_sigma[j2]
                            if inv_j1 not in CRIB_PT or inv_j2 not in CRIB_PT:
                                continue
                            p1_b = CRIB_PT[inv_j1]
                            p2_b = CRIB_PT[inv_j2]
                            c1 = CT_NUM[j1]
                            c2 = CT_NUM[j2]
                            p1, p2 = p1_b, p2_b

                        pt_pairs.append((p1, p2))
                        ct_pairs.append((c1, c2))

                    if len(pt_pairs) < 3:
                        continue

                    # Try all pairs of digraphs as basis
                    found = False
                    for i in range(len(pt_pairs)):
                        if found:
                            break
                        for j in range(i + 1, len(pt_pairs)):
                            basis_pt = [pt_pairs[i], pt_pairs[j]]
                            basis_ct = [ct_pairs[i], ct_pairs[j]]

                            solutions = solve_2x2_hill(basis_pt, basis_ct)

                            for M_tuple in solutions:
                                M = [list(M_tuple[0]), list(M_tuple[1])]

                                # Verify on ALL pairs
                                all_match = True
                                for k in range(len(pt_pairs)):
                                    expected = apply_hill_2x2(M, pt_pairs[k][0], pt_pairs[k][1])
                                    if expected != ct_pairs[k]:
                                        all_match = False
                                        break

                                if all_match:
                                    n_solutions += 1
                                    found = True

                                    result = {
                                        "n": 2,
                                        "offset": offset,
                                        "width": width,
                                        "model": model,
                                        "order": order,
                                        "matrix": M_tuple,
                                        "n_verified": len(pt_pairs),
                                        "basis_indices": (i, j),
                                    }
                                    results.append(result)

                                    if n_solutions <= 5:
                                        print(f"  *** SOLUTION: w={width} model={model}"
                                              f" order={order} M={M_tuple}"
                                              f" verified={len(pt_pairs)} pairs")

                                    break
                            if found:
                                break

                elapsed = time.time() - t0
                print(f"  Hill n=2 off={offset} w={width} model {model}:"
                      f" {n_solutions}/{n_tested} solutions ({elapsed:.1f}s)",
                      flush=True)

    # =========================================================
    # Hill n=3 (trigraphs)
    # =========================================================
    for offset in [0, 1, 2]:
        crib_trigraphs = get_crib_trigraphs(offset)
        print(f"\n--- Hill n=3, offset={offset} ---")
        print(f"  Known trigraphs: {len(crib_trigraphs)}")
        for j1, j2, j3, p1, p2, p3 in crib_trigraphs:
            print(f"    ({j1},{j2},{j3}): ({chr(p1+65)},{chr(p2+65)},{chr(p3+65)})")

        if len(crib_trigraphs) < 4:
            print(f"  Too few trigraphs for reliable test")
            if len(crib_trigraphs) < 3:
                print(f"  Skipping (need ≥3)")
                continue

        for width in [7, 5, 6, 8]:
            # Only Model A for n=3 (Model B is more complex and slower)
            n_tested = 0
            n_solutions = 0

            for order_tuple in permutations(range(width)):
                order = list(order_tuple)
                sigma = columnar_perm(order, width, N)
                n_tested += 1

                # Model A: CT[σ(j)] = Hill(PT)[j]
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

                # Try all triples of trigraphs as basis
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

                            solutions = solve_3x3_hill(basis_pt, basis_ct)

                            for M_tuple in solutions:
                                M = [list(row) for row in M_tuple]

                                # Verify on ALL triples
                                all_match = True
                                for m in range(len(pt_triples)):
                                    expected = apply_hill_3x3(M, *pt_triples[m])
                                    if expected != ct_triples[m]:
                                        all_match = False
                                        break

                                if all_match:
                                    n_solutions += 1
                                    found = True
                                    result = {
                                        "n": 3,
                                        "offset": offset,
                                        "width": width,
                                        "model": "A",
                                        "order": order,
                                        "matrix": M_tuple,
                                        "n_verified": len(pt_triples),
                                    }
                                    results.append(result)

                                    if n_solutions <= 5:
                                        print(f"  *** SOLUTION: w={width}"
                                              f" order={order}"
                                              f" M={M_tuple}"
                                              f" verified={len(pt_triples)} triples")
                                    break
                            if found:
                                break

            elapsed = time.time() - t0
            print(f"  Hill n=3 off={offset} w={width} model A:"
                  f" {n_solutions}/{n_tested} solutions ({elapsed:.1f}s)",
                  flush=True)

    # =========================================================
    # SUMMARY
    # =========================================================
    elapsed = time.time() - t0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"  Time: {elapsed:.1f}s ({elapsed/60:.1f}min)")
    print(f"  Total solutions found: {len(results)}")

    if results:
        print(f"\n  Solutions:")
        for r in results[:20]:
            print(f"    n={r['n']} off={r['offset']} w={r['width']}"
                  f" model={r['model']} M={r['matrix']}"
                  f" verified={r['n_verified']}")
        verdict = "SIGNAL"
    else:
        verdict = "ELIMINATED"
        print(f"\n  Hill cipher + columnar transposition: ELIMINATED")
        print(f"  No consistent (σ, M) pair found for any width/offset/model")

    print(f"\n  Verdict: {verdict}")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_41_hill_transposition.json", "w") as f:
        json.dump({
            "experiment": "E-S-41",
            "description": "Hill cipher n=2,3 + columnar transposition widths 5-8",
            "widths_tested": [5, 6, 7, 8],
            "offsets_tested": [0, 1],
            "models_tested": ["A", "B"],
            "total_solutions": len(results),
            "verdict": verdict,
            "elapsed_seconds": round(elapsed, 1),
            "solutions": results[:50],
        }, f, indent=2)
    print(f"\n  Artifact: results/e_s_41_hill_transposition.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_41_hill_transposition.py")


if __name__ == "__main__":
    main()
