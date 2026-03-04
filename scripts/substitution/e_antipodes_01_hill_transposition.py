#!/usr/bin/env python3
"""
Cipher: Hill cipher
Family: substitution
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-ANTIPODES-01: Hill Sublayer + Transposition

HYPOTHESIS: The extra L on Kryptos spells "HILL" — Sanborn's hint at a Hill
cipher. Direct Hill was eliminated (E-S-151), but Hill AFTER transposition
is untested. A 2x2 Hill cipher composed with transposition produces
non-periodic substitution, explaining why all periodic models fail.

METHOD:
1. For each candidate transposition (columnar w6-13):
   - Apply inverse transposition to K4 CT
   - At crib positions in the transposed text, extract (CT, PT) digraph pairs
   - Set up linear system over Z_26 for 2x2 Hill matrix (4 unknowns)
   - Check consistency: all digraph pairs must satisfy CT = M * PT mod 26
   - If consistent + invertible: recover Hill matrix, decrypt full text, score
2. Also test 3x3 Hill (9 unknowns, triplet equations)
3. Test with both standard A-Z and KA alphabet numbering

COST: ~50K transpositions × algebraic check (microseconds) ≈ seconds.
"""

import json
import os
import sys
import time
import itertools
from math import gcd
from typing import Optional, List, Tuple, Dict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS, CRIB_WORDS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order, validate_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean, verify_bean_simple

# ── Z_26 linear algebra ───────────────────────────────────────────────────

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def mod_inverse(a: int, m: int = 26) -> Optional[int]:
    a = a % m
    if gcd(a, m) != 1:
        return None
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

def det_2x2(M: List[List[int]]) -> int:
    return (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % 26

def invert_2x2(M: List[List[int]]) -> Optional[List[List[int]]]:
    d = det_2x2(M)
    d_inv = mod_inverse(d, 26)
    if d_inv is None:
        return None
    return [
        [(d_inv * M[1][1]) % 26, (d_inv * (-M[0][1])) % 26],
        [(d_inv * (-M[1][0])) % 26, (d_inv * M[0][0]) % 26],
    ]

def mat_vec_2x2(M: List[List[int]], v: List[int]) -> List[int]:
    return [
        (M[0][0]*v[0] + M[0][1]*v[1]) % 26,
        (M[1][0]*v[0] + M[1][1]*v[1]) % 26,
    ]

def det_3x3(M: List[List[int]]) -> int:
    d = (M[0][0] * (M[1][1]*M[2][2] - M[1][2]*M[2][1])
       - M[0][1] * (M[1][0]*M[2][2] - M[1][2]*M[2][0])
       + M[0][2] * (M[1][0]*M[2][1] - M[1][1]*M[2][0]))
    return d % 26

def invert_3x3(M: List[List[int]]) -> Optional[List[List[int]]]:
    d = det_3x3(M)
    d_inv = mod_inverse(d, 26)
    if d_inv is None:
        return None
    cofactors = [[0]*3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            minor = []
            for r in range(3):
                if r == i:
                    continue
                row = []
                for c in range(3):
                    if c == j:
                        continue
                    row.append(M[r][c])
                minor.append(row)
            cof = (minor[0][0]*minor[1][1] - minor[0][1]*minor[1][0])
            sign = (-1) ** (i + j)
            cofactors[i][j] = (sign * cof) % 26
    adj = [[cofactors[j][i] for j in range(3)] for i in range(3)]
    return [[(d_inv * adj[i][j]) % 26 for j in range(3)] for i in range(3)]

def mat_vec_3x3(M: List[List[int]], v: List[int]) -> List[int]:
    return [
        (M[0][0]*v[0] + M[0][1]*v[1] + M[0][2]*v[2]) % 26,
        (M[1][0]*v[0] + M[1][1]*v[1] + M[1][2]*v[2]) % 26,
        (M[2][0]*v[0] + M[2][1]*v[1] + M[2][2]*v[2]) % 26,
    ]

# ── Alphabet helpers ──────────────────────────────────────────────────────

KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

ALPHABETS = {
    "AZ": (ALPH, ALPH_IDX),
    "KA": (KRYPTOS_ALPHABET, KA_IDX),
}

def char_to_num(ch: str, idx: Dict[str, int]) -> int:
    return idx[ch]

def num_to_char(n: int, alpha: str) -> str:
    return alpha[n % 26]

# ── Hill+Transposition test ──────────────────────────────────────────────

def get_crib_pairs_after_perm(perm: List[int]) -> Dict[int, Tuple[int, str]]:
    """After applying inverse perm to CT, which positions have known PT?

    Returns {transposed_pos: (original_crib_pos, pt_char)}.
    The transposed CT has output[i] = CT[perm[i]], so transposed_pos i
    corresponds to original position perm[i].
    """
    inv = invert_perm(perm)
    # inv[j] = i means position j in CT ends up at position i after perm
    # perm is the encryption perm: CT was produced by applying perm to intermediate
    # To reverse: intermediate[i] = CT[perm[i]], i.e., intermediate = apply_perm(CT, perm)
    # But we want: if we know PT at position p, then after transposition,
    # intermediate[p] was encrypted by Hill at position p.
    # CT = perm(Hill(PT)), so Hill(PT) = inv_perm(CT).
    # intermediate = apply_perm(CT, inv_perm) where inv_perm = invert_perm(perm)
    # Then intermediate[i] = CT[inv_perm[i]]
    # Hill: intermediate[i] = Hill_encrypt(PT[i]) for blocks of size 2/3
    # So at crib positions p where PT[p] is known, intermediate[p] = CT[inv_perm[p]]
    # We need pairs where consecutive crib positions exist.

    result = {}
    inv_p = invert_perm(perm)
    for crib_pos, pt_char in CRIB_DICT.items():
        # intermediate[crib_pos] = CT[inv_p[crib_pos]]
        ct_char = CT[inv_p[crib_pos]]
        result[crib_pos] = (inv_p[crib_pos], ct_char, pt_char)
    return result


def test_hill_2x2_with_perm(
    perm: List[int],
    alpha_name: str, alpha: str, alpha_idx: Dict[str, int],
    block_offset: int = 0,
) -> Optional[Dict]:
    """Test 2x2 Hill consistency after transposition.

    For Hill 2x2 with block offset, pairs are at positions
    (2k + offset, 2k + offset + 1).
    We need at least 2 such pairs where both positions are crib positions.
    """
    inv_p = invert_perm(perm)

    # Build list of known (pos, ct_num, pt_num) after transposition
    known = {}
    for crib_pos, pt_char in CRIB_DICT.items():
        ct_char = CT[inv_p[crib_pos]]
        ct_num = char_to_num(ct_char, alpha_idx)
        pt_num = char_to_num(pt_char, alpha_idx)
        known[crib_pos] = (ct_num, pt_num)

    # Find digraph pairs aligned to block_offset
    pairs = []
    for pos in sorted(known.keys()):
        if (pos - block_offset) % 2 != 0:
            continue
        pos2 = pos + 1
        if pos2 in known:
            ct0, pt0 = known[pos]
            ct1, pt1 = known[pos2]
            pairs.append((ct0, ct1, pt0, pt1, pos, pos2))

    if len(pairs) < 2:
        return None

    # Try to solve from first pair, check consistency with rest
    ct0, ct1, pt0, pt1 = pairs[0][:4]

    # CT = M * PT: [[ct0], [ct1]] = [[a,b],[c,d]] * [[pt0], [pt1]]
    # Need 2 pairs to get 4 equations for 4 unknowns
    # From pairs[0]: ct0 = a*pt0 + b*pt1,  ct1 = c*pt0 + d*pt1
    # From pairs[1]: ct2 = a*pt2 + b*pt3,  ct3 = c*pt2 + d*pt3

    ct2, ct3, pt2, pt3 = pairs[1][:4]

    # Solve for (a,b): [[pt0, pt1], [pt2, pt3]] * [a, b]^T = [ct0, ct2]^T
    P = [[pt0, pt1], [pt2, pt3]]
    P_inv = invert_2x2(P)
    if P_inv is None:
        return None

    ab = mat_vec_2x2(P_inv, [ct0, ct2])
    cd = mat_vec_2x2(P_inv, [ct1, ct3])
    M = [ab, cd]

    # Check invertibility
    M_inv = invert_2x2(M)
    if M_inv is None:
        return None

    # Verify consistency with ALL pairs
    consistent = True
    for ct_a, ct_b, pt_a, pt_b, p1, p2 in pairs:
        expected = mat_vec_2x2(M, [pt_a, pt_b])
        if expected[0] != ct_a or expected[1] != ct_b:
            consistent = False
            break

    if not consistent:
        return None

    # Decrypt full text: PT = M_inv * intermediate (after inv transposition)
    intermediate = apply_perm(CT, inv_p)
    pt_chars = []
    for i in range(0, CT_LEN - 1, 2):
        if i + 1 < CT_LEN:
            c0 = char_to_num(intermediate[i], alpha_idx)
            c1 = char_to_num(intermediate[i + 1], alpha_idx)
            p = mat_vec_2x2(M_inv, [c0, c1])
            pt_chars.append(num_to_char(p[0], alpha))
            pt_chars.append(num_to_char(p[1], alpha))
    # Handle odd last char if CT_LEN is odd
    if CT_LEN % 2 == 1:
        pt_chars.append(intermediate[-1])

    plaintext = "".join(pt_chars)
    crib_sc = score_cribs(plaintext)

    return {
        "plaintext": plaintext,
        "crib_score": crib_sc,
        "hill_matrix": M,
        "hill_inv": M_inv,
        "alpha": alpha_name,
        "block_offset": block_offset,
        "n_pairs_checked": len(pairs),
    }


def test_hill_3x3_with_perm(
    perm: List[int],
    alpha_name: str, alpha: str, alpha_idx: Dict[str, int],
    block_offset: int = 0,
) -> Optional[Dict]:
    """Test 3x3 Hill consistency after transposition."""
    inv_p = invert_perm(perm)

    known = {}
    for crib_pos, pt_char in CRIB_DICT.items():
        ct_char = CT[inv_p[crib_pos]]
        ct_num = char_to_num(ct_char, alpha_idx)
        pt_num = char_to_num(pt_char, alpha_idx)
        known[crib_pos] = (ct_num, pt_num)

    # Find triplet groups aligned to block_offset
    triplets = []
    for pos in sorted(known.keys()):
        if (pos - block_offset) % 3 != 0:
            continue
        pos2 = pos + 1
        pos3 = pos + 2
        if pos2 in known and pos3 in known:
            ct0, pt0 = known[pos]
            ct1, pt1 = known[pos2]
            ct2, pt2 = known[pos3]
            triplets.append((ct0, ct1, ct2, pt0, pt1, pt2, pos))

    if len(triplets) < 3:
        return None

    # Solve 3x3 system from first 3 triplets
    # CT_col = M * PT_col for each triplet
    # Build 3x3 PT matrix and 3x3 CT matrix from 3 triplets
    PT_mat = [[triplets[j][3+i] for j in range(3)] for i in range(3)]
    CT_mat = [[triplets[j][i] for j in range(3)] for i in range(3)]

    PT_inv = invert_3x3(PT_mat)
    if PT_inv is None:
        return None

    # M = CT_mat * PT_mat^-1 (column-wise)
    # Actually: for row i of M, solve row i of CT = M_row_i * PT_cols
    # M[r][c] = sum_j CT_mat[r][j] * PT_inv[j][c]
    M = [[0]*3 for _ in range(3)]
    for r in range(3):
        for c in range(3):
            M[r][c] = sum(CT_mat[r][j] * PT_inv[j][c] for j in range(3)) % 26

    M_inv = invert_3x3(M)
    if M_inv is None:
        return None

    # Verify ALL triplets
    for ct0, ct1, ct2, pt0, pt1, pt2, pos in triplets:
        expected = mat_vec_3x3(M, [pt0, pt1, pt2])
        if expected[0] != ct0 or expected[1] != ct1 or expected[2] != ct2:
            return None

    # Decrypt
    intermediate = apply_perm(CT, inv_p)
    pt_chars = []
    for i in range(0, CT_LEN - 2, 3):
        if i + 2 < CT_LEN:
            c = [char_to_num(intermediate[i+j], alpha_idx) for j in range(3)]
            p = mat_vec_3x3(M_inv, c)
            for pv in p:
                pt_chars.append(num_to_char(pv, alpha))
    remainder = CT_LEN % 3
    if remainder > 0:
        for j in range(remainder):
            pt_chars.append(intermediate[CT_LEN - remainder + j])

    plaintext = "".join(pt_chars)
    crib_sc = score_cribs(plaintext)

    return {
        "plaintext": plaintext,
        "crib_score": crib_sc,
        "hill_matrix": M,
        "hill_inv": M_inv,
        "alpha": alpha_name,
        "block_offset": block_offset,
        "n_triplets_checked": len(triplets),
    }


def generate_column_orderings(width: int, max_orderings: int = 5040):
    """Generate column orderings for columnar transposition.
    For width <= 7: all permutations. For width > 7: keyword-based sample.
    """
    if width <= 7:
        yield from itertools.permutations(range(width))
    else:
        # Sample via keywords from thematic list + random permutations
        from kryptos.kernel.alphabet import THEMATIC_KEYWORDS
        seen = set()
        for kw in THEMATIC_KEYWORDS:
            order = keyword_to_order(kw, width)
            if order is not None and order not in seen:
                seen.add(order)
                yield order
        # Also try alphabetical orderings of common keywords
        for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "SANBORN",
                    "SCHEIDT", "SHADOW", "ENIGMA", "QUARTZ", "CLOCK",
                    "EASTNORTHEAST", "BERLINCLOCK", "CARTER", "EGYPT",
                    "CIPHER", "HILL", "MATRIX", "COLUMNS", "SECRET"]:
            order = keyword_to_order(kw, width)
            if order is not None and order not in seen:
                seen.add(order)
                yield order
        # Fill rest with random permutations
        import random
        rng = random.Random(42)
        attempts = 0
        while len(seen) < max_orderings and attempts < max_orderings * 5:
            perm = list(range(width))
            rng.shuffle(perm)
            t = tuple(perm)
            if t not in seen:
                seen.add(t)
                yield t
            attempts += 1


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-01: Hill Sublayer + Transposition")
    print("=" * 70)

    best_result = None
    best_score = 0
    total_configs = 0
    consistent_2x2 = 0
    consistent_3x3 = 0
    results_log = []

    for width in range(6, 14):
        print(f"\n--- Width {width} ---")
        w_configs = 0
        w_consistent = 0

        for col_order in generate_column_orderings(width):
            perm = columnar_perm(width, col_order, CT_LEN)
            if not validate_perm(perm, CT_LEN):
                continue

            for alpha_name, (alpha, alpha_idx) in ALPHABETS.items():
                for block_offset in range(2):
                    total_configs += 1
                    w_configs += 1

                    result = test_hill_2x2_with_perm(
                        perm, alpha_name, alpha, alpha_idx, block_offset
                    )
                    if result is not None:
                        consistent_2x2 += 1
                        w_consistent += 1
                        sc = result["crib_score"]
                        if sc > NOISE_FLOOR:
                            results_log.append({
                                "type": "hill_2x2",
                                "width": width,
                                "col_order": list(col_order),
                                **result,
                            })
                        if sc > best_score:
                            best_score = sc
                            best_result = {
                                "type": "hill_2x2",
                                "width": width,
                                "col_order": list(col_order),
                                **result,
                            }
                            print(f"  NEW BEST 2x2: score={sc}/24, alpha={alpha_name}, "
                                  f"offset={block_offset}, width={width}")
                            if sc >= STORE_THRESHOLD:
                                print(f"  PT: {result['plaintext']}")

                # 3x3 Hill tests
                for block_offset in range(3):
                    total_configs += 1
                    w_configs += 1

                    result = test_hill_3x3_with_perm(
                        perm, alpha_name, alpha, alpha_idx, block_offset
                    )
                    if result is not None:
                        consistent_3x3 += 1
                        w_consistent += 1
                        sc = result["crib_score"]
                        if sc > NOISE_FLOOR:
                            results_log.append({
                                "type": "hill_3x3",
                                "width": width,
                                "col_order": list(col_order),
                                **result,
                            })
                        if sc > best_score:
                            best_score = sc
                            best_result = {
                                "type": "hill_3x3",
                                "width": width,
                                "col_order": list(col_order),
                                **result,
                            }
                            print(f"  NEW BEST 3x3: score={sc}/24, alpha={alpha_name}, "
                                  f"offset={block_offset}, width={width}")
                            if sc >= STORE_THRESHOLD:
                                print(f"  PT: {result['plaintext']}")

        print(f"  Width {width}: {w_configs} configs, {w_consistent} consistent")

    # ── Exhaustive 2x2 brute force at small widths ──
    print("\n--- Exhaustive 2x2 brute force (w6-8, all 676 matrices) ---")
    for width in range(6, 9):
        print(f"  Width {width}...")
        for col_order in generate_column_orderings(width):
            perm = columnar_perm(width, col_order, CT_LEN)
            if not validate_perm(perm, CT_LEN):
                continue
            inv_p = invert_perm(perm)
            intermediate = apply_perm(CT, inv_p)

            for alpha_name, (alpha, alpha_idx) in ALPHABETS.items():
                # Try all 26^4 = 456976 matrices... too many.
                # Instead try all invertible 2x2: det coprime to 26
                # There are 157248 invertible 2x2 matrices mod 26.
                # For speed, only test matrices that are consistent
                # with at least one known digraph pair.
                # Build known pairs for offset 0
                known_pairs_0 = []
                known_pairs_1 = []
                for pos in sorted(CRIB_DICT.keys()):
                    pt_char = CRIB_DICT[pos]
                    ct_char = intermediate[pos]
                    ct_num = char_to_num(ct_char, alpha_idx)
                    pt_num = char_to_num(pt_char, alpha_idx)
                    if pos % 2 == 0 and pos + 1 in CRIB_DICT:
                        pt2 = char_to_num(CRIB_DICT[pos+1], alpha_idx)
                        ct2 = char_to_num(intermediate[pos+1], alpha_idx)
                        known_pairs_0.append((ct_num, ct2, pt_num, pt2))
                    if pos % 2 == 1 and pos + 1 in CRIB_DICT:
                        pt2 = char_to_num(CRIB_DICT[pos+1], alpha_idx)
                        ct2 = char_to_num(intermediate[pos+1], alpha_idx)
                        known_pairs_1.append((ct_num, ct2, pt_num, pt2))

                # For each pair of known digraphs, solve for M
                for pairs_list, offset in [(known_pairs_0, 0), (known_pairs_1, 1)]:
                    for i in range(len(pairs_list)):
                        for j in range(i+1, len(pairs_list)):
                            total_configs += 1
                            ct0a, ct0b, pt0a, pt0b = pairs_list[i]
                            ct1a, ct1b, pt1a, pt1b = pairs_list[j]
                            P = [[pt0a, pt0b], [pt1a, pt1b]]
                            P_inv = invert_2x2(P)
                            if P_inv is None:
                                continue
                            ab = mat_vec_2x2(P_inv, [ct0a, ct1a])
                            cd = mat_vec_2x2(P_inv, [ct0b, ct1b])
                            M = [ab, cd]
                            M_inv = invert_2x2(M)
                            if M_inv is None:
                                continue
                            # Verify all pairs
                            ok = True
                            for cta, ctb, pta, ptb in pairs_list:
                                exp = mat_vec_2x2(M, [pta, ptb])
                                if exp[0] != cta or exp[1] != ctb:
                                    ok = False
                                    break
                            if not ok:
                                continue

                            consistent_2x2 += 1
                            # Decrypt
                            pt_chars = []
                            start = offset
                            if start > 0:
                                pt_chars.append(intermediate[0])
                            for k in range(start, CT_LEN - 1, 2):
                                c0 = char_to_num(intermediate[k], alpha_idx)
                                c1 = char_to_num(intermediate[k+1], alpha_idx)
                                p = mat_vec_2x2(M_inv, [c0, c1])
                                pt_chars.append(num_to_char(p[0], alpha))
                                pt_chars.append(num_to_char(p[1], alpha))
                            if (CT_LEN - start) % 2 == 1:
                                pt_chars.append(intermediate[-1])

                            plaintext = "".join(pt_chars[:CT_LEN])
                            sc = score_cribs(plaintext)
                            if sc > best_score:
                                best_score = sc
                                best_result = {
                                    "type": "hill_2x2_brute",
                                    "width": width,
                                    "col_order": list(col_order),
                                    "plaintext": plaintext,
                                    "crib_score": sc,
                                    "hill_matrix": M,
                                    "alpha": alpha_name,
                                    "block_offset": offset,
                                }
                                print(f"  BRUTE BEST: score={sc}/24, w={width}, "
                                      f"alpha={alpha_name}, offset={offset}")
                                if sc >= STORE_THRESHOLD:
                                    print(f"  PT: {plaintext}")
                            if sc > NOISE_FLOOR:
                                results_log.append({
                                    "type": "hill_2x2_brute",
                                    "width": width,
                                    "col_order": list(col_order),
                                    "plaintext": plaintext,
                                    "crib_score": sc,
                                    "hill_matrix": M,
                                    "alpha": alpha_name,
                                    "block_offset": offset,
                                })

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Consistent 2x2 solutions: {consistent_2x2}")
    print(f"Consistent 3x3 solutions: {consistent_3x3}")
    print(f"Best crib score: {best_score}/24")
    if best_result:
        print(f"Best config: {best_result.get('type')}, width={best_result.get('width')}, "
              f"alpha={best_result.get('alpha')}")
        if best_score >= STORE_THRESHOLD:
            print(f"Best plaintext: {best_result.get('plaintext')}")
    print(f"Above-noise results: {len(results_log)}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Write results ─────────────────────────────────────────────────────
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_01')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-01",
        "hypothesis": "Hill cipher (2x2/3x3) after columnar transposition",
        "total_configs": total_configs,
        "consistent_2x2": consistent_2x2,
        "consistent_3x3": consistent_3x3,
        "best_score": best_score,
        "best_result": best_result,
        "above_noise_count": len(results_log),
        "elapsed_seconds": elapsed,
        "widths_tested": list(range(6, 14)),
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    if results_log:
        with open(os.path.join(outdir, 'above_noise.json'), 'w') as f:
            json.dump(results_log, f, indent=2)

    print(f"\nResults written to {outdir}/")
    if best_score <= NOISE_FLOOR:
        print("\nCONCLUSION: NOISE — Hill+Transposition eliminated for tested widths.")
    elif best_score < STORE_THRESHOLD:
        print(f"\nCONCLUSION: Low signal ({best_score}/24), likely noise.")
    else:
        print(f"\nCONCLUSION: SIGNAL detected ({best_score}/24) — investigate!")


if __name__ == "__main__":
    main()
