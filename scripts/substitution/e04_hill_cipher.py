#!/usr/bin/env python3
"""
Cipher: Hill cipher
Family: substitution
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-04: Hill Cipher hypothesis for K4.

Motivation: The anomaly registry (§B1) documents an extra letter "L" on the
Vigenère tableau that creates "HILL" reading down the right side. The Hill
cipher uses matrix multiplication over Z₂₆ — a fundamentally different
cipher family from Vigenère.

Tests:
1. Pure Hill cipher (2×2 and 3×3) — derive matrix from crib equations
2. Vigenère + Hill (two-layer, consistent with "LAYER TWO")
3. Hill + Vigenère
4. Hill + transposition
5. Exhaustive 2×2 Hill (676² = ~460K matrices)
"""

import sys
import os
import math
from itertools import product
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]


def num_to_char(n):
    return chr(ord('A') + (n % 26))


def score_cribs(pt_nums):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == ALPH_IDX[ch]:
            matches += 1
    return matches


def check_bean(pt_nums):
    key = [(CT_NUM[i] - pt_nums[i]) % MOD for i in range(len(pt_nums))]
    for a, b in BEAN_EQ:
        if key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if key[a] == key[b]:
            return False
    return True


def mod_inverse(a, m=26):
    """Modular multiplicative inverse using extended GCD."""
    if a == 0:
        return None
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        return None
    return x % m


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mat2_det(m):
    """Determinant of 2×2 matrix mod 26."""
    return (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % MOD


def mat2_inv(m):
    """Inverse of 2×2 matrix mod 26, or None if singular."""
    det = mat2_det(m)
    det_inv = mod_inverse(det)
    if det_inv is None:
        return None
    return [
        [(det_inv * m[1][1]) % MOD, (det_inv * (-m[0][1])) % MOD],
        [(det_inv * (-m[1][0])) % MOD, (det_inv * m[0][0]) % MOD],
    ]


def mat2_mul_vec(m, v):
    """Multiply 2×2 matrix by 2-vector mod 26."""
    return [
        (m[0][0] * v[0] + m[0][1] * v[1]) % MOD,
        (m[1][0] * v[0] + m[1][1] * v[1]) % MOD,
    ]


def hill2_decrypt(ct_nums, inv_matrix):
    """Decrypt using 2×2 Hill cipher with given inverse matrix."""
    pt = []
    for i in range(0, len(ct_nums) - 1, 2):
        pair = [ct_nums[i], ct_nums[i + 1]]
        dec = mat2_mul_vec(inv_matrix, pair)
        pt.extend(dec)
    if len(ct_nums) % 2 == 1:
        pt.append(ct_nums[-1])  # last char unchanged if odd
    return pt


def hill2_encrypt(pt_nums, matrix):
    """Encrypt using 2×2 Hill cipher."""
    ct = []
    for i in range(0, len(pt_nums) - 1, 2):
        pair = [pt_nums[i], pt_nums[i + 1]]
        enc = mat2_mul_vec(matrix, pair)
        ct.extend(enc)
    if len(pt_nums) % 2 == 1:
        ct.append(pt_nums[-1])
    return ct


def mat3_det(m):
    """Determinant of 3×3 matrix mod 26."""
    d = (m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
         - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
         + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]))
    return d % MOD


def mat3_inv(m):
    """Inverse of 3×3 matrix mod 26, or None if singular."""
    det = mat3_det(m)
    det_inv = mod_inverse(det)
    if det_inv is None:
        return None

    # Cofactor matrix
    cofactors = [[0] * 3 for _ in range(3)]
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
                    row.append(m[r][c])
                minor.append(row)
            cof = (minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0]) % MOD
            if (i + j) % 2 == 1:
                cof = (-cof) % MOD
            cofactors[i][j] = cof

    # Transpose cofactor matrix (adjugate) and multiply by det_inv
    inv = [[0] * 3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            inv[i][j] = (det_inv * cofactors[j][i]) % MOD
    return inv


def mat3_mul_vec(m, v):
    """Multiply 3×3 matrix by 3-vector mod 26."""
    return [
        (m[0][0] * v[0] + m[0][1] * v[1] + m[0][2] * v[2]) % MOD,
        (m[1][0] * v[0] + m[1][1] * v[1] + m[1][2] * v[2]) % MOD,
        (m[2][0] * v[0] + m[2][1] * v[1] + m[2][2] * v[2]) % MOD,
    ]


def hill3_decrypt(ct_nums, inv_matrix):
    """Decrypt using 3×3 Hill cipher."""
    pt = []
    for i in range(0, len(ct_nums) - 2, 3):
        triple = [ct_nums[i], ct_nums[i + 1], ct_nums[i + 2]]
        dec = mat3_mul_vec(inv_matrix, triple)
        pt.extend(dec)
    remainder = len(ct_nums) % 3
    if remainder > 0:
        pt.extend(ct_nums[-remainder:])
    return pt


def vig_decrypt(ct_nums, key_nums):
    period = len(key_nums)
    return [(ct_nums[i] - key_nums[i % period]) % MOD for i in range(len(ct_nums))]


def vig_encrypt(pt_nums, key_nums):
    period = len(key_nums)
    return [(pt_nums[i] + key_nums[i % period]) % MOD for i in range(len(pt_nums))]


def main():
    print("=" * 80)
    print("E-04: Hill Cipher Hypothesis for K4")
    print("=" * 80)

    results = []

    # ── Phase 1: Algebraic solution for 2×2 Hill from cribs ──────────────────

    print("\n── Phase 1: Algebraic 2×2 Hill from crib pairs ──")

    # For a 2×2 Hill cipher: [C₁,C₂]ᵀ = M * [P₁,P₂]ᵀ mod 26
    # Using two consecutive crib pairs gives 4 equations in 4 unknowns
    # M = C_mat * P_mat⁻¹

    # Collect all consecutive crib pairs
    crib_positions = sorted(CRIB_DICT.keys())
    crib_pairs = []
    for i in range(len(crib_positions) - 1):
        p1, p2 = crib_positions[i], crib_positions[i + 1]
        if p2 == p1 + 1:  # consecutive
            ct1, ct2 = CT_NUM[p1], CT_NUM[p2]
            pt1, pt2 = ALPH_IDX[CRIB_DICT[p1]], ALPH_IDX[CRIB_DICT[p2]]
            crib_pairs.append((p1, ct1, ct2, pt1, pt2))

    print(f"  Found {len(crib_pairs)} consecutive crib pairs")

    # Try all pairs of crib-pairs for block alignment offset 0 and 1
    hill2_solutions = []
    for offset in range(2):  # Block starts at even or odd positions
        for i in range(len(crib_pairs)):
            for j in range(i + 1, len(crib_pairs)):
                p1_a, ct1_a, ct2_a, pt1_a, pt2_a = crib_pairs[i]
                p1_b, ct1_b, ct2_b, pt1_b, pt2_b = crib_pairs[j]

                # Check block alignment: both pairs must start at same parity as offset
                if p1_a % 2 != offset or p1_b % 2 != offset:
                    continue

                P_mat = [[pt1_a, pt1_b], [pt2_a, pt2_b]]
                C_mat = [[ct1_a, ct1_b], [ct2_a, ct2_b]]

                P_inv = mat2_inv(P_mat)
                if P_inv is None:
                    continue

                # M = C_mat * P_inv
                M = [
                    [(C_mat[0][0] * P_inv[0][0] + C_mat[0][1] * P_inv[1][0]) % MOD,
                     (C_mat[0][0] * P_inv[0][1] + C_mat[0][1] * P_inv[1][1]) % MOD],
                    [(C_mat[1][0] * P_inv[0][0] + C_mat[1][1] * P_inv[1][0]) % MOD,
                     (C_mat[1][0] * P_inv[0][1] + C_mat[1][1] * P_inv[1][1]) % MOD],
                ]

                # Verify M is invertible
                M_inv = mat2_inv(M)
                if M_inv is None:
                    continue

                # Decrypt full CT
                pt = hill2_decrypt(CT_NUM, M_inv)
                score = score_cribs(pt)

                if score >= 8:
                    bean = check_bean(pt)
                    pt_text = ''.join(num_to_char(n) for n in pt)
                    tag = f"Hill2 offset={offset} pairs=({p1_a},{p1_b})"
                    hill2_solutions.append((score, M, M_inv, tag, bean))
                    print(f"  {tag}: M={M} score={score}/{N_CRIBS} "
                          f"{'BEAN✓' if bean else 'bean✗'}")
                    if score >= 12:
                        print(f"    PT: {pt_text[:50]}...")

    print(f"  Found {len(hill2_solutions)} Hill-2 solutions with score ≥ 8")

    # ── Phase 2: Exhaustive 2×2 Hill (all invertible matrices) ───────────────

    print("\n── Phase 2: Exhaustive 2×2 Hill (all invertible matrices) ──")
    print("  Testing all 2×2 matrices with det coprime to 26...")

    # Coprime to 26 means gcd(det, 26) = 1, so det ∈ {1,3,5,7,9,11,15,17,19,21,23,25}
    coprime_to_26 = {d for d in range(26) if math.gcd(d, 26) == 1}
    count = 0
    best_exhaustive = (0, None, None, "", False)

    for a in range(26):
        for b in range(26):
            for c in range(26):
                for d in range(26):
                    det = (a * d - b * c) % 26
                    if det not in coprime_to_26:
                        continue
                    count += 1

                    M = [[a, b], [c, d]]
                    M_inv = mat2_inv(M)
                    if M_inv is None:
                        continue

                    # Quick check: decrypt just the crib positions first
                    # For offset 0: pairs are (0,1), (2,3), ...
                    # Position 21 is in pair starting at 20 (offset 0) or 21 (offset 1)
                    for offset in range(2):
                        # Check a few crib positions quickly
                        quick_match = 0
                        quick_fail = False

                        for pos in [21, 22, 63, 64]:
                            if pos not in CRIB_DICT:
                                continue
                            block_start = pos - ((pos - offset) % 2)
                            if block_start < 0 or block_start + 1 >= CT_LEN:
                                continue
                            pair = [CT_NUM[block_start], CT_NUM[block_start + 1]]
                            dec = mat2_mul_vec(M_inv, pair)
                            target = ALPH_IDX[CRIB_DICT[pos]]
                            idx_in_pair = pos - block_start
                            if dec[idx_in_pair] == target:
                                quick_match += 1
                            else:
                                quick_fail = True
                                break

                        if quick_fail or quick_match < 2:
                            continue

                        # Full decrypt
                        pt = []
                        for i in range(offset, CT_LEN - 1, 2):
                            pair = [CT_NUM[i], CT_NUM[i + 1]]
                            dec = mat2_mul_vec(M_inv, pair)
                            pt.extend(dec)

                        # Pad for positions before offset and after
                        full_pt = [CT_NUM[i] for i in range(offset)] + pt
                        if len(full_pt) < CT_LEN:
                            full_pt.extend(CT_NUM[len(full_pt):CT_LEN])
                        full_pt = full_pt[:CT_LEN]

                        score = score_cribs(full_pt)
                        if score > best_exhaustive[0]:
                            bean = check_bean(full_pt)
                            best_exhaustive = (score, M, M_inv, f"offset={offset}", bean)

                        if score >= 10:
                            bean = check_bean(full_pt)
                            pt_text = ''.join(num_to_char(n) for n in full_pt)
                            bean_str = "BEAN✓" if bean else "bean✗"
                            print(f"  ** Hill2 M={M} offset={offset}: score={score}/{N_CRIBS} {bean_str}")
                            print(f"     PT: {pt_text[:50]}...")
                            results.append((score, f"Hill2 M={M} off={offset}", M, bean))

    print(f"  Tested {count:,} invertible 2×2 matrices")
    if best_exhaustive[0] > 0:
        s, M, Mi, tag, bean = best_exhaustive
        print(f"  Best exhaustive: score={s}/{N_CRIBS} M={M} {tag} {'BEAN✓' if bean else 'bean✗'}")

    # ── Phase 3: Vigenère + Hill (LAYER TWO) ─────────────────────────────────

    print("\n── Phase 3: Vigenère(period p) + Hill2 — 'LAYER TWO' ──")
    print("  For each period, solve Hill matrix algebraically from Vig-decrypted cribs")

    # For small Vigenère periods, try all keys and check if a Hill layer fits
    for period in range(1, 8):
        print(f"  Period {period}...")
        # We know the Vigenère keystream at crib positions
        # For the Vig+Hill model: CT = Hill(Vig_encrypt(PT, vig_key))
        # So Vig_encrypt(PT, vig_key) = Hill⁻¹(CT)
        # Or equivalently: intermediate = Vig_encrypt(PT, key) and CT = Hill(intermediate)
        #
        # Strategy: for each candidate Vig key at crib positions, compute
        # intermediate = Vig_encrypt(PT_crib, key_crib), then solve for Hill matrix

        # Actually, we need to try all possible Vigenère keys at the crib positions.
        # For period p, the key at position i is key[i % p].
        # At crib positions, we need key[pos % p] for each crib pos.
        # The distinct residues within the ENE crib (21-33) mod p give us constraints.

        # Simpler approach: for each period, enumerate key values at the needed residues
        residues_needed = set()
        for pos in CRIB_DICT:
            residues_needed.add(pos % period)

        n_residues = len(residues_needed)
        if n_residues > 6:  # Too many to enumerate
            continue

        # Enumerate all possible key values for the needed residues
        best_for_period = (0, None, None)
        configs_tested = 0

        for key_vals in product(range(26), repeat=n_residues):
            configs_tested += 1
            residue_list = sorted(residues_needed)
            key_map = dict(zip(residue_list, key_vals))

            # Compute intermediate at crib positions: inter[pos] = (PT[pos] + key[pos%p]) % 26
            inter_at_cribs = {}
            for pos, ch in CRIB_DICT.items():
                pt_val = ALPH_IDX[ch]
                k = key_map[pos % period]
                inter_at_cribs[pos] = (pt_val + k) % MOD

            # Now solve for Hill matrix: CT[pos] = Hill(inter[pos], inter[pos+1])
            # Need consecutive pairs in the intermediate
            # Try block offset 0
            for offset in range(2):
                # Find pairs where both positions are crib positions
                pairs_for_solve = []
                for pos in sorted(inter_at_cribs.keys()):
                    partner = pos + 1 if (pos - offset) % 2 == 0 else pos - 1
                    if partner in inter_at_cribs:
                        block_start = min(pos, partner)
                        if (block_start - offset) % 2 == 0:
                            i1 = inter_at_cribs[block_start]
                            i2 = inter_at_cribs[block_start + 1]
                            c1 = CT_NUM[block_start]
                            c2 = CT_NUM[block_start + 1]
                            pairs_for_solve.append((i1, i2, c1, c2))

                if len(pairs_for_solve) < 2:
                    continue

                # Try first two pairs to solve for matrix
                i1a, i2a, c1a, c2a = pairs_for_solve[0]
                i1b, i2b, c1b, c2b = pairs_for_solve[1]

                P_mat = [[i1a, i1b], [i2a, i2b]]
                C_mat = [[c1a, c1b], [c2a, c2b]]

                P_inv = mat2_inv(P_mat)
                if P_inv is None:
                    continue

                H = [
                    [(C_mat[0][0] * P_inv[0][0] + C_mat[0][1] * P_inv[1][0]) % MOD,
                     (C_mat[0][0] * P_inv[0][1] + C_mat[0][1] * P_inv[1][1]) % MOD],
                    [(C_mat[1][0] * P_inv[0][0] + C_mat[1][1] * P_inv[1][0]) % MOD,
                     (C_mat[1][0] * P_inv[0][1] + C_mat[1][1] * P_inv[1][1]) % MOD],
                ]

                H_inv = mat2_inv(H)
                if H_inv is None:
                    continue

                # Verify against remaining pairs
                verified = 2
                for k_idx in range(2, len(pairs_for_solve)):
                    i1, i2, c1, c2 = pairs_for_solve[k_idx]
                    enc = mat2_mul_vec(H, [i1, i2])
                    if enc[0] == c1 and enc[1] == c2:
                        verified += 1

                if verified < 3:
                    continue

                # Full decrypt: Hill⁻¹(CT) → intermediate, then Vig_decrypt(inter, key)
                full_key = [0] * CT_LEN
                for i in range(CT_LEN):
                    r = i % period
                    full_key[i] = key_map.get(r, 0)  # 0 for unknown residues

                inter = hill2_decrypt(CT_NUM, H_inv)
                inter = [CT_NUM[i] for i in range(offset)] + inter
                if len(inter) < CT_LEN:
                    inter.extend(CT_NUM[len(inter):CT_LEN])
                inter = inter[:CT_LEN]

                pt = [(inter[i] - full_key[i]) % MOD for i in range(CT_LEN)]
                score = score_cribs(pt)

                if score > best_for_period[0]:
                    best_for_period = (score, H, key_vals)

                if score >= 12:
                    bean = check_bean(pt)
                    pt_text = ''.join(num_to_char(n) for n in pt)
                    print(f"    ** p={period} off={offset} H={H} key={key_vals}: "
                          f"score={score}/{N_CRIBS} {'BEAN✓' if bean else 'bean✗'}")
                    print(f"       PT: {pt_text[:50]}...")
                    results.append((score, f"Vig(p={period})+Hill2", H, bean))

        if best_for_period[0] >= 6:
            print(f"    Best for period {period}: score={best_for_period[0]}/{N_CRIBS}")
        if configs_tested > 0 and configs_tested % 100000 == 0:
            print(f"    ... {configs_tested:,} configs tested")

    # ── Phase 4: Hill cipher with YAR/DYARO-derived matrix ───────────────────

    print("\n── Phase 4: YAR/DYARO as Hill cipher matrix elements ──")

    # YAR = [24, 0, 17], DYARO = [3, 24, 0, 17, 14]
    yar = [24, 0, 17]
    dyaro = [3, 24, 0, 17, 14]

    # 2×2 matrices from DYARO subsets
    for i in range(len(dyaro)):
        for j in range(len(dyaro)):
            for k in range(len(dyaro)):
                for l in range(len(dyaro)):
                    M = [[dyaro[i], dyaro[j]], [dyaro[k], dyaro[l]]]
                    det = mat2_det(M)
                    if math.gcd(det, 26) != 1:
                        continue
                    M_inv = mat2_inv(M)
                    if M_inv is None:
                        continue

                    for offset in range(2):
                        pt = []
                        for idx in range(offset, CT_LEN - 1, 2):
                            pair = [CT_NUM[idx], CT_NUM[idx + 1]]
                            dec = mat2_mul_vec(M_inv, pair)
                            pt.extend(dec)
                        full_pt = [CT_NUM[i2] for i2 in range(offset)] + pt
                        if len(full_pt) < CT_LEN:
                            full_pt.extend(CT_NUM[len(full_pt):CT_LEN])
                        full_pt = full_pt[:CT_LEN]

                        score = score_cribs(full_pt)
                        if score >= 8:
                            bean = check_bean(full_pt)
                            print(f"  DYARO matrix {M} off={offset}: score={score}/{N_CRIBS} "
                                  f"{'BEAN✓' if bean else 'bean✗'}")
                            results.append((score, f"DYARO Hill2 {M}", M, bean))

    # 3×3 matrix from YAR
    for perm in [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]:
        # Fill 3×3 with rotations of YAR
        M3 = [
            [yar[perm[0]], yar[perm[1]], yar[perm[2]]],
            [yar[(perm[0] + 1) % 3], yar[(perm[1] + 1) % 3], yar[(perm[2] + 1) % 3]],
            [yar[(perm[0] + 2) % 3], yar[(perm[1] + 2) % 3], yar[(perm[2] + 2) % 3]],
        ]
        det3 = mat3_det(M3)
        if math.gcd(det3, 26) != 1:
            continue
        M3_inv = mat3_inv(M3)
        if M3_inv is None:
            continue

        pt = hill3_decrypt(CT_NUM, M3_inv)
        score = score_cribs(pt[:CT_LEN])
        if score >= 6:
            print(f"  YAR 3×3 M={M3}: score={score}/{N_CRIBS}")
            results.append((score, f"YAR Hill3", M3, False))

    # ── Summary ──────────────────────────────────────────────────────────────

    print("\n" + "=" * 80)
    print("SUMMARY: Top Hill Cipher Results")
    print("=" * 80)

    results.sort(key=lambda x: -x[0])
    for score, tag, M, bean in results[:15]:
        bean_str = "BEAN✓" if bean else "bean✗"
        print(f"  {score}/{N_CRIBS} {bean_str} | {tag}")

    best = results[0] if results else (0, "none", None, False)
    print(f"\nBest: {best[0]}/{N_CRIBS}")
    if best[0] >= 17:
        print("SUCCESS: Hill cipher shows strong signal")
    elif best[0] >= 10:
        print("INTERESTING: Above noise, investigate further")
    else:
        print("FAILURE: Pure Hill cipher / Vig+Hill at noise floor")

    print("\n[E-04 COMPLETE]")
    return best[0]


if __name__ == "__main__":
    main()
