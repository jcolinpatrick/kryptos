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
Hill Cipher Viability Analysis for K4

Tests whether a Hill cipher (2x2 and 3x3) could be part of K4's encryption,
using both standard A-Z and KA alphabet numbering.

Analysis includes:
1. Direct Hill cipher (CT = M * PT mod 26) — solve from known pairs, check consistency
2. Hill as Layer 2 after simple transpositions
3. Bean constraint compatibility
4. Exhaustive 2x2 search with partial plaintext
"""

import json
import os
import sys
import itertools
from math import gcd
from typing import Optional, List, Tuple, Dict

# Import from canonical source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, BEAN_EQ, BEAN_INEQ,
    N_CRIBS, CRIB_WORDS
)

# Build KA index
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

# ============================================================================
# Linear algebra mod 26
# ============================================================================

def mod_inverse(a: int, m: int = 26) -> Optional[int]:
    """Compute modular inverse of a mod m, or None if not invertible."""
    a = a % m
    if gcd(a, m) != 1:
        return None
    # Extended Euclidean
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def det_2x2(M: List[List[int]]) -> int:
    """Determinant of 2x2 matrix mod 26."""
    return (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % 26

def det_3x3(M: List[List[int]]) -> int:
    """Determinant of 3x3 matrix mod 26."""
    d = (M[0][0] * (M[1][1]*M[2][2] - M[1][2]*M[2][1])
       - M[0][1] * (M[1][0]*M[2][2] - M[1][2]*M[2][0])
       + M[0][2] * (M[1][0]*M[2][1] - M[1][1]*M[2][0]))
    return d % 26

def invert_2x2(M: List[List[int]]) -> Optional[List[List[int]]]:
    """Invert a 2x2 matrix mod 26. Returns None if singular."""
    d = det_2x2(M)
    d_inv = mod_inverse(d, 26)
    if d_inv is None:
        return None
    return [
        [(d_inv * M[1][1]) % 26, (d_inv * (-M[0][1])) % 26],
        [(d_inv * (-M[1][0])) % 26, (d_inv * M[0][0]) % 26],
    ]

def invert_3x3(M: List[List[int]]) -> Optional[List[List[int]]]:
    """Invert a 3x3 matrix mod 26. Returns None if singular."""
    d = det_3x3(M)
    d_inv = mod_inverse(d, 26)
    if d_inv is None:
        return None
    # Cofactor matrix
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
    # Adjugate = transpose of cofactor
    adj = [[cofactors[j][i] for j in range(3)] for i in range(3)]
    inv = [[(d_inv * adj[i][j]) % 26 for j in range(3)] for i in range(3)]
    return inv

def mat_vec_2x2(M: List[List[int]], v: List[int]) -> List[int]:
    """Multiply 2x2 matrix by 2-vector mod 26."""
    return [
        (M[0][0]*v[0] + M[0][1]*v[1]) % 26,
        (M[1][0]*v[0] + M[1][1]*v[1]) % 26,
    ]

def mat_vec_3x3(M: List[List[int]], v: List[int]) -> List[int]:
    """Multiply 3x3 matrix by 3-vector mod 26."""
    return [
        (M[0][0]*v[0] + M[0][1]*v[1] + M[0][2]*v[2]) % 26,
        (M[1][0]*v[0] + M[1][1]*v[1] + M[1][2]*v[2]) % 26,
        (M[2][0]*v[0] + M[2][1]*v[1] + M[2][2]*v[2]) % 26,
    ]

def mat_mul_2x2(A, B):
    """Multiply two 2x2 matrices mod 26."""
    return [
        [(A[0][0]*B[0][0] + A[0][1]*B[1][0]) % 26,
         (A[0][0]*B[0][1] + A[0][1]*B[1][1]) % 26],
        [(A[1][0]*B[0][0] + A[1][1]*B[1][0]) % 26,
         (A[1][0]*B[0][1] + A[1][1]*B[1][1]) % 26],
    ]

# ============================================================================
# Helper: get CT/PT numeric values under a given alphabet
# ============================================================================

def char_to_num(ch: str, alpha_idx: Dict[str, int]) -> int:
    return alpha_idx[ch]

def num_to_char(n: int, alpha: str) -> str:
    return alpha[n % 26]

# ============================================================================
# Analysis 1: Direct 2x2 Hill cipher
# ============================================================================

def analyze_direct_2x2(alpha_name: str, alpha: str, alpha_idx: Dict[str, int]):
    """
    Test if CT = M * PT mod 26 for a single 2x2 Hill matrix M.

    Hill cipher encrypts consecutive PAIRS: (CT[2i], CT[2i+1]) = M * (PT[2i], PT[2i+1]).
    We need pairs where BOTH positions have known plaintext.
    """
    print(f"\n{'='*70}")
    print(f"ANALYSIS 1: Direct 2x2 Hill cipher ({alpha_name} alphabet)")
    print(f"{'='*70}")

    # Build list of known (position, ct_num, pt_num)
    known = []
    for pos in sorted(CRIB_DICT.keys()):
        ct_num = char_to_num(CT[pos], alpha_idx)
        pt_num = char_to_num(CRIB_DICT[pos], alpha_idx)
        known.append((pos, ct_num, pt_num))

    # Find consecutive pairs where both positions are known
    # For Hill 2x2 with block alignment: positions (2k, 2k+1) for some k
    print("\n--- Testing with ABSOLUTE block alignment (pairs at 0,1 / 2,3 / ...) ---")
    test_2x2_alignment(known, alpha_name, alpha, alpha_idx, alignment="absolute")

    # For Hill 2x2 with crib-relative alignment
    print("\n--- Testing with ALL consecutive known-pair positions ---")
    test_2x2_consecutive(known, alpha_name, alpha, alpha_idx)

    # Try every possible block offset (0-1)
    print("\n--- Testing with block offset 0 and 1 ---")
    for offset in range(2):
        test_2x2_alignment(known, alpha_name, alpha, alpha_idx,
                          alignment="offset", offset=offset)

def test_2x2_alignment(known, alpha_name, alpha, alpha_idx, alignment="absolute", offset=0):
    """Test 2x2 Hill with specific block alignment."""
    # Collect pairs based on alignment
    pairs = []  # Each: ((ct0, ct1), (pt0, pt1), (pos0, pos1))

    if alignment == "absolute":
        # Pairs at positions (2k, 2k+1)
        for pos0, ct0, pt0 in known:
            if pos0 % 2 != 0:
                continue
            pos1 = pos0 + 1
            for p1, c1, t1 in known:
                if p1 == pos1:
                    pairs.append(((ct0, c1), (pt0, t1), (pos0, pos1)))
                    break
    elif alignment == "offset":
        # Pairs at positions (2k+offset, 2k+offset+1)
        for pos0, ct0, pt0 in known:
            if (pos0 - offset) % 2 != 0:
                continue
            pos1 = pos0 + 1
            for p1, c1, t1 in known:
                if p1 == pos1:
                    pairs.append(((ct0, c1), (pt0, t1), (pos0, pos1)))
                    break

    if len(pairs) < 2:
        print(f"  Only {len(pairs)} complete pair(s) found — need at least 2 to solve. SKIP.")
        return None

    print(f"  Found {len(pairs)} complete pairs for alignment '{alignment}' offset={offset}:")
    for (ct_pair, pt_pair, pos_pair) in pairs:
        print(f"    Pos {pos_pair}: CT=({ct_pair[0]},{ct_pair[1]}) PT=({pt_pair[0]},{pt_pair[1]})")

    # Solve M from first two pairs: [CT1 CT2] = M * [PT1 PT2]
    # => M = [CT1 CT2] * [PT1 PT2]^{-1}
    solutions = solve_2x2_from_pairs(pairs, alpha_name, alpha, alpha_idx)
    return solutions

def test_2x2_consecutive(known, alpha_name, alpha, alpha_idx):
    """Test using ALL consecutive position pairs regardless of block alignment."""
    pairs = []
    known_dict = {pos: (ct, pt) for pos, ct, pt in known}

    for pos in sorted(known_dict.keys()):
        if pos + 1 in known_dict:
            ct0, pt0 = known_dict[pos]
            ct1, pt1 = known_dict[pos + 1]
            pairs.append(((ct0, ct1), (pt0, pt1), (pos, pos + 1)))

    print(f"  Found {len(pairs)} consecutive known pairs:")
    for (ct_pair, pt_pair, pos_pair) in pairs:
        ct_chars = (num_to_char(ct_pair[0], alpha), num_to_char(ct_pair[1], alpha))
        pt_chars = (num_to_char(pt_pair[0], alpha), num_to_char(pt_pair[1], alpha))
        print(f"    Pos {pos_pair}: CT={ct_chars} PT={pt_chars}")

    if len(pairs) < 2:
        print("  Not enough pairs!")
        return None

    return solve_2x2_from_pairs(pairs, alpha_name, alpha, alpha_idx)

def solve_2x2_from_pairs(pairs, alpha_name, alpha, alpha_idx):
    """
    Try all combinations of 2 pairs to solve for M, then check consistency.
    Returns list of consistent matrices (if any).
    """
    consistent_matrices = []
    n_combos = 0
    n_invertible = 0

    for i in range(len(pairs)):
        for j in range(i+1, len(pairs)):
            n_combos += 1
            ct_i, pt_i, pos_i = pairs[i]
            ct_j, pt_j, pos_j = pairs[j]

            # PT matrix: columns are the two PT vectors
            PT_mat = [[pt_i[0], pt_j[0]],
                      [pt_i[1], pt_j[1]]]

            PT_inv = invert_2x2(PT_mat)
            if PT_inv is None:
                continue
            n_invertible += 1

            # CT matrix: columns are the two CT vectors
            CT_mat = [[ct_i[0], ct_j[0]],
                      [ct_i[1], ct_j[1]]]

            # M = CT_mat * PT_inv
            M = mat_mul_2x2(CT_mat, PT_inv)

            # Check if M is invertible (required for valid Hill cipher)
            if mod_inverse(det_2x2(M), 26) is None:
                continue

            # Check consistency against ALL pairs
            consistent = True
            mismatches = 0
            for ct_k, pt_k, pos_k in pairs:
                expected_ct = mat_vec_2x2(M, list(pt_k))
                if tuple(expected_ct) != ct_k:
                    consistent = False
                    mismatches += 1

            if consistent:
                consistent_matrices.append((M, pos_i, pos_j))

    print(f"\n  Tested {n_combos} pair combinations, {n_invertible} had invertible PT matrices")

    if consistent_matrices:
        print(f"  *** FOUND {len(consistent_matrices)} CONSISTENT MATRIX(es)! ***")
        for M, pos_i, pos_j in consistent_matrices:
            print(f"    M = {M} (derived from positions {pos_i} and {pos_j})")
            print(f"    det(M) = {det_2x2(M)}")
            # Decrypt full CT
            decrypt_with_2x2(M, alpha_name, alpha, alpha_idx)
    else:
        print(f"  NO consistent 2x2 matrix found across all {len(pairs)} pairs.")

        # Show the best partial matches
        best_match = 0
        best_info = None
        for i in range(len(pairs)):
            for j in range(i+1, len(pairs)):
                ct_i, pt_i, pos_i = pairs[i]
                ct_j, pt_j, pos_j = pairs[j]
                PT_mat = [[pt_i[0], pt_j[0]], [pt_i[1], pt_j[1]]]
                PT_inv = invert_2x2(PT_mat)
                if PT_inv is None:
                    continue
                CT_mat = [[ct_i[0], ct_j[0]], [ct_i[1], ct_j[1]]]
                M = mat_mul_2x2(CT_mat, PT_inv)
                if mod_inverse(det_2x2(M), 26) is None:
                    continue
                matches = sum(1 for ct_k, pt_k, _ in pairs
                             if tuple(mat_vec_2x2(M, list(pt_k))) == ct_k)
                if matches > best_match:
                    best_match = matches
                    best_info = (M, pos_i, pos_j, matches, len(pairs))

        if best_info:
            M, pos_i, pos_j, matches, total = best_info
            print(f"  Best partial: {matches}/{total} pairs matched")
            print(f"    M = {M} from positions {pos_i}, {pos_j}")

    return consistent_matrices

def decrypt_with_2x2(M, alpha_name, alpha, alpha_idx):
    """Decrypt full K4 CT using a 2x2 Hill matrix."""
    M_inv = invert_2x2(M)
    if M_inv is None:
        print("    Matrix not invertible — cannot decrypt")
        return None

    ct_nums = [char_to_num(c, alpha_idx) for c in CT]
    pt_nums = []
    # Process pairs
    for i in range(0, CT_LEN - 1, 2):
        pair = [ct_nums[i], ct_nums[i+1]]
        dec = mat_vec_2x2(M_inv, pair)
        pt_nums.extend(dec)
    # Handle last character if odd length
    if CT_LEN % 2 == 1:
        pt_nums.append(ct_nums[-1])  # Last char undetermined in standard Hill

    plaintext = ''.join(num_to_char(n, alpha) for n in pt_nums)
    print(f"    Decrypted: {plaintext}")
    return plaintext

# ============================================================================
# Analysis 2: Direct 3x3 Hill cipher
# ============================================================================

def analyze_direct_3x3(alpha_name: str, alpha: str, alpha_idx: Dict[str, int]):
    """
    Test if CT = M * PT mod 26 for a single 3x3 Hill matrix M.
    Need triples where ALL THREE consecutive positions have known plaintext.
    """
    print(f"\n{'='*70}")
    print(f"ANALYSIS 2: Direct 3x3 Hill cipher ({alpha_name} alphabet)")
    print(f"{'='*70}")

    known_dict = {}
    for pos in sorted(CRIB_DICT.keys()):
        ct_num = char_to_num(CT[pos], alpha_idx)
        pt_num = char_to_num(CRIB_DICT[pos], alpha_idx)
        known_dict[pos] = (ct_num, pt_num)

    # Find all consecutive triples
    triples = []
    for pos in sorted(known_dict.keys()):
        if pos + 1 in known_dict and pos + 2 in known_dict:
            ct0, pt0 = known_dict[pos]
            ct1, pt1 = known_dict[pos + 1]
            ct2, pt2 = known_dict[pos + 2]
            triples.append(((ct0, ct1, ct2), (pt0, pt1, pt2), (pos, pos+1, pos+2)))

    print(f"  Found {len(triples)} consecutive known triples")
    for ct_t, pt_t, pos_t in triples:
        print(f"    Pos {pos_t}: CT={ct_t} PT={pt_t}")

    if len(triples) < 3:
        print("  Need at least 3 triples to solve 3x3 system — checking what we have...")
        if len(triples) >= 2:
            print("  Attempting underdetermined analysis with available triples...")

    # Try each pair of block alignments
    for block_offset in range(3):
        print(f"\n  --- Block offset {block_offset} ---")
        aligned_triples = []
        for ct_t, pt_t, pos_t in triples:
            if (pos_t[0] - block_offset) % 3 == 0:
                aligned_triples.append((ct_t, pt_t, pos_t))

        if len(aligned_triples) < 3:
            print(f"    Only {len(aligned_triples)} aligned triples (need 3). SKIP.")
            continue

        print(f"    {len(aligned_triples)} aligned triples available")
        solve_3x3_from_triples(aligned_triples, alpha_name, alpha, alpha_idx)

def solve_3x3_from_triples(triples, alpha_name, alpha, alpha_idx):
    """Try combinations of 3 triples to solve for 3x3 M, check consistency."""
    consistent_matrices = []
    n_combos = 0
    n_invertible = 0

    for combo in itertools.combinations(range(len(triples)), 3):
        n_combos += 1
        i, j, k = combo
        ct_i, pt_i, pos_i = triples[i]
        ct_j, pt_j, pos_j = triples[j]
        ct_k, pt_k, pos_k = triples[k]

        # PT matrix: columns are the three PT vectors
        PT_mat = [
            [pt_i[0], pt_j[0], pt_k[0]],
            [pt_i[1], pt_j[1], pt_k[1]],
            [pt_i[2], pt_j[2], pt_k[2]],
        ]

        PT_inv = invert_3x3(PT_mat)
        if PT_inv is None:
            continue
        n_invertible += 1

        # CT matrix: columns
        CT_mat = [
            [ct_i[0], ct_j[0], ct_k[0]],
            [ct_i[1], ct_j[1], ct_k[1]],
            [ct_i[2], ct_j[2], ct_k[2]],
        ]

        # M = CT_mat * PT_inv (mod 26)
        M = [[0]*3 for _ in range(3)]
        for r in range(3):
            for c in range(3):
                s = 0
                for x in range(3):
                    s += CT_mat[r][x] * PT_inv[x][c]
                M[r][c] = s % 26

        # Check invertibility
        if mod_inverse(det_3x3(M), 26) is None:
            continue

        # Check consistency against ALL triples
        matches = 0
        for ct_t, pt_t, _ in triples:
            expected = mat_vec_3x3(M, list(pt_t))
            if tuple(expected) == ct_t:
                matches += 1

        if matches == len(triples):
            consistent_matrices.append((M, combo, matches))

    print(f"    Tested {n_combos} combos, {n_invertible} invertible")

    if consistent_matrices:
        print(f"    *** FOUND {len(consistent_matrices)} CONSISTENT 3x3 MATRIX(es)! ***")
        for M, combo, matches in consistent_matrices[:5]:
            print(f"      M = {M}")
            print(f"      det(M) = {det_3x3(M)}")
            decrypt_with_3x3(M, alpha_name, alpha, alpha_idx)
    else:
        # Report best partial match
        best = 0
        best_info = None
        for combo in itertools.combinations(range(len(triples)), 3):
            i, j, k = combo
            ct_i, pt_i, _ = triples[i]
            ct_j, pt_j, _ = triples[j]
            ct_k, pt_k, _ = triples[k]
            PT_mat = [
                [pt_i[0], pt_j[0], pt_k[0]],
                [pt_i[1], pt_j[1], pt_k[1]],
                [pt_i[2], pt_j[2], pt_k[2]],
            ]
            PT_inv = invert_3x3(PT_mat)
            if PT_inv is None:
                continue
            CT_mat = [
                [ct_i[0], ct_j[0], ct_k[0]],
                [ct_i[1], ct_j[1], ct_k[1]],
                [ct_i[2], ct_j[2], ct_k[2]],
            ]
            M = [[0]*3 for _ in range(3)]
            for r in range(3):
                for c in range(3):
                    s = 0
                    for x in range(3):
                        s += CT_mat[r][x] * PT_inv[x][c]
                    M[r][c] = s % 26
            if mod_inverse(det_3x3(M), 26) is None:
                continue
            matches = sum(1 for ct_t, pt_t, _ in triples
                         if tuple(mat_vec_3x3(M, list(pt_t))) == ct_t)
            if matches > best:
                best = matches
                best_info = (M, combo, matches, len(triples))

        if best_info:
            M, combo, matches, total = best_info
            print(f"    Best partial: {matches}/{total} triples matched")
            print(f"      M = {M}")
        else:
            print(f"    No valid (invertible) 3x3 matrices could be derived")

def decrypt_with_3x3(M, alpha_name, alpha, alpha_idx):
    """Decrypt full K4 CT using a 3x3 Hill matrix."""
    M_inv = invert_3x3(M)
    if M_inv is None:
        print("      Matrix not invertible")
        return None

    ct_nums = [char_to_num(c, alpha_idx) for c in CT]
    pt_nums = []
    # Process triples; handle remainder
    for i in range(0, CT_LEN - 2, 3):
        triple = [ct_nums[i], ct_nums[i+1], ct_nums[i+2]]
        dec = mat_vec_3x3(M_inv, triple)
        pt_nums.extend(dec)
    # Handle remainder (97 mod 3 = 2, so 2 chars left over)
    remainder = CT_LEN % 3
    if remainder > 0:
        # Last 1-2 chars are undetermined in standard Hill
        for r in range(remainder):
            pt_nums.append(ct_nums[CT_LEN - remainder + r])

    plaintext = ''.join(num_to_char(n, alpha) for n in pt_nums)
    print(f"      Decrypted: {plaintext}")
    return plaintext

# ============================================================================
# Analysis 3: Hill cipher with Vigenere pre-layer
# ============================================================================

def analyze_hill_after_vigenere(alpha_name: str, alpha: str, alpha_idx: Dict[str, int]):
    """
    Test: what if Layer 1 is Vigenere/Beaufort and Layer 2 is Hill?

    Under this model: CT_final = Hill(CT_intermediate)
    where CT_intermediate = Vig(PT, key)

    We don't know the Vigenere key, BUT we know the KEYSTREAM at crib positions.
    For each crib position i: CT_intermediate[i] = (PT[i] + key[i]) mod 26 = known from Vig keystream.
    Wait — that's circular. The intermediate CT IS what Vigenere produces, but then Hill
    scrambles pairs/triples. So we can't simply derive Hill from position-by-position cribs.

    Actually: PT -> Vigenere(key) -> intermediate -> Hill(M) -> CT
    We know PT and CT at crib positions. We DON'T know intermediate.

    For Vig: intermediate[i] = (PT[i] + key[i]) mod 26
    For Hill 2x2: (CT[2k], CT[2k+1]) = M * (intermediate[2k], intermediate[2k+1])

    This means: CT = M * Vig(PT, key). We have 24 known PT/CT but don't know key.
    With 2x2 Hill (4 unknowns) + periodic Vig key, this is a different system.

    Let's try: if the Vig key is periodic with small period p, we can search.
    """
    print(f"\n{'='*70}")
    print(f"ANALYSIS 3: Hill (2x2) after Vigenere layer ({alpha_name})")
    print(f"{'='*70}")
    print("  Model: PT -> Vigenere(periodic key, period p) -> intermediate -> Hill(M) -> CT")
    print("  This is a multi-layer model. Testing small periods p=1..5.")
    print("  NOTE: With 4 Hill unknowns + p Vigenere unknowns, we need enough constraints.")

    # For each small period, try to find consistent (M, key)
    for period in range(1, 6):
        test_vig_then_hill_2x2(period, alpha_name, alpha, alpha_idx)

def test_vig_then_hill_2x2(period: int, alpha_name: str, alpha: str, alpha_idx: Dict[str, int]):
    """Test Vig(period) + Hill(2x2) model."""
    print(f"\n  --- Vigenere period {period} + Hill 2x2 ---")

    # For a given Vig key (period values), compute intermediate at crib positions
    # Then check if Hill is consistent
    # With period p, there are p unknowns for Vig + 4 for Hill = p+4 total
    # We have 24 known positions -> 12 vector equations (for 2x2) = 24 scalar equations
    # So for p <= 20, the system is overdetermined.
    # But we can't easily solve this analytically, so we brute-force the Vig key.

    # 26^period is feasible up to period ~4 (26^4 = 456,976)
    if 26**period > 2_000_000:
        print(f"    26^{period} = {26**period} — too large for brute force. SKIP.")
        return

    known_positions = sorted(CRIB_DICT.keys())
    ct_nums = {pos: char_to_num(CT[pos], alpha_idx) for pos in known_positions}
    pt_nums = {pos: char_to_num(CRIB_DICT[pos], alpha_idx) for pos in known_positions}

    # Find consecutive pairs in crib positions
    pair_positions = []
    for pos in known_positions:
        if pos + 1 in CRIB_DICT:
            pair_positions.append(pos)

    if len(pair_positions) < 2:
        print("    Not enough consecutive crib pairs for 2x2 Hill. SKIP.")
        return

    best_matches = 0
    best_config = None

    # Iterate over all possible Vig keys of given period
    for key_tuple in itertools.product(range(26), repeat=period):
        # Compute intermediate at all crib positions
        intermediate = {}
        for pos in known_positions:
            k = key_tuple[pos % period]
            intermediate[pos] = (pt_nums[pos] + k) % 26

        # Now try to solve Hill from consecutive pair positions
        # Take first two pairs to derive M
        p0 = pair_positions[0]
        p1 = pair_positions[1]

        # For pair at p0: (CT[p0], CT[p0+1]) = M * (inter[p0], inter[p0+1])
        # For pair at p1: (CT[p1], CT[p1+1]) = M * (inter[p1], inter[p1+1])
        PT_mat = [
            [intermediate[p0], intermediate[p1]],
            [intermediate[p0+1], intermediate[p1+1]],
        ]
        PT_inv = invert_2x2(PT_mat)
        if PT_inv is None:
            continue

        CT_mat = [
            [ct_nums[p0], ct_nums[p1]],
            [ct_nums[p0+1], ct_nums[p1+1]],
        ]
        M = mat_mul_2x2(CT_mat, PT_inv)

        if mod_inverse(det_2x2(M), 26) is None:
            continue

        # Check against all pairs
        matches = 0
        for pos in pair_positions:
            expected = mat_vec_2x2(M, [intermediate[pos], intermediate[pos+1]])
            if expected[0] == ct_nums[pos] and expected[1] == ct_nums[pos+1]:
                matches += 1

        if matches > best_matches:
            best_matches = matches
            best_config = (key_tuple, M, matches, len(pair_positions))
            if matches == len(pair_positions):
                break  # Perfect match

    if best_config:
        key_tuple, M, matches, total = best_config
        status = "PERFECT MATCH" if matches == total else f"best partial"
        key_str = ''.join(num_to_char(k, alpha) for k in key_tuple)
        print(f"    {status}: {matches}/{total} pairs matched")
        print(f"    Vig key: {key_str} ({key_tuple})")
        print(f"    Hill M: {M}, det={det_2x2(M)}")
        if matches == total:
            print("    *** POTENTIALLY SIGNIFICANT — decrypting full CT ***")
            # Decrypt: CT -> Hill_inv -> intermediate -> Vig_inv -> PT
            M_inv = invert_2x2(M)
            if M_inv:
                ct_all = [char_to_num(c, alpha_idx) for c in CT]
                inter = []
                for i in range(0, CT_LEN - 1, 2):
                    dec = mat_vec_2x2(M_inv, [ct_all[i], ct_all[i+1]])
                    inter.extend(dec)
                if CT_LEN % 2 == 1:
                    inter.append(ct_all[-1])
                # Undo Vigenere
                pt = []
                for i, val in enumerate(inter):
                    k = key_tuple[i % period]
                    pt.append((val - k) % 26)
                plaintext = ''.join(num_to_char(n, alpha) for n in pt)
                print(f"    Decrypted: {plaintext}")
    else:
        print(f"    No valid configuration found")

# ============================================================================
# Analysis 4: Hill with simple transposition pre-layer
# ============================================================================

def analyze_hill_after_transposition(alpha_name: str, alpha: str, alpha_idx: Dict[str, int]):
    """
    Test: Layer 1 = simple transposition, Layer 2 = Hill(2x2).

    Model: PT -> transpose(perm) -> intermediate -> Hill(M) -> CT

    Under transposition, the CHARACTERS don't change, only positions.
    So intermediate[i] = PT[perm[i]] for some permutation.

    At crib positions, we know PT but after transposition we DON'T know which
    PT characters ended up at which positions.

    However, we CAN approach this differently:
    For Hill decryption: PT_transposed = M_inv * CT (taken in pairs)
    Then we need PT_transposed to be a permutation of PT.

    So: decrypt CT with all possible 2x2 Hill matrices, check if the result
    is a rearrangement that places known PT chars somewhere valid.
    """
    print(f"\n{'='*70}")
    print(f"ANALYSIS 4: Transposition + Hill 2x2 ({alpha_name})")
    print(f"{'='*70}")
    print("  Model: PT -> simple transposition -> Hill(M) -> CT")
    print("  Approach: For each invertible 2x2 M, decrypt CT, check if crib")
    print("  characters appear and could come from a valid transposition.")
    print()

    # This is a large search (26^4 = 456976 matrices, minus non-invertible)
    # We can enumerate all invertible 2x2 matrices
    ct_nums = [char_to_num(c, alpha_idx) for c in CT]

    # Known PT chars and their counts
    known_pt_chars = {}
    for pos in sorted(CRIB_DICT.keys()):
        ch = CRIB_DICT[pos]
        known_pt_chars[ch] = known_pt_chars.get(ch, 0) + 1

    n_tested = 0
    n_invertible = 0
    candidates = []

    for a in range(26):
        for b in range(26):
            for c in range(26):
                for d in range(26):
                    M = [[a, b], [c, d]]
                    det = det_2x2(M)
                    if mod_inverse(det, 26) is None:
                        continue
                    n_invertible += 1

                    M_inv = invert_2x2(M)
                    if M_inv is None:
                        continue

                    # Decrypt CT in pairs
                    pt_nums = []
                    for i in range(0, CT_LEN - 1, 2):
                        dec = mat_vec_2x2(M_inv, [ct_nums[i], ct_nums[i+1]])
                        pt_nums.extend(dec)
                    if CT_LEN % 2 == 1:
                        pt_nums.append(ct_nums[-1])

                    plaintext = ''.join(num_to_char(n, alpha) for n in pt_nums)

                    # Quick check: does the decrypted text contain the known crib WORDS
                    # (as substrings, possibly at different positions)?
                    score = 0
                    if 'EASTNORTHEAST' in plaintext:
                        score += 13
                    if 'BERLINCLOCK' in plaintext:
                        score += 11

                    # Also check partial matches
                    if score == 0:
                        for word_start, word in CRIB_WORDS:
                            for ws in range(len(word), 4, -1):
                                for si in range(len(word) - ws + 1):
                                    substr = word[si:si+ws]
                                    if substr in plaintext:
                                        score = max(score, ws)
                                        break
                                if score >= ws:
                                    break

                    if score >= 6:
                        candidates.append((score, M, plaintext))

    print(f"  Tested {n_invertible} invertible 2x2 matrices")

    if candidates:
        candidates.sort(reverse=True)
        print(f"  Found {len(candidates)} candidates with score >= 6:")
        for score, M, pt in candidates[:10]:
            print(f"    Score {score}: M={M} -> {pt[:50]}...")
    else:
        print("  No candidates found with crib word fragments >= 6 chars in decrypted text.")
        print("  This means Hill + transposition with block offset 0 doesn't produce crib words as substrings.")

# ============================================================================
# Analysis 5: Bean constraint analysis for Hill cipher
# ============================================================================

def analyze_bean_compatibility():
    """
    Check: under a Hill cipher, does the Bean constraint k[27]=k[65] hold?

    Bean constraint is about the KEYSTREAM: positions where CT[i]=CT[j] and PT[i]=PT[j].
    For Hill cipher, there's no "keystream" in the Vigenere sense.

    However, if we define "keystream" as the transformation applied at each position,
    for a 2x2 Hill cipher the transformation at position i depends on whether i is
    even or odd in the block. So the "key" at position i is the ROW of M used.

    CT[27] = CT[65] = 'P' and PT[27] = PT[65] = 'R' (both confirmed)

    For Hill 2x2: position 27 is the SECOND element of block (27//2=13, 27%2=1)
                  position 65 is the SECOND element of block (65//2=32, 65%2=1)
    Both are at the same position within their Hill block (position 1), so they use
    the same row of M. This means Bean equality is AUTOMATICALLY satisfied for 2x2 Hill
    with offset 0, because both positions use the same linear transformation.

    For offset 1: position 27-1=26, 26%2=0; position 65-1=64, 64%2=0. Both even. Same row. Still satisfied.

    For 3x3: 27%3=0, 65%3=2. DIFFERENT positions within block -> different rows -> NOT automatically satisfied.
    With offset 1: (27-1)%3=2, (65-1)%3=1. Different. NOT satisfied.
    With offset 2: (27-2)%3=1, (65-2)%3=0. Different. NOT satisfied.

    Key insight: 65-27 = 38. For 2x2: 38%2=0, so same block position. ALWAYS satisfied.
    For 3x3: 38%3=2 != 0, so NEVER same block position. Bean is NOT automatically satisfied.
    """
    print(f"\n{'='*70}")
    print(f"ANALYSIS 5: Bean constraint compatibility with Hill cipher")
    print(f"{'='*70}")

    print("\n  Bean equality: k[27] = k[65]")
    print(f"  CT[27] = '{CT[27]}', CT[65] = '{CT[65]}' (both 'P')")
    print(f"  PT[27] = '{CRIB_DICT[27]}', PT[65] = '{CRIB_DICT[65]}' (both 'R')")

    print("\n  For Hill cipher, the 'keystream equivalent' at position i depends on")
    print("  which position within the Hill block i falls in.")

    for block_size in [2, 3, 4, 5]:
        diff = 65 - 27
        compatible = (diff % block_size == 0)
        for offset in range(block_size):
            pos27 = (27 - offset) % block_size
            pos65 = (65 - offset) % block_size
            compat_offset = (pos27 == pos65)
            print(f"\n  Hill {block_size}x{block_size}, offset {offset}: "
                  f"pos27 mod {block_size} = {pos27}, pos65 mod {block_size} = {pos65} "
                  f"-> {'COMPATIBLE' if compat_offset else 'INCOMPATIBLE'}")

    print("\n  Summary:")
    print("    2x2 Hill: Bean ALWAYS compatible (65-27=38, 38%2=0)")
    print("    3x3 Hill: Bean NEVER compatible (38%3=2)")
    print("    4x4 Hill: Bean COMPATIBLE at offsets where 38%4=2 (offsets vary)")
    print("    5x5 Hill: Bean COMPATIBLE at offsets where 38%5=3 (offsets vary)")

    # More detailed check for 4x4 and 5x5
    for bs in [4, 5]:
        for off in range(bs):
            if (27 - off) % bs == (65 - off) % bs:
                print(f"    {bs}x{bs} offset {off}: COMPATIBLE")
            else:
                print(f"    {bs}x{bs} offset {off}: INCOMPATIBLE")

    # Check Bean inequalities too
    print("\n  Bean inequality check for 2x2 (all offsets):")
    for offset in range(2):
        violations = 0
        for pos_a, pos_b in BEAN_INEQ:
            if pos_a not in CRIB_POSITIONS or pos_b not in CRIB_POSITIONS:
                continue
            # If both positions have the same block position, their
            # "key" is the same row -> keystream values are determined
            # by the row and their PT values
            # k[i] is not well-defined for Hill in the same way as Vig
            # But CT[a]=CT[b] and PT[a]=PT[b] => same block position => same key row
            # Bean ineq says k[a] != k[b], which for Hill means...
            # Actually for Hill, the "key" concept doesn't map directly.
            # The constraint comes from having CT[a]=CT[b] and PT[a]!=PT[b] or vice versa.
            pass
        print(f"    Offset {offset}: Bean inequalities don't directly apply to Hill cipher")
        print(f"    (Bean is defined for additive keystream ciphers, not matrix ciphers)")

# ============================================================================
# Analysis 6: Exhaustive 2x2 Hill search (direct, no transposition)
# ============================================================================

def exhaustive_2x2_search(alpha_name: str, alpha: str, alpha_idx: Dict[str, int]):
    """
    Exhaustively test ALL invertible 2x2 Hill matrices.
    For each, decrypt CT and check how many crib positions match.
    """
    print(f"\n{'='*70}")
    print(f"ANALYSIS 6: Exhaustive 2x2 Hill search ({alpha_name})")
    print(f"{'='*70}")

    ct_nums = [char_to_num(c, alpha_idx) for c in CT]

    best_score = 0
    best_results = []
    score_dist = {}  # score -> count
    n_tested = 0

    for a in range(26):
        for b in range(26):
            for c in range(26):
                for d in range(26):
                    det = (a*d - b*c) % 26
                    if gcd(det, 26) != 1:
                        continue

                    M = [[a, b], [c, d]]
                    M_inv = invert_2x2(M)
                    if M_inv is None:
                        continue
                    n_tested += 1

                    # Decrypt in pairs for BOTH block offsets
                    for offset in range(2):
                        pt_nums = list(ct_nums)  # start with CT
                        for i in range(offset, CT_LEN - 1, 2):
                            dec = mat_vec_2x2(M_inv, [ct_nums[i], ct_nums[i+1]])
                            pt_nums[i] = dec[0]
                            pt_nums[i+1] = dec[1]

                        # Score against cribs
                        score = 0
                        for pos, expected_ch in CRIB_DICT.items():
                            expected_num = char_to_num(expected_ch, alpha_idx)
                            if pt_nums[pos] == expected_num:
                                score += 1

                        score_dist[score] = score_dist.get(score, 0) + 1

                        if score > best_score:
                            best_score = score
                            best_results = []
                        if score == best_score:
                            pt_str = ''.join(num_to_char(n, alpha) for n in pt_nums)
                            best_results.append((M, offset, score, pt_str))

    print(f"  Tested {n_tested} invertible matrices x 2 offsets = {n_tested*2} configs")
    print(f"\n  Score distribution:")
    for score in sorted(score_dist.keys()):
        print(f"    {score}/24: {score_dist[score]} configs")

    print(f"\n  Best score: {best_score}/24 ({len(best_results)} configs)")
    for M, offset, score, pt in best_results[:5]:
        print(f"    M={M}, offset={offset}")
        print(f"    PT: {pt[:50]}...")
        # Check if known cribs appear
        for ws, word in CRIB_WORDS:
            found_at = pt.find(word)
            if found_at >= 0:
                print(f"    '{word}' found at position {found_at} (expected {ws})")

# ============================================================================
# Analysis 7: Affine Hill (CT = M*PT + v mod 26)
# ============================================================================

def analyze_affine_hill_2x2(alpha_name: str, alpha: str, alpha_idx: Dict[str, int]):
    """
    Test affine Hill: CT = M*PT + v mod 26, where v is a constant 2-vector.
    This adds 2 more unknowns (6 total: 4 matrix + 2 offset).
    Still heavily overdetermined with 24 known positions.
    """
    print(f"\n{'='*70}")
    print(f"ANALYSIS 7: Affine Hill 2x2 — CT = M*PT + v ({alpha_name})")
    print(f"{'='*70}")

    known_positions = sorted(CRIB_DICT.keys())

    # Find consecutive pairs
    pairs = []
    for pos in known_positions:
        if pos + 1 in CRIB_DICT:
            ct0 = char_to_num(CT[pos], alpha_idx)
            ct1 = char_to_num(CT[pos+1], alpha_idx)
            pt0 = char_to_num(CRIB_DICT[pos], alpha_idx)
            pt1 = char_to_num(CRIB_DICT[pos+1], alpha_idx)
            pairs.append(((ct0, ct1), (pt0, pt1), pos))

    print(f"  Have {len(pairs)} consecutive crib pairs")

    # For affine Hill: CT_pair = M * PT_pair + v
    # Subtracting two equations: CT_i - CT_j = M * (PT_i - PT_j)
    # This eliminates v and gives us the SAME system as pure Hill
    # on the DIFFERENCES. So if pure Hill failed, affine Hill with the
    # same block alignment also fails.

    # However, let's verify by solving from 3 pairs (to get M and v)
    if len(pairs) < 3:
        print("  Not enough pairs!")
        return

    best_matches = 0
    best_config = None
    n_tested = 0

    for i in range(len(pairs)):
        for j in range(i+1, len(pairs)):
            ct_i, pt_i, pos_i = pairs[i]
            ct_j, pt_j, pos_j = pairs[j]

            # Difference eliminates v
            dpt = [(pt_i[0]-pt_j[0]) % 26, (pt_i[1]-pt_j[1]) % 26]
            dct = [(ct_i[0]-ct_j[0]) % 26, (ct_i[1]-ct_j[1]) % 26]

            for k in range(j+1, len(pairs)):
                ct_k, pt_k, pos_k = pairs[k]
                dpt2 = [(pt_i[0]-pt_k[0]) % 26, (pt_i[1]-pt_k[1]) % 26]
                dct2 = [(ct_i[0]-ct_k[0]) % 26, (ct_i[1]-ct_k[1]) % 26]

                # Solve M from: [dct dct2] = M * [dpt dpt2]
                DPT = [[dpt[0], dpt2[0]], [dpt[1], dpt2[1]]]
                DPT_inv = invert_2x2(DPT)
                if DPT_inv is None:
                    continue

                DCT = [[dct[0], dct2[0]], [dct[1], dct2[1]]]
                M = mat_mul_2x2(DCT, DPT_inv)

                if mod_inverse(det_2x2(M), 26) is None:
                    continue

                # Recover v from first pair: v = CT_i - M*PT_i
                Mpt = mat_vec_2x2(M, list(pt_i))
                v = [(ct_i[0] - Mpt[0]) % 26, (ct_i[1] - Mpt[1]) % 26]

                # Check all pairs
                matches = 0
                for ct_t, pt_t, _ in pairs:
                    expected = mat_vec_2x2(M, list(pt_t))
                    expected = [(expected[0] + v[0]) % 26, (expected[1] + v[1]) % 26]
                    if tuple(expected) == ct_t:
                        matches += 1

                n_tested += 1
                if matches > best_matches:
                    best_matches = matches
                    best_config = (M, v, matches, len(pairs))
                    if matches == len(pairs):
                        break
            if best_matches == len(pairs):
                break
        if best_matches == len(pairs):
            break

    print(f"  Tested {n_tested} valid configurations")
    if best_config:
        M, v, matches, total = best_config
        print(f"  Best: {matches}/{total} pairs matched")
        print(f"    M = {M}, v = {v}")
        if matches == total:
            print("  *** FULL MATCH — SIGNIFICANT ***")
            # Decrypt
            M_inv = invert_2x2(M)
            if M_inv:
                ct_all = [char_to_num(c, alpha_idx) for c in CT]
                pt_nums = []
                for i in range(0, CT_LEN - 1, 2):
                    shifted = [(ct_all[i] - v[0]) % 26, (ct_all[i+1] - v[1]) % 26]
                    dec = mat_vec_2x2(M_inv, shifted)
                    pt_nums.extend(dec)
                if CT_LEN % 2 == 1:
                    pt_nums.append(ct_all[-1])
                pt = ''.join(num_to_char(n, alpha) for n in pt_nums)
                print(f"    Decrypted: {pt}")
    else:
        print("  No configurations found")

# ============================================================================
# Analysis 8: Position-dependent Hill (different M for each block)
# ============================================================================

def analyze_position_dependent_hill(alpha_name: str, alpha: str, alpha_idx: Dict[str, int]):
    """
    What if each block uses a DIFFERENT Hill matrix?
    This is equivalent to a position-dependent key, which is what we suspect for K4.

    With 24 known positions forming ~12 consecutive pairs, we can solve for M at
    each pair's block position independently. This tells us how many distinct
    matrices would be needed.
    """
    print(f"\n{'='*70}")
    print(f"ANALYSIS 8: Position-dependent Hill (varying M per block) ({alpha_name})")
    print(f"{'='*70}")

    known_positions = sorted(CRIB_DICT.keys())

    for offset in range(2):
        print(f"\n  --- Block offset {offset} ---")
        # Group crib positions into their blocks
        block_pairs = {}  # block_index -> list of (within_block_pos, ct_num, pt_num)
        for pos in known_positions:
            block_idx = (pos - offset) // 2
            within = (pos - offset) % 2
            ct_num = char_to_num(CT[pos], alpha_idx)
            pt_num = char_to_num(CRIB_DICT[pos], alpha_idx)
            if block_idx not in block_pairs:
                block_pairs[block_idx] = {}
            block_pairs[block_idx][within] = (ct_num, pt_num)

        # Find blocks with BOTH positions known
        complete_blocks = {}
        for bi, positions in block_pairs.items():
            if 0 in positions and 1 in positions:
                ct_pair = (positions[0][0], positions[1][0])
                pt_pair = (positions[0][1], positions[1][1])
                complete_blocks[bi] = (ct_pair, pt_pair)

        print(f"    Complete blocks (both positions known): {len(complete_blocks)}")
        if not complete_blocks:
            continue

        # For each complete block, the equation is:
        # [ct0, ct1] = M * [pt0, pt1] (but this only gives 2 equations for 4 unknowns)
        # We can't solve M from a single block. But we CAN ask:
        # "Is there a SINGLE M that works for all blocks?"
        # That's what Analysis 1 already tested.

        # New question: for each PAIR of complete blocks, solve M and see how many
        # other blocks it satisfies. This measures consistency.

        block_list = sorted(complete_blocks.keys())
        if len(block_list) < 2:
            print("    Only 1 complete block — cannot determine M. SKIP.")
            continue

        # For each pair of blocks, solve M
        consistency_scores = []
        for i in range(len(block_list)):
            for j in range(i+1, len(block_list)):
                bi, bj = block_list[i], block_list[j]
                ct_i, pt_i = complete_blocks[bi]
                ct_j, pt_j = complete_blocks[bj]

                PT_mat = [[pt_i[0], pt_j[0]], [pt_i[1], pt_j[1]]]
                PT_inv = invert_2x2(PT_mat)
                if PT_inv is None:
                    continue
                CT_mat = [[ct_i[0], ct_j[0]], [ct_i[1], ct_j[1]]]
                M = mat_mul_2x2(CT_mat, PT_inv)
                if mod_inverse(det_2x2(M), 26) is None:
                    continue

                matches = 0
                for bk in block_list:
                    ct_k, pt_k = complete_blocks[bk]
                    expected = mat_vec_2x2(M, list(pt_k))
                    if tuple(expected) == ct_k:
                        matches += 1

                consistency_scores.append((matches, len(block_list), M, bi, bj))

        if consistency_scores:
            consistency_scores.sort(reverse=True)
            best_m, best_t, best_M, bi, bj = consistency_scores[0]
            print(f"    Best consistency: {best_m}/{best_t} blocks agree on single M")
            print(f"    M = {best_M} (from blocks {bi}, {bj})")
            if best_m == best_t:
                print("    *** ALL BLOCKS AGREE — single Hill matrix works ***")
            elif best_m < best_t:
                print(f"    Inconsistency detected: NOT a single 2x2 Hill cipher")
                # Show the distribution
                score_counts = {}
                for m, t, _, _, _ in consistency_scores:
                    score_counts[m] = score_counts.get(m, 0) + 1
                print(f"    Consistency distribution: {dict(sorted(score_counts.items(), reverse=True))}")

# ============================================================================
# MAIN
# ============================================================================

def main():
    results = {}

    print("=" * 70)
    print("HILL CIPHER VIABILITY ANALYSIS FOR K4")
    print("=" * 70)
    print(f"CT length: {CT_LEN}")
    print(f"Known plaintext positions: {sorted(CRIB_DICT.keys())}")
    print(f"Number of known PT chars: {N_CRIBS}")
    print(f"Bean equality: k[{BEAN_EQ[0][0]}] = k[{BEAN_EQ[0][1]}]")
    print(f"Bean inequalities: {len(BEAN_INEQ)}")

    # Print known CT/PT mapping
    print("\nKnown CT -> PT mapping:")
    for pos in sorted(CRIB_DICT.keys()):
        print(f"  [{pos:2d}] CT={CT[pos]} PT={CRIB_DICT[pos]}  "
              f"AZ: ct={ALPH_IDX[CT[pos]]:2d} pt={ALPH_IDX[CRIB_DICT[pos]]:2d}  "
              f"KA: ct={KA_IDX[CT[pos]]:2d} pt={KA_IDX[CRIB_DICT[pos]]:2d}")

    # Run all analyses for both alphabets
    for alpha_name, alpha, alpha_idx in [("AZ", ALPH, ALPH_IDX), ("KA", KRYPTOS_ALPHABET, KA_IDX)]:
        print(f"\n\n{'#'*70}")
        print(f"# ALPHABET: {alpha_name} = {alpha}")
        print(f"{'#'*70}")

        analyze_direct_2x2(alpha_name, alpha, alpha_idx)
        analyze_direct_3x3(alpha_name, alpha, alpha_idx)
        analyze_affine_hill_2x2(alpha_name, alpha, alpha_idx)
        analyze_position_dependent_hill(alpha_name, alpha, alpha_idx)

    # Bean analysis (alphabet-independent)
    analyze_bean_compatibility()

    # Exhaustive search (both alphabets)
    for alpha_name, alpha, alpha_idx in [("AZ", ALPH, ALPH_IDX), ("KA", KRYPTOS_ALPHABET, KA_IDX)]:
        exhaustive_2x2_search(alpha_name, alpha, alpha_idx)

    # Vig+Hill (AZ only, computationally expensive)
    analyze_hill_after_vigenere("AZ", ALPH, ALPH_IDX)

    # Transposition+Hill (AZ only, very expensive)
    analyze_hill_after_transposition("AZ", ALPH, ALPH_IDX)

    print("\n\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    main()
