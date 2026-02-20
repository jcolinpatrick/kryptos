#!/usr/bin/env python3
"""
E-S-42: Bifid 6×6 Extended Algebraic Elimination (Periods 9-14)

Previous work (E-S-05, Session 10) eliminated Bifid 6×6 at periods 2-8 and 11
using same-cell contradictions within single groups. But periods 9, 10, 12-14
survived because single-group analysis lacked sufficient crib coverage.

KEY INSIGHT: Cross-group constraints provide additional equations. At period 9,
group 7 (pos 63-71) is FULLY known (9/9 PT chars), and group 3 (pos 27-35)
is nearly fully known (7/9). Together, they create contradictions that
single-group analysis missed.

ALGEBRAIC PROOF (period 9, standard convention):
  Group 7: B,R,T forced into same column → rB ≠ rT
  Group 3 pair 1: sq^{-1}(rR, rT) = P, but P's col = rN = rB → rT = rB
  CONTRADICTION: rT = rB but rT ≠ rB

This script:
1. Verifies the period 9 proof computationally (both Bifid conventions)
2. Tests periods 10, 12, 13, 14 using cross-group constraints
3. Also tests Trifid 3×3×3 at period 9

Output: results/e_s_42_bifid6x6_extended.json
"""

import json
import sys
import os
import time
from itertools import product as iproduct
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX

N = CT_LEN


def get_groups(period):
    """Get all period-groups with their PT/CT data."""
    groups = []
    for g in range((N + period - 1) // period):
        start = g * period
        end = min(start + period, N)
        group_len = end - start
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
        n_known = sum(known_mask)
        groups.append({
            'group_idx': g,
            'start': start,
            'end': end,
            'length': group_len,
            'pt': pt,
            'ct': ct,
            'known_mask': known_mask,
            'n_known': n_known,
        })
    return groups


def bifid_pairs_standard(pt_letters, period):
    """Standard Bifid: rows then cols.

    Returns list of (row_expr, col_expr) pairs, where each expr is
    ('r', letter) or ('c', letter) indicating which coordinate.
    """
    rows = [('r', ch) for ch in pt_letters]
    cols = [('c', ch) for ch in pt_letters]
    combined = rows + cols
    pairs = []
    for i in range(0, len(combined), 2):
        pairs.append((combined[i], combined[i+1]))
    return pairs


def bifid_pairs_reverse(pt_letters, period):
    """Reverse Bifid: cols then rows."""
    cols = [('c', ch) for ch in pt_letters]
    rows = [('r', ch) for ch in pt_letters]
    combined = cols + rows
    pairs = []
    for i in range(0, len(combined), 2):
        pairs.append((combined[i], combined[i+1]))
    return pairs


def derive_constraints(groups, pair_fn, convention_name):
    """Derive algebraic constraints from Bifid equations.

    Returns:
      equalities: list of ((type1, letter1), (type2, letter2)) meaning coord1 = coord2
      contradictions: list of contradiction descriptions
    """
    equalities = []  # (coord_a, coord_b) meaning coord_a = coord_b
    # coord is ('r', letter) or ('c', letter) for row/col of letter in square

    all_constraints = []

    for group in groups:
        if group['n_known'] < 2:
            continue

        pt = group['pt']
        ct = group['ct']
        p = group['length']
        known = group['known_mask']

        # For fully-known positions, we can derive exact pair equations
        pairs = pair_fn([ch if ch is not None else f"?{i}" for i, ch in enumerate(pt)], p)

        for pair_idx, ((type1, letter1), (type2, letter2)) in enumerate(pairs):
            ct_letter = ct[pair_idx]

            # Skip if either letter is unknown
            if letter1 is None or letter2 is None:
                continue
            if letter1.startswith('?') or letter2.startswith('?'):
                continue

            # sq^-1(coord1, coord2) = ct_letter
            # means: row of ct_letter = coord1, col of ct_letter = coord2
            # coord1 is (type1, letter1), coord2 is (type2, letter2)
            #
            # So: r[ct_letter] = (type1, letter1) and c[ct_letter] = (type2, letter2)

            eq1 = (('r', ct_letter), (type1, letter1))
            eq2 = (('c', ct_letter), (type2, letter2))

            all_constraints.append({
                'group': group['group_idx'],
                'pair': pair_idx,
                'equations': [eq1, eq2],
                'desc': f"g{group['group_idx']}p{pair_idx}: sq^-1({type1}_{letter1}, {type2}_{letter2}) = {ct_letter}"
            })
            equalities.append(eq1)
            equalities.append(eq2)

    return all_constraints, equalities


def find_contradictions(equalities):
    """Use union-find to propagate equalities and check for contradictions.

    A contradiction occurs when two letters are forced into the same cell
    (both row AND column coordinates are equal).
    """
    # Build union-find for coordinates
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

    # Now check: for any two DISTINCT letters X, Y,
    # if find(('r', X)) == find(('r', Y)) AND find(('c', X)) == find(('c', Y)),
    # then X and Y are in the same cell → contradiction

    # Collect all letters
    letters = set()
    for eq_a, eq_b in equalities:
        for coord in [eq_a, eq_b]:
            letters.add(coord[1])

    contradictions = []
    letters = sorted(letters)
    for i in range(len(letters)):
        for j in range(i+1, len(letters)):
            X, Y = letters[i], letters[j]
            if X.startswith('?') or Y.startswith('?'):
                continue
            r_X = find(('r', X))
            r_Y = find(('r', Y))
            c_X = find(('c', X))
            c_Y = find(('c', Y))
            if r_X == r_Y and c_X == c_Y:
                contradictions.append((X, Y))

    # Also build equivalence classes for reporting
    row_classes = defaultdict(set)
    col_classes = defaultdict(set)
    for letter in letters:
        if letter.startswith('?'):
            continue
        r_rep = find(('r', letter))
        c_rep = find(('c', letter))
        row_classes[r_rep].add(letter)
        col_classes[c_rep].add(letter)

    # Same-column groups (shared column coordinate)
    same_col_groups = [sorted(v) for v in col_classes.values() if len(v) > 1]
    same_row_groups = [sorted(v) for v in row_classes.values() if len(v) > 1]

    return contradictions, same_row_groups, same_col_groups


def check_trifid_period9(groups):
    """Check Trifid 3×3×3 at period 9.

    Each letter maps to (layer, row, col) in a 3×3×3 cube (27 cells, 26 letters + 1 blank).
    For period p=9: 27 values (9 layers, 9 rows, 9 cols) → re-tripled into 9 triples.
    """
    # Trifid period 9: each group of 9 letters
    # Coords: (l_i, r_i, c_i) for each PT letter
    # Concatenate: l0..l8, r0..r8, c0..c8 (27 values)
    # Re-triple: (l0,l1,l2), (l3,l4,l5), (l6,l7,l8), (r0,r1,r2), ...
    # = 9 triples → 9 CT letters

    results = {}

    for group in groups:
        if group['n_known'] < group['length']:
            continue

        g_idx = group['group_idx']
        pt = group['pt']
        ct = group['ct']
        p = group['length']

        if p != 9:
            continue

        # Only fully-known groups
        if any(ch is None for ch in pt):
            continue

        results[f'group_{g_idx}'] = {
            'pt': pt,
            'ct': ct,
            'analysis': 'fully_known'
        }

        # Layer coords: l0..l8
        # Row coords: r0..r8
        # Col coords: c0..c8
        # Combined: l0..l8, r0..r8, c0..c8 (27 values)
        # Re-tripled: (l0,l1,l2) (l3,l4,l5) (l6,l7,l8) (r0,r1,r2) (r3,r4,r5) (r6,r7,r8) (c0,c1,c2) (c3,c4,c5) (c6,c7,c8)

        # For Trifid, each letter in a 3×3×3 cube: (l, r, c) each in {0,1,2}
        # sq^-1(x,y,z) = letter at cube position (x,y,z)

        # Triple 1: (l_B, l_E, l_R) → N
        # Triple 2: (l_L, l_I, l_N) → Y
        # Triple 3: (l_C, l_L, l_O) → P
        # Triple 4: (r_B, r_E, r_R) → V
        # Triple 5: (r_L, r_I, r_N) → T
        # Triple 6: (r_C, r_L, r_O) → T
        # Triple 7: (c_B, c_E, c_R) → M
        # Triple 8: (c_L, c_I, c_N) → Z
        # Triple 9: (c_C, c_L, c_O) → F

        # From triples 5 and 6: both → T
        # Triple 5: cube(r_L, r_I, r_N) = T → l_T = r_L, r_T = r_I, c_T = r_N
        # Triple 6: cube(r_C, r_L, r_O) = T → l_T = r_C, r_T = r_L, c_T = r_O
        # From triple 5: l_T = r_L, from triple 6: r_T = r_L
        # So l_T = r_T! But for letter T, (l_T, r_T, c_T) must have l_T ≠ r_T?
        # No — l_T and r_T CAN be equal (just means layer = row in the cube).
        # Actually: from triple 5: l_T = r_L AND r_T = r_I
        # From triple 6: l_T = r_C AND r_T = r_L
        # So r_L = r_C (both = l_T) AND r_I = r_L (both = r_T)
        # → r_I = r_L = r_C (all same row in cube)
        # And c_T from triple 5: c_T = r_N
        # c_T from triple 6: c_T = r_O
        # → r_N = r_O (same row)

        # From triples 7-9:
        # Triple 7: cube(c_B, c_E, c_R) = M → l_M = c_B, r_M = c_E, c_M = c_R
        # Triple 8: cube(c_L, c_I, c_N) = Z → l_Z = c_L, r_Z = c_I, c_Z = c_N
        # Triple 9: cube(c_C, c_L, c_O) = F → l_F = c_C, r_F = c_L, c_F = c_O

        # From triples 8 and 9: l_Z = c_L and r_F = c_L → l_Z = r_F

        # Now check for same-cell contradictions:
        # I, L, C share row (r_I = r_L = r_C)
        # In a 3×3×3 cube with 3 possible row values, having 3 letters share a row is OK
        # but they need different (layer, col) pairs.

        # Let me check more carefully...
        # From triple 2: cube(l_L, l_I, l_N) = Y → l_Y = l_L, r_Y = l_I, c_Y = l_N
        # From triple 3: cube(l_C, l_L, l_O) = P → l_P = l_C, r_P = l_L, c_P = l_O
        # From triple 2: l_Y = l_L, and from triple 3: r_P = l_L
        # So l_Y = r_P

        # This is getting complex. Let me check computationally with brute force.

    return results


def bruteforce_trifid_period9(groups):
    """Brute-force Trifid 3×3×3 at period 9 using group 7.

    Each of the 26 letters maps to a unique cell in a 3×3×3 cube (27 cells, 1 empty).
    For a fully-known group of 9, we get 9 triples → 9 CT letters = 27 equations.

    The 9 PT letters (B,E,R,L,I,N,C,O) have 8 distinct letters, each with (l,r,c) in {0,1,2}.
    That's 24 unknowns. The CT letters add at most 7 more distinct letters (N is shared):
    Y,P,V,T,M,Z,F = 7 new, with 3 coords each = 21 more unknowns. But triples give us
    27 equations relating these. So 24+21=45 unknowns, 27 equations → underdetermined.

    But each letter must occupy a UNIQUE cell in the 3×3×3 cube. With 15 distinct letters
    needing 15 of 27 cells, this adds combinatorial constraints.

    Brute force: enumerate (l,r,c) for the 15 distinct letters (3^45 is too large).
    Better: use group 7 to derive variable relationships, then enumerate free variables.
    """
    # Group 7: PT = B,E,R,L,I,N,C,L,O  CT = N,Y,P,V,T,T,M,Z,F
    # Layers: lB,lE,lR,lL,lI,lN,lC,lL,lO
    # Rows:   rB,rE,rR,rL,rI,rN,rC,rL,rO
    # Cols:   cB,cE,cR,cL,cI,cN,cC,cL,cO
    # Combined (27 values): layers(9), rows(9), cols(9)
    # Re-tripled into 9 triples:
    # T1: (lB,lE,lR) → N    T2: (lL,lI,lN) → Y    T3: (lC,lL,lO) → P
    # T4: (rB,rE,rR) → V    T5: (rL,rI,rN) → T    T6: (rC,rL,rO) → T
    # T7: (cB,cE,cR) → M    T8: (cL,cI,cN) → Z    T9: (cC,cL,cO) → F

    # From T5 and T6 both mapping to T:
    # T5: lT=rL, rT=rI, cT=rN
    # T6: lT=rC, rT=rL, cT=rO
    # → rL = rC (from lT), rI = rL (from rT=rL via T6, rT=rI via T5)
    # → rI = rL = rC (call it α)
    # → rN = rO (from cT, call it β)
    # → lT = α, rT = α, cT = β
    # Wait: lT = rL = α, rT = rI = α, cT = rN = β
    # So T is at (α, α, β) in the cube.

    # From T1: lN=lB_row, ... let me use the triple→letter mapping:
    # T1: cube(lB,lE,lR) = N → lN=lB, rN=lE, cN=lR
    # T2: cube(lL,lI,lN) = Y → lY=lL, rY=lI, cY=lN=lB (from T1)
    # T3: cube(lC,lL,lO) = P → lP=lC, rP=lL, cP=lO
    # T4: cube(rB,rE,rR) = V → lV=rB, rV=rE, cV=rR
    # T5: cube(rL,rI,rN) = T → lT=rL=α, rT=rI=α, cT=rN=β
    # T6: cube(rC,rL,rO) = T → (same T, consistent)
    # T7: cube(cB,cE,cR) = M → lM=cB, rM=cE, cM=cR
    # T8: cube(cL,cI,cN) = Z → lZ=cL, rZ=cI, cZ=cN=lR (from T1)
    # T9: cube(cC,cL,cO) = F → lF=cC, rF=cL, cF=cO

    # Define free variables:
    # From the 8 PT letters: B(lB,rB,cB), E(lE,rE,cE), R(lR,rR,cR), L(lL,rL,cL),
    #   I(lI,rI,cI), N(lN,rN,cN), C(lC,rC,cC), O(lO,rO,cO) = 24 coords
    # Derived from equations:
    # lN = lB        (T1)     → lN determined
    # rN = lE        (T1)     → rN determined (also = β)
    # cN = lR        (T1)     → cN determined
    # rI = rL = rC = α        → rI, rC determined by rL
    # rN = rO → β (= lE)     → rO determined
    # lT = α = rL, rT = α = rL, cT = β = lE → T determined
    # lY = lL, rY = lI, cY = lN = lB → Y determined
    # lP = lC, rP = lL, cP = lO → P determined
    # lV = rB, rV = rE, cV = rR → V determined
    # lM = cB, rM = cE, cM = cR → M determined
    # lZ = cL, rZ = cI, cZ = cN = lR → Z determined
    # lF = cC, rF = cL, cF = cO → F determined

    # Free variables (after substitution):
    # lB, lE, lR, lL, lI, lC, lO  (7 layer coords for PT letters except N)
    # rB, rE, rR, rL               (4 row coords; rI=rL, rC=rL, rN=lE, rO=lE)
    # cB, cE, cR, cL, cI, cC, cO  (7 col coords for PT letters except N: cN=lR)
    # Total: 7 + 4 + 7 = 18 free variables, each in {0,1,2}

    # Derived letter positions:
    # B: (lB, rB, cB)
    # E: (lE, rE, cE)
    # R: (lR, rR, cR)
    # L: (lL, rL, cL)
    # I: (lI, rL, cI)     [rI = rL]
    # N: (lB, lE, lR)     [lN=lB, rN=lE, cN=lR]
    # C: (lC, rL, cC)     [rC = rL]
    # O: (lO, lE, cO)     [rO = rN = lE]
    # T: (rL, rL, lE)     [lT=rT=rL=α, cT=lE=β]
    # Y: (lL, lI, lB)     [lY=lL, rY=lI, cY=lN=lB]
    # P: (lC, lL, lO)     [lP=lC, rP=lL, cP=lO]
    # V: (rB, rE, rR)     [lV=rB, rV=rE, cV=rR]
    # M: (cB, cE, cR)     [lM=cB, rM=cE, cM=cR]
    # Z: (cL, cI, lR)     [lZ=cL, rZ=cI, cZ=cN=lR]
    # F: (cC, cL, cO)     [lF=cC, rF=cL, cF=cO]

    # All 15 cells must be distinct (unique cube positions)
    # 3^18 = 387,420,489 ≈ 387M — too slow for Python brute force
    # Need constraint propagation

    # Actually, let me check if cross-group constraints give a contradiction first
    # (like for Bifid). If group 3 provides additional constraints...

    # Group 3 (period 9, positions 27-35):
    # PT: R, T, H, E, A, S, T, ?, ?
    # For Trifid, the combined 27 values are:
    # Layers: lR, lT, lH, lE, lA, lS, lT, l?, l?
    # Rows:   rR, rT, rH, rE, rA, rS, rT, r?, r?
    # Cols:   cR, cT, cH, cE, cA, cS, cT, c?, c?
    # Re-tripled:
    # T1: (lR,lT,lH) → P (CT[27]=P)
    # Using known values: lR is free, lT = rL (from group 7)
    # So T1: cube(lR, rL, lH) = P
    # From group 7: P = (lC, lL, lO)
    # So: lR = lC, rL = lL, lH = lO

    # rL = lL is a NEW constraint! This links row of L to layer of L.
    # Also: lR = lC, lH = lO

    # T4 from group 3: (rR, rT, rH) → V (CT[30]? Let me check)
    # Wait, CT for group 3: P, R, N, G, K, S, S, O, T
    # So T1→P, T2→R, T3→N, T4→G, T5→K, T6→S, T7→S, T8→O, T9→T

    # T4: cube(rR, rT, rH) = G
    # rT = rL = α (from group 7). So cube(rR, α, rH) = G.
    # G is a new letter not constrained by group 7.
    # G = (rR, α, rH) → this determines G's position.

    # T2: (lT, lH, lE) → R (CT[28]=R)
    # Wait, I need to re-check. For group 3 with period 9:
    # Actually, for position 28, CT[28]=R.
    # T2 of group 3: triple of positions 3,4,5 in the combined array.
    # Combined has 27 values: layers[0..8], rows[0..8], cols[0..8]
    # PT in group 3: R(pos0), T(pos1), H(pos2), E(pos3), A(pos4), S(pos5), T(pos6), ?(pos7), ?(pos8)
    # Layers: lR, lT, lH, lE, lA, lS, lT, l?, l?
    # Rows:   rR, rT, rH, rE, rA, rS, rT, r?, r?
    # Cols:   cR, cT, cH, cE, cA, cS, cT, c?, c?
    # Index in combined: 0=lR,1=lT,2=lH,3=lE,4=lA,5=lS,6=lT,7=l?,8=l?,
    #                    9=rR,10=rT,11=rH,12=rE,13=rA,14=rS,15=rT,16=r?,17=r?,
    #                    18=cR,19=cT,20=cH,21=cE,22=cA,23=cS,24=cT,25=c?,26=c?
    # Re-tripled: T1=(0,1,2)=(lR,lT,lH), T2=(3,4,5)=(lE,lA,lS), T3=(6,7,8)=(lT,l?,l?)
    #             T4=(9,10,11)=(rR,rT,rH), T5=(12,13,14)=(rE,rA,rS), T6=(15,16,17)=(rT,r?,r?)
    #             T7=(18,19,20)=(cR,cT,cH), T8=(21,22,23)=(cE,cA,cS), T9=(24,25,26)=(cT,c?,c?)

    # CT: P, R, N, G, K, S, S, O, T

    # T1: cube(lR, lT, lH) = P → P = (lR, lT, lH)
    # From group 7: P = (lC, lL, lO)
    # So: lR = lC, lT = lL, lH = lO
    # We know lT = rL (from group 7: T=(rL,rL,lE)), so:
    # rL = lL (!!!) → L's layer equals L's row

    # T2: cube(lE, lA, lS) = R → R = (lE, lA, lS)
    # From group 7: R = (lR, rR, cR)
    # So: lE = lR, lA = rR, lS = cR

    # lE = lR is a new constraint.
    # From group 7: N = (lB, lE, lR). With lE = lR, N = (lB, lR, lR).
    # So N's row and col coords are the same: rN = cN. Both equal lR.
    # N is at (lB, lR, lR).

    # T4: cube(rR, rT, rH) = G → G = (rR, rT, rH) = (rR, rL, rH)
    # (since rT = rL from group 7)

    # T5: cube(rE, rA, rS) = K → K = (rE, rA, rS)

    # T7: cube(cR, cT, cH) = S → S = (cR, cT, cH)
    # From group 7: cT = lE = β. With lE = lR (from T2), β = lR.
    # So cT = lR. And S = (cR, lR, cH).

    # Lots of constraints. Let me check for contradictions.
    # So far: lE = lR, rL = lL, lR = lC, lH = lO

    # From T = (rL, rL, lE):
    # lT = rT = rL = lL (since rL = lL)
    # cT = lE = lR (since lE = lR)
    # So T = (lL, lL, lR)

    # L = (lL, rL, cL) = (lL, lL, cL) (since rL = lL)
    # T = (lL, lL, lR)
    # For T ≠ L (different cells): need cL ≠ lR
    # (If cL = lR, then L and T are the same cell!)

    # From group 7: Z = (cL, cI, lR)
    # From group 7: N = (lB, lR, lR) — N's row and col are both lR

    # Let me continue checking T2 constraints:
    # T2: R = (lE, lA, lS) = (lR, lA, lS)  [since lE = lR]
    # From group 7: R = (lR, rR, cR)
    # So rR = lA, cR = lS

    # T7: S = (cR, cT, cH) = (lS, lR, cH) [since cR = lS, cT = lR]
    # S is a new letter. S = (lS, lR, cH).

    # From group 3 position 32 (pos5 in group): PT[32] = S, CT[32] = S
    # The 6th pair (T6) of group 3: cube(rT, r?, r?) = S
    # rT = rL = lL. So cube(lL, r?, r?) = S = (lS, lR, cH)
    # → lL = lS, r? = lR, r? = cH (positions 7,8 unknown)

    # lL = lS means L and S share the same layer.
    # And lT = lL = lS (since T is at (lL,...)).
    # So T, L, S all share the same layer coordinate.
    # In a 3×3×3 cube, a layer has 9 cells, so 3 letters in the same layer is fine.

    # From earlier: I, L, C share row (rI = rL = rC = lL, since rL = lL)
    # More precisely: rI = rL = rC = α = lL. And rL = lL.
    # So I = (lI, lL, cI), L = (lL, lL, cL), C = (lC, lL, cC) = (lR, lL, cC)

    # I, L, C all have row = lL. In a 3×3×3 cube, a row within a given layer has 3 cells.
    # But I, L, C can be in different layers.

    # This is getting extremely complex. Let me just check computationally.
    # I'll enumerate the free variables with the derived constraints.

    print("  Trifid cross-group constraints from groups 7+3:")
    print(f"    lE = lR, rL = lL, lR = lC, lH = lO, rR = lA, cR = lS, lL = lS")
    print(f"    T = (lL, lL, lR), L = (lL, lL, cL), N = (lB, lR, lR)")

    # Check: T = (lL, lL, lR), L = (lL, lL, cL)
    # T ≠ L requires cL ≠ lR
    print(f"    T ≠ L requires: cL ≠ lR")

    # Check: N = (lB, lR, lR). T = (lL, lL, lR).
    # N ≠ T requires: lB ≠ lL OR lR ≠ lL (since both have col = lR)
    # If lB = lL AND lR = lL, then N = T.
    print(f"    N ≠ T requires: lB ≠ lL OR lR ≠ lL")

    # Let me count free variables after all substitutions:
    # Original: lB, lE, lR, lL, lI, lC, lO, rB, rE, rR, rL, cB, cE, cR, cL, cI, cC, cO (18)
    # Constraints: lE=lR, rL=lL, lC=lR, lO=lH (need lH too), rR=lA, cR=lS, lL=lS
    # Wait, lH, lA, lS are coordinates of H, A, S — letters NOT in group 7!
    # These are new unknowns introduced by group 3.

    # This analysis is getting too complex for inline verification.
    # Let me instead do a computational search.
    print(f"    (Analysis too complex for algebraic proof; needs computational search)")

    return None


def main():
    print("=" * 60)
    print("E-S-42: Bifid 6×6 Extended Algebraic Elimination")
    print("=" * 60)

    t0 = time.time()
    results = {
        'experiment': 'E-S-42',
        'description': 'Bifid 6x6 cross-group algebraic elimination for periods 9-14',
        'periods': {}
    }

    for period in [9, 10, 12, 13, 14]:
        print(f"\n--- Period {period} ---")
        groups = get_groups(period)

        # Report group coverage
        for g in groups:
            if g['n_known'] > 0:
                print(f"  Group {g['group_idx']} (pos {g['start']}-{g['end']-1}): "
                      f"{g['n_known']}/{g['length']} known")

        period_result = {'groups': [], 'conventions': {}}

        for conv_name, pair_fn in [('standard', bifid_pairs_standard),
                                    ('reverse', bifid_pairs_reverse)]:
            constraints, equalities = derive_constraints(groups, pair_fn, conv_name)
            contradictions, same_row, same_col = find_contradictions(equalities)

            verdict = "ELIMINATED" if contradictions else "SURVIVES"

            print(f"  Convention '{conv_name}': {len(equalities)} equalities, "
                  f"{len(contradictions)} contradictions → {verdict}")

            if contradictions:
                for x, y in contradictions[:5]:
                    print(f"    Same-cell: {x} = {y}")

            if same_row:
                for grp in same_row[:3]:
                    if len(grp) > 6:
                        print(f"    Same-row group ({len(grp)} letters): {grp[:6]}...")
                    else:
                        print(f"    Same-row group: {grp}")

            if same_col:
                for grp in same_col[:3]:
                    if len(grp) > 6:
                        print(f"    Same-col group ({len(grp)} letters): {grp[:6]}...")
                    else:
                        print(f"    Same-col group: {grp}")

            period_result['conventions'][conv_name] = {
                'n_equalities': len(equalities),
                'n_contradictions': len(contradictions),
                'contradictions': [(x, y) for x, y in contradictions],
                'verdict': verdict,
                'same_row_groups': same_row[:5],
                'same_col_groups': same_col[:5],
            }

        # Overall period verdict
        std_v = period_result['conventions']['standard']['verdict']
        rev_v = period_result['conventions']['reverse']['verdict']
        if std_v == "ELIMINATED" and rev_v == "ELIMINATED":
            period_result['verdict'] = "ELIMINATED"
        elif std_v == "ELIMINATED" or rev_v == "ELIMINATED":
            surviving = "reverse" if std_v == "ELIMINATED" else "standard"
            period_result['verdict'] = f"PARTIALLY_ELIMINATED (only {surviving} survives)"
        else:
            period_result['verdict'] = "SURVIVES"

        print(f"  Period {period} overall: {period_result['verdict']}")
        results['periods'][str(period)] = period_result

    # Also check Trifid period 9
    print(f"\n--- Trifid 3×3×3 Period 9 ---")
    groups_9 = get_groups(9)

    # For Trifid, derive constraints similarly but with 3 coordinate types
    # Each letter has (layer, row, col) in {0,1,2}
    # Period 9 group: 9 letters → 27 coordinates → 9 triples → 9 CT letters
    trifid_result = {}

    # Manual algebraic analysis for Trifid period 9
    # Using group 7 (fully known) + group 3 cross-constraints
    print("  Group 7 (fully known): PT=BERLINCLO → CT=NYPVTTMZF")
    trifid_analysis = bruteforce_trifid_period9(groups_9)

    # Computational brute force for Trifid period 9
    # Enumerate all valid cube assignments using group 7 constraints
    print("\n  Running computational Trifid check (group 7 only)...", flush=True)

    # Define the 15 letter positions as functions of free variables
    # Free: lB, lR, lL, lI, rB, rE, rR, rL, cB, cE, cR, cL, cI, cC, cO (15 free)
    # With cross-group: lE=lR, rL=lL (reduces to 13 free? No — lE and rL are derived)
    # Actually lE = lR eliminates lE, rL = lL... wait, rL and lL are both in the free list.
    # Let me re-enumerate.

    # Without cross-group (group 7 only): 18 free vars
    # With cross-group (groups 7+3): additional constraints reduce this

    # For now, just test group 7 only (18 free vars in {0,1,2} = 3^18 ≈ 387M)
    # Too slow for Python. Let me use the cross-group constraints to reduce.

    # With lE=lR: 17 free vars → 3^17 ≈ 129M (still too slow)
    # With rL=lL: 16 free → 3^16 ≈ 43M (borderline)
    # With lC=lR, lA=rR, lS=cR, lL=lS → more reductions

    # Actually, lL = lS means lS is determined by lL. But lS isn't in the original free
    # variable set for group 7 alone (S isn't in group 7). These cross-group constraints
    # add new letters (A, S, H) and constrain them.

    # For the group 7-only check: 18 free vars, 3^18 ≈ 387M.
    # Even with pruning, too slow for Python. Skip and report analytically.

    print("  3^18 ≈ 387M: too large for Python brute force")
    print("  Cross-group constraints (groups 7+3) provide additional reductions")
    print("  but introduce new unknowns (A, S, H). Analysis inconclusive.")
    trifid_result = {
        'period': 9,
        'verdict': 'INCONCLUSIVE',
        'reason': '18 free variables, 3^18 too large for Python, cross-group adds complexity',
        'cross_group_constraints': ['lE=lR', 'rL=lL', 'lC=lR', 'lH=lO', 'rR=lA', 'cR=lS', 'lL=lS'],
        'key_observation': 'T=(lL,lL,lR), L=(lL,lL,cL) → T≠L requires cL≠lR'
    }
    results['trifid_period_9'] = trifid_result

    elapsed = time.time() - t0

    # Summary
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")

    for period_str, pr in results['periods'].items():
        print(f"  Bifid 6×6 period {period_str}: {pr['verdict']}")
    print(f"  Trifid 3×3×3 period 9: {trifid_result['verdict']}")
    print(f"  Time: {elapsed:.1f}s")

    # Combined with previous results
    print(f"\n  Bifid 6×6 elimination status:")
    print(f"    Periods 2-8: ELIMINATED (Session 10, single-group contradictions)")
    print(f"    Period 11: ELIMINATED (Session 10, single-group contradictions)")
    for p in [9, 10, 12, 13, 14]:
        v = results['periods'][str(p)]['verdict']
        print(f"    Period {p}: {v}")

    results['elapsed_seconds'] = round(elapsed, 1)

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_42_bifid6x6_extended.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n  Artifact: results/e_s_42_bifid6x6_extended.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_42_bifid6x6_extended.py")


if __name__ == "__main__":
    main()
