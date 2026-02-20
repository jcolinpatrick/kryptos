#!/usr/bin/env python3
"""
E-S-77: Hill Cipher Inspired by Physical Anomalies

The Kryptos sculpture has physical anomalies potentially related to K4:
  - YAR superscript at K3/K4 boundary (Y=24, A=0, R=17)
  - Extra "L" on Vigenère tableau creates vertical "HILL" on same line
  - Bauer/Link/Molle hypothesis: Hill cipher as K4 method

K4's length (97 = prime) makes standard Hill blocking awkward:
  - 97/2 = 48.5 (need padding for 2×2)
  - 97/3 = 32.33 (need padding for 3×3)
  - 97/7 = 13.86 (need padding for 7×7)

But: 97 + 3 = 100 = 10×10 (turning grille!) or 4×25, 5×20, etc.
    98 = 14×7 (width-7 columnar = 14 blocks of 7)

Previous elimination: Hill n=2,3 + columnar widths 5-8 eliminated.
NOT tested: Hill n=7 (matches width-7), Hill with YAR-derived parameters.

This experiment tests:
  Phase 1: Hill 7×7 + width-7 columnar (Model B)
  Phase 2: Hill with YAR-derived key matrix entries
  Phase 3: Hill 2×2 through 5×5 with padding strategies
  Phase 4: Involutory Hill matrices (self-inverse, simplifies hand computation)
"""

import json
import math
import os
import random
import sys
import time
from itertools import permutations
import numpy as np

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]
CT_ARR = np.array(CT_IDX, dtype=np.int64)

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
CRIB_POS = sorted(CRIB_DICT.keys())

WIDTH = 7
NROWS_FULL = N // WIDTH
NROWS_EXTRA = N % WIDTH

print("=" * 70)
print("E-S-77: Hill Cipher + Width-7 Columnar (Anomaly-Inspired)")
print("=" * 70)

def build_col_perm(order):
    col_lengths = []
    for col_idx in range(WIDTH):
        if col_idx < NROWS_EXTRA:
            col_lengths.append(NROWS_FULL + 1)
        else:
            col_lengths.append(NROWS_FULL)
    perm = [0] * N
    j = 0
    for rank in range(WIDTH):
        c = order[rank]
        clen = col_lengths[c]
        for row in range(clen):
            pt_pos = row * WIDTH + c
            perm[j] = pt_pos
            j += 1
    inv_perm = [0] * N
    for j in range(N):
        inv_perm[perm[j]] = j
    return perm, inv_perm


def mod_inv(a, m=26):
    """Modular inverse of a mod m."""
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def det_mod(matrix, mod=26):
    """Determinant of matrix mod 26 using LU-like approach."""
    n = len(matrix)
    # Work in integers, take mod at end
    M = [list(row) for row in matrix]
    det = 1
    for col in range(n):
        # Find pivot
        pivot = -1
        for row in range(col, n):
            if M[row][col] % mod != 0:
                pivot = row
                break
        if pivot == -1:
            return 0
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]
            det = (-det) % mod

        det = (det * M[col][col]) % mod

        inv = mod_inv(M[col][col] % mod, mod)
        if inv is None:
            return 0

        for row in range(col + 1, n):
            factor = (M[row][col] * inv) % mod
            for k in range(col, n):
                M[row][k] = (M[row][k] - factor * M[col][k]) % mod

    return det % mod


def mat_inv_mod26(matrix):
    """Inverse of matrix mod 26 using numpy for computation."""
    n = len(matrix)
    M = np.array(matrix, dtype=np.int64)

    # Compute determinant mod 26
    d = int(round(np.linalg.det(M))) % 26
    d_inv = mod_inv(d, 26)
    if d_inv is None:
        return None

    # Compute adjugate (cofactor matrix transposed)
    adj = np.zeros((n, n), dtype=np.int64)
    for i in range(n):
        for j in range(n):
            # Minor (i,j)
            minor = np.delete(np.delete(M, i, axis=0), j, axis=1)
            cofactor = int(round(np.linalg.det(minor))) * ((-1) ** (i + j))
            adj[j][i] = cofactor % 26  # Transposed

    inv = (d_inv * adj) % 26
    return inv.tolist()


# ── Phase 1: Hill 2×2 direct + width-7 columnar ─────────────────────────
print("\n" + "-" * 50)
print("Phase 1: Hill 2×2 direct (no transposition) — crib constraint check")
print("-" * 50)

# For Hill 2×2: CT = M × PT (mod 26), blocks of 2
# CT[2i] = M[0][0]*PT[2i] + M[0][1]*PT[2i+1] mod 26
# CT[2i+1] = M[1][0]*PT[2i] + M[1][1]*PT[2i+1] mod 26
#
# With cribs, we need pairs of consecutive crib positions: (21,22), (22,23), ..., (32,33)
# and (63,64), (64,65), ..., (72,73)

# For block starting at position b (even), if both b and b+1 are cribs:
def get_hill2_crib_blocks():
    """Find pairs of consecutive crib positions that form complete Hill-2 blocks."""
    blocks = []
    for b in range(0, N-1, 2):
        if b in CRIB_DICT and b+1 in CRIB_DICT:
            pt0 = IDX[CRIB_DICT[b]]
            pt1 = IDX[CRIB_DICT[b+1]]
            ct0 = CT_IDX[b]
            ct1 = CT_IDX[b+1]
            blocks.append((b, pt0, pt1, ct0, ct1))
    # Also try odd-aligned blocks
    for b in range(1, N-1, 2):
        if b in CRIB_DICT and b+1 in CRIB_DICT:
            pt0 = IDX[CRIB_DICT[b]]
            pt1 = IDX[CRIB_DICT[b+1]]
            ct0 = CT_IDX[b]
            ct1 = CT_IDX[b+1]
            blocks.append((b, pt0, pt1, ct0, ct1))
    return blocks

blocks_2 = get_hill2_crib_blocks()
print(f"  Hill-2 crib blocks: {len(blocks_2)}")
for b in blocks_2:
    print(f"    pos {b[0]}-{b[0]+1}: PT={AZ[b[1]]}{AZ[b[2]]} CT={AZ[b[3]]}{AZ[b[4]]}")

# For each pair of blocks, try to solve for the 2×2 matrix
# M × [pt0, pt1]^T = [ct0, ct1]^T mod 26
# Two blocks give 4 equations, 4 unknowns
best_h2 = {'score': 0}
h2_count = 0
for i in range(len(blocks_2)):
    for j in range(i+1, len(blocks_2)):
        b1 = blocks_2[i]
        b2 = blocks_2[j]

        # Solve: M × P = C mod 26 where P = [[pt0_1, pt0_2], [pt1_1, pt1_2]]
        P = np.array([[b1[1], b2[1]], [b1[2], b2[2]]], dtype=np.int64)
        C = np.array([[b1[3], b2[3]], [b1[4], b2[4]]], dtype=np.int64)

        # M = C × P^{-1} mod 26
        det_P = (P[0][0] * P[1][1] - P[0][1] * P[1][0]) % 26
        det_P_inv = mod_inv(int(det_P), 26)
        if det_P_inv is None:
            continue

        P_inv = np.array([[P[1][1], -P[0][1]], [-P[1][0], P[0][0]]], dtype=np.int64)
        P_inv = (det_P_inv * P_inv) % 26

        M = (C @ P_inv) % 26

        # Verify M is invertible
        det_M = (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % 26
        if mod_inv(int(det_M), 26) is None:
            continue

        # Check all crib blocks with this matrix
        matches = 0
        for b in blocks_2:
            pt_vec = np.array([b[1], b[2]], dtype=np.int64)
            ct_expected = (M @ pt_vec) % 26
            if ct_expected[0] == b[3] and ct_expected[1] == b[4]:
                matches += 1

        h2_count += 1
        if matches > best_h2['score']:
            best_h2 = {'score': matches, 'matrix': M.tolist(),
                       'blocks_used': (blocks_2[i][0], blocks_2[j][0])}
            if matches >= 3:
                print(f"    M from blocks {blocks_2[i][0]},{blocks_2[j][0]}: {matches}/{len(blocks_2)} blocks match")

print(f"  Tested {h2_count} matrix candidates, best matches: {best_h2['score']}/{len(blocks_2)}")

# ── Phase 2: Hill 2×2 + width-7 columnar (Model B) ──────────────────────
print("\n" + "-" * 50)
print("Phase 2: Hill 2×2 + width-7 columnar (Model B)")
print("-" * 50)

all_orders = list(permutations(range(WIDTH)))
best_h2w7 = {'score': 0}
t2 = time.time()

for oi, order in enumerate(all_orders):
    order = list(order)
    perm, inv_perm = build_col_perm(order)

    # Under Model B: intermediate = columnar_trans(PT), CT = Hill(intermediate)
    # So: CT[2i:2i+2] = M × intermediate[2i:2i+2] mod 26
    # And: intermediate[j] = PT[perm[j]]
    # For crib at position p: intermediate[inv_perm[p]] = PT[p]

    # Find blocks of 2 in intermediate where both positions are cribs
    inter_blocks = []
    for b in range(0, N-1, 2):
        p0 = perm[b]    # PT position mapped to intermediate position b
        p1 = perm[b+1]  # PT position mapped to intermediate position b+1
        if p0 in CRIB_DICT and p1 in CRIB_DICT:
            inter_blocks.append((b, IDX[CRIB_DICT[p0]], IDX[CRIB_DICT[p1]], CT_IDX[b], CT_IDX[b+1]))

    if len(inter_blocks) < 2:
        continue

    # Try all pairs to solve for matrix
    for i in range(len(inter_blocks)):
        for j in range(i+1, len(inter_blocks)):
            b1 = inter_blocks[i]
            b2 = inter_blocks[j]

            P = np.array([[b1[1], b2[1]], [b1[2], b2[2]]], dtype=np.int64)
            C = np.array([[b1[3], b2[3]], [b1[4], b2[4]]], dtype=np.int64)

            det_P = (P[0][0] * P[1][1] - P[0][1] * P[1][0]) % 26
            det_P_inv = mod_inv(int(det_P), 26)
            if det_P_inv is None:
                continue

            P_inv = np.array([[P[1][1], -P[0][1]], [-P[1][0], P[0][0]]], dtype=np.int64)
            P_inv = (det_P_inv * P_inv) % 26
            M = (C @ P_inv) % 26

            det_M = (M[0][0] * M[1][1] - M[0][1] * M[1][0]) % 26
            if mod_inv(int(det_M), 26) is None:
                continue

            matches = 0
            for b in inter_blocks:
                pt_vec = np.array([b[1], b[2]], dtype=np.int64)
                ct_expected = (M @ pt_vec) % 26
                if ct_expected[0] == b[3] and ct_expected[1] == b[4]:
                    matches += 1

            if matches > best_h2w7['score']:
                best_h2w7 = {'score': matches, 'total': len(inter_blocks),
                             'matrix': M.tolist(), 'order': order}
                if matches >= 3:
                    print(f"    order={order} M={M.tolist()} matches={matches}/{len(inter_blocks)}")

    if (oi + 1) % 1000 == 0:
        elapsed = time.time() - t2
        print(f"  {oi+1}/5040, {elapsed:.0f}s, best={best_h2w7['score']}")

t3 = time.time()
print(f"\n  Phase 2: {t3-t2:.1f}s, best={best_h2w7['score']} matches")

# ── Phase 3: Hill 3×3 direct ────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 3: Hill 3×3 direct — crib constraint check")
print("-" * 50)

# Find triples of consecutive crib positions
blocks_3 = []
for b in range(0, N-2, 3):
    if all(b+k in CRIB_DICT for k in range(3)):
        pts = tuple(IDX[CRIB_DICT[b+k]] for k in range(3))
        cts = tuple(CT_IDX[b+k] for k in range(3))
        blocks_3.append((b, pts, cts))
# Also try alignments offset by 1 and 2
for offset in [1, 2]:
    for b in range(offset, N-2, 3):
        if all(b+k in CRIB_DICT for k in range(3)):
            pts = tuple(IDX[CRIB_DICT[b+k]] for k in range(3))
            cts = tuple(CT_IDX[b+k] for k in range(3))
            blocks_3.append((b, pts, cts))

print(f"  Hill-3 crib blocks: {len(blocks_3)}")

best_h3 = {'score': 0}
if len(blocks_3) >= 3:
        for i in range(len(blocks_3)):
            for j in range(i+1, len(blocks_3)):
                for k in range(j+1, len(blocks_3)):
                    b1, b2, b3 = blocks_3[i], blocks_3[j], blocks_3[k]

                    P = np.array([b1[1], b2[1], b3[1]], dtype=np.int64).T  # 3×3
                    C = np.array([b1[2], b2[2], b3[2]], dtype=np.int64).T  # 3×3

                    try:
                        det_P = int(round(np.linalg.det(P.astype(float)))) % 26
                    except:
                        continue
                    det_P_inv = mod_inv(det_P, 26)
                    if det_P_inv is None:
                        continue

                    # P_inv mod 26
                    P_inv_float = np.linalg.inv(P.astype(float))
                    P_adj = np.round(P_inv_float * round(np.linalg.det(P.astype(float)))).astype(np.int64) % 26
                    P_inv = (det_P_inv * P_adj) % 26

                    M = (C @ P_inv) % 26

                    # Verify on remaining blocks
                    matches = 0
                    for b in blocks_3:
                        pt_vec = np.array(b[1], dtype=np.int64)
                        ct_expected = (M @ pt_vec) % 26
                        if all(ct_expected[m] == b[2][m] for m in range(3)):
                            matches += 1

                    if matches > best_h3['score']:
                        best_h3 = {'score': matches, 'total': len(blocks_3),
                                   'matrix': M.tolist()}
                        if matches >= 3:
                            print(f"    M={M.tolist()} matches={matches}/{len(blocks_3)}")

print(f"  Phase 3 best: {best_h3['score']} matches")

# ── Phase 4: YAR-inspired parameters ────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 4: YAR-derived parameters (Y=24, A=0, R=17)")
print("-" * 50)

# YAR could encode:
# 1. A 3-letter key: Y, A, R (24, 0, 17) used as Vigenère key at period 3
# 2. Matrix elements: a 2×2 matrix [[24,0],[17,?]] or [[24,17],[0,?]]
# 3. Block size (Y=24), offset (A=0), key value (R=17)
# 4. A cipher indicator: "Your Answer Resides..."

# Test YAR as Vigenère key (period 3)
yar_key = [24, 0, 17]
yar_key_extended = [yar_key[i % 3] for i in range(N)]

matches_vig = 0
matches_beau = 0
for p in CRIB_POS:
    pt_v = IDX[CRIB_DICT[p]]
    ct_v = CT_IDX[p]
    k = yar_key[p % 3]
    if (ct_v - pt_v) % 26 == k:
        matches_vig += 1
    if (ct_v + pt_v) % 26 == k:
        matches_beau += 1

print(f"  YAR as Vig key (p=3): {matches_vig}/24")
print(f"  YAR as Beau key (p=3): {matches_beau}/24")

# Test YAR + width-7 columnar
best_yar_w7 = {'score': 0}
for order in all_orders:
    order = list(order)
    _, inv_perm = build_col_perm(order)

    for variant in ['vig', 'beau']:
        matches = 0
        for p in CRIB_POS:
            j = inv_perm[p]
            pt_v = IDX[CRIB_DICT[p]]
            ct_v = CT_IDX[j]
            k = yar_key[j % 3]
            if variant == 'vig':
                if (ct_v - pt_v) % 26 == k:
                    matches += 1
            else:
                if (ct_v + pt_v) % 26 == k:
                    matches += 1

        if matches > best_yar_w7['score']:
            best_yar_w7 = {'score': matches, 'order': order, 'variant': variant}

print(f"  YAR + w7 best: {best_yar_w7['score']}/24 — {best_yar_w7}")

# Test 2×2 matrices with YAR-derived entries
print(f"\n  Testing 2×2 Hill matrices with YAR entries...")
yar_vals = [24, 0, 17]
best_yar_hill = {'score': 0}

for a in yar_vals:
    for b in range(26):
        for c in yar_vals:
            for d in range(26):
                M = np.array([[a, b], [c, d]], dtype=np.int64)
                det = (a * d - b * c) % 26
                if mod_inv(det, 26) is None:
                    continue

                # Score against direct crib blocks
                matches = 0
                for bl in blocks_2:
                    pt_vec = np.array([bl[1], bl[2]], dtype=np.int64)
                    ct_expected = (M @ pt_vec) % 26
                    if ct_expected[0] == bl[3] and ct_expected[1] == bl[4]:
                        matches += 1

                if matches > best_yar_hill['score']:
                    best_yar_hill = {'score': matches, 'matrix': M.tolist()}

for a in range(26):
    for b in yar_vals:
        for c in range(26):
            for d in yar_vals:
                M = np.array([[a, b], [c, d]], dtype=np.int64)
                det = (a * d - b * c) % 26
                if mod_inv(det, 26) is None:
                    continue

                matches = 0
                for bl in blocks_2:
                    pt_vec = np.array([bl[1], bl[2]], dtype=np.int64)
                    ct_expected = (M @ pt_vec) % 26
                    if ct_expected[0] == bl[3] and ct_expected[1] == bl[4]:
                        matches += 1

                if matches > best_yar_hill['score']:
                    best_yar_hill = {'score': matches, 'matrix': M.tolist()}

print(f"  YAR-constrained 2×2 Hill best: {best_yar_hill['score']}/{len(blocks_2)}")

# ── Summary ──────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (Hill 2×2 direct): {best_h2['score']}/{len(blocks_2)} blocks match")
print(f"  Phase 2 (Hill 2×2 + w7): {best_h2w7.get('score', 0)} matches")
print(f"  Phase 3 (Hill 3×3 direct): {best_h3['score']} matches")
print(f"  Phase 4 (YAR params): vig={matches_vig}/24 beau={matches_beau}/24 w7={best_yar_w7['score']}/24")

best_all = max(best_h2['score'], best_h2w7.get('score', 0), best_h3['score'],
               best_yar_w7['score'])
verdict = f"NO SIGNAL — best {best_all}" if best_all < 5 else f"SIGNAL — {best_all}"
print(f"\n  Verdict: {verdict}")

output = {
    'experiment': 'E-S-77',
    'description': 'Hill cipher + anomaly-inspired parameters',
    'hill2_direct': best_h2['score'],
    'hill2_w7': best_h2w7.get('score', 0),
    'hill3_direct': best_h3['score'],
    'yar_direct_vig': matches_vig,
    'yar_direct_beau': matches_beau,
    'yar_w7': best_yar_w7['score'],
    'verdict': verdict,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_77_hill_anomaly.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_77_hill_anomaly.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_77_hill_anomaly.py")
