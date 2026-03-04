#!/usr/bin/env python3
"""
Cipher: autokey
Family: polyalphabetic
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-69b: Test the 15 PT-autokey + w7 survivors from E-S-69."""

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]
CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}
WIDTH = 7
COL_LENS = [14, 14, 14, 14, 14, 14, 13]

survivors = [
    ([0, 6, 4, 3, 5, 1, 2], 62, 'vbeau'),
    ([0, 2, 6, 3, 1, 5, 4], 50, 'vig'),
    ([0, 4, 5, 1, 3, 6, 2], 23, 'vbeau'),
    ([4, 2, 5, 6, 3, 0, 1], 50, 'vig'),
    ([4, 2, 5, 6, 3, 1, 0], 50, 'beau'),
    ([4, 5, 1, 2, 6, 0, 3], 62, 'vbeau'),
    ([4, 5, 1, 6, 2, 0, 3], 62, 'vbeau'),
    ([6, 4, 0, 3, 5, 1, 2], 76, 'vbeau'),
    ([6, 4, 0, 5, 3, 1, 2], 76, 'vbeau'),
    ([6, 4, 2, 5, 3, 0, 1], 37, 'vig'),
    ([6, 4, 2, 5, 3, 1, 0], 37, 'beau'),
    ([6, 4, 3, 0, 5, 1, 2], 76, 'vbeau'),
    ([6, 4, 3, 5, 0, 1, 2], 76, 'vbeau'),
    ([6, 4, 5, 0, 3, 1, 2], 76, 'vbeau'),
    ([6, 4, 5, 3, 0, 1, 2], 76, 'vbeau'),
]

for order, k, vname in survivors:
    # Build permutations
    perm = [0] * N
    inv_perm = [0] * N
    pos = 0
    for grid_col in order:
        for row in range(COL_LENS[grid_col]):
            pt_pos = row * WIDTH + grid_col
            perm[pos] = pt_pos
            inv_perm[pt_pos] = pos
            pos += 1

    # Seed intermediate with crib values
    intermediate = [None] * N
    for p, c in CRIB_DICT.items():
        j = inv_perm[p]
        intermediate[j] = IDX[c]

    # Propagate autokey
    changed = True
    iters = 0
    while changed and iters < 200:
        changed = False
        iters += 1
        for j in range(N):
            if intermediate[j] is not None:
                # Forward: compute intermediate[j+k]
                if j + k < N and intermediate[j + k] is None:
                    if vname == 'vig':
                        intermediate[j + k] = (CT_IDX[j + k] - intermediate[j]) % 26
                    elif vname == 'beau':
                        intermediate[j + k] = (intermediate[j] - CT_IDX[j + k]) % 26
                    elif vname == 'vbeau':
                        intermediate[j + k] = (CT_IDX[j + k] + intermediate[j]) % 26
                    changed = True
                # Backward: compute intermediate[j-k]
                if j - k >= 0 and intermediate[j - k] is None:
                    if vname == 'vig':
                        intermediate[j - k] = (CT_IDX[j] - intermediate[j]) % 26
                    elif vname == 'beau':
                        intermediate[j - k] = (CT_IDX[j] + intermediate[j]) % 26
                    elif vname == 'vbeau':
                        intermediate[j - k] = (intermediate[j] - CT_IDX[j]) % 26
                    changed = True

    # Check consistency: do propagated values match cribs?
    match_count = 0
    contradictions = 0
    for p, expected in CRIB_DICT.items():
        j = inv_perm[p]
        if intermediate[j] is not None:
            if AZ[intermediate[j]] == expected:
                match_count += 1
            else:
                contradictions += 1

    # Untranspose
    pt = [None] * N
    for j in range(N):
        if intermediate[j] is not None:
            pt[perm[j]] = intermediate[j]
    filled = sum(1 for x in pt if x is not None)
    pt_str = ''.join(AZ[x] if x is not None else '.' for x in pt)

    status = "CONSISTENT" if contradictions == 0 else f"CONTRADICTION ({contradictions})"
    print(f"order={order} k={k} {vname}: {status}, cribs={match_count}/24, filled={filled}/{N}")
    if contradictions == 0 and filled > 30:
        print(f"  PT: {pt_str}")
