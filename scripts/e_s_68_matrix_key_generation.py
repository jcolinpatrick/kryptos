#!/usr/bin/env python3
"""
E-S-68: Matrix-Based Key Generation + Width-7 Columnar

"Coding charts" strongly suggests physical lookup tables. This tests key
generation methods that use a matrix/tableau to produce a non-periodic key:

1. KEYWORD-DERIVED KEY TABLE: Write a keyword-mixed alphabet into a 5×5 or
   6×6 grid. Read off a key by tracing a path through the grid (spiral,
   diagonal, snake, etc.). This produces a non-periodic key from a keyword.

2. STRADDLING CHECKERBOARD KEY: Use a straddling checkerboard to encode a
   keyword into digits, then use those digits as the key.

3. BEAUFORT TABLEAU WITH KEYWORD: Apply Beaufort using a keyword-generated
   alphabet as the cipher alphabet (Quagmire variant).

4. KEYED CAESAR PER ROW: Each row of the width-7 grid gets a different
   shift derived from a keyword.

5. PROGRESSIVE KEY: Start with a keyword, shift by +1 each repetition
   (or +N, or by letter values).

6. MATRIX TRANSPOSITION KEY: Write keyword into a matrix, read off in
   a different order to generate the key.

All combined with width-7 columnar (Model B).
"""

import json
import os
import sys
import time
from itertools import permutations, product

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)  # 97

CRIB_DICT = {
    21: 'E', 22: 'A', 23: 'S', 24: 'T', 25: 'N', 26: 'O', 27: 'R',
    28: 'T', 29: 'H', 30: 'E', 31: 'A', 32: 'S', 33: 'T',
    63: 'B', 64: 'E', 65: 'R', 66: 'L', 67: 'I', 68: 'N', 69: 'C',
    70: 'L', 71: 'O', 72: 'C', 73: 'K'
}

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
IDX = {c: i for i, c in enumerate(AZ)}
CT_IDX = [IDX[c] for c in CT]

WIDTH = 7
COL_LENS = [14, 14, 14, 14, 14, 14, 13]

# Thematic keywords
KEYWORDS = [
    'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'LUCID',
    'SCHEIDT', 'SANBORN', 'LANGLEY', 'BERLIN', 'CLOCK',
    'EASTNORTHEAST', 'BERLINCLOCK', 'PHANTOM', 'SECRET',
    'INVISIBLE', 'UNDERGRUUND', 'MAGNETIC', 'PASSAGE',
    'DESPERATLY', 'REMAINS', 'LUMINANCE', 'IQLUSION',
    'CENTRAL', 'INTELLIGENCE', 'AGENCY', 'EGYPT',
    'TUTANKHAMUN', 'CARTER', 'TOMB', 'PHARAOH',
    'POINT', 'MESSAGE', 'DELIVER', 'FREEDOM',
    'KRYPTOSPALIMPSEST', 'PALIMPSESTKRYPTOS',
    'ABSCISSAKRYPTOS', 'KRYPTOSABSCISSA',
]

print("=" * 70)
print("E-S-68: Matrix-Based Key Generation + Width-7 Columnar")
print("=" * 70)

crib_items = list(CRIB_DICT.items())

def check_cribs(key, var_sign=1, inv_perm=None):
    """Count crib matches under given key, variant, and transposition."""
    cribs = 0
    for p, expected in crib_items:
        if inv_perm is not None:
            j = inv_perm[p]
        else:
            j = p
        kv = key[j]
        ct_v = CT_IDX[j]
        pt_v = (ct_v - var_sign * kv) % 26
        if AZ[pt_v] == expected:
            cribs += 1
    return cribs

def build_inv_perm(order):
    """Build inverse permutation for width-7 columnar."""
    inv_perm = [0] * N
    pos = 0
    for grid_col in order:
        for row in range(COL_LENS[grid_col]):
            pt_pos = row * WIDTH + grid_col
            inv_perm[pt_pos] = pos
            pos += 1
    return inv_perm

def mixed_alphabet(keyword):
    """Generate mixed alphabet from keyword."""
    seen = set()
    alpha = []
    for c in keyword.upper():
        if c in AZ and c not in seen:
            alpha.append(c)
            seen.add(c)
    for c in AZ:
        if c not in seen:
            alpha.append(c)
            seen.add(c)
    return ''.join(alpha)

# ── Phase 1: Progressive Key ──────────────────────────────────────────────
print("\n" + "-" * 50)
print("Phase 1: Progressive Key (keyword + increment per cycle)")
print("-" * 50)

best_p1 = {'cribs': 0}
configs_p1 = 0
t0 = time.time()

for kw in KEYWORDS:
    kw_vals = [IDX[c] for c in kw.upper() if c in AZ]
    kw_len = len(kw_vals)
    if kw_len == 0:
        continue

    for increment in range(27):  # 0-26 increment per cycle
        # Key[i] = kw_vals[i % kw_len] + (i // kw_len) * increment
        key = [(kw_vals[i % kw_len] + (i // kw_len) * increment) % 26 for i in range(N)]

        # Direct (no transposition)
        for var_sign in (1, -1):
            cribs = check_cribs(key, var_sign)
            configs_p1 += 1
            if cribs > best_p1['cribs']:
                vname = 'vig' if var_sign == 1 else 'beau'
                best_p1 = {'cribs': cribs, 'keyword': kw, 'increment': increment, 'variant': vname, 'trans': 'direct'}
                if cribs >= 10:
                    print(f"  ** HIT: {cribs}/24 {kw} inc={increment} {vname}")

        # With width-7 columnar
        for order in permutations(range(WIDTH)):
            inv_perm = build_inv_perm(order)
            for var_sign in (1, -1):
                cribs = check_cribs(key, var_sign, inv_perm)
                configs_p1 += 1
                if cribs > best_p1['cribs']:
                    vname = 'vig' if var_sign == 1 else 'beau'
                    best_p1 = {'cribs': cribs, 'keyword': kw, 'increment': increment,
                               'variant': vname, 'order': list(order)}
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 {kw} inc={increment} {vname} order={list(order)}")

    if time.time() - t0 > 600:
        print(f"  Phase 1 timeout after {kw}, {configs_p1:,} configs")
        break

t1 = time.time()
print(f"  {configs_p1:,} configs, {t1-t0:.1f}s, best={best_p1['cribs']}/24")

# ── Phase 2: Matrix-read key (keyword in 5x5, 6x6, 7x14 grid) ────────────
print("\n" + "-" * 50)
print("Phase 2: Matrix-read key (keyword alphabet in grids)")
print("-" * 50)

def grid_readings(alpha, rows, cols):
    """Generate different readings of an alphabet arranged in rows×cols grid."""
    # Arrange alphabet in grid
    grid = []
    for r in range(rows):
        row = []
        for c in range(cols):
            idx = r * cols + c
            if idx < len(alpha):
                row.append(alpha[idx])
            else:
                row.append('X')
        grid.append(row)

    readings = {}

    # Row-major (normal)
    readings['row_major'] = [grid[r][c] for r in range(rows) for c in range(cols)]

    # Column-major
    readings['col_major'] = [grid[r][c] for c in range(cols) for r in range(rows)]

    # Snake (boustrophedon)
    snake = []
    for r in range(rows):
        if r % 2 == 0:
            snake.extend(grid[r])
        else:
            snake.extend(reversed(grid[r]))
    readings['snake'] = snake

    # Diagonal (top-left to bottom-right)
    diag = []
    for d in range(rows + cols - 1):
        for r in range(rows):
            c = d - r
            if 0 <= c < cols:
                diag.append(grid[r][c])
    readings['diagonal'] = diag

    # Spiral (clockwise from top-left)
    spiral = []
    top, bottom, left, right = 0, rows-1, 0, cols-1
    while top <= bottom and left <= right:
        for c in range(left, right+1): spiral.append(grid[top][c])
        top += 1
        for r in range(top, bottom+1): spiral.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left-1, -1): spiral.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top-1, -1): spiral.append(grid[r][left])
            left += 1
    readings['spiral'] = spiral

    return readings

best_p2 = {'cribs': 0}
configs_p2 = 0
t2 = time.time()

grid_dims = [(5, 6), (6, 5), (7, 4), (4, 7), (13, 2), (2, 13)]

for kw in KEYWORDS[:20]:  # Top 20 keywords
    alpha = mixed_alphabet(kw)

    for rows, cols in grid_dims:
        readings = grid_readings(alpha, rows, cols)
        for rname, reading in readings.items():
            # Use reading as key (cycling if needed)
            reading_idx = [IDX[c] for c in reading if c in AZ]
            rlen = len(reading_idx)
            if rlen == 0:
                continue

            # Generate key by repeating the reading
            key = [reading_idx[i % rlen] for i in range(N)]

            # Direct
            for var_sign in (1, -1):
                cribs = check_cribs(key, var_sign)
                configs_p2 += 1
                if cribs > best_p2['cribs']:
                    vname = 'vig' if var_sign == 1 else 'beau'
                    best_p2 = {'cribs': cribs, 'keyword': kw, 'grid': f'{rows}x{cols}',
                               'reading': rname, 'variant': vname, 'trans': 'direct'}
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 {kw} {rows}x{cols} {rname} {vname}")

            # Progressive (non-repeating): read the alphabet multiple times with shift
            for shift in range(1, 26):
                key = [(reading_idx[i % rlen] + (i // rlen) * shift) % 26 for i in range(N)]
                for var_sign in (1, -1):
                    cribs = check_cribs(key, var_sign)
                    configs_p2 += 1
                    if cribs > best_p2['cribs']:
                        vname = 'vig' if var_sign == 1 else 'beau'
                        best_p2 = {'cribs': cribs, 'keyword': kw, 'grid': f'{rows}x{cols}',
                                   'reading': rname, 'shift': shift, 'variant': vname}
                        if cribs >= 10:
                            print(f"  ** HIT: {cribs}/24 {kw} {rows}x{cols} {rname} shift={shift} {vname}")

t3 = time.time()
print(f"  {configs_p2:,} configs, {t3-t2:.1f}s, best={best_p2['cribs']}/24")

# ── Phase 3: Keyed Caesar per row (width-7 grid) ──────────────────────────
print("\n" + "-" * 50)
print("Phase 3: Keyed Caesar per row (width-7 grid)")
print("-" * 50)

best_p3 = {'cribs': 0}
configs_p3 = 0
t4 = time.time()

for kw in KEYWORDS:
    kw_vals = [IDX[c] for c in kw.upper() if c in AZ]
    kw_len = len(kw_vals)
    if kw_len == 0:
        continue

    # Each row r gets shift = kw_vals[r % kw_len]
    # Key is applied AFTER transposition (Model B)
    # In CT-space, position j is in column col(j) at row row(j)
    # The shift depends on the ROW in the original grid

    for order in permutations(range(WIDTH)):
        inv_perm = build_inv_perm(order)

        # For Model B: CT[j] = (PT[perm[j]] + key[j]) % 26
        # key[j] depends on the ROW of the original PT position perm[j]
        # perm[j] = row * 7 + col → row = perm[j] // 7
        # So key[j] = kw_vals[(perm[j] // 7) % kw_len]

        # But we check cribs using inv_perm: for crib at PT pos p,
        # j = inv_perm[p], row = p // 7
        # key_at_j = kw_vals[(p // 7) % kw_len]

        for var_sign in (1, -1):
            cribs = 0
            for p, expected in crib_items:
                j = inv_perm[p]
                row = p // WIDTH
                kv = kw_vals[row % kw_len]
                ct_v = CT_IDX[j]
                pt_v = (ct_v - var_sign * kv) % 26
                if AZ[pt_v] == expected:
                    cribs += 1
            configs_p3 += 1
            if cribs > best_p3['cribs']:
                vname = 'vig' if var_sign == 1 else 'beau'
                best_p3 = {'cribs': cribs, 'keyword': kw, 'variant': vname, 'order': list(order)}
                if cribs >= 10:
                    print(f"  ** HIT: {cribs}/24 {kw} {vname} order={list(order)}")

    if time.time() - t4 > 300:
        print(f"  Phase 3 timeout after {kw}, {configs_p3:,} configs")
        break

t5 = time.time()
print(f"  {configs_p3:,} configs, {t5-t4:.1f}s, best={best_p3['cribs']}/24")

# ── Phase 4: Key from transposed keyword ──────────────────────────────────
print("\n" + "-" * 50)
print("Phase 4: Key from columnar-transposed keyword")
print("-" * 50)
print("  Key = write keyword repeatedly into width-W grid,")
print("  read off columns in order → non-periodic key")

best_p4 = {'cribs': 0}
configs_p4 = 0
t6 = time.time()

for kw in KEYWORDS:
    kw_vals = [IDX[c] for c in kw.upper() if c in AZ]
    kw_len = len(kw_vals)
    if kw_len == 0:
        continue

    # Write keyword into width-W grids, read off columns
    for key_width in range(3, 11):
        # Write keyword (repeated) into key_width columns
        key_rows = (N + key_width - 1) // key_width
        key_total = key_rows * key_width
        flat = [kw_vals[i % kw_len] for i in range(key_total)]

        # Read off columns in all orderings of key_width columns
        for key_order in permutations(range(key_width)):
            key = []
            key_col_lens = [key_rows if c < (N % key_width) or N % key_width == 0 else key_rows - 1
                           for c in range(key_width)]
            # Actually: recalculate properly
            if N % key_width == 0:
                key_col_lens = [key_rows] * key_width
            else:
                key_col_lens = [key_rows if c < (N % key_width) else key_rows - 1
                               for c in range(key_width)]

            for col in key_order:
                for row in range(key_col_lens[col]):
                    key.append(flat[row * key_width + col])

            if len(key) < N:
                continue
            key = key[:N]

            # Test direct
            for var_sign in (1, -1):
                cribs = check_cribs(key, var_sign)
                configs_p4 += 1
                if cribs > best_p4['cribs']:
                    vname = 'vig' if var_sign == 1 else 'beau'
                    best_p4 = {'cribs': cribs, 'keyword': kw, 'key_width': key_width,
                               'key_order': list(key_order), 'variant': vname, 'trans': 'direct'}
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 {kw} kw={key_width} ko={list(key_order)} {vname}")

            if time.time() - t6 > 300:
                break
        if time.time() - t6 > 300:
            break

        # Also test with width-7 columnar on top (skip for key_width > 5 to limit combos)
        if key_width <= 5:
            for ct_order in permutations(range(WIDTH)):
                inv_perm = build_inv_perm(ct_order)
                # Re-read key for this key_order
                key = []
                for col in key_order:
                    for row in range(key_col_lens[col]):
                        key.append(flat[row * key_width + col])
                if len(key) < N:
                    continue
                key = key[:N]

                for var_sign in (1, -1):
                    cribs = check_cribs(key, var_sign, inv_perm)
                    configs_p4 += 1
                    if cribs > best_p4['cribs']:
                        vname = 'vig' if var_sign == 1 else 'beau'
                        best_p4 = {'cribs': cribs, 'keyword': kw, 'key_width': key_width,
                                   'key_order': list(key_order), 'variant': vname,
                                   'ct_order': list(ct_order)}
                        if cribs >= 10:
                            print(f"  ** HIT: {cribs}/24 {kw} kw={key_width} ko={list(key_order)} {vname} ct={list(ct_order)}")

                if time.time() - t6 > 300:
                    break
            if time.time() - t6 > 300:
                break

    if time.time() - t6 > 300:
        print(f"  Phase 4 timeout after {kw}, {configs_p4:,} configs")
        break

t7 = time.time()
print(f"  {configs_p4:,} configs, {t7-t6:.1f}s, best={best_p4['cribs']}/24")

# ── Phase 5: Quagmire variants (keyed alphabet Vigenère) ──────────────────
print("\n" + "-" * 50)
print("Phase 5: Quagmire variants (keyed alphabet rows/columns)")
print("-" * 50)

best_p5 = {'cribs': 0}
configs_p5 = 0
t8 = time.time()

for pt_kw in KEYWORDS[:15]:
    pt_alpha = mixed_alphabet(pt_kw)
    pt_idx_map = {c: i for i, c in enumerate(pt_alpha)}

    for ct_kw in KEYWORDS[:15]:
        ct_alpha = mixed_alphabet(ct_kw)
        ct_idx_from = {i: IDX[c] for i, c in enumerate(ct_alpha)}  # position in ct_alpha → standard index

        for key_kw in KEYWORDS[:15]:
            key_vals = [IDX[c] for c in key_kw if c in AZ]
            key_len = len(key_vals)
            if key_len == 0:
                continue

            # Quagmire I: PT alphabet keyed, CT standard, periodic key
            # Encrypt: find PT letter in pt_alpha, shift by key, read from standard
            # This is equivalent to: sub_pt first, then Vig with key
            # Since periodic Vig is eliminated, skip pure periodic

            # Quagmire with progressive key:
            for inc in range(1, 26):
                key = [(key_vals[i % key_len] + (i // key_len) * inc) % 26 for i in range(N)]

                # Apply Quagmire I: PT → position in pt_alpha → shift by key → CT from standard
                # CT[i] = standard_alpha[(pt_idx_map[PT[i]] + key[i]) % 26]
                # So: pt_idx_map[PT[i]] = (standard_idx(CT[i]) - key[i]) % 26
                # PT[i] = pt_alpha[(IDX[CT[i]] - key[i]) % 26]
                cribs = 0
                for p, expected in crib_items:
                    pt_pos = (CT_IDX[p] - key[p]) % 26
                    if pt_alpha[pt_pos] == expected:
                        cribs += 1
                configs_p5 += 1
                if cribs > best_p5['cribs']:
                    best_p5 = {'cribs': cribs, 'pt_kw': pt_kw, 'key_kw': key_kw,
                               'increment': inc, 'type': 'quagmire_I_prog'}
                    if cribs >= 10:
                        print(f"  ** HIT: {cribs}/24 QI pt={pt_kw} key={key_kw} inc={inc}")

        if time.time() - t8 > 300:
            break
    if time.time() - t8 > 300:
        print(f"  Phase 5 timeout, {configs_p5:,} configs")
        break

t9 = time.time()
print(f"  {configs_p5:,} configs, {t9-t8:.1f}s, best={best_p5['cribs']}/24")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Phase 1 (progressive key): best {best_p1['cribs']}/24 — {best_p1}")
print(f"  Phase 2 (matrix-read key): best {best_p2['cribs']}/24 — {best_p2}")
print(f"  Phase 3 (keyed Caesar/row): best {best_p3['cribs']}/24 — {best_p3}")
print(f"  Phase 4 (transposed keyword key): best {best_p4['cribs']}/24 — {best_p4}")
print(f"  Phase 5 (Quagmire variants): best {best_p5['cribs']}/24 — {best_p5}")

max_cribs = max(best_p1['cribs'], best_p2['cribs'], best_p3['cribs'],
                best_p4['cribs'], best_p5['cribs'])
if max_cribs >= 18:
    verdict = f"SIGNAL — {max_cribs}/24"
elif max_cribs >= 10:
    verdict = f"WEAK SIGNAL — {max_cribs}/24"
else:
    verdict = f"NO SIGNAL — best {max_cribs}/24"

print(f"\n  Verdict: {verdict}")
total = configs_p1 + configs_p2 + configs_p3 + configs_p4 + configs_p5
print(f"  Total configs: {total:,}")

output = {
    'experiment': 'E-S-68',
    'description': 'Matrix-based key generation + width-7 columnar',
    'phase1': best_p1,
    'phase2': best_p2,
    'phase3': best_p3,
    'phase4': best_p4,
    'phase5': best_p5,
    'verdict': verdict,
    'total_configs': total,
}
os.makedirs("results", exist_ok=True)
with open("results/e_s_68_matrix_key.json", "w") as f:
    json.dump(output, f, indent=2)
print(f"\n  Artifact: results/e_s_68_matrix_key.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_68_matrix_key_generation.py")
