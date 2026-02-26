#!/usr/bin/env python3
"""E-CHART-11: K3-style rotation-based transposition at various grid widths.

K3 was encoded using a physical grid rotation method:
1. Write K3 plaintext into a 42x8 grid (row by row)
2. Rotate the grid 90 degrees clockwise
3. Read the rotated grid row by row into a new grid
4. Rotate again, read row by row -> ciphertext

K4 could use the SAME rotation concept but with different grid dimensions.
K4 has 97 chars (prime), but various grid sizes are possible with padding
or partial last rows. Inserting 2 chars makes 99 = 9x11.

Phases:
1. Single rotation at widths 7-14, 97 with 4 rotations x 4 write x 4 read dirs
2. Double rotation (K3 method) at widths 8-11
3. 2-char insertion (99 chars = 9x11 perfect fit)
4. Top rotation configs + keyword substitution
"""
import json
import itertools
import os
import sys
import time

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, CRIB_DICT, N_CRIBS
from kryptos.kernel.scoring.aggregate import score_candidate


def quick_crib_score(pt):
    """Fast crib scoring."""
    return sum(1 for pos, ch in CRIB_DICT.items()
               if pos < len(pt) and pt[pos] == ch)


def vig_decrypt(ct, key):
    pt = []
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % len(key)]]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def beau_decrypt(ct, key):
    pt = []
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % len(key)]]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


# ── Grid Operations ──────────────────────────────────────────────────────

def make_grid(text, width, direction='row_lr'):
    """Write text into a 2D grid using specified direction.

    Directions:
      row_lr:  row by row, left to right (standard)
      row_rl:  row by row, right to left
      col_tb:  column by column, top to bottom
      col_bt:  column by column, bottom to top
    """
    n = len(text)
    nrows = (n + width - 1) // width

    if direction == 'row_lr':
        grid = []
        for r in range(nrows):
            row = list(text[r * width:(r + 1) * width])
            grid.append(row)
        return grid

    elif direction == 'row_rl':
        grid = []
        for r in range(nrows):
            row = list(text[r * width:(r + 1) * width])
            row.reverse()
            grid.append(row)
        return grid

    elif direction == 'col_tb':
        # Fill column by column, top to bottom
        ncols = width
        grid = [[''] * ncols for _ in range(nrows)]
        idx = 0
        for c in range(ncols):
            for r in range(nrows):
                if idx < n:
                    grid[r][c] = text[idx]
                    idx += 1
        return grid

    elif direction == 'col_bt':
        # Fill column by column, bottom to top
        ncols = width
        grid = [[''] * ncols for _ in range(nrows)]
        idx = 0
        for c in range(ncols):
            for r in range(nrows - 1, -1, -1):
                if idx < n:
                    grid[r][c] = text[idx]
                    idx += 1
        return grid

    raise ValueError(f"Unknown direction: {direction}")


def read_grid(grid, direction='row_lr'):
    """Read text from a 2D grid using specified direction.

    Same direction options as make_grid.
    """
    result = []
    nrows = len(grid)
    ncols = max(len(r) for r in grid) if grid else 0

    if direction == 'row_lr':
        for r in range(nrows):
            for c in range(len(grid[r])):
                if grid[r][c]:
                    result.append(grid[r][c])

    elif direction == 'row_rl':
        for r in range(nrows):
            for c in range(len(grid[r]) - 1, -1, -1):
                if grid[r][c]:
                    result.append(grid[r][c])

    elif direction == 'col_tb':
        for c in range(ncols):
            for r in range(nrows):
                if c < len(grid[r]) and grid[r][c]:
                    result.append(grid[r][c])

    elif direction == 'col_bt':
        for c in range(ncols):
            for r in range(nrows - 1, -1, -1):
                if c < len(grid[r]) and grid[r][c]:
                    result.append(grid[r][c])

    return ''.join(result)


def rotate_90_cw(grid):
    """Rotate 2D grid 90 degrees clockwise.
    transpose + reverse each row.
    New grid: rotated[c][nrows-1-r] = grid[r][c]
    Or equivalently: for each column c (left to right), read rows bottom to top.
    """
    nrows = len(grid)
    ncols = max(len(r) for r in grid) if grid else 0

    rotated = []
    for c in range(ncols):
        new_row = []
        for r in range(nrows - 1, -1, -1):
            if c < len(grid[r]) and grid[r][c]:
                new_row.append(grid[r][c])
            # Skip empty cells (incomplete last row)
        rotated.append(new_row)
    return rotated


def rotate_90_ccw(grid):
    """Rotate 2D grid 90 degrees counter-clockwise.
    For each column c (right to left), read rows top to bottom.
    """
    nrows = len(grid)
    ncols = max(len(r) for r in grid) if grid else 0

    rotated = []
    for c in range(ncols - 1, -1, -1):
        new_row = []
        for r in range(nrows):
            if c < len(grid[r]) and grid[r][c]:
                new_row.append(grid[r][c])
        rotated.append(new_row)
    return rotated


def rotate_180(grid):
    """Rotate 2D grid 180 degrees. Reverse order of all cells."""
    nrows = len(grid)
    ncols = max(len(r) for r in grid) if grid else 0

    # Flatten, reverse, refill
    flat = []
    for r in range(nrows):
        for c in range(len(grid[r])):
            if grid[r][c]:
                flat.append(grid[r][c])
    flat.reverse()

    rotated = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(ncols):
            if idx < len(flat):
                row.append(flat[idx])
                idx += 1
        rotated.append(row)
    return rotated


ROTATIONS = {
    '90cw': rotate_90_cw,
    '90ccw': rotate_90_ccw,
    '180': rotate_180,
    '270': lambda g: rotate_90_ccw(g),  # 270 CW = 90 CCW (already have it)
}
# Note: 270 CW is same as 90 CCW, but we keep both labels for clarity.
# Actually 270 CW = 90 CCW. Let's make 270 = three 90CW rotations to be precise.
ROTATIONS['270'] = lambda g: rotate_90_cw(rotate_90_cw(rotate_90_cw(g)))

WRITE_DIRS = ['row_lr', 'row_rl', 'col_tb', 'col_bt']
READ_DIRS = ['row_lr', 'row_rl', 'col_tb', 'col_bt']


def apply_rotation_decrypt(text, width, rotation_name, write_dir, read_dir):
    """Apply rotation-based transposition to decrypt.

    For encryption: write PT into grid (write_dir), rotate, read CT (read_dir).
    For decryption: write CT into grid (INVERSE of read_dir), inverse-rotate,
                    read PT (INVERSE of write_dir).

    But since we're testing all combinations anyway, we can just test all:
    write CT into grid (write_dir), rotate, read out (read_dir).
    """
    grid = make_grid(text, width, write_dir)
    rot_func = ROTATIONS[rotation_name]
    rotated = rot_func(grid)
    return read_grid(rotated, read_dir)


# ═══════════════════════════════════════════════════════════════════════
print("=" * 70)
print("E-CHART-11: K3-Style Rotation-Based Transposition")
print("=" * 70)

results = []
global_best = 0
global_best_config = ""
t0 = time.time()
total_configs = 0

# ── Phase 1: Single rotation at various widths ──────────────────────

print("\n--- Phase 1: Single rotation at various widths ---")
print("  Widths: 7-14, 97")
print(f"  Rotations: {list(ROTATIONS.keys())}")
print(f"  Write dirs: {WRITE_DIRS}")
print(f"  Read dirs: {READ_DIRS}")

p1_best = 0
p1_count = 0
p1_best_configs = []

WIDTHS = [7, 8, 9, 10, 11, 12, 13, 14, 97]

for width in WIDTHS:
    w_best = 0
    for rot_name in ROTATIONS:
        for wd in WRITE_DIRS:
            for rd in READ_DIRS:
                pt = apply_rotation_decrypt(CT, width, rot_name, wd, rd)
                sc = quick_crib_score(pt[:CT_LEN])
                p1_count += 1

                if sc > w_best:
                    w_best = sc
                if sc > p1_best:
                    p1_best = sc
                    cfg = f"w{width}/{rot_name}/write={wd}/read={rd}"
                    global_best_config = cfg
                    print(f"  NEW BEST: {sc}/24 -- {cfg}")
                    if sc >= 8:
                        print(f"    PT: {pt[:70]}...")
                if sc >= 7:
                    p1_best_configs.append({
                        'width': width, 'rot': rot_name,
                        'write': wd, 'read': rd, 'score': sc,
                        'pt': pt[:CT_LEN]
                    })
    # Summary per width
    print(f"  w{width}: best {w_best}/24")

if p1_best > global_best:
    global_best = p1_best
    total_configs += p1_count
print(f"  Phase 1 total: {p1_count} configs, best {p1_best}/24")

# ── Phase 2: Double rotation (K3 method) ────────────────────────────

print("\n--- Phase 2: Double rotation (K3 method) ---")
print("  width1 x width2 in [8, 9, 10, 11]")
print("  Two consecutive 90CW rotations (as in K3), plus 90CW+90CCW, etc.")

p2_best = 0
p2_count = 0
p2_best_configs = []

DOUBLE_WIDTHS = [8, 9, 10, 11]
# K3 method: write row-by-row, rotate 90CW, read row-by-row -> intermediate
# Then write intermediate row-by-row into grid2, rotate 90CW, read row-by-row -> CT
# To decrypt: reverse the process.

ROTATION_PAIRS = [
    ('90cw', '90cw'),     # K3 exact method
    ('90cw', '90ccw'),
    ('90ccw', '90cw'),
    ('90ccw', '90ccw'),
    ('90cw', '180'),
    ('180', '90cw'),
]

for w1 in DOUBLE_WIDTHS:
    for w2 in DOUBLE_WIDTHS:
        for rot1_name, rot2_name in ROTATION_PAIRS:
            # DECRYPT direction: reverse the encryption.
            # Encryption: PT -> grid1(w1) -> rot1 -> read row -> grid2(w2) -> rot2 -> read row -> CT
            # Decryption: CT -> grid2(w2) with inverse read -> inv_rot2 -> read -> grid1(w1) with inv read -> inv_rot1 -> read -> PT

            # But since rotations are their own inverse in different combos,
            # let's just test both directions:

            # Direction A: CT -> write_row(w1) -> rot1 -> read_row -> write_row(w2) -> rot2 -> read_row -> PT
            grid1 = make_grid(CT, w1, 'row_lr')
            rotated1 = ROTATIONS[rot1_name](grid1)
            intermediate = read_grid(rotated1, 'row_lr')

            grid2 = make_grid(intermediate, w2, 'row_lr')
            rotated2 = ROTATIONS[rot2_name](grid2)
            pt = read_grid(rotated2, 'row_lr')

            sc = quick_crib_score(pt[:CT_LEN])
            p2_count += 1

            if sc > p2_best:
                p2_best = sc
                cfg = f"double/w1={w1}/w2={w2}/rot1={rot1_name}/rot2={rot2_name}/dir=A"
                print(f"  NEW BEST: {sc}/24 -- {cfg}")
                if sc >= 8:
                    print(f"    PT: {pt[:70]}...")
            if sc >= 7:
                p2_best_configs.append({
                    'w1': w1, 'w2': w2, 'rot1': rot1_name, 'rot2': rot2_name,
                    'direction': 'A', 'score': sc, 'pt': pt[:CT_LEN]
                })

            # Direction B: reverse order of operations
            # CT -> write_row(w2) -> rot2 -> read_row -> write_row(w1) -> rot1 -> read_row -> PT
            grid2b = make_grid(CT, w2, 'row_lr')
            rotated2b = ROTATIONS[rot2_name](grid2b)
            intermediate_b = read_grid(rotated2b, 'row_lr')

            grid1b = make_grid(intermediate_b, w1, 'row_lr')
            rotated1b = ROTATIONS[rot1_name](grid1b)
            pt_b = read_grid(rotated1b, 'row_lr')

            sc_b = quick_crib_score(pt_b[:CT_LEN])
            p2_count += 1

            if sc_b > p2_best:
                p2_best = sc_b
                cfg = f"double/w1={w2}/w2={w1}/rot1={rot2_name}/rot2={rot1_name}/dir=B"
                print(f"  NEW BEST: {sc_b}/24 -- {cfg}")
                if sc_b >= 8:
                    print(f"    PT: {pt_b[:70]}...")
            if sc_b >= 7:
                p2_best_configs.append({
                    'w1': w2, 'w2': w1, 'rot1': rot2_name, 'rot2': rot1_name,
                    'direction': 'B', 'score': sc_b, 'pt': pt_b[:CT_LEN]
                })

print(f"  Phase 2 total: {p2_count} configs, best {p2_best}/24")
if p2_best > global_best:
    global_best = p2_best
total_configs += p2_count

# Also test with all write/read direction combinations for the K3-exact variant
print("\n  Phase 2b: K3-exact (90cw+90cw) with all write/read dirs at key widths...")
p2b_best = 0
p2b_count = 0

for w1 in [8, 9, 10, 11]:
    for w2 in [8, 9, 10, 11]:
        for wd1 in WRITE_DIRS:
            for rd1 in READ_DIRS:
                for wd2 in WRITE_DIRS:
                    for rd2 in READ_DIRS:
                        grid1 = make_grid(CT, w1, wd1)
                        rotated1 = rotate_90_cw(grid1)
                        intermediate = read_grid(rotated1, rd1)

                        grid2 = make_grid(intermediate, w2, wd2)
                        rotated2 = rotate_90_cw(grid2)
                        pt = read_grid(rotated2, rd2)

                        sc = quick_crib_score(pt[:CT_LEN])
                        p2b_count += 1

                        if sc > p2b_best:
                            p2b_best = sc
                            cfg = f"K3exact/w1={w1}({wd1}->{rd1})/w2={w2}({wd2}->{rd2})"
                            print(f"  NEW BEST: {sc}/24 -- {cfg}")
                            if sc >= 8:
                                print(f"    PT: {pt[:70]}...")
                        if sc >= 7:
                            p2_best_configs.append({
                                'w1': w1, 'w2': w2, 'wd1': wd1, 'rd1': rd1,
                                'wd2': wd2, 'rd2': rd2, 'score': sc,
                                'pt': pt[:CT_LEN]
                            })

print(f"  Phase 2b total: {p2b_count} configs, best {p2b_best}/24")
if p2b_best > global_best:
    global_best = p2b_best
total_configs += p2b_count

# ── Phase 3: 2-char insertion to make 99 = 9x11 ────────────────────

print("\n--- Phase 3: 2-char insertion (99 chars = 9x11 perfect grid) ---")

INSERTION_CHARS = [
    ('C', 'C'),   # Checkpoint Charlie
    ('Y', 'R'),   # YAR
    ('Y', 'A'),   # YAR
    ('A', 'R'),   # YAR
    ('L', 'L'),   # Extra L / HILL
    ('E', 'E'),   # Extra E's
]

# Strategic insertion positions near/between cribs or at boundaries
INSERTION_POSITIONS = list(range(0, CT_LEN + 1, 1))  # All positions

# Use a subset of rotations for speed (most interesting ones)
P3_ROTATIONS = ['90cw', '90ccw', '180']
P3_WRITE_DIRS = ['row_lr', 'col_tb']
P3_READ_DIRS = ['row_lr', 'col_tb']

p3_best = 0
p3_count = 0
p3_best_configs = []

for c1, c2 in INSERTION_CHARS:
    pair_label = f"{c1}{c2}"
    pair_best = 0

    for ins_pos in INSERTION_POSITIONS:
        extended = CT[:ins_pos] + c1 + c2 + CT[ins_pos:]
        assert len(extended) == 99, f"Expected 99, got {len(extended)}"

        # Only test width=9 (9x11 perfect grid) and width=11 (11x9)
        for width in [9, 11]:
            for rot_name in P3_ROTATIONS:
                for wd in P3_WRITE_DIRS:
                    for rd in P3_READ_DIRS:
                        grid = make_grid(extended, width, wd)
                        rotated = ROTATIONS[rot_name](grid)
                        pt_full = read_grid(rotated, rd)

                        # Score the full 99-char PT against cribs
                        sc99 = quick_crib_score(pt_full[:99])

                        # Also score with inserted chars removed
                        # Find where the inserted chars ended up in PT
                        # (this is complex with rotations, so just try both approaches)
                        # Approach: remove chars at the insertion position from PT
                        pt97 = pt_full[:ins_pos] + pt_full[ins_pos + 2:]
                        sc97 = quick_crib_score(pt97[:CT_LEN])

                        sc = max(sc99, sc97)
                        p3_count += 1

                        if sc > pair_best:
                            pair_best = sc
                        if sc > p3_best:
                            p3_best = sc
                            cfg = f"insert={pair_label}@{ins_pos}/w{width}/{rot_name}/wr={wd}/rd={rd}/sc99={sc99}/sc97={sc97}"
                            print(f"  NEW BEST: {sc}/24 -- {cfg}")
                            if sc >= 8:
                                print(f"    PT99: {pt_full[:70]}")
                                print(f"    PT97: {pt97[:70]}")
                        if sc >= 7:
                            p3_best_configs.append({
                                'insert': pair_label, 'ins_pos': ins_pos,
                                'width': width, 'rot': rot_name,
                                'write': wd, 'read': rd,
                                'sc99': sc99, 'sc97': sc97,
                                'score': sc, 'pt': (pt97 if sc97 >= sc99 else pt_full)[:CT_LEN]
                            })

    if pair_best >= 5:
        print(f"  {pair_label}: best {pair_best}/24")

print(f"  Phase 3 total: {p3_count} configs, best {p3_best}/24")
if p3_best > global_best:
    global_best = p3_best
total_configs += p3_count

# Also do double rotation with 9x11 perfect grid (CC insertion)
print("\n  Phase 3b: Double rotation with 9x11 perfect grid (CC insertion)...")
p3b_best = 0
p3b_count = 0

# Only test CC at a few strategic positions with double 90CW rotation
CC_STRATEGIC = [0, 20, 21, 33, 34, 48, 62, 63, 73, 74, 96, 97]

for ins_pos in CC_STRATEGIC:
    extended = CT[:ins_pos] + 'CC' + CT[ins_pos:]
    assert len(extended) == 99

    for w1 in [9, 11]:
        for w2 in [9, 11]:
            # Double 90CW (K3 exact)
            grid1 = make_grid(extended, w1, 'row_lr')
            rot1 = rotate_90_cw(grid1)
            inter = read_grid(rot1, 'row_lr')

            grid2 = make_grid(inter, w2, 'row_lr')
            rot2 = rotate_90_cw(grid2)
            pt_full = read_grid(rot2, 'row_lr')

            sc99 = quick_crib_score(pt_full[:99])
            pt97 = pt_full[:ins_pos] + pt_full[ins_pos + 2:]
            sc97 = quick_crib_score(pt97[:CT_LEN])
            sc = max(sc99, sc97)
            p3b_count += 1

            if sc > p3b_best:
                p3b_best = sc
                cfg = f"CC@{ins_pos}/double90cw/w1={w1}/w2={w2}"
                print(f"  NEW BEST: {sc}/24 -- {cfg}")
                if sc >= 8:
                    print(f"    PT: {(pt97 if sc97 >= sc99 else pt_full)[:70]}")

            # Also try 90CCW + 90CCW
            grid1c = make_grid(extended, w1, 'row_lr')
            rot1c = rotate_90_ccw(grid1c)
            inter_c = read_grid(rot1c, 'row_lr')

            grid2c = make_grid(inter_c, w2, 'row_lr')
            rot2c = rotate_90_ccw(grid2c)
            pt_full_c = read_grid(rot2c, 'row_lr')

            sc99c = quick_crib_score(pt_full_c[:99])
            pt97c = pt_full_c[:ins_pos] + pt_full_c[ins_pos + 2:]
            sc97c = quick_crib_score(pt97c[:CT_LEN])
            sc_c = max(sc99c, sc97c)
            p3b_count += 1

            if sc_c > p3b_best:
                p3b_best = sc_c
                cfg = f"CC@{ins_pos}/double90ccw/w1={w1}/w2={w2}"
                print(f"  NEW BEST: {sc_c}/24 -- {cfg}")

print(f"  Phase 3b total: {p3b_count} configs, best {p3b_best}/24")
if p3b_best > global_best:
    global_best = p3b_best
total_configs += p3b_count

# ── Phase 4: Rotation + keyword substitution ────────────────────────

print("\n--- Phase 4: Top rotation configs + keyword substitution ---")
KEYWORDS = ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'HERBERT', 'CHECKPOINT',
            'BERLIN', 'GOLD', 'CHARLIE', 'CARTER', 'CLOCKWORK', 'EASTNORTHEAST']

# Collect all configs scoring 3+ from phases 1-3 to test with substitution
# For Phase 1, test all width/rotation combos (no permutations, so it's fast)
p4_best = 0
p4_count = 0
p4_best_configs = []

print("  Testing all Phase 1 rotation configs with keywords...")

for width in WIDTHS:
    for rot_name in ROTATIONS:
        for wd in WRITE_DIRS:
            for rd in READ_DIRS:
                pt_trans = apply_rotation_decrypt(CT, width, rot_name, wd, rd)
                if len(pt_trans) < CT_LEN:
                    continue

                for keyword in KEYWORDS:
                    # Vigenere decrypt
                    pt_v = vig_decrypt(pt_trans[:CT_LEN], keyword)
                    sc_v = quick_crib_score(pt_v)
                    p4_count += 1

                    # Beaufort decrypt
                    pt_b = beau_decrypt(pt_trans[:CT_LEN], keyword)
                    sc_b = quick_crib_score(pt_b)
                    p4_count += 1

                    sc = max(sc_v, sc_b)
                    variant = 'vig' if sc_v >= sc_b else 'beau'
                    pt_best = pt_v if sc_v >= sc_b else pt_b

                    if sc > p4_best:
                        p4_best = sc
                        cfg = f"rot(w{width}/{rot_name}/{wd}->{rd})+{variant}/{keyword}"
                        print(f"  NEW BEST: {sc}/24 -- {cfg}")
                        if sc >= 8:
                            print(f"    PT: {pt_best[:70]}...")
                    if sc >= 7:
                        p4_best_configs.append({
                            'width': width, 'rot': rot_name,
                            'write': wd, 'read': rd,
                            'variant': variant, 'keyword': keyword,
                            'score': sc, 'pt': pt_best[:CT_LEN]
                        })

                    # Also try: substitute FIRST, then rotate
                    ct_v = vig_decrypt(CT, keyword)
                    ct_b = beau_decrypt(CT, keyword)

                    for ct_sub, sub_label in [(ct_v, 'vig'), (ct_b, 'beau')]:
                        pt_sr = apply_rotation_decrypt(ct_sub, width, rot_name, wd, rd)
                        sc_sr = quick_crib_score(pt_sr[:CT_LEN])
                        p4_count += 1

                        if sc_sr > p4_best:
                            p4_best = sc_sr
                            cfg = f"{sub_label}/{keyword}+rot(w{width}/{rot_name}/{wd}->{rd})"
                            print(f"  NEW BEST: {sc_sr}/24 -- {cfg}")
                            if sc_sr >= 8:
                                print(f"    PT: {pt_sr[:70]}...")
                        if sc_sr >= 7:
                            p4_best_configs.append({
                                'width': width, 'rot': rot_name,
                                'write': wd, 'read': rd,
                                'variant': sub_label, 'keyword': keyword,
                                'order': 'sub_first', 'score': sc_sr,
                                'pt': pt_sr[:CT_LEN]
                            })

print(f"  Phase 4 total: {p4_count} configs, best {p4_best}/24")
if p4_best > global_best:
    global_best = p4_best
total_configs += p4_count

# ── Phase 5: Triple rotation (write into grid, rotate, read, repeat 3x) ──

print("\n--- Phase 5: Triple rotation ---")
p5_best = 0
p5_count = 0

for w1 in [8, 9, 10, 11]:
    for w2 in [8, 9, 10, 11]:
        for w3 in [8, 9, 10, 11]:
            # All 90CW rotations
            grid1 = make_grid(CT, w1, 'row_lr')
            r1 = rotate_90_cw(grid1)
            inter1 = read_grid(r1, 'row_lr')

            grid2 = make_grid(inter1, w2, 'row_lr')
            r2 = rotate_90_cw(grid2)
            inter2 = read_grid(r2, 'row_lr')

            grid3 = make_grid(inter2, w3, 'row_lr')
            r3 = rotate_90_cw(grid3)
            pt = read_grid(r3, 'row_lr')

            sc = quick_crib_score(pt[:CT_LEN])
            p5_count += 1

            if sc > p5_best:
                p5_best = sc
                cfg = f"triple90cw/w1={w1}/w2={w2}/w3={w3}"
                print(f"  NEW BEST: {sc}/24 -- {cfg}")
                if sc >= 8:
                    print(f"    PT: {pt[:70]}...")

print(f"  Phase 5 total: {p5_count} configs, best {p5_best}/24")
if p5_best > global_best:
    global_best = p5_best
total_configs += p5_count

# ── Phase 6: Wider width sweep with single rotation + keyword ───────

print("\n--- Phase 6: Extended width sweep (widths 15-48) single rotation ---")
p6_best = 0
p6_count = 0

WIDE_WIDTHS = list(range(15, 49))

for width in WIDE_WIDTHS:
    for rot_name in ['90cw', '90ccw']:
        for wd in ['row_lr', 'col_tb']:
            for rd in ['row_lr', 'col_tb']:
                pt = apply_rotation_decrypt(CT, width, rot_name, wd, rd)
                sc = quick_crib_score(pt[:CT_LEN])
                p6_count += 1

                if sc > p6_best:
                    p6_best = sc
                    cfg = f"w{width}/{rot_name}/{wd}->{rd}"
                    print(f"  NEW BEST: {sc}/24 -- {cfg}")
                    if sc >= 8:
                        print(f"    PT: {pt[:70]}...")

print(f"  Phase 6 total: {p6_count} configs, best {p6_best}/24")
if p6_best > global_best:
    global_best = p6_best
total_configs += p6_count

# ── Full scoring for anything >= 7 ──

print("\n--- Full scoring for configs >= 7/24 ---")
all_notable = (
    [(c, 'P1') for c in p1_best_configs if c['score'] >= 7] +
    [(c, 'P2') for c in p2_best_configs if c['score'] >= 7] +
    [(c, 'P3') for c in p3_best_configs if c['score'] >= 7] +
    [(c, 'P4') for c in p4_best_configs if c['score'] >= 7]
)

for cfg, phase in all_notable:
    pt = cfg['pt']
    if len(pt) >= CT_LEN:
        sb = score_candidate(pt[:CT_LEN])
        print(f"  [{phase}] {sb.summary} -- score={cfg['score']}")
        cfg['full_score'] = sb.to_dict()

# ── Summary ──────────────────────────────────────────────────────────

elapsed = time.time() - t0
print(f"\n{'=' * 70}")
print(f"E-CHART-11: K3-Style Rotation Summary")
print(f"{'=' * 70}")
print(f"Total configs tested: {total_configs}")
print(f"Time: {elapsed:.1f}s")
print(f"Phase 1 (single rotation):  best {p1_best}/24")
print(f"Phase 2 (double rotation):  best {max(p2_best, p2b_best)}/24")
print(f"Phase 3 (2-char insert):    best {max(p3_best, p3b_best)}/24")
print(f"Phase 4 (rot + keyword):    best {p4_best}/24")
print(f"Phase 5 (triple rotation):  best {p5_best}/24")
print(f"Phase 6 (wide widths):      best {p6_best}/24")
print(f"GLOBAL BEST: {global_best}/24")

if global_best <= 6:
    classification = "NOISE"
elif global_best <= 9:
    classification = "NOISE (marginal)"
elif global_best <= 17:
    classification = "STORE"
else:
    classification = "SIGNAL -- INVESTIGATE!"

print(f"CLASSIFICATION: {classification}")
print(f"{'=' * 70}")

# ── Save results ─────────────────────────────────────────────────────

os.makedirs('results', exist_ok=True)

output = {
    'experiment': 'E-CHART-11',
    'description': 'K3-style rotation-based transposition at various grid widths',
    'total_configs': total_configs,
    'elapsed_seconds': round(elapsed, 1),
    'global_best': global_best,
    'classification': classification,
    'phase_results': {
        'phase1_single_rotation': {'configs': p1_count, 'best': p1_best},
        'phase2_double_rotation': {'configs': p2_count + p2b_count, 'best': max(p2_best, p2b_best)},
        'phase3_insertion': {'configs': p3_count + p3b_count, 'best': max(p3_best, p3b_best)},
        'phase4_rot_plus_keyword': {'configs': p4_count, 'best': p4_best},
        'phase5_triple_rotation': {'configs': p5_count, 'best': p5_best},
        'phase6_wide_widths': {'configs': p6_count, 'best': p6_best},
    },
    'notable_results': [c for c in
        p1_best_configs + p2_best_configs + p3_best_configs + p4_best_configs
        if c.get('score', 0) >= 7
    ],
}

with open('results/e_chart_11_rotation.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"\nArtifact: results/e_chart_11_rotation.json")
