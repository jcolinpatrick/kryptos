#!/usr/bin/env python3
"""E-CHART-07: Width-9 grid with inserted characters (CC hypothesis).

Theory: K4's chart is a 9×11 grid (99 cells). The sculpture has 97 chars,
meaning 2 characters exist on the chart but were omitted from the carving.
These could be CC (Checkpoint Charlie), or letters from anomalies.

Tests:
1. Pure w9 transposition (no inserted chars) - all 9! orderings
2. Insert CC at all 100 possible position pairs - all 9! orderings
3. Insert other letter pairs from anomalies
4. Best configs + Vigenere/Beaufort with keywords
"""
import json, itertools, os, sys, time
from collections import defaultdict

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, CRIB_DICT, N_CRIBS
from kryptos.kernel.scoring.aggregate import score_candidate

def columnar_decrypt(ct, width, order):
    """Decrypt columnar transposition. order[i] = which column is read i-th."""
    n = len(ct)
    nrows = (n + width - 1) // width
    ncols = width
    # Number of long columns (length nrows) vs short (length nrows-1)
    n_long = n - (nrows - 1) * ncols  # = n % ncols if n%ncols != 0, else ncols
    if n % ncols == 0:
        n_long = ncols

    # Determine length of each column based on order
    col_lens = [0] * ncols
    for col in range(ncols):
        if col < n_long:
            col_lens[col] = nrows
        else:
            col_lens[col] = nrows - 1

    # Split CT into columns according to reading order
    cols = {}
    pos = 0
    for rank in range(ncols):
        col_idx = order[rank]
        length = col_lens[col_idx]
        cols[col_idx] = ct[pos:pos+length]
        pos += length

    # Read row by row
    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(cols.get(col, '')):
                result.append(cols[col][row])
    return ''.join(result)

def quick_crib_score(pt):
    """Fast crib scoring without full score_candidate overhead."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == ch:
            matches += 1
    return matches

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

print("=" * 70)
print("E-CHART-07: Width-9 Grid with Inserted Characters")
print("=" * 70)

results = []
global_best = 0
global_config = ""
t0 = time.time()

# ── Phase 1: Pure width-9 transposition (97 chars, no insertion) ──
print("\n--- Phase 1: Pure w9 transposition, 97 chars ---")
p1_best = 0
p1_count = 0
for order in itertools.permutations(range(9)):
    pt = columnar_decrypt(CT, 9, list(order))
    sc = quick_crib_score(pt)
    p1_count += 1
    if sc > p1_best:
        p1_best = sc
        cfg = f"w9/order={list(order)}"
        print(f"  NEW BEST: {sc}/24 — {cfg}")
        if sc >= 8:
            print(f"    PT: {pt}")
            results.append({'phase': 1, 'score': sc, 'order': list(order), 'pt': pt[:60]})
if p1_best > global_best:
    global_best = p1_best
print(f"  Phase 1: {p1_count} configs, best {p1_best}/24")

# ── Phase 2: Insert CC at every position pair, then w9 transposition ──
# Insert 2 chars into CT to make 99 chars, then decrypt as 9×11 grid
print("\n--- Phase 2: Insert CC to make 99 chars, then w9 transposition ---")
# Strategy: for each single insertion point (insert both chars together: CC)
# Try CC at positions 0..97 (98 positions for consecutive CC)
p2_best = 0
p2_count = 0
p2_best_configs = []

# First pass: test CC inserted at each position with ALL orderings
# CC consecutive: 98 positions × 362,880 orderings = 35.6M - too many
# Instead: for each insertion position, test a SUBSET of orderings (identity, reverse,
# and any that scored well in Phase 1)
# Then do exhaustive on the best insertion positions.

# Collect top orderings from Phase 1
print("  Collecting top orderings from Phase 1 for pre-screening...")
top_orderings_p1 = []
for order in itertools.permutations(range(9)):
    pt = columnar_decrypt(CT, 9, list(order))
    sc = quick_crib_score(pt)
    if sc >= max(p1_best - 2, 3):
        top_orderings_p1.append((list(order), sc))
print(f"  {len(top_orderings_p1)} orderings within 2 of Phase 1 best")

# Also include identity, reverse, and some structured orderings
base_orderings = [
    list(range(9)),           # identity
    list(range(8, -1, -1)),   # reverse
    [1,3,5,7,0,2,4,6,8],     # odds-then-evens
    [0,2,4,6,8,1,3,5,7],     # evens-then-odds
]
for o in base_orderings:
    if o not in [x[0] for x in top_orderings_p1]:
        top_orderings_p1.append((o, 0))

INSERTION_CHARS_PAIRS = [
    ('C', 'C'),  # Checkpoint Charlie
    ('Y', 'R'),  # From YAR (missing A?)
    ('Y', 'A'),  # From YAR
    ('A', 'R'),  # From YAR
    ('D', 'Y'),  # From DYAR
    ('L', 'L'),  # Extra L → HILL (double L)
    ('E', 'E'),  # Extra E's from Morse
    ('Q', 'M'),  # ? = Q, M from unknown
    ('S', 'C'),  # Misspelling pair
    ('E', 'A'),  # Misspelling pair
    ('I', 'E'),  # Misspelling pair
    ('L', 'Q'),  # Misspelling pair
]

print(f"\n  Testing {len(INSERTION_CHARS_PAIRS)} char pairs × 98 positions × {len(top_orderings_p1)} orderings...")

for c1, c2 in INSERTION_CHARS_PAIRS:
    pair_best = 0
    pair_label = f"{c1}{c2}"
    for insert_pos in range(CT_LEN + 1):
        # Insert c1 and c2 consecutively at insert_pos
        extended = CT[:insert_pos] + c1 + c2 + CT[insert_pos:]
        assert len(extended) == 99, f"Expected 99, got {len(extended)}"

        for order, _ in top_orderings_p1:
            pt_full = columnar_decrypt(extended, 9, order)
            # Remove the inserted chars from the plaintext? No — the plaintext
            # includes them. The CT on the sculpture is the RESULT of removing
            # them from the full 99-char ciphertext.
            # Actually: the CHART has 99 chars. The transposition was done on 99 chars.
            # Then 2 chars were removed to produce the 97-char sculpture CT.
            # So to decrypt: reinsert 2 chars, then reverse the transposition.
            sc = quick_crib_score(pt_full[:97])  # PT is 99 chars, but cribs are at positions for 97-char text
            # Actually cribs are at absolute positions in the PLAINTEXT, which would be 99 chars
            # This is tricky — if PT is 99 chars, crib positions shift
            # Let's score both: the full 99-char PT, and also PT with the inserted chars removed

            # Score full 99-char PT (if cribs are at same absolute positions)
            sc99 = 0
            for pos, ch in CRIB_DICT.items():
                if pos < len(pt_full) and pt_full[pos] == ch:
                    sc99 += 1

            # Score with inserted chars removed from PT
            pt_removed = pt_full[:insert_pos] + pt_full[insert_pos+2:]
            sc97 = quick_crib_score(pt_removed)

            sc = max(sc99, sc97)
            p2_count += 1

            if sc > pair_best:
                pair_best = sc
            if sc > p2_best:
                p2_best = sc
                cfg = f"insert={pair_label}@{insert_pos}/order={order}/sc99={sc99}/sc97={sc97}"
                print(f"  NEW BEST: {sc}/24 — {cfg}")
                if sc >= 10:
                    print(f"    PT99: {pt_full}")
                    print(f"    PT97: {pt_removed[:60]}")
                if sc >= 8:
                    results.append({
                        'phase': 2, 'score': sc, 'insert': pair_label,
                        'insert_pos': insert_pos, 'order': order,
                        'pt99': pt_full[:60], 'pt97': pt_removed[:60],
                    })
    # print(f"    {pair_label}: best {pair_best}/24")

if p2_best > global_best:
    global_best = p2_best
print(f"  Phase 2: {p2_count} configs, best {p2_best}/24")

# ── Phase 3: Exhaustive w9 orderings for best insertion configs ──
print("\n--- Phase 3: Exhaustive w9 for best Phase 2 insertion positions ---")
# Find top insertion configs from Phase 2
p3_best = 0
p3_count = 0

# Test CC at a few strategic positions with ALL orderings
CC_STRATEGIC_POSITIONS = [0, 1, 20, 21, 33, 34, 48, 49, 62, 63, 73, 74, 95, 96, 97]

for insert_pos in CC_STRATEGIC_POSITIONS:
    extended = CT[:insert_pos] + 'C' + 'C' + CT[insert_pos:]
    pos_best = 0
    for order in itertools.permutations(range(9)):
        pt_full = columnar_decrypt(extended, 9, list(order))
        pt_removed = pt_full[:insert_pos] + pt_full[insert_pos+2:]
        sc = quick_crib_score(pt_removed)
        # Also check the 99-char version
        sc99 = 0
        for pos, ch in CRIB_DICT.items():
            if pos < len(pt_full) and pt_full[pos] == ch:
                sc99 += 1
        sc = max(sc, sc99)
        p3_count += 1
        if sc > pos_best:
            pos_best = sc
        if sc > p3_best:
            p3_best = sc
            cfg = f"CC@{insert_pos}/order={list(order)}"
            print(f"  NEW BEST: {sc}/24 — {cfg}")
            if sc >= 10:
                print(f"    PT: {pt_removed[:60]}...")
            if sc >= 8:
                results.append({
                    'phase': 3, 'score': sc, 'insert_pos': insert_pos,
                    'order': list(order), 'pt': pt_removed[:60],
                })
    print(f"    CC@{insert_pos}: best {pos_best}/24 ({362880} orderings)")

if p3_best > global_best:
    global_best = p3_best
print(f"  Phase 3: {p3_count} configs, best {p3_best}/24")

# ── Phase 4: Width-9 + keyword substitution (no insertion) ──
print("\n--- Phase 4: w9 transposition + keyword substitution ---")
p4_best = 0
p4_count = 0
KEYWORDS = ['KRYPTOS', 'HERBERT', 'STOPWATCH', 'PALIMPSEST', 'ABSCISSA',
            'GOLD', 'CHARLIE', 'CHECKPOINT', 'CARTER', 'BERLIN', 'YAR']

for keyword in KEYWORDS:
    kw_best = 0
    for order in itertools.permutations(range(9)):
        untrans = columnar_decrypt(CT, 9, list(order))
        # Model A: transpose then substitute
        pt_a = vig_decrypt(untrans, keyword)
        sc_a = quick_crib_score(pt_a)
        pt_b = beau_decrypt(untrans, keyword)
        sc_b = quick_crib_score(pt_b)
        sc = max(sc_a, sc_b)
        p4_count += 2
        if sc > kw_best:
            kw_best = sc
        if sc > p4_best:
            p4_best = sc
            variant = 'vig' if sc_a >= sc_b else 'beau'
            pt = pt_a if sc_a >= sc_b else pt_b
            cfg = f"w9+{variant}/{keyword}/order={list(order)}"
            print(f"  NEW BEST: {sc}/24 — {cfg}")
            if sc >= 10:
                print(f"    PT: {pt}")
            if sc >= 8:
                results.append({
                    'phase': 4, 'score': sc, 'keyword': keyword,
                    'variant': variant, 'order': list(order), 'pt': pt[:60],
                })
    print(f"    {keyword}: best {kw_best}/24")

if p4_best > global_best:
    global_best = p4_best
print(f"  Phase 4: {p4_count} configs, best {p4_best}/24")

# ── Phase 5: Non-columnar reading orders on 9×11 grid ──
print("\n--- Phase 5: Alternative reading orders on 9×11 grid ---")
p5_best = 0
p5_count = 0

def grid_write_rows(text, width):
    """Write text into grid row by row, return 2D grid."""
    nrows = (len(text) + width - 1) // width
    grid = []
    for r in range(nrows):
        row = text[r*width:(r+1)*width]
        grid.append(list(row))
    return grid

def read_spiral_cw(grid):
    """Read grid in clockwise spiral from top-left."""
    result = []
    if not grid:
        return ''
    rows = [list(r) for r in grid]
    while rows:
        # top row left to right
        result.extend(rows.pop(0))
        # right column top to bottom
        for r in rows:
            if r:
                result.append(r.pop())
        # bottom row right to left
        if rows:
            result.extend(reversed(rows.pop()))
        # left column bottom to top
        for r in reversed(rows):
            if r:
                result.append(r.pop(0))
    return ''.join(result)

def read_diagonal(grid, width, nrows):
    """Read grid in diagonal order."""
    result = []
    for d in range(width + nrows - 1):
        for r in range(nrows):
            c = d - r
            if 0 <= c < width and r < len(grid) and c < len(grid[r]):
                result.append(grid[r][c])
    return ''.join(result)

def read_boustrophedon(grid):
    """Read grid alternating left-to-right and right-to-left."""
    result = []
    for i, row in enumerate(grid):
        if i % 2 == 0:
            result.extend(row)
        else:
            result.extend(reversed(row))
    return ''.join(result)

# For each reading pattern, write CT into the grid with that pattern,
# then read out row-by-row to get the "plaintext"
# (reverse: write row-by-row, read with pattern = encrypt)
# So to decrypt: write CT with the pattern, read row-by-row

# Actually for a transposition cipher:
# Encrypt: write PT row-by-row into grid, read out with pattern
# Decrypt: write CT with the pattern, read row-by-row

# Let's try: assume CT was produced by reading a 9-wide grid in various orders
# To decrypt: we need to reverse the reading order

# Simple approach: try writing CT into the grid using each reading pattern,
# then reading row-by-row to recover PT

for width in [9, 10, 11]:
    nrows = (CT_LEN + width - 1) // width

    # Row-by-row write, column-by-column read (standard columnar — already tested)

    # Spiral read
    grid = grid_write_rows(CT, width)
    pt_spiral = read_spiral_cw([r[:] for r in grid])[:CT_LEN]
    sc = quick_crib_score(pt_spiral)
    p5_count += 1
    if sc > p5_best:
        p5_best = sc
        print(f"  NEW BEST: {sc}/24 — spiral_cw/w{width}")

    # Diagonal read
    pt_diag = read_diagonal(grid, width, nrows)[:CT_LEN]
    sc = quick_crib_score(pt_diag)
    p5_count += 1
    if sc > p5_best:
        p5_best = sc
        print(f"  NEW BEST: {sc}/24 — diagonal/w{width}")

    # Boustrophedon read
    pt_boust = read_boustrophedon(grid)[:CT_LEN]
    sc = quick_crib_score(pt_boust)
    p5_count += 1
    if sc > p5_best:
        p5_best = sc
        print(f"  NEW BEST: {sc}/24 — boustrophedon/w{width}")

    # Reverse spiral, reverse diagonal, reverse boustrophedon
    for name, pt in [('rev_spiral', pt_spiral[::-1]), ('rev_diag', pt_diag[::-1]),
                     ('rev_boust', pt_boust[::-1])]:
        sc = quick_crib_score(pt)
        p5_count += 1
        if sc > p5_best:
            p5_best = sc
            print(f"  NEW BEST: {sc}/24 — {name}/w{width}")

    # 90° rotation (like K3!)
    # Write into width×nrows grid, rotate 90° CW, read row-by-row
    # For K3: 42×8 grid rotated to 8×42, then rotated again
    # Rotation = transpose + reverse each row
    if all(len(r) == width for r in grid[:-1]):  # full rows except possibly last
        # Pad last row
        last_row = grid[-1] + [''] * (width - len(grid[-1]))
        padded = grid[:-1] + [last_row]

        # Rotate 90° CW: transpose then reverse each row
        rotated = []
        for c in range(width):
            new_row = []
            for r in range(len(padded) - 1, -1, -1):
                if padded[r][c]:
                    new_row.append(padded[r][c])
            rotated.append(new_row)
        pt_rot = ''.join(''.join(r) for r in rotated)[:CT_LEN]
        sc = quick_crib_score(pt_rot)
        p5_count += 1
        if sc > p5_best:
            p5_best = sc
            print(f"  NEW BEST: {sc}/24 — rotate90cw/w{width}")

        # Rotate 90° CCW
        rotated_ccw = []
        for c in range(width - 1, -1, -1):
            new_row = []
            for r in range(len(padded)):
                if padded[r][c]:
                    new_row.append(padded[r][c])
            rotated_ccw.append(new_row)
        pt_rot_ccw = ''.join(''.join(r) for r in rotated_ccw)[:CT_LEN]
        sc = quick_crib_score(pt_rot_ccw)
        p5_count += 1
        if sc > p5_best:
            p5_best = sc
            print(f"  NEW BEST: {sc}/24 — rotate90ccw/w{width}")

        # Rotate 180°
        pt_rot180 = CT[::-1]
        sc = quick_crib_score(pt_rot180)
        p5_count += 1
        if sc > p5_best:
            p5_best = sc
            print(f"  NEW BEST: {sc}/24 — rotate180/w{width}")

if p5_best > global_best:
    global_best = p5_best
print(f"  Phase 5: {p5_count} configs, best {p5_best}/24")

# ── Summary ──
elapsed = time.time() - t0
print(f"\n{'=' * 70}")
print(f"TOTAL TIME: {elapsed:.1f}s")
print(f"GLOBAL BEST: {global_best}/24")
print(f"Results above noise: {len([r for r in results if r['score'] >= 7])}")
if global_best <= 9:
    print("CLASSIFICATION: NOISE")
elif global_best <= 17:
    print("CLASSIFICATION: STORE")
else:
    print("CLASSIFICATION: SIGNAL — INVESTIGATE!")
print(f"{'=' * 70}")

os.makedirs('results', exist_ok=True)
with open('results/e_chart_07_width9_cc.json', 'w') as f:
    json.dump({
        'experiment': 'E-CHART-07',
        'description': 'Width-9 grid with CC insertion + reading orders',
        'global_best': global_best,
        'classification': 'NOISE' if global_best <= 9 else 'STORE' if global_best <= 17 else 'SIGNAL',
        'results': results,
    }, f, indent=2)
print(f"Artifact: results/e_chart_07_width9_cc.json")
