#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Exploit the width-31 grid discovery for K4 transposition.

KEY INSIGHT: K4 occupies a specific position on Sanborn's 31-wide working chart.
If the transposition IS a column reading from this chart, we can test it directly.

K4 on the 31-wide grid:
  Row 11 (partial): cols 27-30 = OBKR  (4 chars)
  Row 12 (full):    cols 0-30  = UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO (31 chars)
  Row 13 (full):    cols 0-30  = TWTQSJQSSEKZZWATJKLUDIAWINFBNYP (31 chars)
  Row 14 (full):    cols 0-30  = VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR (31 chars)

Columns 0-26: 3 chars each (rows 12-14) = 81 chars
Columns 27-30: 4 chars each (rows 11-14) = 16 chars
Total: 81 + 16 = 97 ✓

Test plan:
  A) Read K4 column-by-column from the 31-wide grid in various orders
  B) For each reading, try Vig/Beaufort with known keywords
  C) Also test K4 standalone at various grid widths with route ciphers
"""

import itertools

K4_CARVED = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

CRIB_WORDS = ["EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "BERLIN", "CLOCK",
              "SLOWLY", "CHAMBER", "CANDLE", "MIST", "EAST", "NORTH"]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]

# ─── Grid construction ────────────────────────────────────────────────────────

def build_k4_grid_31():
    """Place K4 on the 31-wide grid exactly as it appears in Sanborn's chart.
    Returns dict: (row, col) -> char, and the grid dimensions."""
    grid = {}
    pos = 0
    # Row 11 partial: cols 27-30
    for col in range(27, 31):
        grid[(0, col)] = K4_CARVED[pos]  # 0-indexed within K4 block
        pos += 1
    # Rows 12-14: full width
    for row_offset in range(1, 4):
        for col in range(31):
            grid[(row_offset, col)] = K4_CARVED[pos]
            pos += 1
    assert pos == 97
    return grid

def read_columns(grid, col_order, num_rows=4, num_cols=31, top_to_bottom=True):
    """Read grid column-by-column in given column order.
    Handles irregular grid (row 0 only has cols 27-30)."""
    result = []
    for col in col_order:
        for row in (range(num_rows) if top_to_bottom else range(num_rows-1, -1, -1)):
            if (row, col) in grid:
                result.append(grid[(row, col)])
    return ''.join(result)

def read_columns_boustrophedon(grid, col_order, num_rows=4, num_cols=31):
    """Read columns alternating top-to-bottom and bottom-to-top."""
    result = []
    for i, col in enumerate(col_order):
        if i % 2 == 0:
            rows = range(num_rows)
        else:
            rows = range(num_rows - 1, -1, -1)
        for row in rows:
            if (row, col) in grid:
                result.append(grid[(row, col)])
    return ''.join(result)

# ─── Substitution ─────────────────────────────────────────────────────────────

def vigenere_decrypt(ct, key, alphabet):
    idx = {ch: i for i, ch in enumerate(alphabet)}
    n = len(alphabet)
    return ''.join(alphabet[(idx[c] - idx[key[i % len(key)]]) % n] for i, c in enumerate(ct))

def beaufort_decrypt(ct, key, alphabet):
    idx = {ch: i for i, ch in enumerate(alphabet)}
    n = len(alphabet)
    return ''.join(alphabet[(idx[key[i % len(key)]] - idx[c]) % n] for i, c in enumerate(ct))

def variant_beaufort_decrypt(ct, key, alphabet):
    idx = {ch: i for i, ch in enumerate(alphabet)}
    n = len(alphabet)
    return ''.join(alphabet[(idx[c] + idx[key[i % len(key)]]) % n] for i, c in enumerate(ct))

# ─── Column order generators ─────────────────────────────────────────────────

def keyword_column_order(keyword, ncols=31):
    """Generate column order from keyword, extended to ncols columns.
    Maps keyword to ranks, remaining columns appended in order."""
    if len(keyword) > ncols:
        keyword = keyword[:ncols]
    # Rank keyword letters
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    sorted_indexed = sorted(indexed, key=lambda x: (x[0], x[1]))
    ranks = [0] * len(keyword)
    for rank, (_, pos) in enumerate(sorted_indexed):
        ranks[pos] = rank

    # For keyword shorter than ncols: remaining columns get ranks after keyword
    order = list(ranks)
    next_rank = len(keyword)
    for i in range(len(keyword), ncols):
        order.append(next_rank)
        next_rank += 1

    # Convert to column reading order: rank 0 first, then rank 1, etc.
    col_order = [0] * ncols
    for col, rank in enumerate(order):
        col_order[rank] = col
    return col_order

def rtl_order(ncols=31):
    return list(range(ncols - 1, -1, -1))

def ltr_order(ncols=31):
    return list(range(ncols))

# ─── Crib checking ───────────────────────────────────────────────────────────

def check_cribs(text):
    found = []
    for crib in CRIB_WORDS:
        if crib in text:
            found.append((crib, text.index(crib)))
    return found

# ─── Standalone grid transpositions (K4 at various widths) ───────────────────

def columnar_read(text, width, col_order=None, top_to_bottom=True):
    """Write text in rows of 'width', read columns in given order."""
    nrows = (len(text) + width - 1) // width
    # Build grid
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    if col_order is None:
        col_order = list(range(width))

    result = []
    for col in col_order:
        rows = range(nrows) if top_to_bottom else range(nrows - 1, -1, -1)
        for row in rows:
            if (row, col) in grid:
                result.append(grid[(row, col)])
    return ''.join(result)

def spiral_read(text, width):
    """Write text in rows, read in clockwise spiral."""
    nrows = (len(text) + width - 1) // width
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    result = []
    top, bottom, left, right = 0, nrows - 1, 0, width - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            if (top, c) in grid: result.append(grid[(top, c)])
        top += 1
        for r in range(top, bottom + 1):
            if (r, right) in grid: result.append(grid[(r, right)])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if (bottom, c) in grid: result.append(grid[(bottom, c)])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if (r, left) in grid: result.append(grid[(r, left)])
            left += 1
    return ''.join(result)

def diagonal_read(text, width):
    """Write text in rows, read diagonals (top-right to bottom-left)."""
    nrows = (len(text) + width - 1) // width
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    result = []
    for d in range(nrows + width - 1):
        for r in range(max(0, d - width + 1), min(nrows, d + 1)):
            c = d - r
            if (r, c) in grid:
                result.append(grid[(r, c)])
    return ''.join(result)

def snake_read(text, width):
    """Write text in rows, read boustrophedon (snake/zigzag)."""
    nrows = (len(text) + width - 1) // width
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    result = []
    for r in range(nrows):
        cols = range(width) if r % 2 == 0 else range(width - 1, -1, -1)
        for c in cols:
            if (r, c) in grid:
                result.append(grid[(r, c)])
    return ''.join(result)

# ─── Double columnar transposition ───────────────────────────────────────────

def double_columnar(text, w1, w2, order1=None, order2=None):
    """Double columnar: write in w1-wide rows, read cols (order1),
    then write result in w2-wide rows, read cols (order2)."""
    intermediate = columnar_read(text, w1, order1)
    return columnar_read(intermediate, w2, order2)

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN TEST BATTERY
# ═══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("GRID-31 K4 TRANSPOSITION SEARCH")
print("=" * 80)
print(f"K4 carved ({len(K4_CARVED)}): {K4_CARVED}")
print()

all_results = []

# ─── SECTION A: Column readings from the 31-wide grid ────────────────────────

print("SECTION A: Column readings from 31-wide working chart")
print("-" * 60)

grid = build_k4_grid_31()

# Test keyword column orders on 31-wide grid
for kw in KEYWORDS:
    for direction in ["TTB", "BTT"]:
        ttb = (direction == "TTB")
        col_order = keyword_column_order(kw, 31)
        reordered = read_columns(grid, col_order, top_to_bottom=ttb)

        # Also boustrophedon
        reordered_boust = read_columns_boustrophedon(grid, col_order)

        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for decrypt_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau"), (variant_beaufort_decrypt, "VarBeau")]:
                    # Standard column reading
                    pt = decrypt_fn(reordered, sub_kw, alpha)
                    cribs = check_cribs(pt)
                    if cribs:
                        desc = f"Grid31-Col({kw},{direction})+{fn_name}({sub_kw},{alpha_name})"
                        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))

                    # Boustrophedon column reading
                    pt2 = decrypt_fn(reordered_boust, sub_kw, alpha)
                    cribs2 = check_cribs(pt2)
                    if cribs2:
                        desc = f"Grid31-ColBoust({kw},{direction})+{fn_name}({sub_kw},{alpha_name})"
                        all_results.append((len(cribs2), sum(len(c) for c, _ in cribs2), desc, pt2, cribs2))

# RTL and LTR column orders
for direction_name, order_fn in [("RTL", rtl_order), ("LTR", ltr_order)]:
    for ttb in [True, False]:
        col_order = order_fn(31)
        reordered = read_columns(grid, col_order, top_to_bottom=ttb)

        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for decrypt_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                    pt = decrypt_fn(reordered, sub_kw, alpha)
                    cribs = check_cribs(pt)
                    if cribs:
                        dir_str = "TTB" if ttb else "BTT"
                        desc = f"Grid31-{direction_name}({dir_str})+{fn_name}({sub_kw},{alpha_name})"
                        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))

# Also try: no substitution (pure transposition — check if reading columns gives English)
for kw in KEYWORDS:
    col_order = keyword_column_order(kw, 31)
    reordered = read_columns(grid, col_order, top_to_bottom=True)
    cribs = check_cribs(reordered)
    if cribs:
        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), f"Grid31-Col({kw})-NoSub", reordered, cribs))

configs_a = len(KEYWORDS) * 2 * 2 * len(KEYWORDS) * 2 * 3 + 2 * 2 * len(KEYWORDS) * 2 * 2 + len(KEYWORDS)
print(f"  Tested ~{configs_a} configurations")

# ─── SECTION B: K4 standalone columnar at various widths ─────────────────────

print("\nSECTION B: K4 standalone columnar transposition")
print("-" * 60)

configs_b = 0
WIDTHS = list(range(2, 49)) + [62, 63, 70, 77, 84, 91, 97]

for width in WIDTHS:
    # Standard column orders: LTR, RTL
    for order_name, col_order in [("LTR", list(range(width))), ("RTL", list(range(width - 1, -1, -1)))]:
        reordered = columnar_read(K4_CARVED, width, col_order)
        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for decrypt_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                    pt = decrypt_fn(reordered, sub_kw, alpha)
                    cribs = check_cribs(pt)
                    if cribs:
                        desc = f"Col(w={width},{order_name})+{fn_name}({sub_kw},{alpha_name})"
                        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))
                    configs_b += 1

    # Keyword column orders
    for kw in KEYWORDS:
        if len(kw) <= width:
            col_order = keyword_column_order(kw, width)
            reordered = columnar_read(K4_CARVED, width, col_order)
            for sub_kw in KEYWORDS:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    for decrypt_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                        pt = decrypt_fn(reordered, sub_kw, alpha)
                        cribs = check_cribs(pt)
                        if cribs:
                            desc = f"KeyCol(w={width},{kw})+{fn_name}({sub_kw},{alpha_name})"
                            all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))
                        configs_b += 1

print(f"  Tested {configs_b} configurations")

# ─── SECTION C: Route ciphers ────────────────────────────────────────────────

print("\nSECTION C: Route ciphers (spiral, diagonal, snake)")
print("-" * 60)

configs_c = 0
ROUTE_WIDTHS = list(range(2, 49)) + [97]

for width in ROUTE_WIDTHS:
    for route_fn, route_name in [(spiral_read, "Spiral"), (diagonal_read, "Diag"), (snake_read, "Snake")]:
        reordered = route_fn(K4_CARVED, width)
        if len(reordered) != 97:
            continue

        # No substitution
        cribs = check_cribs(reordered)
        if cribs:
            desc = f"{route_name}(w={width})-NoSub"
            all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, reordered, cribs))

        # With substitution
        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for decrypt_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                    pt = decrypt_fn(reordered, sub_kw, alpha)
                    cribs = check_cribs(pt)
                    if cribs:
                        desc = f"{route_name}(w={width})+{fn_name}({sub_kw},{alpha_name})"
                        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))
                    configs_c += 1

print(f"  Tested {configs_c} configurations")

# ─── SECTION D: Double columnar (keyed) ─────────────────────────────────────

print("\nSECTION D: Double columnar with keyed column orders")
print("-" * 60)

configs_d = 0
# Focus on multiples of 7 and factors near K4
W_PAIRS = []
for w1 in [7, 8, 14, 21, 28, 31]:
    for w2 in [7, 8, 14, 21, 28, 31]:
        W_PAIRS.append((w1, w2))

for w1, w2 in W_PAIRS:
    for kw1 in KEYWORDS:
        order1 = keyword_column_order(kw1, w1) if len(kw1) <= w1 else None
        if order1 is None:
            continue
        for kw2 in KEYWORDS:
            order2 = keyword_column_order(kw2, w2) if len(kw2) <= w2 else None
            if order2 is None:
                continue

            reordered = double_columnar(K4_CARVED, w1, w2, order1, order2)
            if len(reordered) != 97:
                continue

            # Try with and without substitution
            cribs = check_cribs(reordered)
            if cribs:
                desc = f"DblCol({w1}:{kw1},{w2}:{kw2})-NoSub"
                all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, reordered, cribs))

            for sub_kw in KEYWORDS:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    pt = vigenere_decrypt(reordered, sub_kw, alpha)
                    cribs = check_cribs(pt)
                    if cribs:
                        desc = f"DblCol({w1}:{kw1},{w2}:{kw2})+Vig({sub_kw},{alpha_name})"
                        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))

                    pt = beaufort_decrypt(reordered, sub_kw, alpha)
                    cribs = check_cribs(pt)
                    if cribs:
                        desc = f"DblCol({w1}:{kw1},{w2}:{kw2})+Beau({sub_kw},{alpha_name})"
                        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))
                    configs_d += 1

# Also: RTL column orders for both steps
for w1, w2 in W_PAIRS:
    for o1_name, o1 in [("RTL", list(range(w1-1,-1,-1))), ("LTR", list(range(w1)))]:
        for o2_name, o2 in [("RTL", list(range(w2-1,-1,-1))), ("LTR", list(range(w2)))]:
            reordered = double_columnar(K4_CARVED, w1, w2, o1, o2)
            if len(reordered) != 97:
                continue
            for sub_kw in KEYWORDS:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    pt = vigenere_decrypt(reordered, sub_kw, alpha)
                    cribs = check_cribs(pt)
                    if cribs:
                        desc = f"DblCol({w1}:{o1_name},{w2}:{o2_name})+Vig({sub_kw},{alpha_name})"
                        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))

                    pt = beaufort_decrypt(reordered, sub_kw, alpha)
                    cribs = check_cribs(pt)
                    if cribs:
                        desc = f"DblCol({w1}:{o1_name},{w2}:{o2_name})+Beau({sub_kw},{alpha_name})"
                        all_results.append((len(cribs), sum(len(c) for c, _ in cribs), desc, pt, cribs))
                    configs_d += 1

print(f"  Tested {configs_d} configurations")

# ─── SECTION E: K3-inspired widths with keyed orders ─────────────────────────

print("\nSECTION E: K3-inspired widths (multiples of 7) with ALL column order permutations")
print("-" * 60)

# For width 7, try ALL 7! = 5040 column permutations
configs_e = 0
for width in [7]:
    nrows = (97 + width - 1) // width  # 14 rows
    for perm in itertools.permutations(range(width)):
        col_order = list(perm)
        reordered = columnar_read(K4_CARVED, width, col_order)

        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                pt_vig = vigenere_decrypt(reordered, sub_kw, alpha)
                cribs_vig = check_cribs(pt_vig)
                if cribs_vig:
                    desc = f"Col7(perm={''.join(str(x) for x in col_order)})+Vig({sub_kw},{alpha_name})"
                    all_results.append((len(cribs_vig), sum(len(c) for c, _ in cribs_vig), desc, pt_vig, cribs_vig))

                pt_beau = beaufort_decrypt(reordered, sub_kw, alpha)
                cribs_beau = check_cribs(pt_beau)
                if cribs_beau:
                    desc = f"Col7(perm={''.join(str(x) for x in col_order)})+Beau({sub_kw},{alpha_name})"
                    all_results.append((len(cribs_beau), sum(len(c) for c, _ in cribs_beau), desc, pt_beau, cribs_beau))
                configs_e += 1

# Width 8: try all 8! = 40320 column permutations (still feasible)
for width in [8]:
    for perm in itertools.permutations(range(width)):
        col_order = list(perm)
        reordered = columnar_read(K4_CARVED, width, col_order)

        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                pt_vig = vigenere_decrypt(reordered, sub_kw, alpha)
                cribs_vig = check_cribs(pt_vig)
                if cribs_vig:
                    desc = f"Col8(perm={''.join(str(x) for x in col_order)})+Vig({sub_kw},{alpha_name})"
                    all_results.append((len(cribs_vig), sum(len(c) for c, _ in cribs_vig), desc, pt_vig, cribs_vig))

                pt_beau = beaufort_decrypt(reordered, sub_kw, alpha)
                cribs_beau = check_cribs(pt_beau)
                if cribs_beau:
                    desc = f"Col8(perm={''.join(str(x) for x in col_order)})+Beau({sub_kw},{alpha_name})"
                    all_results.append((len(cribs_beau), sum(len(c) for c, _ in cribs_beau), desc, pt_beau, cribs_beau))
                configs_e += 1

print(f"  Tested {configs_e} configurations")

# ═══════════════════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

total = configs_a + configs_b + configs_c + configs_d + configs_e
print(f"\n{'=' * 80}")
print(f"TOTAL: {total:,} configurations tested")
print(f"RESULTS: {len(all_results)} with crib matches")
print(f"{'=' * 80}")

if all_results:
    # Sort by total crib chars matched (descending)
    all_results.sort(key=lambda x: (-x[1], -x[0]))
    print("\nTOP RESULTS:")
    for i, (ncribs, nchars, desc, pt, cribs) in enumerate(all_results[:50]):
        crib_str = ', '.join(f"{c}@{p}" for c, p in cribs)
        print(f"  {i+1:3d}. [{nchars:2d} chars, {ncribs} cribs] {desc}")
        print(f"       Cribs: {crib_str}")
        print(f"       PT: {pt[:80]}")
        print()
else:
    print("\nNO CRIB MATCHES FOUND across any section.")
    print()
    print("Diagnostic samples (no substitution):")
    grid = build_k4_grid_31()
    for kw in ["KRYPTOS"]:
        col_order = keyword_column_order(kw, 31)
        reordered = read_columns(grid, col_order, top_to_bottom=True)
        print(f"  Grid31-Col({kw}): {reordered[:70]}...")
    for width in [7, 8]:
        reordered_rtl = columnar_read(K4_CARVED, width, list(range(width-1, -1, -1)))
        print(f"  Col(w={width},RTL): {reordered_rtl[:70]}...")
    print(f"  Spiral(w=7): {spiral_read(K4_CARVED, 7)[:70]}...")
    print(f"  Snake(w=7):  {snake_read(K4_CARVED, 7)[:70]}...")
