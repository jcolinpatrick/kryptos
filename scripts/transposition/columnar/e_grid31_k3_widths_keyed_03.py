#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
Test K4 with K3's exact widths (21, 28) but with KEYED column orders.

K3 = double columnar RTL at widths 21 and 28.
HYPOTHESIS: K4 uses same widths but keyword-ordered columns.

Also test: single columnar at 21 or 28 with all keyword orders,
and AMSCO cipher (alternating 1-2 char groups) at various widths.
"""
import itertools
import sys

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
            "EASTNORTHEAST", "ENIGMA", "SHADOW", "MASQUERADE"]

CRIB_WORDS_MAJOR = ["EASTNORTHEAST", "BERLINCLOCK"]
CRIB_WORDS_MINOR = ["NORTHEAST", "BERLIN", "CLOCK", "SLOWLY", "CHAMBER",
                     "CANDLE", "MIST", "EAST", "NORTH"]


def keyword_to_order(keyword, ncols):
    kw = keyword[:ncols] if len(keyword) > ncols else keyword
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    sorted_idx = sorted(indexed, key=lambda x: (x[0], x[1]))
    ranks = [0] * len(kw)
    for rank, (_, pos) in enumerate(sorted_idx):
        ranks[pos] = rank
    order = list(ranks)
    next_rank = len(kw)
    for _ in range(len(kw), ncols):
        order.append(next_rank)
        next_rank += 1
    col_order = [0] * ncols
    for col, rank in enumerate(order):
        col_order[rank] = col
    return col_order


def columnar_encrypt(text, width, col_order):
    nrows = (len(text) + width - 1) // width
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch
    result = []
    for col in col_order:
        for row in range(nrows):
            if (row, col) in grid:
                result.append(grid[(row, col)])
    return ''.join(result)


def columnar_decrypt(ct, width, col_order):
    n = len(ct)
    nrows = (n + width - 1) // width
    remainder = n % width
    col_lengths = {}
    for col in range(width):
        col_lengths[col] = nrows if (remainder == 0 or col < remainder) else nrows - 1
    columns = {}
    pos = 0
    for col in col_order:
        clen = col_lengths[col]
        columns[col] = ct[pos:pos + clen]
        pos += clen
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(columns.get(col, '')):
                result.append(columns[col][row])
    return ''.join(result)


def vigenere_decrypt(ct, key, alpha):
    idx = {ch: i for i, ch in enumerate(alpha)}
    n = len(alpha)
    return ''.join(alpha[(idx[c] - idx[key[i % len(key)]]) % n] for i, c in enumerate(ct))


def beaufort_decrypt(ct, key, alpha):
    idx = {ch: i for i, ch in enumerate(alpha)}
    n = len(alpha)
    return ''.join(alpha[(idx[key[i % len(key)]] - idx[c]) % n] for i, c in enumerate(ct))


def check_cribs(text):
    major = [(c, text.index(c)) for c in CRIB_WORDS_MAJOR if c in text]
    minor = [(c, text.index(c)) for c in CRIB_WORDS_MINOR
             if c in text and not any(c in m[0] for m in major)]
    return major, minor


def score_result(major, minor):
    return sum(len(c) for c, _ in major) * 10 + sum(len(c) for c, _ in minor)


# ─── AMSCO helpers ────────────────────────────────────────────────────────────

def amsco_encrypt(text, width, col_order, start_with=1):
    """AMSCO cipher: write alternating 1/2 char groups into grid, read by columns."""
    nrows_max = (len(text) * 2 // (3 * width)) + 3  # rough upper bound
    grid = {}
    pos = 0
    char_count = start_with  # 1 or 2 chars for first cell
    for row in range(nrows_max):
        for col in range(width):
            if pos >= len(text):
                break
            take = min(char_count, len(text) - pos)
            grid[(row, col)] = text[pos:pos + take]
            pos += take
            char_count = 3 - char_count  # alternate 1↔2
        if pos >= len(text):
            break

    actual_rows = max(r for (r, c) in grid) + 1 if grid else 0

    result = []
    for col in col_order:
        for row in range(actual_rows):
            if (row, col) in grid:
                result.append(grid[(row, col)])
    return ''.join(result)


def amsco_decrypt(ct, width, col_order, start_with=1):
    """Inverse AMSCO: distribute CT into columns, then read row by row."""
    # First, figure out the grid structure by simulating the write
    nrows_max = (len(ct) * 2 // (3 * width)) + 3
    cell_sizes = {}
    pos = 0
    char_count = start_with
    for row in range(nrows_max):
        for col in range(width):
            if pos >= len(ct):
                break
            take = min(char_count, len(ct) - pos)
            cell_sizes[(row, col)] = take
            pos += take
            char_count = 3 - char_count
        if pos >= len(ct):
            break

    actual_rows = max(r for (r, c) in cell_sizes) + 1 if cell_sizes else 0

    # Calculate chars per column
    col_char_counts = {}
    for col in range(width):
        total = sum(cell_sizes.get((row, col), 0) for row in range(actual_rows))
        col_char_counts[col] = total

    # Fill columns from CT in col_order
    columns = {}
    pos = 0
    for col in col_order:
        count = col_char_counts.get(col, 0)
        columns[col] = ct[pos:pos + count]
        pos += count

    # Read row by row
    result = []
    col_positions = {col: 0 for col in range(width)}
    for row in range(actual_rows):
        for col in range(width):
            size = cell_sizes.get((row, col), 0)
            if size > 0 and col in columns:
                start = col_positions[col]
                result.append(columns[col][start:start + size])
                col_positions[col] = start + size
    return ''.join(result)


results = []
print("=" * 80)
print("K3-WIDTHS KEYED + AMSCO CIPHER SEARCH")
print("=" * 80)

# ─── SECTION 1: Double columnar at K3 widths with ALL keyword orders ─────────

print("\nSECTION 1: Double columnar at widths (21,28) and (28,21) with keyword orders")
count1 = 0

WIDTH_PAIRS = [(21, 28), (28, 21), (21, 21), (28, 28), (21, 14), (14, 21),
               (28, 14), (14, 28), (21, 31), (31, 21), (28, 31), (31, 28)]

for w1, w2 in WIDTH_PAIRS:
    for kw1 in KEYWORDS:
        o1 = keyword_to_order(kw1, w1) if len(kw1) <= w1 else None
        if o1 is None:
            continue
        for kw2 in KEYWORDS:
            o2 = keyword_to_order(kw2, w2) if len(kw2) <= w2 else None
            if o2 is None:
                continue

            for d1, fn1 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                for d2, fn2 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                    intermediate = fn1(K4, w1, o1)
                    reordered = fn2(intermediate, w2, o2)
                    if len(reordered) != 97:
                        continue

                    for sub_kw in KEYWORDS[:4]:  # Focus on main keywords
                        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                            pt = vigenere_decrypt(reordered, sub_kw, alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score_result(major, minor)
                                desc = f"Dbl({w1}{d1}:{kw1},{w2}{d2}:{kw2})+Vig({sub_kw},{alpha_name})"
                                results.append((s, desc, pt, major + minor))

                            pt = beaufort_decrypt(reordered, sub_kw, alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score_result(major, minor)
                                desc = f"Dbl({w1}{d1}:{kw1},{w2}{d2}:{kw2})+Beau({sub_kw},{alpha_name})"
                                results.append((s, desc, pt, major + minor))
                            count1 += 1

    # Also with RTL/LTR first step, keyword second step (and vice versa)
    for o1_name, o1 in [("RTL", list(range(w1-1,-1,-1)))]:
        for kw2 in KEYWORDS:
            o2 = keyword_to_order(kw2, w2) if len(kw2) <= w2 else None
            if o2 is None:
                continue
            for d1, fn1 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                for d2, fn2 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                    intermediate = fn1(K4, w1, o1)
                    reordered = fn2(intermediate, w2, o2)
                    if len(reordered) != 97:
                        continue
                    for sub_kw in KEYWORDS[:4]:
                        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                            pt = vigenere_decrypt(reordered, sub_kw, alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score_result(major, minor)
                                desc = f"Dbl({w1}{d1}:RTL,{w2}{d2}:{kw2})+Vig({sub_kw},{alpha_name})"
                                results.append((s, desc, pt, major + minor))
                            pt = beaufort_decrypt(reordered, sub_kw, alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score_result(major, minor)
                                desc = f"Dbl({w1}{d1}:RTL,{w2}{d2}:{kw2})+Beau({sub_kw},{alpha_name})"
                                results.append((s, desc, pt, major + minor))
                            count1 += 1

print(f"  Tested {count1:,} configurations")

# ─── SECTION 2: AMSCO cipher at key widths ───────────────────────────────────

print("\nSECTION 2: AMSCO cipher (alternating 1-2 char groups)")
count2 = 0

AMSCO_WIDTHS = list(range(3, 20)) + [21, 28, 31]

for width in AMSCO_WIDTHS:
    orders_to_test = [("LTR", list(range(width))), ("RTL", list(range(width-1,-1,-1)))]
    for kw in KEYWORDS:
        if len(kw) <= width:
            orders_to_test.append((kw, keyword_to_order(kw, width)))

    for order_name, col_order in orders_to_test:
        for start in [1, 2]:
            for direction, trans_fn in [("ENC", amsco_encrypt), ("DEC", amsco_decrypt)]:
                try:
                    reordered = trans_fn(K4, width, col_order, start)
                except Exception:
                    continue
                if len(reordered) != 97:
                    continue

                for sub_kw in KEYWORDS[:4]:
                    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                        pt = vigenere_decrypt(reordered, sub_kw, alpha)
                        major, minor = check_cribs(pt)
                        if major or minor:
                            s = score_result(major, minor)
                            desc = f"AMSCO{width}-{direction}({order_name},s={start})+Vig({sub_kw},{alpha_name})"
                            results.append((s, desc, pt, major + minor))

                        pt = beaufort_decrypt(reordered, sub_kw, alpha)
                        major, minor = check_cribs(pt)
                        if major or minor:
                            s = score_result(major, minor)
                            desc = f"AMSCO{width}-{direction}({order_name},s={start})+Beau({sub_kw},{alpha_name})"
                            results.append((s, desc, pt, major + minor))
                        count2 += 1

print(f"  Tested {count2:,} configurations")

# ─── SECTION 3: Exhaustive width-7 DOUBLE columnar (all 5040 × 5040 = too big) ─

# Instead: exhaustive single columnar at w=21 and w=28 with KRYPTOS-length subkeys
# For w=21, we can try all 21!/14! keyed permutations... too many.
# Instead: try the KRYPTOS key repeated to fill 21 positions

print("\nSECTION 3: Single columnar at w=21 and w=28 with cyclic keyword orders")
count3 = 0

def cyclic_keyword_order(keyword, ncols):
    """Repeat keyword cyclically to fill ncols, then rank to get column order."""
    extended = ''.join(keyword[i % len(keyword)] for i in range(ncols))
    indexed = [(ch, i) for i, ch in enumerate(extended)]
    sorted_idx = sorted(indexed, key=lambda x: (x[0], x[1]))
    col_order = [0] * ncols
    for rank, (_, pos) in enumerate(sorted_idx):
        col_order[rank] = pos
    return col_order


for width in [21, 28, 31, 14, 42]:
    for kw in KEYWORDS:
        for order_fn, order_name in [(keyword_to_order, "ext"), (cyclic_keyword_order, "cyc")]:
            try:
                col_order = order_fn(kw, width)
            except Exception:
                continue
            if len(col_order) != width:
                continue

            for direction, trans_fn in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                reordered = trans_fn(K4, width, col_order)
                if len(reordered) != 97:
                    continue

                # No substitution
                major, minor = check_cribs(reordered)
                if major or minor:
                    s = score_result(major, minor)
                    desc = f"Col{width}-{direction}({kw}-{order_name})-NoSub"
                    results.append((s, desc, reordered, major + minor))

                for sub_kw in KEYWORDS[:4]:
                    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                        pt = vigenere_decrypt(reordered, sub_kw, alpha)
                        major, minor = check_cribs(pt)
                        if major or minor:
                            s = score_result(major, minor)
                            desc = f"Col{width}-{direction}({kw}-{order_name})+Vig({sub_kw},{alpha_name})"
                            results.append((s, desc, pt, major + minor))

                        pt = beaufort_decrypt(reordered, sub_kw, alpha)
                        major, minor = check_cribs(pt)
                        if major or minor:
                            s = score_result(major, minor)
                            desc = f"Col{width}-{direction}({kw}-{order_name})+Beau({sub_kw},{alpha_name})"
                            results.append((s, desc, pt, major + minor))
                        count3 += 1

print(f"  Tested {count3:,} configurations")

# ─── SECTION 4: Width 7 with KRYPTOS key, all 7!×7!=25M double combos ────────
# This is feasible: iterate all 5040 first-step column orders at w=7,
# for each try all 7 KRYPTOS-cycle shifts for second step at w=7

print("\nSECTION 4: Double columnar w=7, all first-step perms × KRYPTOS-shifted second step")
count4 = 0

# KRYPTOS orders: original + 6 cyclic rotations
kryptos_orders = []
for shift in range(7):
    rotated = "KRYPTOS"[shift:] + "KRYPTOS"[:shift]
    kryptos_orders.append(keyword_to_order(rotated, 7))

for perm1 in itertools.permutations(range(7)):
    o1 = list(perm1)
    for o2 in kryptos_orders:
        for d1, fn1 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
            for d2, fn2 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                intermediate = fn1(K4, 7, o1)
                reordered = fn2(intermediate, 7, o2)
                if len(reordered) != 97:
                    continue

                # Quick: just Vig/KRYPTOS/AZ
                pt = vigenere_decrypt(reordered, "KRYPTOS", AZ)
                major, minor = check_cribs(pt)
                if major or minor:
                    s = score_result(major, minor)
                    p1 = ''.join(str(x) for x in o1)
                    desc = f"Dbl7({d1}:{p1},{d2}:KR)+Vig(KRYPTOS,AZ)"
                    results.append((s, desc, pt, major + minor))

                pt = beaufort_decrypt(reordered, "KRYPTOS", AZ)
                major, minor = check_cribs(pt)
                if major or minor:
                    s = score_result(major, minor)
                    p1 = ''.join(str(x) for x in o1)
                    desc = f"Dbl7({d1}:{p1},{d2}:KR)+Beau(KRYPTOS,AZ)"
                    results.append((s, desc, pt, major + minor))
                count4 += 1

print(f"  Tested {count4:,} configurations")

# ═══════════════════════════════════════════════════════════════════════════════

total = count1 + count2 + count3 + count4
print(f"\n{'=' * 80}")
print(f"GRAND TOTAL: {total:,} configurations tested")
print(f"RESULTS: {len(results)} with any crib matches")
print(f"{'=' * 80}")

if results:
    results.sort(key=lambda x: -x[0])
    print("\nTOP RESULTS:")
    for i, (score, desc, pt, cribs) in enumerate(results[:30]):
        crib_str = ', '.join(f"{c}@{p}" for c, p in cribs)
        print(f"  {i+1:3d}. [score={score:3d}] {desc}")
        print(f"       Cribs: {crib_str}")
        print(f"       PT: {pt[:80]}")
        print()

    major_hits = [r for r in results if r[0] >= 50]
    if major_hits:
        print("!!! MAJOR CRIB MATCHES !!!")
        for s, d, pt, c in major_hits:
            print(f"  SCORE {s}: {d}")
            print(f"  PT: {pt}")
    else:
        print("No major crib matches.")
else:
    print("\nZERO crib matches.")
