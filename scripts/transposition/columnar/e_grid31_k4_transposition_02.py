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
Grid-31 K4 transposition search — INVERSE direction + expanded keys.

CRITICAL FIX: Previous script only applied columnar ENCRYPT direction.
Must also test DECRYPT direction (write into columns, read by rows).

Under Model 2: PT → substitution → real CT → transposition → carved text
To recover real CT: carved text → INVERSE transposition → real CT → INVERSE substitution → PT

If encrypt = "write in rows, read columns", then decrypt = "write in columns, read rows"
"""

import itertools
import sys

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

CRIB_WORDS_MAJOR = ["EASTNORTHEAST", "BERLINCLOCK"]
CRIB_WORDS_MINOR = ["NORTHEAST", "BERLIN", "CLOCK", "SLOWLY", "CHAMBER",
                     "CANDLE", "MIST", "EAST", "NORTH", "WEST"]

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
            "EASTNORTHEAST", "ENIGMA", "MASQUERADE"]


def keyword_to_order(keyword, ncols):
    """Keyword → column reading order. Extends shorter keywords with remaining cols in order."""
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


def columnar_encrypt(text, width, col_order=None):
    """Write in rows of 'width', read columns in col_order. (ENCRYPT direction)"""
    nrows = (len(text) + width - 1) // width
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    if col_order is None:
        col_order = list(range(width))

    result = []
    for col in col_order:
        for row in range(nrows):
            if (row, col) in grid:
                result.append(grid[(row, col)])
    return ''.join(result)


def columnar_decrypt(ct, width, col_order=None):
    """Write into columns (in col_order), read rows. (DECRYPT direction)
    Handles irregular columns — some cols may be longer than others."""
    n = len(ct)
    nrows = (n + width - 1) // width
    remainder = n % width  # Number of columns with nrows chars (if remainder > 0)

    if col_order is None:
        col_order = list(range(width))

    # Determine column lengths
    # In standard columnar: first 'remainder' columns (in WRITE order) have nrows chars,
    # rest have nrows-1. But with irregular grids, it depends on column order.
    # For columnar decrypt: the SHORT columns are those with index >= remainder in the GRID layout.
    col_lengths = {}
    for col in range(width):
        if remainder == 0:
            col_lengths[col] = nrows
        else:
            col_lengths[col] = nrows if col < remainder else nrows - 1

    # Fill columns in col_order
    columns = {}
    pos = 0
    for col in col_order:
        clen = col_lengths[col]
        columns[col] = ct[pos:pos + clen]
        pos += clen

    # Read row by row
    result = []
    for row in range(nrows):
        for col in range(width):
            if row < len(columns.get(col, '')):
                result.append(columns[col][row])
    return ''.join(result)


def vigenere_decrypt(ct, key, alphabet):
    idx = {ch: i for i, ch in enumerate(alphabet)}
    n = len(alphabet)
    return ''.join(alphabet[(idx[c] - idx[key[i % len(key)]]) % n] for i, c in enumerate(ct))


def beaufort_decrypt(ct, key, alphabet):
    idx = {ch: i for i, ch in enumerate(alphabet)}
    n = len(alphabet)
    return ''.join(alphabet[(idx[key[i % len(key)]] - idx[c]) % n] for i, c in enumerate(ct))


def check_cribs(text):
    major = [(c, text.index(c)) for c in CRIB_WORDS_MAJOR if c in text]
    minor = [(c, text.index(c)) for c in CRIB_WORDS_MINOR if c in text and c not in [m[0] for m in major] and not any(c in m[0] for m in major)]
    return major, minor


def score_result(major, minor):
    return sum(len(c) for c, _ in major) * 10 + sum(len(c) for c, _ in minor)


results = []

print("=" * 80)
print("GRID-31 K4 TRANSPOSITION — BOTH DIRECTIONS + EXPANDED KEYS")
print("=" * 80)
print(f"K4 ({len(K4)}): {K4}")
print()

# ─── SECTION 1: Width 7 — ALL 5040 column permutations × BOTH directions ─────

print("SECTION 1: Width 7, all 5040 permutations, both encrypt/decrypt directions")
count = 0
for perm in itertools.permutations(range(7)):
    col_order = list(perm)

    for direction, trans_fn in [("ENC", columnar_encrypt), ("DEC", columnar_decrypt)]:
        reordered = trans_fn(K4, 7, col_order)
        if len(reordered) != 97:
            continue

        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for dec_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                    pt = dec_fn(reordered, sub_kw, alpha)
                    major, minor = check_cribs(pt)
                    if major or minor:
                        s = score_result(major, minor)
                        perm_str = ''.join(str(x) for x in col_order)
                        desc = f"Col7-{direction}({perm_str})+{fn_name}({sub_kw},{alpha_name})"
                        results.append((s, desc, pt, major + minor))
                    count += 1

        # Also: no substitution (pure transposition)
        major, minor = check_cribs(reordered)
        if major or minor:
            s = score_result(major, minor)
            perm_str = ''.join(str(x) for x in col_order)
            desc = f"Col7-{direction}({perm_str})-NoSub"
            results.append((s, desc, reordered, major + minor))

print(f"  Tested {count:,} configs, {len(results)} hits so far")

# ─── SECTION 2: Width 8 — ALL 40320 permutations × BOTH directions ──────────

print("SECTION 2: Width 8, all 40320 permutations, both directions")
count2 = 0
for perm in itertools.permutations(range(8)):
    col_order = list(perm)

    for direction, trans_fn in [("ENC", columnar_encrypt), ("DEC", columnar_decrypt)]:
        reordered = trans_fn(K4, 8, col_order)
        if len(reordered) != 97:
            continue

        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for dec_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                    pt = dec_fn(reordered, sub_kw, alpha)
                    major, minor = check_cribs(pt)
                    if major or minor:
                        s = score_result(major, minor)
                        perm_str = ''.join(str(x) for x in col_order)
                        desc = f"Col8-{direction}({perm_str})+{fn_name}({sub_kw},{alpha_name})"
                        results.append((s, desc, pt, major + minor))
                    count2 += 1

print(f"  Tested {count2:,} configs, {len(results)} hits total")

# ─── SECTION 3: Widths 2-48, keyword and RTL orders, BOTH directions ─────────

print("SECTION 3: Widths 2-48, keyword/RTL orders, both directions")
count3 = 0
for width in range(2, 49):
    orders_to_test = [
        ("LTR", list(range(width))),
        ("RTL", list(range(width - 1, -1, -1))),
    ]
    for kw in KEYWORDS:
        if len(kw) <= width:
            orders_to_test.append((kw, keyword_to_order(kw, width)))

    for order_name, col_order in orders_to_test:
        for direction, trans_fn in [("ENC", columnar_encrypt), ("DEC", columnar_decrypt)]:
            reordered = trans_fn(K4, width, col_order)
            if len(reordered) != 97:
                continue

            for sub_kw in KEYWORDS:
                for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                    for dec_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                        pt = dec_fn(reordered, sub_kw, alpha)
                        major, minor = check_cribs(pt)
                        if major or minor:
                            s = score_result(major, minor)
                            desc = f"Col{width}-{direction}({order_name})+{fn_name}({sub_kw},{alpha_name})"
                            results.append((s, desc, pt, major + minor))
                        count3 += 1

print(f"  Tested {count3:,} configs, {len(results)} hits total")

# ─── SECTION 4: Double columnar, BOTH directions for each step ───────────────

print("SECTION 4: Double columnar, both directions")
count4 = 0
W_PAIRS = [(7, 7), (7, 8), (8, 7), (7, 14), (14, 7), (7, 21), (21, 7),
           (7, 28), (28, 7), (8, 8), (8, 14), (14, 8), (7, 31), (31, 7),
           (8, 31), (31, 8)]

for w1, w2 in W_PAIRS:
    for o1_name, o1 in [("RTL", list(range(w1-1,-1,-1))), ("LTR", list(range(w1)))]:
        for o2_name, o2 in [("RTL", list(range(w2-1,-1,-1))), ("LTR", list(range(w2)))]:
            for d1, fn1 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                for d2, fn2 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                    intermediate = fn1(K4, w1, o1)
                    reordered = fn2(intermediate, w2, o2)
                    if len(reordered) != 97:
                        continue

                    for sub_kw in KEYWORDS:
                        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                            pt = vigenere_decrypt(reordered, sub_kw, alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score_result(major, minor)
                                desc = f"Dbl({w1}{d1}{o1_name},{w2}{d2}{o2_name})+Vig({sub_kw},{alpha_name})"
                                results.append((s, desc, pt, major + minor))

                            pt = beaufort_decrypt(reordered, sub_kw, alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score_result(major, minor)
                                desc = f"Dbl({w1}{d1}{o1_name},{w2}{d2}{o2_name})+Beau({sub_kw},{alpha_name})"
                                results.append((s, desc, pt, major + minor))
                            count4 += 1

    # Also keyed orders
    for kw in ["KRYPTOS"]:
        if len(kw) <= w1 and len(kw) <= w2:
            o1 = keyword_to_order(kw, w1)
            o2 = keyword_to_order(kw, w2)
            for d1, fn1 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                for d2, fn2 in [("E", columnar_encrypt), ("D", columnar_decrypt)]:
                    intermediate = fn1(K4, w1, o1)
                    reordered = fn2(intermediate, w2, o2)
                    if len(reordered) != 97:
                        continue
                    for sub_kw in KEYWORDS:
                        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                            pt = vigenere_decrypt(reordered, sub_kw, alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score_result(major, minor)
                                desc = f"Dbl({w1}E-K,{w2}E-K)+Vig({sub_kw},{alpha_name})"
                                results.append((s, desc, pt, major + minor))
                            count4 += 1

print(f"  Tested {count4:,} configs, {len(results)} hits total")

# ─── SECTION 5: Myszkowski on width 8 with ABSCISSA ─────────────────────────

print("SECTION 5: Myszkowski transposition with ABSCISSA (width 8, duplicate A)")
# ABSCISSA → ranks: A=0,1  B=2  C=3  I=4  S=5,6,7
# Myszkowski: columns with same rank are read left-to-right together
count5 = 0

def myszkowski_encrypt(text, keyword):
    """Myszkowski transposition: write text in rows of len(keyword).
    Columns with duplicate keyword letters are read left-to-right simultaneously."""
    width = len(keyword)
    nrows = (len(text) + width - 1) // width
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    # Group columns by keyword letter
    from collections import defaultdict
    groups = defaultdict(list)
    for i, ch in enumerate(keyword):
        groups[ch].append(i)

    # Read in sorted key order
    result = []
    for key_letter in sorted(groups.keys()):
        cols = groups[key_letter]
        if len(cols) == 1:
            for row in range(nrows):
                if (row, cols[0]) in grid:
                    result.append(grid[(row, cols[0])])
        else:
            # Myszkowski: read row by row across all cols with same letter
            for row in range(nrows):
                for col in cols:
                    if (row, col) in grid:
                        result.append(grid[(row, col)])
    return ''.join(result)


def myszkowski_decrypt(ct, keyword):
    """Inverse of Myszkowski transposition."""
    width = len(keyword)
    nrows = (len(ct) + width - 1) // width
    remainder = len(ct) % width

    from collections import defaultdict
    groups = defaultdict(list)
    for i, ch in enumerate(keyword):
        groups[ch].append(i)

    # Calculate how many chars each group gets
    columns = {}
    pos = 0
    for key_letter in sorted(groups.keys()):
        cols = groups[key_letter]
        if len(cols) == 1:
            col = cols[0]
            clen = nrows if (remainder == 0 or col < remainder) else nrows - 1
            columns[col] = list(ct[pos:pos + clen])
            pos += clen
        else:
            # Myszkowski: interleaved
            total_chars = sum(nrows if (remainder == 0 or c < remainder) else nrows - 1 for c in cols)
            chunk = ct[pos:pos + total_chars]
            pos += total_chars

            # Distribute: row by row across the cols
            col_lists = {c: [] for c in cols}
            ci = 0
            for row in range(nrows):
                for col in cols:
                    clen = nrows if (remainder == 0 or col < remainder) else nrows - 1
                    if row < clen and ci < len(chunk):
                        col_lists[col].append(chunk[ci])
                        ci += 1
            for col in cols:
                columns[col] = col_lists[col]

    # Read row by row
    result = []
    for row in range(nrows):
        for col in range(width):
            if col in columns and row < len(columns[col]):
                result.append(columns[col][row])
    return ''.join(result)


for kw in ["ABSCISSA", "KRYPTOS", "PALIMPSEST", "BERLINCLOCK"]:
    for trans_fn, dir_name in [(myszkowski_encrypt, "MyszE"), (myszkowski_decrypt, "MyszD")]:
        try:
            reordered = trans_fn(K4, kw)
        except Exception:
            continue
        if len(reordered) != 97:
            continue

        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for dec_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                    pt = dec_fn(reordered, sub_kw, alpha)
                    major, minor = check_cribs(pt)
                    if major or minor:
                        s = score_result(major, minor)
                        desc = f"{dir_name}({kw})+{fn_name}({sub_kw},{alpha_name})"
                        results.append((s, desc, pt, major + minor))
                    count5 += 1

        # No substitution
        major, minor = check_cribs(reordered)
        if major or minor:
            s = score_result(major, minor)
            desc = f"{dir_name}({kw})-NoSub"
            results.append((s, desc, reordered, major + minor))

print(f"  Tested {count5:,} configs, {len(results)} hits total")

# ─── SECTION 6: Rail fence ──────────────────────────────────────────────────

print("SECTION 6: Rail fence cipher (2-30 rails)")
count6 = 0

def rail_fence_decrypt(ct, rails):
    """Decrypt rail fence cipher."""
    n = len(ct)
    # Build the rail pattern
    pattern = []
    rail = 0
    direction = 1
    for i in range(n):
        pattern.append(rail)
        rail += direction
        if rail >= rails or rail < 0:
            direction *= -1
            rail += 2 * direction

    # Count chars per rail
    rail_counts = [0] * rails
    for r in pattern:
        rail_counts[r] += 1

    # Fill rails
    rail_chars = {}
    pos = 0
    for r in range(rails):
        rail_chars[r] = list(ct[pos:pos + rail_counts[r]])
        pos += rail_counts[r]

    # Read off
    rail_pos = [0] * rails
    result = []
    for r in pattern:
        result.append(rail_chars[r][rail_pos[r]])
        rail_pos[r] += 1
    return ''.join(result)

def rail_fence_encrypt(pt, rails):
    """Encrypt with rail fence (for testing both directions)."""
    n = len(pt)
    rail_strings = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for i in range(n):
        rail_strings[rail].append(pt[i])
        rail += direction
        if rail >= rails or rail < 0:
            direction *= -1
            rail += 2 * direction
    return ''.join(''.join(r) for r in rail_strings)


for rails in range(2, 31):
    for trans_fn, dir_name in [(rail_fence_encrypt, "RailE"), (rail_fence_decrypt, "RailD")]:
        reordered = trans_fn(K4, rails)
        if len(reordered) != 97:
            continue

        for sub_kw in KEYWORDS:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for dec_fn, fn_name in [(vigenere_decrypt, "Vig"), (beaufort_decrypt, "Beau")]:
                    pt = dec_fn(reordered, sub_kw, alpha)
                    major, minor = check_cribs(pt)
                    if major or minor:
                        s = score_result(major, minor)
                        desc = f"{dir_name}({rails})+{fn_name}({sub_kw},{alpha_name})"
                        results.append((s, desc, pt, major + minor))
                    count6 += 1

        # No sub
        major, minor = check_cribs(reordered)
        if major or minor:
            s = score_result(major, minor)
            desc = f"{dir_name}({rails})-NoSub"
            results.append((s, desc, reordered, major + minor))

print(f"  Tested {count6:,} configs, {len(results)} hits total")

# ═══════════════════════════════════════════════════════════════════════════════

total = count + count2 + count3 + count4 + count5 + count6
print(f"\n{'=' * 80}")
print(f"GRAND TOTAL: {total:,} configurations tested")
print(f"RESULTS: {len(results)} with any crib matches")
print(f"{'=' * 80}")

if results:
    results.sort(key=lambda x: -x[0])
    print("\nTOP RESULTS (sorted by score):")
    for i, (score, desc, pt, cribs) in enumerate(results[:50]):
        crib_str = ', '.join(f"{c}@{p}" for c, p in cribs)
        print(f"  {i+1:3d}. [score={score:3d}] {desc}")
        print(f"       Cribs: {crib_str}")
        print(f"       PT: {pt[:80]}")
        print()

    # Check for any MAJOR crib hits
    major_hits = [r for r in results if r[0] >= 50]
    if major_hits:
        print("!!! MAJOR CRIB MATCHES FOUND !!!")
        for s, d, pt, c in major_hits:
            print(f"  SCORE {s}: {d}")
            print(f"  PT: {pt}")
            print(f"  Cribs: {c}")
    else:
        print("No major crib matches (EASTNORTHEAST or BERLINCLOCK). All hits are partial/minor.")
else:
    print("\nZERO crib matches.")
