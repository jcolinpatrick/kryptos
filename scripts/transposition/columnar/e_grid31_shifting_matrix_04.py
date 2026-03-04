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
"Shifting matrix" transposition — Scheidt's term.

HYPOTHESIS: Write text into rows of width W, then shift each row
left/right by amounts derived from keyword, then read columns.
This is columnar with pre-shifted rows — standard columnar tests
wouldn't detect it because the row alignment is disrupted.

Also test: shifted READ pattern (diagonal offsets) and
"matrix code" variants (Polybius-style coordinate transposition).
"""
import itertools

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]

CRIB_MAJOR = ["EASTNORTHEAST", "BERLINCLOCK"]
CRIB_MINOR = ["NORTHEAST", "BERLIN", "CLOCK", "SLOWLY", "CHAMBER",
              "CANDLE", "MIST", "EAST", "NORTH"]


def vigenere_decrypt(ct, key, alpha):
    idx = {ch: i for i, ch in enumerate(alpha)}
    n = len(alpha)
    return ''.join(alpha[(idx[c] - idx[key[i % len(key)]]) % n] for i, c in enumerate(ct))


def beaufort_decrypt(ct, key, alpha):
    idx = {ch: i for i, ch in enumerate(alpha)}
    n = len(alpha)
    return ''.join(alpha[(idx[key[i % len(key)]] - idx[c]) % n] for i, c in enumerate(ct))


def check_cribs(text):
    major = [(c, text.index(c)) for c in CRIB_MAJOR if c in text]
    minor = [(c, text.index(c)) for c in CRIB_MINOR
             if c in text and not any(c in m[0] for m in major)]
    return major, minor


def score(major, minor):
    return sum(len(c) for c, _ in major) * 10 + sum(len(c) for c, _ in minor)


def keyword_shifts(keyword, width, alphabet):
    """Get shift values from keyword letters (their alphabet positions)."""
    idx = {ch: i for i, ch in enumerate(alphabet)}
    nrows = (97 + width - 1) // width
    shifts = []
    for r in range(nrows):
        key_ch = keyword[r % len(keyword)]
        shifts.append(idx[key_ch] % width)
    return shifts


def keyword_shifts_direct(keyword, width):
    """Shift values = keyword letter positions mod width, using ordinal values."""
    nrows = (97 + width - 1) // width
    shifts = []
    for r in range(nrows):
        key_ch = keyword[r % len(keyword)]
        shifts.append((ord(key_ch) - ord('A')) % width)
    return shifts


def shifted_matrix_encrypt(text, width, shifts, col_order=None):
    """Write text in rows of width W, shift each row left by shifts[row],
    then read columns in col_order."""
    nrows = (len(text) + width - 1) // width
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        # Shift row r left by shifts[r]
        new_c = (c - shifts[r]) % width
        grid[(r, new_c)] = ch

    if col_order is None:
        col_order = list(range(width))

    result = []
    for col in col_order:
        for row in range(nrows):
            if (row, col) in grid:
                result.append(grid[(row, col)])
    return ''.join(result)


def shifted_matrix_decrypt(ct, width, shifts, col_order=None):
    """Inverse: distribute CT into columns, unshift rows, read row by row."""
    n = len(ct)
    nrows = (n + width - 1) // width
    remainder = n % width

    if col_order is None:
        col_order = list(range(width))

    # Determine which cells exist AFTER shifting
    # The shift moves cells around, but the EMPTY cells in the last row stay relative
    # to the SHIFTED positions. This is complex — let's think carefully.
    #
    # In the original grid (before shift), cells exist at (r, c) for:
    #   r < nrows-1: all c in [0, width)
    #   r = nrows-1: c in [0, remainder) if remainder > 0, else all c
    #
    # After shifting row r left by shifts[r]:
    #   Original (r, c) → Shifted (r, (c - shifts[r]) % width)
    #
    # For the last row (if partial), only original c in [0, remainder) exist,
    # so after shifting, they're at (nrows-1, (c - shifts[nrows-1]) % width) for c < remainder

    # Build set of cells that exist in shifted grid
    cells = set()
    for r in range(nrows):
        max_c = width if (r < nrows - 1 or remainder == 0) else remainder
        for c in range(max_c):
            new_c = (c - shifts[r]) % width
            cells.add((r, new_c))

    # Count chars per column in shifted grid
    col_counts = {}
    for col in range(width):
        col_counts[col] = sum(1 for r in range(nrows) if (r, col) in cells)

    # Fill columns from CT in col_order
    columns = {}
    pos = 0
    for col in col_order:
        cnt = col_counts.get(col, 0)
        columns[col] = list(ct[pos:pos + cnt])
        pos += cnt

    # Read shifted grid column by column to rebuild it
    shifted_grid = {}
    col_positions = {col: 0 for col in range(width)}
    for col in col_order:
        for row in range(nrows):
            if (row, col) in cells:
                shifted_grid[(row, col)] = columns[col][col_positions[col]]
                col_positions[col] += 1

    # Unshift: reverse the shift to get original positions
    result_grid = {}
    for (r, new_c), ch in shifted_grid.items():
        orig_c = (new_c + shifts[r]) % width
        result_grid[(r, orig_c)] = ch

    # Read row by row from original positions
    result = []
    for r in range(nrows):
        for c in range(width):
            if (r, c) in result_grid:
                result.append(result_grid[(r, c)])
    return ''.join(result)


# ─── Diagonal reading ────────────────────────────────────────────────────────

def diagonal_read_shifted(text, width, offset=1):
    """Write text in rows, read diagonals with given step offset."""
    nrows = (len(text) + width - 1) // width
    grid = {}
    for i, ch in enumerate(text):
        r, c = divmod(i, width)
        grid[(r, c)] = ch

    result = []
    for start_col in range(width):
        r, c = 0, start_col
        while r < nrows:
            if (r, c) in grid:
                result.append(grid[(r, c)])
            r += 1
            c = (c + offset) % width
    return ''.join(result)


def diagonal_decrypt(ct, width, offset=1):
    """Inverse of diagonal reading: figure out the reading sequence, then place."""
    nrows = (len(ct) + width - 1) // width

    # Build the reading order
    grid_cells = {}
    for i, ch in enumerate(ct):
        r, c = divmod(i, width)
        grid_cells[(r, c)] = None

    order = []
    for start_col in range(width):
        r, c = 0, start_col
        while r < nrows:
            if (r, c) in grid_cells:
                order.append((r, c))
            r += 1
            c = (c + offset) % width

    if len(order) != len(ct):
        return None

    # Place CT in original grid positions
    result_grid = {}
    for i, (r, c) in enumerate(order):
        result_grid[(r, c)] = ct[i]

    # Read row by row
    result = []
    for r in range(nrows):
        for c in range(width):
            if (r, c) in result_grid:
                result.append(result_grid[(r, c)])
    return ''.join(result)


results = []
print("=" * 80)
print("SHIFTING MATRIX + DIAGONAL TRANSPOSITION SEARCH")
print("=" * 80)

# ─── SECTION 1: Shifting matrix ─────────────────────────────────────────────

print("\nSECTION 1: Shifting matrix (row shifts from keyword)")
count1 = 0

WIDTHS = [7, 8, 10, 13, 14, 21, 28, 31]

for width in WIDTHS:
    for shift_kw in KEYWORDS:
        # Multiple shift derivations
        for alpha in [AZ, KA]:
            shifts = keyword_shifts(shift_kw, width, alpha)

            # Also try negative (right) shifts
            for direction in [1, -1]:
                actual_shifts = [s * direction for s in shifts]

                # Multiple column reading orders
                col_orders = [
                    ("LTR", list(range(width))),
                    ("RTL", list(range(width-1, -1, -1))),
                ]
                for ck in KEYWORDS:
                    if len(ck) <= width:
                        indexed = [(ch, i) for i, ch in enumerate(ck[:width])]
                        sorted_idx = sorted(indexed, key=lambda x: (x[0], x[1]))
                        order = [0] * width
                        for rank, (_, pos) in enumerate(sorted_idx):
                            order[rank] = pos
                        # Extend for ncols > len(keyword)
                        full_order = list(order)
                        for j in range(len(ck), width):
                            full_order.append(j)
                        # Rebuild proper col_order
                        if len(full_order) == width:
                            co = [0] * width
                            for ci, rank in enumerate(full_order[:width]):
                                if rank < width:
                                    co[rank] = ci
                            col_orders.append((ck, co))

                for co_name, col_order in col_orders:
                    for trans_dir, trans_fn in [("E", shifted_matrix_encrypt), ("D", shifted_matrix_decrypt)]:
                        try:
                            reordered = trans_fn(K4, width, actual_shifts, col_order)
                        except Exception:
                            continue
                        if len(reordered) != 97:
                            continue

                        for sub_kw in KEYWORDS:
                            for sub_alpha_name, sub_alpha in [("AZ", AZ), ("KA", KA)]:
                                pt = vigenere_decrypt(reordered, sub_kw, sub_alpha)
                                major, minor = check_cribs(pt)
                                if major or minor:
                                    s = score(major, minor)
                                    d = "L" if direction == 1 else "R"
                                    desc = f"ShiftMat{trans_dir}(w={width},sh={shift_kw}/{alpha[:2]}/{d},col={co_name})+Vig({sub_kw},{sub_alpha_name})"
                                    results.append((s, desc, pt, major + minor))

                                pt = beaufort_decrypt(reordered, sub_kw, sub_alpha)
                                major, minor = check_cribs(pt)
                                if major or minor:
                                    s = score(major, minor)
                                    d = "L" if direction == 1 else "R"
                                    desc = f"ShiftMat{trans_dir}(w={width},sh={shift_kw}/{alpha[:2]}/{d},col={co_name})+Beau({sub_kw},{sub_alpha_name})"
                                    results.append((s, desc, pt, major + minor))
                                count1 += 1

print(f"  Tested {count1:,} configurations")

# ─── SECTION 2: Diagonal reading ────────────────────────────────────────────

print("\nSECTION 2: Diagonal reading (various offsets)")
count2 = 0

for width in WIDTHS:
    for offset in range(1, width):  # All possible diagonal offsets
        for trans_dir, trans_fn in [("E", lambda t, w, o: diagonal_read_shifted(t, w, o)),
                                     ("D", lambda t, w, o: diagonal_decrypt(t, w, o))]:
            try:
                reordered = trans_fn(K4, width, offset)
            except Exception:
                continue
            if reordered is None or len(reordered) != 97:
                continue

            for sub_kw in KEYWORDS:
                for sub_alpha_name, sub_alpha in [("AZ", AZ), ("KA", KA)]:
                    pt = vigenere_decrypt(reordered, sub_kw, sub_alpha)
                    major, minor = check_cribs(pt)
                    if major or minor:
                        s = score(major, minor)
                        desc = f"Diag{trans_dir}(w={width},off={offset})+Vig({sub_kw},{sub_alpha_name})"
                        results.append((s, desc, pt, major + minor))

                    pt = beaufort_decrypt(reordered, sub_kw, sub_alpha)
                    major, minor = check_cribs(pt)
                    if major or minor:
                        s = score(major, minor)
                        desc = f"Diag{trans_dir}(w={width},off={offset})+Beau({sub_kw},{sub_alpha_name})"
                        results.append((s, desc, pt, major + minor))
                    count2 += 1

        # No substitution
        for tfn in [diagonal_read_shifted, diagonal_decrypt]:
            try:
                reordered = tfn(K4, width, offset)
            except Exception:
                continue
            if reordered and len(reordered) == 97:
                major, minor = check_cribs(reordered)
                if major or minor:
                    results.append((score(major, minor), f"Diag(w={width},off={offset})-NoSub", reordered, major + minor))

print(f"  Tested {count2:,} configurations")

# ─── SECTION 3: "8 Lines 73" interpretation ─────────────────────────────────

print("\nSECTION 3: '8 Lines 73' — width 8 with all shift patterns from 7-letter keywords")
count3 = 0

# If "8 Lines" = 8 columns and "73" = some other parameter...
# Try: width 8, shifts from all 7-letter keywords (KRYPTOS), also 8-letter (ABSCISSA)
# Also try: first 73 chars + last 24 chars (crib positions?) treated differently

# Exhaustive: width 8, all possible shift patterns from KRYPTOS (each shift 0-7)
# That's 7 unique shift values for 13 rows at width 8
# KRYPTOS shifts mod 8: K=10%8=2, R=17%8=1, Y=24%8=0, P=15%8=7, T=19%8=3, O=14%8=6, S=18%8=2
kryptos_shifts_mod8 = [2, 1, 0, 7, 3, 6, 2]

# Test with shifts = KRYPTOS letter values mod 8
for width in [8]:
    for shift_kw in KEYWORDS:
        nrows = (97 + width - 1) // width  # 13 rows
        shifts_basic = [(ord(shift_kw[r % len(shift_kw)]) - ord('A')) % width for r in range(nrows)]

        for direction in [1, -1]:
            actual_shifts = [s * direction for s in shifts_basic]

            # Test with LTR and RTL column orders
            for co_name, col_order in [("LTR", list(range(width))), ("RTL", list(range(width-1,-1,-1)))]:
                for trans_dir, trans_fn in [("E", shifted_matrix_encrypt), ("D", shifted_matrix_decrypt)]:
                    try:
                        reordered = trans_fn(K4, width, actual_shifts, col_order)
                    except Exception:
                        continue
                    if len(reordered) != 97:
                        continue

                    for sub_kw in KEYWORDS:
                        for sub_alpha_name, sub_alpha in [("AZ", AZ), ("KA", KA)]:
                            pt = vigenere_decrypt(reordered, sub_kw, sub_alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score(major, minor)
                                d = "L" if direction == 1 else "R"
                                desc = f"8Lines(sh={shift_kw}/{d},col={co_name},{trans_dir})+Vig({sub_kw},{sub_alpha_name})"
                                results.append((s, desc, pt, major + minor))

                            pt = beaufort_decrypt(reordered, sub_kw, sub_alpha)
                            major, minor = check_cribs(pt)
                            if major or minor:
                                s = score(major, minor)
                                d = "L" if direction == 1 else "R"
                                desc = f"8Lines(sh={shift_kw}/{d},col={co_name},{trans_dir})+Beau({sub_kw},{sub_alpha_name})"
                                results.append((s, desc, pt, major + minor))
                            count3 += 1

# Also: width 8 with KRYPTOS-keyed column order + shifts
for shift_kw in KEYWORDS:
    nrows = (97 + 8 - 1) // 8
    shifts = [(ord(shift_kw[r % len(shift_kw)]) - ord('A')) % 8 for r in range(nrows)]

    for direction in [1, -1]:
        actual_shifts = [s * direction for s in shifts]

        for ck in ["ABSCISSA"]:  # 8-letter keyword for 8 columns
            co = []
            indexed = [(ch, i) for i, ch in enumerate(ck)]
            sorted_idx = sorted(indexed, key=lambda x: (x[0], x[1]))
            for rank, (_, pos) in enumerate(sorted_idx):
                co.append(pos)
            # co is now the column reading order derived from ABSCISSA

            for trans_fn, td in [(shifted_matrix_encrypt, "E"), (shifted_matrix_decrypt, "D")]:
                try:
                    reordered = trans_fn(K4, 8, actual_shifts, co)
                except Exception:
                    continue
                if len(reordered) != 97:
                    continue

                for sub_kw in KEYWORDS:
                    for sa_name, sa in [("AZ", AZ), ("KA", KA)]:
                        pt = vigenere_decrypt(reordered, sub_kw, sa)
                        major, minor = check_cribs(pt)
                        if major or minor:
                            results.append((score(major, minor),
                                f"8Lines(sh={shift_kw}/col=ABSCISSA/{td})+Vig({sub_kw},{sa_name})",
                                pt, major + minor))
                        pt = beaufort_decrypt(reordered, sub_kw, sa)
                        major, minor = check_cribs(pt)
                        if major or minor:
                            results.append((score(major, minor),
                                f"8Lines(sh={shift_kw}/col=ABSCISSA/{td})+Beau({sub_kw},{sa_name})",
                                pt, major + minor))
                        count3 += 1

print(f"  Tested {count3:,} configurations")

# ─── SECTION 4: Scytale (wrap around cylinder) ──────────────────────────────

print("\nSECTION 4: Scytale cipher (helical wrap)")
count4 = 0

def scytale_encrypt(text, circumference):
    """Scytale: write around cylinder with given circumference, read off linearly."""
    n = len(text)
    cols = (n + circumference - 1) // circumference
    result = []
    for c in range(cols):
        for r in range(circumference):
            pos = r * cols + c
            if pos < n:
                result.append(text[pos])
    return ''.join(result)

def scytale_decrypt(ct, circumference):
    """Inverse scytale."""
    n = len(ct)
    cols = (n + circumference - 1) // circumference
    result = [''] * n
    pos = 0
    for c in range(cols):
        for r in range(circumference):
            idx = r * cols + c
            if idx < n and pos < n:
                result[idx] = ct[pos]
                pos += 1
    return ''.join(result)


for circ in range(2, 49):
    for trans_fn, td in [(scytale_encrypt, "E"), (scytale_decrypt, "D")]:
        reordered = trans_fn(K4, circ)
        if len(reordered) != 97:
            continue

        for sub_kw in KEYWORDS:
            for sa_name, sa in [("AZ", AZ), ("KA", KA)]:
                pt = vigenere_decrypt(reordered, sub_kw, sa)
                major, minor = check_cribs(pt)
                if major or minor:
                    results.append((score(major, minor),
                        f"Scytale{td}(c={circ})+Vig({sub_kw},{sa_name})", pt, major + minor))
                pt = beaufort_decrypt(reordered, sub_kw, sa)
                major, minor = check_cribs(pt)
                if major or minor:
                    results.append((score(major, minor),
                        f"Scytale{td}(c={circ})+Beau({sub_kw},{sa_name})", pt, major + minor))
                count4 += 1

    # No sub
    for trans_fn, td in [(scytale_encrypt, "E"), (scytale_decrypt, "D")]:
        reordered = trans_fn(K4, circ)
        if len(reordered) == 97:
            major, minor = check_cribs(reordered)
            if major or minor:
                results.append((score(major, minor), f"Scytale{td}(c={circ})-NoSub", reordered, major + minor))

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
    for i, (s, desc, pt, cribs) in enumerate(results[:20]):
        crib_str = ', '.join(f"{c}@{p}" for c, p in cribs)
        print(f"  {i+1:2d}. [score={s:3d}] {desc}")
        print(f"      Cribs: {crib_str}")
        print(f"      PT: {pt[:80]}")
        print()

    major = [r for r in results if r[0] >= 50]
    if major:
        print("!!! MAJOR CRIB MATCHES !!!")
        for s, d, pt, c in major:
            print(f"  SCORE {s}: {d}")
            print(f"  PT: {pt}")
    else:
        print("No major crib matches.")
else:
    print("\nZERO crib matches.")
