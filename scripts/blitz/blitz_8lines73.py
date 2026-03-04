#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_8lines73.py — Exhaustive test of "8 Lines 73" interpretations for K4.

Sanborn's yellow legal pad notation: "8 Lines 73"
This script tests EVERY plausible interpretation:

A) 8-row grids: K4 laid out in 8 rows with various widths
B) "73" as a grid dimension, key parameter, or offset
C) Columnar transposition with 8-letter keywords and various widths
D) Period-8 Vigenère on rearranged CT
E) 8 rows of the 28×31 tableau as reading keys
F) K3-inspired double rotation with 8 as a dimension
G) Route ciphers on 8-row grids (spiral, snake, diagonal)
H) 73 as CT length (first 73 or last 73 chars)
I) 8 lines of 73 characters (8×73=584 — tableau subset?)
J) Combined: 8-col columnar then Vig with period matching

All candidates tested against Vig/Beaufort × multiple keywords × AZ/KA alphabets.
"""

from __future__ import annotations

import itertools
import math
import sys
import time

sys.path.insert(0, "scripts")
sys.path.insert(0, "src")

from kbot_harness import (
    K4_CARVED,
    K4_LEN,
    AZ,
    KA,
    KEYWORDS,
    CRIBS,
    apply_permutation,
    beau_decrypt,
    has_cribs,
    score_text,
    score_text_per_char,
    test_perm,
    test_unscramble,
    vig_decrypt,
)

# ── Globals ─────────────────────────────────────────────────────────────────

BEST_SCORE = -9999.0
BEST_RESULT = None
RESULTS = []
TOTAL_TESTED = 0
CRIB_HITS = []

# K3 ciphertext and plaintext for reference
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI"
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOET"
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT"
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR"
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# Full bottom-half grid (K3 + ? + K4, width 31)
BOTTOM_HALF = K3_CT + "?" + K4_CARVED  # 336 + 1 + 97 = 434


def record(label: str, candidate_ct: str, extra: str = ""):
    """Test a candidate CT ordering and record if interesting."""
    global BEST_SCORE, BEST_RESULT, TOTAL_TESTED
    TOTAL_TESTED += 1

    if len(candidate_ct) != 97:
        return

    for key in KEYWORDS:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(candidate_ct, key, alpha)
                except (ValueError, IndexError):
                    continue

                crib_hits = has_cribs(pt)
                sc = score_text_per_char(pt)

                if crib_hits:
                    msg = f"*** CRIB HIT *** [{label}] {cipher_name}/{key}/{alpha_name}: {pt[:50]}... cribs={crib_hits}"
                    print(msg)
                    CRIB_HITS.append({
                        "label": label,
                        "ct": candidate_ct,
                        "pt": pt,
                        "key": key,
                        "cipher": cipher_name,
                        "alpha": alpha_name,
                        "cribs": crib_hits,
                        "score": sc,
                        "extra": extra,
                    })

                if sc > BEST_SCORE:
                    BEST_SCORE = sc
                    BEST_RESULT = {
                        "label": label,
                        "ct": candidate_ct,
                        "pt": pt,
                        "key": key,
                        "cipher": cipher_name,
                        "alpha": alpha_name,
                        "score": sc,
                        "extra": extra,
                    }

                if sc > -5.5:
                    RESULTS.append({
                        "label": label,
                        "ct": candidate_ct[:30] + "...",
                        "pt": pt[:40] + "...",
                        "key": key,
                        "cipher": cipher_name,
                        "alpha": alpha_name,
                        "score": sc,
                        "extra": extra,
                    })


# ── Helper functions ────────────────────────────────────────────────────────

def columnar_read(text: str, ncols: int, col_order: list[int]) -> str:
    """Read text written row-by-row into ncols columns, read by col_order."""
    nrows = math.ceil(len(text) / ncols)
    grid = []
    for r in range(nrows):
        row = text[r * ncols : (r + 1) * ncols]
        grid.append(row)
    result = []
    for c in col_order:
        for r in range(nrows):
            if c < len(grid[r]):
                result.append(grid[r][c])
    return "".join(result)


def columnar_unread(ct: str, ncols: int, col_order: list[int]) -> str:
    """Inverse of columnar_read: given CT read by columns, reconstruct row-by-row."""
    nrows = math.ceil(len(ct) / ncols)
    # Figure out how many chars in each column
    full_cols = len(ct) % ncols  # number of columns with nrows chars
    if full_cols == 0:
        full_cols = ncols

    col_lengths = []
    for c in range(ncols):
        # Find the position of column c in the read order
        read_pos = col_order.index(c)
        if full_cols == ncols:
            col_lengths.append(nrows)
        elif read_pos < full_cols:
            col_lengths.append(nrows)
        else:
            col_lengths.append(nrows - 1)

    # Actually, we need lengths by read order
    cols_by_order = {}
    idx = 0
    for read_idx, c in enumerate(col_order):
        # Determine this column's length
        # Column c has nrows chars if c < (len % ncols), else nrows-1
        # But we need to account for irregular grid
        if len(ct) % ncols == 0:
            clen = nrows
        else:
            # Columns 0..(remainder-1) have nrows, rest have nrows-1
            # But this depends on which columns are "full" in the original grid
            # Full columns are 0..(len%ncols - 1)
            if c < (len(ct) % ncols):
                clen = nrows
            else:
                clen = nrows - 1
        cols_by_order[c] = ct[idx:idx + clen]
        idx += clen

    # Reconstruct grid
    result = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(cols_by_order.get(c, "")):
                result.append(cols_by_order[c][r])
    return "".join(result)


def keyword_to_order(keyword: str) -> list[int]:
    """Convert keyword to column ordering (alphabetical position)."""
    indexed = sorted(range(len(keyword)), key=lambda i: (keyword[i], i))
    order = [0] * len(keyword)
    for rank, orig_idx in enumerate(indexed):
        order[orig_idx] = rank
    return order


def keyword_col_order(keyword: str) -> list[int]:
    """Return the column read order derived from keyword."""
    indexed = sorted(range(len(keyword)), key=lambda i: (keyword[i], i))
    return indexed


def route_spiral_cw(text: str, nrows: int, ncols: int) -> str:
    """Read text in CW spiral from top-left on nrows x ncols grid."""
    grid = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(ncols):
            if idx < len(text):
                row.append(text[idx])
                idx += 1
            else:
                row.append("")
        grid.append(row)

    result = []
    top, bottom, left, right = 0, nrows - 1, 0, ncols - 1
    while top <= bottom and left <= right:
        for c in range(left, right + 1):
            if grid[top][c]:
                result.append(grid[top][c])
        top += 1
        for r in range(top, bottom + 1):
            if grid[r][right]:
                result.append(grid[r][right])
        right -= 1
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if grid[bottom][c]:
                    result.append(grid[bottom][c])
            bottom -= 1
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if grid[r][left]:
                    result.append(grid[r][left])
            left += 1
    return "".join(result)


def route_snake(text: str, nrows: int, ncols: int) -> str:
    """Read text in snake (boustrophedon) pattern."""
    grid = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(ncols):
            if idx < len(text):
                row.append(text[idx])
                idx += 1
            else:
                row.append("")
        grid.append(row)

    result = []
    for r in range(nrows):
        if r % 2 == 0:
            for c in range(ncols):
                if grid[r][c]:
                    result.append(grid[r][c])
        else:
            for c in range(ncols - 1, -1, -1):
                if grid[r][c]:
                    result.append(grid[r][c])
    return "".join(result)


def route_columns_down(text: str, nrows: int, ncols: int) -> str:
    """Read text column by column, top to bottom."""
    grid = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(ncols):
            if idx < len(text):
                row.append(text[idx])
                idx += 1
            else:
                row.append("")
        grid.append(row)

    result = []
    for c in range(ncols):
        for r in range(nrows):
            if grid[r][c]:
                result.append(grid[r][c])
    return "".join(result)


def route_diagonal(text: str, nrows: int, ncols: int) -> str:
    """Read text along diagonals (top-right to bottom-left)."""
    grid = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(ncols):
            if idx < len(text):
                row.append(text[idx])
                idx += 1
            else:
                row.append("")
        grid.append(row)

    result = []
    for d in range(nrows + ncols - 1):
        for r in range(nrows):
            c = d - r
            if 0 <= c < ncols and grid[r][c]:
                result.append(grid[r][c])
    return "".join(result)


def double_rotation(text: str, w1: int, w2: int) -> str:
    """K3-style double rotation: write into w1 cols, rotate CW, read; write into w2 cols, rotate CW, read."""
    n = len(text)
    if n % w1 != 0 or n % w2 != 0:
        return ""

    h1 = n // w1
    # Write into w1 cols (h1 rows), rotate CW, read
    # Rotate CW: new grid is h1 cols x w1 rows
    # new[r][c] = old[h1-1-c][r]
    inter = []
    for r in range(w1):
        for c in range(h1):
            old_r = h1 - 1 - c
            old_c = r
            inter.append(text[old_r * w1 + old_c])
    inter_text = "".join(inter)

    h2 = n // w2
    # Write into w2 cols (h2 rows), rotate CW, read
    result = []
    for r in range(w2):
        for c in range(h2):
            old_r = h2 - 1 - c
            old_c = r
            result.append(inter_text[old_r * w2 + old_c])
    return "".join(result)


def pad_to_length(text: str, target: int, pad_char: str = "X") -> str:
    """Pad text with pad_char to reach target length."""
    return text + pad_char * (target - len(text))


# ── SECTION A: 8-row grids with various widths ─────────────────────────────

def test_8row_grids():
    """Test K4 in 8-row grids, read by columns and routes."""
    print("\n=== SECTION A: 8-row grids ===")
    ct = K4_CARVED

    # Try widths 12 and 13 (8*12=96, 8*13=104)
    for ncols in range(2, 50):
        nrows = 8
        needed = nrows * ncols
        if needed < 97:
            padded = ct  # will have short last row
        else:
            padded = pad_to_length(ct, needed)

        # Column-by-column read
        col_ct = route_columns_down(ct, nrows, ncols)
        if len(col_ct) == 97:
            record(f"A:8row_coldown_w{ncols}", col_ct)

        # Reverse column read
        rev_col = route_columns_down(ct, nrows, ncols)
        if rev_col:
            record(f"A:8row_coldown_rev_w{ncols}", rev_col[::-1])

        # Snake read
        snake_ct = route_snake(ct, nrows, ncols)
        if len(snake_ct) == 97:
            record(f"A:8row_snake_w{ncols}", snake_ct)

        # Spiral read
        spiral_ct = route_spiral_cw(ct, nrows, ncols)
        if len(spiral_ct) == 97:
            record(f"A:8row_spiral_w{ncols}", spiral_ct)

        # Diagonal read
        diag_ct = route_diagonal(ct, nrows, ncols)
        if len(diag_ct) == 97:
            record(f"A:8row_diag_w{ncols}", diag_ct)

    # Also try with ncols=8 (swap rows/cols interpretation)
    for nrows_var in range(2, 50):
        ncols_var = 8
        col_ct = route_columns_down(ct, nrows_var, ncols_var)
        if len(col_ct) == 97:
            record(f"A:8col_coldown_r{nrows_var}", col_ct)

        snake_ct = route_snake(ct, nrows_var, ncols_var)
        if len(snake_ct) == 97:
            record(f"A:8col_snake_r{nrows_var}", snake_ct)

    print(f"  Section A: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION B: "73" as dimension/parameter ──────────────────────────────────

def test_73_parameter():
    """Test 73 as a grid dimension, offset, or subsection length."""
    print("\n=== SECTION B: 73 as parameter ===")
    ct = K4_CARVED

    # 73 chars from various positions
    for start in range(25):  # first 73 from position 0..24
        sub = ct[start:start + 73]
        if len(sub) == 73:
            record(f"B:first73_from{start}", sub + ct[:start] + ct[start + 73:],
                   extra=f"73 chars from pos {start}")

    # Last 73, first 24 appended
    record(f"B:last73+first24", ct[24:] + ct[:24])
    record(f"B:first73+last24", ct[:73] + ct[73:])

    # 73 as column width (8 rows would need ~9 extra)
    # skip if not 97

    # 73 as a skip/step
    for step in [73, 97 - 73]:  # step=73 and step=24
        perm = [(i * step) % 97 for i in range(97)]
        if len(set(perm)) == 97:
            reordered = apply_permutation(ct, perm)
            record(f"B:step{step}_mod97", reordered)

    # Additive: step through positions adding 73 each time
    for start in range(97):
        perm = [(start + i * 73) % 97 for i in range(97)]
        if len(set(perm)) == 97:
            reordered = apply_permutation(ct, perm)
            record(f"B:add73_start{start}", reordered)

    # 73 as period with 8 as key length
    # Try reading 73 chars at period 8
    for offset in range(8):
        selected = ct[offset::8]
        record(f"B:period8_offset{offset}", pad_to_length(selected, 97) if len(selected) < 97 else selected[:97])

    print(f"  Section B: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION C: Columnar transposition with 8-letter keywords ────────────────

def test_columnar_8():
    """Columnar transposition with width 8 using various keyword orderings."""
    print("\n=== SECTION C: Columnar transposition width 8 ===")
    ct = K4_CARVED

    # Keywords of length 8
    kw8_candidates = ["ABSCISSA", "KRYPTOSS", "PALLIMPS", "EASTNO", "SCHEIDT"]
    # Also try all permutations of 8 columns (8! = 40320)
    # That's tractable!

    # First, try keyword-derived orderings
    for kw in KEYWORDS:
        if len(kw) <= 12:
            order = keyword_col_order(kw)
            # Columnar read (write row-by-row, read by keyword columns)
            col_ct = columnar_read(ct, len(kw), order)
            if len(col_ct) == 97:
                record(f"C:colread_kw{kw}", col_ct)

            # Columnar unread (inverse: CT was written by columns, read rows)
            try:
                unread_ct = columnar_unread(ct, len(kw), order)
                if len(unread_ct) == 97:
                    record(f"C:colunread_kw{kw}", unread_ct)
            except Exception:
                pass

    # All 8! = 40320 permutations of 8 columns
    print("  Testing all 8! column permutations (width 8)...")
    count = 0
    for perm8 in itertools.permutations(range(8)):
        perm_list = list(perm8)
        col_ct = columnar_read(ct, 8, perm_list)
        if len(col_ct) == 97:
            record(f"C:col8_perm{''.join(str(x) for x in perm_list)}", col_ct)

        # Also inverse
        try:
            unread_ct = columnar_unread(ct, 8, perm_list)
            if len(unread_ct) == 97:
                record(f"C:col8_inv_perm{''.join(str(x) for x in perm_list)}", unread_ct)
        except Exception:
            pass

        count += 1
        if count % 10000 == 0:
            print(f"    {count}/40320 perms, best={BEST_SCORE:.2f}")

    # Width 13 (8 rows of 13, -7 padding)
    print("  Testing columnar width 13 (8*13=104)...")
    padded13 = pad_to_length(ct, 104)
    for perm13 in itertools.permutations(range(13)):
        # Too many: 13! is huge. Use keyword-derived only.
        break  # Skip full enumeration

    # Width 13 with keyword orderings only
    for kw in KEYWORDS:
        if len(kw) == 13:
            order = keyword_col_order(kw)
            col_ct = columnar_read(ct, 13, order)
            record(f"C:col13_kw{kw}", col_ct)

    # Width 12 (8*12=96, need 1 extra)
    print("  Testing columnar width 12...")
    for kw in KEYWORDS:
        if len(kw) <= 12:
            # Pad kw to 12 if needed
            pass
        order12 = keyword_col_order("KRYPTOSABCDE"[:12])
        col_ct = columnar_read(ct, 12, order12)
        if len(col_ct) == 97:
            record(f"C:col12_kw{kw}", col_ct)

    print(f"  Section C: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION D: Period-8 Vigenère on rearranged CT ───────────────────────────

def test_period8_vig():
    """Try period-8 keys on various unscrambled CT orderings."""
    print("\n=== SECTION D: Period-8 Vigenère ===")
    ct = K4_CARVED

    # Generate candidate reorderings
    reorderings = [
        ("identity", ct),
        ("reversed", ct[::-1]),
    ]

    # Column-down reads at width 8
    for w in [8, 12, 13]:
        reorderings.append((f"coldown_w{w}", route_columns_down(ct, math.ceil(97 / w), w)))
        reorderings.append((f"snake_w{w}", route_snake(ct, math.ceil(97 / w), w)))

    # For each reordering, try all 8-char keyword substrings and period-8 keys
    tested_keys = set()
    for kw in KEYWORDS:
        if len(kw) >= 8:
            tested_keys.add(kw[:8])
        if len(kw) <= 8:
            tested_keys.add(kw)

    # Also try KRYPTOS padded
    tested_keys.add("KRYPTOSA")
    tested_keys.add("KRYPTOSB")
    tested_keys.add("ABSCISSA")

    for label, reordered in reorderings:
        if len(reordered) != 97:
            continue
        for key in tested_keys:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    pt = cipher_fn(reordered, key, alpha)
                    crib_hits = has_cribs(pt)
                    sc = score_text_per_char(pt)
                    if crib_hits:
                        print(f"  CRIB HIT: D:{label}/{cipher_name}/{key}/{alpha_name}: {pt[:50]}")
                        CRIB_HITS.append({
                            "label": f"D:{label}",
                            "ct": reordered,
                            "pt": pt,
                            "key": key,
                            "cipher": cipher_name,
                            "alpha": alpha_name,
                            "cribs": crib_hits,
                            "score": sc,
                        })

    print(f"  Section D: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION E: 8 rows of 28×31 tableau as reading keys ─────────────────────

def test_tableau_rows():
    """Use rows from the KA Vigenere tableau to define reading order."""
    print("\n=== SECTION E: Tableau rows as reading keys ===")

    # Build KA Vigenère tableau (26×26 body)
    tableau = []
    for r in range(26):
        row = KA[r:] + KA[:r]
        tableau.append(row)

    # The 28×31 tableau has header, 26 body rows, footer
    # Header: ABCDEFGHIJKLMNOPQRSTUVWXYZ + ABCD (30 body chars)
    # Body rows: each shifted KA with key column
    # Footer: same as header

    # Try using 8 specific tableau rows to define permutations
    # Which 8 rows? Try all C(26,8) = 1562275 — too many
    # Instead, try thematic selections:

    # KRYPTOS = rows K,R,Y,P,T,O,S,A in KA order
    kryptos_rows = [KA.index(c) for c in "KRYPTOSA"]  # 8 chars
    print(f"  KRYPTOSA row indices: {kryptos_rows}")

    # ABSCISSA = rows A,B,S,C,I,S,S,A — has repeats, use unique
    abscissa_unique = []
    for c in "ABSCISSA":
        idx = KA.index(c)
        if idx not in abscissa_unique:
            abscissa_unique.append(idx)
    print(f"  ABSCISSA unique row indices: {abscissa_unique}")

    # Use tableau row content to define column reading order
    for row_set_name, row_indices in [
        ("KRYPTOSA", kryptos_rows),
        ("ABSCISSA_uniq", abscissa_unique),
        ("first8", list(range(8))),
        ("last8", list(range(18, 26))),
        ("evens8", list(range(0, 16, 2))),
        ("odds8", list(range(1, 16, 2))),
    ]:
        # Concatenate selected rows
        selected = "".join(tableau[r] for r in row_indices)

        # Use first 97 chars as a substitution key
        if len(selected) >= 97:
            key_stream = selected[:97]
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    pt = cipher_fn(K4_CARVED, key_stream, alpha)
                    sc = score_text_per_char(pt)
                    crib_hits = has_cribs(pt)
                    if crib_hits:
                        print(f"  CRIB HIT: E:{row_set_name}/{cipher_name}/{alpha_name}: {pt[:50]}")
                    if sc > -5.5:
                        RESULTS.append({
                            "label": f"E:tableau_{row_set_name}",
                            "pt": pt[:40],
                            "score": sc,
                            "cipher": cipher_name,
                            "alpha": alpha_name,
                        })

        # Use row content to define a permutation (position of each letter)
        # Map: for each position i in K4, find K4[i] in the tableau row
        for ri in row_indices:
            row_text = tableau[ri]
            # Build permutation: position in row of K4[i] mod 26
            # This gives a 26-element mapping, not a 97-element permutation
            # Instead, use row to define column reordering
            pass

    print(f"  Section E: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION F: K3-inspired double rotation with 8 as dimension ──────────────

def test_double_rotation_8():
    """K3 used double rotation (24×14 → 8×42). Try similar with 8 as a dimension for K4."""
    print("\n=== SECTION F: Double rotation with 8 ===")
    ct = K4_CARVED

    # 97 is prime, so no exact factor pairs. We need to pad.
    # Try padding to various multiples
    for target_len in [104, 96, 112, 120, 128, 136, 144, 152, 160, 168, 176, 184, 192, 200]:
        if target_len < 97:
            continue

        padded = pad_to_length(ct, target_len)
        factors = []
        for f in range(2, target_len):
            if target_len % f == 0:
                factors.append(f)

        # Try all pairs where 8 is one dimension
        for w1 in factors:
            for w2 in factors:
                if w1 * (target_len // w1) != target_len:
                    continue
                if w2 * (target_len // w2) != target_len:
                    continue
                if 8 not in (w1, w2, target_len // w1, target_len // w2):
                    continue

                result = double_rotation(padded, w1, w2)
                if result and len(result) >= 97:
                    record(f"F:dblrot_{w1}x{target_len // w1}_{w2}x{target_len // w2}_pad{target_len}",
                           result[:97])

    # Also try with K4 embedded in the 14×31 grid (extract K4 region)
    # K4 spans rows 10-13 of the bottom half (0-indexed)
    # Row 10: 4 chars (cols 27-30), Row 11: 31, Row 12: 31, Row 13: 31 = 4+31+31+31 = 97
    # Try rotating just K4's L-shaped region
    # Read K4 from the grid by column instead of by row
    k4_grid = [
        "OBKR",                               # Row 10 partial (cols 27-30)
        "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",     # Row 11
        "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",     # Row 12
        "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",    # Row 13
    ]

    # Read by columns from the grid, treating partial first row
    # Build a full 4×31 grid with blanks for the missing first-row positions
    full_grid = [" " * 27 + "OBKR",
                 "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
                 "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
                 "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"]

    # Column read (skip blanks)
    col_read = []
    for c in range(31):
        for r in range(4):
            ch = full_grid[r][c] if c < len(full_grid[r]) else " "
            if ch != " ":
                col_read.append(ch)
    col_read_str = "".join(col_read)
    record("F:k4_14x31_colread", col_read_str)

    # Reverse column read
    col_read_rev = []
    for c in range(30, -1, -1):
        for r in range(4):
            ch = full_grid[r][c] if c < len(full_grid[r]) else " "
            if ch != " ":
                col_read_rev.append(ch)
    record("F:k4_14x31_colread_rev", "".join(col_read_rev))

    # Bottom-up column read
    col_read_bu = []
    for c in range(31):
        for r in range(3, -1, -1):
            ch = full_grid[r][c] if c < len(full_grid[r]) else " "
            if ch != " ":
                col_read_bu.append(ch)
    record("F:k4_14x31_colread_bottomup", "".join(col_read_bu))

    print(f"  Section F: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION G: Route ciphers on 8-row grids ─────────────────────────────────

def test_routes_8row():
    """Various route cipher patterns on 8-row grids."""
    print("\n=== SECTION G: Route ciphers on 8-row grids ===")
    ct = K4_CARVED

    for ncols in [12, 13, 14, 15, 16, 17, 31]:
        nrows = 8
        if nrows * ncols < 97:
            continue
        padded = pad_to_length(ct, nrows * ncols) if nrows * ncols > 97 else ct

        # All four spiral directions
        spiral = route_spiral_cw(ct, nrows, ncols)
        record(f"G:spiral_8x{ncols}", spiral[:97])

        # Snake (boustrophedon)
        snake = route_snake(ct, nrows, ncols)
        record(f"G:snake_8x{ncols}", snake[:97])

        # Column-first
        coldown = route_columns_down(ct, nrows, ncols)
        record(f"G:coldown_8x{ncols}", coldown[:97])

        # Diagonal
        diag = route_diagonal(ct, nrows, ncols)
        record(f"G:diag_8x{ncols}", diag[:97])

        # Reverse of each
        record(f"G:spiral_rev_8x{ncols}", spiral[:97][::-1])
        record(f"G:snake_rev_8x{ncols}", snake[:97][::-1])
        record(f"G:coldown_rev_8x{ncols}", coldown[:97][::-1])

    # Also ncols=8 interpretation
    for nrows_var in [12, 13, 14, 15, 16, 17, 31]:
        ncols_var = 8
        spiral = route_spiral_cw(ct, nrows_var, ncols_var)
        record(f"G:spiral_{nrows_var}x8", spiral[:97])
        snake = route_snake(ct, nrows_var, ncols_var)
        record(f"G:snake_{nrows_var}x8", snake[:97])
        coldown = route_columns_down(ct, nrows_var, ncols_var)
        record(f"G:coldown_{nrows_var}x8", coldown[:97])

    print(f"  Section G: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION H: 8 lines of 73 chars (8×73=584) ──────────────────────────────

def test_8x73():
    """8 lines of 73: 584 chars from the full cipher panel."""
    print("\n=== SECTION H: 8×73 from cipher panel ===")

    # Full K1-K4 (approximate: K1=63, K2=69-ish, K3=336, K4=97)
    # The "8 lines 73" might refer to something on the 28×31=868 grid
    # 8 rows × 73 = 584, or 73 rows × 8 = 584

    # From the 28×31 grid, 8 rows = 8×31 = 248
    # 73 might mean: read 73 chars from the grid, skipping some

    # Try: every 8th character from the master grid
    # Or: 73 positions selected by an 8-step pattern

    ct = K4_CARVED

    # Simple: read every 8th char
    for start in range(8):
        selected = ct[start::8]
        # This gives 12-13 chars, not 97. But test what we get.
        # Can't make 97 from this alone.
        pass

    # 73 columns × some row count?
    # 73 doesn't divide 97

    # Interleave: split K4 into 8 groups, reassemble
    for group_size in [8, 12, 13]:
        # Split into groups
        groups = [ct[i::group_size] for i in range(group_size)]
        # Reassemble in different orders
        for perm in itertools.permutations(range(min(group_size, 8))):
            if group_size > 8:
                break
            reassembled = "".join(groups[p] for p in perm)
            if len(reassembled) >= 97:
                record(f"H:interleave{group_size}_{''.join(str(x) for x in perm)}", reassembled[:97])

    print(f"  Section H: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION I: Combined 8-col columnar + Vig ───────────────────────────────

def test_combined_col8_vig():
    """Columnar with 8 columns, THEN Vigenère with various keys."""
    print("\n=== SECTION I: Columnar(8) + Vigenère ===")
    ct = K4_CARVED

    # For each 8-column permutation, unscramble, then try Vig
    # Already covered in Section C, but here we do inverse columnar
    # (CT was produced by columnar, so we reverse it)

    # Test specifically: ABSCISSA (8 letters!) as column key
    abscissa_order = keyword_col_order("ABSCISSA")
    print(f"  ABSCISSA column order: {abscissa_order}")

    # Write CT into 8 columns by keyword order, read rows
    try:
        unscrambled = columnar_unread(ct, 8, abscissa_order)
        record("I:col8_ABSCISSA_unread", unscrambled)
    except Exception:
        pass

    # Also forward
    scrambled = columnar_read(ct, 8, abscissa_order)
    record("I:col8_ABSCISSA_read", scrambled)

    # KRYPTOS (7 cols) then pad to 8
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SCHEIDT", "BERLINCL"]:
        order = keyword_col_order(kw)
        try:
            unscrambled = columnar_unread(ct, len(kw), order)
            record(f"I:col{len(kw)}_{kw}_unread", unscrambled)
        except Exception:
            pass
        scrambled = columnar_read(ct, len(kw), order)
        record(f"I:col{len(kw)}_{kw}_read", scrambled)

    print(f"  Section I: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION J: "8 Lines" as 8-step skip (decimation) ───────────────────────

def test_8step_decimation():
    """'8 Lines' as reading every 8th character (decimation/rail fence)."""
    print("\n=== SECTION J: 8-step decimation / rail fence ===")
    ct = K4_CARVED

    # Decimation: read position 0, 8, 16, ... then 1, 9, 17, ... etc
    for n_rails in [8]:
        for start_offset in range(n_rails):
            # Standard decimation
            order = []
            for rail in range(n_rails):
                pos = (rail + start_offset) % n_rails
                while pos < 97:
                    order.append(pos)
                    pos += n_rails
            if len(set(order)) == 97:
                reordered = "".join(ct[i] for i in order)
                record(f"J:decimate8_offset{start_offset}", reordered)

    # Rail fence cipher (zigzag) with 8 rails
    for n_rails in [8]:
        # Build rail fence pattern
        rails = [[] for _ in range(n_rails)]
        rail = 0
        direction = 1
        for i in range(97):
            rails[rail].append(i)
            if rail == 0:
                direction = 1
            elif rail == n_rails - 1:
                direction = -1
            rail += direction

        # Read off rails to get positions
        order = []
        for r in rails:
            order.extend(r)

        if len(set(order)) == 97:
            # CT was written in zigzag, read off rails
            reordered = "".join(ct[i] for i in order)
            record(f"J:railfence8_forward", reordered)

            # Inverse: CT is the rail fence reading, recover original
            inv_order = [0] * 97
            for new_pos, old_pos in enumerate(order):
                inv_order[old_pos] = new_pos
            reordered_inv = "".join(ct[inv_order[i]] for i in range(97))
            record(f"J:railfence8_inverse", reordered_inv)

    # Also try 73 rails (weird but test it)
    # And rail fence with other numbers of rails
    for n_rails in [7, 8, 12, 13, 24, 73]:
        rails = [[] for _ in range(n_rails)]
        rail = 0
        direction = 1
        for i in range(97):
            rails[rail].append(i)
            if rail == 0:
                direction = 1
            elif rail == n_rails - 1:
                direction = -1
            rail += direction

        order = []
        for r in rails:
            order.extend(r)

        if len(set(order)) == 97:
            reordered = "".join(ct[i] for i in order)
            record(f"J:railfence{n_rails}", reordered)

            inv_order = [0] * 97
            for new_pos, old_pos in enumerate(order):
                inv_order[old_pos] = new_pos
            reordered_inv = "".join(ct[inv_order[i]] for i in range(97))
            record(f"J:railfence{n_rails}_inv", reordered_inv)

    print(f"  Section J: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION K: Step-based permutations involving 8 and 73 ──────────────────

def test_step_permutations():
    """Try step-based permutations mod 97 using 8, 73, and related values."""
    print("\n=== SECTION K: Step permutations ===")
    ct = K4_CARVED

    # gcd(step, 97) must = 1 for full permutation (97 is prime, so all steps work)
    steps = [8, 73, 24, 7, 13, 31, 14, 42, 11, 86, 3, 4, 5, 6, 9, 10, 15, 16, 17, 19, 20, 21, 23, 25,
             26, 27, 28, 29, 30, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 43, 44, 45, 46, 47, 48,
             49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
             69, 70, 71, 72, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 87, 88, 89, 90,
             91, 92, 93, 94, 95, 96]

    for step in steps:
        for start in range(97):
            perm = [(start + i * step) % 97 for i in range(97)]
            if len(set(perm)) == 97:
                reordered = apply_permutation(ct, perm)
                record(f"K:step{step}_start{start}", reordered)

    print(f"  Section K: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION L: "8 Lines 73" as Nihilist/bifurcation ────────────────────────

def test_bifurcation():
    """Split K4 at position 73 (or into groups of 73 and 24)."""
    print("\n=== SECTION L: Bifurcation at 73 ===")
    ct = K4_CARVED

    part1 = ct[:73]   # First 73
    part2 = ct[73:]   # Last 24

    # Interleave
    interleaved = []
    i, j = 0, 0
    for pos in range(97):
        if pos % 4 < 3 and i < len(part1):  # 3:1 ratio (73:24 ≈ 3:1)
            interleaved.append(part1[i])
            i += 1
        elif j < len(part2):
            interleaved.append(part2[j])
            j += 1
        elif i < len(part1):
            interleaved.append(part1[i])
            i += 1
    record("L:interleave_73_24_3to1", "".join(interleaved))

    # Reverse part2 then concat
    record("L:73+rev24", part1 + part2[::-1])
    record("L:rev73+24", part1[::-1] + part2)
    record("L:rev73+rev24", part1[::-1] + part2[::-1])

    # Split at 24, reverse each
    p1 = ct[:24]
    p2 = ct[24:]
    record("L:rev24+73", p1[::-1] + p2)
    record("L:24+rev73", p1 + p2[::-1])

    # Weave: take alternately from 73-block and 24-block
    for stride1 in [1, 2, 3, 4, 8]:
        for stride2 in [1, 2, 3, 4, 8]:
            woven = []
            i, j = 0, 0
            while i < len(part1) or j < len(part2):
                for _ in range(stride1):
                    if i < len(part1):
                        woven.append(part1[i])
                        i += 1
                for _ in range(stride2):
                    if j < len(part2):
                        woven.append(part2[j])
                        j += 1
            if len(woven) == 97:
                record(f"L:weave_{stride1}_{stride2}", "".join(woven))

    # Also split at other positions related to 8
    for split_pos in [8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88]:
        p1 = ct[:split_pos]
        p2 = ct[split_pos:]
        # Swap
        record(f"L:swap_at_{split_pos}", p2 + p1)
        record(f"L:swap_rev_at_{split_pos}", p2[::-1] + p1[::-1])

    print(f"  Section L: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION M: K3 grid rows (8 rows of K3's working grid) ──────────────────

def test_k3_grid_8rows():
    """K3 uses 8-column and 42-row grid (8×42=336). 'Lines' could refer to K3 grid rows."""
    print("\n=== SECTION M: K3 grid structure with 8 ===")
    ct = K4_CARVED

    # K3's second grid is 8 columns × 42 rows
    # "8 Lines" could mean: use 8 of these column rails as key

    # K3 double rotation formula applied partially to K4
    # Try: only one rotation (not double)
    # Single rotation: write into w cols, rotate CW, read
    for w in [8, 12, 13, 24, 31, 42]:
        if 97 % w != 0:
            # Pad
            h = math.ceil(97 / w)
            padded = pad_to_length(ct, w * h)
        else:
            h = 97 // w
            padded = ct

        n = len(padded)
        # Write into w cols (h rows), rotate CW: new grid is h cols × w rows
        result = []
        for r in range(w):
            for c in range(h):
                old_r = h - 1 - c
                old_c = r
                result.append(padded[old_r * w + old_c])
        result_str = "".join(result)
        record(f"M:single_rot_w{w}", result_str[:97])
        record(f"M:single_rot_w{w}_rev", result_str[:97][::-1])

    # K3 step pattern on K4: -86 mod 97 = 11
    # Already tested in elimination. Skip.

    # "73" could be K3 row 73: position in K3's 42-row × 8-col grid
    # Row 73 of what? K3 only has 42 rows in the 8-col grid.
    # Maybe 73rd character of K3?
    print(f"  K3[73] = '{K3_CT[73] if 73 < len(K3_CT) else 'N/A'}'")

    print(f"  Section M: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION N: AMSCO with 8 columns ────────────────────────────────────────

def test_amsco_8():
    """AMSCO transposition with 8 columns (alternating 1-2 char cells)."""
    print("\n=== SECTION N: AMSCO 8-col ===")
    ct = K4_CARVED

    # AMSCO fills cells alternating 1-char and 2-char
    # With 8 columns, each row has ~12 chars (4×1 + 4×2 = 12)
    # 97 / 12 ≈ 8 rows (good match!)

    # Build AMSCO grid
    def amsco_fill(text, ncols, start_with_1=True):
        """Fill AMSCO grid. Returns grid[row][col] = substring."""
        grid = []
        idx = 0
        row = 0
        while idx < len(text):
            row_data = []
            for c in range(ncols):
                # Determine cell size
                if (row + c + (0 if start_with_1 else 1)) % 2 == 0:
                    size = 1
                else:
                    size = 2
                cell = text[idx:idx + size]
                if not cell:
                    break
                row_data.append(cell)
                idx += len(cell)
            grid.append(row_data)
            row += 1
        return grid

    def amsco_read_cols(grid, col_order):
        """Read AMSCO grid by column order."""
        result = []
        for c in col_order:
            for row in grid:
                if c < len(row):
                    result.append(row[c])
        return "".join(result)

    def amsco_unread(ct_text, ncols, col_order, start_with_1=True):
        """Inverse AMSCO: given CT read by columns, reconstruct row-by-row text."""
        # First, figure out cell sizes
        total = len(ct_text)
        grid_sizes = []
        idx = 0
        row = 0
        while idx < total:
            row_sizes = []
            for c in range(ncols):
                if (row + c + (0 if start_with_1 else 1)) % 2 == 0:
                    size = 1
                else:
                    size = 2
                if idx + size > total:
                    size = total - idx
                if size <= 0:
                    break
                row_sizes.append(size)
                idx += size
            grid_sizes.append(row_sizes)
            row += 1

        nrows = len(grid_sizes)

        # Calculate column lengths
        col_lengths = {}
        for c in range(ncols):
            total_col = 0
            for r in range(nrows):
                if c < len(grid_sizes[r]):
                    total_col += grid_sizes[r][c]
            col_lengths[c] = total_col

        # Split CT into columns by read order
        col_data = {}
        idx = 0
        for c in col_order:
            clen = col_lengths.get(c, 0)
            col_data[c] = ct_text[idx:idx + clen]
            idx += clen

        # Reconstruct row by row
        result = []
        col_pointers = {c: 0 for c in range(ncols)}
        for r in range(nrows):
            for c in range(ncols):
                if c < len(grid_sizes[r]):
                    size = grid_sizes[r][c]
                    ptr = col_pointers[c]
                    result.append(col_data.get(c, "")[ptr:ptr + size])
                    col_pointers[c] = ptr + size
        return "".join(result)

    # Test ABSCISSA (8 letters!) as AMSCO key
    for kw in ["ABSCISSA", "KRYPTOSA", "SCHEIDT8"[:8], "BERLINCL"]:
        if len(kw) != 8:
            kw = kw[:8]
            if len(kw) < 8:
                continue
        order = keyword_col_order(kw)
        for start_1 in [True, False]:
            grid = amsco_fill(ct, 8, start_1)
            read_ct = amsco_read_cols(grid, order)
            record(f"N:amsco8_{kw}_s{'1' if start_1 else '2'}_read", read_ct[:97])

            try:
                unread_ct = amsco_unread(ct, 8, order, start_1)
                record(f"N:amsco8_{kw}_s{'1' if start_1 else '2'}_unread", unread_ct[:97])
            except Exception:
                pass

    # Test all 8! AMSCO column orders with start_with_1=True
    print("  Testing all 8! AMSCO column orders...")
    count = 0
    for perm8 in itertools.permutations(range(8)):
        perm_list = list(perm8)
        for start_1 in [True, False]:
            grid = amsco_fill(ct, 8, start_1)
            read_ct = amsco_read_cols(grid, perm_list)
            if len(read_ct) >= 97:
                record(f"N:amsco8_p{''.join(str(x) for x in perm_list)}_s{'1' if start_1 else '2'}",
                       read_ct[:97])
        count += 1
        if count % 10000 == 0:
            print(f"    {count}/40320 perms, best={BEST_SCORE:.2f}")

    print(f"  Section N: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION O: "8 Lines 73" as grid coordinates ────────────────────────────

def test_grid_coordinates():
    """'8' and '73' as coordinates or offsets on the 28×31 grid."""
    print("\n=== SECTION O: Grid coordinates ===")
    ct = K4_CARVED

    # Row 8, Col 73 doesn't exist (31 cols max)
    # But 73 mod 31 = 11, so row 8, col 11?
    # Or: position 8*31 = 248 on the cipher grid (within K3)
    # Or: position 73 on the cipher grid

    # Read the 28×31 grid starting from various (row, col) pairs
    # Build full 868-char grid (K1+K2+?s+K3+?+K4)
    # We only have K3 and K4 easily available
    # K4 starts at position 434+336+1 = but we need full grid...

    # Use the bottom half only (K3+?+K4 = 434 chars, 14 rows × 31 cols)
    grid_text = K3_CT + "Q" + ct  # Using Q for the ? delimiter

    # Read starting from position 73 of this grid
    for start in [73, 8, 8 * 31, 73 - 31]:
        if start < 0 or start >= len(grid_text):
            continue
        reordered = grid_text[start:start + 97]
        if len(reordered) == 97:
            record(f"O:grid_from_pos{start}", reordered)

    # Read every 8th char from position 73
    selected = ""
    for i in range(73, len(grid_text), 8):
        selected += grid_text[i]
        if len(selected) == 97:
            break
    if len(selected) == 97:
        record(f"O:every8th_from73", selected)

    # Diagonal reading: start at (row=8, col=0), step by (1, 73 mod 31)
    # Various diagonal steps
    for row_start in [0, 7, 8]:
        for col_start in [0, 10, 11, 72]:
            if col_start >= 31:
                continue
            diag_chars = []
            r, c = row_start, col_start
            visited = set()
            while len(diag_chars) < 97:
                pos = r * 31 + c
                if pos >= len(grid_text) or pos in visited:
                    break
                visited.add(pos)
                diag_chars.append(grid_text[pos])
                r = (r + 1) % 14
                c = (c + 8) % 31  # step 8 columns
            if len(diag_chars) == 97:
                record(f"O:diag_r{row_start}_c{col_start}_step8", "".join(diag_chars))

    print(f"  Section O: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION P: Myszkowski transposition (repeated letters) ─────────────────

def test_myszkowski():
    """Myszkowski transposition: keyword with repeated letters, cols with same letter read together."""
    print("\n=== SECTION P: Myszkowski transposition ===")
    ct = K4_CARVED

    # ABSCISSA has repeated letters: A(x2), S(x2)
    # Myszkowski: columns with same key letter are read left-to-right row by row
    kw = "ABSCISSA"
    # Key ordering: A=0, B=1, C=2, I=3, S=4, S=4, A=0 -- wait, need proper assignment
    # A(pos 0) and A(pos 7) share rank 0
    # B(pos 1) = rank 1
    # C(pos 3) = rank 2
    # I(pos 4) = rank 3
    # S(pos 2), S(pos 5), S(pos 6) share rank 4

    # Actually standard Myszkowski: assign ranks by sorted unique chars
    unique_sorted = sorted(set(kw))
    rank_map = {ch: i for i, ch in enumerate(unique_sorted)}
    ranks = [rank_map[ch] for ch in kw]
    n_unique_ranks = len(unique_sorted)

    ncols = len(kw)  # 8
    nrows = math.ceil(97 / ncols)

    # Fill grid
    grid = []
    idx = 0
    for r in range(nrows):
        row = []
        for c in range(ncols):
            if idx < len(ct):
                row.append(ct[idx])
                idx += 1
            else:
                row.append("")
        grid.append(row)

    # Read by rank (columns with same rank read together row-by-row)
    result = []
    for rank in range(n_unique_ranks):
        cols_with_rank = [c for c in range(ncols) if ranks[c] == rank]
        for r in range(nrows):
            for c in cols_with_rank:
                if grid[r][c]:
                    result.append(grid[r][c])

    myszkowski_ct = "".join(result)
    record(f"P:myszkowski_ABSCISSA_read", myszkowski_ct)

    # Inverse: CT was produced by Myszkowski, recover original
    # Need to know column lengths
    full_cells = 97 % ncols  # columns 0..(full_cells-1) have nrows chars
    if full_cells == 0:
        full_cells = ncols

    # Calculate chars per rank group
    rank_lengths = {}
    for rank in range(n_unique_ranks):
        cols_with_rank = [c for c in range(ncols) if ranks[c] == rank]
        total = 0
        for c in cols_with_rank:
            if c < full_cells:
                total += nrows
            else:
                total += nrows - 1
        rank_lengths[rank] = total

    # Split CT into groups by rank
    rank_data = {}
    idx = 0
    for rank in range(n_unique_ranks):
        rlen = rank_lengths[rank]
        rank_data[rank] = ct[idx:idx + rlen]
        idx += rlen

    # Distribute back to columns
    col_data = {}
    for rank in range(n_unique_ranks):
        cols_with_rank = [c for c in range(ncols) if ranks[c] == rank]
        # Within a rank group, chars are read row-by-row across the columns
        data = rank_data[rank]
        ptr = 0
        # Initialize col_data for these columns
        for c in cols_with_rank:
            col_data[c] = []

        for r in range(nrows):
            for c in cols_with_rank:
                col_len = nrows if c < full_cells else nrows - 1
                if r < col_len and ptr < len(data):
                    col_data[c].append(data[ptr])
                    ptr += 1

    # Reconstruct row by row
    result_inv = []
    for r in range(nrows):
        for c in range(ncols):
            if r < len(col_data.get(c, [])):
                result_inv.append(col_data[c][r])

    myszkowski_inv = "".join(result_inv)
    record(f"P:myszkowski_ABSCISSA_inv", myszkowski_inv)

    # Try other keywords
    for kw_test in ["KRYPTOS", "PALIMPSEST", "BERLINCLOCK", "SANBORN", "EASTNORTHEAST"]:
        unique_sorted = sorted(set(kw_test))
        rank_map = {ch: i for i, ch in enumerate(unique_sorted)}
        ranks = [rank_map[ch] for ch in kw_test]
        n_unique_ranks = len(unique_sorted)
        ncols = len(kw_test)
        nrows = math.ceil(97 / ncols)

        grid = []
        idx = 0
        for r in range(nrows):
            row = []
            for c in range(ncols):
                if idx < len(ct):
                    row.append(ct[idx])
                    idx += 1
                else:
                    row.append("")
            grid.append(row)

        result = []
        for rank in range(n_unique_ranks):
            cols_with_rank = [c for c in range(ncols) if ranks[c] == rank]
            for r in range(nrows):
                for c in cols_with_rank:
                    if c < len(grid[r]) and grid[r][c]:
                        result.append(grid[r][c])

        if len("".join(result)) == 97:
            record(f"P:myszkowski_{kw_test}", "".join(result))

    print(f"  Section P: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION Q: Complete column transposition at width 13 (8×13-7) ──────────

def test_columnar_13():
    """Width 13: 8 rows × 13 cols = 104, but 97 means irregular grid (7 short cols)."""
    print("\n=== SECTION Q: Columnar width 13 (8 rows) ===")
    ct = K4_CARVED

    # All keyword-derived orderings for width 13
    # EASTNORTHEAST is 13 letters!
    for kw in ["EASTNORTHEAST", "BERLINCLOCKA", "BERLINCLOCK" + "AB"]:
        if len(kw) < 13:
            kw = kw + "A" * (13 - len(kw))
        kw = kw[:13]
        order = keyword_col_order(kw)
        col_ct = columnar_read(ct, 13, order)
        record(f"Q:col13_{kw}", col_ct[:97])

        try:
            unread = columnar_unread(ct, 13, order)
            record(f"Q:col13_inv_{kw}", unread[:97])
        except Exception:
            pass

    # KRYPTOS extended to 13: KRYPTOSABCDEF (KA alphabet)
    for ext in ["KRYPTOSABCDEF", "KRYPTOSGHIJLM", "KRYPTOSPALIMS"]:
        ext = ext[:13]
        order = keyword_col_order(ext)
        col_ct = columnar_read(ct, 13, order)
        record(f"Q:col13_{ext}", col_ct[:97])
        try:
            unread = columnar_unread(ct, 13, order)
            record(f"Q:col13_inv_{ext}", unread[:97])
        except Exception:
            pass

    print(f"  Section Q: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION R: Grille extract with period 8 ────────────────────────────────

def test_grille_period8():
    """Use the grille extract (100 chars) as key material with period 8."""
    print("\n=== SECTION R: Grille extract + period 8 ===")
    ct = K4_CARVED

    # New grille extract (100 chars)
    GRILLE_NEW = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"

    # Old grille extract (106 chars)
    GRILLE_OLD = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

    for grille_name, grille in [("new100", GRILLE_NEW), ("old106", GRILLE_OLD)]:
        # Use first 97 chars as running key
        if len(grille) >= 97:
            running_key = grille[:97]
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    pt = cipher_fn(ct, running_key, alpha)
                    sc = score_text_per_char(pt)
                    crib_hits = has_cribs(pt)
                    if crib_hits or sc > -5.5:
                        record(f"R:grille_{grille_name}_runkey", pt)
                    if crib_hits:
                        print(f"  CRIB HIT: R:grille_{grille_name}/{cipher_name}/{alpha_name}: {pt[:50]}")

        # Use grille chars to define permutation (position of each char in KA)
        perm_indices = []
        for ch in grille[:97]:
            perm_indices.append(KA.index(ch) % 97)
        # This likely has collisions. Check.
        if len(set(perm_indices)) == 97:
            reordered = apply_permutation(ct, perm_indices)
            record(f"R:grille_{grille_name}_ka_perm", reordered)

        # Use every 8th char from grille as period-8 key
        for offset in range(8):
            key8 = grille[offset::8][:8]
            if len(key8) < 8:
                key8 = key8 + "A" * (8 - len(key8))
            # Cycle the 8-char key across 97 positions
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    pt = cipher_fn(ct, key8, alpha)
                    sc = score_text_per_char(pt)
                    crib_hits = has_cribs(pt)
                    if crib_hits or sc > -5.5:
                        record(f"R:grille_{grille_name}_p8_off{offset}_{cipher_name}_{alpha_name}", pt)

    print(f"  Section R: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── SECTION S: Two-step: columnar(8) + columnar(various) ───────────────────

def test_double_columnar():
    """Two rounds of columnar transposition, first with width 8."""
    print("\n=== SECTION S: Double columnar ===")
    ct = K4_CARVED

    # First columnar with keyword, then second columnar
    for kw1 in ["ABSCISSA", "KRYPTOSA"]:
        order1 = keyword_col_order(kw1[:8])
        try:
            intermediate = columnar_unread(ct, 8, order1)
        except Exception:
            continue

        if len(intermediate) != 97:
            continue

        for kw2 in KEYWORDS:
            order2 = keyword_col_order(kw2)
            try:
                final = columnar_unread(intermediate, len(kw2), order2)
                if len(final) == 97:
                    record(f"S:dblcol_8:{kw1}_{len(kw2)}:{kw2}", final)
            except Exception:
                pass

            # Also forward
            final_fwd = columnar_read(intermediate, len(kw2), order2)
            if len(final_fwd) == 97:
                record(f"S:dblcol_8:{kw1}_{len(kw2)}:{kw2}_fwd", final_fwd)

    # Second columnar first, then width 8
    for kw2 in KEYWORDS:
        order2 = keyword_col_order(kw2)
        try:
            intermediate = columnar_unread(ct, len(kw2), order2)
        except Exception:
            continue

        if len(intermediate) != 97:
            continue

        for kw1 in ["ABSCISSA", "KRYPTOSA"]:
            order1 = keyword_col_order(kw1[:8])
            try:
                final = columnar_unread(intermediate, 8, order1)
                if len(final) == 97:
                    record(f"S:dblcol_{len(kw2)}:{kw2}_8:{kw1}", final)
            except Exception:
                pass

    print(f"  Section S: {TOTAL_TESTED} candidates tested, best={BEST_SCORE:.2f}")


# ── MAIN ────────────────────────────────────────────────────────────────────

def main():
    start_time = time.time()
    print("=" * 70)
    print("blitz_8lines73.py — Exhaustive test of '8 Lines 73' interpretations")
    print(f"K4: {K4_CARVED}")
    print(f"Length: {K4_LEN}")
    print("=" * 70)

    test_8row_grids()
    test_73_parameter()
    test_columnar_8()
    test_period8_vig()
    test_tableau_rows()
    test_double_rotation_8()
    test_routes_8row()
    test_8x73()
    test_combined_col8_vig()
    test_8step_decimation()
    test_step_permutations()
    test_bifurcation()
    test_k3_grid_8rows()
    test_amsco_8()
    test_grid_coordinates()
    test_myszkowski()
    test_columnar_13()
    test_grille_period8()
    test_double_columnar()

    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print(f"FINAL SUMMARY")
    print(f"=" * 70)
    print(f"Total candidates tested: {TOTAL_TESTED}")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Best score: {BEST_SCORE:.4f}/char")

    if CRIB_HITS:
        print(f"\n*** {len(CRIB_HITS)} CRIB HITS FOUND ***")
        for hit in CRIB_HITS:
            print(f"  [{hit['label']}] {hit['cipher']}/{hit.get('key','')}/{hit.get('alpha','')}")
            print(f"    PT: {hit['pt'][:60]}...")
            print(f"    Cribs: {hit.get('cribs', hit.get('crib_hits', []))}")
    else:
        print("\nNo crib hits found.")

    if BEST_RESULT:
        print(f"\nBest result:")
        print(f"  Label: {BEST_RESULT['label']}")
        print(f"  Score: {BEST_RESULT['score']:.4f}/char")
        print(f"  Key: {BEST_RESULT['key']}, Cipher: {BEST_RESULT['cipher']}, Alpha: {BEST_RESULT['alpha']}")
        print(f"  PT: {BEST_RESULT['pt'][:60]}...")
        print(f"  CT: {BEST_RESULT['ct'][:60]}...")
        if BEST_RESULT.get('extra'):
            print(f"  Extra: {BEST_RESULT['extra']}")

    if RESULTS:
        print(f"\nResults above -5.5/char: {len(RESULTS)}")
        # Sort by score descending
        RESULTS.sort(key=lambda x: x['score'], reverse=True)
        for r in RESULTS[:20]:
            print(f"  [{r['label']}] {r['score']:.4f} {r['cipher']}/{r['key']}/{r['alpha']}: {r['pt'][:40]}")
    else:
        print("\nNo results above -5.5/char threshold.")

    print(f"\nDone in {elapsed:.1f}s.")


if __name__ == "__main__":
    main()
