#!/usr/bin/env python3
"""
Cipher: exploratory/bespoke
Family: exploration
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-BESPOKE-05: 98-character hypothesis — insert one char to make K4 grid-friendly.

Theory:
- K4 has 97 chars (prime → no clean grid factorization).
- 98 = 2 × 7 × 7 = 14 × 7. EXTREMELY grid-friendly.
- KRYPTOS is 7 letters → width-7 with 98 chars = exactly 14 rows.
- The tableau has an extra "L" (HILL). Inserting L → 98 chars.
- DESPARATLY is missing an E vs DESPERATELY → deletion instruction?
- K3 used a physical grid. Grid-based methods are Sanborn's style.

Phases:
1. Insert L at every position → 7×14 columnar, all 5040 orderings × 2 ciphers
2. Insert A-Z at structural positions → 7×14 with KRYPTOS-derived orderings + 14×7
3. Width-14 columnar with keyword-derived orderings
4. Remove one character (97→96 = 8×12, 6×16, 4×24) with keyword orderings
5. "Double operation" — insert L + width-7 KRYPTOS columnar + Vigenère KRYPTOS

Run: PYTHONPATH=src python3 -u scripts/e_bespoke_05_98chars.py
"""
import json
import itertools
import os
import sys
import time

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, N_CRIBS, KRYPTOS_ALPHABET,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def quick_crib_score(pt, crib_dict=CRIB_DICT):
    """Fast crib scoring."""
    return sum(1 for pos, ch in crib_dict.items()
               if pos < len(pt) and pt[pos] == ch)


def shifted_crib_dict(insert_pos, n_inserted=1):
    """Return crib dict with positions shifted to account for insertion.

    After inserting n_inserted chars at insert_pos in CT, the plaintext
    is longer. Crib positions that were >= insert_pos need to shift right.
    """
    shifted = {}
    for pos, ch in CRIB_DICT.items():
        if pos >= insert_pos:
            shifted[pos + n_inserted] = ch
        else:
            shifted[pos] = ch
    return shifted


def vig_decrypt(ct, key):
    """Vigenère decrypt: PT = (CT - K) mod 26."""
    pt = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def beau_decrypt(ct, key):
    """Beaufort decrypt: PT = (K - CT) mod 26."""
    pt = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


def keyword_to_order(keyword, width):
    """Convert a keyword to a columnar transposition ordering.

    The ordering is: columns are read in alphabetical order of the keyword letters.
    Ties broken left-to-right. Returns list where order[rank] = column_index.
    """
    if len(keyword) < width:
        # Extend keyword by repeating or appending alphabet
        keyword = (keyword * ((width // len(keyword)) + 1))[:width]
    elif len(keyword) > width:
        keyword = keyword[:width]

    # Assign ranks: sort (letter, original_index) pairs
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    order = [idx for _, idx in indexed]
    return order


def columnar_decrypt(ct, width, order):
    """Decrypt columnar transposition.

    Encryption: write PT row-by-row into grid of given width,
                read out columns in the order specified.
    order[rank] = which column is read at rank-th position.

    Decryption: split CT into columns (in reading order),
                place them back, read row-by-row.
    """
    n = len(ct)
    nrows = (n + width - 1) // width
    ncols = width

    # How many "long" columns (nrows chars) vs "short" (nrows-1 chars)
    n_long = n - (nrows - 1) * ncols
    if n % ncols == 0:
        n_long = ncols

    # Determine length of each column based on its position
    # Long columns are the FIRST n_long columns (0..n_long-1)
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
        cols[col_idx] = ct[pos:pos + length]
        pos += length

    # Read row by row
    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(cols.get(col, '')):
                result.append(cols[col][row])
    return ''.join(result)


def columnar_encrypt(pt, width, order):
    """Encrypt with columnar transposition (for verification).

    Write PT row-by-row, read columns in order.
    """
    n = len(pt)
    nrows = (n + width - 1) // width

    # Write into grid row-by-row
    grid = []
    for r in range(nrows):
        row = list(pt[r * width:(r + 1) * width])
        grid.append(row)

    # Read columns in order
    result = []
    for rank in range(width):
        col_idx = order[rank]
        for r in range(nrows):
            if col_idx < len(grid[r]):
                result.append(grid[r][col_idx])
    return ''.join(result)


# ── Precompute KRYPTOS-derived orderings ─────────────────────────────────────

# KRYPTOS alphabetical ranking: K=0, R=5, Y=6, P=4, T=5...
# Standard: rank by alphabetical order of letters
KRYPTOS_ORDER_7 = keyword_to_order("KRYPTOS", 7)
# KRYPTOS = K(10), R(17), Y(24), P(15), T(19), O(14), S(18)
# Sorted: K(0)=10, O(5)=14, P(3)=15, R(1)=17, S(6)=18, T(4)=19, Y(2)=24
# So alphabetical ranking: K=rank0, R=rank3, Y=rank6, P=rank2, T=rank5, O=rank1, S=rank4
# order[rank] = col_idx: order = [0, 5, 3, 1, 6, 4, 2]
print(f"KRYPTOS order (7-col): {KRYPTOS_ORDER_7}")

KRYPTOS_ORDER_7_REV = list(reversed(KRYPTOS_ORDER_7))

# For width-14, extend KRYPTOS: KRYPTOSKRYPTOS
KRYPTOS_ORDER_14 = keyword_to_order("KRYPTOSKRYPTOS", 14)
print(f"KRYPTOS×2 order (14-col): {KRYPTOS_ORDER_14}")

PALIMPSEST_ORDER_14 = keyword_to_order("PALIMPSESTABCD", 14)
ABSCISSA_ORDER_14 = keyword_to_order("ABSCISSAKRYPTO", 14)

# Also try: "KRYPTOSABCDEFG" for 14 columns
KRYPTOS_EXTEND_14 = keyword_to_order("KRYPTOSABCDEFG", 14)

# Additional keyword orderings for width-7
ADDITIONAL_KW_7 = [
    ("PALIMPS", keyword_to_order("PALIMPS", 7)),
    ("ABSCISS", keyword_to_order("ABSCISS", 7)),
    ("HERBERT", keyword_to_order("HERBERT", 7)),
    ("BERLINN", keyword_to_order("BERLINN", 7)),
    ("CHARLIE", keyword_to_order("CHARLIE", 7)),
    ("SCHEIDT", keyword_to_order("SCHEIDT", 7)),
    ("SANBORN", keyword_to_order("SANBORN", 7)),
]

# ═══════════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("E-BESPOKE-05: 98-Character Hypothesis (Insert One Char)")
print("=" * 70)
print(f"CT length: {CT_LEN}")
print(f"98 = 2 × 7 × 7 = 14 × 7")
print(f"KRYPTOS = 7 letters → width-7 with 98 chars = 14 rows exactly")
print()

results = []
global_best = 0
global_best_config = ""
t0 = time.time()
total_configs = 0

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5 (moved first — HIGHEST PRIORITY): Insert L + KRYPTOS columnar + Vig
# ═════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PHASE 5 (PRIORITY): Insert L + width-7 KRYPTOS columnar + Vigenère")
print("=" * 70)
print("  Insert L at each of 98 positions")
print("  Apply width-7 columnar with KRYPTOS alphabetical ordering")
print("  Decrypt with Vigenère key KRYPTOS, then Beaufort key KRYPTOS")
print()

p5_best = 0
p5_count = 0
p5_top_positions = []  # (score, insert_pos, variant, pt)

for insert_pos in range(CT_LEN + 1):  # 0..97 = 98 positions
    extended = CT[:insert_pos] + 'L' + CT[insert_pos:]
    assert len(extended) == 98

    # Columnar decrypt with KRYPTOS ordering
    untrans = columnar_decrypt(extended, 7, KRYPTOS_ORDER_7)

    # Vigenère with key KRYPTOS
    pt_v = vig_decrypt(untrans, "KRYPTOS")
    # Score against ORIGINAL crib positions (the plaintext is 98 chars,
    # and we don't know if the extra char shifts cribs or not)
    sc_v_orig = quick_crib_score(pt_v)
    # Also score against shifted cribs
    shifted = shifted_crib_dict(insert_pos)
    sc_v_shift = quick_crib_score(pt_v, shifted)
    sc_v = max(sc_v_orig, sc_v_shift)

    # Beaufort with key KRYPTOS
    pt_b = beau_decrypt(untrans, "KRYPTOS")
    sc_b_orig = quick_crib_score(pt_b)
    sc_b_shift = quick_crib_score(pt_b, shifted)
    sc_b = max(sc_b_orig, sc_b_shift)

    sc = max(sc_v, sc_b)
    variant = 'vig' if sc_v >= sc_b else 'beau'
    pt = pt_v if sc_v >= sc_b else pt_b
    p5_count += 2

    if sc > p5_best:
        p5_best = sc
        cfg = f"L@{insert_pos}/w7-KRYPTOS/{variant}"
        print(f"  NEW BEST: {sc}/24 — {cfg}")
        if sc >= 8:
            print(f"    PT: {pt}")
    if sc >= 3:
        p5_top_positions.append((sc, insert_pos, variant, pt[:80]))

# Now test ALL 5040 orderings for the TOP 10 insertion positions
p5_top_positions.sort(reverse=True)
top_insert_positions = list(set(pos for _, pos, _, _ in p5_top_positions[:10]))
print(f"\n  Top insertion positions: {top_insert_positions}")
print(f"  Testing all 5040 orderings for top positions...")

p5b_best = p5_best
p5b_count = 0

for insert_pos in top_insert_positions:
    extended = CT[:insert_pos] + 'L' + CT[insert_pos:]
    shifted = shifted_crib_dict(insert_pos)
    pos_best = 0

    for order in itertools.permutations(range(7)):
        order = list(order)
        untrans = columnar_decrypt(extended, 7, order)

        # Vigenère
        pt_v = vig_decrypt(untrans, "KRYPTOS")
        sc_v = max(quick_crib_score(pt_v), quick_crib_score(pt_v, shifted))

        # Beaufort
        pt_b = beau_decrypt(untrans, "KRYPTOS")
        sc_b = max(quick_crib_score(pt_b), quick_crib_score(pt_b, shifted))

        sc = max(sc_v, sc_b)
        variant = 'vig' if sc_v >= sc_b else 'beau'
        pt = pt_v if sc_v >= sc_b else pt_b
        p5b_count += 2

        if sc > pos_best:
            pos_best = sc
        if sc > p5b_best:
            p5b_best = sc
            cfg = f"L@{insert_pos}/w7-order={order}/{variant}"
            print(f"  NEW BEST: {sc}/24 — {cfg}")
            if sc >= 8:
                print(f"    PT: {pt}")
            if sc >= 10:
                results.append({
                    'phase': '5b', 'score': sc, 'insert_char': 'L',
                    'insert_pos': insert_pos, 'order': order,
                    'variant': variant, 'pt': pt[:80],
                })

    if pos_best >= 5:
        print(f"    L@{insert_pos}: best {pos_best}/24 (5040 orderings)")

p5_best = max(p5_best, p5b_best)
p5_total = p5_count + p5b_count
if p5_best > global_best:
    global_best = p5_best
    global_best_config = f"Phase 5: Insert L + w7 KRYPTOS"
total_configs += p5_total
print(f"\n  Phase 5 total: {p5_total} configs, best {p5_best}/24")

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1: Insert L at every position → all 5040 w7 orderings × 2 ciphers
# ═════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PHASE 1: Insert L at every position, all 7! orderings, Vig+Beau KRYPTOS")
print("=" * 70)
print("  98 positions × 5040 orderings × 2 variants = 987,840 configs")
print()

p1_best = 0
p1_count = 0
p1_results = []
REPORT_THRESHOLD = 8

for insert_pos in range(CT_LEN + 1):
    extended = CT[:insert_pos] + 'L' + CT[insert_pos:]
    assert len(extended) == 98
    shifted = shifted_crib_dict(insert_pos)
    pos_best = 0

    for order in itertools.permutations(range(7)):
        order = list(order)
        untrans = columnar_decrypt(extended, 7, order)

        # Vigenère
        pt_v = vig_decrypt(untrans, "KRYPTOS")
        sc_v = max(quick_crib_score(pt_v), quick_crib_score(pt_v, shifted))

        # Beaufort
        pt_b = beau_decrypt(untrans, "KRYPTOS")
        sc_b = max(quick_crib_score(pt_b), quick_crib_score(pt_b, shifted))

        sc = max(sc_v, sc_b)
        variant = 'vig' if sc_v >= sc_b else 'beau'
        pt = pt_v if sc_v >= sc_b else pt_b
        p1_count += 2

        if sc > pos_best:
            pos_best = sc
        if sc > p1_best:
            p1_best = sc
            cfg = f"L@{insert_pos}/w7/{order}/{variant}"
            print(f"  NEW BEST: {sc}/24 — {cfg}")
            if sc >= REPORT_THRESHOLD:
                print(f"    PT: {pt}")
        if sc >= REPORT_THRESHOLD:
            p1_results.append({
                'phase': 1, 'score': sc, 'insert_pos': insert_pos,
                'order': order, 'variant': variant, 'pt': pt[:80],
            })

    if insert_pos % 20 == 0:
        elapsed = time.time() - t0
        print(f"  ... insert_pos={insert_pos}/{CT_LEN}, "
              f"best={p1_best}/24, {p1_count} configs, {elapsed:.0f}s")

if p1_best > global_best:
    global_best = p1_best
    global_best_config = "Phase 1: Insert L + w7 all orderings"
total_configs += p1_count
results.extend(p1_results)
print(f"\n  Phase 1 total: {p1_count} configs, best {p1_best}/24")

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2: Insert A-Z at structural positions → width 7 and 14
# ═════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PHASE 2: Insert A-Z at structural positions")
print("=" * 70)

# Structural positions
STRUCTURAL_POSITIONS = [
    0,      # prepend
    20,     # T=20, "T IS YOUR POSITION"
    33,     # end of EASTNORTHEAST crib
    48,     # near midpoint
    49,     # midpoint
    63,     # start of BERLINCLOCK crib
    97,     # append
]

# Keyword orderings for width-7
KW_ORDERS_7 = [
    ("KRYPTOS", KRYPTOS_ORDER_7),
    ("KRYPTOS_REV", KRYPTOS_ORDER_7_REV),
    ("identity", list(range(7))),
    ("reverse", list(range(6, -1, -1))),
] + ADDITIONAL_KW_7

# Width-14 orderings
KW_ORDERS_14 = [
    ("KRYPTOSx2", KRYPTOS_ORDER_14),
    ("KRYPTOSABCDEFG", KRYPTOS_EXTEND_14),
    ("PALIMPSEST+", PALIMPSEST_ORDER_14),
    ("ABSCISSA+", ABSCISSA_ORDER_14),
    ("identity14", list(range(14))),
    ("reverse14", list(range(13, -1, -1))),
]

p2_best = 0
p2_count = 0
p2_results = []

print(f"  {len(STRUCTURAL_POSITIONS)} positions × 26 letters × "
      f"({len(KW_ORDERS_7)} w7 + {len(KW_ORDERS_14)} w14) orderings × 2 ciphers")
print()

for insert_pos in STRUCTURAL_POSITIONS:
    for letter in ALPH:
        extended = CT[:insert_pos] + letter + CT[insert_pos:]
        assert len(extended) == 98
        shifted = shifted_crib_dict(insert_pos)

        # Width-7 (14 rows)
        for kw_name, order in KW_ORDERS_7:
            untrans = columnar_decrypt(extended, 7, order)

            pt_v = vig_decrypt(untrans, "KRYPTOS")
            sc_v = max(quick_crib_score(pt_v), quick_crib_score(pt_v, shifted))

            pt_b = beau_decrypt(untrans, "KRYPTOS")
            sc_b = max(quick_crib_score(pt_b), quick_crib_score(pt_b, shifted))

            sc = max(sc_v, sc_b)
            variant = 'vig' if sc_v >= sc_b else 'beau'
            pt = pt_v if sc_v >= sc_b else pt_b
            p2_count += 2

            if sc > p2_best:
                p2_best = sc
                cfg = f"{letter}@{insert_pos}/w7-{kw_name}/{variant}"
                print(f"  NEW BEST: {sc}/24 — {cfg}")
                if sc >= REPORT_THRESHOLD:
                    print(f"    PT: {pt}")
            if sc >= REPORT_THRESHOLD:
                p2_results.append({
                    'phase': 2, 'score': sc, 'letter': letter,
                    'insert_pos': insert_pos, 'width': 7,
                    'kw': kw_name, 'order': order, 'variant': variant,
                    'pt': pt[:80],
                })

        # Width-14 (7 rows)
        for kw_name, order in KW_ORDERS_14:
            untrans = columnar_decrypt(extended, 14, order)

            pt_v = vig_decrypt(untrans, "KRYPTOS")
            sc_v = max(quick_crib_score(pt_v), quick_crib_score(pt_v, shifted))

            pt_b = beau_decrypt(untrans, "KRYPTOS")
            sc_b = max(quick_crib_score(pt_b), quick_crib_score(pt_b, shifted))

            sc = max(sc_v, sc_b)
            variant = 'vig' if sc_v >= sc_b else 'beau'
            pt = pt_v if sc_v >= sc_b else pt_b
            p2_count += 2

            if sc > p2_best:
                p2_best = sc
                cfg = f"{letter}@{insert_pos}/w14-{kw_name}/{variant}"
                print(f"  NEW BEST: {sc}/24 — {cfg}")
                if sc >= REPORT_THRESHOLD:
                    print(f"    PT: {pt}")
            if sc >= REPORT_THRESHOLD:
                p2_results.append({
                    'phase': 2, 'score': sc, 'letter': letter,
                    'insert_pos': insert_pos, 'width': 14,
                    'kw': kw_name, 'order': order, 'variant': variant,
                    'pt': pt[:80],
                })

    print(f"    pos={insert_pos}: best so far {p2_best}/24, {p2_count} configs")

if p2_best > global_best:
    global_best = p2_best
    global_best_config = "Phase 2: Insert A-Z at structural positions"
total_configs += p2_count
results.extend(p2_results)
print(f"\n  Phase 2 total: {p2_count} configs, best {p2_best}/24")

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2b: Insert A-Z at structural positions → ALL 5040 w7 orderings
# ═════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PHASE 2b: Insert A-Z at 3 most promising positions, ALL w7 orderings")
print("=" * 70)

# Pick the 3 most promising (letter, position) from Phase 2, plus always test
# the theoretically motivated ones
PRIORITY_COMBOS = [
    (0, 'L'),    # Prepend L (tableau extra L)
    (97, 'L'),   # Append L
    (20, 'L'),   # T=20 position
    (33, 'L'),   # End of ENE crib
    (63, 'L'),   # Start of BC crib
    (0, 'E'),    # Prepend E (DESPARATLY missing E)
    (97, 'E'),   # Append E
    (48, 'L'),   # Midpoint
]

p2b_best = 0
p2b_count = 0

for insert_pos, letter in PRIORITY_COMBOS:
    extended = CT[:insert_pos] + letter + CT[insert_pos:]
    shifted = shifted_crib_dict(insert_pos)
    pos_best = 0

    for order in itertools.permutations(range(7)):
        order = list(order)
        untrans = columnar_decrypt(extended, 7, order)

        pt_v = vig_decrypt(untrans, "KRYPTOS")
        sc_v = max(quick_crib_score(pt_v), quick_crib_score(pt_v, shifted))

        pt_b = beau_decrypt(untrans, "KRYPTOS")
        sc_b = max(quick_crib_score(pt_b), quick_crib_score(pt_b, shifted))

        sc = max(sc_v, sc_b)
        variant = 'vig' if sc_v >= sc_b else 'beau'
        pt = pt_v if sc_v >= sc_b else pt_b
        p2b_count += 2

        if sc > pos_best:
            pos_best = sc
        if sc > p2b_best:
            p2b_best = sc
            cfg = f"{letter}@{insert_pos}/w7/{order}/{variant}"
            print(f"  NEW BEST: {sc}/24 — {cfg}")
            if sc >= REPORT_THRESHOLD:
                print(f"    PT: {pt}")

    print(f"    {letter}@{insert_pos}: best {pos_best}/24")

if p2b_best > global_best:
    global_best = p2b_best
    global_best_config = "Phase 2b: Insert letter + w7 exhaustive"
total_configs += p2b_count
print(f"\n  Phase 2b total: {p2b_count} configs, best {p2b_best}/24")

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3: Width-14 columnar with keyword-derived orderings
# ═════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PHASE 3: Width-14 columnar (14! too large; use keyword orderings)")
print("=" * 70)

# Additional keywords to try for 14-column ordering
KEYWORDS_14 = [
    "KRYPTOSKRYPTOS",    # KRYPTOS repeated
    "KRYPTOSABCDEFG",    # KRYPTOS + continuation
    "PALIMPSESTABCD",    # PALIMPSEST extended
    "ABSCISSAKRYPTO",    # ABSCISSA + KRYPTOS
    "EASTNORTHEAST",     # Crib (13 chars, extend to 14)
    "BERLINCLOCKXYZ",    # Crib extended
    "HERBERTKRYPTOS",    # HERBERT (Sanborn)
    "SCHEIDTCRYPTOS",    # Scheidt
    "DESPERATELYABC",    # DESPERATELY
    "DESPARATLYKRYP",    # DESPARATLY
    "CHECKPOINTCHAR",    # Checkpoint Charlie
]

# Also generate shifted KRYPTOS orderings
SHIFTED_KW_14 = []
for shift in range(7):
    kw = "KRYPTOS"[shift:] + "KRYPTOS"[:shift]
    kw14 = (kw * 2)[:14]
    SHIFTED_KW_14.append((f"KRYPTOS_shift{shift}", keyword_to_order(kw14, 14)))

ALL_ORDERS_14 = KW_ORDERS_14.copy()
for kw in KEYWORDS_14:
    kw14 = (kw + "ABCDEFGHIJKLMN")[:14]
    ALL_ORDERS_14.append((kw[:10], keyword_to_order(kw14, 14)))
ALL_ORDERS_14.extend(SHIFTED_KW_14)

# Deduplicate orderings
seen_orders = set()
unique_orders_14 = []
for name, order in ALL_ORDERS_14:
    key = tuple(order)
    if key not in seen_orders:
        seen_orders.add(key)
        unique_orders_14.append((name, order))

p3_best = 0
p3_count = 0
p3_results = []

CIPHER_KEYS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HERBERT", "BERLIN",
    "CHARLIE", "SANBORN", "SCHEIDT", "DESPERATELY",
]

print(f"  {CT_LEN + 1} insert positions × {len(unique_orders_14)} orderings × "
      f"{len(CIPHER_KEYS)} keys × 2 ciphers")
print()

for insert_pos in range(CT_LEN + 1):
    extended = CT[:insert_pos] + 'L' + CT[insert_pos:]
    shifted = shifted_crib_dict(insert_pos)

    for kw_name, order in unique_orders_14:
        untrans = columnar_decrypt(extended, 14, order)

        for cipher_key in CIPHER_KEYS:
            pt_v = vig_decrypt(untrans, cipher_key)
            sc_v = max(quick_crib_score(pt_v), quick_crib_score(pt_v, shifted))

            pt_b = beau_decrypt(untrans, cipher_key)
            sc_b = max(quick_crib_score(pt_b), quick_crib_score(pt_b, shifted))

            sc = max(sc_v, sc_b)
            variant = 'vig' if sc_v >= sc_b else 'beau'
            pt = pt_v if sc_v >= sc_b else pt_b
            p3_count += 2

            if sc > p3_best:
                p3_best = sc
                cfg = f"L@{insert_pos}/w14-{kw_name}/{variant}-{cipher_key}"
                print(f"  NEW BEST: {sc}/24 — {cfg}")
                if sc >= REPORT_THRESHOLD:
                    print(f"    PT: {pt}")
            if sc >= REPORT_THRESHOLD:
                p3_results.append({
                    'phase': 3, 'score': sc, 'insert_pos': insert_pos,
                    'width': 14, 'col_kw': kw_name, 'order': order,
                    'cipher_key': cipher_key, 'variant': variant,
                    'pt': pt[:80],
                })

    if insert_pos % 20 == 0:
        elapsed = time.time() - t0
        print(f"  ... L@{insert_pos}/{CT_LEN}, best={p3_best}/24, "
              f"{p3_count} configs, {elapsed:.0f}s")

if p3_best > global_best:
    global_best = p3_best
    global_best_config = "Phase 3: Width-14 + keyword orderings"
total_configs += p3_count
results.extend(p3_results)
print(f"\n  Phase 3 total: {p3_count} configs, best {p3_best}/24")

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4: Remove one character (97→96)
# ═════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PHASE 4: Remove one character (97→96 = 8×12 or 6×16 or 4×24)")
print("=" * 70)

# 96 factorizations: 8×12, 12×8, 6×16, 16×6, 4×24, 24×4
WIDTHS_96 = [8, 12, 6, 16, 4, 24]

# Keyword orderings for each width
def get_orders_for_width(w):
    """Get keyword-derived orderings for a given width."""
    orders = [
        ("identity", list(range(w))),
        ("reverse", list(range(w - 1, -1, -1))),
    ]
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "HERBERT", "BERLIN",
               "CHARLIE", "SANBORN", "SCHEIDT"]:
        orders.append((kw, keyword_to_order(kw, w)))
    # Deduplicate
    seen = set()
    unique = []
    for name, order in orders:
        key = tuple(order)
        if key not in seen:
            seen.add(key)
            unique.append((name, order))
    return unique

p4_best = 0
p4_count = 0
p4_results = []

for remove_pos in range(CT_LEN):
    ct96 = CT[:remove_pos] + CT[remove_pos + 1:]
    assert len(ct96) == 96

    # Adjust crib dict: positions after remove_pos shift left by 1
    adj_crib = {}
    for pos, ch in CRIB_DICT.items():
        if pos < remove_pos:
            adj_crib[pos] = ch
        elif pos > remove_pos:
            adj_crib[pos - 1] = ch
        # If pos == remove_pos, that crib position is removed

    for width in WIDTHS_96:
        orders = get_orders_for_width(width)
        for kw_name, order in orders:
            untrans = columnar_decrypt(ct96, width, order)

            for cipher_key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                pt_v = vig_decrypt(untrans, cipher_key)
                sc_v = quick_crib_score(pt_v, adj_crib)

                pt_b = beau_decrypt(untrans, cipher_key)
                sc_b = quick_crib_score(pt_b, adj_crib)

                # Also try no substitution (transposition only)
                sc_none = quick_crib_score(untrans, adj_crib)

                sc = max(sc_v, sc_b, sc_none)
                if sc_none >= sc_v and sc_none >= sc_b:
                    variant = 'none'
                    pt = untrans
                elif sc_v >= sc_b:
                    variant = 'vig'
                    pt = pt_v
                else:
                    variant = 'beau'
                    pt = pt_b
                p4_count += 3  # vig + beau + none

                if sc > p4_best:
                    p4_best = sc
                    cfg = f"rm@{remove_pos}/w{width}-{kw_name}/{variant}-{cipher_key}"
                    print(f"  NEW BEST: {sc}/24 — {cfg}")
                    if sc >= REPORT_THRESHOLD:
                        print(f"    PT: {pt}")
                if sc >= REPORT_THRESHOLD:
                    p4_results.append({
                        'phase': 4, 'score': sc, 'remove_pos': remove_pos,
                        'removed_char': CT[remove_pos], 'width': width,
                        'col_kw': kw_name, 'cipher_key': cipher_key,
                        'variant': variant, 'pt': pt[:80],
                    })

    if remove_pos % 20 == 0:
        elapsed = time.time() - t0
        print(f"  ... rm@{remove_pos}/{CT_LEN - 1}, best={p4_best}/24, "
              f"{p4_count} configs, {elapsed:.0f}s")

if p4_best > global_best:
    global_best = p4_best
    global_best_config = "Phase 4: Remove one char"
total_configs += p4_count
results.extend(p4_results)
print(f"\n  Phase 4 total: {p4_count} configs, best {p4_best}/24")

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1b: Insert L + w7 columnar (NO substitution — pure transposition)
# ═════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PHASE 1b: Insert L + w7 columnar, NO substitution (pure transposition)")
print("=" * 70)

p1b_best = 0
p1b_count = 0

for insert_pos in range(CT_LEN + 1):
    extended = CT[:insert_pos] + 'L' + CT[insert_pos:]
    shifted = shifted_crib_dict(insert_pos)

    for order in itertools.permutations(range(7)):
        order = list(order)
        untrans = columnar_decrypt(extended, 7, order)

        # Score with original and shifted cribs (no substitution)
        sc_orig = quick_crib_score(untrans)
        sc_shift = quick_crib_score(untrans, shifted)
        sc = max(sc_orig, sc_shift)
        p1b_count += 1

        if sc > p1b_best:
            p1b_best = sc
            cfg = f"L@{insert_pos}/w7/{order}/no_sub"
            print(f"  NEW BEST: {sc}/24 — {cfg}")
            if sc >= REPORT_THRESHOLD:
                print(f"    PT: {untrans}")
                results.append({
                    'phase': '1b', 'score': sc, 'insert_pos': insert_pos,
                    'order': order, 'variant': 'none', 'pt': untrans[:80],
                })

    if insert_pos % 20 == 0:
        elapsed = time.time() - t0
        print(f"  ... L@{insert_pos}/{CT_LEN}, best={p1b_best}/24, "
              f"{p1b_count} configs, {elapsed:.0f}s")

if p1b_best > global_best:
    global_best = p1b_best
    global_best_config = "Phase 1b: Insert L + w7 no sub"
total_configs += p1b_count
print(f"\n  Phase 1b total: {p1b_count} configs, best {p1b_best}/24")

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 6: Insert L + K3-style grid rotation (write row-by-row, rotate, read)
# ═════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 70)
print("PHASE 6: Insert L + K3-style grid rotation (7×14 and 14×7)")
print("=" * 70)

def make_grid(text, width):
    """Write text into grid row by row."""
    n = len(text)
    nrows = (n + width - 1) // width
    grid = []
    for r in range(nrows):
        row = list(text[r * width:(r + 1) * width])
        grid.append(row)
    return grid


def read_grid_rowwise(grid):
    """Read grid row by row, left to right."""
    return ''.join(''.join(row) for row in grid)


def rotate_90_cw(grid):
    """Rotate grid 90 degrees clockwise."""
    nrows = len(grid)
    ncols = max(len(r) for r in grid) if grid else 0
    rotated = []
    for c in range(ncols):
        new_row = []
        for r in range(nrows - 1, -1, -1):
            if c < len(grid[r]) and grid[r][c]:
                new_row.append(grid[r][c])
        rotated.append(new_row)
    return rotated


def rotate_90_ccw(grid):
    """Rotate grid 90 degrees counter-clockwise."""
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


def read_grid_colwise(grid):
    """Read grid column by column, top to bottom."""
    result = []
    nrows = len(grid)
    ncols = max(len(r) for r in grid) if grid else 0
    for c in range(ncols):
        for r in range(nrows):
            if c < len(grid[r]) and grid[r][c]:
                result.append(grid[r][c])
    return ''.join(result)


p6_best = 0
p6_count = 0

ROTATIONS = [
    ("90cw", rotate_90_cw),
    ("90ccw", rotate_90_ccw),
    ("180", lambda g: rotate_90_cw(rotate_90_cw(g))),
    ("double_90cw", lambda g: rotate_90_cw(rotate_90_cw(g))),  # Same as 180 via 2×CW
]

READ_FUNCS = [
    ("row", read_grid_rowwise),
    ("col", read_grid_colwise),
]

for insert_pos in range(0, CT_LEN + 1, 1):
    extended = CT[:insert_pos] + 'L' + CT[insert_pos:]
    shifted = shifted_crib_dict(insert_pos)

    for width in [7, 14]:
        grid = make_grid(extended, width)

        for rot_name, rot_func in ROTATIONS:
            rotated = rot_func(grid)

            for rd_name, rd_func in READ_FUNCS:
                pt = rd_func(rotated)
                sc_orig = quick_crib_score(pt)
                sc_shift = quick_crib_score(pt, shifted)

                # Also try with Vig/Beau KRYPTOS
                pt_v = vig_decrypt(pt[:98], "KRYPTOS") if len(pt) >= 98 else pt
                sc_v_orig = quick_crib_score(pt_v) if pt_v != pt else 0
                sc_v_shift = quick_crib_score(pt_v, shifted) if pt_v != pt else 0

                pt_b = beau_decrypt(pt[:98], "KRYPTOS") if len(pt) >= 98 else pt
                sc_b_orig = quick_crib_score(pt_b) if pt_b != pt else 0
                sc_b_shift = quick_crib_score(pt_b, shifted) if pt_b != pt else 0

                sc = max(sc_orig, sc_shift, sc_v_orig, sc_v_shift,
                         sc_b_orig, sc_b_shift)
                p6_count += 1

                if sc > p6_best:
                    p6_best = sc
                    # Determine which variant was best
                    all_scores = [
                        (sc_orig, 'none', pt), (sc_shift, 'none_shift', pt),
                        (sc_v_orig, 'vig', pt_v), (sc_v_shift, 'vig_shift', pt_v),
                        (sc_b_orig, 'beau', pt_b), (sc_b_shift, 'beau_shift', pt_b),
                    ]
                    best_variant = max(all_scores, key=lambda x: x[0])
                    cfg = (f"L@{insert_pos}/w{width}/{rot_name}/read={rd_name}/"
                           f"{best_variant[1]}")
                    print(f"  NEW BEST: {sc}/24 — {cfg}")
                    if sc >= REPORT_THRESHOLD:
                        print(f"    PT: {best_variant[2][:80]}")

    if insert_pos % 20 == 0:
        elapsed = time.time() - t0
        print(f"  ... L@{insert_pos}/{CT_LEN}, best={p6_best}/24, "
              f"{p6_count} configs, {elapsed:.0f}s")

if p6_best > global_best:
    global_best = p6_best
    global_best_config = "Phase 6: Insert L + K3 rotation"
total_configs += p6_count
print(f"\n  Phase 6 total: {p6_count} configs, best {p6_best}/24")

# ═════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═════════════════════════════════════════════════════════════════════════════

elapsed = time.time() - t0
print(f"\n{'=' * 70}")
print(f"E-BESPOKE-05: 98-Character Hypothesis — FINAL SUMMARY")
print(f"{'=' * 70}")
print(f"Total configs tested: {total_configs:,}")
print(f"Time: {elapsed:.1f}s ({elapsed / 60:.1f}m)")
print(f"")
print(f"Phase 5 (PRIORITY: L + w7 KRYPTOS):    best {p5_best}/24")
print(f"Phase 1 (L at all pos, all w7 orders):  best {p1_best}/24")
print(f"Phase 1b (L + w7, no sub):              best {p1b_best}/24")
print(f"Phase 2 (A-Z at structural, kw orders): best {p2_best}/24")
print(f"Phase 2b (A-Z at priority, all w7):     best {p2b_best}/24")
print(f"Phase 3 (w14 + keyword orderings):      best {p3_best}/24")
print(f"Phase 4 (remove one char, 96):          best {p4_best}/24")
print(f"Phase 6 (K3-style rotation):            best {p6_best}/24")
print(f"")
print(f"GLOBAL BEST: {global_best}/24")

if global_best <= 6:
    classification = "NOISE"
elif global_best <= 9:
    classification = "NOISE (marginal)"
elif global_best <= 17:
    classification = "STORE"
else:
    classification = "SIGNAL — INVESTIGATE!"

print(f"CLASSIFICATION: {classification}")
print(f"{'=' * 70}")

# ── Save results ──────────────────────────────────────────────────────────────

os.makedirs('results', exist_ok=True)

output = {
    'experiment': 'E-BESPOKE-05',
    'description': '98-character hypothesis: insert one char to make K4 grid-friendly (7×14)',
    'theory': (
        '97 is prime (no grid). 98 = 7×14. KRYPTOS = 7 letters. '
        'Tableau has extra L. DESPARATLY missing E = deletion instruction? '
        'K3 used physical grid rotation.'
    ),
    'total_configs': total_configs,
    'elapsed_seconds': round(elapsed, 1),
    'global_best': global_best,
    'classification': classification,
    'phase_results': {
        'phase5_priority_L_KRYPTOS': {'configs': p5_total, 'best': p5_best},
        'phase1_L_all_w7': {'configs': p1_count, 'best': p1_best},
        'phase1b_L_w7_nosub': {'configs': p1b_count, 'best': p1b_best},
        'phase2_AZ_structural': {'configs': p2_count, 'best': p2_best},
        'phase2b_AZ_exhaustive_w7': {'configs': p2b_count, 'best': p2b_best},
        'phase3_w14_keywords': {'configs': p3_count, 'best': p3_best},
        'phase4_remove_char': {'configs': p4_count, 'best': p4_best},
        'phase6_K3_rotation': {'configs': p6_count, 'best': p6_best},
    },
    'notable_results': [r for r in results if r.get('score', 0) >= REPORT_THRESHOLD],
}

with open('results/e_bespoke_05_98chars.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"\nArtifact: results/e_bespoke_05_98chars.json")
