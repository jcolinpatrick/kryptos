#!/usr/bin/env python3
"""Shifted tableau overlay: the +1 column offset from the extra L.

Cipher: cylinder shifted overlay
Family: grille
Status: active
Keyspace: ~50K configs
Last run: never
Best score: n/a

The extra L on row N creates a +1 column shift for everything below row 14
when the tableau is read as a continuous strip on a cylinder of circumference 31.

K4 sits entirely in the shifted zone (rows 24-27). This means the tableau
key for each K4 character is shifted by 1 position relative to what we've
always assumed.

Key insight: The shifted key column for K4 rows reads K,R,Y — the start
of KRYPTOS. This might not be coincidence.

Tests:
 A) Shifted tableau overlay + periodic keywords
 B) The shifted column 0 as a key source (KA from position 17=L)
 C) Row-key model where K4 rows use K,R,Y,(P) instead of X,Y,Z,(footer)
 D) Two-layer: shifted overlay + keyword Vigenere
 E) Every column offset 0-30 (not just +1) systematically
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.free_crib import score_free_fast

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

GRID_W = 31
GRID_H = 28
K4_START = 771  # position in the 868-cell grid

# K4 grid positions
K4_GRID = []
for i in range(CT_LEN):
    pos = K4_START + i
    r = pos // GRID_W
    c = pos % GRID_W
    K4_GRID.append((r, c))

# Build complete tableau (L at [0,0])
KRYPTOS_RAW = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # 32 chars
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",
]

# Build cylinder grid
cyl = []
for r, raw in enumerate(KRYPTOS_RAW):
    if r == 0:
        row = 'L' + raw[1:]
    elif r == 14:
        row = raw[:31]
    else:
        row = raw
    cyl.append(row)

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
    "DEFECTOR", "PARALLAX", "COLOPHON", "SHADOW",
    "URANIA", "QUARTZ", "FILTER", "CIPHER",
    "HIDDEN", "LIGHT", "POINT", "CLOCK",
    "MATRIX", "BERLIN", "LODGE", "COMPASS",
    "NEEDLE", "VERDIGRIS",
]

results = []
THRESHOLD = 6

def try_decrypt(ct, key_nums, variant, label):
    pt = decrypt_text(ct, key_nums, variant)
    sc = score_free_fast(pt)
    if sc > THRESHOLD:
        results.append((sc, label, variant.value, pt))
        print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:50]}...")
    return sc

total = 0

# ==================================================================
# MODEL A: Shifted tableau overlay with column offsets
# For each K4 position (r,c), use tableau at (r, (c+offset)%31) as key
# The extra L suggests offset=1 for rows > 14 (or constant offset for all)
# ==================================================================
print("=" * 70)
print("MODEL A: Shifted tableau overlay (K4 key = tableau[(r, (c+offset)%31)])")
print("=" * 70)

for offset in range(31):
    key_nums = []
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        shifted_c = (c + offset) % GRID_W
        ch = cyl[r][shifted_c]
        if ch == ' ':
            ch = 'A'  # fallback for footer blank
        key_nums.append(ALPH_IDX[ch])

    for variant in VARIANTS:
        label = f"tab_offset_{offset}"
        try_decrypt(CT, key_nums, variant, label)
        total += 1

print(f"  Model A: {total} configs")

# ==================================================================
# MODEL B: Split offset — rows 0-14 use offset 0, rows 15+ use offset 1
# This is the exact physical model from the continuous strip
# ==================================================================
print()
print("=" * 70)
print("MODEL B: Split offset (upper=0, lower=1) — continuous strip model")
print("=" * 70)

b_total = 0
for upper_off in range(31):
    for lower_off in range(31):
        key_nums = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            off = upper_off if r <= 14 else lower_off
            shifted_c = (c + off) % GRID_W
            ch = cyl[r][shifted_c]
            if ch == ' ':
                ch = 'A'
            key_nums.append(ALPH_IDX[ch])

        for variant in VARIANTS:
            label = f"split_u{upper_off}_l{lower_off}"
            try_decrypt(CT, key_nums, variant, label)
            b_total += 1

total += b_total
print(f"  Model B: {b_total} configs ({31*31*3})")

# ==================================================================
# MODEL C: Row-key from shifted column 0 + periodic keyword
# Shifted col 0 for K4 rows: K(24), R(25), Y(26), D(27)
# Or using KA-order key: K=0, R=1, Y=2 -> KRYPTOS period!
# ==================================================================
print()
print("=" * 70)
print("MODEL C: Shifted column-0 row key + keyword Vigenere")
print("=" * 70)

# Shifted key column for rows > 14
shifted_keycol = {}
for r in range(28):
    if r <= 14:
        shifted_keycol[r] = cyl[r][0]
    else:
        # Column 0 in shifted grid = original column 30
        shifted_keycol[r] = cyl[r][30] if 30 < len(cyl[r]) else cyl[r][-1]
        if shifted_keycol[r] == ' ':
            shifted_keycol[r] = 'D'  # footer col 30

print("Shifted key column for K4 rows:")
for r in range(24, 28):
    orig = cyl[r][0]
    shifted = shifted_keycol[r]
    print(f"  Row {r}: original key='{orig}', shifted key='{shifted}'")

# K4 row keys (shifted): K, R, Y, D
# What if the row key modifies the keyword?
c_total = 0
for kw in KEYWORDS:
    kw_nums = [ALPH_IDX[c] for c in kw]
    kw_len = len(kw)

    for variant in VARIANTS:
        # Model C1: row_key XOR keyword
        key_nums = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            row_key = ALPH_IDX[shifted_keycol[r]]
            kw_val = kw_nums[i % kw_len]
            key_nums.append((row_key + kw_val) % 26)

        label = f"rowkey_add_{kw}"
        try_decrypt(CT, key_nums, variant, label)
        c_total += 1

        # Model C2: row_key + col_key from header
        key_nums = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            row_key = ALPH_IDX[shifted_keycol[r]]
            col_key = ALPH_IDX[cyl[0][c]]
            key_nums.append((row_key + col_key) % 26)

        label = f"rowkey_colkey_add_{kw}"
        try_decrypt(CT, key_nums, variant, label)
        c_total += 1

        # Model C3: just the shifted row key (K,R,Y,D repeating)
        key_nums = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            key_nums.append(ALPH_IDX[shifted_keycol[r]])

        label = f"rowkey_only"
        sc = try_decrypt(CT, key_nums, variant, label)
        c_total += 1

total += c_total
print(f"  Model C: {c_total} configs")

# ==================================================================
# MODEL D: K,R,Y as 3-letter key (derived from shifted column)
# The shifted key column shows K4 uses key K,R,Y — which IS KRYPTOS
# truncated. Try KRYPTOS but with the period locked to row position.
# ==================================================================
print()
print("=" * 70)
print("MODEL D: K,R,Y row-key as pointer to KRYPTOS period 3")
print("=" * 70)

d_total = 0
# If K,R,Y means KRYPTOS period 3, try KRY as key
kry = [ALPH_IDX[c] for c in "KRY"]
for variant in VARIANTS:
    # Apply KRY to K4 character-by-character (period 3)
    key_nums = [kry[i % 3] for i in range(CT_LEN)]
    label = "KRY_period3"
    try_decrypt(CT, key_nums, variant, label)
    d_total += 1

    # Apply KRY per ROW (each row gets one key)
    key_nums = []
    row_keys = {'24': ALPH_IDX['K'], '25': ALPH_IDX['R'], '26': ALPH_IDX['Y']}
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        if r == 24:
            key_nums.append(ALPH_IDX['K'])
        elif r == 25:
            key_nums.append(ALPH_IDX['R'])
        elif r == 26:
            key_nums.append(ALPH_IDX['Y'])
        else:
            key_nums.append(ALPH_IDX['D'])  # footer row -> D from shifted col
    label = "KRY_per_row"
    try_decrypt(CT, key_nums, variant, label)
    d_total += 1

# Try KRY combined with column-periodic keyword
for kw in KEYWORDS:
    kw_nums = [ALPH_IDX[c] for c in kw]
    kw_len = len(kw)
    for variant in VARIANTS:
        # Row key from KRY + column key from keyword
        key_nums = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            if r == 24:
                rk = ALPH_IDX['K']
            elif r == 25:
                rk = ALPH_IDX['R']
            elif r == 26:
                rk = ALPH_IDX['Y']
            else:
                rk = ALPH_IDX['D']
            ck = kw_nums[c % kw_len]
            key_nums.append((rk + ck) % 26)
        label = f"KRY_row+{kw}_col"
        try_decrypt(CT, key_nums, variant, label)
        d_total += 1

        # Same but subtract
        key_nums = []
        for i in range(CT_LEN):
            r, c = K4_GRID[i]
            if r == 24:
                rk = ALPH_IDX['K']
            elif r == 25:
                rk = ALPH_IDX['R']
            elif r == 26:
                rk = ALPH_IDX['Y']
            else:
                rk = ALPH_IDX['D']
            ck = kw_nums[c % kw_len]
            key_nums.append((rk - ck) % 26)
        label = f"KRY_row-{kw}_col"
        try_decrypt(CT, key_nums, variant, label)
        d_total += 1

total += d_total
print(f"  Model D: {d_total} configs")

# ==================================================================
# MODEL E: KA-index tableau lookup (using KA instead of AZ)
# If the cylinder encodes KA-index relationships...
# ==================================================================
print()
print("=" * 70)
print("MODEL E: KA-index based key from shifted tableau")
print("=" * 70)

e_total = 0
for offset in [0, 1, -1, 2, -2, 11, 17]:  # 11=AZ(L), 17=KA(L)
    key_nums = []
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        shifted_c = (c + offset) % GRID_W
        ch = cyl[r][shifted_c]
        if ch == ' ':
            ch = 'A'
        # Use KA index instead of AZ index
        ki = KA_IDX[ch]
        key_nums.append(ki)

    for variant in VARIANTS:
        label = f"ka_idx_off{offset}"
        try_decrypt(CT, key_nums, variant, label)
        e_total += 1

total += e_total
print(f"  Model E: {e_total} configs")

# ==================================================================
# MODEL F: Transposition via shifted reading order
# The +1 offset changes the LINEAR position of K4 characters
# Try reading K4 from the shifted grid positions
# ==================================================================
print()
print("=" * 70)
print("MODEL F: Transposition from shifted grid + keyword decrypt")
print("=" * 70)

f_total = 0

# In the shifted model, K4 characters at (r,c) map to (r, (c+1)%31)
# This changes the linear reading order
for shift_amount in range(1, 31):
    # Build new reading order: sort K4 positions by shifted linear position
    shifted_positions = []
    for i in range(CT_LEN):
        r, c = K4_GRID[i]
        new_c = (c + shift_amount) % GRID_W
        new_linear = r * GRID_W + new_c
        shifted_positions.append((new_linear, i))

    shifted_positions.sort()
    perm = [idx for _, idx in shifted_positions]

    # Apply permutation to CT
    permuted = ''.join(CT[perm[i]] for i in range(CT_LEN))

    for kw in ['KRYPTOS', 'HOROLOGE', 'PALIMPSEST', 'ABSCISSA']:
        kw_nums = [ALPH_IDX[c] for c in kw]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(permuted, kw_nums, variant)
            sc = score_free_fast(pt)
            if sc > THRESHOLD:
                results.append((sc, f"shift{shift_amount}_{kw}", variant.value, pt))
                print(f"  ** SCORE {sc}: shift{shift_amount}_{kw} | {variant.value} | {pt[:50]}...")
            f_total += 1

total += f_total
print(f"  Model F: {f_total} configs")

# ==================================================================
# MODEL G: Column-first reading of K4 zone with shift
# ==================================================================
print()
print("=" * 70)
print("MODEL G: Column-first reading with shifted start column")
print("=" * 70)

g_total = 0

# Build K4 position map
k4_map = {}
for i in range(CT_LEN):
    r, c = K4_GRID[i]
    k4_map[(r, c)] = CT[i]

for start_col_offset in range(31):
    for direction in [1, -1]:  # L-to-R or R-to-L columns
        reading = ''
        cols = list(range(31))
        if direction == -1:
            cols = cols[::-1]
        # Rotate columns by start_col_offset
        cols = cols[start_col_offset:] + cols[:start_col_offset]

        for c in cols:
            for r in range(24, 28):
                if (r, c) in k4_map:
                    reading += k4_map[(r, c)]

        if len(reading) != CT_LEN:
            continue

        for kw in ['KRYPTOS', 'HOROLOGE', 'PALIMPSEST', 'ABSCISSA']:
            kw_nums = [ALPH_IDX[c] for c in kw]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(reading, kw_nums, variant)
                sc = score_free_fast(pt)
                if sc > THRESHOLD:
                    results.append((sc, f"colfirst_off{start_col_offset}_dir{direction}_{kw}", variant.value, pt))
                    print(f"  ** SCORE {sc}: colfirst off{start_col_offset} dir{direction} {kw} | {variant.value} | {pt[:40]}...")
                g_total += 1

total += g_total
print(f"  Model G: {g_total} configs")

# ==================================================================
# MODEL H: The "L=11" constant shift on all known good keywords
# L fills [0,0]. L=11 in AZ. What if we add/subtract 11 from every
# key position when decrypting?
# ==================================================================
print()
print("=" * 70)
print("MODEL H: L=11 constant shift modifier on keywords")
print("=" * 70)

h_total = 0
for kw in KEYWORDS:
    kw_nums = [ALPH_IDX[c] for c in kw]
    kw_len = len(kw)
    for l_mod in [11, -11, 17, -17, 12, -12]:  # 11=AZ(L), 17=KA(L), 12=L-to-L distance
        shifted = [(k + l_mod) % 26 for k in kw_nums]
        shifted_kw = ''.join(ALPH[k] for k in shifted)
        for variant in VARIANTS:
            key_seq = [shifted[i % kw_len] for i in range(CT_LEN)]
            pt = decrypt_text(CT, key_seq, variant)
            sc = score_free_fast(pt)
            if sc > THRESHOLD:
                results.append((sc, f"{kw}+{l_mod}={shifted_kw}", variant.value, pt))
                print(f"  ** SCORE {sc}: {kw}+{l_mod}={shifted_kw} | {variant.value} | {pt[:40]}...")
            h_total += 1

total += h_total
print(f"  Model H: {h_total} configs")

# ==================================================================
# SUMMARY
# ==================================================================
print()
print("=" * 70)
print(f"TOTAL: {total} configurations tested")
print("=" * 70)

if results:
    results.sort(reverse=True)
    print(f"\n{len(results)} results above threshold {THRESHOLD}:")
    for sc, label, var, pt in results[:20]:
        print(f"  SCORE {sc:2d}: {label} | {var} | {pt[:50]}")
else:
    print("\nNo results above threshold.")

print()
print("STRUCTURAL INSIGHTS:")
print(f"  Shifted key column for K4 rows: K, R, Y, D")
print(f"  K, R, Y = first 3 letters of KRYPTOS")
print(f"  L at [0,0] -> L-to-L span = 12 rows (13 including both L's)")
print(f"  Both halves of shifted grid anchor at L:")
print(f"    Upper (rows 0-14): AZ order from L")
print(f"    Lower (rows 15-27): KA order from KA[17]=L")
print(f"  L bridges the two alphabets AZ and KA")

print("\nDONE")
