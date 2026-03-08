#!/usr/bin/env python3
"""Helical offset from the extra L on tableau row N.

Cipher: Vigenere/Beaufort + progressive per-row key offset
Family: grille
Status: active
Keyspace: ~50K configs
Last run: never
Best score: n/a

Motivation: The extra L on tableau row N (row 14, center split) creates a
+1 character overflow on a 31-wide cylinder. If the cylinder is read
helically, this extra character shifts all subsequent rows by +1 column.
The offset ACCUMULATES: row 15 is offset by +1, row 16 by +2, etc.

For K4 at rows 24-27:
  Row 24: offset = 24 - 14 = +10
  Row 25: offset = 25 - 14 = +11
  Row 26: offset = 26 - 14 = +12
  Row 27: offset = 27 - 14 = +13

This creates a PER-ROW PROGRESSIVE KEY SHIFT that differs from:
  - Standard periodic Vigenere (uniform key alignment)
  - Column-keyed Vigenere (uniform rotation across all rows)

The extra L is Kryptos-only (absent from Antipodes), making it part of
"the clue on Kryptos that ISN'T on Antipodes."

Additional models:
  - Light from below (pool): bottom rows project widest, upward through
    cipher cutouts onto the tableau. This suggests K4's key comes from
    the UPPER tableau rows (light carries K4 text upward).
  - Variable helical pitch: the offset per row might not be exactly 1
    (could be based on the extra L's exact column position).
  - Reversed projection: upward projection from below reverses the
    vertical ordering (K4 row 27 = closest to light = innermost).
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.free_crib import score_free_fast

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

GRID_W = 31
GRID_H = 28
EXTRA_L_ROW = 14  # Row N (key letter N) — center split

# K4 grid positions
K4_GRID = []
K4_START_POS = 771
for i in range(CT_LEN):
    pos = K4_START_POS + i
    K4_GRID.append((pos // GRID_W, pos % GRID_W))

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
    "DEFECTOR", "PARALLAX", "COLOPHON", "SHADOW",
    "URANIA", "QUARTZ", "FILTER", "CIPHER",
    "HIDDEN", "LIGHT", "MATRIX", "BERLIN",
    "POINT", "CLOCK",
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
THRESHOLD = 6
results = []


def try_decrypt(ct_text, key_nums, variant, label):
    pt = decrypt_text(ct_text, key_nums, variant)
    sc = score_free_fast(pt)
    if sc > THRESHOLD:
        results.append((sc, label, variant.value, pt))
        print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:50]}...")


def build_helical_key(kw_nums, kw_len, pitch, base_offset, hinge_row):
    """Build key sequence with progressive per-row offset.

    For each K4 position at (row, col):
      key_index = (col + base_offset + pitch * (row - hinge_row)) % kw_len
    """
    key_seq = []
    for i in range(CT_LEN):
        row, col = K4_GRID[i]
        row_offset = pitch * (row - hinge_row)
        key_idx = (col + base_offset + row_offset) % kw_len
        key_seq.append(kw_nums[key_idx])
    return key_seq


def build_reversed_helical_key(kw_nums, kw_len, pitch, base_offset, hinge_row):
    """Same but with reversed column order per row (projection model).

    On the inside of a cylinder, columns read right-to-left.
    Effective column = (GRID_W - 1 - col) for full rows.
    """
    key_seq = []
    for i in range(CT_LEN):
        row, col = K4_GRID[i]
        eff_col = (GRID_W - 1 - col) if col < GRID_W else col
        row_offset = pitch * (row - hinge_row)
        key_idx = (eff_col + base_offset + row_offset) % kw_len
        key_seq.append(kw_nums[key_idx])
    return key_seq


def main():
    total_configs = 0

    # ================================================================
    # MODEL 1: Progressive helical offset from extra L
    # Offset per row = pitch × (row - hinge_row)
    # pitch = 1 (standard: one extra L = one char per row)
    # hinge_row = 14 (row N where extra L lives)
    # base_offset = 0..30 (where on the circumference we start)
    # ================================================================
    print("=" * 70)
    print("MODEL 1: Progressive helical offset (pitch=1, hinge=row 14)")
    print("=" * 70)

    m1_configs = 0
    for kw in KEYWORDS:
        kw_nums = [ALPH_IDX[c] for c in kw]
        kw_len = len(kw)

        for base_offset in range(GRID_W):
            key_seq = build_helical_key(kw_nums, kw_len, pitch=1,
                                        base_offset=base_offset, hinge_row=EXTRA_L_ROW)
            for variant in VARIANTS:
                try_decrypt(CT, key_seq, variant, f"helix_p1_{kw}_off{base_offset}")
                m1_configs += 1

    total_configs += m1_configs
    print(f"  Model 1: {m1_configs} configs")

    # ================================================================
    # MODEL 2: Variable pitch (2, 3, 5, 7, 13, 26, 30)
    # The helical pitch might not be 1 — it could relate to the
    # keyword length, a prime, or 26 (alphabet size).
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 2: Variable helical pitch")
    print("=" * 70)

    m2_configs = 0
    pitches = [2, 3, 4, 5, 6, 7, 8, 10, 13, 15, 17, 26, 30]

    for pitch in pitches:
        for kw in KEYWORDS:
            kw_nums = [ALPH_IDX[c] for c in kw]
            kw_len = len(kw)

            for base_offset in range(GRID_W):
                key_seq = build_helical_key(kw_nums, kw_len, pitch=pitch,
                                            base_offset=base_offset, hinge_row=EXTRA_L_ROW)
                for variant in VARIANTS:
                    try_decrypt(CT, key_seq, variant,
                               f"helix_p{pitch}_{kw}_off{base_offset}")
                    m2_configs += 1

        if (pitches.index(pitch) + 1) % 4 == 0:
            print(f"  ... pitch {pitch}, {m2_configs} configs so far")

    total_configs += m2_configs
    print(f"  Model 2: {m2_configs} configs")

    # ================================================================
    # MODEL 3: Reversed columns + helical offset (inside-cylinder view)
    # From inside the cylinder (projection perspective), columns are
    # mirrored. Combined with the helical offset from the extra L.
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 3: Reversed columns + helical offset")
    print("=" * 70)

    # Build reversed CT (each row read right-to-left)
    rev_chars = list(CT[0:4])[::-1]  # Row 24 cols 27-30 reversed
    for start in [4, 35, 66]:
        end = min(start + 31, 97)
        rev_chars.extend(list(CT[start:end])[::-1])
    reversed_ct = "".join(rev_chars)
    assert len(reversed_ct) == 97

    m3_configs = 0
    for pitch in [1, 2, 3, 5, 7, 13, 26, 30]:
        for kw in KEYWORDS:
            kw_nums = [ALPH_IDX[c] for c in kw]
            kw_len = len(kw)

            for base_offset in range(GRID_W):
                key_seq = build_reversed_helical_key(kw_nums, kw_len, pitch=pitch,
                                                     base_offset=base_offset,
                                                     hinge_row=EXTRA_L_ROW)
                for variant in VARIANTS:
                    try_decrypt(reversed_ct, key_seq, variant,
                               f"rev_helix_p{pitch}_{kw}_off{base_offset}")
                    m3_configs += 1

    total_configs += m3_configs
    print(f"  Model 3: {m3_configs} configs")

    # ================================================================
    # MODEL 4: Upward projection model (light from pool below)
    # K4 rows 24-27 are closest to the light (bottom of panel).
    # In upward projection, row 27 is "innermost" (closest to light),
    # row 24 is "outermost". This reverses the vertical ordering.
    # Also: upward projection through cipher text onto tableau means
    # cipher rows map to tableau rows with vertical inversion.
    # K4 row 27 → tableau row 0 (header), row 24 → tableau row 3, etc.
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 4: Upward projection (light from pool)")
    print("=" * 70)

    m4_configs = 0

    # 4a: Inverted row order for key alignment
    # K4 row r maps to tableau row (GRID_H - 1 - r + v_offset)
    for v_offset in range(28):
        for h_offset in range(31):
            key_nums = []
            for i in range(CT_LEN):
                row, col = K4_GRID[i]
                # Upward projection: invert row
                proj_row = (GRID_H - 1 - row + v_offset) % GRID_H
                proj_col = (col + h_offset) % GRID_W

                # Read tableau value at projected position
                if proj_row == 0 or proj_row == 27:
                    # Header/footer
                    if proj_col == 0:
                        key_nums.append(0)
                    else:
                        key_nums.append((proj_col - 1) % 26)
                elif 1 <= proj_row <= 26:
                    if proj_col == 0:
                        key_nums.append(ALPH_IDX[ALPH[proj_row - 1]])
                    else:
                        ka_idx = (proj_row - 1 + proj_col - 1) % 26
                        key_nums.append(ALPH_IDX[KA[ka_idx]])
                else:
                    key_nums.append(0)

            for variant in VARIANTS:
                pt = decrypt_text(CT, key_nums, variant)
                sc = score_free_fast(pt)
                if sc > THRESHOLD:
                    label = f"upward_proj_v{v_offset}_h{h_offset}"
                    results.append((sc, label, variant.value, pt))
                    print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:50]}...")
                m4_configs += 1

        if (v_offset + 1) % 7 == 0:
            print(f"  ... v_offset {v_offset+1}/28, {m4_configs} configs")

    total_configs += m4_configs
    print(f"  Model 4: {m4_configs} configs")

    # ================================================================
    # MODEL 5: Helical offset + period 32 (from extra L)
    # What if the true grid width is 32 (the extra-L row width)?
    # K4 chars would align differently on a width-32 grid.
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 5: Width-32 grid (extra L = true period)")
    print("=" * 70)

    m5_configs = 0
    # On a width-32 grid, K4[i] at position (K4_START_POS + i) maps to:
    #   row = (K4_START_POS + i) // 32
    #   col = (K4_START_POS + i) % 32
    # But K4_START_POS was computed for width 31. On width 32:
    # Total chars before K4 = 63 + 1 + 369 + 1 + 336 + 1 = 771
    # On width-32 grid: K4 starts at row 771//32 = 24, col 771%32 = 3

    W32_START_ROW = 771 // 32  # = 24
    W32_START_COL = 771 % 32   # = 3

    k4_grid_32 = []
    for i in range(CT_LEN):
        pos = 771 + i
        k4_grid_32.append((pos // 32, pos % 32))

    for kw in KEYWORDS:
        kw_nums = [ALPH_IDX[c] for c in kw]
        kw_len = len(kw)

        for base_offset in range(32):
            key_seq = []
            for i in range(CT_LEN):
                row, col = k4_grid_32[i]
                key_idx = (col + base_offset) % kw_len
                key_seq.append(kw_nums[key_idx])

            for variant in VARIANTS:
                pt = decrypt_text(CT, key_seq, variant)
                sc = score_free_fast(pt)
                if sc > THRESHOLD:
                    label = f"w32_{kw}_off{base_offset}"
                    results.append((sc, label, variant.value, pt))
                    print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:50]}...")
                m5_configs += 1

    total_configs += m5_configs
    print(f"  Model 5: {m5_configs} configs")

    # ================================================================
    # MODEL 6: Combined — helical offset + upward projection (inverted)
    # Light from below inverts the row ordering AND the extra L
    # creates a progressive offset. Combine both effects.
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL 6: Helical offset + inverted rows (bottom-up projection)")
    print("=" * 70)

    m6_configs = 0
    # Invert K4 rows: row 27→row 0, row 26→row 1, row 25→row 2, row 24→row 3
    # Then apply helical offset based on distance from hinge
    inv_row_map = {27: 0, 26: 1, 25: 2, 24: 3}

    for pitch in [1, 2, 3, 5, 7, 13]:
        for kw in KEYWORDS:
            kw_nums = [ALPH_IDX[c] for c in kw]
            kw_len = len(kw)

            for base_offset in range(GRID_W):
                key_seq = []
                for i in range(CT_LEN):
                    row, col = K4_GRID[i]
                    inv_row = inv_row_map[row]
                    row_offset = pitch * inv_row
                    key_idx = (col + base_offset + row_offset) % kw_len
                    key_seq.append(kw_nums[key_idx])

                for variant in VARIANTS:
                    try_decrypt(CT, key_seq, variant,
                               f"inv_helix_p{pitch}_{kw}_off{base_offset}")
                    m6_configs += 1

    total_configs += m6_configs
    print(f"  Model 6: {m6_configs} configs")

    # ================================================================
    # SUMMARY
    # ================================================================
    print("\n" + "=" * 70)
    print(f"TOTAL: {total_configs} configurations tested")
    print("=" * 70)

    if results:
        results.sort(reverse=True)
        print(f"\n{len(results)} results above threshold {THRESHOLD}:")
        for sc, label, var, pt in results[:20]:
            print(f"  SCORE {sc:2d}: {label} | {var} | {pt[:50]}")
    else:
        print("\nNo results above threshold.")

    print("\nDONE")


if __name__ == "__main__":
    main()
