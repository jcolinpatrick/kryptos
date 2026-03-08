#!/usr/bin/env python3
"""Panel rearrangement: 4 Kryptos copper sheets reassembled as nested cylinders.

Cipher: Vigenere/Beaufort + panel rearrangement
Family: grille
Status: active
Keyspace: ~50K configs
Last run: never
Best score: n/a

Motivation: The Code Room (1990) shows the Kryptos TABLEAU wrapped into a
cylinder with a specific arrangement: Tableau Lower (TL) in front, Tableau
Upper (TU) in back. This is a rearrangement of the 4 physical copper sheets.

If the decryptor must rearrange the panels into nested cylinders (cipher
inside, tableau outside), different arrangements create different key
schedules for Vigenere decryption.

Key insight: on a cylinder, walking continuously around the back panel
reads columns in REVERSE order (30->0 instead of 0->30). This affects
which cipher columns align with which tableau columns.

The 4 panels (each 14 rows x 31 cols):
  CU = Cipher Upper (rows 0-13): K1 + K2
  CL = Cipher Lower (rows 14-27): K3 + K4
  TU = Tableau Upper (rows 0-13): header + body rows 1-13
  TL = Tableau Lower (rows 14-27): body rows 14-26 + footer

Arrangement types:
  SAME: CL front + CU back  /  TL front + TU back  (Code Room match)
  CROSS: CL front + CU back  /  TU front + TL back  (mismatched halves)
  INV: CU front + CL back  /  TL front + TU back
  DBL_CROSS: CU front + CL back  /  TU front + TL back

For each arrangement:
  - Direct facing: cipher row r faces which tableau row?
  - Back panel column reversal: cipher col c faces tableau col (30-c)?
  - Combined row+column remapping creates a novel key schedule
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.free_crib import score_free_fast

# ── Tableau structure ───────────────────────────────────────────────────
# The Kryptos tableau (28 rows × 31 cols):
#   Row 0 (header): cols 1-30 = ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (standard AZ)
#   Rows 1-26 (body): col 0 = key letter (A-Z), cols 1-30 = KA shifted
#   Row 27 (footer): cols 1-30 = ABCDEFGHIJKLMNOPQRSTUVWXYZABCD

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

GRID_W = 31
GRID_H = 28
HALF_H = 14  # each half has 14 rows

# K4 positions in the full 28×31 grid
K4_START_POS = 771  # linear position
K4_GRID = []
for i in range(CT_LEN):
    pos = K4_START_POS + i
    K4_GRID.append((pos // GRID_W, pos % GRID_W))

assert K4_GRID[0] == (24, 27)  # O
assert K4_GRID[96] == (27, 30)  # R

# ── Build full tableau content ──────────────────────────────────────────
def tableau_value(r, c):
    """Return the character at tableau position (r, c).
    r: 0-27, c: 0-30."""
    if r == 0 or r == 27:
        # Header/footer
        if c == 0:
            return None  # blank
        return ALPH[(c - 1) % 26]
    else:
        # Body row
        if c == 0:
            return ALPH[r - 1]  # Key column: A for row 1, Z for row 26
        # KA shifted by (r-1): KA[(r-1+c-1) % 26]
        return KA[(r - 1 + c - 1) % 26]


# ── Arrangement models ──────────────────────────────────────────────────
# Each arrangement defines how cipher (r, c) maps to tableau (r', c')

def make_arrangement(cipher_lower_front, tableau_lower_front, back_col_reversed):
    """Return a function that maps cipher (row, col) to tableau (row, col).

    cipher_lower_front: if True, cipher lower (14-27) is front, upper (0-13) is back
    tableau_lower_front: if True, tableau lower (14-27) is front, upper (0-13) is back
    back_col_reversed: if True, back panel columns are reversed (30-c)
    """
    def mapper(cipher_row, cipher_col):
        # Determine if cipher position is on front or back of cylinder
        if cipher_lower_front:
            cipher_is_front = (cipher_row >= HALF_H)
        else:
            cipher_is_front = (cipher_row < HALF_H)

        # Effective row within the half (0-13)
        if cipher_row >= HALF_H:
            half_row = cipher_row - HALF_H  # 0-13 within lower half
        else:
            half_row = cipher_row  # 0-13 within upper half

        # Map to tableau half
        if cipher_is_front:
            # Front cipher -> front tableau
            if tableau_lower_front:
                tab_row = HALF_H + half_row  # map to lower tableau
            else:
                tab_row = half_row  # map to upper tableau
            tab_col = cipher_col  # same column (both front)
        else:
            # Back cipher -> back tableau
            if tableau_lower_front:
                tab_row = half_row  # map to upper tableau (back)
            else:
                tab_row = HALF_H + half_row  # map to lower tableau (back)

            if back_col_reversed:
                # Walking around cylinder, back columns read in reverse
                if cipher_col == 0:
                    tab_col = 0  # edge case: col 0 stays
                else:
                    tab_col = GRID_W - cipher_col  # reverse within cols 1-30
            else:
                tab_col = cipher_col

        return tab_row, tab_col

    return mapper


# ── Decryption helpers ──────────────────────────────────────────────────
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
THRESHOLD = 6

results = []


def try_key_schedule(key_nums, ct_text, label):
    """Try decrypting with a given key schedule."""
    for variant in VARIANTS:
        pt = decrypt_text(ct_text, key_nums, variant)
        sc = score_free_fast(pt)
        if sc > THRESHOLD:
            results.append((sc, label, variant.value, pt))
            print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:50]}...")


def main():
    total_configs = 0

    # ================================================================
    # PHASE 1: Row-remapped key schedule from panel rearrangement
    # For each arrangement, K4 cipher rows face different tableau rows.
    # The key for each K4 char comes from the aligned tableau position.
    # ================================================================
    print("=" * 70)
    print("PHASE 1: Panel rearrangement key schedules")
    print("=" * 70)

    arrangements = [
        # (name, cipher_lower_front, tableau_lower_front, back_reversed)
        ("SAME_norv",      True,  True,  False),  # Code Room pattern, no reversal
        ("SAME_rev",       True,  True,  True),   # Code Room pattern, back reversed
        ("CROSS_norv",     True,  False, False),   # Cipher lower front, tableau UPPER front
        ("CROSS_rev",      True,  False, True),
        ("INV_norv",       False, True,  False),   # Cipher UPPER front, tableau lower front
        ("INV_rev",        False, True,  True),
        ("DBL_CROSS_norv", False, False, False),   # Both inverted
        ("DBL_CROSS_rev",  False, False, True),
    ]

    for arr_name, clf, tlf, brev in arrangements:
        mapper = make_arrangement(clf, tlf, brev)

        # Compute key from tableau alignment
        key_nums = []
        valid = True
        detail_rows = []

        for i in range(CT_LEN):
            cr, cc = K4_GRID[i]
            tr, tc = mapper(cr, cc)
            tv = tableau_value(tr, tc)
            if tv is None:
                key_nums.append(0)  # blank position, use 0
            else:
                key_nums.append(ALPH_IDX[tv])

            if i < 10:
                detail_rows.append(f"K4[{i}]({cr},{cc})->tab({tr},{tc})={tv}")

        print(f"\n  {arr_name}:")
        print(f"    First 10 mappings: {'; '.join(detail_rows)}")
        print(f"    Key chars: {''.join(ALPH[k] for k in key_nums[:31])}...")

        try_key_schedule(key_nums, CT, arr_name)
        total_configs += 3  # 3 variants

        # Also try with rotational offset (horizontal shift between cylinders)
        for h_shift in range(1, 31):
            shifted_key = []
            for i in range(CT_LEN):
                cr, cc = K4_GRID[i]
                # Shift cipher column before mapping
                shifted_cc = (cc + h_shift) % GRID_W
                tr, tc = mapper(cr, shifted_cc)
                tv = tableau_value(tr, tc)
                if tv is None:
                    shifted_key.append(0)
                else:
                    shifted_key.append(ALPH_IDX[tv])
            try_key_schedule(shifted_key, CT, f"{arr_name}_hshift{h_shift}")
            total_configs += 3

    print(f"\n  Phase 1: {total_configs} configs tested")

    # ================================================================
    # PHASE 2: Row remap + keyword-based key
    # Instead of reading the key from the tableau, use a keyword but
    # apply it based on the REMAPPED column position.
    # Rearrangement changes which column position each character
    # effectively occupies.
    # ================================================================
    print("\n" + "=" * 70)
    print("PHASE 2: Rearrangement + keyword-based column key")
    print("=" * 70)

    KEYWORDS = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
        "DEFECTOR", "PARALLAX", "COLOPHON", "SHADOW",
        "URANIA", "QUARTZ", "FILTER", "CIPHER",
        "HIDDEN", "LIGHT", "MATRIX", "BERLIN",
    ]

    p2_configs = 0
    # The back panel has reversed columns when read continuously.
    # K4 is in the LOWER half (rows 14-27).
    # If lower is FRONT, K4 reads normally.
    # If lower is BACK, K4 columns are REVERSED.

    for kw in KEYWORDS:
        kw_nums = [ALPH_IDX[c] for c in kw]
        kw_len = len(kw)

        # Case 1: K4 on front (normal column order) — standard periodic key
        # This is what we've always tested, skip it.

        # Case 2: K4 on BACK of cylinder (reversed columns)
        # Each row's columns are reversed, changing the key alignment
        reversed_ct_chars = []
        reversed_positions = []

        # Row 24: cols 27-30 → reversed to 30-27
        for c in range(30, 26, -1):
            idx = (24 - 24) * 0  # we'll use CT directly
            reversed_positions.append(c)
        # Rows 25-27: cols 0-30 → reversed to 30-0
        for row in range(25, 28):
            for c in range(30, -1, -1):
                reversed_positions.append(c)

        # Build reversed CT
        # Row 24 chars are CT[0:4], reversed
        reversed_ct_chars = list(CT[0:4])[::-1]
        # Rows 25-27 chars are CT[4:35], CT[35:66], CT[66:97], each reversed
        for start in [4, 35, 66]:
            end = min(start + 31, 97)
            reversed_ct_chars.extend(list(CT[start:end])[::-1])
        reversed_ct = "".join(reversed_ct_chars)
        assert len(reversed_ct) == 97

        # Apply keyword based on reversed column positions
        for h_shift in range(31):
            key_seq = []
            for i, col in enumerate(reversed_positions):
                eff_col = (col + h_shift) % GRID_W
                key_seq.append(kw_nums[eff_col % kw_len])

            for variant in VARIANTS:
                pt = decrypt_text(reversed_ct, key_seq, variant)
                sc = score_free_fast(pt)
                if sc > THRESHOLD:
                    label = f"back_rev_{kw}_hshift{h_shift}"
                    results.append((sc, label, variant.value, pt))
                    print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:50]}...")
                p2_configs += 1

    total_configs += p2_configs
    print(f"  Phase 2: {p2_configs} configs tested")

    # ================================================================
    # PHASE 3: Vertical shift (sliding cylinders up/down)
    # If the inner cylinder slides vertically relative to the outer,
    # cipher rows face different tableau rows.
    # Try all 28 vertical offsets × 31 horizontal × 3 variants.
    # Use the tableau value directly as the key.
    # ================================================================
    print("\n" + "=" * 70)
    print("PHASE 3: Vertical + horizontal cylinder shift (direct tableau key)")
    print("=" * 70)

    p3_configs = 0
    for v_shift in range(28):
        for h_shift in range(31):
            key_nums = []
            for i in range(CT_LEN):
                cr, cc = K4_GRID[i]
                tr = (cr + v_shift) % GRID_H
                tc = (cc + h_shift) % GRID_W
                tv = tableau_value(tr, tc)
                if tv is None:
                    key_nums.append(0)
                else:
                    key_nums.append(ALPH_IDX[tv])

            for variant in VARIANTS:
                pt = decrypt_text(CT, key_nums, variant)
                sc = score_free_fast(pt)
                if sc > THRESHOLD:
                    label = f"vshift{v_shift}_hshift{h_shift}"
                    results.append((sc, label, variant.value, pt))
                    print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:50]}...")
                p3_configs += 1

        if (v_shift + 1) % 7 == 0:
            print(f"  ... v_shift {v_shift+1}/28, {p3_configs} configs")

    total_configs += p3_configs
    print(f"  Phase 3: {p3_configs} configs tested")

    # ================================================================
    # PHASE 4: Combined — reversed CT + tableau key from rearrangement
    # K4 on back panel (reversed), facing cross-arranged tableau
    # ================================================================
    print("\n" + "=" * 70)
    print("PHASE 4: Reversed K4 + tableau key (all v/h shifts)")
    print("=" * 70)

    # Build reversed CT and its grid positions
    rev_ct = reversed_ct  # from Phase 2
    rev_grid = []
    # Row 24 cols 30,29,28,27
    for c in [30, 29, 28, 27]:
        rev_grid.append((24, c))
    # Rows 25-27 cols 30→0
    for r in [25, 26, 27]:
        for c in range(30, -1, -1):
            rev_grid.append((r, c))
    assert len(rev_grid) == 97

    p4_configs = 0
    for v_shift in range(28):
        for h_shift in range(31):
            key_nums = []
            for i in range(CT_LEN):
                cr, cc = rev_grid[i]
                tr = (cr + v_shift) % GRID_H
                tc = (cc + h_shift) % GRID_W
                tv = tableau_value(tr, tc)
                if tv is None:
                    key_nums.append(0)
                else:
                    key_nums.append(ALPH_IDX[tv])

            for variant in VARIANTS:
                pt = decrypt_text(rev_ct, key_nums, variant)
                sc = score_free_fast(pt)
                if sc > THRESHOLD:
                    label = f"rev_vshift{v_shift}_hshift{h_shift}"
                    results.append((sc, label, variant.value, pt))
                    print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:50]}...")
                p4_configs += 1

        if (v_shift + 1) % 7 == 0:
            print(f"  ... v_shift {v_shift+1}/28, {p4_configs} configs")

    total_configs += p4_configs
    print(f"  Phase 4: {p4_configs} configs tested")

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
