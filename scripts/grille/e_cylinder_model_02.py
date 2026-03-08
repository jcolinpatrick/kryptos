#!/usr/bin/env python3
"""Two-cylinder model: cipher panel + tableau panel as concentric cylinders.

Cipher: Vigenere/Beaufort + cylindrical alignment
Family: grille
Status: active
Keyspace: ~30K configs
Last run: never
Best score: n/a

Motivation: The Code Room (1990) shows the Kryptos tableau wrapped into a
projection cylinder. If we curve the cipher text panel into a SECOND cylinder
(matching the pool radius), the two panels form concentric cylinders.

The key insight: on a flat panel, Vigenere key position = linear position.
On a cylinder, key position = COLUMN position (angular position on the
cylinder). This creates a fundamentally different key schedule.

Three models tested:
  A) Column-keyed Vigenere: key depends on grid column, not linear position
  B) Diagonal-keyed: key depends on (row+col) % 26 — natural consequence
     of two concentric KA tableau cylinders
  C) Full-grid helical extraction: helical path through all 28 rows of the
     cylinder, extracting K4 chars in encounter order

The 28x31 cipher grid:
  K4 positions: row 24 cols 27-30 (4 chars) + rows 25-27 full (93 chars)
  Full grid: K1(63) + ?(1) + K2(369) + ?(1) + K3(336) + ?(1) + K4(97) = 868
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant
from kryptos.kernel.scoring.free_crib import score_free_fast

# ── Grid constants ──────────────────────────────────────────────────────
GRID_WIDTH = 31
GRID_HEIGHT = 28
GRID_SIZE = GRID_WIDTH * GRID_HEIGHT  # 868

# K4 position in the full 28×31 grid
K4_START_POS = 771  # position in the 868-char linear sequence
K4_START_ROW = 24   # row in the 28-row grid (0-indexed)
K4_START_COL = 27   # column where K4 begins

# Build (row, col) for each K4 character
K4_GRID = []
for i in range(CT_LEN):
    pos = K4_START_POS + i
    row = pos // GRID_WIDTH
    col = pos % GRID_WIDTH
    K4_GRID.append((row, col))

assert len(K4_GRID) == 97
assert K4_GRID[0] == (24, 27)  # O
assert K4_GRID[96] == (27, 30)  # R (last char)

# ── Full 868-char grid (for helical extraction) ────────────────────────
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

# Full grid: K1 + ? + K2 + ? + K3 + ? + K4
FULL_GRID = K1_CT + "?" + K2_CT + "?" + K3_CT + "?" + CT
assert len(FULL_GRID) == GRID_SIZE, f"Grid size {len(FULL_GRID)} != {GRID_SIZE}"

# Verify K4 position
for i in range(CT_LEN):
    assert FULL_GRID[K4_START_POS + i] == CT[i], f"K4 mismatch at {i}"

# K4 linear positions in the full 868-char grid
K4_POSITIONS = set(range(K4_START_POS, K4_START_POS + CT_LEN))

# ── Keywords ────────────────────────────────────────────────────────────
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE",
    "DEFECTOR", "PARALLAX", "COLOPHON", "SHADOW",
    "URANIA", "QUARTZ", "FILTER", "CIPHER",
    "HIDDEN", "LIGHT", "POINT", "CLOCK",
    "MATRIX", "BERLIN",
]

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

THRESHOLD = 6  # free crib score to report

# ── Scoring ─────────────────────────────────────────────────────────────
results = []

def try_decrypt(ct_text, key_nums, variant, label):
    """Decrypt and score, recording any hits above threshold."""
    pt = decrypt_text(ct_text, key_nums, variant)
    sc = score_free_fast(pt)
    if sc > THRESHOLD:
        results.append((sc, label, variant.value, pt))
        print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:40]}...")


def main():
    ct_nums = [ALPH_IDX[c] for c in CT]
    total_configs = 0

    # ================================================================
    # MODEL A: Column-keyed Vigenere
    # Key for K4[i] = keyword[column_of_K4[i] % keyword_len]
    # With rotational offset R: key = keyword[(col + R) % 31 % kw_len]
    # ================================================================
    print("=" * 70)
    print("MODEL A: Column-keyed Vigenere (key depends on grid column)")
    print("=" * 70)

    for kw in KEYWORDS:
        kw_nums = [ALPH_IDX[c] for c in kw]
        kw_len = len(kw)

        for rotation in range(31):
            # Build key sequence based on column position
            key_seq = []
            for i in range(CT_LEN):
                row, col = K4_GRID[i]
                effective_col = (col + rotation) % GRID_WIDTH
                key_idx = effective_col % kw_len
                key_seq.append(kw_nums[key_idx])

            for variant in VARIANTS:
                label = f"col_keyed_{kw}_rot{rotation}"
                try_decrypt(CT, key_seq, variant, label)
                total_configs += 1

    print(f"  Model A: {total_configs} configs tested")

    # ================================================================
    # MODEL A2: Column-keyed with REVERSED rows (projection model)
    # Reading from inside the cylinder, each row is mirrored.
    # The "reversed CT" has rows read right-to-left, but the column
    # position for key lookup uses the ORIGINAL column.
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL A2: Column-keyed + row reversal (projection/inside reading)")
    print("=" * 70)

    # Build reversed K4: reverse each row independently
    reversed_ct_chars = []
    reversed_grid = []  # (row, col) for key lookup in reversed order

    # Row 24: cols 27-30 → reversed to 30-27
    row24_chars = list(CT[0:4])
    row24_grid = [(24, c) for c in range(27, 31)]
    reversed_ct_chars.extend(reversed(row24_chars))
    reversed_grid.extend(reversed(row24_grid))

    # Rows 25-27: cols 0-30 → reversed to 30-0
    for row_offset, row_num in enumerate([25, 26, 27]):
        start = 4 + row_offset * 31
        end = start + 31
        row_chars = list(CT[start:end])
        row_grid = [(row_num, c) for c in range(31)]
        reversed_ct_chars.extend(reversed(row_chars))
        reversed_grid.extend(reversed(row_grid))

    reversed_ct = "".join(reversed_ct_chars)
    assert len(reversed_ct) == 97

    a2_configs = 0
    for kw in KEYWORDS:
        kw_nums = [ALPH_IDX[c] for c in kw]
        kw_len = len(kw)

        for rotation in range(31):
            key_seq = []
            for i in range(CT_LEN):
                row, col = reversed_grid[i]
                effective_col = (col + rotation) % GRID_WIDTH
                key_idx = effective_col % kw_len
                key_seq.append(kw_nums[key_idx])

            for variant in VARIANTS:
                label = f"col_keyed_rev_{kw}_rot{rotation}"
                try_decrypt(reversed_ct, key_seq, variant, label)
                a2_configs += 1

    total_configs += a2_configs
    print(f"  Model A2: {a2_configs} configs tested")

    # ================================================================
    # MODEL B: Diagonal-keyed (row+col model)
    # Two concentric KA tableau cylinders: key = (row + col + D) % 26
    # Maps to KA alphabet index. Test all 26 offsets × 3 variants.
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL B: Diagonal-keyed — key = KA[(row+col+D) % 26]")
    print("=" * 70)

    b_configs = 0
    for D in range(26):
        key_seq = []
        for i in range(CT_LEN):
            row, col = K4_GRID[i]
            ka_idx = (row + col + D) % 26
            # Convert KA index to standard ALPH index
            key_seq.append(ALPH_IDX[KA[ka_idx]])

        for variant in VARIANTS:
            label = f"diag_keyed_D{D}"
            try_decrypt(CT, key_seq, variant, label)
            b_configs += 1

    # Also test with reversed rows
    for D in range(26):
        key_seq = []
        for i in range(CT_LEN):
            row, col = reversed_grid[i]
            ka_idx = (row + col + D) % 26
            key_seq.append(ALPH_IDX[KA[ka_idx]])

        for variant in VARIANTS:
            label = f"diag_keyed_rev_D{D}"
            try_decrypt(reversed_ct, key_seq, variant, label)
            b_configs += 1

    total_configs += b_configs
    print(f"  Model B: {b_configs} configs tested")

    # ================================================================
    # MODEL B2: Row-keyed (each row uses a single key from the key column)
    # In the two-cylinder model, the key column (A-Z) determines the
    # Vigenere shift for each entire row.
    # Row 24→key X (AZ[23]), Row 25→key Y, Row 26→key Z, Row 27→footer
    # Test with vertical offsets (sliding cylinders up/down).
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL B2: Row-keyed (each row gets one key from key column)")
    print("=" * 70)

    b2_configs = 0
    for v_offset in range(28):
        key_seq = []
        valid = True
        for i in range(CT_LEN):
            row, col = K4_GRID[i]
            effective_row = (row + v_offset) % GRID_HEIGHT
            # Body rows 1-26 have key column A-Z
            if 1 <= effective_row <= 26:
                key_char = ALPH[effective_row - 1]  # row 1→A, row 26→Z
            else:
                # Header/footer: try both extremes
                key_char = ALPH[0]  # Use A as fallback
            key_seq.append(ALPH_IDX[key_char])

        for variant in VARIANTS:
            label = f"row_keyed_voff{v_offset}"
            try_decrypt(CT, key_seq, variant, label)
            b2_configs += 1

    # Also combine with horizontal rotation
    for v_offset in range(28):
        for h_offset in range(31):
            key_seq = []
            for i in range(CT_LEN):
                row, col = K4_GRID[i]
                eff_row = (row + v_offset) % GRID_HEIGHT
                eff_col = (col + h_offset) % GRID_WIDTH
                # Tableau body value at (eff_row, eff_col):
                # For body rows, tableau[r][c] = KA[(r-1 + c-1) % 26] for c >= 1
                if 1 <= eff_row <= 26 and 1 <= eff_col <= 30:
                    ka_idx = (eff_row - 1 + eff_col - 1) % 26
                    key_seq.append(ALPH_IDX[KA[ka_idx]])
                elif 1 <= eff_row <= 26 and eff_col == 0:
                    # Key column
                    key_seq.append(ALPH_IDX[ALPH[eff_row - 1]])
                else:
                    # Header/footer — use column value from header
                    # Header: ABCDEFGHIJKLMNOPQRSTUVWXYZABCD (30 chars at cols 1-30)
                    if 1 <= eff_col <= 30:
                        key_seq.append((eff_col - 1) % 26)
                    else:
                        key_seq.append(0)

            for variant in VARIANTS:
                label = f"tableau_align_v{v_offset}_h{h_offset}"
                try_decrypt(CT, key_seq, variant, label)
                b2_configs += 1

    total_configs += b2_configs
    print(f"  Model B2: {b2_configs} configs tested")

    # ================================================================
    # MODEL C: Full-grid helical extraction
    # Helical path through ALL 28 rows of the cylinder (868 chars).
    # Extract K4 characters in the order the helix encounters them.
    # Then decrypt with standard periodic Vigenere.
    # ================================================================
    print("\n" + "=" * 70)
    print("MODEL C: Full-grid helical K4 extraction")
    print("=" * 70)

    c_configs = 0
    c_patterns = 0

    for shift in range(31):  # helical shift per row
        for start_col in range(31):
            for direction in [1, -1]:  # top-down or bottom-up
                rows = list(range(28)) if direction == 1 else list(range(27, -1, -1))
                k4_order = []  # indices into K4 (0-96)

                for row_idx, r in enumerate(rows):
                    base_col = (start_col + shift * row_idx) % 31
                    for step in range(31):
                        c = (base_col + step) % 31
                        pos = r * 31 + c
                        if pos in K4_POSITIONS:
                            k4_idx = pos - K4_START_POS
                            if k4_idx not in [x for x in k4_order]:
                                k4_order.append(k4_idx)

                if len(k4_order) != 97:
                    continue

                c_patterns += 1
                # Apply permutation to CT
                permuted_ct = "".join(CT[k4_order[i]] for i in range(97))

                for kw in KEYWORDS:
                    kw_nums = [ALPH_IDX[c] for c in kw]
                    for variant in VARIANTS:
                        pt = decrypt_text(permuted_ct, kw_nums, variant)
                        sc = score_free_fast(pt)
                        if sc > THRESHOLD:
                            label = f"helix_full_shift{shift}_col{start_col}_dir{direction}_{kw}"
                            results.append((sc, label, variant.value, pt))
                            print(f"  ** SCORE {sc}: {label} | {variant.value} | {pt[:40]}...")
                        c_configs += 1

        if (shift + 1) % 5 == 0:
            print(f"  ... shift {shift+1}/31, {c_patterns} valid patterns, {c_configs} configs")

    total_configs += c_configs
    print(f"  Model C: {c_configs} configs ({c_patterns} patterns)")

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
