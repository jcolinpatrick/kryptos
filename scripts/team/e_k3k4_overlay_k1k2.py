#!/usr/bin/env python3
"""
Cipher: K3+K4 overlaid on K1+K2 chart grid
Family: team
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""E-K3K4-OVERLAY: Test whether K3+K4 combined and mapped onto the K1-K2
chart grid (14×31) produces K4's cipher key or reveals a second message.

Hypothesis: "X LAYER TWO" means K3 has a second layer accessed by combining
K3+K4 with K1+K2 in the shared 14×31 grid. Antipodes puts K3→K4 as one
continuous block (433 chars = 336+97). K3+K4 = 14×31 = K1-K2 chart dims.

Tests:
1. K3+K4 in 14×31 grid (various fill orders) overlaid on K1+K2 CT
2. K1+K2 CT values at K4 grid positions as running key for K4
3. Beaufort/Vig/VBeau of K3+K4 grid against K1+K2 grid → second message
4. ? and X positions as grille holes / operation points
5. K3 CT + K4 CT as continuous stream, Antipodes ordering
"""
import sys
import os
import json
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, N_CRIBS,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

RESULTS_PATH = os.path.join(_ROOT, "results", "e_k3k4_overlay_k1k2.json")

# ── Source texts ─────────────────────────────────────────────────────────

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"

K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLGTI"
    "MVMZJANQLVKQEDAGDVFRPJUNGEUNAQZ"
    "GZLECGYUXUEENJTBJLBQCRTBJDFHRRY"
    "IZETKZEMVDUFKSJHKFWHKUWQLSZFTIH"
    "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEV"
    "LDKFEZMOQQJLTTUGSYQPFEUNLAVIDXF"
    "LGGTEZFKZBSFDQVGOGIPUFXHHDRKFFH"
    "QNTGPUAECNUVPDJMQCLQUMUNEDFQELZ"
    "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQ"
    "FMPNZGLFLPMRJQYALMGNUVPDXVKPDQU"
    "MEBEDMHDAFM"
)

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNETP"
    "RNGATIHNRARPESLNNELEBLPIIACAEWMTW"
    "NDITEENRAHCTENEUDRETNHAEOETFOLSED"
    "TIWENHAEIOYTEYQHEENCTAYCREIFTBRSP"
    "AMHHEWENATAMATEGYEERLBTEEFOASFIOT"
    "UETUAEOTOARMAEERTNRTIBSEDDNIAAHTT"
    "MSTEWPIEROAGRIEWFEBAECTDDHILCEIHS"
    "ITEGOEAOSDDRYDLORITRKLMLEHAGTDHAR"
    "DPNEOHMGFMFEUHEECDMRIPFEIMEHNLSS"
    "TTRTVDOHW"
)

K4_CT = CT  # "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# K2 plaintext (for reference)
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOS"
    "SIBLETHEYUSEDTHEEARTHSMAGNETICFI"
    "ELDXTHEINFORMATIONWASGATHEREDANDT"
    "RANSMITTEDUNDERGROUNDTOANUNKNOWNL"
    "OCATIONXDOESLANGLEYKNOWABOUTTHISX"
    "THEYSHOULDXITSBURIEDOUTTHERESOME"
    "WHEREXWHOKNOWSTHEEXACTLOCATIONXON"
    "LYWWXTHISWASHISLASTMESSAGEXTHIRTY"
    "EIGHTDEGREESFIFTYSEVENNMINURESSIX"
    "POINTFIVESECONDSWESTXIDBYROWS"
)

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def to_nums(text, idx=AZ_IDX):
    return [idx[c] for c in text if c in idx]


def from_nums(nums, alpha=AZ):
    return "".join(alpha[n % MOD] for n in nums)


# ── Grid builders ────────────────────────────────────────────────────────

def fill_grid_cols_bottom_to_top(text, rows, cols):
    """Fill grid column-by-column, bottom to top (K3 style)."""
    grid = [[''] * cols for _ in range(rows)]
    idx = 0
    for c in range(cols):
        for r in range(rows - 1, -1, -1):
            if idx < len(text):
                grid[r][c] = text[idx]
                idx += 1
    return grid


def fill_grid_cols_top_to_bottom(text, rows, cols):
    """Fill grid column-by-column, top to bottom."""
    grid = [[''] * cols for _ in range(rows)]
    idx = 0
    for c in range(cols):
        for r in range(rows):
            if idx < len(text):
                grid[r][c] = text[idx]
                idx += 1
    return grid


def fill_grid_rows_left_to_right(text, rows, cols):
    """Fill grid row-by-row, left to right (standard)."""
    grid = [[''] * cols for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(text):
                grid[r][c] = text[idx]
                idx += 1
    return grid


def fill_grid_serpentine_cols(text, rows, cols):
    """Fill grid column-by-column, alternating bottom-to-top / top-to-bottom."""
    grid = [[''] * cols for _ in range(rows)]
    idx = 0
    for c in range(cols):
        if c % 2 == 0:  # bottom to top
            for r in range(rows - 1, -1, -1):
                if idx < len(text):
                    grid[r][c] = text[idx]
                    idx += 1
        else:  # top to bottom
            for r in range(rows):
                if idx < len(text):
                    grid[r][c] = text[idx]
                    idx += 1
    return grid


def read_grid_rows(grid):
    """Read grid row-by-row, left to right."""
    return ''.join(grid[r][c] for r in range(len(grid)) for c in range(len(grid[0])) if grid[r][c])


def read_grid_cols(grid):
    """Read grid column-by-column, top to bottom."""
    rows, cols = len(grid), len(grid[0])
    return ''.join(grid[r][c] for c in range(cols) for r in range(rows) if grid[r][c])


def read_grid_cols_bottom_to_top(grid):
    """Read grid column-by-column, bottom to top."""
    rows, cols = len(grid), len(grid[0])
    return ''.join(grid[r][c] for c in range(cols) for r in range(rows-1, -1, -1) if grid[r][c])


# ── Test functions ───────────────────────────────────────────────────────

def test_overlay_as_key(k3k4_grid, k1k2_grid, rows, cols, label):
    """Use K1+K2 grid values at K4 positions as running key for K4."""
    results = []

    # K4 occupies the LAST 7 rows (or first 7 rows) of the 31-row grid
    # Try both: K4 at bottom (rows 24-30) and K4 at top (rows 0-6)
    k4_positions_bottom = []  # K4 at rows 24-30
    k4_positions_top = []     # K4 at rows 0-6

    k4_idx = 0
    for r in range(24, min(31, rows)):
        for c in range(cols):
            if k4_idx < 97:
                k4_positions_bottom.append((r, c, k4_idx))
                k4_idx += 1

    k4_idx = 0
    for r in range(min(7, rows)):
        for c in range(cols):
            if k4_idx < 97:
                k4_positions_top.append((r, c, k4_idx))
                k4_idx += 1

    for pos_name, k4_positions in [("k4_bottom", k4_positions_bottom),
                                     ("k4_top", k4_positions_top)]:
        # Extract K1+K2 values at K4 grid positions
        key_chars = []
        for r, c, k4i in k4_positions:
            if r < len(k1k2_grid) and c < len(k1k2_grid[0]) and k1k2_grid[r][c]:
                key_chars.append(k1k2_grid[r][c])
            else:
                key_chars.append('A')  # placeholder

        key_text = ''.join(key_chars)
        if len(key_text) < 97:
            key_text += 'A' * (97 - len(key_text))

        key_nums = to_nums(key_text)
        ct_nums = to_nums(K4_CT)

        for variant_name, decrypt in [
            ("beaufort", lambda c, k: (k - c) % MOD),
            ("vigenere", lambda c, k: (c - k) % MOD),
            ("var_beau", lambda c, k: (c + k) % MOD),
        ]:
            pt_nums = [decrypt(ct_nums[i], key_nums[i]) for i in range(97)]
            pt = from_nums(pt_nums)
            sc = score_cribs(pt)

            if sc >= 4:
                detail = score_cribs_detailed(pt)
                print(f"    {label} {pos_name} {variant_name}: {sc}/24 "
                      f"(ENE={detail['ene_score']}/13 BCL={detail['bc_score']}/11)")
                print(f"      PT[20:40] = {pt[20:40]}")

            results.append({
                "label": label, "position": pos_name, "variant": variant_name,
                "score": sc,
            })

    return results


def test_grid_combination(k3k4_grid, k1k2_grid, rows, cols, label):
    """Combine K3+K4 grid with K1+K2 grid via Beaufort/Vig/VBeau → second message."""
    results = []

    # Full grid combination: apply cipher operation between corresponding cells
    for variant_name, combine in [
        ("beaufort", lambda a, b: (a - b) % MOD),
        ("vigenere", lambda a, b: (a + b) % MOD),
        ("sub", lambda a, b: (b - a) % MOD),
        ("xor_mod26", lambda a, b: (a ^ b) % MOD),
    ]:
        combined = []
        for r in range(rows):
            for c in range(cols):
                if (r < len(k3k4_grid) and c < len(k3k4_grid[0]) and k3k4_grid[r][c] and
                    r < len(k1k2_grid) and c < len(k1k2_grid[0]) and k1k2_grid[r][c]):
                    a = AZ_IDX.get(k3k4_grid[r][c], 0)
                    b = AZ_IDX.get(k1k2_grid[r][c], 0)
                    combined.append(combine(a, b))

        if len(combined) >= 97:
            combined_text = from_nums(combined)
            # Check if K4 positions (last 97 chars or first 97) contain cribs
            # Try the full combined text — check for English fragments
            # Score the K4 portion
            k4_portion_end = combined_text[-97:] if len(combined_text) >= 97 else combined_text
            k4_portion_start = combined_text[:97]

            for portion_name, portion in [("last97", k4_portion_end), ("first97", k4_portion_start)]:
                sc = score_cribs(portion)
                if sc >= 4:
                    detail = score_cribs_detailed(portion)
                    print(f"    {label} {variant_name} {portion_name}: {sc}/24")
                    print(f"      Text[20:40] = {portion[20:40]}")
                results.append({
                    "label": label, "variant": variant_name,
                    "portion": portion_name, "score": sc,
                })

    return results


def test_antipodes_ordering():
    """Test K3→K4→K1→K2 as continuous stream, then rearrange."""
    print("\n" + "=" * 70)
    print("TEST: Antipodes Ordering (K3→K4→K1→K2)")
    print("=" * 70)

    results = []

    # Antipodes order: K3 CT + K4 CT + K1 CT + K2 CT
    antipodes_stream = K3_CT + K4_CT + K1_CT + K2_CT
    print(f"  Antipodes stream: {len(antipodes_stream)} chars")

    # K3+K4 block
    k3k4 = K3_CT + K4_CT
    print(f"  K3+K4 block: {len(k3k4)} chars (should be ~433)")

    # K1+K2 block
    k1k2 = K1_CT + K2_CT
    print(f"  K1+K2 block: {len(k1k2)} chars")

    # Test: K1+K2 CT as running key for K4 (sequential, Antipodes-adjacent)
    print("\n  --- K1+K2 CT as running key for K4 at all offsets ---")
    k1k2_nums = to_nums(k1k2)
    ct_nums = to_nums(K4_CT)
    best = {"score": 0}

    for variant_name, decrypt in [
        ("beaufort", lambda c, k: (k - c) % MOD),
        ("vigenere", lambda c, k: (c - k) % MOD),
        ("var_beau", lambda c, k: (c + k) % MOD),
    ]:
        for offset in range(len(k1k2)):
            key = [k1k2_nums[(i + offset) % len(k1k2_nums)] for i in range(97)]
            pt_nums = [decrypt(ct_nums[i], key[i]) for i in range(97)]
            pt = from_nums(pt_nums)
            sc = score_cribs(pt)
            if sc > best["score"]:
                best = {"score": sc, "variant": variant_name, "offset": offset, "pt": pt}

    print(f"    Best: {best['score']}/24 ({best.get('variant','')} offset={best.get('offset','')})")
    results.append({"test": "k1k2_running_key", **best})

    # Test: K3 CT as running key for K4 at all offsets
    print("\n  --- K3 CT as running key for K4 at all offsets ---")
    k3_nums = to_nums(K3_CT)
    best_k3 = {"score": 0}

    for variant_name, decrypt in [
        ("beaufort", lambda c, k: (k - c) % MOD),
        ("vigenere", lambda c, k: (c - k) % MOD),
        ("var_beau", lambda c, k: (c + k) % MOD),
    ]:
        for offset in range(len(K3_CT)):
            key = [k3_nums[(i + offset) % len(k3_nums)] for i in range(97)]
            pt_nums = [decrypt(ct_nums[i], key[i]) for i in range(97)]
            pt = from_nums(pt_nums)
            sc = score_cribs(pt)
            if sc > best_k3["score"]:
                best_k3 = {"score": sc, "variant": variant_name, "offset": offset, "pt": pt}

    print(f"    Best: {best_k3['score']}/24 ({best_k3.get('variant','')} offset={best_k3.get('offset','')})")
    results.append({"test": "k3_running_key", **best_k3})

    return results


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-K3K4-OVERLAY: K3+K4 Overlaid on K1+K2 Chart Grid")
    print("=" * 70)

    k3k4 = K3_CT + K4_CT
    k1k2 = K1_CT + K2_CT

    print(f"  K3+K4: {len(k3k4)} chars")
    print(f"  K1+K2: {len(k1k2)} chars")
    print(f"  Target grid: 31 rows × 14 cols = {31*14} cells")

    all_results = {"experiment_id": "e_k3k4_overlay_k1k2", "tests": []}
    best_overall = 0

    # ── Build K3+K4 grids (various fill orders) ──────────────────────────
    fill_methods = [
        ("cols_b2t", fill_grid_cols_bottom_to_top),  # K3-style
        ("cols_t2b", fill_grid_cols_top_to_bottom),
        ("rows_l2r", fill_grid_rows_left_to_right),
        ("serp_cols", fill_grid_serpentine_cols),
    ]

    # ── Build K1+K2 grids ────────────────────────────────────────────────
    # K1+K2 chart is natively 31 cols × 14 rows (CT only)
    # When rotated 90°: 14 cols × 31 rows (matching K3+K4)

    # K1+K2 CT lines (from encoding chart, 31 chars each)
    k1k2_lines = []
    # Line 1-2: K1
    k1k2_lines.append(K1_CT[:31])
    k1k2_lines.append(K1_CT[31:62])
    # Lines 3+: K2
    for i in range(0, len(K2_CT), 31):
        k1k2_lines.append(K2_CT[i:i+31])

    print(f"  K1+K2 CT lines: {len(k1k2_lines)} lines")

    # Method A: K1+K2 as 14×31 grid (14 rows, 31 cols = native chart)
    # then rotate to 31×14
    k1k2_native = fill_grid_rows_left_to_right(k1k2, 14, 31)

    # "Rotate 90°": transpose → 31 rows × 14 cols
    k1k2_rotated = [[''] * 14 for _ in range(31)]
    for r in range(14):
        for c in range(31):
            if r < len(k1k2_native) and c < len(k1k2_native[0]) and k1k2_native[r][c]:
                k1k2_rotated[c][r] = k1k2_native[r][c]

    # Method B: K1+K2 CT directly in 31×14 grid (row-by-row)
    k1k2_31x14_rows = fill_grid_rows_left_to_right(k1k2, 31, 14)

    # Method C: K1+K2 CT in 31×14 grid (col-by-col, bottom to top = K3 style)
    k1k2_31x14_cols = fill_grid_cols_bottom_to_top(k1k2, 31, 14)

    k1k2_grids = [
        ("k1k2_rotated", k1k2_rotated),
        ("k1k2_31x14_rows", k1k2_31x14_rows),
        ("k1k2_31x14_cols", k1k2_31x14_cols),
    ]

    # ── Test 1: K1+K2 grid values at K4 positions as key ────────────────
    print("\n" + "=" * 70)
    print("TEST 1: K1+K2 Grid Values at K4 Positions as Running Key")
    print("=" * 70)

    for k3k4_fill_name, k3k4_fill_fn in fill_methods:
        k3k4_grid = k3k4_fill_fn(k3k4, 31, 14)
        for k1k2_name, k1k2_grid in k1k2_grids:
            label = f"{k3k4_fill_name}+{k1k2_name}"
            res = test_overlay_as_key(k3k4_grid, k1k2_grid, 31, 14, label)
            all_results["tests"].extend(res)
            for r in res:
                if r["score"] > best_overall:
                    best_overall = r["score"]

    # ── Test 2: Full grid combination (Beaufort/Vig/VBeau) ──────────────
    print("\n" + "=" * 70)
    print("TEST 2: Full Grid Combination (K3+K4 ⊕ K1+K2)")
    print("=" * 70)

    for k3k4_fill_name, k3k4_fill_fn in fill_methods:
        k3k4_grid = k3k4_fill_fn(k3k4, 31, 14)
        for k1k2_name, k1k2_grid in k1k2_grids:
            label = f"{k3k4_fill_name}+{k1k2_name}"
            res = test_grid_combination(k3k4_grid, k1k2_grid, 31, 14, label)
            all_results["tests"].extend(res)
            for r in res:
                if r["score"] > best_overall:
                    best_overall = r["score"]

    # ── Test 3: Antipodes continuous stream ──────────────────────────────
    res_ant = test_antipodes_ordering()
    all_results["tests"].extend(res_ant)
    for r in res_ant:
        if r.get("score", 0) > best_overall:
            best_overall = r["score"]

    # ── Test 4: K3 PT positions that contain X or ? as grille on K4 ─────
    print("\n" + "=" * 70)
    print("TEST 4: X and ? Positions as Grille Holes")
    print("=" * 70)

    # Find X and ? positions in K2 plaintext
    x_positions_k2 = [i for i, c in enumerate(K2_PT) if c == 'X']
    print(f"  X positions in K2 PT: {x_positions_k2}")
    print(f"  Count: {len(x_positions_k2)}")

    # Map these to the 31×14 grid and check what K4 has at those positions
    for k1k2_name, k1k2_grid in k1k2_grids:
        # Find which grid cells correspond to X positions
        x_cells = []
        idx = 0
        for r in range(31):
            for c in range(14):
                if idx < len(K2_PT) and r < len(k1k2_grid) and c < len(k1k2_grid[0]):
                    if idx < len(K2_PT) and K2_PT[idx] == 'X':
                        x_cells.append((r, c, idx))
                idx += 1

    # Also test: ? positions on the sculpture as selection mask
    # K2 CT has ? at specific positions (3 in K2)
    # These positions in the grid could be grille holes for K4

    # ── Test 5: Direct K1+K2 CT → K4 key mapping via grid ──────────────
    print("\n" + "=" * 70)
    print("TEST 5: Grid-Mapped K1K2 CT as K4 Key (All Grid Configs)")
    print("=" * 70)

    best_test5 = 0
    configs_tested = 0

    # For each way of putting K3+K4 in the grid, the K4 characters
    # end up at specific (row, col) positions. Read the K1+K2 value
    # at those same positions → that's the key.
    for k3k4_fill_name, k3k4_fill_fn in fill_methods:
        k3k4_grid = k3k4_fill_fn(k3k4, 31, 14)

        # Find where K4 chars landed in the grid
        # K4 starts at position len(K3_CT) in the k3k4 stream
        k4_start = len(K3_CT)
        k4_grid_positions = []
        idx = 0
        for r in range(31):
            for c in range(14):
                # This depends on fill method — need to track which text index
                # went to which grid cell
                pass

        # Simpler: rebuild with index tracking
        k4_cells = []
        if "cols_b2t" in k3k4_fill_name:
            idx = 0
            for c in range(14):
                for r in range(30, -1, -1):
                    if idx >= k4_start and idx < k4_start + 97:
                        k4_cells.append((r, c, idx - k4_start))
                    idx += 1
        elif "cols_t2b" in k3k4_fill_name:
            idx = 0
            for c in range(14):
                for r in range(31):
                    if idx >= k4_start and idx < k4_start + 97:
                        k4_cells.append((r, c, idx - k4_start))
                    idx += 1
        elif "rows_l2r" in k3k4_fill_name:
            idx = 0
            for r in range(31):
                for c in range(14):
                    if idx >= k4_start and idx < k4_start + 97:
                        k4_cells.append((r, c, idx - k4_start))
                    idx += 1
        elif "serp_cols" in k3k4_fill_name:
            idx = 0
            for c in range(14):
                if c % 2 == 0:
                    for r in range(30, -1, -1):
                        if idx >= k4_start and idx < k4_start + 97:
                            k4_cells.append((r, c, idx - k4_start))
                        idx += 1
                else:
                    for r in range(31):
                        if idx >= k4_start and idx < k4_start + 97:
                            k4_cells.append((r, c, idx - k4_start))
                        idx += 1

        if not k4_cells:
            continue

        # For each K1+K2 grid arrangement, extract key at K4 positions
        for k1k2_name, k1k2_grid in k1k2_grids:
            key_chars = []
            for r, c, k4i in k4_cells:
                if r < len(k1k2_grid) and c < len(k1k2_grid[0]) and k1k2_grid[r][c]:
                    key_chars.append(k1k2_grid[r][c])
                else:
                    key_chars.append('A')

            key_text = ''.join(key_chars[:97])
            key_nums = to_nums(key_text)
            ct_nums = to_nums(K4_CT)

            for variant_name, decrypt in [
                ("beaufort", lambda c, k: (k - c) % MOD),
                ("vigenere", lambda c, k: (c - k) % MOD),
                ("var_beau", lambda c, k: (c + k) % MOD),
            ]:
                pt_nums = [decrypt(ct_nums[i], key_nums[i]) for i in range(min(97, len(key_nums)))]
                pt = from_nums(pt_nums)
                sc = score_cribs(pt)
                configs_tested += 1

                if sc > best_test5:
                    best_test5 = sc

                if sc >= 5:
                    detail = score_cribs_detailed(pt)
                    print(f"    {k3k4_fill_name}+{k1k2_name} {variant_name}: {sc}/24 "
                          f"(ENE={detail['ene_score']}/13 BCL={detail['bc_score']}/11)")
                    print(f"      PT[20:40] = {pt[20:40]}")
                    print(f"      Key[0:20] = {key_text[:20]}")

                if sc > best_overall:
                    best_overall = sc

    print(f"\n  Test 5: {configs_tested} configs, best = {best_test5}/24")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  OVERALL BEST: {best_overall}/24")
    print(f"  Elapsed: {elapsed:.1f}s")

    if best_overall >= 18:
        print("  *** SIGNAL DETECTED ***")
    elif best_overall >= 10:
        print("  ** INTERESTING **")
    elif best_overall >= 6:
        print("  * Elevated *")
    else:
        print("  Noise floor.")

    all_results["summary"] = {
        "best_overall": best_overall,
        "elapsed": round(elapsed, 1),
    }

    os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"  Results saved to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
