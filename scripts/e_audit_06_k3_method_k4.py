#!/usr/bin/env python3
"""E-AUDIT-06: K3's ACTUAL Method Applied to K4.

[HYPOTHESIS] K4 uses K3-style double rotational transposition combined with
K1/K2-style KA-tableau Vigenère substitution.

CRITICAL CORRECTION: K3 is PURE TRANSPOSITION (no Vigenère). Prior experiments
(E-S-106, E-S-119) incorrectly modeled K3 as "columnar + Vigenère".
K3's actual method: double rotational transposition (write into grid, rotate 90°,
read off; repeat with different grid dimensions). Key: KRYPTOS = 0362514.

K1/K2 both use the KA alphabet tableau (KRYPTOSABCDEFGHIJLMNQUVWXZ), NOT standard
A-Z. If K4 combines K3-style transposition with K1/K2-style substitution, it would
use the KA tableau — which produces DIFFERENT results from standard Vigenère.

Test plan:
Phase 1: K3-exact double rotation on K4 (97 chars, 98 with Q)
Phase 2: Single rotation + KA-tableau Vigenère (all keywords × grid dims)
Phase 3: Double rotation + KA-tableau Vigenère (key combos)
Phase 4: Double rotation + standard AZ Vigenère (for comparison)
Phase 5: K3 column reordering (KRYPTOS key 0362514) + rotation + KA sub

Uses both anchored AND position-free crib scoring.
"""
import json
import math
import os
import sys
import time
from itertools import permutations, product
from typing import List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.alphabet import KA, AZ, Alphabet


# ── KA-tableau Vigenère ──────────────────────────────────────────────────

KA_IDX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}

def ka_encrypt(pt: str, key: str) -> str:
    """Encrypt using KA-tableau Vigenère (as used in K1/K2)."""
    result = []
    klen = len(key)
    for i, ch in enumerate(pt.upper()):
        p_idx = KA_IDX[ch]
        k_idx = KA_IDX[key[i % klen].upper()]
        c_idx = (p_idx + k_idx) % MOD
        result.append(KRYPTOS_ALPHABET[c_idx])
    return ''.join(result)

def ka_decrypt(ct: str, key: str) -> str:
    """Decrypt using KA-tableau Vigenère (as used in K1/K2)."""
    result = []
    klen = len(key)
    for i, ch in enumerate(ct.upper()):
        c_idx = KA_IDX[ch]
        k_idx = KA_IDX[key[i % klen].upper()]
        p_idx = (c_idx - k_idx) % MOD
        result.append(KRYPTOS_ALPHABET[p_idx])
    return ''.join(result)

def ka_beaufort_decrypt(ct: str, key: str) -> str:
    """Beaufort decrypt using KA tableau: PT = KA[(K_ka - C_ka) mod 26]."""
    result = []
    klen = len(key)
    for i, ch in enumerate(ct.upper()):
        c_idx = KA_IDX[ch]
        k_idx = KA_IDX[key[i % klen].upper()]
        p_idx = (k_idx - c_idx) % MOD
        result.append(KRYPTOS_ALPHABET[p_idx])
    return ''.join(result)

def az_decrypt(ct: str, key: str) -> str:
    """Standard Vigenère decrypt using AZ alphabet."""
    result = []
    klen = len(key)
    for i, ch in enumerate(ct.upper()):
        c_idx = ALPH_IDX[ch]
        k_idx = ALPH_IDX[key[i % klen].upper()]
        p_idx = (c_idx - k_idx) % MOD
        result.append(ALPH[p_idx])
    return ''.join(result)

def az_beaufort_decrypt(ct: str, key: str) -> str:
    """Standard Beaufort decrypt: PT = (K - CT) mod 26."""
    result = []
    klen = len(key)
    for i, ch in enumerate(ct.upper()):
        c_idx = ALPH_IDX[ch]
        k_idx = ALPH_IDX[key[i % klen].upper()]
        p_idx = (k_idx - c_idx) % MOD
        result.append(ALPH[p_idx])
    return ''.join(result)


# ── Grid rotation primitives ─────────────────────────────────────────────

def write_grid(text: str, rows: int, cols: int) -> List[List[str]]:
    """Write text into rows×cols grid, row-major. Pad with X if needed."""
    grid_size = rows * cols
    padded = text + 'X' * (grid_size - len(text))
    grid = []
    for r in range(rows):
        row = []
        for c in range(cols):
            row.append(padded[r * cols + c])
        grid.append(row)
    return grid

def read_grid(grid: List[List[str]], max_len: int = None) -> str:
    """Read grid row-major."""
    text = ''.join(ch for row in grid for ch in row)
    return text[:max_len] if max_len else text

def rotate_cw(grid: List[List[str]]) -> List[List[str]]:
    """Rotate grid 90° clockwise."""
    rows, cols = len(grid), len(grid[0])
    new_grid = []
    for c in range(cols):
        new_row = []
        for r in range(rows - 1, -1, -1):
            new_row.append(grid[r][c])
        new_grid.append(new_row)
    return new_grid

def rotate_ccw(grid: List[List[str]]) -> List[List[str]]:
    """Rotate grid 90° counter-clockwise."""
    rows, cols = len(grid), len(grid[0])
    new_grid = []
    for c in range(cols - 1, -1, -1):
        new_row = []
        for r in range(rows):
            new_row.append(grid[r][c])
        new_grid.append(new_row)
    return new_grid

def rotate_180(grid: List[List[str]]) -> List[List[str]]:
    """Rotate grid 180°."""
    return [row[::-1] for row in grid[::-1]]

def reverse_text(text: str) -> str:
    """Reverse the text (equivalent to 180° rotation of 1×N grid)."""
    return text[::-1]

ROTATIONS = {
    "cw90": rotate_cw,
    "ccw90": rotate_ccw,
    "180": rotate_180,
}


def single_rotation_transposition(text: str, rows: int, cols: int,
                                   rotation: str, original_len: int = None) -> str:
    """Write text into grid, rotate, read off."""
    if original_len is None:
        original_len = len(text)
    grid = write_grid(text, rows, cols)
    rotated = ROTATIONS[rotation](grid)
    return read_grid(rotated, original_len)


def double_rotation_transposition(text: str,
                                   rows1: int, cols1: int, rot1: str,
                                   rows2: int, cols2: int, rot2: str,
                                   original_len: int = None) -> str:
    """Two-stage rotational transposition (K3's actual method structure)."""
    if original_len is None:
        original_len = len(text)
    # Step 1
    intermediate = single_rotation_transposition(text, rows1, cols1, rot1, original_len)
    # Step 2
    return single_rotation_transposition(intermediate, rows2, cols2, rot2, original_len)


# ── Keyed columnar reordering ────────────────────────────────────────────

def keyword_column_order(keyword: str) -> List[int]:
    """Convert keyword to column ordering (alphabetical rank)."""
    indexed = [(ch, i) for i, ch in enumerate(keyword.upper())]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * len(keyword)
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order

def reorder_columns(grid: List[List[str]], order: List[int]) -> List[List[str]]:
    """Reorder grid columns according to keyword order.
    Reads columns in rank order (column with rank 0 first, etc.)."""
    cols = len(grid[0])
    # order[i] = rank of column i
    # To read in rank order: find column with rank 0, then rank 1, etc.
    rank_to_col = [0] * cols
    for col_idx, rank in enumerate(order):
        rank_to_col[rank] = col_idx
    new_grid = []
    for row in grid:
        new_row = [row[rank_to_col[r]] for r in range(cols)]
        new_grid.append(new_row)
    return new_grid

def undo_column_reorder(grid: List[List[str]], order: List[int]) -> List[List[str]]:
    """Undo keyed column reordering. Inverse of reorder_columns."""
    cols = len(grid[0])
    rank_to_col = [0] * cols
    for col_idx, rank in enumerate(order):
        rank_to_col[rank] = col_idx
    new_grid = []
    for row in grid:
        new_row = [''] * cols
        for r in range(cols):
            new_row[rank_to_col[r]] = row[r]
        new_grid.append(new_row)
    return new_grid


# ── Scoring ──────────────────────────────────────────────────────────────

def anchored_score(text: str) -> int:
    if len(text) < 74:
        return 0
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(text) and text[pos] == ch)

def score(text: str) -> dict:
    anch = anchored_score(text)
    free = score_free_fast(text)
    ic_val = ic(text) if len(text) >= 20 else 0.0
    return {"a": anch, "f": free, "ic": ic_val}

def is_signal(sc: dict) -> bool:
    return sc["a"] >= 6 or sc["f"] >= 11


# ── Keywords ─────────────────────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
    "CLOCK", "EAST", "NORTH", "IQLUSION", "SANBORN",
    "SCHEIDT", "LANGLEY", "DESPARATLY", "UNDERGROUND",
    "BERLINCLOCK", "EASTNORTHEAST", "WELTZEITUHR",
    "EGYPT", "CARTER", "TUTANKHAMUN", "PHARAOH",
    "MEDUSA", "LUCIFER", "INVISIBLE", "MAGNETIC",
]

KRYPTOS_ORDER = keyword_column_order("KRYPTOS")  # [3,5,0,6,1,4,2] — wait, let me compute
# K=0,R=4,Y=5,P=2,T=3,O=1,S=2... actually:
# Alphabetical: K(0) O(1) P(2) R(3) S(4) T(5) Y(6) — nope
# KRYPTOS: K=pos0, R=pos1, Y=pos2, P=pos3, T=pos4, O=pos5, S=pos6
# Sorted: K(pos0)=rank0, O(pos5)=rank1, P(pos3)=rank2, R(pos1)=rank3, S(pos6)=rank4, T(pos4)=rank5, Y(pos2)=rank6
# So order = [0, 3, 6, 2, 5, 1, 4]
# Let's just compute it properly:
KRYPTOS_ORDER = keyword_column_order("KRYPTOS")


# ── Grid dimensions for K4 ──────────────────────────────────────────────

def get_grid_dims(n: int, min_dim: int = 2, max_dim: int = 50) -> List[Tuple[int, int]]:
    """Get all (rows, cols) where rows*cols >= n and both >= min_dim."""
    dims = []
    for r in range(min_dim, max_dim + 1):
        for c in range(min_dim, max_dim + 1):
            if r * c >= n and r * c <= n + 5:  # Allow small padding
                dims.append((r, c))
    return dims


# ── Phase 1: Pure double rotation (no substitution) ─────────────────────

def phase1():
    print("\nPhase 1: Pure double rotational transposition (K3-style)")
    print("-" * 60)

    texts = {"CT97": CT, "QCT98": "Q" + CT, "CTQ98": CT + "Q"}
    best_a, best_f = 0, 0
    configs = 0
    results = []

    for text_name, text in texts.items():
        n = len(text)
        dims = get_grid_dims(n, 3, 25)

        # Single rotation first (baseline)
        for rows, cols in dims:
            for rot_name in ROTATIONS:
                pt = single_rotation_transposition(text, rows, cols, rot_name, n)
                sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                configs += 1
                if sc["a"] > best_a or sc["f"] > best_f:
                    best_a = max(best_a, sc["a"])
                    best_f = max(best_f, sc["f"])
                    if sc["a"] >= 3 or sc["f"] > 0:
                        print(f"  {text_name} {rows}x{cols} {rot_name}: a={sc['a']}, f={sc['f']}")

        # Double rotation: use key grid dimensions
        key_dims_97 = [(7, 14), (14, 7), (10, 10), (11, 9), (9, 11)]
        key_dims_98 = [(7, 14), (14, 7), (2, 49), (49, 2)]
        key_dims = key_dims_98 if n == 98 else key_dims_97

        for r1, c1 in key_dims:
            if r1 * c1 < n:
                continue
            for rot1 in ROTATIONS:
                intermediate = single_rotation_transposition(text, r1, c1, rot1, n)
                for r2, c2 in key_dims:
                    if r2 * c2 < n:
                        continue
                    for rot2 in ROTATIONS:
                        pt = single_rotation_transposition(intermediate, r2, c2, rot2, n)
                        sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                        configs += 1
                        if sc["a"] > best_a or sc["f"] > best_f:
                            best_a = max(best_a, sc["a"])
                            best_f = max(best_f, sc["f"])
                            if sc["a"] >= 3 or sc["f"] > 0:
                                print(f"  {text_name} {r1}x{c1}→{rot1}→{r2}x{c2}→{rot2}: "
                                      f"a={sc['a']}, f={sc['f']}")

    # Also test with KRYPTOS column reordering
    print("  + KRYPTOS column reordering...")
    for text_name, text in texts.items():
        n = len(text)
        for rows, cols in [(14, 7), (7, 14)]:
            if cols != 7 and rows != 7:
                continue
            if rows * cols < n:
                continue
            padded = text + 'X' * (rows * cols - n)
            grid = write_grid(padded, rows, cols)
            if cols == 7:
                grid_reordered = reorder_columns(grid, KRYPTOS_ORDER)
            else:
                continue  # Can't apply 7-letter key to non-7-col grid
            for rot_name, rot_fn in ROTATIONS.items():
                rotated = rot_fn(grid_reordered)
                pt = read_grid(rotated, n)
                sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                configs += 1
                if sc["a"] > best_a or sc["f"] > best_f:
                    best_a = max(best_a, sc["a"])
                    best_f = max(best_f, sc["f"])
                    print(f"  {text_name} {rows}x{cols}+KRYPTOS→{rot_name}: a={sc['a']}, f={sc['f']}")

            # Also: rotate THEN reorder
            for rot_name, rot_fn in ROTATIONS.items():
                rotated = rot_fn(grid)
                # After rotation of rows×7 grid, we get 7×rows grid
                # Apply KRYPTOS to the 7 rows? That doesn't make sense...
                # Skip if dimensions don't match
                if len(rotated) == 7:
                    rotated_reordered = reorder_columns(rotated, KRYPTOS_ORDER[:len(rotated[0])])
                    pt = read_grid(rotated_reordered, n)
                    sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                    configs += 1

    print(f"  Phase 1: {configs:,} configs, best a={best_a}/24, f={best_f}/24")
    return best_a, best_f, configs


# ── Phase 2: Single rotation + KA-tableau substitution ───────────────────

def phase2():
    print("\nPhase 2: Single rotation + KA-tableau Vigenère")
    print("-" * 60)

    best_a, best_f = 0, 0
    configs = 0

    texts = {"CT97": CT, "QCT98": "Q" + CT, "CTQ98": CT + "Q"}
    key_dims_97 = [(7, 14), (14, 7), (10, 10), (11, 9), (9, 11), (8, 13), (13, 8)]
    key_dims_98 = [(7, 14), (14, 7), (2, 49), (49, 2)]

    for text_name, text in texts.items():
        n = len(text)
        dims = key_dims_98 if n == 98 else key_dims_97

        for rows, cols in dims:
            if rows * cols < n:
                continue
            for rot_name in ROTATIONS:
                # Decrypt: undo rotation first, then undo substitution
                # OR: undo substitution first, then undo rotation
                for order_name, decrypt_ops in [
                    ("rot_then_sub", "rot_first"),
                    ("sub_then_rot", "sub_first"),
                ]:
                    for kw in KEYWORDS:
                        for cipher_fn, cipher_name in [
                            (ka_decrypt, "ka_vig"),
                            (ka_beaufort_decrypt, "ka_beau"),
                            (az_decrypt, "az_vig"),
                            (az_beaufort_decrypt, "az_beau"),
                        ]:
                            if decrypt_ops == "rot_first":
                                # Undo rotation, then undo substitution
                                transposed = single_rotation_transposition(
                                    text, rows, cols, rot_name, n)
                                pt = cipher_fn(transposed, kw)
                            else:
                                # Undo substitution, then undo rotation
                                decrypted = cipher_fn(text, kw)
                                pt = single_rotation_transposition(
                                    decrypted, rows, cols, rot_name, n)

                            sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                            configs += 1

                            if sc["a"] > best_a or sc["f"] > best_f:
                                best_a = max(best_a, sc["a"])
                                best_f = max(best_f, sc["f"])
                                if sc["a"] >= 5 or sc["f"] > 0:
                                    print(f"  {text_name} {rows}x{cols} {rot_name} "
                                          f"{order_name} {cipher_name}({kw}): "
                                          f"a={sc['a']}, f={sc['f']}, ic={sc['ic']:.4f}")

                        if configs % 50000 == 0:
                            print(f"  ... {configs:,} tested, best a={best_a}, f={best_f}",
                                  flush=True)

    print(f"  Phase 2: {configs:,} configs, best a={best_a}/24, f={best_f}/24")
    return best_a, best_f, configs


# ── Phase 3: Double rotation + KA substitution ──────────────────────────

def phase3():
    print("\nPhase 3: Double rotation + KA-tableau Vigenère")
    print("-" * 60)

    best_a, best_f = 0, 0
    configs = 0

    # Focus on the most likely K3-parallel dimensions
    # K3: 42×8 then 24×14 (or 24×14 then 8×42)
    # K4 (98): 14×7 then 7×14 (or 7×14 then 14×7)
    texts = {"CT97": CT, "QCT98": "Q" + CT}
    dim_pairs_97 = [
        ((14, 7), (7, 14)), ((7, 14), (14, 7)),
        ((10, 10), (10, 10)), ((11, 9), (9, 11)),
    ]
    dim_pairs_98 = [
        ((14, 7), (7, 14)), ((7, 14), (14, 7)),
        ((14, 7), (14, 7)), ((7, 14), (7, 14)),
    ]

    # Use top keywords only
    top_keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
                    "WELTZEITUHR", "EASTNORTHEAST", "DESPARATLY"]

    for text_name, text in texts.items():
        n = len(text)
        dim_pairs = dim_pairs_98 if n == 98 else dim_pairs_97

        for (r1, c1), (r2, c2) in dim_pairs:
            if r1 * c1 < n or r2 * c2 < n:
                continue
            for rot1 in ROTATIONS:
                for rot2 in ROTATIONS:
                    # Pure double rotation (no sub)
                    transposed = double_rotation_transposition(
                        text, r1, c1, rot1, r2, c2, rot2, n)

                    for kw in top_keywords:
                        for cipher_fn, cn in [
                            (ka_decrypt, "ka_vig"),
                            (ka_beaufort_decrypt, "ka_beau"),
                        ]:
                            # Sub after double rotation
                            pt = cipher_fn(transposed, kw)
                            sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                            configs += 1
                            if sc["a"] > best_a or sc["f"] > best_f:
                                best_a = max(best_a, sc["a"])
                                best_f = max(best_f, sc["f"])
                                if sc["a"] >= 5 or sc["f"] > 0:
                                    print(f"  {text_name} {r1}x{c1}→{rot1}→{r2}x{c2}→{rot2} "
                                          f"+ {cn}({kw}): a={sc['a']}, f={sc['f']}")

                            # Sub before double rotation
                            decrypted = cipher_fn(text, kw)
                            pt2 = double_rotation_transposition(
                                decrypted, r1, c1, rot1, r2, c2, rot2, n)
                            sc2 = score(pt2[:CT_LEN] if n > CT_LEN else pt2)
                            configs += 1
                            if sc2["a"] > best_a or sc2["f"] > best_f:
                                best_a = max(best_a, sc2["a"])
                                best_f = max(best_f, sc2["f"])
                                if sc2["a"] >= 5 or sc2["f"] > 0:
                                    print(f"  {cn}({kw}) + {text_name} {r1}x{c1}→{rot1}→"
                                          f"{r2}x{c2}→{rot2}: a={sc2['a']}, f={sc2['f']}")

    print(f"  Phase 3: {configs:,} configs, best a={best_a}/24, f={best_f}/24")
    return best_a, best_f, configs


# ── Phase 4: Demonstrate KA vs AZ difference ─────────────────────────────

def phase4():
    print("\nPhase 4: KA vs AZ comparison (proving they're different)")
    print("-" * 60)

    # Show the difference for key keywords
    for kw in ["PALIMPSEST", "KRYPTOS", "ABSCISSA", "WELTZEITUHR"]:
        az_key = [ALPH_IDX[ch] for ch in kw]
        ka_key = [KA_IDX[ch] for ch in kw]
        pt_az = az_decrypt(CT, kw)
        pt_ka = ka_decrypt(CT, kw)
        diff = sum(1 for a, b in zip(pt_az, pt_ka) if a != b)
        sc_az = score(pt_az)
        sc_ka = score(pt_ka)
        print(f"  {kw}:")
        print(f"    AZ key: {az_key[:7]}...")
        print(f"    KA key: {ka_key[:7]}...")
        print(f"    AZ decrypt: {pt_az[:30]}... (a={sc_az['a']}, f={sc_az['f']})")
        print(f"    KA decrypt: {pt_ka[:30]}... (a={sc_ka['a']}, f={sc_ka['f']})")
        print(f"    Differ at {diff}/{CT_LEN} positions")

    return 0, 0, 0


# ── Phase 5: KRYPTOS keyed columnar + rotation + KA sub ─────────────────

def phase5():
    print("\nPhase 5: KRYPTOS keyed columnar + rotation + KA substitution")
    print("-" * 60)

    best_a, best_f = 0, 0
    configs = 0

    texts = {"CT97": CT, "QCT98": "Q" + CT}
    top_keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
                    "WELTZEITUHR", "EASTNORTHEAST", "DESPARATLY",
                    "SHADOW", "SANBORN", "SCHEIDT"]

    for text_name, text in texts.items():
        n = len(text)
        # Width 7 (KRYPTOS length) grids
        for rows, cols in [(14, 7), (7, 14)]:
            if rows * cols < n:
                continue
            padded = text + 'X' * (rows * cols - n)

            # Try all orderings: rotation, keyed reorder, substitution
            for kw_col_name, col_order in [("KRYPTOS", KRYPTOS_ORDER)]:
                if cols == 7:
                    grid = write_grid(padded, rows, cols)

                    # Path A: reorder columns → rotate → read → un-sub
                    for rot_name, rot_fn in ROTATIONS.items():
                        reordered = reorder_columns(grid, col_order)
                        rotated = rot_fn(reordered)
                        transposed = read_grid(rotated, n)

                        for kw in top_keywords:
                            for fn, cn in [(ka_decrypt, "ka_vig"),
                                           (ka_beaufort_decrypt, "ka_beau")]:
                                pt = fn(transposed, kw)
                                sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                                configs += 1
                                if sc["a"] > best_a or sc["f"] > best_f:
                                    best_a = max(best_a, sc["a"])
                                    best_f = max(best_f, sc["f"])
                                    if sc["a"] >= 5 or sc["f"] > 0:
                                        print(f"  A: {text_name} {rows}x{cols} "
                                              f"reorder→{rot_name}→{cn}({kw}): "
                                              f"a={sc['a']}, f={sc['f']}")

                    # Path B: rotate → reorder columns → read → un-sub
                    for rot_name, rot_fn in ROTATIONS.items():
                        rotated = rot_fn(grid)
                        # After rotating a rows×7 grid CW, we get 7×rows
                        # Apply KRYPTOS order to 7 rows... doesn't map well
                        # Instead: if result has 7 columns, reorder those
                        new_cols = len(rotated[0])
                        if new_cols == 7:
                            reordered = reorder_columns(rotated, col_order)
                            transposed = read_grid(reordered, n)

                            for kw in top_keywords:
                                for fn, cn in [(ka_decrypt, "ka_vig"),
                                               (ka_beaufort_decrypt, "ka_beau")]:
                                    pt = fn(transposed, kw)
                                    sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                                    configs += 1
                                    if sc["a"] > best_a or sc["f"] > best_f:
                                        best_a = max(best_a, sc["a"])
                                        best_f = max(best_f, sc["f"])
                                        if sc["a"] >= 5 or sc["f"] > 0:
                                            print(f"  B: {text_name} {rows}x{cols} "
                                                  f"{rot_name}→reorder→{cn}({kw}): "
                                                  f"a={sc['a']}, f={sc['f']}")

                    # Path C: un-sub → reorder → rotate
                    for kw in top_keywords:
                        for fn, cn in [(ka_decrypt, "ka_vig"),
                                       (ka_beaufort_decrypt, "ka_beau")]:
                            decrypted = fn(text, kw)
                            dec_padded = decrypted + 'X' * (rows * cols - n)
                            grid_d = write_grid(dec_padded, rows, cols)
                            reordered = reorder_columns(grid_d, col_order)
                            for rot_name, rot_fn in ROTATIONS.items():
                                rotated = rot_fn(reordered)
                                pt = read_grid(rotated, n)
                                sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                                configs += 1
                                if sc["a"] > best_a or sc["f"] > best_f:
                                    best_a = max(best_a, sc["a"])
                                    best_f = max(best_f, sc["f"])
                                    if sc["a"] >= 5 or sc["f"] > 0:
                                        print(f"  C: {cn}({kw})→{text_name} {rows}x{cols} "
                                              f"reorder→{rot_name}: a={sc['a']}, f={sc['f']}")

                    # Path D: un-sub → rotate → reorder
                    for kw in top_keywords:
                        for fn, cn in [(ka_decrypt, "ka_vig"),
                                       (ka_beaufort_decrypt, "ka_beau")]:
                            decrypted = fn(text, kw)
                            dec_padded = decrypted + 'X' * (rows * cols - n)
                            grid_d = write_grid(dec_padded, rows, cols)
                            for rot_name, rot_fn in ROTATIONS.items():
                                rotated = rot_fn(grid_d)
                                new_cols = len(rotated[0])
                                if new_cols == 7:
                                    reordered = reorder_columns(rotated, col_order)
                                    pt = read_grid(reordered, n)
                                    sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                                    configs += 1
                                    if sc["a"] > best_a or sc["f"] > best_f:
                                        best_a = max(best_a, sc["a"])
                                        best_f = max(best_f, sc["f"])
                                        if sc["a"] >= 5 or sc["f"] > 0:
                                            print(f"  D: {cn}({kw})→{text_name} {rows}x{cols} "
                                                  f"{rot_name}→reorder: a={sc['a']}, f={sc['f']}")

    # Also test with reversed CT (K3's method involves reversal)
    print("  + Reversed CT variants...")
    for text_name_base, text_base in [("CT97", CT), ("QCT98", "Q" + CT)]:
        text = text_base[::-1]
        text_name = text_name_base + "_rev"
        n = len(text)
        for rows, cols in [(14, 7)]:
            if rows * cols < n:
                continue
            padded = text + 'X' * (rows * cols - n)
            grid = write_grid(padded, rows, cols)
            reordered = reorder_columns(grid, KRYPTOS_ORDER)
            for rot_name, rot_fn in ROTATIONS.items():
                rotated = rot_fn(reordered)
                transposed = read_grid(rotated, n)
                for kw in top_keywords:
                    for fn, cn in [(ka_decrypt, "ka_vig"),
                                   (ka_beaufort_decrypt, "ka_beau")]:
                        pt = fn(transposed, kw)
                        sc = score(pt[:CT_LEN] if n > CT_LEN else pt)
                        configs += 1
                        if sc["a"] > best_a or sc["f"] > best_f:
                            best_a = max(best_a, sc["a"])
                            best_f = max(best_f, sc["f"])
                            if sc["a"] >= 5 or sc["f"] > 0:
                                print(f"  {text_name} {rows}x{cols} "
                                      f"reorder→{rot_name}→{cn}({kw}): "
                                      f"a={sc['a']}, f={sc['f']}")

    print(f"  Phase 5: {configs:,} configs, best a={best_a}/24, f={best_f}/24")
    return best_a, best_f, configs


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("E-AUDIT-06: K3's ACTUAL Method Applied to K4")
    print("=" * 72)
    print()
    print("CORRECTION: K3 is PURE transposition (double rotational), not Vig+columnar.")
    print("K1/K2 use KA tableau, not standard A-Z.")
    print("Testing: K3-style rotation + KA-tableau Vigenère (untested combination).")
    print(f"KRYPTOS column order: {KRYPTOS_ORDER}")

    t0 = time.time()

    a1, f1, n1 = phase1()
    a2, f2, n2 = phase2()
    a3, f3, n3 = phase3()
    phase4()  # Demonstration only
    a5, f5, n5 = phase5()

    elapsed = time.time() - t0
    total = n1 + n2 + n3 + n5
    best_a = max(a1, a2, a3, a5)
    best_f = max(f1, f2, f3, f5)

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configs: {total:,}")
    print(f"Time: {elapsed:.1f}s")
    print(f"Best anchored: {best_a}/24")
    print(f"Best free: {best_f}/24")
    print()
    print(f"Phase 1 (pure double rotation):     a={a1}, f={f1} ({n1:,} configs)")
    print(f"Phase 2 (single rot + KA/AZ sub):   a={a2}, f={f2} ({n2:,} configs)")
    print(f"Phase 3 (double rot + KA sub):       a={a3}, f={f3} ({n3:,} configs)")
    print(f"Phase 5 (KRYPTOS reorder+rot+KA):   a={a5}, f={f5} ({n5:,} configs)")
    print()

    if best_f >= 24 or best_a >= 24:
        print("*** BREAKTHROUGH ***")
    elif best_f >= 13 or best_a >= 13:
        print("*** SIGNAL: One full crib. Investigate. ***")
    elif best_a >= 8:
        print("INTERESTING: Above noise threshold. Worth expanded search.")
    else:
        print("NOISE: K3-style double rotation + KA/AZ substitution does not yield cribs.")

    os.makedirs("results/audit", exist_ok=True)
    output = {
        "experiment": "E-AUDIT-06",
        "description": "K3 actual method (double rotation) + KA-tableau substitution",
        "correction": "K3 is pure transposition, not Vig+columnar as previously modeled",
        "total_configs": total,
        "elapsed": elapsed,
        "best_anchored": best_a,
        "best_free": best_f,
    }
    outpath = "results/audit/e_audit_06_k3_method_k4.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {outpath}")


if __name__ == "__main__":
    main()
