#!/usr/bin/env python3
"""Antipodes-as-Device Engine — unified manifest-driven hypothesis tester.

Tests 5 hypothesis families for extracting decryption keys from the physical
(row, col) positions of K4 ciphertext characters in the Antipodes grid.

Usage:
    PYTHONPATH=src python3 -u bin/antipodes_device_engine.py --manifest PATH [--shard N] [--resume]
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from itertools import product
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import verify_bean, verify_bean_simple, BeanResult
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, DECRYPT_FN,
)

# ── Antipodes Grid (47 rows, letters only) ──────────────────────────────────

ANTIPODES_ROWS: List[str] = [
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACH",                     # Row 0, K3
    "TNREYULDSLLSLLNOHSNOSMRWXMNETPRNG",                      # Row 1, K3
    "ATIHNRARPESLNNELEBLPIIACAEWMTWNDITE",                     # Row 2, K3
    "ENRAHCTENEUDRETNHAEOETFOLSEDTIWENH",                      # Row 3, K3
    "AEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWE",                      # Row 4, K3
    "NATAMATEGYEERLBTEEFOASFIOTUETUAEOT",                      # Row 5, K3
    "OARMAEERTNRTIBSEDDNIAAHTTMSTEWPIER",                      # Row 6, K3
    "OAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDD",                     # Row 7, K3
    "RYDLORITRKLMLEHAGTDHARDPNEOHMGFMF",                       # Row 8, K3
    "EUHEECDMRIPFEIMEHNLSSTTRTVDOHWOBK",                        # Row 9, K3->K4
    "RUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTW",                       # Row 10, K4
    "TQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZF",                     # Row 11, K4
    "PKWGDKZXTJCDIGKUHUAUEKCAREMUFPHZL",                        # Row 12, K4->K1 (SPACE)
    "RFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQV",                      # Row 13, K1->K2
    "YUVLLTREVJYQTMKYRDMFDVFPJUDEEHZWE",                       # Row 14, K1->K2
    "TZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQ",                        # Row 15, K2
    "ZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDA",                       # Row 16, K2
    "GDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJL",                      # Row 17, K2
    "BQCETBJDFHRRYIZETKZEMVDUFKSJHKFWHK",                       # Row 18, K2
    "UWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYC",                         # Row 19, K2
    "UQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLA",                        # Row 20, K2
    "VIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF",                        # Row 21, K2
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZ",                         # Row 22, K2
    "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFM",                         # Row 23, K2
    "PNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBE",                          # Row 24, K2
    "DMHDAFMJGZNUPLGEWJLLAETGENDYAHROH",                           # Row 25, K2->K3
    "NLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSL",                         # Row 26, K3
    "LSLLNOHSNOSMRWXMNETPRNGATIHNRARPE",                           # Row 27, K3
    "SLNNELEBLPIIACAEWMTWNDITEENRAHCTEN",                           # Row 28, K3
    "EUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQ",                           # Row 29, K3
    "HEENCTAYCREIFTBRSPAMHHEWENATAMATEG",                            # Row 30, K3
    "YEERLBTEEFOASFIOTUETUAEOTOARMAEERT",                             # Row 31, K3
    "NRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",                            # Row 32, K3
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKL",                            # Row 33, K3 (36 chars)
    "MLEHAGTDHARDPNEOHMGFMFEUHEECDMRIP",                                # Row 34, K3
    "FEIMEHNLSSTTRTVDOHWOBKRUOXOGHULBS",                                  # Row 35, K3->K4
    "OLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZ",                                  # Row 36, K4
    "WATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJ",                                  # Row 37, K4
    "CDIGKUHUAUEKCAREMUFPHZLRFAXYUSDJKZ",                                   # Row 38, K4->K1 (NO space)
    "LDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJY",                                    # Row 39, K1->K2
    "QTMKYRDMFDVFPJUDEEHZWETZYVGWHKKQ",                                       # Row 40, K2
    "ETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPF",                                        # Row 41, K2
    "XHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNG",                                        # Row 42, K2
    "EUNAQZGZLECGYUXUEENJTBJLBQCETBJDFH",                                        # Row 43, K2
    "RRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIH",                                         # Row 44, K2
    "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLD",                                           # Row 45, K2
    "KFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ",                                          # Row 46, K2
]

# ── KA Tableau ──────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KA)}

TABLEAU: List[str] = []
for _shift in range(26):
    TABLEAU.append(KA[_shift:] + KA[:_shift])

# ── Locate K4 in the Antipodes grid ────────────────────────────────────────

@dataclass
class K4Position:
    """(row, col) for a single K4 character in the Antipodes grid."""
    ct_idx: int      # 0..96 position in K4 ciphertext
    row: int         # 0-indexed row in ANTIPODES_ROWS
    col: int         # 0-indexed column within that row
    char: str        # the character (should match CT[ct_idx])


def locate_k4_in_grid() -> Tuple[List[K4Position], List[K4Position]]:
    """Find exact (row, col) for each K4 character in both passes.

    Returns (pass1_positions, pass2_positions), each a list of 97 K4Position.
    """
    # Flatten the grid into a single string with row/col tracking
    flat: List[Tuple[int, int, str]] = []  # (row, col, char)
    for r, row_text in enumerate(ANTIPODES_ROWS):
        for c, ch in enumerate(row_text):
            flat.append((r, c, ch))

    # Build the full flat text for searching
    flat_text = "".join(ch for _, _, ch in flat)

    # Find both occurrences of K4 CT in the flat text
    positions_list: List[List[K4Position]] = []
    search_start = 0
    for pass_num in range(2):
        idx = flat_text.find(CT, search_start)
        if idx == -1:
            raise ValueError(f"K4 CT not found in Antipodes grid (pass {pass_num + 1}, "
                             f"search_start={search_start})")
        positions = []
        for i in range(CT_LEN):
            r, c, ch = flat[idx + i]
            assert ch == CT[i], (
                f"Mismatch at K4[{i}]: grid has '{ch}' at ({r},{c}), "
                f"expected '{CT[i]}'"
            )
            positions.append(K4Position(ct_idx=i, row=r, col=c, char=ch))
        positions_list.append(positions)
        search_start = idx + 1  # continue searching after this occurrence

    return positions_list[0], positions_list[1]


# Compute at module load time
PASS1, PASS2 = locate_k4_in_grid()

# ── Cipher variant helpers ──────────────────────────────────────────────────

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]


def decrypt_with_key(key_values: List[int], variant: CipherVariant) -> str:
    """Decrypt CT using numeric key values and specified variant."""
    fn = DECRYPT_FN[variant]
    return "".join(
        chr(fn(ord(CT[i]) - 65, key_values[i]) + 65)
        for i in range(CT_LEN)
    )


def fast_crib_check(pt: str) -> int:
    """Fast crib match count without full scoring overhead."""
    count = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == ch:
            count += 1
    return count


# ── Hypothesis implementations ──────────────────────────────────────────────

def run_h1_coordinate_lookup(
    params: Dict[str, Any],
    positions: List[K4Position],
    pass_label: str,
    stats: Dict[str, Any],
    results_file: str,
) -> None:
    """H1: Map (row, col) through a function to get tableau coordinates for key."""
    formulas = params.get("formulas", [
        "row_col", "col_row", "row_plus_col", "row_minus_col",
        "col_minus_row", "row_times_col", "row_xor_col",
        "row_mod_col", "col_mod_row",
    ])
    tableau_modes = params.get("tableau_modes", ["ka", "az"])

    for formula_name in formulas:
        for tab_mode in tableau_modes:
            alpha = KA if tab_mode == "ka" else ALPH
            alpha_idx = KA_IDX if tab_mode == "ka" else ALPH_IDX

            # Compute key from formula
            key_values: List[int] = []
            valid = True
            for pos in positions:
                r, c = pos.row, pos.col
                try:
                    if formula_name == "row_col":
                        tr, tc = r % 26, c % 26
                    elif formula_name == "col_row":
                        tr, tc = c % 26, r % 26
                    elif formula_name == "row_plus_col":
                        tr, tc = (r + c) % 26, 0
                    elif formula_name == "row_minus_col":
                        tr, tc = (r - c) % 26, 0
                    elif formula_name == "col_minus_row":
                        tr, tc = (c - r) % 26, 0
                    elif formula_name == "row_times_col":
                        tr, tc = (r * c) % 26, 0
                    elif formula_name == "row_xor_col":
                        tr, tc = (r ^ c) % 26, 0
                    elif formula_name == "row_mod_col":
                        tr, tc = (r % max(c, 1)) % 26, 0
                    elif formula_name == "col_mod_row":
                        tr, tc = (c % max(r, 1)) % 26, 0
                    else:
                        valid = False
                        break

                    # Look up in tableau or use direct value
                    if formula_name in ("row_col", "col_row"):
                        key_letter = TABLEAU[tr][tc]
                        key_values.append(KA_IDX[key_letter] if tab_mode == "ka"
                                          else ALPH_IDX[key_letter])
                    else:
                        key_values.append(tr)
                except Exception:
                    valid = False
                    break

            if not valid or len(key_values) != CT_LEN:
                stats["configs_tested"] += 1
                continue

            for variant in VARIANTS:
                stats["configs_tested"] += 1
                pt = decrypt_with_key(key_values, variant)
                crib_score = fast_crib_check(pt)

                if crib_score > stats["best_score"]:
                    stats["best_score"] = crib_score
                    stats["best_config"] = {
                        "hypothesis": "H1", "formula": formula_name,
                        "tableau": tab_mode, "variant": variant.value,
                        "pass": pass_label, "crib_score": crib_score,
                    }

                if crib_score >= STORE_THRESHOLD:
                    full_score = score_candidate(pt)
                    bean_result = verify_bean(key_values)
                    hit = {
                        "hypothesis": "H1", "formula": formula_name,
                        "tableau": tab_mode, "variant": variant.value,
                        "pass": pass_label,
                        "plaintext": pt,
                        "crib_score": crib_score,
                        "score": full_score.to_dict(),
                        "bean": bean_result.summary,
                        "timestamp": time.time(),
                    }
                    _append_hit(results_file, hit)
                    stats["hits"] += 1
                    if crib_score >= SIGNAL_THRESHOLD:
                        print(f"  *** SIGNAL: H1 {formula_name} {tab_mode} "
                              f"{variant.value} {pass_label} -> {full_score.summary}")

    # Also test with scaling factors on row/col
    factors = params.get("factors", [1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 25])
    for fr in factors:
        for fc in factors:
            if fr == 1 and fc == 1:
                continue  # Already covered by row_col above
            key_values = [((pos.row * fr + pos.col * fc) % MOD) for pos in positions]
            for variant in VARIANTS:
                stats["configs_tested"] += 1
                pt = decrypt_with_key(key_values, variant)
                crib_score = fast_crib_check(pt)

                if crib_score > stats["best_score"]:
                    stats["best_score"] = crib_score
                    stats["best_config"] = {
                        "hypothesis": "H1", "formula": f"fr={fr}_fc={fc}",
                        "variant": variant.value, "pass": pass_label,
                        "crib_score": crib_score,
                    }

                if crib_score >= STORE_THRESHOLD:
                    full_score = score_candidate(pt)
                    bean_result = verify_bean(key_values)
                    hit = {
                        "hypothesis": "H1", "formula": f"fr={fr}_fc={fc}",
                        "variant": variant.value, "pass": pass_label,
                        "plaintext": pt,
                        "crib_score": crib_score,
                        "score": full_score.to_dict(),
                        "bean": bean_result.summary,
                        "timestamp": time.time(),
                    }
                    _append_hit(results_file, hit)
                    stats["hits"] += 1


def run_h2_adjacent_key(
    params: Dict[str, Any],
    positions: List[K4Position],
    pass_label: str,
    stats: Dict[str, Any],
    results_file: str,
) -> None:
    """H2: Use adjacent characters in the Antipodes grid as key letters."""
    neighbor_modes = params.get("neighbor_modes", [
        "left", "right", "above", "below",
        "diag_ul", "diag_ur", "diag_ll", "diag_lr",
        "left2", "right2", "above2", "below2",
    ])

    # Build a 2D lookup for the grid
    max_cols = max(len(row) for row in ANTIPODES_ROWS)
    n_rows = len(ANTIPODES_ROWS)

    def get_char(r: int, c: int) -> Optional[str]:
        if 0 <= r < n_rows and 0 <= c < len(ANTIPODES_ROWS[r]):
            return ANTIPODES_ROWS[r][c]
        return None

    for mode in neighbor_modes:
        for use_ka in [True, False]:
            tab_label = "ka" if use_ka else "az"
            idx_map = KA_IDX if use_ka else ALPH_IDX

            key_values: List[int] = []
            valid = True
            for pos in positions:
                r, c = pos.row, pos.col
                neighbor_char: Optional[str] = None

                if mode == "left":
                    neighbor_char = get_char(r, c - 1)
                elif mode == "right":
                    neighbor_char = get_char(r, c + 1)
                elif mode == "above":
                    neighbor_char = get_char(r - 1, c)
                elif mode == "below":
                    neighbor_char = get_char(r + 1, c)
                elif mode == "diag_ul":
                    neighbor_char = get_char(r - 1, c - 1)
                elif mode == "diag_ur":
                    neighbor_char = get_char(r - 1, c + 1)
                elif mode == "diag_ll":
                    neighbor_char = get_char(r + 1, c - 1)
                elif mode == "diag_lr":
                    neighbor_char = get_char(r + 1, c + 1)
                elif mode == "left2":
                    neighbor_char = get_char(r, c - 2)
                elif mode == "right2":
                    neighbor_char = get_char(r, c + 2)
                elif mode == "above2":
                    neighbor_char = get_char(r - 2, c)
                elif mode == "below2":
                    neighbor_char = get_char(r + 2, c)

                if neighbor_char is None:
                    valid = False
                    break
                key_values.append(idx_map.get(neighbor_char, 0))

            if not valid or len(key_values) != CT_LEN:
                stats["configs_tested"] += 1
                continue

            for variant in VARIANTS:
                stats["configs_tested"] += 1
                pt = decrypt_with_key(key_values, variant)
                crib_score = fast_crib_check(pt)

                if crib_score > stats["best_score"]:
                    stats["best_score"] = crib_score
                    stats["best_config"] = {
                        "hypothesis": "H2", "mode": mode, "alphabet": tab_label,
                        "variant": variant.value, "pass": pass_label,
                        "crib_score": crib_score,
                    }

                if crib_score >= STORE_THRESHOLD:
                    full_score = score_candidate(pt)
                    bean_result = verify_bean(key_values)
                    hit = {
                        "hypothesis": "H2", "mode": mode, "alphabet": tab_label,
                        "variant": variant.value, "pass": pass_label,
                        "plaintext": pt,
                        "crib_score": crib_score,
                        "score": full_score.to_dict(),
                        "bean": bean_result.summary,
                        "timestamp": time.time(),
                    }
                    _append_hit(results_file, hit)
                    stats["hits"] += 1
                    if crib_score >= SIGNAL_THRESHOLD:
                        print(f"  *** SIGNAL: H2 {mode} {tab_label} "
                              f"{variant.value} {pass_label} -> {full_score.summary}")

    # Multi-neighbor: average or XOR of multiple neighbors
    multi_modes = params.get("multi_neighbor_modes", [
        ("left", "right"), ("above", "below"),
        ("left", "above"), ("right", "below"),
    ])

    offset_map = {
        "left": (0, -1), "right": (0, 1), "above": (-1, 0), "below": (1, 0),
        "diag_ul": (-1, -1), "diag_ur": (-1, 1), "diag_ll": (1, -1), "diag_lr": (1, 1),
    }

    for combo in multi_modes:
        for use_ka in [True, False]:
            tab_label = "ka" if use_ka else "az"
            idx_map = KA_IDX if use_ka else ALPH_IDX

            for op in ["add", "xor"]:
                key_values = []
                valid = True
                for pos in positions:
                    r, c = pos.row, pos.col
                    vals: List[int] = []
                    for m in combo:
                        dr, dc = offset_map.get(m, (0, 0))
                        ch = get_char(r + dr, c + dc)
                        if ch is None:
                            valid = False
                            break
                        vals.append(idx_map.get(ch, 0))
                    if not valid:
                        break
                    if op == "add":
                        key_values.append(sum(vals) % MOD)
                    else:
                        result = vals[0]
                        for v in vals[1:]:
                            result ^= v
                        key_values.append(result % MOD)

                if not valid or len(key_values) != CT_LEN:
                    stats["configs_tested"] += 1
                    continue

                combo_name = "+".join(combo)
                for variant in VARIANTS:
                    stats["configs_tested"] += 1
                    pt = decrypt_with_key(key_values, variant)
                    crib_score = fast_crib_check(pt)

                    if crib_score > stats["best_score"]:
                        stats["best_score"] = crib_score
                        stats["best_config"] = {
                            "hypothesis": "H2", "mode": f"multi_{combo_name}_{op}",
                            "alphabet": tab_label,
                            "variant": variant.value, "pass": pass_label,
                            "crib_score": crib_score,
                        }

                    if crib_score >= STORE_THRESHOLD:
                        full_score = score_candidate(pt)
                        hit = {
                            "hypothesis": "H2",
                            "mode": f"multi_{combo_name}_{op}",
                            "alphabet": tab_label,
                            "variant": variant.value, "pass": pass_label,
                            "plaintext": pt, "crib_score": crib_score,
                            "score": full_score.to_dict(),
                            "timestamp": time.time(),
                        }
                        _append_hit(results_file, hit)
                        stats["hits"] += 1


def run_h3_strip_transposition(
    params: Dict[str, Any],
    positions: List[K4Position],
    pass_label: str,
    stats: Dict[str, Any],
    results_file: str,
) -> None:
    """H3: Arrange K4's grid positions into virtual strips, read in various orders."""
    widths = params.get("widths", list(range(5, 21)))
    read_orders = params.get("read_orders", [
        "row_ltr", "row_rtl", "col_down", "col_up",
        "boustrophedon", "spiral_cw", "spiral_ccw",
        "diagonal_main", "diagonal_anti",
    ])

    # For each K4 position, we have (row, col) in the Antipodes.
    # We build a virtual grid of width W from the K4 positions, then read
    # in various orders to produce a permutation of 0..96.

    for width in widths:
        n_vrows = (CT_LEN + width - 1) // width

        for read_order in read_orders:
            stats["configs_tested"] += 1

            # Build the virtual grid: position i goes to vrow = i // width, vcol = i % width
            # Then read in the specified order to get a permutation
            perm: List[int] = []

            if read_order == "row_ltr":
                perm = list(range(CT_LEN))  # Identity, skip this
                continue
            elif read_order == "row_rtl":
                for vr in range(n_vrows):
                    start = vr * width
                    end = min(start + width, CT_LEN)
                    perm.extend(range(end - 1, start - 1, -1))
            elif read_order == "col_down":
                for vc in range(width):
                    for vr in range(n_vrows):
                        idx = vr * width + vc
                        if idx < CT_LEN:
                            perm.append(idx)
            elif read_order == "col_up":
                for vc in range(width):
                    for vr in range(n_vrows - 1, -1, -1):
                        idx = vr * width + vc
                        if idx < CT_LEN:
                            perm.append(idx)
            elif read_order == "boustrophedon":
                for vr in range(n_vrows):
                    start = vr * width
                    end = min(start + width, CT_LEN)
                    if vr % 2 == 0:
                        perm.extend(range(start, end))
                    else:
                        perm.extend(range(end - 1, start - 1, -1))
            elif read_order == "spiral_cw":
                perm = _spiral_order(n_vrows, width, CT_LEN, clockwise=True)
            elif read_order == "spiral_ccw":
                perm = _spiral_order(n_vrows, width, CT_LEN, clockwise=False)
            elif read_order == "diagonal_main":
                perm = _diagonal_order(n_vrows, width, CT_LEN, anti=False)
            elif read_order == "diagonal_anti":
                perm = _diagonal_order(n_vrows, width, CT_LEN, anti=True)
            else:
                continue

            if len(perm) != CT_LEN:
                continue

            # Apply permutation: output[i] = CT[perm[i]]  (gather)
            permuted_ct = "".join(CT[perm[i]] for i in range(CT_LEN))

            # Try identity key (pure transposition) and shifted keys
            crib_score = fast_crib_check(permuted_ct)
            if crib_score > stats["best_score"]:
                stats["best_score"] = crib_score
                stats["best_config"] = {
                    "hypothesis": "H3", "width": width,
                    "read_order": read_order, "pass": pass_label,
                    "key": "identity", "crib_score": crib_score,
                }
            if crib_score >= STORE_THRESHOLD:
                full_score = score_candidate(permuted_ct)
                hit = {
                    "hypothesis": "H3", "width": width,
                    "read_order": read_order, "pass": pass_label,
                    "key": "identity", "plaintext": permuted_ct,
                    "crib_score": crib_score,
                    "score": full_score.to_dict(),
                    "timestamp": time.time(),
                }
                _append_hit(results_file, hit)
                stats["hits"] += 1

            # Also apply inverse permutation: output[perm[i]] = CT[i]
            inv_ct_chars = [""] * CT_LEN
            for i in range(CT_LEN):
                inv_ct_chars[perm[i]] = CT[i]
            inv_permuted_ct = "".join(inv_ct_chars)

            crib_score_inv = fast_crib_check(inv_permuted_ct)
            stats["configs_tested"] += 1
            if crib_score_inv > stats["best_score"]:
                stats["best_score"] = crib_score_inv
                stats["best_config"] = {
                    "hypothesis": "H3", "width": width,
                    "read_order": f"inv_{read_order}", "pass": pass_label,
                    "key": "identity", "crib_score": crib_score_inv,
                }
            if crib_score_inv >= STORE_THRESHOLD:
                full_score = score_candidate(inv_permuted_ct)
                hit = {
                    "hypothesis": "H3", "width": width,
                    "read_order": f"inv_{read_order}", "pass": pass_label,
                    "key": "identity", "plaintext": inv_permuted_ct,
                    "crib_score": crib_score_inv,
                    "score": full_score.to_dict(),
                    "timestamp": time.time(),
                }
                _append_hit(results_file, hit)
                stats["hits"] += 1

            # Try transposition + each cipher variant with position-derived key
            for variant in VARIANTS:
                for key_source in ["row", "col", "row_plus_col"]:
                    stats["configs_tested"] += 1
                    if key_source == "row":
                        key_vals = [positions[perm[i]].row % MOD for i in range(CT_LEN)]
                    elif key_source == "col":
                        key_vals = [positions[perm[i]].col % MOD for i in range(CT_LEN)]
                    else:
                        key_vals = [(positions[perm[i]].row + positions[perm[i]].col) % MOD
                                    for i in range(CT_LEN)]

                    pt = decrypt_with_key(key_vals, variant)
                    # But the PT is in permuted order, we need to un-permute
                    # Actually, transposition acts on the ciphertext BEFORE substitution
                    # So: permute CT, then apply substitution key
                    pt_direct = decrypt_text(permuted_ct, key_vals, variant)
                    crib_score = fast_crib_check(pt_direct)

                    if crib_score > stats["best_score"]:
                        stats["best_score"] = crib_score
                        stats["best_config"] = {
                            "hypothesis": "H3", "width": width,
                            "read_order": read_order, "key_source": key_source,
                            "variant": variant.value, "pass": pass_label,
                            "crib_score": crib_score,
                        }

                    if crib_score >= STORE_THRESHOLD:
                        full_score = score_candidate(pt_direct)
                        hit = {
                            "hypothesis": "H3", "width": width,
                            "read_order": read_order, "key_source": key_source,
                            "variant": variant.value, "pass": pass_label,
                            "plaintext": pt_direct, "crib_score": crib_score,
                            "score": full_score.to_dict(),
                            "timestamp": time.time(),
                        }
                        _append_hit(results_file, hit)
                        stats["hits"] += 1
                        if crib_score >= SIGNAL_THRESHOLD:
                            print(f"  *** SIGNAL: H3 w={width} {read_order} "
                                  f"{key_source} {variant.value} -> {full_score.summary}")


def _spiral_order(n_rows: int, n_cols: int, total: int, clockwise: bool = True) -> List[int]:
    """Generate spiral traversal indices for a virtual grid."""
    indices: List[int] = []
    top, bottom, left, right = 0, n_rows - 1, 0, n_cols - 1

    while top <= bottom and left <= right:
        if clockwise:
            for c in range(left, right + 1):
                idx = top * n_cols + c
                if idx < total:
                    indices.append(idx)
            top += 1
            for r in range(top, bottom + 1):
                idx = r * n_cols + right
                if idx < total:
                    indices.append(idx)
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    idx = bottom * n_cols + c
                    if idx < total:
                        indices.append(idx)
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    idx = r * n_cols + left
                    if idx < total:
                        indices.append(idx)
                left += 1
        else:
            for r in range(top, bottom + 1):
                idx = r * n_cols + left
                if idx < total:
                    indices.append(idx)
            left += 1
            for c in range(left, right + 1):
                idx = bottom * n_cols + c
                if idx < total:
                    indices.append(idx)
            bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    idx = r * n_cols + right
                    if idx < total:
                        indices.append(idx)
                right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    idx = top * n_cols + c
                    if idx < total:
                        indices.append(idx)
                top += 1

    # Deduplicate while preserving order
    seen = set()
    result = []
    for idx in indices:
        if idx not in seen and idx < total:
            seen.add(idx)
            result.append(idx)
    return result


def _diagonal_order(n_rows: int, n_cols: int, total: int, anti: bool = False) -> List[int]:
    """Generate diagonal traversal indices for a virtual grid."""
    indices: List[int] = []
    for d in range(n_rows + n_cols - 1):
        if anti:
            # Anti-diagonal: r+c = d
            for r in range(max(0, d - n_cols + 1), min(n_rows, d + 1)):
                c = d - r
                idx = r * n_cols + c
                if idx < total:
                    indices.append(idx)
        else:
            # Main diagonal direction
            for r in range(max(0, d - n_cols + 1), min(n_rows, d + 1)):
                c = d - r
                idx = r * n_cols + (n_cols - 1 - c)
                if idx < total:
                    indices.append(idx)
    seen = set()
    result = []
    for idx in indices:
        if idx not in seen and idx < total:
            seen.add(idx)
            result.append(idx)
    return result


def run_h4_offset_key(
    params: Dict[str, Any],
    positions: List[K4Position],
    pass_label: str,
    stats: Dict[str, Any],
    results_file: str,
) -> None:
    """H4: Compute key[i] = f(row_i, col_i) mod 26 for various formulas."""
    formulas = params.get("formulas", [
        "row", "col", "row_plus_col", "row_minus_col", "col_minus_row",
        "row_times_col", "row_xor_col", "row_sq_plus_col", "col_sq_plus_row",
        "row_plus_2col", "2row_plus_col", "row_plus_col_sq",
        "abs_row_minus_col", "max_row_col", "min_row_col",
        "row_plus_col_plus_i", "row_times_i", "col_times_i",
    ])
    offsets = params.get("offsets", list(range(26)))

    for formula_name in formulas:
        for offset in offsets:
            key_values: List[int] = []
            for i, pos in enumerate(positions):
                r, c = pos.row, pos.col
                if formula_name == "row":
                    val = r
                elif formula_name == "col":
                    val = c
                elif formula_name == "row_plus_col":
                    val = r + c
                elif formula_name == "row_minus_col":
                    val = r - c
                elif formula_name == "col_minus_row":
                    val = c - r
                elif formula_name == "row_times_col":
                    val = r * c
                elif formula_name == "row_xor_col":
                    val = r ^ c
                elif formula_name == "row_sq_plus_col":
                    val = r * r + c
                elif formula_name == "col_sq_plus_row":
                    val = c * c + r
                elif formula_name == "row_plus_2col":
                    val = r + 2 * c
                elif formula_name == "2row_plus_col":
                    val = 2 * r + c
                elif formula_name == "row_plus_col_sq":
                    val = r + c * c
                elif formula_name == "abs_row_minus_col":
                    val = abs(r - c)
                elif formula_name == "max_row_col":
                    val = max(r, c)
                elif formula_name == "min_row_col":
                    val = min(r, c)
                elif formula_name == "row_plus_col_plus_i":
                    val = r + c + i
                elif formula_name == "row_times_i":
                    val = r * (i + 1)
                elif formula_name == "col_times_i":
                    val = c * (i + 1)
                else:
                    val = 0
                key_values.append((val + offset) % MOD)

            for variant in VARIANTS:
                stats["configs_tested"] += 1
                pt = decrypt_with_key(key_values, variant)
                crib_score = fast_crib_check(pt)

                if crib_score > stats["best_score"]:
                    stats["best_score"] = crib_score
                    stats["best_config"] = {
                        "hypothesis": "H4", "formula": formula_name,
                        "offset": offset, "variant": variant.value,
                        "pass": pass_label, "crib_score": crib_score,
                    }

                if crib_score >= STORE_THRESHOLD:
                    full_score = score_candidate(pt)
                    bean_result = verify_bean(key_values)
                    hit = {
                        "hypothesis": "H4", "formula": formula_name,
                        "offset": offset, "variant": variant.value,
                        "pass": pass_label, "plaintext": pt,
                        "crib_score": crib_score,
                        "score": full_score.to_dict(),
                        "bean": bean_result.summary,
                        "timestamp": time.time(),
                    }
                    _append_hit(results_file, hit)
                    stats["hits"] += 1
                    if crib_score >= SIGNAL_THRESHOLD:
                        print(f"  *** SIGNAL: H4 {formula_name} off={offset} "
                              f"{variant.value} -> {full_score.summary}")


def run_h5_space_anchored(
    params: Dict[str, Any],
    positions: List[K4Position],
    pass_label: str,
    stats: Dict[str, Any],
    results_file: str,
) -> None:
    """H5: Starting from the SPACE position (row 12, between K4 and K1),
    traverse the grid in various patterns. The ORDER in which K4 characters
    are encountered defines a permutation."""

    # Space is between pos 12 col ~25 (after 'R' of EKCAR) and 'E' of EMUFPHZL
    # In row 12: PKWGDKZXTJCDIGKUHUAUEKCAR EMUFPHZL
    # Space is after the K4 content at col ~25 (0-indexed) in row 12
    # The last K4 char in row 12 is 'R' (EKCAR -> R is at some col)
    # Let's find it precisely from PASS1 data
    space_row = 12
    # The space is right after the last K4 char in pass 1
    last_k4_in_row12 = None
    for pos in PASS1:
        if pos.row == space_row:
            last_k4_in_row12 = pos
    if last_k4_in_row12 is not None:
        space_col = last_k4_in_row12.col + 1
    else:
        space_col = 25  # fallback

    traversal_modes = params.get("traversal_modes", [
        "spiral_from_space", "expanding_ring", "row_sweep_from_space",
        "col_sweep_from_space", "manhattan_distance",
        "diagonal_from_space", "reverse_reading",
    ])

    # Build a set of K4 positions for fast lookup
    k4_pos_set: Dict[Tuple[int, int], int] = {}
    for pos in positions:
        k4_pos_set[(pos.row, pos.col)] = pos.ct_idx

    n_rows_grid = len(ANTIPODES_ROWS)
    max_cols = max(len(row) for row in ANTIPODES_ROWS)

    for mode in traversal_modes:
        stats["configs_tested"] += 1

        perm: List[int] = []

        if mode == "manhattan_distance":
            # Sort K4 positions by Manhattan distance from space
            dist_list = []
            for pos in positions:
                d = abs(pos.row - space_row) + abs(pos.col - space_col)
                dist_list.append((d, pos.row, pos.col, pos.ct_idx))
            dist_list.sort()
            perm = [item[3] for item in dist_list]

        elif mode == "expanding_ring":
            # BFS from space position, collect K4 chars in order encountered
            visited: set = set()
            queue: List[Tuple[int, int]] = [(space_row, space_col)]
            visited.add((space_row, space_col))
            while queue:
                next_queue: List[Tuple[int, int]] = []
                for r, c in queue:
                    if (r, c) in k4_pos_set:
                        perm.append(k4_pos_set[(r, c)])
                    for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
                        nr, nc = r + dr, c + dc
                        if (0 <= nr < n_rows_grid and
                                0 <= nc < max_cols and
                                (nr, nc) not in visited):
                            visited.add((nr, nc))
                            next_queue.append((nr, nc))
                queue = next_queue

        elif mode == "spiral_from_space":
            # Spiral outward from space position
            visited_s: set = set()
            directions = [(0, 1), (1, 0), (0, -1), (-1, 0)]  # R, D, L, U
            r, c = space_row, space_col
            di = 0
            steps = 1
            step_count = 0
            turns = 0
            max_steps = n_rows_grid * max_cols

            visited_s.add((r, c))
            if (r, c) in k4_pos_set:
                perm.append(k4_pos_set[(r, c)])

            for _ in range(max_steps):
                dr, dc = directions[di]
                r, c = r + dr, c + dc
                step_count += 1

                if 0 <= r < n_rows_grid and 0 <= c < max_cols:
                    if (r, c) not in visited_s:
                        visited_s.add((r, c))
                        if (r, c) in k4_pos_set:
                            perm.append(k4_pos_set[(r, c)])

                if step_count == steps:
                    step_count = 0
                    di = (di + 1) % 4
                    turns += 1
                    if turns % 2 == 0:
                        steps += 1

                if len(perm) == CT_LEN:
                    break

        elif mode == "row_sweep_from_space":
            # Read rows starting from space_row outward (alternating above/below)
            rows_ordered = [space_row]
            for delta in range(1, n_rows_grid):
                if space_row - delta >= 0:
                    rows_ordered.append(space_row - delta)
                if space_row + delta < n_rows_grid:
                    rows_ordered.append(space_row + delta)

            for r in rows_ordered:
                for c in range(len(ANTIPODES_ROWS[r])):
                    if (r, c) in k4_pos_set:
                        perm.append(k4_pos_set[(r, c)])

        elif mode == "col_sweep_from_space":
            # Read columns starting from space_col outward
            cols_ordered = [space_col]
            for delta in range(1, max_cols):
                if space_col - delta >= 0:
                    cols_ordered.append(space_col - delta)
                if space_col + delta < max_cols:
                    cols_ordered.append(space_col + delta)

            for c in cols_ordered:
                for r in range(n_rows_grid):
                    if (r, c) in k4_pos_set and len(perm) < CT_LEN:
                        perm.append(k4_pos_set[(r, c)])

        elif mode == "diagonal_from_space":
            # Follow diagonals from the space position
            for delta in range(max(n_rows_grid, max_cols)):
                for dr, dc in [(delta, delta), (delta, -delta),
                               (-delta, delta), (-delta, -delta)]:
                    r, c = space_row + dr, space_col + dc
                    if (r, c) in k4_pos_set:
                        ct_idx = k4_pos_set[(r, c)]
                        if ct_idx not in perm:
                            perm.append(ct_idx)

        elif mode == "reverse_reading":
            # Read K4 positions in reverse order (96 down to 0)
            perm = list(range(CT_LEN - 1, -1, -1))

        if len(perm) != CT_LEN:
            # Skip incomplete permutations
            continue

        # Apply permutation as transposition
        permuted_ct = "".join(CT[perm[i]] for i in range(CT_LEN))
        crib_score = fast_crib_check(permuted_ct)

        if crib_score > stats["best_score"]:
            stats["best_score"] = crib_score
            stats["best_config"] = {
                "hypothesis": "H5", "mode": mode,
                "pass": pass_label, "key": "identity",
                "crib_score": crib_score,
            }

        if crib_score >= STORE_THRESHOLD:
            full_score = score_candidate(permuted_ct)
            hit = {
                "hypothesis": "H5", "mode": mode,
                "pass": pass_label, "key": "identity",
                "plaintext": permuted_ct, "crib_score": crib_score,
                "score": full_score.to_dict(),
                "timestamp": time.time(),
            }
            _append_hit(results_file, hit)
            stats["hits"] += 1

        # Also try inverse permutation
        inv_ct_chars = [""] * CT_LEN
        for i in range(CT_LEN):
            inv_ct_chars[perm[i]] = CT[i]
        inv_permuted_ct = "".join(inv_ct_chars)
        crib_score_inv = fast_crib_check(inv_permuted_ct)
        stats["configs_tested"] += 1

        if crib_score_inv > stats["best_score"]:
            stats["best_score"] = crib_score_inv
            stats["best_config"] = {
                "hypothesis": "H5", "mode": f"inv_{mode}",
                "pass": pass_label, "key": "identity",
                "crib_score": crib_score_inv,
            }

        if crib_score_inv >= STORE_THRESHOLD:
            full_score = score_candidate(inv_permuted_ct)
            hit = {
                "hypothesis": "H5", "mode": f"inv_{mode}",
                "pass": pass_label, "key": "identity",
                "plaintext": inv_permuted_ct, "crib_score": crib_score_inv,
                "score": full_score.to_dict(),
                "timestamp": time.time(),
            }
            _append_hit(results_file, hit)
            stats["hits"] += 1

        # Try transposition + substitution with each variant
        for variant in VARIANTS:
            for key_src in ["row", "col", "row_plus_col"]:
                stats["configs_tested"] += 1
                if key_src == "row":
                    key_vals = [positions[perm[i]].row % MOD for i in range(CT_LEN)]
                elif key_src == "col":
                    key_vals = [positions[perm[i]].col % MOD for i in range(CT_LEN)]
                else:
                    key_vals = [(positions[perm[i]].row + positions[perm[i]].col) % MOD
                                for i in range(CT_LEN)]

                pt = decrypt_text(permuted_ct, key_vals, variant)
                cs = fast_crib_check(pt)

                if cs > stats["best_score"]:
                    stats["best_score"] = cs
                    stats["best_config"] = {
                        "hypothesis": "H5", "mode": mode,
                        "key_source": key_src, "variant": variant.value,
                        "pass": pass_label, "crib_score": cs,
                    }

                if cs >= STORE_THRESHOLD:
                    full_score = score_candidate(pt)
                    hit = {
                        "hypothesis": "H5", "mode": mode,
                        "key_source": key_src, "variant": variant.value,
                        "pass": pass_label, "plaintext": pt,
                        "crib_score": cs,
                        "score": full_score.to_dict(),
                        "timestamp": time.time(),
                    }
                    _append_hit(results_file, hit)
                    stats["hits"] += 1
                    if cs >= SIGNAL_THRESHOLD:
                        print(f"  *** SIGNAL: H5 {mode} {key_src} "
                              f"{variant.value} -> {full_score.summary}")


# ── Cross-pass hypotheses ───────────────────────────────────────────────────

def run_cross_pass(
    params: Dict[str, Any],
    stats: Dict[str, Any],
    results_file: str,
) -> None:
    """Test hypotheses that use BOTH passes (pass1 XOR pass2, delta, etc.)."""
    cross_modes = params.get("cross_modes", [
        "row_delta", "col_delta", "row_xor", "col_xor",
        "pos_delta_row_col", "swap_pass_coords",
    ])

    for mode in cross_modes:
        key_values: List[int] = []
        for i in range(CT_LEN):
            p1, p2 = PASS1[i], PASS2[i]
            if mode == "row_delta":
                val = (p2.row - p1.row) % MOD
            elif mode == "col_delta":
                val = (p2.col - p1.col) % MOD
            elif mode == "row_xor":
                val = (p1.row ^ p2.row) % MOD
            elif mode == "col_xor":
                val = (p1.col ^ p2.col) % MOD
            elif mode == "pos_delta_row_col":
                val = ((p2.row - p1.row) + (p2.col - p1.col)) % MOD
            elif mode == "swap_pass_coords":
                val = (p1.row + p2.col) % MOD
            else:
                val = 0
            key_values.append(val)

        for variant in VARIANTS:
            stats["configs_tested"] += 1
            pt = decrypt_with_key(key_values, variant)
            crib_score = fast_crib_check(pt)

            if crib_score > stats["best_score"]:
                stats["best_score"] = crib_score
                stats["best_config"] = {
                    "hypothesis": "cross_pass", "mode": mode,
                    "variant": variant.value, "crib_score": crib_score,
                }

            if crib_score >= STORE_THRESHOLD:
                full_score = score_candidate(pt)
                bean_result = verify_bean(key_values)
                hit = {
                    "hypothesis": "cross_pass", "mode": mode,
                    "variant": variant.value, "plaintext": pt,
                    "crib_score": crib_score,
                    "score": full_score.to_dict(),
                    "bean": bean_result.summary,
                    "timestamp": time.time(),
                }
                _append_hit(results_file, hit)
                stats["hits"] += 1
                if crib_score >= SIGNAL_THRESHOLD:
                    print(f"  *** SIGNAL: cross_pass {mode} "
                          f"{variant.value} -> {full_score.summary}")


# ── Utilities ───────────────────────────────────────────────────────────────

def _append_hit(results_file: str, hit: Dict[str, Any]) -> None:
    """Append a hit to the JSONL results file."""
    os.makedirs(os.path.dirname(results_file) or ".", exist_ok=True)
    with open(results_file, "a") as f:
        f.write(json.dumps(hit) + "\n")


def _save_checkpoint(checkpoint_dir: str, stats: Dict[str, Any]) -> None:
    """Save checkpoint to disk."""
    os.makedirs(checkpoint_dir, exist_ok=True)
    cp_path = os.path.join(checkpoint_dir, "checkpoint.json")
    tmp_path = cp_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(stats, f, indent=2)
    os.replace(tmp_path, cp_path)


def _load_checkpoint(checkpoint_dir: str) -> Optional[Dict[str, Any]]:
    """Load checkpoint if it exists."""
    cp_path = os.path.join(checkpoint_dir, "checkpoint.json")
    if os.path.exists(cp_path):
        with open(cp_path) as f:
            return json.load(f)
    return None


# ── Main engine ─────────────────────────────────────────────────────────────

HYPOTHESIS_RUNNERS = {
    "H1": run_h1_coordinate_lookup,
    "H2": run_h2_adjacent_key,
    "H3": run_h3_strip_transposition,
    "H4": run_h4_offset_key,
    "H5": run_h5_space_anchored,
}


def run_engine(manifest_path: str, shard: Optional[int] = None, resume: bool = False) -> None:
    """Run the engine from a manifest file."""
    with open(manifest_path) as f:
        manifest = json.load(f)

    job_id = manifest.get("job_id", f"antipodes_device_{int(time.time())}")
    hypotheses = manifest.get("hypotheses", [])
    if not hypotheses:
        print("ERROR: No hypotheses specified in manifest.")
        sys.exit(1)

    # Set up paths
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    checkpoint_dir = os.path.join(base_dir, "checkpoints", job_id)
    results_file = os.path.join(base_dir, "results", f"{job_id}.jsonl")
    summary_path = os.path.join(base_dir, "reports", f"{job_id}.summary.json")

    # Initialize stats
    stats: Dict[str, Any] = {
        "job_id": job_id,
        "manifest_path": manifest_path,
        "configs_tested": 0,
        "hits": 0,
        "best_score": 0,
        "best_config": None,
        "start_time": time.time(),
        "last_checkpoint": time.time(),
        "last_progress": time.time(),
        "completed_hypotheses": [],
    }

    # Resume from checkpoint
    if resume:
        cp = _load_checkpoint(checkpoint_dir)
        if cp:
            stats.update(cp)
            print(f"Resumed from checkpoint: {stats['configs_tested']} configs, "
                  f"best={stats['best_score']}")

    # Signal handling
    shutdown_flag = False

    def handle_signal(signum, frame):
        nonlocal shutdown_flag
        if shutdown_flag:
            print("\nForced exit.")
            sys.exit(1)
        shutdown_flag = True
        print(f"\nSignal {signum} received, saving checkpoint and exiting...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Print grid verification
    print(f"Job: {job_id}")
    print(f"Grid: {len(ANTIPODES_ROWS)} rows, "
          f"widths {min(len(r) for r in ANTIPODES_ROWS)}-{max(len(r) for r in ANTIPODES_ROWS)}")
    print(f"K4 Pass 1: rows {PASS1[0].row}-{PASS1[-1].row}, "
          f"first=({PASS1[0].row},{PASS1[0].col})='{PASS1[0].char}'")
    print(f"K4 Pass 2: rows {PASS2[0].row}-{PASS2[-1].row}, "
          f"first=({PASS2[0].row},{PASS2[0].col})='{PASS2[0].char}'")
    print(f"Hypotheses to test: {[h.get('name', h.get('type', '?')) for h in hypotheses]}")
    print(f"Results: {results_file}")
    print("-" * 70)

    for h_spec in hypotheses:
        if shutdown_flag:
            break

        h_type = h_spec.get("type", h_spec.get("name", ""))
        h_params = h_spec.get("params", {})
        passes = h_spec.get("passes", ["pass1", "pass2"])

        # Skip already completed hypotheses on resume
        if h_type in stats.get("completed_hypotheses", []):
            print(f"Skipping {h_type} (already completed)")
            continue

        print(f"\n{'=' * 70}")
        print(f"Running {h_type}")
        print(f"{'=' * 70}")

        runner = HYPOTHESIS_RUNNERS.get(h_type)
        if runner is None and h_type == "cross_pass":
            run_cross_pass(h_params, stats, results_file)
        elif runner is None:
            print(f"WARNING: Unknown hypothesis type '{h_type}', skipping.")
            continue
        else:
            for pass_name in passes:
                if shutdown_flag:
                    break
                positions = PASS1 if pass_name == "pass1" else PASS2
                print(f"  --- {pass_name} ---")
                runner(h_params, positions, pass_name, stats, results_file)

                # Progress reporting
                now = time.time()
                if now - stats["last_progress"] >= 30:
                    elapsed = now - stats["start_time"]
                    rate = stats["configs_tested"] / max(elapsed, 1)
                    print(f"  Progress: {stats['configs_tested']:,} configs, "
                          f"{rate:.0f}/s, best={stats['best_score']}/24, "
                          f"hits={stats['hits']}")
                    stats["last_progress"] = now

                # Checkpoint every 5 minutes
                if now - stats["last_checkpoint"] >= 300:
                    _save_checkpoint(checkpoint_dir, stats)
                    stats["last_checkpoint"] = now
                    print(f"  [checkpoint saved]")

        stats.setdefault("completed_hypotheses", []).append(h_type)

    # Final stats
    elapsed = time.time() - stats["start_time"]
    stats["elapsed_seconds"] = elapsed
    stats["end_time"] = time.time()

    # Save final checkpoint
    _save_checkpoint(checkpoint_dir, stats)

    # Write summary
    summary = {
        "job_id": job_id,
        "manifest_path": manifest_path,
        "configs_tested": stats["configs_tested"],
        "hits": stats["hits"],
        "best_score": stats["best_score"],
        "best_config": stats["best_config"],
        "elapsed_seconds": elapsed,
        "completed_hypotheses": stats.get("completed_hypotheses", []),
        "pass1_range": f"rows {PASS1[0].row}-{PASS1[-1].row}",
        "pass2_range": f"rows {PASS2[0].row}-{PASS2[-1].row}",
        "shutdown_clean": not shutdown_flag,
    }
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n{'=' * 70}")
    print(f"COMPLETE: {job_id}")
    print(f"{'=' * 70}")
    print(f"Configs tested: {stats['configs_tested']:,}")
    print(f"Hits (score >= {STORE_THRESHOLD}): {stats['hits']}")
    print(f"Best score: {stats['best_score']}/24")
    if stats["best_config"]:
        print(f"Best config: {json.dumps(stats['best_config'], indent=2)}")
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/60:.1f}m)")
    print(f"Summary: {summary_path}")
    print(f"Results: {results_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Antipodes-as-Device Engine: manifest-driven K4 hypothesis tester"
    )
    parser.add_argument("--manifest", required=True, help="Path to manifest JSON file")
    parser.add_argument("--shard", type=int, default=None,
                        help="Shard number for parallel execution")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last checkpoint")
    args = parser.parse_args()

    run_engine(args.manifest, shard=args.shard, resume=args.resume)


if __name__ == "__main__":
    main()
