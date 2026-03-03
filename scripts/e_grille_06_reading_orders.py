#!/usr/bin/env python3
"""E-GRILLE-06: Alternative Reading Orders for YAR Grille CT.

The YAR grille extracts 106 letters from a 28-row x 33-column grid.
The standard reading is L-R, T-B. This script tests alternative reading
paths: column-first, reverse, spiral, KA-row-order, diagonal, by-mask-letter,
and modular groupings.

The (row, col) positions are manually extracted from the Cardan Grille image
at reference/Cardan_Grille_1.jpg.

Usage: PYTHONPATH=src python3 -u scripts/e_grille_06_reading_orders.py
"""
from __future__ import annotations

import json
import math
import os
import sys
from collections import Counter, defaultdict
from typing import List, Tuple, Dict, Optional

# ── Constants ────────────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-GRILLE-06"

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH_IDX = {c: i for i, c in enumerate(ALPH)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# (row, col, letter) — extracted from Cardan_Grille_1.jpg
# Row 1-28, Col 1-33 (1-indexed as shown in the image)
# Reading left-to-right, top-to-bottom should reproduce the given CT.
GRILLE_POSITIONS = [
    # Row 1
    (1, 9, 'H'),
    (1, 11, 'J'),
    (1, 13, 'L'),
    (1, 23, 'V'),
    # Row 2
    (2, 1, 'A'),
    (2, 11, 'C'),
    (2, 17, 'I'),
    (2, 21, 'N'),
    (2, 25, 'X'),
    (2, 26, 'Z'),
    # Row 3
    (3, 14, 'H'),
    # Row 4
    (4, 21, 'U'),
    (4, 27, 'Y'),
    (4, 32, 'O'),
    # Row 5
    (5, 6, 'C'),
    (5, 17, 'M'),
    (5, 22, 'W'),
    (5, 31, 'S'),
    # Row 6
    (6, 9, 'E'),
    (6, 32, 'A'),
    # Row 7
    (7, 1, 'F'),
    (7, 25, 'Y'),
    (7, 33, 'B'),
    # Row 8 — empty row (no visible letters)
    # Row 9
    (9, 19, 'Z'),
    (9, 28, 'A'),
    # Row 10
    (10, 30, 'C'),
    # Row 11
    (11, 9, 'J'),
    (11, 31, 'F'),
    # Row 12
    (12, 4, 'H'),
    (12, 5, 'I'),
    (12, 32, 'F'),
    # Row 13
    (13, 15, 'X'),
    (13, 19, 'R'),
    (13, 20, 'Y'),
    # Row 14
    (14, 12, 'V'),
    (14, 27, 'F'),
    # Row 15
    (15, 3, 'I'),
    (15, 4, 'J'),
    (15, 7, 'M'),
    (15, 14, 'X'),
    (15, 24, 'E'),
    (15, 30, 'I'),
    (15, 33, 'L'),
    # Row 16
    (16, 4, 'L'),
    (16, 6, 'N'),
    (16, 24, 'E'),
    (16, 33, 'L'),
    # Row 17
    (17, 2, 'J'),
    (17, 6, 'N'),
    (17, 12, 'X'),
    (17, 13, 'Z'),
    (17, 14, 'K'),
    (17, 29, 'I'),
    (17, 30, 'L'),
    # Row 18
    (18, 13, 'K'),
    (18, 14, 'R'),
    (18, 19, 'D'),
    (18, 27, 'I'),
    (18, 33, 'N'),
    # Row 19
    (19, 14, 'P'),
    (19, 18, 'A'),
    (19, 20, 'D'),
    (19, 21, 'E'),
    (19, 28, 'M'),
    (19, 29, 'N'),
    # Row 20
    (20, 5, 'V'),
    (20, 8, 'Z'),
    (20, 17, 'A'),
    (20, 19, 'C'),
    (20, 21, 'E'),
    (20, 23, 'I'),
    (20, 27, 'M'),
    (20, 33, 'U'),
    # Row 21
    (21, 5, 'W'),
    (21, 15, 'A'),
    (21, 20, 'F'),
    (21, 21, 'G'),
    (21, 23, 'I'),
    (21, 27, 'M'),
    (21, 33, 'U'),
    # Row 22
    (22, 8, 'K'),
    (22, 9, 'R'),
    (22, 19, 'G'),
    (22, 23, 'I'),
    (22, 25, 'L'),
    # Row 23
    (23, 1, 'V'),
    (23, 19, 'H'),
    (23, 25, 'N'),
    (23, 26, 'Q'),
    (23, 32, 'X'),
    # Row 24
    (24, 1, 'W'),
    (24, 8, 'Y'),
    (24, 14, 'A'),
    (24, 15, 'B'),
    (24, 32, 'X'),
    (24, 33, 'Z'),
    # Row 25
    (25, 4, 'K'),
    (25, 18, 'I'),
    (25, 26, 'U'),
    # Row 26
    (26, 18, 'J'),
    # Row 27
    (27, 14, 'F'),
    (27, 22, 'Q'),
    (27, 31, 'R'),
    # Row 28
    (28, 24, 'X'),
    (28, 31, 'C'),
    (28, 32, 'D'),
]

# ── Load scoring data ────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

QUADGRAMS: Dict[str, float] = {}
qg_path = os.path.join(PROJECT_DIR, "data", "english_quadgrams.json")
if os.path.exists(qg_path):
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)
    print(f"[+] Loaded {len(QUADGRAMS)} quadgrams")

ENGLISH_WORDS = set()
wl_path = os.path.join(PROJECT_DIR, "wordlists", "english.txt")
if os.path.exists(wl_path):
    with open(wl_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 4:
                ENGLISH_WORDS.add(w)
    print(f"[+] Loaded {len(ENGLISH_WORDS)} English words (4+ letters)")


def quadgram_score(text: str) -> float:
    if not QUADGRAMS or len(text) < 4:
        return -99.0
    floor = -10.0
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, floor)
    return score / max(1, len(text) - 3)


def count_words(text: str) -> Tuple[int, List[str]]:
    found = []
    for length in range(min(15, len(text)), 3, -1):
        for i in range(len(text) - length + 1):
            word = text[i:i+length]
            if word in ENGLISH_WORDS and word not in found:
                found.append(word)
    return len(found), found


def vigenere_decrypt(ct: str, key: str) -> str:
    pt = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ci - ki) % 26])
    return "".join(pt)


def beaufort_decrypt(ct: str, key: str) -> str:
    pt = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ki - ci) % 26])
    return "".join(pt)


def caesar_shift(text: str, shift: int) -> str:
    return "".join(ALPH[(ALPH_IDX[c] + shift) % 26] for c in text)


# ── Reading Order Functions ──────────────────────────────────────────────────

def sort_lr_tb(positions):
    """Standard: left-to-right, top-to-bottom."""
    return sorted(positions, key=lambda p: (p[0], p[1]))


def sort_tb_lr(positions):
    """Column-first: top-to-bottom, left-to-right."""
    return sorted(positions, key=lambda p: (p[1], p[0]))


def sort_rl_bt(positions):
    """Reverse: right-to-left, bottom-to-top."""
    return sorted(positions, key=lambda p: (-p[0], -p[1]))


def sort_rl_tb(positions):
    """Right-to-left, top-to-bottom."""
    return sorted(positions, key=lambda p: (p[0], -p[1]))


def sort_lr_bt(positions):
    """Left-to-right, bottom-to-top."""
    return sorted(positions, key=lambda p: (-p[0], p[1]))


def sort_bt_lr(positions):
    """Column-first bottom-to-top: bottom-to-top, left-to-right."""
    return sorted(positions, key=lambda p: (p[1], -p[0]))


def sort_bt_rl(positions):
    """Bottom-to-top, right-to-left."""
    return sorted(positions, key=lambda p: (-p[1], -p[0]))


def sort_tb_rl(positions):
    """Top-to-bottom, right-to-left."""
    return sorted(positions, key=lambda p: (-p[1], p[0]))


def sort_snake_rows(positions):
    """Snake: L-R on odd rows, R-L on even rows."""
    return sorted(positions, key=lambda p: (p[0], p[1] if p[0] % 2 == 1 else -p[1]))


def sort_snake_cols(positions):
    """Snake columns: T-B on odd cols, B-T on even cols."""
    return sorted(positions, key=lambda p: (p[1], p[0] if p[1] % 2 == 1 else -p[0]))


def sort_ka_row_order(positions):
    """Read in KA alphabet row order instead of A-Z.

    The tableau rows go A-Z (row indices 1-26 in tableau, mapped to
    cipher rows). KA order: K,R,Y,P,T,O,S,A,B,C,D,E,F,G,H,I,J,L,M,N,Q,U,V,W,X,Z.
    Map each position's row to KA order priority, then sort by (ka_priority, col).
    """
    # The tableau has header at row 0, body A-Z at rows 1-26, footer at row 27.
    # Cipher rows are 0-27 (but image uses 1-28).
    # KA row order maps each body row label to its KA-alphabet position.
    ka_row_priority = {}
    for i, ch in enumerate(KA):
        # Row labeled 'ch' is at image row (ord(ch) - ord('A') + 2)
        # because image row 1 = header, row 2 = A, ..., row 27 = Z, row 28 = footer
        row_num = ord(ch) - ord('A') + 2
        ka_row_priority[row_num] = i
    # Header (row 1) and footer (row 28): put at end
    ka_row_priority[1] = 100
    ka_row_priority[28] = 101

    return sorted(positions, key=lambda p: (ka_row_priority.get(p[0], 999), p[1]))


def sort_spiral_cw(positions):
    """Spiral clockwise from top-left of the bounding box of positions."""
    if not positions:
        return []

    # Build a grid mapping
    pos_set = {(r, c): ch for r, c, ch in positions}
    min_r = min(r for r, c, ch in positions)
    max_r = max(r for r, c, ch in positions)
    min_c = min(c for r, c, ch in positions)
    max_c = max(c for r, c, ch in positions)

    # Generate spiral order through ALL grid cells, pick up positions that exist
    result = []
    top, bottom, left, right = min_r, max_r, min_c, max_c
    while top <= bottom and left <= right:
        # Go right
        for c in range(left, right + 1):
            if (top, c) in pos_set:
                result.append((top, c, pos_set[(top, c)]))
        top += 1
        # Go down
        for r in range(top, bottom + 1):
            if (r, right) in pos_set:
                result.append((r, right, pos_set[(r, right)]))
        right -= 1
        # Go left
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if (bottom, c) in pos_set:
                    result.append((bottom, c, pos_set[(bottom, c)]))
            bottom -= 1
        # Go up
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if (r, left) in pos_set:
                    result.append((r, left, pos_set[(r, left)]))
            left += 1

    return result


def sort_spiral_ccw(positions):
    """Spiral counter-clockwise from top-left."""
    if not positions:
        return []

    pos_set = {(r, c): ch for r, c, ch in positions}
    min_r = min(r for r, c, ch in positions)
    max_r = max(r for r, c, ch in positions)
    min_c = min(c for r, c, ch in positions)
    max_c = max(c for r, c, ch in positions)

    result = []
    top, bottom, left, right = min_r, max_r, min_c, max_c
    while top <= bottom and left <= right:
        # Go down
        for r in range(top, bottom + 1):
            if (r, left) in pos_set:
                result.append((r, left, pos_set[(r, left)]))
        left += 1
        # Go right
        for c in range(left, right + 1):
            if (bottom, c) in pos_set:
                result.append((bottom, c, pos_set[(bottom, c)]))
        bottom -= 1
        # Go up
        if left <= right:
            for r in range(bottom, top - 1, -1):
                if (r, right) in pos_set:
                    result.append((r, right, pos_set[(r, right)]))
            right -= 1
        # Go left
        if top <= bottom:
            for c in range(right, left - 1, -1):
                if (top, c) in pos_set:
                    result.append((top, c, pos_set[(top, c)]))
            top += 1

    return result


def sort_diagonal_tl_br(positions):
    """Diagonal: top-left to bottom-right diagonals."""
    # Sort by (row + col), then by row within each diagonal
    return sorted(positions, key=lambda p: (p[0] + p[1], p[0]))


def sort_diagonal_tr_bl(positions):
    """Diagonal: top-right to bottom-left (anti-diagonal)."""
    # Sort by (row - col), then by row
    return sorted(positions, key=lambda p: (p[0] - p[1], p[0]))


def sort_diagonal_bl_tr(positions):
    """Diagonal: bottom-left to top-right."""
    return sorted(positions, key=lambda p: (p[0] + p[1], -p[0]))


def sort_by_distance_from_center(positions):
    """Read from center outward (Manhattan distance)."""
    center_r = sum(r for r, c, ch in positions) / len(positions)
    center_c = sum(c for r, c, ch in positions) / len(positions)
    return sorted(positions, key=lambda p: (abs(p[0] - center_r) + abs(p[1] - center_c), p[0], p[1]))


def sort_by_distance_from_center_rev(positions):
    """Read from outside inward."""
    center_r = sum(r for r, c, ch in positions) / len(positions)
    center_c = sum(c for r, c, ch in positions) / len(positions)
    return sorted(positions, key=lambda p: (-(abs(p[0] - center_r) + abs(p[1] - center_c)), p[0], p[1]))


def sort_by_col_mod(positions, modulus):
    """Group by column mod N, then within each group by row."""
    return sorted(positions, key=lambda p: (p[1] % modulus, p[0], p[1]))


def sort_by_row_mod(positions, modulus):
    """Group by row mod N, then within each group by col."""
    return sorted(positions, key=lambda p: (p[0] % modulus, p[1], p[0]))


# ── Mask letter separation ──────────────────────────────────────────────────

# The cipher rows and which letters are holes
CIPHER_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",   # row 1 (image row 1 = cipher row 0 header)
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA",
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
]


def identify_mask_letter(positions):
    """For each grille position, determine if it came from a Y, A, or R hole.

    This requires knowing which cipher character was at that position.
    The cipher row index is (image_row - 1), because image rows are 1-indexed
    and correspond to the 28 cipher rows (0-indexed internally but the image
    shows rows 1-28).

    Actually, the image rows 1-28 correspond directly to:
    Row 1 = header of tableau / cipher row 0
    Row 2 = tableau row A / cipher row 1
    etc.

    The cipher rows list is 0-indexed (CIPHER_ROWS[0] = row 1 of image).
    """
    y_positions = []
    a_positions = []
    r_positions = []
    unknown_positions = []

    for r, c, ch in positions:
        cipher_row_idx = r - 1  # convert to 0-indexed
        if 0 <= cipher_row_idx < len(CIPHER_ROWS):
            cipher_row = CIPHER_ROWS[cipher_row_idx]
            # Column is 1-indexed in image, 0-indexed in cipher row
            col_idx = c - 1
            if 0 <= col_idx < len(cipher_row):
                cipher_ch = cipher_row[col_idx]
                if cipher_ch == 'Y':
                    y_positions.append((r, c, ch))
                elif cipher_ch == 'A':
                    a_positions.append((r, c, ch))
                elif cipher_ch == 'R':
                    r_positions.append((r, c, ch))
                else:
                    unknown_positions.append((r, c, ch, cipher_ch))
            else:
                unknown_positions.append((r, c, ch, 'OOB'))
        else:
            unknown_positions.append((r, c, ch, 'OOB'))

    return y_positions, a_positions, r_positions, unknown_positions


# ── Main ─────────────────────────────────────────────────────────────────────

class Result:
    def __init__(self, method: str, text: str, score: float, details: str = ""):
        self.method = method
        self.text = text
        self.score = score
        self.details = details


def test_text(text: str, method: str, results: List[Result]):
    """Test a text with direct reading, Caesar shifts, and Vigenere."""
    configs = 0

    # Direct
    sc = quadgram_score(text)
    results.append(Result(method, text, sc))
    configs += 1

    # All 26 Caesar shifts
    for shift in range(1, 26):
        shifted = caesar_shift(text, shift)
        sc = quadgram_score(shifted)
        if sc > -8.0:
            results.append(Result(f"{method}+caesar({shift})", shifted, sc))
        configs += 1

    # Vigenere with key KRYPTOS
    for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        pt = vigenere_decrypt(text, key)
        sc = quadgram_score(pt)
        if sc > -8.5:
            results.append(Result(f"{method}+vig({key})", pt, sc))
        configs += 1

        pt = beaufort_decrypt(text, key)
        sc = quadgram_score(pt)
        if sc > -8.5:
            results.append(Result(f"{method}+beau({key})", pt, sc))
        configs += 1

    return configs


def main():
    positions = GRILLE_POSITIONS

    print(f"{'='*80}")
    print(f"  {EXPERIMENT_ID}: Alternative Reading Orders for YAR Grille CT")
    print(f"{'='*80}\n")

    # Verify extraction
    lr_tb = sort_lr_tb(positions)
    lr_tb_text = "".join(ch for _, _, ch in lr_tb)
    print(f"Extracted positions: {len(positions)}")
    print(f"L-R T-B read:  {lr_tb_text}")
    print(f"Expected CT:   {GRILLE_CT}")

    if lr_tb_text == GRILLE_CT:
        print("MATCH: L-R T-B extraction matches the given grille CT exactly!")
    else:
        # Find differences
        match_count = sum(1 for a, b in zip(lr_tb_text, GRILLE_CT) if a == b)
        print(f"MISMATCH: {match_count}/{min(len(lr_tb_text), len(GRILLE_CT))} chars match")
        print(f"Lengths: extracted={len(lr_tb_text)}, expected={len(GRILLE_CT)}")
        # Show diffs
        for i in range(min(len(lr_tb_text), len(GRILLE_CT))):
            if lr_tb_text[i] != GRILLE_CT[i]:
                print(f"  pos {i}: extracted='{lr_tb_text[i]}', expected='{GRILLE_CT[i]}'")
                if i > 10:
                    print(f"  ... (showing first mismatches only)")
                    break

    # Identify mask letters
    y_pos, a_pos, r_pos, unk_pos = identify_mask_letter(positions)
    print(f"\nMask letter breakdown:")
    print(f"  Y holes: {len(y_pos)} positions")
    print(f"  A holes: {len(a_pos)} positions")
    print(f"  R holes: {len(r_pos)} positions")
    print(f"  Unknown: {len(unk_pos)} positions")
    if unk_pos:
        print(f"  Unknown details: {unk_pos[:10]}")

    print(f"\nY-hole letters: {''.join(ch for _, _, ch in sorted(y_pos, key=lambda p: (p[0], p[1])))}")
    print(f"A-hole letters: {''.join(ch for _, _, ch in sorted(a_pos, key=lambda p: (p[0], p[1])))}")
    print(f"R-hole letters: {''.join(ch for _, _, ch in sorted(r_pos, key=lambda p: (p[0], p[1])))}")

    results: List[Result] = []
    total_configs = 0

    # ══════════════════════════════════════════════════════════════════════════
    # Test all reading orders
    # ══════════════════════════════════════════════════════════════════════════

    reading_orders = [
        ("lr_tb", sort_lr_tb),
        ("tb_lr", sort_tb_lr),
        ("rl_bt", sort_rl_bt),
        ("rl_tb", sort_rl_tb),
        ("lr_bt", sort_lr_bt),
        ("bt_lr", sort_bt_lr),
        ("bt_rl", sort_bt_rl),
        ("tb_rl", sort_tb_rl),
        ("snake_rows", sort_snake_rows),
        ("snake_cols", sort_snake_cols),
        ("ka_row_order", sort_ka_row_order),
        ("spiral_cw", sort_spiral_cw),
        ("spiral_ccw", sort_spiral_ccw),
        ("diag_tl_br", sort_diagonal_tl_br),
        ("diag_tr_bl", sort_diagonal_tr_bl),
        ("diag_bl_tr", sort_diagonal_bl_tr),
        ("center_out", sort_by_distance_from_center),
        ("outside_in", sort_by_distance_from_center_rev),
    ]

    # Add modular groupings
    for mod in [2, 3, 5, 7]:
        reading_orders.append((f"col_mod{mod}", lambda p, m=mod: sort_by_col_mod(p, m)))
        reading_orders.append((f"row_mod{mod}", lambda p, m=mod: sort_by_row_mod(p, m)))

    print(f"\n[1] Testing {len(reading_orders)} reading orders...")
    for name, sort_fn in reading_orders:
        sorted_pos = sort_fn(positions)
        text = "".join(ch for _, _, ch in sorted_pos)
        n = test_text(text, f"read({name})", results)
        total_configs += n

    print(f"  Tested {total_configs} configs from reading orders")

    # ══════════════════════════════════════════════════════════════════════════
    # Mask letter separation attacks
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n[2] Mask letter separation attacks...")
    mask_configs = 0

    y_text = "".join(ch for _, _, ch in sorted(y_pos, key=lambda p: (p[0], p[1])))
    a_text = "".join(ch for _, _, ch in sorted(a_pos, key=lambda p: (p[0], p[1])))
    r_text = "".join(ch for _, _, ch in sorted(r_pos, key=lambda p: (p[0], p[1])))

    # Concatenation orders
    concat_orders = [
        ("YAR", y_text + a_text + r_text),
        ("RAY", r_text + a_text + y_text),
        ("ARY", a_text + r_text + y_text),
        ("YRA", y_text + r_text + a_text),
        ("AYR", a_text + y_text + r_text),
        ("RYA", r_text + y_text + a_text),
    ]

    for label, text in concat_orders:
        n = test_text(text, f"mask_concat({label})", results)
        mask_configs += n

    # Interleaved
    max_len = max(len(y_text), len(a_text), len(r_text))
    for order_label, groups in [
        ("YAR", [y_text, a_text, r_text]),
        ("RAY", [r_text, a_text, y_text]),
        ("ARY", [a_text, r_text, y_text]),
    ]:
        interleaved = []
        for i in range(max_len):
            for g in groups:
                if i < len(g):
                    interleaved.append(g[i])
        text = "".join(interleaved)
        n = test_text(text, f"mask_interleave({order_label})", results)
        mask_configs += n

    # Each group separately
    for label, text in [("Y_only", y_text), ("A_only", a_text), ("R_only", r_text)]:
        if len(text) >= 4:
            n = test_text(text, f"mask_solo({label})", results)
            mask_configs += n

    # Y and A combined (no R), etc.
    for label, text in [
        ("YA", y_text + a_text),
        ("YR", y_text + r_text),
        ("AR", a_text + r_text),
    ]:
        n = test_text(text, f"mask_pair({label})", results)
        mask_configs += n

    total_configs += mask_configs
    print(f"  Tested {mask_configs} mask separation configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Column-first reads with different mask letter orderings
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n[3] Column-first reads per mask letter...")
    col_mask_configs = 0

    for label, group in [("Y", y_pos), ("A", a_pos), ("R", r_pos)]:
        # Column-first (T-B, L-R) within each group
        sorted_g = sorted(group, key=lambda p: (p[1], p[0]))
        text = "".join(ch for _, _, ch in sorted_g)
        if len(text) >= 4:
            n = test_text(text, f"col_first_mask({label})", results)
            col_mask_configs += n

    # Concatenate column-first reads
    y_col = "".join(ch for _, _, ch in sorted(y_pos, key=lambda p: (p[1], p[0])))
    a_col = "".join(ch for _, _, ch in sorted(a_pos, key=lambda p: (p[1], p[0])))
    r_col = "".join(ch for _, _, ch in sorted(r_pos, key=lambda p: (p[1], p[0])))

    for label, text in [
        ("YAR_col", y_col + a_col + r_col),
        ("RAY_col", r_col + a_col + y_col),
    ]:
        n = test_text(text, f"mask_concat_col({label})", results)
        col_mask_configs += n

    total_configs += col_mask_configs
    print(f"  Tested {col_mask_configs} column-first mask configs")

    # ══════════════════════════════════════════════════════════════════════════
    # KA-alphabet position ordering
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n[4] KA-alphabet position ordering...")
    ka_configs = 0

    # Sort positions by their KA-index of the extracted letter
    ka_sorted = sorted(positions, key=lambda p: (KA.index(p[2]) if p[2] in KA else 99, p[0], p[1]))
    text = "".join(ch for _, _, ch in ka_sorted)
    n = test_text(text, "sort_by_ka_letter", results)
    ka_configs += n

    # Sort by standard alphabet index of extracted letter
    alph_sorted = sorted(positions, key=lambda p: (ALPH_IDX.get(p[2], 99), p[0], p[1]))
    text = "".join(ch for _, _, ch in alph_sorted)
    n = test_text(text, "sort_by_alph_letter", results)
    ka_configs += n

    total_configs += ka_configs
    print(f"  Tested {ka_configs} KA-ordering configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Row parity / checkerboard patterns
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n[5] Row/column parity groupings...")
    parity_configs = 0

    # Even rows then odd rows
    even_rows = sorted([p for p in positions if p[0] % 2 == 0], key=lambda p: (p[0], p[1]))
    odd_rows = sorted([p for p in positions if p[0] % 2 == 1], key=lambda p: (p[0], p[1]))
    for label, group in [
        ("even_then_odd", even_rows + odd_rows),
        ("odd_then_even", odd_rows + even_rows),
    ]:
        text = "".join(ch for _, _, ch in group)
        n = test_text(text, f"parity({label})", results)
        parity_configs += n

    # Even cols then odd cols
    even_cols = sorted([p for p in positions if p[1] % 2 == 0], key=lambda p: (p[0], p[1]))
    odd_cols = sorted([p for p in positions if p[1] % 2 == 1], key=lambda p: (p[0], p[1]))
    for label, group in [
        ("ecol_then_ocol", even_cols + odd_cols),
        ("ocol_then_ecol", odd_cols + even_cols),
    ]:
        text = "".join(ch for _, _, ch in group)
        n = test_text(text, f"parity({label})", results)
        parity_configs += n

    total_configs += parity_configs
    print(f"  Tested {parity_configs} parity configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Results
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'='*80}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*80}\n")

    results.sort(key=lambda r: r.score, reverse=True)

    print(f"Total configurations tested: {total_configs:,}")
    print(f"Results collected: {len(results)}")

    print(f"\n--- TOP 20 RESULTS ---\n")
    for i, r in enumerate(results[:20]):
        nw, words = count_words(r.text)
        print(f"#{i+1} [qg={r.score:.4f}] {r.method}")
        print(f"  Text: {r.text[:90]}{'...' if len(r.text) > 90 else ''}")
        if words:
            print(f"  Words({nw}): {', '.join(words[:10])}")
        print()

    # English threshold check
    english_threshold = -5.5
    promising = [r for r in results if r.score > english_threshold]
    if promising:
        print(f"\n*** PROMISING (qg > {english_threshold}) ***")
        for r in promising:
            nw, words = count_words(r.text)
            print(f"  [{r.score:.4f}] {r.method}")
            print(f"  Text: {r.text}")
    else:
        print(f"\nNo results above English threshold ({english_threshold})")

    # Show mask letter analysis summary
    print(f"\n--- MASK LETTER SUMMARY ---")
    print(f"Y holes ({len(y_pos)}): {y_text}")
    print(f"A holes ({len(a_pos)}): {a_text}")
    print(f"R holes ({len(r_pos)}): {r_text}")

    # Best per-group
    for label in ["Y_only", "A_only", "R_only"]:
        group_results = [r for r in results if label in r.method]
        if group_results:
            best = max(group_results, key=lambda r: r.score)
            print(f"  Best {label}: [{best.score:.4f}] {best.method}")

    print(f"\n{'='*80}")
    print(f"  {EXPERIMENT_ID} COMPLETE — {total_configs:,} configurations tested")
    print(f"{'='*80}")

    return results


if __name__ == "__main__":
    results = main()
