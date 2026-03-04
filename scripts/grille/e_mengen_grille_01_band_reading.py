#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-MENGEN-GRILLE-01: Mengenlehreuhr band structure as Cardan grille reading order.

Hypothesis: The Mengenlehreuhr (Berlin Clock) isn't a direct permutation source —
it's a STRUCTURAL TEMPLATE for how to read the Cardan grille. The clock encodes time
hierarchically in 5 bands (1+4+4+11+4 = 24 lamps). The grille's 28 rows may similarly
be grouped into bands, with holes read band-by-band in varying orders.

Additionally, the T-diagonal (where T is systematically avoided) may define the
band boundaries — where T's column position "jumps" across rows marks the boundary
between bands.

Phases:
  1. Map grille holes with (row, col) coordinates, extract from tableau
  2. Compute T-diagonal positions → detect natural band boundaries
  3. Try many band partitions of the 28 rows (Mengenlehreuhr-style, T-gap-based, etc.)
  4. Within each band, try multiple reading orders for holes
  5. From 107 holes, select 97 → unscrambling permutation for K4
  6. Apply permutation, try Vig/Beau decryption, score via free crib + quadgrams
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
from collections import Counter, defaultdict
from itertools import permutations, product
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, KRYPTOS_ALPHABET, MOD,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, validate_perm,
)
from kryptos.kernel.transforms.vigenere import CipherVariant, decrypt_text

# ── Constants ────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
ALPHABETS = [("AZ", ALPH, ALPH_IDX), ("KA", KA, KA_IDX)]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GRILLE_EXTRACT) == 106

# ── Tableau ──────────────────────────────────────────────────────────────

TABLEAU_ROWS = [
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",                # Row 1: header (31)
    "AKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",                # Row 2: A (31)
    "BRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",                # Row 3: B (31)
    "CYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",                # Row 4: C (31)
    "DPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",                # Row 5: D (31)
    "ETOSABCDEFGHIJLMNQUVWXZKRYPTOSA",                # Row 6: E (31)
    "FOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",                # Row 7: F (31)
    "GSABCDEFGHIJLMNQUVWXZKRYPTOSABC",                # Row 8: G (31)
    "HABCDEFGHIJLMNQUVWXZKRYPTOSABCD",                # Row 9: H (31)
    "IBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",                # Row 10: I (31)
    "JCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",                # Row 11: J (31)
    "KDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",                # Row 12: K (31)
    "LEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",                # Row 13: L (31)
    "MFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",                # Row 14: M (31)
    "NGHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",               # Row 15: N (32) extra L
    "OHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",                # Row 16: O (31)
    "PIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",                # Row 17: P (31)
    "QJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",                # Row 18: Q (31)
    "RLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",                # Row 19: R (31)
    "SMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",                # Row 20: S (31)
    "TNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",                # Row 21: T (31)
    "UQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",                # Row 22: U (31)
    "VUVWXZKRYPTOSABCDEFGHIJLMNQUVWXT",               # Row 23: V (32) extra T
    "WVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",                # Row 24: W (31)
    "XWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",                # Row 25: X (31)
    "YXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",                # Row 26: Y (31)
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",                # Row 27: Z (31)
    " ABCDEFGHIJKLMNOPQRSTUVWXYZABCD",                # Row 28: footer (31)
]

# ── Binary mask ──────────────────────────────────────────────────────────

MASK_TEXT = """1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    ~
0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    1    1    0    1    1    1    1    0    0    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    1    0    ~    ~
1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    ~    ~
1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    ~
1    1    1    0    0    1    0    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    0    ~
1    1    1    1    0    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    0    ~    ~
1    1    0    1    1    0    1    1    1    1    0    0    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    0    1    ~    ~
1    1    1    1    1    0    1    1    0    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    0    1    1    0    1    1    0    ~    ~
1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    0    1    1    0    1    1    0    1    1    ~
1    1    1    1    1    1    1    0    0    1    1    1    1    1    1    1    1    1    1    1    0    1    0    1    0    1    1    1    1    1    1    ~    ~
0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    0    1    1
0    1    1    1    1    1    1    0    1    1    1    1    0    0    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    0    0    ~    ~
1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    1    1    1    0    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    1    1    1    1    1    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    1    1    1    0    1    1    1    1    1    1    0    1    ~    ~
1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    1    0    1    1    1    1    0    0    ~    ~"""


# ── Quadgram scorer ─────────────────────────────────────────────────────

QUADGRAMS: Dict[str, float] = {}
QG_FLOOR = -10.0


def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qpath = os.path.join(os.path.dirname(__file__), "..", "data", "english_quadgrams.json")
    with open(qpath) as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0


def qscore(text: str) -> float:
    if len(text) < 4:
        return QG_FLOOR
    total = 0.0
    for i in range(len(text) - 3):
        total += QUADGRAMS.get(text[i:i + 4], QG_FLOOR)
    return total / (len(text) - 3)


# ── Parse mask → hole coordinates ────────────────────────────────────────

def parse_mask() -> List[Tuple[int, int]]:
    """Parse binary mask → list of (row, col) 0-indexed hole positions."""
    holes = []
    for r, line in enumerate(MASK_TEXT.strip().split('\n')):
        vals = line.split()
        for c, v in enumerate(vals):
            if v == '0':
                holes.append((r, c))
    return holes


def extract_letter(row: int, col: int) -> Optional[str]:
    """Get letter at (row, col) 0-indexed from tableau."""
    if row < 0 or row >= len(TABLEAU_ROWS):
        return None
    tab_row = TABLEAU_ROWS[row]
    if col < 0 or col >= len(tab_row):
        return None
    ch = tab_row[col]
    return ch if ch != ' ' else None


# ── T-diagonal analysis ─────────────────────────────────────────────────

def find_t_columns() -> Dict[int, List[int]]:
    """For each row (0-indexed), find column positions where T appears."""
    t_cols = {}
    for r, tab_row in enumerate(TABLEAU_ROWS):
        t_cols[r] = [c for c, ch in enumerate(tab_row) if ch == 'T']
    return t_cols


def find_t_band_boundaries(t_cols: Dict[int, List[int]]) -> List[int]:
    """Find rows where T-column position 'jumps' significantly → band boundaries.

    Returns list of row indices where a new band starts.
    """
    # Use first T-col in each row (the "primary" T position)
    primary_t = {}
    for r in range(len(TABLEAU_ROWS)):
        cols = t_cols.get(r, [])
        if cols:
            primary_t[r] = cols[0]

    # Find rows where the T-column jumps by more than 2 positions
    boundaries = [0]  # First band always starts at row 0
    rows_with_t = sorted(primary_t.keys())

    for i in range(1, len(rows_with_t)):
        prev_row = rows_with_t[i - 1]
        curr_row = rows_with_t[i]
        if abs(primary_t[curr_row] - primary_t[prev_row]) > 3:
            boundaries.append(curr_row)

    return boundaries


# ── Band partitions ──────────────────────────────────────────────────────

def generate_band_partitions() -> List[Tuple[str, List[List[int]]]]:
    """Generate various ways to partition 28 rows into bands."""
    partitions = []

    # Original Mengenlehreuhr: 1+4+4+11+4 = 24, adapted to 28
    # Skip header/footer (rows 0,27), partition rows 1-26 (26 rows)
    inner_rows = list(range(1, 27))  # rows 1-26 (A-Z)

    # ── Mengenlehreuhr-inspired partitions ──

    # M1: 1+4+4+11+4+2 = 26 (exact Mengen bands + remainder)
    partitions.append(("mengen_1_4_4_11_4_2", [
        inner_rows[0:1],    # Band A: 1 row
        inner_rows[1:5],    # Band B: 4 rows
        inner_rows[5:9],    # Band C: 4 rows
        inner_rows[9:20],   # Band D: 11 rows
        inner_rows[20:24],  # Band E: 4 rows
        inner_rows[24:26],  # Remainder: 2 rows
    ]))

    # M2: 2+4+4+11+4+1 = 26
    partitions.append(("mengen_2_4_4_11_4_1", [
        inner_rows[0:2],
        inner_rows[2:6],
        inner_rows[6:10],
        inner_rows[10:21],
        inner_rows[21:25],
        inner_rows[25:26],
    ]))

    # M3: Pure Mengen mapping rows A-X (24 rows) = 1+4+4+11+4, skip Y,Z
    partitions.append(("mengen_pure_24", [
        inner_rows[0:1],
        inner_rows[1:5],
        inner_rows[5:9],
        inner_rows[9:20],
        inner_rows[20:24],
    ]))

    # M4: Reversed Mengen: 4+11+4+4+1
    partitions.append(("mengen_reversed", [
        inner_rows[0:4],
        inner_rows[4:15],
        inner_rows[15:19],
        inner_rows[19:23],
        inner_rows[23:24],
        inner_rows[24:26],
    ]))

    # M5: Mengen with header/footer as band A
    all_rows = list(range(28))
    partitions.append(("mengen_with_hdr_ftr", [
        [0, 27],           # Band A: header + footer
        all_rows[1:5],     # Band B: 4
        all_rows[5:9],     # Band C: 4
        all_rows[9:20],    # Band D: 11
        all_rows[20:24],   # Band E: 4
        all_rows[24:27],   # Remainder: 3
    ]))

    # ── Uniform partitions ──

    # U1: 4 bands of 7 (skip hdr/ftr)
    partitions.append(("uniform_4x7_nohdr", [
        inner_rows[i:i + 7] for i in range(0, 28, 7) if i + 7 <= 26
    ]))

    # U2: 7 bands of 4 (skip hdr/ftr, 2 remainder)
    bands = [inner_rows[i:i + 4] for i in range(0, 26, 4)]
    partitions.append(("uniform_7x4_nohdr", bands))

    # U3: 2 bands of 13 (skip hdr/ftr)
    partitions.append(("split_2x13", [
        inner_rows[0:13],
        inner_rows[13:26],
    ]))

    # U4: 13 bands of 2
    partitions.append(("split_13x2", [
        inner_rows[i:i + 2] for i in range(0, 26, 2)
    ]))

    # ── K4-inspired partitions ──

    # K1: "8 Lines 73" — bands of 8 rows
    partitions.append(("8lines_73", [
        inner_rows[0:8],
        inner_rows[8:16],
        inner_rows[16:24],
        inner_rows[24:26],
    ]))

    # K2: 7-row bands (KRYPTOS has 7 letters)
    partitions.append(("kryptos_7", [
        inner_rows[0:7],
        inner_rows[7:14],
        inner_rows[14:21],
        inner_rows[21:26],
    ]))

    # ── YAR-inspired (Y=24, A=0, R=17) ──

    # Y1: Split at rows corresponding to YAR values
    # Y=24→row 25 (Y in tableau), A=0→row 1, R=17→row 18
    # Boundaries at rows 1, 18, 25
    partitions.append(("yar_split", [
        inner_rows[0:17],   # rows 1-17
        inner_rows[17:24],  # rows 18-24
        inner_rows[24:26],  # rows 25-26
    ]))

    # ── All 28 rows as single band (control/baseline) ──
    partitions.append(("all_28_rows", [list(range(28))]))

    # ── No header/footer, single band ──
    partitions.append(("inner_26_rows", [inner_rows]))

    # ── Row-T split: rows where T-col <= 15 vs > 15 ──
    # (will be filled dynamically below)

    return partitions


# ── Reading orders for holes within a band ───────────────────────────────

def holes_in_rows(all_holes: List[Tuple[int, int]], rows: List[int]) -> List[Tuple[int, int]]:
    """Filter holes to only those in specified rows."""
    row_set = set(rows)
    return [(r, c) for r, c in all_holes if r in row_set]


def read_lr(holes: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Left-to-right, top-to-bottom."""
    return sorted(holes, key=lambda h: (h[0], h[1]))


def read_rl(holes: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Right-to-left, top-to-bottom."""
    return sorted(holes, key=lambda h: (h[0], -h[1]))


def read_boustro(holes: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Boustrophedon: even rows L-R, odd rows R-L."""
    by_row: Dict[int, List[Tuple[int, int]]] = defaultdict(list)
    for r, c in holes:
        by_row[r].append((r, c))
    result = []
    for i, row in enumerate(sorted(by_row.keys())):
        cells = by_row[row]
        if i % 2 == 0:
            result.extend(sorted(cells, key=lambda h: h[1]))
        else:
            result.extend(sorted(cells, key=lambda h: -h[1]))
    return result


def read_col_major(holes: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Column-major: top-to-bottom within each column, columns L-R."""
    return sorted(holes, key=lambda h: (h[1], h[0]))


def read_col_major_rl(holes: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Column-major: top-to-bottom within each column, columns R-L."""
    return sorted(holes, key=lambda h: (-h[1], h[0]))


def read_by_t_distance(holes: List[Tuple[int, int]], t_cols: Dict[int, List[int]]) -> List[Tuple[int, int]]:
    """Sort holes by distance to T-column in their row (closest first)."""
    def t_dist(h):
        r, c = h
        tcols = t_cols.get(r, [])
        if not tcols:
            return 999
        return min(abs(c - tc) for tc in tcols)
    return sorted(holes, key=lambda h: (t_dist(h), h[0], h[1]))


def read_by_t_distance_far(holes: List[Tuple[int, int]], t_cols: Dict[int, List[int]]) -> List[Tuple[int, int]]:
    """Sort holes by distance to T-column (farthest first)."""
    def t_dist(h):
        r, c = h
        tcols = t_cols.get(r, [])
        if not tcols:
            return 0
        return min(abs(c - tc) for tc in tcols)
    return sorted(holes, key=lambda h: (-t_dist(h), h[0], h[1]))


def read_spiral_cw(holes: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Approximate spiral: sort by angle from centroid."""
    if not holes:
        return []
    avg_r = sum(r for r, c in holes) / len(holes)
    avg_c = sum(c for r, c in holes) / len(holes)
    import math as m
    return sorted(holes, key=lambda h: m.atan2(h[0] - avg_r, h[1] - avg_c))


READING_ORDERS = [
    ("lr", lambda holes, tc: read_lr(holes)),
    ("rl", lambda holes, tc: read_rl(holes)),
    ("boustro", lambda holes, tc: read_boustro(holes)),
    ("col_major", lambda holes, tc: read_col_major(holes)),
    ("col_major_rl", lambda holes, tc: read_col_major_rl(holes)),
    ("t_near", lambda holes, tc: read_by_t_distance(holes, tc)),
    ("t_far", lambda holes, tc: read_by_t_distance_far(holes, tc)),
    ("spiral", lambda holes, tc: read_spiral_cw(holes)),
]


# ── 107→97 selection methods ─────────────────────────────────────────────

def select_97(ordered_holes: List[Tuple[int, int]], method: str) -> List[Tuple[int, int]]:
    """From 107 ordered holes, select 97 to produce a K4 permutation."""
    n = len(ordered_holes)
    if n < 97:
        return []

    if method == "first_97":
        return ordered_holes[:97]
    elif method == "last_97":
        return ordered_holes[n - 97:]
    elif method == "skip_hdr_ftr":
        # Remove holes from rows 0 and 27 (header/footer)
        filtered = [(r, c) for r, c in ordered_holes if r not in (0, 27)]
        return filtered[:97] if len(filtered) >= 97 else []
    elif method == "skip_first_10":
        return ordered_holes[10:107] if n >= 107 else []
    elif method == "every_other_start0":
        # Take positions 0, 2, 4, ... → 54, then fill from odd → 97
        even = ordered_holes[0::2]
        odd = ordered_holes[1::2]
        combined = even + odd
        return combined[:97]
    elif method == "modular_107_97":
        # Select indices i where (i * 97) % 107 < 97
        selected = []
        for i in range(n):
            if (i * 97) % 107 < 97:
                selected.append(ordered_holes[i])
            if len(selected) == 97:
                break
        return selected
    return []


SELECTION_METHODS = [
    "first_97", "last_97", "skip_hdr_ftr",
    "skip_first_10", "every_other_start0", "modular_107_97",
]


# ── Hole-index → K4-position mapping ────────────────────────────────────

def holes_to_perm(selected_holes: List[Tuple[int, int]], method: str) -> Optional[List[int]]:
    """Convert 97 selected holes into a permutation of K4 positions.

    Each hole maps to a K4 position (0-96). The question is HOW.
    """
    if len(selected_holes) != 97:
        return None

    if method == "sequence_index":
        # The i-th hole in reading order → position i in the output
        # This means: output[i] = CT[i], which is identity. Instead:
        # Build perm where perm[i] = the "rank" of the i-th hole
        # In other words, the ORDER of holes IS the permutation.
        # If holes are read in non-standard order, this gives a non-trivial perm.
        #
        # Actually: we want the permutation that unscrambles K4.
        # If the holes define a reading order, then:
        #   real_ct[i] = carved[perm[i]]
        # where perm is derived from the hole ordering.
        #
        # Approach: assign each hole a "natural position" (its index in standard
        # L-R T-B order), then reorder by the band reading order.
        # The resulting sequence of natural positions IS the permutation.

        # Get all 107 holes in standard order for reference
        all_holes_std = parse_mask()
        all_holes_std.sort(key=lambda h: (h[0], h[1]))

        # But we only have 97 selected holes. Build index from their standard order.
        sel_std = sorted(selected_holes, key=lambda h: (h[0], h[1]))
        std_rank = {h: i for i, h in enumerate(sel_std)}

        # The permutation: for position i in the band-ordered sequence,
        # perm[i] = the standard-order rank of that hole
        perm = []
        for h in selected_holes:
            if h in std_rank:
                perm.append(std_rank[h])
            else:
                return None
        return perm

    elif method == "col_position":
        # Use the column index of each hole (mod 97) as the permutation value
        cols = [c % 97 for r, c in selected_holes]
        # This won't be a valid permutation in general
        if len(set(cols)) != 97:
            return None
        return cols

    elif method == "row_col_hash":
        # Hash: (row * 33 + col) % 97
        vals = [(r * 33 + c) % 97 for r, c in selected_holes]
        if len(set(vals)) != 97:
            return None
        return vals

    elif method == "ka_letter_rank":
        # Extract the letter at each hole, rank them → permutation
        letters = []
        for r, c in selected_holes:
            ch = extract_letter(r, c)
            if ch is None:
                return None
            letters.append(ch)
        # Rank by (letter, position) to break ties left-to-right
        indexed = [(ch, i) for i, ch in enumerate(letters)]
        ranked = sorted(indexed, key=lambda x: (KA_IDX.get(x[0], 99), x[1]))
        perm = [0] * 97
        for rank, (_, pos) in enumerate(ranked):
            perm[pos] = rank
        return perm

    return None


PERM_METHODS = ["sequence_index", "ka_letter_rank"]


# ── Scoring ──────────────────────────────────────────────────────────────

def try_decrypt_and_score(
    real_ct: str, perm_label: str, hits: list, top_n: list, configs_tested: list,
) -> None:
    for kw_name in KEYWORDS:
        for alph_name, alph_str, alph_idx in ALPHABETS:
            key_ints = [alph_idx[kw_name[i % len(kw_name)]] for i in range(CT_LEN)]
            for variant in VARIANTS:
                pt = decrypt_text(real_ct, key_ints, variant)
                configs_tested[0] += 1

                ene_pos = pt.find("EASTNORTHEAST")
                bc_pos = pt.find("BERLINCLOCK")
                qg = qscore(pt)

                if ene_pos >= 0 or bc_pos >= 0:
                    hit = {
                        "perm": perm_label,
                        "keyword": kw_name, "alphabet": alph_name,
                        "variant": variant.value, "pt": pt,
                        "ene_pos": ene_pos, "bc_pos": bc_pos, "qg": qg,
                    }
                    hits.append(hit)
                    print(f"\n*** HIT *** {hit}")

                if len(top_n) < 20 or qg > top_n[-1][0]:
                    entry = (qg, perm_label, kw_name, alph_name, variant.value, pt[:40])
                    top_n.append(entry)
                    top_n.sort(key=lambda x: x[0], reverse=True)
                    if len(top_n) > 20:
                        top_n.pop()


def process_perm(perm, label, hits, top_n, configs_tested):
    for direction, p in [("fwd", perm), ("inv", invert_perm(perm))]:
        if not validate_perm(p, CT_LEN):
            continue
        real_ct = apply_perm(CT, p)
        try_decrypt_and_score(real_ct, f"{label}|{direction}", hits, top_n, configs_tested)


# ── Band-order permutations ─────────────────────────────────────────────

def generate_band_orders(n_bands: int) -> List[List[int]]:
    """Generate band orderings to try.

    For small n_bands (<=5), try all permutations.
    For larger, try identity, reverse, and a few shuffles.
    """
    if n_bands <= 5:
        return [list(p) for p in permutations(range(n_bands))]
    else:
        orders = [list(range(n_bands))]  # identity
        orders.append(list(range(n_bands - 1, -1, -1)))  # reverse
        # Swap adjacent pairs
        for i in range(n_bands - 1):
            o = list(range(n_bands))
            o[i], o[i + 1] = o[i + 1], o[i]
            orders.append(o)
        # Even-then-odd
        orders.append([i for i in range(n_bands) if i % 2 == 0] +
                      [i for i in range(n_bands) if i % 2 == 1])
        # Odd-then-even
        orders.append([i for i in range(n_bands) if i % 2 == 1] +
                      [i for i in range(n_bands) if i % 2 == 0])
        return orders


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 72)
    print("E-MENGEN-GRILLE-01: Mengenlehreuhr Band Structure × Cardan Grille")
    print("=" * 72)

    load_quadgrams()
    print(f"Loaded {len(QUADGRAMS)} quadgrams")

    # Parse mask
    all_holes = parse_mask()
    print(f"Parsed {len(all_holes)} holes from mask")

    # T-diagonal analysis
    t_cols = find_t_columns()
    t_boundaries = find_t_band_boundaries(t_cols)
    print(f"\nT-diagonal band boundaries at rows: {t_boundaries}")

    # Show T-column per row
    print("\nT-column positions per tableau row:")
    for r in range(28):
        tc = t_cols.get(r, [])
        holes_in_r = [(rr, cc) for rr, cc in all_holes if rr == r]
        print(f"  Row {r:2d}: T at cols {tc}, {len(holes_in_r)} holes")

    # Add T-boundary-based partition
    band_partitions = generate_band_partitions()

    # Dynamic: T-boundary partition
    if len(t_boundaries) >= 2:
        t_bands = []
        for i in range(len(t_boundaries)):
            start = t_boundaries[i]
            end = t_boundaries[i + 1] if i + 1 < len(t_boundaries) else 28
            t_bands.append(list(range(start, end)))
        band_partitions.append(("t_diagonal_gaps", t_bands))

    # Dynamic: T-col left/right split (T moves from right to left down the tableau)
    left_rows = []   # rows where T is in left half (col < 16)
    right_rows = []  # rows where T is in right half (col >= 16)
    for r in range(1, 27):
        tc = t_cols.get(r, [])
        if tc:
            if tc[0] < 16:
                left_rows.append(r)
            else:
                right_rows.append(r)
    if left_rows and right_rows:
        band_partitions.append(("t_left_right", [right_rows, left_rows]))

    print(f"\nTotal band partitions to test: {len(band_partitions)}")
    for name, bands in band_partitions:
        sizes = [len(b) for b in bands]
        total_holes = sum(len(holes_in_rows(all_holes, b)) for b in bands)
        print(f"  {name}: {len(bands)} bands, sizes={sizes}, holes={total_holes}")

    # ── Main search ──────────────────────────────────────────────────────

    hits: list = []
    top_n: list = []
    configs_tested = [0]
    perms_tested = 0

    for part_name, bands in band_partitions:
        n_bands = len(bands)
        band_orders = generate_band_orders(n_bands)

        # Limit band_orders × reading_orders to avoid explosion
        # For partitions with many band permutations, use fewer reading orders
        if len(band_orders) > 50:
            reading_subset = READING_ORDERS[:3]  # lr, rl, boustro
        else:
            reading_subset = READING_ORDERS

        for band_order in band_orders:
            for read_name, read_fn in reading_subset:
                # Build hole sequence: read each band in band_order,
                # applying reading order within each band
                ordered_holes = []
                for band_idx in band_order:
                    if band_idx < len(bands):
                        band_holes = holes_in_rows(all_holes, bands[band_idx])
                        ordered_band = read_fn(band_holes, t_cols)
                        ordered_holes.extend(ordered_band)

                if len(ordered_holes) < 97:
                    continue

                # Try different 107→97 selections
                for sel_method in SELECTION_METHODS:
                    selected = select_97(ordered_holes, sel_method)
                    if len(selected) != 97:
                        continue

                    # Try different hole→perm mappings
                    for perm_method in PERM_METHODS:
                        perm = holes_to_perm(selected, perm_method)
                        if perm is None or not validate_perm(perm, CT_LEN):
                            continue

                        bo_str = ''.join(str(b) for b in band_order)
                        label = f"{part_name}|bo{bo_str}|{read_name}|{sel_method}|{perm_method}"
                        process_perm(perm, label, hits, top_n, configs_tested)
                        perms_tested += 1

        # Progress
        elapsed = time.time() - t0
        print(f"  [{part_name}] perms={perms_tested} configs={configs_tested[0]} "
              f"hits={len(hits)} elapsed={elapsed:.0f}s")

    # ── Summary ──────────────────────────────────────────────────────────

    elapsed = time.time() - t0
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total permutations tested: {perms_tested}")
    print(f"Total decrypt configs: {configs_tested[0]}")
    print(f"Elapsed: {elapsed:.1f}s ({configs_tested[0] / max(elapsed, 0.1):.0f} configs/sec)")
    print(f"\nCrib hits: {len(hits)}")

    if hits:
        print("\n*** CRIB HITS ***")
        for h in hits:
            print(f"  ENE@{h['ene_pos']} BC@{h['bc_pos']} | {h['perm']} "
                  f"| {h['keyword']}/{h['alphabet']}/{h['variant']} | qg={h['qg']:.3f}")
            print(f"    PT: {h['pt']}")
    else:
        print("  (none)")

    print(f"\nTop 20 by quadgram score:")
    for i, (qg, label, kw, alph, var, pt_prefix) in enumerate(top_n):
        print(f"  {i + 1:2d}. qg={qg:.4f} | {kw}/{alph}/{var} | {label}")
        print(f"      PT: {pt_prefix}...")

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), "..",
                            "kbot_results", "e_mengen_grille_01.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    result = {
        "experiment": "E-MENGEN-GRILLE-01",
        "description": "Mengenlehreuhr band structure as Cardan grille reading order",
        "total_permutations": perms_tested,
        "total_configs": configs_tested[0],
        "elapsed_seconds": round(elapsed, 1),
        "crib_hits": hits,
        "t_band_boundaries": t_boundaries,
        "top_20_quadgram": [
            {"qg": qg, "label": label, "keyword": kw, "alphabet": alph,
             "variant": var, "pt_prefix": pt_prefix}
            for qg, label, kw, alph, var, pt_prefix in top_n
        ],
    }
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nResults saved to {out_path}")

    if hits:
        print("\n*** INVESTIGATE HITS IMMEDIATELY ***")
    else:
        print("\nNo crib hits. Mengenlehreuhr band-reading does not produce the K4 permutation.")


if __name__ == "__main__":
    main()
