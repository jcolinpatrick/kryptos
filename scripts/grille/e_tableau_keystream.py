#!/usr/bin/env python3
# Cipher: Cardan grille / Vigenere keystream
# Family: grille
# Status: active
# Keyspace: ~50K keystream variants x 6 decrypt modes
# Last run:
# Best score:
#
# E-TABLEAU-KEYSTREAM: Systematic Tableau Keystream Extraction
#
# HYPOTHESIS: The Cardan grille applied to the Kryptos Vigenere tableau
# produces a KEYSTREAM (running key) for decrypting K4 in its original
# positional order -- no transposition needed.
#
# Tests 9 families of reading methods on the 26x30 KA tableau body
# (plus structural elements), extracts candidate keystreams, and tries
# all 6 decrypt variants: {Vig, Beau, VarBeau} x {AZ, KA}.
#
# Scoring: quadgram fitness + fixed-position crib matching + free crib search.
#
# Usage: PYTHONPATH=src python3 -u scripts/grille/e_tableau_keystream.py

from __future__ import annotations

import json
import os
import sys
import time
import math
from collections import Counter
from itertools import product
from typing import List, Tuple, Dict, Optional
from multiprocessing import Pool, cpu_count
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
CT_LEN = 97
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(AZ)}

GRILLE_EXTRACT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
assert len(GRILLE_EXTRACT) == 100

# Cribs (0-indexed positions in carved CT)
CRIB_WORDS = [
    (21, "EASTNORTHEAST"),  # positions 21-33
    (63, "BERLINCLOCK"),    # positions 63-73
]
CRIB_DICT = {}
for start, word in CRIB_WORDS:
    for i, ch in enumerate(word):
        CRIB_DICT[start + i] = ch

# Thematic keywords for column reordering
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SANBORN", "SCHEIDT",
    "BERLIN", "CLOCK", "SHADOW", "ENIGMA", "QUARTZ",
    "COMPASS", "PHARAOH", "SPHINX", "CARTER", "EGYPT",
    "VERDIGRIS", "TRIPTYCH", "COLOPHON", "ARMATURE", "OCULUS",
    "URANIA", "LODESTONE", "DESPARATLY", "IQLUSION",
]

# ── Quadgram scorer ──────────────────────────────────────────────────────────

QUADGRAMS: Dict[str, float] = {}
QG_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qg_path = Path(__file__).resolve().parent.parent.parent / "data" / "english_quadgrams.json"
    if not qg_path.exists():
        qg_path = Path("/home/cpatrick/kryptos/data/english_quadgrams.json")
    with open(qg_path) as f:
        data = json.load(f)
    if "logp" in data:
        data = data["logp"]
    QUADGRAMS.update(data)
    QG_FLOOR = min(QUADGRAMS.values())

def qg_score(text: str) -> float:
    """Quadgram log-probability score per character."""
    t = text.upper()
    n = len(t) - 3
    if n <= 0:
        return QG_FLOOR
    total = sum(QUADGRAMS.get(t[i:i+4], QG_FLOOR) for i in range(n))
    return total / n

# ── Tableau construction ─────────────────────────────────────────────────────

def build_tableau_body() -> List[str]:
    """Build the 26x30 tableau body (KA-shifted rows, no labels)."""
    rows = []
    for r in range(26):
        row = ''.join(KA[(c + r) % 26] for c in range(30))
        rows.append(row)
    return rows

TABLEAU_BODY = build_tableau_body()  # 26 rows x 30 cols

def build_full_grid() -> List[str]:
    """Build the full 28x31 grid with header, footer, key column, extra L."""
    header = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
    footer = header
    grid = []
    # Row 0: header (prepend space for key column alignment)
    grid.append(" " + header)  # 31 chars
    # Rows 1-26: key label + body
    for r in range(26):
        key_letter = AZ[r]
        body = TABLEAU_BODY[r]
        row = key_letter + body
        # Row 14 (Key N, r=13) has extra L
        if r == 13:
            row = row + "L"  # 32 chars total
        grid.append(row)
    # Row 27: footer
    grid.append(" " + footer)  # 31 chars
    return grid

FULL_GRID = build_full_grid()

# ── Decrypt functions ────────────────────────────────────────────────────────

def decrypt_vig_az(ct: str, key: str) -> str:
    out = []
    for i, c in enumerate(ct):
        ci = AZ_IDX[c]
        ki = AZ_IDX[key[i % len(key)]]
        out.append(AZ[(ci - ki) % 26])
    return ''.join(out)

def decrypt_beau_az(ct: str, key: str) -> str:
    out = []
    for i, c in enumerate(ct):
        ci = AZ_IDX[c]
        ki = AZ_IDX[key[i % len(key)]]
        out.append(AZ[(ki - ci) % 26])
    return ''.join(out)

def decrypt_varbeau_az(ct: str, key: str) -> str:
    out = []
    for i, c in enumerate(ct):
        ci = AZ_IDX[c]
        ki = AZ_IDX[key[i % len(key)]]
        out.append(AZ[(ci + ki) % 26])
    return ''.join(out)

def decrypt_vig_ka(ct: str, key: str) -> str:
    out = []
    for i, c in enumerate(ct):
        ci = KA_IDX[c]
        ki = KA_IDX[key[i % len(key)]]
        out.append(KA[(ci - ki) % 26])
    return ''.join(out)

def decrypt_beau_ka(ct: str, key: str) -> str:
    out = []
    for i, c in enumerate(ct):
        ci = KA_IDX[c]
        ki = KA_IDX[key[i % len(key)]]
        out.append(KA[(ki - ci) % 26])
    return ''.join(out)

def decrypt_varbeau_ka(ct: str, key: str) -> str:
    out = []
    for i, c in enumerate(ct):
        ci = KA_IDX[c]
        ki = KA_IDX[key[i % len(key)]]
        out.append(KA[(ci + ki) % 26])
    return ''.join(out)

DECRYPT_MODES = [
    ("Vig-AZ", decrypt_vig_az),
    ("Beau-AZ", decrypt_beau_az),
    ("VarBeau-AZ", decrypt_varbeau_az),
    ("Vig-KA", decrypt_vig_ka),
    ("Beau-KA", decrypt_beau_ka),
    ("VarBeau-KA", decrypt_varbeau_ka),
]

# ── Scoring ──────────────────────────────────────────────────────────────────

def score_cribs_fixed(pt: str) -> int:
    """Count how many crib positions match (anchored)."""
    count = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == ch:
            count += 1
    return count

def score_cribs_free(pt: str) -> Tuple[bool, bool, int]:
    """Check if EASTNORTHEAST or BERLINCLOCK appear anywhere."""
    ene = "EASTNORTHEAST" in pt
    bc = "BERLINCLOCK" in pt
    count = 0
    if ene:
        count += 13
    if bc:
        count += 11
    return ene, bc, count

def evaluate_keystream(keystream: str, label: str) -> List[dict]:
    """Try all 6 decrypt modes with this keystream. Return list of results."""
    if len(keystream) < CT_LEN:
        return []

    key = keystream[:CT_LEN]
    results = []

    for mode_name, decrypt_fn in DECRYPT_MODES:
        pt = decrypt_fn(CT, key)
        qg = qg_score(pt)
        crib_fixed = score_cribs_fixed(pt)
        ene, bc, crib_free = score_cribs_free(pt)

        results.append({
            "label": label,
            "mode": mode_name,
            "qg_score": qg,
            "crib_fixed": crib_fixed,
            "crib_free": crib_free,
            "ene_found": ene,
            "bc_found": bc,
            "plaintext": pt,
            "keystream": key[:20] + "...",
        })

    return results

# ── Keystream generators ─────────────────────────────────────────────────────

def gen_diagonal_reads() -> List[Tuple[str, str]]:
    """Generate keystreams by reading the tableau diagonally."""
    body = TABLEAU_BODY
    nrows, ncols = 26, 30
    keystreams = []

    # NW-SE diagonals (top-left to bottom-right)
    for start_col in range(ncols):
        chars = []
        for step in range(max(nrows, ncols)):
            r, c = step, start_col + step
            if r < nrows:
                chars.append(body[r][c % ncols])
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"diag-NWSE-col{start_col}", ks))

    for start_row in range(1, nrows):
        chars = []
        for step in range(max(nrows, ncols)):
            r, c = start_row + step, step
            if r < nrows:
                chars.append(body[r][c % ncols])
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"diag-NWSE-row{start_row}", ks))

    # NE-SW diagonals (top-right to bottom-left)
    for start_col in range(ncols):
        chars = []
        for step in range(max(nrows, ncols)):
            r, c = step, start_col - step
            if r < nrows:
                chars.append(body[r][c % ncols])
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"diag-NESW-col{start_col}", ks))

    for start_row in range(1, nrows):
        chars = []
        for step in range(max(nrows, ncols)):
            r, c = start_row + step, ncols - 1 - step
            if r < nrows:
                chars.append(body[r][c % ncols])
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"diag-NESW-row{start_row}", ks))

    # Full NW-SE diagonal with wrapping: start at (0,0), step (1,1) mod dims
    for start_col in range(ncols):
        chars = []
        r, c = 0, start_col
        for _ in range(nrows * ncols):
            chars.append(body[r % nrows][c % ncols])
            r += 1
            c += 1
            if r >= nrows and c >= ncols:
                break
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"diag-wrap-NWSE-col{start_col}", ks))

    # Full NE-SW diagonal with wrapping
    for start_col in range(ncols):
        chars = []
        r, c = 0, start_col
        for _ in range(nrows * ncols):
            chars.append(body[r % nrows][c % ncols])
            r += 1
            c -= 1
            if r >= nrows:
                break
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"diag-wrap-NESW-col{start_col}", ks))

    # Diagonal with various step sizes
    for dr in range(1, 6):
        for dc in range(1, 6):
            if dr == 1 and dc == 1:
                continue  # already covered
            for start_c in range(ncols):
                chars = []
                r, c = 0, start_c
                visited = set()
                while (r % nrows, c % ncols) not in visited and len(chars) < 200:
                    visited.add((r % nrows, c % ncols))
                    chars.append(body[r % nrows][c % ncols])
                    r += dr
                    c += dc
                ks = ''.join(chars)
                if len(ks) >= CT_LEN:
                    keystreams.append((f"diag-step{dr}x{dc}-col{start_c}", ks))

    return keystreams


def gen_spiral_reads() -> List[Tuple[str, str]]:
    """Generate keystreams by reading the tableau in spiral order."""
    body = TABLEAU_BODY
    nrows, ncols = 26, 30
    keystreams = []

    def spiral_cw(rows, cols):
        """Read a grid in clockwise spiral from outside in."""
        order = []
        top, bot, left, right = 0, rows - 1, 0, cols - 1
        while top <= bot and left <= right:
            for c in range(left, right + 1):
                order.append((top, c))
            top += 1
            for r in range(top, bot + 1):
                order.append((r, right))
            right -= 1
            if top <= bot:
                for c in range(right, left - 1, -1):
                    order.append((bot, c))
                bot -= 1
            if left <= right:
                for r in range(bot, top - 1, -1):
                    order.append((r, left))
                left += 1
        return order

    def spiral_ccw(rows, cols):
        """Read a grid in counter-clockwise spiral from outside in."""
        order = []
        top, bot, left, right = 0, rows - 1, 0, cols - 1
        while top <= bot and left <= right:
            for r in range(top, bot + 1):
                order.append((r, left))
            left += 1
            for c in range(left, right + 1):
                order.append((bot, c))
            bot -= 1
            if left <= right:
                for r in range(bot, top - 1, -1):
                    order.append((r, right))
                right -= 1
            if top <= bot:
                for c in range(right, left - 1, -1):
                    order.append((top, c))
                top += 1
        return order

    # Clockwise spiral
    order_cw = spiral_cw(nrows, ncols)
    ks_cw = ''.join(body[r][c] for r, c in order_cw)
    keystreams.append(("spiral-CW-outside-in", ks_cw))
    keystreams.append(("spiral-CW-inside-out", ks_cw[::-1]))

    # Counter-clockwise spiral
    order_ccw = spiral_ccw(nrows, ncols)
    ks_ccw = ''.join(body[r][c] for r, c in order_ccw)
    keystreams.append(("spiral-CCW-outside-in", ks_ccw))
    keystreams.append(("spiral-CCW-inside-out", ks_ccw[::-1]))

    # Spiral on the full 28x31 grid
    full = FULL_GRID
    full_nrows, full_ncols = len(full), max(len(r) for r in full)
    order_full_cw = spiral_cw(full_nrows, full_ncols)
    chars = []
    for r, c in order_full_cw:
        if r < len(full) and c < len(full[r]):
            ch = full[r][c]
            if ch.isalpha():
                chars.append(ch)
    ks_full = ''.join(chars)
    keystreams.append(("spiral-CW-full28x31", ks_full))
    keystreams.append(("spiral-CW-full28x31-rev", ks_full[::-1]))

    return keystreams


def gen_column_reads() -> List[Tuple[str, str]]:
    """Generate keystreams by reading columns in various orders."""
    body = TABLEAU_BODY
    nrows, ncols = 26, 30
    keystreams = []

    def read_columns(col_order, top_to_bottom=True):
        chars = []
        for c in col_order:
            if top_to_bottom:
                for r in range(nrows):
                    chars.append(body[r][c % ncols])
            else:
                for r in range(nrows - 1, -1, -1):
                    chars.append(body[r][c % ncols])
        return ''.join(chars)

    # Left-to-right, top-to-bottom
    ks = read_columns(range(ncols), True)
    keystreams.append(("cols-LR-TB", ks))

    # Right-to-left, top-to-bottom
    ks = read_columns(range(ncols - 1, -1, -1), True)
    keystreams.append(("cols-RL-TB", ks))

    # Left-to-right, bottom-to-top
    ks = read_columns(range(ncols), False)
    keystreams.append(("cols-LR-BT", ks))

    # Boustrophedon (snake): alternating TB and BT per column
    chars = []
    for c in range(ncols):
        if c % 2 == 0:
            for r in range(nrows):
                chars.append(body[r][c])
        else:
            for r in range(nrows - 1, -1, -1):
                chars.append(body[r][c])
    keystreams.append(("cols-boustrophedon", ''.join(chars)))

    # Keyword-ordered columns
    for keyword in KEYWORDS:
        kw = keyword.upper()
        # Deduplicate
        seen = []
        for ch in kw:
            if ch not in seen and ch in AZ:
                seen.append(ch)
        if len(seen) < 2:
            continue
        # Column permutation from keyword ranking
        indexed = sorted(range(len(seen)), key=lambda i: seen[i])
        # Map to column indices (cycle if keyword shorter than ncols)
        col_order = []
        for i in indexed:
            col_order.append(i)
        # Extend: use keyword length as block size
        kw_len = len(seen)
        full_col_order = []
        n_blocks = (ncols + kw_len - 1) // kw_len
        for block in range(n_blocks):
            for rank in indexed:
                col = block * kw_len + rank
                if col < ncols:
                    full_col_order.append(col)

        ks = read_columns(full_col_order, True)
        keystreams.append((f"cols-kw-{keyword}-TB", ks))

        ks = read_columns(full_col_order, False)
        keystreams.append((f"cols-kw-{keyword}-BT", ks))

    return keystreams


def gen_row_reads() -> List[Tuple[str, str]]:
    """Generate keystreams by reading rows in various orders."""
    body = TABLEAU_BODY
    nrows, ncols = 26, 30
    keystreams = []

    # Standard row-by-row
    ks = ''.join(body[r] for r in range(nrows))
    keystreams.append(("rows-TB-LR", ks))

    # Reverse row order
    ks = ''.join(body[r] for r in range(nrows - 1, -1, -1))
    keystreams.append(("rows-BT-LR", ks))

    # Rows right-to-left
    ks = ''.join(body[r][::-1] for r in range(nrows))
    keystreams.append(("rows-TB-RL", ks))

    # Boustrophedon rows
    chars = []
    for r in range(nrows):
        if r % 2 == 0:
            chars.append(body[r])
        else:
            chars.append(body[r][::-1])
    keystreams.append(("rows-boustrophedon", ''.join(chars)))

    # Keyword-ordered rows: use keyword to permute row reading order
    for keyword in KEYWORDS:
        kw = keyword.upper()
        seen = []
        for ch in kw:
            if ch not in seen and ch in AZ:
                seen.append(ch)
        if len(seen) < 2:
            continue

        # Map keyword letters to row indices (AZ order)
        indexed = sorted(range(len(seen)), key=lambda i: seen[i])
        kw_len = len(seen)
        full_row_order = []
        n_blocks = (nrows + kw_len - 1) // kw_len
        for block in range(n_blocks):
            for rank in indexed:
                row = block * kw_len + rank
                if row < nrows:
                    full_row_order.append(row)

        ks = ''.join(body[r] for r in full_row_order)
        keystreams.append((f"rows-kw-{keyword}", ks))

    # Keyword-reordered columns within rows
    for keyword in KEYWORDS[:8]:  # Top keywords only
        kw = keyword.upper()
        seen = []
        for ch in kw:
            if ch not in seen and ch in AZ:
                seen.append(ch)
        if len(seen) < 2:
            continue

        indexed = sorted(range(len(seen)), key=lambda i: seen[i])
        kw_len = len(seen)
        full_col_order = []
        n_blocks = (ncols + kw_len - 1) // kw_len
        for block in range(n_blocks):
            for rank in indexed:
                col = block * kw_len + rank
                if col < ncols:
                    full_col_order.append(col)

        chars = []
        for r in range(nrows):
            for c in full_col_order:
                chars.append(body[r][c])
        keystreams.append((f"rows-colreorder-{keyword}", ''.join(chars)))

    return keystreams


def gen_knight_reads() -> List[Tuple[str, str]]:
    """Generate keystreams using knight's move pattern on the tableau."""
    body = TABLEAU_BODY
    nrows, ncols = 26, 30
    keystreams = []

    # Knight moves: (dr, dc) pairs
    knight_moves = [
        (2, 1), (2, -1), (-2, 1), (-2, -1),
        (1, 2), (1, -2), (-1, 2), (-1, -2),
    ]

    # L-shaped reads with wrapping
    for move_idx, (dr, dc) in enumerate(knight_moves):
        for start_r in range(0, nrows, 5):
            for start_c in range(0, ncols, 5):
                chars = []
                visited = set()
                r, c = start_r, start_c
                while len(chars) < 200:
                    key = (r % nrows, c % ncols)
                    if key in visited:
                        break
                    visited.add(key)
                    chars.append(body[key[0]][key[1]])
                    r += dr
                    c += dc
                ks = ''.join(chars)
                if len(ks) >= CT_LEN:
                    keystreams.append((f"knight-m{move_idx}-r{start_r}c{start_c}", ks))

    # Extended knight: larger L-shapes
    for dr, dc in [(3, 1), (3, -1), (1, 3), (1, -3), (5, 2), (2, 5)]:
        for start_r in range(0, nrows, 7):
            for start_c in range(0, ncols, 7):
                chars = []
                visited = set()
                r, c = start_r, start_c
                while len(chars) < 200:
                    key = (r % nrows, c % ncols)
                    if key in visited:
                        break
                    visited.add(key)
                    chars.append(body[key[0]][key[1]])
                    r += dr
                    c += dc
                ks = ''.join(chars)
                if len(ks) >= CT_LEN:
                    keystreams.append((f"knight-ext-{dr}x{dc}-r{start_r}c{start_c}", ks))

    return keystreams


def gen_grille_extract_variants() -> List[Tuple[str, str]]:
    """Generate keystreams from the known 100-char grille extract."""
    ge = GRILLE_EXTRACT
    keystreams = []

    # Pad to 100 chars, we need 97 — take first 97 or various subsets

    # Direct use (first 97)
    keystreams.append(("grille-extract-fwd", ge[:97]))
    # Reversed
    keystreams.append(("grille-extract-rev", ge[::-1][:97]))

    # All 100 rotations
    for shift in range(100):
        rotated = ge[shift:] + ge[:shift]
        keystreams.append((f"grille-extract-rot{shift}", rotated[:97]))

    # Reversed rotations
    ge_rev = ge[::-1]
    for shift in range(100):
        rotated = ge_rev[shift:] + ge_rev[:shift]
        keystreams.append((f"grille-extract-revrot{shift}", rotated[:97]))

    # Interleave odd/even positions
    even = ''.join(ge[i] for i in range(0, 100, 2))  # 50 chars
    odd = ''.join(ge[i] for i in range(1, 100, 2))   # 50 chars
    interleaved_eo = even + odd
    keystreams.append(("grille-extract-even-odd", interleaved_eo[:97]))
    interleaved_oe = odd + even
    keystreams.append(("grille-extract-odd-even", interleaved_oe[:97]))

    # Re-interleave: take alternating from even and odd halves
    first_half = ge[:50]
    second_half = ge[50:]
    interleaved_halves = ''.join(
        first_half[i] + second_half[i] for i in range(50)
    )
    keystreams.append(("grille-extract-fold-interleave", interleaved_halves[:97]))

    interleaved_halves_rev = ''.join(
        second_half[i] + first_half[i] for i in range(50)
    )
    keystreams.append(("grille-extract-fold-interleave-rev", interleaved_halves_rev[:97]))

    # Skip every Nth character
    for skip in [2, 3, 5, 7]:
        chars = [ge[i] for i in range(0, 100, skip)]
        remaining = [ge[i] for i in range(100) if i % skip != 0]
        combined = chars + remaining
        keystreams.append((f"grille-extract-skip{skip}", ''.join(combined[:97])))

    # Read in blocks of various sizes
    for block_size in [7, 8, 10, 13]:
        blocks = [ge[i:i+block_size] for i in range(0, 100, block_size)]
        reversed_blocks = [b[::-1] for b in blocks]
        ks = ''.join(reversed_blocks)
        keystreams.append((f"grille-extract-blockrev{block_size}", ks[:97]))

    # Rail fence on grille extract
    for rails in [2, 3, 5, 7]:
        fence = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for ch in ge:
            fence[rail].append(ch)
            rail += direction
            if rail == rails - 1 or rail == 0:
                direction = -direction
        ks = ''.join(''.join(f) for f in fence)
        keystreams.append((f"grille-extract-railfence{rails}", ks[:97]))

    return keystreams


def gen_grid_position_reads() -> List[Tuple[str, str]]:
    """Generate keystreams based on 28x31 grid positions corresponding to K4."""
    keystreams = []

    # K4 starts at row 24, col 27 in the 28x31 cipher panel grid
    # (from the CLAUDE.md: K4 at row 24, col 27)
    # The K4 text fills: row 24 cols 27-30 (4 chars), row 25 (31 chars),
    # row 26 (31 chars), row 27 (31 chars) = 4+31+31+31 = 97

    k4_positions = []
    # Row 24, starting at col 27
    for c in range(27, 31):
        k4_positions.append((24, c))
    # Rows 25-27, full width (cols 0-30)
    for r in range(25, 28):
        for c in range(31):
            k4_positions.append((r, c))
    # Should be 4 + 31*3 = 97
    assert len(k4_positions) == 97, f"Got {len(k4_positions)} K4 positions"

    # Read the TABLEAU at those same positions
    full = FULL_GRID
    chars = []
    for r, c in k4_positions:
        if r < len(full) and c < len(full[r]):
            ch = full[r][c]
            if ch.isalpha():
                chars.append(ch)
            else:
                chars.append('A')  # placeholder for spaces
        else:
            chars.append('A')
    ks = ''.join(chars)
    keystreams.append(("grid-K4-positions-on-tableau", ks))

    # Read tableau at K4 positions in reverse
    keystreams.append(("grid-K4-positions-on-tableau-rev", ks[::-1]))

    # Read the full grid row-by-row, extract just the K4 corresponding positions
    linear_full = []
    for r in range(len(full)):
        for c in range(len(full[r])):
            ch = full[r][c]
            if ch.isalpha():
                linear_full.append(ch)
    # Use the same linear positions as K4 would occupy in a 28x31 flat array
    k4_linear_start = 24 * 31 + 27  # row 24, col 27
    chars = []
    for offset in range(CT_LEN):
        idx = k4_linear_start + offset
        if idx < len(linear_full):
            chars.append(linear_full[idx])
        else:
            # Wrap around
            chars.append(linear_full[idx % len(linear_full)])
    keystreams.append(("grid-K4-linear-on-tableau", ''.join(chars)))

    # Use the Antipodes overlap: K4 at bottom of grid, tableau at bottom rows
    # Read bottom 4 rows of tableau (rows 24-27)
    bottom_chars = []
    for r in range(24, 28):
        if r < len(full):
            for c in range(len(full[r])):
                ch = full[r][c]
                if ch.isalpha():
                    bottom_chars.append(ch)
    ks = ''.join(bottom_chars)
    keystreams.append(("grid-bottom4rows-tableau", ks[:97] if len(ks) >= 97 else ks))

    # 180-degree rotation: K4 ↔ K1 (rows mirror)
    # K4 row 24-27 maps to K1 rows 3-0 under 180° rotation
    mirror_chars = []
    for r in [3, 2, 1, 0]:
        if r < len(full):
            row = full[r][::-1]  # also reverse columns for 180°
            for ch in row:
                if ch.isalpha():
                    mirror_chars.append(ch)
    ks = ''.join(mirror_chars)
    keystreams.append(("grid-180rot-K1-mirror", ks[:97] if len(ks) >= 97 else ks))

    return keystreams


def gen_key_column_seed_reads() -> List[Tuple[str, str]]:
    """Generate keystreams using the key column (A-Z) as seed for row selection."""
    body = TABLEAU_BODY
    nrows, ncols = 26, 30
    keystreams = []

    # Method: for each position i in K4, use CT[i] to pick a row,
    # then read a specific column or use some pattern
    for col_strategy in ["fixed", "sequential", "ct_column", "reverse"]:
        for base_col in range(ncols):
            chars = []
            for i, ct_ch in enumerate(CT):
                row = AZ_IDX[ct_ch]  # CT letter determines row
                if col_strategy == "fixed":
                    c = base_col
                elif col_strategy == "sequential":
                    c = (base_col + i) % ncols
                elif col_strategy == "ct_column":
                    c = AZ_IDX.get(ct_ch, 0) % ncols
                elif col_strategy == "reverse":
                    c = (ncols - 1 - base_col - i) % ncols
                else:
                    c = base_col
                chars.append(body[row][c])
            keystreams.append((f"keycol-{col_strategy}-c{base_col}", ''.join(chars)))

    # Method: use keyword letters to select rows, cycle the keyword
    for keyword in KEYWORDS[:8]:
        kw = keyword.upper()
        for col_start in range(0, ncols, 5):
            chars = []
            for i in range(CT_LEN):
                row = AZ_IDX.get(kw[i % len(kw)], 0)
                c = (col_start + i) % ncols
                chars.append(body[row][c])
            keystreams.append((f"keycol-kw-{keyword}-c{col_start}", ''.join(chars)))

    # Method: CT[i] selects column, keyword letter selects row
    for keyword in KEYWORDS[:8]:
        kw = keyword.upper()
        chars = []
        for i, ct_ch in enumerate(CT):
            row = AZ_IDX.get(kw[i % len(kw)], 0)
            c = AZ_IDX[ct_ch] % ncols
            chars.append(body[row][c])
        keystreams.append((f"keycol-cw-{keyword}", ''.join(chars)))

    return keystreams


def gen_stepping_reads() -> List[Tuple[str, str]]:
    """Generate keystreams by stepping through the linearized tableau."""
    body = TABLEAU_BODY
    nrows, ncols = 26, 30
    total = nrows * ncols  # 780
    keystreams = []

    # Linearize
    linear = ''.join(body[r][c] for r in range(nrows) for c in range(ncols))

    # Every Nth character with various starting positions
    for step in range(1, 40):
        for start in range(min(step, 10)):
            chars = []
            pos = start
            visited = set()
            while len(chars) < CT_LEN and pos not in visited:
                visited.add(pos)
                chars.append(linear[pos % total])
                pos = (pos + step) % total
                if len(visited) > total:
                    break
            if len(chars) >= CT_LEN:
                keystreams.append((f"step{step}-start{start}", ''.join(chars[:CT_LEN])))

    # Steps coprime to 780 give full cycles
    for step in range(1, total):
        if math.gcd(step, total) == 1:
            chars = []
            pos = 0
            for _ in range(CT_LEN):
                chars.append(linear[pos])
                pos = (pos + step) % total
            keystreams.append((f"coprime-step{step}", ''.join(chars)))
        if step > 200:  # cap for performance
            break

    return keystreams


# ── Main evaluation engine ───────────────────────────────────────────────────

def evaluate_batch(args):
    """Evaluate a batch of keystreams. For multiprocessing."""
    keystreams, batch_id = args
    results = []
    for label, ks in keystreams:
        res_list = evaluate_keystream(ks, label)
        for res in res_list:
            if res["qg_score"] > -5.5 or res["crib_fixed"] > 3 or res["crib_free"] > 0:
                results.append(res)
    return results


def main():
    t_start = time.time()
    print("=" * 78)
    print("  E-TABLEAU-KEYSTREAM: Systematic Tableau Keystream Extraction")
    print("=" * 78)
    print(f"  CT: {CT}")
    print(f"  KA: {KA}")
    print(f"  Grille extract (100): {GRILLE_EXTRACT}")
    print()

    # Load quadgrams
    load_quadgrams()
    print(f"  Loaded {len(QUADGRAMS)} quadgrams, floor={QG_FLOOR:.4f}")

    # Output directory
    out_dir = Path("/home/cpatrick/kryptos/results/tableau_keystream")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Generate all keystreams
    print("\n  Generating keystreams...")
    sys.stdout.flush()

    generators = [
        ("1-Diagonal", gen_diagonal_reads),
        ("2-Spiral", gen_spiral_reads),
        ("3-Column", gen_column_reads),
        ("4-Row", gen_row_reads),
        ("5-Knight", gen_knight_reads),
        ("6-GrilleExtract", gen_grille_extract_variants),
        ("7-GridPosition", gen_grid_position_reads),
        ("8-KeyColumnSeed", gen_key_column_seed_reads),
        ("9-Stepping", gen_stepping_reads),
    ]

    all_keystreams: List[Tuple[str, str]] = []
    family_counts = {}

    for family_name, gen_fn in generators:
        ks_list = gen_fn()
        family_counts[family_name] = len(ks_list)
        all_keystreams.extend(ks_list)
        print(f"    {family_name}: {len(ks_list)} keystreams")
        sys.stdout.flush()

    total_ks = len(all_keystreams)
    total_tests = total_ks * 6  # 6 decrypt modes
    print(f"\n  Total keystreams: {total_ks}")
    print(f"  Total decrypt tests: {total_tests}")
    sys.stdout.flush()

    # Evaluate all keystreams
    print("\n  Evaluating keystreams...")
    sys.stdout.flush()

    all_results = []
    best_qg = -99.0
    best_crib = 0
    progress_count = 0

    # Process in batches for progress reporting
    batch_size = 500
    for i in range(0, len(all_keystreams), batch_size):
        batch = all_keystreams[i:i + batch_size]
        for label, ks in batch:
            res_list = evaluate_keystream(ks, label)
            for res in res_list:
                # Track best scores
                if res["qg_score"] > best_qg:
                    best_qg = res["qg_score"]
                if res["crib_fixed"] > best_crib:
                    best_crib = res["crib_fixed"]

                # Keep results above threshold
                if res["qg_score"] > -5.5 or res["crib_fixed"] > 3 or res["crib_free"] > 0:
                    all_results.append(res)

        progress_count += len(batch)
        elapsed = time.time() - t_start
        rate = progress_count / elapsed if elapsed > 0 else 0
        print(f"    Progress: {progress_count}/{total_ks} keystreams "
              f"({elapsed:.1f}s, {rate:.0f}/s) | "
              f"best_qg={best_qg:.3f} best_crib={best_crib}")
        sys.stdout.flush()

    # Sort results
    all_results.sort(key=lambda r: (-r["qg_score"], -r["crib_fixed"]))

    # Report
    print("\n" + "=" * 78)
    print("  RESULTS")
    print("=" * 78)
    print(f"\n  Total results above threshold: {len(all_results)}")
    print(f"  Best quadgram score: {best_qg:.4f}")
    print(f"  Best fixed crib hits: {best_crib}/24")

    # Top results by quadgram score
    print(f"\n  {'='*78}")
    print(f"  TOP 30 BY QUADGRAM SCORE")
    print(f"  {'='*78}")
    for i, res in enumerate(all_results[:30]):
        print(f"  {i+1:3d}. qg={res['qg_score']:.4f} | "
              f"cribs_fixed={res['crib_fixed']}/24 | "
              f"cribs_free={res['crib_free']}/24 | "
              f"{res['mode']:12s} | {res['label']}")
        print(f"       PT: {res['plaintext'][:60]}...")

    # Top results by crib score
    crib_sorted = sorted(all_results, key=lambda r: (-r["crib_fixed"], -r["qg_score"]))
    if crib_sorted and crib_sorted[0]["crib_fixed"] > 0:
        print(f"\n  {'='*78}")
        print(f"  TOP BY CRIB HITS")
        print(f"  {'='*78}")
        for i, res in enumerate(crib_sorted[:20]):
            if res["crib_fixed"] == 0 and res["crib_free"] == 0:
                break
            print(f"  {i+1:3d}. cribs_fixed={res['crib_fixed']}/24 | "
                  f"cribs_free={res['crib_free']}/24 | "
                  f"qg={res['qg_score']:.4f} | "
                  f"{res['mode']:12s} | {res['label']}")
            print(f"       PT: {res['plaintext'][:60]}...")
            if res["ene_found"]:
                idx = res["plaintext"].find("EASTNORTHEAST")
                print(f"       *** EASTNORTHEAST found at position {idx} ***")
            if res["bc_found"]:
                idx = res["plaintext"].find("BERLINCLOCK")
                print(f"       *** BERLINCLOCK found at position {idx} ***")

    # Save results
    results_file = out_dir / "results.json"
    with open(results_file, 'w') as f:
        json.dump({
            "experiment": "E-TABLEAU-KEYSTREAM",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_keystreams": total_ks,
            "total_decrypt_tests": total_tests,
            "results_above_threshold": len(all_results),
            "best_qg_score": best_qg,
            "best_crib_fixed": best_crib,
            "family_counts": family_counts,
            "top_results": all_results[:100],
        }, f, indent=2)
    print(f"\n  Results saved to {results_file}")

    # Summary stats per family
    print(f"\n  {'='*78}")
    print(f"  FAMILY SUMMARY")
    print(f"  {'='*78}")

    family_best = {}
    for res in all_results:
        label = res["label"]
        # Determine family from label prefix
        family = label.split("-")[0] if "-" in label else label
        for gen_name, _ in generators:
            short = gen_name.split("-")[1] if "-" in gen_name else gen_name
            if label.startswith(short.lower()[:4]):
                family = gen_name
                break
        if family not in family_best or res["qg_score"] > family_best[family]["qg_score"]:
            family_best[family] = res

    for family, res in sorted(family_best.items()):
        print(f"  {family:25s}: best_qg={res['qg_score']:.4f} | "
              f"crib_fixed={res['crib_fixed']} | "
              f"{res['mode']} | {res['label']}")

    elapsed = time.time() - t_start
    print(f"\n  Total time: {elapsed:.1f}s")
    print(f"\n{'='*78}")
    print(f"  E-TABLEAU-KEYSTREAM: COMPLETE")
    print(f"{'='*78}")


if __name__ == "__main__":
    main()
