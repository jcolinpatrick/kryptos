#!/usr/bin/env python3
# Cipher: Vigenere/Beaufort with tableau-derived OTP keystream
# Family: grille
# Status: active
# Keyspace: ~1.5M extraction patterns x 6 decrypt modes (constraint-pruned)
# Last run:
# Best score:
#
# E-TABLEAU-OTP: Vigenere Tableau as One-Time Pad Source
#
# HYPOTHESIS: A specific reading pattern through the Kryptos Vigenere tableau
# extracts a 97-character non-repeating keystream that decrypts K4.
#
# KEY INNOVATION: Constraint-guided pruning.  For each cipher variant (Vig/Beau/
# VarBeau x AZ/KA), the required keystream values at all 24 crib positions are
# known exactly.  Any extraction pattern that doesn't produce those exact key
# values at the crib positions is immediately rejected -- no full decryption
# needed.  This typically rejects >99.9% of candidates instantly.
#
# Eight extraction families tested:
#   1. Diagonal reads (main, anti, offset, wrapping, all 26x26)
#   2. Knight's move (all 8 directions, all 676 starts on 26x26)
#   3. Spiral reads (CW/CCW from corners/center, 26x26 and 28x31)
#   4. Row-skip patterns (skip 1-25, forward/reverse columns)
#   5. Fibonacci/prime stepping through linearized 676/780 cells
#   6. Key-column guided (AZ key column selects column from each row)
#   7. HOROLOGE-guided (H,O,R,O,L,O,G,E selects rows/cols cyclically)
#   8. KRYPTOS-guided (K,R,Y,P,T,O,S selects rows/cols cyclically)
#
# Scoring: score_candidate() (anchored) + score_candidate_free() (free search)
#          + quadgram fitness for above-threshold candidates.
#
# Usage: PYTHONPATH=src python3 -u scripts/grille/e_tableau_otp.py

from __future__ import annotations

import json
import math
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

# ── Import from kernel (canonical constants) ─────────────────────────────────

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_WORDS, N_CRIBS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.alphabet import AZ as AZ_ALPH, KA as KA_ALPH
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# ── Local constants ──────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
AZ = ALPH
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(AZ)}

# ── Quadgram scorer ──────────────────────────────────────────────────────────

QUADGRAMS: Dict[str, float] = {}
QG_FLOOR = -10.0


def load_quadgrams():
    global QUADGRAMS, QG_FLOOR
    qg_path = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
    with open(qg_path) as f:
        data = json.load(f)
    if "logp" in data:
        data = data["logp"]
    QUADGRAMS.update(data)
    QG_FLOOR = min(QUADGRAMS.values())


def qg_score(text: str) -> float:
    t = text.upper()
    n = len(t) - 3
    if n <= 0:
        return QG_FLOOR
    total = sum(QUADGRAMS.get(t[i:i + 4], QG_FLOOR) for i in range(n))
    return total / n


# ── Tableau construction ─────────────────────────────────────────────────────

def build_tableau_26x26() -> List[str]:
    """Build the 26x26 KA-shifted Vigenere square body.

    Row r (0-indexed, key letter = AZ[r]) has body:
       KA[(AZ_IDX[key] + c) % 26]  for c in 0..25

    This matches the documented construction rule:
       For key letter with AZ index i, body = KA[i:] + KA[:i]
    """
    rows = []
    for r in range(26):
        # key letter = AZ[r], shift = AZ_IDX[AZ[r]] = r
        row = ''.join(KA[(r + c) % 26] for c in range(26))
        rows.append(row)
    return rows


def build_tableau_26x30() -> List[str]:
    """Build the 26x30 tableau body (26 rows, 30 columns with wrap)."""
    rows = []
    for r in range(26):
        row = ''.join(KA[(r + c) % 26] for c in range(30))
        rows.append(row)
    return rows


def build_full_grid_28x31() -> List[str]:
    """Build the full 28x31 grid with header, footer, key column, extra L."""
    header = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCD"
    body_26x30 = build_tableau_26x30()
    grid = []
    # Row 0: space + header (31 chars)
    grid.append(" " + header)
    # Rows 1-26: key label + 30-char body
    for r in range(26):
        key_letter = AZ[r]
        row = key_letter + body_26x30[r]
        # Row 14 (key=N, r=13 in 0-based body) has extra L
        if r == 13:
            row = row + "L"  # 32 chars total
        grid.append(row)
    # Row 27: space + footer
    grid.append(" " + header)
    return grid


BODY_26x26 = build_tableau_26x26()
BODY_26x30 = build_tableau_26x30()
FULL_GRID = build_full_grid_28x31()

# Linearized 26x26 (676 cells) and 26x30 (780 cells)
LINEAR_26x26 = ''.join(BODY_26x26)
LINEAR_26x30 = ''.join(BODY_26x30)

# ── Decrypt functions ────────────────────────────────────────────────────────


def decrypt_vig_az(ct: str, key: str) -> str:
    return ''.join(AZ[(AZ_IDX[c] - AZ_IDX[key[i]]) % 26] for i, c in enumerate(ct))


def decrypt_beau_az(ct: str, key: str) -> str:
    return ''.join(AZ[(AZ_IDX[key[i]] - AZ_IDX[c]) % 26] for i, c in enumerate(ct))


def decrypt_varbeau_az(ct: str, key: str) -> str:
    return ''.join(AZ[(AZ_IDX[c] + AZ_IDX[key[i]]) % 26] for i, c in enumerate(ct))


def decrypt_vig_ka(ct: str, key: str) -> str:
    return ''.join(KA[(KA_IDX[c] - KA_IDX[key[i]]) % 26] for i, c in enumerate(ct))


def decrypt_beau_ka(ct: str, key: str) -> str:
    return ''.join(KA[(KA_IDX[key[i]] - KA_IDX[c]) % 26] for i, c in enumerate(ct))


def decrypt_varbeau_ka(ct: str, key: str) -> str:
    return ''.join(KA[(KA_IDX[c] + KA_IDX[key[i]]) % 26] for i, c in enumerate(ct))


DECRYPT_MODES = [
    ("Vig-AZ", decrypt_vig_az),
    ("Beau-AZ", decrypt_beau_az),
    ("VarBeau-AZ", decrypt_varbeau_az),
    ("Vig-KA", decrypt_vig_ka),
    ("Beau-KA", decrypt_beau_ka),
    ("VarBeau-KA", decrypt_varbeau_ka),
]

# ── Constraint-guided pruning ────────────────────────────────────────────────
#
# For each (variant, alphabet) combo, we know the exact keystream value at each
# of the 24 crib positions.  Given a candidate keystream (as letters), we check
# whether the keystream letters at crib positions produce the expected key values.
#
# Required key values by variant (from constants.py):
#   Vig-AZ:  K[i] = (CT[i] - PT[i]) mod 26   in AZ
#   Beau-AZ: K[i] = (CT[i] + PT[i]) mod 26   in AZ  (since PT = K - CT → K = PT + CT)
#   VarBeau-AZ: K[i] = (PT[i] - CT[i]) mod 26  in AZ  (since PT = CT + K → K = PT - CT)
#
# For KA variants, same formulas but using KA indices.
#
# We precompute the required KEY LETTER at each crib position for each mode.


def compute_required_key_letters() -> Dict[str, Dict[int, str]]:
    """For each decrypt mode, compute the required keystream letter at each
    crib position.

    Returns dict: mode_name -> {position -> required_key_letter}
    """
    required = {}

    for pos, pt_ch in CRIB_DICT.items():
        ct_ch = CT[pos]

        # Vig-AZ: PT = (CT - K) mod 26 → K = (CT - PT) mod 26
        k_val = (AZ_IDX[ct_ch] - AZ_IDX[pt_ch]) % 26
        required.setdefault("Vig-AZ", {})[pos] = AZ[k_val]

        # Beau-AZ: PT = (K - CT) mod 26 → K = (PT + CT) mod 26
        k_val = (AZ_IDX[pt_ch] + AZ_IDX[ct_ch]) % 26
        required.setdefault("Beau-AZ", {})[pos] = AZ[k_val]

        # VarBeau-AZ: PT = (CT + K) mod 26 → K = (PT - CT) mod 26
        k_val = (AZ_IDX[pt_ch] - AZ_IDX[ct_ch]) % 26
        required.setdefault("VarBeau-AZ", {})[pos] = AZ[k_val]

        # Vig-KA: PT = (CT - K) mod 26 in KA → K = (CT - PT) mod 26 in KA
        k_val = (KA_IDX[ct_ch] - KA_IDX[pt_ch]) % 26
        required.setdefault("Vig-KA", {})[pos] = KA[k_val]

        # Beau-KA: PT = (K - CT) mod 26 in KA → K = (PT + CT) mod 26 in KA
        k_val = (KA_IDX[pt_ch] + KA_IDX[ct_ch]) % 26
        required.setdefault("Beau-KA", {})[pos] = KA[k_val]

        # VarBeau-KA: PT = (CT + K) mod 26 in KA → K = (PT - CT) mod 26 in KA
        k_val = (KA_IDX[pt_ch] - KA_IDX[ct_ch]) % 26
        required.setdefault("VarBeau-KA", {})[pos] = KA[k_val]

    return required


REQUIRED_KEYS = compute_required_key_letters()


def count_key_matches(keystream: str, mode_name: str) -> int:
    """Count how many crib positions have the correct key letter."""
    req = REQUIRED_KEYS[mode_name]
    count = 0
    for pos, needed in req.items():
        if pos < len(keystream) and keystream[pos] == needed:
            count += 1
    return count


def best_mode_matches(keystream: str) -> Tuple[str, int]:
    """Find the decrypt mode with the most key matches for this keystream."""
    best_mode = ""
    best_count = 0
    for mode_name in REQUIRED_KEYS:
        c = count_key_matches(keystream, mode_name)
        if c > best_count:
            best_count = c
            best_mode = mode_name
    return best_mode, best_count


# ── Keystream extraction families ────────────────────────────────────────────


def gen_diagonals() -> List[Tuple[str, str]]:
    """Family 1: Diagonal/step reads on the 26x30 and 26x26 bodies.

    KEY INSIGHT: On 26x26, max cycle length is 26 (too short for 97).
    On 26x30, cycles can reach 390, and 528+ step patterns produce >= 97 cells.
    We focus on 26x30 for unique-cell reads, and use 26x26 only with revisits.
    """
    keystreams = []

    # ── 26x30 body: unique-cell stepping (main source of candidates) ──
    body30 = BODY_26x30
    nr, nc = 26, 30
    for dr in range(1, nr):
        for dc in range(1, nc):
            # Try multiple starting positions
            starts = []
            if dr <= 5 and dc <= 5:
                starts = [(sr, sc) for sr in range(0, nr, 2)
                          for sc in range(0, nc, 2)]
            else:
                starts = [(sr, sc) for sr in range(0, nr, 4)
                          for sc in range(0, nc, 4)]
            for start_r, start_c in starts:
                chars = []
                visited = set()
                r, c = start_r, start_c
                while len(chars) < CT_LEN:
                    key = (r % nr, c % nc)
                    if key in visited:
                        break
                    visited.add(key)
                    chars.append(body30[key[0]][key[1]])
                    r += dr
                    c += dc
                if len(chars) >= CT_LEN:
                    keystreams.append((f"diag30-{dr}x{dc}-r{start_r}c{start_c}",
                                      ''.join(chars[:CT_LEN])))

    # Also try negative dc (anti-diagonal direction) on 26x30
    for dr in range(1, nr):
        for dc in range(1, nc):
            for start_r, start_c in [(0, 0), (0, nc - 1), (0, nc // 2),
                                     (nr // 2, 0), (nr // 2, nc // 2)]:
                chars = []
                visited = set()
                r, c = start_r, start_c
                while len(chars) < CT_LEN:
                    key = (r % nr, c % nc)
                    if key in visited:
                        break
                    visited.add(key)
                    chars.append(body30[key[0]][key[1]])
                    r += dr
                    c = (c - dc) % nc  # negative column step
                if len(chars) >= CT_LEN:
                    keystreams.append((f"diag30-{dr}xm{dc}-r{start_r}c{start_c}",
                                      ''.join(chars[:CT_LEN])))

    # ── 26x26 body: wrapping reads with revisits ──
    body = BODY_26x26
    n = 26
    # Take first 97 cells visited (may revisit same cell)
    for dr in range(1, n):
        for dc in range(1, n):
            for start_c in range(0, n, max(1, n // 7)):
                chars = []
                r, c = 0, start_c
                for _ in range(CT_LEN):
                    chars.append(body[r % n][c % n])
                    r += dr
                    c += dc
                keystreams.append((f"diag26-revisit-{dr}x{dc}-c{start_c}",
                                  ''.join(chars)))

    # Anti-diagonal revisits on 26x26
    for dr in range(1, n):
        for dc in range(1, n):
            for start_c in range(0, n, max(1, n // 7)):
                chars = []
                r, c = 0, start_c
                for _ in range(CT_LEN):
                    chars.append(body[r % n][c % n])
                    r += dr
                    c -= dc
                keystreams.append((f"diag26-revisit-{dr}xm{dc}-c{start_c}",
                                  ''.join(chars)))

    return keystreams


def gen_knights() -> List[Tuple[str, str]]:
    """Family 2: Knight's move patterns on 26x26 and 26x30.

    On a 26x26 grid, knight (2,1) steps with wrapping visit gcd-dependent
    cycle lengths.  Many cycles are shorter than 97.  We handle this by:
      a) Trying all 8 standard knight directions on 26x26 with unique cells
      b) Trying knight moves on 26x30 (where cycle lengths differ)
      c) Allowing revisits (non-unique): just take first 97 positions visited
    """
    keystreams = []

    knight_moves = [
        (2, 1), (2, -1), (-2, 1), (-2, -1),
        (1, 2), (1, -2), (-1, 2), (-1, -2),
    ]

    ext_moves = [
        (3, 1), (3, -1), (1, 3), (1, -3),
        (3, 2), (3, -2), (2, 3), (2, -3),
        (5, 2), (5, -2), (2, 5), (2, -5),
        (4, 1), (4, -1), (1, 4), (1, -4),
        (5, 3), (5, -3), (3, 5), (3, -5),
    ]

    all_moves = knight_moves + ext_moves

    # On 26x26 body (unique cells)
    body = BODY_26x26
    n = 26
    for mi, (dr, dc) in enumerate(all_moves):
        for start_r in range(n):
            for start_c in range(n):
                chars = []
                visited = set()
                r, c = start_r, start_c
                while len(chars) < CT_LEN:
                    key = (r % n, c % n)
                    if key in visited:
                        break
                    visited.add(key)
                    chars.append(body[key[0]][key[1]])
                    r += dr
                    c += dc
                if len(chars) >= CT_LEN:
                    keystreams.append((f"knight26-m{mi}-r{start_r}c{start_c}",
                                      ''.join(chars[:CT_LEN])))

    # On 26x30 body (unique cells) -- more room for longer cycles
    body30 = BODY_26x30
    nr, nc = 26, 30
    for mi, (dr, dc) in enumerate(all_moves):
        # Sample starting positions (every 2nd to limit explosion)
        for start_r in range(0, nr, 2):
            for start_c in range(0, nc, 2):
                chars = []
                visited = set()
                r, c = start_r, start_c
                while len(chars) < CT_LEN:
                    key = (r % nr, c % nc)
                    if key in visited:
                        break
                    visited.add(key)
                    chars.append(body30[key[0]][key[1]])
                    r += dr
                    c += dc
                if len(chars) >= CT_LEN:
                    keystreams.append((f"knight30-m{mi}-r{start_r}c{start_c}",
                                      ''.join(chars[:CT_LEN])))

    # Knight moves with revisits allowed (first 97 positions, may repeat cells)
    for mi, (dr, dc) in enumerate(knight_moves):
        for start_r in range(0, n, 4):
            for start_c in range(0, n, 4):
                chars = []
                r, c = start_r, start_c
                for _ in range(CT_LEN):
                    chars.append(body[r % n][c % n])
                    r += dr
                    c += dc
                keystreams.append((f"knight26-revisit-m{mi}-r{start_r}c{start_c}",
                                  ''.join(chars)))

    return keystreams


def gen_spirals() -> List[Tuple[str, str]]:
    """Family 3: Spiral reads (CW/CCW) from all 4 corners and center."""
    keystreams = []

    def spiral_cw(rows, cols):
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

    # 26x26 body
    body = BODY_26x26
    for name, order_fn in [("CW", spiral_cw), ("CCW", spiral_ccw)]:
        order = order_fn(26, 26)
        ks = ''.join(body[r][c] for r, c in order)
        keystreams.append((f"spiral-{name}-26x26-outside-in", ks[:CT_LEN]))
        keystreams.append((f"spiral-{name}-26x26-inside-out", ks[::-1][:CT_LEN]))

    # 26x30 body
    body30 = BODY_26x30
    for name, order_fn in [("CW", spiral_cw), ("CCW", spiral_ccw)]:
        order = order_fn(26, 30)
        ks = ''.join(body30[r][c] for r, c in order)
        keystreams.append((f"spiral-{name}-26x30-outside-in", ks[:CT_LEN]))
        keystreams.append((f"spiral-{name}-26x30-inside-out", ks[::-1][:CT_LEN]))

    # 28x31 full grid (skip non-alpha)
    full = FULL_GRID
    max_cols = max(len(row) for row in full)
    for name, order_fn in [("CW", spiral_cw), ("CCW", spiral_ccw)]:
        order = order_fn(28, max_cols)
        chars = []
        for r, c in order:
            if r < len(full) and c < len(full[r]):
                ch = full[r][c]
                if ch.isalpha():
                    chars.append(ch)
        ks = ''.join(chars)
        keystreams.append((f"spiral-{name}-28x31-outside-in", ks[:CT_LEN]))
        keystreams.append((f"spiral-{name}-28x31-inside-out", ks[::-1][:CT_LEN]))

    # Spiral from each corner (rotated spirals)
    # Start CW from bottom-right: reverse the outside-in order
    # Start CW from top-right: flip columns
    body = BODY_26x26
    order_cw = spiral_cw(26, 26)

    # From bottom-right: reverse
    ks = ''.join(body[r][c] for r, c in reversed(order_cw))
    keystreams.append(("spiral-CW-26x26-from-BR", ks[:CT_LEN]))

    # From top-right: mirror columns
    ks = ''.join(body[r][25 - c] for r, c in order_cw)
    keystreams.append(("spiral-CW-26x26-from-TR", ks[:CT_LEN]))

    # From bottom-left: mirror rows
    ks = ''.join(body[25 - r][c] for r, c in order_cw)
    keystreams.append(("spiral-CW-26x26-from-BL", ks[:CT_LEN]))

    # Center-out spiral: approximate by starting at (13,13)
    # Use distance from center to order cells
    cells = [(r, c) for r in range(26) for c in range(26)]
    cells_by_dist = sorted(cells, key=lambda rc: (
        max(abs(rc[0] - 13), abs(rc[1] - 13)),  # Chebyshev distance
        rc[0], rc[1]
    ))
    ks = ''.join(body[r][c] for r, c in cells_by_dist)
    keystreams.append(("spiral-center-out-chebyshev", ks[:CT_LEN]))

    cells_by_euclid = sorted(cells, key=lambda rc: (
        (rc[0] - 13) ** 2 + (rc[1] - 13) ** 2,
        rc[0], rc[1]
    ))
    ks = ''.join(body[r][c] for r, c in cells_by_euclid)
    keystreams.append(("spiral-center-out-euclidean", ks[:CT_LEN]))

    return keystreams


def gen_row_skip() -> List[Tuple[str, str]]:
    """Family 4: Row-skip patterns.

    Read row 0, skip N rows, read row N, etc.
    Within each row: forward or reversed.
    """
    body = BODY_26x26
    n = 26
    keystreams = []

    for skip in range(1, 26):
        # Determine row order: 0, skip, 2*skip, ... (mod 26)
        row_order = []
        visited = set()
        r = 0
        while len(row_order) < n:
            if r not in visited:
                visited.add(r)
                row_order.append(r)
            r = (r + skip) % n
            if r in visited and len(row_order) < n:
                # Find next unvisited
                for candidate in range(n):
                    if candidate not in visited:
                        r = candidate
                        break
                else:
                    break

        if len(row_order) < 4:
            continue

        # Forward columns
        chars = []
        for ri in row_order:
            chars.extend(body[ri])
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"rowskip-{skip}-fwd", ks[:CT_LEN]))

        # Reversed columns
        chars = []
        for ri in row_order:
            chars.extend(reversed(body[ri]))
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"rowskip-{skip}-rev", ks[:CT_LEN]))

        # Boustrophedon (alternating direction)
        chars = []
        for idx, ri in enumerate(row_order):
            if idx % 2 == 0:
                chars.extend(body[ri])
            else:
                chars.extend(reversed(body[ri]))
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"rowskip-{skip}-boustro", ks[:CT_LEN]))

    # Also try column-skip patterns (read column 0, skip N cols, etc.)
    for skip in range(1, 26):
        col_order = []
        visited = set()
        c = 0
        while len(col_order) < n:
            if c not in visited:
                visited.add(c)
                col_order.append(c)
            c = (c + skip) % n
            if c in visited and len(col_order) < n:
                for candidate in range(n):
                    if candidate not in visited:
                        c = candidate
                        break
                else:
                    break

        if len(col_order) < 4:
            continue

        chars = []
        for ci in col_order:
            for r in range(n):
                chars.append(body[r][ci])
        ks = ''.join(chars)
        if len(ks) >= CT_LEN:
            keystreams.append((f"colskip-{skip}-fwd", ks[:CT_LEN]))

    return keystreams


def gen_fibonacci_prime() -> List[Tuple[str, str]]:
    """Family 5: Fibonacci/prime stepping through linearized grid cells."""
    keystreams = []

    # Generate Fibonacci numbers
    fibs = [1, 1]
    while len(fibs) < 200:
        fibs.append(fibs[-1] + fibs[-2])

    # Generate primes up to 1000
    def sieve(limit):
        is_prime = [True] * (limit + 1)
        is_prime[0] = is_prime[1] = False
        for i in range(2, int(limit ** 0.5) + 1):
            if is_prime[i]:
                for j in range(i * i, limit + 1, i):
                    is_prime[j] = False
        return [i for i in range(2, limit + 1) if is_prime[i]]

    primes = sieve(1000)

    for grid_size, linear in [(676, LINEAR_26x26), (780, LINEAR_26x30)]:
        grid_label = "26x26" if grid_size == 676 else "26x30"

        # Fibonacci stepping: pos[i] = (pos[i-1] + fib[i]) mod grid_size
        for start in range(0, grid_size, grid_size // 26):
            chars = []
            visited = set()
            pos = start
            for i in range(CT_LEN):
                if pos % grid_size in visited:
                    pos = (pos + 1) % grid_size
                    attempts = 0
                    while pos % grid_size in visited and attempts < grid_size:
                        pos = (pos + 1) % grid_size
                        attempts += 1
                    if attempts >= grid_size:
                        break
                visited.add(pos % grid_size)
                chars.append(linear[pos % grid_size])
                fib_step = fibs[i % len(fibs)]
                pos = (pos + fib_step) % grid_size
            if len(chars) >= CT_LEN:
                keystreams.append((f"fib-step-{grid_label}-s{start}",
                                  ''.join(chars[:CT_LEN])))

        # Fibonacci positions directly: read cell at fib[i] mod grid_size
        chars = [linear[fibs[i] % grid_size] for i in range(CT_LEN)]
        keystreams.append((f"fib-direct-{grid_label}", ''.join(chars)))

        # Prime stepping: pos[i] = (pos[i-1] + prime[i]) mod grid_size
        for start in range(0, grid_size, grid_size // 26):
            chars = []
            visited = set()
            pos = start
            for i in range(CT_LEN):
                if pos % grid_size in visited:
                    pos = (pos + 1) % grid_size
                    attempts = 0
                    while pos % grid_size in visited and attempts < grid_size:
                        pos = (pos + 1) % grid_size
                        attempts += 1
                    if attempts >= grid_size:
                        break
                visited.add(pos % grid_size)
                chars.append(linear[pos % grid_size])
                prime_step = primes[i % len(primes)]
                pos = (pos + prime_step) % grid_size
            if len(chars) >= CT_LEN:
                keystreams.append((f"prime-step-{grid_label}-s{start}",
                                  ''.join(chars[:CT_LEN])))

        # Prime positions directly
        chars = [linear[primes[i] % grid_size] for i in range(CT_LEN)]
        keystreams.append((f"prime-direct-{grid_label}", ''.join(chars)))

        # Triangular numbers: T(n) = n*(n+1)/2
        tri = [i * (i + 1) // 2 for i in range(CT_LEN)]
        chars = [linear[t % grid_size] for t in tri]
        keystreams.append((f"triangular-{grid_label}", ''.join(chars)))

        # Powers of 2
        pow2 = [2 ** i for i in range(CT_LEN)]
        chars = [linear[p % grid_size] for p in pow2]
        keystreams.append((f"pow2-{grid_label}", ''.join(chars)))

        # Golden ratio stepping: pos = floor(i * phi) mod grid_size
        phi = (1 + math.sqrt(5)) / 2
        chars = [linear[int(i * phi) % grid_size] for i in range(CT_LEN)]
        keystreams.append((f"golden-ratio-{grid_label}", ''.join(chars)))

        # Coprime steps through the grid (full cycles)
        for step in range(1, min(grid_size, 300)):
            if math.gcd(step, grid_size) == 1:
                chars = []
                pos = 0
                for _ in range(CT_LEN):
                    chars.append(linear[pos])
                    pos = (pos + step) % grid_size
                keystreams.append((f"coprime-{step}-{grid_label}",
                                  ''.join(chars)))

    return keystreams


def gen_key_column_guided() -> List[Tuple[str, str]]:
    """Family 6: Key-column guided extraction.

    The Kryptos tableau has a key column (A-Z in AZ order, not KA).
    Use each key column letter to select which column to read from that row.
    """
    body = BODY_26x26
    keystreams = []

    # Method A: Key letter → its AZ index → column number
    # For each row r (key=AZ[r]), read column AZ_IDX[AZ[r]] = r
    # This just reads the main diagonal — already in diagonals family.
    # But try with offsets
    for offset in range(26):
        chars = []
        for r in range(26):
            c = (r + offset) % 26
            chars.append(body[r][c])
        # Repeat rows to get 97 chars: cycle
        full = ''.join(chars)
        extended = (full * 4)[:CT_LEN]
        keystreams.append((f"keycol-AZidx-off{offset}", extended))

    # Method B: Key letter → its KA index → column number
    for offset in range(26):
        chars = []
        for r in range(26):
            key_letter = AZ[r]
            c = (KA_IDX[key_letter] + offset) % 26
            chars.append(body[r][c])
        extended = (''.join(chars) * 4)[:CT_LEN]
        keystreams.append((f"keycol-KAidx-off{offset}", extended))

    # Method C: Permutation based: for pos i in K4, use CT[i] to find key row,
    # then read column i%26
    for col_strategy in range(26):
        chars = []
        for i in range(CT_LEN):
            ct_ch = CT[i]
            row = AZ_IDX[ct_ch]
            c = (i + col_strategy) % 26
            chars.append(body[row][c])
        keystreams.append((f"keycol-CTrow-col{col_strategy}", ''.join(chars)))

    # Method D: Key column letter maps to a column index through AZ->KA permutation
    # For each of 26 rows, the key letter determines a "scrambled" column
    # The AZ->KA permutation has cycles (17-cycle, 8-cycle, fixed Z)
    az_to_ka_perm = [KA_IDX[AZ[i]] for i in range(26)]
    for offset in range(26):
        chars = []
        for r in range(26):
            c = (az_to_ka_perm[r] + offset) % 26
            chars.append(body[r][c])
        extended = (''.join(chars) * 4)[:CT_LEN]
        keystreams.append((f"keycol-AZtoKA-off{offset}", extended))

    # Method E: Read one character per row, column determined by successive
    # key-column letters (treating key column as a keystream selector)
    # Key column = A,B,C,...,Z. For position i, row = i%26, col = AZ_IDX[key[i%26]]
    # With additional offset
    for offset in range(26):
        chars = []
        for i in range(CT_LEN):
            r = i % 26
            key_ch = AZ[r]  # key column letter for this row
            c = (AZ_IDX[key_ch] + offset + i // 26) % 26
            chars.append(body[r][c])
        keystreams.append((f"keycol-progressive-off{offset}", ''.join(chars)))

    return keystreams


def gen_horologe_guided() -> List[Tuple[str, str]]:
    """Family 7: HOROLOGE-guided extraction.

    Use H,O,R,O,L,O,G,E (8 letters) to select rows or columns from the tableau,
    cycling through HOROLOGE.
    """
    body = BODY_26x26
    n = 26
    keyword = "HOROLOGE"
    kw_len = len(keyword)
    keystreams = []

    # Method A: HOROLOGE selects row, column = i (sequential)
    for col_offset in range(n):
        chars = []
        for i in range(CT_LEN):
            row = AZ_IDX[keyword[i % kw_len]]
            c = (col_offset + i) % n
            chars.append(body[row][c])
        keystreams.append((f"horologe-rowsel-coff{col_offset}", ''.join(chars)))

    # Method B: HOROLOGE selects column, row = i (sequential)
    for row_offset in range(n):
        chars = []
        for i in range(CT_LEN):
            r = (row_offset + i) % n
            col = AZ_IDX[keyword[i % kw_len]]
            chars.append(body[r][col])
        keystreams.append((f"horologe-colsel-roff{row_offset}", ''.join(chars)))

    # Method C: HOROLOGE letter as KA index for row selection
    for col_offset in range(n):
        chars = []
        for i in range(CT_LEN):
            row = KA_IDX[keyword[i % kw_len]]
            c = (col_offset + i) % n
            chars.append(body[row][c])
        keystreams.append((f"horologe-KArowsel-coff{col_offset}", ''.join(chars)))

    # Method D: HOROLOGE for row, CT[i] for column
    chars = []
    for i in range(CT_LEN):
        row = AZ_IDX[keyword[i % kw_len]]
        col = AZ_IDX[CT[i]] % n
        chars.append(body[row][col])
    keystreams.append(("horologe-row-CTcol", ''.join(chars)))

    chars = []
    for i in range(CT_LEN):
        row = KA_IDX[keyword[i % kw_len]]
        col = KA_IDX[CT[i]] % n
        chars.append(body[row][col])
    keystreams.append(("horologe-KArow-KAcol-CT", ''.join(chars)))

    # Method E: HOROLOGE as step size through linearized grid
    linear = LINEAR_26x26
    for start in range(0, 676, 26):
        chars = []
        pos = start
        visited = set()
        for i in range(CT_LEN):
            p = pos % 676
            if p in visited:
                # Skip to next unvisited
                attempts = 0
                while p in visited and attempts < 676:
                    p = (p + 1) % 676
                    attempts += 1
                if attempts >= 676:
                    break
            visited.add(p)
            chars.append(linear[p])
            step = AZ_IDX[keyword[i % kw_len]] + 1
            pos = p + step
        if len(chars) >= CT_LEN:
            keystreams.append((f"horologe-stepsize-s{start}",
                              ''.join(chars[:CT_LEN])))

    # Method F: Double keyword — HOROLOGE for row, KRYPTOS for column offset
    kw2 = "KRYPTOS"
    for base_offset in range(n):
        chars = []
        for i in range(CT_LEN):
            row = AZ_IDX[keyword[i % kw_len]]
            col = (AZ_IDX[kw2[i % len(kw2)]] + base_offset) % n
            chars.append(body[row][col])
        keystreams.append((f"horologe-row-kryptos-col-off{base_offset}",
                          ''.join(chars)))

    # Also try with other priority keywords
    for kw2_name in ["PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX", "COLOPHON"]:
        chars = []
        for i in range(CT_LEN):
            row = AZ_IDX[keyword[i % kw_len]]
            col = AZ_IDX[kw2_name[i % len(kw2_name)]] % n
            chars.append(body[row][col])
        keystreams.append((f"horologe-row-{kw2_name}-col", ''.join(chars)))

    return keystreams


def gen_kryptos_guided() -> List[Tuple[str, str]]:
    """Family 8: KRYPTOS-guided extraction (7 letters)."""
    body = BODY_26x26
    n = 26
    keyword = "KRYPTOS"
    kw_len = len(keyword)
    keystreams = []

    # Method A: KRYPTOS selects row, column = i (sequential)
    for col_offset in range(n):
        chars = []
        for i in range(CT_LEN):
            row = AZ_IDX[keyword[i % kw_len]]
            c = (col_offset + i) % n
            chars.append(body[row][c])
        keystreams.append((f"kryptos-rowsel-coff{col_offset}", ''.join(chars)))

    # Method B: KRYPTOS selects column, row = i
    for row_offset in range(n):
        chars = []
        for i in range(CT_LEN):
            r = (row_offset + i) % n
            col = AZ_IDX[keyword[i % kw_len]]
            chars.append(body[r][col])
        keystreams.append((f"kryptos-colsel-roff{row_offset}", ''.join(chars)))

    # Method C: KRYPTOS as KA index
    for col_offset in range(n):
        chars = []
        for i in range(CT_LEN):
            row = KA_IDX[keyword[i % kw_len]]
            c = (col_offset + i) % n
            chars.append(body[row][c])
        keystreams.append((f"kryptos-KArowsel-coff{col_offset}", ''.join(chars)))

    # Method D: KRYPTOS row, CT[i] column
    chars = []
    for i in range(CT_LEN):
        row = AZ_IDX[keyword[i % kw_len]]
        col = AZ_IDX[CT[i]] % n
        chars.append(body[row][col])
    keystreams.append(("kryptos-row-CTcol", ''.join(chars)))

    # Method E: KRYPTOS as step sizes
    linear = LINEAR_26x26
    for start in range(0, 676, 26):
        chars = []
        pos = start
        visited = set()
        for i in range(CT_LEN):
            p = pos % 676
            if p in visited:
                attempts = 0
                while p in visited and attempts < 676:
                    p = (p + 1) % 676
                    attempts += 1
                if attempts >= 676:
                    break
            visited.add(p)
            chars.append(linear[p])
            step = AZ_IDX[keyword[i % kw_len]] + 1
            pos = p + step
        if len(chars) >= CT_LEN:
            keystreams.append((f"kryptos-stepsize-s{start}",
                              ''.join(chars[:CT_LEN])))

    # Method F: Double keyword — KRYPTOS row, HOROLOGE column
    kw2 = "HOROLOGE"
    for base_offset in range(n):
        chars = []
        for i in range(CT_LEN):
            row = AZ_IDX[keyword[i % kw_len]]
            col = (AZ_IDX[kw2[i % len(kw2)]] + base_offset) % n
            chars.append(body[row][col])
        keystreams.append((f"kryptos-row-horologe-col-off{base_offset}",
                          ''.join(chars)))

    # Other priority keywords as column selectors
    for kw2_name in ["PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX", "COLOPHON"]:
        chars = []
        for i in range(CT_LEN):
            row = AZ_IDX[keyword[i % kw_len]]
            col = AZ_IDX[kw2_name[i % len(kw2_name)]] % n
            chars.append(body[row][col])
        keystreams.append((f"kryptos-row-{kw2_name}-col", ''.join(chars)))

    # Method G: ABSCISSA, PALIMPSEST as row selectors too (K1/K2 keywords)
    for kw_name, kw_str in [("ABSCISSA", "ABSCISSA"),
                             ("PALIMPSEST", "PALIMPSEST")]:
        kwl = len(kw_str)
        for col_offset in range(n):
            chars = []
            for i in range(CT_LEN):
                row = AZ_IDX[kw_str[i % kwl]]
                c = (col_offset + i) % n
                chars.append(body[row][c])
            keystreams.append((f"{kw_name}-rowsel-coff{col_offset}", ''.join(chars)))

    return keystreams


# ── Main evaluation engine ───────────────────────────────────────────────────

def evaluate_all(keystreams: List[Tuple[str, str]], family_name: str,
                 stats: dict, results: list, constraint_threshold: int = 4):
    """Evaluate keystreams with constraint-guided pruning.

    For each keystream:
      1. Check key matches against all 6 modes (24 checks each = 144 total)
      2. If any mode has >= constraint_threshold matches, do full decrypt
      3. Score with both anchored and free crib scoring

    Args:
        keystreams: list of (label, keystream_string)
        family_name: for reporting
        stats: mutable dict for statistics
        results: mutable list to accumulate results
        constraint_threshold: minimum key matches to proceed with full decrypt
    """
    total = len(keystreams)
    pruned = 0
    evaluated = 0

    for idx, (label, ks) in enumerate(keystreams):
        if len(ks) < CT_LEN:
            continue

        ks97 = ks[:CT_LEN]

        # Constraint check: find best mode match count
        best_mode, best_count = best_mode_matches(ks97)

        if best_count < constraint_threshold:
            pruned += 1
            # Track max pruned score for diagnostics
            if best_count > stats.get("max_pruned_matches", 0):
                stats["max_pruned_matches"] = best_count
            continue

        # This keystream passed constraint filter -- do full evaluation
        evaluated += 1

        for mode_name, decrypt_fn in DECRYPT_MODES:
            match_count = count_key_matches(ks97, mode_name)
            if match_count < constraint_threshold:
                continue

            pt = decrypt_fn(CT, ks97)
            qg = qg_score(pt)

            # Anchored crib score
            from kryptos.kernel.scoring.crib_score import score_cribs
            crib_fixed = score_cribs(pt)

            # Free crib score
            from kryptos.kernel.scoring.free_crib import score_free_fast
            crib_free = score_free_fast(pt)

            result = {
                "label": label,
                "family": family_name,
                "mode": mode_name,
                "key_matches": match_count,
                "qg_score": qg,
                "crib_fixed": crib_fixed,
                "crib_free": crib_free,
                "plaintext": pt,
                "keystream_head": ks97[:30],
            }

            # Track bests
            if qg > stats.get("best_qg", -99.0):
                stats["best_qg"] = qg
                stats["best_qg_result"] = result
            if crib_fixed > stats.get("best_crib_fixed", 0):
                stats["best_crib_fixed"] = crib_fixed
                stats["best_crib_result"] = result
            if crib_free > stats.get("best_crib_free", 0):
                stats["best_crib_free"] = crib_free
            if match_count > stats.get("best_key_matches", 0):
                stats["best_key_matches"] = match_count

            # Store if interesting
            if (qg > -5.5 or crib_fixed > 3 or crib_free > 0 or
                    match_count >= 6):
                results.append(result)

            # Breakthrough check
            if crib_fixed >= 18 or crib_free >= 13:
                print(f"\n  *** SIGNAL DETECTED ***")
                print(f"  Label: {label}")
                print(f"  Mode: {mode_name}")
                print(f"  Key matches: {match_count}/24")
                print(f"  Crib fixed: {crib_fixed}/24")
                print(f"  Crib free: {crib_free}/24")
                print(f"  QG: {qg:.4f}")
                print(f"  PT: {pt}")
                print(f"  KS: {ks97}")
                sys.stdout.flush()

        if evaluated % 500 == 0 and evaluated > 0:
            print(f"    {family_name}: {idx + 1}/{total} checked, "
                  f"{evaluated} evaluated, {pruned} pruned, "
                  f"best_keys={stats.get('best_key_matches', 0)}, "
                  f"best_qg={stats.get('best_qg', -99):.3f}")
            sys.stdout.flush()

    stats["total_keystreams"] = stats.get("total_keystreams", 0) + total
    stats["total_pruned"] = stats.get("total_pruned", 0) + pruned
    stats["total_evaluated"] = stats.get("total_evaluated", 0) + evaluated

    return evaluated, pruned


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    print("=" * 78)
    print("  E-TABLEAU-OTP: Vigenere Tableau as One-Time Pad Source")
    print("=" * 78)
    print(f"  CT: {CT}")
    print(f"  CT_LEN: {CT_LEN}")
    print(f"  KA: {KA}")
    print(f"  AZ: {AZ}")
    print()

    # Verify tableau construction
    print("  Verifying tableau construction...")
    assert BODY_26x26[0] == KA, f"Row 0 should be KA, got {BODY_26x26[0]}"
    # Row for key A (AZ index 0): body starts at KA[0] = K
    assert BODY_26x26[0][0] == 'K', f"Body[0][0] should be K, got {BODY_26x26[0][0]}"
    # Row for key K (AZ index 10): body = KA[10:] + KA[:10]
    # KA = KRYPTOSABCDEFGHIJLMNQUVWXZ, so KA[10] = D
    assert BODY_26x26[10][0] == 'D', f"Body[10][0] should be D, got {BODY_26x26[10][0]}"
    # Row for key Z (AZ index 25): body = KA[25:] + KA[:25] → starts with Z
    assert BODY_26x26[25][0] == 'Z', f"Body[25][0] should be Z, got {BODY_26x26[25][0]}"
    print("  Tableau verified OK.")

    # Print required key letters for reference
    print("\n  Required keystream letters at crib positions:")
    print("  " + "-" * 70)
    for mode_name in sorted(REQUIRED_KEYS.keys()):
        req = REQUIRED_KEYS[mode_name]
        ene_keys = ''.join(req[pos] for pos in range(21, 34))
        bc_keys = ''.join(req[pos] for pos in range(63, 74))
        print(f"  {mode_name:12s}: ENE@21-33=[{ene_keys}]  BC@63-73=[{bc_keys}]")
    print()

    # Load quadgrams
    load_quadgrams()
    print(f"  Loaded {len(QUADGRAMS)} quadgrams, floor={QG_FLOOR:.4f}")

    # Output directory
    out_dir = Path(__file__).resolve().parents[2] / "results" / "tableau_otp"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Global stats and results
    stats: Dict[str, object] = {
        "best_qg": -99.0,
        "best_crib_fixed": 0,
        "best_crib_free": 0,
        "best_key_matches": 0,
        "max_pruned_matches": 0,
        "total_keystreams": 0,
        "total_pruned": 0,
        "total_evaluated": 0,
    }
    all_results: List[dict] = []

    # Generate and evaluate each family
    families = [
        ("1-Diagonals", gen_diagonals),
        ("2-Knights", gen_knights),
        ("3-Spirals", gen_spirals),
        ("4-RowSkip", gen_row_skip),
        ("5-FibPrime", gen_fibonacci_prime),
        ("6-KeyColumn", gen_key_column_guided),
        ("7-HOROLOGE", gen_horologe_guided),
        ("8-KRYPTOS", gen_kryptos_guided),
    ]

    family_stats = {}

    for family_name, gen_fn in families:
        print(f"\n  {'=' * 60}")
        print(f"  Generating {family_name}...")
        sys.stdout.flush()

        t_fam = time.time()
        keystreams = gen_fn()
        gen_time = time.time() - t_fam
        print(f"  Generated {len(keystreams)} keystreams in {gen_time:.1f}s")
        sys.stdout.flush()

        t_eval = time.time()
        evaluated, pruned = evaluate_all(
            keystreams, family_name, stats, all_results,
            constraint_threshold=3  # Require at least 3/24 key matches
        )
        eval_time = time.time() - t_eval

        family_stats[family_name] = {
            "total": len(keystreams),
            "evaluated": evaluated,
            "pruned": pruned,
            "gen_time": gen_time,
            "eval_time": eval_time,
        }

        print(f"  {family_name} complete: {len(keystreams)} generated, "
              f"{evaluated} evaluated, {pruned} pruned ({eval_time:.1f}s)")
        print(f"  Running best: keys={stats.get('best_key_matches', 0)}, "
              f"crib_fixed={stats.get('best_crib_fixed', 0)}, "
              f"crib_free={stats.get('best_crib_free', 0)}, "
              f"qg={stats.get('best_qg', -99):.4f}")
        sys.stdout.flush()

    # ── Results ──────────────────────────────────────────────────────────────

    elapsed = time.time() - t_start

    print("\n" + "=" * 78)
    print("  RESULTS SUMMARY")
    print("=" * 78)
    print(f"\n  Total keystreams generated: {stats['total_keystreams']}")
    print(f"  Total pruned (< 4 key matches): {stats['total_pruned']}")
    print(f"  Total fully evaluated: {stats['total_evaluated']}")
    print(f"  Prune rate: {stats['total_pruned'] / max(1, stats['total_keystreams']) * 100:.1f}%")
    print(f"  Max pruned key matches: {stats['max_pruned_matches']}")
    print(f"\n  Best key matches: {stats['best_key_matches']}/24")
    print(f"  Best anchored crib score: {stats['best_crib_fixed']}/24")
    print(f"  Best free crib score: {stats['best_crib_free']}/24")
    print(f"  Best quadgram score: {stats['best_qg']:.4f}")

    # Sort results
    all_results.sort(key=lambda r: (-r["key_matches"], -r["qg_score"]))

    # Top by key matches
    print(f"\n  {'=' * 70}")
    print(f"  TOP 30 BY KEY MATCHES")
    print(f"  {'=' * 70}")
    for i, res in enumerate(all_results[:30]):
        print(f"  {i + 1:3d}. keys={res['key_matches']:2d}/24 | "
              f"cribs={res['crib_fixed']:2d}/24 | "
              f"free={res['crib_free']:2d}/24 | "
              f"qg={res['qg_score']:.3f} | "
              f"{res['mode']:12s} | {res['label']}")
        if res['key_matches'] >= 6 or res['crib_fixed'] >= 6:
            print(f"       PT: {res['plaintext'][:70]}...")

    # Top by quadgram
    qg_sorted = sorted(all_results, key=lambda r: -r["qg_score"])
    print(f"\n  {'=' * 70}")
    print(f"  TOP 30 BY QUADGRAM SCORE")
    print(f"  {'=' * 70}")
    for i, res in enumerate(qg_sorted[:30]):
        print(f"  {i + 1:3d}. qg={res['qg_score']:.3f} | "
              f"keys={res['key_matches']:2d}/24 | "
              f"cribs={res['crib_fixed']:2d}/24 | "
              f"free={res['crib_free']:2d}/24 | "
              f"{res['mode']:12s} | {res['label']}")

    # Top by crib score
    crib_sorted = sorted(all_results, key=lambda r: (-r["crib_fixed"], -r["qg_score"]))
    if crib_sorted and crib_sorted[0]["crib_fixed"] > 0:
        print(f"\n  {'=' * 70}")
        print(f"  TOP 20 BY ANCHORED CRIB SCORE")
        print(f"  {'=' * 70}")
        for i, res in enumerate(crib_sorted[:20]):
            print(f"  {i + 1:3d}. cribs={res['crib_fixed']:2d}/24 | "
                  f"keys={res['key_matches']:2d}/24 | "
                  f"free={res['crib_free']:2d}/24 | "
                  f"qg={res['qg_score']:.3f} | "
                  f"{res['mode']:12s} | {res['label']}")

    # Check for free crib hits
    free_hits = [r for r in all_results if r["crib_free"] > 0]
    if free_hits:
        print(f"\n  *** FREE CRIB HITS FOUND: {len(free_hits)} ***")
        for res in free_hits:
            print(f"  free={res['crib_free']}/24 | {res['mode']} | {res['label']}")
            print(f"  PT: {res['plaintext']}")

    # Family breakdown
    print(f"\n  {'=' * 70}")
    print(f"  FAMILY BREAKDOWN")
    print(f"  {'=' * 70}")
    print(f"  {'Family':<20s} {'Total':>8s} {'Evaluated':>10s} {'Pruned':>8s} "
          f"{'GenTime':>8s} {'EvalTime':>9s}")
    for fname, fstats in sorted(family_stats.items()):
        print(f"  {fname:<20s} {fstats['total']:>8d} {fstats['evaluated']:>10d} "
              f"{fstats['pruned']:>8d} {fstats['gen_time']:>7.1f}s "
              f"{fstats['eval_time']:>8.1f}s")

    # Key match distribution
    if all_results:
        match_dist = Counter(r["key_matches"] for r in all_results)
        print(f"\n  Key match distribution (stored results):")
        for k in sorted(match_dist.keys(), reverse=True):
            print(f"    {k:2d} matches: {match_dist[k]} results")

    # Save results
    results_file = out_dir / "results.json"
    save_data = {
        "experiment": "E-TABLEAU-OTP",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "elapsed_seconds": elapsed,
        "stats": {k: v for k, v in stats.items()
                  if not isinstance(v, dict)},
        "family_stats": family_stats,
        "total_results_stored": len(all_results),
        "top_by_key_matches": all_results[:50],
        "top_by_qg": qg_sorted[:50],
        "top_by_crib": crib_sorted[:50] if crib_sorted else [],
    }
    # Remove plaintext from saved results to keep file size reasonable
    for category in ["top_by_key_matches", "top_by_qg", "top_by_crib"]:
        for r in save_data[category]:
            if "plaintext" in r and len(r["plaintext"]) > 30:
                r["plaintext_head"] = r["plaintext"][:40]
                # Keep full PT for top results
                if r.get("key_matches", 0) < 8 and r.get("crib_fixed", 0) < 6:
                    del r["plaintext"]

    with open(results_file, 'w') as f:
        json.dump(save_data, f, indent=2, default=str)
    print(f"\n  Results saved to {results_file}")

    print(f"\n  Total elapsed time: {elapsed:.1f}s")
    print(f"\n{'=' * 78}")
    print(f"  E-TABLEAU-OTP: COMPLETE")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
