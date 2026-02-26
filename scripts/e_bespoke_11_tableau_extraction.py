#!/usr/bin/env python3
"""E-BESPOKE-11: Tableau-as-key-source via structured extraction.

Theory: The Vigenere tableau on the Kryptos sculpture is a 26x26 grid using
the KRYPTOS alphabet. Instead of using it AS a cipher mechanism, extract 97
specific characters FROM it (via diagonal, spiral, knight's move, keyword-
guided, or anomaly-guided reads) to create a running key, then decrypt K4.

Phases:
  1. Linear reads (diagonal, anti-diagonal, offset-diagonal, row/col reads)
  2. Spiral reads (CW/CCW from 4 corners)
  3. Knight's move reads (8 directions, multiple start cells)
  4. Keyword-guided extraction (4 methods x 7 keywords)
  5. Misspelling/anomaly guided extraction (step sizes, row selectors, YAR, Morse E)
  6. For each extracted key: Vig, Beaufort, Variant Beaufort decrypt + crib score

Usage: PYTHONPATH=src python3 -u scripts/e_bespoke_11_tableau_extraction.py
"""
import json
import os
import sys
import time

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate

# ── Alphabet setup ─────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

CT_AZ = [AZ_IDX[c] for c in CT]
CT_KA = [KA_IDX[c] for c in CT]

CRIB_PT_AZ = {pos: AZ_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_PT_KA = {pos: KA_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POSITIONS = sorted(CRIB_DICT.keys())

# ── Tableau definition ─────────────────────────────────────────────────

def tableau_cell(row, col):
    """KA tableau: row i is KA shifted left by i. tableau[r][c] = KA[(r+c)%26]."""
    return KA[(row + col) % 26]

def tableau_idx(row, col):
    """Return the KA-index of the character at tableau[row][col]."""
    return (row + col) % 26

def extract_key_chars(coord_func, length=CT_LEN):
    """Extract key characters from tableau. coord_func(i) -> (row, col)."""
    return ''.join(tableau_cell(*coord_func(i)) for i in range(length))

def extract_key_indices_ka(coord_func, length=CT_LEN):
    """Extract key as KA-index values."""
    return [tableau_idx(*coord_func(i)) for i in range(length)]

# ── Cipher variants ────────────────────────────────────────────────────

def decrypt_az_vig(ct_num, key_chars):
    """AZ Vigenere: PT = (CT - KEY) mod 26."""
    key_num = [AZ_IDX[c] for c in key_chars]
    return [(c - k) % 26 for c, k in zip(ct_num, key_num)]

def decrypt_az_beau(ct_num, key_chars):
    """AZ Beaufort: PT = (KEY - CT) mod 26."""
    key_num = [AZ_IDX[c] for c in key_chars]
    return [(k - c) % 26 for c, k in zip(ct_num, key_num)]

def decrypt_az_vbeau(ct_num, key_chars):
    """AZ Variant Beaufort: PT = (CT + KEY) mod 26."""
    key_num = [AZ_IDX[c] for c in key_chars]
    return [(c + k) % 26 for c, k in zip(ct_num, key_num)]

def decrypt_ka_vig(ct_ka, key_ka):
    """KA Vigenere: PT_ka = (CT_ka - KEY_ka) mod 26."""
    return [(c - k) % 26 for c, k in zip(ct_ka, key_ka)]

def decrypt_ka_beau(ct_ka, key_ka):
    """KA Beaufort: PT_ka = (KEY_ka - CT_ka) mod 26."""
    return [(k - c) % 26 for c, k in zip(ct_ka, key_ka)]

def decrypt_ka_vbeau(ct_ka, key_ka):
    """KA Variant Beaufort: PT_ka = (CT_ka + KEY_ka) mod 26."""
    return [(c + k) % 26 for c, k in zip(ct_ka, key_ka)]

# ── Scoring ────────────────────────────────────────────────────────────

def quick_score_az(pt_nums):
    return sum(1 for pos in CRIB_POSITIONS
               if pos < len(pt_nums) and pt_nums[pos] == CRIB_PT_AZ[pos])

def quick_score_ka(pt_ka_nums):
    return sum(1 for pos in CRIB_POSITIONS
               if pos < len(pt_ka_nums) and pt_ka_nums[pos] == CRIB_PT_KA[pos])

def nums_to_text_az(nums):
    return ''.join(AZ[n % 26] for n in nums)

def nums_to_text_ka(nums):
    return ''.join(KA[n % 26] for n in nums)

# ── Test a single key string ──────────────────────────────────────────

def test_key(key_str, method_name, all_results, stats):
    """Test a key string against all 6 cipher variants. Updates stats in-place."""
    if len(key_str) < CT_LEN:
        # Pad by repeating
        reps = (CT_LEN // len(key_str)) + 2
        key_str = (key_str * reps)[:CT_LEN]
    elif len(key_str) > CT_LEN:
        key_str = key_str[:CT_LEN]

    key_ka = [KA_IDX[c] for c in key_str]

    # AZ variants
    for var_name, decrypt_fn, score_fn, to_text in [
        ("AZ_Vig", decrypt_az_vig, quick_score_az, nums_to_text_az),
        ("AZ_Beau", decrypt_az_beau, quick_score_az, nums_to_text_az),
        ("AZ_VBeau", decrypt_az_vbeau, quick_score_az, nums_to_text_az),
    ]:
        pt_nums = decrypt_fn(CT_AZ, key_str)
        score = score_fn(pt_nums)
        stats["total"] += 1

        if score > stats["best_score"]:
            stats["best_score"] = score
            stats["best_config"] = f"{method_name}/{var_name}"

        if score >= NOISE_FLOOR + 1:
            pt_text = to_text(pt_nums)
            result = {
                "method": method_name,
                "variant": var_name,
                "score": score,
                "key_prefix": key_str[:30],
                "plaintext": pt_text,
            }
            all_results.append(result)

            if score >= STORE_THRESHOLD:
                print(f"  ** {method_name}/{var_name}: {score}/24")
                print(f"     Key: {key_str[:40]}...")
                print(f"     PT:  {pt_text[:50]}...")
                sys.stdout.flush()

            if score >= SIGNAL_THRESHOLD:
                sb = score_candidate(pt_text)
                print(f"  *** SIGNAL: {sb.summary}")
                sys.stdout.flush()

    # KA variants
    for var_name, decrypt_fn, score_fn, to_text in [
        ("KA_Vig", decrypt_ka_vig, quick_score_ka, nums_to_text_ka),
        ("KA_Beau", decrypt_ka_beau, quick_score_ka, nums_to_text_ka),
        ("KA_VBeau", decrypt_ka_vbeau, quick_score_ka, nums_to_text_ka),
    ]:
        pt_ka = decrypt_fn(CT_KA, key_ka)
        score = score_fn(pt_ka)
        stats["total"] += 1

        if score > stats["best_score"]:
            stats["best_score"] = score
            stats["best_config"] = f"{method_name}/{var_name}"

        if score >= NOISE_FLOOR + 1:
            pt_text = to_text(pt_ka)
            result = {
                "method": method_name,
                "variant": var_name,
                "score": score,
                "key_prefix": key_str[:30],
                "plaintext": pt_text,
            }
            all_results.append(result)

            if score >= STORE_THRESHOLD:
                print(f"  ** {method_name}/{var_name}: {score}/24")
                print(f"     Key: {key_str[:40]}...")
                print(f"     PT:  {pt_text[:50]}...")
                sys.stdout.flush()

            if score >= SIGNAL_THRESHOLD:
                sb = score_candidate(pt_text)
                print(f"  *** SIGNAL: {sb.summary}")
                sys.stdout.flush()


# ── Keywords for various phases ───────────────────────────────────────

KEYWORDS = {
    "KRYPTOS": "KRYPTOS",
    "PALIMPSEST": "PALIMPSEST",
    "ABSCISSA": "ABSCISSA",
    "BERLINCLOCK": "BERLINCLOCK",
    "YAR": "YAR",
    "CHECKPOINT": "CHECKPOINT",
    "CHARLIE": "CHARLIE",
}

# Convert keywords to KA indices
def kw_to_ka(kw):
    return [KA_IDX[c] for c in kw]

# ── PHASE 1: Linear reads ─────────────────────────────────────────────

def phase1_keys():
    """Generate (name, key_string) pairs for linear tableau reads."""
    keys = []

    # Main diagonal: tableau[i][i] for i=0..25, repeat to 97
    keys.append(("diag_main", extract_key_chars(lambda i: (i % 26, i % 26))))

    # Anti-diagonal: tableau[i][25-i]
    keys.append(("diag_anti", extract_key_chars(lambda i: (i % 26, (25 - i) % 26))))

    # Offset diagonals: tableau[i][(i+k) % 26] for k=0..25
    for k in range(26):
        keys.append((f"diag_offset_{k}", extract_key_chars(lambda i, k=k: (i % 26, (i + k) % 26))))

    # Row reads: read row R from col 0..25, cycle rows per keyword
    for kw_name, kw in KEYWORDS.items():
        kw_ka = kw_to_ka(kw)
        kw_len = len(kw_ka)
        # Method: row = kw[floor(i/26) % kw_len], col = i % 26
        def row_read(i, _kw_ka=kw_ka, _kw_len=kw_len):
            row = _kw_ka[(i // 26) % _kw_len]
            col = i % 26
            return (row, col)
        keys.append((f"row_read_{kw_name}", extract_key_chars(row_read)))

    # Column reads: read column C from row 0..25, cycle columns per keyword
    for kw_name, kw in KEYWORDS.items():
        kw_ka = kw_to_ka(kw)
        kw_len = len(kw_ka)
        def col_read(i, _kw_ka=kw_ka, _kw_len=kw_len):
            row = i % 26
            col = _kw_ka[(i // 26) % _kw_len]
            return (row, col)
        keys.append((f"col_read_{kw_name}", extract_key_chars(col_read)))

    # Interleaved row reads: row = kw[i % kw_len], col = i
    for kw_name, kw in KEYWORDS.items():
        kw_ka = kw_to_ka(kw)
        kw_len = len(kw_ka)
        def interleaved_row(i, _kw_ka=kw_ka, _kw_len=kw_len):
            return (_kw_ka[i % _kw_len], i % 26)
        keys.append((f"interleaved_row_{kw_name}", extract_key_chars(interleaved_row)))

    # Interleaved column reads: row = i, col = kw[i % kw_len]
    for kw_name, kw in KEYWORDS.items():
        kw_ka = kw_to_ka(kw)
        kw_len = len(kw_ka)
        def interleaved_col(i, _kw_ka=kw_ka, _kw_len=kw_len):
            return (i % 26, _kw_ka[i % _kw_len])
        keys.append((f"interleaved_col_{kw_name}", extract_key_chars(interleaved_col)))

    return keys


# ── PHASE 2: Spiral reads ─────────────────────────────────────────────

def spiral_cw(start_row, start_col, n=26):
    """Generate coordinates for a clockwise spiral on an n×n grid."""
    visited = set()
    coords = []
    r, c = start_row, start_col
    # Directions: right, down, left, up
    dr = [0, 1, 0, -1]
    dc = [1, 0, -1, 0]
    d = 0  # start going right

    # Determine initial direction based on start corner
    if start_row == 0 and start_col == 0:
        d = 0  # right
    elif start_row == 0 and start_col == n - 1:
        d = 1  # down
    elif start_row == n - 1 and start_col == n - 1:
        d = 2  # left
    elif start_row == n - 1 and start_col == 0:
        d = 3  # up

    for _ in range(n * n):
        coords.append((r % n, c % n))
        visited.add((r, c))
        # Try to continue in current direction
        nr, nc = r + dr[d], c + dc[d]
        if 0 <= nr < n and 0 <= nc < n and (nr, nc) not in visited:
            r, c = nr, nc
        else:
            # Turn clockwise
            d = (d + 1) % 4
            nr, nc = r + dr[d], c + dc[d]
            if 0 <= nr < n and 0 <= nc < n and (nr, nc) not in visited:
                r, c = nr, nc
            else:
                break  # stuck
    return coords

def spiral_ccw(start_row, start_col, n=26):
    """Generate coordinates for a counter-clockwise spiral."""
    visited = set()
    coords = []
    r, c = start_row, start_col
    # Directions: down, right, up, left (CCW from top-left)
    dr = [1, 0, -1, 0]
    dc = [0, 1, 0, -1]
    d = 0

    if start_row == 0 and start_col == 0:
        d = 0  # down
    elif start_row == 0 and start_col == n - 1:
        d = 3  # left
    elif start_row == n - 1 and start_col == n - 1:
        d = 2  # up
    elif start_row == n - 1 and start_col == 0:
        d = 1  # right

    for _ in range(n * n):
        coords.append((r % n, c % n))
        visited.add((r, c))
        nr, nc = r + dr[d], c + dc[d]
        if 0 <= nr < n and 0 <= nc < n and (nr, nc) not in visited:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            nr, nc = r + dr[d], c + dc[d]
            if 0 <= nr < n and 0 <= nc < n and (nr, nc) not in visited:
                r, c = nr, nc
            else:
                break
    return coords

def phase2_keys():
    """Generate (name, key_string) pairs for spiral reads."""
    keys = []
    corners = [(0, 0), (0, 25), (25, 0), (25, 25)]

    for sr, sc in corners:
        # Clockwise spiral
        coords = spiral_cw(sr, sc)
        key_str = ''.join(tableau_cell(r, c) for r, c in coords[:CT_LEN])
        keys.append((f"spiral_cw_{sr}_{sc}", key_str))

        # Counter-clockwise spiral
        coords = spiral_ccw(sr, sc)
        key_str = ''.join(tableau_cell(r, c) for r, c in coords[:CT_LEN])
        keys.append((f"spiral_ccw_{sr}_{sc}", key_str))

    return keys


# ── PHASE 3: Knight's move reads ──────────────────────────────────────

KNIGHT_MOVES = [
    (2, 1), (2, -1), (-2, 1), (-2, -1),
    (1, 2), (1, -2), (-1, 2), (-1, -2),
]

def knight_tour(start_row, start_col, dr, dc, n=26, length=CT_LEN):
    """Walk a knight's move path on an n×n grid with wraparound."""
    coords = []
    r, c = start_row, start_col
    for _ in range(length):
        coords.append((r, c))
        r = (r + dr) % n
        c = (c + dc) % n
    return coords

def phase3_keys():
    """Generate (name, key_string) pairs for knight's move reads."""
    keys = []

    start_cells = [
        (0, 0),
        (0, KA_IDX['K']),  # K position in KA
        (KA_IDX['Y'], KA_IDX['A']),   # Y, A from YAR
        (KA_IDX['A'], KA_IDX['R']),   # A, R from YAR
        (KA_IDX['R'], KA_IDX['Y']),   # R, Y from YAR (reversed)
        (0, 19),  # T=19 (A=0), "T IS YOUR POSITION"
    ]

    for sr, sc in start_cells:
        for dr, dc in KNIGHT_MOVES:
            coords = knight_tour(sr, sc, dr, dc)
            key_str = ''.join(tableau_cell(r, c) for r, c in coords)
            keys.append((f"knight_{sr}_{sc}_d{dr}_{dc}", key_str))

    return keys


# ── PHASE 4: Keyword-guided extraction ───────────────────────────────

def phase4_keys():
    """Generate (name, key_string) pairs for keyword-guided extraction."""
    keys = []

    for kw_name, kw in KEYWORDS.items():
        kw_ka = kw_to_ka(kw)
        kw_len = len(kw_ka)

        # Method A: Row = keyword[i % len], Column = i % 26
        def method_a(i, _kw_ka=kw_ka, _kw_len=kw_len):
            return (_kw_ka[i % _kw_len], i % 26)
        keys.append((f"kw_A_{kw_name}", extract_key_chars(method_a)))

        # Method B: Row = i % 26, Column = keyword[i % len]
        def method_b(i, _kw_ka=kw_ka, _kw_len=kw_len):
            return (i % 26, _kw_ka[i % _kw_len])
        keys.append((f"kw_B_{kw_name}", extract_key_chars(method_b)))

        # Method C: Row = keyword[i % len], Column = keyword[(i+1) % len]
        def method_c(i, _kw_ka=kw_ka, _kw_len=kw_len):
            return (_kw_ka[i % _kw_len], _kw_ka[(i + 1) % _kw_len])
        keys.append((f"kw_C_{kw_name}", extract_key_chars(method_c)))

        # Method D: Row = keyword[i % len], Column = i mod 26
        def method_d(i, _kw_ka=kw_ka, _kw_len=kw_len):
            return (_kw_ka[i % _kw_len], i % 26)
        keys.append((f"kw_D_{kw_name}", extract_key_chars(method_d)))

        # Method E: Row = i mod 26, Column = keyword[i % len] + i (progressive)
        def method_e(i, _kw_ka=kw_ka, _kw_len=kw_len):
            return (i % 26, (_kw_ka[i % _kw_len] + i) % 26)
        keys.append((f"kw_E_{kw_name}", extract_key_chars(method_e)))

        # Method F: Row = keyword[i % len] + i (progressive), Column = i
        def method_f(i, _kw_ka=kw_ka, _kw_len=kw_len):
            return ((_kw_ka[i % _kw_len] + i) % 26, i % 26)
        keys.append((f"kw_F_{kw_name}", extract_key_chars(method_f)))

        # Method G: Autokey-style: Row = keyword for first kw_len chars,
        # then row = previous extracted char index. Column = i.
        autokey_indices = []
        for i in range(CT_LEN):
            if i < kw_len:
                row = kw_ka[i]
            else:
                row = autokey_indices[i - kw_len]
            col = i % 26
            autokey_indices.append(tableau_idx(row, col))
        key_str = ''.join(KA[idx] for idx in autokey_indices)
        keys.append((f"kw_G_autokey_{kw_name}", key_str))

    # Also try pairs of keywords
    kw_pairs = [
        ("KRYPTOS", "PALIMPSEST"),
        ("KRYPTOS", "ABSCISSA"),
        ("PALIMPSEST", "ABSCISSA"),
        ("KRYPTOS", "BERLINCLOCK"),
        ("YAR", "KRYPTOS"),
    ]
    for kw1_name, kw2_name in kw_pairs:
        kw1_ka = kw_to_ka(kw1_name)
        kw2_ka = kw_to_ka(kw2_name)
        kw1_len = len(kw1_ka)
        kw2_len = len(kw2_ka)

        # Row from kw1, col from kw2
        def pair_rc(i, _k1=kw1_ka, _l1=kw1_len, _k2=kw2_ka, _l2=kw2_len):
            return (_k1[i % _l1], _k2[i % _l2])
        keys.append((f"kw_pair_{kw1_name}_{kw2_name}", extract_key_chars(pair_rc)))

        # Row from kw2, col from kw1
        def pair_cr(i, _k1=kw1_ka, _l1=kw1_len, _k2=kw2_ka, _l2=kw2_len):
            return (_k2[i % _l2], _k1[i % _l1])
        keys.append((f"kw_pair_{kw2_name}_{kw1_name}", extract_key_chars(pair_cr)))

    return keys


# ── PHASE 5: Misspelling/anomaly guided extraction ───────────────────

# Misspelling data: (correct, on_sculpture, pos_in_word_of_error)
# S->C (pos 7), L->Q (pos 2), O->U (pos 10), E->A (pos 5), I->E (pos 4)
MISSPELLING_POSITIONS = [7, 2, 10, 5, 4]
MISSPELLING_WRONG = "CQUAE"  # the wrong letters on the sculpture
MISSPELLING_RIGHT = "SLOUI"  # the correct letters

# "EQUAL" letter values in AZ
EQUAL_AZ = [AZ_IDX[c] for c in "EQUAL"]   # [4, 16, 20, 0, 11]
EQUAL_KA = [KA_IDX[c] for c in "EQUAL"]

# YAR values (KA indexed)
YAR_KA = [KA_IDX[c] for c in "YAR"]    # Y, A, R in KA
YAR_AZ = [AZ_IDX[c] for c in "YAR"]    # [24, 0, 17]

# Morse E positions (approximate — 26 extra E's in Morse code)
# These are approximate positions in the Morse code where stray E's appear.
# From anomaly_registry: 26 extra E's (alphabet-sized set of markers).
# Without exact positions, use the values [0..25] as the 26 "E markers"
MORSE_E_INDICES = list(range(26))

def phase5_keys():
    """Generate (name, key_string) pairs for anomaly-guided extraction."""
    keys = []

    # Method 1: Misspelling positions as step sizes
    # Walk through tableau with step = misspelling_positions cycling
    ms_len = len(MISSPELLING_POSITIONS)
    def ms_step(i, _ms=MISSPELLING_POSITIONS, _ml=ms_len):
        # Accumulate steps
        pos = 0
        for j in range(i):
            pos += _ms[j % _ml]
        row = pos % 26
        col = i % 26
        return (row, col)
    keys.append(("ms_step_row", extract_key_chars(ms_step)))

    # Same but step in column direction
    def ms_step_col(i, _ms=MISSPELLING_POSITIONS, _ml=ms_len):
        pos = 0
        for j in range(i):
            pos += _ms[j % _ml]
        row = i % 26
        col = pos % 26
        return (row, col)
    keys.append(("ms_step_col", extract_key_chars(ms_step_col)))

    # Method 2: Misspelling wrong letter VALUES as row selectors
    wrong_ka = [KA_IDX[c] for c in MISSPELLING_WRONG]
    wl = len(wrong_ka)
    def ms_wrong_row(i, _wk=wrong_ka, _wl=wl):
        return (_wk[i % _wl], i % 26)
    keys.append(("ms_wrong_row", extract_key_chars(ms_wrong_row)))

    # Method 3: Misspelling right letter VALUES as row selectors
    right_ka = [KA_IDX[c] for c in MISSPELLING_RIGHT]
    rl = len(right_ka)
    def ms_right_row(i, _rk=right_ka, _rl=rl):
        return (_rk[i % _rl], i % 26)
    keys.append(("ms_right_row", extract_key_chars(ms_right_row)))

    # Method 4: EQUAL letter values cycling as row selectors, col = i
    eq_len = len(EQUAL_KA)
    def equal_row_ka(i, _eq=EQUAL_KA, _el=eq_len):
        return (_eq[i % _el], i % 26)
    keys.append(("equal_row_ka", extract_key_chars(equal_row_ka)))

    def equal_row_az(i, _eq=EQUAL_AZ, _el=eq_len):
        return (_eq[i % _el], i % 26)
    keys.append(("equal_row_az", extract_key_chars(equal_row_az)))

    # Also EQUAL as column selectors
    def equal_col_ka(i, _eq=EQUAL_KA, _el=eq_len):
        return (i % 26, _eq[i % _el])
    keys.append(("equal_col_ka", extract_key_chars(equal_col_ka)))

    # Method 5: YAR cycling as row selectors
    yar_len = len(YAR_KA)
    def yar_row_ka(i, _yar=YAR_KA, _yl=yar_len):
        return (_yar[i % _yl], i % 26)
    keys.append(("yar_row_ka", extract_key_chars(yar_row_ka)))

    def yar_row_az(i, _yar=YAR_AZ, _yl=yar_len):
        return (_yar[i % _yl], i % 26)
    keys.append(("yar_row_az", extract_key_chars(yar_row_az)))

    def yar_col_ka(i, _yar=YAR_KA, _yl=yar_len):
        return (i % 26, _yar[i % _yl])
    keys.append(("yar_col_ka", extract_key_chars(yar_col_ka)))

    def yar_col_az(i, _yar=YAR_AZ, _yl=yar_len):
        return (i % 26, _yar[i % _yl])
    keys.append(("yar_col_az", extract_key_chars(yar_col_az)))

    # YAR progressive: row = YAR[i%3] + i, col = i
    def yar_prog_row(i, _yar=YAR_KA, _yl=yar_len):
        return ((_yar[i % _yl] + i) % 26, i % 26)
    keys.append(("yar_prog_row_ka", extract_key_chars(yar_prog_row)))

    # Method 6: Morse E positions as indices into the tableau
    # Read tableau[e_pos][i] for each i, cycling through the 26 E positions
    me_len = len(MORSE_E_INDICES)
    def morse_e_row(i, _me=MORSE_E_INDICES, _mel=me_len):
        return (_me[i % _mel], i % 26)
    keys.append(("morse_e_row", extract_key_chars(morse_e_row)))

    def morse_e_col(i, _me=MORSE_E_INDICES, _mel=me_len):
        return (i % 26, _me[i % _mel])
    keys.append(("morse_e_col", extract_key_chars(morse_e_col)))

    # Method 7: Combined YAR + EQUAL
    # YAR[i%3] as row, EQUAL[i%5] as col
    def yar_equal(i, _yar=YAR_KA, _eq=EQUAL_KA):
        return (_yar[i % 3], _eq[i % 5])
    keys.append(("yar_equal_ka", extract_key_chars(yar_equal)))

    # EQUAL[i%5] as row, YAR[i%3] as col
    def equal_yar(i, _yar=YAR_KA, _eq=EQUAL_KA):
        return (_eq[i % 5], _yar[i % 3])
    keys.append(("equal_yar_ka", extract_key_chars(equal_yar)))

    # Method 8: "T IS YOUR POSITION" — T=19 as starting row
    # Read from row 19 with various column patterns
    def t_row_seq(i):
        return (19, i % 26)
    keys.append(("t_row_19_seq", extract_key_chars(t_row_seq)))

    # T=19 as column
    def t_col_seq(i):
        return (i % 26, 19)
    keys.append(("t_col_19_seq", extract_key_chars(t_col_seq)))

    # T=19 as starting row, progressive
    def t_row_prog(i):
        return ((19 + i) % 26, i % 26)
    keys.append(("t_row_19_prog", extract_key_chars(t_row_prog)))

    # Method 9: DYAR / DYARO values (if 5-char version)
    DYARO_KA = [KA_IDX[c] for c in "DYARO"]
    dyaro_len = 5
    def dyaro_row(i, _d=DYARO_KA, _dl=dyaro_len):
        return (_d[i % _dl], i % 26)
    keys.append(("dyaro_row_ka", extract_key_chars(dyaro_row)))

    def dyaro_col(i, _d=DYARO_KA, _dl=dyaro_len):
        return (i % 26, _d[i % _dl])
    keys.append(("dyaro_col_ka", extract_key_chars(dyaro_col)))

    # Method 10: Coordinate values from K2: 38,57,6,5,77,8,44
    COORDS = [38, 57, 6, 5, 77, 8, 44]
    coords_mod = [v % 26 for v in COORDS]
    coords_len = len(coords_mod)
    def coords_row(i, _c=coords_mod, _cl=coords_len):
        return (_c[i % _cl], i % 26)
    keys.append(("coords_row", extract_key_chars(coords_row)))

    def coords_col(i, _c=coords_mod, _cl=coords_len):
        return (i % 26, _c[i % _cl])
    keys.append(("coords_col", extract_key_chars(coords_col)))

    return keys


# ── PHASE 6: Cross-phase combination — diagonal with keyword offset ──

def phase6_keys():
    """Additional creative combinations."""
    keys = []

    # Row = CT letter KA-index, col = i (CT itself guides the extraction)
    ct_ka_vals = [KA_IDX[c] for c in CT]
    def ct_guided_row(i, _ct=ct_ka_vals):
        return (_ct[i], i % 26)
    keys.append(("ct_guided_row", extract_key_chars(ct_guided_row)))

    # Col = CT letter KA-index, row = i
    def ct_guided_col(i, _ct=ct_ka_vals):
        return (i % 26, _ct[i])
    keys.append(("ct_guided_col", extract_key_chars(ct_guided_col)))

    # Row = CT[i], Col = CT[96-i] (CT forward + CT reversed)
    def ct_bidir(i, _ct=ct_ka_vals):
        return (_ct[i], _ct[CT_LEN - 1 - i])
    keys.append(("ct_bidir", extract_key_chars(ct_bidir)))

    # Fibonacci-like walk: start at (0,0), each step is (prev_row, prev_col+prev_row)
    fib_coords = [(0, 1)]
    for i in range(1, CT_LEN):
        pr, pc = fib_coords[-1]
        fib_coords.append(((pr + pc) % 26, (pc + pr + pc) % 26))
    key_str = ''.join(tableau_cell(r, c) for r, c in fib_coords[:CT_LEN])
    keys.append(("fibonacci_walk", key_str))

    # Golden ratio walk: step size = round(i * 1.618) mod 26
    def golden_walk(i):
        step = round(i * 1.618033988749895) % 26
        return (step, i % 26)
    keys.append(("golden_walk_row", extract_key_chars(golden_walk)))

    def golden_walk_col(i):
        step = round(i * 1.618033988749895) % 26
        return (i % 26, step)
    keys.append(("golden_walk_col", extract_key_chars(golden_walk_col)))

    # Triangular number walk: position = T(i) = i*(i+1)/2 mod 26
    def triangular_row(i):
        t = (i * (i + 1) // 2) % 26
        return (t, i % 26)
    keys.append(("triangular_row", extract_key_chars(triangular_row)))

    # Prime-indexed: row = i-th prime mod 26
    primes = []
    n = 2
    while len(primes) < CT_LEN:
        if all(n % p != 0 for p in primes if p * p <= n):
            primes.append(n)
        n += 1
    def prime_row(i, _p=primes):
        return (_p[i] % 26, i % 26)
    keys.append(("prime_row", extract_key_chars(prime_row)))

    def prime_col(i, _p=primes):
        return (i % 26, _p[i] % 26)
    keys.append(("prime_col", extract_key_chars(prime_col)))

    # "HILL" values cycling: H=7, I=8, L=11, L=11 (AZ)
    HILL_AZ = [AZ_IDX[c] for c in "HILL"]
    hill_len = 4
    def hill_row(i, _h=HILL_AZ, _hl=hill_len):
        return (_h[i % _hl], i % 26)
    keys.append(("hill_row_az", extract_key_chars(hill_row)))

    # Snaking read: row 0 L->R, row 1 R->L, row 2 L->R, ...
    snake_coords = []
    for r in range(26):
        if r % 2 == 0:
            for c in range(26):
                snake_coords.append((r, c))
        else:
            for c in range(25, -1, -1):
                snake_coords.append((r, c))
    key_str = ''.join(tableau_cell(r, c) for r, c in snake_coords[:CT_LEN])
    keys.append(("snake_read", key_str))

    # Reverse snake: start from bottom
    snake_rev_coords = []
    for r in range(25, -1, -1):
        if (25 - r) % 2 == 0:
            for c in range(26):
                snake_rev_coords.append((r, c))
        else:
            for c in range(25, -1, -1):
                snake_rev_coords.append((r, c))
    key_str = ''.join(tableau_cell(r, c) for r, c in snake_rev_coords[:CT_LEN])
    keys.append(("snake_rev", key_str))

    return keys


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

print("=" * 72)
print("E-BESPOKE-11: Tableau-as-Key-Source via Structured Extraction")
print("=" * 72)
print(f"  CT: {CT_LEN} chars")
print(f"  KA: {KA}")
print(f"  Tableau: 26x26 grid, cell[r][c] = KA[(r+c) mod 26]")
print(f"  Cribs: {N_CRIBS} positions")
print(f"  Variants: 6 (AZ_Vig, AZ_Beau, AZ_VBeau, KA_Vig, KA_Beau, KA_VBeau)")
print()

t0 = time.time()
all_results = []
stats = {"total": 0, "best_score": 0, "best_config": "none"}
phase_summaries = {}

# ── Phase 1 ────────────────────────────────────────────────────────────

print("-" * 72)
print("PHASE 1: Linear reads (diagonals, row/col reads)")
print("-" * 72)
sys.stdout.flush()

p1_keys = phase1_keys()
print(f"  {len(p1_keys)} key extraction methods")
p1_start = time.time()

for name, key_str in p1_keys:
    test_key(key_str, name, all_results, stats)

p1_elapsed = time.time() - p1_start
phase_summaries["Phase 1 (linear)"] = {
    "methods": len(p1_keys),
    "tests": len(p1_keys) * 6,
    "elapsed": p1_elapsed,
    "best": stats["best_score"],
}
print(f"  Phase 1 done: {len(p1_keys)*6} tests, best={stats['best_score']}/24 [{p1_elapsed:.1f}s]")
print()
sys.stdout.flush()

# ── Phase 2 ────────────────────────────────────────────────────────────

print("-" * 72)
print("PHASE 2: Spiral reads (CW/CCW from 4 corners)")
print("-" * 72)
sys.stdout.flush()

p2_keys = phase2_keys()
print(f"  {len(p2_keys)} spiral extraction methods")
p2_start = time.time()
p2_best_before = stats["best_score"]

for name, key_str in p2_keys:
    test_key(key_str, name, all_results, stats)

p2_elapsed = time.time() - p2_start
phase_summaries["Phase 2 (spirals)"] = {
    "methods": len(p2_keys),
    "tests": len(p2_keys) * 6,
    "elapsed": p2_elapsed,
    "best": stats["best_score"],
}
print(f"  Phase 2 done: {len(p2_keys)*6} tests, best={stats['best_score']}/24 [{p2_elapsed:.1f}s]")
print()
sys.stdout.flush()

# ── Phase 3 ────────────────────────────────────────────────────────────

print("-" * 72)
print("PHASE 3: Knight's move reads")
print("-" * 72)
sys.stdout.flush()

p3_keys = phase3_keys()
print(f"  {len(p3_keys)} knight's move extraction methods")
p3_start = time.time()

for name, key_str in p3_keys:
    test_key(key_str, name, all_results, stats)

p3_elapsed = time.time() - p3_start
phase_summaries["Phase 3 (knights)"] = {
    "methods": len(p3_keys),
    "tests": len(p3_keys) * 6,
    "elapsed": p3_elapsed,
    "best": stats["best_score"],
}
print(f"  Phase 3 done: {len(p3_keys)*6} tests, best={stats['best_score']}/24 [{p3_elapsed:.1f}s]")
print()
sys.stdout.flush()

# ── Phase 4 ────────────────────────────────────────────────────────────

print("-" * 72)
print("PHASE 4: Keyword-guided extraction")
print("-" * 72)
sys.stdout.flush()

p4_keys = phase4_keys()
print(f"  {len(p4_keys)} keyword-guided extraction methods")
p4_start = time.time()

for name, key_str in p4_keys:
    test_key(key_str, name, all_results, stats)

p4_elapsed = time.time() - p4_start
phase_summaries["Phase 4 (keywords)"] = {
    "methods": len(p4_keys),
    "tests": len(p4_keys) * 6,
    "elapsed": p4_elapsed,
    "best": stats["best_score"],
}
print(f"  Phase 4 done: {len(p4_keys)*6} tests, best={stats['best_score']}/24 [{p4_elapsed:.1f}s]")
print()
sys.stdout.flush()

# ── Phase 5 ────────────────────────────────────────────────────────────

print("-" * 72)
print("PHASE 5: Misspelling/anomaly-guided extraction")
print("-" * 72)
sys.stdout.flush()

p5_keys = phase5_keys()
print(f"  {len(p5_keys)} anomaly-guided extraction methods")
p5_start = time.time()

for name, key_str in p5_keys:
    test_key(key_str, name, all_results, stats)

p5_elapsed = time.time() - p5_start
phase_summaries["Phase 5 (anomalies)"] = {
    "methods": len(p5_keys),
    "tests": len(p5_keys) * 6,
    "elapsed": p5_elapsed,
    "best": stats["best_score"],
}
print(f"  Phase 5 done: {len(p5_keys)*6} tests, best={stats['best_score']}/24 [{p5_elapsed:.1f}s]")
print()
sys.stdout.flush()

# ── Phase 6 ────────────────────────────────────────────────────────────

print("-" * 72)
print("PHASE 6: Creative combinations (CT-guided, Fibonacci, primes, snake)")
print("-" * 72)
sys.stdout.flush()

p6_keys = phase6_keys()
print(f"  {len(p6_keys)} creative extraction methods")
p6_start = time.time()

for name, key_str in p6_keys:
    test_key(key_str, name, all_results, stats)

p6_elapsed = time.time() - p6_start
phase_summaries["Phase 6 (creative)"] = {
    "methods": len(p6_keys),
    "tests": len(p6_keys) * 6,
    "elapsed": p6_elapsed,
    "best": stats["best_score"],
}
print(f"  Phase 6 done: {len(p6_keys)*6} tests, best={stats['best_score']}/24 [{p6_elapsed:.1f}s]")
print()
sys.stdout.flush()

# ══════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════

total_elapsed = time.time() - t0

print("=" * 72)
print("SUMMARY — E-BESPOKE-11: Tableau Extraction")
print("=" * 72)
print()

total_methods = sum(p["methods"] for p in phase_summaries.values())
total_tests = stats["total"]

for phase_name, info in phase_summaries.items():
    print(f"  {phase_name}: {info['methods']} methods, {info['tests']} tests [{info['elapsed']:.1f}s]")
print()
print(f"  Total methods: {total_methods}")
print(f"  Total tests: {total_tests:,}")
print(f"  Total elapsed: {total_elapsed:.1f}s")
print()
print(f"  Best score: {stats['best_score']}/24")
print(f"  Best config: {stats['best_config']}")
print()

# Show top results
if all_results:
    all_results.sort(key=lambda x: -x["score"])
    top_n = min(20, len(all_results))
    print(f"  Top {top_n} results (score > {NOISE_FLOOR}):")
    for i, r in enumerate(all_results[:top_n]):
        print(f"    {i+1}. {r['method']}/{r['variant']}: {r['score']}/24")
        print(f"       Key: {r['key_prefix']}...")
        print(f"       PT:  {r['plaintext'][:50]}...")
    print()

overall_best = stats["best_score"]
if overall_best >= SIGNAL_THRESHOLD:
    verdict = f"SIGNAL — {overall_best}/24"
elif overall_best > NOISE_FLOOR:
    verdict = f"STORE — {overall_best}/24 (above noise but below signal)"
else:
    verdict = f"NOISE — {overall_best}/24"

print(f"  VERDICT: {verdict}")
print()

# ── Save results ───────────────────────────────────────────────────────

os.makedirs("results", exist_ok=True)
output = {
    "experiment": "E-BESPOKE-11",
    "description": "Tableau-as-key-source via structured extraction",
    "total_methods": total_methods,
    "total_tests": total_tests,
    "elapsed_seconds": total_elapsed,
    "best_score": stats["best_score"],
    "best_config": stats["best_config"],
    "verdict": verdict,
    "phase_summaries": phase_summaries,
    "top_results": all_results[:50] if all_results else [],
}

outpath = "results/e_bespoke_11_tableau_extraction.json"
with open(outpath, "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"  Artifact: {outpath}")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_bespoke_11_tableau_extraction.py")
