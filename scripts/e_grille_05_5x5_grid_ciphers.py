#!/usr/bin/env python3
"""E-GRILLE-05: 5x5 Grid Cipher Attacks on YAR Grille CT.

The YAR grille CT has exactly 25 unique letters (T missing) — a perfect fit
for 5x5 grid ciphers like Playfair, Bifid, ADFGX, and Nihilist.

CT: HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD
Length: 106 chars, 25 unique letters, no T.

Usage: PYTHONPATH=src python3 -u scripts/e_grille_05_5x5_grid_ciphers.py
"""
from __future__ import annotations

import json
import math
import os
import sys
from collections import Counter
from itertools import permutations
from typing import List, Tuple, Dict, Optional

# ── Constants ────────────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-GRILLE-05"

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
CT_LEN = len(GRILLE_CT)  # 106

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPH25 = "ABCDEFGHIJKLMNOPQRSUVWXYZ"  # 25 letters, T removed

# Keywords to try as 5x5 grid keys
KEYWORDS = [
    "KRYPTOS", "KRYPTOS", "ABSCISSA", "PALIMPSEST", "SANBORN",
    "SCHEIDT", "YAR", "CARDAN", "GRILLE", "BERLIN", "CLOCK",
    "BERLINCLOCK", "EASTNORTHEAST", "SHADOW", "LIGHT",
    "UNDERGROUND", "KRYPTOSABCDEFGHIJLMNQUVWXZ",
    "EQUINOX", "MERIDIAN", "CIPHER", "SECRET",
    "", # empty = standard alphabet order
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
    """Log-probability score using quadgrams. Higher = more English-like."""
    if not QUADGRAMS or len(text) < 4:
        return -99.0
    floor = -10.0
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, floor)
    return score / max(1, len(text) - 3)


def count_words(text: str) -> Tuple[int, List[str]]:
    """Count English words (4+ letters) found in text."""
    found = []
    for length in range(min(15, len(text)), 3, -1):
        for i in range(len(text) - length + 1):
            word = text[i:i+length]
            if word in ENGLISH_WORDS and word not in found:
                found.append(word)
    return len(found), found


# ── 5x5 Grid Construction ───────────────────────────────────────────────────

def build_5x5_grid(keyword: str, removed: str = "T") -> str:
    """Build a 5x5 grid alphabet from keyword, removing one letter.

    Returns a 25-character string representing the grid (row-major order).
    """
    seen = set()
    grid = []
    # Process keyword first
    for ch in keyword.upper():
        if ch.isalpha() and ch != removed and ch not in seen:
            seen.add(ch)
            grid.append(ch)
    # Fill remaining with alphabet
    for ch in ALPH:
        if ch != removed and ch not in seen:
            seen.add(ch)
            grid.append(ch)
    assert len(grid) == 25, f"Grid has {len(grid)} chars, expected 25"
    return "".join(grid)


def grid_coords(grid: str, ch: str) -> Tuple[int, int]:
    """Get (row, col) of character in 5x5 grid."""
    idx = grid.index(ch)
    return idx // 5, idx % 5


def grid_at(grid: str, row: int, col: int) -> str:
    """Get character at (row, col) in 5x5 grid."""
    return grid[row * 5 + col]


# ── Playfair ─────────────────────────────────────────────────────────────────

def playfair_decrypt_digraph(grid: str, a: str, b: str) -> Tuple[str, str]:
    """Decrypt a single Playfair digraph."""
    r1, c1 = grid_coords(grid, a)
    r2, c2 = grid_coords(grid, b)

    if r1 == r2:
        # Same row: shift left
        return grid_at(grid, r1, (c1 - 1) % 5), grid_at(grid, r2, (c2 - 1) % 5)
    elif c1 == c2:
        # Same column: shift up
        return grid_at(grid, (r1 - 1) % 5, c1), grid_at(grid, (r2 - 1) % 5, c2)
    else:
        # Rectangle: swap columns
        return grid_at(grid, r1, c2), grid_at(grid, r2, c1)


def playfair_decrypt(ct: str, grid: str, offset: int = 0) -> Optional[str]:
    """Decrypt Playfair cipher.

    offset=0: digraphs at (0,1)(2,3)...
    offset=1: skip first char, digraphs at (1,2)(3,4)...
    """
    text = ct[offset:]
    if len(text) % 2 != 0:
        text = text[:-1]  # drop last char if odd

    # Verify all chars are in the grid
    for ch in text:
        if ch not in grid:
            return None

    pt = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        if a == b:
            # Same-letter digraph — invalid in standard Playfair
            # but we try anyway (some variants allow it)
            pass
        pa, pb = playfair_decrypt_digraph(grid, a, b)
        pt.append(pa)
        pt.append(pb)

    return "".join(pt)


# ── Bifid ────────────────────────────────────────────────────────────────────

def bifid_decrypt(ct: str, grid: str, period: int) -> Optional[str]:
    """Decrypt Bifid cipher with given period."""
    # Verify all chars are in the grid
    for ch in ct:
        if ch not in grid:
            return None

    pt_chars = []

    # Process in blocks of 'period'
    for block_start in range(0, len(ct), period):
        block = ct[block_start:block_start + period]
        block_len = len(block)

        # Get coordinates
        rows = []
        cols = []
        for ch in block:
            r, c = grid_coords(grid, ch)
            rows.append(r)
            cols.append(c)

        # Interleave: the CT coordinates were formed by splitting
        # row coords then col coords. To decrypt, combine them back.
        combined = rows + cols

        # Take pairs from the combined list
        for i in range(block_len):
            r = combined[i]
            c = combined[block_len + i]
            pt_chars.append(grid_at(grid, r, c))

    return "".join(pt_chars)


# ── ADFGX ────────────────────────────────────────────────────────────────────

def adfgx_decrypt(ct: str, grid: str, col_key: List[int]) -> Optional[str]:
    """Decrypt ADFGX cipher.

    ADFGX encryption:
    1. Each PT letter -> 2 ADFGX chars (row, col in 5x5 grid)
    2. Write ADFGX pairs into rows of width=len(col_key)
    3. Read columns in col_key order

    To decrypt:
    1. Reverse the columnar transposition on CT
    2. Take pairs of chars as (row, col) in the grid
    3. Look up the letter

    But CT here is already alphabetic, not ADFGX fractionated.
    We need to interpret CT letters as ADFGX fractionated characters.

    Actually, for ADFGX, the ciphertext IS in the ADFGX alphabet (A,D,F,G,X).
    Let's check if the grille CT could be ADFGX-encoded.
    """
    # ADFGX uses only 5 letters: A, D, F, G, X
    # Our CT has 25 unique letters, so it's NOT directly ADFGX-encoded.
    # ADFGX would produce CT in {A,D,F,G,X} only.
    return None  # Not applicable directly


def adfgx_check(ct: str) -> bool:
    """Check if CT could be ADFGX (only A,D,F,G,X letters)."""
    return all(ch in "ADFGX" for ch in ct)


# ── Nihilist cipher ──────────────────────────────────────────────────────────

def nihilist_decrypt(ct_numbers: List[int], grid: str, key: str) -> Optional[str]:
    """Decrypt Nihilist cipher.

    Nihilist: CT_num = PT_polybius + KEY_polybius
    """
    pt = []
    klen = len(key)
    for i, ct_num in enumerate(ct_numbers):
        key_ch = key[i % klen]
        kr, kc = grid_coords(grid, key_ch)
        key_num = (kr + 1) * 10 + (kc + 1)

        pt_num = ct_num - key_num
        pr = pt_num // 10 - 1
        pc = pt_num % 10 - 1
        if 0 <= pr < 5 and 0 <= pc < 5:
            pt.append(grid_at(grid, pr, pc))
        else:
            return None  # invalid
    return "".join(pt)


def text_to_polybius_numbers(text: str, grid: str) -> Optional[List[int]]:
    """Convert text to Polybius numbers (11-55)."""
    nums = []
    for ch in text:
        if ch not in grid:
            return None
        r, c = grid_coords(grid, ch)
        nums.append((r + 1) * 10 + (c + 1))
    return nums


# ── Polybius square substitution ─────────────────────────────────────────────

def polybius_pairs_decrypt(ct: str, grid: str) -> Optional[str]:
    """Interpret CT as pairs of Polybius coordinates.

    Each pair of CT letters gives (row_letter, col_letter).
    Map each to its position in the grid, then look up the letter.
    """
    if len(ct) % 2 != 0:
        return None

    pt = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i+1]
        if a not in grid or b not in grid:
            return None
        # Interpret grid position of a as row, grid position of b as column
        ra, ca = grid_coords(grid, a)
        rb, cb = grid_coords(grid, b)
        # Various interpretations:
        # Use row of a and col of b
        r, c = ra, cb
        if 0 <= r < 5 and 0 <= c < 5:
            pt.append(grid_at(grid, r, c))
        else:
            return None
    return "".join(pt)


def polybius_pairs_decrypt_v2(ct: str, grid: str) -> Optional[str]:
    """Variant: use col of a and row of b."""
    if len(ct) % 2 != 0:
        return None

    pt = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i+1]
        if a not in grid or b not in grid:
            return None
        ra, ca = grid_coords(grid, a)
        rb, cb = grid_coords(grid, b)
        r, c = ca, rb
        if 0 <= r < 5 and 0 <= c < 5:
            pt.append(grid_at(grid, r, c))
        else:
            return None
    return "".join(pt)


# ── Two-Square / Four-Square ────────────────────────────────────────────────

def two_square_decrypt(ct: str, grid1: str, grid2: str, horizontal: bool = True) -> Optional[str]:
    """Decrypt Two-Square (horizontal or vertical) cipher."""
    if len(ct) % 2 != 0:
        return None

    pt = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i+1]
        if a not in grid1 or b not in grid2:
            return None

        r1, c1 = grid_coords(grid1, a)
        r2, c2 = grid_coords(grid2, b)

        if horizontal:
            # Horizontal two-square: grids side by side
            # PT1 at (r1, c2), PT2 at (r2, c1) — but in standard alphabet grid
            # Actually: PT1 = grid_standard(r1, c2), PT2 = grid_standard(r2, c1)
            # For simplicity, use plain alphabet grid for PT
            pt_grid = ALPH25  # standard order
            pt.append(grid_at(pt_grid, r1, c2))
            pt.append(grid_at(pt_grid, r2, c1))
        else:
            # Vertical two-square
            pt_grid = ALPH25
            pt.append(grid_at(pt_grid, r2, c1))
            pt.append(grid_at(pt_grid, r1, c2))

    return "".join(pt)


# ── Main Attack Runner ───────────────────────────────────────────────────────

class Result:
    def __init__(self, method: str, text: str, score: float, keyword: str = "", details: str = ""):
        self.method = method
        self.text = text
        self.score = score
        self.keyword = keyword
        self.details = details


def run_attacks():
    results: List[Result] = []
    ct = GRILLE_CT
    configs_tested = 0

    print(f"\n{'='*80}")
    print(f"{EXPERIMENT_ID}: 5x5 Grid Cipher Attacks on YAR Grille CT")
    print(f"CT length: {CT_LEN}, Unique letters: {len(set(ct))}")
    print(f"Missing: {sorted(set(ALPH) - set(ct))}")
    print(f"CT: {ct}")
    print(f"{'='*80}\n")

    # Verify LL position
    ll_pos = ct.find("LL")
    print(f"LL found at positions {ll_pos}-{ll_pos+1}")
    print(f"  Digraph alignment 0: pos 42-43 = digraph 21 = '{ct[42]}{ct[43]}' = LL (INVALID in Playfair)")
    print(f"  Digraph alignment 1: pos 41-42 = '{ct[41]}{ct[42]}', pos 43-44 = '{ct[43]}{ct[44]}' (valid)")
    print()

    # Deduplicate keywords
    unique_keywords = list(dict.fromkeys(KEYWORDS))

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 1: Playfair
    # ══════════════════════════════════════════════════════════════════════════
    print("[1] Playfair decryption...")

    # Try T-removed grids
    for kw in unique_keywords:
        grid = build_5x5_grid(kw, removed="T")

        # Check that all CT chars are in the grid
        if not all(ch in grid for ch in ct):
            missing = set(ct) - set(grid)
            continue

        for offset in [0, 1]:
            pt = playfair_decrypt(ct, grid, offset)
            if pt:
                sc = quadgram_score(pt)
                results.append(Result(f"playfair(kw={kw or 'NONE'},off={offset})", pt, sc, kw))
                configs_tested += 1

    # Also try I/J merge instead of T removal (traditional Playfair)
    # But CT has both I and J, so I/J merge would need to handle this
    # Actually, if we merge I/J, we'd replace all J with I in CT first
    for kw in unique_keywords:
        grid_ij = build_5x5_grid(kw, removed="J")
        ct_ij = ct.replace("J", "I")
        if not all(ch in grid_ij for ch in ct_ij):
            continue
        for offset in [0, 1]:
            pt = playfair_decrypt(ct_ij, grid_ij, offset)
            if pt:
                sc = quadgram_score(pt)
                results.append(Result(f"playfair_IJ(kw={kw or 'NONE'},off={offset})", pt, sc, kw))
                configs_tested += 1

    print(f"  Tested {configs_tested} Playfair configs")
    pf_count = configs_tested

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 2: Bifid cipher
    # ══════════════════════════════════════════════════════════════════════════
    print("[2] Bifid cipher decryption...")
    bifid_count = 0

    periods_to_try = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 26, 53, 106]

    for kw in unique_keywords:
        grid = build_5x5_grid(kw, removed="T")
        if not all(ch in grid for ch in ct):
            continue

        for period in periods_to_try:
            pt = bifid_decrypt(ct, grid, period)
            if pt:
                sc = quadgram_score(pt)
                results.append(Result(f"bifid(kw={kw or 'NONE'},p={period})", pt, sc, kw))
                bifid_count += 1

        # Also try I/J merge
        grid_ij = build_5x5_grid(kw, removed="J")
        ct_ij = ct.replace("J", "I")
        if not all(ch in grid_ij for ch in ct_ij):
            continue
        for period in periods_to_try:
            pt = bifid_decrypt(ct_ij, grid_ij, period)
            if pt:
                sc = quadgram_score(pt)
                results.append(Result(f"bifid_IJ(kw={kw or 'NONE'},p={period})", pt, sc, kw))
                bifid_count += 1

    configs_tested += bifid_count
    print(f"  Tested {bifid_count} Bifid configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 3: Polybius pair substitution
    # ══════════════════════════════════════════════════════════════════════════
    print("[3] Polybius pair substitution...")
    poly_count = 0

    for kw in unique_keywords:
        grid = build_5x5_grid(kw, removed="T")
        if not all(ch in grid for ch in ct):
            continue

        # Version 1: row(a), col(b)
        pt = polybius_pairs_decrypt(ct, grid)
        if pt:
            sc = quadgram_score(pt)
            results.append(Result(f"polybius_rc(kw={kw or 'NONE'})", pt, sc, kw))
            poly_count += 1

        # Version 2: col(a), row(b)
        pt = polybius_pairs_decrypt_v2(ct, grid)
        if pt:
            sc = quadgram_score(pt)
            results.append(Result(f"polybius_cr(kw={kw or 'NONE'})", pt, sc, kw))
            poly_count += 1

        # Version 3: full coord interpretation
        # row(a)*5+col(b) and row(b)*5+col(a) — direct Polybius
        for offset in [0, 1]:
            text = ct[offset:]
            if len(text) % 2 != 0:
                text = text[:-1]
            pt_chars = []
            valid = True
            for i in range(0, len(text), 2):
                a, b = text[i], text[i+1]
                if a not in grid or b not in grid:
                    valid = False
                    break
                ra, ca = grid_coords(grid, a)
                rb, cb = grid_coords(grid, b)
                # Interpret (ra, cb) as polybius index
                idx = ra * 5 + cb
                if 0 <= idx < 25:
                    pt_chars.append(grid[idx])
                else:
                    valid = False
                    break
            if valid and pt_chars:
                pt = "".join(pt_chars)
                sc = quadgram_score(pt)
                results.append(Result(f"polybius_idx(kw={kw or 'NONE'},off={offset})", pt, sc, kw))
                poly_count += 1

    configs_tested += poly_count
    print(f"  Tested {poly_count} Polybius pair configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 4: Two-Square cipher
    # ══════════════════════════════════════════════════════════════════════════
    print("[4] Two-Square cipher decryption...")
    twosq_count = 0

    # Try pairs of keywords
    for kw1 in unique_keywords:
        for kw2 in unique_keywords:
            grid1 = build_5x5_grid(kw1, removed="T")
            grid2 = build_5x5_grid(kw2, removed="T")

            if not all(ch in grid1 for ch in ct):
                continue
            if not all(ch in grid2 for ch in ct):
                continue

            for horiz in [True, False]:
                for offset in [0, 1]:
                    text = ct[offset:]
                    if len(text) % 2 != 0:
                        text = text[:-1]
                    pt = two_square_decrypt(text, grid1, grid2, horizontal=horiz)
                    if pt:
                        sc = quadgram_score(pt)
                        dir_label = "horiz" if horiz else "vert"
                        results.append(Result(
                            f"twosquare({dir_label},k1={kw1 or 'NONE'},k2={kw2 or 'NONE'},off={offset})",
                            pt, sc, f"{kw1}/{kw2}"))
                        twosq_count += 1

    configs_tested += twosq_count
    print(f"  Tested {twosq_count} Two-Square configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 5: ADFGX check
    # ══════════════════════════════════════════════════════════════════════════
    print("[5] ADFGX check...")
    is_adfgx = adfgx_check(ct)
    print(f"  CT is ADFGX-compatible (only A,D,F,G,X): {is_adfgx}")
    if not is_adfgx:
        non_adfgx = sorted(set(ct) - set("ADFGX"))
        print(f"  Non-ADFGX letters present: {non_adfgx}")
        print(f"  ADFGX is NOT applicable to this CT")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 6: Nihilist cipher
    # ══════════════════════════════════════════════════════════════════════════
    print("[6] Nihilist cipher decryption...")
    nihilist_count = 0

    # In Nihilist, CT is usually numeric (two-digit numbers).
    # If the grille CT letters represent Polybius coordinates, we can try to
    # interpret them as Nihilist-encoded.
    # Convert CT letters to Polybius numbers using various grids, then try
    # subtracting key Polybius numbers.
    for kw_grid in unique_keywords[:8]:  # limit grid keywords
        grid = build_5x5_grid(kw_grid, removed="T")
        if not all(ch in grid for ch in ct):
            continue

        ct_nums = text_to_polybius_numbers(ct, grid)
        if ct_nums is None:
            continue

        for kw_key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "YAR", "SCHEIDT"]:
            # Remove T from key
            key = kw_key.replace("T", "")
            if not key:
                continue
            if not all(ch in grid for ch in key):
                continue

            pt = nihilist_decrypt(ct_nums, grid, key)
            if pt:
                sc = quadgram_score(pt)
                results.append(Result(f"nihilist(grid={kw_grid or 'NONE'},key={kw_key})", pt, sc, kw_key))
                nihilist_count += 1

    configs_tested += nihilist_count
    print(f"  Tested {nihilist_count} Nihilist configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 7: Seriated Playfair (larger grid variants)
    # ══════════════════════════════════════════════════════════════════════════
    print("[7] Extended Playfair variants (6x6 with digits if applicable)...")
    # The CT has only letters, no digits, so 6x6 with digits doesn't apply.
    # But try Playfair with different removed letters
    for removed in ALPH:
        if removed == "T":
            continue  # already tested
        # Check if all CT chars survive with this letter removed
        if removed in ct:
            continue  # can't remove a letter present in CT

        for kw in unique_keywords[:6]:
            grid = build_5x5_grid(kw, removed=removed)
            if not all(ch in grid for ch in ct):
                continue
            for offset in [0, 1]:
                pt = playfair_decrypt(ct, grid, offset)
                if pt:
                    sc = quadgram_score(pt)
                    results.append(Result(
                        f"playfair(kw={kw or 'NONE'},rm={removed},off={offset})",
                        pt, sc, kw))
                    configs_tested += 1

    print(f"  (Only T can be removed — all other letters appear in CT)")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 8: Bifid with columnar transposition (ADFGX-like hybrid)
    # ══════════════════════════════════════════════════════════════════════════
    print("[8] Bifid + columnar transposition hybrid...")
    hybrid_count = 0

    for kw in unique_keywords[:6]:
        grid = build_5x5_grid(kw, removed="T")
        if not all(ch in grid for ch in ct):
            continue

        # First, convert CT to Polybius coordinates
        coords = []
        for ch in ct:
            r, c = grid_coords(grid, ch)
            coords.append(r)
            coords.append(c)
        # coords is now 212 digits (0-4)

        # Try reversing a columnar transposition on coords
        for width in range(2, 11):
            nrows = math.ceil(len(coords) / width)
            total = nrows * width
            padded = coords + [0] * (total - len(coords))

            # Try reading columns in natural order (undo columnar)
            # This means: write into columns, read rows
            cols_data = []
            short_cols = total - len(coords)
            pos = 0
            for col in range(width):
                col_len = nrows - (1 if col >= width - short_cols else 0)
                cols_data.append(padded[pos:pos + col_len])
                pos += col_len

            # Read rows from the column data
            flat = []
            for row in range(nrows):
                for col in range(width):
                    if row < len(cols_data[col]):
                        flat.append(cols_data[col][row])

            # Now interpret pairs as Polybius coordinates
            pt_chars = []
            for i in range(0, len(flat) - 1, 2):
                r, c = flat[i], flat[i+1]
                if 0 <= r < 5 and 0 <= c < 5:
                    pt_chars.append(grid_at(grid, r, c))

            if pt_chars:
                pt = "".join(pt_chars)
                sc = quadgram_score(pt)
                if sc > -9.0:
                    results.append(Result(
                        f"bifid_columnar(kw={kw or 'NONE'},w={width})",
                        pt, sc, kw))
                hybrid_count += 1

    configs_tested += hybrid_count
    print(f"  Tested {hybrid_count} hybrid configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 9: Conjugated Matrix Bifid (Scheidt's CKM-style)
    # ══════════════════════════════════════════════════════════════════════════
    print("[9] Conjugated Matrix Bifid (two different grids for row/col)...")
    cmb_count = 0

    for kw1 in unique_keywords[:8]:
        for kw2 in unique_keywords[:8]:
            if kw1 == kw2:
                continue  # need different grids
            grid1 = build_5x5_grid(kw1, removed="T")
            grid2 = build_5x5_grid(kw2, removed="T")

            if not all(ch in grid1 for ch in ct) or not all(ch in grid2 for ch in ct):
                continue

            # CM-Bifid: use grid1 for rows, grid2 for columns
            for period in [5, 7, 10, 53, 106]:
                pt_chars = []

                for block_start in range(0, len(ct), period):
                    block = ct[block_start:block_start + period]
                    block_len = len(block)

                    # Get coordinates using grid1
                    rows = []
                    cols = []
                    for ch in block:
                        r, c = grid_coords(grid1, ch)
                        rows.append(r)
                        cols.append(c)

                    combined = rows + cols

                    # Take pairs and decode using grid2
                    for i in range(block_len):
                        r = combined[i]
                        c = combined[block_len + i]
                        if 0 <= r < 5 and 0 <= c < 5:
                            pt_chars.append(grid_at(grid2, r, c))

                if pt_chars:
                    pt = "".join(pt_chars)
                    sc = quadgram_score(pt)
                    if sc > -9.0:
                        results.append(Result(
                            f"cm_bifid(g1={kw1 or 'NONE'},g2={kw2 or 'NONE'},p={period})",
                            pt, sc, f"{kw1}/{kw2}"))
                    cmb_count += 1

    configs_tested += cmb_count
    print(f"  Tested {cmb_count} conjugated matrix bifid configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Attack 10: Four-Square cipher
    # ══════════════════════════════════════════════════════════════════════════
    print("[10] Four-Square cipher decryption...")
    foursq_count = 0

    # Four-Square uses 4 grids: 2 plain (standard) and 2 keyed
    plain_grid = build_5x5_grid("", removed="T")

    for kw1 in unique_keywords[:10]:
        for kw2 in unique_keywords[:10]:
            grid1 = build_5x5_grid(kw1, removed="T")
            grid2 = build_5x5_grid(kw2, removed="T")

            for offset in [0, 1]:
                text = ct[offset:]
                if len(text) % 2 != 0:
                    text = text[:-1]

                pt_chars = []
                valid = True
                for i in range(0, len(text), 2):
                    a, b = text[i], text[i+1]
                    if a not in grid1 or b not in grid2:
                        valid = False
                        break
                    r1, c1 = grid_coords(grid1, a)
                    r2, c2 = grid_coords(grid2, b)
                    # Plaintext: (r1, c2) in plain_grid and (r2, c1) in plain_grid
                    pt_chars.append(grid_at(plain_grid, r1, c2))
                    pt_chars.append(grid_at(plain_grid, r2, c1))

                if valid and pt_chars:
                    pt = "".join(pt_chars)
                    sc = quadgram_score(pt)
                    if sc > -9.0:
                        results.append(Result(
                            f"foursquare(k1={kw1 or 'NONE'},k2={kw2 or 'NONE'},off={offset})",
                            pt, sc, f"{kw1}/{kw2}"))
                    foursq_count += 1

    configs_tested += foursq_count
    print(f"  Tested {foursq_count} Four-Square configs")

    # ══════════════════════════════════════════════════════════════════════════
    # Results
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'='*80}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*80}\n")

    results.sort(key=lambda r: r.score, reverse=True)

    print(f"Total configurations tested: {configs_tested:,}")
    print(f"Total results collected: {len(results)}")

    # English threshold: typical English ~-4.0 to -4.5, random ~-8.0 to -9.0
    print(f"\n--- TOP 20 RESULTS ---\n")
    for i, r in enumerate(results[:20]):
        nw, words = count_words(r.text)
        print(f"#{i+1} [qg={r.score:.4f}] {r.method}")
        print(f"  Text: {r.text[:90]}{'...' if len(r.text) > 90 else ''}")
        print(f"  Words({nw}): {', '.join(words[:10])}")
        print()

    # Check for any approaching English
    english_threshold = -5.5
    promising = [r for r in results if r.score > english_threshold]
    if promising:
        print(f"\n*** PROMISING RESULTS (quadgram > {english_threshold}) ***")
        for r in promising:
            nw, words = count_words(r.text)
            print(f"  [{r.score:.4f}] {r.method}")
            print(f"  Text: {r.text}")
            print(f"  Words: {', '.join(words[:15])}")
    else:
        print(f"\nNo results above English threshold ({english_threshold})")
        print("All results are in the noise/random range.")

    # LL analysis
    print(f"\n--- LL DIGRAPH ANALYSIS ---")
    print(f"CT positions 42-43 = '{ct[42]}{ct[43]}' (LL)")
    print(f"Standard Playfair CANNOT produce identical letter digraphs.")
    print(f"Digraph alignment 0: 'LL' at digraph 21 = INVALID for standard Playfair")
    print(f"Digraph alignment 1: avoids LL digraph = VALID for standard Playfair")
    print(f"Conclusion: If Playfair, must use alignment offset 1 (or variant rules)")

    print(f"\n{'='*80}")
    print(f"{EXPERIMENT_ID} COMPLETE — {configs_tested:,} configurations tested")
    print(f"{'='*80}")

    return results


if __name__ == "__main__":
    results = run_attacks()
