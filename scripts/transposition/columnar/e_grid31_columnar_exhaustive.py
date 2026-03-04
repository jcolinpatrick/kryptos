#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Exhaustive columnar transposition search on width-31 grid and other widths for K4.

Context: Sanborn's working chart uses a 31-character-wide grid. K3+?+K4 = 434 chars
fills exactly 14 rows. K4 sits in the last ~3.1 rows starting at row 11, col 27.

Strategies:
1. Keyword-based columnar transposition on width-31 grid (K4 standalone, 97 chars)
2. K4 standalone on smaller grids (widths 7, 8, 10, 12, 13, etc.)
3. All permutation-based column orders for small widths
4. Grid reading patterns (column-major, diagonal, spiral, serpentine)
5. After each unscrambling, try Vigenere/Beaufort with known keywords

Checks for EASTNORTHEAST and BERLINCLOCK cribs at ANY position in output.
"""
from __future__ import annotations

import itertools
import json
import math
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_WORDS, CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
)
from kryptos.kernel.transforms.transposition import (
    invert_perm, apply_perm, validate_perm,
    columnar_perm, keyword_to_order, myszkowski_perm,
    rail_fence_perm, serpentine_perm, spiral_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, vig_decrypt, beau_decrypt, varbeau_decrypt,
)


# ── Load quadgrams ──────────────────────────────────────────────────────────
QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
QUADGRAMS: Dict[str, float] = {}
QUADGRAM_FLOOR: float = -10.0

def load_quadgrams():
    global QUADGRAMS, QUADGRAM_FLOOR
    with open(QUADGRAM_PATH) as f:
        QUADGRAMS = json.load(f)
    if QUADGRAMS:
        QUADGRAM_FLOOR = min(QUADGRAMS.values()) - 1.0

load_quadgrams()


def quadgram_score(text: str) -> float:
    """Average log-probability per quadgram."""
    if len(text) < 4:
        return QUADGRAM_FLOOR
    total = 0.0
    count = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QUADGRAMS.get(qg, QUADGRAM_FLOOR)
        count += 1
    return total / count if count > 0 else QUADGRAM_FLOOR


# ── Crib checking ──────────────────────────────────────────────────────────
CRIB_STRINGS = ["EASTNORTHEAST", "BERLINCLOCK"]
ALL_CRIBS = CRIB_STRINGS + [
    "EAST", "NORTH", "NORTHEAST", "BERLIN", "CLOCK",
    "SLOWLY", "DESPER", "ATELY", "UNDER", "GROUND",
    "LAYER", "LIGHT", "SHADOW", "TUNNEL", "BURIED",
]

def check_cribs(text: str) -> List[str]:
    """Return list of crib words found anywhere in text."""
    found = []
    for crib in ALL_CRIBS:
        if crib in text:
            found.append(crib)
    return found


def check_primary_cribs(text: str) -> int:
    """Count primary crib characters at canonical positions (0-indexed)."""
    count = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            count += 1
    return count


def check_any_position_cribs(text: str) -> List[Tuple[str, int]]:
    """Check if EASTNORTHEAST or BERLINCLOCK appear at ANY position."""
    found = []
    for crib in CRIB_STRINGS:
        for i in range(len(text) - len(crib) + 1):
            if text[i:i+len(crib)] == crib:
                found.append((crib, i))
    return found


# ── Decryption helpers ──────────────────────────────────────────────────────
KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "EASTNORTHEAST"]
ALPHABETS = {
    "AZ": ALPH,
    "KA": KRYPTOS_ALPHABET,
}

def keyword_to_numeric(keyword: str, alphabet: str = ALPH) -> List[int]:
    """Convert keyword string to numeric key values."""
    idx = {c: i for i, c in enumerate(alphabet)}
    return [idx[c] for c in keyword.upper()]


def decrypt_with_config(ct_text: str, keyword: str, variant: CipherVariant, alphabet: str) -> str:
    """Decrypt with given keyword, variant, and alphabet."""
    idx = {c: i for i, c in enumerate(alphabet)}
    key = [idx[c] for c in keyword.upper()]
    klen = len(key)

    if variant == CipherVariant.VIGENERE:
        fn = lambda c, k: (c - k) % 26
    elif variant == CipherVariant.BEAUFORT:
        fn = lambda c, k: (k - c) % 26
    else:
        fn = lambda c, k: (c + k) % 26

    result = []
    for i, ch in enumerate(ct_text):
        c_val = idx[ch]
        k_val = key[i % klen]
        p_val = fn(c_val, k_val)
        result.append(alphabet[p_val])
    return "".join(result)


# ── Columnar transposition generation ──────────────────────────────────────
def generate_keyword_column_order(keyword: str, width: int) -> Optional[List[int]]:
    """Generate column order from keyword for given width.

    If keyword < width, extend with remaining alphabet letters.
    """
    kw = keyword.upper()
    if len(kw) > width:
        kw = kw[:width]

    # Extend keyword to width if needed
    if len(kw) < width:
        used = set(kw)
        for c in ALPH:
            if c not in used:
                kw += c
                used.add(c)
                if len(kw) == width:
                    break

    if len(kw) < width:
        return None

    # Generate column order: rank each position alphabetically
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    order = [0] * width
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return order


def columnar_encrypt_perm(width: int, col_order: List[int], length: int) -> List[int]:
    """Generate permutation for columnar encryption (write rows, read columns).

    This gives us the permutation that was APPLIED during encryption.
    To UNDO it, we need the inverse.
    """
    nrows = math.ceil(length / width)
    # Write in rows
    grid_positions = []
    for r in range(nrows):
        for c in range(width):
            pos = r * width + c
            if pos < length:
                grid_positions.append((r, c, pos))

    # Read by column order
    perm = []
    for rank in range(width):
        col_idx = col_order.index(rank)
        for r, c, pos in grid_positions:
            if c == col_idx:
                perm.append(pos)

    return perm


def columnar_decrypt(ct_text: str, width: int, col_order: List[int]) -> str:
    """Decrypt columnar transposition: reverse the encrypt process.

    During encryption: write PT in rows, read by column order.
    During decryption: write CT into columns (by order), read rows.
    """
    length = len(ct_text)
    nrows = math.ceil(length / width)

    # Calculate column lengths (some columns may be shorter)
    full_cols = length % width  # number of columns with nrows elements
    if full_cols == 0:
        full_cols = width  # all columns full
        col_lengths = [nrows] * width
    else:
        col_lengths = []
        for c in range(width):
            if c < full_cols:
                col_lengths.append(nrows)
            else:
                col_lengths.append(nrows - 1)

    # But column order determines which columns get the extra row
    # Columns 0..full_cols-1 (by position) have nrows; rest have nrows-1
    # When reading by col_order, we need to know actual column positions

    # Recalculate: which column positions have extra chars?
    remainder = length % width
    if remainder == 0:
        col_lens = {c: nrows for c in range(width)}
    else:
        col_lens = {}
        for c in range(width):
            col_lens[c] = nrows if c < remainder else nrows - 1

    # Write CT into columns by rank order
    grid = {}
    ct_idx = 0
    for rank in range(width):
        col_idx = col_order.index(rank)
        clen = col_lens[col_idx]
        for r in range(clen):
            grid[(r, col_idx)] = ct_text[ct_idx]
            ct_idx += 1

    # Read rows
    result = []
    for r in range(nrows):
        for c in range(width):
            if (r, c) in grid:
                result.append(grid[(r, c)])

    return "".join(result)


def double_columnar_decrypt(ct_text: str, width1: int, order1: List[int],
                             width2: int, order2: List[int]) -> str:
    """Double columnar transposition decryption."""
    intermediate = columnar_decrypt(ct_text, width1, order1)
    return columnar_decrypt(intermediate, width2, order2)


# ── Results tracking ────────────────────────────────────────────────────────
class ResultTracker:
    def __init__(self):
        self.results = []
        self.best_score = -999.0
        self.best_crib_count = 0
        self.total_tested = 0
        self.crib_hits = []

    def record(self, desc: str, unscrambled: str, decrypted: str,
               decrypt_desc: str, qg_score: float):
        self.total_tested += 1

        # Check cribs at any position
        any_cribs = check_any_position_cribs(decrypted)
        # Check cribs at canonical positions
        canon_cribs = check_primary_cribs(decrypted)
        # Check word fragments
        found_words = check_cribs(decrypted)

        entry = {
            "desc": desc,
            "decrypt": decrypt_desc,
            "unscrambled": unscrambled,
            "decrypted": decrypted,
            "qg_score": qg_score,
            "canonical_cribs": canon_cribs,
            "any_position_cribs": any_cribs,
            "found_words": found_words,
        }

        is_interesting = False

        if any_cribs:
            self.crib_hits.append(entry)
            is_interesting = True
            print(f"\n*** CRIB HIT *** {desc} | {decrypt_desc}")
            print(f"    Decrypted: {decrypted}")
            print(f"    Cribs found: {any_cribs}")
            print(f"    QG: {qg_score:.3f}")

        if canon_cribs >= 10:
            is_interesting = True
            print(f"\n*** HIGH CANONICAL CRIBS ({canon_cribs}/24) *** {desc} | {decrypt_desc}")
            print(f"    Decrypted: {decrypted}")

        if qg_score > -5.5:
            is_interesting = True
            if not any_cribs:
                print(f"\n  Good QG ({qg_score:.3f}): {desc} | {decrypt_desc}")
                print(f"    Decrypted: {decrypted[:60]}...")

        if found_words and len(found_words) >= 2:
            is_interesting = True
            if not any_cribs:
                print(f"\n  Words found ({found_words}): {desc} | {decrypt_desc}")

        if is_interesting:
            self.results.append(entry)

        if qg_score > self.best_score:
            self.best_score = qg_score

        if canon_cribs > self.best_crib_count:
            self.best_crib_count = canon_cribs


def try_all_decryptions(tracker: ResultTracker, desc: str, unscrambled: str):
    """Try all keyword/variant/alphabet decryptions on an unscrambled text."""
    # First check the unscrambled text itself
    qg = quadgram_score(unscrambled)
    tracker.record(desc, unscrambled, unscrambled, "identity", qg)

    for kw in KEYWORDS:
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]:
            for alph_name, alph in ALPHABETS.items():
                try:
                    decrypted = decrypt_with_config(unscrambled, kw, variant, alph)
                    qg = quadgram_score(decrypted)
                    d_desc = f"{variant.value}/{kw}/{alph_name}"
                    tracker.record(desc, unscrambled, decrypted, d_desc, qg)
                except Exception:
                    pass


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 1: Width-31 grid with keyword column orders
# ══════════════════════════════════════════════════════════════════════════
def strategy_width31_keywords(tracker: ResultTracker):
    """Columnar transposition on width-31 grid using various keywords."""
    print("\n" + "="*70)
    print("STRATEGY 1: Width-31 columnar transposition with keywords")
    print("="*70)

    for kw in KEYWORDS:
        col_order = generate_keyword_column_order(kw, 31)
        if col_order is None:
            print(f"  Skipping {kw} (too short for width 31)")
            continue

        # Decrypt columnar (undo the transposition)
        unscrambled = columnar_decrypt(CT, 31, col_order)
        print(f"\n  Keyword={kw}, width=31")
        print(f"    Unscrambled: {unscrambled[:50]}...")
        try_all_decryptions(tracker, f"col31/{kw}", unscrambled)

        # Also try the inverse direction
        perm = columnar_encrypt_perm(31, col_order, CT_LEN)
        if len(perm) == CT_LEN:
            unscrambled_inv = apply_perm(CT, perm)
            try_all_decryptions(tracker, f"col31_inv/{kw}", unscrambled_inv)

        # Try reverse column order
        rev_order = [31 - 1 - x for x in col_order]
        unscrambled_rev = columnar_decrypt(CT, 31, rev_order)
        try_all_decryptions(tracker, f"col31_rev/{kw}", unscrambled_rev)


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 2: K4 standalone on various grid widths
# ══════════════════════════════════════════════════════════════════════════
def strategy_various_widths(tracker: ResultTracker):
    """Columnar transposition with various widths and keywords."""
    print("\n" + "="*70)
    print("STRATEGY 2: Various grid widths with keyword column orders")
    print("="*70)

    widths = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20, 24, 25, 31, 32, 33, 48, 49]

    for width in widths:
        for kw in KEYWORDS:
            if len(kw) > width:
                kw_use = kw[:width]
            else:
                kw_use = kw

            col_order = generate_keyword_column_order(kw_use, width)
            if col_order is None:
                continue

            unscrambled = columnar_decrypt(CT, width, col_order)
            try_all_decryptions(tracker, f"col{width}/{kw_use}", unscrambled)

            # Inverse direction
            perm = columnar_encrypt_perm(width, col_order, CT_LEN)
            if len(perm) == CT_LEN and validate_perm(perm, CT_LEN):
                unscrambled_inv = apply_perm(CT, perm)
                try_all_decryptions(tracker, f"col{width}_inv/{kw_use}", unscrambled_inv)


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 3: All column permutations for small widths
# ══════════════════════════════════════════════════════════════════════════
def strategy_brute_force_small_widths(tracker: ResultTracker):
    """Brute-force all column orderings for small widths (up to 8)."""
    print("\n" + "="*70)
    print("STRATEGY 3: Brute-force column orders for small widths")
    print("="*70)

    for width in [5, 6, 7, 8]:
        print(f"\n  Width={width}, permutations={math.factorial(width)}")
        count = 0
        for col_perm in itertools.permutations(range(width)):
            col_order = list(col_perm)

            unscrambled = columnar_decrypt(CT, width, col_order)

            # Quick check: quadgram on unscrambled first
            qg_raw = quadgram_score(unscrambled)

            # Try identity (no substitution)
            tracker.record(f"brute_col{width}/{col_perm}", unscrambled, unscrambled, "identity", qg_raw)

            # Try key decryptions only if raw text shows promise or always for small widths
            for kw in KEYWORDS:
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    for alph_name, alph in ALPHABETS.items():
                        try:
                            decrypted = decrypt_with_config(unscrambled, kw, variant, alph)
                            qg = quadgram_score(decrypted)
                            d_desc = f"{variant.value}/{kw}/{alph_name}"
                            tracker.record(f"brute_col{width}/{col_perm}", unscrambled, decrypted, d_desc, qg)
                        except Exception:
                            pass

            # Also try inverse direction
            perm = columnar_encrypt_perm(width, col_order, CT_LEN)
            if len(perm) == CT_LEN and validate_perm(perm, CT_LEN):
                unscrambled_inv = apply_perm(CT, perm)
                qg_inv = quadgram_score(unscrambled_inv)
                tracker.record(f"brute_col{width}_inv/{col_perm}", unscrambled_inv, unscrambled_inv, "identity", qg_inv)

                for kw in KEYWORDS:
                    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                        for alph_name, alph in ALPHABETS.items():
                            try:
                                decrypted = decrypt_with_config(unscrambled_inv, kw, variant, alph)
                                qg = quadgram_score(decrypted)
                                d_desc = f"{variant.value}/{kw}/{alph_name}"
                                tracker.record(f"brute_col{width}_inv/{col_perm}", unscrambled_inv, decrypted, d_desc, qg)
                            except Exception:
                                pass

            count += 1
            if count % 5000 == 0:
                print(f"    Tested {count} permutations, best QG: {tracker.best_score:.3f}")

        print(f"    Width {width} complete: {count} permutations tested")


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 4: Myszkowski transpositions
# ══════════════════════════════════════════════════════════════════════════
def strategy_myszkowski(tracker: ResultTracker):
    """Myszkowski transposition with keywords."""
    print("\n" + "="*70)
    print("STRATEGY 4: Myszkowski transposition with keywords")
    print("="*70)

    for kw in KEYWORDS:
        perm = myszkowski_perm(kw, CT_LEN)
        if validate_perm(perm, CT_LEN):
            unscrambled = apply_perm(CT, perm)
            try_all_decryptions(tracker, f"myszkowski/{kw}", unscrambled)

            inv = invert_perm(perm)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"myszkowski_inv/{kw}", unscrambled_inv)


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 5: Rail fence
# ══════════════════════════════════════════════════════════════════════════
def strategy_rail_fence(tracker: ResultTracker):
    """Rail fence with various depths."""
    print("\n" + "="*70)
    print("STRATEGY 5: Rail fence transpositions")
    print("="*70)

    for depth in range(2, 20):
        perm = rail_fence_perm(CT_LEN, depth)
        if validate_perm(perm, CT_LEN):
            unscrambled = apply_perm(CT, perm)
            try_all_decryptions(tracker, f"rail_fence/d={depth}", unscrambled)

            inv = invert_perm(perm)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"rail_fence_inv/d={depth}", unscrambled_inv)


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 6: Grid reading patterns (column-major, spiral, serpentine, diagonal)
# ══════════════════════════════════════════════════════════════════════════
def strategy_grid_readings(tracker: ResultTracker):
    """Various grid reading patterns."""
    print("\n" + "="*70)
    print("STRATEGY 6: Grid reading patterns")
    print("="*70)

    widths = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 24, 25, 31, 32, 33]

    for width in widths:
        nrows = math.ceil(CT_LEN / width)

        # Column-major reading (top-to-bottom, left-to-right)
        perm = []
        for c in range(width):
            for r in range(nrows):
                pos = r * width + c
                if pos < CT_LEN:
                    perm.append(pos)
        if len(perm) == CT_LEN and validate_perm(perm, CT_LEN):
            unscrambled = apply_perm(CT, perm)
            try_all_decryptions(tracker, f"colmajor/w={width}", unscrambled)
            inv = invert_perm(perm)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"colmajor_inv/w={width}", unscrambled_inv)

        # Reverse column-major (right-to-left)
        perm_rev = []
        for c in range(width - 1, -1, -1):
            for r in range(nrows):
                pos = r * width + c
                if pos < CT_LEN:
                    perm_rev.append(pos)
        if len(perm_rev) == CT_LEN and validate_perm(perm_rev, CT_LEN):
            unscrambled = apply_perm(CT, perm_rev)
            try_all_decryptions(tracker, f"colmajor_rev/w={width}", unscrambled)

        # Bottom-to-top column reading
        perm_btup = []
        for c in range(width):
            for r in range(nrows - 1, -1, -1):
                pos = r * width + c
                if pos < CT_LEN:
                    perm_btup.append(pos)
        if len(perm_btup) == CT_LEN and validate_perm(perm_btup, CT_LEN):
            unscrambled = apply_perm(CT, perm_btup)
            try_all_decryptions(tracker, f"colmajor_btup/w={width}", unscrambled)

        # Serpentine (horizontal boustrophedon)
        perm_serp = serpentine_perm(nrows, width, CT_LEN, vertical=False)
        if len(perm_serp) == CT_LEN and validate_perm(perm_serp, CT_LEN):
            unscrambled = apply_perm(CT, perm_serp)
            try_all_decryptions(tracker, f"serp_h/w={width}", unscrambled)
            inv = invert_perm(perm_serp)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"serp_h_inv/w={width}", unscrambled_inv)

        # Serpentine (vertical boustrophedon)
        perm_serp_v = serpentine_perm(nrows, width, CT_LEN, vertical=True)
        if len(perm_serp_v) == CT_LEN and validate_perm(perm_serp_v, CT_LEN):
            unscrambled = apply_perm(CT, perm_serp_v)
            try_all_decryptions(tracker, f"serp_v/w={width}", unscrambled)
            inv = invert_perm(perm_serp_v)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"serp_v_inv/w={width}", unscrambled_inv)

        # Spiral (clockwise)
        perm_spiral = spiral_perm(nrows, width, CT_LEN, clockwise=True)
        if len(perm_spiral) == CT_LEN and validate_perm(perm_spiral, CT_LEN):
            unscrambled = apply_perm(CT, perm_spiral)
            try_all_decryptions(tracker, f"spiral_cw/w={width}", unscrambled)
            inv = invert_perm(perm_spiral)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"spiral_cw_inv/w={width}", unscrambled_inv)

        # Spiral (counterclockwise)
        perm_spiral_cc = spiral_perm(nrows, width, CT_LEN, clockwise=False)
        if len(perm_spiral_cc) == CT_LEN and validate_perm(perm_spiral_cc, CT_LEN):
            unscrambled = apply_perm(CT, perm_spiral_cc)
            try_all_decryptions(tracker, f"spiral_ccw/w={width}", unscrambled)
            inv = invert_perm(perm_spiral_cc)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"spiral_ccw_inv/w={width}", unscrambled_inv)

        # Diagonal readings
        # Main diagonal (top-left to bottom-right)
        perm_diag = []
        for d in range(nrows + width - 1):
            for r in range(nrows):
                c = d - r
                if 0 <= c < width:
                    pos = r * width + c
                    if pos < CT_LEN:
                        perm_diag.append(pos)
        if len(perm_diag) == CT_LEN and validate_perm(perm_diag, CT_LEN):
            unscrambled = apply_perm(CT, perm_diag)
            try_all_decryptions(tracker, f"diag_main/w={width}", unscrambled)
            inv = invert_perm(perm_diag)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"diag_main_inv/w={width}", unscrambled_inv)

        # Anti-diagonal (top-right to bottom-left)
        perm_adiag = []
        for d in range(nrows + width - 1):
            for r in range(nrows):
                c = (width - 1) - (d - r)
                if 0 <= c < width:
                    pos = r * width + c
                    if pos < CT_LEN:
                        perm_adiag.append(pos)
        if len(perm_adiag) == CT_LEN and validate_perm(perm_adiag, CT_LEN):
            unscrambled = apply_perm(CT, perm_adiag)
            try_all_decryptions(tracker, f"diag_anti/w={width}", unscrambled)
            inv = invert_perm(perm_adiag)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"diag_anti_inv/w={width}", unscrambled_inv)


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 7: Width-31 grid with K4 in context (rows 11-14)
# ══════════════════════════════════════════════════════════════════════════
def strategy_grid31_context(tracker: ResultTracker):
    """K4 in context of the 31-wide grid, rows 11-14.

    K4 starts at row 11, column 27. We can try reading the K4 portion
    of the grid in various column orders.
    """
    print("\n" + "="*70)
    print("STRATEGY 7: Width-31 grid with K4 in grid context")
    print("="*70)

    # K4's positions in the 31-wide grid:
    # Row 11 (partial): cols 27-30 = 4 chars (OBKR)
    # Row 12 (full): cols 0-30 = 31 chars (UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO)
    # Row 13 (full): cols 0-30 = 31 chars (TWTQSJQSSEKZZWATJKLUDIAWINFBNYP)
    # Row 14 (full): cols 0-30 = 31 chars (VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR)

    # Build a representation of K4 on the grid
    # K4[0-3] are at row 11, cols 27-30
    # K4[4-34] are at row 12, cols 0-30
    # K4[35-65] are at row 13, cols 0-30
    # K4[66-96] are at row 14, cols 0-30

    k4_grid_positions = []  # (row, col, k4_index)
    for i in range(97):
        if i < 4:
            row, col = 11, 27 + i
        elif i < 35:
            row, col = 12, i - 4
        elif i < 66:
            row, col = 13, i - 35
        else:
            row, col = 14, i - 66
        k4_grid_positions.append((row, col, i))

    # Try reading K4's grid positions column by column
    for kw in KEYWORDS:
        col_order = generate_keyword_column_order(kw, 31)
        if col_order is None:
            continue

        # Read K4 chars column-by-column in keyword order
        perm = []
        for rank in range(31):
            target_col = col_order.index(rank)
            for row, col, k4_idx in k4_grid_positions:
                if col == target_col:
                    perm.append(k4_idx)

        if len(perm) == CT_LEN and validate_perm(perm, CT_LEN):
            unscrambled = apply_perm(CT, perm)
            try_all_decryptions(tracker, f"grid31_context/{kw}", unscrambled)

            inv = invert_perm(perm)
            unscrambled_inv = apply_perm(CT, inv)
            try_all_decryptions(tracker, f"grid31_context_inv/{kw}", unscrambled_inv)

    # Also try simple column-major reading of K4's grid
    perm_colmaj = []
    for c in range(31):
        for row, col, k4_idx in k4_grid_positions:
            if col == c:
                perm_colmaj.append(k4_idx)

    if len(perm_colmaj) == CT_LEN and validate_perm(perm_colmaj, CT_LEN):
        unscrambled = apply_perm(CT, perm_colmaj)
        try_all_decryptions(tracker, "grid31_context/colmajor", unscrambled)
        inv = invert_perm(perm_colmaj)
        unscrambled_inv = apply_perm(CT, inv)
        try_all_decryptions(tracker, "grid31_context_inv/colmajor", unscrambled_inv)

    # Reverse column-major
    perm_rev = []
    for c in range(30, -1, -1):
        for row, col, k4_idx in k4_grid_positions:
            if col == c:
                perm_rev.append(k4_idx)

    if len(perm_rev) == CT_LEN and validate_perm(perm_rev, CT_LEN):
        unscrambled = apply_perm(CT, perm_rev)
        try_all_decryptions(tracker, "grid31_context/rev_colmajor", unscrambled)


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 8: Double columnar transposition
# ══════════════════════════════════════════════════════════════════════════
def strategy_double_columnar(tracker: ResultTracker):
    """Double columnar transposition with keyword pairs."""
    print("\n" + "="*70)
    print("STRATEGY 8: Double columnar transposition with keyword pairs")
    print("="*70)

    keyword_pairs = [
        ("KRYPTOS", "PALIMPSEST"),
        ("PALIMPSEST", "KRYPTOS"),
        ("KRYPTOS", "ABSCISSA"),
        ("ABSCISSA", "KRYPTOS"),
        ("KRYPTOS", "KRYPTOS"),
        ("PALIMPSEST", "ABSCISSA"),
        ("ABSCISSA", "PALIMPSEST"),
        ("PALIMPSEST", "PALIMPSEST"),
        ("ABSCISSA", "ABSCISSA"),
    ]

    for kw1, kw2 in keyword_pairs:
        w1 = len(kw1)
        w2 = len(kw2)

        order1 = generate_keyword_column_order(kw1, w1)
        order2 = generate_keyword_column_order(kw2, w2)

        if order1 is None or order2 is None:
            continue

        try:
            unscrambled = double_columnar_decrypt(CT, w1, order1, w2, order2)
            try_all_decryptions(tracker, f"double_col/{kw1}+{kw2}", unscrambled)
        except Exception:
            pass

        # Also try with width-31 as first layer
        order1_31 = generate_keyword_column_order(kw1, 31)
        if order1_31:
            try:
                unscrambled = double_columnar_decrypt(CT, 31, order1_31, w2, order2)
                try_all_decryptions(tracker, f"double_col/31:{kw1}+{kw2}", unscrambled)
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 9: Row-level permutations on width-31 grid
# ══════════════════════════════════════════════════════════════════════════
def strategy_row_permutations(tracker: ResultTracker):
    """Try reordering the rows of K4 on various grid widths."""
    print("\n" + "="*70)
    print("STRATEGY 9: Row permutation (strip reordering)")
    print("="*70)

    for width in [7, 8, 10, 13, 14, 16, 31, 32, 33]:
        nrows = math.ceil(CT_LEN / width)
        if nrows > 8:  # Too many rows to permute
            continue

        print(f"  Width={width}, rows={nrows}, permutations={math.factorial(nrows)}")

        for row_perm in itertools.permutations(range(nrows)):
            # Build strip permutation
            perm = []
            for target_row in range(nrows):
                src_row = row_perm[target_row]
                start = src_row * width
                for c in range(width):
                    pos = start + c
                    if pos < CT_LEN:
                        perm.append(pos)

            if len(perm) != CT_LEN:
                continue
            if not validate_perm(perm, CT_LEN):
                continue

            unscrambled = apply_perm(CT, perm)

            # Quick check with identity + top keywords
            qg_raw = quadgram_score(unscrambled)
            tracker.record(f"rowperm/w={width}/{row_perm}", unscrambled, unscrambled, "identity", qg_raw)

            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    for alph_name, alph in ALPHABETS.items():
                        try:
                            decrypted = decrypt_with_config(unscrambled, kw, variant, alph)
                            qg = quadgram_score(decrypted)
                            d_desc = f"{variant.value}/{kw}/{alph_name}"
                            tracker.record(f"rowperm/w={width}/{row_perm}", unscrambled, decrypted, d_desc, qg)
                        except Exception:
                            pass


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 10: Width-8 "8 Lines" grid — exhaustive special focus
# ══════════════════════════════════════════════════════════════════════════
def strategy_width8_special(tracker: ResultTracker):
    """Special focus on width-8 grid ('8 Lines' from Sanborn's yellow pad).

    97 chars = 12 rows of 8 + 1 remaining char = 13 rows total.
    Also try 8 rows of varying width.
    """
    print("\n" + "="*70)
    print("STRATEGY 10: Width-8 '8 Lines' special focus")
    print("="*70)

    # Width 8, all 8! = 40320 column permutations already covered in strategy 3
    # But also try:

    # 8 rows of width 12 (8*12=96, +1)
    width = 12
    nrows = 9  # ceil(97/12) = 9
    print(f"  Width={width}, rows={nrows}")
    # Too many row permutations, just do column-major and keyword-based
    for kw in KEYWORDS:
        col_order = generate_keyword_column_order(kw, width)
        if col_order:
            unscrambled = columnar_decrypt(CT, width, col_order)
            try_all_decryptions(tracker, f"w8special/col{width}/{kw}", unscrambled)

    # 8 rows of width 13 (8*13=104 > 97, so 7 full rows + 1 partial with 6)
    width = 13
    nrows = 8  # ceil(97/13) = 8
    print(f"  Width={width}, rows={nrows}")
    for kw in KEYWORDS:
        col_order = generate_keyword_column_order(kw, width)
        if col_order:
            unscrambled = columnar_decrypt(CT, width, col_order)
            try_all_decryptions(tracker, f"w8special/col{width}/{kw}", unscrambled)


# ══════════════════════════════════════════════════════════════════════════
# STRATEGY 11: Numeric keyword orderings (K1-K3 key numbers)
# ══════════════════════════════════════════════════════════════════════════
def strategy_numeric_orderings(tracker: ResultTracker):
    """Try column orders based on numeric sequences."""
    print("\n" + "="*70)
    print("STRATEGY 11: Numeric keyword orderings")
    print("="*70)

    # Various numeric sequences that might define column orders
    numeric_keywords = {
        "sequential_7": [0,1,2,3,4,5,6],
        "reverse_7": [6,5,4,3,2,1,0],
        "sequential_8": [0,1,2,3,4,5,6,7],
        "reverse_8": [7,6,5,4,3,2,1,0],
        "kryptos_shifted": [3,5,6,4,2,1,0],  # positions of KRYPTOS in alpha order
    }

    for name, order in numeric_keywords.items():
        width = len(order)
        unscrambled = columnar_decrypt(CT, width, order)
        try_all_decryptions(tracker, f"numeric/{name}", unscrambled)

        perm = columnar_encrypt_perm(width, order, CT_LEN)
        if len(perm) == CT_LEN and validate_perm(perm, CT_LEN):
            unscrambled_inv = apply_perm(CT, perm)
            try_all_decryptions(tracker, f"numeric_inv/{name}", unscrambled_inv)


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
def main():
    print("="*70)
    print("EXHAUSTIVE COLUMNAR TRANSPOSITION SEARCH FOR K4")
    print(f"CT: {CT}")
    print(f"Length: {CT_LEN}")
    print(f"Cribs: {CRIB_STRINGS}")
    print(f"Keywords: {KEYWORDS}")
    print(f"Quadgrams loaded: {len(QUADGRAMS)}")
    print("="*70)

    tracker = ResultTracker()
    t0 = time.time()

    # Run all strategies
    strategy_width31_keywords(tracker)
    strategy_various_widths(tracker)
    strategy_brute_force_small_widths(tracker)
    strategy_myszkowski(tracker)
    strategy_rail_fence(tracker)
    strategy_grid_readings(tracker)
    strategy_grid31_context(tracker)
    strategy_double_columnar(tracker)
    strategy_row_permutations(tracker)
    strategy_width8_special(tracker)
    strategy_numeric_orderings(tracker)

    elapsed = time.time() - t0

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total configurations tested: {tracker.total_tested}")
    print(f"Time: {elapsed:.1f}s")
    print(f"Best quadgram score: {tracker.best_score:.3f}")
    print(f"Best canonical crib count: {tracker.best_crib_count}/24")
    print(f"Crib hits (EASTNORTHEAST/BERLINCLOCK at any position): {len(tracker.crib_hits)}")

    if tracker.crib_hits:
        print("\n  CRIB HITS:")
        for hit in tracker.crib_hits:
            print(f"    {hit['desc']} | {hit['decrypt']}")
            print(f"      Decrypted: {hit['decrypted']}")
            print(f"      Cribs: {hit['any_position_cribs']}")
            print(f"      QG: {hit['qg_score']:.3f}")

    # Top results by quadgram
    if tracker.results:
        print(f"\n  Top {min(20, len(tracker.results))} by quadgram score:")
        sorted_results = sorted(tracker.results, key=lambda x: x['qg_score'], reverse=True)
        for i, r in enumerate(sorted_results[:20]):
            print(f"    {i+1}. QG={r['qg_score']:.3f} | {r['desc']} | {r['decrypt']}")
            print(f"       {r['decrypted'][:70]}...")

    # Save results
    outdir = os.path.join(os.path.dirname(__file__), '..', 'kbot_results')
    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, 'grid31_columnar_results.json')

    save_data = {
        "total_tested": tracker.total_tested,
        "elapsed_seconds": elapsed,
        "best_qg": tracker.best_score,
        "best_crib_count": tracker.best_crib_count,
        "crib_hits": tracker.crib_hits,
        "top_results": sorted(tracker.results, key=lambda x: x['qg_score'], reverse=True)[:50] if tracker.results else [],
    }

    with open(outfile, 'w') as f:
        json.dump(save_data, f, indent=2)

    print(f"\nResults saved to {outfile}")

    return tracker


if __name__ == "__main__":
    main()
