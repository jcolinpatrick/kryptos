#!/usr/bin/env python3
"""
Cipher: Process-based (KA Polybius grid)
Family: exploration
Status: active
Keyspace: ~500K total configs across 5 mechanisms
Last run: 2026-03-21
Best score: TBD
"""
"""E-PROCESS-CIPHERS: Non-algebraic process-based ciphers on 5-wide KA Polybius grid.

HYPOTHESIS: K4's cipher is a hand-executable, non-periodic process that operates
on the 5-wide KA Polybius grid (6 rows × 5 cols, confirmed as part of the stego
layer). Sanborn has "zero mathematical ability" and says it's "embarrassingly simple
once seen." Scheidt says the masking technique "may not be a known technique."

Five mechanisms tested:
  1. Row-cycling substitution (shift rows in grid)
  2. Sliding-row cipher (physical strip sliding)
  3. Polybius pair cipher (coordinate transforms)
  4. Modified bifid on 6×5 grid (26 letters + 4 empty cells)
  5. State-machine cipher (stateful traversal of grid)

Each mechanism is tested with multiple parameter sets, scored against cribs
at known positions, AND scored against known keystream values at 24 crib positions.

Run: PYTHONPATH=src python3 -u scripts/exploration/e_process_ciphers.py
"""

import sys
import os
import json
import time
from collections import Counter
from itertools import product

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD, BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET, ALPH,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate

# ── KA Polybius grid (5-wide, 6 rows) ────────────────────────────────────
KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ (26 chars)

# Build the 6×5 grid (row 5 has only Z at col 0, rest empty)
GRID_ROWS = 6
GRID_COLS = 5
GRID = []
for r in range(GRID_ROWS):
    row = []
    for c in range(GRID_COLS):
        idx = r * GRID_COLS + c
        if idx < len(KA):
            row.append(KA[idx])
        else:
            row.append(None)  # empty cell
    GRID.append(row)

# Lookup: letter -> (row, col)
LETTER_POS = {}
for r in range(GRID_ROWS):
    for c in range(GRID_COLS):
        if GRID[r][c] is not None:
            LETTER_POS[GRID[r][c]] = (r, c)

# Reverse lookup: (row, col) -> letter (only valid cells)
POS_LETTER = {}
for r in range(GRID_ROWS):
    for c in range(GRID_COLS):
        if GRID[r][c] is not None:
            POS_LETTER[(r, c)] = GRID[r][c]


def grid_letter(r, c):
    """Get letter at grid position, handling wraps and empty cells."""
    r = r % GRID_ROWS
    c = c % GRID_COLS
    if GRID[r][c] is not None:
        return GRID[r][c]
    return None


# ── Known keystream at crib positions ──────────────────────────────────────
# Sorted crib positions
CRIB_POS_SORTED = sorted(CRIB_DICT.keys())
# positions 21-33 (ENE) and 63-73 (BC)

# Beaufort keystream: k = (CT + PT) mod 26
BEAU_KEY = {}
for i, pos in enumerate(range(21, 34)):
    BEAU_KEY[pos] = BEAUFORT_KEY_ENE[i]
for i, pos in enumerate(range(63, 74)):
    BEAU_KEY[pos] = BEAUFORT_KEY_BC[i]

# Vigenere keystream: k = (CT - PT) mod 26
VIG_KEY = {}
for i, pos in enumerate(range(21, 34)):
    VIG_KEY[pos] = VIGENERE_KEY_ENE[i]
for i, pos in enumerate(range(63, 74)):
    VIG_KEY[pos] = VIGENERE_KEY_BC[i]


def count_crib_matches(plaintext):
    """Count how many crib positions match."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(plaintext) and plaintext[pos] == ch:
            matches += 1
    return matches


def count_keystream_matches_beau(keystream_at_crib):
    """Count matching Beaufort keystream values at crib positions."""
    matches = 0
    for pos, kval in keystream_at_crib.items():
        if pos in BEAU_KEY and kval == BEAU_KEY[pos]:
            matches += 1
    return matches


def count_keystream_matches_vig(keystream_at_crib):
    """Count matching Vigenere keystream values at crib positions."""
    matches = 0
    for pos, kval in keystream_at_crib.items():
        if pos in VIG_KEY and kval == VIG_KEY[pos]:
            matches += 1
    return matches


# ── Consensus null mask ────────────────────────────────────────────────────
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
# CT73: extract non-null chars from CT97
CT73_POSITIONS = [i for i in range(CT_LEN) if i not in CONSENSUS_NULLS]


# ── Results tracking ───────────────────────────────────────────────────────
ALL_RESULTS = []
BEST_PER_MECHANISM = {}


def record(mechanism, params_str, plaintext, crib_matches, ks_matches_beau=0,
           ks_matches_vig=0, extra=None):
    """Record a result and track best per mechanism."""
    entry = {
        "mechanism": mechanism,
        "params": params_str,
        "crib_matches": crib_matches,
        "ks_beau": ks_matches_beau,
        "ks_vig": ks_matches_vig,
        "plaintext_snippet": plaintext[:40] if plaintext else "",
    }
    if extra:
        entry.update(extra)

    best_metric = max(crib_matches, ks_matches_beau, ks_matches_vig)
    if mechanism not in BEST_PER_MECHANISM or best_metric > BEST_PER_MECHANISM[mechanism]["best_metric"]:
        BEST_PER_MECHANISM[mechanism] = {
            "best_metric": best_metric,
            "entry": entry,
            "full_plaintext": plaintext,
        }

    if best_metric >= 6:  # Store anything above noise
        ALL_RESULTS.append(entry)

    return best_metric


# ============================================================================
# MECHANISM 1: Row-cycling substitution
# ============================================================================

def mechanism_1_row_cycling():
    """Row-cycling substitution on KA Polybius grid.

    For each PT letter, find it in the grid. Move N rows down (wrapping).
    The letter in the same column of the new row is the CT letter.

    Test modes:
      A) Fixed offset 1-5
      B) Progressive offset (1,2,3,4,5,1,2,...)
      C) KRYPTOS-driven offsets (each keyword letter determines row shift)
      D) Beaufort inversion: CT -> PT by shifting rows
    """
    print("\n" + "="*70)
    print("MECHANISM 1: Row-cycling substitution")
    print("="*70)

    total_configs = 0
    best_score = 0

    # Helper: decrypt by shifting CT letter's row UP by offset to get PT
    def decrypt_row_shift(ct_char, offset):
        """Given CT char and row offset, find PT char."""
        if ct_char not in LETTER_POS:
            return ct_char
        r, c = LETTER_POS[ct_char]
        new_r = (r - offset) % GRID_ROWS
        result = grid_letter(new_r, c)
        if result is None:
            # Row 5 only has Z at col 0; other cols are empty
            # Try wrapping further
            for delta in range(1, GRID_ROWS):
                result = grid_letter((new_r - delta) % GRID_ROWS, c)
                if result is not None:
                    break
        return result if result else ct_char

    def encrypt_row_shift(pt_char, offset):
        """Given PT char and row offset, find CT char."""
        if pt_char not in LETTER_POS:
            return pt_char
        r, c = LETTER_POS[pt_char]
        new_r = (r + offset) % GRID_ROWS
        result = grid_letter(new_r, c)
        if result is None:
            for delta in range(1, GRID_ROWS):
                result = grid_letter((new_r + delta) % GRID_ROWS, c)
                if result is not None:
                    break
        return result if result else pt_char

    # Mode A: Fixed offset 1-5
    for offset in range(1, 6):
        pt = ""
        for i, ch in enumerate(CT):
            pt += decrypt_row_shift(ch, offset)
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("1A_fixed_row_shift", f"offset={offset}", pt, crib_m)
        best_score = max(best_score, s)

    # Mode B: Progressive offset (1,2,3,4,5,1,2,...)
    for cycle_len in range(2, 7):
        for start in range(1, 6):
            pt = ""
            for i, ch in enumerate(CT):
                offset = ((start + i) % cycle_len) + 1
                if offset > 5:
                    offset = offset % 5 if offset % 5 != 0 else 5
                pt += decrypt_row_shift(ch, offset)
            crib_m = count_crib_matches(pt)
            total_configs += 1
            s = record("1B_progressive_row_shift", f"cycle={cycle_len},start={start}", pt, crib_m)
            best_score = max(best_score, s)

    # Mode C: KRYPTOS-driven offsets
    KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SEVEN",
                "BERLINCLOCK", "SHADOW", "SANBORN", "KOMPASS", "ENIGMA",
                "ROSETTA", "COLOPHON", "HOROLOGE"]
    for kw in KEYWORDS:
        # Row index of each keyword letter in the KA grid
        kw_offsets = []
        for ch in kw:
            if ch in LETTER_POS:
                kw_offsets.append(LETTER_POS[ch][0] + 1)  # 1-based row
            else:
                kw_offsets.append(1)

        pt = ""
        for i, ch in enumerate(CT):
            offset = kw_offsets[i % len(kw_offsets)]
            pt += decrypt_row_shift(ch, offset)
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("1C_keyword_row_shift", f"kw={kw}", pt, crib_m)
        best_score = max(best_score, s)

        # Also try column index of keyword letter
        kw_col_offsets = []
        for ch in kw:
            if ch in LETTER_POS:
                kw_col_offsets.append(LETTER_POS[ch][1] + 1)
            else:
                kw_col_offsets.append(1)

        pt = ""
        for i, ch in enumerate(CT):
            offset = kw_col_offsets[i % len(kw_col_offsets)]
            pt += decrypt_row_shift(ch, offset)
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("1C_keyword_col_shift", f"kw={kw}", pt, crib_m)
        best_score = max(best_score, s)

    # Mode D: CT-autokey row shift (previous CT letter determines next shift)
    for start_offset in range(1, 6):
        pt = ""
        offset = start_offset
        for i, ch in enumerate(CT):
            pt_ch = decrypt_row_shift(ch, offset)
            pt += pt_ch
            # Next offset from current CT letter's row
            if ch in LETTER_POS:
                offset = (LETTER_POS[ch][0] % 5) + 1
            else:
                offset = 1
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("1D_ct_autokey_row", f"start={start_offset}", pt, crib_m)
        best_score = max(best_score, s)

    # Mode E: PT-autokey row shift
    for start_offset in range(1, 6):
        pt = ""
        offset = start_offset
        for i, ch in enumerate(CT):
            pt_ch = decrypt_row_shift(ch, offset)
            pt += pt_ch
            if pt_ch in LETTER_POS:
                offset = (LETTER_POS[pt_ch][0] % 5) + 1
            else:
                offset = 1
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("1E_pt_autokey_row", f"start={start_offset}", pt, crib_m)
        best_score = max(best_score, s)

    print(f"  Total configs: {total_configs}")
    print(f"  Best crib matches: {best_score}")
    if "1A_fixed_row_shift" in str(BEST_PER_MECHANISM):
        for k, v in BEST_PER_MECHANISM.items():
            if k.startswith("1"):
                print(f"  {k}: best={v['best_metric']}, params={v['entry']['params']}")
    return total_configs


# ============================================================================
# MECHANISM 2: Sliding-row cipher
# ============================================================================

def mechanism_2_sliding_row():
    """Sliding-row cipher: each row of the grid is a physical strip that slides.

    Start with aligned grid. For each letter:
      1. Find CT letter in current grid state
      2. PT letter = same physical position in original grid (or vice versa)
      3. Slide one or more rows by some amount

    Slide rules tested:
      - Fixed slide: row R slides by fixed amount after each letter
      - Progressive: row R slides by 1 more each time
      - CT-driven: slide by column position of CT letter
      - PT-driven: slide by column position of PT letter
      - Alternating: odd positions slide right, even slide left
    """
    print("\n" + "="*70)
    print("MECHANISM 2: Sliding-row cipher")
    print("="*70)

    total_configs = 0
    best_score = 0

    def decrypt_sliding(ct_text, slide_rule, slide_params):
        """Decrypt using sliding rows.

        State: offsets[r] = current horizontal shift for row r
        """
        offsets = [0] * GRID_ROWS
        pt = ""

        for i, ch in enumerate(ct_text):
            if ch not in LETTER_POS:
                pt += ch
                continue

            r, c = LETTER_POS[ch]
            # The "physical" position of this letter has shifted
            # Original col = (c - offsets[r]) % GRID_COLS
            original_c = (c - offsets[r]) % GRID_COLS
            # PT letter = what's at (r, original_c) in ORIGINAL grid
            pt_ch = GRID[r][original_c]
            if pt_ch is None:
                # Handle row 5 (Z only at col 0)
                pt_ch = ch  # fallback
            pt += pt_ch

            # Update slides based on rule
            if slide_rule == "fixed":
                row_to_slide = slide_params.get("row", r)
                amount = slide_params.get("amount", 1)
                offsets[row_to_slide] = (offsets[row_to_slide] + amount) % GRID_COLS
            elif slide_rule == "all_fixed":
                amount = slide_params.get("amount", 1)
                for rr in range(GRID_ROWS):
                    offsets[rr] = (offsets[rr] + amount) % GRID_COLS
            elif slide_rule == "progressive":
                amount = (i + 1) % GRID_COLS
                row_to_slide = slide_params.get("row", r)
                offsets[row_to_slide] = (offsets[row_to_slide] + amount) % GRID_COLS
            elif slide_rule == "ct_driven":
                offsets[r] = (offsets[r] + c + 1) % GRID_COLS
            elif slide_rule == "pt_driven":
                if pt_ch in LETTER_POS:
                    _, pc = LETTER_POS[pt_ch]
                    offsets[r] = (offsets[r] + pc + 1) % GRID_COLS
            elif slide_rule == "alternate":
                direction = 1 if i % 2 == 0 else -1
                amount = slide_params.get("amount", 1)
                offsets[r] = (offsets[r] + direction * amount) % GRID_COLS
            elif slide_rule == "row_specific":
                # Each row slides by its own fixed amount
                amounts = slide_params.get("amounts", [1]*GRID_ROWS)
                for rr in range(GRID_ROWS):
                    offsets[rr] = (offsets[rr] + amounts[rr]) % GRID_COLS
            elif slide_rule == "keyword_driven":
                kw = slide_params.get("keyword", "KRYPTOS")
                kw_ch = kw[i % len(kw)]
                if kw_ch in LETTER_POS:
                    _, kc = LETTER_POS[kw_ch]
                    offsets[r] = (offsets[r] + kc + 1) % GRID_COLS

        return pt

    # Test various slide rules
    # Rule 1: Fixed slide for each row
    for row_to_slide in range(GRID_ROWS):
        for amount in range(1, GRID_COLS):
            pt = decrypt_sliding(CT, "fixed", {"row": row_to_slide, "amount": amount})
            crib_m = count_crib_matches(pt)
            total_configs += 1
            s = record("2A_fixed_row_slide", f"row={row_to_slide},amt={amount}", pt, crib_m)
            best_score = max(best_score, s)

    # Rule 2: All rows slide by fixed amount
    for amount in range(1, GRID_COLS):
        pt = decrypt_sliding(CT, "all_fixed", {"amount": amount})
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("2B_all_rows_slide", f"amt={amount}", pt, crib_m)
        best_score = max(best_score, s)

    # Rule 3: Progressive slide
    for row_to_slide in range(GRID_ROWS):
        pt = decrypt_sliding(CT, "progressive", {"row": row_to_slide})
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("2C_progressive_slide", f"row={row_to_slide}", pt, crib_m)
        best_score = max(best_score, s)

    # Rule 4: CT-driven slide
    pt = decrypt_sliding(CT, "ct_driven", {})
    crib_m = count_crib_matches(pt)
    total_configs += 1
    s = record("2D_ct_driven_slide", "ct_col", pt, crib_m)
    best_score = max(best_score, s)

    # Rule 5: PT-driven slide
    pt = decrypt_sliding(CT, "pt_driven", {})
    crib_m = count_crib_matches(pt)
    total_configs += 1
    s = record("2E_pt_driven_slide", "pt_col", pt, crib_m)
    best_score = max(best_score, s)

    # Rule 6: Alternating direction
    for amount in range(1, GRID_COLS):
        pt = decrypt_sliding(CT, "alternate", {"amount": amount})
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("2F_alternate_slide", f"amt={amount}", pt, crib_m)
        best_score = max(best_score, s)

    # Rule 7: Keyword-driven slide
    KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "SEVEN",
                "BERLINCLOCK", "SHADOW", "SANBORN", "KOMPASS", "ROSETTA"]
    for kw in KEYWORDS:
        pt = decrypt_sliding(CT, "keyword_driven", {"keyword": kw})
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("2G_keyword_slide", f"kw={kw}", pt, crib_m)
        best_score = max(best_score, s)

    # Rule 8: Row-specific fixed amounts (test all combos with small amounts)
    # Only test amount combos where each row shifts 0-4 — but 5^6 = 15625, manageable
    for amounts in product(range(GRID_COLS), repeat=GRID_ROWS):
        if all(a == 0 for a in amounts):
            continue  # skip identity
        pt = decrypt_sliding(CT, "row_specific", {"amounts": list(amounts)})
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("2H_row_specific_slide", f"amounts={amounts}", pt, crib_m)
        best_score = max(best_score, s)

    print(f"  Total configs: {total_configs}")
    print(f"  Best crib matches: {best_score}")
    return total_configs


# ============================================================================
# MECHANISM 3: Polybius pair cipher
# ============================================================================

def mechanism_3_polybius_pair():
    """Polybius pair cipher: transform coordinates.

    Each CT letter -> (row, col) in KA grid.
    Apply f(row, col, position) -> (new_row, new_col).
    PT letter = grid[new_row][new_col].

    This tests simple f/g functions that don't require a separate key.
    """
    print("\n" + "="*70)
    print("MECHANISM 3: Polybius pair cipher (coordinate transforms)")
    print("="*70)

    total_configs = 0
    best_score = 0

    # Define coordinate transform functions
    # Each returns (new_row, new_col) or None if invalid
    TRANSFORMS = []

    # Simple shifts
    for dr in range(-5, 6):
        for dc in range(-4, 5):
            if dr == 0 and dc == 0:
                continue
            TRANSFORMS.append((f"shift_r{dr}_c{dc}",
                               lambda r, c, i, dr=dr, dc=dc: ((r + dr) % GRID_ROWS, (c + dc) % GRID_COLS)))

    # Position-dependent shifts
    for m_r in range(1, 6):
        for m_c in range(1, 5):
            TRANSFORMS.append((f"pos_shift_r{m_r}_c{m_c}",
                               lambda r, c, i, mr=m_r, mc=m_c: ((r + i * mr) % GRID_ROWS, (c + i * mc) % GRID_COLS)))

    # Swap row and col
    TRANSFORMS.append(("swap_rc", lambda r, c, i: (c % GRID_ROWS, r % GRID_COLS)))

    # Reflect
    TRANSFORMS.append(("reflect_r", lambda r, c, i: ((GRID_ROWS - 1 - r) % GRID_ROWS, c)))
    TRANSFORMS.append(("reflect_c", lambda r, c, i: (r, (GRID_COLS - 1 - c) % GRID_COLS)))
    TRANSFORMS.append(("reflect_both", lambda r, c, i: ((GRID_ROWS - 1 - r) % GRID_ROWS, (GRID_COLS - 1 - c) % GRID_COLS)))

    # Cross-coordinate
    TRANSFORMS.append(("r_plus_c", lambda r, c, i: ((r + c) % GRID_ROWS, c)))
    TRANSFORMS.append(("c_plus_r", lambda r, c, i: (r, (c + r) % GRID_COLS)))
    TRANSFORMS.append(("r_plus_c_both", lambda r, c, i: ((r + c) % GRID_ROWS, (c + r) % GRID_COLS)))
    TRANSFORMS.append(("r_times_c", lambda r, c, i: ((r * c) % GRID_ROWS, c)))
    TRANSFORMS.append(("c_times_r", lambda r, c, i: (r, (c * r) % GRID_COLS)))

    # Position modular
    for mod_val in [5, 6, 7]:
        TRANSFORMS.append((f"pos_mod{mod_val}_r",
                           lambda r, c, i, m=mod_val: ((r + i % m) % GRID_ROWS, c)))
        TRANSFORMS.append((f"pos_mod{mod_val}_c",
                           lambda r, c, i, m=mod_val: (r, (c + i % m) % GRID_COLS)))
        TRANSFORMS.append((f"pos_mod{mod_val}_both",
                           lambda r, c, i, m=mod_val: ((r + i % m) % GRID_ROWS, (c + i % m) % GRID_COLS)))

    # Diagonal walk
    TRANSFORMS.append(("diag_walk", lambda r, c, i: ((r + i) % GRID_ROWS, (c + i) % GRID_COLS)))

    # Row = col + const, col = row + const
    for k in range(1, 6):
        TRANSFORMS.append((f"rotate_k{k}", lambda r, c, i, k=k: ((c + k) % GRID_ROWS, (r + k) % GRID_COLS)))

    print(f"  Testing {len(TRANSFORMS)} coordinate transforms...")

    for name, transform_fn in TRANSFORMS:
        pt = ""
        valid = True
        for i, ch in enumerate(CT):
            if ch not in LETTER_POS:
                pt += ch
                continue
            r, c = LETTER_POS[ch]
            nr, nc = transform_fn(r, c, i)
            pt_ch = grid_letter(nr, nc)
            if pt_ch is None:
                # Try adjacent valid cells
                found = False
                for delta_r in range(-1, 2):
                    for delta_c in range(-1, 2):
                        candidate = grid_letter((nr + delta_r) % GRID_ROWS, (nc + delta_c) % GRID_COLS)
                        if candidate is not None:
                            pt_ch = candidate
                            found = True
                            break
                    if found:
                        break
                if not found:
                    pt_ch = ch
            pt += pt_ch

        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("3_coord_transform", f"{name}", pt, crib_m)
        best_score = max(best_score, s)

    print(f"  Total configs: {total_configs}")
    print(f"  Best crib matches: {best_score}")
    return total_configs


# ============================================================================
# MECHANISM 4: Modified bifid on 6×5 grid
# ============================================================================

def mechanism_4_modified_bifid():
    """Modified bifid without I/J merge, using the 6×5 KA Polybius grid.

    Standard bifid: split into rows/cols, interleave, recombine pairs.
    Here the grid has 30 cells (26 letters + 4 empty in row 5).
    Row coordinates are mod 6, column coordinates are mod 5.

    Tested variants:
      A) Standard bifid process (period 5, 7, 8, 13, 24, 97)
      B) Trifid-like using row as third coordinate
      C) Z in row 5 gets special treatment (collapse to row 0)
      D) Extended grid: fill row 5 empty cells with KRYP (cyclic)
    """
    print("\n" + "="*70)
    print("MECHANISM 4: Modified bifid on 6x5 KA grid")
    print("="*70)

    total_configs = 0
    best_score = 0

    def letter_to_coords(ch):
        """Letter -> (row, col) in KA grid."""
        if ch in LETTER_POS:
            return LETTER_POS[ch]
        return (0, 0)  # fallback

    def coords_to_letter_mod(r, c):
        """(row mod 6, col mod 5) -> letter, skipping empty cells."""
        r = r % GRID_ROWS
        c = c % GRID_COLS
        if GRID[r][c] is not None:
            return GRID[r][c]
        # Empty cell (row 5, cols 1-4): wrap to row 0
        return GRID[0][c]

    def coords_to_letter_extended(r, c, extended_grid):
        """Use extended grid (row 5 filled)."""
        r = r % GRID_ROWS
        c = c % GRID_COLS
        return extended_grid[r][c]

    # Build extended grid: fill row 5 empty cells with KRYP
    EXTENDED_GRID = [row[:] for row in GRID]
    fill_chars = "KRYP"
    for c in range(1, GRID_COLS):
        if EXTENDED_GRID[5][c] is None:
            EXTENDED_GRID[5][c] = fill_chars[c - 1]

    # ── Variant A: Standard bifid process ──
    def decrypt_bifid(ct_text, period, coord_fn=coords_to_letter_mod):
        """Decrypt bifid cipher with given period on 6×5 grid.

        Bifid encryption:
          1. Split text into blocks of `period`
          2. For each block: extract row coords and col coords
          3. Concatenate rows then cols: [r0,r1,...,rN,c0,c1,...,cN]
          4. Read pairs from this stream: (stream[0],stream[1]), (stream[2],stream[3])...
          5. Each pair -> letter

        To decrypt: reverse the process.
          1. Split into blocks
          2. For each block: convert each CT letter to coords
          3. These coords came from interleaved pairs
          4. Un-interleave to get original rows and cols
        """
        pt = ""
        n = len(ct_text)

        for start in range(0, n, period):
            block = ct_text[start:start + period]
            blen = len(block)

            # Each block letter gives us a (row, col) pair
            # These pairs were formed from the interleaved stream
            # stream = [r0,r1,...,r_{blen-1}, c0,c1,...,c_{blen-1}]
            # Then pairs: (stream[0],stream[1]), (stream[2],stream[3]),...
            # = the CT letter coords

            ct_rows = []
            ct_cols = []
            for ch in block:
                r, c = letter_to_coords(ch)
                ct_rows.append(r)
                ct_cols.append(c)

            # CT coords come from reading the interleaved stream in pairs
            # stream has 2*blen elements, read as blen pairs
            stream = []
            for j in range(blen):
                stream.append(ct_rows[j])
                stream.append(ct_cols[j])

            # The stream was formed as [pt_r0, pt_r1,..., pt_c0, pt_c1,...]
            # Un-interleave: first blen elements are rows, next blen are cols
            pt_rows = stream[:blen]
            pt_cols = stream[blen:]

            for j in range(blen):
                pt += coord_fn(pt_rows[j], pt_cols[j])

        return pt

    # Test periods
    for period in [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 24, 48, 97]:
        # Standard mod wrap
        pt = decrypt_bifid(CT, period, coords_to_letter_mod)
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("4A_bifid_mod_wrap", f"period={period}", pt, crib_m)
        best_score = max(best_score, s)

        # Extended grid (row 5 filled)
        pt = decrypt_bifid(CT, period,
                           lambda r, c: coords_to_letter_extended(r, c, EXTENDED_GRID))
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("4A_bifid_extended", f"period={period}", pt, crib_m)
        best_score = max(best_score, s)

    # ── Variant B: Column-first interleave ──
    def decrypt_bifid_col_first(ct_text, period, coord_fn=coords_to_letter_mod):
        """Like bifid but interleave cols first then rows."""
        pt = ""
        n = len(ct_text)

        for start in range(0, n, period):
            block = ct_text[start:start + period]
            blen = len(block)

            ct_rows = []
            ct_cols = []
            for ch in block:
                r, c = letter_to_coords(ch)
                ct_rows.append(r)
                ct_cols.append(c)

            # Stream from (col, row) pairs instead of (row, col)
            stream = []
            for j in range(blen):
                stream.append(ct_cols[j])
                stream.append(ct_rows[j])

            pt_cols = stream[:blen]
            pt_rows = stream[blen:]

            for j in range(blen):
                pt += coord_fn(pt_rows[j], pt_cols[j])

        return pt

    for period in [5, 7, 8, 13, 24, 97]:
        pt = decrypt_bifid_col_first(CT, period)
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("4B_bifid_col_first", f"period={period}", pt, crib_m)
        best_score = max(best_score, s)

    # ── Variant C: Seriated key (rows in one chunk, cols in another) ──
    def decrypt_bifid_seriated(ct_text, period, coord_fn=coords_to_letter_mod):
        """Rows are grouped first, then cols (classic seriation)."""
        pt = ""
        n = len(ct_text)

        for start in range(0, n, period):
            block = ct_text[start:start + period]
            blen = len(block)

            ct_rows = []
            ct_cols = []
            for ch in block:
                r, c = letter_to_coords(ch)
                ct_rows.append(r)
                ct_cols.append(c)

            # In classic bifid, the fractionated stream is rows then cols
            frac_stream = ct_rows + ct_cols

            # Read pairs from the stream to get PT coords
            pt_block = ""
            for j in range(0, 2 * blen, 2):
                if j + 1 < len(frac_stream):
                    pt_block += coord_fn(frac_stream[j], frac_stream[j + 1])
                else:
                    pt_block += "X"
            pt += pt_block

        return pt

    for period in [5, 7, 8, 13, 24, 97]:
        pt = decrypt_bifid_seriated(CT, period)
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("4C_bifid_seriated", f"period={period}", pt, crib_m)
        best_score = max(best_score, s)

    # ── Variant D: Keyword-keyed grids ──
    KEYWORDS = ["KRYPTOS", "ABSCISSA", "DEFECTOR", "PALIMPSEST", "SEVEN",
                "SHADOW", "BERLIN", "KOMPASS"]
    for kw in KEYWORDS:
        # Build keyword-mixed alphabet
        seen = set()
        mixed = []
        for ch in kw + ALPH:
            if ch not in seen:
                mixed.append(ch)
                seen.add(ch)
        # Build grid from mixed alphabet
        kw_grid = []
        kw_pos = {}
        for r in range(GRID_ROWS):
            row = []
            for c in range(GRID_COLS):
                idx = r * GRID_COLS + c
                if idx < len(mixed):
                    row.append(mixed[idx])
                    kw_pos[mixed[idx]] = (r, c)
                else:
                    row.append(None)
            kw_grid.append(row)

        def kw_letter_to_coords(ch, pos_dict=kw_pos):
            if ch in pos_dict:
                return pos_dict[ch]
            return (0, 0)

        def kw_coords_to_letter(r, c, g=kw_grid):
            r = r % GRID_ROWS
            c = c % GRID_COLS
            if g[r][c] is not None:
                return g[r][c]
            return g[0][c]

        for period in [5, 7, 8, 13, 24, 97]:
            # Bifid decrypt with keyword grid
            pt = ""
            n = len(CT)
            for start in range(0, n, period):
                block = CT[start:start + period]
                blen = len(block)
                ct_rows = []
                ct_cols = []
                for ch in block:
                    r, c = kw_letter_to_coords(ch)
                    ct_rows.append(r)
                    ct_cols.append(c)
                stream = []
                for j in range(blen):
                    stream.append(ct_rows[j])
                    stream.append(ct_cols[j])
                pt_rows = stream[:blen]
                pt_cols = stream[blen:]
                for j in range(blen):
                    pt += kw_coords_to_letter(pt_rows[j], pt_cols[j])

            crib_m = count_crib_matches(pt)
            total_configs += 1
            s = record("4D_bifid_keyword", f"kw={kw},period={period}", pt, crib_m)
            best_score = max(best_score, s)

    # ── Variant E: Bifid on CT73 (after removing consensus nulls) ──
    CT73 = "".join(CT[i] for i in range(CT_LEN) if i not in CONSENSUS_NULLS)
    # Crib positions mapped to CT73 space
    ct73_crib_map = {}
    ct73_idx = 0
    for i in range(CT_LEN):
        if i not in CONSENSUS_NULLS:
            if i in CRIB_DICT:
                ct73_crib_map[ct73_idx] = CRIB_DICT[i]
            ct73_idx += 1

    for period in [5, 7, 8, 10, 13, 16, 20, 24, 36, 40, 73, 80]:
        pt = decrypt_bifid(CT73, period, coords_to_letter_mod)
        # Score against CT73 crib map
        crib_m = sum(1 for pos, ch in ct73_crib_map.items()
                     if pos < len(pt) and pt[pos] == ch)
        total_configs += 1
        s = record("4E_bifid_ct73", f"period={period}", pt, crib_m)
        best_score = max(best_score, s)

    print(f"  Total configs: {total_configs}")
    print(f"  Best crib matches: {best_score}")
    return total_configs


# ============================================================================
# MECHANISM 5: State-machine cipher
# ============================================================================

def mechanism_5_state_machine():
    """State-machine cipher on the KA Polybius grid.

    State = current position in the grid (one of 26 cells).
    Each step:
      1. State determines a transformation applied to the CT letter
      2. State transitions based on CT, PT, or both

    Transformation rules:
      - Shift by state's row
      - Shift by state's column
      - Shift by (row + col)
      - Shift by (row * col)
      - XOR-like: (letter_pos + state_pos) mod 26

    Transition rules:
      - Move to CT letter's position
      - Move to PT letter's position
      - Move right in grid (wrapping)
      - Move down in grid (wrapping)
      - Move to (row+1, col+1)
      - Move by KRYPTOS-indexed offset
    """
    print("\n" + "="*70)
    print("MECHANISM 5: State-machine cipher")
    print("="*70)

    total_configs = 0
    best_score = 0

    # Enumerate all 26 cells as possible states
    ALL_CELLS = [(r, c) for r in range(GRID_ROWS) for c in range(GRID_COLS)
                 if GRID[r][c] is not None]

    # Shift functions: state (r,c) -> shift amount for Beaufort/Vigenere decryption
    SHIFT_FNS = [
        ("row", lambda r, c: r),
        ("col", lambda r, c: c),
        ("row_plus_col", lambda r, c: r + c),
        ("row_times_col_p1", lambda r, c: r * c + 1),
        ("linear_idx", lambda r, c: r * GRID_COLS + c),
        ("row_minus_col", lambda r, c: (r - c) % MOD),
        ("col_minus_row", lambda r, c: (c - r) % MOD),
    ]

    # Transition functions: (state_r, state_c, ct_char, pt_char, position) -> new (r, c)
    TRANSITION_FNS = [
        ("to_ct_pos", lambda sr, sc, ct, pt, i: LETTER_POS.get(ct, (sr, sc))),
        ("to_pt_pos", lambda sr, sc, ct, pt, i: LETTER_POS.get(pt, (sr, sc))),
        ("move_right", lambda sr, sc, ct, pt, i: (sr, (sc + 1) % GRID_COLS)),
        ("move_down", lambda sr, sc, ct, pt, i: ((sr + 1) % GRID_ROWS, sc)),
        ("move_diag", lambda sr, sc, ct, pt, i: ((sr + 1) % GRID_ROWS, (sc + 1) % GRID_COLS)),
        ("stay", lambda sr, sc, ct, pt, i: (sr, sc)),
        ("ct_row_pt_col",
         lambda sr, sc, ct, pt, i: (LETTER_POS.get(ct, (0, 0))[0],
                                     LETTER_POS.get(pt, (0, 0))[1])),
    ]

    # Test: Beaufort decrypt: PT = (shift - CT) mod 26
    # Also test Vigenere decrypt: PT = (CT - shift) mod 26
    for shift_name, shift_fn in SHIFT_FNS:
        for trans_name, trans_fn in TRANSITION_FNS:
            # Test a subset of start states (KRYPTOS letters + first cell)
            start_chars = "KRYPTOSAZ"
            for start_ch in start_chars:
                if start_ch not in LETTER_POS:
                    continue
                state_r, state_c = LETTER_POS[start_ch]

                # Beaufort decrypt
                pt_beau = ""
                sr, sc = state_r, state_c
                ks_at_crib_beau = {}
                for i, ch in enumerate(CT):
                    shift = shift_fn(sr, sc) % MOD
                    ct_val = ALPH_IDX[ch]
                    pt_val = (shift - ct_val) % MOD  # Beaufort: PT = K - CT
                    pt_ch = ALPH[pt_val]
                    pt_beau += pt_ch

                    if i in CRIB_DICT:
                        # Beaufort key = (CT + PT) mod 26
                        ks_at_crib_beau[i] = (ct_val + pt_val) % MOD

                    # Handle empty cell after transition
                    new_sr, new_sc = trans_fn(sr, sc, ch, pt_ch, i)
                    if grid_letter(new_sr, new_sc) is None:
                        new_sr = new_sr % (GRID_ROWS - 1)  # avoid row 5
                    sr, sc = new_sr, new_sc

                crib_m = count_crib_matches(pt_beau)
                ks_m_b = count_keystream_matches_beau(ks_at_crib_beau)
                total_configs += 1
                s = record("5_state_machine_beau",
                          f"shift={shift_name},trans={trans_name},start={start_ch}",
                          pt_beau, crib_m, ks_m_b)
                best_score = max(best_score, s)

                # Vigenere decrypt
                pt_vig = ""
                sr, sc = state_r, state_c
                ks_at_crib_vig = {}
                for i, ch in enumerate(CT):
                    shift = shift_fn(sr, sc) % MOD
                    ct_val = ALPH_IDX[ch]
                    pt_val = (ct_val - shift) % MOD  # Vigenere: PT = CT - K
                    pt_ch = ALPH[pt_val]
                    pt_vig += pt_ch

                    if i in CRIB_DICT:
                        ks_at_crib_vig[i] = (ct_val - pt_val) % MOD

                    new_sr, new_sc = trans_fn(sr, sc, ch, pt_ch, i)
                    if grid_letter(new_sr, new_sc) is None:
                        new_sr = new_sr % (GRID_ROWS - 1)
                    sr, sc = new_sr, new_sc

                crib_m = count_crib_matches(pt_vig)
                ks_m_v = count_keystream_matches_vig(ks_at_crib_vig)
                total_configs += 1
                s = record("5_state_machine_vig",
                          f"shift={shift_name},trans={trans_name},start={start_ch}",
                          pt_vig, crib_m, ks_matches_vig=ks_m_v)
                best_score = max(best_score, s)

    # ── State machine with KRYPTOS modular state ──
    # State cycles through KRYPTOS letters, each letter determines grid position
    KW = "KRYPTOS"
    for shift_name, shift_fn in SHIFT_FNS:
        pt = ""
        for i, ch in enumerate(CT):
            kw_ch = KW[i % len(KW)]
            sr, sc = LETTER_POS[kw_ch]
            shift = shift_fn(sr, sc) % MOD
            ct_val = ALPH_IDX[ch]
            pt_val = (shift - ct_val) % MOD
            pt += ALPH[pt_val]
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("5_kryptos_cycle_beau", f"shift={shift_name}", pt, crib_m)
        best_score = max(best_score, s)

        pt = ""
        for i, ch in enumerate(CT):
            kw_ch = KW[i % len(KW)]
            sr, sc = LETTER_POS[kw_ch]
            shift = shift_fn(sr, sc) % MOD
            ct_val = ALPH_IDX[ch]
            pt_val = (ct_val - shift) % MOD
            pt += ALPH[pt_val]
        crib_m = count_crib_matches(pt)
        total_configs += 1
        s = record("5_kryptos_cycle_vig", f"shift={shift_name}", pt, crib_m)
        best_score = max(best_score, s)

    # ── Accumulating state machine ──
    # State accumulates: shift = sum of all previous CT (or PT) letter values mod 26
    for cipher_mode in ["beau", "vig"]:
        for accum_source in ["ct", "pt"]:
            for start_val in range(MOD):
                pt = ""
                accum = start_val
                for i, ch in enumerate(CT):
                    ct_val = ALPH_IDX[ch]
                    if cipher_mode == "beau":
                        pt_val = (accum - ct_val) % MOD
                    else:
                        pt_val = (ct_val - accum) % MOD
                    pt_ch = ALPH[pt_val]
                    pt += pt_ch

                    if accum_source == "ct":
                        accum = (accum + ct_val) % MOD
                    else:
                        accum = (accum + pt_val) % MOD

                crib_m = count_crib_matches(pt)
                total_configs += 1
                s = record("5_accumulating",
                          f"mode={cipher_mode},src={accum_source},start={start_val}",
                          pt, crib_m)
                best_score = max(best_score, s)

    # ── Grid-walk state machine ──
    # State walks through grid in reading order, cycling
    for cipher_mode in ["beau", "vig"]:
        for step in range(1, 27):  # step size through grid cells
            pt = ""
            for i, ch in enumerate(CT):
                cell_idx = (i * step) % 26
                sr = cell_idx // GRID_COLS
                sc = cell_idx % GRID_COLS
                shift = (sr * GRID_COLS + sc) % MOD
                ct_val = ALPH_IDX[ch]
                if cipher_mode == "beau":
                    pt_val = (shift - ct_val) % MOD
                else:
                    pt_val = (ct_val - shift) % MOD
                pt += ALPH[pt_val]
            crib_m = count_crib_matches(pt)
            total_configs += 1
            s = record("5_grid_walk", f"mode={cipher_mode},step={step}", pt, crib_m)
            best_score = max(best_score, s)

    print(f"  Total configs: {total_configs}")
    print(f"  Best crib matches: {best_score}")
    return total_configs


# ============================================================================
# BONUS: Mechanism 6 — Polybius-grid Beaufort with grid-derived keystream
# ============================================================================

def mechanism_6_grid_beaufort():
    """Beaufort cipher where the key is derived from grid coordinates of CT.

    Instead of a separate key, the key at each position is computed from
    the CT letter's position in the KA Polybius grid using simple functions.

    This directly targets the known Beaufort keystream values at crib positions.
    If any function matches >=12/24 known keystream values, it's a strong signal.
    """
    print("\n" + "="*70)
    print("MECHANISM 6: Grid-derived Beaufort keystream")
    print("="*70)

    total_configs = 0
    best_score = 0
    best_ks_match = 0

    # Key generation functions: CT_char -> key_value
    # Using grid coordinates of CT letter
    KEY_FUNS = []

    # Basic coordinate functions
    KEY_FUNS.append(("row", lambda r, c, i: r))
    KEY_FUNS.append(("col", lambda r, c, i: c))
    KEY_FUNS.append(("row_plus_col", lambda r, c, i: r + c))
    KEY_FUNS.append(("row_times_col", lambda r, c, i: r * c))
    KEY_FUNS.append(("row_minus_col", lambda r, c, i: (r - c) % MOD))
    KEY_FUNS.append(("col_minus_row", lambda r, c, i: (c - r) % MOD))
    KEY_FUNS.append(("linear_idx", lambda r, c, i: r * GRID_COLS + c))
    KEY_FUNS.append(("linear_idx_rev", lambda r, c, i: 25 - (r * GRID_COLS + c)))

    # Position-dependent
    KEY_FUNS.append(("pos_plus_row", lambda r, c, i: i + r))
    KEY_FUNS.append(("pos_plus_col", lambda r, c, i: i + c))
    KEY_FUNS.append(("pos_times_row", lambda r, c, i: i * r))
    KEY_FUNS.append(("pos_times_col", lambda r, c, i: i * c))
    KEY_FUNS.append(("pos_xor_idx", lambda r, c, i: i ^ (r * GRID_COLS + c)))
    KEY_FUNS.append(("pos_plus_idx", lambda r, c, i: i + r * GRID_COLS + c))

    # Combined with constants
    for k in range(1, 8):
        KEY_FUNS.append((f"row_plus_{k}", lambda r, c, i, k=k: r + k))
        KEY_FUNS.append((f"col_plus_{k}", lambda r, c, i, k=k: c + k))
        KEY_FUNS.append((f"idx_plus_{k}", lambda r, c, i, k=k: r * GRID_COLS + c + k))
        KEY_FUNS.append((f"row_times_{k}", lambda r, c, i, k=k: r * k))
        KEY_FUNS.append((f"col_times_{k}", lambda r, c, i, k=k: c * k))

    # Previous CT letter based
    KEY_FUNS.append(("prev_ct_row", lambda r, c, i: r))  # placeholder, handled below

    print(f"  Testing {len(KEY_FUNS)} key generation functions...")

    for fname, kfn in KEY_FUNS:
        # Compute keystream at ALL positions
        ks_at_crib = {}
        pt = ""
        for i, ch in enumerate(CT):
            if ch not in LETTER_POS:
                pt += ch
                continue
            r, c = LETTER_POS[ch]
            k = kfn(r, c, i) % MOD
            ct_val = ALPH_IDX[ch]

            # Beaufort decrypt: PT = K - CT mod 26
            pt_val = (k - ct_val) % MOD
            pt += ALPH[pt_val]

            if i in CRIB_DICT:
                # Beaufort key = (CT + PT) mod 26
                ks_at_crib[i] = (ct_val + pt_val) % MOD

        crib_m = count_crib_matches(pt)
        ks_m = count_keystream_matches_beau(ks_at_crib)
        total_configs += 1
        s = record("6_grid_beaufort", f"keyfn={fname}", pt, crib_m, ks_m)
        best_score = max(best_score, s)
        best_ks_match = max(best_ks_match, ks_m)

        # Also Vigenere
        ks_at_crib_v = {}
        pt_v = ""
        for i, ch in enumerate(CT):
            if ch not in LETTER_POS:
                pt_v += ch
                continue
            r, c = LETTER_POS[ch]
            k = kfn(r, c, i) % MOD
            ct_val = ALPH_IDX[ch]
            pt_val = (ct_val - k) % MOD
            pt_v += ALPH[pt_val]
            if i in CRIB_DICT:
                ks_at_crib_v[i] = (ct_val - pt_val) % MOD

        crib_m_v = count_crib_matches(pt_v)
        ks_m_v = count_keystream_matches_vig(ks_at_crib_v)
        total_configs += 1
        s = record("6_grid_vigenere", f"keyfn={fname}", pt_v, crib_m_v, ks_matches_vig=ks_m_v)
        best_score = max(best_score, s)
        best_ks_match = max(best_ks_match, ks_m_v)

    # ── Chain function: key depends on PREVIOUS CT letter's grid position ──
    CHAIN_FNS = [
        ("prev_row", lambda pr, pc, r, c, i: pr),
        ("prev_col", lambda pr, pc, r, c, i: pc),
        ("prev_idx", lambda pr, pc, r, c, i: pr * GRID_COLS + pc),
        ("prev_row_plus_cur_col", lambda pr, pc, r, c, i: pr + c),
        ("prev_col_plus_cur_row", lambda pr, pc, r, c, i: pc + r),
        ("prev_idx_plus_cur_idx", lambda pr, pc, r, c, i: (pr * GRID_COLS + pc) + (r * GRID_COLS + c)),
        ("prev_row_xor_cur_row", lambda pr, pc, r, c, i: pr ^ r),
    ]

    for fname, cfn in CHAIN_FNS:
        for cipher_mode in ["beau", "vig"]:
            for start_ch in "KRYPTOSAZ":
                if start_ch not in LETTER_POS:
                    continue
                prev_r, prev_c = LETTER_POS[start_ch]
                pt = ""
                ks_at_crib = {}
                for i, ch in enumerate(CT):
                    if ch not in LETTER_POS:
                        pt += ch
                        continue
                    r, c = LETTER_POS[ch]
                    k = cfn(prev_r, prev_c, r, c, i) % MOD
                    ct_val = ALPH_IDX[ch]
                    if cipher_mode == "beau":
                        pt_val = (k - ct_val) % MOD
                    else:
                        pt_val = (ct_val - k) % MOD
                    pt += ALPH[pt_val]
                    if i in CRIB_DICT:
                        if cipher_mode == "beau":
                            ks_at_crib[i] = (ct_val + pt_val) % MOD
                        else:
                            ks_at_crib[i] = (ct_val - pt_val) % MOD
                    prev_r, prev_c = r, c

                crib_m = count_crib_matches(pt)
                if cipher_mode == "beau":
                    ks_m = count_keystream_matches_beau(ks_at_crib)
                else:
                    ks_m = count_keystream_matches_vig(ks_at_crib)
                total_configs += 1
                s = record(f"6_chain_{cipher_mode}",
                          f"fn={fname},start={start_ch}", pt, crib_m,
                          ks_m if cipher_mode == "beau" else 0,
                          ks_m if cipher_mode == "vig" else 0)
                best_score = max(best_score, s)
                best_ks_match = max(best_ks_match, ks_m)

    print(f"  Total configs: {total_configs}")
    print(f"  Best crib matches: {best_score}")
    print(f"  Best keystream matches: {best_ks_match}")
    return total_configs


# ============================================================================
# MAIN
# ============================================================================

def main():
    start_time = time.time()

    print("E-PROCESS-CIPHERS: Non-algebraic process ciphers on 5-wide KA Polybius grid")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"KA: {KA}")
    print(f"Grid: {GRID_ROWS}x{GRID_COLS}")
    print()
    print("Grid layout:")
    for r in range(GRID_ROWS):
        row_str = " ".join(GRID[r][c] if GRID[r][c] else "." for c in range(GRID_COLS))
        print(f"  Row {r}: {row_str}")
    print()

    total = 0
    total += mechanism_1_row_cycling()
    total += mechanism_2_sliding_row()
    total += mechanism_3_polybius_pair()
    total += mechanism_4_modified_bifid()
    total += mechanism_5_state_machine()
    total += mechanism_6_grid_beaufort()

    elapsed = time.time() - start_time

    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total configurations tested: {total}")
    print(f"Time elapsed: {elapsed:.1f}s")
    print(f"Results above noise (>=6): {len(ALL_RESULTS)}")
    print()

    # Print best per mechanism
    print("Best per mechanism:")
    for mech, data in sorted(BEST_PER_MECHANISM.items()):
        e = data["entry"]
        print(f"  {mech}: {data['best_metric']} "
              f"(crib={e['crib_matches']}, ks_beau={e.get('ks_beau',0)}, "
              f"ks_vig={e.get('ks_vig',0)}) "
              f"params={e['params']}")

    # Score any promising results through full pipeline
    THRESHOLD_FOR_FULL_SCORE = 8
    full_scored = []
    for mech, data in BEST_PER_MECHANISM.items():
        if data["best_metric"] >= THRESHOLD_FOR_FULL_SCORE:
            pt = data["full_plaintext"]
            if pt and len(pt) >= 97:
                sb = score_candidate(pt)
                full_scored.append({
                    "mechanism": mech,
                    "params": data["entry"]["params"],
                    "score_breakdown": sb.summary,
                    "crib_score": sb.crib_score,
                    "ic": sb.ic_value,
                })
                print(f"\n  FULL SCORE for {mech}: {sb.summary}")

    # Write results
    results = {
        "experiment": "E-PROCESS-CIPHERS",
        "description": "Non-algebraic process-based ciphers on 5-wide KA Polybius grid",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ct": CT,
        "ct_len": CT_LEN,
        "ka_grid": KA,
        "total_configs": total,
        "elapsed_seconds": round(elapsed, 1),
        "results_above_noise": len(ALL_RESULTS),
        "best_per_mechanism": {
            mech: {
                "best_metric": data["best_metric"],
                "params": data["entry"]["params"],
                "crib_matches": data["entry"]["crib_matches"],
                "ks_beau": data["entry"].get("ks_beau", 0),
                "ks_vig": data["entry"].get("ks_vig", 0),
                "plaintext_first40": data["entry"]["plaintext_snippet"],
            }
            for mech, data in sorted(BEST_PER_MECHANISM.items())
        },
        "full_scored": full_scored,
        "above_noise_results": ALL_RESULTS[:50],  # top 50
        "verdict": "NOISE" if all(d["best_metric"] < 12 for d in BEST_PER_MECHANISM.values()) else "INVESTIGATE",
    }

    results_path = os.path.join(_ROOT, "results", "e_process_ciphers.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults written to {results_path}")

    # Final verdict
    max_score = max(d["best_metric"] for d in BEST_PER_MECHANISM.values()) if BEST_PER_MECHANISM else 0
    if max_score >= 12:
        print(f"\n*** INVESTIGATE: max score {max_score}/24 — worth deeper analysis ***")
    else:
        print(f"\n*** NOISE: max score {max_score}/24 — all mechanisms eliminated ***")

    return max_score


if __name__ == "__main__":
    sys.exit(0 if main() < 12 else 1)
