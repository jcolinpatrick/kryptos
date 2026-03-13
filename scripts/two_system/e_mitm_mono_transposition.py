#!/usr/bin/env python3
# Cipher: monoalphabetic substitution × structured transposition
# Family: two_system
# Status: active
# Keyspace: ~50M+ (mono-consistency filter eliminates >99.99%)
# Last run:
# Best score:
#
# MEET-IN-THE-MIDDLE: Monoalphabetic Substitution × Structured Transpositions
#
# Model: PT → Transposition T → Intermediate → Mono Substitution S → CT
#
# For any permutation T of {0..96}:
#   CT[T(i)] = S(PT[i])  for all i
#
# The MITM filter exploits the 24 known plaintext positions. For each candidate
# transposition T, we check:
#   1. MONO-CONSISTENCY: Same PT letter → same CT letter at transposed positions.
#      E.g., PT[21]=PT[30]=PT[64]=E, so CT[T(21)]=CT[T(30)]=CT[T(64)] required.
#   2. INJECTIVITY: Different PT letters → different CT letters (mono sub is bijection).
#      13 distinct PT letters must map to 13 distinct CT letters.
#
# This eliminates >99.99% of transpositions instantly (no decryption needed).
#
# For survivors: derive the partial mono sub (13 of 26 pairs known), decrypt all 97
# chars using known pairs (unknown pairs → '?'), score with quadgrams on known chars.
#
# Transposition families tested:
#   1. Columnar (widths 2-10 exhaustive, 11-20 keyword)
#   2. Reverse columnar (write cols, read rows)
#   3. Rail fence (2-30 rails)
#   4. Route ciphers (spiral, snake, diagonal at various grid dims)
#   5. Stride/decimation (read every d-th char, all starts)
#   6. Double rotation (K3-style)
#   7. Reversed CT + all above
#   8. Myszkowski transposition (keyword-based)
#   9. Identity (mono sub only, no transposition)
#
# BONUS: For mono-consistent hits, also try periodic Vigenere at periods 2-13
# on the transposed text (since periodic sub on transposed text is viable).
#
# Usage: PYTHONPATH=src python3 -u scripts/two_system/e_mitm_mono_transposition.py

from __future__ import annotations

import json
import math
import sys
import time
from collections import defaultdict
from itertools import permutations
from typing import Dict, List, Optional, Set, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)

# ── Crib analysis ─────────────────────────────────────────────────────────

# Build the repeated-letter groups from cribs
# EASTNORTHEAST: E(21) A(22) S(23) T(24) N(25) O(26) R(27) T(28) H(29) E(30) A(31) S(32) T(33)
# BERLINCLOCK:   B(63) E(64) R(65) L(66) I(67) N(68) C(69) L(70) O(71) C(72) K(73)

CRIB_POSITIONS_SORTED = sorted(CRIB_POSITIONS)

# Group crib positions by their plaintext letter
PT_LETTER_GROUPS: Dict[str, List[int]] = defaultdict(list)
for pos in CRIB_POSITIONS_SORTED:
    PT_LETTER_GROUPS[CRIB_DICT[pos]].append(pos)

# Repeated letters (positions that must map to same CT letter)
REPEAT_GROUPS: List[List[int]] = [
    positions for positions in PT_LETTER_GROUPS.values() if len(positions) > 1
]

# Number of distinct PT letters in cribs
DISTINCT_PT_LETTERS = list(PT_LETTER_GROUPS.keys())
N_DISTINCT = len(DISTINCT_PT_LETTERS)

# Pre-compute crib positions as a list for fast access
CRIB_POS_LIST = CRIB_POSITIONS_SORTED
CRIB_PT_CHARS = [CRIB_DICT[p] for p in CRIB_POS_LIST]

# CT as a list for indexed access
CT_LIST = list(CT)


def print_crib_analysis():
    """Print the crib letter analysis."""
    print("CRIB ANALYSIS:")
    print(f"  Total crib positions: {N_CRIBS}")
    print(f"  Distinct PT letters:  {N_DISTINCT}")
    print(f"  PT letters: {' '.join(DISTINCT_PT_LETTERS)}")
    print(f"\n  Repeat groups (same PT letter → must map to same CT letter):")
    for letter, positions in sorted(PT_LETTER_GROUPS.items()):
        if len(positions) > 1:
            print(f"    {letter}: positions {positions} ({len(positions)} occurrences)")
    print(f"\n  Unique letters (appear once): ", end="")
    singles = [l for l, p in PT_LETTER_GROUPS.items() if len(p) == 1]
    print(", ".join(f"{l}({PT_LETTER_GROUPS[l][0]})" for l in singles))
    print()


# ── Mono-consistency check ────────────────────────────────────────────────

def check_mono_consistency(perm: List[int]) -> Optional[Dict[str, str]]:
    """Check if a transposition permutation is mono-consistent with cribs.

    For each crib PT position i, the transposition maps it to perm[i].
    At that CT position, we read CT[perm[i]].
    For a monoalphabetic substitution S: CT[perm[i]] = S(PT[i]).

    Consistency requires:
      - Same PT letter → same CT letter (well-definedness of S)
      - Different PT letter → different CT letter (injectivity of S)

    Args:
        perm: Transposition permutation. perm[i] = j means PT position i
              maps to intermediate/CT position j.

    Returns:
        Dict mapping PT letter → CT letter if consistent, None otherwise.
    """
    sub_map: Dict[str, str] = {}  # PT letter → CT letter
    inv_map: Dict[str, str] = {}  # CT letter → PT letter (for injectivity)

    for pt_pos, pt_char in zip(CRIB_POS_LIST, CRIB_PT_CHARS):
        ct_pos = perm[pt_pos]
        ct_char = CT_LIST[ct_pos]

        if pt_char in sub_map:
            # Already seen this PT letter — CT letter must match
            if sub_map[pt_char] != ct_char:
                return None
        else:
            # New PT letter — check injectivity (CT letter not already used)
            if ct_char in inv_map:
                if inv_map[ct_char] != pt_char:
                    return None
            sub_map[pt_char] = ct_char
            inv_map[ct_char] = pt_char

    return sub_map


def derive_full_plaintext(perm: List[int], sub_map: Dict[str, str]) -> str:
    """Given a mono-consistent transposition and partial sub map, decrypt CT.

    For positions where the inverse substitution is known, produce the PT char.
    For unknown mappings, output '?'.

    The inverse permutation gives us: PT[i] = S_inv(CT[perm[i]])
    Equivalently: for each output position j in CT, PT[inv_perm[j]] = S_inv(CT[j])
    """
    # Build inverse substitution: CT letter → PT letter
    inv_sub: Dict[str, str] = {v: k for k, v in sub_map.items()}

    # Build inverse permutation
    inv_perm = [0] * CT_LEN
    for i in range(CT_LEN):
        inv_perm[perm[i]] = i

    # Decrypt
    plaintext = ['?'] * CT_LEN
    for j in range(CT_LEN):
        ct_char = CT_LIST[j]
        pt_pos = inv_perm[j]
        if ct_char in inv_sub:
            plaintext[pt_pos] = inv_sub[ct_char]
        else:
            plaintext[pt_pos] = '?'

    return "".join(plaintext)


# ── Quadgram scorer ───────────────────────────────────────────────────────

def load_quadgrams(path: str = "data/english_quadgrams.json") -> Dict[str, float]:
    """Load quadgram log-probabilities."""
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"  WARNING: Quadgram file not found at {path}")
        return {}


def score_quadgrams(text: str, qg: Dict[str, float]) -> float:
    """Score text by average quadgram log-probability. Ignores '?' characters."""
    if not qg or len(text) < 4:
        return -15.0
    total = 0.0
    count = 0
    floor = min(qg.values()) - 1.0
    for i in range(len(text) - 3):
        gram = text[i:i + 4].upper()
        if '?' in gram:
            continue
        total += qg.get(gram, floor)
        count += 1
    return total / count if count > 0 else -15.0


def score_ic(text: str) -> float:
    """Compute IC, ignoring '?' characters."""
    filtered = [c for c in text if c != '?']
    if len(filtered) <= 1:
        return 0.0
    from collections import Counter
    freq = Counter(filtered)
    n = sum(freq.values())
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


# ── Periodic Vigenere bonus check ─────────────────────────────────────────

def check_periodic_vig_on_transposed(perm: List[int]) -> List[Tuple[int, str, int, str]]:
    """For a given transposition, check if periodic Vig/Beau/VBeau (periods 2-13)
    is crib-consistent on the transposed text.

    Model: PT → transposition T → intermediate → periodic sub → CT

    For crib position i: CT[T(i)] and PT[i] are known.
    Intermediate position j = T(i).
    Key at position j: k[j % period].
    Derive k from CT[j] and PT[i], check consistency per residue class.

    Returns list of (period, variant_name, n_consistent, key_desc) for hits >= 24.
    """
    hits = []

    DERIVE_FNS = {
        "Vig": lambda ct_c, pt_c: (ALPH_IDX[ct_c] - ALPH_IDX[pt_c]) % MOD,
        "Beau": lambda ct_c, pt_c: (ALPH_IDX[ct_c] + ALPH_IDX[pt_c]) % MOD,
        "VBeau": lambda ct_c, pt_c: (ALPH_IDX[pt_c] - ALPH_IDX[ct_c]) % MOD,
    }
    DECRYPT_FNS = {
        "Vig": lambda ct_c, k: ALPH[(ALPH_IDX[ct_c] - k) % MOD],
        "Beau": lambda ct_c, k: ALPH[(k - ALPH_IDX[ct_c]) % MOD],
        "VBeau": lambda ct_c, k: ALPH[(ALPH_IDX[ct_c] + k) % MOD],
    }

    for period in range(2, 14):
        for var_name in ("Vig", "Beau", "VBeau"):
            derive_fn = DERIVE_FNS[var_name]

            # Derive key values per residue class
            residue_keys: Dict[int, Set[int]] = defaultdict(set)
            for pt_pos, pt_char in zip(CRIB_POS_LIST, CRIB_PT_CHARS):
                it_pos = perm[pt_pos]
                ct_char = CT_LIST[it_pos]
                key_val = derive_fn(ct_char, pt_char)
                residue_keys[it_pos % period].add(key_val)

            # Check consistency
            n_consistent = 0
            key_by_residue: Dict[int, int] = {}
            all_consistent = True
            for residue, keys in residue_keys.items():
                n_in_class = sum(1 for pp in CRIB_POS_LIST if perm[pp] % period == residue)
                if len(keys) == 1:
                    n_consistent += n_in_class
                    key_by_residue[residue] = next(iter(keys))
                else:
                    all_consistent = False
                    # Count majority
                    key_counts: Dict[int, int] = defaultdict(int)
                    for pp, pc in zip(CRIB_POS_LIST, CRIB_PT_CHARS):
                        if perm[pp] % period == residue:
                            key_counts[derive_fn(CT_LIST[perm[pp]], pc)] += 1
                    n_consistent += max(key_counts.values())

            if n_consistent >= 24 and all_consistent:
                # Build full key and decrypt
                key = [0] * period
                for r, kv in key_by_residue.items():
                    key[r] = kv
                key_str = "".join(ALPH[k] for k in key)

                # Decrypt: undo substitution on CT, then undo transposition
                decrypt_fn = DECRYPT_FNS[var_name]
                intermediate = "".join(decrypt_fn(CT_LIST[j], key[j % period]) for j in range(CT_LEN))

                # Undo transposition
                inv_perm = [0] * CT_LEN
                for i in range(CT_LEN):
                    inv_perm[perm[i]] = i
                plaintext = "".join(intermediate[inv_perm[j]] for j in range(CT_LEN))

                hits.append((period, var_name, n_consistent, f"key={key_str} PT={plaintext}"))

    return hits


# ── Transposition generators ──────────────────────────────────────────────

def gen_identity() -> Tuple[str, List[int]]:
    """Identity permutation (no transposition — pure monoalphabetic)."""
    yield "identity", list(range(CT_LEN))


def gen_reversal() -> Tuple[str, List[int]]:
    """Simple reversal of the text."""
    yield "reversal", list(range(CT_LEN - 1, -1, -1))


def gen_stride_decimation() -> Tuple[str, List[int]]:
    """Read every d-th character, starting at s. d must be coprime to 97.
    Since 97 is prime, every d in 1..96 is coprime.
    """
    for d in range(2, CT_LEN):
        for s in range(CT_LEN):
            perm = [0] * CT_LEN
            for i in range(CT_LEN):
                perm[i] = (s + i * d) % CT_LEN
            yield f"stride(d={d},s={s})", perm


def gen_rail_fence() -> Tuple[str, List[int]]:
    """Rail fence cipher at various rail counts (2..30).
    Returns the ENCRYPTION permutation: perm[i] = j means PT[i] → CT[j].
    """
    for n_rails in range(2, 31):
        if n_rails >= CT_LEN:
            break
        # Build the rail fence pattern
        rails = [[] for _ in range(n_rails)]
        rail = 0
        direction = 1
        for i in range(CT_LEN):
            rails[rail].append(i)
            if rail == 0:
                direction = 1
            elif rail == n_rails - 1:
                direction = -1
            rail += direction

        # The encryption permutation: reading off rails top to bottom
        perm = [0] * CT_LEN
        out_pos = 0
        for rail_positions in rails:
            for pt_pos in rail_positions:
                perm[pt_pos] = out_pos
                out_pos += 1

        yield f"railfence(rails={n_rails})", perm


def gen_columnar_exhaustive(max_width: int = 10) -> Tuple[str, List[int]]:
    """Columnar transposition with exhaustive column orderings.
    For width w, tests all w! orderings.
    """
    for width in range(2, max_width + 1):
        n_rows = math.ceil(CT_LEN / width)
        total_cells = n_rows * width
        short_cols = total_cells - CT_LEN

        for col_perm in permutations(range(width)):
            col_order = list(col_perm)

            # Compute which columns are short
            col_lengths = []
            for col in range(width):
                if col >= width - short_cols:
                    col_lengths.append(n_rows - 1)
                else:
                    col_lengths.append(n_rows)

            # Compute output start position for each column in read order
            col_starts = {}
            pos = 0
            for order_idx in range(width):
                col_idx = col_order[order_idx]
                col_starts[col_idx] = pos
                pos += col_lengths[col_idx]

            # Build permutation: perm[i] = j means PT[i] → CT[j]
            perm = [0] * CT_LEN
            for i in range(CT_LEN):
                row = i // width
                col = i % width
                if row < col_lengths[col]:
                    perm[i] = col_starts[col] + row

            yield f"columnar(w={width},order={col_order})", perm


def gen_reverse_columnar_exhaustive(max_width: int = 8) -> Tuple[str, List[int]]:
    """Reverse columnar: write by columns (in given order), read by rows.
    This is the transpose of standard columnar.
    """
    for width in range(2, max_width + 1):
        n_rows = math.ceil(CT_LEN / width)
        total_cells = n_rows * width
        short_cols = total_cells - CT_LEN

        for col_perm in permutations(range(width)):
            col_order = list(col_perm)

            # Column lengths
            col_lengths = []
            for col in range(width):
                if col >= width - short_cols:
                    col_lengths.append(n_rows - 1)
                else:
                    col_lengths.append(n_rows)

            # Write by columns in col_order: first fill col_order[0], then col_order[1], ...
            # Read by rows.
            # Input position tracking
            grid = [[None] * width for _ in range(n_rows)]
            input_pos = 0
            for order_idx in range(width):
                col_idx = col_order[order_idx]
                for row in range(col_lengths[col_idx]):
                    grid[row][col_idx] = input_pos
                    input_pos += 1

            # Read by rows to get output
            perm = [0] * CT_LEN
            out_pos = 0
            for row in range(n_rows):
                for col in range(width):
                    if grid[row][col] is not None:
                        perm[grid[row][col]] = out_pos
                        out_pos += 1

            yield f"rev_columnar(w={width},order={col_order})", perm


def gen_columnar_keyword(min_width: int = 11, max_width: int = 20) -> Tuple[str, List[int]]:
    """Columnar transposition with keyword-derived orderings for larger widths.
    Uses thematic keywords plus words from english.txt that match the width.
    """
    # Load thematic keywords
    thematic = []
    try:
        with open("wordlists/thematic_keywords.txt") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    word = line.upper()
                    if word.isalpha():
                        thematic.append(word)
    except FileNotFoundError:
        pass

    # Load english wordlist words of appropriate lengths
    english_words: Dict[int, List[str]] = defaultdict(list)
    try:
        with open("wordlists/english.txt") as f:
            for line in f:
                word = line.strip().upper()
                if word.isalpha() and min_width <= len(word) <= max_width:
                    english_words[len(word)].append(word)
    except FileNotFoundError:
        pass

    for width in range(min_width, max_width + 1):
        n_rows = math.ceil(CT_LEN / width)
        total_cells = n_rows * width
        short_cols = total_cells - CT_LEN

        seen_orders = set()

        # Gather keywords for this width
        keywords_for_width = set()

        # Thematic keywords: truncate/extend to width
        for kw in thematic:
            if len(kw) >= width:
                keywords_for_width.add(kw[:width])
            else:
                ext = (kw * ((width // len(kw)) + 1))[:width]
                keywords_for_width.add(ext)

        # English words of exactly this length
        for word in english_words.get(width, [])[:5000]:  # cap at 5K per width
            keywords_for_width.add(word)

        for kw in keywords_for_width:
            col_order = sorted(range(width), key=lambda i: (kw[i], i))
            col_order_tuple = tuple(col_order)

            # Try both the order and its inverse
            inv_order = [0] * width
            for i, v in enumerate(col_order):
                inv_order[v] = i

            for order, order_desc in [(col_order, "fwd"), (inv_order, "inv")]:
                ot = tuple(order)
                if ot in seen_orders:
                    continue
                seen_orders.add(ot)

                # Compute column lengths
                col_lengths = []
                for col in range(width):
                    if col >= width - short_cols:
                        col_lengths.append(n_rows - 1)
                    else:
                        col_lengths.append(n_rows)

                # Compute permutation
                col_starts = {}
                pos = 0
                for order_idx in range(width):
                    col_idx = order[order_idx]
                    col_starts[col_idx] = pos
                    pos += col_lengths[col_idx]

                perm = [0] * CT_LEN
                for i in range(CT_LEN):
                    row = i // width
                    col = i % width
                    if row < col_lengths[col]:
                        perm[i] = col_starts[col] + row

                yield f"columnar_kw(w={width},kw={kw[:12]}..{order_desc})", perm


def _grid_read_to_perm(read_order: List[int], n_rows: int, n_cols: int) -> Optional[List[int]]:
    """Convert a grid read order to a valid permutation of {0..CT_LEN-1}.

    read_order: list of flat grid indices (r*n_cols+c) in the order they are read.
    The grid has n_rows*n_cols cells, but only CT_LEN chars occupy it.
    Convention: PT is written into the grid in row-major order, filling the first
    CT_LEN cells (row 0 fully, row 1 fully, ..., last row partially).
    Cells beyond CT_LEN are padding (empty).

    Returns perm where perm[write_pos] = read_pos, meaning PT char at write
    position i ends up at output position perm[i].
    Returns None if the permutation is invalid.
    """
    # Determine which grid cells contain real data (row-major fill)
    valid_cells = set()
    for i in range(CT_LEN):
        r = i // n_cols
        c = i % n_cols
        valid_cells.add(r * n_cols + c)

    # Filter read order to only valid cells, preserving order
    filtered_read = [idx for idx in read_order if idx in valid_cells]
    if len(filtered_read) != CT_LEN:
        return None

    # Map grid index → write position (row-major input position)
    grid_to_write = {}
    for i in range(CT_LEN):
        r = i // n_cols
        c = i % n_cols
        grid_to_write[r * n_cols + c] = i

    # perm[write_pos] = output_pos
    perm = [0] * CT_LEN
    for out_pos, grid_idx in enumerate(filtered_read):
        write_pos = grid_to_write[grid_idx]
        perm[write_pos] = out_pos

    if sorted(perm) != list(range(CT_LEN)):
        return None

    return perm


def gen_route_ciphers() -> Tuple[str, List[int]]:
    """Route ciphers: various grid dimensions with spiral, snake, diagonal reads.
    Grid dimensions are factor pairs of CT_LEN or nearby values.
    """
    grid_dims = []
    for n_cols in range(4, 25):
        n_rows = math.ceil(CT_LEN / n_cols)
        if n_rows >= 2 and n_cols >= 2:
            grid_dims.append((n_rows, n_cols))

    for n_rows, n_cols in grid_dims:
        total = n_rows * n_cols

        # --- Spiral inward (clockwise) ---
        for start_corner in range(4):  # TL, TR, BR, BL
            try:
                read_order = _spiral_order(n_rows, n_cols, start_corner)
                perm = _grid_read_to_perm(read_order, n_rows, n_cols)
                if perm is not None:
                    yield f"spiral(r={n_rows},c={n_cols},corner={start_corner})", perm
            except (IndexError, ValueError):
                continue

        # --- Snake (zigzag rows) ---
        for col_first in (False, True):
            try:
                read_order = []
                if not col_first:
                    for r in range(n_rows):
                        cols = range(n_cols) if r % 2 == 0 else range(n_cols - 1, -1, -1)
                        for c in cols:
                            read_order.append(r * n_cols + c)
                else:
                    for c in range(n_cols):
                        rows = range(n_rows) if c % 2 == 0 else range(n_rows - 1, -1, -1)
                        for r in rows:
                            read_order.append(r * n_cols + c)

                perm = _grid_read_to_perm(read_order, n_rows, n_cols)
                if perm is not None:
                    yield f"snake(r={n_rows},c={n_cols},col_first={col_first})", perm
            except (IndexError, ValueError):
                continue

        # --- Diagonal reads ---
        for direction in ("tl_br", "tr_bl"):
            try:
                read_order = _diagonal_order(n_rows, n_cols, direction)
                perm = _grid_read_to_perm(read_order, n_rows, n_cols)
                if perm is not None:
                    yield f"diagonal(r={n_rows},c={n_cols},dir={direction})", perm
            except (IndexError, ValueError):
                continue


def _spiral_order(n_rows: int, n_cols: int, start_corner: int) -> List[int]:
    """Generate spiral read order for a grid, starting from given corner.
    start_corner: 0=TL clockwise, 1=TR clockwise, 2=BR clockwise, 3=BL clockwise
    Returns flat indices in row-major order.
    """
    total = n_rows * n_cols
    visited = [[False] * n_cols for _ in range(n_rows)]
    order = []

    # Direction vectors for clockwise spiral from each corner
    if start_corner == 0:  # TL: right, down, left, up
        dr = [0, 1, 0, -1]
        dc = [1, 0, -1, 0]
        r, c = 0, 0
    elif start_corner == 1:  # TR: down, left, up, right
        dr = [1, 0, -1, 0]
        dc = [0, -1, 0, 1]
        r, c = 0, n_cols - 1
    elif start_corner == 2:  # BR: left, up, right, down
        dr = [0, -1, 0, 1]
        dc = [-1, 0, 1, 0]
        r, c = n_rows - 1, n_cols - 1
    else:  # BL: up, right, down, left
        dr = [-1, 0, 1, 0]
        dc = [0, 1, 0, -1]
        r, c = n_rows - 1, 0

    d = 0
    for _ in range(total):
        idx = r * n_cols + c
        order.append(idx)
        visited[r][c] = True
        nr, nc = r + dr[d], c + dc[d]
        if 0 <= nr < n_rows and 0 <= nc < n_cols and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            r, c = r + dr[d], c + dc[d]

    return order


def _diagonal_order(n_rows: int, n_cols: int, direction: str) -> List[int]:
    """Read grid diagonally."""
    order = []
    if direction == "tl_br":
        for diag in range(n_rows + n_cols - 1):
            for r in range(max(0, diag - n_cols + 1), min(n_rows, diag + 1)):
                c = diag - r
                if c < n_cols:
                    order.append(r * n_cols + c)
    else:  # tr_bl
        for diag in range(n_rows + n_cols - 1):
            for r in range(max(0, diag - n_cols + 1), min(n_rows, diag + 1)):
                c = (n_cols - 1) - (diag - r)
                if 0 <= c < n_cols:
                    order.append(r * n_cols + c)
    return order


def gen_double_rotation() -> Tuple[str, List[int]]:
    """K3-style double rotation on 97 chars.
    First rotation: write into grid1 (r1 × c1) by rows, read by columns.
    Second rotation: write into grid2 (r2 × c2) by rows, read by columns.

    Try various dimension pairs where r1*c1 >= 97 and r2*c2 >= 97.
    """
    dim_pairs = []
    for n_cols in range(4, 25):
        n_rows = math.ceil(CT_LEN / n_cols)
        dim_pairs.append((n_rows, n_cols))

    for r1, c1 in dim_pairs:
        perm1 = _rotation_perm(CT_LEN, r1, c1)
        if perm1 is None:
            continue
        for r2, c2 in dim_pairs:
            perm2 = _rotation_perm(CT_LEN, r2, c2)
            if perm2 is None:
                continue

            # Combined permutation: first perm1, then perm2
            combined = [perm2[perm1[i]] for i in range(CT_LEN)]

            yield f"double_rot({r1}x{c1},{r2}x{c2})", combined


def _rotation_perm(length: int, n_rows: int, n_cols: int) -> Optional[List[int]]:
    """Compute permutation for: write by rows into (n_rows × n_cols), read by columns.
    Returns perm where perm[i] = j means input position i maps to output position j.
    Returns None if dimensions don't work.
    """
    total = n_rows * n_cols
    if total < length:
        return None

    # Write by rows: position i goes to row i//n_cols, col i%n_cols
    # Read by columns: col c, row r → output position = sum of col_lengths[:c] + r
    # For a grid with possible short columns:
    short_cols = total - length

    col_lengths = []
    for col in range(n_cols):
        if col >= n_cols - short_cols:
            col_lengths.append(n_rows - 1)
        else:
            col_lengths.append(n_rows)

    # Column start positions in output
    col_starts = [0] * n_cols
    for c in range(1, n_cols):
        col_starts[c] = col_starts[c - 1] + col_lengths[c - 1]

    perm = [0] * length
    for i in range(length):
        row = i // n_cols
        col = i % n_cols
        if row < col_lengths[col]:
            perm[i] = col_starts[col] + row
        else:
            return None  # shouldn't happen

    if sorted(perm) != list(range(length)):
        return None

    return perm


def gen_myszkowski(max_width: int = 12) -> Tuple[str, List[int]]:
    """Myszkowski transposition: like columnar but columns with same key letter
    are read left-to-right across the row before moving to the next row.

    Uses thematic keywords.
    """
    thematic = []
    try:
        with open("wordlists/thematic_keywords.txt") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    word = line.upper()
                    if word.isalpha() and 3 <= len(word) <= max_width:
                        thematic.append(word)
    except FileNotFoundError:
        pass

    # Also add some manually
    thematic.extend(["KRYPTOS", "KOMPASS", "ABSCISSA", "DEFECTOR", "COLOPHON",
                      "BERLIN", "CLOCK", "POINT", "SHADOW", "ENIGMA",
                      "COMPASS", "SANBORN", "SCHEIDT", "FIVE", "LUCID",
                      "PALIMPSEST", "QUAGMIRE", "VERDIGRIS"])
    thematic = list(set(thematic))

    seen_keys = set()

    for keyword in thematic:
        width = len(keyword)
        if width < 3 or width > max_width:
            continue

        # Check if keyword has repeated letters (Myszkowski differs from columnar only then)
        if len(set(keyword)) == width:
            continue  # No repeats — same as regular columnar

        # Build the Myszkowski key numbering
        # Each letter gets a rank; ties share the same rank
        sorted_chars = sorted(set(keyword))
        char_rank = {c: i for i, c in enumerate(sorted_chars)}
        key_ranks = [char_rank[c] for c in keyword]

        key_tuple = tuple(key_ranks)
        if key_tuple in seen_keys:
            continue
        seen_keys.add(key_tuple)

        n_rows = math.ceil(CT_LEN / width)

        # Build the read order:
        # For each rank (lowest first), read all columns with that rank
        # For tied columns, read across the row before moving to next row
        output = []
        for rank in sorted(set(key_ranks)):
            tied_cols = [c for c in range(width) if key_ranks[c] == rank]
            if len(tied_cols) == 1:
                # Single column: read down
                col = tied_cols[0]
                for row in range(n_rows):
                    idx = row * width + col
                    if idx < CT_LEN:
                        output.append(idx)
            else:
                # Tied columns: read across each row
                for row in range(n_rows):
                    for col in tied_cols:
                        idx = row * width + col
                        if idx < CT_LEN:
                            output.append(idx)

        if len(output) != CT_LEN:
            continue

        # output[out_pos] = input_pos (this is the read order)
        # We need perm[input_pos] = output_pos
        perm = [0] * CT_LEN
        for out_pos, in_pos in enumerate(output):
            perm[in_pos] = out_pos

        if sorted(perm) == list(range(CT_LEN)):
            yield f"myszkowski(kw={keyword})", perm


def gen_reversed_variants(base_gen):
    """Apply reversal before a transposition: reverse CT first, then apply transposition.
    This is equivalent to composing reversal with the transposition.
    """
    rev = list(range(CT_LEN - 1, -1, -1))  # reversal permutation
    for desc, perm in base_gen:
        # Combined: first reverse, then apply perm
        # combined[i] = perm[rev[i]]
        combined = [perm[rev[i]] for i in range(CT_LEN)]
        yield f"rev+{desc}", combined


# ── Main attack ────────────────────────────────────────────────────────────

def attack():
    print("=" * 80)
    print("MEET-IN-THE-MIDDLE: MONO SUBSTITUTION × STRUCTURED TRANSPOSITIONS")
    print("Model: PT → Transposition T → Intermediate → Mono Sub S → CT")
    print("Filter: CT[T(i)] = S(PT[i]) — same PT letter must map to same CT letter")
    print("=" * 80)
    print(f"\nCT: {CT}")
    print(f"Length: {CT_LEN}")
    print(f"Cribs: {N_CRIBS} positions known")
    print()

    print_crib_analysis()

    # Load quadgrams
    qg = load_quadgrams()
    if qg:
        print(f"Loaded {len(qg):,} quadgrams for scoring\n")
    else:
        print("No quadgrams loaded — will use IC scoring only\n")

    # Results tracking
    mono_hits: List[Tuple[float, str, str, Dict[str, str], str]] = []
    # (qg_score, description, plaintext, sub_map, family)
    vig_hits: List[Tuple[int, str, str]] = []
    # (period, variant, description)

    total_tested = 0
    total_mono_consistent = 0
    family_stats: Dict[str, Tuple[int, int, float]] = {}  # family → (tested, hits, best_qg)
    t_global_start = time.time()

    def process_generator(gen_name: str, generator, report_interval: int = 10000):
        """Process a transposition generator through the MITM filter."""
        nonlocal total_tested, total_mono_consistent

        t_start = time.time()
        tested = 0
        hits = 0
        best_qg = -15.0
        best_desc = ""

        for desc, perm in generator:
            tested += 1
            total_tested += 1

            # Fast validation: check permutation is valid
            # (skip for performance — generators should produce valid perms)

            # MITM FILTER: mono-consistency check
            sub_map = check_mono_consistency(perm)

            if sub_map is not None:
                hits += 1
                total_mono_consistent += 1

                # Derive full plaintext
                pt = derive_full_plaintext(perm, sub_map)

                # Score
                qg_s = score_quadgrams(pt, qg) if qg else -15.0
                ic_val = score_ic(pt)

                if qg_s > best_qg:
                    best_qg = qg_s
                    best_desc = desc

                mono_hits.append((qg_s, desc, pt, sub_map, gen_name))

                # Print the hit
                n_known = sum(1 for c in pt if c != '?')
                sub_str = " ".join(f"{k}→{v}" for k, v in sorted(sub_map.items()))
                print(f"\n  *** MONO-CONSISTENT HIT #{total_mono_consistent} ***")
                print(f"  Transposition: {desc}")
                print(f"  Sub map ({len(sub_map)} pairs): {sub_str}")
                print(f"  PT ({n_known}/{CT_LEN} known): {pt}")
                print(f"  Quadgram: {qg_s:+.4f}  IC: {ic_val:.4f}")

                # Verify cribs are correct in plaintext
                crib_ok = True
                for pos in CRIB_POS_LIST:
                    if pt[pos] != CRIB_DICT[pos]:
                        crib_ok = False
                        print(f"  WARNING: Crib mismatch at pos {pos}: got '{pt[pos]}', expected '{CRIB_DICT[pos]}'")
                if crib_ok:
                    print(f"  Crib verification: PASS (all 24 positions correct)")

                # Bonus: check periodic Vigenere on transposed text
                vig_results = check_periodic_vig_on_transposed(perm)
                if vig_results:
                    for period, var, n_cons, vig_desc in vig_results:
                        print(f"  ** PERIODIC VIG HIT: {var} p={period} {vig_desc}")
                        vig_hits.append((period, var, f"{desc} → {vig_desc}"))

                sys.stdout.flush()

            # Progress reporting
            if tested % report_interval == 0:
                elapsed = time.time() - t_start
                rate = tested / elapsed if elapsed > 0 else 0
                print(f"  [{gen_name}] {tested:>10,} tested | {hits} hits | "
                      f"{elapsed:.1f}s ({rate:,.0f}/s)", flush=True)

        elapsed = time.time() - t_start
        rate = tested / elapsed if elapsed > 0 else 0
        print(f"  [{gen_name}] DONE: {tested:>10,} tested | {hits} hits | "
              f"best_qg={best_qg:+.4f} | {elapsed:.1f}s ({rate:,.0f}/s)")
        if best_desc and hits > 0:
            print(f"    Best: {best_desc}")
        sys.stdout.flush()

        family_stats[gen_name] = (tested, hits, best_qg)

    # ── Phase 0: Identity (pure monoalphabetic) ──────────────────────────
    print("\n--- Phase 0: Identity (pure monoalphabetic, no transposition) ---")
    process_generator("identity", gen_identity(), report_interval=1)

    # ── Phase 1: Simple reversal ─────────────────────────────────────────
    print("\n--- Phase 1: Simple reversal ---")
    process_generator("reversal", gen_reversal(), report_interval=1)

    # ── Phase 2: Stride / Decimation ─────────────────────────────────────
    print("\n--- Phase 2: Stride / Decimation (d=2..96, all starts) ---")
    process_generator("stride", gen_stride_decimation(), report_interval=10000)

    # ── Phase 3: Rail Fence ──────────────────────────────────────────────
    print("\n--- Phase 3: Rail Fence (2..30 rails) ---")
    process_generator("railfence", gen_rail_fence(), report_interval=10)

    # ── Phase 4: Columnar exhaustive (widths 2-8) ────────────────────────
    print("\n--- Phase 4: Columnar transposition exhaustive (widths 2-8) ---")
    process_generator("columnar_exh", gen_columnar_exhaustive(max_width=8), report_interval=10000)

    # ── Phase 5: Reverse columnar exhaustive (widths 2-7) ────────────────
    print("\n--- Phase 5: Reverse columnar exhaustive (widths 2-7) ---")
    process_generator("rev_columnar", gen_reverse_columnar_exhaustive(max_width=7), report_interval=10000)

    # ── Phase 6: Columnar width 9-10 exhaustive ──────────────────────────
    print("\n--- Phase 6: Columnar width 9-10 exhaustive ---")
    # Width 9: 362,880 perms. Width 10: 3,628,800 perms.
    # These are large but the mono-consistency filter is O(24) per check.
    for w in [9, 10]:
        print(f"  Starting width {w} ({math.factorial(w):,} permutations)...")
        gen = gen_columnar_exhaustive(max_width=w)
        # Skip widths already done in phase 4
        filtered = ((d, p) for d, p in gen if f"w={w}," in d)
        process_generator(f"columnar_w{w}", filtered, report_interval=100000)

    # ── Phase 7: Columnar keyword (widths 11-20) ─────────────────────────
    print("\n--- Phase 7: Columnar keyword-derived (widths 11-20) ---")
    process_generator("columnar_kw", gen_columnar_keyword(11, 20), report_interval=10000)

    # ── Phase 8: Route ciphers ───────────────────────────────────────────
    print("\n--- Phase 8: Route ciphers (spiral, snake, diagonal) ---")
    process_generator("route", gen_route_ciphers(), report_interval=100)

    # ── Phase 9: Double rotation (K3-style) ──────────────────────────────
    print("\n--- Phase 9: Double rotation (K3-style) ---")
    process_generator("double_rot", gen_double_rotation(), report_interval=10000)

    # ── Phase 10: Myszkowski transposition ───────────────────────────────
    print("\n--- Phase 10: Myszkowski transposition ---")
    process_generator("myszkowski", gen_myszkowski(max_width=12), report_interval=100)

    # ── Phase 11: Reversed CT + columnar (widths 2-8) ────────────────────
    print("\n--- Phase 11: Reversed CT + columnar (widths 2-8) ---")
    process_generator("rev+columnar",
                      gen_reversed_variants(gen_columnar_exhaustive(max_width=8)),
                      report_interval=10000)

    # ── Phase 12: Reversed CT + stride ───────────────────────────────────
    print("\n--- Phase 12: Reversed CT + stride ---")
    process_generator("rev+stride",
                      gen_reversed_variants(gen_stride_decimation()),
                      report_interval=10000)

    # ── Phase 13: Reversed CT + rail fence ───────────────────────────────
    print("\n--- Phase 13: Reversed CT + rail fence ---")
    process_generator("rev+railfence",
                      gen_reversed_variants(gen_rail_fence()),
                      report_interval=10)

    # ── Final Summary ────────────────────────────────────────────────────
    total_elapsed = time.time() - t_global_start

    print(f"\n{'=' * 80}")
    print(f"FINAL SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total transpositions tested:  {total_tested:>12,}")
    print(f"Mono-consistent hits:         {total_mono_consistent:>12,}")
    print(f"Hit rate:                     {total_mono_consistent/max(total_tested,1)*100:>11.6f}%")
    print(f"Periodic Vig bonus hits:      {len(vig_hits):>12,}")
    print(f"Total time:                   {total_elapsed:>11.1f}s")
    print()

    # Per-family stats
    print("PER-FAMILY BREAKDOWN:")
    print(f"  {'Family':<20s} {'Tested':>12s} {'Hits':>8s} {'Hit%':>10s} {'Best QG':>10s}")
    print(f"  {'-'*20} {'-'*12} {'-'*8} {'-'*10} {'-'*10}")
    for fam, (tested, hits, best) in sorted(family_stats.items()):
        pct = hits / max(tested, 1) * 100
        print(f"  {fam:<20s} {tested:>12,} {hits:>8,} {pct:>9.4f}% {best:>+10.4f}")
    print()

    # Sort all mono-consistent hits by quadgram score
    mono_hits.sort(key=lambda x: x[0], reverse=True)

    if mono_hits:
        n_show = min(50, len(mono_hits))
        print(f"TOP {n_show} MONO-CONSISTENT HITS (by quadgram score):")
        print("-" * 110)
        for rank, (qg_s, desc, pt, sub_map, family) in enumerate(mono_hits[:n_show], 1):
            n_known = sum(1 for c in pt if c != '?')
            sub_str = " ".join(f"{k}→{v}" for k, v in sorted(sub_map.items()))
            print(f"  #{rank:3d}  qg={qg_s:+.4f}  [{family}] {desc}")
            print(f"        PT ({n_known}/{CT_LEN}): {pt}")
            print(f"        Sub: {sub_str}")
        print()
    else:
        print("NO mono-consistent transpositions found across all families.\n")

    if vig_hits:
        print(f"PERIODIC VIGENERE BONUS HITS ({len(vig_hits)}):")
        for period, var, desc in vig_hits:
            print(f"  {var} p={period}: {desc}")
        print()

    # Output the sub maps for any hits to allow further analysis
    if mono_hits:
        print("SUBSTITUTION MAP ANALYSIS (all hits):")
        ct_letters_used = set()
        pt_letters_mapped = set()
        for _, _, _, sub_map, _ in mono_hits:
            for pt_l, ct_l in sub_map.items():
                pt_letters_mapped.add(pt_l)
                ct_letters_used.add(ct_l)
        print(f"  PT letters in cribs: {sorted(pt_letters_mapped)}")
        print(f"  CT letters used across all hits: {sorted(ct_letters_used)}")
        unmapped_pt = set(ALPH) - pt_letters_mapped
        unmapped_ct = set(ALPH) - ct_letters_used
        print(f"  Unmapped PT letters (not in cribs): {sorted(unmapped_pt)}")
        print(f"  Unused CT letters (never assigned across all hits): {sorted(unmapped_ct) if unmapped_ct else 'NONE (all used somewhere)'}")
        print()

    # Save results
    results_data = {
        "total_tested": total_tested,
        "mono_consistent": total_mono_consistent,
        "vig_bonus_hits": len(vig_hits),
        "elapsed_seconds": total_elapsed,
        "family_stats": {k: {"tested": v[0], "hits": v[1], "best_qg": v[2]}
                         for k, v in family_stats.items()},
        "hits": [
            {
                "qg_score": h[0],
                "description": h[1],
                "plaintext": h[2],
                "sub_map": h[3],
                "family": h[4],
            }
            for h in mono_hits[:200]
        ],
    }

    import os
    os.makedirs("results", exist_ok=True)
    out_path = "results/mitm_mono_transposition.json"
    try:
        with open(out_path, "w") as f:
            json.dump(results_data, f, indent=2)
        print(f"Results saved to {out_path}")
    except Exception as e:
        print(f"Warning: Could not save results: {e}")

    print(f"\n{'=' * 80}")
    print("DONE")
    print(f"{'=' * 80}")

    return mono_hits


if __name__ == "__main__":
    attack()
