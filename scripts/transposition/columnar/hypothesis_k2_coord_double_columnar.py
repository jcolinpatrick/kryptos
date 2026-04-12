#!/usr/bin/env python3
"""K2-coordinate-derived double columnar transposition hypothesis test.

Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation

HYPOTHESIS:
The K2 coordinates (38 57 6.5 N, 77 8 44 W) encode digits that serve as
column widths and permutation keys for a double columnar transposition.

Coordinate digits: 3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4  (sum = 68)
Ciphertext length: 97

Since 68 != 97, we need creative groupings that sum to 97.

APPROACH:
1. Generate all reasonable digit-grouping schemes from the coordinate string.
2. For each valid grouping (widths sum to 97):
   a. Construct columnar transposition grid
   b. Try permutations of column read-off order (pruned by crib constraints)
   c. Check for BERLINCLOCK and EASTNORTHEAST at known positions
3. Try double transposition with reversed/shifted sequences.
4. Track and report all results.

CRIBS (from canonical constants):
  - EASTNORTHEAST at plaintext positions 21-33
  - BERLINCLOCK at plaintext positions 63-73

Also tests user-stated positions:
  - BERLINCLOCK at position 26
  - EASTNORTHEAST at position 64
"""
from __future__ import annotations

import itertools
import json
import math
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS,
)
from kryptos.kernel.transforms.transposition import (
    invert_perm, apply_perm, validate_perm,
)

# ── Quadgrams ────────────────────────────────────────────────────────────
QUADGRAM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'data', 'english_quadgrams.json')
with open(QUADGRAM_PATH) as f:
    QUADGRAMS = json.load(f)
QUADGRAM_FLOOR = min(QUADGRAMS.values()) - 1.0

def qg_score(text: str) -> float:
    if len(text) < 4:
        return QUADGRAM_FLOOR
    total = sum(QUADGRAMS.get(text[i:i+4], QUADGRAM_FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)


# ── Letter frequency scoring ────────────────────────────────────────────
ENGLISH_FREQ = {
    'A': 0.0817, 'B': 0.0150, 'C': 0.0278, 'D': 0.0425, 'E': 0.1270,
    'F': 0.0223, 'G': 0.0202, 'H': 0.0609, 'I': 0.0697, 'J': 0.0015,
    'K': 0.0077, 'L': 0.0403, 'M': 0.0241, 'N': 0.0675, 'O': 0.0751,
    'P': 0.0193, 'Q': 0.0010, 'R': 0.0599, 'S': 0.0633, 'T': 0.0906,
    'U': 0.0276, 'V': 0.0098, 'W': 0.0236, 'X': 0.0015, 'Y': 0.0197,
    'Z': 0.0007,
}

def freq_score(text: str) -> float:
    """Chi-squared-like frequency score (lower = more English-like)."""
    if len(text) == 0:
        return 999.0
    counts = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    n = len(text)
    chi2 = 0.0
    for c in ALPH:
        expected = ENGLISH_FREQ.get(c, 0.038) * n
        observed = counts.get(c, 0)
        if expected > 0:
            chi2 += (observed - expected) ** 2 / expected
    return chi2


# ── Cribs ────────────────────────────────────────────────────────────────
# Canonical positions from the codebase
CANONICAL_CRIBS = {
    "EASTNORTHEAST": 21,  # positions 21-33
    "BERLINCLOCK": 63,    # positions 63-73
}

# User-stated positions
USER_CRIBS = {
    "BERLINCLOCK": 26,     # positions 26-36
    "EASTNORTHEAST": 64,   # positions 64-76
}

def check_cribs_at_positions(text: str, crib_dict: dict) -> int:
    """Check how many crib characters match at their specified positions."""
    matches = 0
    for word, start in crib_dict.items():
        for i, ch in enumerate(word):
            pos = start + i
            if pos < len(text) and text[pos] == ch:
                matches += 1
    return matches

def check_cribs_anywhere(text: str) -> List[Tuple[str, int]]:
    found = []
    for crib in ["EASTNORTHEAST", "BERLINCLOCK"]:
        idx = text.find(crib)
        while idx != -1:
            found.append((crib, idx))
            idx = text.find(crib, idx + 1)
    return found

def check_short_cribs(text: str) -> List[str]:
    shorts = ["EAST", "NORTH", "NORTHEAST", "BERLIN", "CLOCK",
              "SLOWLY", "DESPER", "ATELY"]
    return [s for s in shorts if s in text]

def check_canonical_cribs(text: str) -> int:
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(text) and text[pos] == ch)


# ── Columnar transposition primitives ────────────────────────────────────

def columnar_encrypt_with_widths(plaintext: str, col_widths: List[int], col_order: List[int]) -> str:
    """Irregular columnar transposition: columns have different widths.

    This is the key function for the hypothesis: column widths come from
    coordinate digits, and col_order is the permutation of columns.

    Encryption: write plaintext into a grid where each column has a
    specified width (height), then read columns in the given order.

    NOTE: For regular columnar, 'widths' means the grid has a fixed number
    of columns with a fixed row width. Here we model it differently:
    the total number of characters per column varies.
    """
    n = len(plaintext)
    assert sum(col_widths) == n, f"Column widths sum {sum(col_widths)} != text length {n}"
    num_cols = len(col_widths)

    # Assign characters to columns
    columns = []
    pos = 0
    for w in col_widths:
        columns.append(plaintext[pos:pos + w])
        pos += w

    # Read in column order
    result = []
    for col_idx in col_order:
        result.append(columns[col_idx])
    return "".join(result)


def columnar_decrypt_with_widths(ciphertext: str, col_widths: List[int], col_order: List[int]) -> str:
    """Decrypt irregular columnar transposition.

    During encryption: text was split into segments of col_widths sizes,
    then segments were rearranged by col_order.

    To decrypt: the ciphertext segments correspond to the columns in
    col_order sequence. We need to invert the order.
    """
    n = len(ciphertext)
    assert sum(col_widths) == n, f"Column widths sum {sum(col_widths)} != text length {n}"
    num_cols = len(col_widths)

    # The ciphertext was produced by reading columns in col_order.
    # So the first segment in CT has length col_widths[col_order[0]],
    # the second has length col_widths[col_order[1]], etc.

    # Extract segments from ciphertext
    segments = {}
    pos = 0
    for i, col_idx in enumerate(col_order):
        seg_len = col_widths[col_idx]
        segments[col_idx] = ciphertext[pos:pos + seg_len]
        pos += seg_len

    # Reconstruct plaintext by reading columns in original order
    return "".join(segments[i] for i in range(num_cols))


def regular_columnar_encrypt(plaintext: str, width: int, col_order: List[int]) -> str:
    """Regular columnar transposition with keyword column order.

    Write plaintext in rows of 'width', then read columns in col_order.
    """
    n = len(plaintext)
    nrows = math.ceil(n / width)
    num_full = n % width if n % width != 0 else width

    # Build columns
    columns = [[] for _ in range(width)]
    for i, ch in enumerate(plaintext):
        col = i % width
        columns[col].append(ch)

    # Read in order
    result = []
    for col_idx in col_order:
        result.extend(columns[col_idx])
    return "".join(result)


def regular_columnar_decrypt(ciphertext: str, width: int, col_order: List[int]) -> str:
    """Decrypt regular columnar transposition."""
    n = len(ciphertext)
    nrows = math.ceil(n / width)
    remainder = n % width

    # Column lengths
    if remainder == 0:
        col_lens = [nrows] * width
    else:
        col_lens = [nrows if c < remainder else nrows - 1 for c in range(width)]

    # Extract segments from CT in col_order sequence
    columns = {}
    pos = 0
    for col_idx in col_order:
        clen = col_lens[col_idx]
        columns[col_idx] = list(ciphertext[pos:pos + clen])
        pos += clen

    # Read rows
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(columns[c]):
                result.append(columns[c][r])
    return "".join(result)


# ── Digit grouping generation ────────────────────────────────────────────

def generate_digit_groupings(digits: List[int], target_sum: int) -> List[Tuple[List[int], str]]:
    """Generate all reasonable groupings of digits that sum to target_sum.

    The digits come from the K2 coordinates: 3,8,5,7,6,5,7,7,8,4,4

    Strategies:
    1. Use individual digits as-is (various subsets)
    2. Combine adjacent digit pairs (e.g., 38, 57, 65, ...)
    3. Mix single and paired digits
    4. Allow digit repetition from the coordinate string
    """
    digit_string = "".join(str(d) for d in digits)
    results = []
    seen = set()

    # Strategy 1: All possible ways to partition the digit string into numbers
    # The digit string is "38576577844"
    def partition_string(s: str, min_val: int = 1, max_val: int = 97) -> List[List[int]]:
        """All ways to split string s into numbers in [min_val, max_val]."""
        if not s:
            return [[]]
        partitions = []
        for i in range(1, len(s) + 1):
            head = int(s[:i])
            if head < min_val or head > max_val:
                if head > max_val:
                    break
                continue
            # Skip numbers with leading zeros (except 0 itself)
            if len(s[:i]) > 1 and s[0] == '0':
                continue
            for rest in partition_string(s[i:], min_val, max_val):
                partitions.append([head] + rest)
        return partitions

    print(f"  Generating partitions of digit string '{digit_string}'...")
    all_partitions = partition_string(digit_string, min_val=1, max_val=97)
    print(f"  Found {len(all_partitions)} total partitions of digit string")

    for parts in all_partitions:
        if sum(parts) == target_sum:
            key = tuple(parts)
            if key not in seen:
                seen.add(key)
                results.append((parts, f"partition({parts})"))

    print(f"  {len(results)} partitions sum to {target_sum}")

    # Strategy 2: Subsets of individual digits
    print(f"  Checking subsets of individual digits...")
    for r in range(1, len(digits) + 1):
        for combo in itertools.combinations(range(len(digits)), r):
            subset = [digits[i] for i in combo]
            if sum(subset) == target_sum:
                key = tuple(sorted(subset))
                desc = f"subset({subset}, indices={combo})"
                if key not in seen:
                    seen.add(key)
                    results.append((subset, desc))

    # Strategy 3: Use all 11 digits but combine some pairs to reach 97
    # Sum of individual digits = 68, need 29 more
    # Combining adjacent pair ab -> 10a+b adds 9*a to the sum
    # So we need combinations where 9*(sum of tens-place digits) = 29
    # 29/9 is not integer, so no simple adjacent-pair combination works
    # But multi-digit numbers add different amounts
    print(f"  Individual digits sum to {sum(digits)}, need {target_sum - sum(digits)} more")

    # Strategy 4: Repeat certain digits (the coordinate repeats some digits)
    # Add extra digits to reach 97
    extra_needed = target_sum - sum(digits)  # 97 - 68 = 29
    print(f"  Extra needed: {extra_needed}")

    # Try adding digits from the coordinate as column widths
    for r in range(1, 6):
        for combo in itertools.combinations_with_replacement(digits, r):
            if sum(combo) == extra_needed:
                extended = digits + list(combo)
                key = tuple(sorted(extended))
                if key not in seen:
                    seen.add(key)
                    desc = f"all_digits+extra({list(combo)})"
                    results.append((extended, desc))

    # Strategy 5: Use the coordinate numbers as-is in various forms
    # 38, 57, 6.5 -> could be 38, 57, 6, 5 or 38, 57, 65
    # 77, 8, 44 -> could be 7, 7, 8, 44 or 77, 8, 4, 4
    coord_interpretations = [
        # Latitude: 38°57'6.5" -> various groupings
        # Longitude: 77°8'44" -> various groupings
        ([38, 57, 6, 5, 77, 8, 44], "coords_natural(38,57,6,5,77,8,44)"),
        ([38, 57, 65, 77, 844], "coords_merged(38,57,65,77,844)"),
        ([38, 57, 65, 77, 8, 44], "coords_merged2(38,57,65,77,8,44)"),
        ([38, 57, 65, 7, 7, 8, 44], "coords_lat_merged(38,57,65,7,7,8,44)"),
        ([3, 8, 57, 65, 77, 8, 44], "coords_split(3,8,57,65,77,8,44)"),
        ([38, 5, 7, 6, 5, 77, 8, 44], "coords_split2(38,5,7,6,5,77,8,44)"),
        ([38, 57, 6, 5, 7, 7, 8, 44], "coords_split3(38,57,6,5,7,7,8,44)"),
        ([38, 57, 6, 5, 7, 78, 44], "coords_split4(38,57,6,5,7,78,44)"),
        ([3, 85, 7, 6, 5, 77, 8, 44], "coords_alt(3,85,7,6,5,77,8,44)"),
        # Just the degree values
        ([38, 77], "degrees(38,77)"),
        ([38, 57, 77, 8], "deg_min(38,57,77,8)"),
        # Sum-adjusted combinations
        ([38, 57, 2], "lat(38,57)+2"),  # sum = 97
        ([77, 8, 12], "lon(77,8)+12"),  # sum = 97
    ]

    for nums, desc in coord_interpretations:
        if sum(nums) == target_sum:
            key = tuple(nums)
            if key not in seen:
                seen.add(key)
                results.append((nums, desc))

    return results


# ── Crib-constrained permutation search ──────────────────────────────────

def find_crib_column(col_widths: List[int], crib_start: int, crib_len: int) -> Optional[Tuple[List[int], List[int]]]:
    """Given column widths and a crib position, find which columns the crib spans.

    Returns (column_indices, offsets_within_columns) or None if impossible.
    """
    # Build cumulative positions
    cum = [0]
    for w in col_widths:
        cum.append(cum[-1] + w)

    # Find which columns the crib characters fall in
    cols_involved = []
    offsets = []
    for i in range(crib_len):
        pos = crib_start + i
        # Find which column this position falls in
        for c in range(len(col_widths)):
            if cum[c] <= pos < cum[c + 1]:
                cols_involved.append(c)
                offsets.append(pos - cum[c])
                break

    return cols_involved, offsets


def compute_column_position_mapping(col_widths: List[int], col_order: List[int]) -> List[int]:
    """Compute the full permutation mapping for a columnar transposition.

    After decryption: plaintext[i] comes from position perm[i] in the ciphertext.
    """
    n = sum(col_widths)
    num_cols = len(col_widths)

    # Build column start positions in plaintext
    pt_starts = [0]
    for w in col_widths:
        pt_starts.append(pt_starts[-1] + w)

    # Build column positions in ciphertext (after reordering by col_order)
    ct_starts = {}
    pos = 0
    for col_idx in col_order:
        ct_starts[col_idx] = pos
        pos += col_widths[col_idx]

    # Build permutation: for each plaintext position, where does it come from in CT
    perm = [0] * n
    for col in range(num_cols):
        for offset in range(col_widths[col]):
            pt_pos = pt_starts[col] + offset
            ct_pos = ct_starts[col] + offset
            perm[pt_pos] = ct_pos

    return perm


def prune_permutations_by_crib(col_widths: List[int], crib_word: str, crib_start: int, ciphertext: str) -> Set[Tuple[int, ...]]:
    """Given a crib at a known plaintext position, determine constraints on column order.

    Returns a set of valid column orderings (as tuples), or None if no pruning possible.
    """
    num_cols = len(col_widths)
    n = sum(col_widths)
    crib_len = len(crib_word)

    # Find which columns the crib spans in plaintext
    cols_offsets = find_crib_column(col_widths, crib_start, crib_len)
    if cols_offsets is None:
        return None

    crib_cols, crib_offsets = cols_offsets

    # For each crib character at position (col, offset):
    # After decryption, that position must contain the crib character.
    # In the ciphertext, the column 'col' data appears at a position
    # determined by col_order. The crib constrains where each column
    # must be placed.

    # This is complex for general case; return None to indicate no pruning
    return None


# ── Main search ──────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    print("=" * 78)
    print("K2 COORDINATE DOUBLE COLUMNAR TRANSPOSITION HYPOTHESIS TEST")
    print("=" * 78)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Coordinate digits: 3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4  (sum = 68)")
    print(f"Target sum: {CT_LEN}")
    print()

    # Canonical crib positions
    print("Canonical crib positions (from codebase):")
    for word, start in CANONICAL_CRIBS.items():
        print(f"  {word} at position {start} (chars {start}-{start+len(word)-1})")
    print("User-stated crib positions:")
    for word, start in USER_CRIBS.items():
        print(f"  {word} at position {start} (chars {start}-{start+len(word)-1})")
    print()

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: Generate all digit grouping schemes
    # ═══════════════════════════════════════════════════════════════════
    print("=" * 78)
    print("PHASE 1: Generating digit grouping schemes")
    print("=" * 78)

    raw_digits = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

    groupings = generate_digit_groupings(raw_digits, CT_LEN)

    print(f"\nTotal valid grouping schemes (sum = {CT_LEN}): {len(groupings)}")
    for i, (widths, desc) in enumerate(groupings):
        print(f"  [{i+1}] {desc}: widths={widths}, sum={sum(widths)}, ncols={len(widths)}")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: Single columnar transposition with each grouping
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 78)
    print("PHASE 2: Single columnar transposition (irregular column widths)")
    print("=" * 78)

    total_tested = 0
    best_qg = -999.0
    best_canonical = 0
    best_user_cribs = 0
    crib_hits = []
    interesting = []

    MAX_PERM_SIZE = 10  # factorial(10) = 3.6M, too much. Use 8 = 40320
    MAX_PERMS = 40320   # 8!

    for gi, (widths, desc) in enumerate(groupings):
        ncols = len(widths)
        n_perms = math.factorial(ncols)

        # Determine if we can enumerate all permutations
        if n_perms <= MAX_PERMS:
            perms_to_try = list(itertools.permutations(range(ncols)))
            sampled = False
        else:
            # Sample: try identity, reverse, and random-ish permutations
            # Also try permutations derived from the coordinate digits
            perms_to_try = []

            # Identity and reverse
            perms_to_try.append(tuple(range(ncols)))
            perms_to_try.append(tuple(range(ncols - 1, -1, -1)))

            # Coordinate-digit-derived orderings
            # Use the raw digits to determine column order
            if ncols <= len(raw_digits):
                # Take first ncols digits, rank them to get an ordering
                subset = raw_digits[:ncols]
                ranked = sorted(range(ncols), key=lambda i: (subset[i], i))
                perms_to_try.append(tuple(ranked))
                # Also reverse ranking
                perms_to_try.append(tuple(ranked[::-1]))

            # Cyclic shifts
            for shift in range(ncols):
                perms_to_try.append(tuple((i + shift) % ncols for i in range(ncols)))

            # Sort by digit value
            digit_order = sorted(range(ncols), key=lambda i: widths[i])
            perms_to_try.append(tuple(digit_order))
            perms_to_try.append(tuple(digit_order[::-1]))

            # Dedup
            perms_to_try = list(set(perms_to_try))
            sampled = True

        for perm in perms_to_try:
            col_order = list(perm)
            try:
                pt = columnar_decrypt_with_widths(CT, widths, col_order)
            except Exception:
                continue

            total_tested += 1
            qg = qg_score(pt)
            canon = check_canonical_cribs(pt)
            user_match = check_cribs_at_positions(pt, USER_CRIBS)
            cribs_at = check_cribs_anywhere(pt)

            if qg > best_qg:
                best_qg = qg
            if canon > best_canonical:
                best_canonical = canon
            if user_match > best_user_cribs:
                best_user_cribs = user_match

            if cribs_at:
                entry = {
                    "desc": f"single/{desc}/order={col_order}",
                    "text": pt,
                    "cribs": cribs_at,
                    "qg": qg,
                    "canon": canon,
                    "user_match": user_match,
                }
                crib_hits.append(entry)
                print(f"\n*** CRIB HIT *** {entry['desc']}")
                print(f"    Text: {pt}")
                print(f"    Cribs: {cribs_at}, QG: {qg:.4f}")

            if canon >= 10 or user_match >= 10:
                entry = {
                    "desc": f"single/{desc}/order={col_order}",
                    "text": pt,
                    "qg": qg,
                    "canon": canon,
                    "user_match": user_match,
                }
                interesting.append(entry)
                print(f"  HIGH CANON: {entry['desc']} canon={canon}/24 user={user_match}/24 QG={qg:.4f}")

            if qg > -6.0:
                short = check_short_cribs(pt)
                if short:
                    entry = {
                        "desc": f"single/{desc}/order={col_order}",
                        "text": pt,
                        "qg": qg,
                        "canon": canon,
                        "user_match": user_match,
                        "short_cribs": short,
                    }
                    interesting.append(entry)
                    print(f"  INTERESTING: {entry['desc']} QG={qg:.4f} words={short}")

        if (gi + 1) % 10 == 0 or gi == len(groupings) - 1:
            print(f"  Grouping {gi+1}/{len(groupings)}: tested={total_tested}, best_qg={best_qg:.4f}, best_canon={best_canonical}")

    phase2_tested = total_tested
    print(f"\nPhase 2 complete: {phase2_tested} tested, best QG={best_qg:.4f}, best canon={best_canonical}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3: Regular columnar transposition using coordinate-derived widths
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 78)
    print("PHASE 3: Regular columnar with coordinate-derived grid widths")
    print("=" * 78)

    # The coordinate digits might specify the grid width for regular columnar
    # Try all individual digits and multi-digit numbers from the coordinates
    coord_widths = [3, 4, 5, 6, 7, 8, 38, 57, 65, 77, 44, 84, 85, 76]

    # Also try sums and products
    coord_widths.extend([
        3 + 8,       # 11
        5 + 7,       # 12
        6 + 5,       # 11 (dup)
        7 + 7,       # 14
        8 + 4,       # 12 (dup)
        4 + 4,       # 8 (dup)
        3 + 8 + 5,   # 16
        7 + 6 + 5,   # 18
        3 * 8,       # 24
        5 * 7,       # 35
    ])
    coord_widths = sorted(set(w for w in coord_widths if 2 <= w <= 48))

    print(f"  Testing regular columnar with widths: {coord_widths}")

    for width in coord_widths:
        ncols = width
        nrows = math.ceil(CT_LEN / width)

        # Generate column orders from coordinate digits
        # Use subsets of raw_digits as column order keys
        col_orders_to_try = []

        # Identity and reverse
        col_orders_to_try.append(list(range(width)))
        col_orders_to_try.append(list(range(width - 1, -1, -1)))

        # Use coordinate digits to derive column order
        if width <= len(raw_digits):
            subset = raw_digits[:width]
            ranked = sorted(range(width), key=lambda i: (subset[i], i))
            col_orders_to_try.append(ranked)
            col_orders_to_try.append(ranked[::-1])

        # For small widths, try all permutations
        if math.factorial(width) <= MAX_PERMS:
            col_orders_to_try = [list(p) for p in itertools.permutations(range(width))]

        # Dedup
        seen_orders = set()
        unique_orders = []
        for order in col_orders_to_try:
            key = tuple(order)
            if key not in seen_orders:
                seen_orders.add(key)
                unique_orders.append(order)

        for col_order in unique_orders:
            try:
                pt = regular_columnar_decrypt(CT, width, col_order)
            except Exception:
                continue

            total_tested += 1
            qg = qg_score(pt)
            canon = check_canonical_cribs(pt)
            user_match = check_cribs_at_positions(pt, USER_CRIBS)
            cribs_at = check_cribs_anywhere(pt)

            if qg > best_qg:
                best_qg = qg
            if canon > best_canonical:
                best_canonical = canon
            if user_match > best_user_cribs:
                best_user_cribs = user_match

            if cribs_at:
                entry = {
                    "desc": f"regular_col/w={width}/order={col_order}",
                    "text": pt,
                    "cribs": cribs_at,
                    "qg": qg,
                    "canon": canon,
                    "user_match": user_match,
                }
                crib_hits.append(entry)
                print(f"\n*** CRIB HIT *** {entry['desc']}")
                print(f"    Text: {pt}")
                print(f"    Cribs: {cribs_at}")

            if canon >= 10 or user_match >= 10 or qg > -5.5:
                interesting.append({
                    "desc": f"regular_col/w={width}/order={col_order}",
                    "text": pt,
                    "qg": qg,
                    "canon": canon,
                    "user_match": user_match,
                })

    phase3_tested = total_tested - phase2_tested
    print(f"\nPhase 3 complete: {phase3_tested} new tests, total={total_tested}")
    print(f"  Best QG so far: {best_qg:.4f}, best canon: {best_canonical}/24")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 4: Double columnar transposition
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 78)
    print("PHASE 4: Double columnar transposition (coordinate-derived widths)")
    print("=" * 78)

    # For double columnar: use coordinate digits for both passes
    # First pass width from latitude digits, second from longitude digits
    lat_digits = [3, 8, 5, 7, 6, 5]   # 38°57'6.5"
    lon_digits = [7, 7, 8, 4, 4]       # 77°8'44"

    double_col_configs = [
        # (width1, width2, description)
        (38, 57, "lat_deg x lat_min"),
        (57, 38, "lat_min x lat_deg"),
        (77, 8, "lon_deg x lon_min"),
        (8, 77, "lon_min x lon_deg"),
        (38, 77, "lat_deg x lon_deg"),
        (77, 38, "lon_deg x lat_deg"),
        (57, 44, "lat_min x lon_sec"),
        (44, 57, "lon_sec x lat_min"),
        (65, 77, "lat_sec x lon_deg"),
        (77, 65, "lon_deg x lat_sec"),
        (7, 8, "digit7 x digit8"),
        (8, 7, "digit8 x digit7"),
        # From individual coordinate digits
        (3, 8, "d3 x d8"),
        (5, 7, "d5 x d7"),
        (4, 4, "d4 x d4"),
        (7, 7, "d7 x d7"),
        (6, 5, "d6 x d5"),
        # Factors of 97
        (97, 1, "97 x 1"),
        (1, 97, "1 x 97"),
        # Multiples of 7 (Kryptos connection)
        (7, 14, "7 x 14"),
        (14, 7, "14 x 7"),
    ]

    # Also add all small width pairs
    for w1 in range(3, 20):
        for w2 in range(3, 20):
            double_col_configs.append((w1, w2, f"w{w1} x w{w2}"))

    # Add coordinate-related widths
    for w1 in [3, 4, 5, 6, 7, 8, 11, 14, 24, 35, 38, 44, 57, 65, 77]:
        for w2 in [3, 4, 5, 6, 7, 8, 11, 14, 24, 35, 38, 44, 57, 65, 77]:
            if (w1, w2, f"w{w1} x w{w2}") not in double_col_configs:
                double_col_configs.append((w1, w2, f"coord_w{w1} x coord_w{w2}"))

    # Dedup
    seen_configs = set()
    unique_configs = []
    for w1, w2, desc in double_col_configs:
        if w1 < 1 or w2 < 1 or w1 > CT_LEN or w2 > CT_LEN:
            continue
        key = (w1, w2)
        if key not in seen_configs:
            seen_configs.add(key)
            unique_configs.append((w1, w2, desc))

    print(f"  Testing {len(unique_configs)} double columnar width pairs")

    phase4_start = total_tested

    for ci, (w1, w2, desc) in enumerate(unique_configs):
        # For each width pair, try various column orderings
        for direction1 in ["ltr", "rtl"]:
            for direction2 in ["ltr", "rtl"]:
                # LTR = identity column order, RTL = reversed
                if direction1 == "ltr":
                    order1 = list(range(w1))
                else:
                    order1 = list(range(w1 - 1, -1, -1))

                if direction2 == "ltr":
                    order2 = list(range(w2))
                else:
                    order2 = list(range(w2 - 1, -1, -1))

                try:
                    # Decrypt: undo pass 2, then undo pass 1
                    intermediate = regular_columnar_decrypt(CT, w2, order2)
                    pt = regular_columnar_decrypt(intermediate, w1, order1)
                except Exception:
                    continue

                total_tested += 1
                qg = qg_score(pt)
                canon = check_canonical_cribs(pt)
                user_match = check_cribs_at_positions(pt, USER_CRIBS)
                cribs_at = check_cribs_anywhere(pt)

                if qg > best_qg:
                    best_qg = qg
                if canon > best_canonical:
                    best_canonical = canon
                if user_match > best_user_cribs:
                    best_user_cribs = user_match

                if cribs_at:
                    entry = {
                        "desc": f"double_col/{desc}/{direction1}+{direction2}",
                        "text": pt,
                        "cribs": cribs_at,
                        "qg": qg,
                        "canon": canon,
                        "user_match": user_match,
                    }
                    crib_hits.append(entry)
                    print(f"\n*** CRIB HIT *** {entry['desc']}")
                    print(f"    Text: {pt}")
                    print(f"    Cribs: {cribs_at}")

                if canon >= 10 or user_match >= 10:
                    interesting.append({
                        "desc": f"double_col/{desc}/{direction1}+{direction2}",
                        "text": pt,
                        "qg": qg,
                        "canon": canon,
                        "user_match": user_match,
                    })

        # Also try keyword-derived column orders for small widths
        if w1 <= 8 and w2 <= 8:
            for p1 in itertools.permutations(range(w1)):
                for p2 in itertools.permutations(range(w2)):
                    try:
                        intermediate = regular_columnar_decrypt(CT, w2, list(p2))
                        pt = regular_columnar_decrypt(intermediate, w1, list(p1))
                    except Exception:
                        continue

                    total_tested += 1
                    qg = qg_score(pt)
                    canon = check_canonical_cribs(pt)
                    user_match = check_cribs_at_positions(pt, USER_CRIBS)
                    cribs_at = check_cribs_anywhere(pt)

                    if qg > best_qg:
                        best_qg = qg
                    if canon > best_canonical:
                        best_canonical = canon
                    if user_match > best_user_cribs:
                        best_user_cribs = user_match

                    if cribs_at:
                        entry = {
                            "desc": f"double_col/{desc}/p1={list(p1)}/p2={list(p2)}",
                            "text": pt,
                            "cribs": cribs_at,
                            "qg": qg,
                            "canon": canon,
                            "user_match": user_match,
                        }
                        crib_hits.append(entry)
                        print(f"\n*** CRIB HIT *** {entry['desc']}")
                        print(f"    Text: {pt}")
                        print(f"    Cribs: {cribs_at}")

                    if canon >= 10 or user_match >= 10 or qg > -5.0:
                        interesting.append({
                            "desc": f"double_col/{desc}/p1={list(p1)}/p2={list(p2)}",
                            "text": pt,
                            "qg": qg,
                            "canon": canon,
                            "user_match": user_match,
                        })

        if (ci + 1) % 50 == 0:
            elapsed = time.time() - t0
            print(f"  Config {ci+1}/{len(unique_configs)}: tested={total_tested}, "
                  f"best_qg={best_qg:.4f}, best_canon={best_canonical}, "
                  f"elapsed={elapsed:.1f}s")

    phase4_tested = total_tested - phase4_start
    print(f"\nPhase 4 complete: {phase4_tested} new tests, total={total_tested}")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 5: Irregular columnar with coordinate-digit column widths
    #          using CRIB CONSTRAINTS to prune search
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 78)
    print("PHASE 5: Crib-constrained search on valid groupings")
    print("=" * 78)

    phase5_start = total_tested

    for gi, (widths, desc) in enumerate(groupings):
        ncols = len(widths)
        n_perms = math.factorial(ncols)

        if n_perms > 1_000_000:
            # Too many permutations even with pruning, skip
            print(f"  Skipping {desc} ({ncols} cols, {n_perms:.0e} perms)")
            continue

        # For each crib position set, try to constrain the column order
        # using the fact that specific plaintext positions must yield
        # specific characters

        # Build position-to-column mapping for this set of widths
        cum = [0]
        for w in widths:
            cum.append(cum[-1] + w)

        # For canonical cribs
        for crib_set_name, cribs in [("canonical", CANONICAL_CRIBS), ("user", USER_CRIBS)]:
            # Map each crib position to the column it falls in
            crib_constraints = {}  # col_idx -> list of (offset, expected_char)
            for word, start in cribs.items():
                for i, ch in enumerate(word):
                    pos = start + i
                    for c in range(ncols):
                        if cum[c] <= pos < cum[c + 1]:
                            if c not in crib_constraints:
                                crib_constraints[c] = []
                            crib_constraints[c].append((pos - cum[c], ch))
                            break

            # Now try all permutations, checking crib constraints early
            if n_perms <= MAX_PERMS:
                for perm in itertools.permutations(range(ncols)):
                    col_order = list(perm)

                    # Quick check: for the given column order, verify that
                    # the CT segments placed at crib positions contain the right chars
                    # This is an early-termination check

                    # Compute where each column's data ends up in plaintext
                    valid = True
                    ct_pos = 0
                    col_ct_ranges = {}
                    for col_idx in col_order:
                        col_ct_ranges[col_idx] = (ct_pos, ct_pos + widths[col_idx])
                        ct_pos += widths[col_idx]

                    # For each constrained column, check if the CT chars at the
                    # corresponding positions match
                    for col_idx, constraints in crib_constraints.items():
                        ct_start, ct_end = col_ct_ranges[col_idx]
                        for offset, expected_char in constraints:
                            ct_char_pos = ct_start + offset
                            if ct_char_pos < CT_LEN and CT[ct_char_pos] != expected_char:
                                valid = False
                                break
                        if not valid:
                            break

                    if not valid:
                        continue

                    # This permutation passes the crib constraint check
                    try:
                        pt = columnar_decrypt_with_widths(CT, widths, col_order)
                    except Exception:
                        continue

                    total_tested += 1
                    qg = qg_score(pt)
                    canon = check_canonical_cribs(pt)
                    user_match = check_cribs_at_positions(pt, USER_CRIBS)
                    cribs_at = check_cribs_anywhere(pt)

                    if qg > best_qg:
                        best_qg = qg
                    if canon > best_canonical:
                        best_canonical = canon
                    if user_match > best_user_cribs:
                        best_user_cribs = user_match

                    if cribs_at:
                        entry = {
                            "desc": f"crib_constrained/{crib_set_name}/{desc}/order={col_order}",
                            "text": pt,
                            "cribs": cribs_at,
                            "qg": qg,
                            "canon": canon,
                            "user_match": user_match,
                        }
                        crib_hits.append(entry)
                        print(f"\n*** CRIB HIT *** {entry['desc']}")
                        print(f"    Text: {pt}")
                        print(f"    Cribs: {cribs_at}")

                    if canon >= 10 or user_match >= 10 or qg > -5.5:
                        interesting.append({
                            "desc": f"crib_constrained/{crib_set_name}/{desc}/order={col_order}",
                            "text": pt,
                            "qg": qg,
                            "canon": canon,
                            "user_match": user_match,
                        })

        if (gi + 1) % 5 == 0 or gi == len(groupings) - 1:
            elapsed = time.time() - t0
            print(f"  Grouping {gi+1}/{len(groupings)}: tested={total_tested}, elapsed={elapsed:.1f}s")

    phase5_tested = total_tested - phase5_start
    print(f"\nPhase 5 complete: {phase5_tested} new tests, total={total_tested}")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 6: Double transposition with reversed/shifted digit sequences
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 78)
    print("PHASE 6: Double irregular columnar (two-pass with coordinate groupings)")
    print("=" * 78)

    phase6_start = total_tested

    # Try pairs of groupings for double transposition
    # This is O(groupings^2 * perms^2) so we must be selective

    # Only use groupings with few columns for the inner loop
    small_groupings = [(w, d) for w, d in groupings if len(w) <= 6]

    print(f"  Small groupings (<=6 cols): {len(small_groupings)}")

    for gi1, (widths1, desc1) in enumerate(small_groupings):
        for gi2, (widths2, desc2) in enumerate(small_groupings):
            if gi1 == gi2:
                continue

            ncols1 = len(widths1)
            ncols2 = len(widths2)

            # Only try if both are small enough for full enumeration
            if math.factorial(ncols1) * math.factorial(ncols2) > 100000:
                continue

            for p1 in itertools.permutations(range(ncols1)):
                for p2 in itertools.permutations(range(ncols2)):
                    try:
                        # Decrypt pass 2, then pass 1
                        intermediate = columnar_decrypt_with_widths(CT, widths2, list(p2))
                        pt = columnar_decrypt_with_widths(intermediate, widths1, list(p1))
                    except Exception:
                        continue

                    total_tested += 1
                    qg = qg_score(pt)
                    canon = check_canonical_cribs(pt)
                    user_match = check_cribs_at_positions(pt, USER_CRIBS)
                    cribs_at = check_cribs_anywhere(pt)

                    if qg > best_qg:
                        best_qg = qg
                    if canon > best_canonical:
                        best_canonical = canon
                    if user_match > best_user_cribs:
                        best_user_cribs = user_match

                    if cribs_at:
                        entry = {
                            "desc": f"double_irreg/{desc1}+{desc2}/p1={list(p1)}/p2={list(p2)}",
                            "text": pt,
                            "cribs": cribs_at,
                            "qg": qg,
                            "canon": canon,
                            "user_match": user_match,
                        }
                        crib_hits.append(entry)
                        print(f"\n*** CRIB HIT *** {entry['desc']}")
                        print(f"    Text: {pt}")

                    if canon >= 10 or user_match >= 10 or qg > -5.0:
                        interesting.append({
                            "desc": f"double_irreg/{desc1}+{desc2}/p1={list(p1)}/p2={list(p2)}",
                            "text": pt,
                            "qg": qg,
                            "canon": canon,
                            "user_match": user_match,
                        })

            if total_tested - phase6_start > 5_000_000:
                print(f"  Phase 6 budget exceeded, stopping early")
                break
        if total_tested - phase6_start > 5_000_000:
            break

    phase6_tested = total_tested - phase6_start
    print(f"\nPhase 6 complete: {phase6_tested} new tests, total={total_tested}")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 7: W-character column boundary analysis
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 78)
    print("PHASE 7: W-character column boundary analysis")
    print("=" * 78)

    # Find all W positions in the ciphertext
    w_positions = [i for i, ch in enumerate(CT) if ch == 'W']
    print(f"  W positions in CT: {w_positions}")
    print(f"  W characters: {len(w_positions)}")

    # Check if W positions align with column boundaries for any grouping
    for widths, desc in groupings:
        cum = [0]
        for w in widths:
            cum.append(cum[-1] + w)
        boundaries = set(cum)

        w_at_boundaries = [pos for pos in w_positions if pos in boundaries]
        if len(w_at_boundaries) >= 2:
            print(f"  {desc}: widths={widths}, boundaries={sorted(boundaries)}")
            print(f"    W at boundaries: {w_at_boundaries} ({len(w_at_boundaries)}/{len(w_positions)})")

    # Also check for coordinate-derived regular widths
    for width in coord_widths:
        boundaries = set(range(0, CT_LEN + 1, width))
        w_at_boundaries = [pos for pos in w_positions if pos in boundaries]
        if len(w_at_boundaries) >= 2:
            print(f"  Regular width {width}: boundaries={sorted(boundaries)}")
            print(f"    W at boundaries: {w_at_boundaries} ({len(w_at_boundaries)}/{len(w_positions)})")

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 8: Comprehensive analysis of digit string "38576577844"
    # ═══════════════════════════════════════════════════════════════════
    print("\n" + "=" * 78)
    print("PHASE 8: Direct digit-string analysis")
    print("=" * 78)

    digit_string = "38576577844"

    # Properties of the digit string
    print(f"  Digit string: {digit_string}")
    print(f"  Individual digits: {[int(d) for d in digit_string]}")
    print(f"  Sum of digits: {sum(int(d) for d in digit_string)}")
    print(f"  Product: {eval('*'.join(digit_string))}")
    print(f"  As number: {int(digit_string)}")
    print(f"  {int(digit_string)} mod 97 = {int(digit_string) % 97}")
    print(f"  {int(digit_string)} mod 26 = {int(digit_string) % 26}")

    # Check if any digit grouping creates a valid key for the Kryptos alphabet
    # Convert digits to letters (1=A, 2=B, ..., 0=Z or similar)
    digit_to_letter_mappings = [
        ("1-indexed", {str(i): ALPH[i-1] for i in range(1, 10)} | {"0": ALPH[25]}),
        ("0-indexed", {str(i): ALPH[i] for i in range(10)}),
    ]

    for map_name, mapping in digit_to_letter_mappings:
        keyword = "".join(mapping.get(d, '?') for d in digit_string)
        print(f"  Digit-to-letter ({map_name}): {keyword}")

    # ═══════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ═══════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print("\n" + "=" * 78)
    print("FINAL SUMMARY")
    print("=" * 78)
    print(f"Total configurations tested: {total_tested:,}")
    print(f"Elapsed time: {elapsed:.1f}s")
    print(f"Best quadgram score: {best_qg:.4f}")
    print(f"Best canonical crib match: {best_canonical}/24")
    print(f"Best user-stated crib match: {best_user_cribs}/24")
    print(f"Full crib hits (word at any position): {len(crib_hits)}")

    if crib_hits:
        print(f"\n  FULL CRIB HITS ({len(crib_hits)}):")
        for h in crib_hits:
            print(f"    {h['desc']}")
            print(f"      Text: {h['text'][:80]}")
            print(f"      Cribs: {h.get('cribs', '?')}")
            print(f"      QG: {h.get('qg', '?'):.4f}, Canon: {h.get('canon', '?')}/24, "
                  f"User: {h.get('user_match', '?')}/24")
    else:
        print("\n  NO FULL CRIB HITS FOUND.")

    # Report interesting results
    if interesting:
        # Dedup
        seen_texts = set()
        unique_interesting = []
        for entry in interesting:
            if entry['text'] not in seen_texts:
                seen_texts.add(entry['text'])
                unique_interesting.append(entry)

        sorted_int = sorted(unique_interesting, key=lambda x: x.get('qg', -999), reverse=True)
        n_show = min(25, len(sorted_int))
        print(f"\n  Top {n_show} interesting results (by QG score):")
        for i, r in enumerate(sorted_int[:n_show]):
            print(f"    {i+1}. QG={r['qg']:.4f} canon={r.get('canon','?')}/24 "
                  f"user={r.get('user_match','?')}/24 | {r['desc']}")
            print(f"       {r['text'][:80]}")
    else:
        print("\n  No interesting results found.")

    # Statistical summary
    print(f"\n  HYPOTHESIS ASSESSMENT:")
    print(f"  The K2 coordinate digits [3,8,5,7,6,5,7,7,8,4,4] were tested as")
    print(f"  column widths and permutation keys for single and double columnar")
    print(f"  transposition in {total_tested:,} configurations.")

    if crib_hits:
        print(f"  RESULT: {len(crib_hits)} configuration(s) produced full crib matches.")
        print(f"  The hypothesis CANNOT BE RULED OUT based on this search.")
    else:
        if best_canonical >= 12:
            print(f"  RESULT: No full crib matches, but best canonical match = {best_canonical}/24.")
            print(f"  This exceeds random expectation (~1/26 per position = ~0.9/24).")
            print(f"  The hypothesis shows WEAK support but no conclusive evidence.")
        else:
            print(f"  RESULT: No full crib matches. Best canonical match = {best_canonical}/24.")
            print(f"  Random expectation is ~{24/26:.1f}/24 = ~{24.0/26:.2f} per trial.")
            print(f"  The hypothesis is NOT SUPPORTED by this search.")

    # Save results
    outdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..', 'results', 'kbot')
    os.makedirs(outdir, exist_ok=True)
    outfile = os.path.join(outdir, 'k2_coord_double_columnar_results.json')

    save_data = {
        "hypothesis": "K2 coordinates encode column widths for double columnar transposition",
        "total_tested": total_tested,
        "elapsed_seconds": elapsed,
        "best_qg": best_qg,
        "best_canonical_crib_match": best_canonical,
        "best_user_crib_match": best_user_cribs,
        "crib_hits": [{k: str(v) if isinstance(v, list) else v for k, v in h.items()}
                      for h in crib_hits],
        "num_valid_groupings": len(groupings),
        "groupings": [(w, d) for w, d in groupings],
    }

    with open(outfile, 'w') as f:
        json.dump(save_data, f, indent=2, default=str)
    print(f"\nResults saved to {outfile}")


if __name__ == "__main__":
    main()
