#!/usr/bin/env python3
"""
Cipher: Berlin Clock transposition permutation
Family: grille
Status: active
Keyspace: ~50k structured permutations (exhaustive by category)
Last run:
Best score:
"""
"""
E-BERLIN-CLOCK-PERM: Berlin Clock (Mengenlehreuhr) as Transposition Scheme

The Berlin Clock (Set Theory Clock / Mengenlehreuhr) is a public art clock
in Berlin that displays time using blocks of lights in rows:
  - Top:   1 seconds blinker (on/off every second)
  - Row 1: 4 red blocks (each = 5 hours)
  - Row 2: 4 red blocks (each = 1 hour)
  - Row 3: 11 blocks (each = 5 minutes, every 3rd is red, rest yellow)
  - Row 4: 4 yellow blocks (each = 1 minute)

Total display elements: 1 + 4 + 4 + 11 + 4 = 24

BERLINCLOCK is a known crib at positions 63-73. HOROLOGE ("timepiece") is
the top keyword candidate (length 8, Bean-compatible).

HYPOTHESES TESTED:
1. Grid dimensions from Berlin Clock structure (4x24+1, 24x4+1, etc.)
2. Column-group reading orders based on row sizes (4, 4, 11, 4)
3. Set-theory partitioning (groups of 5 and 1)
4. Step-11 and step-4 reading patterns
5. Time-based permutations (encode specific times as reading orders)
6. Row-size-inspired block transpositions
7. Seconds blinker as pivot position
8. All 1440 possible Berlin Clock times as 24-column keys
9. Route/spiral cipher readings of BC-dimensioned grids

For each permutation: apply to CT (both forward and inverse), decrypt with
Vig/Beau x AZ/KA using multiple keywords, score with BOTH:
  - score_candidate() (anchored crib matching, 0-24 partial credit)
  - score_candidate_free() (crib substring search anywhere)
  - IC analysis and quadgram scoring for English-likeness
"""

import sys
import os
import json
from datetime import datetime
from math import gcd

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX
from kryptos.kernel.alphabet import AZ, KA, Alphabet
from kryptos.kernel.transforms.vigenere import vig_decrypt, beau_decrypt
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.ngram import NgramScorer

# ── Constants ────────────────────────────────────────────────────────────

KEYWORDS = ["HOROLOGE", "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
            "PARALLAX", "COLOPHON", "CLOCK", "BERLIN", "MENGENLEHREUHR",
            "ZEITGEBER"]

CIPHERS = [
    ("vig_AZ", vig_decrypt, AZ),
    ("beau_AZ", beau_decrypt, AZ),
    ("vig_KA", vig_decrypt, KA),
    ("beau_KA", beau_decrypt, KA),
]

# Berlin Clock row sizes
BC_ROWS = [1, 4, 4, 11, 4]  # blinker + 4 rows
BC_ROWS_NO_BLINK = [4, 4, 11, 4]  # without blinker (sum=23)
BC_TOTAL = sum(BC_ROWS)  # 24

# Load quadgram scorer
try:
    NGRAM = NgramScorer.from_file(
        os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json'))
except FileNotFoundError:
    NGRAM = None

# ── Helper functions ─────────────────────────────────────────────────────

def apply_permutation(text, perm):
    """Apply permutation: output[i] = text[perm[i]] (gather convention)."""
    return "".join(text[p] for p in perm)


def invert_perm(perm):
    """Compute inverse permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def decrypt_with_keyword(ct_text, keyword, decrypt_fn, alphabet):
    """Decrypt ciphertext with repeating keyword using given cipher and alphabet."""
    kw_indices = alphabet.encode(keyword)
    ct_indices = alphabet.encode(ct_text)
    kw_len = len(kw_indices)
    pt_indices = []
    for i, c in enumerate(ct_indices):
        k = kw_indices[i % kw_len]
        pt_indices.append(decrypt_fn(c, k))
    return alphabet.decode(pt_indices)


def test_permutation_full(perm, perm_name, results, best_ref, verbose=False):
    """Test a permutation with all keyword/cipher combos using both scorers.
    Returns number of configs tested."""
    if len(perm) != CT_LEN:
        return 0
    if sorted(perm) != list(range(CT_LEN)):
        return 0

    configs_tested = 0
    unscrambled = apply_permutation(CT, perm)

    for kw in KEYWORDS:
        for cipher_name, decrypt_fn, alphabet in CIPHERS:
            pt = decrypt_with_keyword(unscrambled, kw, decrypt_fn, alphabet)
            configs_tested += 1
            method = f"{perm_name} | {cipher_name} | kw={kw}"

            # Anchored scoring (partial credit per crib position)
            sb = score_candidate(pt)
            anchored_score = sb.crib_score

            # Free scoring (full crib substrings anywhere)
            fsb = score_candidate_free(pt)
            free_score = fsb.crib_score

            # IC
            ic_val = ic(pt)

            # Quadgram
            ngram_pc = None
            if NGRAM is not None:
                ngram_pc = NGRAM.score_per_char(pt)

            # Report anything interesting
            # Anchored: expected random ~2/24 (~8%), interesting if >= 5
            # Free: interesting if > 0 (any full crib substring)
            # IC: random ~0.038, English ~0.065+, interesting if > 0.050
            # Ngram: English ~-2.5 to -3.5, random ~-6.5+, interesting if > -4.5
            is_interesting = (anchored_score >= 5 or
                              free_score > 0 or
                              ic_val > 0.050 or
                              (ngram_pc is not None and ngram_pc > -4.5))

            if is_interesting:
                result = {
                    "anchored_score": anchored_score,
                    "free_score": free_score,
                    "ic": ic_val,
                    "ngram_pc": ngram_pc,
                    "method": method,
                    "plaintext": pt,
                    "summary": sb.summary,
                    "free_summary": fsb.summary,
                }
                results.append(result)

                total_signal = anchored_score + free_score
                if total_signal > best_ref[0]:
                    best_ref[0] = total_signal
                    ng_str = f"{ngram_pc:.2f}" if ngram_pc is not None else "N/A"
                    print(f"  NEW BEST: anchored={anchored_score} free={free_score} "
                          f"IC={ic_val:.4f} ngram={ng_str}")
                    print(f"    Method: {method}")
                    print(f"    PT: {pt}")

    return configs_tested


def test_perm_both_dirs(perm, perm_name, results, best_ref, verbose=False):
    """Test both a permutation and its inverse."""
    n = test_permutation_full(perm, perm_name, results, best_ref, verbose)
    inv = invert_perm(perm)
    n += test_permutation_full(inv, perm_name + " [INV]", results, best_ref, verbose)
    return n


# ── Category 1: Grid dimensions from Berlin Clock ────────────────────────

def gen_grid_perms():
    """Generate permutations based on Berlin Clock-inspired grid dimensions."""
    perms = []

    grid_configs = [
        (4, 24, "4x24"),   # 4 rows (like BC row count) x 24 cols (=BC total)
        (24, 4, "24x4"),   # transposed
        (8, 12, "8x12"),   # HOROLOGE length x 12
        (12, 8, "12x8"),
        (9, 11, "9x11"),   # 11 = BC minute row
        (11, 9, "11x9"),
        (5, 20, "5x20"),   # 5 = BC 5-min/5-hour unit
        (20, 5, "20x5"),
        (7, 14, "7x14"),   # 7x14=98, -1
    ]

    for n_rows, n_cols, label in grid_configs:
        total = n_rows * n_cols
        if total < 97:
            continue

        # Column-major reading
        for extra_pos in ["last", "first"]:
            perm = []
            offset = 0 if extra_pos == "last" else (total - 96 if total > 97 else 1)
            if total == 97 or (total > 97 and extra_pos == "last"):
                for col in range(n_cols):
                    for row in range(n_rows):
                        idx = row * n_cols + col
                        if idx < 97:
                            perm.append(idx)
                if len(perm) == 97 and sorted(perm) == list(range(97)):
                    perms.append((perm, f"grid_{label}_colmajor"))

            if total > 97 and extra_pos == "first":
                # Extra position(s) at start
                perm = []
                for col in range(n_cols):
                    for row in range(n_rows):
                        idx = row * n_cols + col
                        if idx < 97:
                            perm.append(idx)
                if len(perm) == 97 and sorted(perm) == list(range(97)):
                    perms.append((perm, f"grid_{label}_colmajor_trim"))

        # Serpentine (boustrophedon) - rows alternate direction
        perm = []
        for row in range(n_rows):
            if row % 2 == 0:
                for col in range(n_cols):
                    idx = row * n_cols + col
                    if idx < 97:
                        perm.append(idx)
            else:
                for col in range(n_cols - 1, -1, -1):
                    idx = row * n_cols + col
                    if idx < 97:
                        perm.append(idx)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"grid_{label}_serpentine"))

        # Diagonal reading
        perm = []
        visited = set()
        for d in range(n_rows + n_cols - 1):
            for row in range(max(0, d - n_cols + 1), min(n_rows, d + 1)):
                col = d - row
                if col < n_cols:
                    idx = row * n_cols + col
                    if idx < 97 and idx not in visited:
                        perm.append(idx)
                        visited.add(idx)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"grid_{label}_diagonal"))

        # Anti-diagonal reading
        perm = []
        visited = set()
        for d in range(n_rows + n_cols - 1):
            for row in range(max(0, d - n_cols + 1), min(n_rows, d + 1)):
                col = (n_cols - 1) - (d - row)
                if 0 <= col < n_cols:
                    idx = row * n_cols + col
                    if idx < 97 and idx not in visited:
                        perm.append(idx)
                        visited.add(idx)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"grid_{label}_antidiag"))

        # Column-major, columns reversed
        perm = []
        for col in range(n_cols - 1, -1, -1):
            for row in range(n_rows):
                idx = row * n_cols + col
                if idx < 97:
                    perm.append(idx)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"grid_{label}_colmajor_rev"))

        # Column-major, rows reversed within each column
        perm = []
        for col in range(n_cols):
            for row in range(n_rows - 1, -1, -1):
                idx = row * n_cols + col
                if idx < 97:
                    perm.append(idx)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"grid_{label}_colmajor_rowrev"))

    return perms


# ── Category 2: Column-group reading by BC row sizes ─────────────────────

def gen_column_group_perms():
    """Read columns in groups defined by Berlin Clock row sizes."""
    perms = []

    # Group structures to try
    group_configs = [
        ([4, 4, 11, 4], "4_4_11_4"),      # BC rows without blinker (sum=23)
        ([1, 4, 4, 11, 4], "1_4_4_11_4"),  # BC rows with blinker (sum=24)
        ([4, 11, 4, 4], "4_11_4_4"),       # reordered
        ([11, 4, 4, 4], "11_4_4_4"),       # minute row first
        ([4, 4, 4, 11], "4_4_4_11"),       # minute row last
    ]

    for groups, label in group_configs:
        total_cols = sum(groups)
        for n_rows in range(3, 25):
            if n_rows * total_cols < 97:
                continue
            if n_rows * total_cols > 150:
                break

            # Generate all permutations of group order
            import itertools
            for group_perm in itertools.permutations(range(len(groups))):
                perm = []
                for gi in group_perm:
                    col_start = sum(groups[:gi])
                    for c in range(groups[gi]):
                        for r in range(n_rows):
                            idx = r * total_cols + col_start + c
                            if idx < 97:
                                perm.append(idx)
                # Deduplicate
                seen = set()
                clean = []
                for p in perm:
                    if p not in seen and p < 97:
                        seen.add(p)
                        clean.append(p)
                if len(clean) == 97 and sorted(clean) == list(range(97)):
                    perm_label = "_".join(str(group_perm[i]) for i in range(len(groups)))
                    perms.append((clean, f"colgroup_{label}_r{n_rows}_order{perm_label}"))

    return perms


# ── Category 3: Set-theory partitioning ──────────────────────────────────

def gen_set_theory_perms():
    """Partition positions using set-theory concepts."""
    perms = []

    # 3a: Interleave by k strides
    for k in [4, 5, 11, 24]:
        perm = []
        for phase in range(k):
            perm.extend(range(phase, 97, k))
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"interleave_{k}"))

    # 3b: Berlin Clock set-theory cycle
    cycle = [1, 4, 4, 11, 4]
    pos = 0
    ci = 0
    groups = []
    while pos < 97:
        size = min(cycle[ci % len(cycle)], 97 - pos)
        groups.append((pos, size))
        pos += size
        ci += 1

    # Read groups in reverse order
    perm = []
    for start, size in reversed(groups):
        perm.extend(range(start, start + size))
    if len(perm) == 97 and sorted(perm) == list(range(97)):
        perms.append((perm, "bc_cycle_groups_reversed"))

    # Reverse within each group
    perm = []
    for start, size in groups:
        perm.extend(range(start + size - 1, start - 1, -1))
    if len(perm) == 97 and sorted(perm) == list(range(97)):
        perms.append((perm, "bc_cycle_intrarev"))

    # Sort groups by size
    for order in ["asc", "desc"]:
        sg = sorted(groups, key=lambda g: g[1], reverse=(order == "desc"))
        perm = []
        for start, size in sg:
            perm.extend(range(start, start + size))
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"bc_cycle_sizegroup_{order}"))

    # 3c: Hours/minutes decomposition
    # Read positions grouped by p%4 (4 groups of ~24)
    perm = []
    for m in range(4):
        for h in range(25):
            idx = h * 4 + m
            if idx < 97:
                perm.append(idx)
    if len(perm) == 97 and sorted(perm) == list(range(97)):
        perms.append((perm, "hm_minute_groups"))

    # 3d: Block reversal with various block sizes
    for block_size in [4, 5, 8, 11, 24]:
        perm = []
        n_blocks = (97 + block_size - 1) // block_size
        for b in range(n_blocks - 1, -1, -1):
            start = b * block_size
            end = min(start + block_size, 97)
            perm.extend(range(start, end))
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"blocks_{block_size}_reversed"))

    # 3e: Block rotation (shift blocks cyclically)
    for block_size in [4, 5, 8, 11, 24]:
        n_blocks = (97 + block_size - 1) // block_size
        for shift in range(1, n_blocks):
            perm = []
            for b in range(n_blocks):
                actual_b = (b + shift) % n_blocks
                start = actual_b * block_size
                end = min(start + block_size, 97)
                perm.extend(range(start, end))
            if len(perm) == 97 and sorted(perm) == list(range(97)):
                perms.append((perm, f"blocks_{block_size}_rotate_{shift}"))

    return perms


# ── Category 4: Step-based reading ───────────────────────────────────────

def gen_step_perms():
    """Generate step-based permutations inspired by BC dimensions."""
    perms = []

    # 97 is prime, so every step 1..96 generates a full cycle
    for step in range(2, 97):
        perm = [(i * step) % 97 for i in range(97)]
        perms.append((perm, f"step_{step}"))

    # Multi-step: alternate between two steps
    bc_steps = [4, 5, 11, 23, 24]
    for s1 in bc_steps:
        for s2 in bc_steps:
            if s1 == s2:
                continue
            perm = []
            visited = set()
            pos = 0
            for i in range(97):
                while pos % 97 in visited and len(visited) < 97:
                    pos = (pos + 1)
                actual = pos % 97
                if actual in visited:
                    break
                perm.append(actual)
                visited.add(actual)
                if i % 2 == 0:
                    pos = (actual + s1) % 97
                else:
                    pos = (actual + s2) % 97
            if len(perm) == 97 and sorted(perm) == list(range(97)):
                perms.append((perm, f"multistep_{s1}_{s2}"))

    # Rail fence with BC-inspired rail counts
    for n_rails in [4, 5, 8, 11, 24]:
        if n_rails >= 97:
            continue
        rails = [[] for _ in range(n_rails)]
        rail = 0
        direction = 1
        for i in range(97):
            rails[rail].append(i)
            if rail == 0:
                direction = 1
            elif rail == n_rails - 1:
                direction = -1
            rail += direction
        perm = []
        for r in rails:
            perm.extend(r)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"railfence_{n_rails}"))

    return perms


# ── Category 5: Time-based permutations ──────────────────────────────────

def encode_berlin_clock_time(hours, minutes):
    """Encode a time as Berlin Clock display state.
    Returns a list of 24 values (0=off, 1=on/yellow, 2=on/red)."""
    display = []
    # Seconds blinker
    display.append(1)
    # Row 1: 5-hour blocks
    five_hours = hours // 5
    for i in range(4):
        display.append(2 if i < five_hours else 0)
    # Row 2: 1-hour blocks
    one_hours = hours % 5
    for i in range(4):
        display.append(2 if i < one_hours else 0)
    # Row 3: 5-minute blocks (every 3rd is red)
    five_mins = minutes // 5
    for i in range(11):
        if i < five_mins:
            display.append(2 if (i + 1) % 3 == 0 else 1)
        else:
            display.append(0)
    # Row 4: 1-minute blocks
    one_mins = minutes % 5
    for i in range(4):
        display.append(1 if i < one_mins else 0)
    return display


def gen_time_perms():
    """Generate columnar transposition permutations from BC time displays."""
    perms = []

    # Method: for each time, rank 24 columns by light state, use as columnar key
    # But 1440 times x permutations-of-groups is huge, so just do the ranking
    n_cols = 24
    n_rows = 5  # ceil(97/24) = 5

    seen_rankings = set()

    for h in range(24):
        for m in range(60):
            bc_state = encode_berlin_clock_time(h, m)
            # Rank columns: red first, yellow second, off last; ties by position
            col_order = sorted(range(n_cols),
                               key=lambda i: (-bc_state[i], i))
            ranking_key = tuple(col_order)
            if ranking_key in seen_rankings:
                continue
            seen_rankings.add(ranking_key)

            perm = []
            for col in col_order:
                for row in range(n_rows):
                    idx = row * n_cols + col
                    if idx < 97:
                        perm.append(idx)

            if len(perm) == 97 and sorted(perm) == list(range(97)):
                perms.append((perm, f"bctime_{h:02d}{m:02d}_24col"))

    return perms


# ── Category 6: 11-block minute row focus ────────────────────────────────

def gen_eleven_perms():
    """Permutations based on the distinctive 11-block minute row."""
    perms = []

    # Grid with 11 columns
    for n_rows in [9, 10]:
        # 9x11=99, 10x11=110
        perm = []
        for col in range(11):
            for row in range(n_rows):
                idx = row * 11 + col
                if idx < 97:
                    perm.append(idx)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"grid_{n_rows}x11_colmajor"))

    # Grid with 11 rows
    for n_cols in [9, 10]:
        perm = []
        for col in range(n_cols):
            for row in range(11):
                idx = row * n_cols + col
                if idx < 97:
                    perm.append(idx)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"grid_11x{n_cols}_colmajor"))

    # BC minute row color pattern: YYR YYR YYR YY applied cyclically
    # Positions 0,1 = yellow; 2 = red; 3,4 = yellow; 5 = red; ...
    reds = [i for i in range(97) if i % 3 == 2]
    yellows = [i for i in range(97) if i % 3 != 2]
    perms.append((reds + yellows, "bc_minute_red_first"))
    perms.append((yellows + reds, "bc_minute_yellow_first"))

    # Groups of 11 with various reading orders
    # 8 groups of 11 = 88, plus 9 remainder
    for rem_pos in ["end", "start"]:
        for group_read in ["fwd", "rev"]:
            perm = []
            gs = list(range(8))
            if group_read == "rev":
                gs = gs[::-1]

            if rem_pos == "start":
                perm.extend(range(0, 9))
                for g in gs:
                    start = 9 + g * 11
                    perm.extend(range(start, start + 11))
            else:
                for g in gs:
                    start = g * 11
                    perm.extend(range(start, start + 11))
                perm.extend(range(88, 97))

            if len(perm) == 97 and sorted(perm) == list(range(97)):
                perms.append((perm, f"groups11_{rem_pos}_{group_read}"))

    return perms


# ── Category 7: Blinker pivot + simple transforms ───────────────────────

def gen_blinker_perms():
    """Fix one position (blinker) and permute the rest, plus simple transforms."""
    perms = []

    # Full reversal
    perms.append((list(range(96, -1, -1)), "full_reversal"))

    # Halves swapped at various splits
    for split in [24, 48, 49, 53, 63]:
        perm = list(range(split, 97)) + list(range(0, split))
        perms.append((perm, f"halves_swapped_{split}"))

    # Fix position 0, reverse rest
    perms.append(([0] + list(range(96, 0, -1)), "blinker0_rest_rev"))

    # Fix position 96, reverse rest
    perms.append((list(range(95, -1, -1)) + [96], "blinker96_rest_rev"))

    # Interleave from middle outward
    perm = []
    left, right = 48, 49
    perm.append(48)  # middle
    while left > 0 or right < 97:
        left -= 1
        if left >= 0:
            perm.append(left)
        if right < 97:
            perm.append(right)
        right += 1
    if len(perm) == 97:
        perms.append((perm, "middle_outward"))

    # Perfect shuffle (Faro shuffle)
    first_half = list(range(0, 49))
    second_half = list(range(49, 97))
    perm = []
    for i in range(48):
        perm.append(first_half[i])
        perm.append(second_half[i])
    perm.append(first_half[48])
    if len(perm) == 97 and sorted(perm) == list(range(97)):
        perms.append((perm, "faro_shuffle"))

    return perms


# ── Category 8: Route cipher readings ────────────────────────────────────

def gen_route_perms():
    """Route/spiral cipher readings of BC-dimensioned grids."""
    perms = []

    grid_configs = [
        (4, 24, "4x24"), (24, 4, "24x4"),
        (8, 12, "8x12"), (12, 8, "12x8"),
        (9, 11, "9x11"), (11, 9, "11x9"),
    ]

    for n_rows, n_cols, label in grid_configs:
        total = n_rows * n_cols
        if total < 97:
            continue

        # Clockwise spiral
        perm = []
        top, bottom, left, right = 0, n_rows - 1, 0, n_cols - 1
        while top <= bottom and left <= right and len(perm) < total:
            for col in range(left, right + 1):
                perm.append(top * n_cols + col)
            top += 1
            for row in range(top, bottom + 1):
                perm.append(row * n_cols + right)
            right -= 1
            if top <= bottom:
                for col in range(right, left - 1, -1):
                    perm.append(bottom * n_cols + col)
                bottom -= 1
            if left <= right:
                for row in range(bottom, top - 1, -1):
                    perm.append(row * n_cols + left)
                left += 1

        # Take only positions < 97
        clean = [p for p in perm if p < 97]
        seen = set()
        deduped = []
        for p in clean:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        if len(deduped) == 97 and sorted(deduped) == list(range(97)):
            perms.append((deduped, f"spiral_cw_{label}"))

    # Columnar with keyword-based column orders
    for key_word, kw_label in [("BERLINCLOCK", "BC"), ("HOROLOGE", "HOR"),
                                ("CLOCK", "CLK"), ("KRYPTOS", "KRY"),
                                ("BERLIN", "BER")]:
        n_cols = len(key_word)
        n_rows = (97 + n_cols - 1) // n_cols
        key_order = sorted(range(n_cols), key=lambda i: (key_word[i], i))
        perm = []
        for col in key_order:
            for row in range(n_rows):
                idx = row * n_cols + col
                if idx < 97:
                    perm.append(idx)
        if len(perm) == 97 and sorted(perm) == list(range(97)):
            perms.append((perm, f"columnar_{kw_label}"))

    # Double columnar: BERLINCLOCK then HOROLOGE (and reverse)
    for k1, k2, label in [("BERLINCLOCK", "HOROLOGE", "BC_then_HOR"),
                           ("HOROLOGE", "BERLINCLOCK", "HOR_then_BC"),
                           ("KRYPTOS", "HOROLOGE", "KRY_then_HOR"),
                           ("HOROLOGE", "KRYPTOS", "HOR_then_KRY")]:
        # Build perm1
        nc1 = len(k1)
        nr1 = (97 + nc1 - 1) // nc1
        ko1 = sorted(range(nc1), key=lambda i: (k1[i], i))
        p1 = []
        for col in ko1:
            for row in range(nr1):
                idx = row * nc1 + col
                if idx < 97:
                    p1.append(idx)
        if len(p1) != 97 or sorted(p1) != list(range(97)):
            continue
        # Build perm2
        nc2 = len(k2)
        nr2 = (97 + nc2 - 1) // nc2
        ko2 = sorted(range(nc2), key=lambda i: (k2[i], i))
        p2 = []
        for col in ko2:
            for row in range(nr2):
                idx = row * nc2 + col
                if idx < 97:
                    p2.append(idx)
        if len(p2) != 97 or sorted(p2) != list(range(97)):
            continue
        # Compose
        composed = [p1[p2[i]] for i in range(97)]
        if sorted(composed) == list(range(97)):
            perms.append((composed, f"dbl_columnar_{label}"))

    return perms


# ── Main execution ───────────────────────────────────────────────────────

def attack(ciphertext=None, **params):
    """Main attack function following standard contract."""
    if ciphertext is None:
        ciphertext = CT

    results = []
    best = [0]
    total_configs = 0

    generators = [
        ("1: Grid dimensions", gen_grid_perms),
        ("2: Column groups", gen_column_group_perms),
        ("3: Set-theory partitions", gen_set_theory_perms),
        ("4: Step-based (all 95 steps + multistep + railfence)", gen_step_perms),
        ("5: Time-based (1440 times, deduplicated)", gen_time_perms),
        ("6: 11-block minute row", gen_eleven_perms),
        ("7: Blinker pivot / simple transforms", gen_blinker_perms),
        ("8: Route cipher / columnar", gen_route_perms),
    ]

    for cat_name, gen_fn in generators:
        perms = gen_fn()
        print(f"\n{'='*70}")
        print(f"Category {cat_name}")
        print(f"  Generated {len(perms)} permutations (x2 for inverse = {len(perms)*2})")
        cat_configs = 0
        for perm, name in perms:
            n = test_perm_both_dirs(perm, name, results, best)
            cat_configs += n
        total_configs += cat_configs
        n_kw_cipher = len(KEYWORDS) * len(CIPHERS)
        print(f"  Tested {cat_configs} cipher configs "
              f"({len(perms)*2} perms x {n_kw_cipher} kw/cipher combos)")
        print(f"  Running best: {best[0]}")

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"Total cipher configs tested: {total_configs}")
    print(f"Interesting results (anchored>=5 OR free>0 OR IC>0.050 OR ngram>-4.5): "
          f"{len(results)}")
    print(f"Best combined score (anchored + free): {best[0]}")

    if results:
        # Sort by combined score, then anchored, then IC
        results.sort(key=lambda r: (
            -(r["anchored_score"] + r["free_score"]),
            -r["anchored_score"],
            -r["ic"],
        ))
        print(f"\nTop 30 results:")
        for i, r in enumerate(results[:30]):
            ng = f"{r['ngram_pc']:.2f}" if r['ngram_pc'] is not None else "N/A"
            print(f"  [{i+1}] anchored={r['anchored_score']} free={r['free_score']} "
                  f"IC={r['ic']:.4f} ngram={ng}")
            print(f"      Method: {r['method']}")
            print(f"      PT: {r['plaintext'][:60]}...")

        # Also report any with IC > 0.05 specifically
        high_ic = [r for r in results if r["ic"] > 0.050]
        if high_ic:
            print(f"\nHigh IC results (> 0.050):")
            for r in high_ic[:10]:
                print(f"  IC={r['ic']:.4f} anchored={r['anchored_score']} | {r['method']}")

        # Report any with ngram > -4.0 (close to English)
        if any(r["ngram_pc"] is not None and r["ngram_pc"] > -4.0 for r in results):
            high_ng = [r for r in results
                       if r["ngram_pc"] is not None and r["ngram_pc"] > -4.0]
            print(f"\nHigh ngram results (> -4.0):")
            for r in high_ng[:10]:
                print(f"  ngram={r['ngram_pc']:.2f} anchored={r['anchored_score']} | {r['method']}")

    # Save results
    out_path = os.path.join(os.path.dirname(__file__), '..', '..',
                            'results', 'berlin_clock_perm_results.json')
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump({
            "total_configs": total_configs,
            "n_results": len(results),
            "best_combined": best[0],
            "top_results": results[:50],
        }, f, indent=2, default=str)
    print(f"\nResults saved to {out_path}")

    return [(r["anchored_score"] + r["free_score"],
             r.get("plaintext", ""), r["method"]) for r in results[:50]]


if __name__ == "__main__":
    print(f"Berlin Clock Permutation Explorer for K4")
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Keywords: {KEYWORDS}")
    print(f"Ciphers: {[c[0] for c in CIPHERS]}")
    print(f"Berlin Clock rows: {BC_ROWS} (total={BC_TOTAL})")
    print(f"Key relationships: 4*24+1=97, 8*11+9=97, 9*11-2=97")
    if NGRAM:
        print(f"Quadgram scorer: loaded")
    else:
        print(f"Quadgram scorer: NOT AVAILABLE")
    print()

    start = datetime.now()
    attack()
    elapsed = (datetime.now() - start).total_seconds()
    print(f"\nElapsed: {elapsed:.1f}s")
