#!/usr/bin/env python3
"""E-BESPOKE-06: Doubled-letter digraph analysis and CC insertion hypothesis.

Theory:
- K4 has 6 doubled-letter digraphs: BB(18), QQ(25), SS(32), SS(42), ZZ(46), TT(67)
- Uses 5 distinct letters: B, Q, S, Z, T. Notably, CC is ABSENT.
- "Checkpoint Charlie" = NATO phonetic C = Sanborn's "point" clue.
- CC might be missing deliberately — insertion could reveal structure.
- Alternatively, doubles might be nulls, markers, or encode a key.

Phases:
1. Structural analysis of doubled-letter positions and spacings
2. Insert CC at every position (test crib alignment, w7 columnar)
3. Remove doubled letters (nulls hypothesis)
4. Doubles as boundary/section markers (segment analysis)
5. CC insertion near existing C positions + width-7 columnar exhaustive
6. Doubles as cryptographic key material
7. Statistical significance of 6 doubles in 97-char text

Run: PYTHONPATH=src python3 -u scripts/e_bespoke_06_doubles_cc.py
"""
import itertools
import json
import math
import os
import sys
import time
from collections import Counter

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_WORDS, N_CRIBS, KRYPTOS_ALPHABET,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def quick_crib_score(pt, crib_dict=CRIB_DICT):
    """Fast crib scoring."""
    return sum(1 for pos, ch in crib_dict.items()
               if pos < len(pt) and pt[pos] == ch)


def shifted_crib_dict(insert_pos, n_inserted=1):
    """Return crib dict with positions shifted for insertion."""
    shifted = {}
    for pos, ch in CRIB_DICT.items():
        if pos >= insert_pos:
            shifted[pos + n_inserted] = ch
        else:
            shifted[pos] = ch
    return shifted


def vig_decrypt(ct, key):
    """Vigenere decrypt: PT = (CT - K) mod 26."""
    pt = []
    klen = len(key) if isinstance(key, (list, tuple)) else len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        if isinstance(key, (list, tuple)):
            ki = key[i % klen]
        else:
            ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ci - ki) % 26])
    return ''.join(pt)


def beau_decrypt(ct, key):
    """Beaufort decrypt: PT = (K - CT) mod 26."""
    pt = []
    klen = len(key) if isinstance(key, (list, tuple)) else len(key)
    for i, c in enumerate(ct):
        ci = ALPH_IDX[c]
        if isinstance(key, (list, tuple)):
            ki = key[i % klen]
        else:
            ki = ALPH_IDX[key[i % klen]]
        pt.append(ALPH[(ki - ci) % 26])
    return ''.join(pt)


def keyword_to_order(keyword, width):
    """Convert keyword to columnar transposition ordering."""
    if len(keyword) < width:
        keyword = (keyword * ((width // len(keyword)) + 1))[:width]
    elif len(keyword) > width:
        keyword = keyword[:width]
    indexed = [(ch, i) for i, ch in enumerate(keyword)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    order = [idx for _, idx in indexed]
    return order


def columnar_decrypt(ct, width, order):
    """Decrypt columnar transposition."""
    n = len(ct)
    nrows = (n + width - 1) // width
    ncols = width
    n_long = n - (nrows - 1) * ncols
    if n % ncols == 0:
        n_long = ncols
    col_lens = [0] * ncols
    for col in range(ncols):
        if col < n_long:
            col_lens[col] = nrows
        else:
            col_lens[col] = nrows - 1
    cols = {}
    pos = 0
    for rank in range(ncols):
        col_idx = order[rank]
        length = col_lens[col_idx]
        cols[col_idx] = ct[pos:pos + length]
        pos += length
    result = []
    for row in range(nrows):
        for col in range(ncols):
            if row < len(cols.get(col, '')):
                result.append(cols[col][row])
    return ''.join(result)


def ic(text):
    """Index of coincidence."""
    freq = Counter(text.upper())
    n = sum(freq.values())
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


# ── Find all doubled digraphs ────────────────────────────────────────────────

def find_doubles(text):
    """Find all positions where text[i] == text[i+1]."""
    doubles = []
    for i in range(len(text) - 1):
        if text[i] == text[i + 1]:
            doubles.append((i, text[i]))
    return doubles


# ── KRYPTOS ordering for width 7 ────────────────────────────────────────────
KRYPTOS_ORDER_7 = keyword_to_order("KRYPTOS", 7)


# ═══════════════════════════════════════════════════════════════════════════════
print("=" * 72)
print("E-BESPOKE-06: Doubled-Letter Digraph Analysis & CC Insertion")
print("=" * 72)
print(f"CT: {CT}")
print(f"Length: {CT_LEN}")
print()

results = []
global_best = 0
global_best_config = ""
t0 = time.time()
total_configs = 0

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Structural analysis of doubled-letter positions
# ═══════════════════════════════════════════════════════════════════════════════

print("=" * 72)
print("PHASE 1: Structural Analysis of Doubled Letters")
print("=" * 72)

doubles = find_doubles(CT)
print(f"\nDoubled digraphs found: {len(doubles)}")
for pos, ch in doubles:
    print(f"  Position {pos:2d}-{pos+1:2d}: {ch}{ch}  "
          f"(letter value: {ch}={ALPH_IDX[ch]})")

positions = [pos for pos, _ in doubles]
letters = [ch for _, ch in doubles]
letter_vals = [ALPH_IDX[ch] for ch in letters]

# Spacings between consecutive doubles
spacings = [positions[i+1] - positions[i] for i in range(len(positions) - 1)]
print(f"\nPositions of first char of each pair: {positions}")
print(f"Spacings between consecutive doubles: {spacings}")

# Look for arithmetic patterns in spacings
print(f"\nSpacing analysis:")
print(f"  Spacings: {spacings}")
print(f"  Sum of spacings: {sum(spacings)}")
print(f"  First three spacings: {spacings[:3]} (7, 7, 10)")
print(f"  Last two spacings: {spacings[3:]} (4, 21)")
print(f"  Cumulative from first double: {[p - positions[0] for p in positions]}")

# Positions mod various values
for m in [7, 9, 13, 14, 26]:
    mods = [p % m for p in positions]
    print(f"  Positions mod {m:2d}: {mods}")

# Letter analysis
print(f"\nDoubled letters in order: {''.join(letters)} (BQSSZT)")
print(f"Letter values (0-indexed): {letter_vals}")
print(f"Letter values sum: {sum(letter_vals)}")
print(f"Distinct letters: {sorted(set(letters))}")
print(f"Missing from doubled set: C is NOT doubled (hypothesis link)")

# Check if doubled letters spell something via rearrangement
from itertools import permutations as _perms
double_letters_str = ''.join(letters)
print(f"\nRearrangements of BQSSZT that might be meaningful:")
# Just check a few notable patterns — full 6!/2! = 360 permutations
# Check against common abbreviations/words
seen_perms = set()
for p in _perms(letters):
    w = ''.join(p)
    if w not in seen_perms:
        seen_perms.add(w)
# Not a huge set, just list notable patterns
notable = [w for w in seen_perms if w.startswith(('ST', 'BZ', 'QS', 'ZB'))]
print(f"  Total unique rearrangements: {len(seen_perms)}")
print(f"  Sample rearrangements: {sorted(seen_perms)[:20]}")

# Positions as potential alphabet values
print(f"\nPositions as values:")
print(f"  Positions: {positions}")
pos_as_letters = [ALPH[p % 26] for p in positions]
print(f"  Positions mod 26 as letters: {''.join(pos_as_letters)}")
print(f"  = {positions} mod 26 = {[p % 26 for p in positions]} = {''.join(pos_as_letters)}")

# Letter differences between consecutive doubles
if len(letter_vals) > 1:
    letter_diffs = [letter_vals[i+1] - letter_vals[i] for i in range(len(letter_vals) - 1)]
    print(f"\nLetter value differences: {letter_diffs}")
    letter_diffs_mod = [(letter_vals[i+1] - letter_vals[i]) % 26 for i in range(len(letter_vals) - 1)]
    print(f"Letter value differences mod 26: {letter_diffs_mod}")

# Where are C letters in CT?
c_positions = [i for i, ch in enumerate(CT) if ch == 'C']
print(f"\nC positions in CT: {c_positions}")
print(f"Number of C's: {len(c_positions)}")
print(f"Distance between C's: {c_positions[1] - c_positions[0] if len(c_positions) >= 2 else 'N/A'}")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Insert CC at every position
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("PHASE 2: Insert CC at Every Position (99 chars)")
print("=" * 72)
print("  Also insert single C (98 chars = 7 x 14)")
print()

p2_best = 0
p2_count = 0

# Phase 2a: Insert single C at each position (98 chars)
print("--- Phase 2a: Insert single C (98 chars = 7 x 14) ---")
p2a_best = 0
p2a_top = []

for insert_pos in range(CT_LEN + 1):
    extended = CT[:insert_pos] + 'C' + CT[insert_pos:]
    assert len(extended) == 98
    shifted = shifted_crib_dict(insert_pos, 1)

    # Direct crib check (no transposition)
    sc_orig = quick_crib_score(extended)
    sc_shift = quick_crib_score(extended, shifted)

    # Vig/Beau with KRYPTOS
    pt_v = vig_decrypt(extended, "KRYPTOS")
    sc_v = max(quick_crib_score(pt_v), quick_crib_score(pt_v, shifted))

    pt_b = beau_decrypt(extended, "KRYPTOS")
    sc_b = max(quick_crib_score(pt_b), quick_crib_score(pt_b, shifted))

    # Width-7 columnar with KRYPTOS ordering
    untrans = columnar_decrypt(extended, 7, KRYPTOS_ORDER_7)
    pt_v7 = vig_decrypt(untrans, "KRYPTOS")
    sc_v7 = max(quick_crib_score(pt_v7), quick_crib_score(pt_v7, shifted))

    pt_b7 = beau_decrypt(untrans, "KRYPTOS")
    sc_b7 = max(quick_crib_score(pt_b7), quick_crib_score(pt_b7, shifted))

    # Also test transposition-only
    sc_t = max(quick_crib_score(untrans), quick_crib_score(untrans, shifted))

    sc = max(sc_orig, sc_shift, sc_v, sc_b, sc_v7, sc_b7, sc_t)
    p2_count += 7
    p2a_top.append((sc, insert_pos))

    if sc > p2a_best:
        p2a_best = sc
        print(f"  NEW BEST (C@{insert_pos}): {sc}/24")
        if sc >= 8:
            # Report which variant
            all_sc = [
                (sc_orig, 'direct'), (sc_shift, 'direct_shift'),
                (sc_v, 'vig'), (sc_b, 'beau'),
                (sc_v7, 'w7+vig'), (sc_b7, 'w7+beau'), (sc_t, 'w7_only'),
            ]
            best_var = max(all_sc, key=lambda x: x[0])
            print(f"    Best variant: {best_var[1]}")

# Check doubled-letter pattern in extended CT
print(f"\n  Phase 2a best: {p2a_best}/24")
print(f"  Checking doubled-letter pattern for C insertions near existing C's:")
for ins_pos in c_positions + [cp + 1 for cp in c_positions]:
    if ins_pos <= CT_LEN:
        extended = CT[:ins_pos] + 'C' + CT[ins_pos:]
        new_doubles = find_doubles(extended)
        has_cc = any(ch == 'C' for _, ch in new_doubles)
        if has_cc:
            print(f"    C@{ins_pos}: creates CC! New doubles: "
                  f"{[(p, c) for p, c in new_doubles]}")

# Phase 2b: Insert CC at each position (99 chars)
print(f"\n--- Phase 2b: Insert CC (99 chars = 9 x 11 or 3 x 33) ---")
p2b_best = 0

for insert_pos in range(CT_LEN + 1):
    extended = CT[:insert_pos] + 'CC' + CT[insert_pos:]
    assert len(extended) == 99
    shifted = shifted_crib_dict(insert_pos, 2)

    # Direct crib check
    sc_orig = quick_crib_score(extended)
    sc_shift = quick_crib_score(extended, shifted)

    # Vig/Beau with KRYPTOS
    pt_v = vig_decrypt(extended, "KRYPTOS")
    sc_v = max(quick_crib_score(pt_v), quick_crib_score(pt_v, shifted))

    pt_b = beau_decrypt(extended, "KRYPTOS")
    sc_b = max(quick_crib_score(pt_b), quick_crib_score(pt_b, shifted))

    # 99 = 9 x 11: try width-9 columnar with identity/KRYPTOS
    for w in [9, 11]:
        order_id = list(range(w))
        untrans = columnar_decrypt(extended, w, order_id)
        sc_t = max(quick_crib_score(untrans), quick_crib_score(untrans, shifted))
        pt_vw = vig_decrypt(untrans, "KRYPTOS")
        sc_vw = max(quick_crib_score(pt_vw), quick_crib_score(pt_vw, shifted))
        pt_bw = beau_decrypt(untrans, "KRYPTOS")
        sc_bw = max(quick_crib_score(pt_bw), quick_crib_score(pt_bw, shifted))
        sc_w = max(sc_t, sc_vw, sc_bw)
        p2_count += 3
        if sc_w > p2b_best:
            p2b_best = sc_w

    sc = max(sc_orig, sc_shift, sc_v, sc_b)
    p2_count += 4

    # Check new doubled-letter pattern
    new_doubles = find_doubles(extended)

    if sc > p2b_best:
        p2b_best = max(p2b_best, sc)
        print(f"  NEW BEST (CC@{insert_pos}): {max(p2b_best, sc)}/24, "
              f"new doubles: {len(new_doubles)}")

p2_best = max(p2a_best, p2b_best)
if p2_best > global_best:
    global_best = p2_best
    global_best_config = "Phase 2: Insert C/CC"
total_configs += p2_count
print(f"\n  Phase 2 total: {p2_count} configs, best {p2_best}/24")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: Remove doubled letters (nulls hypothesis)
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("PHASE 3: Remove Doubled Letters (Nulls Hypothesis)")
print("=" * 72)

p3_best = 0
p3_count = 0

double_positions = [(pos, pos + 1) for pos, _ in doubles]
print(f"Double pairs (first, second): {double_positions}")

# Strategy A: remove second of each pair
remove_second = sorted([pos + 1 for pos, _ in doubles], reverse=True)
ct_a = list(CT)
for rp in remove_second:
    ct_a.pop(rp)
ct_a = ''.join(ct_a)
print(f"\n  A: Remove second of each pair: {len(ct_a)} chars")
print(f"    Reduced CT: {ct_a}")

# Strategy B: remove first of each pair
remove_first = sorted([pos for pos, _ in doubles], reverse=True)
ct_b = list(CT)
for rp in remove_first:
    ct_b.pop(rp)
ct_b = ''.join(ct_b)
print(f"\n  B: Remove first of each pair: {len(ct_b)} chars")
print(f"    Reduced CT: {ct_b}")

# Strategy C: remove BOTH letters of each pair (97 - 12 = 85 chars)
remove_both = sorted([pos for pos, _ in doubles] + [pos + 1 for pos, _ in doubles],
                     reverse=True)
ct_c = list(CT)
for rp in remove_both:
    ct_c.pop(rp)
ct_c = ''.join(ct_c)
print(f"\n  C: Remove both letters of each pair: {len(ct_c)} chars")
print(f"    Reduced CT: {ct_c}")

# Build adjusted crib dicts for each reduction
def adjust_crib_for_removal(removals):
    """Adjust crib positions after removing positions from CT."""
    removals_set = set(removals)
    sorted_removals = sorted(removals)
    adjusted = {}
    for pos, ch in CRIB_DICT.items():
        if pos in removals_set:
            continue  # crib position removed
        # Count how many removals are before this position
        shift = sum(1 for r in sorted_removals if r < pos)
        adjusted[pos - shift] = ch
    return adjusted

crib_a = adjust_crib_for_removal([pos + 1 for pos, _ in doubles])
crib_b = adjust_crib_for_removal([pos for pos, _ in doubles])
crib_c = adjust_crib_for_removal(
    [pos for pos, _ in doubles] + [pos + 1 for pos, _ in doubles])

print(f"\n  Adjusted crib sizes: A={len(crib_a)}, B={len(crib_b)}, C={len(crib_c)}")

# Test each reduced CT with various methods
for label, reduced_ct, crib in [('A', ct_a, crib_a), ('B', ct_b, crib_b),
                                  ('C', ct_c, crib_c)]:
    n = len(reduced_ct)
    print(f"\n  --- Strategy {label}: {n} chars ---")

    # Direct match
    sc_direct = quick_crib_score(reduced_ct, crib)
    print(f"    Direct crib score: {sc_direct}/24")
    p3_count += 1

    # IC
    ic_val = ic(reduced_ct)
    print(f"    IC: {ic_val:.4f}")

    # Vig/Beau with KRYPTOS
    pt_v = vig_decrypt(reduced_ct, "KRYPTOS")
    sc_v = quick_crib_score(pt_v, crib)
    pt_b = beau_decrypt(reduced_ct, "KRYPTOS")
    sc_b = quick_crib_score(pt_b, crib)
    print(f"    Vig KRYPTOS: {sc_v}/24, Beau KRYPTOS: {sc_b}/24")
    p3_count += 2

    # Columnar with various widths
    factorizations = []
    for w in range(2, n + 1):
        if n % w == 0:
            factorizations.append(w)
    print(f"    Factorizations of {n}: {factorizations}")

    best_col = 0
    for w in factorizations:
        if w > 26:
            continue
        # Try identity, reverse, KRYPTOS ordering
        orders = [
            ("identity", list(range(w))),
            ("reverse", list(range(w - 1, -1, -1))),
            ("KRYPTOS", keyword_to_order("KRYPTOS", w)),
        ]
        for oname, order in orders:
            untrans = columnar_decrypt(reduced_ct, w, order)
            sc_t = quick_crib_score(untrans, crib)

            pt_vt = vig_decrypt(untrans, "KRYPTOS")
            sc_vt = quick_crib_score(pt_vt, crib)

            pt_bt = beau_decrypt(untrans, "KRYPTOS")
            sc_bt = quick_crib_score(pt_bt, crib)

            sc = max(sc_t, sc_vt, sc_bt)
            p3_count += 3

            if sc > best_col:
                best_col = sc
                if sc > p3_best:
                    p3_best = sc
                    print(f"    NEW BEST: {sc}/24 — w{w}/{oname}")

    sc_strategy = max(sc_direct, sc_v, sc_b, best_col)
    print(f"    Strategy {label} best: {sc_strategy}/24")

    if sc_strategy > p3_best:
        p3_best = sc_strategy

if p3_best > global_best:
    global_best = p3_best
    global_best_config = "Phase 3: Remove doubles"
total_configs += p3_count
print(f"\n  Phase 3 total: {p3_count} configs, best {p3_best}/24")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: Doubled letters as position markers / boundary analysis
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("PHASE 4: Doubled Letters as Position Markers")
print("=" * 72)

p4_best = 0
p4_count = 0

# Define segments between doubles
# Doubles at: 18-19, 25-26, 32-33, 42-43, 46-47, 67-68
# Segments: [0-17], [20-24], [27-31], [34-41], [44-45], [48-66], [69-96]
segments = [
    (0, 17),      # before first double
    (20, 24),     # between BB and QQ
    (27, 31),     # between QQ and SS(32)
    (34, 41),     # between SS(32) and SS(42)
    (44, 45),     # between SS(42) and ZZ
    (48, 66),     # between ZZ and TT
    (69, 96),     # after last double
]

print(f"\nSegments between doubled digraphs:")
for i, (start, end) in enumerate(segments):
    seg_text = CT[start:end + 1]
    seg_len = end - start + 1
    print(f"  Segment {i}: [{start:2d}-{end:2d}] len={seg_len:2d}: {seg_text}")

seg_lengths = [end - start + 1 for start, end in segments]
print(f"\nSegment lengths: {seg_lengths}")
print(f"Sum of segment lengths: {sum(seg_lengths)} (vs 97 - 12 = 85 non-double chars)")

# Read first chars of each segment
first_chars = [CT[start] for start, _ in segments]
last_chars = [CT[end] for _, end in segments]
print(f"\nFirst char of each segment: {''.join(first_chars)}")
print(f"Last char of each segment:  {''.join(last_chars)}")

# Read chars AT doubled positions (the doubled letter itself)
double_chars = [CT[pos] for pos, _ in doubles]
print(f"Characters at double positions: {''.join(double_chars)} = BQSSZT")

# Concatenate just the segments (removing doubles)
seg_text = ''.join(CT[start:end + 1] for start, end in segments)
print(f"\nConcatenated segments (no doubles): {seg_text}")
print(f"Length: {len(seg_text)}")
sc_seg = quick_crib_score(seg_text, adjust_crib_for_removal(
    [pos for pos, _ in doubles] + [pos + 1 for pos, _ in doubles]))
print(f"Crib score on segments: {sc_seg}/24")
p4_count += 1

# Try reading segments in reverse order
seg_rev = ''.join(CT[start:end + 1] for start, end in reversed(segments))
print(f"Segments reversed: {seg_rev}")
print(f"Length: {len(seg_rev)}")
p4_count += 1

# Try interleaving odd/even segments
odd_segs = [CT[start:end + 1] for i, (start, end) in enumerate(segments) if i % 2 == 1]
even_segs = [CT[start:end + 1] for i, (start, end) in enumerate(segments) if i % 2 == 0]
print(f"\nOdd segments:  {'|'.join(odd_segs)}")
print(f"Even segments: {'|'.join(even_segs)}")

# Read segment lengths as key values
print(f"\nSegment lengths as key: {seg_lengths}")
seg_key = [l % 26 for l in seg_lengths]
print(f"Segment lengths mod 26: {seg_key}")
if len(seg_key) > 0:
    pt_v = vig_decrypt(CT, seg_key)
    sc_v = quick_crib_score(pt_v)
    pt_b = beau_decrypt(CT, seg_key)
    sc_b = quick_crib_score(pt_b)
    print(f"Vig with segment-length key (period {len(seg_key)}): {sc_v}/24")
    print(f"Beau with segment-length key: {sc_b}/24")
    p4_count += 2
    p4_best = max(p4_best, sc_v, sc_b)

# Segments of the KNOWN PLAINTEXT at double positions
print(f"\nWhat falls at doubled positions in known plaintext?")
for pos, ch in doubles:
    pt_at_pos = CRIB_DICT.get(pos, '?')
    pt_at_pos1 = CRIB_DICT.get(pos + 1, '?')
    print(f"  {ch}{ch} at {pos}-{pos+1}: PT = {pt_at_pos}{pt_at_pos1}")

if p4_best > global_best:
    global_best = p4_best
    global_best_config = "Phase 4: Segment analysis"
total_configs += p4_count
print(f"\n  Phase 4 total: {p4_count} configs, best {p4_best}/24")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: CC insertion near existing C + width-7 columnar exhaustive
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("PHASE 5: CC Insertion Near Existing C's + Width-7 Columnar Exhaustive")
print("=" * 72)

p5_best = 0
p5_count = 0

# C positions in CT: 82 and 95
# Insert C at: position 82 (before C@82 → CC at 82-83)
#              position 83 (after C@82 → CC at 82-83)
#              position 95 (before C@95 → CC at 95-96)
#              position 96 (after C@95 → CC at 95-96)
#              position 82, inserting another C to make 98 chars

insert_positions_c = [82, 83, 95, 96]
print(f"C positions in CT: {c_positions}")
print(f"Testing C insertion at: {insert_positions_c}")
print(f"Each: 5040 orderings x 2 ciphers = 10,080 configs")
print(f"Total: {len(insert_positions_c)} x 10,080 = {len(insert_positions_c) * 10080} configs")
print()

for insert_pos in insert_positions_c:
    extended = CT[:insert_pos] + 'C' + CT[insert_pos:]
    assert len(extended) == 98
    shifted = shifted_crib_dict(insert_pos, 1)

    # Verify CC exists
    new_doubles = find_doubles(extended)
    cc_present = any(ch == 'C' for _, ch in new_doubles)
    cc_pos = [p for p, ch in new_doubles if ch == 'C']
    print(f"  C@{insert_pos}: CC at positions {cc_pos}, "
          f"total doubles: {len(new_doubles)}")

    pos_best = 0

    for order in itertools.permutations(range(7)):
        order = list(order)
        untrans = columnar_decrypt(extended, 7, order)

        # Vigenere KRYPTOS
        pt_v = vig_decrypt(untrans, "KRYPTOS")
        sc_v_orig = quick_crib_score(pt_v)
        sc_v_shift = quick_crib_score(pt_v, shifted)
        sc_v = max(sc_v_orig, sc_v_shift)

        # Beaufort KRYPTOS
        pt_b = beau_decrypt(untrans, "KRYPTOS")
        sc_b_orig = quick_crib_score(pt_b)
        sc_b_shift = quick_crib_score(pt_b, shifted)
        sc_b = max(sc_b_orig, sc_b_shift)

        sc = max(sc_v, sc_b)
        variant = 'vig' if sc_v >= sc_b else 'beau'
        pt = pt_v if sc_v >= sc_b else pt_b
        p5_count += 2

        if sc > pos_best:
            pos_best = sc
        if sc > p5_best:
            p5_best = sc
            cfg = f"C@{insert_pos}/w7/{order}/{variant}"
            print(f"  NEW BEST: {sc}/24 — {cfg}")
            if sc >= 8:
                print(f"    PT: {pt}")
            if sc >= 10:
                results.append({
                    'phase': 5, 'score': sc, 'insert_pos': insert_pos,
                    'order': order, 'variant': variant, 'pt': pt[:80],
                })

    print(f"    C@{insert_pos}: best {pos_best}/24")

if p5_best > global_best:
    global_best = p5_best
    global_best_config = "Phase 5: CC insertion + w7 exhaustive"
total_configs += p5_count
print(f"\n  Phase 5 total: {p5_count} configs, best {p5_best}/24")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: Doubled letters as cryptographic key material
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("PHASE 6: Doubled Letters as Key Material")
print("=" * 72)

p6_best = 0
p6_count = 0

# Key Model 1: BQSSZT as Vigenere/Beaufort key (period 6)
key_letters = 'BQSSZT'
key_vals = [ALPH_IDX[c] for c in key_letters]
print(f"\n  Key model 1: BQSSZT as key (period 6)")
print(f"    Values: {key_vals}")

pt_v = vig_decrypt(CT, key_vals)
sc_v = quick_crib_score(pt_v)
pt_b = beau_decrypt(CT, key_vals)
sc_b = quick_crib_score(pt_b)
print(f"    Vig: {sc_v}/24  PT: {pt_v[:50]}...")
print(f"    Beau: {sc_b}/24  PT: {pt_b[:50]}...")
p6_count += 2
p6_best = max(p6_best, sc_v, sc_b)

# Key Model 2: BBQQSSSSZZTТ — actual doubled chars (period 12)
key_doubled = 'BBQQSSSSZZTT'
key_vals_d = [ALPH_IDX[c] for c in key_doubled]
print(f"\n  Key model 2: BBQQSSSSZZTT as key (period 12)")
print(f"    Values: {key_vals_d}")

pt_v = vig_decrypt(CT, key_vals_d)
sc_v = quick_crib_score(pt_v)
pt_b = beau_decrypt(CT, key_vals_d)
sc_b = quick_crib_score(pt_b)
print(f"    Vig: {sc_v}/24  PT: {pt_v[:50]}...")
print(f"    Beau: {sc_b}/24  PT: {pt_b[:50]}...")
p6_count += 2
p6_best = max(p6_best, sc_v, sc_b)

# Key Model 3: Positions of doubles as key values
# [18, 25, 32, 42, 46, 67] mod 26 = [18, 25, 6, 16, 20, 15]
key_pos = [p % 26 for p in positions]
print(f"\n  Key model 3: Double positions mod 26 as key (period 6)")
print(f"    Positions: {positions}")
print(f"    Mod 26: {key_pos}")
print(f"    As letters: {''.join(ALPH[k] for k in key_pos)}")

pt_v = vig_decrypt(CT, key_pos)
sc_v = quick_crib_score(pt_v)
pt_b = beau_decrypt(CT, key_pos)
sc_b = quick_crib_score(pt_b)
print(f"    Vig: {sc_v}/24  PT: {pt_v[:50]}...")
print(f"    Beau: {sc_b}/24  PT: {pt_b[:50]}...")
p6_count += 2
p6_best = max(p6_best, sc_v, sc_b)

# Key Model 4: Spacings as key
# [7, 7, 10, 4, 21]
key_spacings = spacings
print(f"\n  Key model 4: Spacings as key (period {len(spacings)})")
print(f"    Spacings: {spacings}")

pt_v = vig_decrypt(CT, key_spacings)
sc_v = quick_crib_score(pt_v)
pt_b = beau_decrypt(CT, key_spacings)
sc_b = quick_crib_score(pt_b)
print(f"    Vig: {sc_v}/24  PT: {pt_v[:50]}...")
print(f"    Beau: {sc_b}/24  PT: {pt_b[:50]}...")
p6_count += 2
p6_best = max(p6_best, sc_v, sc_b)

# Key Model 5: Position values directly (period 6)
key_pos_raw = positions  # [18, 25, 32, 42, 46, 67]
print(f"\n  Key model 5: Raw positions as key (period 6, vals mod 26)")
print(f"    Raw: {positions}")

pt_v = vig_decrypt(CT, [p % 26 for p in key_pos_raw])
sc_v = quick_crib_score(pt_v)
pt_b = beau_decrypt(CT, [p % 26 for p in key_pos_raw])
sc_b = quick_crib_score(pt_b)
print(f"    Vig: {sc_v}/24")
print(f"    Beau: {sc_b}/24")
p6_count += 2
p6_best = max(p6_best, sc_v, sc_b)

# Key Model 6: Add CC (C=2) to doubled letters → BCSQSSZT or BCQSSZT, etc.
# Try inserting C at each position in BQSSZT
print(f"\n  Key model 6: Insert C into BQSSZT at each position")
for insert_i in range(len(key_letters) + 1):
    augmented = key_letters[:insert_i] + 'C' + key_letters[insert_i:]
    aug_vals = [ALPH_IDX[c] for c in augmented]

    pt_v = vig_decrypt(CT, aug_vals)
    sc_v = quick_crib_score(pt_v)
    pt_b = beau_decrypt(CT, aug_vals)
    sc_b = quick_crib_score(pt_b)
    p6_count += 2

    sc = max(sc_v, sc_b)
    if sc > p6_best:
        p6_best = sc
        print(f"    NEW BEST: {sc}/24 — key={augmented}")
    if sc >= 5:
        print(f"    {augmented}: vig={sc_v}, beau={sc_b}")

# Key Model 7: CHARLIE (7 letters) as key (Checkpoint Charlie)
print(f"\n  Key model 7: CHARLIE as key (period 7)")
pt_v = vig_decrypt(CT, "CHARLIE")
sc_v = quick_crib_score(pt_v)
pt_b = beau_decrypt(CT, "CHARLIE")
sc_b = quick_crib_score(pt_b)
print(f"    Vig: {sc_v}/24  PT: {pt_v[:50]}...")
print(f"    Beau: {sc_b}/24  PT: {pt_b[:50]}...")
p6_count += 2
p6_best = max(p6_best, sc_v, sc_b)

# Key Model 8: CHECKPOINT as key
for kw in ["CHECKPOINT", "CHECKPOINTCHARLIE", "CC"]:
    pt_v = vig_decrypt(CT, kw)
    sc_v = quick_crib_score(pt_v)
    pt_b = beau_decrypt(CT, kw)
    sc_b = quick_crib_score(pt_b)
    print(f"\n  Key '{kw}': vig={sc_v}/24, beau={sc_b}/24")
    p6_count += 2
    p6_best = max(p6_best, sc_v, sc_b)

# Key Model 9: Doubled letters + columnar transposition
print(f"\n  Key model 9: BQSSZT key + columnar KRYPTOS w7")
for key_model_name, key_model in [
    ("BQSSZT", key_vals),
    ("positions", key_pos),
    ("spacings", key_spacings),
    ("CHARLIE", [ALPH_IDX[c] for c in "CHARLIE"]),
]:
    # Columnar first, then substitute
    untrans = columnar_decrypt(CT, 7, KRYPTOS_ORDER_7)
    pt_v = vig_decrypt(untrans, key_model)
    sc_v = quick_crib_score(pt_v)
    pt_b = beau_decrypt(untrans, key_model)
    sc_b = quick_crib_score(pt_b)
    sc = max(sc_v, sc_b)
    print(f"    w7-KRYPTOS + {key_model_name}: vig={sc_v}, beau={sc_b}")
    p6_count += 2

    # Substitute first, then columnar
    pt_v2 = vig_decrypt(CT, key_model)
    untrans_v = columnar_decrypt(pt_v2, 7, KRYPTOS_ORDER_7)
    sc_v2 = quick_crib_score(untrans_v)
    pt_b2 = beau_decrypt(CT, key_model)
    untrans_b = columnar_decrypt(pt_b2, 7, KRYPTOS_ORDER_7)
    sc_b2 = quick_crib_score(untrans_b)
    print(f"    {key_model_name} + w7-KRYPTOS: vig={sc_v2}, beau={sc_b2}")
    p6_count += 2

    sc_all = max(sc, sc_v2, sc_b2)
    if sc_all > p6_best:
        p6_best = sc_all

if p6_best > global_best:
    global_best = p6_best
    global_best_config = "Phase 6: Doubles as key"
total_configs += p6_count
print(f"\n  Phase 6 total: {p6_count} configs, best {p6_best}/24")

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: Statistical significance of doubled-letter count
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("PHASE 7: Statistical Significance of 6 Doubled Letters")
print("=" * 72)

# In a random 97-char text with uniform letter distribution:
# Each adjacent pair (96 pairs) has P(match) = 1/26
# Expected doubles = 96/26 ≈ 3.692
# Using Poisson approximation or exact binomial

n_pairs = CT_LEN - 1  # 96
p_double = 1.0 / 26
expected = n_pairs * p_double
print(f"\n  Random model: 96 adjacent pairs, P(match) = 1/26")
print(f"  Expected doubles: {expected:.3f}")
print(f"  Observed doubles: {len(doubles)}")

# Exact binomial P(X >= 6) where X ~ Bin(96, 1/26)
# P(X >= 6) = 1 - P(X <= 5)
from math import comb as _comb, factorial as _fact

def binom_pmf(k, n, p):
    return _comb(n, k) * (p ** k) * ((1 - p) ** (n - k))

def binom_cdf(k, n, p):
    return sum(binom_pmf(i, n, p) for i in range(k + 1))

p_ge_6 = 1 - binom_cdf(5, n_pairs, p_double)
p_ge_observed = 1 - binom_cdf(len(doubles) - 1, n_pairs, p_double)

print(f"\n  Exact binomial calculation:")
print(f"  P(X = k) for k = 0..10:")
for k in range(11):
    pk = binom_pmf(k, n_pairs, p_double)
    marker = " <-- OBSERVED" if k == len(doubles) else ""
    print(f"    P(X={k:2d}) = {pk:.6f}{marker}")

print(f"\n  P(X >= 6) = {p_ge_6:.6f}")
print(f"  P(X >= {len(doubles)}) = {p_ge_observed:.6f}")

# Monte Carlo verification
import random
random.seed(42)
N_SIMS = 100_000
double_counts = []
for _ in range(N_SIMS):
    text = ''.join(random.choice(ALPH) for _ in range(CT_LEN))
    count = sum(1 for i in range(len(text) - 1) if text[i] == text[i + 1])
    double_counts.append(count)

mc_ge_6 = sum(1 for c in double_counts if c >= 6) / N_SIMS
mc_mean = sum(double_counts) / N_SIMS
mc_std = (sum((c - mc_mean) ** 2 for c in double_counts) / N_SIMS) ** 0.5

print(f"\n  Monte Carlo verification ({N_SIMS:,} simulations):")
print(f"  Mean doubles in random 97-char text: {mc_mean:.3f}")
print(f"  Std dev: {mc_std:.3f}")
print(f"  P(X >= 6) via MC: {mc_ge_6:.6f}")
print(f"  Z-score of observed (6): {(len(doubles) - mc_mean) / mc_std:.2f}")

# Distribution of double counts in MC
from collections import Counter as _Counter
dist = _Counter(double_counts)
print(f"\n  Distribution of doubles in random text:")
for k in sorted(dist.keys()):
    pct = dist[k] / N_SIMS * 100
    print(f"    {k:2d} doubles: {dist[k]:6d} ({pct:.2f}%)")

# Is K4's letter distribution relevant? (Some letters appear more often)
letter_freq = Counter(CT)
print(f"\n  K4 letter frequencies (top 10):")
for ch, count in letter_freq.most_common(10):
    print(f"    {ch}: {count}")

# Expected doubles given K4's actual letter frequencies
# P(pair i matches) = sum_c (freq[c]/97) * (freq[c]/97)
# But actually adjacent pairs, so it's more like P = sum_c (freq_c / n)^2
p_match_actual = sum((f / CT_LEN) ** 2 for f in letter_freq.values())
expected_actual = n_pairs * p_match_actual
print(f"\n  Expected doubles given K4's letter distribution:")
print(f"  P(adjacent match) = {p_match_actual:.6f} (vs uniform {p_double:.6f})")
print(f"  Expected: {expected_actual:.3f}")
print(f"  Observed: {len(doubles)}")
p_ge_6_actual = 1 - binom_cdf(5, n_pairs, p_match_actual)
print(f"  P(X >= 6 | K4 frequencies) = {p_ge_6_actual:.6f}")

is_significant = p_ge_6 < 0.05
print(f"\n  CONCLUSION: 6 doubles is {'STATISTICALLY SIGNIFICANT' if is_significant else 'NOT statistically significant'} (p={p_ge_6:.4f}, threshold=0.05)")
print(f"  Z-score: {(len(doubles) - mc_mean) / mc_std:.2f}")

# ═══════════════════════════════════════════════════════════════════════════════
# BONUS: Cross-cutting analysis — doubled positions vs crib positions
# ═══════════════════════════════════════════════════════════════════════════════

print(f"\n{'=' * 72}")
print("BONUS: Doubles-Crib Relationship Analysis")
print("=" * 72)

print(f"\nDoubled positions: {positions} (first char of each pair)")
print(f"Crib ranges: 21-33 (ENE), 63-73 (BC)")

# Which doubles fall within crib ranges?
doubles_in_ene = [(p, ch) for p, ch in doubles if 21 <= p <= 33 or 21 <= p + 1 <= 33]
doubles_in_bc = [(p, ch) for p, ch in doubles if 63 <= p <= 73 or 63 <= p + 1 <= 73]
doubles_outside = [(p, ch) for p, ch in doubles
                   if not (21 <= p <= 33 or 21 <= p + 1 <= 33)
                   and not (63 <= p <= 73 or 63 <= p + 1 <= 73)]

print(f"\nDoubles in ENE crib range: {doubles_in_ene}")
print(f"Doubles in BC crib range:  {doubles_in_bc}")
print(f"Doubles outside cribs:     {doubles_outside}")

# The SS at 32-33 is at the END of ENE (position 32='S'=EASTNORTHEAS'T', pos 33='T')
# Actually position 32 is 'S' in CT and crib says PT[32]='S' → self-encrypting!
# And position 33 is crib PT[33]='T'
print(f"\nSS at 32-33:")
print(f"  CT[32] = {CT[32]}, PT[32] = {CRIB_DICT.get(32, '?')}")
print(f"  CT[33] = {CT[33]}, PT[33] = {CRIB_DICT.get(33, '?')}")
print(f"  Self-encrypting at 32: CT=PT=S (key=0!)")

# TT at 67-68 overlaps BC
print(f"\nTT at 67-68:")
print(f"  CT[67] = {CT[67]}, PT[67] = {CRIB_DICT.get(67, '?')}")
print(f"  CT[68] = {CT[68]}, PT[68] = {CRIB_DICT.get(68, '?')}")

# What key values do the doubles produce at crib positions?
print(f"\nKey values at doubled-crib intersections (Vigenere K = CT - PT mod 26):")
for pos, ch in doubles:
    for p in [pos, pos + 1]:
        if p in CRIB_DICT:
            ct_val = ALPH_IDX[CT[p]]
            pt_val = ALPH_IDX[CRIB_DICT[p]]
            k_vig = (ct_val - pt_val) % 26
            k_beau = (ct_val + pt_val) % 26
            print(f"  Position {p}: CT={CT[p]}({ct_val}), PT={CRIB_DICT[p]}({pt_val})"
                  f" → Vig key={k_vig}({ALPH[k_vig]}), Beau key={k_beau}({ALPH[k_beau]})")

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

elapsed = time.time() - t0
print(f"\n{'=' * 72}")
print(f"E-BESPOKE-06: Doubled-Letter Analysis — FINAL SUMMARY")
print(f"{'=' * 72}")
print(f"Total configs tested: {total_configs:,}")
print(f"Time: {elapsed:.1f}s ({elapsed / 60:.1f}m)")
print()
print(f"Phase 1 (structural analysis):       (descriptive)")
print(f"Phase 2 (insert C/CC):               best {p2_best}/24")
print(f"Phase 3 (remove doubles as nulls):   best {p3_best}/24")
print(f"Phase 4 (segment/marker analysis):   best {p4_best}/24")
print(f"Phase 5 (CC near C + w7 exhaustive): best {p5_best}/24")
print(f"Phase 6 (doubles as key):            best {p6_best}/24")
print(f"Phase 7 (statistical significance):  p={p_ge_6:.4f}, z={(len(doubles) - mc_mean) / mc_std:.2f}")
print()
print(f"GLOBAL BEST: {global_best}/24")

if global_best <= 6:
    classification = "NOISE"
elif global_best <= 9:
    classification = "NOISE (marginal)"
elif global_best <= 17:
    classification = "STORE"
else:
    classification = "SIGNAL — INVESTIGATE!"

print(f"CLASSIFICATION: {classification}")

print(f"\nKey structural findings:")
print(f"  Doubled digraphs: BB(18), QQ(25), SS(32), SS(42), ZZ(46), TT(67)")
print(f"  Spacings: {spacings} (7, 7, 10, 4, 21)")
print(f"  Letters: BQSSZT  |  Values: {letter_vals}")
print(f"  Positions mod 26 as letters: {''.join(pos_as_letters)}")
print(f"  C positions in CT: {c_positions} — no CC exists")
print(f"  SS(32) is self-encrypting (CT=PT=S, key=0)")
print(f"  6 doubles: p={p_ge_6:.4f} (NOT statistically significant at p<0.05)"
      if not is_significant else
      f"  6 doubles: p={p_ge_6:.4f} (STATISTICALLY SIGNIFICANT at p<0.05)")
print(f"{'=' * 72}")

# ── Save results ──────────────────────────────────────────────────────────────

os.makedirs('results', exist_ok=True)

output = {
    'experiment': 'E-BESPOKE-06',
    'description': 'Doubled-letter digraph analysis and CC insertion hypothesis',
    'theory': (
        'K4 has 6 doubled digraphs: BB QQ SS SS ZZ TT (5 distinct letters). '
        'CC is absent. Checkpoint Charlie = NATO C. '
        'Missing CC might be deliberate — insert to reveal structure. '
        'Doubles might be nulls, markers, or encode a key.'
    ),
    'total_configs': total_configs,
    'elapsed_seconds': round(elapsed, 1),
    'global_best': global_best,
    'classification': classification,
    'structural_findings': {
        'doubles': [(pos, ch) for pos, ch in doubles],
        'spacings': spacings,
        'letters': double_letters_str,
        'letter_values': letter_vals,
        'c_positions_in_ct': c_positions,
        'statistical_significance': {
            'p_value': round(p_ge_6, 6),
            'z_score': round((len(doubles) - mc_mean) / mc_std, 2),
            'significant': is_significant,
            'expected_doubles': round(expected, 3),
            'observed_doubles': len(doubles),
        },
    },
    'phase_results': {
        'phase2_insert_c_cc': {'configs': p2_count, 'best': p2_best},
        'phase3_remove_nulls': {'configs': p3_count, 'best': p3_best},
        'phase4_markers': {'configs': p4_count, 'best': p4_best},
        'phase5_cc_w7_exhaustive': {'configs': p5_count, 'best': p5_best},
        'phase6_doubles_as_key': {'configs': p6_count, 'best': p6_best},
    },
    'notable_results': [r for r in results if r.get('score', 0) >= 8],
}

with open('results/e_bespoke_06_doubles_cc.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"\nArtifact: results/e_bespoke_06_doubles_cc.json")
