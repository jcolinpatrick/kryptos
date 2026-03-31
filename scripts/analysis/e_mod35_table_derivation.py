#!/usr/bin/env python3
"""
Mod-35 Table Derivation — Comprehensive Search for Installation-Derived Rule

TASK: Find what TRANSCRIBABLE installation data generates the exact 7x5
binary classification table that perfectly separates null from non-null
palette positions in K4.

The target table has 35 cells (7 rows x 5 cols). Only 26 are occupied by
palette positions. Those 26 cells classify as:
  10 pure-null, 13 pure-real, 3 mixed (first-occurrence = null)

We search over all simple rules derivable from installation parameters.

Output: results/mod35_table_derivation.json
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import sys
import os
import json
from collections import defaultdict
from itertools import product, combinations
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, KRYPTOS_ALPHABET, ALPH

# ══════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════
PALETTE = frozenset('BGIKOWZ')
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})

KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = {c: i for i, c in enumerate(ALPH)}

palette_positions = sorted(p for p in range(CT_LEN) if CT[p] in PALETTE)
labels = {p: p in CONSENSUS_NULLS for p in palette_positions}  # True = null

# Build the target table
cell_positions = defaultdict(list)
for p in palette_positions:
    cell_positions[(p % 7, p % 5)].append(p)

target_table = {}  # (r,c) -> True (null) or False (real) -- for occupied, non-mixed cells
                    # Mixed cells: True for first, False for later
for r in range(7):
    for c in range(5):
        positions = cell_positions.get((r, c), [])
        if not positions:
            target_table[(r, c)] = None  # empty
        else:
            null_count = sum(1 for p in positions if labels[p])
            real_count = len(positions) - null_count
            if null_count > 0 and real_count == 0:
                target_table[(r, c)] = True  # null
            elif real_count > 0 and null_count == 0:
                target_table[(r, c)] = False  # real
            else:
                target_table[(r, c)] = 'mixed'

# The 35-bit target: for each (r,c), what classification?
# For occupied cells: null=1, real=0. For mixed: treat as null (since we need "null-ish" classification)
# For empty: we don't care, so we'll track which cells we must match
occupied_cells = [(r, c) for r in range(7) for c in range(5) if target_table[(r, c)] is not None]
occupied_non_mixed = [(r, c) for (r, c) in occupied_cells if target_table[(r, c)] != 'mixed']
mixed_cells = [(r, c) for (r, c) in occupied_cells if target_table[(r, c)] == 'mixed']

# For matching: we need the 23 non-mixed occupied cells correct
# Mixed cells (3) can go either way depending on tiebreaker
# Target binary for non-mixed: 1 = null, 0 = real
target_binary_nm = {(r, c): (1 if target_table[(r, c)] else 0) for (r, c) in occupied_non_mixed}

# Full 35-bit target: null/mixed -> 1, real -> 0, empty -> don't care
# We'll treat mixed as "null-leaning" for the 35-bit representation
target_35bit = 0
for r in range(7):
    for c in range(5):
        bit_idx = r * 5 + c
        val = target_table[(r, c)]
        if val is True or val == 'mixed':
            target_35bit |= (1 << (34 - bit_idx))

# Also compute: for the 26 occupied cells, the 26-bit signature
target_26bit = 0
occupied_sorted = sorted(occupied_cells)
for i, (r, c) in enumerate(occupied_sorted):
    val = target_table[(r, c)]
    if val is True or val == 'mixed':
        target_26bit |= (1 << (25 - i))

print("=" * 90)
print("MOD-35 TABLE DERIVATION — COMPREHENSIVE SEARCH")
print("=" * 90)

# ══════════════════════════════════════════════════════════════════════════
# STEP 1: Reconstruct and verify the exact target table
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STEP 1: TARGET TABLE (verified from raw data)")
print("=" * 90)

print(f"\nPalette positions (35 total): {palette_positions}")
print(f"Null palette (17): {sorted(p for p in palette_positions if labels[p])}")
print(f"Real palette (18): {sorted(p for p in palette_positions if not labels[p])}")

print(f"\n7x5 Classification Table:")
print(f"{'':>10}", end="")
for c5 in range(5):
    print(f"  c={c5}", end="")
print()
for r7 in range(7):
    print(f"  r={r7}:  ", end="")
    for c5 in range(5):
        val = target_table[(r7, c5)]
        if val is None:
            s = "  -  "
        elif val is True:
            s = "  N  "
        elif val is False:
            s = "  R  "
        else:
            s = " N/R "
        print(s, end="")
    print()

print(f"\nOccupied cells: {len(occupied_cells)} (10 null + 13 real + 3 mixed)")
print(f"Empty cells: {35 - len(occupied_cells)}")
print(f"Target 35-bit number: {target_35bit} = 0b{target_35bit:035b}")
print(f"Target 26-bit (occupied only): {target_26bit} = 0b{target_26bit:026b}")

# Verify the table is correct by re-checking all 35 palette positions
verify_correct = 0
for p in palette_positions:
    cell = (p % 7, p % 5)
    val = target_table[cell]
    if val is True:
        predicted_null = True
    elif val is False:
        predicted_null = False
    elif val == 'mixed':
        # First occurrence in cell = null
        predicted_null = (p == min(cell_positions[cell]))
    else:
        predicted_null = False
    if predicted_null == labels[p]:
        verify_correct += 1
    else:
        print(f"  VERIFY ERROR: pos={p} CT={CT[p]} cell={cell} predicted={predicted_null} actual={labels[p]}")
print(f"\nVerification: {verify_correct}/35 correct")
assert verify_correct == 35, "Table verification failed!"

# ══════════════════════════════════════════════════════════════════════════
# STEP 2: Installation parameters
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("STEP 2: INSTALLATION PARAMETERS")
print("=" * 90)

KRYPTOS_WORD = 'KRYPTOS'
KRYPTOS_AZ = [AZ_IDX[c] for c in KRYPTOS_WORD]  # [10,17,24,15,19,14,18]
KRYPTOS_KA = [KA_IDX[c] for c in KRYPTOS_WORD]   # [0,1,2,3,4,5,6]

FIVE_LETTER_WORDS = [
    'SEVEN', 'CLOCK', 'LIGHT', 'FIELD', 'FORCE', 'NORTH', 'SOUTH',
    'MORSE', 'POINT', 'WHEEL', 'EARTH', 'WATER', 'STONE', 'SHADE',
    'LAYER', 'PULSE', 'QUEST', 'LUCID', 'PHASE', 'CYLIC', 'SHIFT',
    'CROSS', 'ANGLE', 'BENCH', 'PAUSE', 'SOLVE', 'THINK', 'PLAIN',
    'CRAFT', 'DOUBT', 'AGENT', 'CRYPT', 'GRAIL', 'PANEL', 'STEEL',
    'PRISM', 'GLASS', 'NIGHT', 'EGYPT', 'PEELS', 'OBEYS', 'DYAHR',
    'MASKS', 'NULLS', 'HOLES', 'STICK', 'LEVEL', 'TOWER', 'SIGMA',
    'DELTA', 'ALPHA', 'BRAVO', 'OSCAR', 'INDIA', 'KILO!',  # NATO
]
# Remove any with non-alpha chars
FIVE_LETTER_WORDS = [w for w in FIVE_LETTER_WORDS if w.isalpha() and len(w) == 5]

# Add some derived from installation
FIVE_LETTER_WORDS.extend(['TABUL', 'CHART', 'LEGAL', 'SHEET'])

# Also test all 5-letter substrings of KRYPTOS alphabet and key phrases
for phrase in ['KRYPTOSABCDEF', 'EASTNORTHEAST', 'BERLINCLOCK', 'PALIMPSEST', 'ABSCISSA', 'DEFECTOR']:
    for i in range(len(phrase) - 4):
        w = phrase[i:i+5]
        if w not in FIVE_LETTER_WORDS:
            FIVE_LETTER_WORDS.append(w)

# Unique only
FIVE_LETTER_WORDS = list(dict.fromkeys(FIVE_LETTER_WORDS))

# Installation numbers
INSTALL_NUMS = {
    'grid_width': 31,
    'grid_height': 28,
    'k4_row': 24,
    'k4_col': 27,
    'k4_len': 97,
    'real_chars': 73,
    'null_count': 24,
    'alpha_size': 26,
    'kryptos_len': 7,
    'ene_start': 21,
    'ene_end': 33,
    'bc_start': 63,
    'bc_end': 73,
    'ene_len': 13,
    'bc_len': 11,
    'five': 5,
    'seven': 7,
    'thirtyfive': 35,
    'lat_deg': 38,
    'lat_min': 57,
    'lat_sec_int': 6,
    'lat_sec_frac': 5,
    'lon_deg': 77,
    'lon_min': 8,
    'lon_sec': 44,
    'compass': 66,
}

print(f"Testing {len(FIVE_LETTER_WORDS)} five-letter words")
print(f"Testing {len(INSTALL_NUMS)} installation numbers")

results = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'target_35bit': target_35bit,
    'target_35bit_bin': f'0b{target_35bit:035b}',
    'target_26bit': target_26bit,
    'occupied_cells': len(occupied_cells),
    'matches': [],
    'near_misses': [],
}

def hamming_distance_table(candidate_table):
    """Compute Hamming distance between candidate and target on occupied non-mixed cells."""
    dist = 0
    for (r, c) in occupied_non_mixed:
        cand = candidate_table.get((r, c))
        tgt = target_binary_nm[(r, c)]
        if cand is None:
            dist += 1  # No prediction = wrong
        elif cand != tgt:
            dist += 1
    return dist

def hamming_full(candidate_table):
    """Distance on all 26 occupied cells (treat mixed as null=1)."""
    dist = 0
    for (r, c) in occupied_cells:
        cand = candidate_table.get((r, c))
        tgt = target_table[(r, c)]
        if tgt == 'mixed':
            tgt_bit = 1  # null-leaning
        else:
            tgt_bit = 1 if tgt else 0
        if cand is None:
            cand_bit = 0  # default real
        else:
            cand_bit = cand
        if cand_bit != tgt_bit:
            dist += 1
    return dist

def record_match(dist, description, table_dict=None):
    entry = {'distance': dist, 'description': description}
    if table_dict:
        entry['table'] = {f"({r},{c})": v for (r, c), v in sorted(table_dict.items())}
    if dist == 0:
        results['matches'].append(entry)
        print(f"  *** EXACT MATCH: {description} ***")
    elif dist <= 2:
        results['near_misses'].append(entry)

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2a: KA alphabet position mod operations
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2a: KA POSITION MOD OPERATIONS")
print("=" * 90)

# For each palette letter, its KA position
# B=8, G=13, I=15, K=0, O=5, W=23, Z=25
palette_ka = {c: KA_IDX[c] for c in PALETTE}
print(f"Palette KA positions: {palette_ka}")

# Test: use (KA_val mod 7, KA_val mod 5) as the cell in the table
# This maps each LETTER to a cell, not each POSITION
print("\nTest: (KA_val mod 7, KA_val mod 5) mapping:")
for c in sorted(PALETTE):
    ka = KA_IDX[c]
    r7, c5 = ka % 7, ka % 5
    # All positions with this letter share the same cell
    pos_list = [p for p in palette_positions if CT[p] == c]
    null_pos = [p for p in pos_list if labels[p]]
    real_pos = [p for p in pos_list if not labels[p]]
    print(f"  {c} KA={ka:>2} -> ({r7},{c5}): {len(null_pos)}N/{len(real_pos)}R positions")

# This doesn't work directly because different positions with the same letter
# can be null or real. But let's check if the letter-based cell assignment
# matches the position-based one for non-mixed cases.

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2b: THRESHOLD RULES on (a*r + b*c + d) mod M
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2b: LINEAR RULES (a*r + b*c + d) mod M")
print("=" * 90)

# For each cell (r,c) in 7x5, compute (a*r + b*c + d) mod M
# Then check if there's a threshold T such that value >= T <=> null
# Use KRYPTOS AZ values for rows and various word AZ values for columns

best_linear = {'dist': 99, 'desc': ''}
linear_exact = 0

# Row encodings: direct (0-6), KRYPTOS AZ values, KRYPTOS KA values
row_encodings = {
    'direct': list(range(7)),
    'KW_AZ': KRYPTOS_AZ,
    'KW_KA': KRYPTOS_KA,
}

for word in FIVE_LETTER_WORDS:
    word_az = [AZ_IDX[c] for c in word]
    word_ka = [KA_IDX[c] for c in word]

    for col_name, col_vals in [('AZ', word_az), ('KA', word_ka)]:
        for row_name, row_vals in row_encodings.items():
            # Operations: sum, diff, beaufort, product
            for op_name, op_func in [
                ('sum', lambda rv, cv: (rv + cv)),
                ('diff', lambda rv, cv: (rv - cv)),
                ('beau', lambda rv, cv: (cv - rv)),
                ('prod', lambda rv, cv: (rv * cv)),
                ('xor', lambda rv, cv: (rv ^ cv)),
            ]:
                for M in range(2, 36):
                    # Compute value for each occupied cell
                    cell_vals = {}
                    for (r, c) in occupied_cells:
                        v = op_func(row_vals[r], col_vals[c]) % M
                        cell_vals[(r, c)] = v

                    # Try every possible threshold set
                    all_vals = set(cell_vals.values())
                    if len(all_vals) < 2:
                        continue

                    # For each subset of values that could be "null"
                    # More efficient: just try each threshold
                    for threshold in range(M):
                        # null if value >= threshold
                        candidate = {}
                        for (r, c) in occupied_cells:
                            candidate[(r, c)] = 1 if cell_vals[(r, c)] >= threshold else 0
                        dist = hamming_full(candidate)
                        if dist < best_linear['dist']:
                            best_linear = {'dist': dist, 'desc': f"{word}:{col_name}+{row_name} op={op_name} mod {M} thresh>={threshold}"}
                        if dist == 0:
                            linear_exact += 1
                            record_match(0, f"LINEAR: {word}:{col_name}+{row_name} op={op_name} mod {M} thresh>={threshold}", candidate)
                        elif dist <= 2:
                            record_match(dist, f"LINEAR: {word}:{col_name}+{row_name} op={op_name} mod {M} thresh>={threshold}", candidate)

                        # Also try: null if value < threshold
                        candidate2 = {}
                        for (r, c) in occupied_cells:
                            candidate2[(r, c)] = 1 if cell_vals[(r, c)] < threshold else 0
                        dist2 = hamming_full(candidate2)
                        if dist2 < best_linear['dist']:
                            best_linear = {'dist': dist2, 'desc': f"{word}:{col_name}+{row_name} op={op_name} mod {M} thresh<{threshold}"}
                        if dist2 == 0:
                            linear_exact += 1
                            record_match(0, f"LINEAR: {word}:{col_name}+{row_name} op={op_name} mod {M} thresh<{threshold}", candidate2)
                        elif dist2 <= 2:
                            record_match(dist2, f"LINEAR: {word}:{col_name}+{row_name} op={op_name} mod {M} thresh<{threshold}", candidate2)

                    # Also try: null if value is in a specific set (for small M)
                    if M <= 7:
                        for null_set_size in range(1, M):
                            for null_set in combinations(range(M), null_set_size):
                                null_set_s = set(null_set)
                                candidate3 = {}
                                for (r, c) in occupied_cells:
                                    candidate3[(r, c)] = 1 if cell_vals[(r, c)] in null_set_s else 0
                                dist3 = hamming_full(candidate3)
                                if dist3 == 0:
                                    linear_exact += 1
                                    record_match(0, f"SET: {word}:{col_name}+{row_name} op={op_name} mod {M} null_set={null_set}", candidate3)
                                elif dist3 <= 2:
                                    record_match(dist3, f"SET: {word}:{col_name}+{row_name} op={op_name} mod {M} null_set={null_set}", candidate3)

print(f"Linear/threshold rules tested. Best distance: {best_linear['dist']} ({best_linear['desc']})")
print(f"Exact matches: {linear_exact}")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2c: KEYWORD x KEYWORD Polybius / tableau intersection
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2c: KEYWORD x KEYWORD TABLEAU LOOKUP")
print("=" * 90)

# For KRYPTOS (row keyword) and a 5-letter word (col keyword):
# The Vigenere/Beaufort tableau output at (row, col) is a single letter.
# Is the cell null/real based on whether the output letter is in some set?

kw7_exact_matches = 0
best_kw7 = {'dist': 99, 'desc': ''}

for word in FIVE_LETTER_WORDS:
    word_az = [AZ_IDX[c] for c in word]

    for variant_name, variant_func in [
        ('vig', lambda k, p: (k - p) % 26),    # K = CT - PT
        ('beau', lambda k, p: (k + p) % 26),   # Beaufort
        ('vbeau', lambda k, p: (p - k) % 26),  # Variant Beaufort
    ]:
        # For each (r,c), compute the tableau output
        outputs = {}
        for r in range(7):
            for c in range(5):
                out = variant_func(KRYPTOS_AZ[r], word_az[c])
                outputs[(r, c)] = out

        # Check if ANY subset of the 26 possible output values separates null from real
        null_outputs = set()
        real_outputs = set()
        mixed_outputs = set()
        for (r, c) in occupied_cells:
            val = target_table[(r, c)]
            out = outputs[(r, c)]
            if val is True:
                null_outputs.add(out)
            elif val is False:
                real_outputs.add(out)
            else:  # mixed
                mixed_outputs.add(out)

        # Perfect separation: null_outputs and real_outputs are disjoint
        overlap = null_outputs & real_outputs
        if not overlap:
            # Check mixed: mixed outputs must be in null_outputs for null-leaning
            desc = f"TABLEAU: KRYPTOS x {word} ({variant_name}): null_outs={sorted(null_outputs)} real_outs={sorted(real_outputs)} mixed_outs={sorted(mixed_outputs)}"
            candidate = {}
            null_set = null_outputs | mixed_outputs
            for (r, c) in occupied_cells:
                candidate[(r, c)] = 1 if outputs[(r, c)] in null_set else 0
            dist = hamming_full(candidate)
            if dist <= 2:
                kw7_exact_matches += 1 if dist == 0 else 0
                record_match(dist, desc, candidate)
                print(f"  DISJOINT ({variant_name}): {word} -> null={sorted(null_outputs)} real={sorted(real_outputs)} dist={dist}")

        if len(overlap) <= 2:
            desc = f"TABLEAU_NEAR: KRYPTOS x {word} ({variant_name}): overlap={sorted(overlap)}"
            if best_kw7['dist'] > len(overlap):
                best_kw7 = {'dist': len(overlap), 'desc': desc}

        # Also check if output being in PALETTE predicts null
        candidate_pal = {}
        for (r, c) in occupied_cells:
            out_letter = ALPH[outputs[(r, c)]]
            candidate_pal[(r, c)] = 1 if out_letter in PALETTE else 0
        dist_pal = hamming_full(candidate_pal)
        if dist_pal <= 2:
            record_match(dist_pal, f"TABLEAU_PAL: KRYPTOS x {word} ({variant_name}): output in PALETTE?", candidate_pal)

        # Check output letter in KA
        for ka_group_name, ka_group in [
            ('ka_row0', set(KA[0:5])),
            ('ka_row1', set(KA[5:10])),
            ('ka_row2', set(KA[10:15])),
            ('ka_row3', set(KA[15:20])),
            ('ka_row4', set(KA[20:25])),
            ('ka_row5', set(KA[25:26])),  # just Z
            ('ka_top3', set(KA[0:15])),
            ('ka_bot3', set(KA[15:26])),
            ('ka_even', set(KA[i] for i in range(0, 26, 2))),
            ('ka_odd', set(KA[i] for i in range(1, 26, 2))),
        ]:
            candidate_kg = {}
            for (r, c) in occupied_cells:
                out_letter = ALPH[outputs[(r, c)]]
                candidate_kg[(r, c)] = 1 if out_letter in ka_group else 0
            dist_kg = hamming_full(candidate_kg)
            if dist_kg <= 2:
                record_match(dist_kg, f"TABLEAU_KA: KRYPTOS x {word} ({variant_name}) output in {ka_group_name}", candidate_kg)

print(f"Keyword-tableau exact matches: {kw7_exact_matches}")
print(f"Best keyword-tableau overlap: {best_kw7['dist']} ({best_kw7['desc']})")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2d: BINARY NUMBER ENCODING
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2d: BINARY NUMBER ENCODING")
print("=" * 90)

# The target has 35 bits. What if it's derived from known numbers in binary?
# 73 in binary = 1001001 (7 bits)
# 97 in binary = 1100001 (7 bits)
# 24 in binary = 11000 (5 bits)
# Concatenations and repetitions

binary_candidates = {}

# Single number repeated to fill 35 bits
for name, num in INSTALL_NUMS.items():
    if num <= 0 or num > 2**35:
        continue
    bits = bin(num)[2:]
    # Repeat to fill 35
    repeated = (bits * (35 // len(bits) + 1))[:35]
    binary_candidates[f"{name}={num} repeated ({bits})"] = int(repeated, 2)

    # Also try the number itself as a 35-bit value
    if num < 2**35:
        binary_candidates[f"{name}={num} direct"] = num

# Pairs of numbers concatenated
key_nums = [73, 97, 24, 7, 5, 35, 13, 11, 26, 31, 28, 38, 57, 6, 77, 8, 44, 66, 21, 33, 63]
for i, n1 in enumerate(key_nums):
    b1 = bin(n1)[2:]
    for n2 in key_nums[i:]:
        b2 = bin(n2)[2:]
        concat = b1 + b2
        if len(concat) <= 35:
            padded = concat.ljust(35, '0')
            binary_candidates[f"{n1}+{n2} concat padded"] = int(padded, 2)
            padded_r = concat.rjust(35, '0')
            binary_candidates[f"{n1}+{n2} concat rpadded"] = int(padded_r, 2)
        if len(concat) >= 35:
            truncated = concat[:35]
            binary_candidates[f"{n1}+{n2} concat trunc"] = int(truncated, 2)

# 73 repeated 5 times (7 bits x 5 = 35!)
b73 = bin(73)[2:]  # 1001001
assert len(b73) == 7
rep73 = b73 * 5
binary_candidates['73 x 5 (perfect fit)'] = int(rep73, 2)

# 97 repeated 5 times (7 bits x 5 = 35)
b97 = bin(97)[2:]  # 1100001
rep97 = b97 * 5
binary_candidates['97 x 5'] = int(rep97, 2)

# 24 repeated 7 times (5 bits x 7 = 35!)
b24 = bin(24)[2:]  # 11000
assert len(b24) == 5
rep24 = b24 * 7
binary_candidates['24 x 7 (perfect fit)'] = int(rep24, 2)

# 13 repeated (4 bits)
b13 = bin(13)[2:]  # 1101
rep13 = (b13 * 9)[:35]
binary_candidates['13 repeated'] = int(rep13, 2)

# 11 repeated (4 bits)
b11 = bin(11)[2:]  # 1011
rep11 = (b11 * 9)[:35]
binary_candidates['11 repeated'] = int(rep11, 2)

# KRYPTOS letter values as 5-bit binary (one per row)
kw_binary = ''.join(f'{v:05b}' for v in KRYPTOS_AZ)  # 7*5 = 35 bits!
binary_candidates['KRYPTOS_AZ as 5-bit'] = int(kw_binary, 2)

# KRYPTOS KA values as 5-bit
kw_ka_binary = ''.join(f'{v:05b}' for v in KRYPTOS_KA)
binary_candidates['KRYPTOS_KA as 5-bit'] = int(kw_ka_binary, 2)

# SEVEN letter values as 7-bit binary (one per col)
for word in FIVE_LETTER_WORDS:
    waz = [AZ_IDX[c] for c in word]
    # 5 letters, each as 5-bit = 25 bits (too short)
    # 5 letters, each as 7-bit = 35 bits!
    w7bit = ''.join(f'{v:07b}' for v in waz)
    if len(w7bit) == 35:
        binary_candidates[f'{word}_AZ as 7-bit'] = int(w7bit, 2)

    wka = [KA_IDX[c] for c in word]
    w7bit_ka = ''.join(f'{v:07b}' for v in wka)
    if len(w7bit_ka) == 35:
        binary_candidates[f'{word}_KA as 7-bit'] = int(w7bit_ka, 2)

# XOR combinations
for name1, val1 in [('73x5', int(b73*5, 2)), ('97x5', int(b97*5, 2)), ('24x7', int(rep24, 2)),
                     ('KW_AZ', int(kw_binary, 2)), ('KW_KA', int(kw_ka_binary, 2))]:
    for name2, val2 in [('73x5', int(b73*5, 2)), ('97x5', int(b97*5, 2)), ('24x7', int(rep24, 2)),
                         ('KW_AZ', int(kw_binary, 2)), ('KW_KA', int(kw_ka_binary, 2))]:
        if name1 >= name2:
            continue
        binary_candidates[f'{name1} XOR {name2}'] = val1 ^ val2
        binary_candidates[f'{name1} AND {name2}'] = val1 & val2
        binary_candidates[f'{name1} OR {name2}'] = val1 | val2

# Also try NOT of each (invert all 35 bits)
for name, val in list(binary_candidates.items()):
    binary_candidates[f'NOT({name})'] = (~val) & ((1 << 35) - 1)

print(f"Testing {len(binary_candidates)} binary candidates...")

best_binary = {'dist': 99, 'desc': ''}
binary_matches = 0

for name, val35 in binary_candidates.items():
    # Convert to table: bit i -> cell (i//5, i%5), MSB first
    candidate = {}
    for bit_idx in range(35):
        r = bit_idx // 5
        c = bit_idx % 5
        bit = (val35 >> (34 - bit_idx)) & 1
        candidate[(r, c)] = bit

    dist = hamming_full(candidate)
    if dist < best_binary['dist']:
        best_binary = {'dist': dist, 'desc': name}
    if dist == 0:
        binary_matches += 1
        record_match(0, f"BINARY: {name} = {val35} = 0b{val35:035b}")
    elif dist <= 2:
        record_match(dist, f"BINARY: {name} = {val35} = 0b{val35:035b}")

print(f"Best binary distance: {best_binary['dist']} ({best_binary['desc']})")
print(f"Exact binary matches: {binary_matches}")

# Also try reading bits in different cell orders (column-major, etc.)
print("\nTrying alternate bit-to-cell mappings...")
for order_name, cell_order in [
    ('col-major', [(r, c) for c in range(5) for r in range(7)]),
    ('snake-row', [(r, c if r%2==0 else 4-c) for r in range(7) for c in range(5)]),
    ('snake-col', [(r if c%2==0 else 6-r, c) for c in range(5) for r in range(7)]),
    ('diagonal', [(r, (r+d)%5) for d in range(5) for r in range(7)]),
]:
    for name, val35 in binary_candidates.items():
        candidate = {}
        for bit_idx in range(35):
            r, c = cell_order[bit_idx]
            bit = (val35 >> (34 - bit_idx)) & 1
            candidate[(r, c)] = bit
        dist = hamming_full(candidate)
        if dist == 0:
            record_match(0, f"BINARY_{order_name}: {name}")
        elif dist <= 2:
            record_match(dist, f"BINARY_{order_name}: {name}")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2e: Polybius-based (KA 5-wide grid)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2e: POLYBIUS-BASED RULES")
print("=" * 90)

# KA Polybius (5 columns):
# Row 0: K R Y P T (indices 0-4)
# Row 1: O S A B C (indices 5-9)
# Row 2: D E F G H (indices 10-14)
# Row 3: I J L M N (indices 15-19)
# Row 4: Q U V W X (indices 20-24)
# Row 5: Z         (index 25)

# Palette letters: B(8), G(13), I(15), K(0), O(5), W(23), Z(25)
# Their (row,col) in KA Polybius:
print("Palette letters in KA Polybius (5-wide):")
for c in sorted(PALETTE):
    ka = KA_IDX[c]
    pr, pc = ka // 5, ka % 5
    print(f"  {c}: KA={ka:>2} -> row={pr}, col={pc}")

# Check: do the Polybius row or column of the LETTER determine the 7x5 cell classification?
# For each 7x5 cell, all palette letters at that cell have a Polybius (row,col).
# Does the Polybius coordinate predict null/real?
print("\nPolybius coordinates at each 7x5 cell:")
for r7 in range(7):
    for c5 in range(5):
        positions = cell_positions.get((r7, c5), [])
        if not positions:
            continue
        val = target_table[(r7, c5)]
        letters = [CT[p] for p in positions]
        poly_coords = [(KA_IDX[l]//5, KA_IDX[l]%5) for l in letters]
        status = 'N' if val is True else 'R' if val is False else '?'
        print(f"  ({r7},{c5})[{status}]: letters={letters} poly={poly_coords}")

# For each pair (polybius_row_feature, polybius_col_feature),
# check if it separates null cells from real cells
# Try: poly_row + r7, poly_row + c5, poly_col + r7, etc.
best_poly = {'dist': 99, 'desc': ''}
poly_matches = 0

# Since different positions in the same cell can have different letters,
# Polybius features vary within a cell. So Polybius can only be a tiebreaker,
# not a primary classifier. The primary is (r7, c5).
# The question is whether there's a rule that uses BOTH (r7,c5) AND poly coords.

# Actually, for the 7x5 TABLE generation (what makes a cell null vs real),
# we need a rule that depends only on (r7,c5) -- not on the specific letters.
# The letters at a cell vary across positions, but the cell classification is fixed.

# So Polybius of the letter can only work if all letters in a cell share
# the same Polybius property. Let's check.
print("\nChecking if Polybius rows are uniform within each 7x5 cell:")
for r7 in range(7):
    for c5 in range(5):
        positions = cell_positions.get((r7, c5), [])
        if not positions:
            continue
        poly_rows = set(KA_IDX[CT[p]] // 5 for p in positions)
        poly_cols = set(KA_IDX[CT[p]] % 5 for p in positions)
        if len(poly_rows) > 1 or len(poly_cols) > 1:
            print(f"  Cell ({r7},{c5}): VARIED poly_rows={poly_rows} poly_cols={poly_cols}")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2f: DIAGONAL / STRIPE PATTERNS
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2f: DIAGONAL AND STRIPE PATTERNS")
print("=" * 90)

best_diag = {'dist': 99, 'desc': ''}

for a in range(-6, 7):
    for b in range(-4, 5):
        for d in range(-35, 36):
            for M in range(2, 36):
                val_set = set()
                for (r, c) in occupied_cells:
                    v = (a * r + b * c + d) % M
                    val_set.add(v)
                if len(val_set) < 2:
                    continue
                # Check every possible null-value set of size up to min(|null_cells|, M/2)
                # This is expensive, so only for small M
                if M > 5:
                    # Just try threshold
                    for thresh in range(M):
                        candidate = {}
                        for (r_c) in occupied_cells:
                            r, c = r_c
                            v = (a * r + b * c + d) % M
                            candidate[(r, c)] = 1 if v < thresh else 0
                        dist = hamming_full(candidate)
                        if dist < best_diag['dist']:
                            best_diag = {'dist': dist, 'desc': f"({a}*r+{b}*c+{d})%{M} < {thresh}"}
                        if dist <= 2:
                            record_match(dist, f"DIAG: ({a}*r+{b}*c+{d})%{M} < {thresh}")
                else:
                    for null_size in range(1, M):
                        for null_vals in combinations(range(M), null_size):
                            nv = set(null_vals)
                            candidate = {}
                            for (r, c) in occupied_cells:
                                v = (a * r + b * c + d) % M
                                candidate[(r, c)] = 1 if v in nv else 0
                            dist = hamming_full(candidate)
                            if dist < best_diag['dist']:
                                best_diag = {'dist': dist, 'desc': f"({a}*r+{b}*c+{d})%{M} in {null_vals}"}
                            if dist <= 2:
                                record_match(dist, f"DIAG: ({a}*r+{b}*c+{d})%{M} in {null_vals}")

# Keep this limited to avoid combinatorial explosion
# We already did a+b+d in range (-6..6, -4..4, -35..35) with M up to 35
# That's 13*9*71*34 = ~283K threshold tests + subset tests for M<=5
print(f"Best diagonal/stripe distance: {best_diag['dist']} ({best_diag['desc']})")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2g: KRYPTOS x WORD dual-keyword comparison
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2g: KRYPTOS x WORD — LETTER IDENTITY RULES")
print("=" * 90)

# For cell (r,c): KRYPTOS[r] and WORD[c] are two letters.
# Rule: is the cell null when these two letters satisfy some condition?
# E.g., KRYPTOS[r] == WORD[c], or they share a Polybius row, etc.

best_identity = {'dist': 99, 'desc': ''}

for word in FIVE_LETTER_WORDS:
    for alpha_name, alpha_idx in [('AZ', AZ_IDX), ('KA', KA_IDX)]:
        kw_vals = [alpha_idx[c] for c in KRYPTOS_WORD]
        w_vals = [alpha_idx[c] for c in word]

        # Test various letter-pair conditions
        conditions = {
            'equal': lambda kr, wc: kr == wc,
            'diff_even': lambda kr, wc: (kr - wc) % 2 == 0,
            'sum_even': lambda kr, wc: (kr + wc) % 2 == 0,
            'same_poly_row': lambda kr, wc: kr // 5 == wc // 5,
            'same_poly_col': lambda kr, wc: kr % 5 == wc % 5,
            'kr_lt_wc': lambda kr, wc: kr < wc,
            'kr_gt_wc': lambda kr, wc: kr > wc,
            'sum_lt13': lambda kr, wc: kr + wc < 13,
            'sum_ge13': lambda kr, wc: kr + wc >= 13,
            'diff_lt0': lambda kr, wc: (kr - wc) % 26 < 13,
            'xor_odd': lambda kr, wc: (kr ^ wc) % 2 == 1,
            'prod_even': lambda kr, wc: (kr * wc) % 2 == 0,
        }

        for cond_name, cond_func in conditions.items():
            candidate = {}
            for (r, c) in occupied_cells:
                candidate[(r, c)] = 1 if cond_func(kw_vals[r], w_vals[c]) else 0
            dist = hamming_full(candidate)
            if dist < best_identity['dist']:
                best_identity = {'dist': dist, 'desc': f"KRYPTOS x {word} ({alpha_name}): {cond_name}"}
            if dist == 0:
                record_match(0, f"IDENTITY: KRYPTOS x {word} ({alpha_name}): {cond_name}", candidate)
            elif dist <= 2:
                record_match(dist, f"IDENTITY: KRYPTOS x {word} ({alpha_name}): {cond_name}", candidate)

print(f"Best identity rule distance: {best_identity['dist']} ({best_identity['desc']})")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2h: PURE ARITHMETIC on (r, c) with installation constants
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2h: (a*r + b*c) mod M with installation constant a, b, M")
print("=" * 90)

# Test with all triples of installation numbers
install_vals = sorted(set(INSTALL_NUMS.values()))
best_arith = {'dist': 99, 'desc': ''}

tested = 0
for a in install_vals:
    for b in install_vals:
        for M in range(2, 36):
            # Compute (a*r + b*c) mod M for each occupied cell
            cell_vals = {}
            for (r, c) in occupied_cells:
                cell_vals[(r, c)] = (a * r + b * c) % M

            # Try threshold
            for thresh in range(1, M):
                candidate = {}
                for (r, c) in occupied_cells:
                    candidate[(r, c)] = 1 if cell_vals[(r, c)] < thresh else 0
                dist = hamming_full(candidate)
                if dist < best_arith['dist']:
                    best_arith = {'dist': dist, 'desc': f"({a}*r+{b}*c)%{M} < {thresh}"}
                if dist <= 2:
                    record_match(dist, f"ARITH: ({a}*r+{b}*c)%{M} < {thresh}")

                candidate2 = {}
                for (r, c) in occupied_cells:
                    candidate2[(r, c)] = 1 if cell_vals[(r, c)] >= thresh else 0
                dist2 = hamming_full(candidate2)
                if dist2 < best_arith['dist']:
                    best_arith = {'dist': dist2, 'desc': f"({a}*r+{b}*c)%{M} >= {thresh}"}
                if dist2 <= 2:
                    record_match(dist2, f"ARITH: ({a}*r+{b}*c)%{M} >= {thresh}")

            tested += 1

print(f"Tested {tested} (a,b,M) triples")
print(f"Best arithmetic distance: {best_arith['dist']} ({best_arith['desc']})")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2i: The 35-bit number — reverse lookup
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2i: REVERSE LOOKUP OF 35-BIT NUMBER")
print("=" * 90)

# The target 35-bit number. What algebraic relationships does it have
# with known installation numbers?

print(f"\nTarget 35-bit: {target_35bit}")
print(f"Binary: {target_35bit:035b}")
print(f"Hex: 0x{target_35bit:09X}")

# Factor the target number
def factorize(n):
    factors = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors

print(f"Factors: {factorize(target_35bit)}")
print(f"target mod 7 = {target_35bit % 7}")
print(f"target mod 5 = {target_35bit % 5}")
print(f"target mod 35 = {target_35bit % 35}")
print(f"target mod 97 = {target_35bit % 97}")
print(f"target mod 73 = {target_35bit % 73}")
print(f"target mod 26 = {target_35bit % 26}")

# Check if target = a * b for installation numbers
for name1, n1 in INSTALL_NUMS.items():
    if n1 == 0:
        continue
    if target_35bit % n1 == 0:
        quotient = target_35bit // n1
        print(f"  {target_35bit} = {n1} ({name1}) * {quotient}")
        # Is quotient also a known number?
        for name2, n2 in INSTALL_NUMS.items():
            if n2 == quotient:
                print(f"    *** quotient = {n2} ({name2}) ***")

# Check a + b, a - b, a XOR b
for name1, n1 in INSTALL_NUMS.items():
    for name2, n2 in INSTALL_NUMS.items():
        if name1 >= name2:
            continue
        if n1 + n2 == target_35bit:
            print(f"  {target_35bit} = {n1}({name1}) + {n2}({name2})")
        if n1 * n2 == target_35bit:
            print(f"  {target_35bit} = {n1}({name1}) * {n2}({name2})")
        if n1 ^ n2 == target_35bit:
            print(f"  {target_35bit} = {n1}({name1}) XOR {n2}({name2})")

# Also try 3-number combinations
for name1, n1 in INSTALL_NUMS.items():
    for name2, n2 in INSTALL_NUMS.items():
        for name3, n3 in INSTALL_NUMS.items():
            if n1 * n2 + n3 == target_35bit:
                print(f"  {target_35bit} = {n1}({name1}) * {n2}({name2}) + {n3}({name3})")
            if n1 * n2 * n3 == target_35bit:
                print(f"  {target_35bit} = {n1}({name1}) * {n2}({name2}) * {n3}({name3})")

# Also check the COMPLEMENT (9 empty cells could go either way)
# How many total 1-bits does our target have?
one_count = bin(target_35bit).count('1')
print(f"\nOne-bits in target: {one_count}")
print(f"Zero-bits in target: {35 - one_count}")

# Try reading the table in different orders
# Column-major reading
target_colmajor = 0
for bit_idx in range(35):
    c = bit_idx // 7
    r = bit_idx % 7
    val = target_table[(r, c)]
    if val is True or val == 'mixed':
        target_colmajor |= (1 << (34 - bit_idx))

print(f"\nColumn-major reading: {target_colmajor} = 0b{target_colmajor:035b}")
print(f"Column-major factors: {factorize(target_colmajor)}")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2j: KRYPTOS x FIVE-LETTER mixed alphabet Beaufort key = N
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2j: BEAUFORT(KRYPTOS, ?) = PALETTE LETTER — WHAT 5-LETTER KEYS?")
print("=" * 90)

# The palette was generated as: SEVEN encrypted through KA Beaufort with key N -> palette
# What if the TABLE itself is generated by a similar Beaufort/Vigenere operation?
# For cell (r,c): Beau(KRYPTOS[r], WORD[c]) = some letter
# Then: null if that letter has some property (e.g., is a vowel, is in first half of alphabet, etc.)

# Actually, let's be more creative. What if the rule is:
# For cell (r,c): LETTER = Beaufort(KRYPTOS[r], WORD[c]) on the KA alphabet
# Null if LETTER is in some fixed set

for word in FIVE_LETTER_WORDS:
    for alpha_name, alpha in [('AZ', ALPH), ('KA', KA)]:
        alpha_idx = {c: i for i, c in enumerate(alpha)}
        kw_vals = [alpha_idx[c] for c in KRYPTOS_WORD]
        w_vals = [alpha_idx[c] for c in word]

        for variant_name, variant_func in [
            ('vig', lambda k, p: (k - p) % 26),
            ('beau', lambda k, p: (k + p) % 26),
            ('vbeau', lambda k, p: (p - k) % 26),
        ]:
            outputs = {}
            for r in range(7):
                for c in range(5):
                    out_idx = variant_func(kw_vals[r], w_vals[c])
                    out_letter = alpha[out_idx]
                    outputs[(r, c)] = out_letter

            # Collect null-cell outputs and real-cell outputs
            null_letters = set()
            real_letters = set()
            for (r, c) in occupied_non_mixed:
                if target_binary_nm[(r, c)] == 1:
                    null_letters.add(outputs[(r, c)])
                else:
                    real_letters.add(outputs[(r, c)])

            overlap = null_letters & real_letters
            if len(overlap) == 0:
                # Perfect separation! Check mixed cells
                mixed_ok = True
                for (r, c) in mixed_cells:
                    out = outputs[(r, c)]
                    # Mixed cells should map to null_letters (null-leaning)
                    if out not in null_letters and out not in real_letters:
                        pass  # New letter, doesn't invalidate
                    elif out in real_letters:
                        mixed_ok = False

                candidate = {}
                null_set = null_letters.copy()
                # Add mixed cell outputs to null set
                for (r, c) in mixed_cells:
                    null_set.add(outputs[(r, c)])

                for (r, c) in occupied_cells:
                    candidate[(r, c)] = 1 if outputs[(r, c)] in null_set else 0
                dist = hamming_full(candidate)

                if dist <= 2:
                    record_match(dist, f"KA_CIPHER: KRYPTOS x {word} ({alpha_name}_{variant_name}): "
                                f"null_letters={sorted(null_letters)} real_letters={sorted(real_letters)}")
                    if dist == 0:
                        print(f"  *** PERFECT: KRYPTOS x {word} ({alpha_name}_{variant_name}) ***")
                        print(f"      Null letters: {sorted(null_letters)}")
                        print(f"      Real letters: {sorted(real_letters)}")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2k: BRUTE-FORCE 5-letter word search with broader cipher ops
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2k: BRUTE-FORCE ALL 5-LETTER WORDS (a-z)")
print("=" * 90)

# Generate ALL possible 5-letter patterns where each letter is from A-Z
# This is 26^5 = ~12M -- too many. Instead, use the structure:
# The 5 columns have values that produce a specific partition.
# We need the null pattern to be exactly {(0,4),(1,0),(1,1),(1,3),(2,2),(3,2),(3,4),(4,4),(5,0),(6,0)}
# plus mixed {(0,0),(2,3),(5,2)}.

# For each column c, row r: we need the cell (r,c) to map to null or real.
# With a threshold rule like (KW[r] + COL[c]) mod M < T, the null/real pattern
# for column c depends only on COL[c].

# Let's check: for each column, what are the required null rows?
print("\nRequired null rows by column:")
null_rows_by_col = {}
for c in range(5):
    null_rows = []
    real_rows = []
    for r in range(7):
        val = target_table[(r, c)]
        if val is True or val == 'mixed':
            null_rows.append(r)
        elif val is False:
            real_rows.append(r)
    null_rows_by_col[c] = (null_rows, real_rows)
    print(f"  col {c}: null_rows={null_rows}, real_rows={real_rows}")

# The null pattern for each column:
# col 0: null={0,1,5,6}, real={2,3}    (4 null, 2 real, 1 empty)
# col 1: null={1}, real={0,2,3,4}       (1 null, 4 real, 2 empty)
# col 2: null={2,3,5}, real={0,6}       (3 null, 2 real, 2 empty)
# col 3: null={1,2}, real={0,3,4,6}     (2 null, 4 real, 1 empty)  [mixed (2,3) counted as null]
# col 4: null={0,3,4}, real={5,6}       (3 null, 2 real, 2 empty)  [note: row 2 is empty]

# For a threshold rule (KW_AZ[r] + x) mod M:
# KW_AZ = [10, 17, 24, 15, 19, 14, 18]
# For column c with value x, the values are:
# (10+x)%M, (17+x)%M, (24+x)%M, (15+x)%M, (19+x)%M, (14+x)%M, (18+x)%M
# We need the values at null_rows to all be < T, and values at real_rows to all be >= T.

# This is a separation problem: for each column, find x and (M,T) such that
# the KW_AZ values at null rows are separated from those at real rows.

# Let's be thorough: for each M from 2 to 35, find which column values x
# produce the correct null/real partition, then check if all 5 columns
# have valid x values.

print("\nSearching for (M, T) where all 5 columns have a valid x value...")

for M in range(2, 36):
    for T in range(1, M):
        # For each column, find all x in [0, M) that produce the right partition
        valid_x_by_col = {}
        all_valid = True
        for c in range(5):
            null_rows, real_rows = null_rows_by_col[c]
            valid_x = []
            for x in range(M):
                null_vals = [(KRYPTOS_AZ[r] + x) % M for r in null_rows]
                real_vals = [(KRYPTOS_AZ[r] + x) % M for r in real_rows]
                if all(v < T for v in null_vals) and all(v >= T for v in real_vals):
                    valid_x.append(x)
            valid_x_by_col[c] = valid_x
            if not valid_x:
                all_valid = False
                break

        if all_valid:
            print(f"  M={M}, T={T}:")
            for c in range(5):
                print(f"    col {c}: valid x = {valid_x_by_col[c]}")

            # Now check: are the valid x values the AZ values of any meaningful word?
            # For each combination
            from itertools import product as iter_product
            count = 1
            for c in range(5):
                count *= len(valid_x_by_col[c])
            if count <= 1000:
                for combo in iter_product(*[valid_x_by_col[c] for c in range(5)]):
                    # combo = (x0, x1, x2, x3, x4)
                    # Can we map these to letters? x = AZ value of the column keyword letter
                    if all(0 <= v < 26 for v in combo):
                        word = ''.join(ALPH[v] for v in combo)
                        desc = f"THRESHOLD: (KW_AZ[r]+{word}_AZ[c])%{M} < {T}"
                        # Verify
                        candidate = {}
                        for (r2, c2) in occupied_cells:
                            v = (KRYPTOS_AZ[r2] + combo[c2]) % M
                            candidate[(r2, c2)] = 1 if v < T else 0
                        dist = hamming_full(candidate)
                        if dist <= 2:
                            record_match(dist, desc)
                            if dist == 0:
                                print(f"      *** WORD: {word} ***")

# Same with KA values
print("\nSearching with KA values...")
for M in range(2, 36):
    for T in range(1, M):
        valid_x_by_col = {}
        all_valid = True
        for c in range(5):
            null_rows, real_rows = null_rows_by_col[c]
            valid_x = []
            for x in range(M):
                null_vals = [(KRYPTOS_KA[r] + x) % M for r in null_rows]
                real_vals = [(KRYPTOS_KA[r] + x) % M for r in real_rows]
                if all(v < T for v in null_vals) and all(v >= T for v in real_vals):
                    valid_x.append(x)
            valid_x_by_col[c] = valid_x
            if not valid_x:
                all_valid = False
                break

        if all_valid:
            print(f"  M={M}, T={T} (KA):")
            for c in range(5):
                print(f"    col {c}: valid x = {valid_x_by_col[c]}")
            count = 1
            for c in range(5):
                count *= len(valid_x_by_col[c])
            if count <= 1000:
                for combo in iter_product(*[valid_x_by_col[c] for c in range(5)]):
                    if all(0 <= v < 26 for v in combo):
                        word = ''.join(KA[v] for v in combo)
                        desc = f"THRESHOLD_KA: (KW_KA[r]+{word}_KA[c])%{M} < {T}"
                        candidate = {}
                        for (r2, c2) in occupied_cells:
                            v = (KRYPTOS_KA[r2] + combo[c2]) % M
                            candidate[(r2, c2)] = 1 if v < T else 0
                        dist = hamming_full(candidate)
                        if dist <= 2:
                            record_match(dist, desc)
                            if dist == 0:
                                print(f"      *** WORD (KA): {word} ***")

# Also try Beaufort: (KW - x) mod M and (x - KW) mod M
print("\nSearching Beaufort variants: (KW_AZ[r] - x) % M and (x - KW_AZ[r]) % M...")
for M in range(2, 36):
    for T in range(1, M):
        for sign_name, sign_func in [('kw-x', lambda kw, x: (kw - x) % M), ('x-kw', lambda kw, x: (x - kw) % M)]:
            valid_x_by_col = {}
            all_valid = True
            for c in range(5):
                null_rows, real_rows = null_rows_by_col[c]
                valid_x = []
                for x in range(M):
                    null_vals = [sign_func(KRYPTOS_AZ[r], x) for r in null_rows]
                    real_vals = [sign_func(KRYPTOS_AZ[r], x) for r in real_rows]
                    if all(v < T for v in null_vals) and all(v >= T for v in real_vals):
                        valid_x.append(x)
                valid_x_by_col[c] = valid_x
                if not valid_x:
                    all_valid = False
                    break

            if all_valid:
                print(f"  M={M}, T={T}, {sign_name} (AZ):")
                count = 1
                for c in range(5):
                    count *= len(valid_x_by_col[c])
                    print(f"    col {c}: valid x = {valid_x_by_col[c]}")
                if count <= 1000:
                    for combo in iter_product(*[valid_x_by_col[c] for c in range(5)]):
                        if all(0 <= v < 26 for v in combo):
                            word = ''.join(ALPH[v] for v in combo)
                            desc = f"BEAU_{sign_name}: ({sign_name.replace('x',word)}_AZ)%{M} < {T}"
                            candidate = {}
                            for (r2, c2) in occupied_cells:
                                v = sign_func(KRYPTOS_AZ[r2], combo[c2])
                                candidate[(r2, c2)] = 1 if v < T else 0
                            dist = hamming_full(candidate)
                            if dist <= 2:
                                record_match(dist, desc)
                                if dist == 0:
                                    print(f"      *** WORD: {word} ({sign_name}) ***")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2l: MULTIPLICATIVE RULES: (a * r * c + b) mod M
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2l: MULTIPLICATIVE RULES")
print("=" * 90)

best_mult = {'dist': 99, 'desc': ''}
for a in install_vals[:15]:  # Top 15 to limit runtime
    for b in range(-10, 11):
        for M in range(2, 20):
            cell_vals = {}
            for (r, c) in occupied_cells:
                cell_vals[(r, c)] = (a * r * c + b) % M
            for thresh in range(1, M):
                candidate = {}
                for (r, c2) in occupied_cells:
                    candidate[(r, c2)] = 1 if cell_vals[(r, c2)] < thresh else 0
                dist = hamming_full(candidate)
                if dist < best_mult['dist']:
                    best_mult = {'dist': dist, 'desc': f"({a}*r*c+{b})%{M} < {thresh}"}
                if dist <= 2:
                    record_match(dist, f"MULT: ({a}*r*c+{b})%{M} < {thresh}")

print(f"Best multiplicative: {best_mult['dist']} ({best_mult['desc']})")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2m: QUADRATIC RULES: (a*r^2 + b*c^2 + d*r*c + e*r + f*c) mod M
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2m: QUADRATIC RULES (limited search)")
print("=" * 90)

best_quad = {'dist': 99, 'desc': ''}
# Limited: a,b,d in {0,1}, e,f from small set, M from 2-13
for a_coeff in range(2):
    for b_coeff in range(2):
        for d_coeff in range(2):
            for e_coeff in range(-3, 4):
                for f_coeff in range(-3, 4):
                    for M in range(2, 14):
                        cell_vals = {}
                        for (r, c) in occupied_cells:
                            v = (a_coeff*r*r + b_coeff*c*c + d_coeff*r*c + e_coeff*r + f_coeff*c) % M
                            cell_vals[(r, c)] = v
                        for thresh in range(1, M):
                            candidate = {}
                            for rc in occupied_cells:
                                candidate[rc] = 1 if cell_vals[rc] < thresh else 0
                            dist = hamming_full(candidate)
                            if dist < best_quad['dist']:
                                best_quad = {'dist': dist, 'desc': f"({a_coeff}r^2+{b_coeff}c^2+{d_coeff}rc+{e_coeff}r+{f_coeff}c)%{M}<{thresh}"}
                            if dist == 0:
                                record_match(0, f"QUAD: ({a_coeff}r^2+{b_coeff}c^2+{d_coeff}rc+{e_coeff}r+{f_coeff}c)%{M}<{thresh}")
                            elif dist <= 2:
                                record_match(dist, f"QUAD: ({a_coeff}r^2+{b_coeff}c^2+{d_coeff}rc+{e_coeff}r+{f_coeff}c)%{M}<{thresh}")

print(f"Best quadratic: {best_quad['dist']} ({best_quad['desc']})")

# ══════════════════════════════════════════════════════════════════════════
# APPROACH 2n: CHECKERBOARD / XOR patterns with offsets
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("APPROACH 2n: CHECKERBOARD AND XOR PATTERNS")
print("=" * 90)

best_check = {'dist': 99, 'desc': ''}

for offset_r in range(7):
    for offset_c in range(5):
        for M_r in range(1, 8):
            for M_c in range(1, 6):
                # Checkerboard: null if ((r+offset_r) // M_r + (c+offset_c) // M_c) is even
                candidate = {}
                for (r, c) in occupied_cells:
                    v = ((r + offset_r) // M_r + (c + offset_c) // M_c) % 2
                    candidate[(r, c)] = v
                dist = hamming_full(candidate)
                if dist < best_check['dist']:
                    best_check = {'dist': dist, 'desc': f"check(({r}+{offset_r})//{M_r}+({c}+{offset_c})//{M_c})%2"}
                if dist <= 2:
                    record_match(dist, f"CHECK: ((r+{offset_r})//{M_r}+(c+{offset_c})//{M_c})%2")

                # Inverted
                candidate_inv = {k: 1-v for k, v in candidate.items()}
                dist_inv = hamming_full(candidate_inv)
                if dist_inv <= 2:
                    record_match(dist_inv, f"CHECK_INV: ((r+{offset_r})//{M_r}+(c+{offset_c})//{M_c})%2==0")

# XOR
for a in range(1, 8):
    for b in range(1, 6):
        candidate = {}
        for (r, c) in occupied_cells:
            candidate[(r, c)] = ((r * a) ^ (c * b)) % 2
        dist = hamming_full(candidate)
        if dist < best_check['dist']:
            best_check = {'dist': dist, 'desc': f"XOR: ({a}*r)^({b}*c)%2"}
        if dist <= 2:
            record_match(dist, f"XOR: ({a}*r)^({b}*c)%2")

print(f"Best checkerboard/XOR: {best_check['dist']} ({best_check['desc']})")

# ══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 90)
print("FINAL SUMMARY")
print("=" * 90)

print(f"\nExact matches (distance 0): {len(results['matches'])}")
for m in results['matches']:
    print(f"  {m['description']}")

print(f"\nNear misses (distance 1-2): {len(results['near_misses'])}")
for m in sorted(results['near_misses'], key=lambda x: x['distance']):
    print(f"  dist={m['distance']}: {m['description']}")

# Save results
output_path = os.path.join(os.path.dirname(__file__), '..', '..', 'results',
                           'mod35_table_derivation.json')
output_path = os.path.abspath(output_path)

results['exact_match_count'] = len(results['matches'])
results['near_miss_count'] = len(results['near_misses'])

with open(output_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)

print(f"\nResults saved to: {output_path}")
print("DONE.")
