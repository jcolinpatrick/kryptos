#!/usr/bin/env python3
"""Novel Method D: Berlin Clock Cipher.

The Mengenlehreuhr (Berlin Clock) displays time using lit/unlit lamps:
- Top: 1 seconds lamp, Row 1: 4 lamps (5hr), Row 2: 4 lamps (1hr)
- Row 3: 11 lamps (5min), Row 4: 4 lamps (1min)
- Structure: 4,4,11,4 = 23 units per display

Also test: Berlin Clock structure defines transposition patterns.
"""
import json
import sys
import os
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed

RESULTS_DIR = os.path.join(os.path.dirname(__file__), '..', 'results', 'novel_methods')
os.makedirs(RESULTS_DIR, exist_ok=True)

best_overall = {"score": 0, "method": "", "text": ""}
all_results = []


def check_candidate(text, method_name):
    global best_overall
    if not text or len(text) < CT_LEN:
        return 0
    text = text[:CT_LEN].upper()
    if not all(c.isalpha() for c in text):
        return 0
    sc = score_cribs(text)
    if sc > best_overall["score"]:
        best_overall = {"score": sc, "method": method_name, "text": text}
    if sc > 2:
        detail = score_cribs_detailed(text)
        all_results.append({"method": method_name, "score": sc,
                           "ene": detail["ene_score"], "bc": detail["bc_score"],
                           "text": text[:50] + "..."})
        print(f"  [ABOVE NOISE] {method_name}: {sc}/24 (ENE={detail['ene_score']}, BC={detail['bc_score']})")
    return sc


def time_to_berlin_clock(hours, minutes):
    """Convert time to Berlin Clock lamp pattern as bit sequence."""
    h5 = hours // 5       # 0-4 lamps in row 1
    h1 = hours % 5        # 0-4 lamps in row 2
    m5 = minutes // 5     # 0-11 lamps in row 3
    m1 = minutes % 5      # 0-4 lamps in row 4
    # Return as list of bits
    bits = []
    bits.extend([1] * h5 + [0] * (4 - h5))      # Row 1: 4 lamps
    bits.extend([1] * h1 + [0] * (4 - h1))      # Row 2: 4 lamps
    bits.extend([1] * m5 + [0] * (11 - m5))     # Row 3: 11 lamps
    bits.extend([1] * m1 + [0] * (4 - m1))      # Row 4: 4 lamps
    return bits  # 23 bits total


def berlin_clock_value(hours, minutes):
    """Convert time to a single numeric value from Berlin Clock."""
    bits = time_to_berlin_clock(hours, minutes)
    return sum(b << i for i, b in enumerate(bits))


print("=" * 60)
print("NOVEL METHOD D: Berlin Clock Cipher")
print("=" * 60)

total_tested = 0

# Method 1: Use Berlin Clock structure (4,4,11,4) as segment boundaries
print("\n--- Method 1: Berlin Clock segment structure ---")
BC_SEGMENTS = [4, 4, 11, 4]  # 23 total
BC_CYCLE = sum(BC_SEGMENTS)  # 23

# Segment CT into groups of 4,4,11,4,4,4,11,4... and rearrange
for seg_order in itertools.permutations(range(4)):
    # Divide CT into repeating (4,4,11,4) segments
    segments = []
    pos = 0
    while pos < CT_LEN:
        group = []
        for seg_len in BC_SEGMENTS:
            end = min(pos + seg_len, CT_LEN)
            group.append(CT[pos:end])
            pos = end
        segments.append(group)

    # Reorder segments within each group
    reordered = ""
    for group in segments:
        for idx in seg_order:
            if idx < len(group):
                reordered += group[idx]
    method = f"bc_segment_order_{''.join(map(str, seg_order))}"
    check_candidate(reordered, method)
    total_tested += 1

# Method 2: CT letter values as times -> Berlin Clock bits -> new letter values
print("\n--- Method 2: CT values as times ---")
for time_scale in [1, 2, 5, 10]:
    pt_chars = []
    for ch in CT:
        val = ALPH_IDX[ch]
        hours = (val * time_scale) // 60 % 24
        minutes = (val * time_scale) % 60
        bc_bits = time_to_berlin_clock(hours, minutes)
        # Convert 23-bit pattern to a value mod 26
        bc_val = sum(bc_bits) % 26
        pt_chars.append(chr(bc_val + 65))
    pt = "".join(pt_chars)
    method = f"ct_as_time_scale{time_scale}"
    check_candidate(pt, method)
    total_tested += 1

# Method 3: Position as time, CT as offset
print("\n--- Method 3: Position as time, CT as offset ---")
for hours_per_pos in [1, 2]:
    for min_per_pos in [1, 5, 10, 15, 30]:
        pt_chars = []
        for i, ch in enumerate(CT):
            total_min = i * min_per_pos
            hours = (total_min // 60 + i * hours_per_pos) % 24
            minutes = total_min % 60
            bc_sum = sum(time_to_berlin_clock(hours, minutes))
            pt_val = (ALPH_IDX[ch] - bc_sum) % 26
            pt_chars.append(chr(pt_val + 65))
        pt = "".join(pt_chars)
        method = f"pos_time_h{hours_per_pos}_m{min_per_pos}"
        check_candidate(pt, method)
        total_tested += 1

        # Additive variant
        pt_chars2 = []
        for i, ch in enumerate(CT):
            total_min = i * min_per_pos
            hours = (total_min // 60 + i * hours_per_pos) % 24
            minutes = total_min % 60
            bc_sum = sum(time_to_berlin_clock(hours, minutes))
            pt_val = (ALPH_IDX[ch] + bc_sum) % 26
            pt_chars2.append(chr(pt_val + 65))
        pt2 = "".join(pt_chars2)
        method2 = f"pos_time_add_h{hours_per_pos}_m{min_per_pos}"
        check_candidate(pt2, method2)
        total_tested += 1

# Method 4: Berlin Clock-inspired transposition
# 97 / 23 ≈ 4.2 cycles; try 23-column grid
print("\n--- Method 4: Berlin Clock transposition (23 columns) ---")
BCOLS = 23
rows_needed = (CT_LEN + BCOLS - 1) // BCOLS
padded = CT + "X" * (rows_needed * BCOLS - CT_LEN)

# Write row-major into 23 columns, read by Berlin Clock segment groups
grid = []
for r in range(rows_needed):
    grid.append(list(padded[r * BCOLS:(r + 1) * BCOLS]))

# Read by segments: cols 0-3, 4-7, 8-18, 19-22
seg_starts = [0, 4, 8, 19]
seg_ends = [4, 8, 19, 23]

for seg_order in itertools.permutations(range(4)):
    result = ""
    for idx in seg_order:
        for c in range(seg_starts[idx], seg_ends[idx]):
            for r in range(rows_needed):
                result += grid[r][c]
    check_candidate(result[:CT_LEN], f"bc_trans_23col_order_{''.join(map(str, seg_order))}")
    total_tested += 1

# Method 5: Key dates encoded via Berlin Clock
print("\n--- Method 5: Key dates as Berlin Clock keys ---")
KEY_DATES = [
    ("1989_nov9_fall_wall", [(19, 0), (8, 9), (11, 9)]),   # 19:00 8/9 11/9
    ("1990_nov3_dedication", [(11, 3), (19, 90)]),
    ("1986_conception", [(19, 86)]),
    ("2020_hint1", [(20, 20)]),
    ("2014_hint2", [(20, 14)]),
    ("1922_carter_tomb", [(19, 22)]),
]

for date_name, time_pairs in KEY_DATES:
    # Generate key from Berlin Clock representations
    key_bits = []
    for h, m in time_pairs:
        h = h % 24
        m = m % 60
        key_bits.extend(time_to_berlin_clock(h, m))

    # Repeat key to cover CT
    if len(key_bits) == 0:
        continue
    key_full = (key_bits * ((CT_LEN // len(key_bits)) + 2))[:CT_LEN]

    for variant_name, variant_fn in [
        ("sub", lambda ct_val, k: (ct_val - k) % 26),
        ("add", lambda ct_val, k: (ct_val + k) % 26),
    ]:
        pt_chars = []
        for i, ch in enumerate(CT):
            pt_val = variant_fn(ALPH_IDX[ch], key_full[i])
            pt_chars.append(chr(pt_val + 65))
        pt = "".join(pt_chars)
        method = f"bc_date_{date_name}_{variant_name}"
        check_candidate(pt, method)
        total_tested += 1

# Method 6: Berlin Clock digit sum as simple key
print("\n--- Method 6: Hour-based cyclic key ---")
for start_hour in range(24):
    key = []
    for i in range(CT_LEN):
        h = (start_hour + i) % 24
        m = (i * 5) % 60
        bc_sum = sum(time_to_berlin_clock(h, m))
        key.append(bc_sum)

    for variant in ["sub", "add"]:
        pt_chars = []
        for i, ch in enumerate(CT):
            if variant == "sub":
                pt_val = (ALPH_IDX[ch] - key[i]) % 26
            else:
                pt_val = (ALPH_IDX[ch] + key[i]) % 26
            pt_chars.append(chr(pt_val + 65))
        pt = "".join(pt_chars)
        method = f"bc_hourkey_start{start_hour}_{variant}"
        check_candidate(pt, method)
        total_tested += 1

print(f"\nTotal Berlin Clock configs tested: {total_tested}")
print(f"Best: {best_overall['method']} -> {best_overall['score']}/24")
if best_overall['score'] > 0:
    print(f"  Text: {best_overall['text'][:60]}...")

with open(os.path.join(RESULTS_DIR, "berlin_clock.json"), "w") as f:
    json.dump({
        "method": "berlin_clock_cipher",
        "total_tested": total_tested,
        "best_score": best_overall["score"],
        "best_method": best_overall["method"],
        "best_text": best_overall["text"],
        "above_noise": all_results,
    }, f, indent=2)

print(f"\nResults saved to results/novel_methods/berlin_clock.json")
