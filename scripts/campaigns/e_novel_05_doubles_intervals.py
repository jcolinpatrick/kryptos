#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""Novel Methods E, I, J: Doubled Letters, Interval/Skip Ciphers, Self-Referential.

E. Doubled letters as structural markers / null characters
I. Interval/skip ciphers with various N and starting positions
J. Self-referential / recursive ciphers (CT encodes its own key)
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
    if not text or len(text) < 20:
        return 0
    text = text.upper()
    if not all(c.isalpha() for c in text):
        return 0
    # For shortened texts, we check against available crib positions
    sc = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            sc += 1
    if sc > best_overall["score"]:
        best_overall = {"score": sc, "method": method_name, "text": text}
    if sc > 2:
        all_results.append({"method": method_name, "score": sc, "text": text[:50] + "..."})
        print(f"  [ABOVE NOISE] {method_name}: {sc}/24")
    return sc


print("=" * 60)
print("NOVEL METHOD E: Doubled Letters as Structural Markers")
print("=" * 60)

total_tested = 0

# Find all doubled positions
doubles = []
for i in range(CT_LEN - 1):
    if CT[i] == CT[i + 1]:
        doubles.append(i)
print(f"Doubled letter positions: {doubles}")
print(f"Doubled letters: {[(i, CT[i:i+2]) for i in doubles]}")

# Method E1: Remove second of each double
print("\n--- E1: Remove second of each double ---")
double_set = set()
for i in doubles:
    double_set.add(i + 1)  # Remove second
reduced = "".join(CT[i] for i in range(CT_LEN) if i not in double_set)
print(f"  Reduced length: {len(reduced)} (removed {len(double_set)} chars)")
check_candidate(reduced, "remove_second_double")
total_tested += 1

# Remove first of each double
double_set_first = set(doubles)
reduced_first = "".join(CT[i] for i in range(CT_LEN) if i not in double_set_first)
check_candidate(reduced_first, "remove_first_double")
total_tested += 1

# Method E2: Doubles mark segment boundaries
print("\n--- E2: Doubles as segment boundaries ---")
# Split at double positions and rearrange
boundaries = [0] + [d + 2 for d in doubles] + [CT_LEN]
segments = []
for i in range(len(boundaries) - 1):
    seg = CT[boundaries[i]:boundaries[i + 1]]
    if seg:
        segments.append(seg)
print(f"  Segments: {len(segments)} -> lengths: {[len(s) for s in segments]}")

# Try reversing each segment
reversed_segs = "".join(s[::-1] for s in segments)
check_candidate(reversed_segs, "double_boundary_reverse_segments")
total_tested += 1

# Try various segment orderings (too many for full permutation, try specific ones)
for order_name, order in [
    ("reverse", list(reversed(range(len(segments))))),
    ("odds_then_evens", [i for i in range(len(segments)) if i % 2 == 1] +
                         [i for i in range(len(segments)) if i % 2 == 0]),
    ("evens_then_odds", [i for i in range(len(segments)) if i % 2 == 0] +
                         [i for i in range(len(segments)) if i % 2 == 1]),
]:
    reordered = "".join(segments[i] for i in order if i < len(segments))
    check_candidate(reordered, f"double_boundary_order_{order_name}")
    total_tested += 1

# Method E3: Double characters are null — remove both copies
print("\n--- E3: Remove both copies of doubles ---")
both_set = set()
for i in doubles:
    both_set.add(i)
    both_set.add(i + 1)
no_doubles = "".join(CT[i] for i in range(CT_LEN) if i not in both_set)
print(f"  No-doubles length: {len(no_doubles)}")
check_candidate(no_doubles, "remove_both_doubles")
total_tested += 1

# Try Caesar shifts on reduced texts
for shift in range(1, 26):
    shifted = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in reduced)
    check_candidate(shifted, f"remove_second_caesar_{shift}")
    total_tested += 1
    shifted2 = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in no_doubles)
    check_candidate(shifted2, f"remove_both_caesar_{shift}")
    total_tested += 1

# Method E4: Double positions encode a secondary message
print("\n--- E4: Doubles encode position info ---")
# The positions of doubles might encode something
double_positions = doubles  # [18, 25, 31, 41, 44, 66]
# Differences between double positions
diffs = [double_positions[i+1] - double_positions[i] for i in range(len(double_positions)-1)]
print(f"  Double position diffs: {diffs}")
# Convert diffs to letters
if all(1 <= d <= 26 for d in diffs):
    msg = "".join(chr(d - 1 + 65) for d in diffs)
    print(f"  Diff message: {msg}")

print("\n" + "=" * 60)
print("NOVEL METHOD I: Interval/Skip Ciphers")
print("=" * 60)

# Method I1: Read every Nth character with various starting positions
print("\n--- I1: Skip ciphers ---")
for n in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 17, 19, 23, 24, 29, 31, 37, 41, 43, 47, 48]:
    for start in range(min(n, CT_LEN)):
        extracted = CT[start::n]
        if len(extracted) >= 10:
            check_candidate(extracted, f"skip_{n}_start_{start}")
            total_tested += 1

# Method I2: Create N interleaved sequences, concatenate
print("\n--- I2: Interleaved sequences ---")
for n in [2, 3, 4, 5, 7, 11, 13]:
    # Deinterleave into N streams
    streams = [CT[i::n] for i in range(n)]
    # Try all orderings of the streams (for small n)
    if n <= 5:
        for perm in itertools.permutations(range(n)):
            concat = "".join(streams[p] for p in perm)
            check_candidate(concat, f"deinterleave_{n}_order_{''.join(map(str, perm))}")
            total_tested += 1
    else:
        # Just try reverse and a few specific orderings
        concat_fwd = "".join(streams)
        check_candidate(concat_fwd, f"deinterleave_{n}_forward")
        total_tested += 1
        concat_rev = "".join(reversed(streams))
        check_candidate(concat_rev, f"deinterleave_{n}_reverse")
        total_tested += 1

# Method I3: Decimation (multiplicative skip)
print("\n--- I3: Decimation ---")
from math import gcd
for mult in range(2, CT_LEN):
    if gcd(mult, CT_LEN) != 1:
        continue  # Skip non-coprime multipliers
    decimated = "".join(CT[(i * mult) % CT_LEN] for i in range(CT_LEN))
    check_candidate(decimated, f"decimate_mult_{mult}")
    total_tested += 1

# Apply Caesar to decimated texts for the most interesting multipliers
for mult in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
    if gcd(mult, CT_LEN) != 1:
        continue
    decimated = "".join(CT[(i * mult) % CT_LEN] for i in range(CT_LEN))
    for shift in range(1, 26):
        shifted = "".join(chr((ord(c) - 65 + shift) % 26 + 65) for c in decimated)
        check_candidate(shifted, f"decimate_{mult}_caesar_{shift}")
        total_tested += 1

print("\n" + "=" * 60)
print("NOVEL METHOD J: Self-Referential / Recursive")
print("=" * 60)

# Method J1: CT[i] mod 26 as key values for position (i+offset) mod 97
print("\n--- J1: CT as its own key with offsets ---")
for offset in range(CT_LEN):
    for variant in ["vig", "beaufort", "add"]:
        pt_chars = []
        for i in range(CT_LEN):
            key_pos = (i + offset) % CT_LEN
            key_val = ALPH_IDX[CT[key_pos]]
            ct_val = ALPH_IDX[CT[i]]
            if variant == "vig":
                pt_val = (ct_val - key_val) % 26
            elif variant == "beaufort":
                pt_val = (key_val - ct_val) % 26
            else:
                pt_val = (ct_val + key_val) % 26
            pt_chars.append(chr(pt_val + 65))
        pt = "".join(pt_chars)
        check_candidate(pt, f"self_key_offset{offset}_{variant}")
        total_tested += 1

# Method J2: CT reversed as key
print("\n--- J2: Reversed CT as key ---")
ct_rev = CT[::-1]
for variant in ["vig", "beaufort", "add"]:
    pt_chars = []
    for i in range(CT_LEN):
        key_val = ALPH_IDX[ct_rev[i]]
        ct_val = ALPH_IDX[CT[i]]
        if variant == "vig":
            pt_val = (ct_val - key_val) % 26
        elif variant == "beaufort":
            pt_val = (key_val - ct_val) % 26
        else:
            pt_val = (ct_val + key_val) % 26
        pt_chars.append(chr(pt_val + 65))
    pt = "".join(pt_chars)
    check_candidate(pt, f"self_reversed_{variant}")
    total_tested += 1

# Method J3: CT frequency-based key
print("\n--- J3: Frequency-based self-key ---")
freq = {}
for ch in CT:
    freq[ch] = freq.get(ch, 0) + 1
freq_sorted = sorted(freq.items(), key=lambda x: -x[1])
freq_key = {ch: i for i, (ch, _) in enumerate(freq_sorted)}

for variant in ["vig", "beaufort", "add"]:
    pt_chars = []
    for i, ch in enumerate(CT):
        key_val = freq_key[ch]
        ct_val = ALPH_IDX[ch]
        if variant == "vig":
            pt_val = (ct_val - key_val) % 26
        elif variant == "beaufort":
            pt_val = (key_val - ct_val) % 26
        else:
            pt_val = (ct_val + key_val) % 26
        pt_chars.append(chr(pt_val + 65))
    pt = "".join(pt_chars)
    check_candidate(pt, f"self_freq_{variant}")
    total_tested += 1

# Method J4: Cumulative self-key (running sum of CT values)
print("\n--- J4: Cumulative self-key ---")
for variant in ["vig", "beaufort"]:
    pt_chars = []
    cumsum = 0
    for i, ch in enumerate(CT):
        ct_val = ALPH_IDX[ch]
        key_val = cumsum % 26
        if variant == "vig":
            pt_val = (ct_val - key_val) % 26
        else:
            pt_val = (key_val - ct_val) % 26
        pt_chars.append(chr(pt_val + 65))
        cumsum += ct_val
    pt = "".join(pt_chars)
    check_candidate(pt, f"self_cumulative_{variant}")
    total_tested += 1

# Method J5: XOR-like with previous plaintext (progressive self-decryption)
print("\n--- J5: Progressive self-decryption ---")
for seed_val in range(26):
    for variant in ["vig", "beaufort"]:
        pt_chars = []
        prev = seed_val
        for i, ch in enumerate(CT):
            ct_val = ALPH_IDX[ch]
            if variant == "vig":
                pt_val = (ct_val - prev) % 26
            else:
                pt_val = (prev - ct_val) % 26
            pt_chars.append(chr(pt_val + 65))
            prev = pt_val
        pt = "".join(pt_chars)
        check_candidate(pt, f"self_progressive_seed{seed_val}_{variant}")
        total_tested += 1

print(f"\nTotal doubles/intervals/self-ref configs tested: {total_tested}")
print(f"Best: {best_overall['method']} -> {best_overall['score']}/24")
if best_overall['score'] > 0:
    print(f"  Text: {best_overall['text'][:60]}...")

with open(os.path.join(RESULTS_DIR, "doubles_intervals_selfref.json"), "w") as f:
    json.dump({
        "method": "doubles_intervals_selfref",
        "total_tested": total_tested,
        "best_score": best_overall["score"],
        "best_method": best_overall["method"],
        "best_text": best_overall["text"],
        "above_noise": all_results,
    }, f, indent=2)

print(f"\nResults saved to results/novel_methods/doubles_intervals_selfref.json")
