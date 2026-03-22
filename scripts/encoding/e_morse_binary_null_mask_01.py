#!/usr/bin/env python3
"""
Cipher: encoding/morse_binary_null
Family: encoding
Status: active
Keyspace: ~200 configs
Last run: never
Best score: n/a

Hypothesis: Converting K4 CT letters to their Morse code equivalents,
then extracting a binary property per letter, yields the null mask.

Motivated by Smithsonian archive: Sanborn's "Russian Decoding Chart"
(2002) shows Letter → Morse → Binary pipeline for Cyrillic Projector.

PRE-REGISTERED MAPPINGS (4):
  1. First Morse symbol is dash → null
  2. First Morse symbol is dot → null
  3. Morse length >= 4 → null
  4. Morse length == 1 → null

SECONDARY MAPPINGS (exploratory, flagged as post-hoc):
  5-6.   Last symbol dash/dot → null
  7-8.   Even/odd Morse length → null
  9-10.  More dashes than dots / vice versa → null
  11-12. Dot parity even/odd → null
  13-16. First two symbols match specific patterns → null
  17-18. Dash count >= 2 / <= 1 → null
  19-20. Palindromic / non-palindromic Morse → null

FULL BINARY STREAM APPROACH:
  21+. Convert all 97 letters to Morse → binary stream (~299 bits).
       Try various extraction rules to map back to 97 positions.

Evaluation: overlap with 17 consensus null positions.
Statistical threshold: pre-registered p < 0.05, post-hoc p < 0.005
(Bonferroni for ~20 secondary tests).

Output: results/e_morse_binary_null_mask_01.json
"""

import json
import os
import sys
import time
from math import comb, log, factorial
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS

# ── MORSE CODE TABLE ────────────────────────────────────────────────────────

MORSE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',
    'E': '.',     'F': '..-.',  'G': '--.',   'H': '....',
    'I': '..',    'J': '.---',  'K': '-.-',   'L': '.-..',
    'M': '--',    'N': '-.',    'O': '---',   'P': '.--.',
    'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',
    'Y': '-.--',  'Z': '--..',
}

# Known ground truth
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
ALL_CRIB_POS = set(range(21, 34)) | set(range(63, 74))  # 24 positions
NULL_PALETTE = set("BIGKOWZ")

# Total nulls expected
EXPECTED_NULLS = 24

print("=" * 70)
print("K4 CT → MORSE → BINARY → NULL MASK")
print("=" * 70)
print(f"CT: {CT}")
print(f"CT length: {CT_LEN}")
print()

# ── Precompute Morse properties for each CT position ─────────────────────

ct_morse = [MORSE[c] for c in CT]
ct_morse_len = [len(m) for m in ct_morse]
ct_first_sym = [m[0] for m in ct_morse]
ct_last_sym = [m[-1] for m in ct_morse]
ct_dot_count = [m.count('.') for m in ct_morse]
ct_dash_count = [m.count('-') for m in ct_morse]

total_morse_symbols = sum(ct_morse_len)
print(f"Total Morse symbols from 97 CT letters: {total_morse_symbols}")
print(f"Morse length distribution: {dict(sorted(Counter(ct_morse_len).items()))}")
print(f"Mean Morse length: {total_morse_symbols/97:.2f}")
print()

# ── Statistical evaluation function ──────────────────────────────────────

def hypergeometric_pvalue(N, K, n, k):
    """
    P(X >= k) under hypergeometric distribution.
    N = population size (97)
    K = number of successes in population (17 consensus nulls)
    n = number of draws (positions selected by rule)
    k = observed successes (overlap)
    """
    if k > min(K, n) or k < max(0, n + K - N):
        return 1.0

    total = 0.0
    for x in range(k, min(K, n) + 1):
        # P(X = x) = C(K,x) * C(N-K, n-x) / C(N, n)
        try:
            p = comb(K, x) * comb(N - K, n - x) / comb(N, n)
            total += p
        except (ValueError, OverflowError):
            pass
    return total


def evaluate_mapping(name, null_positions, category="pre-registered"):
    """Evaluate a null-position mapping against consensus nulls."""
    null_set = set(null_positions)
    count = len(null_set)

    # Overlap with consensus nulls
    overlap = null_set & CONSENSUS_NULLS
    n_overlap = len(overlap)

    # Overlap with crib positions (MUST be zero for valid mask)
    crib_overlap = null_set & ALL_CRIB_POS
    n_crib_conflict = len(crib_overlap)

    # Expected overlap under random selection of 'count' from 97
    expected_overlap = count * 17 / 97

    # Hypergeometric p-value for overlap >= n_overlap
    p_value = hypergeometric_pvalue(97, 17, count, n_overlap)

    # Check if null palette letters are concentrated
    null_letters = [CT[i] for i in null_set]
    palette_in_nulls = sum(1 for c in null_letters if c in NULL_PALETTE)
    palette_expected = count * 35 / 97  # 35 palette letters in CT97

    result = {
        "name": name,
        "category": category,
        "positions_selected": count,
        "target": EXPECTED_NULLS,
        "overlap_with_consensus": n_overlap,
        "expected_overlap": round(expected_overlap, 2),
        "p_value": p_value,
        "crib_conflicts": n_crib_conflict,
        "palette_in_selected": palette_in_nulls,
        "palette_expected": round(palette_expected, 2),
        "null_positions": sorted(null_set),
    }

    # Significance assessment
    if category == "pre-registered":
        sig = "SIGNIFICANT" if p_value < 0.05 else "not significant"
    else:
        sig = "SIGNIFICANT" if p_value < 0.005 else "not significant"

    status = "CONFLICT" if n_crib_conflict > 0 else "clean"

    print(f"  {name:40s}  n={count:2d}  overlap={n_overlap:2d}/17 "
          f"(exp={expected_overlap:.1f})  p={p_value:.4f} [{sig}]  "
          f"cribs={status}  palette={palette_in_nulls}/{count}")

    return result


# ════════════════════════════════════════════════════════════════════════════
# PRE-REGISTERED MAPPINGS (4)
# ════════════════════════════════════════════════════════════════════════════

print("─" * 70)
print("PRE-REGISTERED MAPPINGS (significance threshold: p < 0.05)")
print("─" * 70)

all_results = []

# 1. First symbol is dash → null
nulls_1 = [i for i in range(97) if ct_first_sym[i] == '-']
all_results.append(evaluate_mapping("1. First symbol dash → null", nulls_1, "pre-registered"))

# 2. First symbol is dot → null
nulls_2 = [i for i in range(97) if ct_first_sym[i] == '.']
all_results.append(evaluate_mapping("2. First symbol dot → null", nulls_2, "pre-registered"))

# 3. Morse length >= 4 → null
nulls_3 = [i for i in range(97) if ct_morse_len[i] >= 4]
all_results.append(evaluate_mapping("3. Morse length >= 4 → null", nulls_3, "pre-registered"))

# 4. Morse length == 1 → null
nulls_4 = [i for i in range(97) if ct_morse_len[i] == 1]
all_results.append(evaluate_mapping("4. Morse length == 1 → null", nulls_4, "pre-registered"))


# ════════════════════════════════════════════════════════════════════════════
# SECONDARY MAPPINGS (exploratory, Bonferroni threshold p < 0.005)
# ════════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("SECONDARY MAPPINGS (significance threshold: p < 0.005 Bonferroni)")
print("─" * 70)

# 5. Last symbol is dash → null
nulls_5 = [i for i in range(97) if ct_last_sym[i] == '-']
all_results.append(evaluate_mapping("5. Last symbol dash → null", nulls_5, "secondary"))

# 6. Last symbol is dot → null
nulls_6 = [i for i in range(97) if ct_last_sym[i] == '.']
all_results.append(evaluate_mapping("6. Last symbol dot → null", nulls_6, "secondary"))

# 7. Even Morse length → null
nulls_7 = [i for i in range(97) if ct_morse_len[i] % 2 == 0]
all_results.append(evaluate_mapping("7. Even Morse length → null", nulls_7, "secondary"))

# 8. Odd Morse length → null
nulls_8 = [i for i in range(97) if ct_morse_len[i] % 2 == 1]
all_results.append(evaluate_mapping("8. Odd Morse length → null", nulls_8, "secondary"))

# 9. More dashes than dots → null
nulls_9 = [i for i in range(97) if ct_dash_count[i] > ct_dot_count[i]]
all_results.append(evaluate_mapping("9. More dashes than dots → null", nulls_9, "secondary"))

# 10. More dots than dashes → null
nulls_10 = [i for i in range(97) if ct_dot_count[i] > ct_dash_count[i]]
all_results.append(evaluate_mapping("10. More dots than dashes → null", nulls_10, "secondary"))

# 11. Even dot count → null
nulls_11 = [i for i in range(97) if ct_dot_count[i] % 2 == 0]
all_results.append(evaluate_mapping("11. Even dot count → null", nulls_11, "secondary"))

# 12. Odd dot count → null
nulls_12 = [i for i in range(97) if ct_dot_count[i] % 2 == 1]
all_results.append(evaluate_mapping("12. Odd dot count → null", nulls_12, "secondary"))

# 13-16. First two symbols patterns (only for letters with len >= 2)
for pattern in ['..', '.-', '-.', '--']:
    label = pattern.replace('.', 'dot').replace('-', 'dash')
    nulls = [i for i in range(97) if len(ct_morse[i]) >= 2 and ct_morse[i][:2] == pattern]
    all_results.append(evaluate_mapping(f"13-16. First two = {label} → null", nulls, "secondary"))

# 17. Dash count >= 2 → null
nulls_17 = [i for i in range(97) if ct_dash_count[i] >= 2]
all_results.append(evaluate_mapping("17. Dash count >= 2 → null", nulls_17, "secondary"))

# 18. Dash count <= 1 → null
nulls_18 = [i for i in range(97) if ct_dash_count[i] <= 1]
all_results.append(evaluate_mapping("18. Dash count <= 1 → null", nulls_18, "secondary"))

# 19. Palindromic Morse → null
nulls_19 = [i for i in range(97) if ct_morse[i] == ct_morse[i][::-1]]
all_results.append(evaluate_mapping("19. Palindromic Morse → null", nulls_19, "secondary"))

# 20. Non-palindromic Morse → null
nulls_20 = [i for i in range(97) if ct_morse[i] != ct_morse[i][::-1]]
all_results.append(evaluate_mapping("20. Non-palindromic Morse → null", nulls_20, "secondary"))


# ════════════════════════════════════════════════════════════════════════════
# FULL BINARY STREAM APPROACH
# ════════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("FULL BINARY STREAM APPROACH")
print("─" * 70)

# Convert all 97 CT letters to Morse, concatenate, then to binary
morse_concat = ''.join(ct_morse)
print(f"Concatenated Morse: {len(morse_concat)} symbols")
print(f"First 80 symbols: {morse_concat[:80]}")

# Binary streams: dot=0/dash=1 and dot=1/dash=0
for polarity_name, dot_val, dash_val in [("dot=0 dash=1", '0', '1'), ("dot=1 dash=0", '1', '0')]:
    binary = ''.join(dot_val if c == '.' else dash_val for c in morse_concat)
    print(f"\n  Polarity: {polarity_name}")
    print(f"  Binary length: {len(binary)} bits")
    print(f"  Bit distribution: 0s={binary.count('0')}, 1s={binary.count('1')}")

    # Approach 1: Take every Nth bit where N = len(binary)/97
    ratio = len(binary) / 97
    print(f"  Ratio bits/positions: {ratio:.2f}")

    # Approach 2: Map letter boundaries → one bit per letter
    # Use the cumulative start position of each letter's Morse
    letter_starts = []
    pos = 0
    for m in ct_morse:
        letter_starts.append(pos)
        pos += len(m)

    # Take the bit at the start of each letter's Morse representation
    start_bits = [binary[letter_starts[i]] for i in range(97)]
    nulls_start = [i for i in range(97) if start_bits[i] == '1']
    all_results.append(evaluate_mapping(
        f"Stream: start-bit=1 ({polarity_name})", nulls_start, "secondary"))

    # Take the bit at the end of each letter's Morse representation
    letter_ends = [letter_starts[i] + ct_morse_len[i] - 1 for i in range(97)]
    end_bits = [binary[letter_ends[i]] for i in range(97)]
    nulls_end = [i for i in range(97) if end_bits[i] == '1']
    all_results.append(evaluate_mapping(
        f"Stream: end-bit=1 ({polarity_name})", nulls_end, "secondary"))

    # Approach 3: Cumulative sum mod 2 at letter boundaries
    cum_sum = 0
    nulls_cum = []
    for i in range(97):
        start = letter_starts[i]
        end = start + ct_morse_len[i]
        segment_sum = sum(int(b) for b in binary[start:end])
        cum_sum += segment_sum
        if cum_sum % 2 == 1:
            nulls_cum.append(i)
    all_results.append(evaluate_mapping(
        f"Stream: cumsum mod 2 ({polarity_name})", nulls_cum, "secondary"))

    # Approach 4: XOR of all bits in each letter's Morse
    nulls_xor = []
    for i in range(97):
        start = letter_starts[i]
        end = start + ct_morse_len[i]
        xor_val = 0
        for b in binary[start:end]:
            xor_val ^= int(b)
        if xor_val == 1:
            nulls_xor.append(i)
    all_results.append(evaluate_mapping(
        f"Stream: XOR per letter ({polarity_name})", nulls_xor, "secondary"))

    # Approach 5: Every 3rd bit (closest integer ratio)
    for step in [3, 4, 5]:
        sampled = [binary[i] for i in range(0, len(binary), step)][:97]
        if len(sampled) < 97:
            sampled.extend(['0'] * (97 - len(sampled)))
        nulls_step = [i for i in range(97) if sampled[i] == '1']
        all_results.append(evaluate_mapping(
            f"Stream: every-{step}th bit=1 ({polarity_name})", nulls_step, "secondary"))


# ════════════════════════════════════════════════════════════════════════════
# PALETTE LETTER ANALYSIS
# ════════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PALETTE LETTER MORSE PROPERTIES")
print("─" * 70)

print("\n  Null palette letters and their Morse codes:")
for letter in sorted(NULL_PALETTE):
    m = MORSE[letter]
    print(f"    {letter} = {m:5s}  len={len(m)}  first={m[0]}  last={m[-1]}  "
          f"dots={m.count('.')}  dashes={m.count('-')}  "
          f"palindrome={'Y' if m == m[::-1] else 'N'}")

print("\n  Non-palette letters for comparison:")
non_palette = sorted(set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") - NULL_PALETTE)
for letter in non_palette:
    m = MORSE[letter]
    print(f"    {letter} = {m:5s}  len={len(m)}  first={m[0]}  last={m[-1]}  "
          f"dots={m.count('.')}  dashes={m.count('-')}  "
          f"palindrome={'Y' if m == m[::-1] else 'N'}")

# Check if palette letters share any common Morse property
print("\n  Palette Morse property summary:")
pal_lens = [len(MORSE[c]) for c in NULL_PALETTE]
pal_firsts = [MORSE[c][0] for c in NULL_PALETTE]
pal_lasts = [MORSE[c][-1] for c in NULL_PALETTE]
print(f"    Lengths: {sorted(pal_lens)} (range {min(pal_lens)}-{max(pal_lens)})")
print(f"    First symbols: {Counter(pal_firsts)} (dots={pal_firsts.count('.')}, dashes={pal_firsts.count('-')})")
print(f"    Last symbols:  {Counter(pal_lasts)} (dots={pal_lasts.count('.')}, dashes={pal_lasts.count('-')})")
pal_palindromes = sum(1 for c in NULL_PALETTE if MORSE[c] == MORSE[c][::-1])
print(f"    Palindromic: {pal_palindromes}/7")


# ════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("SUMMARY — K4 CT → Morse → Binary → Null Mask")
print("=" * 70)

# Sort by p-value
sorted_results = sorted(all_results, key=lambda r: r["p_value"])

print("\n  Top 10 mappings by p-value:")
print(f"  {'Rank':4s}  {'Mapping':45s}  {'n':>3s}  {'Overlap':>7s}  {'p-value':>8s}  {'Sig?':>8s}  {'Cribs':>5s}")
print(f"  {'─'*4}  {'─'*45}  {'─'*3}  {'─'*7}  {'─'*8}  {'─'*8}  {'─'*5}")

any_significant = False
for rank, r in enumerate(sorted_results[:10], 1):
    threshold = 0.05 if r["category"] == "pre-registered" else 0.005
    sig = "YES" if r["p_value"] < threshold else "no"
    if sig == "YES":
        any_significant = True
    crib_status = "CLEAN" if r["crib_conflicts"] == 0 else f"BAD({r['crib_conflicts']})"
    print(f"  {rank:4d}  {r['name']:45s}  {r['positions_selected']:3d}  "
          f"{r['overlap_with_consensus']:2d}/17   {r['p_value']:.6f}  {sig:>8s}  {crib_status:>5s}")

# Pre-registered summary
print("\n  PRE-REGISTERED RESULTS:")
for r in all_results[:4]:
    sig = "SIGNIFICANT" if r["p_value"] < 0.05 else "NOT SIGNIFICANT"
    print(f"    {r['name']:45s}  overlap={r['overlap_with_consensus']}/17  p={r['p_value']:.4f}  [{sig}]")

# Overall verdict
print(f"\n  ANY pre-registered mapping significant (p<0.05)?  {'YES' if any([r['p_value'] < 0.05 for r in all_results[:4]]) else 'NO'}")
print(f"  ANY secondary mapping significant (p<0.005)?     {'YES' if any([r['p_value'] < 0.005 for r in all_results[4:]]) else 'NO'}")

if not any_significant:
    verdict = "ELIMINATED"
    print(f"\n  VERDICT: {verdict}")
    print("  Morse code properties of K4 CT letters do NOT predict null positions.")
    print("  The Letter → Morse → Binary pipeline, while confirmed for the")
    print("  Cyrillic Projector, does NOT appear to operate on K4.")
else:
    verdict = "INVESTIGATE"
    print(f"\n  VERDICT: {verdict}")
    print("  One or more mappings show significant overlap. Requires validation.")

# Save results
output = {
    "experiment": "e_morse_binary_null_mask_01",
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "ct": CT,
    "total_morse_symbols": total_morse_symbols,
    "verdict": verdict,
    "pre_registered_count": 4,
    "secondary_count": len(all_results) - 4,
    "any_pre_reg_significant": any(r["p_value"] < 0.05 for r in all_results[:4]),
    "any_secondary_significant": any(r["p_value"] < 0.005 for r in all_results[4:]),
    "results": sorted_results,
}

out_path = os.path.join(_ROOT, "results", "e_morse_binary_null_mask_01.json")
with open(out_path, "w") as f:
    json.dump(output, f, indent=2, default=str)
print(f"\n  Results saved to: {out_path}")
