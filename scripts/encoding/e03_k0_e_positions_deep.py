#!/usr/bin/env python3
"""
Cipher: encoding/extraction
Family: encoding
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
"""E-03: Deep analysis of 26 padding-E positions in Kryptos K0 Morse code.

The Kryptos entrance tablets contain Morse code that decodes to ~86 characters
plus ~26 padding E characters (total ~112 tokens). Key observations:
  - 26 = exact size of the Latin alphabet
  - E in Morse is a single dit (.) -- shortest possible character
  - The misspelling DIGETAL (instead of DIGITAL) adds exactly ONE more E to
    reach 26 padding E's
  - Sanborn was EVASIVE when asked about the extra E's
  - Sanborn said the entrance contains "certain ancient ciphers" (plural)

Analysis phases:
  1. Full K0 reconstruction with position numbering
  2. Binary mask analysis (Bacon cipher, patterns)
  3. E-position arithmetic/algebraic analysis
  4. E-removal analysis
  5. Alternative grouping analysis
  6. 26 E's = key derivation and test against K4
  7. Interleaved cipher analysis
  8. Connection to K4 (Vigenere/Beaufort key tests)

Output: results/e03_k0_e_positions_deep.json
"""

import json
import math
import os
import sys
import time
from collections import Counter
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR, N_CRIBS,
    KRYPTOS_ALPHABET, CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ═══════════════════════════════════════════════════════════════════════════════
# MORSE CODE DATA — Community consensus transcription
# Uppercase = message letter, lowercase 'e' = padding/extra E
# Sources: kryptosfan.wordpress.com, Elonka Dunin, Gillogly photos
# ═══════════════════════════════════════════════════════════════════════════════

MORSE_TOKENS = [
    'e', 'e',  # 2 E's before VIRTUALLY
    'V', 'I', 'R', 'T', 'U', 'A', 'L', 'L', 'Y',
    'e',  # 1 E after VIRTUALLY
    'e', 'e', 'e', 'e', 'e',  # 5 E's before INVISIBLE
    'I', 'N', 'V', 'I', 'S', 'I', 'B', 'L', 'E',  # INVISIBLE (final E is word-E)
    'e',  # 1 E
    'D', 'I', 'G', 'E', 'T', 'A', 'L',  # DIGETAL (E is word-E from misspelling)
    'e', 'e', 'e',  # 3 E's
    'I', 'N', 'T', 'E', 'R', 'P', 'R', 'E', 'T', 'A', 'T', 'I', 'U',  # INTERPRETATIU
    'e', 'e',  # 2 E's
    'S', 'H', 'A', 'D', 'O', 'W',
    'e', 'e',  # 2 E's
    'F', 'O', 'R', 'C', 'E', 'S',  # FORCES (E is word-E)
    'e', 'e', 'e', 'e', 'e',  # 5 E's
    'L', 'U', 'C', 'I', 'D',
    'e', 'e', 'e',  # 3 E's
    'M', 'E', 'M', 'O', 'R', 'Y',  # MEMORY (E is word-E)
    'e',  # 1 E
    'T', 'I', 'S', 'Y', 'O', 'U', 'R',
    'P', 'O', 'S', 'I', 'T', 'I', 'O', 'N',
    'e',  # 1 E
    'S', 'O', 'S',
    'R', 'Q',
]

# E-group sizes COMPUTED from token stream: [2, 6, 1, 3, 2, 2, 5, 3, 1, 1]
# 10 groups, sum = 26.
#
# IMPORTANT: Prior scripts (E-01, E-S-144, E-CHART-04) used [2,1,5,1,3,2,2,5,3,1,1]
# (11 groups) which INCORRECTLY split the run of 6 E's between VIRTUALLY and INVISIBLE
# into "1 after VIRTUALLY" + "5 before INVISIBLE". In the actual token stream, these
# are contiguous (positions 11-16) with no non-e token between them. The correct
# group sizes are [2, 6, 1, 3, 2, 2, 5, 3, 1, 1].
#
# Whether Sanborn INTENDED a semantic break (1 word-gap E + 5 phrase-gap E's) is
# a separate question from the physical transcription. In Morse code, there IS
# no visible break between these E's — they are all just dits.
E_GROUP_SIZES = [2, 6, 1, 3, 2, 2, 5, 3, 1, 1]  # CORRECTED: 10 groups
E_GROUP_SIZES_LEGACY = [2, 1, 5, 1, 3, 2, 2, 5, 3, 1, 1]  # Old (11 groups) for comparison


# ═══════════════════════════════════════════════════════════════════════════════
# CIPHER PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════════

def vig_dec(ct_nums, key_nums):
    p = len(key_nums)
    return [(ct_nums[i] - key_nums[i % p]) % MOD for i in range(len(ct_nums))]


def beau_dec(ct_nums, key_nums):
    p = len(key_nums)
    return [(key_nums[i % p] - ct_nums[i]) % MOD for i in range(len(ct_nums))]


def varbeau_dec(ct_nums, key_nums):
    p = len(key_nums)
    return [(ct_nums[i] + key_nums[i % p]) % MOD for i in range(len(ct_nums))]


def nums_to_text(nums):
    return ''.join(chr(ord('A') + n) for n in nums)


def score_cribs_nums(pt_nums):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == ALPH_IDX[ch]:
            matches += 1
    return matches


def score_cribs_text(text):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            matches += 1
    return matches


def check_bean_vig(pt_nums):
    """Check Bean constraints assuming Vigenere."""
    if len(pt_nums) < CT_LEN:
        return False
    key = [(CT_NUM[i] - pt_nums[i]) % MOD for i in range(CT_LEN)]
    for a, b in BEAN_EQ:
        if key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if key[a] == key[b]:
            return False
    return True


def check_bean_beau(pt_nums):
    """Check Bean constraints assuming Beaufort."""
    if len(pt_nums) < CT_LEN:
        return False
    key = [(CT_NUM[i] + pt_nums[i]) % MOD for i in range(CT_LEN)]
    for a, b in BEAN_EQ:
        if key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if key[a] == key[b]:
            return False
    return True


def ic(text):
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = Counter(text)
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))


def find_crib_anywhere(text, crib):
    """Find all occurrences of crib in text."""
    positions = []
    for i in range(len(text) - len(crib) + 1):
        if text[i:i + len(crib)] == crib:
            positions.append(i)
    return positions


# English quadgram scoring (if available)
QUADGRAMS = None
QUADGRAM_FLOOR = None
try:
    qg_path = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
    if os.path.exists(qg_path):
        with open(qg_path) as f:
            QUADGRAMS = json.load(f)
        QUADGRAM_FLOOR = min(QUADGRAMS.values()) - 1.0
except Exception:
    pass


def quadgram_score(text):
    """Log-probability of text under English quadgram model."""
    if QUADGRAMS is None:
        return None
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        score += QUADGRAMS.get(qg, QUADGRAM_FLOOR)
    return score / max(1, len(text) - 3)


# ═══════════════════════════════════════════════════════════════════════════════
# TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

best_score = 0
best_tag = ""
best_pt = ""
total_configs = 0
results_log = []
findings = {}


def test_and_log(tag, pt_text_or_nums, is_nums=False):
    global best_score, best_tag, best_pt, total_configs
    total_configs += 1
    if is_nums:
        pt_nums = pt_text_or_nums
        pt_text = nums_to_text(pt_nums)
    else:
        pt_text = pt_text_or_nums
        pt_nums = [ALPH_IDX.get(c, 0) for c in pt_text.upper() if c in ALPH_IDX]

    score = score_cribs_text(pt_text[:CT_LEN]) if not is_nums else score_cribs_nums(pt_nums)
    if score > best_score:
        best_score = score
        best_tag = tag
        best_pt = pt_text[:60]
        print(f"  ** NEW BEST: {score}/{N_CRIBS} -- {tag}")
        print(f"     PT: {pt_text[:70]}...")
    if score >= NOISE_FLOOR:
        results_log.append({"tag": tag, "score": score, "pt_prefix": pt_text[:50]})
    return score


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: Full K0 reconstruction with position numbering
# ═══════════════════════════════════════════════════════════════════════════════

def phase1_reconstruct():
    print("=" * 80)
    print("PHASE 1: Full K0 Reconstruction")
    print("=" * 80)

    # Enumerate every position
    padding_e_positions = []  # positions (0-indexed) of padding E's
    word_e_positions = []     # positions of E's that are part of words
    all_chars = []            # all characters in order

    for i, token in enumerate(MORSE_TOKENS):
        if token == 'e':
            padding_e_positions.append(i)
            all_chars.append('E')  # padding E rendered uppercase for display
        else:
            if token == 'E':
                word_e_positions.append(i)
            all_chars.append(token)

    full_text = ''.join(all_chars)

    print(f"\n  Total tokens: {len(MORSE_TOKENS)}")
    print(f"  Padding E count: {len(padding_e_positions)}")
    print(f"  Word-E count: {len(word_e_positions)}")
    print(f"  Non-E message letters: {len(MORSE_TOKENS) - len(padding_e_positions) - len(word_e_positions)}")
    print(f"  Full text length: {len(full_text)}")

    print(f"\n  Full linearized text (E=padding, e=word):")
    # Display with position markers
    line = ""
    for i, token in enumerate(MORSE_TOKENS):
        if token == 'e':
            line += '*'  # asterisk = padding E
        elif token == 'E':
            line += 'e'  # lowercase = word E
        else:
            line += token
    print(f"    {line}")

    # Position numbering
    print(f"\n  Padding E positions (0-indexed in token stream):")
    print(f"    {padding_e_positions}")
    print(f"\n  Word-E positions:")
    print(f"    {word_e_positions}")

    # What words do the word-E's belong to?
    # INVISIBLE[8], DIGETAL[3], INTERPRETATIU[3,7], FORCES[4], MEMORY[1]
    print(f"\n  Word-E context:")
    for wpos in word_e_positions:
        # Find context: 3 tokens before and after
        start = max(0, wpos - 3)
        end = min(len(MORSE_TOKENS), wpos + 4)
        ctx = ''.join(t if t != 'e' else '.' for t in MORSE_TOKENS[start:end])
        print(f"    Pos {wpos}: ...{ctx}... (E in word)")

    # E group analysis
    print(f"\n  E-groups (contiguous padding E runs):")
    groups = []
    current_group = []
    for i, token in enumerate(MORSE_TOKENS):
        if token == 'e':
            current_group.append(i)
        else:
            if current_group:
                groups.append(current_group[:])
                current_group = []
    if current_group:
        groups.append(current_group)

    for gi, group in enumerate(groups):
        print(f"    Group {gi}: size={len(group)}, positions={group}")

    group_sizes = [len(g) for g in groups]
    print(f"\n  Group sizes: {group_sizes}")
    print(f"  Sum of group sizes: {sum(group_sizes)}")
    print(f"  Number of groups: {len(groups)}")

    # FLAG DISCREPANCY with prior scripts
    legacy_sizes = [2, 1, 5, 1, 3, 2, 2, 5, 3, 1, 1]
    if group_sizes != legacy_sizes:
        print(f"\n  *** DISCREPANCY DETECTED ***")
        print(f"  Computed:   {group_sizes} ({len(group_sizes)} groups)")
        print(f"  Legacy E01: {legacy_sizes} ({len(legacy_sizes)} groups)")
        print(f"  The 6-E run after VIRTUALLY was split as 1+5 in prior scripts.")
        print(f"  In the token stream, these are contiguous (no break).")
        print(f"  This means ALL prior E-group key derivations used wrong data.")

    findings['phase1'] = {
        'total_tokens': len(MORSE_TOKENS),
        'padding_e_count': len(padding_e_positions),
        'word_e_count': len(word_e_positions),
        'padding_e_positions': padding_e_positions,
        'word_e_positions': word_e_positions,
        'group_sizes': group_sizes,
        'full_text': full_text,
    }
    return padding_e_positions, word_e_positions, groups


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: Binary mask analysis
# ═══════════════════════════════════════════════════════════════════════════════

def phase2_binary_mask(padding_positions):
    print("\n" + "=" * 80)
    print("PHASE 2: Binary Mask Analysis")
    print("=" * 80)

    # Create binary string: padding-E = 0, everything else = 1
    binary = []
    for i, token in enumerate(MORSE_TOKENS):
        if token == 'e':
            binary.append(0)
        else:
            binary.append(1)

    binary_str = ''.join(str(b) for b in binary)
    n = len(binary_str)

    print(f"\n  Binary mask (0=padding-E, 1=other):")
    # Print in rows of 20
    for i in range(0, n, 20):
        chunk = binary_str[i:i + 20]
        positions = ' '.join(f'{j:2d}' for j in range(i, min(i + 20, n)))
        print(f"    [{i:3d}] {chunk}")

    print(f"\n  Length: {n}")
    print(f"  Zeros (padding-E): {binary.count(0)}")
    print(f"  Ones (non-padding): {binary.count(1)}")

    # --- 2a: Bacon cipher (5-bit groups) ---
    print(f"\n  --- 2a: Bacon Cipher (5-bit groups) ---")
    # Bacon: A=0=00000, B=1=00001, ... Z=25=11001 (or other mapping)
    # Try standard binary (a=00000, b=00001, etc.)
    if n >= 5:
        bacon_letters_standard = []
        bacon_letters_reversed = []  # 0=B, 1=A
        for i in range(0, n - 4, 5):
            chunk = binary[i:i + 5]
            val = sum(bit << (4 - j) for j, bit in enumerate(chunk))
            rev_val = sum((1 - bit) << (4 - j) for j, bit in enumerate(chunk))
            if val < 26:
                bacon_letters_standard.append(chr(ord('A') + val))
            else:
                bacon_letters_standard.append('?')
            if rev_val < 26:
                bacon_letters_reversed.append(chr(ord('A') + rev_val))
            else:
                bacon_letters_reversed.append('?')

        bacon_std = ''.join(bacon_letters_standard)
        bacon_rev = ''.join(bacon_letters_reversed)
        print(f"    Standard (0=a): {bacon_std} ({len(bacon_std)} letters)")
        print(f"    Reversed (0=b): {bacon_rev} ({len(bacon_rev)} letters)")

        # Also try 24-letter Bacon (I/J and U/V merged)
        BACON_24 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # I=J, U=V
        bacon_24_letters = []
        for i in range(0, n - 4, 5):
            chunk = binary[i:i + 5]
            val = sum(bit << (4 - j) for j, bit in enumerate(chunk))
            if val < 24:
                bacon_24_letters.append(BACON_24[val])
            else:
                bacon_24_letters.append('?')
        bacon_24_text = ''.join(bacon_24_letters)
        print(f"    Bacon-24 (I/J, U/V): {bacon_24_text}")

        # Check if any result contains English words
        for name, text in [("standard", bacon_std), ("reversed", bacon_rev), ("bacon24", bacon_24_text)]:
            for crib in ["EAST", "NORTH", "BERLIN", "CLOCK", "KEY", "THE", "AND"]:
                if crib in text:
                    print(f"    ** Found '{crib}' in {name} Bacon decode!")

    # --- 2b: Period analysis ---
    print(f"\n  --- 2b: Period/pattern analysis ---")
    # Check for regular patterns at various periods
    for period in range(2, 20):
        # Count how well binary repeats at this period
        matches = 0
        total = 0
        for i in range(n - period):
            if binary[i] == binary[i + period]:
                matches += 1
            total += 1
        if total > 0:
            ratio = matches / total
            if ratio > 0.70 or ratio < 0.30:  # significantly different from 0.5
                print(f"    Period {period}: match ratio = {ratio:.3f} "
                      f"({'PERIODIC' if ratio > 0.70 else 'ANTI-PERIODIC'})")

    # --- 2c: Autocorrelation ---
    print(f"\n  --- 2c: Autocorrelation of binary mask ---")
    mean_b = sum(binary) / n
    var_b = sum((b - mean_b) ** 2 for b in binary) / n
    if var_b > 0:
        for lag in range(1, min(30, n)):
            cov = sum((binary[i] - mean_b) * (binary[i + lag] - mean_b)
                      for i in range(n - lag)) / (n - lag)
            acf = cov / var_b
            if abs(acf) > 0.3:
                print(f"    Lag {lag}: ACF = {acf:.3f}")

    # --- 2d: Run-length encoding ---
    print(f"\n  --- 2d: Run-length encoding ---")
    runs = []
    current_val = binary[0]
    current_len = 1
    for i in range(1, n):
        if binary[i] == current_val:
            current_len += 1
        else:
            runs.append((current_val, current_len))
            current_val = binary[i]
            current_len = 1
    runs.append((current_val, current_len))

    print(f"    Runs ({len(runs)} total): ", end="")
    for val, length in runs:
        print(f"{'E' if val == 0 else 'L'}×{length} ", end="")
    print()

    # Extract just the run lengths
    run_lengths = [length for _, length in runs]
    zero_runs = [length for val, length in runs if val == 0]
    one_runs = [length for val, length in runs if val == 1]
    print(f"    Padding-E run lengths: {zero_runs}")
    print(f"    Message run lengths: {one_runs}")
    print(f"    All run lengths: {run_lengths}")

    # Do run lengths encode something?
    if len(run_lengths) >= 1:
        # Try run lengths mod 26 as letters
        rl_letters = ''.join(chr(ord('A') + (r - 1) % 26) for r in run_lengths)
        print(f"    Run lengths as letters (1=A): {rl_letters}")
        rl_letters2 = ''.join(chr(ord('A') + r % 26) for r in run_lengths)
        print(f"    Run lengths as letters (0=A): {rl_letters2}")

    findings['phase2'] = {
        'binary_mask': binary_str,
        'bacon_standard': bacon_std if n >= 5 else "",
        'bacon_reversed': bacon_rev if n >= 5 else "",
        'run_lengths': run_lengths,
        'zero_runs': zero_runs,
        'one_runs': one_runs,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: E-position analysis
# ═══════════════════════════════════════════════════════════════════════════════

def phase3_position_analysis(padding_positions):
    print("\n" + "=" * 80)
    print("PHASE 3: E-Position Analysis")
    print("=" * 80)

    pos = padding_positions
    n = len(pos)
    print(f"\n  {n} padding E positions: {pos}")

    # --- 3a: Arithmetic sequence test ---
    print(f"\n  --- 3a: Arithmetic sequence test ---")
    diffs = [pos[i + 1] - pos[i] for i in range(n - 1)]
    print(f"    First differences: {diffs}")
    print(f"    Min diff: {min(diffs)}, Max diff: {max(diffs)}, Mean: {sum(diffs)/len(diffs):.2f}")

    # Check if diffs are constant (arithmetic sequence)
    if len(set(diffs)) == 1:
        print(f"    ** ARITHMETIC SEQUENCE with common difference {diffs[0]}")
    else:
        print(f"    Not an arithmetic sequence ({len(set(diffs))} distinct differences)")

    # Second differences
    second_diffs = [diffs[i + 1] - diffs[i] for i in range(len(diffs) - 1)]
    print(f"    Second differences: {second_diffs}")
    if len(set(second_diffs)) == 1:
        print(f"    ** QUADRATIC PATTERN with constant second difference {second_diffs[0]}")

    # --- 3b: Modular analysis ---
    print(f"\n  --- 3b: Modular analysis ---")
    for m in [2, 3, 5, 7, 11, 13, 26, 97]:
        residues = [p % m for p in pos]
        counts = Counter(residues)
        print(f"    mod {m:2d}: residues = {residues}")
        if m <= 13:
            dist = {r: counts.get(r, 0) for r in range(m)}
            print(f"           distribution = {dict(sorted(dist.items()))}")

    # --- 3c: Map to alphabet positions ---
    print(f"\n  --- 3c: Positions as alphabet values ---")
    # pos mod 26 → letter
    as_letters_mod26 = ''.join(chr(ord('A') + (p % 26)) for p in pos)
    print(f"    pos mod 26 → letters: {as_letters_mod26}")

    # pos mod 26 → letter using KA
    as_ka_mod26 = ''.join(KA[p % 26] for p in pos)
    print(f"    pos mod 26 → KA letters: {as_ka_mod26}")

    # Direct position values (0-indexed) as letters if < 26
    direct_letters = []
    for p in pos:
        if p < 26:
            direct_letters.append(chr(ord('A') + p))
        else:
            direct_letters.append(chr(ord('A') + (p % 26)))
    print(f"    Direct/mod26 → letters: {''.join(direct_letters)}")

    # --- 3d: Index into K4 ---
    print(f"\n  --- 3d: E-positions as K4 indices ---")
    # Use positions mod 97 to index into K4
    k4_chars = ''.join(CT[p % CT_LEN] for p in pos)
    print(f"    K4 chars at E-positions mod 97: {k4_chars}")
    print(f"    IC of extracted chars: {ic(k4_chars):.4f}")

    # Use raw positions (many > 97, so wrap)
    k4_chars_raw = ''.join(CT[p % CT_LEN] for p in pos)
    print(f"    (Same as above since max pos < 97? Max pos = {max(pos)})")

    # --- 3e: Differences as key ---
    print(f"\n  --- 3e: Differences between E positions ---")
    print(f"    Differences: {diffs}")
    diff_letters = ''.join(chr(ord('A') + (d % 26)) for d in diffs)
    print(f"    Diffs mod 26 → letters: {diff_letters}")
    diff_ka = ''.join(KA[d % 26] for d in diffs)
    print(f"    Diffs mod 26 → KA: {diff_ka}")

    # --- 3f: Position within message-letter stream ---
    print(f"\n  --- 3f: E positions counted by message letters ---")
    e_msg_positions = []
    msg_idx = 0
    for t in MORSE_TOKENS:
        if t == 'e':
            e_msg_positions.append(msg_idx)
        else:
            msg_idx += 1
    print(f"    E msg-stream positions: {e_msg_positions}")

    msg_diffs = [e_msg_positions[i + 1] - e_msg_positions[i]
                 for i in range(len(e_msg_positions) - 1)]
    print(f"    Msg-pos differences: {msg_diffs}")

    # These are the number of message letters between consecutive E's
    msg_diff_letters = ''.join(chr(ord('A') + (d % 26)) for d in msg_diffs)
    print(f"    Msg diffs as letters: {msg_diff_letters}")

    # --- 3g: Plot-like analysis ---
    print(f"\n  --- 3g: Visual pattern (X=padding-E) ---")
    max_pos = max(pos)
    grid_width = 20
    grid = ['.' for _ in range(max_pos + 1)]
    for p in pos:
        grid[p] = 'X'
    for i in range(0, max_pos + 1, grid_width):
        chunk = ''.join(grid[i:i + grid_width])
        print(f"    [{i:3d}] {chunk}")

    findings['phase3'] = {
        'positions': pos,
        'differences': diffs,
        'second_differences': second_diffs,
        'as_letters_mod26': as_letters_mod26,
        'e_msg_positions': e_msg_positions,
        'k4_chars_at_positions': k4_chars,
    }

    return e_msg_positions


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4: E-removal analysis
# ═══════════════════════════════════════════════════════════════════════════════

def phase4_e_removal():
    print("\n" + "=" * 80)
    print("PHASE 4: E-Removal Analysis")
    print("=" * 80)

    # Remove all padding E's
    message_only = [t for t in MORSE_TOKENS if t != 'e']
    message_text = ''.join(message_only)

    print(f"\n  Message text (padding E's removed): {message_text}")
    print(f"  Length: {len(message_text)}")
    print(f"  IC: {ic(message_text):.4f}")
    print(f"  Letter frequency:")
    freq = Counter(message_text)
    for ch in sorted(freq, key=freq.get, reverse=True):
        bar = '#' * freq[ch]
        print(f"    {ch}: {freq[ch]:2d} {bar}")

    # Check for known words/patterns
    print(f"\n  Known phrase structure:")
    phrases = [
        "VIRTUALLY", "INVISIBLE", "DIGETAL", "INTERPRETATIU",
        "SHADOW", "FORCES", "LUCID", "MEMORY",
        "TISYOURPOSITION", "SOS", "RQ",
    ]
    idx = 0
    for phrase in phrases:
        loc = message_text.find(phrase, idx)
        if loc >= 0:
            print(f"    [{loc:2d}-{loc + len(phrase) - 1:2d}] {phrase}")
            idx = loc + len(phrase)
        else:
            print(f"    NOT FOUND: {phrase} (starting from {idx})")

    # IC and statistical properties
    qg = quadgram_score(message_text)
    if qg:
        print(f"  Quadgram score: {qg:.3f}/char")

    # What if we also remove word-E's?
    no_e_at_all = [t for t in MORSE_TOKENS if t.upper() != 'E']
    no_e_text = ''.join(no_e_at_all)
    print(f"\n  All E's removed: {no_e_text}")
    print(f"  Length: {len(no_e_text)}")

    # Check if the message text itself has hidden structure
    # Count unique letters, missing letters
    letters_present = set(message_text)
    letters_missing = set(ALPH) - letters_present
    print(f"\n  Letters present: {''.join(sorted(letters_present))} ({len(letters_present)})")
    print(f"  Letters missing: {''.join(sorted(letters_missing))} ({len(letters_missing)})")

    findings['phase4'] = {
        'message_text': message_text,
        'message_length': len(message_text),
        'ic': ic(message_text),
        'letters_missing': sorted(letters_missing),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: Alternative grouping
# ═══════════════════════════════════════════════════════════════════════════════

def phase5_alternative_grouping():
    print("\n" + "=" * 80)
    print("PHASE 5: Alternative E-Based Grouping")
    print("=" * 80)

    # E's as delimiters: split message at padding-E boundaries
    print(f"\n  --- 5a: E-delimited segments ---")
    segments = []
    current = []
    for t in MORSE_TOKENS:
        if t == 'e':
            if current:
                segments.append(''.join(current))
                current = []
        else:
            current.append(t)
    if current:
        segments.append(''.join(current))

    for i, seg in enumerate(segments):
        print(f"    Segment {i:2d}: '{seg}' (len={len(seg)})")

    segment_lengths = [len(s) for s in segments]
    print(f"\n  Segment lengths: {segment_lengths}")
    print(f"  Sum: {sum(segment_lengths)}")

    # Segment lengths as key
    seg_as_letters = ''.join(chr(ord('A') + (l - 1) % 26) for l in segment_lengths)
    print(f"  Segment lengths as letters (1=A): {seg_as_letters}")

    # --- 5b: E-groups as word separators (different from phrase boundaries) ---
    print(f"\n  --- 5b: Grouping by E-group size ---")
    groups = []
    current_group = []
    in_e_run = False
    e_count = 0
    current_segment = []

    for t in MORSE_TOKENS:
        if t == 'e':
            if not in_e_run:
                if current_segment:
                    current_group.append(''.join(current_segment))
                    current_segment = []
                e_count = 1
                in_e_run = True
            else:
                e_count += 1
        else:
            if in_e_run:
                # Group boundary depends on E-run size
                if e_count >= 3:
                    # Major boundary
                    if current_group:
                        groups.append(('MAJOR', e_count, current_group[:]))
                    current_group = []
                else:
                    # Minor boundary (word separator within phrase)
                    groups.append(('MINOR', e_count, current_group[:]))
                    current_group = []
                in_e_run = False
                e_count = 0
            current_segment.append(t)

    if current_segment:
        current_group.append(''.join(current_segment))
    if current_group:
        groups.append(('END', 0, current_group[:]))

    print(f"  Boundary analysis (E-run >= 3 = major):")
    for kind, ecount, grp in groups:
        text = ' '.join(grp) if grp else '(empty)'
        print(f"    {kind}(E={ecount}): {text}")

    # --- 5c: First letter of each E-delimited segment ---
    print(f"\n  --- 5c: First letter of each segment ---")
    first_letters = ''.join(s[0] for s in segments if s)
    last_letters = ''.join(s[-1] for s in segments if s)
    print(f"    First letters: {first_letters}")
    print(f"    Last letters:  {last_letters}")

    # Check for English words
    for crib in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "KEY", "CIA"]:
        if crib in first_letters:
            print(f"    ** Found '{crib}' in first letters!")
        if crib in last_letters:
            print(f"    ** Found '{crib}' in last letters!")

    # --- 5d: Acrostic from phrases ---
    print(f"\n  --- 5d: Acrostic analysis ---")
    phrase_starts = ["VIRTUALLY", "INVISIBLE", "DIGETAL", "INTERPRETATIU",
                     "SHADOW", "FORCES", "LUCID", "MEMORY",
                     "T", "IS", "YOUR", "POSITION", "SOS", "RQ"]
    acrostic = ''.join(p[0] for p in phrase_starts)
    print(f"    Acrostic (first letters of words): {acrostic}")
    # VIDISFLMTIYPSRQ -> any anagram?
    print(f"    Sorted: {''.join(sorted(acrostic))}")

    # Less granular: by phrase
    phrase_groups = ["VIRTUALLYINVISIBLE", "DIGETALINTERPRETATIU",
                     "SHADOWFORCES", "LUCIDMEMORY", "TISYOURPOSITION", "SOS", "RQ"]
    acrostic2 = ''.join(p[0] for p in phrase_groups)
    print(f"    Phrase-level acrostic: {acrostic2}")

    findings['phase5'] = {
        'segments': segments,
        'segment_lengths': segment_lengths,
        'first_letters': first_letters,
        'last_letters': last_letters,
        'acrostic': acrostic,
    }

    return segments, segment_lengths


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: 26 E's = key derivation
# ═══════════════════════════════════════════════════════════════════════════════

def phase6_key_derivation(padding_positions, e_msg_positions):
    print("\n" + "=" * 80)
    print("PHASE 6: 26 E-Positions as Key for K4")
    print("=" * 80)

    n_e = len(padding_positions)

    # --- 6a: Position values mod 26 as key ---
    print(f"\n  --- 6a: Token-stream positions mod 26 as Vig/Beau key ---")
    key_tok_mod26 = [p % 26 for p in padding_positions]
    key_text = ''.join(chr(ord('A') + k) for k in key_tok_mod26)
    print(f"    Key (token pos mod 26): {key_tok_mod26}")
    print(f"    Key as text: {key_text}")

    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", varbeau_dec)]:
        pt_nums = vfn(CT_NUM, key_tok_mod26)
        score = test_and_log(f"P6a_tokmod26_{vname}", pt_nums, is_nums=True)
        if score >= 3:
            bean_v = check_bean_vig(pt_nums) if vname == "Vig" else check_bean_beau(pt_nums)
            pt_text = nums_to_text(pt_nums)
            print(f"      {vname}: score={score}, Bean={'PASS' if bean_v else 'fail'}, PT={pt_text[:50]}")

    # --- 6b: Message-stream positions mod 26 as key ---
    print(f"\n  --- 6b: Message-stream positions mod 26 as key ---")
    key_msg_mod26 = [p % 26 for p in e_msg_positions]
    key_text2 = ''.join(chr(ord('A') + k) for k in key_msg_mod26)
    print(f"    Key (msg pos mod 26): {key_msg_mod26}")
    print(f"    Key as text: {key_text2}")

    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", varbeau_dec)]:
        pt_nums = vfn(CT_NUM, key_msg_mod26)
        score = test_and_log(f"P6b_msgmod26_{vname}", pt_nums, is_nums=True)

    # --- 6c: Ordinal encoding (1st E → A, 2nd E → B, ...) ---
    print(f"\n  --- 6c: Ordinal encoding (1st E=A, 2nd E=B, ..., 26th E=Z) ---")
    # The key IS the alphabet if we map the nth E to the nth letter
    # But what's encoded by the position? The position of the nth E encodes something
    # Map: letter A is at position padding_positions[0], letter B at padding_positions[1], etc.
    # This creates a permutation: for each letter, the E-position tells us where it goes
    key_ordinal = list(range(26))  # A=0, B=1, ..., Z=25
    key_text3 = ALPH
    print(f"    If 26 E's encode ABCDEFGHIJKLMNOPQRSTUVWXYZ:")
    print(f"    Then E-positions create a mapping: A→pos{padding_positions[0]}, "
          f"B→pos{padding_positions[1]}, ..., Z→pos{padding_positions[25]}")

    # Test the alphabet as key
    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
        pt_nums = vfn(CT_NUM, key_ordinal)
        score = test_and_log(f"P6c_ordinal_{vname}", pt_nums, is_nums=True)

    # --- 6d: E-position differences as key ---
    print(f"\n  --- 6d: Differences between E positions as key ---")
    diffs = [padding_positions[i + 1] - padding_positions[i]
             for i in range(len(padding_positions) - 1)]
    key_diffs = [d % 26 for d in diffs]
    print(f"    Diffs: {diffs}")
    print(f"    Diffs mod 26: {key_diffs}")
    print(f"    As letters: {''.join(chr(ord(chr(65)) + k) for k in key_diffs)}")

    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", varbeau_dec)]:
        pt_nums = vfn(CT_NUM, key_diffs)
        score = test_and_log(f"P6d_diffs_{vname}", pt_nums, is_nums=True)

    # --- 6e: E-group sizes repeated as key ---
    print(f"\n  --- 6e: E-group sizes as repeating key (period 11) ---")
    key_groups = E_GROUP_SIZES
    print(f"    Key: {key_groups}")

    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", varbeau_dec)]:
        pt_nums = vfn(CT_NUM, key_groups)
        score = test_and_log(f"P6e_groups_{vname}", pt_nums, is_nums=True)

    # --- 6f: E cumulative sums as key ---
    print(f"\n  --- 6f: E-group cumulative sums as key ---")
    cumsum = []
    s = 0
    for g in E_GROUP_SIZES:
        s += g
        cumsum.append(s)
    key_cumsum = [c % 26 for c in cumsum]
    print(f"    Cumsums: {cumsum}")
    print(f"    Mod 26: {key_cumsum}")

    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", varbeau_dec)]:
        pt_nums = vfn(CT_NUM, key_cumsum)
        score = test_and_log(f"P6f_cumsum_{vname}", pt_nums, is_nums=True)

    # --- 6g: All 26 offsets of each key ---
    print(f"\n  --- 6g: Keys + constant offset (0-25) ---")
    for offset in range(26):
        for base_name, base_key in [
            ("tokmod26", key_tok_mod26),
            ("msgmod26", key_msg_mod26),
            ("diffs", key_diffs),
            ("groups", key_groups),
            ("cumsum", key_cumsum),
        ]:
            shifted_key = [(k + offset) % 26 for k in base_key]
            for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
                pt_nums = vfn(CT_NUM, shifted_key)
                score = test_and_log(f"P6g_{base_name}+{offset}_{vname}", pt_nums, is_nums=True)

    # --- 6h: Key through KA alphabet ---
    print(f"\n  --- 6h: Keys through KA alphabet ---")
    ct_ka = [KA_IDX[c] for c in CT]
    for base_name, base_key in [
        ("tokmod26", key_tok_mod26),
        ("msgmod26", key_msg_mod26),
        ("groups", key_groups),
        ("cumsum", key_cumsum),
    ]:
        for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
            pt_nums = vfn(ct_ka, base_key)
            pt_text = ''.join(KA[n] for n in pt_nums)
            score = test_and_log(f"P6h_{base_name}_KA_{vname}", pt_text)

    findings['phase6'] = {
        'key_tok_mod26': key_tok_mod26,
        'key_msg_mod26': key_msg_mod26,
        'key_diffs': key_diffs,
        'key_groups': list(key_groups),
        'key_cumsum': key_cumsum,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: Interleaved cipher analysis
# ═══════════════════════════════════════════════════════════════════════════════

def phase7_interleaved(padding_positions):
    print("\n" + "=" * 80)
    print("PHASE 7: Interleaved Cipher Analysis")
    print("=" * 80)

    # Separate E-positions and non-E-positions
    e_chars = []
    non_e_chars = []
    e_positions_set = set(padding_positions)

    for i, token in enumerate(MORSE_TOKENS):
        if i in e_positions_set:
            # This is a padding E position, all are 'E'
            e_chars.append('E')
        else:
            non_e_chars.append(token.upper())

    e_text = ''.join(e_chars)
    non_e_text = ''.join(non_e_chars)

    print(f"\n  E-channel ({len(e_chars)} chars): all E's (trivially uniform)")
    print(f"  Non-E channel ({len(non_e_chars)} chars): {non_e_text}")
    print(f"  Non-E IC: {ic(non_e_text):.4f}")

    # The non-E channel IS the message text — already analyzed in Phase 4
    # The interesting question: does the MESSAGE itself carry a hidden message
    # when you read every Nth character?

    print(f"\n  --- 7a: Every Nth character from message text ---")
    msg = non_e_text
    for stride in range(2, 14):
        for offset in range(stride):
            extracted = msg[offset::stride]
            if len(extracted) >= 10:
                ic_val = ic(extracted)
                qg = quadgram_score(extracted)
                if ic_val > 0.055 or (qg and qg > -10.5):
                    print(f"    stride={stride}, offset={offset}: '{extracted[:30]}...' "
                          f"IC={ic_val:.4f}" +
                          (f" QG={qg:.2f}" if qg else ""))

    # --- 7b: Message text at E-positions (message stream) ---
    print(f"\n  --- 7b: Characters in message stream at E-relative positions ---")
    # For each padding E, what message letter comes at the same "absolute" position?
    # (i.e., if we count E's as characters, what's the character at each E position?)
    # This is trivially E for padding positions, so instead:
    # What if E positions in the message stream point to K4 characters?

    # E positions in the message stream (how many msg letters precede each E)
    e_msg_pos = []
    msg_idx = 0
    for t in MORSE_TOKENS:
        if t == 'e':
            e_msg_pos.append(msg_idx)
        else:
            msg_idx += 1

    # Use these as indices into K4
    print(f"\n  --- 7c: E msg-positions as K4 selection indices ---")
    for transform_name, idx_fn in [
        ("direct", lambda p: p % CT_LEN),
        ("reverse", lambda p: (CT_LEN - 1 - p) % CT_LEN),
        ("doubled", lambda p: (2 * p) % CT_LEN),
        ("squared", lambda p: (p * p) % CT_LEN),
    ]:
        indices = [idx_fn(p) for p in e_msg_pos]
        selected = ''.join(CT[i] for i in indices)
        print(f"    {transform_name}: indices={indices[:10]}... chars={selected}")
        # Test selected text as key for K4
        if len(selected) >= 5:
            key_nums = [ALPH_IDX[c] for c in selected]
            for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
                pt_nums = vfn(CT_NUM, key_nums)
                test_and_log(f"P7c_{transform_name}_{vname}", pt_nums, is_nums=True)

    # --- 7d: Reading order interleave ---
    print(f"\n  --- 7d: Interleave K0 with K4 ---")
    # What if K0 message letters and K4 letters are interleaved?
    # K0 message = 86 chars, K4 = 97 chars
    # Interleave: K0[0], K4[0], K0[1], K4[1], ...
    k0_msg = non_e_text
    interleaved = []
    for i in range(max(len(k0_msg), CT_LEN)):
        if i < len(k0_msg):
            interleaved.append(k0_msg[i])
        if i < CT_LEN:
            interleaved.append(CT[i])
    interleaved_text = ''.join(interleaved)
    print(f"    Interleaved length: {len(interleaved_text)}")
    print(f"    First 50: {interleaved_text[:50]}")

    # Check for cribs in interleaved
    for crib in ["EASTNORTHEAST", "BERLINCLOCK", "SHADOW", "LUCID", "KRYPTOS"]:
        found = find_crib_anywhere(interleaved_text, crib)
        if found:
            print(f"    ** Found '{crib}' at position(s) {found} in interleaved text!")

    findings['phase7'] = {
        'non_e_text': non_e_text,
        'non_e_ic': ic(non_e_text),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 8: Connection to K4
# ═══════════════════════════════════════════════════════════════════════════════

def phase8_k4_connection(padding_positions, e_msg_positions, segments, segment_lengths):
    print("\n" + "=" * 80)
    print("PHASE 8: K4 Connection Tests")
    print("=" * 80)

    # --- 8a: 26-value sequence from E-positions as repeating Vig key ---
    print(f"\n  --- 8a: E-position derived keys vs K4 (comprehensive) ---")

    # Build multiple key derivations
    keys_to_test = {}

    # Token positions raw (mod 26)
    keys_to_test['tok_pos_mod26'] = [p % 26 for p in padding_positions]

    # Message positions raw (mod 26)
    keys_to_test['msg_pos_mod26'] = [p % 26 for p in e_msg_positions]

    # Segment lengths
    keys_to_test['seg_lengths'] = segment_lengths

    # Group sizes
    keys_to_test['group_sizes'] = E_GROUP_SIZES

    # Cumulative group sizes mod 26
    cumsum = []
    s = 0
    for g in E_GROUP_SIZES:
        s += g
        cumsum.append(s % 26)
    keys_to_test['group_cumsum'] = cumsum

    # Token position differences
    tok_diffs = [padding_positions[i + 1] - padding_positions[i]
                 for i in range(len(padding_positions) - 1)]
    keys_to_test['tok_diffs'] = [d % 26 for d in tok_diffs]

    # Message position differences
    msg_diffs = [e_msg_positions[i + 1] - e_msg_positions[i]
                 for i in range(len(e_msg_positions) - 1)]
    keys_to_test['msg_diffs'] = [d % 26 for d in msg_diffs]

    # Reversed versions
    for name in list(keys_to_test.keys()):
        keys_to_test[name + '_rev'] = list(reversed(keys_to_test[name]))

    # Known thematic keywords combined with E-derived keys
    thematic_keys = {
        'KRYPTOS': [ALPH_IDX[c] for c in 'KRYPTOS'],
        'PALIMPSEST': [ALPH_IDX[c] for c in 'PALIMPSEST'],
        'ABSCISSA': [ALPH_IDX[c] for c in 'ABSCISSA'],
    }

    print(f"  Testing {len(keys_to_test)} E-derived keys x 3 variants x 2 alphabets...")

    for kname, key in keys_to_test.items():
        for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VBeau", varbeau_dec)]:
            # AZ alphabet
            pt_nums = vfn(CT_NUM, key)
            score = test_and_log(f"P8a_{kname}_{vname}_AZ", pt_nums, is_nums=True)
            if score >= 8:
                bean = check_bean_vig(pt_nums) if vname == "Vig" else check_bean_beau(pt_nums)
                pt_text = nums_to_text(pt_nums)
                print(f"      ** {kname} {vname} AZ: score={score}, "
                      f"Bean={'PASS' if bean else 'fail'}, PT={pt_text[:50]}")

            # KA alphabet
            ct_ka = [KA_IDX[c] for c in CT]
            pt_nums_ka = vfn(ct_ka, key)
            pt_text_ka = ''.join(KA[n] for n in pt_nums_ka)
            score_ka = test_and_log(f"P8a_{kname}_{vname}_KA", pt_text_ka)
            if score_ka >= 8:
                print(f"      ** {kname} {vname} KA: score={score_ka}, PT={pt_text_ka[:50]}")

    # --- 8b: E-positions as transposition permutation for K4 ---
    print(f"\n  --- 8b: E-positions as partial transposition ---")
    # 26 E positions define 26 values. If these index into K4 (mod 97),
    # they select 26 characters from K4.
    selected_chars = ''.join(CT[p % CT_LEN] for p in padding_positions)
    print(f"    K4 chars at E token positions mod 97: {selected_chars}")
    print(f"    IC: {ic(selected_chars):.4f}")

    selected_chars2 = ''.join(CT[p % CT_LEN] for p in e_msg_positions)
    print(f"    K4 chars at E msg positions mod 97: {selected_chars2}")
    print(f"    IC: {ic(selected_chars2):.4f}")

    # Check if selected chars match any crib fragments
    for crib in ["EASTNORTHEAST", "BERLINCLOCK"]:
        for fragment_len in range(5, min(len(crib) + 1, len(selected_chars) + 1)):
            for start in range(len(crib) - fragment_len + 1):
                frag = crib[start:start + fragment_len]
                if frag in selected_chars:
                    print(f"    ** Fragment '{frag}' found in selected K4 chars!")
                if frag in selected_chars2:
                    print(f"    ** Fragment '{frag}' found in msg-pos selected K4 chars!")

    # --- 8c: E positions mark K4 positions for substitution with known keywords ---
    print(f"\n  --- 8c: E-derived selection + thematic keyword substitution ---")
    for kw_name, kw_key in thematic_keys.items():
        for e_key_name, e_key in [
            ("tok_mod26", [p % 26 for p in padding_positions]),
            ("msg_mod26", [p % 26 for p in e_msg_positions]),
        ]:
            # Combined key: E-derived values XOR/added to keyword
            combined = [(e_key[i % len(e_key)] + kw_key[i % len(kw_key)]) % 26
                        for i in range(CT_LEN)]
            for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
                pt_nums = vfn(CT_NUM, combined)
                score = test_and_log(f"P8c_{e_key_name}+{kw_name}_{vname}", pt_nums, is_nums=True)

    # --- 8d: Free crib search on best candidates ---
    print(f"\n  --- 8d: Free crib search on top candidates ---")
    # For the best-scoring candidates, check if EASTNORTHEAST or BERLINCLOCK
    # appear ANYWHERE in the plaintext (not just at expected positions)
    if results_log:
        top_results = sorted(results_log, key=lambda x: -x['score'])[:5]
        for r in top_results:
            pt = r['pt_prefix']
            # We only have 50-char prefix, but check anyway
            for crib in ["EASTNORTHEAST", "BERLIN", "CLOCK", "EAST", "NORTH"]:
                if crib in pt:
                    print(f"    ** Free crib '{crib}' in {r['tag']} at prefix!")

    # --- 8e: E-count 26 as period for period-26 Vigenere ---
    print(f"\n  --- 8e: Period-26 analysis (26 E's = 26-letter key?) ---")
    # At period 26, K4 wraps 3 times + 19 leftover (97 = 3*26 + 19)
    # Each column of a period-26 Vigenere has very few characters (3-4)
    # So direct frequency analysis is hopeless, but we can test known keys

    # Construct a 26-letter key from E-position differences
    # If 26 is the period, each E marks the start of a new period
    # Token position of nth E divided by n gives approximate spacing
    approx_key = []
    for i, p in enumerate(padding_positions):
        # Map E positions to a key value
        approx_key.append(p % 26)
    # This is just key_tok_mod26 again - already tested above

    # But try: the POSITION of each E within its local E-group
    pos_in_group = []
    group_idx = 0
    pos_within = 0
    groups = []
    current_g = []
    for i, t in enumerate(MORSE_TOKENS):
        if t == 'e':
            current_g.append(i)
        else:
            if current_g:
                groups.append(current_g[:])
                current_g = []
    if current_g:
        groups.append(current_g)

    flat_group_info = []
    for gi, grp in enumerate(groups):
        for pi, pos in enumerate(grp):
            flat_group_info.append((gi, pi, len(grp)))

    # Key = (group_index * group_size + position_within_group) mod 26
    key_complex = [(gi * gs + pi) % 26 for gi, pi, gs in flat_group_info]
    print(f"    Complex key: {key_complex}")
    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
        pt_nums = vfn(CT_NUM, key_complex)
        test_and_log(f"P8e_complex_{vname}", pt_nums, is_nums=True)

    # --- 8f: Segment lengths as transposition key for K4 ---
    print(f"\n  --- 8f: Segment lengths as columnar transposition key ---")
    # Segment lengths: [9, 9, 7, 13, 6, 6, 5, 6, 15, 3, 2]
    # These define the column read order for a columnar transposition
    # Number of segments = 11 (or fewer if we combine)
    # K4 in 11-wide grid = 9 rows x 11 cols (= 99, need 97)

    from itertools import permutations

    # Use segment lengths to derive a column order
    # Sort by size to get a ranking
    indexed_segs = sorted(enumerate(segment_lengths), key=lambda x: (x[1], x[0]))
    col_order_by_size = [0] * len(segment_lengths)
    for rank, (orig_idx, _) in enumerate(indexed_segs):
        col_order_by_size[orig_idx] = rank

    print(f"    Segment lengths: {segment_lengths}")
    print(f"    Column order (by size): {col_order_by_size}")

    # Apply width-11 columnar with this order
    width = len(segment_lengths)
    if width <= CT_LEN:
        nrows = (CT_LEN + width - 1) // width
        # Determine column lengths
        long_cols = CT_LEN % width if CT_LEN % width != 0 else width
        col_lens = [nrows if c < long_cols else nrows - 1 for c in range(width)]

        # Read columns in col_order_by_size
        cols = {}
        pos = 0
        for rank in range(width):
            col_idx = col_order_by_size.index(rank)
            clen = col_lens[col_idx]
            cols[col_idx] = CT[pos:pos + clen]
            pos += clen

        # Read off row by row
        result = []
        for r in range(nrows):
            for c in range(width):
                if c in cols and r < len(cols[c]):
                    result.append(cols[c][r])
        pt_text = ''.join(result)
        score = test_and_log("P8f_seg_columnar_fwd", pt_text)

        # Also try the inverse
        cols2 = {}
        pos = 0
        inv_order = [0] * width
        for i, v in enumerate(col_order_by_size):
            inv_order[v] = i
        for rank in range(width):
            col_idx = inv_order[rank]
            clen = col_lens[col_idx]
            cols2[col_idx] = CT[pos:pos + clen]
            pos += clen

        result2 = []
        for r in range(nrows):
            for c in range(width):
                if c in cols2 and r < len(cols2[c]):
                    result2.append(cols2[c][r])
        pt_text2 = ''.join(result2)
        test_and_log("P8f_seg_columnar_inv", pt_text2)

    findings['phase8'] = {
        'total_configs': total_configs,
        'best_score': best_score,
        'best_tag': best_tag,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 9: Additional deep tests
# ═══════════════════════════════════════════════════════════════════════════════

def phase9_deep_tests(padding_positions, e_msg_positions):
    print("\n" + "=" * 80)
    print("PHASE 9: Deep / Combinatorial Tests")
    print("=" * 80)

    # --- 9a: E positions as a Polybius-like grid selector ---
    print(f"\n  --- 9a: E-positions in 5x5/6x5 Polybius grid ---")
    # 26 E's. Pair them as (row, col) for 5x5 grid: 13 pairs -> 13 letters
    for grid_dim, grid_letters in [(5, "ABCDEFGHIKLMNOPQRSTUVWXYZ"),
                                    (6, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")]:
        paired_letters = []
        for i in range(0, len(padding_positions) - 1, 2):
            r = padding_positions[i] % grid_dim
            c = padding_positions[i + 1] % grid_dim
            idx = r * grid_dim + c
            if idx < len(grid_letters):
                paired_letters.append(grid_letters[idx])
        paired_text = ''.join(paired_letters)
        print(f"    {grid_dim}x{grid_dim} pairs: {paired_text}")

        # Also try msg positions
        paired_msg = []
        for i in range(0, len(e_msg_positions) - 1, 2):
            r = e_msg_positions[i] % grid_dim
            c = e_msg_positions[i + 1] % grid_dim
            idx = r * grid_dim + c
            if idx < len(grid_letters):
                paired_msg.append(grid_letters[idx])
        paired_msg_text = ''.join(paired_msg)
        print(f"    {grid_dim}x{grid_dim} msg pairs: {paired_msg_text}")

    # --- 9b: E-group sizes as Morse code ---
    print(f"\n  --- 9b: E-group sizes as Morse code ---")
    # Map: 1 = dit (.), 2+ = dah (-)
    morse_from_groups = []
    for g in E_GROUP_SIZES:
        if g == 1:
            morse_from_groups.append('.')
        elif g == 2:
            morse_from_groups.append('-')
        elif g == 3:
            morse_from_groups.append('-.')  # or could be -.
        elif g == 5:
            morse_from_groups.append('.....')  # or word boundary
        else:
            morse_from_groups.append('?' * g)

    morse_str = ' '.join(morse_from_groups)
    print(f"    E-groups as Morse (1=dit, 2=dah): {morse_str}")

    # Alternative: group sizes directly as numbers
    # [2,1,5,1,3,2,2,5,3,1,1]
    # In base 6 (max digit 5): represent as multi-digit number
    base6_val = 0
    for g in E_GROUP_SIZES:
        base6_val = base6_val * 6 + g
    print(f"    As base-6 number: {base6_val}")
    print(f"    Mod 26: {base6_val % 26} = {chr(ord('A') + base6_val % 26)}")
    print(f"    Mod 97: {base6_val % 97}")

    # --- 9c: Cross-reference with K4 letter frequencies ---
    print(f"\n  --- 9c: K4 letter frequency at E-derived positions ---")
    # Which K4 letters are most common at E-derived positions?
    for name, positions in [
        ("token positions mod 97", [p % CT_LEN for p in padding_positions]),
        ("msg positions mod 97", [p % CT_LEN for p in e_msg_positions]),
    ]:
        chars = ''.join(CT[p] for p in positions)
        freq = Counter(chars)
        top5 = freq.most_common(5)
        print(f"    {name}: {chars}")
        print(f"      Top 5: {top5}")

    # --- 9d: Period-13 test (len(EASTNORTHEAST) = 13) ---
    print(f"\n  --- 9d: E-derived keys at period 13 ---")
    # 26 = 2 * 13. The 26 E positions could encode TWO period-13 keys
    half1 = [padding_positions[i] % 26 for i in range(0, 26, 2)]  # Even-indexed
    half2 = [padding_positions[i] % 26 for i in range(1, 26, 2)]  # Odd-indexed
    print(f"    Even-indexed E positions mod 26: {half1}")
    print(f"    Odd-indexed E positions mod 26: {half2}")

    for name, key13 in [("even_epos", half1), ("odd_epos", half2)]:
        for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
            pt_nums = vfn(CT_NUM, key13)
            test_and_log(f"P9d_{name}_{vname}", pt_nums, is_nums=True)

    # --- 9e: Test E-group sizes as Beaufort key for d=13 anomaly ---
    print(f"\n  --- 9e: E-related keys at interesting periods ---")
    # Bean-compatible periods: 8, 13, 16, 19, 20, 23, 24, 26
    for period in [8, 13, 16, 19, 20, 23, 24, 26]:
        # Derive a key of the given period from E-data
        # Method: take first `period` values from various E-derived sequences
        for name, full_key in [
            ("tok_mod26", [p % 26 for p in padding_positions]),
            ("msg_mod26", [p % 26 for p in e_msg_positions]),
            ("groups", E_GROUP_SIZES),
        ]:
            key = full_key[:period]
            if len(key) < period:
                key = key * ((period // len(key)) + 1)
                key = key[:period]
            for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
                pt_nums = vfn(CT_NUM, key)
                score = test_and_log(f"P9e_p{period}_{name}_{vname}", pt_nums, is_nums=True)

    findings['phase9'] = {
        'total_configs_after_p9': total_configs,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    global best_score, best_tag, total_configs
    t0 = time.time()

    print("=" * 80)
    print("E-03: Deep Analysis of K0 Padding-E Positions")
    print("=" * 80)
    print(f"K4 CT: {CT}")
    print(f"K4 length: {CT_LEN}")
    print(f"Morse tokens: {len(MORSE_TOKENS)}")
    print(f"E-group sizes: {E_GROUP_SIZES} (sum={sum(E_GROUP_SIZES)})")
    print()

    # Phase 1: Reconstruct K0
    padding_positions, word_e_positions, e_groups = phase1_reconstruct()

    # Compute message-stream E positions for later phases
    e_msg_positions = []
    msg_idx = 0
    for t in MORSE_TOKENS:
        if t == 'e':
            e_msg_positions.append(msg_idx)
        else:
            msg_idx += 1

    # Phase 2: Binary mask
    phase2_binary_mask(padding_positions)

    # Phase 3: Position analysis
    e_msg_pos = phase3_position_analysis(padding_positions)

    # Phase 4: E-removal
    phase4_e_removal()

    # Phase 5: Alternative grouping
    segments, segment_lengths = phase5_alternative_grouping()

    # Phase 6: Key derivation
    phase6_key_derivation(padding_positions, e_msg_positions)

    # Phase 7: Interleaved cipher
    phase7_interleaved(padding_positions)

    # Phase 8: K4 connection
    phase8_k4_connection(padding_positions, e_msg_positions, segments, segment_lengths)

    # Phase 9: Deep tests
    phase9_deep_tests(padding_positions, e_msg_positions)

    # ═══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total configurations tested: {total_configs:,}")
    print(f"Results above noise ({NOISE_FLOOR}): {len(results_log)}")
    print(f"Best score: {best_score}/{N_CRIBS} ({best_tag})")
    if best_pt:
        print(f"Best PT prefix: {best_pt}")
    print(f"Elapsed: {elapsed:.1f}s")

    if results_log:
        print(f"\nTop 20 results:")
        for r in sorted(results_log, key=lambda x: -x['score'])[:20]:
            print(f"  score={r['score']}/{N_CRIBS} | {r['tag']}")

    verdict = ("SIGNAL" if best_score >= 18 else
               ("STORE" if best_score >= 10 else
                ("INTERESTING" if best_score >= NOISE_FLOOR else "NOISE")))
    print(f"\nVERDICT: {verdict}")

    # Key structural findings
    print(f"\n{'=' * 80}")
    print("KEY STRUCTURAL FINDINGS")
    print("=" * 80)

    print(f"""
  1. Padding E count: {len(padding_positions)} (26 = alphabet size)
  2. E-group sizes: {E_GROUP_SIZES} ({len(E_GROUP_SIZES)} groups)
  3. E-group cumulative sums: {[sum(E_GROUP_SIZES[:i+1]) for i in range(len(E_GROUP_SIZES))]}
  4. Segment count (between E-groups): {len(segments)}
  5. Segment lengths: {segment_lengths}

  The 26 padding E's split the K0 message into {len(segments)} segments.
  These segments contain {sum(segment_lengths)} message characters.

  CRITICAL OBSERVATION: The misspelling DIGETAL (should be DIGITAL) adds
  exactly one more word-E, making the word-E count higher. But the PADDING-E
  count is exactly 26 regardless of the misspelling. The misspelling affects
  the message content, not the padding structure.

  The E-group sizes [2,6,1,3,2,2,5,3,1,1] (CORRECTED) could represent:
    - A period-10 key (not 11 as prior scripts assumed)
    - Column widths for variable-width transposition
    - Step sizes for a running-key selector
    - A Morse-like binary message (1=dit, 2=dah, 3/5/6=boundaries)

  NOTE: Prior scripts (E-01, E-S-144, E-CHART-04) used INCORRECT group sizes
  [2,1,5,1,3,2,2,5,3,1,1] (11 groups) which split the contiguous run of 6 E's
  between VIRTUALLY and INVISIBLE. All prior E-group-as-key tests should be
  re-examined with the corrected [2,6,1,3,2,2,5,3,1,1] (10 groups).
""")

    # Save results
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment_id": "E-03",
        "hypothesis": "26 padding E's in K0 Morse code carry cipher information for K4",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_tag": best_tag,
        "elapsed_seconds": elapsed,
        "verdict": verdict,
        "findings": findings,
        "results_above_noise": sorted(results_log, key=lambda x: -x['score'])[:100],
        "key_data": {
            "padding_e_positions": padding_positions,
            "e_msg_positions": e_msg_positions,
            "e_group_sizes": E_GROUP_SIZES,
            "segments": segments,
            "segment_lengths": segment_lengths,
        },
        "repro_command": "PYTHONPATH=src python3 -u scripts/encoding/e03_k0_e_positions_deep.py",
    }

    with open("results/e03_k0_e_positions_deep.json", "w") as f:
        json.dump(artifact, f, indent=2, default=str)

    print(f"\nResults saved to results/e03_k0_e_positions_deep.json")
    print(f"\n[E-03 COMPLETE]")
    return best_score


if __name__ == "__main__":
    main()
