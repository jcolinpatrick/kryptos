#!/usr/bin/env python3
"""E-01: Extract and analyze the extra E's in Kryptos Morse code (K0).

Hypothesis: The 26 extra E's in Morse K0 mark adjacent letters that encode
K1's key or a K4 primer.

Data source: Community-consensus transcription (Gillogly photos, Elonka Dunin,
Gary Phillips, kryptosfan.wordpress.com). The Morse code on the entrance slabs
decodes to a sequence of words interspersed with extra E characters.

IMPORTANT CAVEAT: The exact count and positions of extra E's are approximate
(25-26 depending on interpretation). This experiment tests the SIGNAL in the
adjacent-letter sequences, not the exact count.
"""

import sys
import os
import math
from collections import Counter
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]

# ── MORSE CODE DATA ─────────────────────────────────────────────────────────
# Best community-consensus transcription of entrance slab Morse code.
# Each character is either a letter from the message or 'e' (lowercase) for
# the extra/padding E characters. This preserves word boundaries.
#
# Sources: kryptosfan.wordpress.com, rumkin.com/reference/kryptos/k0/,
#          Elonka Dunin's transcription, Gillogly photos.
#
# Encoding: uppercase = message letter, lowercase 'e' = extra E padding

# Panel 1: VIRTUALLY INVISIBLE
# Two leading E's, then VIRTUALLY, trailing E, then 5-6 E's, then INVISIBLE
# Panel 2: DIGETAL INTERPRETATIU
# Leading E, DIGETAL, 3 trailing E's, INTERPRETATIU
# Panel 3: SHADOW FORCES
# 2 leading E's, SHADOW, 2 trailing E's, FORCES, 5 trailing E's
# Panel 4: LUCID MEMORY
# LUCID, 3 trailing E's, MEMORY, 1 trailing E
# Panel 5: T IS YOUR POSITION
# T IS YOUR POSITION, 1 trailing E
# Panel 6: SOS
# Panel 7: RQ

# Linearized token sequence (each token is either a message letter or extra-E)
# Using the most commonly cited count of 25 extra E's:
MORSE_TOKENS = [
    'e', 'e',  # 2 E's before VIRTUALLY
    'V', 'I', 'R', 'T', 'U', 'A', 'L', 'L', 'Y',
    'e',  # 1 E after VIRTUALLY
    'e', 'e', 'e', 'e', 'e',  # 5 E's before INVISIBLE
    'I', 'N', 'V', 'I', 'S', 'I', 'B', 'L', 'E',  # INVISIBLE (the E here is part of the word)
    'e',  # 1 E before DIGETAL (or after INVISIBLE)
    'D', 'I', 'G', 'E', 'T', 'A', 'L',  # DIGETAL (E here is the misspelling, part of word)
    'e', 'e', 'e',  # 3 E's after DIGETAL
    'I', 'N', 'T', 'E', 'R', 'P', 'R', 'E', 'T', 'A', 'T', 'I', 'U',  # INTERPRETATIU
    'e', 'e',  # 2 E's before SHADOW
    'S', 'H', 'A', 'D', 'O', 'W',
    'e', 'e',  # 2 E's after SHADOW
    'F', 'O', 'R', 'C', 'E', 'S',  # FORCES (E is part of word)
    'e', 'e', 'e', 'e', 'e',  # 5 E's after FORCES
    'L', 'U', 'C', 'I', 'D',
    'e', 'e', 'e',  # 3 E's after LUCID
    'M', 'E', 'M', 'O', 'R', 'Y',  # MEMORY (E is part of word)
    'e',  # 1 E after MEMORY
    'T', 'I', 'S', 'Y', 'O', 'U', 'R',
    'P', 'O', 'S', 'I', 'T', 'I', 'O', 'N',
    'e',  # 1 E after POSITION
    'S', 'O', 'S',
    'R', 'Q',
]


def num_to_char(n):
    return chr(ord('A') + (n % 26))


def vig_decrypt(ct_nums, key_nums):
    period = len(key_nums)
    return [(ct_nums[i] - key_nums[i % period]) % MOD for i in range(len(ct_nums))]


def beaufort_decrypt(ct_nums, key_nums):
    period = len(key_nums)
    return [(key_nums[i % period] - ct_nums[i]) % MOD for i in range(len(ct_nums))]


def score_cribs(pt_nums):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == ALPH_IDX[ch]:
            matches += 1
    return matches


def check_bean(pt_nums):
    key = [(CT_NUM[i] - pt_nums[i]) % MOD for i in range(len(pt_nums))]
    for a, b in BEAN_EQ:
        if key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if key[a] == key[b]:
            return False
    return True


def chi_squared_test(counts, expected_freq=None, n=None):
    """Chi-squared test against uniform distribution."""
    if expected_freq is None:
        total = sum(counts.values())
        expected = total / 26
    else:
        total = n if n else sum(counts.values())
        expected = total * expected_freq

    chi2 = 0
    for i in range(26):
        letter = chr(ord('A') + i)
        observed = counts.get(letter, 0)
        chi2 += (observed - expected) ** 2 / expected

    # Degrees of freedom = 25 (26 categories - 1)
    # p < 0.05 at df=25 → chi² > 37.65
    return chi2


# English letter frequencies (approximate)
ENGLISH_FREQ = {
    'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127,
    'F': 0.022, 'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002,
    'K': 0.008, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075,
    'P': 0.019, 'Q': 0.001, 'R': 0.060, 'S': 0.063, 'T': 0.091,
    'U': 0.028, 'V': 0.010, 'W': 0.023, 'X': 0.002, 'Y': 0.020,
    'Z': 0.001,
}


def main():
    print("=" * 80)
    print("E-01: Morse Code Extra-E Extraction and Analysis")
    print("=" * 80)

    # ── Parse and validate ───────────────────────────────────────────────────

    extra_e_count = sum(1 for t in MORSE_TOKENS if t == 'e')
    message_letters = [t for t in MORSE_TOKENS if t != 'e']
    message_text = ''.join(message_letters)

    print(f"\n  Total tokens: {len(MORSE_TOKENS)}")
    print(f"  Extra E's: {extra_e_count}")
    print(f"  Message letters: {len(message_letters)}")
    print(f"  Message text: {message_text}")

    # ── Extract flanking letters ─────────────────────────────────────────────

    print("\n── Phase 1: Extract letters adjacent to each extra E ──")

    # For each extra E, find the nearest message letter before and after
    before_letters = []
    after_letters = []
    e_positions = []

    for i, token in enumerate(MORSE_TOKENS):
        if token != 'e':
            continue
        e_positions.append(i)

        # Look backward for nearest message letter
        before = None
        for j in range(i - 1, -1, -1):
            if MORSE_TOKENS[j] != 'e':
                before = MORSE_TOKENS[j]
                break
        before_letters.append(before)

        # Look forward for nearest message letter
        after = None
        for j in range(i + 1, len(MORSE_TOKENS)):
            if MORSE_TOKENS[j] != 'e':
                after = MORSE_TOKENS[j]
                break
        after_letters.append(after)

    print(f"\n  Extra E positions (in token stream): {e_positions}")
    print(f"  Before-letters: {''.join(b if b else '_' for b in before_letters)}")
    print(f"  After-letters:  {''.join(a if a else '_' for a in after_letters)}")

    # Deduplicate: for consecutive E's, the "before" is the same letter
    # Let's also extract unique flanking letters (one per E-group)
    e_groups = []
    current_group = []
    for i, token in enumerate(MORSE_TOKENS):
        if token == 'e':
            current_group.append(i)
        else:
            if current_group:
                e_groups.append(current_group[:])
                current_group = []
    if current_group:
        e_groups.append(current_group)

    group_before = []
    group_after = []
    for group in e_groups:
        first_e = group[0]
        last_e = group[-1]
        # Before first E in group
        before = None
        for j in range(first_e - 1, -1, -1):
            if MORSE_TOKENS[j] != 'e':
                before = MORSE_TOKENS[j]
                break
        group_before.append(before)
        # After last E in group
        after = None
        for j in range(last_e + 1, len(MORSE_TOKENS)):
            if MORSE_TOKENS[j] != 'e':
                after = MORSE_TOKENS[j]
                break
        group_after.append(after)

    print(f"\n  E-groups: {len(e_groups)} groups with sizes {[len(g) for g in e_groups]}")
    print(f"  Group-before letters: {''.join(b if b else '_' for b in group_before)}")
    print(f"  Group-after letters:  {''.join(a if a else '_' for a in group_after)}")

    # ── Statistical tests ────────────────────────────────────────────────────

    print("\n── Phase 2: Statistical analysis of extracted sequences ──")

    sequences = {
        "S1 (before each E)": [b for b in before_letters if b],
        "S2 (after each E)": [a for a in after_letters if a],
        "S3 (group-before)": [b for b in group_before if b],
        "S4 (group-after)": [a for a in group_after if a],
        "S5 (group-before+after concat)": ([b for b in group_before if b] +
                                             [a for a in group_after if a]),
    }

    for name, seq in sequences.items():
        text = ''.join(seq)
        counts = Counter(text)
        chi2_uniform = chi_squared_test(counts)

        # Also test against English frequencies
        total = len(seq)
        chi2_english = 0
        for i in range(26):
            letter = chr(ord('A') + i)
            observed = counts.get(letter, 0)
            expected_eng = total * ENGLISH_FREQ.get(letter, 0.001)
            if expected_eng > 0:
                chi2_english += (observed - expected_eng) ** 2 / expected_eng

        print(f"\n  {name}: n={len(seq)}, text='{text}'")
        print(f"    Frequency: {dict(sorted(counts.items()))}")
        print(f"    Chi² vs uniform: {chi2_uniform:.1f} (critical at p<0.05: 37.65)")
        print(f"    Chi² vs English: {chi2_english:.1f}")
        print(f"    {'** NON-RANDOM (vs uniform)' if chi2_uniform > 37.65 else 'Random (vs uniform)'}")
        print(f"    {'** ENGLISH-LIKE' if chi2_english < 37.65 else 'NOT English-like'}")

    # ── Test as cipher keys ──────────────────────────────────────────────────

    print("\n── Phase 3: Test extracted sequences as K4 cipher keys ──")

    results = []
    for name, seq in sequences.items():
        if len(seq) < 2:
            continue
        key_nums = [ALPH_IDX[c] for c in seq]

        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, key_nums)
            score = score_cribs(pt)
            if score >= 4:
                bean = check_bean(pt)
                pt_text = ''.join(num_to_char(n) for n in pt)
                bean_str = "BEAN✓" if bean else "bean✗"
                print(f"  {name} ({variant}): score={score}/{N_CRIBS} {bean_str}")
                results.append((score, f"{name}_{variant}", key_nums, bean))

    # ── Phase 4: Test if flanking letters match known keywords ───────────────

    print("\n── Phase 4: Pattern matching against known keywords ──")

    keywords = {
        "PALIMPSEST": "PALIMPSEST",
        "PALIMPCEST": "PALIMPCEST",
        "ABSCISSA": "ABSCISSA",
        "KRYPTOS": "KRYPTOS",
        "BERLIN": "BERLIN",
        "CLOCK": "CLOCK",
        "WELTZEITUHR": "WELTZEITUHR",
    }

    for name, seq in sequences.items():
        text = ''.join(seq).upper()
        for kw_name, keyword in keywords.items():
            # Check if keyword is a substring
            if keyword in text:
                print(f"  ** MATCH: {name} contains '{keyword}'!")

            # Check if keyword is an anagram of text (or substring)
            if len(text) >= len(keyword):
                for start in range(len(text) - len(keyword) + 1):
                    substr = text[start:start + len(keyword)]
                    if sorted(substr) == sorted(keyword):
                        print(f"  ** ANAGRAM: {name}[{start}:{start+len(keyword)}] "
                              f"= anagram of '{keyword}'")

    # ── Phase 5: Numeric value of E-positions ────────────────────────────────

    print("\n── Phase 5: E-position numeric values as key ──")

    # The positions of extra E's within the message-letter stream
    # could themselves be key values
    msg_letter_positions_of_e = []
    msg_idx = 0
    for token in MORSE_TOKENS:
        if token == 'e':
            msg_letter_positions_of_e.append(msg_idx)
        else:
            msg_idx += 1

    print(f"  E positions (in message-letter count): {msg_letter_positions_of_e}")

    # Use E group sizes as key
    group_sizes = [len(g) for g in e_groups]
    print(f"  E group sizes: {group_sizes}")

    for name, key in [
        ("E_positions_mod26", [p % MOD for p in msg_letter_positions_of_e]),
        ("E_group_sizes", group_sizes),
        ("E_group_cumulative", [sum(group_sizes[:i+1]) for i in range(len(group_sizes))]),
    ]:
        key_nums = [k % MOD for k in key]
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, key_nums)
            score = score_cribs(pt)
            if score >= 5:
                bean = check_bean(pt)
                print(f"  {name} ({variant}): score={score}/{N_CRIBS} "
                      f"{'BEAN✓' if bean else 'bean✗'}")
                results.append((score, f"{name}_{variant}", key_nums, bean))

    # ── Phase 6: Inter-E letter counts as key ────────────────────────────────

    print("\n── Phase 6: Message letters between E's as key values ──")

    # Count message letters between consecutive extra E's
    inter_e_counts = []
    msg_count = 0
    for token in MORSE_TOKENS:
        if token == 'e':
            inter_e_counts.append(msg_count)
            msg_count = 0
        else:
            msg_count += 1
    if msg_count > 0:
        inter_e_counts.append(msg_count)  # trailing

    print(f"  Inter-E message letter counts: {inter_e_counts}")

    # Between E-groups
    inter_group_counts = []
    msg_count = 0
    in_group = False
    for token in MORSE_TOKENS:
        if token == 'e':
            if not in_group:
                inter_group_counts.append(msg_count)
                msg_count = 0
                in_group = True
        else:
            msg_count += 1
            in_group = False
    if msg_count > 0:
        inter_group_counts.append(msg_count)

    print(f"  Inter-group counts: {inter_group_counts}")

    for name, key in [
        ("inter_E_counts", inter_e_counts),
        ("inter_group_counts", inter_group_counts),
    ]:
        key_nums = [k % MOD for k in key]
        for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
            pt = dfn(CT_NUM, key_nums)
            score = score_cribs(pt)
            if score >= 5:
                bean = check_bean(pt)
                print(f"  {name} ({variant}): score={score}/{N_CRIBS} "
                      f"{'BEAN✓' if bean else 'bean✗'}")
                results.append((score, f"{name}_{variant}", key_nums, bean))

    # ── Phase 7: Nth letter after each E (not just adjacent) ─────────────────

    print("\n── Phase 7: Nth letter after each extra E ──")

    for n in range(1, 6):
        seq = []
        for i, token in enumerate(MORSE_TOKENS):
            if token != 'e':
                continue
            # Find nth message letter after this E
            msg_count = 0
            for j in range(i + 1, len(MORSE_TOKENS)):
                if MORSE_TOKENS[j] != 'e':
                    msg_count += 1
                    if msg_count == n:
                        seq.append(MORSE_TOKENS[j])
                        break

        if len(seq) >= 5:
            text = ''.join(seq)
            key_nums = [ALPH_IDX[c] for c in seq]
            for variant, dfn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                pt = dfn(CT_NUM, key_nums)
                score = score_cribs(pt)
                if score >= 5:
                    print(f"  {n}th-after-E ({variant}): seq='{text}' "
                          f"score={score}/{N_CRIBS}")
                    results.append((score, f"{n}th_after_E_{variant}", key_nums, False))

    # ── Summary ──────────────────────────────────────────────────────────────

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)

    results.sort(key=lambda x: -x[0])
    for score, tag, key, bean in results[:10]:
        bean_str = "BEAN✓" if bean else "bean✗"
        print(f"  {score}/{N_CRIBS} {bean_str} | {tag}")

    best = results[0] if results else (0, "none", [], False)
    print(f"\nBest: {best[0]}/{N_CRIBS}")

    if best[0] >= 15:
        print("SUCCESS: Morse E-adjacent letters show signal as K4 key")
    elif best[0] >= 8:
        print("INTERESTING: Above noise, investigate further")
    else:
        print("FAILURE: Morse E-adjacent letters → at noise floor as direct key")

    # ── Key observation ──────────────────────────────────────────────────────

    print("\n── KEY OBSERVATIONS ──")
    print("  The flanking letters are primarily determined by English word")
    print("  structure (word-initial and word-final letters), so non-randomness")
    print("  in frequency does NOT necessarily indicate a hidden key.")
    print("  The critical test is whether they produce crib matches, not whether")
    print("  their distribution is non-uniform.")

    print("\n[E-01 COMPLETE]")
    return best[0]


if __name__ == "__main__":
    main()
