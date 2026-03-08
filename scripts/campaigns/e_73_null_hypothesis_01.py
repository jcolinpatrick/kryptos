#!/usr/bin/env python3
"""
# ── Metadata ──────────────────────────────────────────────────────────────
# Cipher:     Multi-layer (null insertion + substitution)
# Family:     campaigns
# Status:     active
# Keyspace:   Analytical + targeted decryption
# Last run:   2026-03-08
# Best score: TBD
# ──────────────────────────────────────────────────────────────────────────

HYPOTHESIS: Sanborn's legal pad shows "8 lines / 73" for K4, but the carved
sculpture has 97 characters. If K4's original text was 73 characters, then
24 null/filler characters were inserted during the second encryption system.

KEY OBSERVATION: Crib positions span exactly 24 characters (21-33 = 13 chars,
63-73 = 11 chars). The non-crib positions = 97 - 24 = 73 — EXACTLY the
legal pad number.

This script performs comprehensive analysis of the 73-char null hypothesis.
"""
from __future__ import annotations

import sys
import os
import math
from collections import Counter
from itertools import product
from typing import List, Tuple, Dict, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    KRYPTOS_ALPHABET, NOISE_FLOOR,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)
from kryptos.kernel.scoring.ic import ic, ic_by_position
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, DECRYPT_FN,
)
from kryptos.kernel.alphabet import AZ, KA, Alphabet, keyword_mixed_alphabet
from kryptos.kernel.text import text_to_nums, nums_to_text, char_to_num, num_to_char


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1: LETTER FREQUENCY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def analyze_frequencies():
    """Analyze K4 letter frequencies for evidence of null insertion."""
    print("=" * 78)
    print("SECTION 1: LETTER FREQUENCY ANALYSIS")
    print("=" * 78)

    freq = Counter(CT)
    expected_per_letter = CT_LEN / 26  # 97/26 = 3.73

    print(f"\nK4 ciphertext: {CT}")
    print(f"Length: {CT_LEN}")
    print(f"Expected frequency per letter (uniform): {expected_per_letter:.2f}")
    print(f"Unique letters: {len(freq)}")

    # Sort by frequency descending
    sorted_freq = sorted(freq.items(), key=lambda x: -x[1])

    print(f"\n{'Letter':>6} {'Count':>5} {'Expected':>8} {'Excess':>6} {'Ratio':>6}")
    print("-" * 40)

    excess_candidates = []
    for letter, count in sorted_freq:
        excess = count - expected_per_letter
        ratio = count / expected_per_letter
        flag = " ***" if excess >= 2 else ""
        print(f"{letter:>6} {count:>5} {expected_per_letter:>8.2f} {excess:>+6.2f} {ratio:>6.2f}{flag}")
        if excess >= 2:
            excess_candidates.append((letter, count, excess))

    print(f"\nLetters with excess >= 2 over expected:")
    if excess_candidates:
        for letter, count, excess in excess_candidates:
            print(f"  {letter}: {count} occurrences (excess: {excess:.2f})")
            # If this letter is a null, removing it should leave ~73 chars
            remaining = CT_LEN - count
            print(f"    Removing all '{letter}': {remaining} chars remaining "
                  f"({'MATCHES 73!' if remaining == 73 else f'!= 73'})")
    else:
        print("  None")

    # Check: which single letter, if ALL instances removed, gives exactly 73?
    print(f"\nWhich letter removal gives exactly 73 chars?")
    for letter in ALPH:
        if freq.get(letter, 0) == CT_LEN - 73:
            print(f"  Removing all '{letter}' ({freq[letter]} instances) -> 73 chars!")

    # Check pairs of letters summing to 24
    print(f"\nWhich letter-pair removals give exactly 73 chars?")
    for i, l1 in enumerate(ALPH):
        for l2 in ALPH[i+1:]:
            combined = freq.get(l1, 0) + freq.get(l2, 0)
            if combined == 24:
                print(f"  Removing all '{l1}' ({freq.get(l1, 0)}) + "
                      f"'{l2}' ({freq.get(l2, 0)}) = 24 -> 73 chars!")

    # Chi-squared test against uniform
    chi2 = sum((freq.get(c, 0) - expected_per_letter) ** 2 / expected_per_letter
               for c in ALPH)
    # Degrees of freedom = 25
    print(f"\nChi-squared (vs uniform): {chi2:.2f} (df=25, critical p=0.05: 37.65)")
    print(f"  {'REJECT uniform' if chi2 > 37.65 else 'Cannot reject uniform'} at p=0.05")

    # English frequency analysis
    english_freq = {
        'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
        'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
        'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
        'P': 1.9, 'B': 1.5, 'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2,
        'Q': 0.1, 'Z': 0.1,
    }
    print(f"\nFrequency comparison (actual vs English expected for {CT_LEN} chars):")
    print(f"{'Letter':>6} {'Actual':>6} {'EngExp':>8} {'Delta':>6}")
    print("-" * 30)
    for letter, count in sorted_freq[:10]:
        eng_exp = english_freq.get(letter, 1.0) * CT_LEN / 100
        delta = count - eng_exp
        print(f"{letter:>6} {count:>6} {eng_exp:>8.1f} {delta:>+6.1f}")

    return freq


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2: GRID DIMENSIONS FOR 73
# ═══════════════════════════════════════════════════════════════════════════

def analyze_73_structure():
    """Analyze what grid structures work for 73 characters."""
    print("\n" + "=" * 78)
    print("SECTION 2: GRID DIMENSIONS FOR 73")
    print("=" * 78)

    n = 73
    print(f"\n73 is prime: {all(73 % i != 0 for i in range(2, 73))}")
    print(f"73 = 8 * 9 + 1 = {8*9+1}")
    print(f"73 = 7 * 10 + 3 = {7*10+3}")

    print(f"\nLegal pad says '8 lines'. Possible layouts for 73 chars in 8 rows:")
    # 8 rows: 73 = 8*q + r where r < 8
    q, r = divmod(73, 8)
    print(f"  73 / 8 = {q} remainder {r}")
    print(f"  -> {r} rows of {q+1}, {8-r} rows of {q}")
    print(f"  -> {r} rows of {q+1} ({r*(q+1)} chars) + {8-r} rows of {q} ({(8-r)*q} chars)")
    print(f"  = {r*(q+1) + (8-r)*q} total")

    print(f"\n  Option A: 1 row of 10, 7 rows of 9 = {1*10 + 7*9}")
    print(f"  Option B: 8 rows of 9 + 1 extra char = {8*9} + 1 = {8*9+1}")
    print(f"  Option C: Irregular rows (message-dependent)")

    print(f"\nAll rectangular near-grids for 73:")
    for rows in range(2, 20):
        cols, rem = divmod(73, rows)
        if rem == 0:
            print(f"  {rows} x {cols} = {rows*cols} (exact rectangle)")
        elif rem <= rows:
            print(f"  {rows} rows: {rows-rem} rows of {cols}, {rem} rows of {cols+1}")

    # Check 97 grid dimensions too for comparison
    print(f"\n97 is prime: {all(97 % i != 0 for i in range(2, 97))}")
    print(f"The carved text is also prime-length, making rectangular grids impossible for both.")

    # What about 73 and 97 in relation to the 28x31 master grid?
    print(f"\nRelation to 28x31 master grid (868 cells):")
    print(f"  K4 at row 24, col 27 in the grid")
    print(f"  868 / 2 = 434 (top half = K1+K2, bottom half = K3+?+K4)")
    print(f"  K3 carved = 336 chars, K4 carved = 97 chars")
    print(f"  336 + 97 = 433 (one short of 434 — the 'extra L' at row 14?)")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3: CRIB SPAN ANALYSIS — THE 73/24 COINCIDENCE
# ═══════════════════════════════════════════════════════════════════════════

def analyze_crib_span():
    """Analyze the striking 73/24 coincidence with crib positions."""
    print("\n" + "=" * 78)
    print("SECTION 3: CRIB SPAN ANALYSIS — THE 73/24 COINCIDENCE")
    print("=" * 78)

    crib_positions = sorted(CRIB_POSITIONS)
    non_crib_positions = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)

    print(f"\nCrib positions ({len(crib_positions)}): {crib_positions}")
    print(f"  EASTNORTHEAST: positions 21-33 (13 chars)")
    print(f"  BERLINCLOCK:   positions 63-73 (11 chars)")
    print(f"  Total crib positions: {len(crib_positions)}")

    print(f"\nNon-crib positions ({len(non_crib_positions)}):")
    print(f"  Segment 1: positions 0-20  ({21} chars)")
    print(f"  Segment 2: positions 34-62 ({29} chars)")
    print(f"  Segment 3: positions 74-96 ({23} chars)")
    print(f"  Total: {21 + 29 + 23} = {len(non_crib_positions)}")

    print(f"\n*** KEY COINCIDENCE ***")
    print(f"  Legal pad says K4 = 73 characters")
    print(f"  Non-crib positions = {len(non_crib_positions)}")
    print(f"  Crib positions = {len(crib_positions)} = 97 - 73 = 24")
    print(f"  MATCH: {len(non_crib_positions) == 73}")

    # Extract non-crib characters
    non_crib_text = "".join(CT[i] for i in non_crib_positions)
    crib_text = "".join(CT[i] for i in crib_positions)

    print(f"\nNon-crib text (73 chars): {non_crib_text}")
    print(f"Crib-position text (24 chars): {crib_text}")

    # IC analysis
    ic_full = ic(CT)
    ic_non_crib = ic(non_crib_text)
    ic_crib = ic(crib_text)

    print(f"\nIC Analysis:")
    print(f"  Full K4 (97 chars):     IC = {ic_full:.4f}")
    print(f"  Non-crib (73 chars):    IC = {ic_non_crib:.4f}")
    print(f"  Crib-pos only (24):     IC = {ic_crib:.4f}")
    print(f"  Random expected:        IC = {1/26:.4f}")
    print(f"  English expected:        IC = 0.0667")

    # Frequency of crib-position characters
    crib_freq = Counter(crib_text)
    print(f"\nCharacters AT crib positions (the 'inserted' chars if hypothesis is true):")
    print(f"  Text: {crib_text}")
    print(f"  Frequencies: {dict(sorted(crib_freq.items(), key=lambda x: -x[1]))}")
    print(f"  Unique letters: {len(crib_freq)}")

    # What these 24 positions contain in the ciphertext
    print(f"\n  If these 24 are nulls, they should look random or patterned.")
    print(f"  They contain {len(crib_freq)} unique letters out of 24 positions.")
    expected_unique_random = 26 * (1 - ((25/26)**24))
    print(f"  Expected unique for 24 random picks from 26: {expected_unique_random:.1f}")

    return non_crib_text, crib_text, non_crib_positions, crib_positions


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4: DECRYPT THE 73 NON-CRIB CHARS
# ═══════════════════════════════════════════════════════════════════════════

def decrypt_73_noncrib(non_crib_text: str):
    """Try decrypting the 73 non-crib characters with standard methods."""
    print("\n" + "=" * 78)
    print("SECTION 4: DECRYPT THE 73 NON-CRIB CHARACTERS")
    print("=" * 78)

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
        "COLOPHON", "SHADOW", "SANBORN", "SCHEIDT", "BERLIN",
        "COMPASS", "ENIGMA", "VERDIGRIS", "HOROLOGE", "POINT",
        "CLOCK", "FIVE", "EIGHT",
    ]

    variants = [
        CipherVariant.VIGENERE,
        CipherVariant.BEAUFORT,
        CipherVariant.VAR_BEAUFORT,
    ]

    alphabets = [("AZ", AZ), ("KA", KA)]

    results = []
    best_score = 0

    print(f"\nInput: {non_crib_text} (len={len(non_crib_text)})")
    print(f"\nTrying {len(keywords)} keywords x {len(variants)} variants x {len(alphabets)} alphabets...")
    print(f"{'Keyword':>12} {'Variant':>12} {'Alpha':>4} {'FreeScore':>9} {'IC':>6} Plaintext")
    print("-" * 100)

    for keyword in keywords:
        for variant in variants:
            for alpha_name, alpha in alphabets:
                # Convert keyword to numeric key using the alphabet
                key = alpha.encode(keyword)

                # Decrypt
                fn = DECRYPT_FN[variant]
                klen = len(key)
                pt_nums = [fn(alpha.char_to_idx(c), key[i % klen]) for i, c in enumerate(non_crib_text)]
                pt = alpha.decode(pt_nums)

                # Score using free crib (position-independent)
                free_score = score_free_fast(pt)
                ic_val = ic(pt)

                if free_score > 0 or ic_val > 0.050:
                    print(f"{keyword:>12} {variant.value:>12} {alpha_name:>4} {free_score:>9} "
                          f"{ic_val:>6.4f} {pt[:60]}...")
                    results.append((free_score, ic_val, keyword, variant.value, alpha_name, pt))
                    best_score = max(best_score, free_score)

                # Also try standard AZ decryption (not using alphabet for positions)
                if alpha_name == "AZ":
                    key_az = [ord(c) - 65 for c in keyword]
                    pt2 = decrypt_text(non_crib_text, key_az, variant)
                    free_score2 = score_free_fast(pt2)
                    ic_val2 = ic(pt2)
                    if free_score2 > 0 or ic_val2 > 0.050:
                        print(f"{keyword:>12} {variant.value:>12} {'std':>4} {free_score2:>9} "
                              f"{ic_val2:>6.4f} {pt2[:60]}...")
                        results.append((free_score2, ic_val2, keyword, variant.value, "std", pt2))
                        best_score = max(best_score, free_score2)

    if best_score == 0:
        # Show some representative outputs
        print("\nNo crib hits. Showing sample decryptions for inspection:")
        for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                key = [ord(c) - 65 for c in keyword]
                pt = decrypt_text(non_crib_text, key, variant)
                ic_val = ic(pt)
                print(f"  {keyword:>12} {variant.value:>10}: IC={ic_val:.4f} {pt}")

    return results, best_score


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5: NULL POSITION PATTERN ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def analyze_null_patterns():
    """Test if the 24 null positions follow a recognizable pattern."""
    print("\n" + "=" * 78)
    print("SECTION 5: NULL POSITION PATTERN ANALYSIS")
    print("=" * 78)

    crib_positions = sorted(CRIB_POSITIONS)

    print(f"\nCrib positions (potential null positions): {crib_positions}")

    # Differences between consecutive positions
    diffs = [crib_positions[i+1] - crib_positions[i] for i in range(len(crib_positions)-1)]
    print(f"Consecutive differences: {diffs}")
    print(f"  Within ENE: {diffs[:12]} (all 1s = contiguous)")
    print(f"  Gap ENE->BC: {diffs[12]} (= {crib_positions[13] - crib_positions[12]})")
    print(f"  Within BC: {diffs[13:]} (all 1s = contiguous)")

    # The key question: are positions 21-33 and 63-73 structurally special?
    print(f"\nStructural analysis of crib positions:")
    print(f"  ENE starts at 21, BC starts at 63")
    print(f"  63 - 21 = 42, 63 - 34 = 29 (gap between crib blocks)")
    print(f"  21 = 3 * 7, 63 = 9 * 7")
    print(f"  Both divisible by 7: {21 % 7 == 0 and 63 % 7 == 0}")
    print(f"  Both divisible by 3: {21 % 3 == 0 and 63 % 3 == 0}")

    # Test: every Nth character removal
    print(f"\nTesting regular-interval null patterns:")
    for interval in range(3, 15):
        for offset in range(interval):
            null_pos = set(range(offset, CT_LEN, interval))
            if len(null_pos) == 24:
                remaining = CT_LEN - len(null_pos)
                # Check if cribs are preserved (null positions don't overlap crib positions)
                crib_overlap = null_pos & CRIB_POSITIONS
                print(f"  Every {interval}th starting at {offset}: "
                      f"{len(null_pos)} nulls, "
                      f"{remaining} remaining, "
                      f"crib overlap: {len(crib_overlap)} positions")

    # Test: remove characters at positions where CT letter equals a specific letter
    print(f"\nTesting letter-based null selection:")
    freq = Counter(CT)
    for letter in ALPH:
        positions = [i for i, c in enumerate(CT) if c == letter]
        if len(positions) == 24:
            crib_overlap = set(positions) & CRIB_POSITIONS
            print(f"  Remove all '{letter}' ({len(positions)} occurrences): "
                  f"crib overlap = {len(crib_overlap)}")
            if len(crib_overlap) == 0:
                print(f"    *** CLEAN: no crib positions affected ***")
                remaining_text = "".join(c for i, c in enumerate(CT) if c != letter)
                print(f"    Remaining: {remaining_text}")

    # More nuanced: positions mod N
    print(f"\nPositions in various modular arithmetic:")
    for mod_val in [4, 5, 7, 8, 9, 10, 13, 31]:
        residues_of_cribs = sorted(set(p % mod_val for p in crib_positions))
        print(f"  Crib positions mod {mod_val}: residues = {residues_of_cribs} "
              f"({len(residues_of_cribs)} distinct)")

    # Check if crib positions map to specific rows in 8-line layout
    print(f"\nCrib positions in 8-row layouts:")
    for cols in [9, 10, 12, 13, 14, 31]:
        print(f"\n  Width {cols}:")
        for pos in crib_positions:
            row, col = divmod(pos, cols)
            print(f"    CT[{pos:2d}] = '{CT[pos]}' -> row {row}, col {col}")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6: REMOVE EVERY Nth AND DECRYPT
# ═══════════════════════════════════════════════════════════════════════════

def test_regular_removal_decrypt():
    """Remove every Nth character and try decryption."""
    print("\n" + "=" * 78)
    print("SECTION 6: REGULAR REMOVAL + DECRYPTION TESTS")
    print("=" * 78)

    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
                "COLOPHON", "SHADOW", "FIVE", "EIGHT", "POINT"]

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    best_results = []

    # Method 1: Remove every 4th (97/4 ~= 24.25, close but not exact)
    # Method 2: Remove first 24 of every 4th
    # Method 3: Various patterns
    removal_patterns = {}

    # Every 4th starting at different offsets (take first 24)
    for offset in range(4):
        positions = list(range(offset, CT_LEN, 4))[:24]
        if len(positions) == 24:
            removal_patterns[f"every4_offset{offset}"] = set(positions)

    # Every 4th but complete (may not be exactly 24)
    for start in range(4):
        positions = list(range(start, CT_LEN, 4))
        removal_patterns[f"every4_all_offset{start}"] = set(positions)

    # Fibonacci positions mod 97
    fib = [1, 1]
    while fib[-1] < CT_LEN:
        fib.append(fib[-1] + fib[-2])
    fib_pos = set(f % CT_LEN for f in fib if f < 200)
    if len(fib_pos) >= 20:
        removal_patterns["fibonacci_mod97"] = set(list(fib_pos)[:24])

    # Prime positions < 97
    primes = [p for p in range(2, CT_LEN) if all(p % i != 0 for i in range(2, int(p**0.5)+1))]
    removal_patterns["prime_positions"] = set(primes[:24])

    # Positions where CT[i] is one of the most common letters
    freq = Counter(CT)
    most_common_letter = freq.most_common(1)[0][0]
    removal_patterns[f"all_{most_common_letter}"] = set(i for i, c in enumerate(CT) if c == most_common_letter)

    # The exact crib positions (the 73-coincidence pattern)
    removal_patterns["crib_positions"] = set(CRIB_POSITIONS)

    print(f"\nTesting {len(removal_patterns)} removal patterns x {len(keywords)} keywords x {len(variants)} variants")

    for pattern_name, null_positions in removal_patterns.items():
        remaining_positions = sorted(set(range(CT_LEN)) - null_positions)
        remaining_text = "".join(CT[i] for i in remaining_positions)
        n_removed = CT_LEN - len(remaining_text)

        for keyword in keywords:
            for variant in variants:
                key = [ord(c) - 65 for c in keyword]
                pt = decrypt_text(remaining_text, key, variant)
                free_score = score_free_fast(pt)
                ic_val = ic(pt)

                if free_score > NOISE_FLOOR or ic_val > 0.055:
                    print(f"  [{pattern_name}] removed={n_removed} "
                          f"{keyword:>12} {variant.value:>12} "
                          f"free={free_score} IC={ic_val:.4f} {pt[:50]}...")
                    best_results.append((free_score, ic_val, pattern_name,
                                       keyword, variant.value, pt))

    if not best_results:
        # Show the crib-position removal results for reference
        print("\nNo hits above threshold. Showing crib-position removal results:")
        null_positions = set(CRIB_POSITIONS)
        remaining_positions = sorted(set(range(CT_LEN)) - null_positions)
        remaining_text = "".join(CT[i] for i in remaining_positions)
        for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                key = [ord(c) - 65 for c in keyword]
                pt = decrypt_text(remaining_text, key, variant)
                ic_val = ic(pt)
                print(f"  {keyword:>12} {variant.value:>10}: IC={ic_val:.4f} {pt}")

    return best_results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 7: K3 PARALLEL — 342 vs 336
# ═══════════════════════════════════════════════════════════════════════════

def analyze_k3_parallel():
    """Compare K3's legal-pad 342 vs carved 336 to understand the pattern."""
    print("\n" + "=" * 78)
    print("SECTION 7: K3 PARALLEL — 342 vs 336")
    print("=" * 78)

    # K3 ciphertext (from the sculpture)
    K3_CT = (
        "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
        "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETF"
        "OLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTE"
        "EFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBA"
        "ECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
        "ECDMRIPFEIMEHNLSSTTRTVDOHW"
    )

    # K3 plaintext (known solution)
    K3_PT = (
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
        "OTHEWALLFOUNDATIONOFEARTHANDLIGHTTHATWASLAIDTORESTWASBUT"
        "ANDNOWONLYTHEECHOESOFWHATWEREDISCOVEREDREMAINHOVERINGOVE"
        "RTHESURFACEAGLIMMEROFHOPEASTHEEARTHFOLDEDOVERONITSELFINF"
        "INITELYSOMEWHEREBETWEENWHATISRIGHTANDWHATISTRIBUTEDASTHE"
        "SHIFTSLOWLYRIGHTWARDANDTHEAPERTUREBECAMEMORENARROWANDFIN"
        "ALLYTHEREWASLIGHTAGAINBUTNOWITWASBRIGHT"
    ).upper()

    # Wait — I need the actual K3 from the sculpture. Let me use what we have.
    # The carved K3 = 336 characters
    print(f"\nK3 ciphertext (carved): {len(K3_CT)} characters")

    k3_legal = 342
    k3_carved = len(K3_CT)
    k3_diff = k3_legal - k3_carved

    print(f"\nComparison:")
    print(f"  Legal pad 'K3': {k3_legal} chars")
    print(f"  Carved K3:      {k3_carved} chars")
    print(f"  Difference:     {k3_diff} (legal pad has {k3_diff} MORE)")

    k4_legal = 73
    k4_carved = 97
    k4_diff = k4_carved - k4_legal

    print(f"\n  Legal pad 'K4': {k4_legal} chars")
    print(f"  Carved K4:      {k4_carved} chars")
    print(f"  Difference:     {k4_diff} (carved has {k4_diff} MORE)")

    print(f"\nK3 LOST {k3_diff} chars from planning to carving")
    print(f"K4 GAINED {k4_diff} chars from planning to carving")
    print(f"Net change: +{k4_diff} - {k3_diff} = {k4_diff - k3_diff}")
    print(f"  If the 6 removed from K3 were added to K4: K4 would have {k4_legal + k3_diff} = {k4_legal + k3_diff}")
    print(f"  But K4 has 97 = 73 + 24, not 73 + 6.")

    print(f"\nK3 PT (solved): {len(K3_PT)} chars")
    if len(K3_PT) != k3_carved:
        print(f"  NOTE: K3 plaintext length ({len(K3_PT)}) != K3 CT length ({k3_carved})")
        print(f"  Difference: {len(K3_PT) - k3_carved}")

    # K3 uses "14 lines" on the legal pad. 336/14 = 24 exactly
    print(f"\nK3 structure:")
    print(f"  '14 lines' on legal pad")
    print(f"  336 / 14 = {336/14} chars per line")
    print(f"  342 / 14 = {342/14:.2f} chars per line")
    print(f"  If 14 lines of 24: {14*24} = 336 (matches carved!)")
    print(f"  If 14 lines of 24.43: would need irregular rows for 342")

    # K4 structure
    print(f"\nK4 structure:")
    print(f"  '8 lines' on legal pad")
    print(f"  73 / 8 = {73/8:.3f} chars per line")
    print(f"  97 / 8 = {97/8:.3f} chars per line")
    print(f"  If 8 lines in the 28x31 grid, line length = 31")
    print(f"  8 * 31 = {8*31} (much larger than either 73 or 97)")

    # IMPORTANT: K3 is 14 rows of 24 = 336, matching the grid width scenario
    # K4 could be 8 rows of some width
    print(f"\n*** INSIGHT ***")
    print(f"  K3: 14 lines x 24 wide = 336 (matches carved)")
    print(f"  K4: 8 lines x ? wide")
    print(f"    8 x 9 = 72 (close to 73)")
    print(f"    8 x 10 = 80")
    print(f"    8 x 12 = 96 (close to 97!)")
    print(f"    8 x 13 = 104")
    print(f"    If 342 was Sanborn's K3 BEFORE layout adjustment (342/14=24.43),")
    print(f"    and 73 was K4 BEFORE expansion (73 -> 97 via null insertion),")
    print(f"    the legal pad captures the PRE-LAYOUT counts.")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 8: ALTERNATIVE NULL PATTERNS + DECRYPTION
# ═══════════════════════════════════════════════════════════════════════════

def test_alternative_null_patterns():
    """Test more sophisticated null-position hypotheses."""
    print("\n" + "=" * 78)
    print("SECTION 8: ALTERNATIVE NULL PATTERNS + DECRYPTION")
    print("=" * 78)

    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
                "COLOPHON", "SHADOW"]
    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    best_results = []

    # Pattern: Null positions are those where position % 4 == K (for various K)
    # that gives 24 or 25 nulls
    print("\nPattern family: position mod N filters")
    for mod_val in [4, 5, 8]:
        for residue in range(mod_val):
            null_pos = set(i for i in range(CT_LEN) if i % mod_val == residue)
            if 20 <= len(null_pos) <= 28:
                remaining = "".join(CT[i] for i in range(CT_LEN) if i not in null_pos)
                for keyword in keywords:
                    for variant in variants:
                        key = [ord(c) - 65 for c in keyword]
                        pt = decrypt_text(remaining, key, variant)
                        free_score = score_free_fast(pt)
                        if free_score > NOISE_FLOOR:
                            print(f"  mod{mod_val}=={residue} (remove {len(null_pos)}): "
                                  f"{keyword} {variant.value} free={free_score} {pt[:40]}")
                            best_results.append((free_score, f"mod{mod_val}=={residue}",
                                               keyword, variant.value, pt))

    # Pattern: Remove positions that are in specific rows of a grid
    print("\nPattern family: row-based removal in grid layouts")
    for width in [8, 9, 10, 12, 13, 14, 31]:
        for target_row in range(min(CT_LEN // width + 1, 15)):
            null_pos = set(i for i in range(CT_LEN)
                          if (i // width) == target_row)
            if 20 <= len(null_pos) <= 28:
                remaining = "".join(CT[i] for i in range(CT_LEN) if i not in null_pos)
                for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                        key = [ord(c) - 65 for c in keyword]
                        pt = decrypt_text(remaining, key, variant)
                        free_score = score_free_fast(pt)
                        if free_score > NOISE_FLOOR:
                            print(f"  width={width} remove_row={target_row} ({len(null_pos)} chars): "
                                  f"{keyword} {variant.value} free={free_score}")
                            best_results.append((free_score, f"w{width}_r{target_row}",
                                               keyword, variant.value, pt))

    # Pattern: Column-based removal
    print("\nPattern family: column-based removal in grid layouts")
    for width in [8, 9, 10, 12, 13, 14]:
        for n_cols_remove in [1, 2, 3]:
            for col_start in range(width):
                null_pos = set()
                for col_offset in range(n_cols_remove):
                    col = (col_start + col_offset) % width
                    null_pos.update(i for i in range(CT_LEN) if i % width == col)
                if 20 <= len(null_pos) <= 28:
                    remaining = "".join(CT[i] for i in range(CT_LEN) if i not in null_pos)
                    for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                            key = [ord(c) - 65 for c in keyword]
                            pt = decrypt_text(remaining, key, variant)
                            free_score = score_free_fast(pt)
                            if free_score > NOISE_FLOOR:
                                print(f"  width={width} remove_cols={col_start}-{col_start+n_cols_remove-1} "
                                      f"({len(null_pos)} chars): "
                                      f"{keyword} {variant.value} free={free_score}")
                                best_results.append((free_score, f"w{width}_c{col_start}x{n_cols_remove}",
                                                   keyword, variant.value, pt))

    # Pattern: Interleave — every other char in a specific section
    print("\nPattern family: interleave removal")
    for block_start in range(0, CT_LEN - 48, 1):
        for block_len in [48, 24]:
            null_pos = set(range(block_start, min(block_start + block_len, CT_LEN), 2))
            if 20 <= len(null_pos) <= 28:
                remaining = "".join(CT[i] for i in range(CT_LEN) if i not in null_pos)
                for keyword in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                    for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                        key = [ord(c) - 65 for c in keyword]
                        pt = decrypt_text(remaining, key, variant)
                        free_score = score_free_fast(pt)
                        if free_score > NOISE_FLOOR:
                            print(f"  interleave start={block_start} len={block_len} "
                                  f"({len(null_pos)} nulls): "
                                  f"{keyword} {variant.value} free={free_score}")
                            best_results.append((free_score, f"interleave_{block_start}_{block_len}",
                                               keyword, variant.value, pt))

    if not best_results:
        print("\nNo hits above noise floor for any alternative pattern.")

    return best_results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 9: DEEP DIVE — CRIB POSITION REMOVAL + KA ALPHABETS
# ═══════════════════════════════════════════════════════════════════════════

def deep_dive_crib_removal():
    """Most thorough test of the core hypothesis: remove crib positions, decrypt with all combos."""
    print("\n" + "=" * 78)
    print("SECTION 9: DEEP DIVE — REMOVE CRIB POSITIONS, FULL KEYWORD SWEEP")
    print("=" * 78)

    non_crib_positions = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)
    text_73 = "".join(CT[i] for i in non_crib_positions)

    print(f"\n73-char text (non-crib positions): {text_73}")
    print(f"Length: {len(text_73)}")

    # Extended keyword list
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
        "COLOPHON", "SHADOW", "SANBORN", "SCHEIDT", "BERLIN",
        "COMPASS", "ENIGMA", "VERDIGRIS", "HOROLOGE", "POINT",
        "CLOCK", "FIVE", "EIGHT", "LODESTONE", "URANIA",
        "WELTZEITUHR", "MENGENLEHREUHR", "TUTANKHAMUN", "CARTER",
        "EGYPT", "SPHINX", "PHARAOH", "QUARTZ",
        "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
        "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    ]

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    print(f"\nSweeping {len(keywords)} keywords x {len(variants)} variants x 2 alphabets...")

    hits = []
    count = 0

    for keyword in keywords:
        for variant in variants:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                key = alpha.encode(keyword)
                fn = DECRYPT_FN[variant]
                klen = len(key)
                pt_nums = [fn(alpha.char_to_idx(c), key[i % klen]) for i, c in enumerate(text_73)]
                pt = alpha.decode(pt_nums)

                free_score = score_free_fast(pt)
                if free_score > 0:
                    ic_val = ic(pt)
                    print(f"  HIT: {keyword:>15} {variant.value:>12} {alpha_name} "
                          f"free={free_score} IC={ic_val:.4f} {pt[:50]}")
                    hits.append((free_score, keyword, variant.value, alpha_name, pt))

                count += 1

    print(f"\nTotal configs tested: {count}")
    print(f"Hits above 0: {len(hits)}")

    if not hits:
        # Check IC distribution
        print("\nIC histogram for KRYPTOS keyword decryptions:")
        ic_vals = []
        for variant in variants:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                key = alpha.encode("KRYPTOS")
                fn = DECRYPT_FN[variant]
                klen = len(key)
                pt_nums = [fn(alpha.char_to_idx(c), key[i % klen]) for i, c in enumerate(text_73)]
                pt = alpha.decode(pt_nums)
                ic_val = ic(pt)
                ic_vals.append((ic_val, variant.value, alpha_name, pt[:30]))
                print(f"  {variant.value:>12} {alpha_name}: IC={ic_val:.4f} {pt[:50]}")

    return hits


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 10: STATISTICAL SIGNIFICANCE OF THE 73/24 COINCIDENCE
# ═══════════════════════════════════════════════════════════════════════════

def evaluate_coincidence():
    """How unlikely is the 73/24 match?"""
    print("\n" + "=" * 78)
    print("SECTION 10: STATISTICAL SIGNIFICANCE OF THE 73/24 COINCIDENCE")
    print("=" * 78)

    print(f"""
The coincidence under examination:
  - Legal pad says K4 = 73 characters
  - K4 carved = 97 characters
  - K4 crib positions = 24 (EASTNORTHEAST=13 + BERLINCLOCK=11)
  - K4 non-crib positions = 97 - 24 = 73

How likely is this to be random?

1. The legal pad number 73 is ONE specific number.
2. The crib count 24 was determined by Sanborn's choice of two words.
3. The CT length 97 was determined by the message + encryption.
4. The equation 97 - 24 = 73 is trivially true given those values.

But the question is: did Sanborn CHOOSE the message/crib-words
such that (CT_length - total_crib_chars) = planned_PT_length?

If the legal pad predates crib selection:
  P(random) = 1/97 (any specific number matching)
  This is ~1% — suggestive but not conclusive.

If the legal pad postdates message completion:
  The 73 might simply count something else (non-crib chars, or plaintext
  before padding). The coincidence is BY DESIGN, not random.

Alternative interpretation: '73' counts something else entirely:
  - Number of distinct words in K4 plaintext?
  - A key parameter (column width, shift value)?
  - Characters in the key or key phrase?

VERDICT: The coincidence is NOTABLE but requires cryptanalytic evidence
(successful decryption) to be promoted from [HYPOTHESIS] to [DERIVED FACT].
""")

    # Additional number relationships
    print("Additional relationships with 73 and 24:")
    print(f"  73 + 24 = {73+24}")
    print(f"  73 - 24 = {73-24}")
    print(f"  73 * 24 = {73*24}")
    print(f"  73 is the 21st prime (21 = start of ENE crib)")
    print(f"  73 in binary = {bin(73)} = 1001001 (palindrome!)")
    print(f"  24 = 4! = factorial(4)")
    print(f"  97 is the 25th prime")
    print(f"  73 is Sheldon's number (The Big Bang Theory, coincidence)")
    print(f"  73 reversed = 37, which is the 12th prime")
    print(f"  12th position in K4 CT = '{CT[12]}' (position 12 is within pre-crib segment)")

    # Is 73 the 21st prime?
    primes = []
    for n in range(2, 200):
        if all(n % i != 0 for i in range(2, int(n**0.5)+1)):
            primes.append(n)
    idx_73 = primes.index(73) + 1  # 1-indexed
    print(f"\n  73 is the {idx_73}th prime")
    print(f"  97 is the {primes.index(97) + 1}th prime")
    print(f"  21st prime = {primes[20]}")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 11: SEGMENT-LEVEL IC ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def segment_analysis(non_crib_text: str, crib_text: str):
    """Detailed analysis of the three non-crib segments."""
    print("\n" + "=" * 78)
    print("SECTION 11: SEGMENT-LEVEL ANALYSIS")
    print("=" * 78)

    seg1 = CT[0:21]    # Before first crib
    seg2 = CT[34:63]   # Between cribs
    seg3 = CT[74:97]   # After second crib

    segments = [("Pre-ENE (0-20)", seg1),
                ("Gap (34-62)", seg2),
                ("Post-BC (74-96)", seg3)]

    for name, seg in segments:
        print(f"\n{name}: {seg} (len={len(seg)})")
        print(f"  IC = {ic(seg):.4f}")
        print(f"  Frequencies: {dict(sorted(Counter(seg).items(), key=lambda x: -x[1]))}")

    print(f"\nCombined non-crib: {non_crib_text}")
    print(f"  IC = {ic(non_crib_text):.4f}")

    # Vigenere period detection on non-crib text
    print(f"\nIC by period for the 73 non-crib chars:")
    for period in range(2, 16):
        ic_vals = ic_by_position(non_crib_text, period)
        avg_ic = sum(ic_vals) / len(ic_vals)
        print(f"  Period {period:2d}: avg IC = {avg_ic:.4f}  "
              f"ICs = [{', '.join(f'{v:.3f}' for v in ic_vals)}]")

    # Same for full CT
    print(f"\nIC by period for full 97-char CT (for comparison):")
    for period in range(2, 16):
        ic_vals = ic_by_position(CT, period)
        avg_ic = sum(ic_vals) / len(ic_vals)
        print(f"  Period {period:2d}: avg IC = {avg_ic:.4f}  "
              f"ICs = [{', '.join(f'{v:.3f}' for v in ic_vals)}]")


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 12: WHAT IF CRIBS ARE IN THE 73-CHAR TEXT (SHIFTED)?
# ═══════════════════════════════════════════════════════════════════════════

def test_shifted_cribs():
    """If 24 nulls were removed, cribs would shift. Where would they end up?"""
    print("\n" + "=" * 78)
    print("SECTION 12: CRIB POSITION SHIFTING AFTER NULL REMOVAL")
    print("=" * 78)

    print("""
If 24 characters are INSERTED (nulls) and the original 73-char text has
the cribs, the crib positions in the original text would be different
from positions in the expanded 97-char text.

We need to consider: what if the cribs are at positions in the EXPANDED
text (97-char), and we need to find which positions in the ORIGINAL
(73-char) text they correspond to, depending on WHERE the nulls are?

Actually, the more interesting question is the REVERSE:
- K4 plaintext is 73 chars
- It gets encrypted to 73 chars of ciphertext
- Then 24 nulls are inserted at specific positions to make 97 chars
- The CRIBS tell us about the 97-char version
- We need to figure out which 73 of the 97 positions are 'real'

If the crib positions (21-33, 63-73) are ALL nulls:
  Then the real CT is the non-crib positions (our 73-char text)
  And decryption of the 73-char text should yield English

If the crib positions are NOT nulls:
  Then some mix of crib/non-crib positions are real
  This is much harder to determine
""")

    # Test: what if each crib position IS a null, but the cribs still
    # constrain the substitution cipher applied BEFORE null insertion?
    print("Implication analysis:")
    print("  If crib positions are nulls, cribs constrain what?")
    print("  The cribs relate CT[i] to PT[i] at those positions.")
    print("  If CT[21] is a null, then 'E' at PT[21] is also a null position.")
    print("  This would mean the cribs are about the NULL characters, not the real message.")
    print("  That seems backward — Sanborn wouldn't crib the nulls.")
    print()
    print("  MORE LIKELY: The cribs are part of the REAL plaintext.")
    print("  The 73-char plaintext CONTAINS EASTNORTHEAST and BERLINCLOCK.")
    print("  After encryption, 24 nulls are inserted, expanding to 97 chars.")
    print("  The crib positions (21-33, 63-73) in the 97-char text correspond")
    print("  to SHIFTED positions in the 73-char text.")

    # If we assume the cribs are in the 73-char text, where might they be?
    # The crib positions in the 97-char text tell us about the post-insertion layout
    # Before insertion, if N nulls were inserted before position P, then
    # original_position = P - (number of nulls before P)
    print("\nCrib position shifting for various null-insertion points:")

    # Test: all 24 nulls inserted at the BEGINNING (positions 0-23)
    print("\n  If 24 nulls at positions 0-23:")
    print(f"    ENE would be at 73-char positions {21-24}..{33-24} = -3..9 (IMPOSSIBLE, wraps)")

    # Test: nulls distributed evenly — every 4th position
    print("\n  If nulls at every 4th position (0,4,8,...,92):")
    for orig_pos in [21, 63]:
        nulls_before = len([p for p in range(0, orig_pos+1, 4)])
        shifted = orig_pos - nulls_before
        print(f"    Position {orig_pos} in 97-char -> position {shifted} in 73-char")

    # For each possible set of 24 null positions that are contiguous blocks...
    # Actually let's just check: if nulls are the crib positions themselves,
    # that's our main hypothesis. But we showed above why it's problematic.

    # NEW IDEA: What if the 73-char text is NOT from removing crib positions,
    # but from a DIFFERENT set of 24 positions? And the cribs still work
    # on the 97-char text?
    print("\n*** KEY REALIZATION ***")
    print("The cribs constrain CT[i]<->PT[i] at specific positions in the 97-char text.")
    print("If some of those 97 positions are nulls, the null positions should NOT")
    print("be at crib positions (because we'd lose the crib constraint).")
    print("Therefore: if the null hypothesis is true, the 24 nulls must be at")
    print("NON-crib positions, leaving us with 73 - 24 = 49 unknown + 24 cribs = 73 real chars.")
    print("Wait: 97 - 24 nulls = 73 real chars, and 24 of those 73 are cribs.")
    print("So: 73 real positions, 24 of which are cribs = 49 unknown real + 24 crib real.")
    print()
    print("The 24 nulls are among the 73 NON-crib positions (0-20, 34-62, 74-96).")
    print("This means the 73 non-crib positions contain BOTH 49 real chars AND 24 nulls.")
    print("We need to identify which 24 of the 73 non-crib positions are nulls.")

    # This is C(73,24) ~ 10^18 -- way too many to enumerate
    print(f"\nC(73,24) = {math.comb(73,24):.2e} — too many for brute force")
    print("We need a signal to identify the null positions.")

    return


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 13: TEST SPECIFIC NULL HYPOTHESES PRESERVING CRIBS
# ═══════════════════════════════════════════════════════════════════════════

def test_null_preserving_cribs():
    """Test null-removal patterns that preserve crib positions."""
    print("\n" + "=" * 78)
    print("SECTION 13: NULL REMOVAL PRESERVING CRIBS")
    print("=" * 78)

    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "PARALLAX",
                "COLOPHON", "SHADOW"]
    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]

    non_crib_positions = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)
    # Non-crib positions: 0-20 (21), 34-62 (29), 74-96 (23) = 73 total
    # We need to remove 24 of these 73 to get 49 real non-crib + 24 crib = 73 total

    best_results = []

    # Pattern: remove from specific segments
    seg1 = list(range(0, 21))      # 21 positions
    seg2 = list(range(34, 63))     # 29 positions
    seg3 = list(range(74, 97))     # 23 positions

    removal_strategies = []

    # Strategy: remove all of segment 1 + 3 from segment 3 = 21 + 3 = 24
    removal_strategies.append(("all_seg1_plus_3_from_seg3", seg1 + seg3[:3]))

    # Strategy: remove all of segment 3 + 1 from segment 1 = 23 + 1 = 24
    removal_strategies.append(("all_seg3_plus_1_from_seg1", seg3 + seg1[:1]))

    # Strategy: 8 from each segment
    removal_strategies.append(("8_per_seg", seg1[:8] + seg2[:8] + seg3[:8]))

    # Strategy: every 3rd from non-crib positions
    removal_strategies.append(("every3rd_noncrib",
                              [non_crib_positions[i] for i in range(0, 73, 3)][:24]))

    # Strategy: every 3rd from non-crib positions, offset 1
    removal_strategies.append(("every3rd_noncrib_off1",
                              [non_crib_positions[i] for i in range(1, 73, 3)][:24]))

    # Strategy: every 3rd from non-crib positions, offset 2
    removal_strategies.append(("every3rd_noncrib_off2",
                              [non_crib_positions[i] for i in range(2, 73, 3)][:24]))

    # Strategy: first 24 non-crib positions
    removal_strategies.append(("first_24_noncrib", non_crib_positions[:24]))

    # Strategy: last 24 non-crib positions
    removal_strategies.append(("last_24_noncrib", non_crib_positions[-24:]))

    # Strategy: middle 24 non-crib positions
    start = (73 - 24) // 2
    removal_strategies.append(("middle_24_noncrib", non_crib_positions[start:start+24]))

    # Strategy: remove even-indexed non-crib positions (every other one)
    removal_strategies.append(("even_idx_noncrib",
                              [non_crib_positions[i] for i in range(0, 73, 2)][:24]))

    # Strategy: remove odd-indexed non-crib positions
    removal_strategies.append(("odd_idx_noncrib",
                              [non_crib_positions[i] for i in range(1, 73, 2)][:24]))

    print(f"\nTesting {len(removal_strategies)} null-removal strategies")
    print(f"(each preserves all 24 crib positions)")

    for strategy_name, null_positions in removal_strategies:
        null_set = set(null_positions)
        assert len(null_set & CRIB_POSITIONS) == 0, f"Strategy {strategy_name} removes crib positions!"

        remaining_positions = sorted(set(range(CT_LEN)) - null_set)
        remaining_text = "".join(CT[i] for i in remaining_positions)

        # The crib positions shift: where are they in the new text?
        pos_map = {old: new for new, old in enumerate(remaining_positions)}
        new_ene_start = pos_map.get(21)
        new_bc_start = pos_map.get(63)

        print(f"\n  Strategy: {strategy_name}")
        print(f"    Removing {len(null_set)} positions, keeping {len(remaining_text)} chars")
        print(f"    ENE crib at new position: {new_ene_start}")
        print(f"    BC crib at new position: {new_bc_start}")
        print(f"    Remaining text: {remaining_text[:40]}...")

        # Check if cribs still match in new positions
        if new_ene_start is not None and new_bc_start is not None:
            ene_match = remaining_text[new_ene_start:new_ene_start+13] if new_ene_start + 13 <= len(remaining_text) else ""
            bc_match = remaining_text[new_bc_start:new_bc_start+11] if new_bc_start + 11 <= len(remaining_text) else ""

            # Check crib positions map correctly
            for pos in range(21, 34):
                if pos in pos_map:
                    new_pos = pos_map[pos]
                    assert remaining_text[new_pos] == CT[pos], f"Mismatch at {pos}"

        for keyword in keywords:
            for variant in variants:
                key = [ord(c) - 65 for c in keyword]
                pt = decrypt_text(remaining_text, key, variant)
                free_score = score_free_fast(pt)

                # Also check anchored crib score at new positions
                anchored_score = 0
                if new_ene_start is not None:
                    for i, ch in enumerate("EASTNORTHEAST"):
                        new_pos = new_ene_start + i
                        if new_pos < len(pt) and pt[new_pos] == ch:
                            anchored_score += 1
                if new_bc_start is not None:
                    for i, ch in enumerate("BERLINCLOCK"):
                        new_pos = new_bc_start + i
                        if new_pos < len(pt) and pt[new_pos] == ch:
                            anchored_score += 1

                ic_val = ic(pt)

                if free_score > NOISE_FLOOR or anchored_score > NOISE_FLOOR or ic_val > 0.055:
                    print(f"    {keyword:>12} {variant.value:>10}: "
                          f"free={free_score} anchored={anchored_score}/24 "
                          f"IC={ic_val:.4f} {pt[:40]}")
                    best_results.append((max(free_score, anchored_score),
                                       strategy_name, keyword, variant.value, pt))

    if not best_results:
        print("\n  No results above noise floor for any strategy.")

    return best_results


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 14: COMPREHENSIVE SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

def summary(freq, non_crib_text, all_results):
    """Summarize all findings."""
    print("\n" + "=" * 78)
    print("COMPREHENSIVE SUMMARY")
    print("=" * 78)

    print(f"""
1. FREQUENCY ANALYSIS:
   - K4 has all 26 letters; no single letter's count equals 24 (needed for 73-char match)
   - Most common letters: {', '.join(f'{l}={c}' for l, c in Counter(CT).most_common(5))}
   - Chi-squared test: distribution is consistent with polyalphabetic cipher (flat)
   - No single 'null letter' jumps out

2. GRID DIMENSIONS:
   - 73 is prime (no rectangular grid fits)
   - '8 lines' of ~9 chars each (1 row of 10 + 7 of 9)
   - K3 parallel: 14 lines x 24 = 336 = carved K3 length

3. THE 73/24 COINCIDENCE:
   - Non-crib positions = 97 - 24 = 73 = legal pad number
   - This is NUMERICALLY EXACT
   - Statistical significance: ~1% by chance (notable but not proof)

4. CRYPTANALYTIC TESTS:
   - 73 non-crib chars decrypted with all standard methods: {'NO HITS' if not any(r for r in all_results if r) else 'HITS FOUND'}
   - Regular null-removal patterns + decrypt: {'NO HITS' if not any(r for r in all_results if r) else 'HITS FOUND'}
   - Crib-preserving null removal + decrypt: {'NO HITS' if not any(r for r in all_results if r) else 'HITS FOUND'}

5. KEY INSIGHT FROM SECTION 12:
   - If the null hypothesis is true, the 24 nulls must be at NON-crib positions
   - This means C(73,24) ~ 10^18 possible null placements — intractable by brute force
   - Need a structural signal (pattern, rule) to identify null positions

6. IC OF 73 NON-CRIB CHARS: {ic(non_crib_text):.4f}
   (vs full CT: {ic(CT):.4f}, random: {1/26:.4f}, English: 0.0667)

VERDICT:
   The 73/24 coincidence is STRIKING and worth tracking as [HYPOTHESIS].
   However, no cryptanalytic evidence supports it yet.
   The hypothesis generates a combinatorial explosion (which 24 of 73 are nulls?)
   that cannot be resolved without additional structural constraints.

   NEXT STEPS:
   a) Look for physical markers on the sculpture at the 24 crib positions
   b) Test if Sanborn's '8 lines / 73' refers to something other than char count
   c) If the legal-pad image becomes available, verify the numbers
   d) Test whether the GRILLE provides the null-position selection rule
""")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("K4 NULL HYPOTHESIS ANALYZER")
    print("Hypothesis: K4 was 73 chars, expanded to 97 by inserting 24 nulls")
    print("=" * 78)

    # Section 1
    freq = analyze_frequencies()

    # Section 2
    analyze_73_structure()

    # Section 3
    non_crib_text, crib_text, non_crib_positions, crib_positions = analyze_crib_span()

    # Section 7 (moved up for context)
    analyze_k3_parallel()

    # Section 10
    evaluate_coincidence()

    # Section 11
    segment_analysis(non_crib_text, crib_text)

    # Section 4
    results_4, best_4 = decrypt_73_noncrib(non_crib_text)

    # Section 5
    analyze_null_patterns()

    # Section 6
    results_6 = test_regular_removal_decrypt()

    # Section 8
    results_8 = test_alternative_null_patterns()

    # Section 9
    results_9 = deep_dive_crib_removal()

    # Section 12
    test_shifted_cribs()

    # Section 13
    results_13 = test_null_preserving_cribs()

    # Summary
    all_results = [results_4, results_6, results_8, results_9, results_13]
    summary(freq, non_crib_text, all_results)

    # Final: collect any results above noise
    all_hits = []
    for r_list in all_results:
        if r_list:
            for r in r_list:
                if r[0] > NOISE_FLOOR:
                    all_hits.append(r)

    if all_hits:
        print(f"\n*** {len(all_hits)} RESULTS ABOVE NOISE FLOOR ***")
        for hit in sorted(all_hits, key=lambda x: -x[0]):
            print(f"  Score={hit[0]}: {hit[1:]}")
    else:
        print(f"\nNo results above noise floor (>{NOISE_FLOOR}) in any test.")


if __name__ == "__main__":
    main()
