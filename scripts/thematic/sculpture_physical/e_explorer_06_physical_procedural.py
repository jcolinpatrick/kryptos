#!/usr/bin/env python3
"""
Cipher: physical/coordinate
Family: thematic/sculpture_physical
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-EXPLORER-06: Physical/procedural cipher hypotheses.

Testing cipher methods inspired by Sanborn's "not a math solution" and
the physical properties of the sculpture. These are hand-executable
procedures that wouldn't appear in any cryptography textbook.

H1: Clock-hand reading order (Weltzeituhr / Berlin Clock)
    - The Berlin Clock (Mengenlehreuhr) displays time in a specific
      5-row pattern. Use its structure to define a reading order for K4.
    - "BERLINCLOCK" as a crib + "a reminder" suggests the clock's
      structure IS the method, not just a plaintext word.

H2: Coordinate-pair extraction
    - K2 gives coordinates: 38 57 6.5 N 77 8 44 W
    - Use these numbers as positions or offsets in K4
    - Extract letters at those positions, or use as key values

H3: Stencil cipher (grille) with irregular holes
    - Sanborn's "coding charts" may be physical stencils
    - A stencil placed over K4 reveals certain positions
    - Multiple stencil placements (rotations/shifts) reveal the full message
    - Test: positions selected by modular arithmetic, digit sequences,
      or derived from K1-K3 structure

H4: Progressive/layered unmasking
    - "Designed to unveil itself... pull up one layer... pull up another"
    - Each layer reveals part of the plaintext or a key for the next layer
    - Test: apply K3 method, extract partial PT, use that PT to derive
      the next key/method

H5: Misspelling-derived transformation
    - PALIMPCEST, IQLUSION, UNDERGRUUND, DESPARATLY, DIGETAL
    - Wrong letters: C, Q, U, A, E (anagram of EQUAL)
    - Positions of wrong letters may encode transformation parameters
    - Test as shift values, column selectors, or position markers

All constants from kryptos.kernel.constants.
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.scoring.ic import ic

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
ARTIFACTS_DIR = REPO_ROOT / "artifacts"
ARTIFACTS_DIR.mkdir(exist_ok=True)

CT_NUMS = [ALPH_IDX[c] for c in CT]
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

# Load quadgram scorer
try:
    ngram_scorer = NgramScorer.from_file(REPO_ROOT / "data" / "english_quadgrams.json")
    HAS_NGRAM = True
except Exception as e:
    print(f"Warning: quadgram scorer unavailable: {e}")
    ngram_scorer = None
    HAS_NGRAM = False


# ============================================================================
# H1: Berlin Clock reading order
# ============================================================================

def berlin_clock_reading_orders():
    """Generate reading orders based on Berlin Clock (Mengenlehreuhr) structure.

    The Berlin Clock has 5 rows:
    Row 0: 1 lamp (seconds, flashes)
    Row 1: 4 lamps (5-hour blocks)
    Row 2: 4 lamps (1-hour blocks)
    Row 3: 11 lamps (5-minute blocks)
    Row 4: 4 lamps (1-minute blocks)

    Total: 24 lamps. And 24 = number of known crib positions.

    We map 97 chars into a grid inspired by this structure and read
    in various orders.
    """
    # Clock structure: [1, 4, 4, 11, 4] = 24 total "slots"
    # Map 97 chars: fill rows proportionally
    # Row sizes for 97 chars: scale up by ~4x: [4, 16, 16, 45, 16] = 97
    row_sizes = [4, 16, 16, 45, 16]
    assert sum(row_sizes) == 97

    orders = []

    # Order 1: read rows top-to-bottom, left-to-right (normal)
    order = list(range(97))
    orders.append(("top_down_lr", order))

    # Order 2: read rows bottom-to-top, left-to-right
    offset = 0
    row_starts = []
    for size in row_sizes:
        row_starts.append(offset)
        offset += size
    order = []
    for size, start in reversed(list(zip(row_sizes, row_starts))):
        order.extend(range(start, start + size))
    orders.append(("bottom_up_lr", order))

    # Order 3: alternating direction (serpentine)
    order = []
    for i, (size, start) in enumerate(zip(row_sizes, row_starts)):
        if i % 2 == 0:
            order.extend(range(start, start + size))
        else:
            order.extend(range(start + size - 1, start - 1, -1))
    orders.append(("serpentine", order))

    # Order 4: read by "time significance" - minutes first, hours last
    # Row 4 (1-min), Row 3 (5-min), Row 2 (1-hr), Row 1 (5-hr), Row 0 (sec)
    order = []
    for idx in [4, 3, 2, 1, 0]:
        start = row_starts[idx]
        order.extend(range(start, start + row_sizes[idx]))
    orders.append(("time_significance", order))

    # Order 5: column-first reading on the clock grid
    # Read down columns: pos 0 from each row, then pos 1 from each row, etc.
    max_cols = max(row_sizes)
    order = []
    for col in range(max_cols):
        for row_idx, (size, start) in enumerate(zip(row_sizes, row_starts)):
            if col < size:
                order.append(start + col)
    orders.append(("column_first", order))

    return orders


def test_h1_berlin_clock():
    """Test Berlin Clock-inspired reading orders."""
    print("\n" + "=" * 70)
    print("H1: Berlin Clock reading order")
    print("=" * 70)

    orders = berlin_clock_reading_orders()
    results = []
    best_score = 0

    for name, order in orders:
        if len(order) != CT_LEN or sorted(order) != list(range(CT_LEN)):
            print(f"  {name}: invalid permutation (len={len(order)}), skipping")
            continue

        # Apply permutation: read CT in the given order
        reordered = "".join(CT[i] for i in order)

        # Check cribs against reordered text
        score = sum(1 for pos, ch in CRIB_DICT.items()
                    if pos < len(reordered) and reordered[pos] == ch)

        # Also check: cribs in the INVERTED permutation
        # (maybe the order was used to WRITE, not to READ)
        inv = [0] * CT_LEN
        for i, o in enumerate(order):
            inv[o] = i
        inv_reordered = "".join(CT[inv[i]] for i in range(CT_LEN))
        inv_score = sum(1 for pos, ch in CRIB_DICT.items()
                        if pos < len(inv_reordered) and inv_reordered[pos] == ch)

        use_score = max(score, inv_score)
        direction = "forward" if score >= inv_score else "inverse"

        if use_score > best_score:
            best_score = use_score

        # Also try each reading order as transposition before Vigenere
        # Apply inverse permutation to CT, then try simple Caesar shifts
        for shift in range(26):
            pt = "".join(ALPH[(ALPH_IDX[c] - shift) % MOD] for c in inv_reordered)
            shift_score = sum(1 for pos, ch in CRIB_DICT.items()
                              if pos < len(pt) and pt[pos] == ch)
            if shift_score > use_score:
                use_score = shift_score
                direction = f"inv+caesar{shift}"

        if use_score > best_score:
            best_score = use_score

        results.append({
            "name": name,
            "score": use_score,
            "direction": direction,
        })
        print(f"  {name}: score={use_score}/24 ({direction})")

    print(f"\nBest: {best_score}/24")
    return {"best_score": best_score, "results": results}


# ============================================================================
# H2: Coordinate-pair extraction
# ============================================================================

def test_h2_coordinates():
    """Test K2 coordinates as key material for K4.

    Coordinates: 38 57 6.5 N  77 8 44 W
    Numbers: 38, 57, 6, 5, 77, 8, 44
    Also test: 3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4 (individual digits)
    """
    print("\n" + "=" * 70)
    print("H2: K2 coordinate-derived keys")
    print("=" * 70)

    # Various numeric sequences from the coordinates
    coord_sequences = {
        "numbers": [38, 57, 6, 5, 77, 8, 44],
        "digits": [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4],
        "mod26_numbers": [38 % 26, 57 % 26, 6, 5, 77 % 26, 8, 44 % 26],
        "lat_lon_digits": [3, 8, 5, 7, 0, 6, 5, 7, 7, 0, 8, 4, 4],
        "degrees_only": [38, 57, 77, 8],
        "reversed_digits": [4, 4, 8, 7, 7, 5, 6, 7, 5, 8, 3],
    }

    # Also try date-derived sequences
    date_sequences = {
        "berlin_wall_date": [1, 1, 0, 9, 1, 9, 8, 9],  # 11/09/1989
        "egypt_1986": [1, 9, 8, 6],
        "cia_founding": [1, 9, 4, 7],
        "kryptos_year": [1, 9, 9, 0],
        "combined_dates": [1, 9, 8, 6, 1, 9, 8, 9],
    }

    all_sequences = {**coord_sequences, **date_sequences}

    results = []
    best_score = 0

    for seq_name, seq in all_sequences.items():
        seq_len = len(seq)
        if seq_len == 0:
            continue

        # Test as periodic Vigenere key (mod 26)
        key = [v % 26 for v in seq]

        for variant_name, decrypt in [
            ("vig", lambda c, k: (c - k) % MOD),
            ("beau", lambda c, k: (k - c) % MOD),
            ("vb", lambda c, k: (c + k) % MOD),
        ]:
            pt = "".join(ALPH[decrypt(CT_NUMS[i], key[i % seq_len])]
                         for i in range(CT_LEN))
            score = sum(1 for pos, ch in CRIB_DICT.items()
                        if pos < len(pt) and pt[pos] == ch)

            if score > best_score:
                best_score = score

            if score >= 4:
                results.append({
                    "sequence": seq_name,
                    "variant": variant_name,
                    "key": key[:10],
                    "score": score,
                    "pt_preview": pt[:30],
                })

        # Test as position extractor: read CT at positions given by cumulative sum
        cumsum = []
        total = 0
        for v in seq:
            total += v
            if total < CT_LEN:
                cumsum.append(total)

        extracted = "".join(CT[p] for p in cumsum if p < CT_LEN)
        if len(extracted) >= 5:
            # Check if extracted chars match any crib fragment
            for crib_start, crib_word in [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]:
                for offset in range(len(extracted) - 3):
                    match_len = 0
                    for j in range(min(len(crib_word), len(extracted) - offset)):
                        if extracted[offset + j] == crib_word[j]:
                            match_len += 1
                    if match_len >= 3:
                        results.append({
                            "sequence": seq_name,
                            "method": "position_extract",
                            "extracted": extracted,
                            "match": f"{match_len} chars of {crib_word}",
                        })

    print(f"Configs tested: {len(all_sequences) * 3}")
    print(f"Best crib score: {best_score}/24")
    print(f"Results with score >= 4: {len([r for r in results if r.get('score', 0) >= 4])}")

    if results:
        for r in sorted(results, key=lambda x: -x.get("score", 0))[:5]:
            if "score" in r:
                print(f"  {r['sequence']}+{r['variant']}: {r['score']}/24 PT={r.get('pt_preview', '')}")

    return {"best_score": best_score, "results": results}


# ============================================================================
# H3: Stencil cipher with irregular holes
# ============================================================================

def test_h3_stencil():
    """Test stencil/grille cipher hypotheses.

    A stencil has holes at specific positions. Place it over CT,
    read the visible letters. Rotate/shift the stencil, read again.
    After N placements, you have the full plaintext.

    Key insight: if the stencil has ~24 holes (matching 24 cribs),
    one placement might reveal all crib positions.

    We test stencils derived from:
    - K1-K3 structure (positions of specific letters)
    - Misspelling positions
    - Berlin Clock structure (24 lamps)
    """
    print("\n" + "=" * 70)
    print("H3: Stencil cipher hypotheses")
    print("=" * 70)

    results = []
    best_overlap = 0

    # Stencil 1: positions derived from the KRYPTOS keyword
    # K=10, R=17, Y=24, P=15, T=19, O=14, S=18
    kryptos_positions = [ALPH_IDX[c] for c in "KRYPTOS"]
    # Extend: multiply by factors to cover more of CT
    for factor in range(1, 15):
        positions = sorted(set((p * factor) % CT_LEN for p in kryptos_positions))
        overlap = sum(1 for p in positions if p in CRIB_DICT)
        if overlap > best_overlap:
            best_overlap = overlap
            results.append({
                "stencil": f"KRYPTOS_factor{factor}",
                "positions": positions[:20],
                "n_holes": len(positions),
                "crib_overlap": overlap,
            })

    # Stencil 2: positions from misspelling letters CQUAE
    # C=2, Q=16, U=20, A=0, E=4
    missp = [ALPH_IDX[c] for c in "CQUAE"]
    for stride in range(1, 20):
        positions = sorted(set((m + stride * i) % CT_LEN
                               for m in missp
                               for i in range(CT_LEN // stride + 1)
                               if (m + stride * i) < CT_LEN))
        overlap = sum(1 for p in positions if p in CRIB_DICT)
        if overlap > best_overlap:
            best_overlap = overlap
            results.append({
                "stencil": f"CQUAE_stride{stride}",
                "n_holes": len(positions),
                "crib_overlap": overlap,
            })

    # Stencil 3: 24-hole stencil at crib positions (trivially matches)
    # Instead test: can we find a RULE that generates exactly the crib positions?
    crib_pos_sorted = sorted(CRIB_DICT.keys())
    print(f"\n  Crib positions: {crib_pos_sorted}")

    # Check if crib positions follow any arithmetic pattern
    diffs = [crib_pos_sorted[i+1] - crib_pos_sorted[i]
             for i in range(len(crib_pos_sorted)-1)]
    print(f"  Crib position differences: {diffs}")
    diff_counter = Counter(diffs)
    print(f"  Most common diff: {diff_counter.most_common(3)}")

    # The cribs are at 21-33 (diff=1) and 63-73 (diff=1) with a gap of 30
    # So the "stencil" is two contiguous blocks separated by 30 positions

    # Stencil 4: try reading CT at positions that skip crib regions
    # (complementary stencil - the NON-crib positions)
    non_crib = [i for i in range(CT_LEN) if i not in CRIB_DICT]
    non_crib_text = "".join(CT[i] for i in non_crib)
    print(f"\n  Non-crib CT ({len(non_crib)} chars): {non_crib_text[:30]}...")
    ic_non_crib = ic(non_crib_text)
    print(f"  IC of non-crib region: {ic_non_crib:.4f}")

    # Check if non-crib region has different statistical properties
    crib_text = "".join(CT[i] for i in crib_pos_sorted)
    ic_crib = ic(crib_text)
    print(f"  IC of crib region: {ic_crib:.4f}")

    print(f"\nBest crib overlap from generated stencils: {best_overlap}/24")

    return {"best_overlap": best_overlap, "results": results[:10]}


# ============================================================================
# H4: Progressive layered unmasking
# ============================================================================

def test_h4_layered_unmasking():
    """Test Sanborn's "pull up one layer, pull up another layer."

    Layer 1: Apply a simple known transformation to get intermediate text
    Layer 2: Apply a second transformation to get plaintext

    We test combinations of:
    - Layer 1: Caesar (shift 0-25), reverse, KRYPTOS alphabet remap
    - Layer 2: Vigenere with short keyword, Beaufort, KRYPTOS-keyed

    The key insight: "designed to unveil itself" suggests each layer
    reveals something that helps decode the next layer.
    """
    print("\n" + "=" * 70)
    print("H4: Progressive layered unmasking")
    print("=" * 70)

    results = []
    best_score = 0
    configs_tested = 0

    # Layer 1 options
    layer1_transforms = {}

    # Caesar shifts
    for shift in range(26):
        layer1_transforms[f"caesar_{shift}"] = "".join(
            ALPH[(CT_NUMS[i] + shift) % MOD] for i in range(CT_LEN))

    # KRYPTOS alphabet remap: CT through KRYPTOS ordering
    layer1_transforms["ka_to_std"] = "".join(
        ALPH[KA_IDX[c]] for c in CT)

    # Standard to KRYPTOS remap
    layer1_transforms["std_to_ka"] = "".join(
        KRYPTOS_ALPHABET[ALPH_IDX[c]] for c in CT)

    # Reverse
    layer1_transforms["reverse"] = CT[::-1]

    # Atbash (A<->Z, B<->Y, etc.)
    layer1_transforms["atbash"] = "".join(
        ALPH[25 - CT_NUMS[i]] for i in range(CT_LEN))

    # Layer 2: Vigenere/Beaufort with short keywords
    keywords_l2 = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
        "LAYER", "EQUAL", "SHADOW", "LIGHT", "CIA",
        "SCHEIDT", "SANBORN", "EAST", "NORTH",
    ]

    for l1_name, intermediate in layer1_transforms.items():
        inter_nums = [ALPH_IDX[c] for c in intermediate]

        for keyword in keywords_l2:
            kw_nums = [ALPH_IDX[c] for c in keyword]
            kw_len = len(kw_nums)

            for variant_name, decrypt in [
                ("vig", lambda c, k: (c - k) % MOD),
                ("beau", lambda c, k: (k - c) % MOD),
            ]:
                pt = "".join(
                    ALPH[decrypt(inter_nums[i], kw_nums[i % kw_len])]
                    for i in range(CT_LEN))

                score = sum(1 for pos, ch in CRIB_DICT.items()
                            if pos < len(pt) and pt[pos] == ch)
                configs_tested += 1

                if score > best_score:
                    best_score = score

                if score >= 6:
                    results.append({
                        "layer1": l1_name,
                        "layer2": f"{variant_name}_{keyword}",
                        "score": score,
                        "pt_preview": pt[:30],
                    })

    print(f"Configs tested: {configs_tested}")
    print(f"Best crib score: {best_score}/24")

    if results:
        print(f"\nResults with score >= 6:")
        for r in sorted(results, key=lambda x: -x["score"])[:10]:
            print(f"  {r['layer1']} + {r['layer2']}: {r['score']}/24")
            print(f"    PT: {r['pt_preview']}...")

    return {"best_score": best_score, "configs_tested": configs_tested, "results": results}


# ============================================================================
# H5: Misspelling-derived transformation
# ============================================================================

def test_h5_misspellings():
    """Test if the misspelling pattern encodes cipher parameters.

    Known misspellings:
    - PALIMPSEST -> PALIMPCEST (S->C at position 7 of keyword)
    - ILLUSION -> IQLUSION (L->Q at position 2)
    - UNDERGROUND -> UNDERGRUUND (O->U at position 10)
    - DESPERATELY -> DESPARATLY (E->A at position 5; E dropped at 8)
    - DIGITAL -> DIGETAL (I->E at position 4)

    Wrong letters: C, Q, U, A, E
    Correct letters replaced: S, L, O, E, I
    Alphabetic positions of wrong: C=2, Q=16, U=20, A=0, E=4
    Alphabetic positions of correct: S=18, L=11, O=14, E=4, I=8
    Word positions: 7, 2, 10, 5, 4

    Tests:
    1. Use wrong-letter positions [2,16,20,0,4] as Vigenere key
    2. Use correct-letter positions [18,11,14,4,8] as Vigenere key
    3. Use word-internal positions [7,2,10,5,4] as Vigenere key
    4. Use differences (wrong - correct) as key: [-16,5,6,-4,-4] mod 26
    5. Use the EQUAL anagram as a keyword
    """
    print("\n" + "=" * 70)
    print("H5: Misspelling-derived transformations")
    print("=" * 70)

    # Derived key sequences
    key_sequences = {
        "wrong_positions": [2, 16, 20, 0, 4],           # C, Q, U, A, E
        "correct_positions": [18, 11, 14, 4, 8],         # S, L, O, E, I
        "word_positions": [7, 2, 10, 5, 4],              # where in each word
        "differences": [10, 5, 6, 22, 22],               # (wrong-correct) mod 26
        "reverse_diff": [16, 21, 20, 4, 4],              # (correct-wrong) mod 26
        "equal_kw": [4, 16, 20, 0, 11],                  # E, Q, U, A, L
    }

    # Additional: concatenated sequences
    key_sequences["wrong_then_correct"] = [2, 16, 20, 0, 4, 18, 11, 14, 4, 8]
    key_sequences["all_combined"] = [7, 2, 10, 5, 4, 2, 16, 20, 0, 4]

    results = []
    best_score = 0

    for seq_name, key in key_sequences.items():
        key_len = len(key)

        for variant_name, decrypt in [
            ("vig", lambda c, k: (c - k) % MOD),
            ("beau", lambda c, k: (k - c) % MOD),
            ("vb", lambda c, k: (c + k) % MOD),
        ]:
            pt = "".join(ALPH[decrypt(CT_NUMS[i], key[i % key_len])]
                         for i in range(CT_LEN))
            score = sum(1 for pos, ch in CRIB_DICT.items()
                        if pos < len(pt) and pt[pos] == ch)

            if score > best_score:
                best_score = score

            if score >= 4:
                results.append({
                    "key": seq_name,
                    "variant": variant_name,
                    "score": score,
                    "pt_preview": pt[:30],
                })

            # Also try with KRYPTOS alphabet
            pt_ka = "".join(
                KRYPTOS_ALPHABET[decrypt(KA_IDX[CT[i]], key[i % key_len])]
                for i in range(CT_LEN))
            score_ka = sum(1 for pos, ch in CRIB_DICT.items()
                           if pos < len(pt_ka) and pt_ka[pos] == ch)

            if score_ka > best_score:
                best_score = score_ka

            if score_ka >= 4:
                results.append({
                    "key": seq_name + "_ka",
                    "variant": variant_name,
                    "score": score_ka,
                    "pt_preview": pt_ka[:30],
                })

    print(f"Best crib score: {best_score}/24")
    print(f"Results with score >= 4: {len([r for r in results if r.get('score', 0) >= 4])}")

    if results:
        for r in sorted(results, key=lambda x: -x.get("score", 0))[:5]:
            print(f"  {r['key']}+{r['variant']}: {r['score']}/24 PT={r['pt_preview']}")

    return {"best_score": best_score, "results": results}


# ============================================================================
# BONUS: Crib-derived complete key analysis
# ============================================================================

def test_bonus_crib_key_extension():
    """Attempt to extend the known keystream to unconstrained positions.

    We have 24 key values (Vigenere convention). Can we find a function
    f(pos) -> key_value that fits all 24 and predicts the remaining 73?

    Test polynomial fits, lookup table patterns, and modular functions.
    """
    print("\n" + "=" * 70)
    print("BONUS: Key extension analysis")
    print("=" * 70)

    # Known key values (Vigenere)
    known_key = {}
    for i, pos in enumerate(range(21, 34)):
        known_key[pos] = list(VIGENERE_KEY_ENE)[i]
    for i, pos in enumerate(range(63, 74)):
        known_key[pos] = list(VIGENERE_KEY_BC)[i]

    positions = sorted(known_key.keys())
    key_values = [known_key[p] for p in positions]

    print(f"Known key at {len(positions)} positions")

    # Test: polynomial f(pos) mod 26 of degree d
    best_poly_score = 0
    for degree in range(1, 8):
        # Try to fit polynomial to known points using brute force for small degrees
        # For degree 1: k = (a*pos + b) mod 26
        if degree == 1:
            for a in range(26):
                for b in range(26):
                    matches = sum(1 for pos, k in known_key.items()
                                  if (a * pos + b) % 26 == k)
                    if matches > best_poly_score:
                        best_poly_score = matches
                        if matches >= 5:
                            print(f"  deg1: k=({a}*pos+{b}) mod 26: {matches}/24 matches")

        elif degree == 2:
            for a in range(26):
                for b in range(26):
                    for c_coeff in range(26):
                        matches = sum(1 for pos, k in known_key.items()
                                      if (a * pos * pos + b * pos + c_coeff) % 26 == k)
                        if matches >= 6:
                            print(f"  deg2: k=({a}*pos^2+{b}*pos+{c_coeff}) mod 26: {matches}/24")
                            if matches > best_poly_score:
                                best_poly_score = matches

    print(f"\nBest polynomial fit: {best_poly_score}/24 matches")

    # Test: key as lookup in KRYPTOS alphabet
    for start in range(26):
        ka_key = [(ALPH_IDX[KRYPTOS_ALPHABET[(start + i) % 26]])
                  for i in range(CT_LEN)]
        matches = sum(1 for pos, k in known_key.items() if ka_key[pos] == k)
        if matches >= 4:
            print(f"  KA starting at {start} ({KRYPTOS_ALPHABET[start]}): {matches}/24 matches")

    return {"best_poly_score": best_poly_score}


# ============================================================================
# Main
# ============================================================================

def main():
    print("E-EXPLORER-06: Physical/Procedural Cipher Hypotheses")
    print(f"CT: {CT[:20]}...{CT[-10:]}")
    print(f"CT length: {CT_LEN}")
    print(f"Cribs: {N_CRIBS} positions")

    t0 = time.time()
    all_results = {}

    h1 = test_h1_berlin_clock()
    all_results["h1_berlin_clock"] = h1

    h2 = test_h2_coordinates()
    all_results["h2_coordinates"] = h2

    h3 = test_h3_stencil()
    all_results["h3_stencil"] = h3

    h4 = test_h4_layered_unmasking()
    all_results["h4_layered"] = h4

    h5 = test_h5_misspellings()
    all_results["h5_misspellings"] = h5

    bonus = test_bonus_crib_key_extension()
    all_results["bonus_key_extension"] = bonus

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total time: {elapsed:.1f}s")
    print(f"H1 (Berlin Clock orders):     best={h1['best_score']}/24")
    print(f"H2 (Coordinate-derived keys): best={h2['best_score']}/24")
    print(f"H3 (Stencil cipher):          best_overlap={h3['best_overlap']}/24")
    print(f"H4 (Layered unmasking):       best={h4['best_score']}/24")
    print(f"H5 (Misspelling-derived):     best={h5['best_score']}/24")

    print("\n--- INTERPRETATION ---")
    for label, score in [
        ("H1", h1['best_score']),
        ("H2", h2['best_score']),
        ("H4", h4['best_score']),
        ("H5", h5['best_score']),
    ]:
        if score >= 18:
            print(f"{label}: SIGNAL ({score}/24)")
        elif score >= 10:
            print(f"{label}: INTERESTING ({score}/24)")
        elif score >= 7:
            print(f"{label}: MARGINAL ({score}/24)")
        else:
            print(f"{label}: NOISE ({score}/24)")

    out_path = ARTIFACTS_DIR / "explorer_06_results.json"
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
