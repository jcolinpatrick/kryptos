#!/usr/bin/env python3
"""Card-based cipher hypothesis tests against K4.

Tests H1-H6 as defined in the card cipher research plan.
Results written to results/card_cipher_tests/

Usage:
    PYTHONPATH=src python3 -u scripts/e_card_cipher_tests.py
"""
from __future__ import annotations

import json
import os
import itertools
import string
from collections import Counter
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from kryptos.kernel.scoring.aggregate import score_candidate, ScoreBreakdown
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.constraints.bean import verify_bean, BeanResult

OUTDIR = "results/card_cipher_tests"
os.makedirs(OUTDIR, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════
# Card constants and utilities
# ═══════════════════════════════════════════════════════════════════════

SUITS = ["Spades", "Hearts", "Diamonds", "Clubs"]
RANKS = ["A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"]
RANK_VALUES = {"A": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7,
               "8": 8, "9": 9, "10": 10, "J": 11, "Q": 12, "K": 13}

# Face card letters in the alphabet
FACE_CARD_LETTERS = set("KQJA")  # King, Queen, Jack, Ace


def new_deck_order() -> List[Tuple[str, str]]:
    """Standard new deck order: A-K of Spades, A-K of Hearts, K-A of Diamonds, K-A of Clubs."""
    deck = []
    for suit in ["Spades", "Hearts"]:
        for rank in RANKS:
            deck.append((rank, suit))
    for suit in ["Diamonds", "Clubs"]:
        for rank in reversed(RANKS):
            deck.append((rank, suit))
    return deck


def sorted_deck_order() -> List[Tuple[str, str]]:
    """Sorted deck: all suits in order A-K."""
    return [(r, s) for s in SUITS for r in RANKS]


def card_value(rank: str, suit: str) -> int:
    """Numeric value of a card (1-52)."""
    suit_idx = SUITS.index(suit)
    return suit_idx * 13 + RANK_VALUES[rank]


def deck_to_keystream_ranks(deck: List[Tuple[str, str]], length: int) -> List[int]:
    """Extract rank values (1-13) from deck, cycling if needed."""
    ranks = [RANK_VALUES[r] for r, s in deck]
    return [ranks[i % len(ranks)] for i in range(length)]


def deck_to_keystream_values(deck: List[Tuple[str, str]], length: int) -> List[int]:
    """Extract card values (1-52) from deck, cycling if needed."""
    vals = [card_value(r, s) for r, s in deck]
    return [vals[i % len(vals)] for i in range(length)]


def decrypt_vigenere(ct: str, keystream: List[int]) -> str:
    """Decrypt: PT[i] = (CT[i] - key[i]) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        pt_val = (ALPH_IDX[c] - keystream[i]) % MOD
        pt.append(ALPH[pt_val])
    return "".join(pt)


def decrypt_beaufort(ct: str, keystream: List[int]) -> str:
    """Decrypt: PT[i] = (key[i] - CT[i]) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        pt_val = (keystream[i] - ALPH_IDX[c]) % MOD
        pt.append(ALPH[pt_val])
    return "".join(pt)


def decrypt_addition(ct: str, keystream: List[int]) -> str:
    """Decrypt: PT[i] = (CT[i] + key[i]) mod 26."""
    pt = []
    for i, c in enumerate(ct):
        pt_val = (ALPH_IDX[c] + keystream[i]) % MOD
        pt.append(ALPH[pt_val])
    return "".join(pt)


def evaluate_plaintext(pt: str, label: str) -> Dict:
    """Score a candidate plaintext and return a result dict."""
    sc = score_candidate(pt)
    return {
        "label": label,
        "plaintext": pt,
        "crib_score": sc.crib_score,
        "ene_score": sc.ene_score,
        "bc_score": sc.bc_score,
        "ic_value": sc.ic_value,
        "classification": sc.crib_classification,
        "summary": sc.summary,
    }


best_results = []  # Track best across all hypotheses


def track_best(result: Dict):
    """Track result if above noise."""
    best_results.append(result)


# ═══════════════════════════════════════════════════════════════════════
# H1: CARD-VALUE SUBTRACTION
# ═══════════════════════════════════════════════════════════════════════

def test_h1():
    """Test card-value subtraction with various mappings and deck orders."""
    print("=" * 70)
    print("H1: CARD-VALUE SUBTRACTION")
    print("=" * 70)

    results = []
    decks = {
        "new_deck": new_deck_order(),
        "sorted_deck": sorted_deck_order(),
    }

    # Also test reversed deck orders
    decks["new_deck_reversed"] = list(reversed(new_deck_order()))
    decks["sorted_deck_reversed"] = list(reversed(sorted_deck_order()))

    for deck_name, deck in decks.items():
        # Keystream from rank values (1-13), mod 26
        ks_rank = deck_to_keystream_ranks(deck, CT_LEN)

        # Keystream from card values (1-52), mod 26
        ks_card = deck_to_keystream_values(deck, CT_LEN)

        for ks_name, ks in [("rank_mod26", ks_rank), ("cardval_mod26", ks_card)]:
            ks_mod = [k % MOD for k in ks]

            for dec_name, dec_fn in [("vig_sub", decrypt_vigenere),
                                      ("beaufort", decrypt_beaufort),
                                      ("addition", decrypt_addition)]:
                label = f"H1_{deck_name}_{ks_name}_{dec_name}"
                pt = dec_fn(CT, ks_mod)
                result = evaluate_plaintext(pt, label)
                results.append(result)

                if result["crib_score"] > 2:
                    print(f"  [!] {label}: crib={result['crib_score']}/24, IC={result['ic_value']:.4f}")
                    track_best(result)

    # Also test with KA-alphabet indexing instead of standard
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    for deck_name, deck in list(decks.items())[:2]:  # Just new and sorted
        ks_rank = deck_to_keystream_ranks(deck, CT_LEN)
        ks_mod = [k % MOD for k in ks_rank]

        # Decrypt using KA ordering for CT
        pt_chars = []
        for i, c in enumerate(CT):
            pt_val = (ka_idx[c] - ks_mod[i]) % MOD
            pt_chars.append(KRYPTOS_ALPHABET[pt_val])
        pt = "".join(pt_chars)
        label = f"H1_{deck_name}_rank_KA_sub"
        result = evaluate_plaintext(pt, label)
        results.append(result)
        if result["crib_score"] > 2:
            print(f"  [!] {label}: crib={result['crib_score']}/24")
            track_best(result)

    # Test two-card keystream: pair of cards combined to make one key letter
    for deck_name, deck in list(decks.items())[:2]:
        vals = [RANK_VALUES[r] for r, s in deck]
        # Method 1: card1 + card2 mod 26
        ks_pairs_add = [(vals[2*i % len(vals)] + vals[(2*i+1) % len(vals)]) % MOD
                        for i in range(CT_LEN)]
        # Method 2: card1 * 2 + card2 mod 26
        ks_pairs_mul = [(vals[2*i % len(vals)] * 2 + vals[(2*i+1) % len(vals)]) % MOD
                        for i in range(CT_LEN)]

        for ks_name, ks in [("pair_add", ks_pairs_add), ("pair_mul", ks_pairs_mul)]:
            for dec_name, dec_fn in [("vig_sub", decrypt_vigenere), ("beaufort", decrypt_beaufort)]:
                label = f"H1_{deck_name}_{ks_name}_{dec_name}"
                pt = dec_fn(CT, ks)
                result = evaluate_plaintext(pt, label)
                results.append(result)
                if result["crib_score"] > 2:
                    print(f"  [!] {label}: crib={result['crib_score']}/24")
                    track_best(result)

    max_crib = max(r["crib_score"] for r in results)
    avg_crib = sum(r["crib_score"] for r in results) / len(results)
    print(f"\n  H1 Summary: {len(results)} configs tested")
    print(f"  Max crib score: {max_crib}/24, Avg: {avg_crib:.1f}/24")
    print(f"  Expected random: ~0.9/24")

    return results


# ═══════════════════════════════════════════════════════════════════════
# H2: SUIT-BASED SUBSTITUTION
# ═══════════════════════════════════════════════════════════════════════

def test_h2():
    """Test suit-based substitution ciphers."""
    print("\n" + "=" * 70)
    print("H2: SUIT-BASED SUBSTITUTION")
    print("=" * 70)

    results = []

    # Split alphabet into 2 groups of 13 (like two suits)
    # Each group maps to the other
    half1 = ALPH[:13]  # A-M
    half2 = ALPH[13:]  # N-Z

    # Simple swap: A<->N, B<->O, ..., M<->Z
    sub_table = {}
    for i in range(13):
        sub_table[half1[i]] = half2[i]
        sub_table[half2[i]] = half1[i]

    pt = "".join(sub_table[c] for c in CT)
    result = evaluate_plaintext(pt, "H2_half_swap_AZ")
    results.append(result)

    # Same but with KA alphabet
    ka_half1 = KRYPTOS_ALPHABET[:13]  # KRYPTOSABCDEF
    ka_half2 = KRYPTOS_ALPHABET[13:]  # GHIJLMNQUVWXZ
    sub_ka = {}
    for i in range(13):
        sub_ka[ka_half1[i]] = ka_half2[i]
        sub_ka[ka_half2[i]] = ka_half1[i]

    pt = "".join(sub_ka[c] for c in CT)
    result = evaluate_plaintext(pt, "H2_half_swap_KA")
    results.append(result)

    # Card-rank grouping: map letters by card rank
    # A=1, B=2, ..., M=13, then N=1, O=2, ..., Z=13
    # Letters sharing same rank swap
    for i in range(13):
        letter1 = ALPH[i]       # A-M
        letter2 = ALPH[i + 13]  # N-Z
        sub_table[letter1] = letter2
        sub_table[letter2] = letter1

    # 4 groups of 6-7 (like 4 suits of ~6.5 letters each)
    groups = [ALPH[i:i+7] if i < 5 else ALPH[i:i+7] for i in range(0, 26, 7)]
    # Actually, split 26 into 4 groups: 7,7,6,6
    g1 = ALPH[0:7]    # ABCDEFG
    g2 = ALPH[7:14]   # HIJKLMN
    g3 = ALPH[14:20]  # OPQRST
    g4 = ALPH[20:26]  # UVWXYZ

    # Substitution: each group rotates by 13 within group pair
    # g1 <-> g3 partially, g2 <-> g4 partially
    # This is more exploratory
    for shift in range(1, 26):
        pt = "".join(ALPH[(ALPH_IDX[c] + shift) % MOD] for c in CT)
        result = evaluate_plaintext(pt, f"H2_caesar_{shift}")
        results.append(result)
        if result["crib_score"] > 2:
            print(f"  [!] H2_caesar_{shift}: crib={result['crib_score']}/24")
            track_best(result)

    # Atbash (reverse alphabet)
    pt = "".join(ALPH[25 - ALPH_IDX[c]] for c in CT)
    result = evaluate_plaintext(pt, "H2_atbash_AZ")
    results.append(result)

    # Atbash with KA alphabet
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    pt = "".join(KRYPTOS_ALPHABET[25 - ka_idx[c]] for c in CT)
    result = evaluate_plaintext(pt, "H2_atbash_KA")
    results.append(result)

    max_crib = max(r["crib_score"] for r in results)
    avg_crib = sum(r["crib_score"] for r in results) / len(results)
    print(f"\n  H2 Summary: {len(results)} configs tested")
    print(f"  Max crib score: {max_crib}/24, Avg: {avg_crib:.1f}/24")

    return results


# ═══════════════════════════════════════════════════════════════════════
# H3: DECK-SHUFFLE TRANSPOSITION
# ═══════════════════════════════════════════════════════════════════════

def test_h3():
    """Test deck-shuffle transposition hypotheses."""
    print("\n" + "=" * 70)
    print("H3: DECK-SHUFFLE TRANSPOSITION")
    print("=" * 70)

    results = []

    decks = {
        "new_deck": new_deck_order(),
        "sorted_deck": sorted_deck_order(),
        "new_deck_reversed": list(reversed(new_deck_order())),
    }

    for deck_name, deck in decks.items():
        # Card values as permutation indices
        perm_vals = [card_value(r, s) - 1 for r, s in deck]  # 0-indexed (0-51)

        # Method A: Apply first 52 cards to first 52 positions,
        # then cards 1-45 to remaining positions
        perm_full = perm_vals[:] + perm_vals[:45]  # 97 positions
        # Clamp to valid range and treat mod 97
        perm_mod97 = [v % CT_LEN for v in perm_full[:CT_LEN]]

        # Check if this produces a valid permutation (bijective)
        if len(set(perm_mod97)) == CT_LEN:
            pt = "".join(CT[perm_mod97[i]] for i in range(CT_LEN))
            result = evaluate_plaintext(pt, f"H3_{deck_name}_mod97_gather")
            results.append(result)
            if result["crib_score"] > 2:
                print(f"  [!] {result['label']}: crib={result['crib_score']}/24")
                track_best(result)

            # Also try scatter (inverse)
            inv_perm = [0] * CT_LEN
            for i, p in enumerate(perm_mod97):
                inv_perm[p] = i
            pt = "".join(CT[inv_perm[i]] for i in range(CT_LEN))
            result = evaluate_plaintext(pt, f"H3_{deck_name}_mod97_scatter")
            results.append(result)
            if result["crib_score"] > 2:
                print(f"  [!] {result['label']}: crib={result['crib_score']}/24")
                track_best(result)
        else:
            print(f"  {deck_name}_mod97: not a valid permutation (collisions)")

        # Method B: Read off positions in card-value order
        # (sort CT by card position to get PT)
        # First 52 positions, sorted by card order
        indices_by_card = sorted(range(52), key=lambda i: perm_vals[i])
        # Then remaining 45 positions in order
        full_indices = indices_by_card + list(range(52, CT_LEN))
        pt = "".join(CT[full_indices[i]] for i in range(CT_LEN))
        result = evaluate_plaintext(pt, f"H3_{deck_name}_sortcard_52")
        results.append(result)
        if result["crib_score"] > 2:
            print(f"  [!] {result['label']}: crib={result['crib_score']}/24")
            track_best(result)

        # Method C: Use rank values (1-13) as columnar transposition key
        rank_key = [RANK_VALUES[r] for r, s in deck]
        # Use first N cards as the column key for width N transposition
        for width in [7, 8, 9, 10, 13]:
            key = rank_key[:width]
            # Columnar transposition: read off by column order
            n_rows = (CT_LEN + width - 1) // width

            # Create the grid (read in by rows)
            grid = []
            idx = 0
            for row in range(n_rows):
                row_data = []
                for col in range(width):
                    if idx < CT_LEN:
                        row_data.append(CT[idx])
                        idx += 1
                    else:
                        row_data.append("")
                grid.append(row_data)

            # Read off columns in key order
            col_order = sorted(range(width), key=lambda c: key[c])
            pt_chars = []
            for col in col_order:
                for row in range(n_rows):
                    if grid[row][col]:
                        pt_chars.append(grid[row][col])

            pt = "".join(pt_chars)
            if len(pt) == CT_LEN:
                result = evaluate_plaintext(pt, f"H3_{deck_name}_columnar_w{width}")
                results.append(result)
                if result["crib_score"] > 2:
                    print(f"  [!] {result['label']}: crib={result['crib_score']}/24")
                    track_best(result)

            # Also try reading in by columns, out by rows (inverse)
            # This is the decryption of the above
            grid2 = [[""] * width for _ in range(n_rows)]
            idx = 0
            for col in col_order:
                for row in range(n_rows):
                    if row * width + col < CT_LEN:
                        grid2[row][col] = CT[idx]
                        idx += 1

            pt_chars = []
            for row in range(n_rows):
                for col in range(width):
                    if grid2[row][col]:
                        pt_chars.append(grid2[row][col])

            pt = "".join(pt_chars)
            if len(pt) == CT_LEN:
                result = evaluate_plaintext(pt, f"H3_{deck_name}_inv_columnar_w{width}")
                results.append(result)
                if result["crib_score"] > 2:
                    print(f"  [!] {result['label']}: crib={result['crib_score']}/24")
                    track_best(result)

    max_crib = max(r["crib_score"] for r in results) if results else 0
    avg_crib = sum(r["crib_score"] for r in results) / len(results) if results else 0
    print(f"\n  H3 Summary: {len(results)} configs tested")
    print(f"  Max crib score: {max_crib}/24, Avg: {avg_crib:.1f}/24")

    return results


# ═══════════════════════════════════════════════════════════════════════
# H4: CARD RANK AS KEYSTREAM
# ═══════════════════════════════════════════════════════════════════════

def test_h4():
    """Test card rank as keystream values."""
    print("\n" + "=" * 70)
    print("H4: CARD RANK AS KEYSTREAM")
    print("=" * 70)

    results = []

    decks = {
        "new_deck": new_deck_order(),
        "sorted_deck": sorted_deck_order(),
        "new_deck_reversed": list(reversed(new_deck_order())),
        "sorted_deck_reversed": list(reversed(sorted_deck_order())),
    }

    for deck_name, deck in decks.items():
        # Keystream variants
        ranks = [RANK_VALUES[r] for r, s in deck]
        card_vals = [card_value(r, s) for r, s in deck]
        suit_vals = [SUITS.index(s) for r, s in deck]

        keystreams = {
            "rank_1_13": [r for r in ranks],
            "rank_0_12": [r - 1 for r in ranks],
            "cardval_1_52": card_vals,
            "suit_0_3": suit_vals,
            "rank_plus_suit": [ranks[i] + suit_vals[i] for i in range(52)],
            "rank_times_suit": [ranks[i] * (suit_vals[i] + 1) for i in range(52)],
        }

        for ks_name, ks_raw in keystreams.items():
            # Cycle keystream to cover 97 characters
            ks = [ks_raw[i % len(ks_raw)] % MOD for i in range(CT_LEN)]

            for dec_name, dec_fn in [("vig", decrypt_vigenere),
                                      ("beau", decrypt_beaufort),
                                      ("add", decrypt_addition)]:
                label = f"H4_{deck_name}_{ks_name}_{dec_name}"
                pt = dec_fn(CT, ks)
                result = evaluate_plaintext(pt, label)
                results.append(result)
                if result["crib_score"] > 2:
                    print(f"  [!] {label}: crib={result['crib_score']}/24")
                    track_best(result)

    # Special test: Solitaire/Pontifex keystream
    # Bruce Schneier's Solitaire cipher uses a deck to generate keystream
    # Test with standard deck order
    print("\n  Testing Solitaire (Pontifex) cipher...")
    solitaire_results = test_solitaire()
    results.extend(solitaire_results)

    max_crib = max(r["crib_score"] for r in results) if results else 0
    avg_crib = sum(r["crib_score"] for r in results) / len(results) if results else 0
    print(f"\n  H4 Summary: {len(results)} configs tested")
    print(f"  Max crib score: {max_crib}/24, Avg: {avg_crib:.1f}/24")

    return results


def solitaire_keystream(deck: List[int], length: int) -> List[int]:
    """Generate Solitaire/Pontifex keystream.

    Deck is 54 cards: 1-52 = cards, 53,54 = jokers A,B.
    """
    d = deck[:]
    ks = []

    while len(ks) < length:
        # Step 1: Move joker A (53) down one
        pos_a = d.index(53)
        if pos_a == len(d) - 1:
            d.insert(1, d.pop(pos_a))
        else:
            d[pos_a], d[pos_a + 1] = d[pos_a + 1], d[pos_a]

        # Step 2: Move joker B (54) down two
        pos_b = d.index(54)
        if pos_b == len(d) - 1:
            d.insert(2, d.pop(pos_b))
        elif pos_b == len(d) - 2:
            d.insert(1, d.pop(pos_b))
        else:
            d[pos_b], d[pos_b + 1] = d[pos_b + 1], d[pos_b]
            d[pos_b + 1], d[pos_b + 2] = d[pos_b + 2], d[pos_b + 1]

        # Step 3: Triple cut
        pos_a = d.index(53)
        pos_b = d.index(54)
        top = min(pos_a, pos_b)
        bot = max(pos_a, pos_b)
        d = d[bot + 1:] + d[top:bot + 1] + d[:top]

        # Step 4: Count cut
        bottom_card = d[-1]
        cut_val = min(bottom_card, 53)  # Jokers count as 53
        d = d[cut_val:-1] + d[:cut_val] + [d[-1]]

        # Step 5: Output card
        top_card = d[0]
        look = min(top_card, 53)
        output = d[look]
        if output <= 52:
            ks.append(output)

    return ks


def test_solitaire() -> List[Dict]:
    """Test Solitaire/Pontifex cipher with various deck orderings."""
    results = []

    # Standard deck: 1-52, then joker A (53), joker B (54)
    std_deck = list(range(1, 55))

    # Also test reversed
    rev_deck = list(range(52, 0, -1)) + [53, 54]

    # KRYPTOS-ordered deck: map KA alphabet positions to card values
    # K=1, R=2, Y=3, P=4, T=5, O=6, S=7, A=8, B=9, C=10, D=11, E=12, F=13
    # G=14, H=15, I=16, J=17, L=18, M=19, N=20, Q=21, U=22, V=23, W=24, X=25, Z=26
    # Then 27-52 for the second "suit", then jokers
    ka_deck = list(range(1, 53)) + [53, 54]  # Same as std for now

    for deck_name, deck in [("std_solitaire", std_deck),
                             ("rev_solitaire", rev_deck)]:
        try:
            ks_raw = solitaire_keystream(deck, CT_LEN)
            ks = [(k - 1) % MOD for k in ks_raw]  # Convert 1-52 to 0-25

            for dec_name, dec_fn in [("vig", decrypt_vigenere), ("beau", decrypt_beaufort)]:
                label = f"H4_{deck_name}_{dec_name}"
                pt = dec_fn(CT, ks)
                result = evaluate_plaintext(pt, label)
                results.append(result)
                if result["crib_score"] > 2:
                    print(f"  [!] {label}: crib={result['crib_score']}/24")
                    track_best(result)
        except Exception as e:
            print(f"  Error with {deck_name}: {e}")

    # Test Solitaire with passphrase keying
    # Key the deck using "KRYPTOS" as passphrase
    for passphrase in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK"]:
        try:
            keyed_deck = key_solitaire_deck(std_deck[:], passphrase)
            ks_raw = solitaire_keystream(keyed_deck, CT_LEN)
            ks = [(k - 1) % MOD for k in ks_raw]

            for dec_name, dec_fn in [("vig", decrypt_vigenere), ("beau", decrypt_beaufort)]:
                label = f"H4_solitaire_{passphrase}_{dec_name}"
                pt = dec_fn(CT, ks)
                result = evaluate_plaintext(pt, label)
                results.append(result)
                if result["crib_score"] > 2:
                    print(f"  [!] {label}: crib={result['crib_score']}/24")
                    track_best(result)
        except Exception as e:
            print(f"  Error with solitaire_{passphrase}: {e}")

    return results


def key_solitaire_deck(deck: List[int], passphrase: str) -> List[int]:
    """Key a Solitaire deck using a passphrase."""
    d = deck[:]
    for ch in passphrase.upper():
        if ch not in ALPH:
            continue
        val = ALPH_IDX[ch] + 1  # A=1, B=2, ..., Z=26

        # Step 1: Move joker A down one
        pos_a = d.index(53)
        if pos_a == len(d) - 1:
            d.insert(1, d.pop(pos_a))
        else:
            d[pos_a], d[pos_a + 1] = d[pos_a + 1], d[pos_a]

        # Step 2: Move joker B down two
        pos_b = d.index(54)
        if pos_b == len(d) - 1:
            d.insert(2, d.pop(pos_b))
        elif pos_b == len(d) - 2:
            d.insert(1, d.pop(pos_b))
        else:
            d[pos_b], d[pos_b + 1] = d[pos_b + 1], d[pos_b]
            d[pos_b + 1], d[pos_b + 2] = d[pos_b + 2], d[pos_b + 1]

        # Step 3: Triple cut
        pos_a = d.index(53)
        pos_b = d.index(54)
        top = min(pos_a, pos_b)
        bot = max(pos_a, pos_b)
        d = d[bot + 1:] + d[top:bot + 1] + d[:top]

        # Step 4: Count cut
        bottom_card = d[-1]
        cut_val = min(bottom_card, 53)
        d = d[cut_val:-1] + d[:cut_val] + [d[-1]]

        # Step 5: Count cut using passphrase letter value
        d = d[val:-1] + d[:val] + [d[-1]]

    return d


# ═══════════════════════════════════════════════════════════════════════
# H5: FACE CARDS AS MARKERS (MOST IMPORTANT TEST)
# ═══════════════════════════════════════════════════════════════════════

def test_h5():
    """Test face-card letters as markers/nulls."""
    print("\n" + "=" * 70)
    print("H5: FACE CARDS AS MARKERS / NULLS")
    print("  (The most important test per task specification)")
    print("=" * 70)

    results = {}

    # Face card letters: K, Q, J, A
    # Count occurrences in CT
    face_count = {ch: CT.count(ch) for ch in "KQJA"}
    total_face = sum(face_count.values())
    non_face_ct = "".join(c for c in CT if c not in FACE_CARD_LETTERS)

    print(f"\n  Face-card letters in K4 CT:")
    print(f"    K: {face_count['K']} occurrences")
    print(f"    Q: {face_count['Q']} occurrences")
    print(f"    J: {face_count['J']} occurrences")
    print(f"    A: {face_count['A']} occurrences")
    print(f"    Total face-card letters: {total_face}/{CT_LEN}")
    print(f"    Remaining after removal: {len(non_face_ct)} chars")
    print(f"    Non-face CT: {non_face_ct}")

    # Positions of face-card letters
    face_positions = [i for i, c in enumerate(CT) if c in FACE_CARD_LETTERS]
    non_face_positions = [i for i, c in enumerate(CT) if c not in FACE_CARD_LETTERS]
    print(f"\n  Face-card positions: {face_positions}")

    # Check which crib positions are face-card letters
    crib_face = {pos: CT[pos] for pos in CRIB_DICT if CT[pos] in FACE_CARD_LETTERS}
    crib_non_face = {pos: CT[pos] for pos in CRIB_DICT if CT[pos] not in FACE_CARD_LETTERS}
    print(f"\n  Crib positions that ARE face-card letters: {crib_face}")
    print(f"  Crib positions that are NOT face-card letters: {len(crib_non_face)}/{N_CRIBS}")

    # Statistical analysis of the non-face CT
    ic_full = ic(CT)
    ic_non_face = ic(non_face_ct)
    print(f"\n  IC analysis:")
    print(f"    Full CT IC: {ic_full:.4f}")
    print(f"    Non-face CT IC: {ic_non_face:.4f}")
    print(f"    English IC: 0.0667")
    print(f"    Random IC: 0.0385")

    # Letter frequency analysis
    freq_full = Counter(CT)
    freq_non_face = Counter(non_face_ct)

    # Chi-squared test against uniform distribution
    expected_uniform_full = CT_LEN / 26
    chi2_full = sum((freq_full.get(c, 0) - expected_uniform_full) ** 2 / expected_uniform_full
                    for c in ALPH)

    non_face_alph = set(ALPH) - FACE_CARD_LETTERS
    expected_uniform_nf = len(non_face_ct) / len(non_face_alph)
    chi2_nf = sum((freq_non_face.get(c, 0) - expected_uniform_nf) ** 2 / expected_uniform_nf
                  for c in non_face_alph)

    print(f"\n  Chi-squared vs uniform:")
    print(f"    Full CT: {chi2_full:.2f} (df=25)")
    print(f"    Non-face CT: {chi2_nf:.2f} (df={len(non_face_alph)-1})")

    # Expected frequency of K,Q,J,A in random 97-char text
    expected_per_letter = CT_LEN / 26
    print(f"\n  Expected count per letter in random 97-char text: {expected_per_letter:.1f}")
    print(f"  Actual K count: {face_count['K']}, deviation: {face_count['K'] - expected_per_letter:+.1f}")
    print(f"  Actual Q count: {face_count['Q']}, deviation: {face_count['Q'] - expected_per_letter:+.1f}")
    print(f"  Actual J count: {face_count['J']}, deviation: {face_count['J'] - expected_per_letter:+.1f}")
    print(f"  Actual A count: {face_count['A']}, deviation: {face_count['A'] - expected_per_letter:+.1f}")
    print(f"  Combined KQJA: {total_face}, expected: {4*expected_per_letter:.1f}, "
          f"deviation: {total_face - 4*expected_per_letter:+.1f}")

    # Test: remove face-card letters and try simple decryptions on remainder
    print(f"\n  Testing decryptions on non-face CT ({len(non_face_ct)} chars)...")

    # Caesar shifts on non-face
    best_caesar_nf = {"score": 0}
    for shift in range(1, 26):
        pt = "".join(ALPH[(ALPH_IDX[c] - shift) % MOD] for c in non_face_ct)
        sc = score_candidate(pt)
        if sc.crib_score > best_caesar_nf["score"]:
            best_caesar_nf = {"score": sc.crib_score, "shift": shift, "pt": pt}

    print(f"  Best Caesar on non-face: crib={best_caesar_nf['score']}/24")

    # Test: face-card positions encode operation switches
    # e.g., K = shift the remaining cipher operation
    # Try: segment CT by face-card positions, apply different shifts to each segment
    segments = []
    prev = 0
    for pos in face_positions:
        if prev < pos:
            segments.append((prev, pos, CT[prev:pos]))
        prev = pos + 1
    if prev < CT_LEN:
        segments.append((prev, CT_LEN, CT[prev:CT_LEN]))

    print(f"\n  Segments between face-card markers: {len(segments)}")
    for start, end, seg in segments[:10]:
        print(f"    [{start}:{end}] ({len(seg)} chars): {seg[:30]}...")

    # Test: face-card letters indicate suit (K=0, Q=1, J=2, A=3)
    # and remaining letters encode within that suit
    face_to_suit = {"K": 0, "Q": 1, "J": 2, "A": 3}

    # Build face-card position data
    face_data = [(i, CT[i], face_to_suit.get(CT[i])) for i in range(CT_LEN) if CT[i] in FACE_CARD_LETTERS]
    print(f"\n  Face-card sequence: {''.join(CT[i] for i in face_positions)}")

    # Interval analysis between face-card positions
    if len(face_positions) > 1:
        intervals = [face_positions[i+1] - face_positions[i] for i in range(len(face_positions)-1)]
        print(f"  Intervals between face-cards: {intervals}")
        print(f"  Mean interval: {sum(intervals)/len(intervals):.1f}")

    # Test: extract only face-card letters as a separate message
    face_only = "".join(CT[i] for i in face_positions)
    print(f"\n  Face-card letters only: {face_only}")
    print(f"  Face-card letter count: {len(face_only)}")

    # Store results
    results = {
        "face_counts": face_count,
        "total_face": total_face,
        "non_face_length": len(non_face_ct),
        "non_face_ct": non_face_ct,
        "face_positions": face_positions,
        "ic_full": ic_full,
        "ic_non_face": ic_non_face,
        "chi2_full": chi2_full,
        "chi2_non_face": chi2_nf,
        "crib_positions_with_face_letters": crib_face,
        "segments_between_markers": len(segments),
        "best_caesar_non_face": best_caesar_nf["score"],
    }

    # ── Extended face-card analysis ──
    # Test multiple null-letter sets (not just KQJA)
    print(f"\n  Testing alternative null-letter sets...")
    alt_null_sets = {
        "KQJA": FACE_CARD_LETTERS,
        "KQJ": set("KQJ"),  # Without Ace
        "KA": set("KA"),    # Just K and A (KA alphabet reference)
        "JQKA_plus_10": set("KQJA") | set("X"),  # 10 ~ X (24th letter)?
    }

    for null_name, null_set in alt_null_sets.items():
        remaining = "".join(c for c in CT if c not in null_set)
        ic_rem = ic(remaining) if len(remaining) > 1 else 0
        print(f"    Remove {null_name}: {len(remaining)} chars, IC={ic_rem:.4f}")

    return results


# ═══════════════════════════════════════════════════════════════════════
# H6: KA ALPHABET AS CARD MAPPING
# ═══════════════════════════════════════════════════════════════════════

def test_h6():
    """Test KA alphabet as card mapping."""
    print("\n" + "=" * 70)
    print("H6: KA ALPHABET AS CARD MAPPING")
    print("=" * 70)

    results = []

    # KA alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ
    # Position 0=K, 1=R, ..., 16=J, ..., 20=Q, ..., 25=Z
    ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

    # Map face cards to their KA positions
    face_ka_pos = {c: ka_idx[c] for c in "KQJA"}
    print(f"  Face-card positions in KA alphabet:")
    print(f"    K = position {face_ka_pos['K']} (King)")
    print(f"    Q = position {face_ka_pos['Q']} (Queen)")
    print(f"    J = position {face_ka_pos['J']} (Jack)")
    print(f"    A = position {face_ka_pos['A']} (Ace)")

    # Test: KA position values as Vigenère key
    # Each CT letter's KA position as the "card value"
    ks_ka = [ka_idx[c] for c in CT]

    # Test: Use KA ordering to define a substitution
    # KA[i] -> ALPH[i] (K->A, R->B, Y->C, ...)
    ka_to_az = {KRYPTOS_ALPHABET[i]: ALPH[i] for i in range(26)}
    pt = "".join(ka_to_az[c] for c in CT)
    result = evaluate_plaintext(pt, "H6_KA_to_AZ_sub")
    results.append(result)
    print(f"  KA->AZ substitution: crib={result['crib_score']}/24, IC={result['ic_value']:.4f}")

    # Reverse: AZ[i] -> KA[i]
    az_to_ka = {ALPH[i]: KRYPTOS_ALPHABET[i] for i in range(26)}
    pt = "".join(az_to_ka[c] for c in CT)
    result = evaluate_plaintext(pt, "H6_AZ_to_KA_sub")
    results.append(result)
    print(f"  AZ->KA substitution: crib={result['crib_score']}/24, IC={result['ic_value']:.4f}")

    # Test: KA position as card rank mapping
    # Position 0-12 = first suit (rank 1-13), 13-25 = second suit (rank 1-13)
    # So K(0)=rank1/suit1, ..., J(16)=rank4/suit2, ..., Q(20)=rank8/suit2
    ka_rank = [(ka_idx[c] % 13) + 1 for c in CT]
    ka_suit = [ka_idx[c] // 13 for c in CT]

    print(f"\n  KA-mapped ranks: {ka_rank[:20]}...")
    print(f"  KA-mapped suits: {ka_suit[:20]}...")

    # Use rank as keystream
    ks_rank = [r % MOD for r in ka_rank]
    for dec_name, dec_fn in [("vig", decrypt_vigenere), ("beau", decrypt_beaufort)]:
        label = f"H6_KA_rank_ks_{dec_name}"
        pt = dec_fn(CT, ks_rank)
        result = evaluate_plaintext(pt, label)
        results.append(result)
        if result["crib_score"] > 2:
            print(f"  [!] {label}: crib={result['crib_score']}/24")
            track_best(result)

    # Test: Two-layer — first KA substitution, then Vigenère
    # KA-sub then shift by card-derived keystream
    ka_subbed = "".join(ka_to_az[c] for c in CT)
    for shift in range(1, 26):
        pt = "".join(ALPH[(ALPH_IDX[c] - shift) % MOD] for c in ka_subbed)
        result = evaluate_plaintext(pt, f"H6_KAsub_caesar{shift}")
        results.append(result)
        if result["crib_score"] > 2:
            print(f"  [!] H6_KAsub_caesar{shift}: crib={result['crib_score']}/24")
            track_best(result)

    # Test: interleave based on KA position parity (suit 0 vs suit 1)
    suit0_chars = [CT[i] for i in range(CT_LEN) if ka_idx[CT[i]] < 13]
    suit1_chars = [CT[i] for i in range(CT_LEN) if ka_idx[CT[i]] >= 13]
    print(f"\n  KA suit 0 (pos 0-12): {len(suit0_chars)} chars")
    print(f"  KA suit 1 (pos 13-25): {len(suit1_chars)} chars")

    # Test: Map CT through KA-based Polybius square
    # 5x5 grid from KA alphabet (drop one letter — but K4 uses all 26!)
    # Use 6x5 grid instead (26 cells, 4 empty)
    # or use KA as-is with position = row*5+col or similar
    for grid_width in [5, 6, 7, 9, 13]:
        # Convert CT to grid coordinates
        coords = [(ka_idx[c] // grid_width, ka_idx[c] % grid_width) for c in CT]
        # Read off row values, then col values
        rows = [r for r, c in coords]
        cols = [c for r, c in coords]

        # Try: use rows as keystream
        ks_rows = [r % MOD for r in rows]
        pt = decrypt_vigenere(CT, ks_rows)
        result = evaluate_plaintext(pt, f"H6_KA_grid{grid_width}_row_ks")
        results.append(result)
        if result["crib_score"] > 2:
            print(f"  [!] {result['label']}: crib={result['crib_score']}/24")
            track_best(result)

    max_crib = max(r["crib_score"] for r in results) if results else 0
    avg_crib = sum(r["crib_score"] for r in results) / len(results) if results else 0
    print(f"\n  H6 Summary: {len(results)} configs tested")
    print(f"  Max crib score: {max_crib}/24, Avg: {avg_crib:.1f}/24")

    return results


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("Card-Based Cipher Hypothesis Tests for K4")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Known cribs: EASTNORTHEAST (21-33), BERLINCLOCK (63-73)")
    print()

    all_results = {}

    h1_results = test_h1()
    all_results["H1_card_value_subtraction"] = h1_results

    h2_results = test_h2()
    all_results["H2_suit_based_substitution"] = h2_results

    h3_results = test_h3()
    all_results["H3_deck_shuffle_transposition"] = h3_results

    h4_results = test_h4()
    all_results["H4_card_rank_keystream"] = h4_results

    h5_results = test_h5()
    all_results["H5_face_card_markers"] = h5_results

    h6_results = test_h6()
    all_results["H6_ka_card_mapping"] = h6_results

    # ── Final Summary ──
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)

    # Gather all scored results (H5 returns a dict, not a list of scored results)
    all_scored = []
    for key, val in all_results.items():
        if isinstance(val, list):
            all_scored.extend(val)

    if all_scored:
        all_scored.sort(key=lambda r: r["crib_score"], reverse=True)

        print(f"\nTotal configurations tested: {len(all_scored)}")
        max_score = all_scored[0]["crib_score"]
        print(f"Maximum crib score: {max_score}/24")
        print(f"Expected random: ~0.9/24")

        print(f"\nTop 10 results:")
        for r in all_scored[:10]:
            print(f"  {r['label']}: crib={r['crib_score']}/24, IC={r['ic_value']:.4f}, "
                  f"ENE={r['ene_score']}/13, BC={r['bc_score']}/11")

        # Any above noise?
        above_noise = [r for r in all_scored if r["crib_score"] > 6]
        if above_noise:
            print(f"\n*** {len(above_noise)} results ABOVE NOISE FLOOR (>6/24) ***")
            for r in above_noise:
                print(f"  {r['label']}: {r['summary']}")
        else:
            print(f"\nNo results above noise floor (>6/24).")

    # H5 special summary
    if isinstance(all_results.get("H5_face_card_markers"), dict):
        h5 = all_results["H5_face_card_markers"]
        print(f"\nH5 Face-Card Analysis Key Findings:")
        print(f"  KQJA count in CT: {h5['total_face']}/{CT_LEN} "
              f"(expected: {4*CT_LEN/26:.1f})")
        print(f"  IC after removing KQJA: {h5['ic_non_face']:.4f} "
              f"(full CT: {h5['ic_full']:.4f})")

        ic_improvement = h5["ic_non_face"] > h5["ic_full"]
        print(f"  IC {'IMPROVED' if ic_improvement else 'did NOT improve'} after removing face-card letters")

        if h5["crib_positions_with_face_letters"]:
            print(f"  WARNING: {len(h5['crib_positions_with_face_letters'])} crib positions contain "
                  f"face-card letters: {h5['crib_positions_with_face_letters']}")
            print(f"  This means face-card removal DISRUPTS known cribs — nulls hypothesis weakened.")
        else:
            print(f"  No crib positions contain face-card letters (consistent with nulls hypothesis)")

    # Save results
    output_path = os.path.join(OUTDIR, "card_cipher_results.json")

    # Serialize (convert non-serializable types)
    def make_serializable(obj):
        if isinstance(obj, dict):
            return {str(k): make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [make_serializable(x) for x in obj]
        elif isinstance(obj, (set, frozenset)):
            return sorted(make_serializable(x) for x in obj)
        elif isinstance(obj, float):
            return round(obj, 6)
        return obj

    serializable = make_serializable(all_results)
    with open(output_path, "w") as f:
        json.dump(serializable, f, indent=2, default=str)
    print(f"\nResults saved to {output_path}")

    # Verdict
    print("\n" + "=" * 70)
    print("VERDICT")
    print("=" * 70)

    if all_scored and max(r["crib_score"] for r in all_scored) > 6:
        print("Some results exceeded noise floor — investigate further.")
    else:
        print("ALL card-based cipher hypotheses produced NOISE-level results.")
        print("No evidence that K4 is encrypted with a playing-card-based cipher")
        print("under any of the tested configurations.")


if __name__ == "__main__":
    main()
