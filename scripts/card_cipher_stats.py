#!/usr/bin/env python3
"""
Card-cipher statistical analysis of K4 ciphertext.

Investigates whether K4's letter distribution shows signatures consistent
with a playing-card-based cipher. Checks mod-13 (rank), mod-4 (suit),
face-card clustering, bigram context, and cross-section comparison.

Output: results/card_cipher_stats/
"""

import json
import math
import os
import sys
from collections import Counter
from itertools import combinations

# Import from project constants — never hardcode
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET

# ── K1–K3 ciphertexts for cross-comparison ──────────────────────────────
# Extracted from the sculpture; K1+K2 use Vigenere with KA alphabet, K3 is transposition
# These are the CIPHERTEXT characters, not plaintext
K1_CT = (
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
)
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLG"      # ? removed
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVHDWKBFUFPWNTDFIYCUQZERE"       # ? removed
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZMFKZBSFDQVGOGIPUFXHHDRKF"      # Z? -> ZM, ? removed
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

FACE_CARDS = {'K', 'Q', 'J', 'A'}
FACE_NAMES = {'K': 'King', 'Q': 'Queen', 'J': 'Jack', 'A': 'Ace'}

OUT_DIR = "results/card_cipher_stats"


def freq_analysis(text, label=""):
    """Full frequency analysis with expected English comparison."""
    # English letter frequencies (standard)
    eng_freq = {
        'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
        'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
        'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
        'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
        'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
        'Z': 0.074
    }

    n = len(text)
    counts = Counter(text)

    print(f"\n{'='*70}")
    print(f"FREQUENCY ANALYSIS: {label} (n={n})")
    print(f"{'='*70}")
    print(f"{'Letter':>6} {'Count':>5} {'Obs%':>7} {'Eng%':>7} {'Delta':>7} {'Chi2':>8}")
    print(f"{'-'*6:>6} {'-'*5:>5} {'-'*7:>7} {'-'*7:>7} {'-'*7:>7} {'-'*8:>8}")

    chi2_total = 0.0
    results = []
    for ch in ALPH:
        obs = counts.get(ch, 0)
        obs_pct = 100.0 * obs / n
        eng_pct = eng_freq[ch]
        delta = obs_pct - eng_pct
        expected = eng_pct * n / 100.0
        chi2_contrib = (obs - expected) ** 2 / expected if expected > 0 else 0
        chi2_total += chi2_contrib
        marker = " ***" if abs(delta) > 3.0 else " **" if abs(delta) > 2.0 else " *" if abs(delta) > 1.5 else ""
        print(f"{ch:>6} {obs:>5} {obs_pct:>7.2f} {eng_pct:>7.3f} {delta:>+7.2f} {chi2_contrib:>8.3f}{marker}")
        results.append({
            'letter': ch, 'count': obs, 'obs_pct': obs_pct,
            'eng_pct': eng_pct, 'delta': delta, 'chi2_contrib': chi2_contrib
        })

    print(f"\nChi-squared total: {chi2_total:.3f} (df=25, critical p=0.05: 37.65)")
    print(f"  -> {'REJECT' if chi2_total > 37.65 else 'FAIL TO REJECT'} null hypothesis of English-like distribution")

    # Uniform distribution chi-squared
    expected_uniform = n / 26.0
    chi2_uniform = sum((counts.get(ch, 0) - expected_uniform) ** 2 / expected_uniform for ch in ALPH)
    print(f"\nChi-squared vs uniform: {chi2_uniform:.3f} (df=25, critical p=0.05: 37.65)")
    print(f"  -> {'REJECT' if chi2_uniform > 37.65 else 'FAIL TO REJECT'} null hypothesis of uniform distribution")

    return results, chi2_total, chi2_uniform


def face_card_analysis(text, label=""):
    """Analyze positions and clustering of face-card letters K, Q, J, A."""
    n = len(text)
    positions = {ch: [] for ch in FACE_CARDS}
    for i, ch in enumerate(text):
        if ch in FACE_CARDS:
            positions[ch].append(i)

    total_face = sum(len(v) for v in positions.values())
    face_pct = 100.0 * total_face / n

    print(f"\n{'='*70}")
    print(f"FACE-CARD ANALYSIS: {label} (n={n})")
    print(f"{'='*70}")
    print(f"Total face-card letters (K,Q,J,A): {total_face}/{n} = {face_pct:.1f}%")

    # Expected in English
    eng_face_pct = 0.772 + 0.095 + 0.153 + 8.167  # K + Q + J + A
    print(f"Expected in English: {eng_face_pct:.2f}%")
    print(f"Expected in uniform random: {4/26*100:.2f}%")

    for ch in ['K', 'Q', 'J', 'A']:
        pos_list = positions[ch]
        eng_pct = {'K': 0.772, 'Q': 0.095, 'J': 0.153, 'A': 8.167}[ch]
        obs_pct = 100.0 * len(pos_list) / n
        print(f"\n  {FACE_NAMES[ch]} ({ch}): count={len(pos_list)}, obs={obs_pct:.2f}%, eng={eng_pct:.3f}%")
        print(f"    Positions: {pos_list}")
        if len(pos_list) >= 2:
            gaps = [pos_list[i+1] - pos_list[i] for i in range(len(pos_list)-1)]
            print(f"    Gaps: {gaps}")
            print(f"    Mean gap: {sum(gaps)/len(gaps):.2f}, Std gap: {(sum((g - sum(gaps)/len(gaps))**2 for g in gaps)/len(gaps))**0.5:.2f}")

    # Clustering analysis: divide into segments
    all_face_positions = sorted(p for positions_list in positions.values() for p in positions_list)
    print(f"\n  All face-card positions (sorted): {all_face_positions}")

    # Segment analysis
    segments = [(0, 24), (25, 52), (53, 72), (73, 96)]
    print(f"\n  Segment distribution:")
    for s_start, s_end in segments:
        count_in_seg = sum(1 for p in all_face_positions if s_start <= p <= s_end)
        seg_len = s_end - s_start + 1
        density = count_in_seg / seg_len
        print(f"    [{s_start:>2}-{s_end:>2}] ({seg_len:>2} chars): {count_in_seg} face cards, density={density:.3f}")

    # Runs test: are face cards clustered or dispersed?
    binary = [1 if text[i] in FACE_CARDS else 0 for i in range(n)]
    n1 = sum(binary)
    n0 = n - n1
    runs = 1
    for i in range(1, n):
        if binary[i] != binary[i-1]:
            runs += 1
    expected_runs = 1 + 2 * n0 * n1 / n
    var_runs = 2 * n0 * n1 * (2 * n0 * n1 - n) / (n * n * (n - 1))
    z_runs = (runs - expected_runs) / (var_runs ** 0.5) if var_runs > 0 else 0
    print(f"\n  Runs test: {runs} runs (expected {expected_runs:.1f}, z={z_runs:.2f})")
    print(f"    -> {'Clustered' if z_runs < -1.96 else 'Dispersed' if z_runs > 1.96 else 'No significant clustering/dispersion'} (p<0.05 threshold)")

    return positions, all_face_positions


def mod_analysis(text, modulus, label=""):
    """Analyze text under modular arithmetic (mod-13 for ranks, mod-4 for suits)."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"MOD-{modulus} ANALYSIS: {label} (n={n})")
    print(f"{'='*70}")

    # Standard alphabet mapping: A=0, B=1, ..., Z=25
    values_std = [ALPH_IDX[ch] for ch in text]
    residues_std = [v % modulus for v in values_std]

    # KA alphabet mapping
    ka_idx = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}
    values_ka = [ka_idx[ch] for ch in text]
    residues_ka = [v % modulus for v in values_ka]

    for mapping_name, residues, values in [("Standard A=0", residues_std, values_std),
                                            ("KA alphabet", residues_ka, values_ka)]:
        print(f"\n  Mapping: {mapping_name}")
        counts = Counter(residues)
        expected = n / modulus
        chi2 = sum((counts.get(r, 0) - expected) ** 2 / expected for r in range(modulus))
        df = modulus - 1
        # Critical values for common df
        critical = {3: 7.815, 12: 21.026, 25: 37.652}.get(df, None)

        print(f"  Residue distribution:")
        for r in range(modulus):
            c = counts.get(r, 0)
            bar = '#' * c
            print(f"    r={r:>2}: {c:>3} ({100*c/n:>5.1f}%) {bar}")

        print(f"  Chi-squared: {chi2:.3f} (df={df}" +
              (f", critical p=0.05: {critical}" if critical else "") + ")")
        if critical:
            print(f"    -> {'REJECT' if chi2 > critical else 'FAIL TO REJECT'} null hypothesis of uniform mod-{modulus}")

        # Consecutive residue differences
        diffs = [(residues[i+1] - residues[i]) % modulus for i in range(n-1)]
        diff_counts = Counter(diffs)
        print(f"\n  Consecutive residue differences (mod {modulus}):")
        for d in range(modulus):
            c = diff_counts.get(d, 0)
            print(f"    d={d:>2}: {c:>3}")

        # Autocorrelation of residues
        print(f"\n  Autocorrelation of mod-{modulus} residues:")
        for lag in [1, 2, 3, 4, 5, 13, 26]:
            if lag >= n:
                continue
            pairs = [(residues[i], residues[i+lag]) for i in range(n-lag)]
            match_count = sum(1 for a, b in pairs if a == b)
            expected_match = (n - lag) / modulus
            print(f"    lag={lag:>2}: matches={match_count:>3} (expected={expected_match:.1f}, ratio={match_count/expected_match:.3f})")

    # Special: Card-value mapping (A=1, B=2, ..., M=13=K, N=14=A, ...)
    # Under mod-13: A=1, B=2, ..., M=0 (K=13≡0), N=1 (A), etc.
    print(f"\n  Special: Card-value mapping (A=1, B=2, ..., Z=26) mod-{modulus}")
    values_card = [(ALPH_IDX[ch] + 1) % modulus for ch in text]
    counts_card = Counter(values_card)
    expected = n / modulus
    chi2_card = sum((counts_card.get(r, 0) - expected) ** 2 / expected for r in range(modulus))
    for r in range(modulus):
        c = counts_card.get(r, 0)
        # Which letters map to this residue?
        letters = [ALPH[i] for i in range(26) if (i + 1) % modulus == r]
        print(f"    r={r:>2}: {c:>3} ({100*c/n:>5.1f}%) letters={letters}")
    print(f"  Chi-squared: {chi2_card:.3f}")


def bigram_context(text, target_letters, label=""):
    """Analyze bigram context around target letters."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"BIGRAM CONTEXT AROUND {target_letters}: {label}")
    print(f"{'='*70}")

    for target in target_letters:
        positions = [i for i, ch in enumerate(text) if ch == target]
        if not positions:
            continue

        print(f"\n  Letter {target} (count={len(positions)}):")

        # What precedes it?
        preceding = Counter()
        following = Counter()
        bigrams_before = Counter()
        bigrams_after = Counter()

        for p in positions:
            if p > 0:
                preceding[text[p-1]] += 1
                bigrams_before[text[p-1] + target] += 1
            if p < n - 1:
                following[text[p+1]] += 1
                bigrams_after[target + text[p+1]] += 1

        print(f"    Preceding letters: {dict(preceding.most_common())}")
        print(f"    Following letters: {dict(following.most_common())}")
        print(f"    Bigrams before: {dict(bigrams_before.most_common())}")
        print(f"    Bigrams after: {dict(bigrams_after.most_common())}")

        # Context windows (3 chars each side)
        print(f"    Context windows:")
        for p in positions:
            start = max(0, p - 3)
            end = min(n, p + 4)
            context = text[start:end]
            marker_pos = p - start
            display = context[:marker_pos] + '[' + context[marker_pos] + ']' + context[marker_pos+1:]
            print(f"      pos {p:>2}: ...{display}...")


def cross_section_comparison():
    """Compare face-card distribution across K1, K2, K3, K4."""
    sections = {
        'K1': K1_CT,
        'K2': K2_CT,
        'K3': K3_CT,
        'K4': CT,
    }

    print(f"\n{'='*70}")
    print(f"CROSS-SECTION FACE-CARD COMPARISON")
    print(f"{'='*70}")

    print(f"\n{'Section':>8} {'n':>4} {'K':>3} {'Q':>3} {'J':>3} {'A':>3} {'Total':>5} {'%':>7} {'K%':>7} {'Q%':>7} {'J%':>7}")
    print(f"{'---':>8} {'---':>4} {'---':>3} {'---':>3} {'---':>3} {'---':>3} {'---':>5} {'---':>7} {'---':>7} {'---':>7} {'---':>7}")

    section_data = {}
    for name, text in sections.items():
        counts = Counter(text)
        n = len(text)
        k_c = counts.get('K', 0)
        q_c = counts.get('Q', 0)
        j_c = counts.get('J', 0)
        a_c = counts.get('A', 0)
        total = k_c + q_c + j_c + a_c
        pct = 100.0 * total / n
        print(f"{name:>8} {n:>4} {k_c:>3} {q_c:>3} {j_c:>3} {a_c:>3} {total:>5} {pct:>7.1f} {100*k_c/n:>7.2f} {100*q_c/n:>7.2f} {100*j_c/n:>7.02f}")
        section_data[name] = {
            'n': n, 'K': k_c, 'Q': q_c, 'J': j_c, 'A': a_c,
            'total': total, 'pct': pct
        }

    # Full frequency comparison table
    print(f"\n  Full letter frequency comparison:")
    print(f"{'Letter':>8} {'K1%':>7} {'K2%':>7} {'K3%':>7} {'K4%':>7} {'Eng%':>7}")
    eng_freq = {
        'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
        'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
        'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
        'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
        'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
        'Z': 0.074
    }
    for ch in ALPH:
        pcts = []
        for name, text in sections.items():
            c = Counter(text)
            pcts.append(100.0 * c.get(ch, 0) / len(text))
        print(f"{ch:>8} {pcts[0]:>7.2f} {pcts[1]:>7.2f} {pcts[2]:>7.2f} {pcts[3]:>7.2f} {eng_freq[ch]:>7.3f}")

    return section_data


def alphabet_card_mappings(text, label=""):
    """Test various 26-letter-to-card mappings for structure."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"ALPHABET-TO-CARD MAPPINGS: {label}")
    print(f"{'='*70}")

    # Mapping 1: Standard A=0..Z=25, rank = value % 13, suit = value // 13 (first 13=spades, next 13=hearts)
    # But 26 letters = 2 suits worth of cards
    print(f"\n  Mapping 1: Standard order, 2 suits (A-M = suit 0, N-Z = suit 1)")
    suits = [ALPH_IDX[ch] // 13 for ch in text]
    ranks = [ALPH_IDX[ch] % 13 for ch in text]
    suit_counts = Counter(suits)
    rank_counts = Counter(ranks)
    print(f"    Suit distribution: {dict(suit_counts)} (expected ~{n/2:.0f} each)")
    suit_chi2 = sum((suit_counts.get(s, 0) - n/2)**2 / (n/2) for s in range(2))
    print(f"    Suit chi-squared: {suit_chi2:.3f} (df=1, critical=3.841)")
    print(f"    Rank distribution (0-12):")
    for r in range(13):
        c = rank_counts.get(r, 0)
        letters = [ALPH[i] for i in range(26) if i % 13 == r]
        print(f"      rank {r:>2}: {c:>3} ({100*c/n:>5.1f}%) letters={letters}")
    rank_chi2 = sum((rank_counts.get(r, 0) - n/13)**2 / (n/13) for r in range(13))
    print(f"    Rank chi-squared: {rank_chi2:.3f} (df=12, critical=21.026)")

    # Mapping 2: KA alphabet order
    print(f"\n  Mapping 2: KA alphabet order, 2 suits (first 13 = suit 0, last 13 = suit 1)")
    ka_idx = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}
    ka_suits = [ka_idx[ch] // 13 for ch in text]
    ka_ranks = [ka_idx[ch] % 13 for ch in text]
    ka_suit_counts = Counter(ka_suits)
    ka_rank_counts = Counter(ka_ranks)
    print(f"    KA alphabet: {KRYPTOS_ALPHABET}")
    print(f"    Suit 0 letters: {KRYPTOS_ALPHABET[:13]}")
    print(f"    Suit 1 letters: {KRYPTOS_ALPHABET[13:]}")
    print(f"    Suit distribution: {dict(ka_suit_counts)} (expected ~{n/2:.0f} each)")
    ka_suit_chi2 = sum((ka_suit_counts.get(s, 0) - n/2)**2 / (n/2) for s in range(2))
    print(f"    Suit chi-squared: {ka_suit_chi2:.3f} (df=1, critical=3.841)")
    print(f"    Rank distribution (0-12):")
    for r in range(13):
        c = ka_rank_counts.get(r, 0)
        letters = [KRYPTOS_ALPHABET[i] for i in range(26) if i % 13 == r]
        print(f"      rank {r:>2}: {c:>3} ({100*c/n:>5.1f}%) letters={letters}")
    ka_rank_chi2 = sum((ka_rank_counts.get(r, 0) - n/13)**2 / (n/13) for r in range(13))
    print(f"    Rank chi-squared: {ka_rank_chi2:.3f} (df=12, critical=21.026)")

    # Mapping 3: Card-natural (A=1, 2-10, J=11, Q=12, K=13)
    # Try: first letter of each card name -> A,2,3,...9,T(10),J,Q,K
    # But this is a playing card mapping, not a letter mapping per se
    # Instead: test what if the 97 chars represent 97 card draws?
    print(f"\n  Mapping 3: Playing-card natural order")
    print(f"    If A=Ace(1), B=2, C=3, ..., J=Jack(10), K=King(11), ...")
    print(f"    Standard letter-to-rank: value = (letter_index % 13) + 1")
    card_ranks = [(ALPH_IDX[ch] % 13) + 1 for ch in text]
    print(f"    Rank sequence (first 20): {card_ranks[:20]}")
    print(f"    Sum of all ranks: {sum(card_ranks)} (expected for 97 random: {97 * 7:.0f})")

    # Mapping 4: 4-suit interpretation with 26 = 4*6 + 2
    print(f"\n  Mapping 4: 4-suit interpretation (26 = 4*6 + 2 remainder)")
    print(f"    Suit = letter_index % 4")
    suits4 = [ALPH_IDX[ch] % 4 for ch in text]
    suit4_counts = Counter(suits4)
    expected4 = n / 4.0
    chi2_4suit = sum((suit4_counts.get(s, 0) - expected4)**2 / expected4 for s in range(4))
    for s in range(4):
        c = suit4_counts.get(s, 0)
        letters = [ALPH[i] for i in range(26) if i % 4 == s]
        print(f"    suit {s}: {c:>3} ({100*c/n:>5.1f}%) letters={letters}")
    print(f"    Chi-squared: {chi2_4suit:.3f} (df=3, critical=7.815)")

    # KA variant of 4-suit
    print(f"\n  Mapping 4b: 4-suit via KA alphabet")
    ka_suits4 = [ka_idx[ch] % 4 for ch in text]
    ka_suit4_counts = Counter(ka_suits4)
    ka_chi2_4suit = sum((ka_suit4_counts.get(s, 0) - expected4)**2 / expected4 for s in range(4))
    for s in range(4):
        c = ka_suit4_counts.get(s, 0)
        letters = [KRYPTOS_ALPHABET[i] for i in range(26) if i % 4 == s]
        print(f"    suit {s}: {c:>3} ({100*c/n:>5.1f}%) letters={letters}")
    print(f"    Chi-squared: {ka_chi2_4suit:.3f} (df=3, critical=7.815)")


def face_card_position_patterns(text, label=""):
    """Test if positions of K, Q, J, A form arithmetic sequences or mark boundaries."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"FACE-CARD POSITION PATTERNS: {label}")
    print(f"{'='*70}")

    positions = {}
    for ch in ['K', 'Q', 'J', 'A']:
        positions[ch] = [i for i, c in enumerate(text) if c == ch]

    all_face = sorted(p for ch in FACE_CARDS for p in positions.get(ch, []))

    # Test for arithmetic sequences in each letter's positions
    for ch in ['K', 'Q', 'J', 'A']:
        pos = positions[ch]
        if len(pos) < 3:
            continue
        print(f"\n  {ch} positions: {pos}")

        # Check all pairs for common differences
        diffs = set()
        for i in range(len(pos)):
            for j in range(i+1, len(pos)):
                diffs.add(pos[j] - pos[i])

        # Check for arithmetic progression subsets
        for d in sorted(diffs):
            if d <= 0 or d > n:
                continue
            # Find longest AP with difference d starting from each position
            for start in pos:
                seq = [start]
                nxt = start + d
                while nxt in pos:
                    seq.append(nxt)
                    nxt += d
                if len(seq) >= 3:
                    print(f"    AP with d={d}: {seq} (length {len(seq)})")

    # Combined face-card positions: test for divisibility patterns
    print(f"\n  All face-card positions: {all_face}")
    if all_face:
        print(f"  Face-card gaps: {[all_face[i+1] - all_face[i] for i in range(len(all_face)-1)]}")

        # Mod patterns in positions
        for m in [4, 7, 13, 26]:
            residues = [p % m for p in all_face]
            print(f"    Positions mod {m}: {residues}")
            counts = Counter(residues)
            expected = len(all_face) / m
            if expected > 0:
                chi2 = sum((counts.get(r, 0) - expected)**2 / expected for r in range(m))
                print(f"      Chi-squared: {chi2:.3f} (df={m-1})")

    # Do face cards mark suit boundaries if text is divided into 4 parts?
    quarter = n // 4  # ~24
    print(f"\n  Suit-boundary test (quarter={quarter}):")
    for ch in ['K', 'Q', 'J', 'A']:
        near_boundary = [p for p in positions[ch] if any(abs(p - b) <= 2 for b in [0, quarter, 2*quarter, 3*quarter, n-1])]
        print(f"    {ch} near quarter boundaries: {near_boundary}")


def digraph_analysis(text, label=""):
    """Analyze digraph (pair) frequencies for card-cipher structure."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"DIGRAPH & REPEAT ANALYSIS: {label}")
    print(f"{'='*70}")

    # Count all digraphs
    digraphs = Counter()
    for i in range(n - 1):
        digraphs[text[i:i+2]] += 1

    # Most common
    print(f"\n  Top 20 digraphs:")
    for dg, count in digraphs.most_common(20):
        print(f"    {dg}: {count}")

    # Repeated digraphs (count >= 2)
    repeated = {dg: c for dg, c in digraphs.items() if c >= 2}
    print(f"\n  Repeated digraphs (count >= 2): {len(repeated)}")
    for dg, c in sorted(repeated.items(), key=lambda x: -x[1]):
        positions_list = [i for i in range(n-1) if text[i:i+2] == dg]
        print(f"    {dg}: {c} times at positions {positions_list}")

    # Double letters
    doubles = [(i, text[i]) for i in range(n-1) if text[i] == text[i+1]]
    print(f"\n  Double letters: {doubles}")
    print(f"  Double letter count: {len(doubles)}")
    expected_doubles = sum(c * (c - 1) for c in Counter(text).values()) / n
    print(f"  Expected doubles (based on freq): {expected_doubles:.2f}")

    # Trigraphs
    trigraphs = Counter()
    for i in range(n - 2):
        trigraphs[text[i:i+3]] += 1
    repeated_tri = {tg: c for tg, c in trigraphs.items() if c >= 2}
    if repeated_tri:
        print(f"\n  Repeated trigraphs:")
        for tg, c in sorted(repeated_tri.items(), key=lambda x: -x[1]):
            positions_list = [i for i in range(n-2) if text[i:i+3] == tg]
            print(f"    {tg}: {c} times at positions {positions_list}")


def index_of_coincidence_by_mod(text, modulus, label=""):
    """Calculate IC for subsets defined by position mod modulus."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"IC BY POSITION MOD {modulus}: {label}")
    print(f"{'='*70}")

    for r in range(modulus):
        subset = [text[i] for i in range(n) if i % modulus == r]
        if len(subset) < 2:
            continue
        counts = Counter(subset)
        m = len(subset)
        ic = sum(c * (c - 1) for c in counts.values()) / (m * (m - 1)) if m > 1 else 0
        print(f"  Residue {r:>2} (n={m:>2}): IC={ic:.4f}")

    # Overall IC for reference
    counts = Counter(text)
    ic_all = sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))
    print(f"  Overall IC: {ic_all:.4f} (English ~0.0667, Random ~0.0385)")


def card_value_sum_analysis(text, label=""):
    """Test if card values at various positions sum to meaningful totals."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"CARD-VALUE SUM ANALYSIS: {label}")
    print(f"{'='*70}")

    # Standard A=1..Z=26
    values = [ALPH_IDX[ch] + 1 for ch in text]
    total = sum(values)
    print(f"  Total sum (A=1..Z=26): {total}")
    print(f"  Expected for 97 random letters: {97 * 13.5:.1f}")
    print(f"  Mean value: {total/n:.2f} (expected 13.5)")

    # Mod-52 sum (full deck)
    print(f"  Total mod 52: {total % 52}")
    print(f"  Total mod 54: {total % 54} (with jokers)")

    # Running sum mod 26
    print(f"\n  Running sum mod 26 (first 30):")
    running = 0
    for i in range(min(30, n)):
        running = (running + values[i]) % 26
        letter = ALPH[running]
        print(f"    pos {i:>2}: +{values[i]:>2} ({text[i]}) -> sum mod 26 = {running:>2} ({letter})")

    # Check if running sum produces readable text
    running = 0
    derived = []
    for v in values:
        running = (running + v) % 26
        derived.append(ALPH[running])
    derived_text = ''.join(derived)
    print(f"\n  Derived text (running sum mod 26): {derived_text}")

    # XOR-like: consecutive difference mod 26
    diff_text = ''.join(ALPH[(values[i+1] - values[i]) % 26] for i in range(n-1))
    print(f"  Consecutive differences mod 26: {diff_text}")


def period_13_analysis(text, label=""):
    """Deep analysis of period-13 structure (one suit's worth)."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"PERIOD-13 DEEP ANALYSIS: {label}")
    print(f"{'='*70}")

    # Split text into period-13 rows
    rows = []
    for i in range(0, n, 13):
        row = text[i:i+13]
        rows.append(row)

    print(f"  Text in period-13 rows ({len(rows)} rows):")
    for i, row in enumerate(rows):
        vals = [ALPH_IDX[ch] for ch in row]
        print(f"    Row {i}: {row}  values={vals}")

    # Column analysis
    print(f"\n  Column analysis:")
    for col in range(13):
        column = [text[i] for i in range(col, n, 13)]
        counts = Counter(column)
        ic = sum(c*(c-1) for c in counts.values()) / (len(column) * (len(column)-1)) if len(column) > 1 else 0
        print(f"    Col {col:>2}: {''.join(column)} IC={ic:.4f} freq={dict(counts)}")

    # Diagonal analysis
    print(f"\n  Main diagonal (row i, col i%13):")
    diag = [text[i*13 + i%13] for i in range(min(len(rows), 13)) if i*13 + i%13 < n]
    print(f"    {''.join(diag)}")

    # Anti-diagonal
    print(f"  Anti-diagonal (row i, col (12-i)%13):")
    adiag = [text[i*13 + (12-i)%13] for i in range(min(len(rows), 13)) if i*13 + (12-i)%13 < n]
    print(f"    {''.join(adiag)}")


def monte_carlo_face_card_test(text, n_trials=100000):
    """Monte Carlo test: how unusual is K4's face-card count and clustering?"""
    import random
    n = len(text)

    print(f"\n{'='*70}")
    print(f"MONTE CARLO FACE-CARD SIGNIFICANCE TEST (n_trials={n_trials})")
    print(f"{'='*70}")

    # Observed stats
    obs_face_count = sum(1 for ch in text if ch in FACE_CARDS)
    obs_k = sum(1 for ch in text if ch == 'K')
    obs_q = sum(1 for ch in text if ch == 'Q')
    obs_j = sum(1 for ch in text if ch == 'J')
    obs_kqj = obs_k + obs_q + obs_j  # excluding A since A is common in English

    # Expected under uniform random
    random.seed(42)
    face_counts = []
    kqj_counts = []
    k_counts = []

    for _ in range(n_trials):
        sample = ''.join(random.choice(ALPH) for _ in range(n))
        fc = sum(1 for ch in sample if ch in FACE_CARDS)
        kqj = sum(1 for ch in sample if ch in {'K', 'Q', 'J'})
        k_c = sum(1 for ch in sample if ch == 'K')
        face_counts.append(fc)
        kqj_counts.append(kqj)
        k_counts.append(k_c)

    # P-values
    p_face = sum(1 for x in face_counts if x >= obs_face_count) / n_trials
    p_kqj = sum(1 for x in kqj_counts if x >= obs_kqj) / n_trials
    p_k = sum(1 for x in k_counts if x >= obs_k) / n_trials

    mean_face = sum(face_counts) / n_trials
    mean_kqj = sum(kqj_counts) / n_trials
    mean_k = sum(k_counts) / n_trials

    print(f"\n  Face cards (K,Q,J,A) in K4: {obs_face_count}/97")
    print(f"    Under uniform random: mean={mean_face:.2f}")
    print(f"    P(X >= {obs_face_count}): {p_face:.4f}")

    print(f"\n  K+Q+J (no A) in K4: {obs_kqj}/97")
    print(f"    Under uniform random: mean={mean_kqj:.2f}")
    print(f"    P(X >= {obs_kqj}): {p_kqj:.4f}")

    print(f"\n  K count in K4: {obs_k}/97")
    print(f"    Under uniform random: mean={mean_k:.2f}")
    print(f"    P(X >= {obs_k}): {p_k:.4f}")

    # Also test against K4's actual frequency distribution (is the face-card count
    # unusual given K4's overall non-uniform distribution?)
    # Use K4's observed letter frequencies as the null
    freq = Counter(text)
    weights = [freq.get(ch, 0) for ch in ALPH]
    total_w = sum(weights)
    # Normalized probabilities
    probs = [w / total_w for w in weights]

    # Under K4's own distribution, how likely is the specific K/Q/J pattern?
    # This tests whether K/Q/J are over-represented even WITHIN K4's distribution
    # (tautological for the overall count, but useful for clustering)

    # Test: segment 25-52 has 10/28 face cards. How unusual?
    seg_start, seg_end = 25, 52
    seg_len = seg_end - seg_start + 1
    obs_seg_face = sum(1 for i in range(seg_start, seg_end + 1) if text[i] in FACE_CARDS)
    seg_face_rate = obs_face_count / n  # overall rate

    seg_counts = []
    for _ in range(n_trials):
        sample = ''.join(random.choice(ALPH) for _ in range(n))
        sc = sum(1 for i in range(seg_start, seg_end + 1) if sample[i] in FACE_CARDS)
        seg_counts.append(sc)

    p_seg = sum(1 for x in seg_counts if x >= obs_seg_face) / n_trials
    mean_seg = sum(seg_counts) / n_trials

    print(f"\n  Face cards in segment [{seg_start}-{seg_end}] ({seg_len} chars): {obs_seg_face}")
    print(f"    Under uniform random: mean={mean_seg:.2f}")
    print(f"    P(X >= {obs_seg_face}): {p_seg:.4f}")


def spectral_analysis(text, label=""):
    """Simple DFT-based spectral analysis of letter values."""
    n = len(text)
    print(f"\n{'='*70}")
    print(f"SPECTRAL ANALYSIS (DFT): {label}")
    print(f"{'='*70}")

    values = [ALPH_IDX[ch] for ch in text]
    mean_v = sum(values) / n
    centered = [v - mean_v for v in values]

    # Compute DFT magnitudes for key frequencies
    print(f"  DFT magnitudes at key frequencies:")
    for freq in [1, 2, 3, 4, 5, 7, 13, 26, 48, 49]:
        if freq > n // 2:
            continue
        re = sum(centered[t] * math.cos(2 * math.pi * freq * t / n) for t in range(n))
        im = sum(centered[t] * math.sin(2 * math.pi * freq * t / n) for t in range(n))
        mag = math.sqrt(re*re + im*im)
        print(f"    freq={freq:>3} (period={n/freq:.1f}): magnitude={mag:.3f}")

    # Top 10 frequencies by magnitude
    all_mags = []
    for freq in range(1, n // 2 + 1):
        re = sum(centered[t] * math.cos(2 * math.pi * freq * t / n) for t in range(n))
        im = sum(centered[t] * math.sin(2 * math.pi * freq * t / n) for t in range(n))
        mag = math.sqrt(re*re + im*im)
        all_mags.append((freq, mag, n/freq))

    all_mags.sort(key=lambda x: -x[1])
    print(f"\n  Top 10 DFT frequencies:")
    for freq, mag, period in all_mags[:10]:
        print(f"    freq={freq:>3} (period={period:.1f}): magnitude={mag:.3f}")


def main():
    print("=" * 70)
    print("K4 CARD-CIPHER STATISTICAL ANALYSIS")
    print("=" * 70)
    print(f"Ciphertext: {CT}")
    print(f"Length: {CT_LEN}")

    results = {}

    # 1. Full frequency analysis
    freq_results, chi2_eng, chi2_uni = freq_analysis(CT, "K4")
    results['frequency'] = {
        'chi2_vs_english': chi2_eng,
        'chi2_vs_uniform': chi2_uni,
        'details': freq_results
    }

    # 2. Face-card analysis
    face_positions, all_face_pos = face_card_analysis(CT, "K4")
    results['face_cards'] = {
        'positions': {ch: pos for ch, pos in face_positions.items()},
        'all_positions': all_face_pos
    }

    # 3. Mod-13 analysis (rank structure)
    mod_analysis(CT, 13, "K4")

    # 4. Mod-4 analysis (suit structure)
    mod_analysis(CT, 4, "K4")

    # 5. Bigram context around face cards
    bigram_context(CT, ['K', 'Q', 'J', 'A'], "K4")

    # 6. Cross-section comparison
    section_data = cross_section_comparison()
    results['cross_section'] = section_data

    # 7. Alphabet-to-card mappings
    alphabet_card_mappings(CT, "K4")

    # 8. Face-card position patterns
    face_card_position_patterns(CT, "K4")

    # 9. Digraph/repeat analysis
    digraph_analysis(CT, "K4")

    # 10. IC by position mod N
    for mod in [4, 13]:
        index_of_coincidence_by_mod(CT, mod, "K4")

    # 11. Card-value sum analysis
    card_value_sum_analysis(CT, "K4")

    # 12. Period-13 deep analysis
    period_13_analysis(CT, "K4")

    # 13. Monte Carlo significance tests
    monte_carlo_face_card_test(CT, n_trials=100000)

    # 14. Spectral analysis
    spectral_analysis(CT, "K4")

    # Save structured results
    os.makedirs(OUT_DIR, exist_ok=True)

    # Convert sets/frozensets for JSON
    def make_serializable(obj):
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if isinstance(obj, dict):
            return {k: make_serializable(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [make_serializable(v) for v in obj]
        return obj

    with open(os.path.join(OUT_DIR, "results.json"), 'w') as f:
        json.dump(make_serializable(results), f, indent=2)

    print(f"\n\n{'='*70}")
    print("SUMMARY OF KEY FINDINGS")
    print(f"{'='*70}")
    print(f"Results saved to {OUT_DIR}/results.json")


if __name__ == "__main__":
    main()
